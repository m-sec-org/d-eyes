package memscan

import (
	"context"
	"errors"
	"syscall"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

type fakeProcess struct {
	regions []Region
	index   int
}

func (f *fakeProcess) Query(_ uintptr) (Region, bool, error) {
	if f.index >= len(f.regions) {
		return Region{}, false, nil
	}
	region := f.regions[f.index]
	f.index++
	return region, true, nil
}

func (f *fakeProcess) Read(_ uintptr, buf []byte) (int, error) {
	for i := range buf {
		buf[i] = 'A'
	}
	return len(buf), nil
}

type partialCopyReadProcess struct {
	reads int
}

func (p *partialCopyReadProcess) Query(_ uintptr) (Region, bool, error) {
	return Region{Base: 0, Size: 25, State: memCommit, Protect: pageExecuteReadWrite}, true, nil
}

func (p *partialCopyReadProcess) Read(_ uintptr, buf []byte) (int, error) {
	p.reads++
	for i := range buf {
		buf[i] = 'A'
	}
	if p.reads == 1 {
		return len(buf) / 2, syscall.Errno(299) // ERROR_PARTIAL_COPY
	}
	return len(buf), nil
}

type readErrorProcess struct {
	regions  []Region
	index    int
	current  Region
	failBase uintptr
	failErr  error
}

func (p *readErrorProcess) Query(_ uintptr) (Region, bool, error) {
	if p.index >= len(p.regions) {
		return Region{}, false, nil
	}
	region := p.regions[p.index]
	p.index++
	p.current = region
	return region, true, nil
}

func (p *readErrorProcess) Read(_ uintptr, buf []byte) (int, error) {
	if p.current.Base == p.failBase {
		return 0, p.failErr
	}
	for i := range buf {
		buf[i] = 'A'
	}
	return len(buf), nil
}

type zeroReadProcess struct {
	region Region
	seen   bool
}

func (p *zeroReadProcess) Query(_ uintptr) (Region, bool, error) {
	if p.seen {
		return Region{}, false, nil
	}
	p.seen = true
	return p.region, true, nil
}

func (p *zeroReadProcess) Read(_ uintptr, _ []byte) (int, error) {
	return 0, nil
}

type slowReadProcess struct {
	region Region
	seen   bool
	sleep  time.Duration
}

func (p *slowReadProcess) Query(_ uintptr) (Region, bool, error) {
	if p.seen {
		return Region{}, false, nil
	}
	p.seen = true
	return p.region, true, nil
}

func (p *slowReadProcess) Read(_ uintptr, buf []byte) (int, error) {
	time.Sleep(p.sleep)
	for i := range buf {
		buf[i] = 'A'
	}
	return len(buf), nil
}

func TestWalkStopsAtMaxRegions(t *testing.T) {
	api := &fakeProcess{
		regions: []Region{
			{Base: 0, Size: 10, State: memCommit, Protect: pageExecuteReadWrite},
			{Base: 10, Size: 10, State: memCommit, Protect: pageExecuteReadWrite},
			{Base: 20, Size: 10, State: memCommit, Protect: pageExecuteReadWrite},
		},
	}

	stats, err := walk(context.Background(), api, Options{
		Filter:     FilterRWX,
		ChunkSize:  4,
		MaxRegions: 2,
	}, func(_ Chunk) error { return nil })
	require.NoError(t, err)
	require.Equal(t, 3, stats.RegionsEnumerated)
	require.Equal(t, 2, stats.RegionsMatched)
	require.Equal(t, 2, stats.RegionsRead)
	require.True(t, stats.Degraded)
	require.Contains(t, stats.DegradedReasons, DegradedMaxRegions)
}

func TestWalkStopsAtMaxBytes(t *testing.T) {
	api := &fakeProcess{
		regions: []Region{
			{Base: 0, Size: 1000, State: memCommit, Protect: pageExecuteReadWrite},
		},
	}

	var visited int
	stats, err := walk(context.Background(), api, Options{
		Filter:    FilterRWX,
		ChunkSize: 200,
		MaxBytes:  350,
	}, func(_ Chunk) error {
		visited++
		return nil
	})
	require.NoError(t, err)
	require.Equal(t, 1, stats.RegionsMatched)
	require.Equal(t, 1, stats.RegionsRead)
	require.Equal(t, uint64(350), stats.BytesRead)
	require.Equal(t, 2, visited)
	require.True(t, stats.Degraded)
	require.Contains(t, stats.DegradedReasons, DegradedMaxBytes)
}

func TestWalkMarksDegradedWhenContextExpired(t *testing.T) {
	api := &fakeProcess{
		regions: []Region{
			{Base: 0, Size: 10, State: memCommit, Protect: pageExecuteReadWrite},
		},
	}

	ctx, cancel := context.WithDeadline(context.Background(), time.Now().Add(-1*time.Second))
	defer cancel()

	stats, err := walk(ctx, api, Options{
		Filter:    FilterRWX,
		ChunkSize: 4,
	}, func(_ Chunk) error { return nil })
	require.NoError(t, err)
	require.True(t, stats.Degraded)
	require.Contains(t, stats.DegradedReasons, DegradedTimeout)
}

func TestWalkContinuesAfterPartialCopy(t *testing.T) {
	api := &partialCopyReadProcess{}

	var visitedBytes int
	stats, err := walk(context.Background(), api, Options{
		Filter:    FilterRWX,
		ChunkSize: 10,
	}, func(chunk Chunk) error {
		visitedBytes += len(chunk.Data)
		return nil
	})
	require.NoError(t, err)
	require.Equal(t, 25, visitedBytes)
	require.Equal(t, uint64(25), stats.BytesRead)
	require.Equal(t, 3, stats.ReadAttempts)
	require.Equal(t, 1, stats.ReadErrors)
	require.Equal(t, 1, stats.ReadErrorsByKind[ReadErrorPartialCopy])
}

func TestWalkFiltersRegionsByReadableCommittedAndBackendFilter(t *testing.T) {
	const pageExecuteRead = uint32(0x20)

	regions := []Region{
		{Base: 0, Size: 10, State: memCommit, Protect: pageNoAccess},
		{Base: 10, Size: 10, State: memCommit, Protect: pageExecuteReadWrite | pageGuard},
		{Base: 20, Size: 10, State: 0, Protect: pageExecuteReadWrite},
		{Base: 30, Size: 10, State: memCommit, Protect: pageExecuteRead},
		{Base: 40, Size: 10, State: memCommit, Protect: pageExecuteReadWrite},
	}

	apiCommitted := &fakeProcess{regions: regions}
	visitedCommitted := 0
	stats, err := walk(context.Background(), apiCommitted, Options{
		Filter:    FilterCommitted,
		ChunkSize: 4,
	}, func(_ Chunk) error {
		visitedCommitted++
		return nil
	})
	require.NoError(t, err)
	require.Equal(t, 5, stats.RegionsEnumerated)
	require.Equal(t, 2, stats.RegionsMatched)
	require.Equal(t, 2, stats.RegionsRead)
	require.Equal(t, uint64(20), stats.BytesRead)
	require.Equal(t, 6, visitedCommitted)
	require.False(t, stats.Degraded)

	apiRWX := &fakeProcess{regions: regions}
	visitedRWX := 0
	stats, err = walk(context.Background(), apiRWX, Options{
		Filter:    FilterRWX,
		ChunkSize: 4,
	}, func(_ Chunk) error {
		visitedRWX++
		return nil
	})
	require.NoError(t, err)
	require.Equal(t, 5, stats.RegionsEnumerated)
	require.Equal(t, 1, stats.RegionsMatched)
	require.Equal(t, 1, stats.RegionsRead)
	require.Equal(t, uint64(10), stats.BytesRead)
	require.Equal(t, 3, visitedRWX)
	require.False(t, stats.Degraded)
}

func TestWalkSkipsUnknownFilter(t *testing.T) {
	api := &fakeProcess{
		regions: []Region{
			{Base: 0, Size: 10, State: memCommit, Protect: pageExecuteReadWrite},
		},
	}

	stats, err := walk(context.Background(), api, Options{
		Filter:    RegionFilter("bogus"),
		ChunkSize: 4,
	}, func(_ Chunk) error { return nil })
	require.NoError(t, err)
	require.Equal(t, 1, stats.RegionsEnumerated)
	require.Equal(t, 0, stats.RegionsMatched)
	require.Equal(t, 0, stats.RegionsRead)
	require.Equal(t, uint64(0), stats.BytesRead)
	require.False(t, stats.Degraded)
	require.Equal(t, 0, stats.ReadAttempts)
	require.Equal(t, 0, stats.ReadErrors)
}

func TestWalkReadErrorStopsRegionButContinues(t *testing.T) {
	api := &readErrorProcess{
		regions: []Region{
			{Base: 0, Size: 4, State: memCommit, Protect: pageExecuteReadWrite},
			{Base: 4, Size: 4, State: memCommit, Protect: pageExecuteReadWrite},
		},
		failBase: 0,
		failErr:  syscall.Errno(5),
	}

	visited := 0
	stats, err := walk(context.Background(), api, Options{
		Filter:    FilterRWX,
		ChunkSize: 4,
	}, func(_ Chunk) error {
		visited++
		return nil
	})
	require.NoError(t, err)
	require.Equal(t, 2, stats.RegionsEnumerated)
	require.Equal(t, 2, stats.RegionsMatched)
	require.Equal(t, 1, stats.RegionsRead)
	require.Equal(t, uint64(4), stats.BytesRead)
	require.Equal(t, 1, stats.ReadErrors)
	require.Equal(t, 1, stats.ReadErrorsByKind[ReadErrorAccessDenied])
	require.Equal(t, 2, stats.ReadAttempts)
	require.Equal(t, 1, visited)
}

func TestWalkZeroReadCountsAsError(t *testing.T) {
	api := &zeroReadProcess{
		region: Region{Base: 0, Size: 10, State: memCommit, Protect: pageExecuteReadWrite},
	}

	stats, err := walk(context.Background(), api, Options{
		Filter:    FilterRWX,
		ChunkSize: 4,
	}, func(_ Chunk) error { return nil })
	require.NoError(t, err)
	require.Equal(t, 1, stats.RegionsEnumerated)
	require.Equal(t, 1, stats.RegionsMatched)
	require.Equal(t, 0, stats.RegionsRead)
	require.Equal(t, uint64(0), stats.BytesRead)
	require.Equal(t, 1, stats.ReadAttempts)
	require.Equal(t, 1, stats.ReadErrors)
	require.Equal(t, 1, stats.ReadErrorsByKind[ReadErrorZeroRead])
}

func TestWalkMarksDegradedWhenContextCanceled(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	api := &fakeProcess{
		regions: []Region{
			{Base: 0, Size: 10, State: memCommit, Protect: pageExecuteReadWrite},
		},
	}

	stats, err := walk(ctx, api, Options{
		Filter:    FilterRWX,
		ChunkSize: 4,
	}, func(_ Chunk) error { return nil })
	require.NoError(t, err)
	require.True(t, stats.Degraded)
	require.Contains(t, stats.DegradedReasons, DegradedCanceled)
}

func TestWalkTimeoutOptionMarksDegraded(t *testing.T) {
	api := &slowReadProcess{
		region: Region{Base: 0, Size: 8, State: memCommit, Protect: pageExecuteReadWrite},
		sleep:  20 * time.Millisecond,
	}

	stats, err := walk(context.Background(), api, Options{
		Filter:    FilterRWX,
		ChunkSize: 4,
		Timeout:   5 * time.Millisecond,
	}, func(_ Chunk) error { return nil })
	require.NoError(t, err)
	require.True(t, stats.Degraded)
	require.Contains(t, stats.DegradedReasons, DegradedTimeout)
	require.Greater(t, stats.BytesRead, uint64(0))
}

type queryErrorProcess struct {
	err error
}

func (p queryErrorProcess) Query(_ uintptr) (Region, bool, error) {
	return Region{}, false, p.err
}

func (p queryErrorProcess) Read(_ uintptr, _ []byte) (int, error) {
	return 0, nil
}

type queryErrorAfterProcess struct {
	err  error
	step int
}

func (p *queryErrorAfterProcess) Query(_ uintptr) (Region, bool, error) {
	if p.step == 0 {
		p.step++
		return Region{Base: 0, Size: 4, State: memCommit, Protect: pageExecuteReadWrite}, true, nil
	}
	return Region{}, false, p.err
}

func (p *queryErrorAfterProcess) Read(_ uintptr, buf []byte) (int, error) {
	for i := range buf {
		buf[i] = 'A'
	}
	return len(buf), nil
}

func TestWalkReturnsVisitError(t *testing.T) {
	api := &fakeProcess{
		regions: []Region{
			{Base: 0, Size: 8, State: memCommit, Protect: pageExecuteReadWrite},
		},
	}
	visitErr := errors.New("visit failed")

	stats, err := walk(context.Background(), api, Options{
		Filter:    FilterRWX,
		ChunkSize: 4,
	}, func(_ Chunk) error {
		return visitErr
	})
	require.ErrorIs(t, err, visitErr)
	require.Equal(t, 1, stats.RegionsEnumerated)
	require.Equal(t, 1, stats.RegionsMatched)
	require.Equal(t, 0, stats.RegionsRead)
	require.Equal(t, uint64(4), stats.BytesRead)
	require.Equal(t, 1, stats.ReadAttempts)
	require.False(t, stats.Degraded)
}

func TestWalkPropagatesQueryError(t *testing.T) {
	queryErr := errors.New("query failed")
	api := queryErrorProcess{err: queryErr}

	stats, err := walk(context.Background(), api, Options{
		Filter:    FilterRWX,
		ChunkSize: 4,
	}, func(_ Chunk) error { return nil })
	require.ErrorIs(t, err, queryErr)
	require.Equal(t, 0, stats.RegionsEnumerated)
	require.Equal(t, 0, stats.RegionsMatched)
	require.Equal(t, 0, stats.ReadAttempts)
	require.False(t, stats.Degraded)
}

func TestWalkPropagatesQueryErrorAfterSomeProgress(t *testing.T) {
	queryErr := errors.New("query failed")
	api := &queryErrorAfterProcess{err: queryErr}

	visited := 0
	stats, err := walk(context.Background(), api, Options{
		Filter:    FilterRWX,
		ChunkSize: 4,
	}, func(_ Chunk) error {
		visited++
		return nil
	})
	require.ErrorIs(t, err, queryErr)
	require.Equal(t, 1, stats.RegionsEnumerated)
	require.Equal(t, 1, stats.RegionsMatched)
	require.Equal(t, 1, stats.RegionsRead)
	require.Equal(t, uint64(4), stats.BytesRead)
	require.Equal(t, 1, visited)
	require.False(t, stats.Degraded)
}

func TestWalkStopsSafelyWhenQueryReturnsZeroSize(t *testing.T) {
	api := &fakeProcess{
		regions: []Region{
			{Base: 0, Size: 0, State: memCommit, Protect: pageExecuteReadWrite},
		},
	}

	stats, err := walk(context.Background(), api, Options{
		Filter:    FilterRWX,
		ChunkSize: 4,
	}, func(_ Chunk) error { return nil })
	require.NoError(t, err)
	require.Equal(t, 1, stats.RegionsEnumerated)
	require.Equal(t, 0, stats.RegionsMatched)
	require.Equal(t, 0, stats.RegionsRead)
	require.Equal(t, uint64(0), stats.BytesRead)
	require.Equal(t, 0, stats.ReadAttempts)
	require.Equal(t, 0, stats.ReadErrors)
	require.False(t, stats.Degraded)
}

func TestWalkStopsSafelyWhenQueryDoesNotAdvanceAddress(t *testing.T) {
	api := &fakeProcess{
		regions: []Region{
			{Base: 0, Size: 4, State: memCommit, Protect: pageExecuteReadWrite},
			{Base: 0, Size: 4, State: memCommit, Protect: pageExecuteReadWrite},
		},
	}

	visited := 0
	stats, err := walk(context.Background(), api, Options{
		Filter:    FilterRWX,
		ChunkSize: 4,
	}, func(_ Chunk) error {
		visited++
		return nil
	})
	require.NoError(t, err)
	require.Equal(t, 2, stats.RegionsEnumerated)
	require.Equal(t, 1, stats.RegionsMatched)
	require.Equal(t, 1, stats.RegionsRead)
	require.Equal(t, uint64(4), stats.BytesRead)
	require.Equal(t, 1, visited)
	require.False(t, stats.Degraded)
}
