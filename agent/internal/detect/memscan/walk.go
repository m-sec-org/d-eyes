package memscan

import (
	"context"
	"errors"
)

type processAPI interface {
	Query(addr uintptr) (Region, bool, error)
	Read(addr uintptr, buf []byte) (int, error)
}

func walk(ctx context.Context, api processAPI, opts Options, visit func(Chunk) error) (Stats, error) {
	if api == nil {
		return Stats{}, errors.New("memscan: process api is nil")
	}
	if visit == nil {
		return Stats{}, errors.New("memscan: visit callback is nil")
	}

	opts = opts.normalize()
	if opts.Timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, opts.Timeout)
		defer cancel()
	}

	stats := Stats{}

	stop := func(reason string) Stats {
		if err := ctx.Err(); err != nil {
			switch err {
			case context.Canceled:
				stats.addDegradedReason(DegradedCanceled)
			case context.DeadlineExceeded:
				stats.addDegradedReason(DegradedTimeout)
			default:
				stats.addDegradedReason(reason)
			}
			return stats
		}
		stats.addDegradedReason(reason)
		return stats
	}

	addr := uintptr(0)
	for {
		if ctx.Err() != nil {
			stats = stop(DegradedTimeout)
			break
		}

		region, ok, err := api.Query(addr)
		if err != nil {
			return stats, err
		}
		if !ok {
			break
		}
		stats.RegionsEnumerated++

		if region.Size == 0 {
			break
		}
		next := region.End()
		if next <= addr {
			break
		}
		addr = next

		if !isReadableCommitted(region) {
			continue
		}
		switch opts.Filter {
		case FilterCommitted:
			// No additional filter.
		case FilterRWX:
			if !isRWXProtect(region.Protect) {
				continue
			}
		default:
			continue
		}

		if opts.MaxRegions > 0 && stats.RegionsMatched >= opts.MaxRegions {
			stats = stop(DegradedMaxRegions)
			break
		}
		stats.RegionsMatched++

		readSome := false
		stopScan := false
		stopReason := ""
		for offset := uintptr(0); offset < region.Size; {
			if ctx.Err() != nil {
				stopScan = true
				stopReason = DegradedTimeout
				break
			}
			if opts.MaxBytes > 0 && stats.BytesRead >= opts.MaxBytes {
				stopScan = true
				stopReason = DegradedMaxBytes
				break
			}

			remainingInRegion := uint64(region.Size - offset)
			budget := uint64(opts.ChunkSize)
			if remainingInRegion < budget {
				budget = remainingInRegion
			}
			if opts.MaxBytes > 0 {
				remainingBudget := opts.MaxBytes - stats.BytesRead
				if remainingBudget == 0 {
					stopScan = true
					stopReason = DegradedMaxBytes
					break
				}
				if remainingBudget < budget {
					budget = remainingBudget
				}
			}

			buf := make([]byte, int(budget))
			stats.ReadAttempts++
			n, err := api.Read(region.Base+offset, buf)
			if n > 0 {
				readSome = true
				stats.BytesRead += uint64(n)
				if err := visit(Chunk{
					Region:  region,
					Address: region.Base + offset,
					Data:    buf[:n],
				}); err != nil {
					return stats, err
				}
				offset += uintptr(n)
			}

			if err != nil {
				kind := classifyReadError(err)
				stats.addReadError(kind)
				if kind == ReadErrorPartialCopy && n > 0 {
					continue
				}
				break
			}
			if n == 0 {
				stats.addReadError(ReadErrorZeroRead)
				break
			}
			if n < int(budget) {
				break
			}
		}
		if readSome {
			stats.RegionsRead++
		}
		if stopScan {
			stats = stop(stopReason)
			break
		}
	}

	return stats, nil
}
