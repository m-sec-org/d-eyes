//go:build !windows

package memscan

import "context"

type Process struct{}

func Open(_ int) (*Process, error) {
	return nil, ErrUnsupportedPlatform
}

func (p *Process) Close() error {
	return nil
}

func (p *Process) Walk(_ context.Context, _ Options, _ func(Chunk) error) (Stats, error) {
	return Stats{}, ErrUnsupportedPlatform
}
