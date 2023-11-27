package filedetection

import (
	"io"
	"sync"

	"github.com/targodan/go-errors"
)

type Iterator interface {
	Next() (File, error)
	Close() error
}

type concatIterator struct {
	i         int
	iterators []Iterator
}

func concat(it1 Iterator, it2 Iterator) Iterator {
	if it1 == nil {
		return it2
	}
	if it2 == nil {
		return it1
	}
	cit1, ok1 := it1.(*concatIterator)
	cit2, ok2 := it2.(*concatIterator)
	if ok1 && ok2 {
		cit1.iterators = append(cit1.iterators, cit2.iterators...)
		return cit1
	}
	if ok1 {
		cit1.iterators = append(cit1.iterators, it2)
		return cit1
	}
	if ok2 {
		cit2.iterators = append(cit2.iterators, it1)
		return cit2
	}
	return &concatIterator{
		i:         0,
		iterators: []Iterator{it1, it2},
	}
}

func Concat(iterators ...Iterator) Iterator {
	var ret Iterator
	for _, it := range iterators {
		ret = concat(ret, it)
	}
	return ret
}

func (it *concatIterator) Next() (File, error) {
	if it.i >= len(it.iterators) {
		return nil, io.EOF
	}

	f, err := it.iterators[it.i].Next()
	if err == io.EOF {
		it.i++
		return it.Next()
	}
	return f, err
}

func (it *concatIterator) Close() error {
	var err error
	for _, iterator := range it.iterators {
		err = errors.NewMultiError(err, iterator.Close())
	}
	return err
}

type concurrentIterator struct {
	iterators []Iterator
	c         chan *nextEntry
	wg        *sync.WaitGroup
	closed    bool
}

func concurrent(it1 Iterator, it2 Iterator) Iterator {
	if it1 == nil {
		return it2
	}
	if it2 == nil {
		return it1
	}
	cit1, ok1 := it1.(*concurrentIterator)
	cit2, ok2 := it2.(*concurrentIterator)
	if ok1 && ok2 {
		panic("cannot combine two concurrent iterators")
	}
	if ok1 {
		cit1.iterators = append(cit1.iterators, it2)
		cit1.wg.Add(1)
		go cit1.consume(len(cit1.iterators) - 1)
		return cit1
	}
	if ok2 {
		cit2.iterators = append(cit2.iterators, it1)
		cit2.wg.Add(1)
		go cit2.consume(len(cit2.iterators) - 1)
		return cit2
	}

	cit := &concurrentIterator{
		iterators: []Iterator{it1, it2},
		c:         make(chan *nextEntry),
		wg:        new(sync.WaitGroup),
	}
	cit.wg.Add(2)
	go cit.consume(0)
	go cit.consume(1)

	go func() {
		cit.wg.Wait()
		close(cit.c)
	}()
	return cit
}

func Concurrent(iterators ...Iterator) Iterator {
	var cit Iterator
	for _, it := range iterators {
		cit = concurrent(cit, it)
	}
	return cit
}

func (it *concurrentIterator) consume(i int) {
	defer it.wg.Done()

	for {
		f, err := it.iterators[i].Next()
		if err == io.EOF {
			break
		}

		it.c <- &nextEntry{
			File: f,
			Err:  err,
		}
	}
}

func (it *concurrentIterator) Next() (File, error) {
	if it.closed {
		return nil, io.EOF
	}

	next := <-it.c
	if next == nil {
		return nil, io.EOF
	}

	return next.File, next.Err
}

func (it *concurrentIterator) Close() error {
	if it.closed {
		return nil
	}
	it.closed = true

	var err error
	for _, iterator := range it.iterators {
		err = errors.NewMultiError(err, iterator.Close())
	}
	return err
}
