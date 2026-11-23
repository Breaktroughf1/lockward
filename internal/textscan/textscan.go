// Package textscan streams a whole file through line-oriented matchers with
// bounded memory. It never truncates: every byte is examined, however large
// the file (THREAT_MODEL T3). Lines longer than the block size are examined
// in overlapping windows so a pattern cannot hide across a boundary.
package textscan

import (
	"bytes"
	"errors"
	"io"
)

// Sizes. A pattern longer than Overlap could in theory be split across two
// windows of a single over-long line; every pattern Lockward uses is shorter.
const (
	BlockSize = 64 << 10
	Overlap   = 1 << 10
)

// Scan reads r and calls line for every line (without the trailing newline)
// of each block for which want returns true. want sees a whole block of
// complete lines at once, so cheap literal prefilters run once per block
// instead of once per line. Line numbers start at 1.
func Scan(r io.Reader, want func(block []byte) bool, line func(n int, b []byte)) error {
	buf := make([]byte, BlockSize)
	var pending []byte // incomplete last line carried into the next block
	lineNo := 1
	for {
		n, err := io.ReadFull(r, buf)
		eof := errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF)
		if err != nil && !eof {
			return err
		}
		data := make([]byte, 0, len(pending)+n)
		data = append(data, pending...)
		data = append(data, buf[:n]...)
		end := bytes.LastIndexByte(data, '\n')
		switch {
		case eof:
			end = len(data) - 1 // flush everything
		case end < 0 && len(data) > BlockSize:
			// One over-long line: examine this window, keep an overlap.
			if want(data) {
				line(lineNo, data)
			}
			pending = append([]byte{}, data[len(data)-Overlap:]...)
			continue
		case end < 0:
			pending = append([]byte{}, data...)
			continue
		}
		complete := data[:end+1]
		if len(complete) > 0 {
			if want(complete) {
				for _, l := range bytes.SplitAfter(complete, []byte{'\n'}) {
					if len(l) == 0 {
						continue
					}
					line(lineNo, bytes.TrimSuffix(l, []byte{'\n'}))
					if bytes.HasSuffix(l, []byte{'\n'}) {
						lineNo++
					}
				}
			} else {
				lineNo += bytes.Count(complete, []byte{'\n'})
			}
		}
		if eof {
			return nil
		}
		pending = append([]byte{}, data[end+1:]...)
	}
}
