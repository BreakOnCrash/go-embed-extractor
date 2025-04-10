package extractor

import (
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
)

type EmbedFile struct {
	Name string `json:"name,omitempty"`
	Data []byte `json:"data,omitempty"`
	Hash []byte `json:"hash,omitempty"`
}

func Extract(fpath string, vaddr uint64) (ret []EmbedFile, err error) {
	parser, err := NewParser(fpath)
	if err != nil {
		return nil, err
	}
	defer parser.Close()

	fr, err := NewFileReader(fpath)
	if err != nil {
		return nil, err
	}
	defer fr.Close()

	// parse embed header
	embedHeaderOff, err := parser.ConvRelativeOffset(vaddr)
	if err != nil {
		return nil, err
	}
	header, err := fr.ReadUint64(3, embedHeaderOff)
	if err != nil {
		return nil, err
	}
	if header[1] != header[2] { // length and capacity
		return nil, errors.New("invalid embed header")
	}

	filesOff, err := parser.ConvRelativeOffset(header[0])
	if err != nil {
		return nil, err
	}

	// parse embed files
	for i := header[1]; i > 0; i-- {
		// parse file name
		name, err := fr.ReadUint64(2, filesOff)
		if err != nil {
			return nil, err
		}
		offset, err := parser.ConvRelativeOffset(name[0])
		if err != nil {
			return nil, err
		}
		fname, err := fr.ReadBytes(int(name[1]), offset)
		if err != nil {
			return nil, err
		}

		// parse file content
		filesOff += 16
		var fcontent []byte
		content, err := fr.ReadUint64(2, filesOff)
		if err != nil {
			return nil, err
		}
		if content[0] != 0 {
			offset, err = parser.ConvRelativeOffset(content[0])
			if err != nil {
				return nil, err
			}
			fcontent, err = fr.ReadBytes(int(content[1]), offset)
			if err != nil {
				return nil, err
			}
		}

		// parse file hash
		filesOff += 16
		hash, err := fr.ReadBytes(16, filesOff)
		if err != nil {
			return nil, err
		}

		// create embed file
		ret = append(ret, EmbedFile{Name: string(fname), Data: fcontent, Hash: hash})
		filesOff += 16
	}

	return ret, nil
}

type FileReader struct {
	f *os.File
}

func NewFileReader(fpath string) (*FileReader, error) {
	file, err := os.Open(fpath)
	if err != nil {
		return nil, err
	}

	return &FileReader{f: file}, nil
}

func (fr *FileReader) Close() error {
	if fr.f != nil {
		return fr.f.Close()
	}

	return nil
}

var bufpool = sync.Pool{
	New: func() interface{} {
		buf := make([]byte, 8)
		return &buf
	},
}

func (fr *FileReader) ReadUint64(size int, off uint64) ([]uint64, error) {
	if fr.f == nil {
		return nil, os.ErrClosed
	}

	ret := make([]uint64, 0)
	for i := 0; i < size; i++ {
		bufptr := bufpool.Get().(*[]byte)
		buf := *bufptr
		defer bufpool.Put(bufptr)

		n, err := fr.f.ReadAt(buf, int64(off))
		if err != nil {
			return nil, err
		}

		if n != 8 {
			return nil, errors.New("read size mismatch")
		}

		off += 8
		ret = append(ret, binary.LittleEndian.Uint64(buf))
	}

	if len(ret) != size {
		return nil, errors.New("read size mismatch")
	}

	return ret, nil
}

func (fr *FileReader) ReadBytes(size int, off uint64) ([]byte, error) {
	if fr.f == nil {
		return nil, os.ErrClosed
	}

	ret := make([]byte, size)
	n, err := fr.f.ReadAt(ret, int64(off))
	if err != nil {
		return nil, err
	}

	if n != size {
		return nil, errors.New("read size mismatch")
	}

	return ret, nil
}

func Save(files []EmbedFile, output string) error {
	if err := os.MkdirAll(output, 0755); err != nil {
		return err
	}

	for _, ef := range files {
		fullPath := filepath.Join(output, ef.Name)

		if strings.HasSuffix(ef.Name, "/") {
			if err := os.MkdirAll(fullPath, 0755); err != nil {
				return err
			}
		}

		parentDir := filepath.Dir(fullPath)
		if err := os.MkdirAll(parentDir, 0755); err != nil {
			return err
		}

		if ef.Data != nil {
			if err := os.WriteFile(fullPath, ef.Data, 0644); err != nil {
				return fmt.Errorf("failed to write file %s: %v", fullPath, err)
			}
		}
	}

	return nil
}
