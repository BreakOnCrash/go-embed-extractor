package extractor

import (
	"fmt"
	"os"
)

type Filetype string

const (
	FiletypeELF   Filetype = "ELF"
	FiletypePE    Filetype = "PE"
	FiletypeMachO Filetype = "Mach-O"
)

func GetFileType(filePath string) (Filetype, error) {
	// Check the file type using the magic number
	file, err := os.Open(filePath)
	if err != nil {
		return "", err
	}
	defer file.Close()

	// Read the first few bytes to determine the file type
	header := make([]byte, 4)
	if _, err := file.Read(header); err != nil {
		return "", err
	}

	switch {
	case header[0] == 0x7F && header[1] == 'E' && header[2] == 'L' && header[3] == 'F':
		return FiletypeELF, nil
	case header[0] == 'M' && header[1] == 'Z':
		return FiletypePE, nil
	case header[0] == 0xCF && header[1] == 0xFA && header[2] == 0xED:
		return FiletypeMachO, nil
	}

	return "", fmt.Errorf("unknown file type")
}
