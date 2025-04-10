package extractor

import "testing"

func TestGetFileType(t *testing.T) {
	tests := []struct {
		name     string
		filePath string
		expected Filetype
	}{
		{"ELF", "testdata/embedemo_elf", FiletypeELF},
		{"PE", "testdata/embedemo_pe", FiletypePE},
		{"Mach-O", "testdata/embedemo_macho", FiletypeMachO},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fileType, err := GetFileType(test.filePath)
			if err != nil {
				t.Fatalf("expected no error, got %v", err)
			}
			if fileType != test.expected {
				t.Fatalf("expected %v, got %v", test.expected, fileType)
			}
		})
	}
}
