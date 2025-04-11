# go-embed-extractor

go-embed-extractor is a lightweight Go tool for extracting files embedded in Go binaries using the `embed` package.
It provides a simple way for developers and reverse engineers to analyze and recover embedded static resources, such as HTML, CSS, images, or other files.

## Features
- Extract embedded files from Go binaries.  
- Supports multiple architecture files (MachO, ELF, PE).  
- Option to save extracted files to a specified directory.

## Basic Usage

1. Use some decompilation tools to obtain the `embed.FS` structure virtual address.

![](https://github.com/user-attachments/assets/ff9f39df-aba8-477e-a135-73dbc932261f)

2. Extract embedded files from a Go binary:
```bash
gee -target -target ./tests/embedemo_macho -vaddr 0x00000001000EAA00
```

## References

- [Extracting Go Embeds](https://web.archive.org/web/20230606135339/https://0x00sec.org/t/extracting-go-embeds/34885)
