package extractor

import (
	"debug/elf"
	"debug/macho"
	"debug/pe"
	"fmt"
)

type FileParser interface {
	ConvRelativeOffset(vaddr uint64) (uint64, error)
	Close() error
}

func NewParser(fpath string) (FileParser, error) {
	ftype, err := GetFileType(fpath)
	if err != nil {
		return nil, err
	}

	switch ftype {
	case FiletypeMachO:
		return NewMachOParser(fpath)
	case FiletypeELF:
		return NewELFParser(fpath)
	case FiletypePE:
		return NewPEParser(fpath)
	}

	return nil, fmt.Errorf("unsupported file format")
}

type MachOParser struct {
	f *macho.File
}

func NewMachOParser(fpath string) (*MachOParser, error) {
	f, err := macho.Open(fpath)
	if err != nil {
		return nil, err
	}

	return &MachOParser{f: f}, nil
}

func (m *MachOParser) ConvRelativeOffset(vaddr uint64) (uint64, error) {
	rodata := m.f.Section("__rodata")
	if vaddr < rodata.Addr || vaddr > rodata.Addr+rodata.Size {
		return m.findSection(vaddr)
	}

	return uint64(rodata.Offset) + vaddr - rodata.Addr, nil
}

func (m *MachOParser) findSection(vaddr uint64) (uint64, error) {
	for _, sec := range m.f.Sections {
		if vaddr >= sec.Addr && vaddr < sec.Addr+sec.Size {
			return uint64(sec.Offset) + vaddr - sec.Addr, nil
		}
	}

	return 0, fmt.Errorf("vaddr %x not found in any section", vaddr)
}

func (m *MachOParser) Close() error {
	if m.f != nil {
		return m.f.Close()
	}
	return nil
}

type ELFParser struct {
	f *elf.File
}

func NewELFParser(fpath string) (*ELFParser, error) {
	f, err := elf.Open(fpath)
	if err != nil {
		return nil, err
	}

	return &ELFParser{f: f}, nil
}

func (e *ELFParser) ConvRelativeOffset(vaddr uint64) (uint64, error) {
	rodata := e.f.Section(".rodata")
	if rodata != nil && vaddr >= rodata.Addr && vaddr <= rodata.Addr+rodata.Size {
		return rodata.Offset + (vaddr - rodata.Addr), nil
	}

	return e.findSection(vaddr)
}

func (e *ELFParser) findSection(vaddr uint64) (uint64, error) {
	for _, sec := range e.f.Sections {
		if sec.Type != elf.SHT_NULL &&
			vaddr >= sec.Addr &&
			vaddr < sec.Addr+sec.Size {
			return sec.Offset + (vaddr - sec.Addr), nil
		}
	}
	return 0, fmt.Errorf("vaddr %x not found in any section", vaddr)
}

func (e *ELFParser) Close() error {
	if e.f != nil {
		return e.f.Close()
	}
	return nil
}

type PEParser struct {
	f         *pe.File
	imageBase uint64
}

func NewPEParser(fpath string) (*PEParser, error) {
	f, err := pe.Open(fpath)
	if err != nil {
		return nil, err
	}

	var imageBase uint64
	switch hdr := f.OptionalHeader.(type) {
	case *pe.OptionalHeader32:
		imageBase = uint64(hdr.ImageBase)
	case *pe.OptionalHeader64:
		imageBase = uint64(hdr.ImageBase)
	}

	return &PEParser{f: f, imageBase: imageBase}, nil
}

func (p *PEParser) ConvRelativeOffset(vaddr uint64) (uint64, error) {
	rva := vaddr - p.imageBase

	rdata := p.f.Section(".rdata")
	if rdata != nil && rva >= uint64(rdata.VirtualAddress) && vaddr <= uint64(rdata.VirtualAddress+rdata.Size) {
		return uint64(rdata.Offset) + (rva - uint64(rdata.VirtualAddress)), nil
	}

	return p.findSection(rva)
}

func (p *PEParser) findSection(rva uint64) (uint64, error) {
	for _, sec := range p.f.Sections {
		if rva >= uint64(sec.VirtualAddress) &&
			rva < uint64(sec.VirtualAddress+sec.Size) {
			return uint64(sec.Offset) + (rva - uint64(sec.VirtualAddress)), nil
		}
	}
	return 0, fmt.Errorf("vaddr %x not found in any section", rva)
}

func (p *PEParser) Close() error {
	if p.f != nil {
		return p.f.Close()
	}
	return nil
}
