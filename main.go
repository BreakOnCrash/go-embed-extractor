package main

import (
	"flag"
	"fmt"
	"log"
	"strconv"
	"strings"

	"github.com/BreakOnCrash/gee/extractor"
)

func main() {
	fpath := flag.String("target", "", "Target file path")
	vaddr := flag.String("vaddr", "", "emebd-files virtual address e.g.(0x0010034)")
	output := flag.String("output", "out", "Save emebd-files path")

	flag.Parse()

	if *fpath == "" || *vaddr == "" {
		flag.Usage()
		return
	}

	addr, err := strconv.ParseUint(strings.TrimLeft(strings.TrimLeft(*vaddr, "0x"), "0X"), 16, 64)
	if err != nil {
		log.Fatal(err)
	}

	files, err := extractor.Extract(*fpath, addr)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("[+] Extract %d files\n", len(files))

	fmt.Printf("Save to %s\n", *output)
	if err := extractor.Save(files, *output); err != nil {
		log.Fatal(err)
	}
}
