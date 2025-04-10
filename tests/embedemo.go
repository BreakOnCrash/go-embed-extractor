package main

import (
	"embed"
	"fmt"
	"log"
)

//go:embed misc
var embedFiles embed.FS

func main() {
	content, err := embedFiles.ReadFile("misc/sample.txt")
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(string(content))
}
