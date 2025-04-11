build:
	@CGO_ENABLED=0 go build -ldflags "-s -w" -trimpath -o bin/gee main.go

test:
	@cd tests/
	@CGO_ENABLED=0 GOOS=darwin go build -ldflags "-s -w" -trimpath -o tests/embedemo_macho tests/embedemo.go
	@CGO_ENABLED=0 GOOS=linux go build -ldflags "-s -w" -trimpath -o tests/embedemo_elf tests/embedemo.go
	@CGO_ENABLED=0 GOOS=windows go build -ldflags "-s -w" -trimpath -o tests/embedemo_pe tests/embedemo.go

	@echo "unit test"
	@go run main.go -target ./tests/embedemo_elf -vaddr 0x00000000000F8F60 -output out/elf
	@go run main.go -target ./tests/embedemo_macho -vaddr 0x00000001000EAA00 -output out/macho
	@go run main.go -target ./tests/embedemo_pe -vaddr 0x00000001000F3B00 -output out/pe