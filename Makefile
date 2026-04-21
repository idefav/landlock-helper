.PHONY: build test

build:
	go build -o landlock-helper main.go generate.go exec.go exec_config.go exec_landlock_linux.go exec_landlock_unsupported.go

test:
	go test ./...

install:
	go install .
