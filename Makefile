BINARY := bin/twig-cloud

.PHONY: build run test lint clean

build:
	go build -o $(BINARY) ./cmd/server

run:
	go run ./cmd/server

test:
	go test ./...

lint:
	@files=$$(gofmt -l .); if [ -n "$$files" ]; then echo "gofmt needed on:"; echo "$$files"; exit 1; fi
	go vet ./...

clean:
	rm -rf bin
