BINARY   := chatmail
GOFLAGS  := -trimpath -buildvcs=false
VERSION  := $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
LDFLAGS  := -s -w -X main.version=$(VERSION)

.PHONY: build test race fuzz bench install clean

build:

	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 GOAMD64=v3 go build $(GOFLAGS) -ldflags "$(LDFLAGS)" -o $(BINARY) ./cmd/chatmail && upx --lzma --best $(BINARY)

test:
	go test ./...

race:
	go test -race ./...

fuzz:
	go test -fuzz=FuzzDeserialize -fuzztime=30s ./internal/database/ || true

bench:
	go test -bench=. -benchmem ./internal/database/

install: build
	useradd --system --no-create-home $(BINARY)
	install -Dm755 $(BINARY) /usr/local/bin/$(BINARY)

clean:
	rm -f $(BINARY)
