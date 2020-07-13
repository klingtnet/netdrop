.PHONY: clean test

VERSION:=$(shell git describe --always --tags)

netdrop: test *.go
	go build -o $@ -ldflags "-X main.Version=$(VERSION)" .

install: netdrop
	install -Dm 0755 netdrop ~/.local/bin/netdrop

test:
	go test .

clean:
	rm -f netdrop
