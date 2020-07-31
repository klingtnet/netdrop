.PHONY: clean test

VERSION:=$(shell git describe --always --tags)
GO_FILES:=$(wildcard *.go)

cross: $(GO_FILES) netdrop
	GOOS=windows go build -ldflags "-X main.Version=$(VERSION)" .
	GOOS=darwin go build -o netdrop.mac -ldflags "-X main.Version=$(VERSION)" .
	GOOS=linux GOARCH=arm go build -o netdrop.pi -ldflags "-X main.Version=$(VERSION)" .

netdrop: test $(GO_FILES)
	go build -o $@ -ldflags "-X main.Version=$(VERSION)" .

install: netdrop
	install -Dm 0755 netdrop ~/.local/bin/netdrop

test:
	go test .

clean:
	rm -f netdrop
