.PHONY: all install fmt test test-install

all:
	env GO111MODULE=on go build -v ./...

install:
	env GO111MODULE=on go install -v ./...

fmt:
	pandoc -o tmp.md -s README.md
	mv tmp.md README.md

test:
	gocheck -c

test-install:
	go get github.com/frankbraun/gocheck
	go get golang.org/x/tools/cmd/goimports
	go get golang.org/x/lint/golint
