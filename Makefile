build:
	go build -v -o bin/migration *.go

run: build
	bin/migration
