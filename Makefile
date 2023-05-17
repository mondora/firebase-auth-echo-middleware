format:
	go fmt $(shell go list ./... | grep -v /vendor/) && \
	go vet $(shell go list ./... | grep -v /vendor/) && \
	golangci-lint run --fast --issues-exit-code 1

test:
	go test -race $(shell go list ./... | grep -v /vendor/)

gofumpt:
	gofumpt -w -extra -lang 1.20 .

tidy:
	go mod tidy -compat=1.20

vuln:
	govulncheck -v ./...
