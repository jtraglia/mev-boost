VERSION ?= $(shell git describe --tags --always --dirty="-dev")
DOCKER_REPO := flashbots/mev-boost

# Remove all file system paths from the executable.
GO_BUILD_FLAGS += -trimpath
# Make the build more verbose.
GO_BUILD_FLAGS += -v

# Set linker flags to:
#   -w: disables DWARF debugging information.
GO_BUILD_LDFLAGS += -w
#   -s: disables symbol table information.
GO_BUILD_LDFLAGS += -s
#   -X: sets the value of the symbol.
GO_BUILD_LDFLAGS += -X 'github.com/flashbots/mev-boost/config.Version=$(VERSION)'

.PHONY: all
all: build

.PHONY: v
v:
	@echo "${VERSION}"

.PHONY: build
build:
	CGO_ENABLED=0 go build $(GO_BUILD_FLAGS) -ldflags "$(GO_BUILD_LDFLAGS)" -o mev-boost .

.PHONY: build-testcli
build-testcli:
	go build $(GO_BUILD_FLAGS) -ldflags "$(GO_BUILD_LDFLAGS)" -o test-cli ./cmd/test-cli

.PHONY: test
test:
	go test ./...

.PHONY: test-race
test-race:
	go test -race ./...

.PHONY: lint
lint:
	gofmt -d -s .
	gofumpt -d -extra .
	staticcheck ./...
	golangci-lint run

.PHONY: test-coverage
test-coverage:
	go test -race -v -covermode=atomic -coverprofile=coverage.out ./...
	go tool cover -func coverage.out

.PHONY: cover
cover:
	go test -coverprofile=coverage.out ./...
	go tool cover -func coverage.out
	unlink coverage.out

.PHONY: cover-html
cover-html:
	go test -coverprofile=coverage.out ./...
	go tool cover -html=coverage.out
	unlink coverage.out

.PHONY: run-mergemock-integration
run-mergemock-integration: build
	./scripts/run_mergemock_integration.sh

.PHONY: docker-image
docker-image:
	DOCKER_BUILDKIT=1 docker build --platform linux/amd64 --build-arg VERSION=${VERSION} . -t mev-boost
	docker tag mev-boost:latest ${DOCKER_REPO}:${VERSION}
	docker tag mev-boost:latest ${DOCKER_REPO}:latest

.PHONY: clean
clean:
	git clean -fdx
