BINARY_NAME=dorkforge
BUILD_DIR=bin
GO=/usr/local/go/bin/go

.PHONY: all build test clean install

all: test build

build:
	@mkdir -p $(BUILD_DIR)
	$(GO) build -ldflags="-s -w" -o $(BUILD_DIR)/$(BINARY_NAME) ./cmd/dorkforge
	@ln -sf $(BINARY_NAME) $(BUILD_DIR)/df
	@echo "Build complete: $(BUILD_DIR)/$(BINARY_NAME) (and symlink $(BUILD_DIR)/df)"

test:
	$(GO) test -v -race ./...

clean:
	rm -rf $(BUILD_DIR)

install: build
	cp $(BUILD_DIR)/$(BINARY_NAME) $(HOME)/go/bin/$(BINARY_NAME) || sudo cp $(BUILD_DIR)/$(BINARY_NAME) /usr/local/bin/$(BINARY_NAME)
	@echo "Installed dorkforge to PATH"
