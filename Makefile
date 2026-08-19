BINARY_NAME=dorkforge
ALIAS_NAME=dfg
BUILD_DIR=bin
GO=/usr/local/go/bin/go

.PHONY: all build test clean install

all: test build

build:
	@mkdir -p $(BUILD_DIR)
	$(GO) build -ldflags="-s -w" -o $(BUILD_DIR)/$(BINARY_NAME) ./cmd/dorkforge
	@rm -f $(BUILD_DIR)/df
	@ln -sf $(BINARY_NAME) $(BUILD_DIR)/$(ALIAS_NAME)
	@echo "Build complete: $(BUILD_DIR)/$(BINARY_NAME) (and symlink $(BUILD_DIR)/$(ALIAS_NAME))"

test:
	$(GO) test -v -race ./...

clean:
	rm -rf $(BUILD_DIR)

install: build
	cp $(BUILD_DIR)/$(BINARY_NAME) $(HOME)/go/bin/$(BINARY_NAME) || sudo cp $(BUILD_DIR)/$(BINARY_NAME) /usr/local/bin/$(BINARY_NAME)
	cp $(BUILD_DIR)/$(BINARY_NAME) $(HOME)/go/bin/$(ALIAS_NAME) || sudo cp $(BUILD_DIR)/$(BINARY_NAME) /usr/local/bin/$(ALIAS_NAME)
	@echo "Installed dorkforge and dfg alias to PATH"
