# Go parameters
GOCMD=go
GOBUILD=$(GOCMD) build
GOCLEAN=$(GOCMD) clean
GOTEST=$(GOCMD) test
GOGET=$(GOCMD) get

# Name of the binary executable
BINARY_NAME=velvetstore

# Directories
SRC_DIR=./
OUT_DIR=./bin

# Default target
all: clean build

# Build the Go application
build:
	@echo "Building $(BINARY_NAME)..."
	@mkdir -p $(OUT_DIR)
	@$(GOBUILD) -o $(OUT_DIR)/$(BINARY_NAME) $(SRC_DIR)

# Clean build artifacts
clean:
	@echo "Cleaning..."
	@$(GOCLEAN)
	@rm -rf $(OUT_DIR)

# Run the Go application
run: build
	@echo "Starting $(BINARY_NAME)..."
	@$(OUT_DIR)/$(BINARY_NAME)

# Install dependencies (if needed)
deps:
	@$(GOGET) github.com/gorilla/mux
	@$(GOGET) github.com/sirupsen/logrus

# Run tests
test:
	@$(GOTEST) -v $(SRC_DIR)

.PHONY: all build clean run deps test
