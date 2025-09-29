# Makefile for Envoy External Authorization Service

# Variables
BINARY_NAME=ext-authz
DOCKER_IMAGE=ext-authz-service
VERSION?=latest
COVERAGE_FILE=coverage.out
COVERAGE_HTML=coverage.html

# Go parameters
GOCMD=go
GOBUILD=$(GOCMD) build
GOCLEAN=$(GOCMD) clean
GOTEST=$(GOCMD) test
GOGET=$(GOCMD) get
GOMOD=$(GOCMD) mod

# Build flags
LDFLAGS=-ldflags "-X main.Version=$(VERSION) -X main.BuildTime=$(shell date -u '+%Y-%m-%d_%H:%M:%S')"

.PHONY: all build clean test coverage lint security run docker help

# Default target
all: clean lint test build

# Build the binary
build:
	@echo "Building $(BINARY_NAME)..."
	$(GOBUILD) $(LDFLAGS) -o $(BINARY_NAME) .

# Clean build artifacts
clean:
	@echo "Cleaning..."
	$(GOCLEAN)
	rm -f $(BINARY_NAME)
	rm -f $(COVERAGE_FILE) $(COVERAGE_HTML)

# Run tests
test:
	@echo "Running tests..."
	$(GOTEST) -v -race ./...

# Run tests with coverage
coverage:
	@echo "Running tests with coverage..."
	$(GOTEST) -v -race -coverprofile=$(COVERAGE_FILE) ./...
	$(GOCMD) tool cover -html=$(COVERAGE_FILE) -o $(COVERAGE_HTML)
	@echo "Coverage report generated: $(COVERAGE_HTML)"

# Run benchmarks
bench:
	@echo "Running benchmarks..."
	$(GOTEST) -bench=. -benchmem ./...

# Lint code
lint:
	@echo "Running linter..."
	golangci-lint run

# Security scan
security:
	@echo "Running security scan..."
	gosec ./...

# Format code
fmt:
	@echo "Formatting code..."
	$(GOCMD) fmt ./...

# Tidy dependencies
tidy:
	@echo "Tidying dependencies..."
	$(GOMOD) tidy

# Download dependencies
deps:
	@echo "Downloading dependencies..."
	$(GOMOD) download

# Run the application
run: build
	@echo "Running $(BINARY_NAME)..."
	./$(BINARY_NAME)

# Build Docker image
docker:
	@echo "Building Docker image..."
	docker build -t $(DOCKER_IMAGE):$(VERSION) .
	docker tag $(DOCKER_IMAGE):$(VERSION) $(DOCKER_IMAGE):latest

# Run Docker container
docker-run: docker
	@echo "Running Docker container..."
	docker run --rm -p 50051:50051 \
		-v $(PWD)/config.yaml:/app/config.yaml \
		$(DOCKER_IMAGE):$(VERSION)

# Build cross-platform binaries
build-all:
	@echo "Building cross-platform binaries..."
	GOOS=linux GOARCH=amd64 $(GOBUILD) $(LDFLAGS) -o $(BINARY_NAME)-linux-amd64 .
	GOOS=linux GOARCH=arm64 $(GOBUILD) $(LDFLAGS) -o $(BINARY_NAME)-linux-arm64 .
	GOOS=darwin GOARCH=amd64 $(GOBUILD) $(LDFLAGS) -o $(BINARY_NAME)-darwin-amd64 .
	GOOS=darwin GOARCH=arm64 $(GOBUILD) $(LDFLAGS) -o $(BINARY_NAME)-darwin-arm64 .
	GOOS=windows GOARCH=amd64 $(GOBUILD) $(LDFLAGS) -o $(BINARY_NAME)-windows-amd64.exe .

# Install development tools
install-tools:
	@echo "Installing development tools..."
	$(GOGET) github.com/golangci/golangci-lint/cmd/golangci-lint@latest
	$(GOGET) github.com/securecodewarrior/gosec/v2/cmd/gosec@latest

# Kubernetes deployment
k8s-deploy:
	@echo "Deploying to Kubernetes..."
	kubectl apply -k k8s/

# Kubernetes cleanup
k8s-clean:
	@echo "Cleaning up Kubernetes resources..."
	kubectl delete -k k8s/

# Show help
help:
	@echo "Available targets:"
	@echo "  build       - Build the binary"
	@echo "  clean       - Clean build artifacts"
	@echo "  test        - Run tests"
	@echo "  coverage    - Run tests with coverage report"
	@echo "  bench       - Run benchmarks"
	@echo "  lint        - Run linter"
	@echo "  security    - Run security scan"
	@echo "  fmt         - Format code"
	@echo "  tidy        - Tidy dependencies"
	@echo "  deps        - Download dependencies"
	@echo "  run         - Build and run the application"
	@echo "  docker      - Build Docker image"
	@echo "  docker-run  - Build and run Docker container"
	@echo "  build-all   - Build cross-platform binaries"
	@echo "  k8s-deploy  - Deploy to Kubernetes"
	@echo "  k8s-clean   - Clean up Kubernetes resources"
	@echo "  install-tools - Install development tools"
	@echo "  help        - Show this help message"
