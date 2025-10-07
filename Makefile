# Cortex Syslog Generator - Modern Development Makefile
# Supports Windows (PowerShell), Linux, and macOS

# Platform detection
UNAME_S := $(shell uname -s 2>/dev/null || echo Windows)
ifeq ($(UNAME_S),Windows_NT)
    DETECTED_OS := Windows
    PYTHON := python
    VENV := .venv
    VENVBIN := $(VENV)\Scripts
    ACTIVATE := $(VENVBIN)\activate
    RM := rmdir /s /q
    MKDIR := mkdir
else ifeq ($(UNAME_S),Darwin)
    DETECTED_OS := macOS
    PYTHON := python3
    VENV := .venv
    VENVBIN := $(VENV)/bin
    ACTIVATE := $(VENVBIN)/activate
    RM := rm -rf
    MKDIR := mkdir -p
else
    DETECTED_OS := Linux
    PYTHON := python3
    VENV := .venv
    VENVBIN := $(VENV)/bin
    ACTIVATE := $(VENVBIN)/activate
    RM := rm -rf
    MKDIR := mkdir -p
endif

# Colors for output (Unix-like systems only)
ifneq ($(DETECTED_OS),Windows)
RED := \033[31m
GREEN := \033[32m
YELLOW := \033[33m
BLUE := \033[34m
RESET := \033[0m
else
RED := 
GREEN := 
YELLOW := 
BLUE := 
RESET := 
endif

.DEFAULT_GOAL := help
.PHONY: help venv install install-prod install-dev clean test lint format type-check security
.PHONY: run demo build docker docker-build docker-run docker-clean pre-commit

## 🚀 Development Environment Setup
venv: $(ACTIVATE)  ## Create virtual environment
$(ACTIVATE): requirements.txt pyproject.toml
	@echo "$(GREEN)Creating virtual environment for $(DETECTED_OS)...$(RESET)"
	$(PYTHON) -m venv $(VENV)
ifeq ($(DETECTED_OS),Windows)
	$(VENVBIN)\python -m pip install --upgrade pip setuptools wheel
	$(VENVBIN)\pip install -e ".[dev]"
else
	$(VENVBIN)/python -m pip install --upgrade pip setuptools wheel
	$(VENVBIN)/pip install -e ".[dev]"
endif
	@echo "$(GREEN)Virtual environment ready! Run: source $(ACTIVATE)$(RESET)"

## 📦 Installation Options
install: venv  ## Install development dependencies
	@echo "$(GREEN)Installing development dependencies...$(RESET)"
ifeq ($(DETECTED_OS),Windows)
	$(VENVBIN)\pip install -e ".[dev]"
else
	$(VENVBIN)/pip install -e ".[dev]"
endif

install-prod: $(ACTIVATE)  ## Install production dependencies only
	@echo "$(GREEN)Installing production dependencies...$(RESET)"
ifeq ($(DETECTED_OS),Windows)
	$(VENVBIN)\pip install -r requirements-prod.txt
else
	$(VENVBIN)/pip install -r requirements-prod.txt
endif

install-dev: venv  ## Install development dependencies
	@echo "$(GREEN)Installing development dependencies...$(RESET)"
ifeq ($(DETECTED_OS),Windows)
	$(VENVBIN)\pip install -r requirements.txt
else
	$(VENVBIN)/pip install -r requirements.txt
endif

## 🏃 Application Execution
run: venv  ## Run Flask web application (localhost:5001)
	@echo "$(GREEN)Starting Cortex Syslog Generator Web UI...$(RESET)"
ifeq ($(DETECTED_OS),Windows)
	$(VENVBIN)\python app.py
else
	$(VENVBIN)/python app.py
endif

demo: venv  ## Run interactive CLI demo
	@echo "$(GREEN)Starting interactive demo...$(RESET)"
ifeq ($(DETECTED_OS),Windows)
	$(VENVBIN)\python demo_xgen.py
else
	$(VENVBIN)/python demo_xgen.py
endif

demo-cortex: venv  ## Run Cortex-specific demo scenarios
	@echo "$(GREEN)Starting Cortex XDR demo scenarios...$(RESET)"
ifeq ($(DETECTED_OS),Windows)
	$(VENVBIN)\python demo_cortex_standalone.py
else
	$(VENVBIN)/python demo_cortex_standalone.py
endif

demo-enhanced: venv  ## Run enhanced features demo
	@echo "$(GREEN)Starting enhanced features demo...$(RESET)"
ifeq ($(DETECTED_OS),Windows)
	$(VENVBIN)\python demo_enhanced_features.py
else
	$(VENVBIN)/python demo_enhanced_features.py
endif

## 🧪 Testing and Quality Assurance
test: venv  ## Run all tests with coverage
	@echo "$(GREEN)Running test suite...$(RESET)"
ifeq ($(DETECTED_OS),Windows)
	$(VENVBIN)\pytest -v --cov=src --cov-report=html --cov-report=term-missing
else
	$(VENVBIN)/pytest -v --cov=src --cov-report=html --cov-report=term-missing
endif

test-fast: venv  ## Run tests without coverage (faster)
	@echo "$(GREEN)Running fast test suite...$(RESET)"
ifeq ($(DETECTED_OS),Windows)
	$(VENVBIN)\pytest -v -x
else
	$(VENVBIN)/pytest -v -x
endif

test-integration: venv  ## Run integration tests only
	@echo "$(GREEN)Running integration tests...$(RESET)"
ifeq ($(DETECTED_OS),Windows)
	$(VENVBIN)\pytest -v -m integration
else
	$(VENVBIN)/pytest -v -m integration
endif

## 🔧 Code Quality Tools
lint: venv  ## Run all linting tools
	@echo "$(GREEN)Running linting tools...$(RESET)"
ifeq ($(DETECTED_OS),Windows)
	$(VENVBIN)\ruff check src tests
	$(VENVBIN)\black --check src tests
else
	$(VENVBIN)/ruff check src tests
	$(VENVBIN)/black --check src tests
endif

format: venv  ## Format code with black and ruff
	@echo "$(GREEN)Formatting code...$(RESET)"
ifeq ($(DETECTED_OS),Windows)
	$(VENVBIN)\black src tests *.py
	$(VENVBIN)\ruff check src tests --fix
else
	$(VENVBIN)/black src tests *.py
	$(VENVBIN)/ruff check src tests --fix
endif

type-check: venv  ## Run type checking with mypy
	@echo "$(GREEN)Running type checks...$(RESET)"
ifeq ($(DETECTED_OS),Windows)
	$(VENVBIN)\mypy src
else
	$(VENVBIN)/mypy src
endif

security: venv  ## Run security analysis with bandit
	@echo "$(GREEN)Running security analysis...$(RESET)"
ifeq ($(DETECTED_OS),Windows)
	$(VENVBIN)\bandit -r src
else
	$(VENVBIN)/bandit -r src
endif

pre-commit: venv  ## Install and run pre-commit hooks
	@echo "$(GREEN)Setting up pre-commit hooks...$(RESET)"
ifeq ($(DETECTED_OS),Windows)
	$(VENVBIN)\pre-commit install
	$(VENVBIN)\pre-commit run --all-files
else
	$(VENVBIN)/pre-commit install
	$(VENVBIN)/pre-commit run --all-files
endif

## 🔍 Quality Gate (CI/CD)
quality: venv lint type-check security test  ## Run all quality checks
	@echo "$(GREEN)✅ All quality checks passed!$(RESET)"

## 📦 Build and Distribution
build: venv  ## Build distribution packages
	@echo "$(GREEN)Building distribution packages...$(RESET)"
ifeq ($(DETECTED_OS),Windows)
	$(VENVBIN)\python -m build
else
	$(VENVBIN)/python -m build
endif

## 🐳 Docker Support
docker-build:  ## Build Docker image
	@echo "$(GREEN)Building Docker image...$(RESET)"
	docker build -t cortex-syslog-generator:latest .
	docker build -t cortex-syslog-generator:$(shell git rev-parse --short HEAD) .

docker-run:  ## Run Docker container
	@echo "$(GREEN)Running Docker container...$(RESET)"
	docker run -p 5001:5001 --rm cortex-syslog-generator:latest

docker-dev:  ## Run Docker container with development setup
	@echo "$(GREEN)Running Docker container in development mode...$(RESET)"
	docker run -p 5001:5001 -v $(PWD):/app --rm cortex-syslog-generator:latest

docker-compose:  ## Run with docker-compose (if available)
	@echo "$(GREEN)Starting services with docker-compose...$(RESET)"
	docker-compose up -d

docker-clean:  ## Clean Docker images and containers
	@echo "$(YELLOW)Cleaning Docker images...$(RESET)"
	docker system prune -f
	docker rmi cortex-syslog-generator:latest 2>/dev/null || true

## 🧹 Cleanup
clean:  ## Clean build artifacts and caches
	@echo "$(YELLOW)Cleaning build artifacts...$(RESET)"
	$(RM) __pycache__ .pytest_cache build dist *.egg-info htmlcov .coverage .mypy_cache .ruff_cache 2>/dev/null || true
ifeq ($(DETECTED_OS),Windows)
	find . -name "*.pyc" -delete 2>nul || true
	find . -name "__pycache__" -type d -exec rmdir /s /q {} + 2>nul || true
else
	find . -name "*.pyc" -delete 2>/dev/null || true
	find . -name "__pycache__" -type d -exec rm -rf {} + 2>/dev/null || true
endif

clean-all: clean  ## Clean everything including venv
	@echo "$(YELLOW)Removing virtual environment...$(RESET)"
	$(RM) $(VENV) 2>/dev/null || true

## ℹ️  Information
info:  ## Show environment information
	@echo "$(BLUE)=== Environment Information ===$(RESET)"
	@echo "Detected OS: $(DETECTED_OS)"
	@echo "Python: $(PYTHON)"
	@echo "Virtual Environment: $(VENV)"
	@echo "Activate Command: source $(ACTIVATE)"
	@echo "Project Version: $(shell grep '^version' pyproject.toml | cut -d'"' -f2)"
ifeq ($(DETECTED_OS),Windows)
	@echo "Platform-specific notes: Using Windows PowerShell commands"
else
	@echo "Platform-specific notes: Using Unix-like commands"
endif

## 📚 Help
help:  ## Show this help message
	@echo "$(BLUE)Cortex Syslog Generator - Development Makefile$(RESET)"
	@echo "$(BLUE)Detected Platform: $(DETECTED_OS)$(RESET)"
	@echo ""
	@echo "Available targets:"
	@grep -E '^[a-zA-Z_-]+:.*?## ' Makefile | awk 'BEGIN {FS = ":.*?## "}; {printf "  $(GREEN)%-20s$(RESET) %s\n", $$1, $$2}'
	@echo ""
	@echo "$(YELLOW)Quick Start:$(RESET)"
	@echo "  make venv     # Create virtual environment"
	@echo "  make install  # Install dependencies"
	@echo "  make run      # Start web application"
	@echo "  make test     # Run test suite"
	@echo "  make quality  # Run all quality checks"
