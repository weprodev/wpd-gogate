# ============================================================================
# ANSI Color Codes
# ============================================================================
CYAN    := \033[36m
GREEN   := \033[32m
YELLOW  := \033[33m
BLUE    := \033[34m
MAGENTA := \033[35m
BOLD    := \033[1m
RESET   := \033[0m

.DEFAULT_GOAL := help

.PHONY: install lint test race test-integration db-start db-stop audit help

## Install Go dependencies
install:
	@printf "$(BOLD)$(CYAN)📦 Installing dependencies...$(RESET)\n"
	@go mod download
	@go mod tidy
	@printf "$(GREEN)✅ Dependencies installed!$(RESET)\n\n"

## Run golangci-lint checking code quality
lint:
	@printf "$(BOLD)$(YELLOW)🔍 Linting Go...$(RESET)\n"
	@golangci-lint run
	@printf "$(GREEN)✅ Lint checks passed!$(RESET)\n\n"

## Run unit tests (mock database)
test:
	@printf "$(BOLD)$(CYAN)🧪 Running unit tests...$(RESET)\n"
	@go test -v ./...
	@printf "$(GREEN)✅ Unit tests passed!$(RESET)\n\n"

## Run unit tests with Go race detector
race:
	@printf "$(BOLD)$(CYAN)🧪 Running race tests...$(RESET)\n"
	@go test -v -race ./...
	@printf "$(GREEN)✅ Race tests passed!$(RESET)\n\n"

## Spin up local database and run E2E Postgres integration tests
test-integration: db-start
	@printf "$(BOLD)$(YELLOW)🛢️  Running E2E Integration tests against Postgres...$(RESET)\n"
	@TEST_DB_HOST=localhost \
	 TEST_DB_PORT=54322 \
	 TEST_DB_USER=test_user \
	 TEST_DB_PASSWORD=test_password \
	 TEST_DB_NAME=test_gogate \
	 go test -v -race ./... || (make db-stop && exit 1)
	@make db-stop
	@printf "$(GREEN)✅ Integration tests passed!$(RESET)\n\n"

## Spin up PostgreSQL test container via Docker Compose
db-start:
	@printf "$(BOLD)$(BLUE)🐳 Starting PostgreSQL test container...$(RESET)\n"
	@docker compose -f docker-compose.test.yml up -d --wait
	@printf "$(GREEN)✅ PostgreSQL is ready!$(RESET)\n\n"

## Shut down PostgreSQL test container
db-stop:
	@printf "$(BOLD)$(MAGENTA)🛑 Stopping PostgreSQL test container...$(RESET)\n"
	@docker compose -f docker-compose.test.yml down -v
	@printf "$(GREEN)✅ PostgreSQL test container stopped and cleaned!$(RESET)\n\n"

## Full quality gate audit: lint + unit tests + integration tests
audit:
	@printf "$(BOLD)$(MAGENTA)🏁 Starting QA Audit...$(RESET)\n"
	@printf "$(CYAN)━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━$(RESET)\n"
	@make lint
	@make test-integration
	@printf "$(CYAN)━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━$(RESET)\n"
	@printf "$(BOLD)$(GREEN)🎉 QA Audit Successful!$(RESET)\n"

## Display available make targets
help:
	@printf "\n"
	@printf "$(BOLD)$(CYAN)━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━$(RESET)\n"
	@printf "$(BOLD)$(CYAN)           wpd-gogate Automation Pipeline                 $(RESET)\n"
	@printf "$(BOLD)$(CYAN)━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━$(RESET)\n"
	@printf "\n"
	@printf "   $(YELLOW)make install$(RESET)            Install and tidy Go dependencies\n"
	@printf "   $(YELLOW)make lint$(RESET)               Run golangci-lint code checks\n"
	@printf "   $(YELLOW)make test$(RESET)               Run standard mock unit tests\n"
	@printf "   $(YELLOW)make race$(RESET)               Run unit tests with race detection\n"
	@printf "   $(YELLOW)make test-integration$(RESET)    Run E2E Postgres integration tests in Docker\n"
	@printf "   $(YELLOW)make db-start$(RESET)           Start Postgres test container manually\n"
	@printf "   $(YELLOW)make db-stop$(RESET)            Stop and clean Postgres test container\n"
	@printf "   $(YELLOW)make audit$(RESET)              Run lint, unit tests, and E2E integration checks\n"
	@printf "\n"
	@printf "$(BOLD)$(CYAN)━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━$(RESET)\n"
	@printf "\n"
