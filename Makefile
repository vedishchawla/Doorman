.PHONY: up down test unit-test bench certs

# Run unit tests across all packages (uses local go if installed, falls back to Docker Go container).
unit-test:
	@which go >/dev/null 2>&1 && go test -v ./... || docker run --rm -v "$$(pwd):/app" -w /app golang:1.22.8-alpine3.20 go test -v ./...

# Generate self-signed TLS certs for nginx (idempotent).
certs:
	@chmod +x nginx/certs/generate.sh
	@nginx/certs/generate.sh

# Build images, generate certs, and start all services.
up: certs
	docker compose up -d --build

# Stop and remove all containers, volumes, and networks.
down:
	docker compose down -v

# Run unit tests and smoke-test running services.
test: unit-test
	@echo ""
	@echo "=== Container status ==="
	@docker compose ps
	@echo ""
	@echo "=== Keycloak health (host → management port 9000) ==="
	@curl -sf http://localhost:9000/health/ready 2>/dev/null | python3 -m json.tool || echo "Keycloak not ready yet"
	@echo ""
	@echo "=== OPA health (host → port 8181) ==="
	@curl -sf http://localhost:8181/health 2>/dev/null || echo "OPA not ready yet"
	@echo ""
	@echo "=== nginx / backend-a (host → https://localhost) ==="
	@curl -sk https://localhost/ 2>/dev/null | python3 -m json.tool || echo "nginx not ready yet"
	@echo ""

# Benchmark stub – k6 scripts will be added later.
bench:
	@echo "bench: k6 benchmarks not implemented yet"
