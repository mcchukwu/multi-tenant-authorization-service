APP_NAME := multi-tenant-authorization-service
CMD_PATH := ./cmd
BIN_PATH := bin

.PHONY: run build test fmt vet migrate bootstrap clean

run:
	go run $(CMD_PATH)

build:
	CGO_ENABLED=0 go build -trimpath -o $(BIN_PATH)/$(APP_NAME) $(CMD_PATH)

test:
	go test ./...

fmt:
	gofmt -l .

vet:
	go vet ./...

migrate:
	go run ./cmd/migrate

bootstrap:
	docker compose up -d --wait
	$(MAKE) migrate

clean:
	rm -rf $(BIN_PATH)
