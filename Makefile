APP_NAME := multi-tenant-authorization-service
CMD_PATH := ./cmd
BIN_PATH := bin

.PHONY: run build clean test

run: 
	go run $(CMD_PATH)

build:
	go build -o $(BIN_PATH)/$(APP_NAME) $(CMD_PATH)

clean:
	rm -rf $(BIN_PATH)

test:
	go test ./...
	
migrate:
	migrate -source "file://./migrations" -database "postgres://miracle:nolly@localhost:5435/mtasdb?sslmode=disable"
