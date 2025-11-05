.PHONY: test dev-up dev-down proto

GO=go
dc=docker compose -f deploy/docker-compose.yaml

 test:
	$(GO) test ./...

dev-up:
	$(dc) up --build -d

dev-down:
	$(dc) down -v

 proto:
	cd proto/agentservicepb && go generate
