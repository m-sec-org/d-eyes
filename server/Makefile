.PHONY: test dev-up dev-down proto perfcheck

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

perfcheck:
	METRICS_URL=$${METRICS_URL:-http://127.0.0.1:8080/metrics} \
	PROM_URL=$${PROM_URL:-} \
	PROM_WINDOW=$${PROM_WINDOW:-5m} \
	CPU_P95=$${CPU_P95_THRESHOLD:-80} \
	MEM_P95=$${MEM_P95_THRESHOLD:-85} \
	IO_P95=$${IO_P95_THRESHOLD:-80} \
	FAIL_RATE=$${FAILURE_RATE_THRESHOLD:-0.01} \
	Bearer=$${PERF_BEARER_TOKEN:-} \
	CA_FILE=$${PERF_CA_FILE:-} \
	JSON_OUT=$${PERF_JSON_OUT:-} \
	$(GO) run ./tools/perfcheck \
		--metrics-url $$METRICS_URL \
		--cpu-p95-threshold $$CPU_P95 \
		--mem-p95-threshold $$MEM_P95 \
		--io-p95-threshold $$IO_P95 \
		--failure-rate-threshold $$FAIL_RATE \
		$$( [ -n "$$PROM_URL" ] && printf -- ' --prom-url %s' "$$PROM_URL" ) \
		$$( [ -n "$$PROM_URL" ] && [ -n "$$PROM_WINDOW" ] && printf -- ' --window %s' "$$PROM_WINDOW" ) \
		$$( [ -n "$$Bearer" ] && printf -- ' --bearer-token %s' "$$Bearer" ) \
		$$( [ -n "$$CA_FILE" ] && printf -- ' --ca-file %s' "$$CA_FILE" ) \
		$$( [ -n "$$JSON_OUT" ] && printf -- ' --json %s' "$$JSON_OUT" )
