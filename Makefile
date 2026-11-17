.PHONY: help test test-short test-noise test-expand test-full-noise test-protocol benchmark demo coms fmt vet

GO ?= go

# Shared settings for benchmarks, noise tests, demo, and communication.
# Keep previous BENCH_* make variables and CHARTS_BENCH_* env names as aliases.
CHARTS_PROFILE ?= $(or $(BENCH_PROFILE),$(CHARTS_BENCH_PROFILE),paper)
CHARTS_N ?= $(or $(BENCH_N),$(CHARTS_BENCH_N))
CHARTS_B ?= $(or $(BENCH_B),$(CHARTS_BENCH_B))
CHARTS_THREADS ?= $(or $(BENCH_THREADS),4)
export CHARTS_PROFILE CHARTS_N CHARTS_B
export CHARTS_LOGN CHARTS_LOGQ CHARTS_LOGP CHARTS_T
export CHARTS_SMUDGING_SECURITY_BITS CHARTS_LOG2_ROUTED_NOISE
export GOMAXPROCS = $(CHARTS_THREADS)

BENCH_PATTERN ?= BenchmarkProtocol
BENCHTIME ?= 1x
BENCH_COUNT ?= 1

help:
	@echo "make test             Run the complete test suite"
	@echo "make test-short       Run the CI-sized test suite"
	@echo "make test-expand      Run sparse-expansion equivalence tests"
	@echo "make test-protocol    Run protocol tests with the shared settings"
	@echo "make test-noise       Run the routing noise report test"
	@echo "make test-full-noise  Run routing and collective-output noise tests"
	@echo "make benchmark        Run protocol phase benchmarks"
	@echo "make demo             Run the end-to-end routing demo"
	@echo "make coms             Report communication sizes"
	@echo "Shared settings: CHARTS_PROFILE CHARTS_N CHARTS_B CHARTS_THREADS"
	@echo "BGV overrides: CHARTS_LOGN CHARTS_LOGQ CHARTS_LOGP CHARTS_T"
	@echo "Noise overrides: CHARTS_SMUDGING_SECURITY_BITS CHARTS_LOG2_ROUTED_NOISE"

test:
	$(GO) test -count=1 -timeout=0 -p 1 ./...

test-short:
	$(GO) test -short -count=1 -timeout=0 -p 1 ./...

test-expand:
	$(GO) test -count=1 -run '^TestExpandSparse' -v ./charts

test-protocol:
	$(GO) test -run '^Test(Multiparty|CoefficientEncryption|RequestEncoding|DirectRoute|Route|Sender|Decode|RoutingCorrectness)' -v -count=1 -timeout=0 -p 1 ./charts ./tests

test-noise test-full-noise:
	$(GO) test -run '^TestFullNoiseAndCorrectness$$' -v -count=1 -timeout=0 ./tests

benchmark:
	$(GO) test -run '^$$' -bench '$(BENCH_PATTERN)' -benchmem \
		-benchtime=$(BENCHTIME) -count=$(BENCH_COUNT) -timeout=0 ./tests

demo:
	$(GO) run ./cmd/demo

coms:
	$(GO) run ./cmd/communication

fmt:
	$(GO) fmt ./...

vet:
	$(GO) vet ./...
