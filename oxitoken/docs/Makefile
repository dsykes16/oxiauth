# Makefile
SHELL := /bin/sh

CARGO      := cargo
JQ         := jq

ENC_BENCH_JQ  := util/enc_bench_table.jq
ENC_BENCH_JSON := util/enc_bench.json
ENC_BENCH_MD   := src/bench_tables/EncodingPerformance.md

VAL_BENCH_JQ  := util/val_bench_table.jq
VAL_BENCH_JSON := util/val_bench.json
VAL_BENCH_MD   := src/bench_tables/ValidationPerformance.md

.PHONY: test bench clean

test:
	$(CARGO) llvm-cov nextest
	$(CARGO) llvm-cov report --html

bench: $(ENC_BENCH_MD) $(VAL_BENCH_MD)

$(ENC_BENCH_JSON):
	$(CARGO) criterion --bench encode --message-format=json > $@

$(VAL_BENCH_JSON):
	$(CARGO) criterion --bench validate --message-format=json > $@

$(ENC_BENCH_MD): $(ENC_BENCH_JSON)
	$(JQ) -rnf $(ENC_BENCH_JQ) $(ENC_BENCH_JSON) > $@

$(VAL_BENCH_MD): $(VAL_BENCH_JSON)
	$(JQ) -rnf $(VAL_BENCH_JQ) $(VAL_BENCH_JSON) > $@

clean:
	rm -f $(ENC_BENCH_JSON) $(ENC_BENCH_MD)
	rm -f $(VAL_BENCH_JSON) $(VAL_BENCH_MD)
