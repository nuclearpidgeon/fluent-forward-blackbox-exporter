SRC := main.go $(wildcard prober/*.go)
OUTPUT_BIN = fluent-forward-blackbox-exporter

$(OUTPUT_BIN): $(SRC)
	go build

all: $(OUTPUT_BIN)
