BINARY  := prism
GOFLAGS := -ldflags="-s -w"
KEYDIR  := configs
GO      ?= go

.PHONY: build test clean keygen vet release proto bundle install

build:
	$(GO) build $(GOFLAGS) -o $(BINARY) ./cmd/prism

release:
	CGO_ENABLED=0 $(GO) build -trimpath -ldflags="-s -w" -o $(BINARY) ./cmd/prism

bundle: release
	cp $(BINARY) deploy/$(BINARY)
	@echo "Prepared deploy/$(BINARY)"
	@echo "Upload deploy/ to the target host and run sudo ./deploy/setup.sh"

test:
	$(GO) test ./...

test-stress:
	$(GO) test -v -run TestSQLiteStress -count=1 ./internal/controller/

vet:
	$(GO) vet ./...

clean:
	rm -f $(BINARY) deploy/$(BINARY)

keygen:
	$(GO) run ./cmd/prism --mode keygen --key-dir $(KEYDIR)

proto:
	PATH="$$HOME/go/bin:$$PATH" buf generate

install: bundle
	@echo "Local installation is performed on the target host via deploy/setup.sh"
