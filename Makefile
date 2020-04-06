SRC_DIRS = cmd pkg


.PHONY: default
default: build

.PHONY: build
#build:  bindata control-plane-operator
build: bindata
	go build -mod=vendor -o bin/hypershift-installer github.com/openshift-hive/hypershift-installer/cmd

.PHONY: bindata
bindata:
	hack/update-bindata.sh

.PHONY: verify-gofmt
verify-gofmt:
	@echo Verifying gofmt
	@gofmt -l -s $(SRC_DIRS)>.out 2>&1 || true
	@[ ! -s .out ] || \
	  (echo && echo "*** Please run 'make fmt' in order to fix the following:" && \
	  cat .out && echo && rm .out && false)
	@rm .out

.PHONY: verify
verify: verify-gofmt
