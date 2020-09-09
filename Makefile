SRC_DIRS = cmd pkg


.PHONY: default
default: verify build

.PHONY: build
build: bindata
	go build -mod=vendor -o bin/hypershift-installer github.com/openshift-hive/hypershift-installer/cmd/hypershift-installer
	go build -mod=vendor -o bin/machineset-transform github.com/openshift-hive/hypershift-installer/cmd/machineset-transform

.PHONY: bindata
bindata:
	hack/update-bindata.sh

.PHONY: verify-bindata
verify-bindata:
	hack/verify-bindata.sh

.PHONY: verify-gofmt
verify-gofmt:
	@echo Verifying gofmt
	@gofmt -l -s $(SRC_DIRS)>.out 2>&1 || true
	@[ ! -s .out ] || \
	  (echo && echo "*** Please run 'make fmt' in order to fix the following:" && \
	  cat .out && echo && rm .out && false)
	@rm .out

.PHONY: verify
verify: verify-gofmt verify-bindata
