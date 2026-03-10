# pkt workspace — cross-platform packet capture (Linux build system)
# Usage: make [linux|all|test|setcap|clean|check]
#
# Windows: use .\build.ps1 instead (Makefile requires bash/Linux environment)

DIST := dist

LINUX_CAPTURE := $(DIST)/capture-linux-amd64

export CGO_ENABLED = 0
export GOARCH      = amd64

.PHONY: all linux clean test setcap check

all: linux

## Build for Linux (amd64, static — works on any distro)
linux: $(DIST)
	GOOS=linux go build -trimpath -o $(LINUX_CAPTURE) ./examples/cmd/capture/
	@echo Built: $(LINUX_CAPTURE)

$(DIST):
	mkdir -p $(DIST)

## Run tests (no root required)
test:
	GOOS=linux go test ./bpf/...      -v
	GOOS=linux go test ./afpacket/... -v

## Grant CAP_NET_RAW to the Linux binary (requires root/sudo).
## Once set, the binary captures packets without running as root.
setcap: linux
	setcap cap_net_raw+eip $(LINUX_CAPTURE)
	@echo "$(LINUX_CAPTURE): cap_net_raw+eip granted"

## Remove build artefacts
clean:
	rm -rf $(DIST)

## Compile + vet
check: linux
	GOOS=linux go vet ./bpf/... ./afpacket/... ./capture/...
	@echo All checks passed
