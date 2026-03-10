# pkt workspace — cross-platform packet capture
# Usage: make [linux|windows|all|test|setcap|clean|check]
#
# Windows: Chocolatey GNU make (choco install make) ou MSYS2.
#          Sinon: .\build.ps1 -Target all

BINARY      := pkt
DIST        := dist
CAPTURE_PKG := ./capture

LINUX_OUT   := $(DIST)/$(BINARY)-linux-amd64
WINDOWS_OUT := $(DIST)/$(BINARY)-windows-amd64.exe

export CGO_ENABLED = 0
export GOARCH      = amd64

ifeq ($(OS),Windows_NT)
  MKDIR = powershell -Command "New-Item -ItemType Directory -Force -Path '$(DIST)' | Out-Null"
  RM    = powershell -Command "Remove-Item -Recurse -Force -ErrorAction SilentlyContinue '$(DIST)'"
  ECHO  = cmd /c echo
else
  MKDIR = mkdir -p $(DIST)
  RM    = rm -rf $(DIST)
  ECHO  = echo
endif

.PHONY: all linux windows clean test setcap check

all: linux windows

## Build for Linux (amd64, static — works on any distro)
linux: $(DIST)
	GOOS=linux go build -trimpath -o $(LINUX_OUT) $(CAPTURE_PKG)
	@$(ECHO) Built: $(LINUX_OUT)

## Build for Windows (amd64)
windows: $(DIST)
	GOOS=windows go build -trimpath -o $(WINDOWS_OUT) $(CAPTURE_PKG)
	@$(ECHO) Built: $(WINDOWS_OUT)

$(DIST):
	$(MKDIR)

## Run tests (no root required)
test:
	GOOS=windows go test ./windivert/filter/... -v
	GOOS=linux   go test ./bpf/...             -v

## Grant CAP_NET_RAW to the Linux binary (Linux, requires root/sudo).
## Once set, the binary captures packets without running as root.
setcap: linux
	setcap cap_net_raw+eip $(LINUX_OUT)
	@echo "$(LINUX_OUT): cap_net_raw+eip granted"

## Remove build artefacts
clean:
	$(RM)

## Compile + vet both platforms
check: linux windows
	GOOS=windows go vet ./windivert/...
	GOOS=linux   go vet ./bpf/... ./afpacket/...
	@$(ECHO) All checks passed
