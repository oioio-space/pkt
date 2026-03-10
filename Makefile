# pkt workspace — cross-platform packet capture
# Usage: make [linux|windows|all|test|setcap|clean|check]
#
# Windows: Chocolatey GNU make (choco install make) ou MSYS2.
#          Sinon: .\build.ps1 -Target all

DIST := dist

LINUX_CAPTURE   := $(DIST)/capture-linux-amd64
WINDOWS_CAPTURE := $(DIST)/capture-windows-amd64.exe
WINDOWS_MODIFY  := $(DIST)/modify-payload-windows-amd64.exe
WINDOWS_DROP    := $(DIST)/drop-windows-amd64.exe

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
	GOOS=linux go build -trimpath -o $(LINUX_CAPTURE) ./examples/cmd/capture/
	@$(ECHO) Built: $(LINUX_CAPTURE)

## Build for Windows (amd64)
windows: $(DIST)
	GOOS=windows go build -trimpath -o $(WINDOWS_CAPTURE) ./examples/cmd/capture/
	GOOS=windows go build -trimpath -o $(WINDOWS_MODIFY)  ./examples/cmd/modify-payload/
	GOOS=windows go build -trimpath -o $(WINDOWS_DROP)    ./examples/cmd/drop/
	@$(ECHO) Built: $(WINDOWS_CAPTURE) $(WINDOWS_MODIFY) $(WINDOWS_DROP)

$(DIST):
	$(MKDIR)

## Run tests (no root required)
test:
	GOOS=windows go test ./windivert/filter/... -v
	GOOS=linux   go test ./bpf/...             -v

## Grant CAP_NET_RAW to the Linux binary (Linux, requires root/sudo).
## Once set, the binary captures packets without running as root.
setcap: linux
	setcap cap_net_raw+eip $(LINUX_CAPTURE)
	@echo "$(LINUX_CAPTURE): cap_net_raw+eip granted"

## Remove build artefacts
clean:
	$(RM)

## Compile + vet both platforms
check: linux windows
	GOOS=windows go vet ./windivert/...
	GOOS=linux   go vet ./bpf/... ./afpacket/...
	@$(ECHO) All checks passed
