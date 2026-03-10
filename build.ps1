# build.ps1 — Build, test and vet pkt (Windows)
# Usage: .\build.ps1 [-Target linux|windows|all|test|check|clean]
param(
    [ValidateSet("linux","windows","all","test","check","clean")]
    [string]$Target = "all",
    [switch]$Clean
)

$ErrorActionPreference = "Stop"
$root = $PSScriptRoot
$dist = Join-Path $root "dist"

if ($Clean -or $Target -eq "clean") {
    Remove-Item -Recurse -Force $dist -ErrorAction SilentlyContinue
    Write-Host "Cleaned dist/"
    exit 0
}

New-Item -ItemType Directory -Force -Path $dist | Out-Null

$env:CGO_ENABLED = "0"
$env:GOARCH      = "amd64"

function Build-Linux {
    $env:GOOS = "linux"
    $out = Join-Path $dist "capture-linux-amd64"
    Write-Host "Building Linux capture..."
    & go build -trimpath -o $out ./examples/cmd/capture/
    Write-Host "Built: $out"
}

function Build-Windows {
    $env:GOOS = "windows"

    $bins = @{
        "capture-windows-amd64.exe"       = "./examples/cmd/capture/"
        "modify-payload-windows-amd64.exe" = "./examples/cmd/modify-payload/"
        "drop-windows-amd64.exe"           = "./examples/cmd/drop/"
        "filter-windows-amd64.exe"         = "./examples/cmd/filter/"
    }

    foreach ($name in $bins.Keys) {
        Write-Host "Building $name..."
        $out = Join-Path $dist $name
        & go build -trimpath -o $out $bins[$name]
        Write-Host "Built: $out"
    }
}

function Run-Tests {
    Write-Host "Running Windows tests..."
    $env:GOOS = "windows"
    & go test ./windivert/filter/... -v
    Write-Host "Running Linux tests (cross-compiled)..."
    $env:GOOS = "linux"
    & go test ./bpf/...      -v
    & go test ./afpacket/... -v
}

function Run-Check {
    Build-Linux
    Build-Windows
    Write-Host "Vetting Windows packages..."
    $env:GOOS = "windows"
    & go vet ./windivert/... ./capture/... ./examples/...
    Write-Host "Vetting Linux packages..."
    $env:GOOS = "linux"
    & go vet ./bpf/... ./afpacket/... ./capture/...
    Write-Host "All checks passed."
}

switch ($Target) {
    "linux"   { Build-Linux }
    "windows" { Build-Windows }
    "all"     { Build-Linux; Build-Windows }
    "test"    { Run-Tests }
    "check"   { Run-Check }
}
