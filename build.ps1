# build.ps1 — Build pkt examples for Linux and/or Windows
# Usage: .\build.ps1 [-Target linux|windows|all] [-Clean]
param(
    [ValidateSet("linux","windows","all")]
    [string]$Target = "all",
    [switch]$Clean
)

$ErrorActionPreference = "Stop"
$dist = Join-Path $PSScriptRoot "dist"

if ($Clean) {
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
    go build -trimpath -o $out ./examples/cmd/capture/
    Write-Host "Built: $out"
}

function Build-Windows {
    $env:GOOS = "windows"

    $outCapture = Join-Path $dist "capture-windows-amd64.exe"
    Write-Host "Building Windows capture..."
    go build -trimpath -o $outCapture ./examples/cmd/capture/
    Write-Host "Built: $outCapture"

    $outModify = Join-Path $dist "modify-payload-windows-amd64.exe"
    Write-Host "Building Windows modify-payload..."
    go build -trimpath -o $outModify ./examples/cmd/modify-payload/
    Write-Host "Built: $outModify"

    $outDrop = Join-Path $dist "drop-windows-amd64.exe"
    Write-Host "Building Windows drop..."
    go build -trimpath -o $outDrop ./examples/cmd/drop/
    Write-Host "Built: $outDrop"

    $outFilter = Join-Path $dist "filter-windows-amd64.exe"
    Write-Host "Building Windows filter..."
    go build -trimpath -o $outFilter ./examples/cmd/filter/
    Write-Host "Built: $outFilter"
}

switch ($Target) {
    "linux"   { Build-Linux }
    "windows" { Build-Windows }
    "all"     { Build-Linux; Build-Windows }
}
