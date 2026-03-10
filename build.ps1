# build.ps1 — Build pkt for Linux and/or Windows
# Usage: .\build.ps1 [-Target linux|windows|all] [-Clean]
param(
    [ValidateSet("linux","windows","all")]
    [string]$Target = "all",
    [switch]$Clean
)

$ErrorActionPreference = "Stop"
$dist  = Join-Path $PSScriptRoot "dist"
$capkg = "./capture"

if ($Clean) {
    Remove-Item -Recurse -Force $dist -ErrorAction SilentlyContinue
    Write-Host "Cleaned dist/"
    exit 0
}

New-Item -ItemType Directory -Force -Path $dist | Out-Null

$env:CGO_ENABLED = "0"
$env:GOARCH      = "amd64"

function Build-Linux {
    $out = Join-Path $dist "pkt-linux-amd64"
    $env:GOOS = "linux"
    Write-Host "Building Linux..."
    go build -trimpath -o $out $capkg
    Write-Host "Built: $out"
}

function Build-Windows {
    $out = Join-Path $dist "pkt-windows-amd64.exe"
    $env:GOOS = "windows"
    Write-Host "Building Windows..."
    go build -trimpath -o $out $capkg
    Write-Host "Built: $out"
}

switch ($Target) {
    "linux"   { Build-Linux }
    "windows" { Build-Windows }
    "all"     { Build-Linux; Build-Windows }
}
