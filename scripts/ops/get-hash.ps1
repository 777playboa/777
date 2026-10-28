param(
    [Parameter(Mandatory = $true)]
    [string]$JarPath
)

$ErrorActionPreference = "Stop"

$resolved = $JarPath
if (-not [System.IO.Path]::IsPathRooted($resolved)) {
    $resolved = Join-Path (Get-Location) $JarPath
}
if (-not (Test-Path -LiteralPath $resolved -PathType Leaf)) {
    Write-Error "Jar not found: $resolved"
    exit 1
}
$resolved = (Resolve-Path -LiteralPath $resolved).Path

$Hash = (Get-FileHash -LiteralPath $resolved -Algorithm SHA256).Hash.ToLower()

Write-Host ""
Write-Host "Jar: $resolved"
Write-Host "------------------------------------------------------------"
Write-Host "Hash:"
Write-Host "$Hash"
Write-Host "------------------------------------------------------------"