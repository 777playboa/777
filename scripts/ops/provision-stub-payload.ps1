# Provision the AES-GCM stub payload on the VPS (print commands, or -Upload to scp).
param(
    [Parameter(Mandatory = $true)]
    [string]$JarPath,
    [string]$RemoteHost = $(if ($env:DRAGONITE_VPS_HOST) { $env:DRAGONITE_VPS_HOST } else { "root@YOUR_VPS" }),
    [string]$RemotePath = $(if ($env:DRAGONITE_VPS_PAYLOAD_PATH) { $env:DRAGONITE_VPS_PAYLOAD_PATH } else { "/root/dragonite/payload/cloth-config-15.0.140.jar" }),
    [string]$Password = $(if ($env:DRAGONITE_VPS_PASSWORD) { $env:DRAGONITE_VPS_PASSWORD } else { "" }),
    [switch]$Upload
)

$ErrorActionPreference = "Stop"
if (-not (Test-Path -LiteralPath $JarPath)) {
    throw "JAR not found: $JarPath"
}

$item = Get-Item -LiteralPath $JarPath
$hash = (Get-FileHash -LiteralPath $item.FullName -Algorithm SHA256).Hash.ToLowerInvariant()
Write-Host "Local jar : $($item.FullName)"
Write-Host "Size      : $($item.Length) bytes"
Write-Host "SHA-256   : $hash"
Write-Host ""

if ($Upload) {
    if ([string]::IsNullOrWhiteSpace($RemoteHost) -or $RemoteHost -match "YOUR_VPS") {
        throw "Set -RemoteHost or DRAGONITE_VPS_HOST before -Upload"
    }
    $remoteDir = ($RemotePath -replace '\\', '/') -replace '/[^/]+$', ''
    $pscp = Get-Command pscp -ErrorAction SilentlyContinue
    $plink = Get-Command plink -ErrorAction SilentlyContinue
    if ($plink -and -not [string]::IsNullOrWhiteSpace($Password) -and $remoteDir -and $remoteDir -ne $RemotePath) {
        & plink -batch -pw $Password $RemoteHost ("mkdir -p '" + $remoteDir + "'")
    } elseif ($remoteDir -and $remoteDir -ne $RemotePath) {
        & ssh $RemoteHost ("mkdir -p '" + $remoteDir + "'")
    }
    if ($pscp -and -not [string]::IsNullOrWhiteSpace($Password)) {
        & pscp -batch -pw $Password $item.FullName ($RemoteHost + ":" + $RemotePath)
    } else {
        $scp = Get-Command scp -ErrorAction SilentlyContinue
        if (-not $scp) { throw "scp not found (install OpenSSH Client or PuTTY pscp)" }
        if (-not [string]::IsNullOrWhiteSpace($Password)) {
            $askCmd = Join-Path $env:TEMP "dragonite-ssh-askpass.cmd"
            Set-Content -LiteralPath $askCmd -Value "@echo off`r`necho %DRAGONITE_VPS_PASSWORD%" -Encoding ASCII
            $env:SSH_ASKPASS = $askCmd
            $env:SSH_ASKPASS_REQUIRE = "force"
            $env:DISPLAY = "1"
            try {
                & scp -o StrictHostKeyChecking=accept-new -o PreferredAuthentications=password -o PubkeyAuthentication=no -q $item.FullName ($RemoteHost + ":" + $RemotePath)
            } finally {
                Remove-Item -LiteralPath $askCmd -Force -ErrorAction SilentlyContinue
            }
        } else {
            & scp -q $item.FullName ($RemoteHost + ":" + $RemotePath)
        }
    }
    if ($null -ne $LASTEXITCODE -and $LASTEXITCODE -ne 0) {
        throw "scp failed exit=$LASTEXITCODE"
    }
    Write-Host "Uploaded → ${RemoteHost}:${RemotePath}" -ForegroundColor Green
    Write-Host "Restart auth-server so DRAGONITE_PAYLOAD_PATH picks up the new bytes."
    exit 0
}

Write-Host "1) Register this hash on the auth server (release registry / admin jar-hash)."
Write-Host "2) Upload payload:"
Write-Host "   scp `"$($item.FullName)`" ${RemoteHost}:${RemotePath}"
Write-Host "   Or: powershell -File ...\provision-stub-payload.ps1 -JarPath ... -Upload"
Write-Host "3) Ensure VPS .env has:"
Write-Host "   ALLOW_STUB_LOADER=true"
Write-Host "   ALLOW_STUB_HWID_RELAX=false"
Write-Host "   DRAGONITE_PAYLOAD_PATH=$RemotePath"
Write-Host "4) Restart auth-server."
Write-Host ""
Write-Host "Stub clients will download this file AES-GCM-encrypted after /v1/stub/session."
