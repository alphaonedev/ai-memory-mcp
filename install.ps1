# Copyright 2026 AlphaOne LLC
# SPDX-License-Identifier: Apache-2.0
#Requires -Version 5.1
<#
.SYNOPSIS
    Install ai-memory for Windows.
.DESCRIPTION
    Downloads the latest ai-memory release, extracts it to ~/.local/bin,
    adds it to the user PATH, and verifies the installation.
.PARAMETER InsecureSkipChecksum
    Install WITHOUT verifying the SHA-256 checksum of the downloaded
    archive. This disables the only integrity control this installer has.
    Provided as a parameter - and deliberately NOT as an environment
    variable - so that bypassing verification is a per-invocation,
    reviewable decision that cannot be silently inherited by a whole fleet
    from a base image or CI environment (#2449).
.EXAMPLE
    irm https://raw.githubusercontent.com/alphaonedev/ai-memory-mcp/main/install.ps1 | iex
.EXAMPLE
    .\install.ps1 -InsecureSkipChecksum
#>
param(
    [switch]$InsecureSkipChecksum
)

$ErrorActionPreference = 'Stop'

# Every abort in the checksum gate ends here, so there is exactly ONE
# machine-readable token proving a refusal was deliberate rather than an
# unrelated crash. Mirrors install.sh's `abort_unverified`.
function Stop-UnverifiedInstall {
    Write-Host ""
    Write-Host "ai-memory: install aborted (checksum gate #2449)" -ForegroundColor Red
    exit 1
}

$Repo = "alphaonedev/ai-memory-mcp"
$Binary = "ai-memory.exe"
$InstallDir = if ($env:AI_MEMORY_INSTALL_DIR) { $env:AI_MEMORY_INSTALL_DIR } else { Join-Path $env:USERPROFILE ".local\bin" }

# Detect architecture
$Arch = [System.Runtime.InteropServices.RuntimeInformation]::OSArchitecture
switch ($Arch) {
    'X64'   { $archLabel = "x86_64" }
    'Arm64' { $archLabel = "x86_64"; Write-Host "Note: ARM64 detected, using x86_64 build (only Windows target available)." -ForegroundColor Yellow }
    default { Write-Host "Unsupported architecture: $Arch" -ForegroundColor Red; exit 1 }
}

$Target = "${archLabel}-pc-windows-msvc"
$Asset = "ai-memory-${Target}.zip"
$ReleaseUrl = "https://github.com/${Repo}/releases/latest/download/${Asset}"
$ChecksumUrl = "${ReleaseUrl}.sha256"

Write-Host "Detected platform: $Target"
Write-Host "Installing to: $InstallDir"
Write-Host ""

# Create install directory
if (-not (Test-Path $InstallDir)) {
    try {
        New-Item -ItemType Directory -Path $InstallDir -Force | Out-Null
        Write-Host "Created directory: $InstallDir"
    } catch {
        Write-Host "Error: Could not create directory '$InstallDir'. Check permissions." -ForegroundColor Red
        exit 1
    }
}

# Download to temp file
$TempDir = Join-Path ([System.IO.Path]::GetTempPath()) ("ai-memory-install-" + [System.Guid]::NewGuid().ToString("N").Substring(0, 8))
New-Item -ItemType Directory -Path $TempDir -Force | Out-Null
$ZipPath = Join-Path $TempDir $Asset

try {
    Write-Host "Downloading $Asset..."
    try {
        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
        $wc = New-Object System.Net.WebClient
        $wc.DownloadFile($ReleaseUrl, $ZipPath)
    } catch [System.Net.WebException] {
        $status = $_.Exception.Response.StatusCode.value__
        if ($status -eq 404) {
            Write-Host ""
            Write-Host "Error: Release not found (404)." -ForegroundColor Red
            Write-Host "The pre-built binary may not be available yet." -ForegroundColor Yellow
            Write-Host "Install from source instead:" -ForegroundColor Yellow
            Write-Host "  cargo install ai-memory" -ForegroundColor Cyan
            exit 1
        }
        throw
    }

    # Validate download (file size check)
    $FileSize = (Get-Item $ZipPath).Length
    if ($FileSize -lt 1024) {
        Write-Host "Error: Downloaded file is too small ($FileSize bytes). The download may be corrupt." -ForegroundColor Red
        Write-Host "Try installing from source instead:" -ForegroundColor Yellow
        Write-Host "  cargo install ai-memory" -ForegroundColor Cyan
        exit 1
    }
    Write-Host "Downloaded $([math]::Round($FileSize / 1MB, 1)) MB"

    # --- BEGIN checksum gate (#2449) -- fail CLOSED ---
    #
    # Before #2449 this script performed NO checksum verification at all -
    # it downloaded the zip, sanity-checked only that it was larger than
    # 1 KB, and extracted it. That is strictly worse than install.sh's
    # fail-open branch, which at least attempted a fetch. release.yml also
    # published no .sha256 for this zip, so there was nothing to verify
    # against even if it had tried; both halves are fixed together.
    #
    # Same rule as install.sh: a missing, unfetchable, malformed, or
    # mismatched checksum ABORTS. The bypass is a PARAMETER only, never an
    # environment variable, so it cannot be silently inherited fleet-wide
    # from a base image or CI environment.
    #
    # Scope, stated honestly: the checksum is served from the SAME origin
    # as the archive, so this proves INTEGRITY (no corruption, truncation,
    # or mirror/CDN substitution), NOT AUTHENTICITY against a compromised
    # release pipeline. Signed build provenance is tracked for v1.x.
    #
    # No hashing-tool ladder is needed here: Get-FileHash is built into
    # PowerShell 5.1, which this script already requires.
    if ($InsecureSkipChecksum) {
        Write-Host ""
        Write-Host "DANGER: checksum verification bypassed via -InsecureSkipChecksum." -ForegroundColor Red
        Write-Host "DANGER: the binary being installed is UNVERIFIED." -ForegroundColor Red
        Write-Host ""
    } else {
        Write-Host "Verifying checksum..."
        $ChecksumPath = Join-Path $TempDir "$Asset.sha256"
        try {
            $wcSum = New-Object System.Net.WebClient
            $wcSum.DownloadFile($ChecksumUrl, $ChecksumPath)
        } catch {
            Write-Host "Error: could not download the SHA-256 checksum for $Asset" -ForegroundColor Red
            Write-Host "  $ChecksumUrl" -ForegroundColor Red
            Write-Host ""
            Write-Host "Refusing to install an unverified binary." -ForegroundColor Red
            Write-Host "Releases cut before v1.0.0 may not publish a .sha256 asset." -ForegroundColor Yellow
            Write-Host "Options:" -ForegroundColor Yellow
            Write-Host "  - build from source:  cargo install ai-memory" -ForegroundColor Cyan
            Write-Host "  - accept the risk explicitly:  .\install.ps1 -InsecureSkipChecksum" -ForegroundColor Cyan
            Stop-UnverifiedInstall
        }

        # A 200-response carrying a garbage body (captive portal, proxy
        # error page, truncated transfer) must never be mistaken for a
        # checksum, so the digest shape is validated rather than assumed.
        $FirstLine = Get-Content -Path $ChecksumPath -TotalCount 1 -ErrorAction SilentlyContinue
        $ExpectedHash = ''
        if ($FirstLine) { $ExpectedHash = (($FirstLine -split '\s+') | Select-Object -First 1).ToLower() }
        if ($ExpectedHash -notmatch '^[0-9a-f]{64}$') {
            Write-Host "Error: the checksum file at" -ForegroundColor Red
            Write-Host "  $ChecksumUrl" -ForegroundColor Red
            Write-Host "does not contain a valid SHA-256 digest." -ForegroundColor Red
            Write-Host ""
            Write-Host "Refusing to install an unverified binary." -ForegroundColor Red
            Stop-UnverifiedInstall
        }

        $ActualHash = (Get-FileHash -Algorithm SHA256 -Path $ZipPath).Hash.ToLower()
        if ($ActualHash -notmatch '^[0-9a-f]{64}$') {
            Write-Host "Error: could not compute a SHA-256 digest of $Asset." -ForegroundColor Red
            Write-Host ""
            Write-Host "Refusing to install an unverified binary." -ForegroundColor Red
            Stop-UnverifiedInstall
        }

        if ($ExpectedHash -ne $ActualHash) {
            Write-Host "Error: CHECKSUM MISMATCH -- refusing to install $Asset." -ForegroundColor Red
            Write-Host "  Expected: $ExpectedHash" -ForegroundColor Red
            Write-Host "  Actual:   $ActualHash" -ForegroundColor Red
            Write-Host ""
            Write-Host "The download is corrupt or has been tampered with." -ForegroundColor Red
            Write-Host "Do NOT run the downloaded file. Re-run the installer; if the" -ForegroundColor Yellow
            Write-Host "mismatch persists, report it at" -ForegroundColor Yellow
            Write-Host "  https://github.com/${Repo}/issues" -ForegroundColor Cyan
            Stop-UnverifiedInstall
        }

        Write-Host "Checksum OK: $ActualHash" -ForegroundColor Green
    }
    # --- END checksum gate (#2449) ---

    # Extract
    Write-Host "Extracting..."
    $ExtractDir = Join-Path $TempDir "extracted"
    Expand-Archive -Path $ZipPath -DestinationPath $ExtractDir -Force

    # Find and copy binary
    $BinarySrc = Get-ChildItem -Path $ExtractDir -Filter $Binary -Recurse | Select-Object -First 1
    if (-not $BinarySrc) {
        Write-Host "Error: Could not find $Binary in the archive." -ForegroundColor Red
        exit 1
    }

    try {
        Copy-Item -Path $BinarySrc.FullName -Destination (Join-Path $InstallDir $Binary) -Force
    } catch {
        Write-Host "Error: Could not copy binary to '$InstallDir'. Check permissions." -ForegroundColor Red
        Write-Host "You may need to close any running ai-memory processes first." -ForegroundColor Yellow
        exit 1
    }

    Write-Host ""
    Write-Host "Installed $Binary to $InstallDir" -ForegroundColor Green

    # Add to user PATH if not already present
    $UserPath = [Environment]::GetEnvironmentVariable("Path", "User")
    if ($UserPath -split ";" -notcontains $InstallDir) {
        try {
            [Environment]::SetEnvironmentVariable("Path", "$UserPath;$InstallDir", "User")
            $env:Path = "$env:Path;$InstallDir"
            Write-Host "Added $InstallDir to user PATH."
            Write-Host "Note: Restart your terminal for PATH changes to take effect in new sessions." -ForegroundColor Yellow
        } catch {
            Write-Host "Warning: Could not update PATH automatically." -ForegroundColor Yellow
            Write-Host "Add this directory to your PATH manually: $InstallDir" -ForegroundColor Yellow
        }
    } else {
        Write-Host "$InstallDir is already in PATH."
    }

    # Verify installation
    Write-Host ""
    $BinaryPath = Join-Path $InstallDir $Binary
    try {
        $output = & $BinaryPath stats 2>&1
        if ($LASTEXITCODE -eq 0) {
            Write-Host "Verification passed: ai-memory is working." -ForegroundColor Green
        } else {
            Write-Host "Warning: ai-memory exited with code $LASTEXITCODE (this is OK for first run)." -ForegroundColor Yellow
        }
    } catch {
        Write-Host "Warning: Could not verify installation. The binary may still work." -ForegroundColor Yellow
    }

    # Success message
    Write-Host ""
    Write-Host "========================================" -ForegroundColor Cyan
    Write-Host "  ai-memory installed successfully!" -ForegroundColor Cyan
    Write-Host "========================================" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "Next steps:"
    Write-Host "  1. Restart your terminal (for PATH update)"
    Write-Host "  2. Run:  ai-memory --help"
    Write-Host "  3. Configure your AI client's MCP settings:"
    Write-Host ""
    Write-Host '     {' -ForegroundColor Gray
    Write-Host '       "mcpServers": {' -ForegroundColor Gray
    Write-Host '         "memory": {' -ForegroundColor Gray
    Write-Host '           "command": "ai-memory",' -ForegroundColor Gray
    Write-Host '           "args": ["mcp", "--tier", "smart"]' -ForegroundColor Gray
    Write-Host '         }' -ForegroundColor Gray
    Write-Host '       }' -ForegroundColor Gray
    Write-Host '     }' -ForegroundColor Gray
    Write-Host ""

} finally {
    # Cleanup temp directory
    Remove-Item -Path $TempDir -Recurse -Force -ErrorAction SilentlyContinue
}
