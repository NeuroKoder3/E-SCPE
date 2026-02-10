Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$root = Split-Path -Parent $MyInvocation.MyCommand.Path
$dist = Join-Path $root "dist"
$winuiProj = Join-Path $root "winui\EscpeWinUI.csproj"
$testProj = Join-Path $root "winui.tests\EscpeWinUI.Tests.csproj"
$publishDir = Join-Path $root "winui\bin\Release\net8.0-windows10.0.19041.0"

# Optional: set to your Authenticode certificate thumbprint.
# Example: $env:ESCPE_SIGN_THUMBPRINT = "ABC123..."
$signThumbprint = $env:ESCPE_SIGN_THUMBPRINT
$timestampUrl = "http://timestamp.digicert.com"

Write-Host "== E-SCPE build script =="
New-Item -ItemType Directory -Force -Path $dist | Out-Null

# -----------------------------------------------
# Step 1: Rust tests
# -----------------------------------------------
Write-Host "1) cargo test"
& cargo test
if ($LASTEXITCODE -ne 0) { throw "cargo test failed" }

# -----------------------------------------------
# Step 2: Dependency audit (cargo-deny)
# -----------------------------------------------
Write-Host "2) cargo deny check (supply-chain audit)"
$denyInstalled = Get-Command cargo-deny -ErrorAction SilentlyContinue
if ($denyInstalled) {
    & cargo deny check 2>&1
    if ($LASTEXITCODE -ne 0) {
        Write-Warning "cargo deny check reported issues (non-fatal for build)"
    }
} else {
    Write-Warning "cargo-deny not installed -- skipping supply-chain audit. Install with: cargo install cargo-deny"
}

# -----------------------------------------------
# Step 3: Rust release build
# -----------------------------------------------
Write-Host "3) cargo build --release"
& cargo build --release
if ($LASTEXITCODE -ne 0) { throw "cargo build failed" }

# -----------------------------------------------
# Step 4: SBOM generation
# -----------------------------------------------
Write-Host "4) generate SBOM (CycloneDX)"
$cdxInstalled = Get-Command cargo-cyclonedx -ErrorAction SilentlyContinue
if ($cdxInstalled) {
    & cargo cyclonedx --format json --output-file (Join-Path $dist "sbom.cdx.json") 2>&1
} else {
    Write-Warning "cargo-cyclonedx not installed -- skipping SBOM. Install with: cargo install cargo-cyclonedx"
}

# -----------------------------------------------
# Step 5: C# tests
# -----------------------------------------------
Write-Host "5) dotnet test (C# unit tests)"
& dotnet test $testProj -c Release --no-restore
if ($LASTEXITCODE -ne 0) { throw "dotnet test failed" }

# -----------------------------------------------
# Step 6: WinUI build + publish
# -----------------------------------------------
Write-Host "6) dotnet build (WinUI)"
& dotnet build $winuiProj -c Release
if ($LASTEXITCODE -ne 0) { throw "dotnet build failed" }

Write-Host "7) dotnet publish (WinUI)"
& dotnet publish $winuiProj -c Release -r win-x64 --self-contained true -p:PublishDir="$publishDir\"
if ($LASTEXITCODE -ne 0) { throw "dotnet publish failed" }

# -----------------------------------------------
# Step 7: Code signing (optional, requires cert)
# -----------------------------------------------
if ($signThumbprint) {
    Write-Host "8) Authenticode signing binaries"
    $binariesToSign = @(
        (Join-Path $root "target\release\escpe.exe"),
        (Join-Path $root "target\release\escpe_core.dll"),
        (Join-Path $publishDir "EscpeWinUI.exe")
    )
    foreach ($bin in $binariesToSign) {
        if (Test-Path $bin) {
            Write-Host "   Signing $bin"
            & signtool sign /sha1 $signThumbprint /fd sha256 /tr $timestampUrl /td sha256 $bin
            if ($LASTEXITCODE -ne 0) { throw "signtool failed for $bin" }
        } else {
            Write-Warning "   Binary not found: $bin"
        }
    }
} else {
    Write-Warning "8) Skipping code signing (ESCPE_SIGN_THUMBPRINT not set)"
}

# -----------------------------------------------
# Step 8: Build MSI installer
# -----------------------------------------------
Write-Host "9) build MSI (WiX v4)"
$msiPath = Join-Path $dist "E-SCPE.msi"
$wixInstalled = Get-Command wix -ErrorAction SilentlyContinue
if ($wixInstalled) {
    & wix build (Join-Path $root "installer\main.wxs") -bindpath $publishDir -o $msiPath
    if ($LASTEXITCODE -ne 0) { throw "WiX build failed" }

    # Sign the MSI if certificate is available
    if ($signThumbprint -and (Test-Path $msiPath)) {
        Write-Host "   Signing MSI"
        & signtool sign /sha1 $signThumbprint /fd sha256 /tr $timestampUrl /td sha256 $msiPath
    }
} else {
    Write-Warning "WiX v4 toolset not installed -- skipping MSI build"
}

# -----------------------------------------------
# Step 9: Collect artifacts
# -----------------------------------------------
Write-Host "10) collect artifacts"
Copy-Item (Join-Path $root "target\release\escpe.exe") $dist -Force
Copy-Item (Join-Path $root "target\release\escpe_core.dll") $dist -Force
if (Test-Path (Join-Path $publishDir "EscpeWinUI.exe")) {
    Copy-Item (Join-Path $publishDir "EscpeWinUI.exe") $dist -Force
}

Write-Host ""
Write-Host "=== Build complete ==="
Write-Host "Artifacts written to $dist"
Write-Host ""
if (-not $signThumbprint) {
    Write-Warning "IMPORTANT: Binaries are NOT code-signed. Set ESCPE_SIGN_THUMBPRINT for production."
}
