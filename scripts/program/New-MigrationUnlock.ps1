<#
.SYNOPSIS
    Mint a single-use unlock token authorising one Alembic migration file.

.DESCRIPTION
    This is the ONLY supported way to authorise a write under
    apps/api/migrations/versions/. Agents may never create, modify, copy, rename, delete or
    self-issue a token -- the committed hooks deny any agent access to the unlock directory,
    which lives OUTSIDE the repository and is therefore never tracked by git.

    The token binds the exact repository, branch, base SHA, migration filename, approved
    purpose, issuer and expiry. Maximum TTL is 60 minutes. It is consumed atomically by
    .claude/hooks/guard_migration_unlock.py on first use, and a token for one migration can
    never authorise another migration or another branch.

    A token contains NO credentials, connection strings or secret material. The hook rejects
    any token carrying an unexpected field.

    SERIALISATION. CI cannot detect branching Alembic heads: two agents on two branches each
    writing the same down_revision produce two PRs that both pass independently, and the
    break appears only after the second merge. This script therefore refuses to mint a second
    token while an unconsumed one exists.

    WHAT THIS DOES NOT AUTHORISE. Approving a migration is not approval to change the sole
    Alembic head, to run the migration against any real database, to deploy, or to merge.
    Those remain independently denied.

    HONEST BOUNDARY. This is an agent-error guardrail, not a security boundary against a
    malicious process running under your own OS identity.

.PARAMETER MigrationFilename
    Exact basename of the migration file to authorise, e.g. 'a1b2c3d4e5f6_add_widget.py'.

.PARAMETER Purpose
    Short human-readable statement of what the migration is approved to do.

.PARAMETER TtlMinutes
    Token lifetime in minutes. Default 60; 60 is also the enforced maximum.

.PARAMETER Revoke
    Remove all outstanding tokens instead of minting one.

.EXAMPLE
    .\scripts\program\New-MigrationUnlock.ps1 -MigrationFilename 'b7c1_add_scoring.py' -Purpose 'Add scoring event table'
#>
[CmdletBinding(DefaultParameterSetName = 'Mint')]
param(
    [Parameter(Mandatory = $true, ParameterSetName = 'Mint')]
    [string] $MigrationFilename,

    [Parameter(Mandatory = $true, ParameterSetName = 'Mint')]
    [string] $Purpose,

    [Parameter(ParameterSetName = 'Mint')]
    [ValidateRange(1, 60)]
    [int] $TtlMinutes = 60,

    [Parameter(Mandatory = $true, ParameterSetName = 'Revoke')]
    [switch] $Revoke
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$MaxTtlMinutes = 60

function Stop-Refused {
    param([string] $Reason)
    Write-Host ''
    Write-Host 'REFUSED: no unlock token was issued.' -ForegroundColor Red
    Write-Host "  $Reason" -ForegroundColor Red
    Write-Host ''
    exit 1
}

function Get-UnlockDirectory {
    if (-not [string]::IsNullOrWhiteSpace($env:SECP_MIGRATION_UNLOCK_DIR)) {
        return $env:SECP_MIGRATION_UNLOCK_DIR
    }
    if (-not [string]::IsNullOrWhiteSpace($env:LOCALAPPDATA)) {
        return (Join-Path $env:LOCALAPPDATA 'secp-migration-unlock')
    }
    return (Join-Path $HOME '.local/state/secp-migration-unlock')
}

$RepoRoot = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
$pyproject = Join-Path $RepoRoot 'pyproject.toml'
if (-not (Test-Path -LiteralPath $pyproject)) {
    Stop-Refused "No pyproject.toml under '$RepoRoot'."
}
if (-not ((Get-Content -LiteralPath $pyproject -Raw) -match '(?m)^name\s*=\s*"secp"')) {
    Stop-Refused "'$RepoRoot' is not the SECP repository."
}

$unlockDir = Get-UnlockDirectory
if (-not (Test-Path -LiteralPath $unlockDir)) {
    New-Item -ItemType Directory -Path $unlockDir -Force | Out-Null
}

# The unlock directory must never be inside the repository.
$resolvedUnlock = (Resolve-Path -LiteralPath $unlockDir).Path
if ($resolvedUnlock.StartsWith($RepoRoot, [System.StringComparison]::OrdinalIgnoreCase)) {
    Stop-Refused "The unlock directory '$resolvedUnlock' is inside the repository. Tokens must live outside it."
}

if ($Revoke) {
    $removed = 0
    Get-ChildItem -LiteralPath $resolvedUnlock -Filter '*.json' -File -ErrorAction SilentlyContinue |
        ForEach-Object { Remove-Item -LiteralPath $_.FullName -Force; $removed++ }
    Write-Host "Revoked $removed outstanding unlock token(s) in $resolvedUnlock." -ForegroundColor Yellow
    exit 0
}

if ($TtlMinutes -gt $MaxTtlMinutes) {
    Stop-Refused "TTL $TtlMinutes exceeds the enforced maximum of $MaxTtlMinutes minutes."
}

# --- Serialisation: at most one outstanding token --------------------------------------

$outstanding = @(Get-ChildItem -LiteralPath $resolvedUnlock -Filter '*.json' -File -ErrorAction SilentlyContinue)
if ($outstanding.Count -gt 0) {
    $names = ($outstanding | ForEach-Object { $_.Name }) -join ', '
    Stop-Refused "$($outstanding.Count) unconsumed unlock token(s) already exist ($names). CI cannot detect branching Alembic heads, so only one live migration contract is permitted. Re-run with -Revoke once that work is merged or abandoned."
}

# --- Bind to exact repository state ----------------------------------------------------

Push-Location -LiteralPath $RepoRoot
try {
    $branch = (& git rev-parse --abbrev-ref HEAD).Trim()
    $baseSha = (& git rev-parse HEAD).Trim()
}
finally {
    Pop-Location
}

if ([string]::IsNullOrWhiteSpace($branch) -or $branch -eq 'HEAD') {
    Stop-Refused 'Could not resolve a named branch (detached HEAD?).'
}
if ($branch -eq 'main' -or $branch -eq 'master') {
    Stop-Refused "Branch is '$branch'. Migrations are authored on a feature branch, never on main."
}
if ([string]::IsNullOrWhiteSpace($baseSha)) {
    Stop-Refused 'Could not resolve HEAD.'
}

$leaf = Split-Path -Leaf $MigrationFilename
if ($leaf -ne $MigrationFilename) {
    Stop-Refused "Pass the migration BASENAME only, not a path. Received '$MigrationFilename'."
}
if ($leaf -notmatch '^[A-Za-z0-9_.-]+\.py$') {
    Stop-Refused "'$leaf' is not a valid migration filename (expected a .py basename)."
}

$issuedAt = (Get-Date).ToUniversalTime()
$expiresAt = $issuedAt.AddMinutes($TtlMinutes)
$issuer = "$env:USERNAME@$env:COMPUTERNAME"
if ([string]::IsNullOrWhiteSpace($env:USERNAME)) { $issuer = 'operator' }

$nonceBytes = New-Object 'System.Byte[]' 16
[System.Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($nonceBytes)
$nonce = -join ($nonceBytes | ForEach-Object { $_.ToString('x2') })

# Field set must match REQUIRED_FIELDS in .claude/hooks/guard_migration_unlock.py exactly.
# The hook rejects any unexpected field, which is what keeps secrets out of a token.
$token = [ordered]@{
    version            = 1
    repository         = $RepoRoot
    branch             = $branch
    base_sha           = $baseSha
    migration_filename = $leaf
    purpose            = $Purpose
    issuer             = $issuer
    issued_at          = $issuedAt.ToString('yyyy-MM-ddTHH:mm:ssZ')
    expires_at         = $expiresAt.ToString('yyyy-MM-ddTHH:mm:ssZ')
    nonce              = $nonce
}

$tokenPath = Join-Path $resolvedUnlock "unlock-$nonce.json"
# Windows PowerShell's `Out-File -Encoding utf8` emits a UTF-8 BOM, which a strict UTF-8
# JSON reader rejects. Write BOM-free UTF-8 so the token is portable.
$tokenJson = $token | ConvertTo-Json -Depth 4
[System.IO.File]::WriteAllText($tokenPath, $tokenJson, (New-Object System.Text.UTF8Encoding $false))

Write-Host ''
Write-Host 'Migration unlock token issued.' -ForegroundColor Green
Write-Host "  migration : $leaf"
Write-Host "  branch    : $branch"
Write-Host "  base SHA  : $baseSha"
Write-Host "  purpose   : $Purpose"
Write-Host "  expires   : $($token.expires_at) (TTL $TtlMinutes min, single use)"
Write-Host "  location  : $tokenPath"
Write-Host ''
Write-Host '  This authorises ONE write to ONE migration file on THIS branch.' -ForegroundColor Yellow
Write-Host '  It does NOT authorise changing the sole head, running the migration' -ForegroundColor Yellow
Write-Host '  against any database, deploying, or merging.' -ForegroundColor Yellow
Write-Host ''
