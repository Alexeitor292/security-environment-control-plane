<#
.SYNOPSIS
    Launch the standing SECP Program Lead session.

.DESCRIPTION
    Establishes the reviewed model, permission, teammate and session-name posture for the
    standing Program Lead, and fails closed before starting if the guardrail layer is not
    intact.

    AUTHORITY MODEL — read this before using the script.

    This launcher starts Claude Code with --permission-mode bypassPermissions. That removes
    ALL ordinary Claude approval prompts and grants the session FULL HOST AUTHORITY: it can
    read, write and execute anything the invoking operator can.

    The committed hooks in .claude/hooks/ remain the deterministic enforcement layer. They
    reduce ACCIDENTAL project-policy violations by agents -- force push, history rewriting,
    pushing to main, marking ready, merging, production trust-root changes, provider
    mutation, OpenTofu/Terraform apply or destroy, safety-seal changes, unauthorised
    migrations, and writes outside the active task contract.

    They are NOT an operating-system security boundary. Anything running under the
    operator's identity can edit the hooks, mint or consume unlock tokens, or start a
    session with --safe-mode or --bare, all of which disable hooks entirely. Deny-rule
    string matching is likewise evadable. Run this only in a checkout you trust.

    Effort: no --effort flag is passed. Activate Ultracode interactively once the session
    is up:  /effort ultracode

.PARAMETER SessionName
    Display name for the session (shown in the prompt box, /resume picker and title).

.PARAMETER SkipModelProbe
    Skip the live model-availability probe. The probe costs one trivial round trip.

.PARAMETER WhatIf
    Print the resolved command line and exit without launching.

.EXAMPLE
    .\scripts\program\Start-ProgramLead.ps1
#>
[CmdletBinding()]
param(
    [string] $SessionName = 'SECP Program Lead',
    [switch] $SkipModelProbe,
    [switch] $WhatIf
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$Model = 'opus[1m]'
$AgentName = 'secp-program-lead'
$PermissionMode = 'bypassPermissions'
$TeammateMode = 'in-process'

$RequiredHooks = @(
    '_common.py',
    'guard_bash.py',
    'guard_writes.py',
    'guard_migration_unlock.py',
    'record_evidence.py',
    'guard_task_completion.py',
    'guard_teammate_idle.py',
    'session_start_orient.py'
)

function Stop-FailClosed {
    param([string] $Reason)
    Write-Host ''
    Write-Host 'REFUSED: the SECP Program Lead was not started.' -ForegroundColor Red
    Write-Host "  $Reason" -ForegroundColor Red
    Write-Host ''
    exit 1
}

# ---------------------------------------------------------------------------------------
# Resolve the repository from this script's own location. No machine-specific paths are
# stored in this file.
# ---------------------------------------------------------------------------------------

$RepoRoot = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path

# --- Fail closed: the checkout must be the SECP repository -----------------------------

$pyproject = Join-Path $RepoRoot 'pyproject.toml'
$charter = Join-Path $RepoRoot 'docs\PROJECT_CHARTER.md'
if (-not (Test-Path -LiteralPath $pyproject)) {
    Stop-FailClosed "No pyproject.toml under '$RepoRoot'."
}
if (-not (Test-Path -LiteralPath $charter)) {
    Stop-FailClosed "No docs/PROJECT_CHARTER.md under '$RepoRoot'."
}
if (-not ((Get-Content -LiteralPath $pyproject -Raw) -match '(?m)^name\s*=\s*"secp"')) {
    Stop-FailClosed "'$RepoRoot' is not the SECP repository (pyproject name is not 'secp')."
}

# --- Fail closed: committed hook configuration must be present -------------------------

$settingsPath = Join-Path $RepoRoot '.claude\settings.json'
if (-not (Test-Path -LiteralPath $settingsPath)) {
    Stop-FailClosed "Committed hook configuration '.claude/settings.json' is missing."
}
try {
    $settings = Get-Content -LiteralPath $settingsPath -Raw | ConvertFrom-Json
}
catch {
    Stop-FailClosed ".claude/settings.json is not valid JSON: $($_.Exception.Message)"
}
if ($null -eq $settings.PSObject.Properties['hooks']) {
    Stop-FailClosed ".claude/settings.json declares no 'hooks' block."
}
foreach ($requiredEvent in @('PreToolUse', 'PostToolUse', 'SessionStart', 'TaskCompleted', 'TeammateIdle')) {
    if ($null -eq $settings.hooks.PSObject.Properties[$requiredEvent]) {
        Stop-FailClosed ".claude/settings.json does not wire the '$requiredEvent' hook event."
    }
}

# --- Fail closed: every required hook file must exist ----------------------------------

$hooksDir = Join-Path $RepoRoot '.claude\hooks'
foreach ($hook in $RequiredHooks) {
    if (-not (Test-Path -LiteralPath (Join-Path $hooksDir $hook))) {
        Stop-FailClosed "Required hook file '.claude/hooks/$hook' is missing."
    }
}

# --- Fail closed: bypassPermissions must not be disabled by managed configuration ------

$managedCandidates = @(
    (Join-Path $env:ProgramData 'ClaudeCode\managed-settings.json'),
    'C:\Program Files\ClaudeCode\managed-settings.json',
    '/Library/Application Support/ClaudeCode/managed-settings.json',
    '/etc/claude-code/managed-settings.json'
)
foreach ($candidate in $managedCandidates) {
    if ([string]::IsNullOrWhiteSpace($candidate)) { continue }
    if (-not (Test-Path -LiteralPath $candidate)) { continue }
    try {
        $managed = Get-Content -LiteralPath $candidate -Raw | ConvertFrom-Json
    }
    catch {
        Stop-FailClosed "Managed configuration '$candidate' is unreadable; refusing to guess its policy."
    }
    if ($null -ne $managed.PSObject.Properties['permissions']) {
        $perms = $managed.permissions
        if ($null -ne $perms.PSObject.Properties['disableBypassPermissionsMode']) {
            if ($perms.disableBypassPermissionsMode -eq 'disable') {
                Stop-FailClosed "Managed configuration '$candidate' sets permissions.disableBypassPermissionsMode = 'disable'. The standing Program Lead requires bypassPermissions and will not fall back to a prompting mode."
            }
        }
    }
}

# --- Fail closed: the claude CLI must be present ---------------------------------------

$claude = Get-Command claude -ErrorAction SilentlyContinue
if ($null -eq $claude) {
    Stop-FailClosed "The 'claude' CLI is not on PATH."
}

# --- Fail closed: the requested model must be available --------------------------------

if (-not $SkipModelProbe) {
    Write-Host "Probing model availability ($Model)..." -ForegroundColor DarkGray
    $probe = & claude --model $Model -p 'Reply with exactly: MODEL_OK' 2>&1 | Out-String
    if ($probe -match 'issue with the selected model' -or $probe -match 'may not exist') {
        Stop-FailClosed "Model '$Model' is unavailable to this account: $($probe.Trim())"
    }
    if ($probe -notmatch 'MODEL_OK') {
        Stop-FailClosed "Model probe for '$Model' did not return the expected response. Output: $($probe.Trim())"
    }
}

# ---------------------------------------------------------------------------------------
# Deterministic child-model selection.
#
# CLAUDE_CODE_SUBAGENT_MODEL is a single global override that silently supersedes every
# per-agent `model:` frontmatter and the per-invocation model parameter for all subagents
# and teammates. Set it explicitly so child posture is deterministic rather than ambient.
# ---------------------------------------------------------------------------------------

$env:CLAUDE_CODE_SUBAGENT_MODEL = $Model
Remove-Item Env:CLAUDE_CODE_DISABLE_1M_CONTEXT -ErrorAction SilentlyContinue

# ---------------------------------------------------------------------------------------
# Compose the command line.
# ---------------------------------------------------------------------------------------

$claudeArgs = @(
    '--model', $Model,
    '--permission-mode', $PermissionMode,
    '-n', $SessionName
)

# The agent definition arrives in PR 2. Passing --agent before it exists cannot resolve.
$agentDefinition = Join-Path $RepoRoot ".claude\agents\$AgentName.md"
if (Test-Path -LiteralPath $agentDefinition) {
    $claudeArgs = @('--agent', $AgentName) + $claudeArgs
}
else {
    Write-Host "NOTE: .claude/agents/$AgentName.md does not exist yet (it arrives in PR 2)." -ForegroundColor Yellow
    Write-Host '      Launching with the model/permission/teammate/name posture only.' -ForegroundColor Yellow
}

# --teammate-mode is a real but HIDDEN client flag. Tolerate its removal.
$helpText = & claude --help 2>&1 | Out-String
$teammateSupported = $true
if ($helpText -match 'unknown option') { $teammateSupported = $false }
if ($teammateSupported) {
    $claudeArgs += @('--teammate-mode', $TeammateMode)
}

Write-Host ''
Write-Host 'SECP Program Lead' -ForegroundColor Cyan
Write-Host "  repository      : $RepoRoot"
Write-Host "  model           : $Model"
Write-Host "  permission mode : $PermissionMode  (NO approval prompts; FULL HOST AUTHORITY)"
Write-Host "  hooks           : $($RequiredHooks.Count) committed guards verified present"
Write-Host ''
Write-Host '  Effort is NOT pinned at launch. Activate Ultracode interactively:' -ForegroundColor Yellow
Write-Host '      /effort ultracode' -ForegroundColor Yellow
Write-Host ''

if ($WhatIf) {
    $rendered = $claudeArgs | ForEach-Object {
        if ($_ -match '\s') { "'$_'" } else { $_ }
    }
    Write-Host "claude $($rendered -join ' ')"
    exit 0
}

Push-Location -LiteralPath $RepoRoot
try {
    & claude @claudeArgs
    exit $LASTEXITCODE
}
finally {
    Pop-Location
}
