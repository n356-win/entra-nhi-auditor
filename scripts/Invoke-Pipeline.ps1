<#
.SYNOPSIS
    Runs the whole assessment in one command, against one tenant read, into one run directory.

.DESCRIPTION
    WHY THIS EXISTS - AND WHY SCRIPT 03 STILL READS A FILE RATHER THAN THE TENANT
    ------------------------------------------------------------------------------
    The obvious question after losing an evening to a stale inventory is: why does 03 not just
    query Graph itself? It is a fair question and the answer is not "that is how it was built."

    SCRIPT 01 IS THE ONLY SCRIPT THAT TOUCHES THE TENANT. Everything after it reads the file
    01 produced. That split buys four things, and the first is the one that matters:

      1. THE FINDING IS REPRODUCIBLE. An assessment finding has to be defensible months later.
         "svc-provisioning had no human owner on 25 October" is a claim, and nhi_inventory.json is
         the evidence for it. If 03 queried live, re-running it next week would give different
         answers and NOBODY COULD TELL whether the tenant changed or the rule did. An auditor
         asking "show me the data behind this" needs an artifact, not a promise to re-query.

      2. THE CLASSIFIER NEEDS NO CREDENTIALS. 03, 04 and 05 hold no tenant access at all. The
         judgement logic can run in CI, on an analyst's laptop, or against a client's exported
         data without anyone granting it Graph permissions. For a tool whose entire argument is
         least privilege, that is not a detail.

      3. YOU CAN RE-CLASSIFY HISTORY. Change a rule, re-run 03 against last quarter's
         inventory, and diff. That is how you prove a rule change found something new rather
         than the tenant having moved. Impossible against a live tenant, by definition.

      4. POINT-IN-TIME CONSISTENCY. Reading 342 identities takes minutes, and objects change
         while you read them. A snapshot is internally consistent. A classifier streaming live
         queries can contradict itself inside one report.

    SO THE SNAPSHOT IS CORRECT. What was wrong is that nothing MADE the snapshot fresh, and
    nothing SAID when it was taken. Those are different problems with different fixes:

      - "nothing said when"  -> fixed in 03 and 05: capture timestamp, age, and a stale banner.
      - "nothing made it fresh" -> THIS SCRIPT. One command, one tenant read, one run id.

    Running the four scripts by hand and forgetting the first is not a discipline problem to be
    solved with more care. It is a missing default. The pipeline is the default now; the
    individual scripts remain for when you deliberately want to re-classify an older run.

.PARAMETER SkipAttestation
    Omit stage 04. Attestation is a QUARTERLY cycle and this pipeline is safe to run weekly -
    generating a new cycle every scan would produce attestation records nobody asked for and
    make the cadence meaningless. Off is the honest default for a routine scan; pass
    -IncludeAttestation deliberately, at quarter end.

.PARAMETER Anonymise
    Passed to 05. Replaces identity names with Identity-001 style labels. Use for anything
    that leaves your machine.

.EXAMPLE
    ./Invoke-Pipeline.ps1
    Weekly scan: 01 -> 03 -> 05, one run directory, no attestation cycle.

.EXAMPLE
    ./Invoke-Pipeline.ps1 -IncludeAttestation -Anonymise
    Quarter end: the full chain, with a publishable report.

.NOTES
    READ-ONLY. Calls no script that writes to the tenant - 99-New-LabFixture.ps1 is
    deliberately not part of this chain and never will be.
#>

[CmdletBinding()]
param(
    [switch]$IncludeAttestation,
    [switch]$Anonymise,
    [switch]$SkipSignInActivity,
    [switch]$SkipPermissions,

    # Azure RBAC for managed identities. Needs a management.azure.com token - see 01's help.
    [switch]$IncludeAzureRbac,
    [string]$ArmAccessToken
)

$ErrorActionPreference = 'Stop'

if (-not (Get-MgContext)) { throw "Not connected. Run 00-Connect-Lab.ps1 first." }

# ONE RUN ID FOR THE WHOLE CHAIN, computed once here.
#
# Each script can resolve its own run id from output/latest-run.txt, and that works fine when
# a human runs them in order within a few minutes. It is exactly what fails when they do not:
# the pointer moves, or does not, and the later scripts silently read a different run than the
# one just produced. Passing it explicitly makes the run ATOMIC BY CONSTRUCTION rather than by
# timing - the same reasoning as the GitHub workflow.
$runId  = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH-mmZ')
$scriptRoot = $PSScriptRoot
$root   = Join-Path $scriptRoot '..\output'
$runDir = Join-Path $root "runs\$runId"

Write-Host ""
Write-Host "  Run id : $runId" -ForegroundColor Cyan
Write-Host "  Tenant : $((Get-MgContext).TenantId)" -ForegroundColor DarkGray
Write-Host "  Output : $runDir" -ForegroundColor DarkGray
Write-Host ""

$started = Get-Date

# =============================================================================
# SHADOW FILES - refuse to run with stale outputs sitting at output/ root
# =============================================================================
# Added 2026-10-26, after they cost an evening.
#
# Before run compartmentalisation, the scripts wrote nhi_inventory.json and friends flat into
# output/. Those files are still there afterwards, they never update again, and they are named
# IDENTICALLY to the real outputs now written under output/runs/<RunId>/.
#
# What that produced: twelve correct pipeline runs, and every inspection reading a snapshot
# from ten days earlier - because the obvious file to open is output/nhi_inventory.json, and
# it looked completely normal. Not stale-looking. Not empty. Just old, and silently wrong by
# ten days. The diagnosis landed on "re-run 01" three separate times while 01 had been running
# correctly all along.
#
# A file that LOOKS like current output and is not is worse than a missing file, for the same
# reason an empty collection is worse than an error: nothing about it announces the problem.
#
# So the pipeline refuses to start while they exist. Not a warning - warnings scroll past, and
# this one already did. The fix is one delete and the message says exactly which files.
$shadowNames = @(
    'nhi_inventory.json', 'nhi_findings.json', 'nhi_ownership.csv', 'control_report.md',
    'attestation_records.json', 'attestation_results.json', 'attestation_report.md'
)
$shadows = @($shadowNames | ForEach-Object {
    $p = Join-Path $root $_
    if (Test-Path $p) { $p }
})

if ($shadows.Count -gt 0) {
    Write-Host ""
    Write-Host "  ##################################################################" -ForegroundColor Red
    Write-Host "  #  STALE OUTPUT FILES AT output/ ROOT" -ForegroundColor Red
    Write-Host "  ##################################################################" -ForegroundColor Red
    Write-Host ""
    foreach ($s in $shadows) {
        $age = [Math]::Round(((Get-Date) - (Get-Item $s).LastWriteTime).TotalDays, 1)
        Write-Host "    $(Split-Path $s -Leaf)  -  $age days old" -ForegroundColor Yellow
    }
    Write-Host ""
    Write-Host "  These predate run directories and will NEVER be updated again, but they are" -ForegroundColor Gray
    Write-Host "  named exactly like the real outputs now written to output/runs/<RunId>/." -ForegroundColor Gray
    Write-Host "  Opening one gives you a snapshot that looks current and is not." -ForegroundColor Gray
    Write-Host ""
    Write-Host "  Delete them, then re-run:" -ForegroundColor Cyan
    Write-Host "      Remove-Item '$root\*.json','$root\*.csv' -Exclude 'lab-fixture-manifest.json'" -ForegroundColor White
    Write-Host ""
    throw "Refusing to run while stale outputs shadow the run directories. See above."
}

function Invoke-Stage {
    <#  Runs one stage and stops the pipeline if it fails.

        No try/catch that swallows and continues. A failed stage means every later stage reads
        incomplete input, and a report built on incomplete input is worse than no report - it
        looks finished. $ErrorActionPreference = 'Stop' plus this guard means the chain either
        completes or says where it stopped.                                                  #>
    param(
        [string]$Name,
        [string]$Script,
        [Parameter(Mandatory)][hashtable]$StageParameters
    )

    Write-Host "──────────────────────────────────────────────────────────────" -ForegroundColor DarkGray
    Write-Host " $Name" -ForegroundColor White
    Write-Host "──────────────────────────────────────────────────────────────" -ForegroundColor DarkGray

    $path = Join-Path $scriptRoot $Script
    if (-not (Test-Path $path)) { throw "Missing script: $path" }

    # No $LASTEXITCODE check here, deliberately. It is set by NATIVE executables, not by
    # PowerShell scripts, so a stale value left by some earlier native call would abort a
    # perfectly good pipeline - a failure invented by the guard itself, which is precisely the
    # class of bug this project keeps finding. $ErrorActionPreference = 'Stop' plus the throw
    # inside each script is the real mechanism, and the output assertion at the end is the
    # check that the stage actually produced something.
    & $path @StageParameters

    Write-Host ""
}

# --- 01 - the only tenant read -------------------------------------------------------------
$a01 = @{ RunId = $runId }
if ($SkipSignInActivity) { $a01.SkipSignInActivity = $true }
if ($SkipPermissions)    { $a01.SkipPermissions    = $true }
if ($IncludeAzureRbac)   { $a01.IncludeAzureRbac   = $true; $a01.ArmAccessToken = $ArmAccessToken }

Invoke-Stage -Name '1/4  Inventory  (reads the tenant)' -Script '01-Get-NHIInventory.ps1' -StageParameters $a01

# --- 03 - classify -------------------------------------------------------------------------
Invoke-Stage -Name '2/4  Ownership and findings' -Script '03-New-OwnershipMap.ps1' -StageParameters @{ RunId = $runId }

# --- 04 - attestation, only when asked -----------------------------------------------------
if ($IncludeAttestation) {
    Invoke-Stage -Name '3/4  Attestation cycle' -Script '04-Invoke-AttestationCycle.ps1' `
                 -StageParameters @{ RunId = $runId; Stage = 'All'; Simulate = $true }
} else {
    Write-Host " 3/4  Attestation - SKIPPED (quarterly; pass -IncludeAttestation)" -ForegroundColor DarkGray
    Write-Host ""
}

# --- 05 - control report -------------------------------------------------------------------
$a05 = @{ RunId = $runId }
if ($Anonymise) { $a05.Anonymise = $true }
Invoke-Stage -Name '4/4  Control report' -Script '05-New-ControlReport.ps1' -StageParameters $a05

# --- Verify what was actually produced -----------------------------------------------------
# Asserted, not assumed. A pipeline that prints "complete" without checking its own outputs is
# the same failure as a control report that prints NOT APPLICABLE for a population it never
# enumerated: a confident statement about something nobody looked at.
$expected = @('nhi_inventory.json', 'nhi_ownership.csv', 'nhi_findings.json', 'control_report.md')
$missing  = @($expected | Where-Object { -not (Test-Path (Join-Path $runDir $_)) })

Write-Host "──────────────────────────────────────────────────────────────" -ForegroundColor DarkGray
if ($missing.Count -gt 0) {
    throw "Pipeline finished but these outputs are missing from $runDir : $($missing -join ', ')"
}

$elapsed = [Math]::Round(((Get-Date) - $started).TotalSeconds)
Write-Host " Complete in ${elapsed}s - every output below came from ONE tenant read." -ForegroundColor Green
Write-Host ""

# THE FULL PATH, EVERY TIME, NOT JUST THE FILE NAMES.
#
# Printing "nhi_inventory.json" and leaving the reader to find it is how the wrong copy gets
# opened. The run directory is the answer to "which one is current", so it goes on every line
# rather than once at the bottom where it is read as decoration.
foreach ($e in $expected) { Write-Host "   $runDir\$e" -ForegroundColor Gray }
if ($IncludeAttestation) { Write-Host "   $root\attestation\  (cycle)" -ForegroundColor Gray }
Write-Host ""

# Flag aborted runs. They are inventory-only directories left by a stage that failed, and they
# are the other thing that looks like a result and is not. Harmless to keep, confusing to
# mistake for the current run - so they are named rather than left to be discovered.
$aborted = @(Get-ChildItem (Join-Path $root 'runs') -Directory -ErrorAction SilentlyContinue |
             Where-Object { -not (Test-Path (Join-Path $_.FullName 'control_report.md')) })
if ($aborted.Count -gt 0) {
    Write-Host "   $($aborted.Count) incomplete run director$(if($aborted.Count -eq 1){'y'}else{'ies'}) present (no control report - a stage failed):" -ForegroundColor DarkYellow
    foreach ($a in $aborted) { Write-Host "     $($a.Name)" -ForegroundColor DarkGray }
    Write-Host "   Safe to delete. They are not this run." -ForegroundColor DarkGray
    Write-Host ""
}
