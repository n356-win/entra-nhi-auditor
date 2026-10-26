<#
.SYNOPSIS
    Builds a deliberately imperfect ownership distribution in the lab tenant, so that every
    ownership rule fires and the attestation cycle has real people to address.

.DESCRIPTION
    THIS IS A TEST FIXTURE. It is the only script in this repository that WRITES to the
    tenant, and that is a boundary worth stating loudly rather than discovering later.

    THE PROBLEM IT SOLVES
    ---------------------
    Every tenant-owned identity in the lab currently reports NO_OWNER. That is a real finding,
    but it makes two things impossible:

      - The attestation cycle has nobody to send a request to. Script 04 generates records
        addressed to no one, and the 70/10/20 response simulation is meaningless because
        there is no owner whose behaviour is being simulated.
      - Only ONE ownership rule ever fires. ORPHANED_OWNER, NO_HUMAN_OWNER and the
        two-owner requirement for privileged identities are never exercised, so they have
        never been proven to work.

    THE MISTAKE TO AVOID
    --------------------
    Assigning a valid owner to everything. That makes the report clean, proves nothing, and
    removes the finding the tool exists to produce. A demo tenant with no findings demonstrates
    a tool that cannot find anything.

    WHAT THIS DOES INSTEAD
    ----------------------
    Builds the distribution a REAL estate has a year into a governance programme - mostly
    owned, some owned badly, some not at all:

      Active human owner           the clean case. Attestation gets a reply.
      Two active human owners      meets the policy's minimum for privileged identities
      DEPARTED human owner         disabled account -> ORPHANED_OWNER, Critical
      Group as owner               -> NO_HUMAN_OWNER. Ask a group, nobody answers.
      Service principal as owner   -> NO_HUMAN_OWNER. The appearance of accountability.
      No owner at all              -> NO_OWNER, High

    Every ownership rule fires. The attestation population is realistic. And the report tells
    a story rather than printing one finding fifteen times.

    WHY THE DEPARTED OWNER MATTERS MOST
    -----------------------------------
    ORPHANED_OWNER is the Critical finding and the one that lands hardest in a conversation,
    because it is worse than having no owner: the identity PASSED every previous review, so it
    has accumulated trust that nobody is holding any more. You cannot produce it without a
    disabled user, and creating one takes two minutes.

.PARAMETER WhatIf
    Show the plan without touching anything. RUN THIS FIRST. Always.

.PARAMETER Confirm
    Required to make any change. There is no default-on path.

.PARAMETER Revert
    Remove every owner assignment and user this script created, using the manifest it wrote.

.NOTES
    PERMISSIONS - AND WHY THIS SCRIPT CAN NEVER RUN IN THE PIPELINE
    ---------------------------------------------------------------
    To create users and assign owners this needs:

        User.ReadWrite.All           create fixture users (NOT needed if you pass -*OwnerUpn)
        Application.ReadWrite.All    assign owners to service principals
        Directory.ReadWrite.All      directory object writes
        Group.ReadWrite.All          ONLY for the GroupOwner bucket - see below

    GROUP.READWRITE.ALL IS OPTIONAL AND WAS MISSING FROM THIS LIST UNTIL 2026-10-25.
    The first real run failed on it:

        New-MgGroup_CreateExpanded: Insufficient privileges to complete the operation.
        Status: 403 (Forbidden) ErrorCode: Authorization_RequestDenied

    Directory.ReadWrite.All does not reliably cover group creation. Without this scope the
    GroupOwner bucket is SKIPPED with a warning and the rest of the fixture still builds -
    those identities simply stay unowned and report NO_OWNER rather than NO_HUMAN_OWNER.
    Pass -GroupOwnerId with an existing group to exercise the bucket without the scope.

    Application.ReadWrite.All AND Directory.ReadWrite.All ARE BOTH IN THE ESCALATION SET that
    03-New-OwnershipMap.ps1 reports as Critical. Application.ReadWrite.All can add credentials
    to any app registration in the tenant, including privileged ones.

    So this script needs exactly the permissions the scanner must never hold. That is not an
    awkward exception - it is the boundary the whole project argues for, made concrete:

        THE AUDITOR STAYS READ-ONLY. REMEDIATION RUNS UNDER A HUMAN WITH PIM ACTIVATION.

    Therefore:
      - Run it interactively, as yourself, with PIM activated.
      - NEVER give these permissions to the scanner's app registration.
      - NEVER call it from 00b-Connect-Pipeline.ps1 or any workflow.
      - Deactivate PIM when you are done.

    LAB TENANTS ONLY. This creates users and rewrites ownership. Running it anywhere that
    matters would be a serious incident, which is why nothing here is implicit.

    UNRUN. Like everything else in this folder.
#>

[CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
param(
    [string]$InventoryPath,
    [string]$ManifestPath = (Join-Path $PSScriptRoot '..\output\lab-fixture-manifest.json'),
    [string]$DomainSuffix,
    [switch]$Revert,

    # ---------------------------------------------------------------------------------------
    # USE ACCOUNTS YOU ALREADY HAVE, instead of creating fixture users.
    # ---------------------------------------------------------------------------------------
    # Added because it is the better path when the tenant already contains real enabled and
    # disabled accounts, and because it removes the only part of this script that creates
    # people.
    #
    # The DEPARTED owner is the one that matters: ORPHANED_OWNER only fires on a genuinely
    # DISABLED account. A real disabled account produces a real finding; a fixture user you
    # disabled thirty seconds ago produces the same row with less meaning behind it.
    #
    # Pass any subset. Anything not supplied is created as a fixture user instead, so the
    # script still works end to end on an empty tenant.
    [string]$ActiveOwnerUpn,
    [string]$DepartedOwnerUpn,
    [string]$SecondOwnerUpn,

    # Reuse an existing group / service principal for the NO_HUMAN_OWNER buckets rather than
    # creating a group. Same reasoning.
    [string]$GroupOwnerId,
    [string]$SpOwnerId,

    # Cap how many identities are touched. A lab tenant has a few hundred service principals
    # and almost all of them are Microsoft first-party, which this never touches - but a cap
    # makes a mistake small and is worth having on the one script that writes.
    [int]$MaxTargets = 40
)

$ErrorActionPreference = 'Stop'

# =============================================================================
# GUARD - refuse to run without an explicit, deliberate confirmation
# =============================================================================
if (-not (Get-MgContext)) { throw "Not connected. Run 00-Connect-Lab.ps1 first." }

$ctx = Get-MgContext
Write-Host ""
Write-Host "  ######################################################################" -ForegroundColor Yellow
Write-Host "  #  THIS SCRIPT WRITES TO TENANT $($ctx.TenantId)" -ForegroundColor Yellow
Write-Host "  #  It creates users and changes ownership. LAB TENANTS ONLY." -ForegroundColor Yellow
Write-Host "  ######################################################################" -ForegroundColor Yellow
Write-Host ""

# Verify the connection actually holds write scopes, and say so out loud. A reader should see
# the privilege being used, not discover it from a failure three calls in.
$writeScopes = @($ctx.Scopes | Where-Object { $_ -match 'ReadWrite' })
if ($writeScopes) {
    Write-Warning "Session holds write scopes: $($writeScopes -join ', ')"
    Write-Warning "These are escalation-class permissions. Deactivate PIM when you finish."
}


# =============================================================================
# THE PLAN - declarative, so the distribution is visible before anything runs
# =============================================================================
# Proportions, not counts, so this scales to whatever the tenant actually holds. The shape is
# what matters: mostly owned, some owned badly, some not at all.
$plan = @(
    @{ Bucket='ActiveOwner';    Share=0.35; Produces='Clean - attestation gets a reply' }
    @{ Bucket='TwoOwners';      Share=0.10; Produces='Clean - meets the 2-owner rule for privileged identities' }
    @{ Bucket='DepartedOwner';  Share=0.20; Produces='ORPHANED_OWNER (Critical) - the finding that lands' }
    @{ Bucket='GroupOwner';     Share=0.15; Produces='NO_HUMAN_OWNER - ask a group, nobody answers' }
    @{ Bucket='SpOwner';        Share=0.05; Produces='NO_HUMAN_OWNER - the appearance of accountability' }
    @{ Bucket='NoOwner';        Share=0.15; Produces='NO_OWNER (High) - left deliberately untouched' }
)

Write-Host "Planned ownership distribution:" -ForegroundColor Cyan
foreach ($p in $plan) {
    Write-Host ("  {0,-14} {1,5:P0}  {2}" -f $p.Bucket, $p.Share, $p.Produces)
}
Write-Host ""


# =============================================================================
# THE FIXTURE USERS
# =============================================================================
# Three people, because three states are needed. Named so that anyone opening the tenant in
# six months can see instantly that they are synthetic - a fixture user mistaken for a real
# employee is its own small incident.
$fixtureUsers = @(
    @{ Nick='lab-owner-active';   Display='LAB FIXTURE - Active Owner';   Enabled=$true  }
    @{ Nick='lab-owner-departed'; Display='LAB FIXTURE - Departed Owner'; Enabled=$false }
    @{ Nick='lab-owner-second';   Display='LAB FIXTURE - Second Owner';   Enabled=$true  }
)

if (-not $DomainSuffix) {
    # Use the tenant's initial domain - always present, always routable internally.
    $DomainSuffix = (Get-MgOrganization).VerifiedDomains |
                    Where-Object IsInitial | Select-Object -First 1 -ExpandProperty Name
    if (-not $DomainSuffix) { throw "Could not determine a domain. Pass -DomainSuffix." }
}

Write-Host "Fixture users will be created under @$DomainSuffix" -ForegroundColor DarkGray
Write-Host ""


# =============================================================================
# REVERT
# =============================================================================
# Written BEFORE the create path, deliberately. A fixture you cannot remove is not a fixture,
# it is damage - and the manifest is what makes removal possible, so it is written as the
# changes happen rather than at the end where a failure would strand them.
if ($Revert) {
    if (-not (Test-Path $ManifestPath)) { throw "No manifest at $ManifestPath. Nothing to revert." }

    $manifest = Get-Content $ManifestPath -Raw | ConvertFrom-Json
    Write-Host "Reverting $($manifest.OwnerAssignments.Count) owner assignment(s) and $($manifest.Users.Count) user(s)..." -ForegroundColor Cyan

    foreach ($a in $manifest.OwnerAssignments) {
        if ($PSCmdlet.ShouldProcess($a.TargetName, "Remove owner $($a.OwnerId)")) {
            try {
                Remove-MgServicePrincipalOwnerByRef -ServicePrincipalId $a.TargetId -DirectoryObjectId $a.OwnerId -ErrorAction Stop
            } catch {
                Write-Warning "  Could not remove owner from $($a.TargetName): $($_.Exception.Message)"
            }
        }
    }

    # ONLY accounts this script created are listed in the manifest. An account passed in via
    # -ActiveOwnerUpn and friends is never recorded there, so a revert can never delete one of
    # your real users - that asymmetry is deliberate and is the reason the create path
    # distinguishes the two.
    foreach ($u in $manifest.Users) {
        if ($PSCmdlet.ShouldProcess($u.DisplayName, 'Delete fixture user')) {
            try { Remove-MgUser -UserId $u.Id -ErrorAction Stop }
            catch { Write-Warning "  Could not delete $($u.DisplayName): $($_.Exception.Message)" }
        }
    }

    # Groups the fixture created. Guarded on the property existing so a manifest written by an
    # earlier version of this script still reverts cleanly instead of throwing.
    if ($manifest.PSObject.Properties['Groups']) {
        foreach ($g in @($manifest.Groups)) {
            if ($PSCmdlet.ShouldProcess($g.DisplayName, 'Delete fixture group')) {
                try { Remove-MgGroup -GroupId $g.Id -ErrorAction Stop }
                catch { Write-Warning "  Could not delete $($g.DisplayName): $($_.Exception.Message)" }
            }
        }
    }

    Remove-Item $ManifestPath -Force
    Write-Host "Reverted. Re-run 01 and 03 to confirm the tenant is back to NO_OWNER everywhere." -ForegroundColor Green
    return
}


# =============================================================================
# CREATE
# =============================================================================
# The first failure you hit running this belongs in TROUBLESHOOTING.md. This is the only
# script in the repo that writes to a directory, and a write failing for a scope reason
# teaches more than the twenty reads that worked.

# --- The manifest, written incrementally ---------------------------------------------------
# Built as a live object and flushed to disk after EVERY change, not at the end. A crash
# halfway through must still leave something the -Revert path can undo; a manifest written
# last is a manifest that does not exist at the moment you need it most.
$manifest = @{
    CreatedUtc       = (Get-Date).ToUniversalTime().ToString('o')
    TenantId         = $ctx.TenantId
    Plan             = $null      # filled once the target set is resolved - see Plan provenance
    Users            = [System.Collections.Generic.List[object]]::new()
    Groups           = [System.Collections.Generic.List[object]]::new()
    OwnerAssignments = [System.Collections.Generic.List[object]]::new()
}

$manifestDir = Split-Path $ManifestPath -Parent
if (-not (Test-Path $manifestDir)) { New-Item -ItemType Directory -Path $manifestDir -Force | Out-Null }

# =============================================================================
# LOAD AN EXISTING MANIFEST AND APPEND TO IT - never start a fresh one over the top
# =============================================================================
# Found 2026-10-25 before it did any damage, while working out whether a second run was safe.
# IT WAS NOT.
#
# Save-Manifest does Set-Content, and $manifest was rebuilt empty at the top of every run. So
# a second run - to add -GroupOwnerId, say, or to top up a bucket - would have OVERWRITTEN the
# manifest recording the first run's 12 owner assignments. Those assignments would still exist
# in the tenant, and -Revert would no longer know about a single one of them.
#
# A fixture you cannot fully remove is not a fixture, it is damage. That sentence is already
# in this file's header, written before the create path existed, and the create path broke it
# on the second invocation.
#
# Prior entries are loaded and appended to. The assignment loop is already idempotent, so a
# re-run adds only what is genuinely new and the manifest stays the complete record of
# everything this script has ever changed in the tenant.
if (Test-Path $ManifestPath) {
    try {
        $prior = Get-Content $ManifestPath -Raw | ConvertFrom-Json

        foreach ($u in @($prior.Users))            { if ($u) { $manifest.Users.Add($u) } }
        foreach ($g in @($prior.Groups))           { if ($g) { $manifest.Groups.Add($g) } }
        foreach ($a in @($prior.OwnerAssignments)) { if ($a) { $manifest.OwnerAssignments.Add($a) } }

        # Keep the ORIGINAL creation timestamp. It marks when the tenant was first modified,
        # which is the question anyone auditing this later actually asks.
        if ($prior.CreatedUtc) { $manifest.CreatedUtc = $prior.CreatedUtc }

        Write-Host "Existing manifest loaded: $($manifest.OwnerAssignments.Count) prior assignment(s), $($manifest.Users.Count) prior user(s)." -ForegroundColor DarkGray
        Write-Host "This run APPENDS to it. Nothing already recorded will be lost." -ForegroundColor DarkGray
        Write-Host ""
    }
    catch {
        # Refuse rather than overwrite. An unreadable manifest may still be the only record of
        # what was changed, and clobbering it is unrecoverable.
        throw ("Found a manifest at $ManifestPath that could not be parsed: $($_.Exception.Message). " +
               "Move it aside manually before re-running - overwriting it would strand any owner " +
               "assignments it records.")
    }
}

function Save-Manifest {
    # Converted through a plain hashtable so the Lists serialise as JSON arrays. Depth 6
    # because the assignment records nest one level.
    $snapshot = @{
        CreatedUtc       = $manifest.CreatedUtc
        TenantId         = $manifest.TenantId
        Plan             = $manifest.Plan
        Users            = @($manifest.Users)
        Groups           = @($manifest.Groups)
        OwnerAssignments = @($manifest.OwnerAssignments)
    }
    $snapshot | ConvertTo-Json -Depth 6 | Set-Content $ManifestPath -Encoding UTF8
}


# --- Resolve the owner principals ----------------------------------------------------------
function Resolve-OrCreateUser {
    <#  Returns an object with Id/DisplayName/Upn for one owner role.

        Prefers an account the operator named. Creates a fixture user only when none was
        supplied - and records it in the manifest so -Revert can delete it. An account the
        operator passed in is NEVER added to the manifest's Users list, because reverting must
        not delete a real person.                                                            #>
    param(
        [string]$Upn,          # existing account, if the operator named one
        [hashtable]$Fixture,   # the fixture definition to fall back to
        [string]$Role
    )

    if ($Upn) {
        $existing = Get-MgUser -Filter "userPrincipalName eq '$Upn'" -Property 'id,displayName,userPrincipalName,accountEnabled' -ErrorAction SilentlyContinue |
                    Select-Object -First 1
        if (-not $existing) { throw "No user found with UPN '$Upn' (role: $Role)." }

        # The departed role is the whole reason ORPHANED_OWNER exists. An ENABLED account in
        # that slot silently produces no finding, and the run looks like it worked.
        if ($Role -eq 'DepartedOwner' -and $existing.AccountEnabled) {
            Write-Warning "  '$Upn' is ENABLED but was passed as the departed owner."
            Write-Warning "  ORPHANED_OWNER requires a DISABLED account and will NOT fire. Disable it, or pass a different account."
        }
        if ($Role -ne 'DepartedOwner' -and -not $existing.AccountEnabled) {
            Write-Warning "  '$Upn' is DISABLED but was passed as '$Role'. Attestation responses from it will simulate as No Response."
        }

        Write-Host "  $Role -> existing user $($existing.UserPrincipalName)" -ForegroundColor DarkGray
        return [pscustomobject]@{ Id = $existing.Id; DisplayName = $existing.DisplayName; Upn = $existing.UserPrincipalName; Created = $false }
    }

    $upnNew = "$($Fixture.Nick)@$DomainSuffix"

    # Idempotent: a re-run after a partial failure must not fail on "user already exists".
    $already = Get-MgUser -Filter "userPrincipalName eq '$upnNew'" -Property 'id,displayName,userPrincipalName' -ErrorAction SilentlyContinue |
               Select-Object -First 1
    if ($already) {
        Write-Host "  $Role -> reusing existing fixture user $upnNew" -ForegroundColor DarkGray
        $manifest.Users.Add(@{ Id = $already.Id; DisplayName = $already.DisplayName; Upn = $upnNew }); Save-Manifest
        return [pscustomobject]@{ Id = $already.Id; DisplayName = $already.DisplayName; Upn = $upnNew; Created = $true }
    }

    if (-not $PSCmdlet.ShouldProcess($upnNew, "Create fixture user (enabled=$($Fixture.Enabled))")) {
        return [pscustomobject]@{ Id = "WHATIF-$($Fixture.Nick)"; DisplayName = $Fixture.Display; Upn = $upnNew; Created = $false }
    }

    # Random password, never printed and never stored. Nobody signs in as these accounts -
    # they exist to be pointed at. A fixture password in a manifest would be a real finding
    # in a tool that reports on credential hygiene.
    $pw = [System.Guid]::NewGuid().ToString('N') + '!Aa9'

    $new = New-MgUser -DisplayName $Fixture.Display `
                      -MailNickname $Fixture.Nick `
                      -UserPrincipalName $upnNew `
                      -AccountEnabled:$Fixture.Enabled `
                      -PasswordProfile @{ Password = $pw; ForceChangePasswordNextSignIn = $true } `
                      -ErrorAction Stop

    Write-Host "  $Role -> created $upnNew (enabled=$($Fixture.Enabled))" -ForegroundColor Green
    $manifest.Users.Add(@{ Id = $new.Id; DisplayName = $Fixture.Display; Upn = $upnNew }); Save-Manifest

    return [pscustomobject]@{ Id = $new.Id; DisplayName = $Fixture.Display; Upn = $upnNew; Created = $true }
}

Write-Host "Resolving owner principals..." -ForegroundColor Cyan

$ownerActive   = Resolve-OrCreateUser -Upn $ActiveOwnerUpn   -Fixture $fixtureUsers[0] -Role 'ActiveOwner'
$ownerDeparted = Resolve-OrCreateUser -Upn $DepartedOwnerUpn -Fixture $fixtureUsers[1] -Role 'DepartedOwner'
$ownerSecond   = Resolve-OrCreateUser -Upn $SecondOwnerUpn   -Fixture $fixtureUsers[2] -Role 'SecondOwner'

# --- Group owner -----------------------------------------------------------------------
# A group as owner is the NO_HUMAN_OWNER case that looks fine on a dashboard: the ownership
# field is populated, and an attestation addressed to it reaches nobody in particular.
$ownerGroupId = $GroupOwnerId
if (-not $ownerGroupId) {
    $gName = 'LAB FIXTURE - Owning Group'
    $g = Get-MgGroup -Filter "displayName eq '$gName'" -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($g) {
        $ownerGroupId = $g.Id
        Write-Host "  GroupOwner -> reusing $gName" -ForegroundColor DarkGray
    }
    elseif ($PSCmdlet.ShouldProcess($gName, 'Create fixture group')) {
        # NON-FATAL. Fixed 2026-10-25 after the first real run.
        #
        # This was -ErrorAction Stop under a script-wide $ErrorActionPreference = 'Stop', so a
        # 403 on group creation ABORTED THE ENTIRE FIXTURE:
        #
        #     New-MgGroup_CreateExpanded: Insufficient privileges to complete the operation.
        #     Status: 403 (Forbidden) ErrorCode: Authorization_RequestDenied
        #     => 0 owner assignment(s), 0 created user(s)
        #
        # Two mistakes, and the first one is mine: the NOTES block lists the permissions this
        # script needs and I added group creation WITHOUT adding Group.ReadWrite.All to it.
        # Directory.ReadWrite.All does not reliably cover group creation.
        #
        # The second is the design error worth keeping: the GROUP OWNER BUCKET IS 15% OF THE
        # FIXTURE, and its failure took the other 85% with it. A sub-step that serves one
        # bucket must degrade to skipping that bucket, never abort the run - the same
        # "necessary vs sufficient" distinction the control map makes about testability.
        try {
            $g = New-MgGroup -DisplayName $gName -MailNickname 'lab-fixture-owners' `
                             -MailEnabled:$false -SecurityEnabled:$true -ErrorAction Stop
            $ownerGroupId = $g.Id
            Write-Host "  GroupOwner -> created $gName" -ForegroundColor Green
            $manifest.Groups.Add(@{ Id = $g.Id; DisplayName = $gName }); Save-Manifest
        }
        catch {
            Write-Warning "  GroupOwner -> could NOT create the fixture group: $($_.Exception.Message)"
            Write-Warning "  Needs Group.ReadWrite.All. The GroupOwner bucket will be SKIPPED;"
            Write-Warning "  those identities stay unowned and report NO_OWNER instead of NO_HUMAN_OWNER."
            Write-Warning "  Re-run 00-Connect-Lab.ps1 with Group.ReadWrite.All, or pass -GroupOwnerId <existing group>."
            $ownerGroupId = $null
        }
    }
}

# --- Service principal owner -------------------------------------------------------------
# NEVER created. Reuses one that already exists, because creating a service principal to act
# as an owner adds an ungoverned identity to a tenant in order to demonstrate ungoverned
# identities.
$ownerSpId = $SpOwnerId


# --- Targets -------------------------------------------------------------------------------
# Tenant-owned, non-managed-identity service principals only.
#   Microsoft first-party  - not ours to own, and assigning owners would be meaningless
#   managed identities     - cannot have Entra owners even in principle
if (-not $InventoryPath) {
    $outputRoot = Join-Path $PSScriptRoot '..\output'
    $latest = Join-Path $outputRoot 'latest-run.txt'
    if (Test-Path $latest) {
        $runId = (Get-Content $latest -Raw).Trim()
        $InventoryPath = Join-Path (Join-Path $outputRoot "runs\$runId") 'nhi_inventory.json'
    }
}
if (-not $InventoryPath -or -not (Test-Path $InventoryPath)) {
    throw "No inventory found. Run 01-Get-NHIInventory.ps1 first, or pass -InventoryPath."
}

$inv = Get-Content $InventoryPath -Raw | ConvertFrom-Json

# PLATFORM-MANAGED APPS THAT LIVE IN YOUR TENANT. Added 2026-10-25 after the first dry run
# put this in the GroupOwner bucket:
#
#     "aad-extensions-app. Do not modify. Used by AAD for storing user data."
#
# It is tenant-owned, so it passes every filter above - and its display name is Microsoft
# telling you, in the name field, not to touch it. Assigning an owner would probably be
# harmless, but "probably harmless" is not the standard for the one script here that writes,
# and a fixture that modifies an object labelled DO NOT MODIFY is indefensible in a review
# whatever the outcome.
$excludedNamePatterns = @(
    'aad-extensions-app*'          # AAD B2C/B2B extension attribute storage
    '*Do not modify*'              # the label itself - Microsoft uses it on managed objects
    'LAB FIXTURE*'                 # this script's own artifacts
)

# AGENT IDENTITIES ARE EXCLUDED FROM TARGETING. Added 2026-10-25, from the first real run.
#
# Owner writes against an agentIdentity are REFUSED, with the same session and scope that
# succeeds on every ordinary service principal in the same loop:
#
#     + <active owner>                               (ordinary SPs - all succeeded)
#     Root-agents  [253cd2ad]
#     WARNING: FAILED on Root-agents: [Authorization_RequestDenied]
#
# Same token, same cmdlet, same Application.ReadWrite.All - the only variable is the object
# class. So agent identities sit behind a SEPARATE AUTHORIZATION BOUNDARY for ownership
# writes, and Application.ReadWrite.All does not cross it.
#
# They also do not need the fixture: the portal already shows them with a Full owner AND a
# Sponsor, both platform-managed at creation. Targeting them adds nothing to the ownership
# distribution and generates a guaranteed failure per agent on every run.
#
# This is a FINDING, not an obstacle - see TROUBLESHOOTING.md. It is also why the scanner
# cannot be a remediation tool for agents even if someone wanted it to be.
$allCandidates = @($inv.Identities |
    Where-Object {
        $_.ObjectClass -eq 'ServicePrincipal' -and
        $_.IsTenantOwned -and
        -not $_.IsManagedIdentity -and
        -not ($_.PSObject.Properties['IsAgentIdentity'] -and $_.IsAgentIdentity)
    })

$targets = @($allCandidates | Where-Object {
    $name = [string]$_.DisplayName
    $keep = $true
    foreach ($pat in $excludedNamePatterns) { if ($name -like $pat) { $keep = $false; break } }
    $keep
} | Sort-Object Id)              # SORTED: the assignment below must be reproducible across runs

$excludedCount = $allCandidates.Count - $targets.Count
if ($excludedCount -gt 0) {
    Write-Host "  $excludedCount platform-managed identit$(if($excludedCount -eq 1){'y'}else{'ies'}) excluded from targeting." -ForegroundColor DarkGray
}

# =============================================================================
# PLAN PROVENANCE - what inventory was this planned against?
# =============================================================================
# Added 2026-10-25 because a -WhatIf planned 19 targets and the -Confirm that followed
# executed against 15, and NEITHER RUN RECORDED ENOUGH TO SAY WHY. The distribution had to be
# reverse-engineered from bucket sizes in the manifest afterwards, which is exactly the kind
# of archaeology this project keeps proving is a substitute for instrumentation.
#
# "Deterministic" was true but under-specified. The slicing is stable FOR A FIXED INVENTORY -
# sort the same list, slice it the same way, get the same buckets. It says nothing about two
# runs reading DIFFERENT inventories, which is what happens the moment 01 is re-run or the
# exclusion rules change between a dry run and a real one. Both are legitimate; the defect is
# that the script could not tell you it had happened.
#
# So the plan now carries its own provenance: which inventory, generated when, how many
# targets, and a short hash of the ordered id list. Two runs with the same TargetSetHash
# produce identical buckets, guaranteed. Two runs with different hashes planned against
# different data, and the hash says so in one line instead of three paragraphs of inference.
$invGenerated = if ($inv.PSObject.Properties['GeneratedUtc']) { $inv.GeneratedUtc } else { '(unknown)' }

$idString = ($targets.Id -join '|')
$sha      = [System.Security.Cryptography.SHA256]::Create()
$hashFull = [BitConverter]::ToString($sha.ComputeHash([Text.Encoding]::UTF8.GetBytes($idString))).Replace('-','')
$sha.Dispose()
$targetSetHash = $hashFull.Substring(0, 12)

Write-Host ""
Write-Host "Plan provenance" -ForegroundColor Cyan
Write-Host "  inventory      : $InventoryPath"       -ForegroundColor DarkGray
Write-Host "  generated      : $invGenerated"        -ForegroundColor DarkGray
Write-Host "  eligible       : $($allCandidates.Count) candidates, $($targets.Count) after exclusions" -ForegroundColor DarkGray
Write-Host "  TargetSetHash  : $targetSetHash"       -ForegroundColor White
Write-Host "  (run -WhatIf and the real run against the SAME hash, or the buckets will differ)" -ForegroundColor DarkGray

$manifest.Plan = @{
    InventoryPath      = "$InventoryPath"
    InventoryGenerated = "$invGenerated"
    CandidateCount     = $allCandidates.Count
    TargetCount        = $targets.Count
    ExcludedCount      = $excludedCount
    TargetSetHash      = $targetSetHash
    # The ordered list itself. It is the only thing that makes a past run reproducible, and it
    # costs a few hundred bytes.
    TargetIdsInOrder   = @($targets | ForEach-Object { @{ Id = $_.Id; DisplayName = $_.DisplayName } })
}

if ($targets.Count -gt $MaxTargets) {
    Write-Warning "$($targets.Count) eligible targets; capping at $MaxTargets. Raise -MaxTargets to cover more."
    $targets = $targets[0..($MaxTargets - 1)]
}

Write-Host ""
Write-Host "$($targets.Count) eligible target identities." -ForegroundColor Cyan

if ($targets.Count -eq 0) {
    throw "No tenant-owned, non-managed-identity service principals in the inventory. Nothing to do."
}


# --- Assign ---------------------------------------------------------------------------------
# DETERMINISTIC, not random. Walking the sorted list and slicing it by cumulative share means
# the same tenant produces the same distribution every run - so a change in the control report
# is a change in the CODE, not a reshuffle of the fixture. A random fixture makes every
# regression ambiguous.
$assignIndex = 0
$cursor      = 0
$buckets     = @{}

foreach ($p in $plan) {
    $count = [Math]::Round($targets.Count * $p.Share)
    $buckets[$p.Bucket] = @()
    for ($i = 0; $i -lt $count -and $cursor -lt $targets.Count; $i++) {
        $buckets[$p.Bucket] += $targets[$cursor]; $cursor++
    }
}
# Rounding leftovers go to NoOwner - the bucket that requires no action and cannot be wrong.
while ($cursor -lt $targets.Count) { $buckets['NoOwner'] += $targets[$cursor]; $cursor++ }

function Add-Owner {
    param($Target, $OwnerId, [string]$OwnerLabel, [string]$Bucket)

    if (-not $OwnerId) {
        Write-Warning "  $($Target.DisplayName): no owner available for bucket $Bucket - skipped."
        return
    }
    if ("$OwnerId".StartsWith('WHATIF-')) { return }

    # Idempotent. Re-running must not stack duplicate owners or fail on a conflict.
    $current = @(Get-MgServicePrincipalOwner -ServicePrincipalId $Target.Id -ErrorAction SilentlyContinue)
    if ($current.Id -contains $OwnerId) {
        Write-Host "    already owned by $OwnerLabel" -ForegroundColor DarkGray
        return
    }

    if ($PSCmdlet.ShouldProcess($Target.DisplayName, "Add owner $OwnerLabel [$Bucket]")) {
        try {
            New-MgServicePrincipalOwnerByRef -ServicePrincipalId $Target.Id `
                -BodyParameter @{ '@odata.id' = "https://graph.microsoft.com/the control-mapping stage/directoryObjects/$OwnerId" } `
                -ErrorAction Stop

            # Manifest FIRST-CLASS and flushed immediately. If the next call throws, this one
            # is still revertible.
            $manifest.OwnerAssignments.Add(@{
                TargetId = $Target.Id; TargetName = $Target.DisplayName
                OwnerId  = $OwnerId;   Bucket     = $Bucket
            })
            Save-Manifest

            Write-Host "    + $OwnerLabel" -ForegroundColor Green
        }
        catch {
            # A failure here is DATA - most often an insufficient-scope error, which is the
            # single most instructive thing this script can show you.
            Write-Warning "    FAILED on $($Target.DisplayName): $($_.Exception.Message)"
        }
    }
}

Write-Host ""
foreach ($p in $plan) {
    $set = @($buckets[$p.Bucket])
    Write-Host "$($p.Bucket) - $($set.Count) identit$(if($set.Count -eq 1){'y'}else{'ies'})" -ForegroundColor Cyan

    foreach ($t in $set) {
        # Object id alongside the name. The first dry run listed "Root-agents" in BOTH the
        # ActiveOwner and GroupOwner buckets, which reads as a duplicate assignment and is not
        # one: three distinct objects in this tenant share that display name (the agent
        # identity, the blueprint's service principal, the blueprint's app registration).
        # Same lesson as the control report - in Entra, DisplayName is not an identifier.
        $shortId = "$($t.Id)".Substring(0, [Math]::Min(8, "$($t.Id)".Length))
        Write-Host "  $($t.DisplayName)  [$shortId]" -ForegroundColor Gray
        switch ($p.Bucket) {
            'ActiveOwner'   { Add-Owner -Target $t -OwnerId $ownerActive.Id   -OwnerLabel $ownerActive.Upn   -Bucket $p.Bucket }
            'TwoOwners'     {
                                Add-Owner -Target $t -OwnerId $ownerActive.Id -OwnerLabel $ownerActive.Upn -Bucket $p.Bucket
                                Add-Owner -Target $t -OwnerId $ownerSecond.Id -OwnerLabel $ownerSecond.Upn -Bucket $p.Bucket
                            }
            'DepartedOwner' { Add-Owner -Target $t -OwnerId $ownerDeparted.Id -OwnerLabel $ownerDeparted.Upn -Bucket $p.Bucket }
            'GroupOwner'    { Add-Owner -Target $t -OwnerId $ownerGroupId     -OwnerLabel 'fixture group'    -Bucket $p.Bucket }
            'SpOwner'       {
                                if ($ownerSpId) { Add-Owner -Target $t -OwnerId $ownerSpId -OwnerLabel 'service principal' -Bucket $p.Bucket }
                                else { Write-Host "    skipped - pass -SpOwnerId to exercise this bucket" -ForegroundColor DarkYellow }
                            }
            'NoOwner'       { Write-Host "    (left deliberately unowned)" -ForegroundColor DarkGray }
        }
    }
    Write-Host ""
}

Save-Manifest

Write-Host "Manifest: $ManifestPath" -ForegroundColor DarkGray
Write-Host "$($manifest.OwnerAssignments.Count) owner assignment(s), $($manifest.Users.Count) created user(s)." -ForegroundColor Green
Write-Host ""
Write-Host "Next: re-run 01 -> 03 -> 04. Every ownership rule should now fire, and the" -ForegroundColor Cyan
Write-Host "attestation simulation has real owner states to correlate against." -ForegroundColor Cyan
Write-Host "Undo with:  .\99-New-LabFixture.ps1 -Revert -Confirm" -ForegroundColor DarkGray
