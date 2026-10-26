<#
.SYNOPSIS
    Turns the raw inventory into classified findings: who owns each identity, what is wrong
    with it, and how serious that is.

.DESCRIPTION
    Turns the inventory into accountability: who owns each identity, whether that owner can
    actually attest for it, and how serious the gap is. Produces orphaned-owner, excessive-
    scope, dormancy and credential-type findings alongside the ownership map itself.

    Reads  : output/nhi_inventory.json   (produced by 01-Get-NHIInventory.ps1)
    Writes : output/nhi_ownership.csv    one row per identity, for humans and spreadsheets
             output/nhi_findings.json    structured findings, consumed by Phases 4 and 5

    Makes NO calls to the tenant. This is pure transformation of a file you already have,
    which means it is safe to run repeatedly while you tune the rules - and you will tune
    them, several times.

.PARAMETER DormancyDays
    How many days without a sign-in before an identity counts as dormant. Default 90.

.PARAMETER LongLivedSecretDays
    Secret lifetime beyond which it is flagged as excessively long. Default 180.

.PARAMETER TerraformStatePath
    OPTIONAL. Path to a Terraform state file, or a directory containing terraform.tfstate.

    Supply it and RULE 7 runs, classifying every tenant-owned app registration as declared
    in code or clicked into existence. OMIT IT AND RULE 7 IS SKIPPED ENTIRELY - an empty
    managed set would otherwise flag every identity in the tenant, which is exactly how an
    NHI report gets closed and never reopened.

    DEFERRED feature, not part of this tool or the control-mapping stage. Off unless a state file is supplied.

.EXAMPLE
    .\03-New-OwnershipMap.ps1

.EXAMPLE
    .\03-New-OwnershipMap.ps1 -DormancyDays 60 -LongLivedSecretDays 90
    Stricter thresholds - useful for showing a client the effect of tightening policy.

.EXAMPLE
    .\03-New-OwnershipMap.ps1 -TerraformStatePath ..\terraform\terraform.tfstate
    Adds IaC provenance. Produces the coverage figure: what percentage of PRIVILEGED
    non-human identities are declared in code rather than clicked into existence.

.NOTES
    THE SEVERITY MODEL
      Critical  Privilege escalation is possible, or the owner is gone
      High      Nobody can attest to it, or a credential has already failed
      Medium    A hygiene problem that will become High if ignored
      Low       A better practice is available
      Info      A POSITIVE finding - report good practice, not only problems

    RULE 7 (IaC provenance) IS OPT-IN and does nothing unless -TerraformStatePath is given.
    Its finding codes are IAC_MANAGED (Info), UNMANAGED_IDENTITY (Low) and
    UNMANAGED_PRIVILEGED (High). The severity split is deliberate and is explained in full
    at the rule itself - do not raise UNMANAGED_IDENTITY without reading that note.

    Every rule below is MECHANICALLY CHECKABLE. There are no judgement calls anywhere in this
    script. That is deliberate: a finding you can point at a specific field for is defensible
    to an auditor, and one based on your opinion is not.
#>

[CmdletBinding()]
param(
    # RUN COMPARTMENTALISATION - added 25 Oct 2026. See 01-Get-NHIInventory.ps1 for the why.
    #
    # Script 01 owns the run id and records it in output/latest-run.txt. This script reads
    # that pointer so the whole pipeline lands in one directory without the caller tracking
    # anything. Pass -RunId explicitly to re-process an older run - which is the point of
    # keeping them: you can re-run the classification against last quarter's inventory after
    # changing a rule, and compare.
    [string]$OutputRoot = (Join-Path $PSScriptRoot '..\output'),

    [Alias('RunId')][string]$RunIdentifier = $(
        $pointer = Join-Path $OutputRoot 'latest-run.txt'
        if (Test-Path $pointer) { (Get-Content $pointer -Raw).Trim() }
        else { throw "No run found. Run 01-Get-NHIInventory.ps1 first, or pass -RunId." }
    ),

    [string]$RunDir        = (Join-Path $OutputRoot "runs\$RunIdentifier"),
    [string]$InventoryPath = (Join-Path $RunDir 'nhi_inventory.json'),
    [string]$CsvPath       = (Join-Path $RunDir 'nhi_ownership.csv'),
    [string]$FindingsPath  = (Join-Path $RunDir 'nhi_findings.json'),
    [int]$DormancyDays = 90,
    [int]$LongLivedSecretDays = 180,

    # OPTIONAL - path to a Terraform state file (or a directory containing one).
    #
    # Supply this and RULE 7 runs: every tenant-owned app registration gets classified as
    # either declared-in-code or clicked-into-existence. Leave it empty and RULE 7 is SKIPPED
    # ENTIRELY - see the long note above RULE 7 for why that is the only safe default.
    #
    # Deferred feature. Validate against a known-good state file before trusting it.
    [string]$TerraformStatePath = ''
)

$ErrorActionPreference = 'Stop'

if (-not (Test-Path $InventoryPath)) {
    throw "Inventory not found at $InventoryPath. Run 01-Get-NHIInventory.ps1 first."
}

$data = Get-Content $InventoryPath -Raw | ConvertFrom-Json
$now  = (Get-Date).ToUniversalTime()

# =============================================================================
# INVENTORY FRESHNESS - say how old the data is, every time
# =============================================================================
# Added 2026-10-25 after a run that cost an evening. Owners were assigned in the tenant and
# confirmed in the portal; the CSV, the findings, the control report and the attestation all
# continued to report UNASSIGNED. Every one of them was correct about a seventeen-hour-old
# inventory and none of them said so.
#
# 01 is the ONLY script that reads the tenant. Everything after it reads a FILE. So no output
# downstream can be fresher than the inventory it was built from - and until now not one of
# them printed that timestamp. A stale report and a current report were byte-identical in
# every respect that a reader checks.
#
# This is the same failure mode as NOT APPLICABLE and as the rules that could never fire:
# the absence of information rendering as a clean result. The fix is the same one every time -
# make the tool state what it knows and when it knew it.
# TIMEZONE BUG, FIXED 2026-10-26. The first run of this code reported an age of -5.0 HOURS -
# an inventory from the future.
#
# The file holds correct ISO-8601: "2026-10-26T04:49:03.0819079Z". But ConvertFrom-Json
# PARSES ISO date strings into [datetime] objects, so $data.GeneratedUtc is already a DateTime
# with Kind=Local after conversion. Casting it to [string] rendered it in LOCAL format
# ("10/26/2026 04:49:03", the Z gone), and casting that back to [datetime] and calling
# .ToUniversalTime() added the offset a second time. Five hours of drift, in the one field
# whose entire job is telling a reader how stale the data is.
#
# Handled by type rather than by string: if it is already a DateTime, use it; only parse when
# it genuinely is text, and treat that text as UTC rather than local.
$rawGenerated          = if ($data.PSObject.Properties['GeneratedUtc']) { $data.GeneratedUtc } else { $null }
$inventoryGeneratedUtc = $null
$inventoryAgeHours     = $null

if ($rawGenerated) {
    try {
        $invTime =
            if ($rawGenerated -is [datetime]) {
                # Already parsed by ConvertFrom-Json. Kind may be Local or Unspecified; both
                # describe the same instant, and ToUniversalTime normalises Local correctly.
                if ($rawGenerated.Kind -eq [System.DateTimeKind]::Unspecified) {
                    [datetime]::SpecifyKind($rawGenerated, [System.DateTimeKind]::Utc)
                } else {
                    $rawGenerated.ToUniversalTime()
                }
            }
            else {
                # Genuine string. AdjustToUniversal + AssumeUniversal stops a trailing Z being
                # applied twice, which is exactly what the naive cast did.
                [datetime]::Parse([string]$rawGenerated, [cultureinfo]::InvariantCulture,
                                  [System.Globalization.DateTimeStyles]::AdjustToUniversal -bor
                                  [System.Globalization.DateTimeStyles]::AssumeUniversal)
            }

        # Round-trip format, so the value this script WRITES is unambiguous even after the
        # next ConvertFrom-Json. Propagating a local-format string downstream would hand the
        # same bug to script 05.
        $inventoryGeneratedUtc = $invTime.ToString('o')
        $inventoryAgeHours     = [Math]::Round(($now - $invTime).TotalHours, 1)

        # A negative age means the clock maths is wrong, not that the tenant was read in the
        # future. Say so rather than printing it - a nonsensical number that is displayed
        # without comment teaches a reader to ignore the field.
        if ($inventoryAgeHours -lt -0.1) {
            Write-Warning "Computed a NEGATIVE inventory age ($inventoryAgeHours h). Treating age as unknown."
            $inventoryAgeHours = $null
        }
    }
    catch {
        Write-Warning "Could not interpret GeneratedUtc '$rawGenerated': $($_.Exception.Message)"
        $inventoryGeneratedUtc = [string]$rawGenerated
    }
}

Write-Host ""
Write-Host "Inventory: $InventoryPath" -ForegroundColor DarkGray
if ($null -ne $inventoryAgeHours) {
    $ageColour = if ($inventoryAgeHours -gt 24) { 'Red' } elseif ($inventoryAgeHours -gt 2) { 'Yellow' } else { 'DarkGray' }
    Write-Host "Captured : $inventoryGeneratedUtc  ($inventoryAgeHours hours ago)" -ForegroundColor $ageColour

    # Loud, and deliberately hard to read past. The tenant was changed between the scan and
    # this run more than once during development, and a DarkGray line would not have stopped it.
    if ($inventoryAgeHours -gt 2) {
        Write-Host ""
        Write-Host "  ##################################################################" -ForegroundColor Yellow
        Write-Host "  #  STALE INVENTORY - $inventoryAgeHours hours old" -ForegroundColor Yellow
        Write-Host "  #  Every finding below describes the tenant AS IT WAS THEN." -ForegroundColor Yellow
        Write-Host "  #  If you have changed ownership since, re-run 01 first:" -ForegroundColor Yellow
        Write-Host "  #      .\01-Get-NHIInventory.ps1" -ForegroundColor Yellow
        Write-Host "  ##################################################################" -ForegroundColor Yellow
        Write-Host ""
    }
}
else {
    Write-Host "Captured : UNKNOWN - inventory has no GeneratedUtc" -ForegroundColor Red
}


# #############################################################################
#  THE PERMISSION RISK SETS
# #############################################################################
#  This is where the tool stops being a list and starts being an assessment.
# #############################################################################

# -----------------------------------------------------------------------------
# PRIVILEGE ESCALATION SET
# -----------------------------------------------------------------------------
# Any service principal holding one of these can, directly or in a single further step,
# grant itself Global Administrator. Walk through why each one qualifies:
#
#   RoleManagement.ReadWrite.Directory
#       Can assign directory roles - including Global Administrator, to itself. The most
#       direct path there is.
#
#   AppRoleAssignment.ReadWrite.All
#       Can grant application permissions - so it can grant itself any OTHER permission,
#       including the one above. One step removed from the same outcome.
#
#   Application.ReadWrite.All
#       Can add credentials to ANY app registration, including highly privileged ones. Add a
#       secret to a privileged app, authenticate as it, inherit its permissions.
#
#   Directory.ReadWrite.All
#       Broad directory write. Less surgical than the others but still extremely powerful.
#
# A service principal holding one of these WITH NO OWNER is the single most alarming finding
# this tool can produce - and most tenants have at least one.
$EscalationPermissions = @(
    'RoleManagement.ReadWrite.Directory'
    'AppRoleAssignment.ReadWrite.All'
    'Application.ReadWrite.All'
    'Directory.ReadWrite.All'
)

# -----------------------------------------------------------------------------
# HIGH IMPACT SET
# -----------------------------------------------------------------------------
# These do not lead to Global Admin, but they give broad access to data or to users. Serious,
# and worth an owner's explicit confirmation - but distinct from escalation, and keeping the
# two categories separate is what stops your report crying wolf.
$HighImpactPermissions = @(
    'User.ReadWrite.All'
    'Group.ReadWrite.All'
    'GroupMember.ReadWrite.All'
    'Mail.ReadWrite'
    'Mail.Send'                              # can send mail AS anyone - a phishing primitive
    'Files.ReadWrite.All'
    'Sites.FullControl.All'
    'DeviceManagementConfiguration.ReadWrite.All'
)


function New-Finding {
    <#  Tiny constructor so every finding has an identical shape.
        Code is machine-readable and is what Phase 5 maps to controls.
        Detail is human-readable and is what appears in the report. #>
    param([string]$Code, [string]$Severity, [string]$Detail)
    [pscustomobject]@{ Code = $Code; Severity = $Severity; Detail = $Detail }
}


# #############################################################################
#  INFRASTRUCTURE-AS-CODE PROVENANCE  (RULE 7 support)
# #############################################################################
#  Every other rule in this script describes a PROPERTY of an identity - its owner, its
#  credentials, its permissions. This one describes where it CAME FROM.
#
#  An identity declared in a Terraform module has four things by construction:
#      an owner         the repository, and the team that owns the repository
#      a justification  the commit message and the pull request that merged it
#      a history        git log, with reviewers
#      an intended state  the module - which is what makes drift detectable at all
#
#  An identity someone clicked into existence in the portal has none of those four, and
#  nothing in the directory records the difference. So the question this supports is one no
#  other NHI tool asks:
#
#      "Which of your non-human identities are declared in code, and which were clicked
#       into existence?"
#
#  WARNING - THIS CODE HAS NEVER BEEN RUN. Like the rest of the scripts in this folder it
#  was written without a tenant or a Terraform install to test against. Verify it against
#  a sanitised fixture with known IaC provenance BEFORE trusting a single number it
#  produces. The failure mode to watch for is a parser that silently returns nothing.
# #############################################################################

function Get-IaCManagedIds {
    <#
        .SYNOPSIS
        Reads a Terraform state file and returns the identity object IDs it declares.

        .OUTPUTS
        [System.Collections.Generic.HashSet[string]] of lower-cased GUIDs. HashSet rather than
        an array for the same reason script 01 uses one: this gets tested once per identity,
        so an O(n) array scan becomes O(n-squared) across a few hundred service principals.

        .NOTES
        Terraform state is JSON, schema version 4, shaped roughly:

            { "version": 4,
              "resources": [
                { "mode": "managed",
                  "type": "azuread_application",
                  "instances": [ { "attributes": { "object_id": "...", "client_id": "..." } } ] } ] }

        Two traps, both of which silently corrupt the coverage figure rather than erroring:

        1. mode must be "managed". A "data" entry is a READ-ONLY LOOKUP of something
           Terraform does not own. Counting those inflates your coverage percentage - and
           that percentage is the one number from this whole feature anyone will ever quote
           back at you, so it is the worst possible place to be wrong.

        2. The azuread provider renamed 'application_id' to 'client_id' at v3.0. Both are
           handled below. Do not take my word for either name: run
               terraform providers schema -json
           which dumps the exact schema for the provider version YOU have pinned. Ask the
           binary rather than the documentation - it cannot be out of date.
    #>
    param([Parameter(Mandatory)][string]$Path)

    $set = [System.Collections.Generic.HashSet[string]]::new()

    # Accept either a state file or a directory containing the conventional filename.
    $file = $Path
    if (Test-Path -Path $Path -PathType Container) {
        $file = Join-Path $Path 'terraform.tfstate'
    }
    if (-not (Test-Path -Path $file -PathType Leaf)) {
        throw "Terraform state not found at '$file'. RULE 7 cannot run without it."
    }

    $state = Get-Content -Path $file -Raw | ConvertFrom-Json

    if (-not $state.resources) {
        Write-Warning "State file at '$file' declares no resources. RULE 7 will treat every identity as undeclared, which is almost certainly wrong - check you pointed at the right state."
    }

    # Only these resource types create a directory identity. Anything else in state is
    # infrastructure, not an identity, and is none of this script's business.
    $identityTypes = @(
        'azuread_application'
        'azuread_service_principal'
        'azurerm_user_assigned_identity'
    )

    foreach ($r in @($state.resources)) {

        if ($r.mode -ne 'managed')          { continue }   # trap 1 - see .NOTES
        if ($r.type -notin $identityTypes)  { continue }

        foreach ($inst in @($r.instances)) {
            $a = $inst.attributes
            if (-not $a) { continue }

            # Collect every identifier the object might be matched on later. Entra will hand
            # us an object ID in some places and an application (client) ID in others, and
            # which one appears depends on the object class - so index both and let RULE 7
            # test whichever it has.
            foreach ($key in 'object_id', 'client_id', 'application_id', 'principal_id') {
                $v = $a.$key
                if ($v -and $v -is [string]) { [void]$set.Add($v.ToLower()) }
            }
        }
    }

    return ,$set
}


# Load the managed set ONCE, before the loop, rather than re-reading the file per identity.
$iacEnabled    = -not [string]::IsNullOrWhiteSpace($TerraformStatePath)
$iacManagedIds = $null

if ($iacEnabled) {
    $iacManagedIds = Get-IaCManagedIds -Path $TerraformStatePath
    Write-Host "IaC provenance: $($iacManagedIds.Count) identifier(s) declared in Terraform state." -ForegroundColor Cyan
} else {
    Write-Verbose "No -TerraformStatePath supplied. RULE 7 (IaC provenance) skipped."
}


# =============================================================================
# MAIN LOOP - classify every identity
# =============================================================================
$rows     = [System.Collections.Generic.List[object]]::new()   # flat, for the CSV
$findings = [System.Collections.Generic.List[object]]::new()   # structured, for Phases 4 and 5

# Denominators, counted as the loop runs rather than reconstructed afterwards. ASSESSED is the
# number this script actually applied rules to - external Microsoft and third-party principals
# exit early and are NOT assessed, so including them would inflate the population and make
# every rate look better than it is.
$assessedCount   = 0
$externalSkipped = 0

foreach ($id in $data.Identities) {

    # Findings accumulate here for this one identity.
    $f = [System.Collections.Generic.List[object]]::new()


    # -------------------------------------------------------------------------
    # EARLY EXIT - external identities are inventoried but never flagged
    # -------------------------------------------------------------------------
    # Microsoft first-party and third-party SaaS service principals have no tenant owner BY
    # DESIGN. Flagging them for "no owner" would generate 150 false findings and is precisely
    # the mistake that makes NHI tools get ignored.
    #
    # We still record them - you want the complete picture, and "how many third-party apps
    # have been consented to in this tenant" is itself an interesting number - but they get a
    # separate classification and no findings.
    if (-not $id.IsTenantOwned -and -not $id.IsManagedIdentity) {
        $externalSkipped++

        # SCHEMA MUST MATCH THE ASSESSED ROW EXACTLY - including the columns added 2026-10-25.
        #
        # Export-Csv derives its headers from the FIRST object in the collection. External
        # principals are the overwhelming majority here (325 of 342) and come first in
        # enumeration order, so a column missing from THIS row is a column missing from the
        # ENTIRE CSV - silently, with no error. ObjectId, OwnerSource and InventoryUtc were
        # added to the assessed row below and omitted here, which would have dropped all three
        # from every row in the file.
        #
        # Worth stating as a rule: whenever two code paths write to one CSV, they are one
        # schema. Adding a field to one of them and not the other does not produce a partial
        # column, it produces no column.
        $rows.Add([pscustomobject]@{
            DisplayName    = $id.DisplayName
            ObjectId       = $id.Id
            OwnerSource    = if ($id.ObjectClass -eq 'Application') { 'App registrations > Owners' } else { 'Enterprise applications > Owners' }
            ObjectClass    = $id.ObjectClass
            Type           = $id.ServicePrincipalType
            Classification = 'External (Microsoft / third-party)'
            Owner          = 'N/A - not tenant-owned'
            OwnerCount     = 0
            Enabled        = $id.AccountEnabled
            Created        = $id.CreatedDateTime
            LastSignIn     = $id.LastSignIn
            TopSeverity    = 'Info'
            FindingCount   = 0
            Findings       = ''
            AppId          = $id.AppId
            InventoryUtc   = $inventoryGeneratedUtc
        })
        continue    # nothing further to assess
    }


    # -------------------------------------------------------------------------
    # RULE 1 - Ownership. The headline finding.
    # -------------------------------------------------------------------------
    $ownerNames      = @()
    $orphaned        = $false
    $ownerStateUnres = @()   # owners whose enabled state could not be determined

    foreach ($o in @($id.Owners | Where-Object { $null -ne $_ })) {
        # Prefer UPN (unique, actionable) over display name (ambiguous).
        $ownerNames += ($o.UserPrincipalName ? $o.UserPrincipalName : $o.DisplayName)

        # THE SUBTLE ONE: an owner object that EXISTS but whose account is DISABLED is worse
        # than having no owner at all. A governance dashboard shows the identity as owned and
        # therefore governed; in reality the owner left the company months ago and nobody will
        # ever respond to an attestation request. It looks fine and is not.
        if ($o.AccountEnabled -eq $false) { $orphaned = $true }

        # UNRESOLVED IS NOT ENABLED. Added 2026-10-25 with the accountEnabled fix in script 01.
        #
        # Until today the owners carried AccountEnabled = $null on EVERY record, because the
        # /owners navigation does not return that field. `$null -eq $false` is FALSE, so
        # $orphaned was never set and ORPHANED_OWNER - the Critical finding this tool calls
        # the one that lands hardest - was unreachable code. It failed silently and looked
        # exactly like a clean result.
        #
        # Script 01 now resolves the state per owner and sets EnabledResolved. Anything still
        # unresolved is reported, because an owner whose state is unknown must not be counted
        # as a governed one. A group legitimately has no accountEnabled and is marked resolved
        # at source, so it does not land here.
        $hasFlag = $null -ne $o.PSObject.Properties['EnabledResolved']
        if ($hasFlag -and -not $o.EnabledResolved) {
            $ownerStateUnres += ($o.UserPrincipalName ? $o.UserPrincipalName : $o.DisplayName)
        }
        elseif (-not $hasFlag -and $null -eq $o.AccountEnabled -and $o.ObjectType -notmatch 'group') {
            # Inventory written before the fix. Say so rather than silently assuming enabled.
            $ownerStateUnres += ($o.UserPrincipalName ? $o.UserPrincipalName : $o.DisplayName)
        }
    }

    if ($ownerStateUnres.Count -gt 0) {
        $f.Add((New-Finding 'OWNER_STATE_UNRESOLVED' 'Info' "Could not determine whether $($ownerStateUnres.Count) owner(s) are enabled: $($ownerStateUnres -join '; '). ORPHANED_OWNER cannot be evaluated for this identity, so the absence of that finding here is NOT evidence the owner is active. If this appears on every identity, the inventory predates the accountEnabled fix - re-run 01-Get-NHIInventory.ps1."))
    }

    # -------------------------------------------------------------------------
    # MANAGED IDENTITIES CANNOT HAVE ENTRA OWNERS. FALSE POSITIVE FIXED 26 Oct 2026.
    # -------------------------------------------------------------------------
    # Found on the FIRST REAL RUN of this tool, against the lab tenant.
    #
    # An Azure Automation Account named "automation-acct-01" came back as NO_OWNER / High. The portal
    # showed an Owner on it. Both were correct, and the tool was still wrong, because there
    # are TWO UNRELATED OWNERSHIP MODELS and this script only reads one:
    #
    #   ENTRA OBJECT OWNERS   /servicePrincipals/{id}/owners
    #                         Graph. What Get-MgServicePrincipalOwner returns. What RULE 1
    #                         above is testing.
    #
    #   AZURE RBAC            Microsoft.Authorization/roleAssignments on the ARM resource
    #                         A different control plane, a different API, a different SDK.
    #                         NOT IN GRAPH AT ALL.
    #
    # The Owner in the portal was an Azure RBAC role assignment inherited from the
    # subscription. This script cannot see it and never will, because Graph does not expose
    # the ARM authorization plane.
    #
    # Worse: a SYSTEM-ASSIGNED managed identity CANNOT HAVE Entra owners even in principle.
    # It is created and destroyed with its parent Azure resource. There is no owner field to
    # populate, so NO_OWNER is not an under-governed identity - it is a category error.
    #
    # THE GENERAL LESSON, which is worth more than the fix:
    #
    #   For managed identities, accountability lives in Azure RBAC on the parent resource,
    #   not in Entra object owners. ANY identity governance tool that reads only Graph will
    #   report every managed identity in the tenant as unowned - and be wrong every time.
    #
    # Flagging all of them High is precisely the behaviour that gets a security tool ignored,
    # which is the same reasoning as the Microsoft first-party early-exit further up.
    if ($id.IsManagedIdentity) {

        # THREE OUTCOMES NOW, not one. Updated 2026-10-25, when script 01 gained the optional
        # Azure RBAC lookup (-IncludeAzureRbac). Previously this always reported the boundary,
        # even when the answer was obtainable - it just needed a second token audience.
        $rbacLooked = ($null -ne $id.PSObject.Properties['RbacLookupPerformed']) -and $id.RbacLookupPerformed
        $rbacCount  = if ($id.PSObject.Properties['RbacPrincipals']) { @($id.RbacPrincipals).Count } else { 0 }

        if ($rbacLooked -and $rbacCount -gt 0) {
            # The question is ANSWERED. Still Info, and still not an "owner": a role assignment
            # says who CAN act on the resource, not who is ACCOUNTABLE for it. An inherited
            # subscription-level assignment usually names a platform team rather than the
            # person who would answer an attestation - which is exactly what the lab's
            # `automation-acct-01` showed, scoped "Subscription (Inherited)".
            $scopeText = if ($id.RbacScope) { " Nearest scope: $($id.RbacScope)." } else { '' }
            $f.Add((New-Finding 'MI_RBAC_ACCOUNTABILITY' 'Info' "Managed identity with $rbacCount Azure RBAC assignment(s) on the parent resource.$scopeText A role assignment establishes who CAN act on the resource, not who is accountable for it - an inherited subscription-scope assignment typically names a platform team. Treat as weaker evidence than a named Entra owner."))
        }
        elseif ($rbacLooked -and $rbacCount -eq 0) {
            # Asked and found nothing. Genuinely different from not having asked, and the
            # distinction matters: this one IS a posture finding.
            $f.Add((New-Finding 'MI_NO_RBAC_ASSIGNMENT' 'Medium' 'Managed identity with no Azure RBAC assignment found on any scope readable by this account. Either nobody holds access on the parent resource, or the scanning account cannot see the scope that grants it. Confirm in Azure IAM before treating as unowned.'))
        }
        else {
            # Not asked. Report the boundary - accurate, and now also says how to close it.
            $f.Add((New-Finding 'MI_OWNERSHIP_NOT_IN_GRAPH' 'Info' 'Managed identity. Accountability is held as Azure RBAC on the parent resource, which Microsoft Graph cannot see. Not assessed: re-run 01-Get-NHIInventory.ps1 with -IncludeAzureRbac and an ARM access token to resolve it, or verify manually in Azure IAM on the parent resource.'))
        }

        # A failed lookup is reported, never swallowed. A silent failure here would read as
        # "not asked" and the report would look clean for a question that errored.
        if ($id.PSObject.Properties['RbacLookupError'] -and $id.RbacLookupError) {
            $f.Add((New-Finding 'MI_RBAC_LOOKUP_FAILED' 'Info' "Azure RBAC lookup was attempted and failed: $($id.RbacLookupError). Ownership for this identity is UNASSESSED, not clean."))
        }

        # An orphaned owner is still worth reporting IF one somehow exists - a user-assigned
        # managed identity is a standalone resource and the model is less absolute there.
        if ($orphaned) {
            $f.Add((New-Finding 'ORPHANED_OWNER' 'Critical' 'Assigned owner account is disabled. Appears governed but is not.'))
        }
    }
    elseif ($id.OwnerCount -eq 0 -and $id.PSObject.Properties['IsAgentIdentity'] -and $id.IsAgentIdentity) {
        # AGENT IDENTITY WITH ZERO OWNERS READ - and that is NOT the same as having none.
        # Measured 2026-10-25, during the first fixture run:
        #
        #   The portal's Owners and sponsors blade shows Root-agents with a Full owner AND a
        #   Sponsor. The fixture's idempotency check calls Get-MgServicePrincipalOwner on that
        #   same object before assigning, and skips if an owner is already present. IT DID NOT
        #   SKIP - it went on to attempt the write. So /servicePrincipals/{id}/owners does not
        #   return what the Agents blade displays.
        #
        # Therefore OwnerCount == 0 on an agent identity means "not readable by this route",
        # not "unowned". Emitting NO_OWNER at High here would be the NO_SPONSOR bug a second
        # time: a High finding that fires on correctly-governed objects because the tool is
        # reading the wrong relationship.
        #
        # Reported as Info and phrased as a gap in the TOOL, which is what it is.
        $f.Add((New-Finding 'AGENT_OWNER_NOT_IN_SP_OWNERS' 'Info' 'Agent identity returning zero owners from /servicePrincipals/{id}/owners. The Entra portal shows owners and sponsors for agent identities that this navigation property does not return, so this is UNREADABLE rather than UNOWNED. Verify in the agent''s Owners and sponsors blade. Do not treat as a posture finding until the correct relationship is identified.'))
    }
    elseif ($id.OwnerCount -eq 0 -and $id.ObjectClass -eq 'Application') {
        # ===================================================================================
        # AN APP REGISTRATION IS NOT THE THING THAT HAS ACCESS. Split out 2026-10-25.
        # ===================================================================================
        # Until now both object classes got NO_OWNER / High with the wording "Nobody can
        # attest to this identity" - a SERVICE PRINCIPAL sentence, emitted against 14 of the
        # 17 app registrations in the lab tenant. The severity was defensible; the claim was
        # not, and in an auditor-facing report the claim is the part that gets read.
        #
        # THE TWO OBJECTS HOLD DIFFERENT THINGS, SO THEIR OWNERS ANSWER DIFFERENT QUESTIONS:
        #
        #   Application (app registration)   the DEFINITION. Client secrets and certificates,
        #                                    requested API permissions, redirect URIs.
        #                                    Owner = who may mint a new credential or request
        #                                    a broader permission. CHANGE CONTROL.
        #
        #   Service principal (enterprise)   the INSTANCE in this tenant. Granted consent,
        #                                    app role assignments, sign-in activity.
        #                                    Owner = who confirms the ACCESS is still needed.
        #                                    ATTESTATION.
        #
        # "Is this still needed?" is a question about ACCESS, and access belongs to the
        # service principal - it holds the grants, it appears in the sign-in logs, and
        # disabling it is the remediation. An app registration with no service principal in
        # the tenant has no access to attest to at all.
        #
        # AND THE ASYMMETRY THAT MAKES SP-FIRST THE ONLY WORKABLE CHOICE: a third-party SaaS
        # app - Okta, AWS IAM Identity Center, Workday - has a service principal here and NO
        # app registration, because the registration lives in the vendor's tenant. 325 service
        # principals against 17 app registrations in this tenant. Driving attestation off app
        # registrations would simply not see most of the estate.
        #
        # So an unowned app registration is a REAL finding and a DIFFERENT one: nobody is
        # accountable for the credentials. Kept at High because minting a secret on an
        # unowned app registration is exactly how a forgotten identity becomes an incident -
        # but named and worded for what it actually is.
        $f.Add((New-Finding 'NO_APP_REGISTRATION_OWNER' 'High' 'App registration with no owner. Nobody is accountable for this application''s CREDENTIALS and requested permissions - who may add a client secret or request broader API access. This is credential custody, not access attestation: the matching service principal is the object that holds the access and is attested separately.'))
    }
    elseif ($id.OwnerCount -eq 0) {
        $f.Add((New-Finding 'NO_OWNER' 'High' 'No owner assigned. Nobody can attest to this identity.'))
    }
    else {
        # ===================================================================================
        # NO_HUMAN_OWNER - WRITTEN 2026-10-25. IT HAD NEVER BEEN IMPLEMENTED.
        # ===================================================================================
        # 99-New-LabFixture.ps1 names this finding NINE times. Two of its six buckets exist
        # solely to manufacture it - GroupOwner at 15% and SpOwner at 5%, a fifth of the whole
        # distribution. The rule did not exist in this script. Not broken, not mis-scoped:
        # ABSENT. The fixture was generating input for a detection nobody had written.
        #
        # Caught from the CSV, by reading it rather than trusting it:
        #
        #   svc-provisioning  ServicePrincipal  Tenant-owned  app1  1  TRUE  None  0
        #
        # An identity whose ONLY owner is another service principal: OwnerCount 1, severity
        # None, zero findings - and the attestation cycle then recorded it as APPROVED,
        # because "has an owner" was treated as "has someone to ask".
        #
        # THIS IS THE MOST DANGEROUS OWNERSHIP STATE THERE IS, and it is worse than NO_OWNER.
        # An unowned identity is visibly ungoverned and shows up in every report. An identity
        # owned by a group or a service principal LOOKS governed: the ownership column is
        # populated, the dashboard is green, the access review goes out and is auto-approved
        # or quietly ignored, and the identity accumulates trust that no human ever granted.
        # "Ask a group" means nobody answers. "Ask a service principal" means nobody is even
        # capable of answering.
        #
        # High, matching NO_OWNER. The same accountability gap, wearing a disguise.
        $humanOwners = @($id.Owners | Where-Object { $_.ObjectType -match '(?i)\.user$' })
        $nonHuman    = @($id.Owners | Where-Object { $_.ObjectType -notmatch '(?i)\.user$' })

        # Only assert this when the owner TYPE is actually known. An inventory written before
        # ObjectType was captured would otherwise have every owner read as non-human and the
        # rule would fire on the entire estate - the inverse of the bug it fixes, and exactly
        # the failure the NO_SPONSOR rule already taught this project once.
        $typesKnown = @($id.Owners | Where-Object { $_.ObjectType }).Count -eq @($id.Owners).Count

        if ($typesKnown -and $humanOwners.Count -eq 0 -and $nonHuman.Count -gt 0) {
            $kinds = @($nonHuman | ForEach-Object {
                if ($_.ObjectType -match '(?i)group') { 'group' }
                elseif ($_.ObjectType -match '(?i)servicePrincipal') { 'service principal' }
                else { 'non-user object' }
            } | Sort-Object -Unique) -join ', '

            $f.Add((New-Finding 'NO_HUMAN_OWNER' 'High' "Owned only by a $kinds ($($nonHuman.DisplayName -join '; ')). The ownership field is populated, so this identity APPEARS governed on any dashboard - but there is no human to answer an attestation request. Worse than having no owner at all, because it does not look like a gap. Assign a named human owner."))
        }
        elseif (-not $typesKnown) {
            $f.Add((New-Finding 'OWNER_TYPE_UNKNOWN' 'Info' 'Owner object types were not recorded in this inventory, so NO_HUMAN_OWNER could not be evaluated. Re-run 01-Get-NHIInventory.ps1. The absence of that finding here is not evidence of a human owner.'))
        }

        if ($orphaned) {
            $f.Add((New-Finding 'ORPHANED_OWNER' 'Critical' 'Assigned owner account is disabled. Appears governed but is not.'))
        }
    }


    # -------------------------------------------------------------------------
    # RULE 1b - SPONSOR. The accountability object owner is not.
    # -------------------------------------------------------------------------
    # Added 22 Oct 2026, after the Savill transcript confirmed the model:
    #
    #   "Every single agent ID MUST have a sponsor. So this is the person responsible. They
    #    have accountability for the agent. They decide is this agent is still needed or not.
    #    So you won't end up with these orphaned agents. Now OPTIONALLY I can add owners.
    #    That would be from a technology perspective."
    #
    # Three roles, and only one of them is accountability:
    #   SPONSOR   mandatory on agent identities. Decides whether the agent is still needed.
    #   OWNER     optional. Technical permissions ON the agent.
    #   MANAGER   optional.
    #
    # THE ASYMMETRY, which is the most valuable thing in this script:
    #
    #   An agent IDENTITY cannot exist without an accountable human.
    #   An agent on an APPLICATION SERVICE PRINCIPAL can.
    #
    # Microsoft closed the orphaned-agent hole for the new object class and left it open for
    # the old one - and the old one is what a great many tenants are still producing. The lab's
    # own jobs-alert-agent is in exactly that state: two owners, one of them a service
    # principal, and no sponsor because the concept does not apply to it.
    #
    # ===================================================================================
    # FIXED 2026-10-25. THIS RULE COULD NOT FAIL TO FIRE.
    # ===================================================================================
    # The comment above claimed the rule was "inert ... it runs only when the inventory
    # actually carries the field". THAT GUARD WAS NEVER WRITTEN. It tested
    # `if (-not $id.SponsorId)` against a SponsorId that script 01 hardcoded to $null - so
    # `-not $null` was always true and NO_SPONSOR fired at CRITICAL on every agent identity in
    # every run, asserting:
    #
    #     "Microsoft makes sponsorship mandatory at creation, so this should not be
    #      possible - something bypassed the control path."
    #
    # The portal's Owners and sponsors blade shows Root-agents with one user listed TWICE:
    # Full owner AND Sponsor. The sponsor existed throughout. The tool published three Critical
    # findings accusing Microsoft's platform of a bypassed control, in a correctly configured
    # tenant, as the top three items of an auditor-facing report.
    #
    # Two lessons, and the second is the transferable one:
    #   1. A comment describing a guard is not a guard.
    #   2. "Field is falsy" and "field was never populated" are different states. Collapsing
    #      them is the same defect as the capability probe that could only confirm its own
    #      hypothesis - a check with no path to the negative result - except this one points
    #      OUTWARD and makes an accusation about someone else's product.
    #
    # The guard is now real: the finding requires an AUTHORITATIVE lookup. Script 01 sets
    # SponsorLookupPerformed only when a sponsors endpoint actually answered.
    if ($null -ne $id.PSObject.Properties['IsAgentIdentity'] -and $id.IsAgentIdentity) {

        $sponsorLooked = ($null -ne $id.PSObject.Properties['SponsorLookupPerformed']) -and $id.SponsorLookupPerformed
        $sponsorCount  = if ($id.PSObject.Properties['SponsorCount']) { [int]$id.SponsorCount } else { 0 }

        if (-not $sponsorLooked) {
            # UNRESOLVED. No sponsors endpoint answered, so this script knows nothing about
            # sponsorship for this object and says exactly that. Info, and phrased so nobody
            # reads it as a posture finding.
            $methodNote = if ($id.PSObject.Properties['SponsorLookupErrors'] -and @($id.SponsorLookupErrors).Count -gt 0) {
                ' Candidate endpoints were tried and none answered.'
            } else { '' }
            $f.Add((New-Finding 'SPONSOR_NOT_ASSESSED' 'Info' "Agent identity. Sponsorship could not be read from Graph, so it is UNASSESSED - not absent.$methodNote Verify in Entra under the agent's Owners and sponsors blade."))
        }
        elseif ($sponsorCount -eq 0) {
            # Asked, answered, and the answer was none. NOW the finding means something -
            # Microsoft makes sponsorship mandatory at creation, so a genuine zero is a real
            # anomaly rather than an artifact of a null field.
            $f.Add((New-Finding 'NO_SPONSOR' 'Critical' "Agent identity with no sponsor, confirmed by lookup via $($id.SponsorLookupMethod). Microsoft makes sponsorship mandatory at creation, so this should not be possible - investigate how the agent was created."))
        }
        else {
            # Sponsored. Recorded positively: a tool that only ever reports problems reads as
            # noise, and an attestation needs the accountable name, not just the absence of a
            # finding about it.
            $names = @($id.Sponsors | ForEach-Object { if ($_.UserPrincipalName) { $_.UserPrincipalName } else { $_.DisplayName } })
            $f.Add((New-Finding 'AGENT_SPONSORED' 'Info' "Agent identity with $sponsorCount sponsor(s): $($names -join '; '). This is the accountable human for attestation purposes - distinct from the technical owner."))
        }
    }
    elseif ($id.IsAgentClassified) {
        # Agent-shaped, but NOT an agent identity - i.e. secured by an application service
        # principal. The sponsor concept does not apply, so there is no mandatory accountability
        # at all. This is the normal state for pre-platform agents, and that is the point.
        $f.Add((New-Finding 'SP_SECURED_AGENT' 'Medium' 'Agent secured by an application service principal rather than an agent identity. No sponsor requirement applies, so nothing guarantees an accountable human.'))
    }


    # -------------------------------------------------------------------------
    # RULE 2 - Credential hygiene
    # -------------------------------------------------------------------------
    # Managed identities are skipped entirely. Azure rotates their credentials; there is
    # literally nothing for an administrator to act on. Flagging them would be a false
    # positive that signals you do not know the platform.
    if (-not $id.IsManagedIdentity) {

        $hasPassword = $false
        $hasCert     = $false

        foreach ($c in @($id.Credentials)) {
            if ($c.Kind -eq 'Password')    { $hasPassword = $true }
            if ($c.Kind -eq 'Certificate') { $hasCert = $true }

            # Order matters here - these are mutually exclusive states, checked worst first.
            if ($c.NoExpiry) {
                # A credential with no end date never expires and will never be rotated by
                # any process that keys off expiry. Genuinely dangerous.
                $f.Add((New-Finding 'CRED_NO_EXPIRY' 'High' "$($c.Kind) '$($c.DisplayName)' has no expiry date."))
            }
            elseif ($c.Expired -eq $true) {
                # Already expired but still configured. Either the identity is broken and
                # nobody noticed, or something is still using it - both are worth knowing.
                $f.Add((New-Finding 'CRED_EXPIRED' 'High' "$($c.Kind) '$($c.DisplayName)' expired $([math]::Abs($c.DaysLeft)) days ago but remains configured."))
            }
            elseif ($null -ne $c.DaysLeft -and $c.DaysLeft -gt $LongLivedSecretDays) {
                # Valid, but for far too long. The longer a secret lives, the longer a
                # compromise of it stays useful to an attacker.
                $f.Add((New-Finding 'CRED_LONG_LIVED' 'Medium' "$($c.Kind) valid for a further $($c.DaysLeft) days - exceeds the $LongLivedSecretDays day policy."))
            }
            elseif ($null -ne $c.DaysLeft -and $c.DaysLeft -le 30 -and $c.DaysLeft -ge 0) {
                # Operational warning rather than a security finding - but useful, because an
                # unnoticed expiry means an outage.
                $f.Add((New-Finding 'CRED_EXPIRING' 'Low' "$($c.Kind) expires in $($c.DaysLeft) days."))
            }
        }

        # A recommendation rather than a defect: certificates and federated credentials are
        # both stronger than client secrets.
        if ($hasPassword -and -not $hasCert) {
            $f.Add((New-Finding 'SECRET_OVER_CERT' 'Low' 'Uses a client secret where a certificate or federated credential would be stronger.'))
        }
    }


    # NOTE on agent identities and credentials, added 22 Oct 2026.
    # Savill, 17:43 - "It is the BLUEPRINT that authenticates. These agent identities we're
    # going to end up creating DO NOT HAVE THEIR OWN CREDENTIALS."
    #
    # So RULE 2 finding nothing on an agent identity is CORRECT, not a gap. The credential
    # risk for an agent lives on its BLUEPRINT, and the blueprint is a different object this
    # script does not yet read. Microsoft's own framing of why that matters:
    #
    #   "A compromise of the blueprint's credentials affects ALL agent identities under it,
    #    which is why blueprint count is a security boundary decision."
    #
    # One blueprint can mint 250 agent identities. Assessing the children and ignoring the
    # parent inspects the symptom and skips the cause. Blueprint credential assessment is a
    # Agent object-model work - see WALKTHROUGH.md.

    # -------------------------------------------------------------------------
    # RULE 3 - Workload identity federation: a POSITIVE finding
    # -------------------------------------------------------------------------
    # Report good practice, not only problems. A tool that produces nothing but complaints
    # reads as noise; one that recognises when something is done well reads as judgement -
    # and the person reading it is far more likely to trust the complaints.
    if ($id.FederatedIdentityCredentials -and @($id.FederatedIdentityCredentials).Count -gt 0) {
        $f.Add((New-Finding 'FEDERATED_CRED' 'Info' "Uses workload identity federation ($(@($id.FederatedIdentityCredentials).Count) credential(s)) - no stored secret. Good practice."))
    }


    # -------------------------------------------------------------------------
    # RULE 4 - Excessive scope. The most valuable rule in the script.
    # -------------------------------------------------------------------------
    foreach ($r in @($id.AppRoleAssignments)) {
        $perm = $r.PermissionName
        if (-not $perm) { continue }   # unresolved GUID - cannot classify what we cannot name

        if ($perm -in $EscalationPermissions) {
            $f.Add((New-Finding 'EXCESSIVE_SCOPE_ESCALATION' 'Critical' "Holds '$perm' on $($r.ResourceDisplayName) - privilege escalation to Global Administrator is possible."))
        }
        elseif ($perm -in $HighImpactPermissions) {
            $f.Add((New-Finding 'HIGH_IMPACT_PERMISSION' 'High' "Holds '$perm' on $($r.ResourceDisplayName)."))
        }
    }


    # -------------------------------------------------------------------------
    # RULE 5 - Dormancy, and the distinction that keeps you honest
    # -------------------------------------------------------------------------
    # READ THIS CAREFULLY, because it is the difference between a careful tool and one that
    # gets an administrator to delete something they needed.
    #
    # "No sign-in record found" does NOT mean "unused". It can mean:
    #   - the identity genuinely has not been used, OR
    #   - its last use predates the log retention window, OR
    #   - it authenticates through a flow that is not captured in that report
    #
    # So we report NO_SIGNIN_RECORD and DORMANT as two different findings with different
    # severities and different wording. Never write "unused" in output you cannot prove.
    $ageDays = $null
    if ($id.CreatedDateTime) {
        $ageDays = [int]($now - ([datetime]$id.CreatedDateTime).ToUniversalTime()).TotalDays
    }

    # Only assess dormancy for identities old enough for it to mean anything. A service
    # principal created last week has not had a chance to be used.
    if ($id.ObjectClass -eq 'ServicePrincipal' -and $null -ne $ageDays -and $ageDays -gt $DormancyDays) {

        if ($id.LastSignIn) {
            # We have a record, so we can measure properly.
            $idle = [int]($now - ([datetime]$id.LastSignIn).ToUniversalTime()).TotalDays
            if ($idle -gt $DormancyDays) {
                # AGENT BASELINES ARE NOT HUMAN BASELINES. Added 22 Oct 2026.
                # Savill, 31:44 - "If I saw a human working 24 hours a day, that's a bit odd...
                # If I see an AGENT working 24 hours a day, that's EXPECTED."
                # And 36:22 - a user reading 500 documents in 5 minutes is exfiltration; an
                # agent scanning a thousand in 3 minutes is retrieval augmented generation.
                #
                # An agent may be invoked twice a year BY DESIGN and be perfectly healthy.
                # Frequency tells you almost nothing about an agent, so the service-account
                # threshold is reported under a separate code with its reasoning attached,
                # rather than being quietly applied to a population it was never written for.
                if ($id.IsAgentClassified) {
                    $f.Add((New-Finding 'DORMANT_AGENT' 'Low' "No sign-in for $idle days. NOTE: agent invocation is event-driven and may be infrequent by design - this is weaker evidence of disuse than it would be for a service account. Confirm with the sponsor before acting."))
                }
                else {
                    $f.Add((New-Finding 'DORMANT' 'Medium' "No sign-in for $idle days."))
                }
            }
        }
        elseif ($id.SignInRecordFound -eq $false) {
            # We looked and found nothing. Say exactly that, and say what it does not prove.
            $f.Add((New-Finding 'NO_SIGNIN_RECORD' 'Low' "No sign-in record found. NOT proof of disuse - may predate the log retention window. Verify before acting."))
        }
    }


    # -------------------------------------------------------------------------
    # RULE 6 - Disabled, but still holding credentials
    # -------------------------------------------------------------------------
    # Low severity because a disabled account cannot authenticate - but it is untidy, and if
    # anyone ever re-enables it the credentials come straight back with it.
    if ($id.AccountEnabled -eq $false -and @($id.Credentials).Count -gt 0) {
        $f.Add((New-Finding 'DISABLED_WITH_CREDS' 'Low' 'Account disabled but credentials remain configured.'))
    }


    # -------------------------------------------------------------------------
    # RULE 7 - IaC provenance: declared in code, or clicked into existence?
    # -------------------------------------------------------------------------
    # WHY THIS IS GUARDED, AND WHY THE GUARD IS NOT OPTIONAL
    #
    # If no state file was supplied, the managed set is empty - and an empty set means EVERY
    # identity tests as undeclared. The report would then flag all of them, which is the
    # textbook way an NHI tool gets closed and never reopened. It is the same mistake the
    # Microsoft first-party early-exit above exists to prevent, so the rule REFUSES TO RUN
    # rather than guessing. "No data" and "nothing is managed" are different claims and this
    # script will only ever make the one it can support.
    #
    # SEVERITY DESIGN - read this before changing the numbers
    #
    #   IAC_MANAGED           Info    A positive, like FEDERATED_CRED. Found in state.
    #   UNMANAGED_IDENTITY    Low     On its own this is a COVERAGE METRIC, not a
    #                                 vulnerability. Most tenants are near 100% undeclared,
    #                                 and a High finding that fires on everything is noise.
    #   UNMANAGED_PRIVILEGED  High    Undeclared AND holding escalation or high-impact
    #                                 permissions. THIS is the one that means something.
    #
    # The composite is the entire point. Joined with NO_OWNER it reads: this identity can
    # escalate to Global Administrator, nobody is accountable for it, and it exists outside
    # any declared configuration. Three findings you already produce, plus one new one.
    #
    # SCOPE - deliberately narrow, for now
    #
    # Only application-type service principals are assessed. A SYSTEM-assigned managed
    # identity is created and destroyed with its parent Azure resource and cannot be declared
    # independently, so flagging one as undeclared is a false positive. USER-assigned managed
    # identities CAN be declared (azurerm_user_assigned_identity) and telling the two apart
    # needs the ARM resource ID from alternativeNames - a refinement for later, noted in
    # measured against a real blueprint rather than guessed at here.
    if ($iacEnabled -and -not $id.IsManagedIdentity) {

        $declared = $false
        foreach ($candidate in $id.Id, $id.AppId) {
            if ($candidate -and $iacManagedIds.Contains(([string]$candidate).ToLower())) {
                $declared = $true
                break
            }
        }

        if ($declared) {
            $f.Add((New-Finding 'IAC_MANAGED' 'Info' 'Declared in Terraform state - has a repository owner, a commit justification and a reviewable change history. Good practice.'))
        }
        else {
            # Was anything serious already found on this identity? Reuse the codes rather
            # than re-deriving privilege, so the two rules can never disagree.
            $codes = $f | ForEach-Object { $_.Code }
            $isPrivileged = ($codes -contains 'EXCESSIVE_SCOPE_ESCALATION') -or
                            ($codes -contains 'HIGH_IMPACT_PERMISSION')

            if ($isPrivileged) {
                $f.Add((New-Finding 'UNMANAGED_PRIVILEGED' 'High' 'Holds privileged permissions and is NOT declared in infrastructure-as-code. No commit, no review, no intended state to detect drift against.'))
            }
            else {
                $f.Add((New-Finding 'UNMANAGED_IDENTITY' 'Low' 'Not declared in infrastructure-as-code. Created outside any reviewable configuration. Coverage gap rather than a vulnerability on its own.'))
            }
        }
    }


    # -------------------------------------------------------------------------
    # ROLL UP - what is the worst thing wrong with this identity?
    # -------------------------------------------------------------------------
    # A numeric rank lets us sort severities properly. Sorting the strings alphabetically
    # would put 'Critical' before 'High' by luck and 'Low' before 'Medium' wrongly.
    $order = @{ 'Critical' = 5; 'High' = 4; 'Medium' = 3; 'Low' = 2; 'Info' = 1 }

    # Info findings are positives, so they must not count toward the problem tally.
    $actionable = $f | Where-Object { $_.Severity -ne 'Info' }

    $top = 'None'
    if ($f.Count -gt 0) {
        $top = ($f | Sort-Object { $order[$_.Severity] } -Descending | Select-Object -First 1).Severity
    }

    # This identity had rules applied to it. External principals exited above and are counted
    # separately, so Assessed is the denominator that actually means something.
    $assessedCount++

    # Flat row for the CSV - one line per identity, openable in Excel.
    # SCHEMA NOTE: the external early-exit row above must carry these same columns. Export-Csv
    # takes its headers from the first object only.
    $rows.Add([pscustomobject]@{
        DisplayName    = $id.DisplayName

        # OBJECT ID AND THE SOURCE BLADE. Added 2026-10-25.
        #
        # 17 display names in the lab tenant produce more than one CSV row, and "Root-agents"
        # produces three. Without the object id they are indistinguishable, and a reader
        # comparing the CSV against the portal concludes the tool is wrong when it is not.
        #
        # OwnerSource names the blade the Owner column came from, because an application and
        # its service principal have SEPARATE, INDEPENDENT owner lists and Entra shows them on
        # different pages. Measured on HRProvisioning: the Enterprise application has one
        # owner, the App registration has none, and BOTH are correct. Anyone checking the CSV
        # against the portal needs to know which page to open.
        ObjectId       = $id.Id
        OwnerSource    = if ($id.ObjectClass -eq 'Application') {
                             'App registrations > Owners'
                         } else {
                             'Enterprise applications > Owners'
                         }

        ObjectClass    = $id.ObjectClass
        Type           = $id.ServicePrincipalType
        Classification = if ($id.IsManagedIdentity) { 'Managed identity' } else { 'Tenant-owned' }
        Owner          = if ($ownerNames) { $ownerNames -join '; ' } else { 'UNASSIGNED' }
        OwnerCount     = $id.OwnerCount
        Enabled        = $id.AccountEnabled
        Created        = $id.CreatedDateTime
        LastSignIn     = $id.LastSignIn
        TopSeverity    = $top
        FindingCount   = $actionable.Count
        Findings       = (($f | ForEach-Object { $_.Code }) -join '; ')
        AppId          = $id.AppId

        # Provenance on every row. The CSV is the artifact people open in Excel, forward, and
        # read a week later - and until today nothing in it said when the tenant was actually
        # read. A seventeen-hour-stale report looked exactly like a current one.
        InventoryUtc   = $inventoryGeneratedUtc
    })

    # Structured record for Phases 4 and 5 - keeps the full detail the CSV flattens away.
    if ($f.Count -gt 0) {
        $findings.Add([pscustomobject]@{
            DisplayName = $id.DisplayName
            AppId       = $id.AppId
            ObjectId    = $id.Id
            ObjectClass = $id.ObjectClass

            # Added 26 Oct 2026 after the first real run. ObjectClass alone says
            # "ServicePrincipal" for a managed identity, which is true and useless - it hides
            # the one distinction that changes how every other field should be read. Someone
            # reading the findings file without the CSV open could not tell that NO_OWNER
            # does not apply to this object class.
            Classification = if ($id.IsManagedIdentity) { 'ManagedIdentity' }
                             elseif ($id.IsTenantOwned) { 'TenantOwned' }
                             else                        { 'External' }

            # AGENT POPULATION - added 2026-10-25 to fix a live scoping bug in script 05.
            #
            # 05 decided agent-ness two ways: the presence of an agent-specific FINDING code,
            # or `Classification -eq 'Agent'`. But Classification is written three lines above
            # and is only ever ManagedIdentity / TenantOwned / External - it is NEVER 'Agent'.
            # So that branch was dead, and agent-ness collapsed to "has an agent finding".
            #
            # The consequence is the dangerous direction: a CORRECTLY GOVERNED agent - owned,
            # sponsored, not dormant - has no agent findings, so it was not counted as an agent
            # at all. With one well-governed agent in a tenant, $agentCount came out 0,
            # populationEmpty fired, and IAM-18 / IAM-16 printed NOT APPLICABLE. The better the
            # tenant, the more likely the agent controls silently scoped themselves to nothing.
            #
            # Population membership is a property of the IDENTITY, never of its findings.
            # Carried through from the inventory so 05 can read it instead of inferring it.
            IsAgent    = [bool]$id.IsAgentClassified
            AgentClass = if ($id.PSObject.Properties['AgentClass']) { $id.AgentClass } else { $null }

            Owner       = if ($ownerNames) { $ownerNames -join '; ' } else { $null }
            TopSeverity = $top
            Findings    = $f
        })
    }
}


# =============================================================================
# WRITE THE OUTPUT
# =============================================================================
$outDir = Split-Path $CsvPath -Parent
if (-not (Test-Path $outDir)) { New-Item -ItemType Directory -Path $outDir -Force | Out-Null }

# -NoTypeInformation drops the #TYPE header line that older PowerShell writes and that makes
# the file awkward to open in Excel.
$rows | Export-Csv -Path $CsvPath -NoTypeInformation -Encoding UTF8

# The findings file records the thresholds used, so a report can always be traced back to the
# parameters that produced it. Two runs with different thresholds are different assessments.
[pscustomobject]@{
    GeneratedUtc = $now.ToString('o')
    # IaCStateChecked records whether RULE 7 ran at all. A report that does not say so
    # cannot be read correctly later: 'no UNMANAGED findings' means something completely
    # different when the rule was skipped than when it ran and found none.
    # PROVENANCE OF THE UNDERLYING TENANT READ. Carried so script 05 can print it in the
    # control report and so a findings file found on disk in six months can still say when the
    # tenant was actually looked at. A findings file that cannot date itself is an assertion,
    # not evidence.
    InventoryPath        = "$InventoryPath"
    InventoryGeneratedUtc = $inventoryGeneratedUtc
    InventoryAgeHours     = $inventoryAgeHours

    # THE DENOMINATOR. Added 2026-10-25.
    #
    # This file lists EXCEPTIONS - an identity with no findings is deliberately absent, which
    # is why a service principal disappears from it the moment someone assigns it an owner.
    # That is correct, and it leaves a hole: "7 identities affected" has no "out of what".
    #
    # Without a population count, every rate in the control report is uncomputable and script
    # 05 has to infer scope from the exceptions themselves - which is precisely how $agentCount
    # came to be derived from agent FINDINGS and therefore undercounted every well-governed
    # agent to zero.
    #
    # An exceptions list that cannot state its own population is the NOT APPLICABLE problem in
    # another costume: the reader cannot tell "7 of 16 are broken" from "7 of 7 we bothered to
    # look at". Both render as "7".
    Population = @{
        TotalIdentities      = @($data.Identities).Count
        Assessed             = $assessedCount
        WithFindings         = @($findings).Count
        Clean                = $assessedCount - @($findings).Count
        ExternalSkipped      = $externalSkipped
        ServicePrincipals    = @($data.Identities | Where-Object { $_.ObjectClass -eq 'ServicePrincipal' }).Count
        Applications         = @($data.Identities | Where-Object { $_.ObjectClass -eq 'Application' }).Count
        ManagedIdentities    = @($data.Identities | Where-Object { $_.IsManagedIdentity }).Count
        # ===============================================================================
        # AGENTS vs AGENT-SHAPED OBJECTS. These are different numbers and conflating them
        # is why the tool reported 3 agent identities where the portal shows 2.
        # ===============================================================================
        # ONE AGENT IS UP TO THREE DIRECTORY OBJECTS:
        #
        #     the app registration       (definition)
        #     its service principal      (instance)
        #     the agent identity         (the Entra Agent ID object, if it has one)
        #
        # Counting objects therefore over-counts agents, and the over-count grows with how
        # well-formed the agent is - the MORE complete an agent's object graph, the more times
        # it is counted. Measured in the lab: three distinct objects are named "Root-agents"
        # and all three look agent-shaped to a per-object count.
        #
        # AgentObjectsTotal is honest about what it is: objects. AgentsDistinct is the number
        # a human means by "how many agents do I have", deduplicated on appId because an
        # application and its service principal share one, falling back to object id for
        # agent identities which have no separate appId.
        #
        # A DISCREPANCY WITH THE PORTAL IS A FINDING, NOT AN ERROR. The Agents blade filter
        # "Uses agent identity: Yes" is Entra's own count of true Agent IDs. If AgentIdentities
        # below disagrees with it, one of two things is true and both are worth knowing:
        # either this tool's detection is over-matching, or Graph types an object as
        # agentIdentity that the portal declines to list. AgentIdentityObjectIds exists so the
        # two can be compared object by object instead of argued about as totals.
        AgentObjectsTotal    = @($data.Identities | Where-Object { $_.IsAgentClassified }).Count

        AgentsDistinct       = @($data.Identities |
                                 Where-Object { $_.IsAgentClassified } |
                                 ForEach-Object { if ($_.AppId) { "appid:$($_.AppId)" } else { "oid:$($_.Id)" } } |
                                 Sort-Object -Unique).Count

        AgentIdentities      = @($data.Identities | Where-Object { $_.AgentClass -eq 'AgentIdentity' }).Count
        AgentsSpSecured      = @($data.Identities | Where-Object { $_.AgentClass -eq 'SpSecured' }).Count

        # The receipts. Compare against the portal's Agents blade directly rather than
        # trusting either count - this is the list that makes the disagreement checkable.
        AgentIdentityObjectIds = @($data.Identities |
                                   Where-Object { $_.AgentClass -eq 'AgentIdentity' } |
                                   ForEach-Object { @{ Id = $_.Id; DisplayName = $_.DisplayName; SpType = $_.ServicePrincipalType; ODataType = $_.AgentODataType } })
    }

    Parameters   = @{
        DormancyDays        = $DormancyDays
        LongLivedSecretDays = $LongLivedSecretDays
        IaCStateChecked     = $iacEnabled
        IaCDeclaredCount    = if ($iacEnabled) { $iacManagedIds.Count } else { $null }
    }
    Findings     = $findings
} | ConvertTo-Json -Depth 10 | Set-Content -Path $FindingsPath -Encoding UTF8


# =============================================================================
# SUMMARISE
# =============================================================================
Write-Host ""
Write-Host "Ownership mapping complete." -ForegroundColor Green
Write-Host "  $($rows.Count) identities classified"
Write-Host ""

foreach ($sev in 'Critical','High','Medium','Low') {
    $c = ($rows | Where-Object TopSeverity -eq $sev).Count
    if ($c -gt 0) {
        $colour = switch ($sev) { 'Critical' {'Red'} 'High' {'Yellow'} default {'Gray'} }
        Write-Host ("  {0,-9} {1}" -f $sev, $c) -ForegroundColor $colour
    }
}

# -----------------------------------------------------------------------------
# THE MONEY FINDING
# -----------------------------------------------------------------------------
# An identity that can escalate to Global Administrator AND has nobody responsible for it.
# This combination is what makes the whole tool land in a conversation - it is concrete,
# serious, and almost always present.
$crit = $findings | Where-Object {
    $_.Findings.Code -contains 'EXCESSIVE_SCOPE_ESCALATION' -and $_.Findings.Code -contains 'NO_OWNER'
}

if ($crit) {
    Write-Host ""
    Write-Host "!! $($crit.Count) identit(ies) hold escalation permissions AND have no owner." -ForegroundColor Red
    Write-Host "   This is the finding that makes the whole tool land in a conversation." -ForegroundColor Red
    foreach ($c in $crit) { Write-Host "     - $($c.DisplayName)" -ForegroundColor Red }
}

# -----------------------------------------------------------------------------
# IaC COVERAGE - the number that actually travels
# -----------------------------------------------------------------------------
# The per-identity rows are not where RULE 7 lands. THIS is:
#
#     "11% of your privileged non-human identities are declared in code."
#
# One percentage, trends over time, and it survives being repeated in a board meeting -
# which is more than can be said for a 400-row CSV.
#
# Computed over the PRIVILEGED SUBSET ONLY. A coverage figure diluted by every low-risk
# service principal in the tenant means nothing, and an auditor will say so. The full-estate
# figure is printed underneath it for context, clearly labelled as the different number it is.
if ($iacEnabled) {

    $assessed   = $findings | Where-Object { $_.Findings.Code -contains 'IAC_MANAGED' -or
                                             $_.Findings.Code -contains 'UNMANAGED_IDENTITY' -or
                                             $_.Findings.Code -contains 'UNMANAGED_PRIVILEGED' }

    $privileged = $findings | Where-Object { $_.Findings.Code -contains 'EXCESSIVE_SCOPE_ESCALATION' -or
                                             $_.Findings.Code -contains 'HIGH_IMPACT_PERMISSION' }

    $privDeclared = @($privileged | Where-Object { $_.Findings.Code -contains 'IAC_MANAGED' }).Count
    $privTotal    = @($privileged).Count

    $allDeclared  = @($assessed | Where-Object { $_.Findings.Code -contains 'IAC_MANAGED' }).Count
    $allTotal     = @($assessed).Count

    Write-Host ""
    Write-Host "Infrastructure-as-code coverage" -ForegroundColor Cyan

    if ($privTotal -gt 0) {
        $pct = [math]::Round(($privDeclared / $privTotal) * 100, 1)
        Write-Host ("  {0}% of PRIVILEGED identities are declared in code ({1} of {2})" -f $pct, $privDeclared, $privTotal) -ForegroundColor Cyan
        Write-Host "  ^ this is the figure to quote. The one below is not the same claim." -ForegroundColor DarkGray
    } else {
        Write-Host "  No privileged identities found - no privileged coverage figure to report." -ForegroundColor DarkGray
    }

    if ($allTotal -gt 0) {
        $pctAll = [math]::Round(($allDeclared / $allTotal) * 100, 1)
        Write-Host ("  {0}% of all assessed tenant-owned identities ({1} of {2})" -f $pctAll, $allDeclared, $allTotal) -ForegroundColor DarkGray
    }
}


# -----------------------------------------------------------------------------
# THE SECOND MONEY FINDING - privileged, unowned AND undeclared
# -----------------------------------------------------------------------------
# One step worse than the block above. An identity that can take over the tenant, that nobody
# is accountable for, and that exists outside any reviewable configuration. There is no
# document anywhere in the organisation that explains why this exists.
if ($iacEnabled) {
    $worst = $findings | Where-Object {
        $_.Findings.Code -contains 'UNMANAGED_PRIVILEGED' -and $_.Findings.Code -contains 'NO_OWNER'
    }

    if ($worst) {
        Write-Host ""
        Write-Host "!! $(@($worst).Count) identit(ies) are privileged, unowned AND undeclared in code." -ForegroundColor Red
        Write-Host "   Nothing in this organisation records why these exist." -ForegroundColor Red
        foreach ($w in $worst) { Write-Host "     - $($w.DisplayName)" -ForegroundColor Red }
    }
}


Write-Host ""
Write-Host "Written: $CsvPath"
Write-Host "         $FindingsPath"
Write-Host "Both contain REAL TENANT DATA - confirm .gitignore excludes them." -ForegroundColor Yellow
Write-Host "Next: .\04-Invoke-AttestationCycle.ps1 -Simulate" -ForegroundColor Cyan
