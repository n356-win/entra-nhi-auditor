<#
.SYNOPSIS
    Enumerates every non-human identity in the tenant - app registrations, service principals
    and managed identities - with their owners, credentials, permissions and sign-in activity.

.DESCRIPTION
    This is the core of this tool. It enumerates every non-human identity in an Entra tenant and
    collects what an attestation actually needs: owners, application permissions, credential
    state, dormancy, and agent classification.

    READ-ONLY. This script makes no changes to the tenant.

    PERMISSION BOUNDARY - read this before running it anywhere but your own lab:
    unlike the the external scanner DNS checks, which only read public records and are safe to run against
    anyone, this script requires authenticated access to a tenant. Run it only against a
    tenant you own or have been explicitly asked to assess.

.PARAMETER OutputPath
    Where to write the inventory JSON. Default: ..\output\nhi_inventory.json

.PARAMETER SkipSignInActivity
    Skip the beta sign-in activity lookup. Use this if you do not hold AuditLog.Read.All.
    The script still works; you just lose dormancy detection.

.PARAMETER SkipPermissions
    Skip per-identity permission enumeration. Much faster, but you lose excessive-scope
    detection - which is the most valuable finding the tool produces. Use for a quick pass
    on a large tenant, not for a real assessment.

.EXAMPLE
    .\01-Get-NHIInventory.ps1

.EXAMPLE
    .\01-Get-NHIInventory.ps1 -SkipPermissions -Verbose
    Fast pass on a large tenant, with progress detail.

.NOTES
    BETA DEPENDENCY
    Sign-in activity comes from /beta/reports/servicePrincipalSignInActivities. Beta endpoints
    can change without notice. Declare this in your published README - shipping a tool that
    silently depends on beta and breaks later costs you the trust the tool was built to earn.

    PERFORMANCE
    Owner and permission lookups are one API call per identity. A tenant with 300 service
    principals therefore makes roughly 600 extra calls and can take several minutes. This is
    unavoidable with the Graph SDK; use -SkipPermissions when you just want a quick count.
#>

[CmdletBinding()]
param(
    # ---------------------------------------------------------------------------------------
    # RUN COMPARTMENTALISATION - added 25 Oct 2026.
    # ---------------------------------------------------------------------------------------
    # Every execution writes to its own dated directory and NOTHING is ever overwritten.
    #
    # WHY THIS IS NOT HOUSEKEEPING. One dated report is a screenshot. Four consecutive dated
    # reports are a control - you can show an auditor that the non-response rate fell over four
    # quarters. Fixed output filenames destroy that on the second run, which is exactly what
    # 04 was doing until this change.
    #
    # THIS SCRIPT OWNS THE RUN ID. It creates the directory and writes a pointer file so that
    # 03 and 05 land in the SAME run without anyone having to pass the id around by hand.
    # Supply -RunId explicitly to re-run into an existing directory.
    [string]$RunId,

    [string]$OutputRoot,

    [string]$RunDir,
    [string]$OutputPath,

    [switch]$SkipSignInActivity,
    [switch]$SkipPermissions,

    # AZURE RBAC LOOKUP FOR MANAGED IDENTITIES - added 2026-10-25.
    #
    # Off by default and deliberately so. ARM is a different token audience
    # (management.azure.com) from Graph, so this needs a SECOND token the lab does not
    # otherwise acquire. With the switch off, managed identities still report
    # MI_OWNERSHIP_NOT_IN_GRAPH, which remains accurate.
    #
    # With it on, the tool answers the question instead of declaring it out of scope: it reads
    # Microsoft.Authorization/roleAssignments for each managed identity and reports who holds
    # access on the parent resource. Still read-only - Reader on the scope is enough.
    #
    # Get the token with either:
    #     Connect-AzAccount; $t = (Get-AzAccessToken -ResourceUrl 'https://management.azure.com').Token
    #     az login;          $t = az account get-access-token --resource https://management.azure.com --query accessToken -o tsv
    # then:  .\01-Get-NHIInventory.ps1 -IncludeAzureRbac -ArmAccessToken $t
    [switch]$IncludeAzureRbac,
    [string]$ArmAccessToken
)

# Resolve dependent defaults after parameter binding.
if (-not $RunId) { $RunId = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH-mmZ') }
if (-not $OutputRoot) { $OutputRoot = Join-Path $PSScriptRoot '..\output' }
if (-not $RunDir) { $RunDir = Join-Path $OutputRoot "runs\$RunId" }
if (-not $OutputPath) { $OutputPath = Join-Path $RunDir 'nhi_inventory.json' }

# Create the run directory and record it as current. 03 and 05 read this file, which means a
# human can also just open it to see which run is live - a pointer beats a second copy of
# every output file, and duplicating real tenant data on disk is a cost with no upside.
if (-not (Test-Path $RunDir)) { New-Item -ItemType Directory -Path $RunDir -Force | Out-Null }
$RunId | Set-Content -Path (Join-Path $OutputRoot 'latest-run.txt') -Encoding UTF8 -NoNewline

Write-Host "Run ID: $RunId" -ForegroundColor Cyan
Write-Host "Output: $RunDir" -ForegroundColor DarkGray

$ErrorActionPreference = 'Stop'
$script:StartTime = Get-Date

# Fail immediately and clearly if the session is not connected, rather than producing a
# confusing authentication error 200 lines later.
if (-not (Get-MgContext)) { throw "Not connected. Run .\00-Connect-Lab.ps1 first." }

# Create the output directory if it does not exist yet.
$outDir = Split-Path $OutputPath -Parent
if (-not (Test-Path $outDir)) { New-Item -ItemType Directory -Path $outDir -Force | Out-Null }


# #############################################################################
#  BACKGROUND - the three classes of non-human identity
# #############################################################################
#
#  Getting this distinction right is the difference between a useful inventory and a
#  meaningless one. Most people conflate the first two and produce nonsense.
#
#  APP REGISTRATION  (Graph type: application)
#     The DEFINITION of an application. It lives in YOUR tenant. It is where client secrets
#     and certificates are configured. When someone says "rotate the credential", this is
#     the object they mean.
#
#  SERVICE PRINCIPAL (Graph type: servicePrincipal)
#     The INSTANCE of an application inside a tenant. Every app registration has one. But so
#     does every Microsoft first-party app and every third-party SaaS product anyone in your
#     tenant has ever consented to. A typical tenant has 150-400 of these and most are NOT
#     yours.
#
#  MANAGED IDENTITY  (a servicePrincipal with servicePrincipalType = 'ManagedIdentity')
#     An Azure-managed service principal. Crucially: it has NO rotatable secret. Azure
#     handles its credentials entirely. A tool that flags managed identities for credential
#     rotation tells an experienced administrator immediately that you do not understand the
#     platform - so we exclude them from all credential findings.
#
# #############################################################################


# =============================================================================
# STEP 1 - App registrations (the definitions, owned by this tenant)
# =============================================================================
# -All makes the SDK follow pagination for you. Without it you get only the first page
# (usually 100 objects) and would silently under-report on any real tenant.
#
# -Property limits which fields Graph returns. This is not just tidiness: requesting fewer
# properties is measurably faster, and some properties are not returned at all unless you
# ask for them explicitly.
Write-Host "[1/5] Reading app registrations..." -ForegroundColor Cyan

$apps = Get-MgApplication -All -Property @(
    'id'                      # the object ID in this tenant
    'appId'                   # the GLOBAL application ID - this is the join key to service principals
    'displayName'
    'createdDateTime'
    'signInAudience'          # single tenant, multi-tenant, or personal accounts
    'passwordCredentials'     # client secrets
    'keyCredentials'          # certificates
    'requiredResourceAccess'  # permissions the app has REQUESTED (not necessarily granted)
)

Write-Host "      $($apps.Count) app registrations"


# =============================================================================
# STEP 2 - Service principals (the instances - includes Microsoft and third parties)
# =============================================================================
Write-Host "[2/5] Reading service principals..." -ForegroundColor Cyan

$sps = Get-MgServicePrincipal -All -Property @(
    'id'
    'appId'
    'displayName'
    'servicePrincipalType'    # 'Application' | 'ManagedIdentity' | 'Legacy' | 'SocialIdp'
    'accountEnabled'
    'createdDateTime'
    'passwordCredentials'
    'keyCredentials'
    'appOwnerOrganizationId'  # which tenant owns the underlying app - useful for spotting Microsoft
    'tags'
)

Write-Host "      $($sps.Count) service principals"

# -----------------------------------------------------------------------------
# THE DISTINCTION THAT MAKES THE INVENTORY CREDIBLE
# -----------------------------------------------------------------------------
# Which of these service principals do WE actually own?
#
# A service principal is tenant-owned if its appId matches one of our own app registrations.
# Everything else is Microsoft first-party (Office, Teams, Defender...) or a third-party SaaS
# product someone consented to.
#
# WHY THIS MATTERS: reporting all 300 service principals as findings is the single mistake
# that makes NHI tools get ignored. 170 of them being Microsoft's is not a finding. We still
# inventory them - you want the complete picture - but we classify them separately and never
# flag them for owner assignment.
#
# A HashSet is used rather than a plain array because we do hundreds of lookups against it;
# HashSet lookup is constant time, array lookup is not.
$ownedAppIds = [System.Collections.Generic.HashSet[string]]::new()
foreach ($a in $apps) {
    if ($a.AppId) { [void]$ownedAppIds.Add($a.AppId) }   # [void] suppresses the True/False that Add returns
}

# Print a breakdown by type. This single line of output is worth screenshotting for
# WALKTHROUGH.md - it is the first moment the tenant's real shape becomes visible.
$byType = $sps | Group-Object ServicePrincipalType | Sort-Object Count -Descending
foreach ($g in $byType) { Write-Host ("      {0,-20} {1}" -f $g.Name, $g.Count) }


# =============================================================================
# STEP 3 - Sign-in activity (BETA) - this is how dormancy is detected
# =============================================================================
# GOTCHA WORTH KNOWING: service principal sign-in activity is NOT a property of the
# servicePrincipal object. You cannot get it from Get-MgServicePrincipal no matter which
# properties you request. It lives in a completely separate beta report.
#
# This trips up almost everyone the first time.
$signInMap = @{}   # keyed by appId, so we can join it back to each service principal

if (-not $SkipSignInActivity) {
    Write-Host "[3/5] Reading sign-in activity (beta)..." -ForegroundColor Cyan
    try {
        $uri = 'https://graph.microsoft.com/beta/reports/servicePrincipalSignInActivities'
        $page = 0

        # Manual pagination. Invoke-MgGraphRequest is a raw REST call, so unlike the
        # Get-Mg* cmdlets it does NOT follow @odata.nextLink for you. You must loop.
        # This is exactly the `while response is not None` loop in azure_audit.py.
        while ($uri) {
            $resp = Invoke-MgGraphRequest -Method GET -Uri $uri

            foreach ($r in $resp.value) {
                if ($r.appId) { $signInMap[$r.appId] = $r }
            }

            # When there are no more pages, @odata.nextLink is absent and the loop ends.
            $uri = $resp.'@odata.nextLink'
            $page++
            Write-Verbose "  page $page, $($signInMap.Count) records so far"
        }

        Write-Host "      $($signInMap.Count) sign-in activity records"
    }
    catch {
        # Degrade gracefully rather than failing the whole run. Missing AuditLog.Read.All is
        # a common, recoverable situation - the rest of the inventory is still valuable.
        Write-Warning "Sign-in activity unavailable: $($_.Exception.Message)"
        Write-Warning "Dormancy detection will be degraded. This needs AuditLog.Read.All."
        Write-Warning "Worth a TROUBLESHOOTING.md entry if this is the first time you hit it."
    }
}
else {
    Write-Host "[3/5] Skipping sign-in activity (-SkipSignInActivity)" -ForegroundColor DarkGray
}


# #############################################################################
#  HELPER FUNCTIONS
# #############################################################################
#  Each does exactly one thing. Single responsibility at the function level, so a change to
#  how credentials are read cannot alter how owners are resolved.
# #############################################################################

# #############################################################################
#  OPEN QUESTION, UNRESOLVED - THE AGENT UNDERCOUNT
#  Raised 2026-10-25 by the portal, not by this script. Read before trusting any agent count.
# #############################################################################
#
#  The Entra portal's Agents | Agent identities blade lists THREE agent identities in the lab
#  tenant. Its "Uses agent identity" filter returns only TWO:
#
#      Root-agents     1a2b3c4d-0001-4000-8000-00000000a001   uses agent identity: YES
#      MSTeams-Agent   1a2b3c4d-0002-4000-8000-00000000a002   uses agent identity: YES
#      jobs-alert-agent 1a2b3c4d-0003-4000-8000-00000000a003  uses agent identity: NO
#
#  TWO CONSEQUENCES.
#
#  1. jobs-alert-agent legitimately has NO isEntraAgentId. Entra itself says it does not use an
#     agent identity - it is the documented service-principal fallback. So the tag family is
#     the ONLY way this script can classify it, and an absent isEntraAgentId on it is correct
#     rather than a gap. Four probe runs reported that absence as a finding; it was not one.
#
#  2. THE SERIOUS ONE, STILL UNVERIFIED. Root-agents and MSTeams-Agent appeared in NEITHER the
#     17 applications NOR the 325 service principals the probe enumerated. If true agent
#     identities are not addressable as service principals, THIS SCRIPT CANNOT SEE THEM - it
#     enumerates applications, servicePrincipals and managed identities, and nothing else.
#     The inventory would then undercount agents by construction, reporting 1 agent in a
#     tenant with 3, and the control report would inherit that silently.
#
#     That is the undercount argument pointing the other way: not "Agent-ID inventories
#     undercount app-registration agents", but "an app/SP inventory undercounts Agent IDs".
#     Both can be true at once, which would mean NEITHER view alone is a complete inventory -
#     a stronger and more useful finding than either on its own.
#
#  DO NOT change the enumeration on this reasoning alone. Resolve it first, by resolving each
#  agent identity id through /directoryObjects/{id} to read its @odata.type, and checking
#  whether /servicePrincipals/{id} reaches it. That answers the question with evidence instead
#  of inference, and the answer decides whether STEP 1 of this script needs a fourth source.
# #############################################################################

function Get-SponsorSummary {
    <#
        Resolves the SPONSORS of an agent identity - the mandatory accountable human.

        WHY THIS EXISTS: A FALSE POSITIVE THAT COULD NOT FAIL TO FIRE.
        --------------------------------------------------------------
        SponsorId was hardcoded to $null here, with the comment "Null is honest; a guess is
        not." That was right. What was wrong is that RULE 1b in 03-New-OwnershipMap.ps1 then
        tested `if (-not $id.SponsorId)` and raised NO_SPONSOR at CRITICAL - so a field that
        was ALWAYS null produced a finding that ALWAYS fired, on every agent identity, saying:

            "Microsoft makes sponsorship mandatory at creation, so this should not be
             possible - something bypassed the control path."

        The portal's Owners and sponsors blade for Root-agents shows the same user twice: once
        as Full owner, once as SPONSOR. The sponsor was there the whole time. The tool was
        asserting that Microsoft's mandatory control had been bypassed, at the top of an
        auditor-facing report, about a correctly configured tenant.

        That is the same defect as the capability probe that could only ever confirm its own
        hypothesis - a check with no path to the negative result - except this one points
        outward and makes an inflammatory claim about someone else's platform.

        HOW IT RESOLVES THEM
        --------------------
        The relationship name is NOT documented anywhere this lab has read, so the candidates
        below are TRIED IN ORDER and the one that answers is recorded in SponsorLookupMethod.
        Nothing is invented: if every candidate fails, the result says UNRESOLVED and RULE 1b
        stays inert rather than guessing.

        A 400/404 on a candidate is DATA, not an error - it tells you that navigation property
        does not exist on this type, which is worth recording once and not re-probing.
    #>
    param([string]$ObjectId)

    $result = @{
        Sponsors = @(); SponsorCount = 0; Looked = $false
        Method = $null; Errors = @()
    }
    if (-not $ObjectId) { return $result }

    # Ordered best-guess-first. 'sponsors' is a real Entra navigation property on USER objects
    # (B2B guest sponsorship), so Microsoft reusing the name on an agent identity is the most
    # plausible shape - but plausible is not verified, which is why the method is recorded.
    $candidates = @(
        "https://graph.microsoft.com/beta/servicePrincipals/$ObjectId/sponsors",
        "https://graph.microsoft.com/the control-mapping stage/servicePrincipals/$ObjectId/sponsors"
    )

    foreach ($uri in $candidates) {
        try {
            $resp = Invoke-MgGraphRequest -Method GET -Uri $uri -OutputType PSObject -ErrorAction Stop

            # ASSIGN, THEN WRAP. @(expression) on a property is safe; @(function-call) is not.
            $val   = if ($resp.PSObject.Properties['value']) { $resp.value } else { $null }
            $items = @($val)

            $result.Looked = $true
            $result.Method = $uri -replace '^https://graph\.microsoft\.com/', ''
            $result.Sponsors = @($items | ForEach-Object {
                [pscustomobject]@{
                    Id          = $_.id
                    DisplayName = $_.displayName
                    UserPrincipalName = $(if ($_.PSObject.Properties['userPrincipalName']) { $_.userPrincipalName } else { $null })
                    Type        = $(if ($_.PSObject.Properties['@odata.type']) { $_.'@odata.type' } else { $null })
                }
            })
            $result.SponsorCount = @($result.Sponsors).Count
            return $result
        }
        catch {
            $m = $_.ErrorDetails.Message; if (-not $m) { $m = $_.Exception.Message }
            $result.Errors += ($m -replace '\s+', ' ')
        }
    }

    # Every candidate failed. Looked stays FALSE on purpose: "I could not ask" must never be
    # recorded the same way as "I asked and the answer was none". That conflation is what
    # produced the NO_SPONSOR false positive in the first place.
    return $result
}


function Get-ManagedIdentityRbacOwner {
    <#
        Resolves accountability for a MANAGED IDENTITY from Azure RBAC, which Microsoft Graph
        cannot see.

        WHY A SECOND TOOL AND A SECOND TOKEN.
        -------------------------------------
        There are two unrelated ownership models and this lab previously read only one:

            Entra object owners   /servicePrincipals/{id}/owners        Graph  - readable
            Azure RBAC            Microsoft.Authorization/roleAssignments ARM  - NOT in Graph

        A system-assigned managed identity CANNOT have Entra owners - it is created and
        destroyed with its parent Azure resource. So MI_OWNERSHIP_NOT_IN_GRAPH was accurate,
        but it reported a boundary instead of an answer: the portal plainly showed an Owner on
        `automation-acct-01`, it was an RBAC assignment inherited from the subscription, and the tool
        said "not visible".

        ARM is a DIFFERENT AUDIENCE (management.azure.com), so the Graph token cannot call it.
        This needs its own token, which is why it is opt-in via -IncludeAzureRbac rather than
        always-on: without an ARM token the call fails, and a lab that cannot get one should
        still complete.

        STAYS READ-ONLY. Lists role assignments. Reader on the scope is sufficient.

        Honest limitation, stated because it changes how the result should be read: a role
        assignment is not the same thing as an owner. It says who CAN act on the resource, not
        who is ACCOUNTABLE for it, and an inherited subscription-level assignment often names
        a platform team rather than the person who would answer an attestation. It is better
        evidence than nothing and worse evidence than a named Entra owner - so it is reported
        as RbacPrincipals with its Scope, never merged into the Owners field.
    #>
    param(
        [string]$PrincipalId,     # the managed identity's service principal object id
        [string]$ArmToken         # bearer token for https://management.azure.com
    )

    $result = @{ RbacPrincipals = @(); Scope = $null; Looked = $false; Error = $null }
    if (-not $PrincipalId -or -not $ArmToken) { return $result }

    try {
        # Tenant-wide query for assignments naming this principal. Requires Reader somewhere
        # above the resource; returns only what the caller is allowed to see, which is the
        # correct behaviour for an auditor tool.
        $uri = "https://management.azure.com/providers/Microsoft.Authorization/roleAssignments" +
               "?api-version=2022-04-01&`$filter=principalId eq '$PrincipalId'"

        $resp = Invoke-RestMethod -Method GET -Uri $uri -Headers @{ Authorization = "Bearer $ArmToken" } -ErrorAction Stop

        $assignments = @($resp.value)
        $result.Looked = $true

        if ($assignments.Count -gt 0) {
            $result.RbacPrincipals = @($assignments | ForEach-Object {
                [pscustomobject]@{
                    Scope            = $_.properties.scope
                    RoleDefinitionId = $_.properties.roleDefinitionId
                    PrincipalType    = $_.properties.principalType
                }
            })
            $result.Scope = ($assignments | Select-Object -First 1).properties.scope
        }
    }
    catch {
        $result.Error = $_.Exception.Message
        Write-Verbose "ARM RBAC lookup failed for $PrincipalId : $($result.Error)"
    }

    return $result
}


function Get-AgentDetail {
    <#
        Re-fetches ONE agent identity by id and returns its agent-specific properties.

        WHY THIS EXISTS, AND WHY 02b DOES NOT.
        --------------------------------------
        The planned 02b-Get-AgentInventory.ps1 was going to enumerate agents separately. It is
        not needed, for two measured reasons:

          1. Script 01 ALREADY enumerates them. The 2026-10-25 inventory contains both agent
             identities as ServicePrincipalType='ServiceIdentity'. There is no undercount -
             agentIdentity is a SUBTYPE of servicePrincipal and comes back in the collection.

          2. There is nothing else to enumerate. /beta/agentIdentities, /the control-mapping stage/agentIdentities,
             /beta/directory/agentIdentities, /beta/agentIdentityBlueprints and
             /beta/directory/agentIdentityBlueprints ALL return
             400 "Resource not found for the segment". Those paths do not exist.

        What IS missing is DEPTH, not breadth: the /servicePrincipals COLLECTION returns a
        narrower projection than /servicePrincipals/{id}. Fetching by id returns 61 fields;
        the listing does not include the 11 agent-specific ones. That is why the 2026-10-25
        inventory recorded AgentDetectionMethod='ODataType:agentIdentity' - so the type WAS
        visible - while BlueprintParentId, AgentAppId and all four lifecycle fields came back
        null on the very same records.

        So 02b collapses into this function: one extra GET per agent, not a whole stage. In a
        tenant with three agents that is three requests. If an estate ever has hundreds, this
        is the thing to batch with $batch - not a reason to build a separate script.

        Returns a hashtable with null values when the fetch fails, so a caller never has to
        null-check the result itself - a failed detail fetch degrades the record, it does not
        break the run.
    #>
    param([string]$ObjectId)

    $empty = @{
        ODataType = $null; BlueprintId = $null; AgentAppId = $null; InstanceMode = $null
        LifecycleState = $null; LifecycleReason = $null; LifecycleModified = $null
        NonComplianceDisableDate = $null; DetailFetched = $false
    }
    if (-not $ObjectId) { return $empty }

    try {
        # Raw request, not the SDK cmdlet: the SDK's ServicePrincipal model has no properties
        # for agentIdentity-only fields, so it silently drops them even when the wire response
        # carries them. -OutputType PSObject keeps the shape predictable.
        $raw = Invoke-MgGraphRequest -Method GET -OutputType PSObject -ErrorAction Stop `
            -Uri "https://graph.microsoft.com/beta/servicePrincipals/$ObjectId"

        $read = {
            param($name)
            if ($raw.PSObject.Properties[$name]) { $raw.$name } else { $null }
        }

        return @{
            ODataType                = (& $read '@odata.type')
            BlueprintId              = (& $read 'agentIdentityBlueprintId')
            AgentAppId               = (& $read 'agentAppId')
            InstanceMode             = (& $read 'instanceMode')
            LifecycleState           = (& $read 'lifecyclePolicyComplianceState')
            LifecycleReason          = (& $read 'lifecyclePolicyComplianceStateReason')
            LifecycleModified        = (& $read 'lifecyclePolicyComplianceStateLastModifiedDateTime')
            NonComplianceDisableDate = (& $read 'lifecyclePolicyNonComplianceDisablementDateTime')
            DetailFetched            = $true
        }
    }
    catch {
        Write-Verbose "Agent detail fetch failed for $ObjectId : $($_.Exception.Message)"
        return $empty
    }
}


function Get-AgentTagMatch {
    <#
        Returns the tags on an object that belong to the AGENT TAG FAMILY, or an empty set.

        MEASURED, NOT GUESSED - 2026-10-25, against a live
        tenant. This replaces `tags -contains 'agent'`, which matched ZERO objects out of 17
        applications and every paged service principal. There is no tag called 'agent'.

        What a Copilot Studio agent actually carries:

            AgenticApp                                platform marker: this is an agent
            AIAgentBuilder                            platform marker: built by an agent builder
            AgentCreatedBy:CopilotStudio              PROVENANCE - which builder created it
            power-virtual-agents-<environmentGuid>    the Power Platform ENVIRONMENT

        The real vocabulary is strictly better than the one I assumed. 'agent' would have been
        a bare boolean; these carry the BUILDER and the ENVIRONMENT, which is provenance and
        blast radius - and neither is available on any documented Graph property.

        SCOPE OF THE EVIDENCE. One agent, one builder (Copilot Studio), one tenant.
        'AgenticApp' and 'AIAgentBuilder' look platform-level and 'AgentCreatedBy:' is plainly
        a prefix convention, but an agent from Foundry, Security Copilot or a third-party
        builder may tag differently. So this matches a FAMILY and the caller RECORDS which
        tags matched - the next agent either confirms the pattern or extends it, and either
        way the inventory says which it was.

        Still the weakest of the three signals. isEntraAgentId and agentSubjectParentId are
        properties set by the platform; a tag is a convention, and conventions change without
        a breaking-change notice. Ordered last for that reason.
    #>
    param($Obj)

    if ($null -eq $Obj) { return ,@() }

    # Four places tags can hide, and the 2026-10-25 run found them empty in the first one on
    # Application objects - the inventory recorded `Tags = [None]` for an app the raw Graph
    # response shows carrying four tags. The old code did `$tags = @($Obj.Tags)` and then
    # tested `.Count -eq 0` before trying the next accessor, but @($null) has Count 1, so a
    # NULL .Tags property blocked every fallback. Nulls are stripped before the count test now.
    $tags = @()
    foreach ($src in @(
        { $Obj.Tags },
        { $Obj.tags },
        { if ($Obj.PSObject.Properties['AdditionalProperties'] -and $Obj.AdditionalProperties -and
              $Obj.AdditionalProperties.ContainsKey('tags')) { $Obj.AdditionalProperties['tags'] } },
        { if ($Obj.PSObject.Properties['AdditionalProperties'] -and $Obj.AdditionalProperties -and
              $Obj.AdditionalProperties.ContainsKey('Tags')) { $Obj.AdditionalProperties['Tags'] } }
    )) {
        $candidate = @((& $src) | Where-Object { $null -ne $_ -and "$_".Trim() -ne '' })
        if ($candidate.Count -gt 0) { $tags = $candidate; break }
    }

    if ($tags.Count -eq 0) { return ,@() }

    # Comma: an empty result must stay an empty array rather than unrolling to $null, and a
    # single match must not arrive as a bare string. Same arity trap that cost four probe runs.
    return ,@($tags | Where-Object {
        $_ -eq 'AgenticApp'               -or
        $_ -eq 'AgenticInstance'          -or   # SERVICE-PRINCIPAL ONLY - see note below
        $_ -eq 'AIAgentBuilder'           -or
        $_ -like 'AgentCreatedBy:*'       -or
        $_ -like 'power-virtual-agents-*' -or
        $_ -eq 'agent'                    # the original hypothesis, kept so it is still tested
    })
}


function Get-AgentObjectRole {
    <#
        Returns 'Instance', 'Definition' or $null for an agent-tagged object.

        A DEFINITION/INSTANCE SPLIT, found by comparing the two objects in the lab tenant
        rather than from any documentation (2026-10-25):

            application      1a2b3c4d-..  AgenticApp,                  AIAgentBuilder, AgentCreatedBy:*, pva-*
            servicePrincipal 1a2b3c4d-..  AgenticApp, AgenticInstance, AIAgentBuilder, AgentCreatedBy:*, pva-*

        Same display name, same environment, same builder. The only difference is that the
        service principal also carries 'AgenticInstance'. So the application is the agent's
        DEFINITION and the service principal is its INSTANCE - the same shape as the
        blueprint/agent-identity model, expressed in tags instead of properties.

        WHY THIS MATTERS FOR THE CONTROL REPORT. The agent appears TWICE in the inventory, as
        two object classes, and a naive agent count double-counts it. Worse, the two are not
        interchangeable: only the INSTANCE can hold permissions and be signed in as, so a
        control about what an agent can reach must be evaluated against the service principal,
        while a control about how the agent was defined belongs to the application. Scoring
        both identically would report every agent finding twice and attribute half of them to
        an object that cannot have the problem.

        One agent, one builder, one tenant - so this is a PATTERN, not a rule. Recorded as a
        field rather than acted on silently.
    #>
    param($Obj, $TagMatch)

    # ASSIGN, THEN WRAP. This function shipped as `$m = @(Get-AgentTagMatch -Obj $Obj)` - the
    # @(function) trap, committed in the same edit that documented it. Get-AgentTagMatch
    # returns ,@(...) so @(...) around the CALL produced a one-element array holding the tag
    # array, every -contains test compared a string against an array and returned false, and
    # AgentObjectRole came back 'Unknown' for every object in the tenant including the one
    # carrying AgenticInstance.
    #
    # $TagMatch is accepted so callers that already computed the match pass it in instead of
    # recomputing - fewer call sites, fewer chances to reintroduce the same trap.
    $m = if ($null -ne $TagMatch) { @($TagMatch) } else {
        $tmp = Get-AgentTagMatch -Obj $Obj
        @($tmp)
    }

    if ($m.Count -eq 0) { return $null }
    if ($m -contains 'AgenticInstance') { return 'Instance' }
    if ($m -contains 'AgenticApp')      { return 'Definition' }
    return 'Unknown'
}


function Get-CredentialSummary {
    <#
        Normalises a set of password or certificate credentials into a consistent shape and
        works out the expiry state of each.

        Returns an empty set for managed identities - the caller skips them entirely, because
        a managed identity has no credential an administrator can rotate.
    #>
    param([object[]]$CredentialObjects, [string]$Kind)

    $now = (Get-Date).ToUniversalTime()   # always compare UTC to UTC; Graph returns UTC
    $out = @()

    foreach ($c in @($CredentialObjects)) {     # @() guards against $null and single-item collections
        if (-not $c) { continue }

        $end = $null
        if ($c.EndDateTime) { $end = [datetime]$c.EndDateTime }

        $daysLeft = $null
        $expired  = $null

        if ($end) {
            # Negative DaysLeft means it expired that many days ago.
            $daysLeft = [int]($end.ToUniversalTime() - $now).TotalDays
            $expired  = $end.ToUniversalTime() -lt $now
        }

        $out += [pscustomobject]@{
            Kind        = $Kind                 # 'Password' or 'Certificate'
            KeyId       = [string]$c.KeyId
            DisplayName = $c.DisplayName
            StartDate   = if ($c.StartDateTime) { ([datetime]$c.StartDateTime).ToString('o') } else { $null }
            EndDate     = if ($end) { $end.ToString('o') } else { $null }
            DaysLeft    = $daysLeft
            Expired     = $expired
            NoExpiry    = ($null -eq $end)      # a credential with no end date at all - a real finding
        }
    }
    return $out
}


# Owner id -> @{ Enabled; Resolved }. A handful of owners usually covers a whole estate, so
# caching turns one lookup per OWNERSHIP EDGE into one per DISTINCT OWNER. Script-scoped so it
# survives across every call in the run.
$script:ownerEnabledCache = @{}

function Get-OwnerSummary {
    <#
        Retrieves the owners of a service principal or app registration.

        Ownership is THE headline finding of this tool. An identity with no owner is one
        nobody can attest to, nobody will notice being abused, and nobody will clean up.

        We capture AccountEnabled on each owner because an owner whose account is DISABLED is
        worse than no owner at all: the identity looks governed and is not.
    #>
    param(
        [string]$ObjectId,
        [ValidateSet('ServicePrincipal','Application')][string]$Type
    )

    try {
        $owners = if ($Type -eq 'ServicePrincipal') {
            Get-MgServicePrincipalOwner -ServicePrincipalId $ObjectId -All -ErrorAction Stop
        } else {
            Get-MgApplicationOwner -ApplicationId $ObjectId -All -ErrorAction Stop
        }

        $res = @()
        foreach ($o in @($owners)) {
            # Owners come back as generic directoryObject. displayName, userPrincipalName and
            # @odata.type arrive in AdditionalProperties rather than as first-class properties.
            $props = $o.AdditionalProperties

            # ===========================================================================
            # accountEnabled IS NOT IN THE /owners RESPONSE. Fixed 2026-10-25.
            # ===========================================================================
            # This used to read $props['accountEnabled'] and that key is NEVER PRESENT -
            # Graph's owners navigation returns a reduced directoryObject projection without
            # it. Measured: a real inventory recorded
            #
            #     "DisplayName": "<an active user>", ..., "AccountEnabled": null
            #
            # for an account that is demonstrably enabled and signed into the portal.
            #
            # THE CONSEQUENCE WAS THAT ORPHANED_OWNER COULD NEVER FIRE. Rule 1 in script 03
            # tests `if ($o.AccountEnabled -eq $false)`, and in PowerShell `$null -eq $false`
            # is FALSE. So the Critical finding this tool describes as "the one that lands
            # hardest" - an identity whose owner has left - was unreachable code, and the
            # entire DepartedOwner bucket of the lab fixture existed to feed a rule that could
            # not produce an output.
            #
            # Third rule this week with the same defect: NO_SPONSOR could ONLY fire, NO_OWNER
            # fired falsely on agents, and this one could never fire. All three were rules
            # whose input field was never populated, and none of them failed loudly.
            #
            # Resolved with a per-owner lookup, CACHED because a handful of owners typically
            # covers an entire estate - the lab has 3 owners across ~16 identities, so this is
            # 3 calls, not 16.
            $ownerId   = $o.Id
            $odataType = $props['@odata.type']
            $enabled   = $null
            $resolved  = $false

            if ($ownerId) {
                if ($script:ownerEnabledCache.ContainsKey($ownerId)) {
                    $cached   = $script:ownerEnabledCache[$ownerId]
                    $enabled  = $cached.Enabled
                    $resolved = $cached.Resolved
                }
                else {
                    # Groups have no accountEnabled at all - absence there is correct, not a
                    # failed lookup, and marking it resolved keeps it out of the unresolved
                    # bucket in script 03.
                    if ($odataType -match 'group') {
                        $enabled = $null; $resolved = $true
                    }
                    else {
                        try {
                            $u = Invoke-MgGraphRequest -Method GET -OutputType PSObject -ErrorAction Stop `
                                 -Uri "https://graph.microsoft.com/the control-mapping stage/directoryObjects/$ownerId`?`$select=id,accountEnabled"
                            if ($u.PSObject.Properties['accountEnabled']) {
                                $enabled = [bool]$u.accountEnabled; $resolved = $true
                            }
                        }
                        catch {
                            Write-Verbose "accountEnabled lookup failed for owner $ownerId : $($_.Exception.Message)"
                        }
                    }
                    $script:ownerEnabledCache[$ownerId] = @{ Enabled = $enabled; Resolved = $resolved }
                }
            }

            $res += [pscustomobject]@{
                Id                = $ownerId
                DisplayName       = $props['displayName']
                UserPrincipalName = $props['userPrincipalName']
                AccountEnabled    = $enabled
                # Distinguishes "disabled" from "could not determine". Without this, an owner
                # whose state is unknown is indistinguishable from an enabled one, which is
                # how ORPHANED_OWNER silently died in the first place.
                EnabledResolved   = $resolved
                ObjectType        = $odataType   # tells you user vs group vs SP
            }
        }
        return $res
    }
    catch {
        # A failed owner lookup should not abort the whole inventory - log it and move on.
        Write-Verbose "Owner lookup failed for $ObjectId : $($_.Exception.Message)"
        return @()
    }
}


function Get-AppRoleSummary {
    <#
        Retrieves APPLICATION permissions granted to a service principal.

        These are the permissions the identity holds in its own right, with no signed-in user
        involved - which makes them the ones that matter most. This is where excessive scope
        actually lives, and it is the hardest and most valuable part of this tool.

        (Delegated permissions - oauth2PermissionGrants - act on behalf of a signed-in user
        and are a separate, generally lower-risk category.)
    #>
    param([string]$ServicePrincipalId)

    try {
        $grants = Get-MgServicePrincipalAppRoleAssignment -ServicePrincipalId $ServicePrincipalId -All -ErrorAction Stop

        $res = @()
        foreach ($g in @($grants)) {
            $res += [pscustomobject]@{
                ResourceDisplayName = $g.ResourceDisplayName   # e.g. "Microsoft Graph"
                ResourceId          = $g.ResourceId            # the resource SP's object ID
                AppRoleId           = [string]$g.AppRoleId     # a GUID - meaningless until resolved
            }
        }
        return $res
    }
    catch {
        Write-Verbose "App role lookup failed for $ServicePrincipalId"
        return @()
    }
}


# Resolving appRoleId GUIDs into readable permission names.
#
# Graph returns permissions as GUIDs. "Directory.ReadWrite.All" is actually
# 19dbc75e-c2e2-444c-a770-ec69d8559fc7 - unreadable, and useless for risk classification.
#
# To translate, you fetch the RESOURCE service principal (usually Microsoft Graph itself) and
# read its appRoles collection, which maps each GUID to a name.
#
# We cache aggressively because almost every grant resolves against the same handful of
# resources - without the cache this would be hundreds of redundant API calls.
$script:RoleNameCache = @{}

function Resolve-AppRoleName {
    param([string]$ResourceId, [string]$AppRoleId)

    if ([string]::IsNullOrWhiteSpace($ResourceId) -or [string]::IsNullOrWhiteSpace($AppRoleId)) { return $null }

    $key = "$ResourceId|$AppRoleId"
    if ($script:RoleNameCache.ContainsKey($key)) { return $script:RoleNameCache[$key] }

    try {
        # One call gets us EVERY role for this resource, so we cache them all at once.
        $resource = Get-MgServicePrincipal -ServicePrincipalId $ResourceId -Property 'appRoles' -ErrorAction Stop
        foreach ($r in @($resource.AppRoles)) {
            $script:RoleNameCache["$ResourceId|$($r.Id)"] = $r.Value
        }
    }
    catch {
        Write-Verbose "Could not resolve app roles for resource $ResourceId"
    }

    if ($script:RoleNameCache.ContainsKey($key)) { return $script:RoleNameCache[$key] }

    # Cache the miss too, so we do not retry a failing lookup on every subsequent identity.
    $script:RoleNameCache[$key] = $null
    return $null
}


# =============================================================================
# STEP 4 - Build the inventory
# =============================================================================
# This is the slow part: owners and permissions are one API call each, per identity.
Write-Host "[4/5] Building inventory (owners, permissions, dormancy)..." -ForegroundColor Cyan

# A generic List is used instead of += on an array. PowerShell arrays are immutable, so +=
# copies the entire array every time - fine for 10 items, painful for 400.
$inventory = [System.Collections.Generic.List[object]]::new()
$i = 0

foreach ($sp in $sps) {

    # Progress every 25 items rather than every item - Write-Progress is surprisingly
    # expensive and updating it constantly measurably slows the loop.
    $i++
    if ($i % 25 -eq 0) {
        Write-Progress -Activity "Enumerating identities" -Status "$i of $($sps.Count)" `
                       -PercentComplete (($i / [math]::Max($sps.Count,1)) * 100)
    }

    $isManagedIdentity = ($sp.ServicePrincipalType -eq 'ManagedIdentity')

    # AGENT IDENTITIES ARE TENANT-OWNED BY DEFINITION. Fixed 2026-10-25.
    #
    # THE BUG: ownership was `$ownedAppIds.Contains($sp.AppId)` alone - "is there an
    # application registration in this tenant with this appId?". An agent identity has
    # AppId == its own object id and NO application object behind it, so the test failed,
    # IsTenantOwned came out false, Classification became 'External (Microsoft / third-party)'
    # and the owner lookup below was SKIPPED entirely.
    #
    # Measured consequence in the 2026-10-25 run: Root-agents (1a2b3c4d) and MSTeams-Agent
    # (1a2b3c4d) were both filed as external third-party identities with
    # "N/A - not tenant-owned" in the owner column - two agents the user created in their own
    # tenant, reported as somebody else's. Nothing about them was attestable, and the CSV said
    # so in a way that looked deliberate rather than broken.
    #
    # ServicePrincipalType 'ServiceIdentity' is what Entra assigns an agent identity (measured:
    # 2 of 342 objects in the lab tenant). An object of that type exists because somebody in
    # THIS tenant created an agent, which is the definition of tenant-owned.
    $isAgentIdentityType = ($sp.ServicePrincipalType -eq 'ServiceIdentity')
    $isTenantOwned       = $ownedAppIds.Contains([string]$sp.AppId) -or $isAgentIdentityType

    # --- Credentials ---------------------------------------------------------
    # Skipped entirely for managed identities. See the background note at the top: they have
    # no rotatable secret, and flagging them signals you do not know the platform.
    $creds = @()
    if (-not $isManagedIdentity) {
        $creds += Get-CredentialSummary -CredentialObjects $sp.PasswordCredentials -Kind 'Password'
        $creds += Get-CredentialSummary -CredentialObjects $sp.KeyCredentials      -Kind 'Certificate'
    }

    # --- Owners --------------------------------------------------------------
    # Only looked up for identities we actually own or manage. Microsoft first-party service
    # principals have no tenant owner BY DESIGN - looking them up wastes an API call per
    # identity and flagging them would be noise.
    $owners = @()
    if ($isTenantOwned -or $isManagedIdentity) {
        $owners = Get-OwnerSummary -ObjectId $sp.Id -Type 'ServicePrincipal'
    }

    # --- Azure RBAC, managed identities only ----------------------------------
    # Opt-in. Answers the accountability question Graph structurally cannot: a system-assigned
    # managed identity has no Entra owner even in principle, and whoever holds RBAC on the
    # parent resource is the closest thing to an accountable party.
    #
    # Kept in its OWN field, never merged into Owners. A role assignment says who CAN act, not
    # who is ACCOUNTABLE - an inherited subscription-level assignment usually names a platform
    # team, not the person who would answer an attestation. Merging the two would quietly
    # upgrade weak evidence to strong.
    $rbac = $null
    if ($isManagedIdentity -and $IncludeAzureRbac) {
        $rbac = Get-ManagedIdentityRbacOwner -PrincipalId $sp.Id -ArmToken $ArmAccessToken
    }

    # --- Permissions ---------------------------------------------------------
    $appRoles = @()
    if (-not $SkipPermissions) {
        $appRoles = Get-AppRoleSummary -ServicePrincipalId $sp.Id

        # Attach the human-readable permission name to each grant. -Force overwrites if the
        # property somehow already exists, which keeps re-runs safe.
        foreach ($r in $appRoles) {
            $r | Add-Member -NotePropertyName 'PermissionName' `
                 -NotePropertyValue (Resolve-AppRoleName -ResourceId $r.ResourceId -AppRoleId $r.AppRoleId) -Force
        }
    }

    # --- Sign-in activity ----------------------------------------------------
    # Joined by appId from the map we built in step 3.
    $signIn = $signInMap[[string]$sp.AppId]

    # --- Agent tag family ----------------------------------------------------
    # Computed ONCE here rather than three times inside the record below, because it is read
    # by AgentDetectionMethod, AgentTagsMatched, AgentBuilder, AgentEnvironmentId and
    # IsAgentClassified. Assigned to a variable first - @(Get-AgentTagMatch ...) would collapse
    # a multi-tag match to Count 1, which is the arity trap documented in TROUBLESHOOTING.
    $agentTagMatch = Get-AgentTagMatch -Obj $sp
    $agentTagMatch = @($agentTagMatch)

    # --- Real agent properties (measured 2026-10-25) --------------------------
    # Read with PSObject guards because the SDK's ServicePrincipal model may not carry
    # agentIdentity-only fields even when the wire response does. Every read is a plain
    # property read on the default projection - no $select, which the negative control proved
    # is silently ignored for unknown names on these endpoints.
    $agentOdataType = $(
        if ($sp.PSObject.Properties['@odata.type']) { [string]$sp.'@odata.type' }
        elseif ($sp.PSObject.Properties['AdditionalProperties'] -and $sp.AdditionalProperties) {
            # The SDK parks unmodelled fields here, which is where '@odata.type' usually lands.
            if ($sp.AdditionalProperties.ContainsKey('@odata.type')) { [string]$sp.AdditionalProperties['@odata.type'] } else { $null }
        }
        else { $null }
    )

    # DEPTH FETCH. The collection listing does not carry the agent-specific properties - only
    # /servicePrincipals/{id} does - so an object that LOOKS like an agent gets one extra GET.
    # See Get-AgentDetail for why this replaces the planned 02b script entirely.
    #
    # Gated so the tenant is not re-queried 342 times for 3 agents: fetch only when the type
    # says ServiceIdentity, @odata.type says agentIdentity, or the tags say agent.
    $agentDetail  = $null
    $sponsorInfo  = $null
    # SUBSTRING MATCH HERE IS DELIBERATE, unlike the classification tests further down.
    # This decides only WHETHER TO FETCH MORE DETAIL, and fetching it for a blueprint
    # principal is exactly what makes the agentIdentity-vs-agentIdentityBlueprintPrincipal
    # distinction visible. Be broad when deciding what to look at; be exact when deciding
    # what something IS.
    if ($isAgentIdentityType -or ($agentOdataType -match 'agentIdentity') -or $agentTagMatch.Count -gt 0) {
        $agentDetail = Get-AgentDetail -ObjectId $sp.Id

        # The id fetch is authoritative over the listing for the type too - the listing may
        # omit @odata.type where the detail response states it.
        if ($agentDetail.ODataType) { $agentOdataType = [string]$agentDetail.ODataType }

        # SPONSORS. Only asked for objects that could have one, and the answer - including
        # "could not ask" - is recorded rather than defaulted. RULE 1b in script 03 keys off
        # SponsorLookupPerformed, so an unresolved lookup produces no finding at all.
        $sponsorInfo = Get-SponsorSummary -ObjectId $sp.Id
    }

    $agentBlueprintId = $(if ($agentDetail) { $agentDetail.BlueprintId }  else { $null })
    $agentAppIdValue  = $(if ($agentDetail) { $agentDetail.AgentAppId }   else { $null })

    $inventory.Add([pscustomobject]@{
        ObjectClass          = 'ServicePrincipal'
        Id                   = $sp.Id
        AppId                = $sp.AppId
        DisplayName          = $sp.DisplayName
        ServicePrincipalType = $sp.ServicePrincipalType
        IsManagedIdentity    = $isManagedIdentity
        IsTenantOwned        = $isTenantOwned

        # -----------------------------------------------------------------------------------
        # AGENT CLASSIFICATION - added 27 Oct 2026. THESE WERE DEAD PROPERTIES.
        # -----------------------------------------------------------------------------------
        # 03-New-OwnershipMap.ps1 reads IsAgentIdentity, IsAgentClassified and SponsorId. This
        # script never wrote them, so every agent rule has been dead code since it was added -
        # which is why SP_SECURED_AGENT appeared nowhere in the first real run despite the lab
        # containing exactly that.
        #
        # THE REAL DISCRIMINATORS ARE DOCUMENTED BUT THE PROPERTY NAMES ARE NOT VERIFIED:
        #   - agent identities are service principals with an "agent" SUBTYPE CLASSIFICATION
        #   - they carry ParentID pointing at their blueprint
        #   - sponsorship is MANDATORY on agent identities and absent on application SPs
        #
        # Those exact Graph property names have since been measured against a live tenant.
        # Before they were,
        # this uses a NAME HEURISTIC, which is weak and is marked as such everywhere it lands.
        #
        # ===================================================================================
        # CORRECTED 2026-10-25. isEntraAgentId AND agentSubjectParentId DO NOT EXIST.
        # ===================================================================================
        # They came from reading beta $metadata, and $metadata is a schema catalogue for every
        # type Graph knows - not a statement about what an object returns. Worse, the probe
        # that "confirmed" them used $select, and the negative control proved Graph SILENTLY
        # IGNORES unknown $select names on these endpoints: a property that cannot exist came
        # back 200 with the name quietly dropped, exactly like these two did. So "accepted but
        # not returned" never meant "exists but null" - it meant NOTHING.
        #
        # What settled it was reading a REAL agent identity's default projection, where every
        # field returned is a field that exists, no interpretation required:
        #
        #     GET /beta/servicePrincipals/1a2b3c4d-0001-4000-8000-00000000a001
        #     @odata.type = #microsoft.graph.agentIdentity          <- 61 fields, not 50
        #
        # THE REAL AGENT PROPERTIES, measured not guessed - 11 beyond a plain servicePrincipal:
        #
        #   @odata.type                       '#microsoft.graph.agentIdentity' - THE discriminator
        #   agentIdentityBlueprintId          the blueprint link (what I called agentSubjectParentId)
        #   agentAppId                        the agent's app id
        #   instanceMode
        #   clientIdMetadataDocumentUrl       }
        #   hasClientIdMetadataDocument       } client-id metadata document
        #   lifecyclePolicyComplianceState                      }
        #   lifecyclePolicyComplianceStateReason                } LIFECYCLE GOVERNANCE,
        #   lifecyclePolicyComplianceStateLastModifiedDateTime  } straight off the object
        #   lifecyclePolicyNonComplianceDisablementDateTime     }
        #
        # The lifecycle four are the find. Entra tracks an agent's compliance with a lifecycle
        # policy AND the date it gets auto-disabled for non-compliance, as first-class readable
        # properties. That is attestation evidence Microsoft maintains for you - nothing in this
        # lab needs to infer it.
        #
        # MEASURED IN THE LAB TENANT: both agents return
        #   agentAppId = agentIdentityBlueprintId = 1a2b3c4d-0005-4000-8000-00000000a005
        # One blueprint, two agents - matching the portal exactly, and confirming that BLUEPRINT
        # COUNT IS THE SECURITY BOUNDARY: the blueprint holds the credentials, the agents hold none.
        #
        # AND THE SPLIT THAT MATTERS MOST. The SP-secured agent (jobs-alert-agent) returns a
        # 50-field plain servicePrincipal with NO field matching /agent/i at all. So:
        #
        #   true agentIdentity  -> typed object, blueprint link, lifecycle compliance state
        #   SP-secured agent    -> nothing. TAGS ARE THE ONLY EVIDENCE THAT IT IS AN AGENT.
        #
        # Two classes of agent in one tenant with completely different governance surfaces.
        # The tag family is not the weak signal it was ordered last as - for the SP-secured
        # class it is the ONLY signal, and that is the lab's headline.
        #
        # Property reads stay PSObject-guarded: the Graph PowerShell SDK may not deserialise
        # agentIdentity-only fields onto its ServicePrincipal model even when the wire response
        # carries them. If BlueprintParentId comes back null on a known agent, that is the
        # cause - switch that call to Invoke-MgGraphRequest and read the raw object.
        #
        # THE TAG SIGNAL IS NOT PROVEN. This comment used to read "PROVEN: the probe
        # beta/applications?$filter=tags/any(t:t eq 'agent') returned 200 with exactly 1 item."
        # Two things were wrong with that, and both are worth keeping written down:
        #
        #   1. The "1 item" count came out of probe code that had a known object-shape bug at
        #      the time it printed that number. The 2026-10-25 re-run, with the reader fixed,
        #      got a 200 with an EMPTY collection from the same filter. One of those two counts
        #      is wrong and the broken-reader one is the likelier candidate.
        #
        #   2. OBJECT TYPE MISMATCH, which survives regardless of the count. The probe filtered
        #      /applications. This code reads $sp.Tags on a SERVICE PRINCIPAL. Those are
        #      different entities with independently populated tag collections, so a result on
        #      one was never evidence about the other. The probe's ground-truth step now checks
        #      both collections for exactly this reason.
        #
        # Treat 'Tag' in AgentDetectionMethod as an inference until the probe's ground-truth
        # table shows a real tag vocabulary. isEntraAgentId and agentSubjectParentId are
        # properties set by the platform; a tag is a naming convention, and conventions are
        # the weakest evidence in this list, which is why it is ordered last.
        #
        # The name heuristic is GONE. A tag is set by the platform; a display name is set by
        # whoever typed it, and '(Microsoft Copilot Studio)' would have missed every agent
        # from Foundry, Security Copilot or a third-party builder.
        #
        # Ordered best-evidence-first so AgentDetectionMethod records HOW each classification
        # was reached. A reader must be able to tell a confirmed agent from an inferred one
        # without re-running anything.
        # EXACT TYPE MATCH, NOT A SUBSTRING. Fixed 2026-10-26.
        #
        # This tested `-match 'agentIdentity'`, which is a SUBSTRING match - and Graph has a
        # second type whose name contains it:
        #
        #     #microsoft.graph.agentIdentity                     a real agent identity
        #     #microsoft.graph.agentIdentityBlueprintPrincipal   the BLUEPRINT's principal
        #
        # So the blueprint's service principal was classified as an agent identity. The tool
        # reported 3 agent identities where the portal's "Uses agent identity: Yes" filter
        # shows 2, and the extra one was bf4d34b1 - the Root-agents BLUEPRINT, not an agent.
        #
        # The portal was right and the regex was wrong. Worth noting how it was caught: by
        # recording AgentODataType as a FIELD rather than only matching on it, so the actual
        # value could be read back. A classification you cannot inspect is one you cannot
        # check, and this one disagreed with Entra's own count for days.
        AgentDetectionMethod = $(
            if     ($agentOdataType -eq '#microsoft.graph.agentIdentity')          { 'ODataType:agentIdentity' }
            elseif ($agentOdataType -match 'agentIdentityBlueprintPrincipal')      { 'ODataType:blueprintPrincipal' }
            elseif ($agentBlueprintId)                                             { 'AgentIdentityBlueprintId' }
            elseif ($agentTagMatch.Count -gt 0)                                    { "TagFamily:$($agentTagMatch -join '+')" }
            else                                                                   { 'None' }
        )

        # The blueprint is the SECURITY BOUNDARY, not an agent. It holds the credentials the
        # agents it mints do not have, and one blueprint can mint up to 250 identities - so it
        # belongs in the inventory, counted separately, never inside the agent population.
        IsAgentBlueprint = [bool]($agentOdataType -match 'agentIdentityBlueprintPrincipal')

        # The matching tags themselves, not just the fact that something matched. An auditor
        # asking "why is this an agent?" gets the evidence instead of a boolean.
        AgentTagsMatched = $agentTagMatch

        # 'Instance' on a service principal carrying AgenticInstance. The object that can hold
        # permissions and be signed in as - so this is the one agent-reachability controls must
        # be scored against, and the one that must not be double-counted with its application.
        AgentObjectRole = (Get-AgentObjectRole -Obj $sp -TagMatch $agentTagMatch)

        # PROVENANCE and BLAST RADIUS, both lifted out of the tags because neither exists as a
        # documented Graph property. AgentCreatedBy: names the builder that created the agent;
        # power-virtual-agents-<guid> names the Power Platform environment it lives in.
        # These are exactly the two facts an attestation record needs and cannot otherwise get.
        AgentBuilder = $(
            $b = @($agentTagMatch | Where-Object { $_ -like 'AgentCreatedBy:*' }) | Select-Object -First 1
            if ($b) { $b -replace '^AgentCreatedBy:','' } else { $null }
        )
        AgentEnvironmentId = $(
            $e = @($agentTagMatch | Where-Object { $_ -like 'power-virtual-agents-*' }) | Select-Object -First 1
            if ($e) { $e -replace '^power-virtual-agents-','' } else { $null }
        )

        # TRUE agent identity - the modern object class, confirmed by Entra's own boolean.
        # Still beta-only, so it may be absent; absent means false, not "assume yes".
        # TRUE agent identity, by the only discriminator that survived measurement: Graph
        # returns '#microsoft.graph.agentIdentity' as the object's @odata.type. The blueprint
        # link is accepted as a fallback because an object carrying agentIdentityBlueprintId is
        # an agent identity whatever the SDK did or did not deserialise onto @odata.type.
        IsAgentIdentity = [bool](($agentOdataType -eq '#microsoft.graph.agentIdentity') -or
                                 ($agentBlueprintId -and $agentOdataType -notmatch 'BlueprintPrincipal'))

        # Agent-SHAPED by any route. This is what scopes the agentic controls, and it must
        # include SP-secured agents - they carry NO agent property of any kind (measured: the
        # SP-secured agent returns a plain 50-field servicePrincipal with nothing matching
        # /agent/i), so tags are the only thing that classifies them and excluding tag matches
        # would hide the finding this lab exists for.
        IsAgentClassified = [bool](
            ($agentOdataType -eq '#microsoft.graph.agentIdentity') -or
            ($agentBlueprintId -and $agentOdataType -notmatch 'BlueprintPrincipal') -or
            ($agentTagMatch.Count -gt 0)
        )

        # WHICH CLASS OF AGENT. The two have completely different governance surfaces, and a
        # control report that cannot tell them apart will claim coverage it does not have:
        #   AgentIdentity -> typed object, blueprint link, lifecycle compliance state
        #   SpSecured     -> nothing readable; tags are the sole evidence
        AgentClass = $(
            if     ($agentOdataType -match 'agentIdentityBlueprintPrincipal')       { 'Blueprint' }
            elseif (($agentOdataType -eq '#microsoft.graph.agentIdentity') -or $agentBlueprintId) { 'AgentIdentity' }
            elseif ($agentTagMatch.Count -gt 0)                                     { 'SpSecured' }
            else                                                                    { $null }
        )

        # The blueprint's own app id. Equal to AgentIdentityBlueprintId in the lab tenant.
        AgentAppId = $agentAppIdValue

        # Platform-maintained lifecycle evidence. Null on everything that is not a true agent
        # identity - including SP-secured agents, which is itself the point: Entra tracks
        # lifecycle compliance for one class of agent and not the other.
        AgentLifecycleComplianceState  = $(if ($agentDetail) { $agentDetail.LifecycleState }           else { $null })
        AgentLifecycleComplianceReason = $(if ($agentDetail) { $agentDetail.LifecycleReason }          else { $null })
        AgentLifecycleStateModified    = $(if ($agentDetail) { $agentDetail.LifecycleModified }        else { $null })
        AgentNonComplianceDisableDate  = $(if ($agentDetail) { $agentDetail.NonComplianceDisableDate } else { $null })
        AgentInstanceMode              = $(if ($agentDetail) { $agentDetail.InstanceMode }             else { $null })

        # Distinguishes "not an agent, so no lifecycle data expected" from "an agent whose
        # detail fetch failed". Without it, a null lifecycle state reads as a clean result in
        # both cases - the NOT APPLICABLE problem one field down.
        AgentDetailFetched             = $(if ($agentDetail) { [bool]$agentDetail.DetailFetched } else { $false })

        # Azure RBAC on the parent resource, for managed identities. Separate from Owners on
        # purpose - see the note at the lookup. RbacLookupPerformed distinguishes "not asked"
        # from "asked and found nothing", which is the same absent-versus-empty distinction
        # that cost four probe runs.
        RbacPrincipals                 = $(if ($rbac) { @($rbac.RbacPrincipals) } else { @() })
        RbacScope                      = $(if ($rbac) { $rbac.Scope }  else { $null })
        RbacLookupPerformed            = $(if ($rbac) { [bool]$rbac.Looked } else { $false })
        RbacLookupError                = $(if ($rbac) { $rbac.Error }  else { $null })

        # The raw type string, recorded rather than only matched on, so a reader can check the
        # classification instead of trusting it. The 2026-10-25 run classified an ordinary
        # Application-type SP (1a2b3c4d) as AgentClass=AgentIdentity and there was no way to
        # see what @odata.type it had actually returned.
        AgentODataType                 = $agentOdataType

        # The blueprint this agent descends from. Null on an application service principal -
        # which is itself the SP_SECURED_AGENT signal, and is the IAM-AG-03 delegation check
        # once 02b enumerates blueprints.
        BlueprintParentId = $agentBlueprintId

        # SPONSOR - the mandatory accountable human on an agent identity.
        #
        # This WAS hardcoded `SponsorId = $null` with the note "Null is honest; a guess is
        # not." The note was right and the consequence was not: RULE 1b in script 03 tested
        # `if (-not $id.SponsorId)` and raised NO_SPONSOR at Critical, so an always-null field
        # produced an always-firing finding claiming Microsoft's mandatory control had been
        # bypassed. The portal shows Root-agents with a Sponsor AND a Full owner, both the same
        # user. The tool was wrong about a correctly configured tenant, loudly, at the top of
        # the report.
        #
        # Now resolved by lookup, with the critical distinction preserved in its own field:
        #   SponsorLookupPerformed = $true  -> the answer is authoritative, 0 means 0
        #   SponsorLookupPerformed = $false -> UNRESOLVED; script 03 must not infer anything
        Sponsors              = $(if ($sponsorInfo) { @($sponsorInfo.Sponsors) } else { @() })
        SponsorCount          = $(if ($sponsorInfo) { [int]$sponsorInfo.SponsorCount } else { 0 })
        SponsorLookupPerformed= $(if ($sponsorInfo) { [bool]$sponsorInfo.Looked } else { $false })
        SponsorLookupMethod   = $(if ($sponsorInfo) { $sponsorInfo.Method } else { $null })
        SponsorLookupErrors   = $(if ($sponsorInfo) { @($sponsorInfo.Errors) } else { @() })

        # Kept for compatibility with anything already reading it, but derived from the lookup
        # instead of being a permanent null.
        SponsorId = $(
            if ($sponsorInfo -and @($sponsorInfo.Sponsors).Count -gt 0) { @($sponsorInfo.Sponsors)[0].Id }
            else { $null }
        )

        AccountEnabled       = $sp.AccountEnabled
        CreatedDateTime      = if ($sp.CreatedDateTime) { ([datetime]$sp.CreatedDateTime).ToString('o') } else { $null }
        Owners               = $owners
        OwnerCount           = $owners.Count
        Credentials          = $creds
        AppRoleAssignments   = $appRoles
        LastSignIn           = if ($signIn) { $signIn.lastSignInActivity.lastSignInDateTime } else { $null }

        # IMPORTANT: this flag distinguishes "we looked and found no record" from "we never
        # looked". Phase 3 needs that difference to avoid reporting an identity as unused
        # when we simply have no data about it.
        SignInRecordFound    = [bool]$signIn
    })
}
Write-Progress -Activity "Enumerating identities" -Completed


# -----------------------------------------------------------------------------
# App registrations are inventoried SEPARATELY from service principals.
# -----------------------------------------------------------------------------
# They are the definitions, and their credentials are the ones that actually get rotated.
# Treating them as the same object type as service principals is the conflation error
# described at the top of this script.
foreach ($app in $apps) {

    $creds  = @()
    $creds += Get-CredentialSummary -CredentialObjects $app.PasswordCredentials -Kind 'Password'
    $creds += Get-CredentialSummary -CredentialObjects $app.KeyCredentials      -Kind 'Certificate'

    $owners = Get-OwnerSummary -ObjectId $app.Id -Type 'Application'

    # --- Workload identity federation: a POSITIVE finding --------------------
    # Federated credentials mean the app authenticates using a token from an external issuer
    # (GitHub Actions, Kubernetes, another cloud) and has NO stored secret at all.
    #
    # This is the strongest possible remediation for credential findings - it does not rotate
    # the secret, it eliminates it. We detect it so the report can say so.
    #
    # A tool that only ever reports problems reads as noise. One that recognises good practice
    # reads as judgement.
    $fedCreds = @()
    try {
        $fed = Invoke-MgGraphRequest -Method GET `
               -Uri "https://graph.microsoft.com/the control-mapping stage/applications/$($app.Id)/federatedIdentityCredentials"

        foreach ($f in @($fed.value)) {
            $fedCreds += [pscustomobject]@{
                Name    = $f.name
                Issuer  = $f.issuer     # who is trusted to issue the token
                Subject = $f.subject    # WHICH identity from that issuer - over-broad subject
                                        # matching is the whole vulnerability class here
            }
        }
    }
    catch {
        Write-Verbose "No federated credentials readable for $($app.DisplayName)"
    }

    # --- Agent tag family, on the APPLICATION ---------------------------------
    # ADDED 2026-10-25, and it closes a gap that would have hidden the lab's only agent.
    #
    # The ground-truth probe found the agent tags on the APPLICATION object
    # (jobs-alert-agent, 1a2b3c4d-0004-4000-8000-00000000a004) - 1 of 17 applications tagged,
    # and NOT on any service principal in the paged enumeration. But agent classification was
    # only ever computed in the service-principal branch, so this record came out with no
    # agent fields whatsoever.
    #
    # The consequence was silent and total: script 05 scopes the agentic controls with
    # Select-ForControl on IsAgentClassified. A record missing that property is never selected,
    # so IAM-18 and IAM-16 would have reported an EMPTY agent population - NOT APPLICABLE -
    # in a tenant that demonstrably contains an agent. The headline finding of the whole lab,
    # scoped out of its own control report by a missing field.
    # ASSIGN, THEN WRAP - the @(function) trap again, and this one was the expensive instance.
    #
    # Written as `@(Get-AgentTagMatch -Obj $app)` this produced a NESTED array: AgentTagsMatched
    # came out as [[]] whose .Count is 1, so `$agentTagMatchApp.Count -gt 0` was TRUE for every
    # application in the tenant. All 17 app registrations were classified as agents, the report
    # announced "service-principal-secured: 17" when the real number is 1, and
    # AgentDetectionMethod printed the literal string "TagFamily:System.Object[]" because
    # -join on a nested array stringifies the inner array.
    #
    # Sixteen false agents in an auditor-facing document, from one pair of parentheses.
    $tagMatchAppRaw   = Get-AgentTagMatch -Obj $app
    $agentTagMatchApp = @($tagMatchAppRaw)

    $inventory.Add([pscustomobject]@{
        ObjectClass                  = 'Application'
        Id                           = $app.Id
        AppId                        = $app.AppId
        DisplayName                  = $app.DisplayName
        ServicePrincipalType         = 'AppRegistration'
        IsManagedIdentity            = $false
        IsTenantOwned                = $true      # by definition - it is in our tenant
        AccountEnabled               = $null      # not applicable to app registrations
        CreatedDateTime              = if ($app.CreatedDateTime) { ([datetime]$app.CreatedDateTime).ToString('o') } else { $null }
        Owners                       = $owners
        OwnerCount                   = $owners.Count
        Credentials                  = $creds
        AppRoleAssignments           = @()
        FederatedIdentityCredentials = $fedCreds
        SignInAudience               = $app.SignInAudience

        # Same shape as the service-principal record so every downstream filter works on both
        # object classes without special-casing. An application has no isEntraAgentId and no
        # agentSubjectParentId - those are service-principal properties - so tags are the only
        # agent signal available here, and AgentDetectionMethod says so plainly.
        # Recorded from the same multi-accessor read the tag match uses, so the inventory shows
        # the tags that were actually evaluated. Reading $app.Tags directly here is what put
        # `Tags = [None]` in the 2026-10-25 inventory next to a populated AgentTagsMatched.
        Tags                         = @($tagMatchAppRaw)
        AgentTagsMatched             = $agentTagMatchApp

        # 'Definition' - an application carries AgenticApp but NOT AgenticInstance. It defines
        # the agent; it cannot hold permissions or sign in. Controls about agent REACHABILITY
        # belong to the Instance record, not this one.
        AgentObjectRole              = (Get-AgentObjectRole -Obj $app -TagMatch $agentTagMatchApp)
        AgentDetectionMethod         = $(
            if ($agentTagMatchApp.Count -gt 0) { "TagFamily:$($agentTagMatchApp -join '+')" } else { 'None' }
        )
        AgentBuilder                 = $(
            $b = @($agentTagMatchApp | Where-Object { $_ -like 'AgentCreatedBy:*' }) | Select-Object -First 1
            if ($b) { $b -replace '^AgentCreatedBy:','' } else { $null }
        )
        AgentEnvironmentId           = $(
            $e = @($agentTagMatchApp | Where-Object { $_ -like 'power-virtual-agents-*' }) | Select-Object -First 1
            if ($e) { $e -replace '^power-virtual-agents-','' } else { $null }
        )
        IsAgentIdentity              = $false     # never true on an application object
        IsAgentClassified            = [bool]($agentTagMatchApp.Count -gt 0)
        BlueprintParentId            = $null      # service-principal concept only
        SponsorId                    = $null

        # Same field set as the service-principal record so no downstream filter has to
        # special-case object class. An application is only ever the DEFINITION half of an
        # agent, so it is 'SpSecured' at most and never carries lifecycle state - Entra tracks
        # that on the agent identity, which is a service principal.
        AgentClass                     = $(if ($agentTagMatchApp.Count -gt 0) { 'SpSecured' } else { $null })
        AgentAppId                     = $null
        AgentLifecycleComplianceState  = $null
        AgentLifecycleComplianceReason = $null
        AgentLifecycleStateModified    = $null
        AgentNonComplianceDisableDate  = $null
        AgentInstanceMode              = $null

        # Applications have no agent-detail endpoint - lifecycle state lives on the agent
        # identity, which is a service principal. False here means "not applicable", not
        # "fetch failed", and the field exists so those two cannot be confused downstream.
        AgentDetailFetched             = $false
        AgentODataType                 = $null

        # Applications are not Azure resources, so there is no RBAC plane to read.
        RbacPrincipals                 = @()
        RbacScope                      = $null
        RbacLookupPerformed            = $false
        RbacLookupError                = $null
    })
}


# =============================================================================
# STEP 5 - Write the output and summarise
# =============================================================================
Write-Host "[5/5] Writing output..." -ForegroundColor Cyan

# The output records not just the data but the CONDITIONS it was gathered under: which
# tenant, when, which beta endpoints were involved. An assessment artifact that cannot say
# how it was produced is not much use to an auditor.
$payload = [pscustomobject]@{
    GeneratedUtc      = (Get-Date).ToUniversalTime().ToString('o')
    TenantId          = (Get-MgContext).TenantId
    ToolVersion       = '0.5-dev'
    BetaEndpointsUsed = @(if (-not $SkipSignInActivity) { 'reports/servicePrincipalSignInActivities' })
    Counts            = [pscustomobject]@{
        AppRegistrations  = $apps.Count
        ServicePrincipals = $sps.Count
        TenantOwned       = ($inventory | Where-Object IsTenantOwned).Count
        ManagedIdentities = ($inventory | Where-Object IsManagedIdentity).Count
        External          = ($inventory | Where-Object { -not $_.IsTenantOwned }).Count
    }
    Identities        = $inventory
}

# -Depth 12 matters. ConvertTo-Json defaults to depth 2 and will SILENTLY truncate nested
# objects - your credentials and owners would come out as the literal string
# "System.Object[]". This is one of the most common PowerShell data-loss bugs.
$payload | ConvertTo-Json -Depth 12 | Set-Content -Path $OutputPath -Encoding UTF8

$elapsed = [int]((Get-Date) - $script:StartTime).TotalSeconds

Write-Host ""
Write-Host "Inventory complete in ${elapsed}s" -ForegroundColor Green
Write-Host ("  App registrations : {0}" -f $payload.Counts.AppRegistrations)
Write-Host ("  Service principals: {0}" -f $payload.Counts.ServicePrincipals)
Write-Host ("  Tenant-owned      : {0}" -f $payload.Counts.TenantOwned)
Write-Host ("  Managed identities: {0}" -f $payload.Counts.ManagedIdentities)
Write-Host ("  External (MS/3rd) : {0}" -f $payload.Counts.External)
Write-Host ""

# A preview of the headline finding. Phase 3 does the real classification, but seeing this
# number at the end of Phase 1 is the moment the tool first justifies itself.
$noOwner = $inventory | Where-Object { $_.IsTenantOwned -and $_.OwnerCount -eq 0 }
if ($noOwner) {
    Write-Host "$($noOwner.Count) tenant-owned identities have NO OWNER." -ForegroundColor Yellow
    Write-Host "That is the headline finding. Phase 3 classifies and scores it." -ForegroundColor Yellow
}

Write-Host ""
Write-Host "Written to: $OutputPath"
Write-Host "This file contains REAL TENANT DATA - confirm .gitignore excludes it." -ForegroundColor Yellow
Write-Host "Next: .\03-New-OwnershipMap.ps1" -ForegroundColor Cyan
