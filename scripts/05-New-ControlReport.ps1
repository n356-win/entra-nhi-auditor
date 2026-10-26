<#
.SYNOPSIS
    Maps the Phase 3 findings to published control sets and produces an auditor-shaped
    report. This is the control-mapping stage - the layer that makes the tool citable rather than merely useful.

.DESCRIPTION
    NIST, CSA and OWASP all published agentic control sets in February 2026. Every one of them
    tells you what SHOULD be true. Not one of them tells you whether it IS true in a specific
    tenant. This script is that missing layer, and it is the whole reason the tool is worth
    building.

    Reads  : output/nhi_findings.json       (from 03-New-OwnershipMap.ps1)
             reference/control-map.json      YOUR mapping - see the note below
    Writes : output/control_report.md

.PARAMETER ControlMapPath
    JSON mapping control IDs to finding codes. YOU write this after reading the source
    documents. A starter file is generated on first run if one does not exist.

.PARAMETER Anonymise
    Replace identity names with Identity-001, Identity-002 and so on. Use this for anything
    you publish - see the note at the bottom of this help.

.EXAMPLE
    .\05-New-ControlReport.ps1

.EXAMPLE
    .\05-New-ControlReport.ps1 -Anonymise
    Safe for publication - no real identity names in the output.

.NOTES
    THE CONTROL MAP IS YOURS TO WRITE, AND THAT IS DELIBERATE

    This script ships with PLACEHOLDER control IDs rather than real ones. That is not
    laziness - putting fabricated standard citations into an auditor-facing report is the
    fastest conceivable way to destroy the tool's credibility, and an auditor would catch it
    within minutes.

    Read the CSA AICM Agentic Control Supplement and the NIST NCCoE agent identity paper,
    then fill in reference/control-map.json yourself. The script warns loudly, in the console
    AND in the report, until you have.

    See reference/CONTROL-MAPPING.md for the table structure and for the list of controls
    that genuinely CANNOT be tested from directory data.
#>

[CmdletBinding()]
param(
    # RUN COMPARTMENTALISATION - added 25 Oct 2026. See 01-Get-NHIInventory.ps1 for the why.
    #
    # The report lands in the SAME run directory as the findings it was built from. That is
    # not tidiness: a control report separated from the evidence that produced it cannot be
    # defended. Keeping them together means a run directory is a complete, self-contained
    # assessment that still makes sense when opened a year later.
    [string]$OutputRoot = (Join-Path $PSScriptRoot '..\output'),

    [string]$RunId = $(
        $pointer = Join-Path $OutputRoot 'latest-run.txt'
        if (Test-Path $pointer) { (Get-Content $pointer -Raw).Trim() }
        else { throw "No run found. Run 01-Get-NHIInventory.ps1 first, or pass -RunId." }
    ),

    [string]$RunDir         = (Join-Path $OutputRoot "runs\$RunId"),
    [string]$FindingsPath   = (Join-Path $RunDir 'nhi_findings.json'),
    [string]$ReportPath     = (Join-Path $RunDir 'control_report.md'),

    # The control map is NOT per-run. It is the mapping itself, versioned with the repo, and
    # a run directory records which findings were produced - not which controls exist.
    [string]$ControlMapPath = (Join-Path $PSScriptRoot '..\reference\control-map.json'),

    [switch]$Anonymise
)

$ErrorActionPreference = 'Stop'

if (-not (Test-Path $FindingsPath)) {
    throw "Findings not found at $FindingsPath. Run 03-New-OwnershipMap.ps1 first."
}


# =============================================================================
# STEP 1 - The control map (generated as a starter if absent)
# =============================================================================
# The structure is the point here, not the content. Each entry answers four questions:
#   Which standard?  Which control?  Which of MY findings prove or disprove it?
#   And crucially - can it be fully tested at all, or only partially?
# REGENERATION IS NOW CONDITIONAL ON CONTENT, NOT JUST EXISTENCE. Fixed 2026-10-25.
#
# THE BUG: this was `if (-not (Test-Path $ControlMapPath))`. The corrected 13-entry map below
# therefore only got written when the file was ABSENT - and the file already existed, holding
# six entries from the retired draft set. So every run since the control IDs were "fixed" has
# loaded the stale file and the fix never reached a single report.
#
# The symptom was visible and I missed it: the report printed
#   "No draft or proposed control identifiers are cited in this report."
# and then cited `CSA AICM Agentic (draft)` five times, in the same document. A report that
# contradicts its own compliance statement is worse than one that makes no statement, and this
# is the exact class of error - a citation to a non-existent control ID - that the script's own
# header says would "destroy the tool's credibility within minutes."
#
# A control map is CODE-VERSIONED REFERENCE DATA, not user state. It is regenerated whenever it
# is absent, carries an older MapVersion, or cites any draft source - and the old file is kept
# alongside so nothing a reader hand-edited is destroyed silently.
# VERSION DERIVED FROM CONTENT, NOT HAND-MAINTAINED. Fixed 2026-10-26.
#
# This was a literal string I had to remember to bump. I did not. Finding codes were added to
# IAM-03 - NO_HUMAN_OWNER, AGENT_SPONSORED, NO_APP_REGISTRATION_OWNER and the rest - the
# version stayed at '2026-10-25.1', the map on disk was therefore judged current, and the new
# codes never reached a single report. NO_HUMAN_OWNER fired correctly in script 03 and then
# appeared under no control at all.
#
# That is the stale-control-map bug a second time, one layer down, and the first fix caused
# it: regenerating on version mismatch only helps if the version actually changes.
#
# A hand-maintained version of machine-generated content is a promise to remember something,
# and this file already documents what those are worth. The version is now a HASH of the map's
# own control ids and finding codes, computed below once $starter exists - so any change to
# what the map scores changes the version automatically, and the map on disk regenerates
# without anyone deciding to.
$needsRegen  = $false
$regenReason = $null

function Get-ControlMapFingerprint {
    <#  A stable hash over the parts that decide what gets scored. Intent text and limitation
        wording are deliberately EXCLUDED - rewording a limitation is not a scoring change and
        should not force every map on disk to regenerate. #>
    param($Map)

    $material = ($Map |
        Where-Object { $_.ControlId -and $_.ControlId -ne 'MAP-VERSION' } |
        Sort-Object ControlId |
        ForEach-Object { "$($_.ControlId)|$($_.AppliesTo)|$($_.Testable)|$(@($_.FindingCodes) -join ',')" }
    ) -join "`n"

    $sha  = [System.Security.Cryptography.SHA256]::Create()
    $hash = [BitConverter]::ToString($sha.ComputeHash([Text.Encoding]::UTF8.GetBytes($material))).Replace('-','')
    $sha.Dispose()
    return $hash.Substring(0, 12)
}

if (-not (Test-Path $ControlMapPath)) {
    $needsRegen = $true; $regenReason = 'no control map found'
}
else {
    try {
        $existing = Get-Content $ControlMapPath -Raw | ConvertFrom-Json

        $existingVersion = @($existing | Where-Object { $_.PSObject.Properties['MapVersion'] } |
                             Select-Object -First 1 -ExpandProperty MapVersion)
        $draftCitations  = @($existing | Where-Object { $_.Source -and $_.Source -match '(?i)draft|placeholder|proposed' })

        if ($draftCitations.Count -gt 0) {
            $needsRegen = $true
            $regenReason = "$($draftCitations.Count) entr$(if($draftCitations.Count -eq 1){'y'}else{'ies'}) cite a DRAFT source: $(@($draftCitations.Source | Sort-Object -Unique) -join ', ')"
        }
        # The version comparison happens AFTER $starter is built, because the expected version
        # is now a fingerprint OF $starter and cannot be known before it exists.
    }
    catch {
        $needsRegen = $true; $regenReason = "existing map is unreadable: $($_.Exception.Message)"
        $existingVersion = $null
    }
}

# The authoritative map is built UNCONDITIONALLY now - it is a data literal, it costs nothing,
# and the fingerprint that decides whether the copy on disk is current is computed from it.
# Building it only when regenerating is what made the version a thing to remember.
if ($true) {

    # -------------------------------------------------------------------------------------
    # UPDATED 24 Oct 2026 - real control IDs, placeholders retired.
    # -------------------------------------------------------------------------------------
    # Source: CSA Labs, "AICM Agentic Control Supplement: Domain-by-Domain Gap Analysis",
    # white paper, STATUS: DRAFT, 2026-03-27. Proposes 24 new control objectives supplementing
    # AICM v1.0 (10 Jul 2025, 243 controls across 18 domains).
    #
    # CITE IT AS A PROPOSED SUPPLEMENT, NOT AS RATIFIED AICM. The precision costs nothing and
    # is the difference between careful and sloppy in front of an auditor.
    #
    # THREE THINGS THAT CHANGED, and why:
    #
    #  1. The six REPLACE-ME placeholders are gone. Real IDs below.
    #
    #  2. THE "NIST NCCoE" ROW IS DELETED. That document is a CONCEPT PAPER SEEKING PUBLIC
    #     COMMENT - no control IDs, no testable requirements, comment period closed 2 Apr
    #     2026. Treating it as a control source was wrong. The real NIST controls live in
    #     SP 800-207, SP 800-63-4 and NISTIR 8587, and none of those have been read yet, so
    #     nothing is mapped to them. An unmapped finding is honest; an invented citation is
    #     not recoverable.
    #
    #  3. The fake 'ATTESTATION' finding code is gone. Script 03 never emits it. Attestation
    #     evidence comes from script 04's output, which is a different input entirely - see
    #     the AttestationEvidence flag below.
    #
    # Testable = 'Full'    - the findings fully determine pass or fail
    # Testable = 'Partial' - a NECESSARY but not SUFFICIENT condition. ALWAYS pair with a
    #                        Limitation explaining the gap.
    # Testable = 'None'    - cannot be assessed from identity data at all. Report it as such;
    #                        the not-testable list is a feature, not an omission.
    $starter = @(
        # VERSION STAMP. Carried on the first entry so a future run can tell a current map from
        # a superseded one without parsing every control. Bump $controlMapVersion above and
        # here together whenever the mapping changes, and every existing map regenerates.
        @{ MapVersion=$controlMapVersion; Source='META'; ControlId='MAP-VERSION'; AppliesTo='None'
           Intent='Version stamp for the control map. Not a control; excluded from the report.'
           FindingCodes=@(); Testable='None'
           Limitation='Metadata row.' }

        # ===================================================================================
        # REBUILT 29 Oct 2026 FROM THE PUBLISHED MATRICES. The draft IDs are gone.
        # ===================================================================================
        # Sources now on disk and read:
        #   CCM  v4.1.1  (2026-10-02)  general cloud controls, IAM-01..IAM-15
        #   AICM v1.1.1  (2026-07-22)  AI systems, 247 controls, IAM-01..IAM-18
        #
        # TWO THINGS THIS CHANGES, AND THE FIRST IS A CORRECTION:
        #
        # 1. IAM-AG-01..04 AND LOG-AG-01 ARE GONE. They came from a DRAFT white paper and
        #    DO NOT EXIST in AICM v1.1.1 - a check of all 247 published control IDs returns
        #    no "-AG-" identifiers at all. They were labelled "(draft)" and "proposed", which
        #    was honest, but citing a proposal when the ratified matrix is available is a
        #    choice nobody would defend in a review. Replaced with published IDs.
        #
        # 2. THE NON-AGENT GAP IS CLOSED. CCM/AICM IAM and CEK govern ordinary non-human
        #    identities, so UNMAPPED-02 largely disappears. The findings were always real;
        #    they now carry identifiers a reader can look up.
        #
        # IAM-01..IAM-15 are IDENTICAL in CCM v4.1.1 and AICM v1.1.1, so those cite both.
        # IAM-16..IAM-18 exist ONLY in AICM - they are the AI-specific additions.

        # ----- AGENTS ----------------------------------------------------------------------
        @{ Source='AICM v1.1.1'; ControlId='IAM-18'; AppliesTo='Agent'
           Intent='Agent Access Restriction: restrict agents access to the tools and plugins necessary for the activity or use case at hand, per need-to-know and least privilege'
           FindingCodes=@('AGENT_CAPABILITY_OPAQUE','SP_SECURED_AGENT','EXCESSIVE_SCOPE_ESCALATION','HIGH_IMPACT_PERMISSION')
           Testable='Partial'
           # THE HEADLINE, AND IT IS NOW A RATIFIED CONTROL RATHER THAN A PROPOSAL.
           # IAM-18 requires restricting an agent's access to TOOLS AND PLUGINS. The lab agent
           # holds SharePoint MCP and Mail MCP; Entra reports zero permissions for it.
           # YOU CANNOT RESTRICT WHAT YOU CANNOT ENUMERATE - and the enumeration is not in the
           # directory. That is a direct failure of a published control, demonstrated in a
           # real tenant.
           Limitation='Tool and plugin grants live in Power Platform, not Entra. This tool can prove the enumeration is absent from the directory; it cannot read the platform-side grant itself.' }

        @{ Source='AICM v1.1.1'; ControlId='IAM-16'; AppliesTo='Agent'
           Intent='Knowledge Access Control - need to know: policy for access to knowledge, information and data in the context of the AI system'
           FindingCodes=@()
           Testable='None'
           Limitation='Knowledge-source scoping is a Copilot Studio / platform configuration, not a directory attribute. Out of scope by construction - reported so the control is not silently omitted.' }

        # ----- ALL NON-HUMAN IDENTITIES -----------------------------------------------------
        @{ Source='CCM v4.1.1 / AICM v1.1.1'; ControlId='IAM-03'; AppliesTo='AllNHI'
           Intent='Identity Inventory: manage, store, and regularly review the inventory of identities, and monitor their level of access'
           # Codes added 2026-10-25 alongside the sponsor and RBAC fixes. Three of these are
           # POSITIVE or NOT-ASSESSED states, and they belong here precisely because IAM-03 is
           # about the inventory being MANAGED: "sponsored by a named human" is evidence FOR
           # the control, and "could not be assessed" must appear in the report rather than
           # being absent from it, which would read as compliance.
           FindingCodes=@('NO_OWNER','NO_SPONSOR','AGENT_SPONSORED','SPONSOR_NOT_ASSESSED',
                          'AGENT_OWNER_NOT_IN_SP_OWNERS','OWNER_STATE_UNRESOLVED',
                          'NO_APP_REGISTRATION_OWNER','NO_HUMAN_OWNER','OWNER_TYPE_UNKNOWN',
                          'MI_OWNERSHIP_NOT_IN_GRAPH','MI_RBAC_ACCOUNTABILITY','MI_NO_RBAC_ASSIGNMENT',
                          'MI_RBAC_LOOKUP_FAILED','UNMANAGED_IDENTITY','UNMANAGED_PRIVILEGED','IAC_MANAGED')
           Testable='Partial'
           # The control this whole tool exists to serve. An identity nobody owns is in the
           # inventory but not MANAGED, which is what the control actually asks for.
           Limitation='Can prove an identity is inventoried and whether an owner is recorded. Cannot prove the inventory is REVIEWED - that is the attestation cycle, IAM-08.' }

        @{ Source='CCM v4.1.1 / AICM v1.1.1'; ControlId='IAM-05'; AppliesTo='AllNHI'
           Intent='Least Privilege: employ the least privilege principle when implementing information system access'
           FindingCodes=@('EXCESSIVE_SCOPE_ESCALATION','HIGH_IMPACT_PERMISSION')
           Testable='Partial'
           Limitation='Can detect high-privilege grants mechanically. Cannot judge business necessity - that requires the owner, which is why IAM-08 exists.' }

        @{ Source='CCM v4.1.1 / AICM v1.1.1'; ControlId='IAM-07'; AppliesTo='AllNHI'
           Intent='Access Changes and Revocation: de-provision or modify identity access in a timely manner'
           FindingCodes=@('DISABLED_WITH_CREDS','DORMANT','DORMANT_AGENT','NO_SIGNIN_RECORD')
           Testable='Partial'
           Limitation='Residue is detectable. "Timely" is not measurable from a snapshot. NO_SIGNIN_RECORD is NOT proof of disuse - it may predate log retention.' }

        @{ Source='CCM v4.1.1 / AICM v1.1.1'; ControlId='IAM-08'; AppliesTo='AllNHI'
           Intent='Access Review: review and revalidate identity access for least privilege and separation of duties, at least annually or upon significant changes'
           FindingCodes=@()
           Testable='Partial'
           # Evidenced by script 04, not by script 03. The attestation report IS the artefact
           # this control asks for, which is why Phase 4 is not optional.
           Limitation='Evidenced by the attestation cycle (04-Invoke-AttestationCycle.ps1), not by these findings. The policy sets 90 days against the control minimum of annually.' }

        @{ Source='CCM v4.1.1 / AICM v1.1.1'; ControlId='IAM-10'; AppliesTo='AllNHI'
           Intent='Management of Privileged Access Roles: privileged access granted for a TIME-LIMITED period; prevent accumulation of segregated privileged access'
           FindingCodes=@('CRED_LONG_LIVED','CRED_NO_EXPIRY','EXCESSIVE_SCOPE_ESCALATION')
           Testable='Full'
           Limitation='A credential with no expiry on a privileged identity is a direct, mechanical failure of the time-limited requirement.' }

        @{ Source='CCM v4.1.1 / AICM v1.1.1'; ControlId='IAM-13'; AppliesTo='AllNHI'
           Intent='Strong Authentication: adopt digital certificates OR ALTERNATIVES WHICH ACHIEVE AN EQUIVALENT LEVEL OF SECURITY FOR SYSTEM IDENTITIES'
           FindingCodes=@('SECRET_OVER_CERT','FEDERATED_CRED')
           Testable='Full'
           # Note the wording - "system identities" is non-human identities, named explicitly.
           # A client secret where a certificate or federated credential would work is a
           # failure of this control, and FEDERATED_CRED is a PASS against it. One of the few
           # places the tool can report a positive against a published control.
           Limitation='Directly testable. FEDERATED_CRED evidences compliance; SECRET_OVER_CERT evidences the gap.' }

        @{ Source='CCM v4.1.1 / AICM v1.1.1'; ControlId='IAM-14'; AppliesTo='AllNHI'
           Intent='Credentials Management: secure management of authentication credentials'
           FindingCodes=@('CRED_NO_EXPIRY','CRED_EXPIRED','CRED_EXPIRING')
           Testable='Full' }

        @{ Source='CCM v4.1.1 / AICM v1.1.1'; ControlId='CEK-12'; AppliesTo='AllNHI'
           Intent='Key Rotation: rotate cryptographic keys in accordance with the calculated cryptoperiod'
           FindingCodes=@('CRED_LONG_LIVED','CRED_EXPIRED')
           Testable='Full'
           Limitation='The 180-day threshold is this lab policy, not a control-mandated figure. CEK-12 requires a CALCULATED cryptoperiod - state yours and the reasoning.' }

        @{ Source='CCM v4.1.1 / AICM v1.1.1'; ControlId='CEK-13'; AppliesTo='AllNHI'
           Intent='Key Revocation: revoke and remove keys before end of cryptoperiod, when compromised, OR WHEN AN ENTITY IS NO LONGER PART OF THE ORGANIZATION'
           FindingCodes=@('ORPHANED_OWNER','DISABLED_WITH_CREDS')
           Testable='Full'
           # The clause "or an entity is no longer part of the organization" is ORPHANED_OWNER
           # exactly. A departed owner whose identity still holds live credentials is a named,
           # published control failure - not just untidy governance.
           Limitation='ORPHANED_OWNER maps directly to the departed-entity clause. Credential state is visible; whether revocation was ATTEMPTED is not.' }

        @{ Source='CCM v4.1.1 / AICM v1.1.1'; ControlId='LOG-05'; AppliesTo='AllNHI'
           Intent='Audit Logs Monitoring and Response: correlate and monitor audit logs to detect suspicious or anomalous activity deviating from expected patterns'
           FindingCodes=@()
           Testable='None'
           Limitation='This tool is a point-in-time posture assessment, NOT a monitor. Continuous anomaly detection requires SIEM correlation. Out of scope by construction - say so rather than implying coverage.' }

        # ----- STILL GENUINELY UNMAPPED ------------------------------------------------------
        @{ Source='UNMAPPED'; ControlId='UNMAPPED-01'; AppliesTo='AllNHI'
           Intent='Findings with no published control objective - the gap is the finding'
           FindingCodes=@('DELEGATION_ESCALATION','AGENT_FACTORY_CAPACITY')
           Testable='Full'
           # ===============================================================================
           # SOURCES NOW READ - 2026-10-25. The answer is that NO published control objective
           # covers these, and that is a RESULT rather than an outstanding task.
           # ===============================================================================
           #
           # NIST NCCoE, "Accelerating the Adoption of Software and AI Agent Identity and
           # Authorization" (concept paper, 11pp). It is an AGENDA, not a control catalogue -
           # it poses the questions rather than answering them. Verbatim, p5:
           #
           #     "How do we handle delegation of authority for 'on behalf of' scenarios?"
           #     "How do we establish 'least privilege' for an agent, especially when its
           #      required actions might not be fully predictable when deployed?"
           #
           # Those are DELEGATION_ESCALATION, written by NIST as open problems. Nothing to map
           # to - and quoting them is a stronger position than a mapping would be, because it
           # shows the tool detecting a condition NIST has publicly flagged as unsolved.
           #
           # NIST SP 800-207 (Zero Trust Architecture) gives ADJACENT PRINCIPLES, not testable
           # controls. The closest are Tenet 3 (per-session access) and Tenet 6 ("all resource
           # authentication and authorization are dynamic and strictly enforced before access
           # is allowed"). A standing inherited grant from a blueprint is in tension with both.
           # But a tenet is an architectural principle, not an auditable control objective, and
           # citing it as though a tenant could PASS or FAIL it would be the same overreach as
           # the retired IAM-AG-* identifiers. Referenced as rationale, never as a control id.
           #
           # NIST SP 800-63-4 is identity proofing and authentication assurance. Out of scope:
           # it governs how strongly an identity is established, not what a verified identity
           # may delegate afterwards.
           #
           # AGENT_FACTORY_CAPACITY (a blueprint able to mint up to 250 agent identities, all
           # inheriting its grants) has no analogue in ANY of the four documents. It is a
           # platform-specific concentration risk that the published frameworks predate.
           Limitation='NOT a mapping gap to be closed - a genuine absence, now evidenced. CCM v4.1.1 and AICM v1.1.1 contain no control for blueprint-to-agent permission inheritance; the NIST NCCoE paper poses delegation-of-authority as an OPEN QUESTION (p5) rather than specifying a control; SP 800-207 offers Tenets 3 and 6 as principles, which are not auditable control objectives; SP 800-63-4 covers identity proofing, not post-authentication delegation. Report these findings on their own terms and cite the NCCoE question verbatim. Do not invent an identifier.' }
    )

    # ---------------------------------------------------------------------------------------
    # NOW the version is knowable: it is a fingerprint of the map just built.
    # ---------------------------------------------------------------------------------------
    $controlMapVersion = Get-ControlMapFingerprint -Map $starter

    # Stamp it onto the metadata row so the file on disk carries the fingerprint of the content
    # it actually holds.
    foreach ($row in $starter) {
        if ($row.ControlId -eq 'MAP-VERSION') { $row.MapVersion = $controlMapVersion }
    }

    if (-not $needsRegen -and $existingVersion -and $existingVersion[0] -ne $controlMapVersion) {
        $needsRegen  = $true
        $regenReason = "control map CONTENT changed (fingerprint $($existingVersion[0]) -> $controlMapVersion)"
    }
    elseif (-not $needsRegen -and -not $existingVersion) {
        $needsRegen  = $true
        $regenReason = 'existing map carries no fingerprint'
    }

    if ($needsRegen) {
        if (Test-Path $ControlMapPath) {
            # Keep the superseded file rather than overwriting it in place. If someone
            # hand-edited a limitation or added a mapping, that work is recoverable.
            $backup = "$ControlMapPath.superseded-$(Get-Date -Format 'yyyyMMdd-HHmmss')"
            Copy-Item $ControlMapPath $backup -Force
            Write-Warning "Control map regenerated - $regenReason."
            Write-Warning "Previous map kept at: $backup"
        }
        else {
            Write-Warning "No control map found. Writing it to $ControlMapPath."
        }

        $dir = Split-Path $ControlMapPath -Parent
        if (-not (Test-Path $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
        $starter | ConvertTo-Json -Depth 6 | Set-Content $ControlMapPath -Encoding UTF8
    }
}

$findingsDoc = Get-Content $FindingsPath   -Raw | ConvertFrom-Json
$controlMap  = Get-Content $ControlMapPath -Raw | ConvertFrom-Json

# Drop the metadata row so it is never scored or printed as a control.
$controlMap = @($controlMap | Where-Object { $_.Source -ne 'META' })

# LAST LINE OF DEFENCE. The regeneration logic above should make this unreachable, but a
# hand-edited or hand-restored map can still reintroduce a draft citation - and the one thing
# this report must never do is cite a control identifier that does not exist in a published
# matrix. Fail loudly instead of printing it: a crash is recoverable, a fabricated citation in
# a document someone forwards to an auditor is not.
$draftsLoaded = @($controlMap | Where-Object { $_.Source -and $_.Source -match '(?i)draft|placeholder|proposed' })
if ($draftsLoaded.Count -gt 0) {
    throw ("Control map cites $($draftsLoaded.Count) DRAFT source(s): " +
           "$(@($draftsLoaded.ControlId) -join ', '). " +
           "Delete $ControlMapPath and re-run to regenerate from the published matrices.")
}

$anonymousLabels = @{}
$identityIndex = 0
foreach ($entry in $findingsDoc.Findings) {
    if (-not $anonymousLabels.ContainsKey($entry.AppId)) {
        $identityIndex++
        $anonymousLabels[$entry.AppId] = "Identity-{0:D3}" -f $identityIndex
    }
}


# =============================================================================
# STEP 2 - Invert the findings so they can be looked up by code
# =============================================================================
# Phase 3 produced data organised BY IDENTITY: "this app has these three problems."
# A control report needs the opposite: "which identities have this problem?"
#
# So we build a lookup keyed by finding code. One pass now saves scanning the whole findings
# set once per control later.
#
# SCOPING FIX - 27 Oct 2026. THIS WAS A CATEGORY ERROR.
# -----------------------------------------------------------------------------
# The first real report scored Okta-SAML-SSO, AWS IAM Identity Center, Workday and
# HashiCorp-Vault-PAM against IAM-AG-01 - "AGENT identity registration".
#
# None of those are agents. They are SSO integrations and HR provisioning connectors. The
# AICM Agentic Supplement proposes 24 controls FOR AGENTIC AI. Applying them to every service
# principal in a tenant is the same mistake as flagging managed identities NO_OWNER: a rule
# applied to a population it was never written for.
#
# WHY IT MATTERS MORE THAN IT LOOKS. The framework hierarchy is:
#
#     CCM .......................... general cloud controls
#       AICM v1.0 .................. AI systems. 243 controls, superset of CCM
#         Agentic Supplement ....... 24 AGENT-specific controls   <- all we have read
#
# Ordinary non-human identities belong to the IAM domain of CCM/AICM v1.0, or to NIST
# SP 800-207 / SP 800-63-4. NONE of those have been read, so there is NO control mapping for
# them yet. Saying so is correct; borrowing an agent control because it is the only one in
# the file is not.
#
# Each control now declares AppliesTo and is evaluated ONLY against that population.
$byCode = @{}

# Initialised explicitly rather than relied on to be $null when unset - under Set-StrictMode
# an unassigned variable throws, and this one is read in the report header.
$script:usedLegacyAgentInference = $false

foreach ($entry in $findingsDoc.Findings) {

    # Which population is this identity in? Classification is written by script 03.
    # Anything without it is treated as a non-agent, which is the safe default: an agent
    # wrongly excluded is a gap you will notice, a service principal wrongly scored as an
    # agent is a false claim in an auditor-facing document.
    # FIXED 2026-10-25. This used to read `Classification -eq 'Agent'` as its authoritative
    # test - but script 03 writes Classification as ManagedIdentity / TenantOwned / External
    # and never 'Agent', so that branch was DEAD. Agent-ness collapsed to "has an agent
    # finding", which fails in the worst possible direction: a correctly governed agent has no
    # agent findings, so it was not counted as an agent, $agentCount came out 0,
    # populationEmpty fired, and IAM-18 / IAM-16 printed NOT APPLICABLE. The better the tenant,
    # the more likely the agent controls scoped themselves to nothing and said so as if it
    # were a result.
    #
    # Population membership is a property of the IDENTITY, not of its findings. Script 03 now
    # carries IsAgent and AgentClass through from the inventory, so read them.
    $isAgent = $false
    if ($entry.PSObject.Properties['IsAgent']) {
        $isAgent = [bool]$entry.IsAgent
    }
    else {
        # Pre-2026-10-25 findings files have no IsAgent field. Fall back to the old inference
        # so an older run still produces a report, and say so rather than pretending the
        # population is authoritative.
        foreach ($f in $entry.Findings) {
            if ($f.Code -in 'SP_SECURED_AGENT','NO_SPONSOR','DORMANT_AGENT','AGENT_CAPABILITY_OPAQUE') {
                $isAgent = $true
            }
        }
        $script:usedLegacyAgentInference = $true
    }

    $agentClass = if ($entry.PSObject.Properties['AgentClass']) { $entry.AgentClass } else { $null }

    foreach ($f in $entry.Findings) {

        if (-not $byCode.ContainsKey($f.Code)) {
            $byCode[$f.Code] = [System.Collections.Generic.List[object]]::new()
        }

        $byCode[$f.Code].Add([pscustomobject]@{
            DisplayName = $entry.DisplayName
            AppId       = $entry.AppId
            ObjectId    = $entry.ObjectId
            # Carried so Get-Label can disambiguate same-named objects. Script 03 writes
            # ObjectClass; absent on pre-2026-10-25 findings files, which Get-Label handles.
            ObjectClass = $entry.ObjectClass
            Severity    = $f.Severity
            Detail      = $f.Detail
            IsAgent     = $isAgent
            AgentClass  = $agentClass
        })
    }
}

function Select-ForControl {
    <#  Filters a code's hits down to the population the control actually governs.

        AppliesTo = 'Agent'   only agent-classified identities
        AppliesTo = 'AllNHI'  everything
        missing               treated as 'Agent', because every control currently in the
                              map comes from the AGENTIC supplement. Defaulting the other
                              way would silently recreate the bug this function exists to
                              fix.                                                        #>
    param($Hits, $AppliesTo)

    if ($AppliesTo -eq 'AllNHI') { return $Hits }
    return @($Hits | Where-Object { $_.IsAgent })
}


function Get-Label {
    <#  Returns either the real identity name or an anonymous placeholder.
        Centralised in one function so that -Anonymise cannot be partially applied -
        a report that anonymises most names but leaks three is worse than one that
        anonymises none, because it creates false confidence. #>
    param($Item)
    if ($Anonymise) { return $anonymousLabels[$Item.AppId] }

    # OBJECT ID AND CLASS, NOT JUST THE NAME. Added 2026-10-25.
    #
    # DisplayName alone made the 2026-10-25 report self-contradicting. THREE distinct objects
    # in the lab tenant are all called "Root-agents":
    #
    #     1a2b3c4d-...  agentIdentity      the agent identity itself
    #     1a2b3c4d-...  servicePrincipal   the blueprint's service principal
    #     1a2b3c4d-...  application        the blueprint's app registration
    #
    # So the report showed "Root-agents | Critical | Agent identity with no sponsor ... should
    # not be possible" and "Root-agents | Medium | Agent secured by an application service
    # principal rather than an agent identity. No sponsor requirement applies" - two findings
    # that directly contradict each other, on what a reader could only read as one object.
    #
    # They were never contradictory. They are two different objects with the same name, and
    # the report simply could not say so. A short object-id suffix and the class fix it.
    #
    # This is the general hazard: in an Entra tenant DisplayName is NOT unique and is not an
    # identifier. Any auditor-facing row keyed on it will eventually merge two objects and
    # present the result as an inconsistency in the tenant rather than in the report.
    $name  = $Item.DisplayName
    $short = if ($Item.ObjectId) { "$($Item.ObjectId)".Substring(0, [Math]::Min(8, "$($Item.ObjectId)".Length)) } else { $null }
    $cls   = $Item.ObjectClass

    if ($short -and $cls) { return "$name ``$short``, $cls" }
    if ($short)           { return "$name ``$short``" }
    return $name
}


# =============================================================================
# STEP 3 - Build the report
# =============================================================================
$md = [System.Collections.Generic.List[string]]::new()

$md.Add("# Agent & Non-Human Identity Posture Report")
$md.Add("")
$md.Add("**Generated:** $((Get-Date).ToUniversalTime().ToString('yyyy-MM-dd HH:mm')) UTC  ")

# WHEN THE TENANT WAS ACTUALLY READ - not when this document was written.
#
# These are different timestamps and the difference is the whole point. Script 01 is the only
# one that touches the tenant; 03 and 05 read files. A control report generated two minutes
# ago from a seventeen-hour-old inventory is a seventeen-hour-old assessment wearing a fresh
# date, and that is exactly what happened on 2026-10-25: owners were assigned and confirmed in
# the portal while the report kept saying UNASSIGNED, correctly, about a tenant that no longer
# existed. Nothing in the document gave a reader any way to notice.
$invUtc = if ($findingsDoc.PSObject.Properties['InventoryGeneratedUtc']) { $findingsDoc.InventoryGeneratedUtc } else { $null }
$invAge = if ($findingsDoc.PSObject.Properties['InventoryAgeHours'])     { $findingsDoc.InventoryAgeHours }     else { $null }

if ($invUtc) {
    $md.Add("**Tenant read:** $invUtc$(if ($null -ne $invAge) { " ($invAge h before the findings were classified)" })  ")
} else {
    $md.Add("**Tenant read:** unknown - findings file predates provenance tracking. Re-run 01 and 03.  ")
}

$md.Add("**Identities with findings:** $(@($findingsDoc.Findings).Count)  ")
$md.Add("**Controls assessed:** $(@($controlMap).Count)")
$md.Add("")

# A banner, not a footnote. Anything over a day old is reporting on a tenant that has probably
# moved, and a reader skimming for the verdict must not be able to miss it.
if ($null -ne $invAge -and $invAge -gt 24) {
    $md.Add("> ## STALE DATA WARNING")
    $md.Add(">")
    $md.Add("> **The tenant was last read $invAge hours before these findings were classified.**")
    $md.Add("> Every result below describes the tenant as it was then. Re-run")
    $md.Add("> ``01-Get-NHIInventory.ps1``, then ``03`` and ``05``, before treating this as current.")
    $md.Add("")
}

# Population counts. A reader has to know how many agents were in scope before any agent
# control result means anything - "PASS" against a population of zero is not a pass.
# Count DISTINCT agent identities. An earlier version of this summed per-code counts, which
# double-counted any agent carrying more than one agent finding - the sort of arithmetic that
# makes a headline number quietly wrong while every individual row is right.
$agentCount = @($byCode.Values |
                ForEach-Object { $_ } |
                Where-Object IsAgent |
                Select-Object -ExpandProperty AppId -Unique).Count

# The two agent CLASSES have different readable governance surfaces, so a single agent count
# overstates what the report can actually evidence. Measured 2026-10-25: a true agentIdentity
# exposes a blueprint link and platform-maintained lifecycle compliance state; an SP-secured
# agent exposes NOTHING agent-shaped and is identifiable only by its tags. Stating the split
# is what stops a reader treating uniform coverage as uniform evidence.
$agentHits   = @($byCode.Values | ForEach-Object { $_ } | Where-Object IsAgent)
$trueIdCount = @($agentHits | Where-Object { $_.AgentClass -eq 'AgentIdentity' } |
                 Select-Object -ExpandProperty AppId -Unique).Count
$spSecCount  = @($agentHits | Where-Object { $_.AgentClass -eq 'SpSecured' } |
                 Select-Object -ExpandProperty AppId -Unique).Count

if ($script:usedLegacyAgentInference) {
    $md.Add("> **Note.** This findings file predates the ``IsAgent`` field, so the agent")
    $md.Add("> population was inferred from the presence of agent findings. A correctly")
    $md.Add("> governed agent has no agent findings and is therefore MISSING from the counts")
    $md.Add("> below. Re-run scripts 01 and 03 for an authoritative population.")
    $md.Add("")
}

$md.Add("> **Scope.** This report covers two populations and they are NOT scored against the")
$md.Add("> same controls. **Agent identities: $agentCount** (true agent identities:")
$md.Add("> $trueIdCount, service-principal-secured: $spSecCount). The two classes are not")
$md.Add("> equally evidenced: a true agent identity exposes a blueprint link and")
$md.Add("> platform-maintained lifecycle compliance state, while an SP-secured agent exposes no")
$md.Add("> agent property at all and is identifiable only by its tags. A control scored against")
$md.Add("> the second class rests on weaker evidence, and this report does not pretend")
$md.Add("> otherwise. `IAM-18` (Agent Access Restriction)")
$md.Add("> and `IAM-16` govern agents only; the `IAM-03/05/07/08/10/13/14` and `CEK-*` controls")
$md.Add("> govern every non-human identity. Applying an agent control to an ordinary service")
$md.Add("> principal would be a category error, so each control is scored only against the")
$md.Add("> population it governs.")
$md.Add("")

# --- The placeholder guard ---------------------------------------------------
# If the control map still contains placeholder IDs, the report says so AT THE TOP, in the
# document itself - not just in the console where it is easily missed. A draft that looks
# finished is how fabricated citations end up in front of an auditor.
$placeholders = @($controlMap | Where-Object { $_.ControlId -like 'REPLACE-ME*' })

if ($placeholders.Count -gt 0) {
    $md.Add("> **DRAFT - control identifiers are placeholders.** $($placeholders.Count) control(s)")
    $md.Add("> still carry placeholder IDs. Replace them from the CSA AICM Agentic Control")
    $md.Add("> Supplement before this report is shown to anyone. Fabricated standard citations")
    $md.Add("> in an auditor-facing document are unrecoverable.")
    $md.Add("")
}

# Every report states its source and that source's status. The supplement is a DRAFT white
# paper proposing controls, not ratified AICM - and a report that blurs the two invites the
# one question you cannot recover from.
$md.Add("> **Control sources — both published and ratified:**")
$md.Add("> **CSA Cloud Controls Matrix v4.1.1** (2026-10-02) and **CSA AI Controls Matrix v1.1.1**")
$md.Add("> (2026-07-22, 247 controls). `IAM-01`–`IAM-15` and `CEK-*` are identical in both;")
$md.Add("> `IAM-16`–`IAM-18` exist only in AICM and are the AI-specific additions.")
$md.Add("")
$md.Add("> **No draft or proposed control identifiers are cited in this report.** An earlier")
$md.Add("> version used `IAM-AG-*` IDs from an unratified white paper; those do not appear in")
$md.Add("> AICM v1.1.1 and have been replaced with published equivalents.")
$md.Add("")

# Findings the tool produces but no control claims. Surfaced rather than quietly dropped,
# because a mapping that silently discards output is worse than one with an obvious hole.
$unmapped = @($controlMap | Where-Object { $_.Source -eq 'UNMAPPED' })
if ($unmapped.Count -gt 0) {
    $codes = ($unmapped.FindingCodes | Sort-Object -Unique) -join ', '
    $md.Add("> **Unmapped findings:** $codes")
    $md.Add("> These are produced by this tool but not yet mapped to a published control.")
    $md.Add("> No identifier has been invented for them. See 'Not assessed' below.")
    $md.Add("")
}

# --- Executive summary -------------------------------------------------------
# Only fully testable controls can be counted as passing. Partial controls are reported
# separately, and controls marked None cannot be assessed from these findings at all.
$pass = 0; $fail = 0; $partialWithFindings = 0
$partialWithoutFindings = 0; $notAssessed = 0

foreach ($c in $controlMap) {
    $hits = 0
    foreach ($code in $c.FindingCodes) {
        if ($byCode.ContainsKey($code)) {
            # Scope to the population this control governs. See Select-ForControl.
            $hits += @(Select-ForControl -Hits $byCode[$code] -AppliesTo $c.AppliesTo).Count
        }
    }

    switch ($c.Testable) {
        'Full' {
            if ($hits -eq 0) { $pass++ }
            else { $fail++ }
        }
        'Partial' {
            if ($hits -eq 0) { $partialWithoutFindings++ }
            else { $partialWithFindings++ }
        }
        'None' { $notAssessed++ }
        default { throw "Unsupported Testable value '$($c.Testable)' for control '$($c.ControlId)'." }
    }
}

$md.Add("## Executive summary")
$md.Add("")
$md.Add("| | Count |")
$md.Add("|---|---:|")
$md.Add("| Fully testable controls with no findings | $pass |")
$md.Add("| Fully testable controls with findings | $fail |")
$md.Add("| Partially testable controls with findings | $partialWithFindings |")
$md.Add("| Partially testable controls with no findings | $partialWithoutFindings |")
$md.Add("| Controls not assessed | $notAssessed |")
$md.Add("")

# The three worst things, named, right at the top. An executive summary that makes a reader
# scroll to find the bad news is not a summary.
$critical = @()
foreach ($entry in $findingsDoc.Findings) {
    if ($entry.TopSeverity -eq 'Critical') { $critical += $entry }
}

if ($critical.Count -gt 0) {
    $md.Add("### Most serious findings")
    $md.Add("")
    $i = 0
    foreach ($c in ($critical | Select-Object -First 5)) {
        $i++
        $worst = ($c.Findings | Where-Object Severity -eq 'Critical' | Select-Object -First 1)
        $md.Add("$i. **$(Get-Label $c)** - $($worst.Detail)")
    }
    $md.Add("")
}

# --- Per-control detail ------------------------------------------------------
$md.Add("## Control results")
$md.Add("")

foreach ($c in $controlMap) {

    # Gather every identity that triggered any finding mapped to this control, SCOPED to the
    # population the control governs.
    # ONE ROW PER IDENTITY, NOT PER FINDING. Fixed 2026-10-25.
    #
    # This list used to collect every matching FINDING, so an identity appeared once for each
    # finding that mapped to the control. Two compounding sources:
    #
    #   1. A control aggregates several codes. IAM-10 maps CRED_LONG_LIVED, CRED_NO_EXPIRY
    #      and EXCESSIVE_SCOPE_ESCALATION; CEK-12 maps CRED_LONG_LIVED and CRED_EXPIRED.
    #      An identity with two of them was listed twice.
    #
    #   2. Script 03 emits credential findings ONCE PER CREDENTIAL. An app registration with
    #      three long-lived secrets produces three CRED_LONG_LIVED findings on its own.
    #
    # Together: one app with three long-lived secrets and a no-expiry certificate appeared
    # FOUR TIMES under IAM-10 - which is exactly what the duplicate rows under CEK-12 and
    # IAM-10 were.
    #
    # Why it matters beyond tidiness: a reader counts rows to judge scale. Four rows reads as
    # four exposed identities, and overstating the problem in an auditor-facing document is
    # the same category of error as understating it - both mean the number cannot be trusted.
    # It would also make "12 identities affected" disagree with the 7 in the CSV, and a
    # reader who spots that stops believing the rest of the document.
    #
    # Deduplicated on ObjectId, falling back to AppId then DisplayName for older findings
    # files that predate ObjectId. The contributing findings are COUNTED rather than dropped,
    # because "3 credentials" is genuine information - it just is not three identities.
    $affected    = [System.Collections.Generic.List[object]]::new()
    $seenKeys    = @{}
    $hitsPerKey  = @{}

    foreach ($code in $c.FindingCodes) {
        if ($byCode.ContainsKey($code)) {
            foreach ($x in (Select-ForControl -Hits $byCode[$code] -AppliesTo $c.AppliesTo)) {

                $key = if ($x.ObjectId)        { "$($x.ObjectId)" }
                       elseif ($x.AppId)       { "appid:$($x.AppId)" }
                       else                    { "name:$($x.DisplayName)" }

                if ($seenKeys.ContainsKey($key)) {
                    # Already listed. Record that another finding contributed so the count is
                    # preserved even though the row is not repeated.
                    $hitsPerKey[$key]++
                    continue
                }

                $seenKeys[$key]   = $true
                $hitsPerKey[$key] = 1
                $affected.Add($x)
            }
        }
    }

    # An agent control in a tenant with no agents is NOT a pass. Nothing was tested. Reporting
    # "PASS" there would be a claim the evidence does not support - and the inverse of the bug
    # this scoping work fixed, where agent controls were scored against everything.
    $populationEmpty = ($c.AppliesTo -ne 'AllNHI') -and ($agentCount -eq 0)

    $status = switch ($c.Testable) {
        'None' { 'NOT ASSESSED' }
        'Partial' {
            if ($populationEmpty)       { 'NOT APPLICABLE - no agents in scope' }
            elseif ($affected.Count -eq 0) { 'NO FINDINGS (PARTIAL)' }
            else { 'FINDINGS' }
        }
        'Full' {
            if ($populationEmpty)       { 'NOT APPLICABLE - no agents in scope' }
            elseif ($affected.Count -eq 0) { 'PASS' }
            else { 'FINDINGS' }
        }
        default { throw "Unsupported Testable value '$($c.Testable)' for control '$($c.ControlId)'." }
    }

    $scopeLabel = if ($c.AppliesTo -eq 'AllNHI') { 'All non-human identities' } else { 'Agent identities only' }

    $md.Add("### $($c.ControlId) - $($c.Intent)")
    $md.Add("")
    $md.Add("**Source:** $($c.Source)  ")
    $md.Add("**Applies to:** $scopeLabel  ")
    $md.Add("**Status:** $status  ")
    $md.Add("**Testability:** $($c.Testable)")

    # The limitation is printed with the result, not buried in an appendix. A reader needs to
    # know the boundary of the claim at the moment they read the claim.
    if ($c.Limitation) {
        $md.Add("")
        $md.Add("> **Limitation:** $($c.Limitation)")
    }
    $md.Add("")

    if ($affected.Count -gt 0) {
        $affectedIdentityCount = @($affected.AppId | Sort-Object -Unique).Count
        $md.Add("**$affectedIdentityCount affected identit(ies):**")
        $md.Add("")
        $md.Add("| Identity | Severity | Detail |")
        $md.Add("|---|---|---|")
        foreach ($a in ($affected | Sort-Object Severity)) {
            $md.Add("| $(Get-Label $a) | $($a.Severity) | $($a.Detail) |")
        }
    }
    else { $md.Add("_No findings._") }

    $md.Add("")
}

# --- What this tool cannot tell you ------------------------------------------
# THIS SECTION IS A FEATURE, NOT AN APOLOGY.
#
# A tool that claims to assess controls it cannot actually measure is worse than one that is
# honestly scoped, and an auditor will find the overreach immediately. Publishing the
# boundary of your own tool is also the most interesting thing you will have to say to the
# standards community - it is precisely where the whole category currently stops.
$md.Add("## Not assessed")
$md.Add("")
$md.Add("These cannot be determined from directory data and require manual review. Listing")
$md.Add("them is deliberate: a tool that claims to assess controls it cannot measure is worse")
$md.Add("than one honestly scoped.")
$md.Add("")
$md.Add("| Not testable | Why |")
$md.Add("|---|---|")
$md.Add("| Whether a permission set is *necessary* | Business justification is not a directory attribute. Use the attestation cycle. |")
$md.Add("| Whether the agent was approved before creation | No approval record exists in Graph. This is a process control. |")
$md.Add("| Whether the identity handles regulated data | Data classification is not an identity property. |")
$md.Add("| Whether the assigned owner is the *right* owner | Graph records who the owner is, not whether that is appropriate. |")
$md.Add("| What the agent does when invoked | Behaviour is not an identity attribute. Runtime monitoring - out of scope for a directory-data assessment. |")
$md.Add("")

# --- Method ------------------------------------------------------------------
# Every caveat that affects how the findings should be read, collected in one place. An
# assessment artifact that cannot explain how it was produced is not much use to an auditor.
$md.Add("## Method and limitations")
$md.Add("")
$md.Add("- Read-only Microsoft Graph scopes: ``Application.Read.All``, ``Directory.Read.All``, ``AuditLog.Read.All``, ``RoleManagement.Read.Directory``")
$md.Add("- Sign-in activity uses a **beta** endpoint (``/beta/reports/servicePrincipalSignInActivities``) which may change without notice")
$md.Add("- **'No sign-in record' is not evidence of disuse.** A record may be absent because it predates the log retention window. Verify before decommissioning anything.")
$md.Add("- Managed identities are excluded from credential-rotation findings by design: Azure manages their credentials and there is nothing an administrator can rotate.")
$md.Add("- Microsoft first-party and third-party service principals are inventoried but not flagged for owner assignment - they have no tenant owner by design.")
$md.Add("")
$md.Add("---")
$md.Add("")
$md.Add("_Generated by 05-New-ControlReport.ps1._")


# =============================================================================
# STEP 4 - Write and summarise
# =============================================================================
$outDir = Split-Path $ReportPath -Parent
if (-not (Test-Path $outDir)) { New-Item -ItemType Directory -Path $outDir -Force | Out-Null }

$md -join "`n" | Set-Content $ReportPath -Encoding UTF8

Write-Host ""
Write-Host "Control report written: $ReportPath" -ForegroundColor Green
Write-Host "  Controls assessed : $(@($controlMap).Count)"
Write-Host "  Fully testable, no findings : $pass"
Write-Host "  Fully testable, findings    : $fail"
Write-Host "  Partially testable findings : $partialWithFindings"
Write-Host "  Partially testable, clear   : $partialWithoutFindings"
Write-Host "  Not assessed                : $notAssessed"

if ($placeholders.Count -gt 0) {
    Write-Host ""
    Write-Host "!! $($placeholders.Count) control(s) still have PLACEHOLDER IDs." -ForegroundColor Red
    Write-Host "   Replace them from the source documents before showing this to anyone." -ForegroundColor Red
}

Write-Host ""
Write-Host "For anything you PUBLISH: use -Anonymise, and report aggregates only." -ForegroundColor Yellow
Write-Host "The client's report names their identities. Your article names nobody." -ForegroundColor Yellow
