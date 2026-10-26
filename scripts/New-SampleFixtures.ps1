<#
.SYNOPSIS
    Turns a real run into publishable sample fixtures, and REFUSES to write them if any real
    identifier survives.

.DESCRIPTION
    samples/ is the one directory .gitignore deliberately un-ignores (`!samples/**`). It is what
    lets somebody clone this repository and see what the tool produces without having a tenant,
    and it is the only place real-looking output is published on purpose.

    So it has to be sanitised, and "sanitised" has to be VERIFIED rather than intended.

    WHY NOT JUST FIND-AND-REPLACE
    -----------------------------
    Because the files reference each other. nhi_findings.json points at object ids in
    nhi_inventory.json; nhi_ownership.csv carries the same ids again; the control report quotes
    8-character prefixes of them. Replace each file independently and the sample becomes
    incoherent - findings about objects that do not appear in the inventory, which is worse than
    no sample at all because it looks like a bug in the tool.

    One mapping is built across ALL files first, then applied everywhere. The same real GUID
    always becomes the same fake GUID, so every cross-reference survives.

    WHAT IS REPLACED AND WHAT IS KEPT
    ---------------------------------
    REPLACED  every GUID, tenant-owned display names, UPNs, the tenant domain
    KEPT      Microsoft first-party service principal names (Office 365 Exchange Online, Azure
              ESTS Service and so on). Those are public product names, they are the same in every
              tenant, and keeping them is what makes the sample look like a real estate rather
              than a toy. A sample of 342 identities named Identity-001..342 demonstrates nothing.
    KEPT      every finding code, severity, count and structure - the sample has to be an honest
              representation of what the tool outputs, or it is marketing.

    THE VERIFICATION IS THE POINT
    -----------------------------
    After writing, every output file is re-read and scanned for the real tenant id, the real
    domain, and any real GUID from the mapping. If one survives, the samples are DELETED and the
    script throws. A sanitiser that can fail silently is the same defect this project has spent
    its life finding - so this one cannot.

.PARAMETER RunDir
    The run to sanitise. Defaults to the current run from output/latest-run.txt.

.PARAMETER TenantDomain
    Your tenant's domain, replaced with contoso.example wherever it appears. Read from the
    inventory when not supplied.

.EXAMPLE
    ./New-SampleFixtures.ps1
    Sanitise the latest run into samples/.
#>

[CmdletBinding()]
param(
    [string]$RunDir,
    [string]$SamplesDir = (Join-Path $PSScriptRoot '..\samples'),
    [string]$TenantDomain
)

$ErrorActionPreference = 'Stop'

$outputRoot = Join-Path $PSScriptRoot '..\output'

if (-not $RunDir) {
    $pointer = Join-Path $outputRoot 'latest-run.txt'
    if (-not (Test-Path $pointer)) { throw "No latest-run.txt. Run Invoke-Pipeline.ps1 first, or pass -RunDir." }
    $RunDir = Join-Path $outputRoot ("runs\" + (Get-Content $pointer -Raw).Trim())
}
if (-not (Test-Path $RunDir)) { throw "Run directory not found: $RunDir" }

Write-Host ""
Write-Host "  Source : $RunDir" -ForegroundColor DarkGray
Write-Host "  Target : $SamplesDir" -ForegroundColor DarkGray
Write-Host ""

$files = @('nhi_inventory.json','nhi_findings.json','nhi_ownership.csv','control_report.md') |
         Where-Object { Test-Path (Join-Path $RunDir $_) }

if ($files.Count -eq 0) { throw "No recognisable outputs in $RunDir." }

# ATTESTATION LIVES SOMEWHERE ELSE, AND THE FIRST VERSION OF THIS SCRIPT MISSED IT ENTIRELY.
#
# Scan outputs go to output/runs/<RunId>/. Attestation goes to output/attestation/<CycleId>/,
# because a cycle is QUARTERLY and spans many scans - that separation is deliberate and it is
# exactly what made the cycle invisible to a sampler that only walked the run directory.
#
# It matters more than the file count suggests: the attestation report is the artifact that
# demonstrates the governance loop closing, and it is where "No Response - Non-Human Owner"
# appears. A samples/ directory without it shows the inventory and the scoring but not the
# part that makes this a governance tool rather than a scanner.
$attestFiles = @()
$cycleDir    = $null

$attestRoot = Join-Path $outputRoot 'attestation'
if (Test-Path $attestRoot) {
    # Most recent cycle. CycleIds sort lexically (2026-Q4), so the last one is the newest.
    $cycleDir = @(Get-ChildItem $attestRoot -Directory | Sort-Object Name) | Select-Object -Last 1
    if ($cycleDir) {
        $attestFiles = @('attestation_records.json','attestation_results.json','attestation_report.md','cycle.json') |
                       Where-Object { Test-Path (Join-Path $cycleDir.FullName $_) }
        Write-Host "  Cycle  : $($cycleDir.Name)  ($($attestFiles.Count) file(s))" -ForegroundColor DarkGray
    }
}
if ($attestFiles.Count -eq 0) {
    Write-Warning "No attestation cycle found. Samples will show the scan but not the governance loop."
    Write-Warning "Run: .\Invoke-Pipeline.ps1 -IncludeAttestation"
}


# =============================================================================
# PASS 1 - build ONE mapping from every file
# =============================================================================
# ONE work list: every file to sanitise, with where it came from and where it goes. Built here
# so the mapping, the write and the verification all walk the SAME set - three separate lists
# is three chances for a file to be sanitised but not verified, or verified but not written.
$work = [System.Collections.Generic.List[object]]::new()
foreach ($f in $files) {
    $work.Add([pscustomobject]@{ Source = (Join-Path $RunDir $f); Target = (Join-Path $SamplesDir $f); Label = $f })
}
foreach ($f in $attestFiles) {
    # Flattened into samples/attestation/ so the directory is self-describing without needing
    # the cycle id in the path.
    $work.Add([pscustomobject]@{
        Source = (Join-Path $cycleDir.FullName $f)
        Target = (Join-Path (Join-Path $SamplesDir 'attestation') $f)
        Label  = "attestation/$f"
    })
}

$allText = ($work | ForEach-Object { Get-Content $_.Source -Raw }) -join "`n"

# Real person display names, harvested from the SOURCE so the verifier can prove they are gone.
# Collected here and never written to disk - this list exists only in memory, for the length of
# one run. Matching "FirstName LastName" shapes inside the owner and sponsor structures rather
# than guessing at the whole document, so ordinary prose is not mistaken for a person.
$realPersonNames = @(
    [regex]::Matches($allText, '"(?:DisplayName|displayName)"\s*:\s*"([A-Z][a-z]+(?:\s+[A-Z][a-z\-'']+)+)"') |
        ForEach-Object { $_.Groups[1].Value } |
        Sort-Object -Unique
)
if ($realPersonNames.Count -gt 0) {
    Write-Host "  $($realPersonNames.Count) person display name(s) detected and will be pseudonymised" -ForegroundColor DarkGray
}

$guidPattern = '[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}'
$realGuids   = @([regex]::Matches($allText, $guidPattern) | ForEach-Object { $_.Value.ToLower() } | Sort-Object -Unique)

# Microsoft's well-known identifiers stay as themselves. They are public, identical in every
# tenant, and replacing them would make the sample WRONG rather than anonymous.
#
# MATCHED BY PATTERN, NOT BY A HAND-WRITTEN LIST. The list below used to hold four GUIDs, and
# the first real run failed verification with 21 leak signals because of what it missed.
#
# Microsoft's first-party application IDs occupy a structured block:
#
#     00000001-0000-0000-c000-000000000000   Azure classic
#     00000002-0000-0ff1-ce00-000000000000   Office 365 Exchange Online
#     00000003-0000-0ff1-ce00-000000000000   Office 365 SharePoint Online
#     00000004-0000-0ff1-ce00-000000000000   Skype for Business Online
#     00000014-0000-0000-c000-000000000000   Microsoft.Azure.SyncFabric
#
# Only two of those were listed, so the rest were MAPPED - which both made the sample wrong and
# produced the failure. The ones that were kept share 8-character prefixes with the ones that
# were mapped (00000002, 00000003...), so the verifier found a "real prefix" inside a GUID it
# had deliberately preserved and correctly refused to publish.
#
# The guard was right. The input to it was wrong. A hand-written list of a structured namespace
# is the same defect as a hand-maintained version string: a promise to remember something.
$wellKnownPattern = '^0000[0-9a-f]{4}-0000-(0000|0ff1)-(c000|ce00)-000000000000$'

$wellKnownExplicit = @(
    '14d82eec-204b-4c2f-b7e8-296a70dab67e'   # Microsoft Graph Command Line Tools
    '797f4846-ba00-4fd7-ba43-dac1f8f63013'   # Azure Resource Manager (Windows Azure Service Mgmt)
    '1950a258-227b-4e31-a9cf-717495945fc2'   # Microsoft Azure PowerShell
    '04b07795-8ddb-461a-bbee-02f9e1bf7b46'   # Microsoft Azure CLI
    'cf36b471-5b44-428c-9ce7-313bf84528de'   # Microsoft Bing Search
    '0000000c-0000-0000-c000-000000000000'   # Microsoft App Access Panel
)

function Test-WellKnownGuid {
    param([string]$Guid)
    if ($Guid -match $wellKnownPattern)   { return $true }
    if ($wellKnownExplicit -contains $Guid) { return $true }
    return $false
}

$wellKnown = @($realGuids | Where-Object { Test-WellKnownGuid -Guid $_ })
Write-Host "  $($wellKnown.Count) Microsoft first-party GUIDs preserved as themselves" -ForegroundColor DarkGray

$guidMap = @{}
$realGuidPrefixes = @($realGuids | ForEach-Object { $_.Substring(0,8) })
$usedSyntheticGuids = @{}
$usedSyntheticPrefixes = @{}
$sha256 = [System.Security.Cryptography.SHA256]::Create()
try {
    $i = 0
    foreach ($g in $realGuids) {
        if ($wellKnown -contains $g) { continue }
        $i++

        # Deterministic valid GUIDs avoid real prefixes, keeping abbreviated references distinct.
        $salt = 0
        while ($true) {
            $seed = [System.Text.Encoding]::UTF8.GetBytes(('{0}:{1}' -f $g, $salt))
            $hex = [System.BitConverter]::ToString($sha256.ComputeHash($seed)).Replace('-', '').ToLowerInvariant()
            $variant = '89ab'[$salt % 4]
            $synthetic = '{0}-{1}-4{2}-{3}{4}-{5}' -f `
                $hex.Substring(0,8), $hex.Substring(8,4), $hex.Substring(13,3), `
                $variant, $hex.Substring(17,3), $hex.Substring(20,12)
            $syntheticPrefix = $synthetic.Substring(0,8)

            $containsRealPrefix = $false
            foreach ($prefix in $realGuidPrefixes) {
                if ($synthetic.IndexOf($prefix, [System.StringComparison]::OrdinalIgnoreCase) -ge 0) {
                    $containsRealPrefix = $true
                    break
                }
            }

            if (-not $containsRealPrefix -and
                -not $usedSyntheticGuids.ContainsKey($synthetic) -and
                -not $usedSyntheticPrefixes.ContainsKey($syntheticPrefix)) {
                break
            }
            $salt++
        }

        $guidMap[$g] = $synthetic
        $usedSyntheticGuids[$synthetic] = $true
        $usedSyntheticPrefixes[$syntheticPrefix] = $true
    }
}
finally {
    $sha256.Dispose()
}

# The tenant domain.
if (-not $TenantDomain) {
    $m = [regex]::Match($allText, '@([A-Za-z0-9][A-Za-z0-9.\-]*\.[A-Za-z]{2,})')
    if ($m.Success) { $TenantDomain = $m.Groups[1].Value }
}

# Tenant-owned display names -> generic equivalents. Microsoft first-party names are NOT in this
# list and are deliberately preserved.
$nameMap = [ordered]@{
    'nhi-scanner'          = 'svc-identity-scanner'
    'HashiCorp-Vault-PAM'  = 'svc-secrets-broker'
    'hashicorpvault2'      = 'svc-secrets-broker-legacy'
    'HRProvisioning'       = 'svc-hr-provisioning'
    'CABProvisioning'      = 'svc-change-provisioning'
    'Okta-SAML-SSO'        = 'svc-sso-primary'
    'okta sso1'            = 'svc-sso-secondary'
    'aws sso'              = 'svc-cloud-sso'
    'AWS IAM Identity Center (successor to AWS Single Sign-On)' = 'svc-cloud-identity-center'
    'Workday'              = 'svc-hcm-connector'
    'Prov-v0.5'                 = 'svc-provisioning-v2'
    'autowayne'            = 'automation-acct-01'
    'TestApp'              = 'svc-sandbox-app'
    'app1'                 = 'svc-legacy-app'
    'Root-agents'          = 'agent-blueprint-root'
    'MSTeams-Agent'        = 'agent-collab-assistant'
    'jobs-alert-agent (Microsoft Copilot Studio)' = 'agent-alerts (Microsoft Copilot Studio)'
    'API-driven provisioning to Microsoft Entra ID' = 'svc-inbound-provisioning'
}

Write-Host "  $($guidMap.Count) GUIDs mapped, $($nameMap.Count) names mapped" -ForegroundColor DarkGray
if ($TenantDomain) { Write-Host "  domain  : $TenantDomain -> contoso.example" -ForegroundColor DarkGray }
Write-Host ""


# =============================================================================
# PASS 2 - apply the mapping everywhere
# =============================================================================
function ConvertTo-Sanitised {
    param([string]$Text)

    # GUIDs first. Case-insensitive, and the 8-character prefixes the control report prints are
    # handled by replacing the full GUID before anything shortens it.
    foreach ($k in $guidMap.Keys) {
        $Text = [regex]::Replace($Text, [regex]::Escape($k), $guidMap[$k], 'IgnoreCase')
    }
    # Short forms that appear in report tables (first 8 chars).
    foreach ($k in $guidMap.Keys) {
        $Text = [regex]::Replace($Text, [regex]::Escape($k.Substring(0,8)), $guidMap[$k].Substring(0,8), 'IgnoreCase')
    }

    # Longest names first, so "Okta-SAML-SSO" is not partially eaten by a shorter key.
    foreach ($k in ($nameMap.Keys | Sort-Object { $_.Length } -Descending)) {
        $Text = [regex]::Replace($Text, [regex]::Escape($k), $nameMap[$k], 'IgnoreCase')
    }

    if ($TenantDomain) {
        $Text = [regex]::Replace($Text, [regex]::Escape($TenantDomain), 'contoso.example', 'IgnoreCase')
    }

    # PEOPLE. Both their UPNs and their DISPLAY NAMES.
    #
    # Two defects fixed here on 2026-10-26, and the first one had already shipped into samples/.
    #
    # 1. ONLY UPNs WERE REPLACED. An owner appears in the inventory twice - as
    #    "UserPrincipalName": "first.last@..." AND as "DisplayName": "First Last". The second
    #    form survived, so a real colleague's name sat in the file that exists to be published.
    #    A sanitiser that handles the machine-readable form of an identifier and not the human
    #    one has done the easy half.
    #
    # 2. THE MAPPING WAS HARDCODED IN THIS SCRIPT. It listed the real names it was replacing -
    #    a literal table of real-name = pseudonym pairs. This script ships, so the source code
    #    published the real names AND the key to de-anonymise the samples, which is worse than
    #    not sanitising at all, because the output looks safe.
    #
    # Now derived: people are discovered from the data, assigned stable pseudonyms by order of
    # appearance, and NOTHING real is written down here. The script can be read by anyone
    # without learning a single real name.
    $Text = [regex]::Replace($Text, '[A-Za-z0-9._%-]+@contoso\.example', {
        param($m)
        $local = $m.Value.Split('@')[0].ToLower()
        if (-not $script:personMap.ContainsKey($local)) {
            $script:personIndex++
            $script:personMap[$local] = 'person{0:d2}' -f $script:personIndex
        }
        "$($script:personMap[$local])@contoso.example"
    })

    # Display names of the same people. Driven off the UPN local-parts already mapped, so the
    # two forms stay consistent: first.last -> person03 and "First Last" -> "Person 03".
    foreach ($local in @($script:personMap.Keys)) {
        $pseudonym = $script:personMap[$local]
        $titled    = 'Person ' + $pseudonym.Substring(6)

        # "first.last" -> "First Last" / "First  Last" / "first last"
        $parts   = @($local -split '[._-]+' | Where-Object { $_ })
        if ($parts.Count -ge 1) {
            $pattern = ($parts | ForEach-Object { [regex]::Escape($_) }) -join '[\s._-]+'
            $Text    = [regex]::Replace($Text, "(?i)\b$pattern\b", $titled)
        }
    }

    # CATCH-ALL for display names whose UPN never appeared. An owner can be present as a
    # DisplayName with no UserPrincipalName beside it - which is exactly how a real name
    # survived into a published sample. Anything the harvester found gets a pseudonym whether
    # or not a matching UPN was ever seen.
    foreach ($person in $realPersonNames) {
        if (-not $script:personMap.ContainsKey($person.ToLower())) {
            $script:personIndex++
            $script:personMap[$person.ToLower()] = 'person{0:d2}' -f $script:personIndex
        }
        $titled = 'Person ' + $script:personMap[$person.ToLower()].Substring(6)
        $Text   = [regex]::Replace($Text, "(?i)\b$([regex]::Escape($person))\b", $titled)
    }

    return $Text
}

# Script-scoped so the mapping is stable across every file - the same person must become the
# same pseudonym in the inventory, the findings, the CSV and the attestation records, or the
# sample is internally inconsistent in exactly the way a reader would notice.
$script:personMap   = @{}
$script:personIndex = 0

if (-not (Test-Path $SamplesDir)) { New-Item -ItemType Directory -Path $SamplesDir -Force | Out-Null }

foreach ($w in $work) {
    $dir = Split-Path $w.Target -Parent
    if (-not (Test-Path $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }

    $clean = ConvertTo-Sanitised -Text (Get-Content $w.Source -Raw)
    $clean | Set-Content $w.Target -Encoding UTF8
    Write-Host "  wrote $($w.Label)" -ForegroundColor Green
}


# =============================================================================
# PASS 3 - VERIFY, and destroy the output if anything real survived
# =============================================================================
# The whole value of this script is here. Sanitisation that is merely attempted is how a tenant
# id ends up in a public repository, and nobody reviews a file they believe is already clean.
Write-Host ""
Write-Host "  Verifying..." -ForegroundColor Cyan

$leaks = [System.Collections.Generic.List[string]]::new()

foreach ($w in $work) {
    $f    = $w.Label
    $text = Get-Content $w.Target -Raw

    foreach ($g in $guidMap.Keys) {
        # The full GUID surviving is always a leak, with no exceptions.
        if ($text -match [regex]::Escape($g)) { $leaks.Add("$f : real GUID $g") }

        # The PREFIX check needs one exclusion, and leaving it out caused the first run to fail
        # on its own correct output.
        #
        # Microsoft's first-party GUIDs are deliberately PRESERVED, and several of them share an
        # 8-character prefix with a tenant GUID that was mapped - 00000002, 00000003 and so on.
        # So searching for a mapped GUID's prefix finds it inside a well-known GUID the script
        # intentionally kept, and reports a leak that is not one.
        #
        # Skipping prefixes that belong to a preserved GUID costs nothing in safety: the full
        # GUID check above is unconditional, and a real tenant GUID cannot share a prefix with
        # a Microsoft first-party one without also being caught there.
        $prefix = $g.Substring(0,8)
        $prefixIsWellKnown = @($wellKnown | Where-Object { $_.StartsWith($prefix) }).Count -gt 0

        if (-not $prefixIsWellKnown -and $text -match [regex]::Escape($prefix)) {
            $leaks.Add("$f : GUID prefix $prefix (of $g)")
        }
    }
    if ($TenantDomain -and $text -match [regex]::Escape($TenantDomain)) { $leaks.Add("$f : tenant domain") }

    # PEOPLE. The real display names are collected from the SOURCE data rather than listed in
    # this script, so the check works on any tenant and the script itself never records a real
    # name. A real colleague's name shipped into samples/ because nothing looked for it.
    foreach ($person in $realPersonNames) {
        if ($text -match "(?i)\b$([regex]::Escape($person))\b") { $leaks.Add("$f : person name '$person'") }
    }

    # Any surviving email on a domain other than the placeholder is a leak by definition.
    $foreignMail = [regex]::Matches($text, '[A-Za-z0-9._%-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}') |
                   Where-Object { $_.Value -notmatch '@contoso\.example$' }
    foreach ($fm in $foreignMail) { $leaks.Add("$f : address $($fm.Value)") }

    foreach ($k in $nameMap.Keys) {
        if ($text -match "(?i)$([regex]::Escape($k))") { $leaks.Add("$f : real name '$k'") }
    }
}

if ($leaks.Count -gt 0) {
    foreach ($w in $work) { Remove-Item $w.Target -Force -ErrorAction SilentlyContinue }

    Write-Host ""
    Write-Host "  SANITISATION FAILED - samples deleted, nothing written." -ForegroundColor Red
    Write-Host ""
    foreach ($l in ($leaks | Sort-Object -Unique | Select-Object -First 20)) {
        Write-Host "    $l" -ForegroundColor Yellow
    }
    Write-Host ""
    throw "$($leaks.Count) real identifier(s) survived sanitisation. Samples removed rather than published."
}

# A README so nobody mistakes the samples for a real assessment.
@"
# Sample output

Generated by ``scripts/New-SampleFixtures.ps1`` from a real run against a lab tenant, with every
GUID, tenant-owned name, UPN and domain replaced.

**Finding codes, severities, counts and structure are unchanged.** This is what the tool actually
produces - only the identifiers are synthetic.

Microsoft first-party service principal names (Azure ESTS Service, Office 365 Exchange Online and
so on) are **kept deliberately**. They are public product names, identical in every tenant, and
they are what makes a 342-identity inventory look like a real estate rather than a toy.

Generated $(Get-Date -Format 'yyyy-MM-dd').
"@ | Set-Content (Join-Path $SamplesDir 'README.md') -Encoding UTF8

Write-Host "  No real identifiers found. $($files.Count) file(s) + README written." -ForegroundColor Green
Write-Host ""
Write-Host "  $SamplesDir" -ForegroundColor DarkGray
Write-Host ""
