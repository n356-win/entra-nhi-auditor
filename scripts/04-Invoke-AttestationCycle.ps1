<#
.SYNOPSIS
    Runs an identity attestation cycle: generate requests, capture responses, produce a
    governance report.

.DESCRIPTION
    Attestation is the recurring process of confirming with an identity's OWNER that the
    access is still required. Access granted once and never reviewed is the main source of
    privilege creep and forgotten service accounts - an inventory tells you what exists, but
    only attestation tells you what should still exist.

    Built as three separate stages - generate, respond, report - because each does exactly one
    job and each reads the output of the one before without mutating it. That separation is
    what makes a cycle auditable: the record of what was asked survives independently of the
    record of what came back.

    THE DESIGN DECISION WORTH UNDERSTANDING
    ---------------------------------------
    "No Response" is treated as a HIGHER priority finding than "Rejected".

        Rejected     = a decision. Somebody looked at it and said no. That is a good outcome -
                       the process worked, and you now have a clear action.
        No Response  = UNCONFIRMED ACCESS. Nobody can tell you whether this should exist.

    Most organisations treat silence as implicit approval, which quietly converts every
    unanswered request into permanent access. Treating silence as the WORST outcome is what
    makes attestation a control rather than a formality. Say this explicitly in your policy
    document - it demonstrates governance thinking rather than scripting.

    Reads  : output/nhi_ownership.csv
    Writes : output/attestation_records.json   (stage 1 - the requests)
             output/attestation_results.json   (stage 2 - the responses)
             output/attestation_report.md      (stage 3 - the deliverable)

.PARAMETER Stage
    Generate, Respond, Report, or All. Separating them lets you re-run just the report after
    tweaking its wording, without regenerating the cycle.

.PARAMETER ResponseWindowDays
    How long owners get to respond. Default 30, which mirrors common enterprise practice -
    long enough to be fair, short enough that stale access does not linger.

.PARAMETER Simulate
    Generate simulated owner responses. REQUIRED in a lab, because there are no real owners
    to reply. The simulation is then DOCUMENTED in the report output - hiding it is how a
    portfolio project gets taken apart in an interview.

.EXAMPLE
    .\04-Invoke-AttestationCycle.ps1 -Simulate

.EXAMPLE
    .\04-Invoke-AttestationCycle.ps1 -Stage Report
    Regenerate just the report from existing results.

.NOTES
    In production, stage 2 is replaced by a real notification integration - email, Teams, or
    a ticketing system - and actual owner responses. Nothing else about the design changes.
#>

[CmdletBinding()]
param(
    [ValidateSet('Generate','Respond','Report','All')]
    [string]$Stage = 'All',

    # ---------------------------------------------------------------------------------------
    # CYCLE COMPARTMENTALISATION - added 25 Oct 2026. THIS WAS A BUG.
    # ---------------------------------------------------------------------------------------
    # Until this change every stage wrote to a fixed filename, so each run DESTROYED the
    # previous cycle. That directly contradicted docs/attestation-policy.md section 7 -
    # "Retain every cycle. Never overwrite a previous one." The policy was right.
    #
    # It matters more than it looks. The value of an attestation programme to an auditor is
    # not this cycle's numbers - it is producing four consecutive dated cycles and showing the
    # non-response rate falling. Overwriting destroys precisely that evidence.
    #
    # NOTE THE QUARTER LABEL, NOT A TIMESTAMP. A cycle is a PERIOD, not an execution. The
    # three stages below run days or weeks apart - Generate, wait for humans, Respond, Report
    # - and all of them belong to the same cycle. Timestamping each stage would scatter one
    # cycle across three directories and make the quarters uncomparable, which is the whole
    # value of keeping them.
    [string]$CycleId = ("{0}-Q{1}" -f (Get-Date).Year, [math]::Ceiling((Get-Date).Month / 3)),

    [string]$OutputRoot = (Join-Path $PSScriptRoot '..\output'),
    [string]$CycleDir   = (Join-Path $OutputRoot "attestation\$CycleId"),

    # The scan this cycle attests to. Defaults to the current run; pass -RunId to attest
    # against an older inventory.
    [string]$RunId = $(
        $pointer = Join-Path $OutputRoot 'latest-run.txt'
        if (Test-Path $pointer) { (Get-Content $pointer -Raw).Trim() } else { $null }
    ),
    [string]$OwnershipCsv = (Join-Path $OutputRoot "runs\$RunId\nhi_ownership.csv"),

    [string]$RecordsPath  = (Join-Path $CycleDir 'attestation_records.json'),
    [string]$ResultsPath  = (Join-Path $CycleDir 'attestation_results.json'),
    [string]$ReportPath   = (Join-Path $CycleDir 'attestation_report.md'),

    [int]$ResponseWindowDays = 30,
    [switch]$Simulate
)

# Refuse to silently clobber a completed cycle. Re-running Generate inside a quarter that
# already has results is almost always a mistake - and if it is deliberate, saying so out loud
# is cheap. An attestation record that quietly changed after the fact is worthless as evidence.
if ($Stage -in 'Generate','All' -and (Test-Path $ResultsPath)) {
    Write-Warning "Cycle $CycleId already has completed results at $ResultsPath."
    Write-Warning "Re-generating will overwrite the record of a cycle that already closed."
    Write-Warning "If that is intended, delete the cycle directory deliberately. If you meant"
    Write-Warning "to start the NEXT cycle, pass -CycleId explicitly."
    throw "Refusing to overwrite a closed cycle. See docs/attestation-policy.md section 7."
}

Write-Host "Attestation cycle: $CycleId" -ForegroundColor Cyan
Write-Host "Attesting to scan run: $RunId" -ForegroundColor DarkGray

$ErrorActionPreference = 'Stop'

$outDir = Split-Path $RecordsPath -Parent
if (-not (Test-Path $outDir)) { New-Item -ItemType Directory -Path $outDir -Force | Out-Null }

# Stamp the cycle so a directory found on its own, years later, still explains itself. An
# evidence artefact that cannot say what it is, when it ran, or what it attested to is not
# evidence.
[pscustomobject]@{
    CycleId        = $CycleId
    ScanRunId      = $RunId
    OpenedUtc      = (Get-Date).ToUniversalTime().ToString('o')
    ResponseWindow = $ResponseWindowDays
    Simulated      = [bool]$Simulate
    Policy         = 'docs/attestation-policy.md'
} | ConvertTo-Json | Set-Content (Join-Path $outDir 'cycle.json') -Encoding UTF8


# #############################################################################
#  STAGE 1 - GENERATE
#  Create one attestation request per identity that needs confirming.
# #############################################################################
function Invoke-Generate {

    if (-not (Test-Path $OwnershipCsv)) {
        throw "Ownership map not found at $OwnershipCsv. Run 03-New-OwnershipMap.ps1 first."
    }

    # External identities are excluded: Microsoft first-party and third-party service
    # principals have no tenant owner to send a request to, and asking somebody to attest to
    # Microsoft's own Office 365 service principal is meaningless.
    #
    # APP REGISTRATIONS ARE ALSO EXCLUDED, and the reasoning matters more than the filter.
    # Added 2026-10-25.
    #
    # Attestation asks ONE question: "is this access still needed?" Access lives on the
    # SERVICE PRINCIPAL - it holds the consent grants and the app role assignments, it is what
    # appears in the sign-in logs, and disabling it is the remediation. An app registration is
    # the DEFINITION: credentials, requested permissions, redirect URIs. Its owner answers a
    # different question - "who may mint a secret for this?" - which is credential custody,
    # reported as NO_APP_REGISTRATION_OWNER by script 03 and not attested here.
    #
    # Including both would also DOUBLE-COUNT every tenant-built app. An application and its
    # service principal share an appId, so the same identity would generate two attestation
    # records addressed to two different owner lists, and a reviewer approving one while the
    # other goes unanswered produces a cycle that is simultaneously complete and incomplete.
    #
    # And the asymmetry that settles it: a third-party SaaS app has a service principal here
    # and NO app registration - the registration lives in the vendor's tenant. 325 service
    # principals against 17 app registrations in the lab. Attesting app registrations would
    # miss most of the estate; attesting service principals covers all of it.
    $identities = Import-Csv $OwnershipCsv |
                  Where-Object { $_.Classification -ne 'External (Microsoft / third-party)' } |
                  Where-Object { $_.ObjectClass   -ne 'Application' }

    $cycleDate = (Get-Date).ToUniversalTime()
    $dueDate   = $cycleDate.AddDays($ResponseWindowDays)

    # A cycle ID makes each run traceable. An auditor asking "which review was this finding
    # from?" needs an answer, and "the one in October" is not one.
    $cycleId = "CYCLE-{0}" -f $cycleDate.ToString('yyyyMMdd')

    $records = foreach ($i in $identities) {
        [pscustomobject]@{
            CycleId           = $cycleId
            DisplayName       = $i.DisplayName
            AppId             = $i.AppId
            ObjectClass       = $i.ObjectClass
            Classification    = $i.Classification
            Owner             = $i.Owner

            # Captured now because it changes what can happen in stage 2. An identity with no
            # owner cannot be attested at all - there is nobody to ask.
            OwnerAssigned     = ($i.Owner -ne 'UNASSIGNED')

            # AN OWNER IS NOT AUTOMATICALLY A RESPONDENT. Added 2026-10-25.
            #
            # OwnerAssigned alone was the eligibility test, and it asks only "is the ownership
            # field populated?". Measured consequence in the lab:
            #
            #   svc-provisioning, whose only owner is the SERVICE PRINCIPAL app1, was issued an
            #   attestation request and the simulation recorded it APPROVED.
            #
            # A service principal cannot approve anything. It cannot read an email, form a
            # judgement, or be held accountable for one. An "approved" row against a non-human
            # owner is a FABRICATED CONTROL EVIDENCE - the single worst output an attestation
            # tool can produce, because it is indistinguishable from a real approval and it is
            # the artifact an auditor relies on.
            #
            # A group is the same failure in a politer form: the request reaches a mailbox
            # nobody owns, or everybody assumes someone else answered.
            #
            # So eligibility now requires a HUMAN owner. Script 03 flags the state as
            # NO_HUMAN_OWNER; this field stops the cycle from papering over it.
            HasHumanOwner     = ($i.Findings -notmatch 'NO_HUMAN_OWNER') -and ($i.Owner -ne 'UNASSIGNED')
            OwnerKindNote     = if ($i.Findings -match 'NO_HUMAN_OWNER') { 'Owner is a group or service principal - cannot respond' } else { $null }

            # Carried through from Phase 3 so the final report can show the severity of what
            # is going unconfirmed. An unanswered request about a Critical identity matters
            # more than an unanswered request about a Low one.
            TopSeverity       = $i.TopSeverity
            Findings          = $i.Findings

            RequestDate       = $cycleDate.ToString('o')
            DueDate           = $dueDate.ToString('o')
            AttestationStatus = 'Pending'
            ResponseDate      = $null
        }
    }

    [pscustomobject]@{
        CycleId            = $cycleId
        GeneratedUtc       = $cycleDate.ToString('o')
        DueDate            = $dueDate.ToString('o')
        ResponseWindowDays = $ResponseWindowDays
        RecordCount        = @($records).Count
        Records            = $records
    } | ConvertTo-Json -Depth 8 | Set-Content $RecordsPath -Encoding UTF8

    Write-Host "Stage 1 - generated $(@($records).Count) attestation requests ($cycleId)." -ForegroundColor Green

    # Surface the unanswerable ones immediately. These never even reach stage 2 as real
    # requests, and they are the most serious category in the final report.
    $unassigned = @($records | Where-Object { -not $_.OwnerAssigned }).Count
    if ($unassigned -gt 0) {
        Write-Host "  $unassigned have NO OWNER to send the request to." -ForegroundColor Yellow
        Write-Host "  These cannot be attested at all - they go straight to escalation." -ForegroundColor Yellow
    }
}


# #############################################################################
#  STAGE 2 - RESPOND
#  In production: send requests and collect real answers.
#  In a lab: simulate, and say so loudly.
# #############################################################################
function Invoke-Respond {

    if (-not (Test-Path $RecordsPath)) { throw "No records found. Run -Stage Generate first." }

    # Deliberately refuses to run without -Simulate. Producing fake attestation data by
    # accident, and later forgetting it was fake, is a genuinely bad outcome - so the switch
    # has to be explicit.
    if (-not $Simulate) {
        Write-Warning "Stage 2 requires -Simulate in a lab environment."
        Write-Warning "In production this stage is a real notification integration and real responses."
        Write-Warning "Re-run with -Simulate to produce lab data."
        return
    }

    $data = Get-Content $RecordsPath -Raw | ConvertFrom-Json
    $now  = (Get-Date).ToUniversalTime()

    # Weighted outcome: 70% Approved / 10% Rejected / 20% No Response. Chosen because it is
    # roughly what real attestation cycles look like - most access genuinely is still needed,
    # a little is not, and a meaningful minority of people simply never reply.
    $results = foreach ($r in $data.Records) {

        # An identity with no owner has nobody to respond. It is NOT "No Response" by choice -
        # there was never a recipient. Conflating the two would hide the more serious problem
        # inside the less serious one, so it gets its own status.
        if (-not $r.OwnerAssigned) {
            $r.AttestationStatus = 'No Owner - Cannot Attest'
            $r.ResponseDate      = $null
            $r
            continue
        }

        # ---------------------------------------------------------------------------------
        # RESPONSE CORRELATES WITH OWNER STATE. Added 28 Oct 2026.
        # ---------------------------------------------------------------------------------
        # A flat 70/10/20 across every record is a coin toss wearing a statistic. It produces
        # a plausible-looking total and teaches nothing, because the interesting question is
        # not HOW MANY people did not reply - it is WHICH ONES, and whether that was
        # predictable from data you already held.
        #
        # It is also the single most useful thing an attestation report can say:
        #
        #     "Every identity owned by someone who has left went unanswered.
        #      You could have known that before you sent a single request."
        #
        # That sentence is the argument for the whole programme. A random simulation cannot
        # produce it, so the simulation is made to behave the way people do.
        # FIXED 2026-10-25 - BOTH PREDICATES WERE PERMANENTLY FALSE.
        #
        # They read $r.OwnerEnabled and $r.OwnerType. Neither field is ever written into an
        # attestation record - the record carries CycleId, DisplayName, AppId, ObjectClass,
        # Classification, Owner, OwnerAssigned, TopSeverity, Findings and the dates, and
        # nothing else. So both evaluated to $false on every record, the whole correlation
        # block was unreachable, and every owned identity fell through to the random 70/10/20.
        #
        # Measured consequence, found by reading the CSV rather than the summary:
        #
        #   svc-provisioning - whose only owner is the service principal app1 - was recorded
        #   "Approved". A service principal cannot approve anything.
        #
        # That is FABRICATED CONTROL EVIDENCE. An approval row is the artifact an auditor
        # relies on most, and this one was generated by a dice roll on behalf of an owner
        # incapable of responding. The comment above promised the simulation "is made to
        # behave the way people do"; it was behaving like a coin.
        #
        # FIFTH rule this week whose input field was never populated. NO_SPONSOR could only
        # fire, NO_OWNER fired falsely on agents, ORPHANED_OWNER could never fire,
        # NO_HUMAN_OWNER was never written at all, and these two were dead predicates. Same
        # defect every time, and not one of them failed loudly.
        #
        # Now derived from fields the record genuinely has. Findings is the string script 03
        # wrote, so the correlation keys off the SAME evidence the control report cites -
        # which also means the two documents can no longer disagree.
        $ownerDeparted = ($r.Findings -match 'ORPHANED_OWNER')
        $ownerNotHuman = ($r.Findings -match 'NO_HUMAN_OWNER') -or
                         ($r.PSObject.Properties['HasHumanOwner'] -and -not $r.HasHumanOwner)

        $status =
            if ($ownerDeparted) {
                # A disabled account cannot reply. This is ORPHANED_OWNER showing its
                # consequence - the identity looked governed right up until someone asked.
                'No Response'
            }
            elseif ($ownerNotHuman) {
                # A group or service principal as owner. Nobody is on the other end. Reported
                # distinctly because "a group did not reply" and "a person did not reply" are
                # different problems with different fixes.
                'No Response - Non-Human Owner'
            }
            else {
                # Active human owner: the 70/10/20 split applies, and now it means something,
                # because the population it is applied to is one that could actually answer.
                $roll = Get-Random -Minimum 1 -Maximum 101
                if     ($roll -le 70) { 'Approved' }
                elseif ($roll -le 80) { 'Rejected' }
                else                  { 'No Response' }
            }

        $r.AttestationStatus = $status

        # Someone who never responded has no response date - leaving it null rather than
        # faking one keeps the data honest.
        if ($status -like 'No Response*') {
            $r.ResponseDate = $null
        }
        else {
            $r.ResponseDate = $now.AddDays(-(Get-Random -Minimum 1 -Maximum $ResponseWindowDays)).ToString('o')
        }

        $r
    }

    # The Simulated flag and note travel WITH the data, so the report can disclose it
    # automatically and nobody can mistake lab output for a real cycle later.
    [pscustomobject]@{
        CycleId        = $data.CycleId
        GeneratedUtc   = $now.ToString('o')
        Simulated      = $true
        SimulationNote = 'Owner responses are simulated and CORRELATE WITH OWNER STATE, not randomly: a departed (disabled) owner never responds; a group or service principal owner never responds; only active human owners get the 70/10/20 split. No real owners were contacted. See docs/attestation-policy.md.'
        Records        = $results
    } | ConvertTo-Json -Depth 8 | Set-Content $ResultsPath -Encoding UTF8

    Write-Host "Stage 2 - captured $(@($results).Count) responses (SIMULATED)." -ForegroundColor Green
}


# #############################################################################
#  STAGE 3 - REPORT
#  The actual deliverable: the document a manager or auditor receives.
# #############################################################################
function Invoke-Report {

    if (-not (Test-Path $ResultsPath)) { throw "No results found. Run -Stage Respond first." }

    $data    = Get-Content $ResultsPath -Raw | ConvertFrom-Json
    $records = $data.Records
    $total   = @($records).Count
    if ($total -eq 0) { throw "No records to report on." }

    # Bucket by outcome.
    $approved   = @($records | Where-Object AttestationStatus -eq 'Approved')
    $rejected   = @($records | Where-Object AttestationStatus -eq 'Rejected')
    $noResponse = @($records | Where-Object AttestationStatus -eq 'No Response')
    $noOwner    = @($records | Where-Object AttestationStatus -eq 'No Owner - Cannot Attest')

    # NON-HUMAN OWNER - ITS OWN BUCKET. Added 2026-10-25.
    #
    # Stage 2 has been able to emit 'No Response - Non-Human Owner' since the simulation was
    # made to correlate with owner state, and NOTHING HERE COUNTED IT. Every bucket above
    # matches its status with -eq, so this one fell through all four while still counting in
    # $total. The record existed, was correct, and was invisible: the summary percentages
    # silently did not sum to 100, and the most serious outcome in the cycle appeared in no row.
    #
    # Measured on svc-provisioning, owned solely by the service principal app1:
    #     "AttestationStatus": "No Response - Non-Human Owner"
    # correctly generated by stage 2, then dropped by stage 3.
    #
    # This is the lab's recurring defect in its final form. Not a rule that could not fire -
    # a rule that fired correctly and was then NOT COUNTED. Same visible symptom: a clean
    # summary that omits the thing you most need to see.
    $nonHumanOwner = @($records | Where-Object AttestationStatus -eq 'No Response - Non-Human Owner')

    # Small helper so percentage formatting is consistent everywhere.
    $pct = { param($n) [math]::Round(($n / $total) * 100, 1) }

    # EXHAUSTIVENESS ASSERTION. The buckets must account for every record, or the summary is
    # arithmetically wrong and nothing in the document would say so. A new status added to
    # stage 2 without a bucket here now fails loudly instead of quietly vanishing - which is
    # exactly how 'No Response - Non-Human Owner' went unnoticed.
    $bucketed = $approved.Count + $rejected.Count + $noResponse.Count + $noOwner.Count + $nonHumanOwner.Count
    if ($bucketed -ne $total) {
        $unaccounted = @($records | Where-Object {
            $_.AttestationStatus -notin 'Approved','Rejected','No Response',
                                        'No Owner - Cannot Attest','No Response - Non-Human Owner'
        })
        $kinds = @($unaccounted.AttestationStatus | Sort-Object -Unique) -join ', '
        throw ("Attestation summary would be wrong: $bucketed of $total records fall into a known " +
               "bucket. Unaccounted status value(s): $kinds. Add a bucket for each before reporting - " +
               "an outcome with no row is an outcome the reader never sees.")
    }

    # Built as a list of lines and joined at the end. Far easier to read and reorder than
    # string concatenation, and it is the same approach attestation_report.py takes.
    $md = [System.Collections.Generic.List[string]]::new()

    $md.Add("# Identity Attestation Report")
    $md.Add("")
    $md.Add("**Cycle:** $($data.CycleId)  ")
    $md.Add("**Report date:** $((Get-Date).ToString('yyyy-MM-dd'))  ")
    $md.Add("**Identities reviewed:** $total")
    $md.Add("")

    # DISCLOSURE, AUTOMATICALLY. If the data says it was simulated, the report says so - it
    # is not left to the author to remember. This is the single most important honesty
    # feature in the whole lab.
    if ($data.Simulated) {
        $md.Add("> **Lab environment.** Owner responses in this cycle are simulated using a weighted")
        $md.Add("> outcome (70% approved, 10% rejected, 20% no response). No real owners were")
        $md.Add("> contacted. In production this stage is a real notification integration. This is")
        $md.Add("> stated plainly rather than hidden - see ``docs/attestation-policy.md``.")
        $md.Add("")
    }

    $md.Add("## Summary")
    $md.Add("")
    $md.Add("| Outcome | Count | Share |")
    $md.Add("|---|---:|---:|")
    $md.Add("| Approved | $($approved.Count) | $(& $pct $approved.Count)% |")
    $md.Add("| Rejected | $($rejected.Count) | $(& $pct $rejected.Count)% |")
    $md.Add("| **No Response** | **$($noResponse.Count)** | **$(& $pct $noResponse.Count)%** |")
    $md.Add("| **No Owner - cannot attest** | **$($noOwner.Count)** | **$(& $pct $noOwner.Count)%** |")
    $md.Add("| **Non-human owner - cannot respond** | **$($nonHumanOwner.Count)** | **$(& $pct $nonHumanOwner.Count)%** |")
    $md.Add("")

    # The distinction this row exists to make, stated where a reader meets the number.
    if ($nonHumanOwner.Count -gt 0) {
        $md.Add("> **Why 'non-human owner' is separate from 'no response'.** A human who does not")
        $md.Add("> reply has made a choice and can be chased. A group or service principal listed")
        $md.Add("> as owner was never capable of replying - there is no recipient, and no amount of")
        $md.Add("> chasing produces one. These identities APPEAR governed on any dashboard because")
        $md.Add("> the ownership field is populated, which makes them harder to find than the ones")
        $md.Add("> with no owner at all. They need a named human owner before the next cycle, not")
        $md.Add("> a reminder email.")
        $md.Add("")
    }

    # --- PRIORITY 1 ----------------------------------------------------------
    # Worse than no response: there was never anybody to ask.
    $md.Add("## Priority 1 - No owner, cannot be attested")
    $md.Add("")
    $md.Add("These identities have no assigned owner, so no attestation request could be sent.")
    $md.Add("They cannot be confirmed as necessary by anyone. This is the most serious category:")
    $md.Add("an identity nobody owns is an identity nobody will notice when it is abused.")
    $md.Add("")
    if ($noOwner.Count -gt 0) {
        $md.Add("| Identity | Class | Severity | Findings |")
        $md.Add("|---|---|---|---|")
        foreach ($r in ($noOwner | Sort-Object TopSeverity -Descending)) {
            $md.Add("| $($r.DisplayName) | $($r.ObjectClass) | $($r.TopSeverity) | $($r.Findings) |")
        }
    } else { $md.Add("_None in this cycle._") }
    $md.Add("")

    # --- PRIORITY 2 ----------------------------------------------------------
    # The ranking that defines the whole philosophy. Explained in the report itself, because
    # a reader will otherwise assume it is a mistake.
    $md.Add("## Priority 2 - No response by due date")
    $md.Add("")
    $md.Add("An owner exists but did not respond within the $($ResponseWindowDays)-day window.")
    $md.Add("**This ranks above Rejected deliberately.** A rejection is a decision; silence is")
    $md.Add("unconfirmed access, and nobody can say whether it should still exist. Treating")
    $md.Add("silence as implicit approval is how stale privilege accumulates.")
    $md.Add("")
    $md.Add("Recommended action: escalate for manual review; suspend access pending confirmation.")
    $md.Add("")
    if ($noResponse.Count -gt 0) {
        $md.Add("| Identity | Owner | Due | Severity |")
        $md.Add("|---|---|---|---|")
        foreach ($r in $noResponse) {
            $due = if ($r.DueDate) { ([datetime]$r.DueDate).ToString('yyyy-MM-dd') } else { '-' }
            $md.Add("| $($r.DisplayName) | $($r.Owner) | $due | $($r.TopSeverity) |")
        }
    } else { $md.Add("_None in this cycle._") }
    $md.Add("")

    # --- PRIORITY 3 ----------------------------------------------------------
    # A clean outcome: somebody looked, decided, and told you. Actionable and low drama.
    $md.Add("## Priority 3 - Rejected, queued for removal")
    $md.Add("")
    $md.Add("Owners confirmed these are no longer required. Revoke in the next maintenance window.")
    $md.Add("")
    if ($rejected.Count -gt 0) {
        $md.Add("| Identity | Owner | Responded |")
        $md.Add("|---|---|---|")
        foreach ($r in $rejected) {
            $resp = if ($r.ResponseDate) { ([datetime]$r.ResponseDate).ToString('yyyy-MM-dd') } else { '-' }
            $md.Add("| $($r.DisplayName) | $($r.Owner) | $resp |")
        }
    } else { $md.Add("_None in this cycle._") }
    $md.Add("")

    # Approved needs no table - it is the expected outcome and listing it adds noise.
    $md.Add("## Approved")
    $md.Add("")
    $md.Add("$($approved.Count) identities confirmed as still required. No action until the next cycle.")
    $md.Add("")
    $md.Add("---")
    $md.Add("")
    $md.Add("_Generated by 04-Invoke-AttestationCycle.ps1. Attestation policy: ``docs/attestation-policy.md``._")

    $md -join "`n" | Set-Content $ReportPath -Encoding UTF8

    Write-Host "Stage 3 - report written." -ForegroundColor Green
    Write-Host ""
    Write-Host "  Approved                 : $($approved.Count)"
    Write-Host "  Rejected                 : $($rejected.Count)"
    Write-Host "  No Response              : $($noResponse.Count)" -ForegroundColor Yellow
    Write-Host "  No Owner (cannot attest) : $($noOwner.Count)" -ForegroundColor Red
    Write-Host ""
    Write-Host "  $ReportPath"
}


# =============================================================================
# DISPATCH - run the requested stage, or all three in order
# =============================================================================
switch ($Stage) {
    'Generate' { Invoke-Generate }
    'Respond'  { Invoke-Respond }
    'Report'   { Invoke-Report }
    'All'      { Invoke-Generate; Invoke-Respond; Invoke-Report }
}

Write-Host ""
Write-Host "Output contains REAL TENANT DATA - confirm .gitignore excludes it." -ForegroundColor Yellow
Write-Host "Next: .\05-New-ControlReport.ps1" -ForegroundColor Cyan
