# Entra NHI & Agent Governance

**A read-only assessment tool for non-human identities in Microsoft Entra — service principals,
app registrations, managed identities, and AI agents — that maps what it finds to published
control objectives.**

Every framework published on agentic AI identity in 2026 tells you what *should* be true. None of
them tells you whether it *is* true in a specific tenant. This is that missing layer.

---

## What it does

| Stage | Script | Output |
|---|---|---|
| Inventory | `01-Get-NHIInventory.ps1` | Every non-human identity, its owners, credentials, permissions, sign-in activity and agent classification |
| Classify | `03-New-OwnershipMap.ps1` | Ownership map + findings: unowned, orphaned, over-permissioned, dormant, agent-specific |
| Attest | `04-Invoke-AttestationCycle.ps1` | A three-stage access-review cycle — generate, respond, report |
| Score | `05-New-ControlReport.ps1` | Findings mapped to **CCM v4.1.1** and **AICM v1.1.1** control objectives |

One command runs the chain against a single tenant read:

```powershell
./scripts/00-Connect-Lab.ps1          # read-only scopes
./scripts/Invoke-Pipeline.ps1         # 01 -> 03 -> 05, one run directory
```

---

## What it found

These came out of running it against a real tenant, not from reading documentation. **All are
n=1 — one tenant, one builder, one agent of each class.** They are reported as *measured here*,
not as statements about how Entra behaves everywhere.

**Agent sponsors are readable, through an undocumented navigation property.** The Owners and
sponsors blade is backed by `GET /beta/servicePrincipals/{id}/sponsors`, which is not in the
documentation this project could find. The tool tries candidate endpoints in order and **records
which one answered** in `SponsorLookupMethod`, so the finding is checkable rather than asserted:

```
SponsorCount = 1
SponsorLookupMethod = beta/servicePrincipals/{id}/sponsors
```

Sponsorship is the accountability relationship on an agent identity — distinct from the technical
owner — so `AGENT_SPONSORED` is reported as a positive finding naming the responsible human, not
merely as the absence of a problem.

**Managed identity accountability is genuinely not in Graph.** It lives in Azure RBAC on the
parent resource, a different control plane entirely. `-IncludeAzureRbac` reads it with a separate
`management.azure.com` token; without that the tool reports the boundary rather than guessing. A
system-assigned managed identity cannot have Entra owners *even in principle*, so reporting one as
unowned is a category error, not a finding.

**Two classes of agent, with completely different governance surfaces.** A true Entra Agent ID is
an OData subtype of `servicePrincipal` carrying 61 fields instead of 50 — including
`agentIdentityBlueprintId` and four **lifecycle-policy compliance** properties, among them the
date the agent is auto-disabled for non-compliance. A service-principal-secured agent carries
**no agent property at all** and is identifiable only by its tags. An auditor asking *"show me
every agent and its lifecycle compliance"* gets a real answer for one class and silence for the
other.

**The agent tag vocabulary, measured rather than assumed.** There is no tag called `agent`. A
Copilot Studio agent carries `AgenticApp`, `AIAgentBuilder`, `AgentCreatedBy:CopilotStudio` and
`power-virtual-agents-<environmentGuid>` — which between them give the **builder** and the
**environment**, neither of which is exposed on any documented property.

**Owner writes on an agent identity are refused** by the same token and cmdlet that succeeds on
every ordinary service principal in the same loop. Agent identities sit behind a separate
authorization boundary for ownership writes — they are readable as service principals and not
writable as them.

**Graph has two agent types whose names differ by a suffix, and one of them is not an agent:**

```
#microsoft.graph.agentIdentity                    an agent
#microsoft.graph.agentIdentityBlueprintPrincipal  the BLUEPRINT that mints agents
```

A substring match on `agentIdentity` catches both. That mistake made this tool report three agent
identities where Entra's own *"Uses agent identity: Yes"* filter shows two — the extra one being
the blueprint, which is the **security boundary** rather than a member of the population it
governs. One blueprint can mint up to 250 identities and holds the credentials they do not have.
Counting it as an agent both inflates the population and hides the thing worth watching.

**One finding maps to no published control, and that is the finding.** `DELEGATION_ESCALATION`
describes a blueprint's permissions being inherited by the agents it mints. CCM and AICM have no
control for it; SP 800-207 offers architectural tenets, not auditable objectives; and the NIST
NCCoE concept paper lists it as an **open question**, verbatim:

> *"How do we handle delegation of authority for 'on behalf of' scenarios?"*

The tool produces evidence for a gap the standards bodies have said out loud they have not closed.

---

## What it cannot do

Stated here rather than discovered later. This list is the point, not an apology.

- **Azure RBAC is invisible to Graph.** Managed identity accountability lives on the ARM control
  plane. `-IncludeAzureRbac` reads it with a separate `management.azure.com` token; without that,
  the tool reports the boundary rather than guessing.
- **Sponsor resolution depends on an undocumented endpoint.** `/beta/servicePrincipals/{id}/sponsors`
  works in the tested tenant. If it stops working the tool reports `SPONSOR_NOT_ASSESSED` —
  **unresolved, never silently "no sponsor"** — and records which endpoints it tried.
- **Tool and plugin grants live in Power Platform, not Entra.** The tool can prove the enumeration
  is missing from the directory; it cannot read the platform-side grant. That gap is the evidence
  for `IAM-18`.
- **Attestation responses are simulated** in lab mode, and every report says so automatically.
- **`DisplayName` is not an identifier.** Three objects in the test tenant share one name. Every
  output carries `ObjectId`.
- **Reports are only as fresh as the inventory.** `01` is the only script that reads the tenant;
  everything downstream reads its file. Each output states when the tenant was read and warns when
  that is stale.

---

## Safety boundary

**The auditor is read-only.** `00-Connect-Lab.ps1` requests three read scopes and nothing else.
`00b-Connect-Pipeline.ps1` **refuses to run** holding any write permission — in app-only auth
there is no signed-in user's role to cap the damage, so a write scope is a hard stop rather than a
warning.

`99-New-LabFixture.ps1` is the single exception: a test fixture that builds a deliberately
imperfect ownership distribution so every rule has something to fire on. It needs
`Application.ReadWrite.All` — **a permission this tool reports as Critical** — which is the
boundary made concrete. Run it interactively with PIM activated, in a lab, and never from a
pipeline. It is not in the GitHub workflow and never will be.

**Scan output is never published as a build artifact.** `nhi_inventory.json` is a complete map of
every non-human identity, its owners and its permissions. `output/` is git-ignored; the weekly
workflow keeps results on the runner and publishes only counts and an anonymised report.

---

## Repository

```
scripts/
  00-Connect-Lab.ps1          interactive, delegated, read-only
  00b-Connect-Pipeline.ps1    GitHub OIDC federation — no secret anywhere
  01-Get-NHIInventory.ps1     the only script that reads the tenant
  03-New-OwnershipMap.ps1     ownership + findings
  04-Invoke-AttestationCycle.ps1
  05-New-ControlReport.ps1    findings -> CCM / AICM control objectives
  99-New-LabFixture.ps1       LAB ONLY — the one script that writes
  Invoke-Pipeline.ps1         the whole chain, one tenant read
.github/workflows/nhi-scan.yml  weekly scan, federated credential, no secret
docs/                         attestation and rotation policies
reference/                    control mapping, Graph permission model, pipeline setup
WALKTHROUGH.md                what actually happened, including the wrong turns
TROUBLESHOOTING.md            every failure, with the symptom and the cause
```

**`TROUBLESHOOTING.md` is the file worth reading.** Anyone can write a README; only someone who
ran the thing can write *"this rule could never fire, and here is how that was found."* It
documents several detections that silently could not produce their own findings — including one
that accused Microsoft of a bypassed control on every agent, in a correctly configured tenant.

---

## Status

**This tool** (inventory, classification, attestation) and **the control-mapping stage** (control scoring) are implemented
and have been run against a live tenant. The findings above came from those runs.

**Not yet done:** sanitised fixtures in `samples/` so the tool can be demonstrated without a
tenant; the GitHub workflow is written but unrun pending federated-credential setup.

---

## Requirements

PowerShell 7+, and the `Microsoft.Graph.Authentication`, `Microsoft.Graph.Applications` and
`Microsoft.Graph.Identity.DirectoryManagement` modules. Read scopes:
`Application.Read.All`, `Directory.Read.All`, `AuditLog.Read.All`.

## Licence

MIT. See [LICENSE](LICENSE).
