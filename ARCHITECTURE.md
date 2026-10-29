# Architecture

**Written 23 October 2026, revised 26 October.** The whole thing in order — what runs when, what
it produces, what consumes it, and when each piece opens. Completes the four-file documentation
standard alongside `README.md`, `WALKTHROUGH.md` and `TROUBLESHOOTING.md`.

---

## 1. The pipeline — what feeds what

```
         ┌─────────────────────────────────────────────────┐
         │  00-Connect-Lab          interactive, delegated │  ← a human, locally
         │  00b-Connect-Pipeline    federated, app-only    │  ← GitHub Actions
         └───────────────────────┬─────────────────────────┘
                                 │  authenticated Graph session
                                 ▼
              ┌───────────────────────────────────┐
              │ 01-Get-NHIInventory               │   THE ONLY STAGE THAT
              │ applications, service principals, │   READS THE TENANT
              │ managed identities, agents        │
              │ → nhi_inventory.json              │
              └───────────────┬───────────────────┘
                              │   every stage below reads a FILE
                              ▼
              ┌───────────────────────────────────┐
              │ 03-New-OwnershipMap               │
              │ ownership, credentials, scope,    │
              │ dormancy, agent classification    │
              │ → nhi_ownership.csv   (humans)    │
              │ → nhi_findings.json   (machines)  │
              └───────────────┬───────────────────┘
                              ├──────────────────────────────┐
                              ▼                              ▼
              ┌───────────────────────────────┐  ┌───────────────────────────┐
              │ 04-Invoke-AttestationCycle    │  │ 05-New-ControlReport      │
              │ ask the SPONSOR (agents) or   │  │ findings → CCM v4.1.1 /   │
              │ the OWNER. Simulated in lab.  │  │ AICM v1.1.1 objectives    │
              │ → attestation_* (3 files)     │  │ → control_report.md       │
              └───────────────────────────────┘  └───────────────────────────┘

         Invoke-Pipeline.ps1 runs 01 → 03 → (04) → 05 against ONE tenant read,
         threading one RunId through every stage into one run directory.
```

**Only `01` touches the tenant.** Everything after it reads the file `01` produced — which is what
makes a finding reproducible, lets the classification logic run without credentials, and allows an
old inventory to be re-classified after a rule changes.

---

## 2. Stages

| Stage | What | Script | Produces |
|---|---|---|---|
| **0** | Connect with least privilege. Understand the permission model. | `00`, `00b` | A verified session |
| **1** | Enumerate apps, service principals, managed identities, agents | `01` | `nhi_inventory.json` |
| **3** | Classify: ownership, credentials, permissions, activity, provenance | `03` | `nhi_findings.json`, `nhi_ownership.csv` |
| **4** | Attestation cycle — ask the accountable human | `04` | Records, results, report |
| **5** | Map findings to published controls | `05` | `control_report.md` |
| **—** | Run the whole chain against one tenant read | `Invoke-Pipeline.ps1` | One run directory |

### Why attestation is not optional

A complete identity registry needs **four attributes** per identity. The directory holds **one**:

| Attribute | In Entra? |
|---|---|
| **Defined scope** | **Yes** — `appRoleAssignments`, `oauth2PermissionGrants` |
| Named human owner | Field exists — **often empty, or a service principal** |
| **Business justification** | **No such field exists anywhere** |
| **Expiry on the identity** | **No** — credentials expire, identities do not |

**The exception, and it is Microsoft's doing:** sponsorship is **mandatory on agent identities**.
So for that one object class the accountable-human attribute *does* exist in the directory.

> **Agent identities: 2 of 4 (scope + sponsor). Everything else: 1 of 4 (scope only).**

**A complete registry is a data-model problem, not a scanning problem.** You cannot scan your way
to a field that does not exist — which is why stage 4 matters: **attestation is how the missing
fields get created.** You ask the sponsor, and their answer *becomes* the justification.

---

## 3. Cadence — two different clocks

**The scripts do not all run together, and treating them as one pipeline is the mistake.**

| Job | Cadence | Why | Cost |
|---|---|---|---|
| **Scan** — `01` → `03` → `05` | **Weekly** | Cheap, read-only, no humans. Detects drift fast. | Minutes |
| **Attestation** — `04` | **Quarterly** | Involves people. Run it monthly and owners rubber-stamp, which is worse than no review. | Days of human latency |

### The bug: `04` overwrites its own history

`04-Invoke-AttestationCycle.ps1` writes to fixed paths — `attestation_records.json`,
`attestation_results.json`, `attestation_report.md`. **Every run destroys the previous cycle.**

That directly contradicts `docs/attestation-policy.md` §7, which says *"Retain every cycle. Never
overwrite a previous one."* **The policy is right and the script is wrong.**

It matters more than it looks: **one dated report is a screenshot; four consecutive ones are a
control.** An attestation programme's value to an auditor is showing the non-response rate falling
over four quarters. Overwriting destroys exactly the evidence that makes it one.

### The fix — **implemented 25 October 2026**

```
output/
├─ runs/                            ← scan output, one directory per run
│  ├─ 2026-10-25T06-00Z/
│  │  ├─ nhi_inventory.json         ← 01
│  │  ├─ nhi_ownership.csv          ← 03
│  │  ├─ nhi_findings.json          ← 03
│  │  └─ control_report.md          ← 05
│  └─ 2026-11-01T06-00Z/
├─ attestation/                     ← one directory per CYCLE, not per run
│  ├─ 2026-Q4/
│  │  ├─ cycle.json                 ← what this cycle is, when, against which run
│  │  ├─ attestation_records.json
│  │  ├─ attestation_results.json
│  │  └─ attestation_report.md
│  └─ 2027-Q1/
└─ latest-run.txt                   ← pointer, written by 01
```

**How the scripts stay in step.** `01` owns the run id — it creates the directory and writes
`latest-run.txt`. `03` and `05` read that pointer, so the whole pipeline lands in one directory
with nobody passing an id around. Pass `-RunId` explicitly to re-process an older run, which is
the point of keeping them: **change a rule, re-run `03` against last quarter's inventory, and
compare.**

**A pointer file, not a `latest/` directory.** An earlier draft of this section proposed copying
the newest output into `latest/`. That duplicates real tenant data on disk for convenience, which
is a cost with no upside. The pointer is one line a human can also just open and read.

**`04` uses a quarter label, not a timestamp — and that asymmetry is deliberate.** A cycle is a
*period*, not an execution. Its three stages run days or weeks apart — Generate, wait for humans,
Respond, Report — and all of them belong to the same cycle. Timestamping each stage would scatter
one cycle across three directories and make quarters uncomparable, which is the entire value of
keeping them. **`04` now refuses to re-generate into a quarter that already has results**, because
an attestation record that quietly changed after the fact is worthless as evidence.

Each cycle also writes `cycle.json` — what it is, when it opened, which scan run it attested to,
and whether responses were simulated. **An evidence artefact that cannot say what it is, when it
ran, and what it attested to is not evidence.**

**Never delete a run directory.** Compress old ones if size becomes a problem; the whole point is
that the history exists.

### "What if a Critical appears between scheduled runs?"

**Two answers, and the first matters more.**

**1. The weekly scan already is the alert.** It fails the build on any Critical, which is a
notification you cannot ignore. Weekly is a short enough window for a posture assessment.

**2. For genuinely real-time detection, this is not the right tool — and that is a boundary worth
defending.** Continuous detection needs Entra audit logs routed to Log Analytics with alert rules
on directory-write events. That is Defender and Azure Monitor territory. Building it here would be
scope creep into a space where Microsoft already does it better.

> **This tool measures posture at a point in time. It is not a monitor.**
> Say that in the report. A tool that states its boundary is trusted on the things inside it.

**What should happen when a Critical does appear:** `workflow_dispatch` lets you re-run on demand,
and the attestation policy should trigger an **off-cycle attestation for that identity only** —
not a wait of up to ninety days. The policy already halves every interval for
`EXCESSIVE_SCOPE_ESCALATION` identities; a new Critical is the same argument, applied on arrival.

---

## 4. The finding codes

| Group | Codes | Population |
|---|---|---|
| **Ownership** | `NO_OWNER` · `ORPHANED_OWNER` | All NHIs |
| | `NO_SPONSOR` · `SP_SECURED_AGENT` | **Agents only** |
| | `MI_OWNERSHIP_NOT_IN_GRAPH` | Managed identities only |
| **Credentials** | `CRED_NO_EXPIRY` · `CRED_EXPIRED` · `CRED_LONG_LIVED` · `CRED_EXPIRING` · `SECRET_OVER_CERT` · `FEDERATED_CRED` | All NHIs |
| **Permissions** | `EXCESSIVE_SCOPE_ESCALATION` · `HIGH_IMPACT_PERMISSION` | All NHIs |
| **Activity** | `DORMANT` · `NO_SIGNIN_RECORD` · `DISABLED_WITH_CREDS` | All NHIs |
| | `DORMANT_AGENT` | **Agents only** |
| **Provenance** *(opt-in)* | `IAC_MANAGED` · `UNMANAGED_IDENTITY` · `UNMANAGED_PRIVILEGED` | All NHIs |
| **Specced, not built** | `AGENT_CAPABILITY_OPAQUE` · `AGENT_FACTORY_CAPACITY` · `DELEGATION_ESCALATION` | **Agents only** |

`AGENT_CAPABILITY_OPAQUE` is the headline. It maps to **IAM-AG-01**, which requires the agent
identity carry its *"authorized tool set"* — and the lab agent's does not.

### The population column is not decoration

**The AICM Agentic Supplement governs agents. Nothing else.** The first real control report scored
`Okta-SAML-SSO`, `AWS IAM Identity Center` and `Workday` against *"**Agent** identity
registration"* — a category error, and the second instance of applying a rule to a population it
was never written for.

So `05-New-ControlReport.ps1` now gives every control an **`AppliesTo`** and evaluates it only
against that population. Non-agent findings land in **`UNMAPPED-02`** — visible and uncounted —
because **This tool has a real control mapping for agents and none for ordinary non-human
identities.** The sets that would govern them (CCM / AICM IAM domain, NIST SP 800-207,
SP 800-63-4) have not been read.

> **A visible hole in a mapping is a scoping decision. A borrowed control is a false claim.**

And the inverse guard: an agent control in a tenant with no agents reports **`NOT APPLICABLE`**,
not `PASS`. **Zero tested is not zero failed.**

### Known gap — the agent flags are not yet populated

`IsAgentIdentity`, `IsAgentClassified` and `SponsorId` are **read by script 03 and written by
nobody.** Script 01 does not set them, so every agent rule above is currently dead code — which is
why `SP_SECURED_AGENT` appears nowhere in the 24 October findings despite `jobs-alert-agent` being
exactly that.

**The real discriminators are now measured**: `@odata.type` is `#microsoft.graph.agentIdentity`
on a true agent identity and `#microsoft.graph.agentIdentityBlueprintPrincipal` on the blueprint,
and `agentIdentityBlueprintId` links the two. Both come from the default projection — no `$select`
interpretation required.

---

## 5. Deferred work

Two capabilities are designed but deliberately not built, because each depends on something the
current version does not establish. A third has since shipped.

| Capability | What it adds | Why it waits |
|---|---|---|
| **IaC provenance** (`UNMANAGED_IDENTITY`) | Flags identities that exist in the directory but in no Terraform state — created by hand, outside any review | Needs a trusted state file. Without one the finding is a guess, and a confident guess is this project's most expensive failure mode |
| **Remediation module** | Declares identities as code so there is an intended configuration to diverge from | Requires the provenance work above; remediation before discovery builds controls for identities you have not found |
| **Scheduled scanning** | Continuous rather than point-in-time assessment | **Shipped and running** — `.github/workflows/nhi-scan.yml`, authenticating through a GitHub OIDC federated credential with no stored secret |

**Why provenance matters more than it looks.** Terraform state is a *justification record*: the
repository is the owner, the commit is the reason, the pull request is the approval. It sources
the one registry attribute the directory has no field for — from outside the directory, for every
identity at once, as a by-product of how the identity was created.

**And why order is not arbitrary.** `terraform plan -detailed-exitcode` returns **2** for drift,
and **you cannot have drift without a declaration**. Continuous assessment of an undeclared estate
is monitoring noise; declaring an estate you have not finished enumerating is worse.

---

## 6. The documents, and what each is for

**The four-file standard**, and the reference material each one leans on.

| File | Purpose |
|---|---|
| `README.md` | What the tool is, what it found, what it cannot do |
| **`ARCHITECTURE.md`** | **This file** — the pipeline, the stage contracts, the data flow |
| `WALKTHROUGH.md` | What actually happened building and running it, including the wrong turns |
| `TROUBLESHOOTING.md` | One entry per incident, **written while it is still broken** |
| `docs/attestation-policy.md` | Cycle length, response types, **sponsor vs owner**, escalation |
| `docs/rotation-policy.md` | Intervals by credential type, agent TTL, blueprint credentials |
| `reference/GRAPH-PERMISSION-MODEL.md` | **Read before connecting.** The two locks, client vs API, where grants live |
| `reference/CONTROL-MAPPING.md` | Findings → published CCM v4.1.1 / AICM v1.1.1 control objectives |
| `reference/PIPELINE-IMPLEMENTATION.md` | GitHub Actions, the OIDC exchange, subject pinning |
| `samples/` | Sanitised output — what the tool produces, without a tenant |

---

## 7. Principles

1. **When this documentation and the tenant disagree, the tenant is right.** Several corrections
   here were caught by opening a portal blade, not by reading code.
2. **Never claim what a product you have not run cannot do.** Claim what you can demonstrate.
   *"An inventory built on this object class undercounts"* is demonstrable. *"Their console cannot
   see it"* is not.
3. **Every detection needs a test proving it can reach each outcome** — that it can fire *and*
   not-fire on demand. Five rules here shipped unable to produce their own findings.
4. **The auditor stays read-only.** Remediation runs under a human with PIM activation.
