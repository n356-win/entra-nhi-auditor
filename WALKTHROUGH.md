# Walkthrough — building and running this against a live tenant

**What actually happened, in order, including the parts that were wrong.**

`README.md` says what the tool does. `ARCHITECTURE.md` says how it is put together.
`TROUBLESHOOTING.md` is the incident log. **This file is the narrative** — how the findings were
reached, which conclusions were withdrawn, and why.

The single most useful thing in it: **five separate detections were written, shipped, and could
not produce their own findings.** None of them failed loudly. Finding that out is most of what
this project taught.

---

## Phase 0 — connect, and prove what you actually got

`00-Connect-Lab.ps1` requests three scopes and then **decodes the token to show which ones
arrived**. That verification is not decoration.

**First real failure.** Admin consent had been granted in the portal, and a test user was still
prompted for approval. The consent was on **Microsoft Graph**
(`00000003-0000-0000-c000-000000000000`) — the *resource*. The PowerShell SDK signs in as
**Microsoft Graph Command Line Tools** (`14d82eec-204b-4c2f-b7e8-296a70dab67e`) — the *client*.
Grants attach to the client's service principal, not the resource's, and both appear in
Enterprise applications with near-identical names.

*Being able to explain why there are two objects is worth more in an interview than the fix.*

---

## Phase 1 — inventory, and the first false positive

First run against the live tenant: **342 identities**. An Azure Automation Account came back
`NO_OWNER` / **High**, while the portal plainly showed an owner.

Both were right. There are **two unrelated ownership models**:

| | Where it lives | Visible to Graph? |
|---|---|---|
| Entra object owners | `/servicePrincipals/{id}/owners` | Yes |
| Azure RBAC | `Microsoft.Authorization/roleAssignments` | **No — different control plane** |

The portal owner was an RBAC assignment inherited from the subscription. A system-assigned managed
identity **cannot have Entra owners even in principle**.

**Why it mattered more than one row:** a mid-size Azure estate has hundreds of managed identities.
Unfixed, this tool would have reported every one as High severity unowned, and been wrong every
time. That is a report nobody reads twice.

Now `MI_OWNERSHIP_NOT_IN_GRAPH` (Info) — reporting the boundary instead of inventing a finding —
with `-IncludeAzureRbac` to answer the question properly using a separate ARM token.

---

## Phase 2 — the agent object model, and four wasted probe runs

The headline claim was *"this agent holds SharePoint and Mail MCP tools; Entra reports no
permissions at all."* Before publishing that, it needed testing. Four runs failed, each
differently, and the sequence is the lesson.

**Run 1 — a probe that could only confirm its own hypothesis.** `Invoke-MgGraphRequest` returns a
**Hashtable**, so `$obj.PSObject.Properties.Name` returned `Count, Keys, Values…` instead of the
JSON fields. The presence test **could never return true**. It reported *"exists, not populated"* —
agreeing with what I expected. *A check that cannot visibly fail will eventually report whatever
its defaults imply.*

**Runs 2 and 3 — guessing at object shape.** Two more wrong guesses, two more runs.

**Run 4 — the output contradicted itself, and that was the answer:**

```
read 'value' via PSObject.Properties
WARNING: 'value' is present in the key list but unreadable
```

Both true. **PowerShell unrolls collections on return**, so `return @()` hands the caller `$null`.
The field was read correctly every time and the empty array evaporated on the way out. The fix is
`return ,$val` — one character.

Then the comma created the *opposite* bug: `@($variable)` flattens one level, `@(command)` collects
a pipeline. A self-test now pins **0, 1 and 2** items — 1 especially, because 1 is also what a
wrapped array reports.

**What the probe finally established:**

- **The negative control killed the method.** `$select=zzzNotARealPropertyName9f3a` returned
  **200 OK** with the name silently dropped. Graph does not validate `$select` here, so
  *"accepted but not returned"* was never evidence of anything, and every earlier verdict was void.
- **The default projection is trustworthy** — whatever Graph returns unasked, exists.
  `GET /beta/servicePrincipals/{id}` on an Agent ID returns **61 fields** against a plain service
  principal's 50.
- `isEntraAgentId`, `agentSubjectParentId`, `agentCapabilities` **do not exist**. They came from
  reading beta `$metadata`, which catalogues every type Graph knows — not what an object returns.
  Both of script 01's primary discriminators were fictional.
- The real properties: `@odata.type`, **`agentIdentityBlueprintId`**, `agentAppId`, and four
  **lifecycle-policy compliance** fields including the auto-disable date.

---

## Phase 2b — the portal found what four instrumented runs missed

The Agents blade, with and without its filter:

| Filter | Count |
|---|---|
| `Uses agent identity: Yes` | **2** |
| *(none)* | **3** |

**Entra itself says `jobs-alert-agent` does not use an agent identity.** Every probe run had
targeted the one object guaranteed not to carry the property, and reported the absence as a
finding.

**Checking the portal against the API is the cheapest audit available.**

It also produced the finding the lab exists for: **two classes of agent with completely different
governance surfaces.** A true Agent ID carries a blueprint link and lifecycle compliance state. An
SP-secured agent carries **nothing** — no field matching `/agent/i` at all — and is identifiable
only by its tags. There is no tag called `agent`; the real vocabulary is `AgenticApp`,
`AIAgentBuilder`, `AgentCreatedBy:CopilotStudio` and `power-virtual-agents-<envGuid>`.

---

## Phase 3 — the fixture, and the rules that could not fire

Every tenant-owned identity reported `NO_OWNER`, so only one rule had ever executed.
`99-New-LabFixture.ps1` builds a deliberately imperfect distribution — 35% cleanly owned, 20%
owned by a **disabled** account, 15% by a group, 5% by a service principal, 15% unowned.

**It needs `Application.ReadWrite.All` — a permission this tool reports as Critical.** That is the
boundary made concrete: *the auditor stays read-only; remediation runs under a human with PIM
activation.*

**First write to a tenant: 403 on group creation**, which aborted the entire fixture before a
single owner was assigned. Two mistakes — a documented permission list that did not match the code
(`Group.ReadWrite.All` was missing), and **a 15% sub-step taking the other 85% down with it.** A
step serving one bucket must degrade to skipping that bucket.

Running it is what exposed the rest:

| Rule | Defect |
|---|---|
| `NO_SPONSOR` | **Could only fire.** Tested an always-`$null` field, so every agent got a Critical accusing Microsoft of a bypassed control — in a tenant where the portal showed the sponsor. |
| `ORPHANED_OWNER` | **Could never fire.** `accountEnabled` is not in the `/owners` response, and `$null -eq $false` is `False`. The Critical finding the docs call *"the one that lands hardest"* was unreachable code. |
| `NO_HUMAN_OWNER` | **Never written.** Named nine times in the fixture; two buckets existed to produce it; absent from script 03 entirely. |
| `NO_OWNER` on agents | **Fired falsely.** Read a relationship the portal populates and Graph does not return. |
| Attestation correlation | **Dead predicates.** Read `OwnerEnabled`/`OwnerType`, fields no record ever carried — so a service principal "approved" an access review. |

**All five tested fields nothing populated. Two produced false findings, three produced silence —
and silence is the one that survives review, because nobody investigates a finding that isn't
there.**

The rule this earned: **every detection needs a test proving it can reach each outcome.** Not that
it runs — that it can fire *and* not-fire on demand. The fixture is that test input.

---

## Phase 4 — attestation, and fabricated evidence

`svc-provisioning` is owned solely by the service principal `app1`. The cycle issued it a request and
recorded **"Approved."**

A service principal cannot approve anything. **That is fabricated control evidence** — generated
by a dice roll on behalf of an owner incapable of responding, and it is the single artifact an
auditor leans on hardest.

Now `No Response - Non-Human Owner`, a distinct status with its own summary row and an
**exhaustiveness assertion** that throws if any status lacks a bucket. The previous version
counted that status in `$total` and in no row, so the percentages silently did not sum to 100.

---

## Phase 5 — control mapping, and two stale-map incidents

The first report cited **`CSA AICM Agentic (draft)`** five times, directly under a line reading
*"No draft or proposed control identifiers are cited in this report."* `IAM-AG-01..04` and
`LOG-AG-01` do not exist in the published AICM v1.1.1 — a check of all 247 control IDs returns no
`-AG-` identifiers at all.

The map had been corrected **in the script**, inside `if (-not (Test-Path $ControlMapPath))` — so
it only wrote when the file was *absent*, and the file existed. Every run since had loaded the
stale copy.

**Fixed, then broken again the same way.** Regeneration on version mismatch only helps if the
version changes, and the version was a literal string I had to remember to bump. I did not.
`NO_HUMAN_OWNER` fired correctly and appeared under no control.

The version is now a **fingerprint of the map's own control IDs and finding codes**. Change what
is scored, and the version changes itself. *A hand-maintained version of machine-generated content
is a promise to remember something.*

---

## The day lost to a filename

Twelve correct pipeline runs, and every inspection read a snapshot from ten days earlier.

Before run compartmentalisation the scripts wrote `nhi_inventory.json` flat into `output/`. Those
files remained, never updated again, named **identically** to the real outputs now written under
`output/runs/<RunId>/`. The obvious file to open was the wrong one, and it looked completely
normal — not stale, not empty, just silently ten days old.

`Invoke-Pipeline.ps1` now **refuses to start** while those filenames exist at `output/` root, and
prints the full run-directory path on every completion line.

**A file that looks like current output and is not is worse than a missing file** — for the same
reason an empty collection is worse than an error. Nothing about it announces the problem.

---

## What a clean run looks like

```
AgentIdentities             2     matches the portal's "Uses agent identity" filter exactly
AGENT_SPONSORED             2     sponsors resolved via an undocumented endpoint
ORPHANED_OWNER              4     3 planted by the fixture + 1 genuine
NO_HUMAN_OWNER              1     a service principal owned only by another service principal
NO_APP_REGISTRATION_OWNER  14
InventoryAgeHours         0.0     the report is reporting on now
```

The fourth `ORPHANED_OWNER` is the one worth pointing at. Three were planted by the fixture; the
fourth was not planted at all: one of the scanner's own owners is **genuinely disabled**. The tool found a real
orphaned owner nobody had planted — which is the rule demonstrating it discriminates, rather than
merely that it fires.

---

## What I would tell someone starting this

**Instrument the instrument.** Every wrong answer here came from a check that could not fail
visibly: a probe confirming its own hypothesis, a rule testing an unpopulated field, a report
citing a map nobody reloaded. The code was never the hard part.

**A comment describing a guard is not a guard.** One rule asserted it was inert for days while
firing on every agent in the tenant.

**`NOT APPLICABLE` is the most dangerous string a control report can print.** It means "no
population found", and nothing in it separates *there was nothing to check* from *I failed to find
what was there*.

**Check the portal against the API.** It cost one screenshot and overturned four instrumented runs.
