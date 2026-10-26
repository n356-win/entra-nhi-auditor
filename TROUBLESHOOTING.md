# Troubleshooting

**One entry per incident. Written at the moment it happens, not afterwards.**

This is the file hiring managers actually read, because it is the one that cannot be faked. Anyone
can write a README. Only someone who ran the thing can write *"it returned 403 with consent
granted, and here is why."*

---

## The two rules

**1. Write it while it is broken.** Three days later it is fiction — you will remember the fix and
forget the symptom, and the symptom is the half that helps anyone else. Thirty seconds now beats a
paragraph of reconstruction later.

**2. Capture the evidence before you fix it.** The portal blade, the raw error, the field list —
two seconds now, impossible afterwards. Several entries below were only resolvable because the
original output was kept verbatim rather than paraphrased.

---

## The template

Copy this. Six lines. If it takes more than three minutes you are writing an essay.

```markdown
## YYYY-MM-DD — symptom in six words

**Symptom:** what you actually saw. Paste the real error text, not a paraphrase.
**Expected:** what should have happened instead.
**Cause:** the real one. If your first guess was wrong, say what it was — that is the useful part.
**Fix:** the exact command or change.
**At scale:** what this would look like in a client tenant with 400 identities.
```

The last line is what separates a lab note from a lab note worth reading: it turns a local
irritation into a statement about what the defect would cost in a real estate.

---

## Entries

### 2026-10-12 — admin consent granted, still prompting for approval

**Symptom:** `Connect-MgGraph` with the four lab scopes prompted *"Need admin approval"* for a test
user with no assigned role, after admin consent had already been granted in the portal.

**Expected:** no prompt. Tenant-wide admin consent should cover all users for those scopes.

**Cause:** consent had been granted on **Microsoft Graph** (`00000003-0000-0000-c000-000000000000`)
— which is the **resource**, the API being called. The Graph PowerShell SDK signs in as a different
app: **Microsoft Graph Command Line Tools** (`14d82eec-204b-4c2f-b7e8-296a70dab67e`). Grants attach
to the **client's** service principal, not the resource's. Both appear in Enterprise applications
with near-identical names, which is why this is easy to get wrong.

**Fix:** sign in as Global Admin with `Connect-MgGraph -Scopes <the four>` and tick *"Consent on
behalf of your organization"* on the consent screen. Grants tenant-wide consent for exactly those
scopes on exactly the right app, in one step. Verify at Enterprise applications → Microsoft Graph
Command Line Tools → Permissions.

**At scale:** in a client tenant this is the difference between "your tool needs admin approval
every time" and "approve it once." Knowing which object to point at saves a round trip with their
admin, and being able to explain *why* there are two objects is a credibility moment.

**Follow-on, not yet observed:** consent is only the first check. A user with no directory role
should still get **403** on `/auditLogs/*` — Microsoft documents Reports Reader, Security Reader or
Security Administrator for `directoryAudits`. **Confirm empirically and add an entry when it
happens.**

### 2026-10-26 — managed identity reported as NO_OWNER, portal shows an owner

**First real run of the tool against a live tenant.** Everything before this was unrun code.

**Symptom:** `nhi_findings.json` reported an Azure Automation Account service principal named
`automation-acct-01` (object `1a2b3c4d-0009-4000-8000-00000000a009`) as:

```json
"ObjectClass": "ServicePrincipal",
"Owner": null,
"TopSeverity": "High",
"Findings": [ { "Code": "NO_OWNER", "Detail": "No owner assigned. Nobody can attest to this identity." } ]
```

The Azure portal showed an Owner on that same resource. Object IDs matched exactly, so it was
definitely the same object.

**Expected:** either an owner reported, or an explanation of why there isn't one.

**First guess, wrong:** that `Get-MgServicePrincipalOwner` had failed silently or been
rate-limited. It had not — the call returned correctly. There genuinely are no Entra owners on
that object.

**Cause — two unrelated ownership models, and the tool reads one:**

| | Where it lives | Visible to Graph? |
|---|---|---|
| **Entra object owners** | `/servicePrincipals/{id}/owners` | **Yes** — this is what RULE 1 tests |
| **Azure RBAC** | `Microsoft.Authorization/roleAssignments` on the ARM resource | **No. Different control plane entirely.** |

The portal Owner was an **Azure RBAC role assignment, inherited from the subscription** — the
screenshot says *"Subscription (Inherited)"* in the Scope column. That is the ARM authorization
plane. Microsoft Graph does not expose it, so this script cannot see it and never will.

And worse: a **system-assigned managed identity cannot have Entra owners even in principle.** It is
created and destroyed with its parent Azure resource. There is no owner field to populate.
`NO_OWNER` was not an under-governed identity — it was a category error.

**Fix:** RULE 1 in `03-New-OwnershipMap.ps1` now branches on `IsManagedIdentity` and emits
`MI_OWNERSHIP_NOT_IN_GRAPH` (**Info**, not High) instead of `NO_OWNER`. It reports the boundary
rather than inventing a finding. `ORPHANED_OWNER` still fires if an owner somehow exists and is
disabled, because user-assigned managed identities are standalone resources and the model is less
absolute there. Also added a `Classification` field to the findings JSON — `ObjectClass` alone said
`ServicePrincipal`, which is true and useless.

**At scale:** this is the single most important false positive in the tool. A mid-size Azure estate
has *hundreds* of managed identities — every VM, Function App, Logic App and Automation Account
with system-assigned identity enabled. **Unfixed, this tool would have reported every one of them
as High severity unowned, and been wrong every time.** That is a report nobody reads twice, and it
is the same failure the Microsoft first-party exclusion was written to prevent.

**The general lesson, which generalises past this tool:** for managed identities, accountability
lives in **Azure RBAC on the parent resource**, not in Entra object owners. Any identity governance
tool that reads only Graph is structurally blind to it. **State that limitation in the README** —
and it is a good answer to "what can't your tool do?", which is a question worth being ready for.

### 2026-10-25 — a probe that could only ever return one answer

**Symptom:** `probe-agent-capability.ps1` reported `agentCapabilities` as *"accepted but not
returned → exists, not populated"* — conveniently confirming the hypothesis it was written to
test. The output also showed the application's properties as:

```
Count, IsFixedSize, IsReadOnly, IsSynchronized, Keys, SyncRoot, Values
```

and `Target: `` objectId ``` — both empty.

**Expected:** Graph field names like `id`, `appId`, `displayName`, `tags`.

**Cause:** **`Invoke-MgGraphRequest` returns a `Hashtable`, not a `PSCustomObject`.** So
`$obj.PSObject.Properties.Name` returned the .NET Hashtable's own members rather than the JSON
keys. The presence test was `$keys -contains 'agentCapabilities'`, which **could never be true**,
whatever Graph actually sent back.

The empty `id` then propagated into the next request as `$filter=appId eq ''`, which Graph
rejected — producing an error that looked like a finding about appId filtering and was nothing of
the sort.

**Fix:** `Get-Keys` / `Get-Field` helpers that handle `IDictionary` and `PSObject` alike, plus
`-OutputType PSObject` on every call. The probe now **prints the field list it is testing
against**, so the verdict can be checked rather than trusted, and **aborts loudly** if it cannot
read an `id` instead of carrying an empty value forward.

**At scale:** this is the dangerous class of bug. It did not crash, it did not warn, and it
returned a plausible answer that happened to agree with what I expected. **A probe whose default
behaviour is to confirm the hypothesis is not a probe.** Any check that cannot visibly fail will
eventually report whatever its defaults imply — and in an auditor-facing tool that is how a false
clean bill of health gets written.

**What survived from the bad run, and what did not:**

| Result | Status |
|---|---|
| `$select=agentCapabilities` returned **200, not 400** | **VALID.** Graph accepted the property name, so it exists on the `application` type. A non-existent property returns *"Could not find a property named"*. |
| "exists, not populated" | **INVALID.** Artefact of the bug. Unresolved. |
| `/beta/agentIdentities`, `/the control-mapping stage/agentIdentities`, `/beta/directory/agentIdentities`, `/beta/agentIdentityBlueprints`, `/beta/directory/agentIdentityBlueprints` all **400 "Resource not found for the segment"** | **VALID.** None of those paths exist. |
| `appId` filter unsupported | **INVALID.** It fired with an empty string. Retest. |

**The collection-path result matters on its own:** agent identities are **not separately
addressable** in Graph. They are service principals carrying agent properties — which means `02b`
must enumerate `servicePrincipals` and filter, not call an agent endpoint. That is a real
constraint on the design, and it is the one solid thing the bad run produced.

### 2026-10-25 — the probe contradicted itself in two consecutive lines, and that was the answer

**Fourth attempt at the same probe.** The previous three each failed differently and none of them
answered the `agentCapabilities` question.

**Symptom:** the console printed these three lines together:

```
    read 'value' via PSObject.Properties
    WARNING: 'value' is present in the key list but unreadable.
    Type: System.Management.Automation.PSCustomObject
  200 OK (2 fields)
  Unwrap failed. Falling back to raw JSON.
InvalidOperation: ...line 276 | $md.Add("Type: ``$($app.GetType().FullName)``")
     | You cannot call a method on a null-valued expression.
```

**Expected:** either the agent's application object, or a clean statement that none was found.

**The contradiction is the diagnosis.** `read 'value' via PSObject.Properties` and `'value' is
present but unreadable` cannot both be true — except they were, because they were measuring
different things. The property existed and was read. What came *back* from the function was null.

**Cause — PowerShell unrolls collections on return.**

```powershell
function f { return @() }
$x = f          # $x is $null, not @()
```

`Get-Field` read `value` correctly every time, got an **empty array**, and `return $val` enumerated
it into zero output objects. The caller assigned nothing and saw `$null`. So an empty collection —
an ordinary 200 meaning *your filter matched nothing* — was indistinguishable from *this field
cannot be read*.

Everything downstream followed from that one conflation:

| Step | What happened |
|---|---|
| `$val0` came back `$null` | ...so the response was treated as a **single entity** |
| `$obj = $r` | the **response envelope** became the "application" |
| `Get-Field -Obj $app -Name 'id'` | an envelope has no `id` → null |
| raw-JSON fallback | `@($parsed.value)[0]` on an empty array → `$null`, the same bug by another route |
| `$app.GetType()` in the abort block | crash — the diagnostic died at the one moment it was needed |

**Fix, four parts:**

1. **`return ,$val`** in `Get-Field`. The unary comma wraps the value so the unroll returns exactly
   what went in. One character, and it was the whole bug.
2. **Collection vs entity is decided by the presence of the `value` key**, never by whether
   something readable came out of it. Empty collections now print `0 item(s) matched` — a result,
   not a silent fall-through.
3. **A self-test** (`Test-GetFieldContract`) runs before any network call and asserts `Get-Field`
   round-trips an empty array, a 2-item array, a hashtable, and a genuinely absent field. The probe
   now fails on its own helper rather than on Graph's data.
4. **Null-guarded the abort block**, and **deleted the raw-JSON fallback** — it was built on the
   theory that `-OutputType PSObject` produced unreadable objects. That theory was wrong, and raw
   JSON reproduces the identical bug. *Consequence: the open question "should `02b` use
   `-OutputType Json` throughout?" is answered **no**. `PSObject` was never the problem.*

**The substantive finding, which is bigger than the bug:**

The filter `beta/applications?$filter=tags/any(t:t eq 'agent')` returned **200 with an empty
collection** — 2 fields, `@odata.context` and an empty `value`. Zero matches.

Script 01's comment claimed that filter was **"PROVEN — returned 200 with exactly 1 item."** That
claim is withdrawn, for two independent reasons:

- The "1 item" count was printed by probe code that had a **known object-shape bug at the time it
  printed it**. It is not usable evidence.
- **Object type mismatch**, which holds whatever the count was: the probe filtered
  `/applications`, while `01-Get-NHIInventory.ps1` reads `$sp.Tags` on a **service principal**.
  Different entities, independently populated tag collections. A result on one was never evidence
  about the other.

So the probe now opens with a **ground-truth step**: enumerate both collections, print every tag on
every tagged object, and report the distinct tag vocabulary — before selecting any target. It also
takes `-ApplicationObjectId` / `-ServicePrincipalObjectId` so the target can be pinned from the
portal instead of guessed by convention.

`agentCapabilities` remains **unanswered**. But the probe can now produce an answer that means
something, which is more than the previous three could.

**At scale:** this is the same failure class as the 2026-10-25 Hashtable entry above, and that is
the point. Both were readers that could not distinguish *absent* from *empty*, and both returned a
plausible answer instead of an error. In an auditor-facing tool that distinction **is** the product:
"this agent has no permissions" and "I could not read this agent's permissions" look identical in a
report and mean opposite things — one is a clean finding, the other is a blind spot being reported
as a clean finding. A control report that cannot tell them apart will eventually certify something
nobody looked at.

**The rule this adds:** *a helper that classifies evidence must be tested against its own edge
cases before it is pointed at real data.* The probe tests Graph; nothing was testing the probe.

#### Addendum, same day — the self-test failed on its first run, and it was right

```
  SELF-TEST FAILED - not proceeding to the network:
    - 2-item array did not round-trip
```

**The fix had introduced a second arity bug, and the test caught it before any network call.**
Which of the five cases passed is the diagnosis:

| Case | Capture idiom | Result |
|---|---|---|
| empty array | `$got = Get-Field …` then `@($got)` | **passed** |
| 2-item array | `@(Get-Field …)` directly | **failed** |

Same helper, same comma. The only variable was **how the result was captured** — and `Invoke-Probe`
used the failing idiom.

**Cause — `@($variable)` and `@(command)` are different operations:**

| Expression | What it does |
|---|---|
| `@($variable)` | casts a **value** to an array, flattening one level. 2 stays 2, empty stays 0. |
| `@(command)` | collects a **pipeline's** output objects. `return ,$val` emits the array as **one** object, so the count comes back **1** whatever is inside. |

So the comma that fixed the empty-array bug *created* this one. Without it an empty array vanished;
with it, a populated array arrives wrapped unless it lands in a variable first. **Same arity
confusion, opposite hat.** `$items[0]` would have handed back the entire array instead of the first
record — the envelope-as-entity bug again, one level down.

**Fix:** every call site assigns before wrapping (`$rawValue = Get-Field …; $items = @($rawValue)`),
in `Invoke-Probe` and at both `Show-Tags` call sites. The capture rule is written out in full at the
top of `Test-GetFieldContract`, and cases now pin **0, 1 and 2** items — 1 especially, because 1 is
also what a wrapped array reports, so that is where a capture bug hides best.

**`Get-Keys` deliberately does NOT use the comma** and must stay that way: it is read via
`(Get-Keys -Obj $r) -contains 'value'`, the single test that decides collection-vs-entity. Add a
comma there and `-contains` is **always false**, every response classifies as a single entity, and
the original bug returns wholesale. Four `Get-Keys` cases now pin that asymmetry against a future
tidy-up that "makes the helpers consistent" — 9 assertions in total.

**At scale:** worth noticing that this bug class has now produced **four** different wrong answers
from the same script — absent-vs-empty twice, and arity twice — and not one of them crashed on the
line that was wrong. The self-test cost about twenty lines and caught the fourth one in under a
second, before it could touch tenant data and produce a fifth plausible-looking report. **That is
the argument for testing the instrument, not just the subject**, and it is the honest answer to
"how do you know your tool is right?" — *because it refuses to run when it isn't.*

### 2026-10-25 — there is no tag called `agent`, and finding that out exposed two worse bugs

**The ground-truth step worked on its first run.** Three findings, in increasing order of
seriousness.

#### 1. The real agent tag vocabulary

`tags -contains 'agent'` matched **0 of 17** applications. The agent is tagged — with four tags,
none of them `agent`:

| Tag | What it is |
|---|---|
| `AgenticApp` | platform marker: this is an agent |
| `AIAgentBuilder` | platform marker: built by an agent builder |
| `AgentCreatedBy:CopilotStudio` | **provenance** — which builder created it |
| `power-virtual-agents-1a2b3c4d-…` | the **Power Platform environment** it belongs to |

**The real vocabulary is better than the one I assumed.** `agent` would have been a bare boolean.
These carry the **builder** and the **environment** — provenance and blast radius — and neither is
exposed on any documented Graph property. `AgentBuilder` and `AgentEnvironmentId` are now extracted
into the inventory record, which gives the attestation record two facts it could not otherwise get.

*Scope of the evidence: one agent, one builder, one tenant.* Matched as a **family**, with the
matching tags recorded in `AgentTagsMatched`, so the next agent either confirms the pattern or
extends it — and the inventory says which.

#### 2. `$top=999` returned 100 objects

The service-principal table reported *"100 total"*. That is **Graph's page size, not the tenant's
count** — the listing stops at object id `47…` and `@odata.nextLink` was never followed. So
*"0 service principals carry tag X"* was only ever true of the first hundred objects.

**Fixed** with a proper `@odata.nextLink` loop and a 50-page guard. **An inventory tool that
silently reads one page is worse than one that refuses to run:** it reports a clean result for data
it never looked at, and nothing in the output says so.

#### 3. The worst one — the agent was tagged on the APPLICATION, and only service principals were classified

Agent classification (`IsAgentClassified`, `AgentDetectionMethod`) was computed **only in the
service-principal branch** of `01-Get-NHIInventory.ps1`. The application record had no agent fields
at all. But the lab's only agent carries its tags on the **application** object
(`jobs-alert-agent`, `1a2b3c4d-0004-4000-8000-00000000a004`) and on **no** service principal in the
paged enumeration.

Script 05 scopes the agentic controls with `Select-ForControl` on `IsAgentClassified`. **A record
missing that property is never selected.** So `IAM-18` and `IAM-16` would have reported an **empty
agent population → NOT APPLICABLE** in a tenant that demonstrably contains an agent.

**The headline finding of this entire lab, scoped out of its own control report by a missing
field — and the report would have looked clean.**

**Fix:** the application record now carries the same agent shape as the service-principal record
(`Tags`, `AgentTagsMatched`, `AgentDetectionMethod`, `AgentBuilder`, `AgentEnvironmentId`,
`IsAgentClassified`), so every downstream filter works across both object classes without
special-casing. `IsAgentIdentity` and `BlueprintParentId` are hard-`$null`/`$false` there, because
they are service-principal properties and pretending otherwise would be the opposite error.

**At scale, and this is the one to remember:** all three bugs produced *clean-looking output*. A
missing tag matched nothing, a truncated page reported a total, and a missing property scoped a
control to zero. **`NOT APPLICABLE` is the most dangerous string a control report can print** — it
means "no population found", and nothing in it distinguishes *there is nothing to check* from *I
failed to find what was there*. Any control framework that lets a scoping bug render as compliance
will eventually certify an estate nobody enumerated. **Scope emptiness must be evidenced, not
assumed:** when a population comes back empty, the report has to say what it searched and how, so
an auditor can tell which of the two happened.

### 2026-10-25 — the probe answered its question, and the answer is void: no negative control

**Symptom:** the pinned run returned a clean, confident verdict:

```
agentCapabilities    on APPLICATION       → 200, accepted but not returned → "exists, not populated"
agentCapabilities    on SERVICE PRINCIPAL → 200, accepted but not returned → "exists, not populated"
isEntraAgentId       on SERVICE PRINCIPAL → 200, accepted but not returned → "exists, not populated"
agentSubjectParentId on SERVICE PRINCIPAL → 200, accepted but not returned → "exists, not populated"
agentSubjectType     on SERVICE PRINCIPAL → 200, accepted but not returned → "exists, not populated"
agentIdentityType    on SERVICE PRINCIPAL → 200, accepted but not returned → "exists, not populated"
```

**Expected:** a mix. Some properties present, some absent, some 400.

**Why six identical verdicts is the tell.** That would mean all five agent properties exist and
all five are null — on an object that demonstrably *is* an agent. `isEntraAgentId` in particular:
either it is `true` here, or this is not an Agent ID and the property should be `false`, not absent.

**Cause: the script's entire interpretive frame was an untested premise.** It reads

| Response | Claimed meaning |
|---|---|
| 400 "Could not find a property named X" | X does not exist on the type |
| 200, X not in the response | X **exists** and is null |

That second row was never verified. If Graph **silently ignores unknown `$select` names** on this
endpoint, then "accepted but not returned" is what *every* name produces — real or invented — and
all six verdicts are void, including the one the script exists to produce.

**This is the same error as the "PROVEN" tag claim, in the same script:** a foundational premise
asserted instead of measured, with every later conclusion resting on it.

**Fix — a negative control, running FIRST:** `$select=id,zzzNotARealPropertyName9f3a`.

- **400** → Graph validates `$select`; "accepted but not returned" is real evidence.
- **200** → Graph ignores unknown names; the frame is dead and the report says so in place of its
  own conclusion.

The probe now prints that verdict before any property probe and marks the whole section VOID if the
control comes back 200.

#### The route that needs no interpretation at all

The run also dumped the application's **default projection** — all 50 fields an unfiltered `GET`
returns. That list is trustworthy by construction: whatever Graph returns unasked exists and is
readable, no `$select` semantics involved.

`agentCapabilities` is **not in it**. But **`appCapabilities` is.**

So `appCapabilities` is better evidence than anything `$select` can offer, and it is now probed
without `$select`. The same default-projection dump plus an `/agent/i` field sweep was added on the
**service principal**, which had never been recorded and is the object that actually holds
permissions. If nothing agent-shaped appears there either, that is the strongest available form of
the headline: *the agent is identifiable in this tenant only by its tags, and no agent-specific
property is readable on it at all* — a claim that survives whatever `$select` turns out to do.

#### Two side findings from the same run

**Paging fix confirmed.** Service principals went **100 → 325** across 4 pages, tagged objects
**52 → 186**. The agent's service principal (`1a2b3c4d-…`) sits past the first page — so the earlier
"0 service principals carry the agent tag" was purely the truncation artifact, now proven rather
than suspected.

**`AgenticInstance`: a definition/instance split, found by comparing objects rather than reading
docs.**

| Object | Tags |
|---|---|
| application `1a2b3c4d-…` | `AgenticApp`, `AIAgentBuilder`, `AgentCreatedBy:CopilotStudio`, `power-virtual-agents-…` |
| servicePrincipal `1a2b3c4d-…` | `AgenticApp`, **`AgenticInstance`**, `AIAgentBuilder`, `AgentCreatedBy:CopilotStudio`, `power-virtual-agents-…` |

Same name, same builder, same environment. The only difference is `AgenticInstance` on the service
principal. **The application is the agent's definition; the service principal is its instance** —
the blueprint/agent-identity shape, expressed in tags instead of properties.

**This has a direct control-report consequence, and it is probably the 28-rows-for-15-identities
duplication:** one agent appears **twice**, as two object classes. A naive agent count
double-counts it, and worse, the two are not interchangeable — only the Instance can hold
permissions or sign in. A control about what an agent can *reach* must be scored against the
service principal; a control about how it was *defined* belongs to the application. Scoring both
identically reports every agent finding twice and attributes half of them to an object that cannot
have the problem. Recorded as `AgentObjectRole` (`Instance` / `Definition`) on both records rather
than acted on silently, because this is one agent from one builder — a pattern, not yet a rule.

**At scale:** every probe needs a negative control, and the cost of omitting one is not a wrong
answer — it is a *confident* wrong answer that agrees with the hypothesis. This script has now
produced five of those. The pattern across all five is identical: **an untested premise at the
foundation, and a verdict that reads as a finding.** A tool that will be shown to an auditor needs
to state what it assumed, not just what it concluded.

### 2026-10-25 — four runs probed the one object guaranteed not to have the property

**The portal found this, not the script.** Agents | Agent identities, with and without its filter:

| Filter | Count | Objects |
|---|---|---|
| `Uses agent identity: Yes` | **2** | Root-agents `1a2b3c4d-…`, MSTeams-Agent `1a2b3c4d-…` |
| *(none)* | **3** | those two **+ jobs-alert-agent `1a2b3c4d-…`** |

**Entra itself classifies `jobs-alert-agent` as not using an agent identity.** It is the
documented service-principal fallback.

#### Consequence 1 — a non-finding reported as a finding

Every probe run so far targeted `jobs-alert-agent`, and reported `isEntraAgentId` as *"exists, not
populated"*. That property was never going to be there. **Wrong object.** The absence is correct
and expected, and reporting it as a result was a category error on top of the untested-`$select`
problem — the two compounded, and the output looked like a finding either way.

It also means the tag family is the **only** route to classifying this agent, which raises the
value of the `AgenticApp` / `AgenticInstance` / `AgentCreatedBy:` vocabulary considerably: for an
SP-secured agent, tags are not weak evidence, they are the **only** evidence.

#### Consequence 2 — the one that matters: a possible agent undercount

`Root-agents` and `MSTeams-Agent` appeared in **neither** the 17 applications **nor** the 325
service principals the probe enumerated — and that enumeration is now properly paged, so
truncation is ruled out.

`01-Get-NHIInventory.ps1` reads applications, servicePrincipals and managed identities. **If true
agent identities are not addressable as service principals, this script cannot see them at all** —
it would report 1 agent in a tenant containing 3, and the control report would inherit that
silently, scoring IAM-18 against a third of the population while printing nothing about the rest.

That is the undercount argument pointing the **other** way. Both can be true at once:

| View | Blind to |
|---|---|
| Agent-ID inventory | app-registration agents (the original claim) |
| application/servicePrincipal inventory | true Agent IDs (this one) |

**If both hold, neither view alone is a complete agent inventory** — which is a stronger and far
more useful finding than either in isolation, and it is demonstrable rather than asserted.

**Not acted on yet, deliberately.** The enumeration stays as it is until measured. The probe now
takes `-AgentIdentityObjectId`, resolves each id through `/beta/directoryObjects/{id}` for its
`@odata.type`, and reports whether `/beta/servicePrincipals/{id}` reaches it. It also dumps the
default projection and every `/agent/i` field — so if a true Agent ID *does* carry
`agentCapabilities`, it will be read **without `$select`**, which sidesteps the negative-control
problem entirely.

**At scale:** this is the fifth bug in this script with an identical shape — *an untested premise
about what is being measured.* Not a coding error. Each time, the instrument worked and was aimed
at the wrong thing, and the output was confident regardless. **The portal disagreeing with the tool
is the cheapest audit available**, and it found in one screenshot what four instrumented runs
missed. Check the UI against the API before trusting either.

### 2026-10-25 — the negative control fired, and the real property names were nothing like the guesses

**The control, one request, decisive:**

```
$select=id,zzzNotARealPropertyName9f3a  ->  200 OK
Fields returned: @odata.context, id
```

**Graph does not validate `$select` on these endpoints.** A property name that cannot exist was
accepted and silently dropped — identically to all six agent properties. So *"200, accepted but not
returned"* was never evidence of anything, and every verdict built on it is **void**, including the
one this script was written to produce. The suspicion is now measured fact.

#### The real properties, from the default projection

`GET /beta/servicePrincipals/1a2b3c4d-…` with no `$select` returns **61 fields** and
`@odata.type = #microsoft.graph.agentIdentity`. A plain service principal returns 50. The 11-field
delta is the answer four runs were reaching for — and every one of them is readable **without
`$select`**, so none of it needs interpreting:

| Property | What it gives you |
|---|---|
| `@odata.type` | `#microsoft.graph.agentIdentity` — **the** discriminator |
| `agentIdentityBlueprintId` | the blueprint link (what I called `agentSubjectParentId`) |
| `agentAppId` | the agent's app id |
| `instanceMode` | |
| `clientIdMetadataDocumentUrl`, `hasClientIdMetadataDocument` | client-id metadata document |
| `lifecyclePolicyComplianceState` | **compliance with a lifecycle policy** |
| `lifecyclePolicyComplianceStateReason` | why |
| `lifecyclePolicyComplianceStateLastModifiedDateTime` | when it last changed |
| `lifecyclePolicyNonComplianceDisablementDateTime` | **when it gets auto-disabled for non-compliance** |

**`isEntraAgentId`, `agentSubjectParentId`, `agentSubjectType`, `agentIdentityType` and
`agentCapabilities` do not exist.** They came from reading beta `$metadata` — which catalogues every
type Graph knows, not what an object returns — and were "confirmed" by the `$select` probe that the
control has now invalidated. Script 01's two primary discriminators were **both fictional**.

The lifecycle four are the find. Entra maintains an agent's policy-compliance state *and its
auto-disable date* as first-class readable properties: **attestation evidence supplied by the
platform**, which nothing in this lab now has to infer.

**Measured in the lab tenant:** both agents return
`agentAppId = agentIdentityBlueprintId = 1a2b3c4d-0005-4000-8000-00000000a005`. One blueprint, two
agents — matching the portal exactly, and confirming that **blueprint count is the security
boundary**: the blueprint holds credentials, the agents hold none.

#### My own bug, in the same output

The script printed *"NOT a service principal … cannot see this object at all"* and, two lines later,
*"Reachable via /beta/servicePrincipals/{id}: **YES** (61 fields)"* — for the same object. I tested
`@odata.type -notmatch 'servicePrincipal'` and read invisibility out of a **string mismatch**.
`agentIdentity` is a *subtype* of servicePrincipal, so it is addressable there despite the name.

Same error shape as everything else here: a verdict inferred from something that was never asked.
The block now reports the type and tests the real question — **collection membership**, since
script 01 builds its inventory by *enumerating* `/servicePrincipals`, not by fetching ids.

#### The split that is actually the headline

| Agent class | Readable governance surface |
|---|---|
| true `agentIdentity` | typed object, blueprint link, **lifecycle compliance state** |
| SP-secured (`jobs-alert-agent`) | **nothing.** 50-field plain SP, no field matching `/agent/i` |

Two classes of agent in one tenant with completely different evidence available. For the SP-secured
class the tag family is not a weak last-resort signal — **it is the only signal there is.** An
auditor asking *"show me every agent and its lifecycle compliance"* gets a real answer for two of
three agents and silence for the third.

`appCapabilities` was probed too: **present but empty.** A real, readable field with nothing in it.

#### A second live bug, found while verifying the fix

Script 05 decided agent-ness from `Classification -eq 'Agent'` — but script 03 writes
`Classification` as `ManagedIdentity` / `TenantOwned` / `External` and **never** `'Agent'`. Dead
branch. Agent-ness therefore collapsed to *"has an agent finding"*, which fails in the worst
direction: **a correctly governed agent has no agent findings**, so it was not counted as an agent,
`$agentCount` came out `0`, `populationEmpty` fired, and `IAM-18` / `IAM-16` printed **NOT
APPLICABLE**. *The better the tenant, the more likely the agent controls silently scoped themselves
to nothing and reported it as a result.*

**Fixed along the whole chain:** 01 writes `AgentClass`, 03 carries `IsAgent` + `AgentClass` through
to the findings file, 05 reads them instead of inferring. Population membership is a property of the
**identity**, never of its findings. Older findings files fall back to the old inference and the
report now says so in a header note rather than presenting the count as authoritative.

**At scale:** the pattern across all of today's bugs is one thing — *a verdict read out of something
that was never measured*. `$metadata` treated as a statement about objects; a 200 treated as proof a
property exists; a type name treated as a reachability claim; the absence of findings treated as the
absence of a population. None crashed. All produced confident output. **The negative control is the
cheapest defence against the entire class**, and it cost one request.

### 2026-10-25 — a Critical finding that could not fail to fire, accusing Microsoft

**Symptom:** the three most serious findings in the report were

```
1. Root-agents   1a2b3c4d  - Agent identity with no sponsor ... something bypassed the control path.
2. MSTeams-Agent 1a2b3c4d  - Agent identity with no sponsor ... something bypassed the control path.
3. Root-agents   1a2b3c4d  - Agent identity with no sponsor ... something bypassed the control path.
```

**Expected:** nothing. The portal's **Owners and sponsors** blade for Root-agents lists the same
user **twice** — once as `Full owner`, once as `Sponsor`. Every agent was correctly sponsored.

**Cause — a guard that was described but never written.** RULE 1b carried this comment:

> *PROPERTY NAME NOT YET VERIFIED … Until it does, this rule is inert … it runs only when the
> inventory actually carries the field, so it cannot fire wrongly on data that does not have it.*

It did not check that. It checked `if (-not $id.SponsorId)` — against a `SponsorId` that script 01
hardcoded to `$null` with the note *"Null is honest; a guess is not."* The note was right; the
consequence was not. `-not $null` is always true, so **`NO_SPONSOR` fired at Critical on every
agent identity in every run that ever executed.**

**Why this is the worst of the lab's bugs so far.** The others produced wrong numbers. This one
produced a *confident accusation about someone else's product* — "Microsoft makes sponsorship
mandatory at creation, so this should not be possible — something bypassed the control path" — at
the top of an auditor-facing report, about a correctly configured tenant. Anyone who checked the
portal would have found the sponsor in about five seconds, and the tool's credibility with it.

**Fix, in three parts:**

1. `Get-SponsorSummary` in script 01 actually resolves sponsors, trying candidate endpoints in
   order and **recording which one answered** in `SponsorLookupMethod`. Nothing is invented: if
   every candidate fails, the result is UNRESOLVED.
2. `SponsorLookupPerformed` separates *"asked and the answer was none"* from *"could not ask"*.
   RULE 1b keys off that flag, so the rule is now genuinely inert when sponsorship is unreadable.
3. Three outcomes replace one: `AGENT_SPONSORED` (Info, names the accountable human),
   `NO_SPONSOR` (Critical, **only** on a confirmed zero), `SPONSOR_NOT_ASSESSED` (Info, unreadable).

**Two lessons, and the second generalises past this lab:**

- **A comment describing a guard is not a guard.** This one asserted inertness for days.
- **"Field is falsy" and "field was never populated" are different states.** Collapsing them is the
  same defect as the capability probe that could only confirm its own hypothesis — a check with no
  path to the negative result. The difference is direction: that one fooled me, this one would have
  misled a reader about a vendor.

**At scale:** a finding that cannot fail to fire is indistinguishable from a working detection until
someone checks the ground truth, and **the more severe the finding, the less likely anyone checks**
— Critical gets escalated, not verified. Any rule emitting Critical needs a test that proves it can
also emit nothing, and the positive-result finding (`AGENT_SPONSORED`) is what makes that visible on
every run: if the report never says an agent *is* sponsored, the rule is not discriminating.

---

### 2026-10-25 — UNMAPPED-01 resolved: there is no control, and that is the finding

`AGENT_FACTORY_CAPACITY` and `DELEGATION_ESCALATION` had no published control mapping, with four
documents on disk unread. All four have now been read. **No published control objective covers
either**, and that is a result rather than an outstanding task.

| Source | What it actually contains |
|---|---|
| **NIST NCCoE** concept paper (11pp) | An **agenda, not a catalogue.** Verbatim, p5: *"How do we handle delegation of authority for 'on behalf of' scenarios?"* and *"How do we establish 'least privilege' for an agent, especially when its required actions might not be fully predictable when deployed?"* |
| **SP 800-207** (Zero Trust) | **Principles, not controls.** Tenet 3 (per-session access) and Tenet 6 (*"all resource authentication and authorization are dynamic and strictly enforced before access is allowed"*) are both in tension with a standing inherited blueprint grant — but a tenet is architectural, not auditable. |
| **SP 800-63-4** | Identity **proofing and authentication assurance**. Governs how strongly an identity is established, not what a verified identity may delegate afterwards. Out of scope. |
| **CCM v4.1.1 / AICM v1.1.1** | 247 controls, none for blueprint-to-agent permission inheritance. |

**So `DELEGATION_ESCALATION` detects a condition NIST has publicly listed as an open question.**
That is a stronger position than a mapping would be: the tool is not failing to find a control, it
is producing evidence for a gap the standards bodies have stated they have not closed. Quote the
NCCoE question verbatim and report the finding on its own terms.

`AGENT_FACTORY_CAPACITY` — one blueprint able to mint up to 250 agent identities, all inheriting its
grants — has no analogue in any of the four. It is a platform-specific concentration risk the
published frameworks predate.

**Citing SP 800-207's tenets as though a tenant could PASS or FAIL them would be the same overreach
as the retired `IAM-AG-*` identifiers.** They are referenced as rationale in the control map and
never as control ids.

### 2026-10-25 — first write to a tenant: 403 on group creation took the whole fixture down

**The first time anything in this repository wrote to a directory.** Every other script reads.

**Symptom:** `-WhatIf` planned 19 targets across all six buckets perfectly. `-Confirm` then died
on the first real call:

```
New-MgGroup_CreateExpanded: Insufficient privileges to complete the operation.
Status: 403 (Forbidden) ErrorCode: Authorization_RequestDenied
=> 0 owner assignment(s), 0 created user(s)
```

**Expected:** owners assigned to 17 of 19 identities. The group is needed by one bucket.

**Cause 1 — a documented permission list that did not match the code.** The NOTES block names
the scopes this script needs. Group creation was added without adding `Group.ReadWrite.All` to it,
and `Directory.ReadWrite.All` does not reliably cover creating groups. The list was wrong, so the
PIM activation it told you to do was also wrong.

**Cause 2, and the one worth keeping — a 15% sub-step aborted the other 85%.** The call ran with
`-ErrorAction Stop` under a script-wide `$ErrorActionPreference = 'Stop'`, so one optional bucket's
failure ended the run before a single owner was assigned. **A step that serves one bucket must
degrade to skipping that bucket.** Same necessary-versus-sufficient distinction the control map
already makes about testability — applied to execution instead of evidence.

**Fix:** group creation is now wrapped, and on failure warns, names the missing scope, explains
the consequence (*those identities report `NO_OWNER` instead of `NO_HUMAN_OWNER`*), and lets the
other five buckets build. `Group.ReadWrite.All` is documented as **optional**, with
`-GroupOwnerId <existing group>` as the way to exercise the bucket without it.

**Two more things the dry run exposed, both caught before they wrote anything:**

| Problem | Fix |
|---|---|
| `"aad-extensions-app. Do not modify. Used by AAD for storing user data."` was selected as a target. It is tenant-owned so it passed every filter — and Microsoft put the warning *in the display name*. | Name-pattern exclusions. "Probably harmless" is not the standard for the one script that writes, and modifying an object labelled DO NOT MODIFY is indefensible in review whatever the outcome. |
| `Root-agents` appeared in **both** the ActiveOwner and GroupOwner buckets, reading as a duplicate assignment. | It was not one — three distinct objects share that display name. Console output now prints an 8-char object id. **In Entra, DisplayName is not an identifier** — third time that has bitten this project. |

**At scale:** the write path is where a governance tool stops being an observer. Everything else
here fails safe by construction — a read that 403s returns nothing and the report says so. A write
that 403s halfway through leaves a tenant in a state neither the tool nor the operator planned,
which is why the manifest is flushed after every single change rather than at the end. **This run
proved that design: nothing was written, so nothing needed reverting — and had the group succeeded
and an owner assignment failed, the manifest would already have held the completed ones.**

### 2026-10-25 — agent identities refuse owner writes that every other service principal accepts

**This one is a finding, not a defect.** It is the cleanest controlled result the lab has produced.

**Symptom:** mid-fixture, with one token and one loop:

```
    + <active owner>                              <- every ordinary service principal
  Root-agents  [253cd2ad]
  WARNING:  FAILED on Root-agents: [Authorization_RequestDenied]
            Insufficient privileges to complete the operation.
```

**The control is as tight as it gets.** Same session, same `Application.ReadWrite.All`, same
`New-MgServicePrincipalOwnerByRef`, same loop iteration structure, consecutive calls. **The only
variable is the object class.** Ordinary service principals accepted the write; agent identities
refused it. Confirmed across the run — every non-agent target succeeded.

**So `agentIdentity` sits behind a separate authorization boundary for ownership writes, and
`Application.ReadWrite.All` does not cross it.** An agent identity is an OData *subtype* of
servicePrincipal — readable at `/servicePrincipals/{id}`, returned by the collection, carrying all
50 base properties — and yet not writable the same way. **Subtype for reads, distinct object for
writes.**

#### The corollary, which is more serious than the write failure

The fixture checks existing owners before assigning, and skips when one is present. The portal
shows `Root-agents` with a **Full owner** *and* a **Sponsor**. **It did not skip.** So
`/servicePrincipals/{id}/owners` does not return what the Agents blade displays.

That means `OwnerCount == 0` on an agent identity means **"not readable by this route"**, not
**"unowned"** — and emitting `NO_OWNER` at **High** on it would be the `NO_SPONSOR` bug a second
time, in the same week: a severe finding firing on correctly-governed objects because the tool is
reading the wrong relationship.

**Fix:** `AGENT_OWNER_NOT_IN_SP_OWNERS` (Info), phrased as a gap in the tool. `NO_OWNER` at High is
now reserved for objects where zero genuinely means zero. Agent identities are also excluded from
fixture targeting — they are platform-owned and platform-sponsored at creation, so the fixture adds
nothing and generates one guaranteed failure per agent per run.

**Three Entra relationships now confirmed invisible to the obvious Graph route:**

| Relationship | Visible in portal | Returned by the obvious Graph call |
|---|---|---|
| Managed identity accountability | Yes (Azure RBAC) | No — different control plane entirely |
| Agent **sponsor** | Yes | No |
| Agent **owner** | Yes | No |

**At scale, and this is the thesis:** *a governance tool that reads only `/servicePrincipals` is
structurally blind to how agents are actually governed.* Not incomplete — **blind**, and silently,
because every one of those gaps returns an empty collection rather than an error. An empty
collection renders as a clean row. **Three separate accountability relationships in one tenant, all
populated in the portal, all absent from the API surface the entire NHI tooling category is built
on.** That is the finding worth publishing, and it is now demonstrated three independent ways
rather than argued once.

### 2026-10-25 — ORPHANED_OWNER could never fire. The Critical finding was unreachable code.

**Symptom:** after the fixture assigned owners — confirmed in the portal, two active users on
`app1` and the departed user on `autowayne` — the ownership CSV still reported no owners, and no
`ORPHANED_OWNER` appeared anywhere.

**Two separate causes, and the second is far worse than the first.**

#### 1. The inventory was stale (the boring one)

`nhi_inventory.json` carried `GeneratedUtc: 2026-10-25T06:41:43Z`; the fixture wrote owners at
~23:04. Everything downstream — CSV, findings, control report, attestation — derived from that one
file, so every artifact described the tenant as it was seventeen hours earlier.

`01` is the only script that talks to the tenant. **Nothing downstream can be fresher than the
inventory it reads**, and none of the outputs said how old their input was. Re-running `01` fixes
the data; the reporting gap is addressed separately.

#### 2. `accountEnabled` is not in the /owners response — so ORPHANED_OWNER was dead code

The inventory records that *did* have owners looked like this:

```json
{ "DisplayName": "<an active user>", "UserPrincipalName": "...", "AccountEnabled": null }
```

**That account is enabled and was signed into the portal at the time.** Graph's owners navigation
returns a reduced `directoryObject` projection that does not include `accountEnabled`, so
`$props['accountEnabled']` was `$null` on **every owner of every identity, always.**

Rule 1 in script 03 tests:

```powershell
if ($o.AccountEnabled -eq $false) { $orphaned = $true }
```

**`$null -eq $false` is `False` in PowerShell.** So `$orphaned` was never set, and
`ORPHANED_OWNER` — the Critical finding this tool's own documentation calls *"the one that lands
hardest in a conversation"* — **could not be produced by any input whatsoever.** The entire
`DepartedOwner` bucket of the lab fixture, 20% of the distribution, existed to feed a rule with no
reachable output.

**Fix:** `Get-OwnerSummary` resolves each owner's `accountEnabled` with a targeted lookup, **cached
by owner id** — a handful of owners covers a whole estate, so this is 3 calls in the lab, not 16.
Owners now carry `EnabledResolved`, and script 03 emits `OWNER_STATE_UNRESOLVED` (Info) when the
state is unknown, because **an owner whose state could not be determined must not be counted as a
governed one.** Groups legitimately have no `accountEnabled` and are marked resolved at source.

#### Three rules, one defect, one week

| Rule | Defect |
|---|---|
| `NO_SPONSOR` | could **only** fire — tested an always-null field, accused Microsoft on every agent |
| `NO_OWNER` on agents | fired **falsely** — read a relationship the portal populates and Graph does not return |
| `ORPHANED_OWNER` | could **never** fire — tested a field the API never returns |

**All three were rules whose input was never populated. None of them failed loudly.** Two produced
false findings and one produced silence, and silence is the one that survives review — nobody
investigates a finding that isn't there.

**At scale, and this is the rule to carry forward:** *every detection needs a test that proves it
can reach each of its outcomes.* Not that it runs — that it can **fire** and can **not-fire** on
demand. A rule that has never once produced its finding against known-bad input is indistinguishable
from a rule that is working perfectly in a healthy tenant, and the lab fixture exists precisely to
supply that known-bad input. It found this by being run, which is the entire argument for running it.

<!-- new entries below -->
