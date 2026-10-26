# Attestation policy

**Version 0.1 — draft. Lab document.**
Referenced by `04-Invoke-AttestationCycle.ps1` and by every report it generates.

> **Defaults, not decisions.** Every number below is a starting position chosen for a reason that
> is stated. Argue with them. A policy you disagreed with and changed is a policy you will follow;
> one you inherited is one you will ignore.

---

## 1. Scope

Every **tenant-owned non-human identity** in the Entra tenant: application registrations, service
principals, managed identities, agent identities, and agents secured by application service
principals.

**Out of scope:** Microsoft first-party and third-party SaaS service principals. They have no
tenant owner by design, and attesting to them would generate a hundred-plus false findings and
train everyone to ignore the report.

**Out of scope by construction, and stated so nobody assumes otherwise:** anything with no Entra
registration. API keys in configuration files, MCP server endpoints, agents running outside the
tenant. **This policy cannot see them.** Closing that gap is a different piece of work and is not
pretended at here.

---

## 2. Cycle length — 90 days

**Default: quarterly.** Reasoning:

- Short enough that a stale entitlement is caught within one quarter
- Long enough that owners do not start rubber-stamping, which is the real failure mode of access
  review and is worse than no review at all
- Aligns to the quarter boundary auditors already ask about

**Tighten to 30 days** for identities holding escalation permissions
(`EXCESSIVE_SCOPE_ESCALATION`). An identity that can become Global Administrator should not go
three months without someone confirming it is still needed.

**Do not loosen past 90 days.** At six months the owner has forgotten what they approved last time
and the review becomes theatre.

---

## 3. The three response types

| Response | Meaning | Action |
|---|---|---|
| **Approved** | The owner confirms the identity is still required and the access is still appropriate | None. Record and close. |
| **Rejected** | The owner confirms it is no longer needed | Queue for removal in the next maintenance window |
| **No Response** | The owner did not reply by the due date | **Escalate — see §4** |

### The design decision, stated once and kept

> **"No Response" is ranked at a HIGHER priority than "Rejected."**

This is deliberate and counter-intuitive, so it is written down rather than left in the code.

**A rejection is a decision.** Someone looked, thought, and said no. The access is understood and
the outcome is known.

**Silence is not a decision.** It means nobody is watching that identity. The access continues,
unreviewed, with no human able to say what it is for. An identity nobody will speak for is a worse
position than one somebody has decided to remove.

Any report that sorts Rejected above No Response has the risk model backwards.

---

## 4. Escalation

| Day | Event |
|---|---|
| 0 | Attestation issued to the named owner |
| 14 | Due date. No Response is recorded from here. |
| 21 | First reminder to the owner |
| 28 | Escalate to the owner's manager |
| 35 | Escalate to the security team for manual review |
| 45 | **Access suspended pending confirmation** — not deleted |

**Suspend, do not delete.** Deletion is irreversible and will eventually break something that
mattered. Disabling an identity is reversible in seconds and makes exactly the same point: if
nothing breaks in two weeks, nothing needed it.

**For `EXCESSIVE_SCOPE_ESCALATION` identities, halve every interval.** Suspension at day 21.

---

## 5. Who is accountable — sponsor, then owner

**Revised 22 Oct 2026.** This section previously treated *owner* as the accountability role. For
agents that is wrong, and Microsoft's own model is clearer than mine was.

### For agent identities: the sponsor

> *"**Every single agent ID must have a sponsor.** So this is the person responsible. They have
> accountability for the agent. **They decide is this agent is still needed or not.** So you won't
> end up with these orphaned agents. Now **optionally** I can add owners — that would be from a
> technology perspective."* — Savill, 21:06

| Role | Mandatory? | Attest to them? |
|---|---|---|
| **Sponsor** | **Yes, on agent identities** | **Yes — this is the attestation** |
| Owner | No | Only if there is no sponsor |
| Manager | No | No |

**The sponsor's defined job — "decides whether this agent is still needed" — is literally the
attestation question.** Address the cycle to the sponsor. An attestation sent to a technical owner
asks the wrong person: they can change the agent, but they were never asked to justify it.

### The asymmetry this policy exists to catch

> **An agent identity cannot exist without an accountable human. An agent secured by an
> application service principal can.**

Microsoft made sponsorship mandatory for the new object class and left the old one alone.
Pre-platform Copilot Studio agents — which many tenants are still producing — have **no mandatory
accountability at all**. They are exactly the population this cycle exists to catch, and they will
not self-identify.

### For everything else: the owner

**An owner is a named human being who can answer "what is this for?"**

| | Counts |
|---|---|
| A user object | **Yes** |
| A service principal listed as owner | **No** |
| A group | **No** — ask the group and nobody answers |
| A departed user's account | **No** — this is `ORPHANED_OWNER`, which is worse than no owner |

A service principal owning an identity is not accountability. It is the appearance of accountability,
which is more dangerous than its absence because it passes a naive check. This is the
`NO_HUMAN_OWNER` rule, and it exists because a Copilot Studio agent in this lab is owned by
"Microsoft Copilot Studio Service" — a service principal that cannot be asked anything.

**Two owners minimum** for any identity holding escalation permissions. One person leaving should
not orphan a privileged identity.

---

## 6. Lab simulation — read this before showing any output to anyone

**Owner responses in this lab are simulated.** `04-Invoke-AttestationCycle.ps1` generates them on a
weighted random basis — approximately 70% Approved, 10% Rejected, 20% No Response.

**No real owner has been contacted. No real attestation has taken place.**

The 20% No Response rate is set deliberately high. Published figures for first-cycle access reviews
put non-response well above zero, and a simulation that assumes everyone replies produces a report
that looks reassuring and teaches nothing.

**Every generated report carries this statement.** Remove it only when responses are real, and on
that day change the version number of this document.

---

## 6b. Off-cycle attestation — do not wait ninety days for a new Critical

**Added 24 Oct 2026.** The quarterly cycle governs the *routine* review. It is not a reason to
leave a newly-discovered Critical unreviewed for up to three months.

**Trigger an off-cycle attestation, for that identity alone, when the weekly scan first reports:**

- `EXCESSIVE_SCOPE_ESCALATION` on an identity that did not have it last week
- `ORPHANED_OWNER` — the owner has gone and the identity carries accumulated trust nobody holds
- `NO_SPONSOR` on an agent identity — Microsoft makes sponsorship mandatory at creation, so this
  means something bypassed a control

Same escalation ladder as §4, **intervals halved**. This is the existing rule for escalation-
permission identities, applied on arrival rather than on the calendar.

**One identity, not a cycle.** An off-cycle attestation does not reset the quarterly clock, does
not start a new cycle directory, and is recorded inside the current cycle with an
`OffCycle = true` flag. Otherwise the quarterly record stops being comparable, and comparability
across quarters is the entire value of the programme.

## 7. Evidence retention

Each cycle produces:

- `output/attestation_records.json` — what was asked, of whom, when
- `output/attestation_results.json` — what came back, with the thresholds used
- `output/attestation_report.md` — the human-readable deliverable

**Retain every cycle. Never overwrite a previous one.** The value of an attestation programme to an
auditor is not the current cycle — it is being able to produce four consecutive dated cycles and
show that the non-response rate fell.

One cycle is a screenshot. Four cycles is a control.

---

## 8. What this does and does not prove

**Proves:** that a named human was asked, on a date, and what they said.

**Does not prove:** that the permission set is *necessary*. Business justification is not in the
directory, and an owner clicking Approve has not performed an analysis. Attestation records
accountability; it does not establish correctness.

Say this plainly in any report. The boundary is what keeps the rest of it credible.
