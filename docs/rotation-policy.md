# Credential rotation policy

**Version 0.1 — draft. Lab document.**
Every interval below maps to a finding code emitted by `03-New-OwnershipMap.ps1`.

> **Defaults with reasons attached. Change them and change the reason.**

---

## 1. The position this policy starts from

**Rotation is damage limitation, not a control.** Every rotation interval is an admission that a
secret exists, that it can be stolen, and that the only question is for how long it stays useful.

So the ordering is:

1. **Eliminate the credential** — federated identity credential or managed identity. Nothing to
   rotate, nothing to steal, nothing to forget.
2. **If a credential must exist, make it a certificate**, not a client secret.
3. **If it must be a client secret, bound it tightly** and rotate it on the schedule below.

**"Stop rotating this credential; eliminate it" is a better recommendation than any interval in
this document**, and it is available far more often than people assume.

---

## 2. Intervals by credential type

| Credential | Maximum lifetime | Rotate at | Finding code |
|---|---|---|---|
| **Client secret** — standard | 180 days | 150 days | `CRED_LONG_LIVED` beyond 180 |
| **Client secret** — escalation permissions | **90 days** | 75 days | `CRED_LONG_LIVED` + `EXCESSIVE_SCOPE_ESCALATION` |
| **Certificate** | 12 months | 11 months | `CRED_LONG_LIVED` beyond 365 |
| **Federated identity credential** | No expiry — **none needed** | n/a | `FEDERATED_CRED` (Info — a positive) |
| **Managed identity** | No rotatable credential exists | n/a | Excluded from credential rules |
| **Agent identity** | **Holds no credentials of its own** — see §4 | n/a | Assess the blueprint instead |

### Two object classes this table does not cover, and must

**Revised 22 Oct 2026.**

**The blueprint is where an agent's credentials actually live.** Savill, 17:43: *"It is the
blueprint that authenticates. These agent identities do not have their own credentials."* So a
clean credential report across every agent identity in a tenant proves nothing — you inspected the
children and skipped the parent.

> **Assess blueprints as credential-bearing objects in their own right, and at a higher severity
> than anything below.** Microsoft: *"a compromise of the blueprint's credentials affects **all**
> agent identities under it, which is why blueprint count is a security boundary decision."*
> One blueprint can mint 250 agent identities.

Blueprint credentials follow the same preference order as §1 — federation, then certificate, and a
secret only under protest — but with intervals **halved**, because the blast radius is every child.

**The agent user is a user object, and no NHI inventory will find it.** An agent that needs a
mailbox, Teams presence or SharePoint access gets an **agent user**: a real Entra user object,
child of the agent ID. Every NHI tool in existence enumerates service principals and applications.
**An agent user is neither.** It will be missed by construction — including by `01-Get-NHIInventory.ps1`
as currently written. See `ARCHITECTURE.md` for what stage 01 collects.

### Hard rules

- **No credential without an expiry date.** `CRED_NO_EXPIRY` is High severity with no exceptions.
  A credential with no end date is a credential nobody will ever revisit.
- **An expired credential still configured on an enabled identity is a finding, not housekeeping.**
  `CRED_EXPIRED` means something broke and nobody noticed, which says more about the monitoring
  than about the credential.
- **A client secret where a federated credential would work is `SECRET_OVER_CERT`.** Low severity
  individually, but count them — the proportion is a programme-level metric.

---

## 3. Rotation is not complete until the old credential is removed

Adding a new secret and leaving the old one in place is the most common failure in this whole area,
and it reads as compliance on a dashboard.

**Both exist = both work.** The rotation has achieved nothing except doubling the attack surface.

Rotation is: add new → cut over → verify → **delete old** → confirm the credential count returned
to where it started. If the count went up and stayed up, it was not a rotation.

---

## 4. The agent questions this policy exists to answer

The repo this lab was modelled on never asked either of these. They are the reason this document
is worth writing rather than copying.

### 4.1 What is the right TTL for an agent's credential?

**Shorter than a human's, and shorter than a service account's. Default: 90 days.**

The reasoning is a difference in kind, not degree:

- **An agent's purpose changes without its configuration changing.** A human changes role and
  someone files a ticket. An agent gets a new instruction, a new tool, a new knowledge source — and
  its identity, permissions and credentials look identical before and after. *A lab agent here
  gained Mail and SharePoint access with no corresponding change visible in Entra at all.*
- **Agents are created by business users without IT involvement.** The population grows faster than
  any review cycle written for service accounts.
- **Blast radius is broader.** An agent typically holds several connectors; a service account
  usually does one job.

**90 days, and 30 for any agent holding escalation permissions.**

### 4.2 The question underneath it

**Credential TTL is the wrong lever for agents.** You are rotating a secret while the agent's
*capability* changed last Tuesday and nothing recorded it.

The right control is a **capability review** — what tools, connectors and knowledge sources does
this agent have *today*, versus when it was last attested? That belongs in the attestation cycle,
not here, but it is noted here because a rotation policy that quietly implies the problem is solved
would be misleading.

### 4.3 What happens when an agent's owner leaves?

**Day 0 — leaver detected:** every identity they own is flagged `ORPHANED_OWNER`, **Critical**.
Owner-gone is worse than owner-never-assigned: the identity passed every previous check, so it has
accumulated trust nobody is holding any more.

**Day 0 — automatic, no human in the loop:** credential lifetime caps at **30 days** regardless of
its configured expiry. The identity keeps working; its runway shortens.

**Day 7:** an owner must be reassigned, **named and human** (`NO_HUMAN_OWNER` applies). Reassigning
to a group or a service principal does not clear the finding.

**Day 30:** no owner reassigned → **suspend, do not delete.** Same reasoning as the attestation
policy: reversible in seconds, and makes the point just as well.

**For agents specifically:** also check whether the agent's *runtime* still functions without its
owner — whether it holds delegated permissions obtained on that person's behalf. If it does, the
agent's capability silently depends on an account that is being disabled, and it will fail at an
unpredictable moment rather than at a planned one. **Find this before the leaver date, not after.**

---

## 5. Exceptions

An exception requires: a named human approver, a documented reason, and an expiry date on the
exception itself.

**An exception with no expiry is not an exception. It is the new policy, written down dishonestly.**

Review every exception each attestation cycle. Count them in the report — exception volume is a
better measure of whether a policy is working than compliance percentage is.
