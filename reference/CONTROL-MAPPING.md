# Control mapping — findings to published standards

This is the control-mapping layer, and it is the whole differentiator. NIST, CSA and OWASP published
control sets in February 2026. **None of them tells you whether a specific tenant complies.**
That gap is what you are filling.

---

## How to build this table properly

1. Obtain the **CSA AICM Agentic Control Supplement** (24 controls) and the **NIST NCCoE**
   concept paper on software and AI agent identity and authorization. Read them properly.
2. For each control ask one question: **can I mechanically test this from Graph?**
3. Record the answer honestly. Three outcomes only:
   - **Testable** — a finding code from Phase 3 maps to it
   - **Partially testable** — you can test a necessary but not sufficient condition
   - **Not testable** — requires manual review, process evidence, or data Graph does not expose

**Be rigorous about "not testable."** A tool claiming to assess controls it cannot measure is
worse than one honestly scoped, and an auditor will find it in minutes. Your not-testable list
is a feature — it is also the most interesting thing you will have to say to the standards
community in your Phase 5 publication.

---

## CORRECTION — 24 Oct 2026. One of the two source documents is not a control set.

**The NIST NCCoE paper is a concept paper seeking public comment. It contains no controls.**

*"Accelerating the Adoption of Software and AI Agent Identity and Authorization"*, DRAFT, February
2026, NCCoE. It has **no control identifiers, no testable requirements, and no normative language.**
What it has is a list of **open questions** NIST is asking the community, and a list of standards it
is *considering* — MCP, OAuth 2.0/2.1, OIDC, SPIFFE/SPIRE, SCIM, NGAC. **Its public comment period
closed 2 April 2026.**

Every document in this project that treats "NIST NCCoE" as something findings map *to* is wrong,
including earlier versions of this file. **Do not cite it as a control source.**

**Two things it is genuinely good for:**

1. **It names the real NIST documents** where controls actually live: **SP 800-207** (Zero Trust
   Architecture), **SP 800-63-4** (Digital Identity Guidelines), **NISTIR 8587** (Protecting Tokens
   and Assertions from Forgery, Theft, and Misuse). Map to those, not to the concept paper.
2. **Its open questions are a publication brief.** NIST asked *"How might agents be identified in an
   enterprise architecture? What metadata is essential for an AI agent's identity?"* — and you have
   measured the answer in a real tenant. Writing up what Entra actually exposes is a direct response
   to a question NIST put in writing. That is a far stronger relationship to the document than
   pretending to map against controls it does not contain.

---

## THIRD CORRECTION — 29 Oct 2026. The published matrices are now on disk, and the draft IDs are gone.

**`IAM-AG-01`–`IAM-AG-04` and `LOG-AG-01` have been removed from the mapping.**

They came from a **draft white paper**. A check of all **247 control IDs in the published AICM
v1.1.1** returns **no `-AG-` identifiers at all** — they do not exist in the ratified matrix. They
were always labelled "(draft)" and "proposed", which was honest, but **citing a proposal when the
ratified matrix is available is not a choice that survives a review.**

### What is now cited

| Source | Version | Scope |
|---|---|---|
| **CSA Cloud Controls Matrix** | **v4.1.1**, 2026-10-02 | General cloud. `IAM-01`–`IAM-15`, `CEK-*`, `LOG-*` |
| **CSA AI Controls Matrix** | **v1.1.1**, 2026-07-22, 247 controls | AI systems. Adds `IAM-16`–`IAM-18` |

`IAM-01`–`IAM-15` and `CEK-*` are **identical in both**, so they cite both. `IAM-16`–`IAM-18`
exist only in AICM.

### And the non-agent gap is closed

The previous correction said *"this tool has a real control mapping for agents and none for
ordinary non-human identities."* **That is no longer true.** CCM/AICM `IAM` and `CEK` govern them
directly, so `UNMAPPED-02` is retired — those findings now carry identifiers a reader can look up.

---

## The headline got better: `IAM-18` is ratified, and it is about tools

> **IAM-18 — Agent Access Restriction** *(AICM v1.1.1)*
> *"Restrict agents' access to the **tools and plugins** necessary for the activity or use case at
> hand, ensuring adherence to the principles of need-to-know and least privilege."*

Your lab agent holds **SharePoint MCP** and **Mail MCP**. Entra reports **zero permissions** for it.

> **You cannot restrict what you cannot enumerate — and the enumeration is not in the directory.**

`AGENT_CAPABILITY_OPAQUE` was previously a failure of a *proposed* control. It is now a failure of
a **published, ratified one**, demonstrated in a real tenant. That is a materially stronger claim
and it costs nothing to make.

---

## The mapping — published IDs only

### Agents

| Control | Source | Objective | Your codes | Testable? |
|---|---|---|---|---|
| **`IAM-18`** | AICM v1.1.1 | **Restrict agent access to tools and plugins**, need-to-know and least privilege | **`AGENT_CAPABILITY_OPAQUE`**, `SP_SECURED_AGENT`, `EXCESSIVE_SCOPE_ESCALATION` | **Partial — the headline** |
| `IAM-16` | AICM v1.1.1 | Knowledge access control, need-to-know within the AI system | — | **None** — platform config, not directory |

### All non-human identities

| Control | Source | Objective | Your codes | Testable? |
|---|---|---|---|---|
| **`IAM-03`** | CCM / AICM | **Identity Inventory** — manage, store and regularly review the inventory, monitor level of access | `NO_OWNER`, `NO_SPONSOR`, `MI_OWNERSHIP_NOT_IN_GRAPH`, `UNMANAGED_*`, `IAC_MANAGED` | Partial |
| `IAM-05` | CCM / AICM | Least privilege | `EXCESSIVE_SCOPE_ESCALATION`, `HIGH_IMPACT_PERMISSION` | Partial |
| `IAM-07` | CCM / AICM | De-provision or modify access **in a timely manner** | `DISABLED_WITH_CREDS`, `DORMANT`, `DORMANT_AGENT`, `NO_SIGNIN_RECORD` | Partial |
| `IAM-08` | CCM / AICM | **Access Review** — revalidate at least annually | *(the attestation cycle)* | Partial |
| `IAM-10` | CCM / AICM | Privileged access granted for a **time-limited period** | `CRED_LONG_LIVED`, `CRED_NO_EXPIRY`, `EXCESSIVE_SCOPE_ESCALATION` | **Full** |
| **`IAM-13`** | CCM / AICM | **"Adopt digital certificates or alternatives which achieve an equivalent level of security for SYSTEM IDENTITIES"** | `SECRET_OVER_CERT`, **`FEDERATED_CRED`** | **Full** |
| `IAM-14` | CCM / AICM | Credentials management | `CRED_NO_EXPIRY`, `CRED_EXPIRED`, `CRED_EXPIRING` | **Full** |
| `CEK-12` | CCM / AICM | Rotate keys per the **calculated cryptoperiod** | `CRED_LONG_LIVED`, `CRED_EXPIRED` | **Full** |
| **`CEK-13`** | CCM / AICM | Revoke keys when compromised **"or an entity is no longer part of the organization"** | **`ORPHANED_OWNER`**, `DISABLED_WITH_CREDS` | **Full** |
| `LOG-05` | CCM / AICM | Correlate and monitor logs for anomalous activity | — | **None** — this is a posture tool, not a monitor |

### Two mappings worth pausing on

**`IAM-13` names system identities explicitly.** *"Adopt digital certificates or alternatives which
achieve an equivalent level of security **for system identities**."* A client secret where a
federated credential would work is a direct failure — and **`FEDERATED_CRED` is a PASS against it**,
one of the few places this tool reports a positive against a published control rather than only
complaints.

**`CEK-13` contains `ORPHANED_OWNER` almost verbatim.** *"...or an entity is no longer part of the
organization."* A departed owner whose identity still holds live credentials is not untidy
governance — it is a named, published control failure. That is the sentence to use.

### Still genuinely unmapped

`DELEGATION_ESCALATION` and `AGENT_FACTORY_CAPACITY`. Both concern blueprint-to-agent permission
inheritance, which has **no published control** in CCM or AICM v1.1.1. **NIST SP 800-207 and
SP 800-63-4 are now on disk and unread** — check those before concluding none exists.

---

## Findings that are genuinely NOT testable from Graph

State these plainly in the report. Each is a manual-review item.

| Cannot be tested | Why | What to recommend instead |
|---|---|---|
| Is this agent's permission set *necessary*? | Business justification is not in the directory. | Attestation cycle — ask the owner. |
| Was this agent approved before creation? | No approval record in Graph. | Process control outside the tool. |
| Does the agent handle regulated data? | Data classification is not an identity property. | Manual mapping to data inventory. |
| Is the human owner the *right* owner? | Graph records who, not whether appropriate. | Manager attestation. |
| What does the agent actually *do* when invoked? | Behaviour is not an identity attribute. | Runtime monitoring — out of scope for the control-mapping stage, say so. |

That last row matters. Your tool assesses **identity posture**, not **agent behaviour**. Being
explicit about that boundary is what keeps it credible — and it is a genuinely interesting
limitation to write about, because it is where the whole category currently stops.

---

## Report structure for the control-mapping stage

```
# Agent & Non-Human Identity Posture Report
  Tenant, date, tool version, scopes used, beta endpoints used

## Executive summary
  Identities assessed, controls tested, pass / fail / not-testable counts
  The three most serious findings, named

## Control results
  Per control: ID, intent, status, evidence, affected identities

## Findings by severity
  Critical / High / Medium / Low / Info (positives included)

## Not assessed
  Controls requiring manual review, and why — this section is a feature

## Method and limitations
  Read-only scopes, beta dependencies, what "no sign-in record" does and does not mean
```

---

## One rule for the published version

Aggregate findings only. The report a *client* gets names their own identities — that is the
point. The report *you publish* names nothing: "of 28 tenants assessed, 61% had at least one
unowned service principal holding escalation permissions." Same credibility, no exposure.
