# Agent & Non-Human Identity Posture Report

**Generated:** 2026-10-26 22:57 UTC  
**Tenant read:** 10/26/2026 07:41:10 (0 h before the findings were classified)  
**Identities with findings:** 28  
**Controls assessed:** 13

> **Scope.** This report covers two populations and they are NOT scored against the
> same controls. **Agent identities: 3** (true agent identities:
> 2, service-principal-secured: 1). The two classes are not
> equally evidenced: a true agent identity exposes a blueprint link and
> platform-maintained lifecycle compliance state, while an SP-secured agent exposes no
> agent property at all and is identifiable only by its tags. A control scored against
> the second class rests on weaker evidence, and this report does not pretend
> otherwise. IAM-18 (Agent Access Restriction)
> and IAM-16 govern agents only; the IAM-03/05/07/08/10/13/14 and CEK-* controls
> govern every non-human identity. Applying an agent control to an ordinary service
> principal would be a category error, so each control is scored only against the
> population it governs.

> **Control sources — both published and ratified:**
> **CSA Cloud Controls Matrix v4.1.1** (2026-10-02) and **CSA AI Controls Matrix v1.1.1**
> (2026-07-22, 247 controls). IAM-01–IAM-15 and CEK-* are identical in both;
> IAM-16–IAM-18 exist only in AICM and are the AI-specific additions.

> **No draft or proposed control identifiers are cited in this report.** An earlier
> version used IAM-AG-* IDs from an unratified white paper; those do not appear in
> AICM v1.1.1 and have been replaced with published equivalents.

> **Unmapped findings:** AGENT_FACTORY_CAPACITY, DELEGATION_ESCALATION
> These are produced by this tool but not yet mapped to a published control.
> No identifier has been invented for them. See 'Not assessed' below.

## Executive summary

| | Count |
|---|---:|
| Fully testable controls with no findings | 2 |
| Fully testable controls with findings | 4 |
| Partially testable controls with findings | 2 |
| Partially testable controls with no findings | 3 |
| Controls not assessed | 2 |

### Most serious findings

1. **svc-identity-scanner `0b3e74f4`, ServicePrincipal** - Assigned owner account is disabled. Appears governed but is not.
2. **automation-acct-01 `b2ab8ffa`, ServicePrincipal** - Assigned owner account is disabled. Appears governed but is not.
3. **svc-sso-primary `e931d10e`, ServicePrincipal** - Assigned owner account is disabled. Appears governed but is not.
4. **svc-cloud-identity-center `b097b36b`, ServicePrincipal** - Assigned owner account is disabled. Appears governed but is not.

## Control results

### IAM-18 - Agent Access Restriction: restrict agents access to the tools and plugins necessary for the activity or use case at hand, per need-to-know and least privilege

**Source:** AICM v1.1.1  
**Applies to:** Agent identities only  
**Status:** FINDINGS  
**Testability:** Partial

> **Limitation:** Tool and plugin grants live in Power Platform, not Entra. This tool can prove the enumeration is absent from the directory; it cannot read the platform-side grant itself.

**1 affected identit(ies):**

| Identity | Severity | Detail |
|---|---|---|
| agent-alerts (Microsoft Copilot Studio) `02767632`, ServicePrincipal | Medium | Agent secured by an application service principal rather than an agent identity. No sponsor requirement applies, so nothing guarantees an accountable human. |

### IAM-16 - Knowledge Access Control - need to know: policy for access to knowledge, information and data in the context of the AI system

**Source:** AICM v1.1.1  
**Applies to:** Agent identities only  
**Status:** NOT ASSESSED  
**Testability:** None

> **Limitation:** Knowledge-source scoping is a Copilot Studio / platform configuration, not a directory attribute. Out of scope by construction - reported so the control is not silently omitted.

_No findings._

### IAM-03 - Identity Inventory: manage, store, and regularly review the inventory of identities, and monitor their level of access

**Source:** CCM v4.1.1 / AICM v1.1.1  
**Applies to:** All non-human identities  
**Status:** FINDINGS  
**Testability:** Partial

> **Limitation:** Can prove an identity is inventoried and whether an owner is recorded. Cannot prove the inventory is REVIEWED - that is the attestation cycle, IAM-08.

**17 affected identit(ies):**

| Identity | Severity | Detail |
|---|---|---|
| svc-hcm-connector `e8eb98b0`, ServicePrincipal | High | No owner assigned. Nobody can attest to this identity. |
| svc-secrets-broker-legacy `be4962c2`, Application | High | App registration with no owner. Nobody is accountable for this application's CREDENTIALS and requested permissions - who may add a client secret or request broader API access. This is credential custody, not access attestation: the matching service principal is the object that holds the access and is attested separately. |
| svc-cloud-identity-center `cfbff0ea`, Application | High | App registration with no owner. Nobody is accountable for this application's CREDENTIALS and requested permissions - who may add a client secret or request broader API access. This is credential custody, not access attestation: the matching service principal is the object that holds the access and is attested separately. |
| svc-sso-primary `6c3666f2`, Application | High | App registration with no owner. Nobody is accountable for this application's CREDENTIALS and requested permissions - who may add a client secret or request broader API access. This is credential custody, not access attestation: the matching service principal is the object that holds the access and is attested separately. |
| aad-extensions-app. Do not modify. Used by AAD for storing user data. `123038c1`, Application | High | App registration with no owner. Nobody is accountable for this application's CREDENTIALS and requested permissions - who may add a client secret or request broader API access. This is credential custody, not access attestation: the matching service principal is the object that holds the access and is attested separately. |
| svc-secrets-broker `f566f90e`, Application | High | App registration with no owner. Nobody is accountable for this application's CREDENTIALS and requested permissions - who may add a client secret or request broader API access. This is credential custody, not access attestation: the matching service principal is the object that holds the access and is attested separately. |
| svc-sso-secondary `bcd1471a`, Application | High | App registration with no owner. Nobody is accountable for this application's CREDENTIALS and requested permissions - who may add a client secret or request broader API access. This is credential custody, not access attestation: the matching service principal is the object that holds the access and is attested separately. |
| svc-provisioning-v2 `2bdf3862`, Application | High | App registration with no owner. Nobody is accountable for this application's CREDENTIALS and requested permissions - who may add a client secret or request broader API access. This is credential custody, not access attestation: the matching service principal is the object that holds the access and is attested separately. |
| svc-inbound-provisioning `7e726af9`, Application | High | App registration with no owner. Nobody is accountable for this application's CREDENTIALS and requested permissions - who may add a client secret or request broader API access. This is credential custody, not access attestation: the matching service principal is the object that holds the access and is attested separately. |
| svc-provisioning-v2 `8036d9a1`, ServicePrincipal | High | Owned only by a service principal (svc-legacy-app). The ownership field is populated, so this identity APPEARS governed on any dashboard - but there is no human to answer an attestation request. Worse than having no owner at all, because it does not look like a gap. Assign a named human owner. |
| svc-legacy-app `244d40b3`, Application | High | App registration with no owner. Nobody is accountable for this application's CREDENTIALS and requested permissions - who may add a client secret or request broader API access. This is credential custody, not access attestation: the matching service principal is the object that holds the access and is attested separately. |
| svc-identity-scanner `c774c0ab`, Application | High | App registration with no owner. Nobody is accountable for this application's CREDENTIALS and requested permissions - who may add a client secret or request broader API access. This is credential custody, not access attestation: the matching service principal is the object that holds the access and is attested separately. |
| svc-hr-provisioning `943b59f7`, Application | High | App registration with no owner. Nobody is accountable for this application's CREDENTIALS and requested permissions - who may add a client secret or request broader API access. This is credential custody, not access attestation: the matching service principal is the object that holds the access and is attested separately. |
| automation-acct-01 `29d117af`, Application | High | App registration with no owner. Nobody is accountable for this application's CREDENTIALS and requested permissions - who may add a client secret or request broader API access. This is credential custody, not access attestation: the matching service principal is the object that holds the access and is attested separately. |
| svc-hcm-connector `11b1eddc`, Application | High | App registration with no owner. Nobody is accountable for this application's CREDENTIALS and requested permissions - who may add a client secret or request broader API access. This is credential custody, not access attestation: the matching service principal is the object that holds the access and is attested separately. |
| svc-cloud-sso `6b81b4f4`, ServicePrincipal | High | No owner assigned. Nobody can attest to this identity. |
| aad-extensions-app. Do not modify. Used by AAD for storing user data. `8679379d`, ServicePrincipal | High | No owner assigned. Nobody can attest to this identity. |
| svc-cloud-sso `fd2247d5`, Application | High | App registration with no owner. Nobody is accountable for this application's CREDENTIALS and requested permissions - who may add a client secret or request broader API access. This is credential custody, not access attestation: the matching service principal is the object that holds the access and is attested separately. |
| agent-collab-assistant `568b673e`, ServicePrincipal | Info | Agent identity with 1 sponsor(s): person02@contoso.example. This is the accountable human for attestation purposes - distinct from the technical owner. |
| agent-blueprint-root `703da058`, ServicePrincipal | Info | Agent identity with 1 sponsor(s): person02@contoso.example. This is the accountable human for attestation purposes - distinct from the technical owner. |
| automation-acct-01 `a7348710`, ServicePrincipal | Info | Managed identity. Accountability is held as Azure RBAC on the parent resource, which Person 67 cannot see. Not assessed: re-run 01-Get-NHIInventory.ps1 with -IncludeAzureRbac and an ARM access token to resolve it, or verify manually in Azure IAM on the parent resource. |

### IAM-05 - Least Privilege: employ the least privilege principle when implementing information system access

**Source:** CCM v4.1.1 / AICM v1.1.1  
**Applies to:** All non-human identities  
**Status:** NO FINDINGS (PARTIAL)  
**Testability:** Partial

> **Limitation:** Can detect high-privilege grants mechanically. Cannot judge business necessity - that requires the owner, which is why IAM-08 exists.

_No findings._

### IAM-07 - Access Changes and Revocation: de-provision or modify identity access in a timely manner

**Source:** CCM v4.1.1 / AICM v1.1.1  
**Applies to:** All non-human identities  
**Status:** NO FINDINGS (PARTIAL)  
**Testability:** Partial

> **Limitation:** Residue is detectable. "Timely" is not measurable from a snapshot. NO_SIGNIN_RECORD is NOT proof of disuse - it may predate log retention.

_No findings._

### IAM-08 - Access Review: review and revalidate identity access for least privilege and separation of duties, at least annually or upon significant changes

**Source:** CCM v4.1.1 / AICM v1.1.1  
**Applies to:** All non-human identities  
**Status:** NO FINDINGS (PARTIAL)  
**Testability:** Partial

> **Limitation:** Evidenced by the attestation cycle (04-Invoke-AttestationCycle.ps1), not by these findings. The policy sets 90 days against the control minimum of annually.

_No findings._

### IAM-10 - Management of Privileged Access Roles: privileged access granted for a TIME-LIMITED period; prevent accumulation of segregated privileged access

**Source:** CCM v4.1.1 / AICM v1.1.1  
**Applies to:** All non-human identities  
**Status:** FINDINGS  
**Testability:** Full

> **Limitation:** A credential with no expiry on a privileged identity is a direct, mechanical failure of the time-limited requirement.

**6 affected identit(ies):**

| Identity | Severity | Detail |
|---|---|---|
| svc-sso-secondary `fd9136ae`, ServicePrincipal | Medium | Password valid for a further 1028 days - exceeds the 180 day policy. |
| svc-sso-primary `e931d10e`, ServicePrincipal | Medium | Password valid for a further 1001 days - exceeds the 180 day policy. |
| svc-cloud-identity-center `b097b36b`, ServicePrincipal | Medium | Password valid for a further 1037 days - exceeds the 180 day policy. |
| automation-acct-01 `29d117af`, Application | Medium | Certificate valid for a further 316 days - exceeds the 180 day policy. |
| svc-hr-provisioning `943b59f7`, Application | Medium | Certificate valid for a further 317 days - exceeds the 180 day policy. |
| svc-legacy-app `244d40b3`, Application | Medium | Password valid for a further 729 days - exceeds the 180 day policy. |

### IAM-13 - Strong Authentication: adopt digital certificates OR ALTERNATIVES WHICH ACHIEVE AN EQUIVALENT LEVEL OF SECURITY FOR SYSTEM IDENTITIES

**Source:** CCM v4.1.1 / AICM v1.1.1  
**Applies to:** All non-human identities  
**Status:** FINDINGS  
**Testability:** Full

> **Limitation:** Directly testable. FEDERATED_CRED evidences compliance; SECRET_OVER_CERT evidences the gap.

**5 affected identit(ies):**

| Identity | Severity | Detail |
|---|---|---|
| agent-alerts (Microsoft Copilot Studio) `9bef1938`, Application | Info | Uses workload identity federation (2 credential(s)) - no stored secret. Good practice. |
| svc-identity-scanner `c774c0ab`, Application | Info | Uses workload identity federation (1 credential(s)) - no stored secret. Good practice. |
| svc-legacy-app `244d40b3`, Application | Low | Uses a client secret where a certificate or federated credential would be stronger. |
| svc-secrets-broker `f566f90e`, Application | Low | Uses a client secret where a certificate or federated credential would be stronger. |
| svc-secrets-broker-legacy `be4962c2`, Application | Low | Uses a client secret where a certificate or federated credential would be stronger. |

### IAM-14 - Credentials Management: secure management of authentication credentials

**Source:** CCM v4.1.1 / AICM v1.1.1  
**Applies to:** All non-human identities  
**Status:** PASS  
**Testability:** Full

_No findings._

### CEK-12 - Key Rotation: rotate cryptographic keys in accordance with the calculated cryptoperiod

**Source:** CCM v4.1.1 / AICM v1.1.1  
**Applies to:** All non-human identities  
**Status:** FINDINGS  
**Testability:** Full

> **Limitation:** The 180-day threshold is this lab policy, not a control-mandated figure. CEK-12 requires a CALCULATED cryptoperiod - state yours and the reasoning.

**6 affected identit(ies):**

| Identity | Severity | Detail |
|---|---|---|
| svc-sso-secondary `fd9136ae`, ServicePrincipal | Medium | Password valid for a further 1028 days - exceeds the 180 day policy. |
| svc-sso-primary `e931d10e`, ServicePrincipal | Medium | Password valid for a further 1001 days - exceeds the 180 day policy. |
| svc-cloud-identity-center `b097b36b`, ServicePrincipal | Medium | Password valid for a further 1037 days - exceeds the 180 day policy. |
| automation-acct-01 `29d117af`, Application | Medium | Certificate valid for a further 316 days - exceeds the 180 day policy. |
| svc-hr-provisioning `943b59f7`, Application | Medium | Certificate valid for a further 317 days - exceeds the 180 day policy. |
| svc-legacy-app `244d40b3`, Application | Medium | Password valid for a further 729 days - exceeds the 180 day policy. |

### CEK-13 - Key Revocation: revoke and remove keys before end of cryptoperiod, when compromised, OR WHEN AN ENTITY IS NO LONGER PART OF THE ORGANIZATION

**Source:** CCM v4.1.1 / AICM v1.1.1  
**Applies to:** All non-human identities  
**Status:** FINDINGS  
**Testability:** Full

> **Limitation:** ORPHANED_OWNER maps directly to the departed-entity clause. Credential state is visible; whether revocation was ATTEMPTED is not.

**4 affected identit(ies):**

| Identity | Severity | Detail |
|---|---|---|
| svc-identity-scanner `0b3e74f4`, ServicePrincipal | Critical | Assigned owner account is disabled. Appears governed but is not. |
| automation-acct-01 `b2ab8ffa`, ServicePrincipal | Critical | Assigned owner account is disabled. Appears governed but is not. |
| svc-sso-primary `e931d10e`, ServicePrincipal | Critical | Assigned owner account is disabled. Appears governed but is not. |
| svc-cloud-identity-center `b097b36b`, ServicePrincipal | Critical | Assigned owner account is disabled. Appears governed but is not. |

### LOG-05 - Audit Logs Monitoring and Response: correlate and monitor audit logs to detect suspicious or anomalous activity deviating from expected patterns

**Source:** CCM v4.1.1 / AICM v1.1.1  
**Applies to:** All non-human identities  
**Status:** NOT ASSESSED  
**Testability:** None

> **Limitation:** This tool is a point-in-time posture assessment, NOT a monitor. Continuous anomaly detection requires SIEM correlation. Out of scope by construction - say so rather than implying coverage.

_No findings._

### UNMAPPED-01 - Findings with no published control objective - the gap is the finding

**Source:** UNMAPPED  
**Applies to:** All non-human identities  
**Status:** PASS  
**Testability:** Full

> **Limitation:** NOT a mapping gap to be closed - a genuine absence, now evidenced. CCM v4.1.1 and AICM v1.1.1 contain no control for blueprint-to-agent permission inheritance; the NIST NCCoE paper poses delegation-of-authority as an OPEN QUESTION (p5) rather than specifying a control; SP 800-207 offers Tenets 3 and 6 as principles, which are not auditable control objectives; SP 800-63-4 covers identity proofing, not post-authentication delegation. Report these findings on their own terms and cite the NCCoE question verbatim. Do not invent an identifier.

_No findings._

## Not assessed

These cannot be determined from directory data and require manual review. Listing
them is deliberate: a tool that claims to assess controls it cannot measure is worse
than one honestly scoped.

| Not testable | Why |
|---|---|
| Whether a permission set is *necessary* | Business justification is not a directory attribute. Use the attestation cycle. |
| Whether the agent was approved before creation | No approval record exists in Graph. This is a process control. |
| Whether the identity handles regulated data | Data classification is not an identity property. |
| Whether the assigned owner is the *right* owner | Graph records who the owner is, not whether that is appropriate. |
| What the agent does when invoked | Behaviour is not an identity attribute. Runtime monitoring - out of scope for a directory-data assessment. |

## Method and limitations

- Read-only Person 67 scopes: `Application.Read.All`, `Directory.Read.All`, `AuditLog.Read.All`, `RoleManagement.Read.Directory`
- Sign-in activity uses a **beta** endpoint (`/beta/reports/servicePrincipalSignInActivities`) which may change without notice
- **'No sign-in record' is not evidence of disuse.** A record may be absent because it predates the log retention window. Verify before decommissioning anything.
- Managed identities are excluded from credential-rotation findings by design: Azure manages their credentials and there is nothing an administrator can rotate.
- Microsoft first-party and third-party service principals are inventoried but not flagged for owner assignment - they have no tenant owner by design.

---

_Generated by 05-New-ControlReport.ps1._

