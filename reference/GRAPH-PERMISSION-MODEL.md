# The Microsoft Graph permission model

**Written 12 October 2026.** Reference for Phases 0, 1, 3 and 6. Read it once properly; come back
to the tables.

This is the thing that blocks everything else. You cannot enumerate an identity you cannot
authenticate to read, and over-scoping is the most common reason a security tool gets rejected by
a client. It is also the subject your tool *measures*, so you need it precisely, not roughly.

---

## The one-paragraph version

An **application** is a definition. A **service principal** is that definition's local identity
inside one tenant. **Permissions** are published by the API being called, and **granted** to the
caller's service principal — either as *delegated* (the app acts for a signed-in user, and the
user's own privileges still apply) or as *application* permissions (the app acts as itself, with
nothing narrowing it). Every grant is a real object in the directory, and finding the dangerous
ones is what your tool does.

---

## 1. The three object types

### Application object — the blueprint

Graph: `/applications` · Portal: **App registrations**

Lives in **one** tenant — wherever it was registered. It holds the design, not the access:

- display name, redirect URIs, sign-in audience
- `requiredResourceAccess` — the permissions it *wants* (a wish list, not a grant)
- `passwordCredentials` and `keyCredentials` — secrets and certificates
- `federatedIdentityCredentials` — secretless trust (see §7)
- owners

### Service principal — the local identity

Graph: `/servicePrincipals` · Portal: **Enterprise applications**

The instance. One application can have **many** service principals — one in each tenant that uses
it. Linked back to the application by `appId`.

This is the object that actually matters operationally. It is what:

- gets permissions granted to it
- signs in, and appears in sign-in logs
- receives directory role assignments
- gets owners assigned for accountability

> **The portal mapping almost nobody tells you:**
> **App registrations = application objects. Enterprise applications = service principals.**
> Two different blades, two different object types, confusingly similar names.

### Managed identity — the third class

Also a service principal, with `servicePrincipalType = "ManagedIdentity"`, but:

- **no application object you control**
- **no credentials you can see, rotate, or leak** — Azure handles them invisibly

| | System-assigned | User-assigned |
|---|---|---|
| Lifecycle | Created and destroyed **with** its Azure resource | Standalone Azure resource, independent lifecycle |
| Sharing | Tied 1:1 to one resource | Attachable to many resources |
| Terraform | n/a — a property of the parent | `azurerm_user_assigned_identity` |

**Why this changes your risk logic**, and it is the point of item 3 in the learning table:

`CRED_NO_EXPIRY`, `CRED_EXPIRED` and `CRED_LONG_LIVED` are **meaningless** for a managed identity.
There is no credential to assess. Flagging one would be a false positive, which is why script `03`
classifies them separately.

But `NO_OWNER` and `EXCESSIVE_SCOPE_ESCALATION` **still apply in full.** A managed identity with
`RoleManagement.ReadWrite.Directory` and nobody accountable for it is exactly as dangerous as an
app registration in the same state — arguably more, because people assume "no secret" means "safe."

**Telling system- from user-assigned:** the `alternativeNames` property on the service principal
carries the ARM resource ID. That is the distinction, and it is why `01-Get-NHIInventory.ps1` offers `-IncludeAzureRbac` with a separate ARM token.

---

## 2. "Is the client app the service principal? Is that a client?"

Both halves of your question, precisely:

**"Client" is a role in a conversation, not an object type.** In any OAuth exchange there are two
parties:

- the **client** — whoever is *requesting* a token
- the **resource** (or API) — whatever is *being called*

**The client is an application. The service principal is how that application exists in your
tenant.** So they are not the same thing, but they are not separate things either — one is the
local instance of the other.

Your case, concretely:

| Role | Name | App ID | What it is |
|---|---|---|---|
| **Client** | Microsoft Graph Command Line Tools | `14d82eec-204b-4c2f-b7e8-296a70dab67e` | What PowerShell signs in **as**. Created in your tenant the first time anyone runs the SDK. |
| **Resource** | Microsoft Graph | `00000003-0000-0000-c000-000000000000` | The API being **called** |

**Both appear in Enterprise applications**, because both need a local identity — the client so
permissions can be granted *to* it, the resource so permissions can be targeted *at* it.

**That is exactly why your consent went to the wrong place.** Both are called "Microsoft Graph
something," both are in the same list, and only one of them is the client.

> **Grants always attach to the client's service principal.**
> Going to Enterprise applications → *Microsoft Graph* → Permissions shows you what the **API**
> has been granted, which is almost nothing and not what you wanted.

### What the resource publishes

The Microsoft Graph service principal in your tenant advertises every permission it offers:

| Property on the resource SP | Contains |
|---|---|
| `oauth2PermissionScopes` | the **delegated** permissions it offers |
| `appRoles` | the **application** permissions it offers |

**The same name often exists in both lists.** `Directory.Read.All` is both a delegated scope and an
app role, and they behave completely differently. Your tool has to know which kind it found —
reporting "holds Directory.Read.All" without saying which is a finding an auditor will reject.

---

## 3. The two locks

To read anything, **two independent checks** must pass:

| | Question | Set by | Failure looks like |
|---|---|---|---|
| **Lock 1 — Consent** | "Is this *program* allowed to ask?" | The grants on the client's SP | **"Need admin approval"** at sign-in |
| **Lock 2 — Authorization** | "Is *this person* allowed to see it?" | The signed-in user's Entra role | **403 Forbidden** on the API call |

**Delegated = both locks. Application permissions = lock 1 only.**

That asymmetry is the whole reason to prefer delegated for an assessment:

```
Delegated effective access  =  what the app was granted  ∩  what the user can already do
App-only effective access   =  what the app was granted
```

With delegated, your own role is a ceiling the app cannot exceed. With app-only there is no
ceiling — which is why `Directory.Read.All` as an application permission on a standing credential
is an unattended, permanent read of the entire directory, bounded by nothing.

**Your two failures were one at each lock**, which is actually the ideal way to learn this:

1. Consent on the wrong object → lock 1 failed → "Need admin approval"
2. A user with no role → lock 2 would have failed next → 403

---

## 4. Delegated vs application permissions

| | Delegated | Application (app-only) |
|---|---|---|
| Also called | scopes, `scp` | app roles, app permissions, `roles` |
| A user is present? | Yes | No |
| Narrowed by the user's role? | **Yes** | **No** |
| Token claim | `scp` | `roles` |
| Unattended / schedulable? | No | Yes |
| Needs a stored credential? | No | Usually yes |
| Right for | assessments, interactive admin work | pipelines, scheduled jobs |

**Admin consent.** Every permission is flagged by Microsoft as requiring admin consent or not.
**All four of your scopes require it**, so a non-admin can never self-consent to them — no matter
how many times they click. Separately, the tenant has a user-consent setting that can disable user
consent entirely.

**Once admin consent is granted tenant-wide, nobody is prompted again** — for *those exact scopes*,
on *that exact client*. Request a fifth scope later and that one prompts.

---

## 5. Where grants actually live — the Phase 3 mechanic

This is item 5 in the learning table, and it is where "excessive scope" is measured.

### Delegated → `oauth2PermissionGrants`

| Field | Holds | Trap |
|---|---|---|
| `clientId` | the **client service principal's object id** | **It is the object id, NOT the appId**, despite the name. Match on the wrong one and your inventory is silently wrong. |
| `resourceId` | the resource SP's object id | |
| `scope` | **space-separated string** of scope names | Not an array. Split on space. |
| `consentType` | `AllPrincipals` or `Principal` | `AllPrincipals` = admin consented for everyone. `Principal` = one user consented for themselves. |
| `principalId` | the user's id when `consentType` is `Principal` | `null` when `AllPrincipals` |

**`consentType` is a finding in its own right.** A pile of `Principal` grants means individual users
have been consenting to apps one at a time, with no admin review. That is a governance gap worth
reporting.

### Application → `appRoleAssignments`

| Field | Holds |
|---|---|
| `principalId` | the client SP being granted the permission |
| `resourceId` | the resource SP granting it |
| `appRoleId` | **a GUID**, not a name |

**You must resolve the GUID** against the resource SP's `appRoles` collection to get
`Directory.Read.All` out of it. This is why script `03` skips unresolved entries — you cannot
classify what you cannot name, and guessing would be worse than omitting.

> **The inventory bug this causes:** read only `appRoleAssignments` and you miss every delegated
> grant. Read only `oauth2PermissionGrants` and you miss every application permission — including
> the dangerous ones. **This tool must read both.**

---

## 6. How to debug this in ten seconds

```powershell
Get-MgContext
```

| Field | Tells you |
|---|---|
| `AuthType` | `Delegated` or `AppOnly` — settles which model you are in |
| `Scopes` | what you actually got, versus what you asked for |
| `Account` | the signed-in user — empty means app-only |
| `ClientId` | which client app you are using |
| `TenantId` | which tenant |

**Asked-for is not the same as got.** Compare `Scopes` against your `$RequiredScopes` — script `00`
already does this and prints the difference, which is exactly why it is written that way.

If you ever inspect a raw token, **decode it locally and never paste it into a website.** An access
token is a live credential for its lifetime. In the token: `scp` present means delegated, `roles`
present means app-only.

---

## 7. Workload identity federation

Item 6 in the learning table, and the best remediation you can recommend.

`federatedIdentityCredentials` sits on the **application** object. It lets an external identity
provider — GitHub Actions, Kubernetes, another cloud — exchange its own token for an Entra token.

**No client secret exists at all.**

That is the point. Your Phase 3 findings will be full of expiry and rotation problems, and the
honest answer to most of them is not "rotate it more often" — it is **"remove the credential."**
Very few people make that recommendation, and it lands precisely because it eliminates a class of
finding instead of scheduling it.

`issuer` and `subject` must match **exactly**, and **over-broad subject matching is the entire
vulnerability class here** — a subject that matches any branch means any branch can assume the
identity. Pin it to one repository and one branch or environment, then try to break it from a
second branch and write down what happened.

And report a federated credential as a **positive** finding. A tool that only complains reads as
noise; one that recognises good practice reads as judgement.

---

## 8. Your four scopes

| Scope | Lets you read | Admin consent? |
|---|---|---|
| `Application.Read.All` | app registrations and service principals — your core inventory | Yes |
| `Directory.Read.All` | broad directory read, including owners | Yes |
| `AuditLog.Read.All` | sign-in and directory audit logs | Yes |
| `RoleManagement.Read.Directory` | directory role assignments — who holds Global Admin | Yes |

All read-only. None in your escalation set. **Keep it that way** — if you ever add
`Application.ReadWrite.All` for remediation, your own tool would correctly flag your own tool as
Critical, because that permission can add credentials to any app registration. The auditor stays
read-only; remediation runs under a human with PIM activation.

### The role side of lock 2

Microsoft documents the least-privilege roles **per endpoint**, and they are not uniform. For
`/auditLogs/directoryAudits` the documented roles are **Reports Reader, Security Reader, or
Security Administrator** — note that Global Reader is *not* in that list, even though it is a broad
read role.

**So do not take a single role on faith, including from me.** Assign **Global Reader** first,
run script `01`, and see what happens. If audit log calls return 403, add **Reports Reader**.

Then write down whichever combination actually worked, because that becomes the prerequisite line
in your README — and you want it to be *true*, not plausible. Determining it is a legitimate Phase
0 exercise and the answer is worth more than a guess.

---

## 9. Every mistake, named

Both of the real ones are extremely common, and they are the two that teach the model.

| What happened | Why | The correction |
|---|---|---|
| Granted admin consent to **"Microsoft Graph"** | It is the **resource**, not the client. Both are in Enterprise applications with near-identical names. | Grant on **Microsoft Graph Command Line Tools**, `14d82eec-…` |
| Expected consent alone to let a role-less user run it | Delegated checks **both** locks. Consent is lock 1; the user's role is lock 2. | Assign a read role to the user as well |
| Treated "the MS Graph app" as one thing | It is three: the application object, the service principal, and the API being called | §1 and §2 above |

## 10. Next steps, in order

1. **Confirm the client SP exists.** Entra admin center → Enterprise applications → search
   `14d82eec-204b-4c2f-b7e8-296a70dab67e`. Not there means nobody has signed in with the SDK yet,
   so there was nothing to consent on.
2. **Grant tenant-wide consent properly.** As Global Admin:
   ```powershell
   Connect-MgGraph -Scopes 'Application.Read.All','Directory.Read.All','AuditLog.Read.All','RoleManagement.Read.Directory'
   ```
   Tick **"Consent on behalf of your organization"** on the consent screen. One step, right app,
   exactly those scopes.
3. **Verify it stuck.** Enterprise applications → Microsoft Graph Command Line Tools →
   **Permissions**. All four listed as *Granted for \<tenant\>*.
4. **Assign Global Reader** to your test user. Then re-run as that user and confirm **no prompt** —
   that is lock 1 proven open.
5. **Run `01-Get-NHIInventory.ps1` for the first time.** If audit log data comes back empty or 403s,
   that is lock 2, and Reports Reader is the fix. **Write the result in `TROUBLESHOOTING.md`** —
   symptom, cause, fix. This is your first real entry, and it is the file hiring managers read
   because it cannot be faked.
6. **Document the final role requirement in the repo README** as the prerequisite.

Step 5 is the one that matters. Everything above it is setup for the first time your code runs
against a real tenant.

---

## Sources

- [oAuth2PermissionGrant resource type](https://learn.microsoft.com/en-us/graph/api/resources/oauth2permissiongrant?view=graph-rest-1.0)
- [List directoryAudits — permissions and roles](https://learn.microsoft.com/en-us/graph/api/directoryaudit-list?view=graph-rest-1.0)
- [App-only authentication with the Graph PowerShell SDK](https://learn.microsoft.com/en-us/powershell/microsoftgraph/app-only?view=graph-powershell-1.0)
