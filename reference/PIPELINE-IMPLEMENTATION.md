# Running the scanner from a pipeline, with no secret

# How the scheduled scan authenticates without a secret
**Implemented.** The workflow is at `.github/workflows/nhi-scan.yml`.

> **Status, 25 Oct 2026: the workflow now exists** at `.github/workflows/nhi-scan.yml`.
> Until today this document described a file that had never been written — the doc was right
> about the path and the design, and there was simply nothing there. Same doc-versus-reality
> drift as the control map, found the same way: by looking instead of assuming.
>
> **It is UNRUN.** The federated credential, the repo variables and the application permissions
> all have to be configured in Entra before the first run means anything, and the first failure
> belongs in `TROUBLESHOOTING.md`.
>
> **Four things the workflow deliberately does NOT do**, each one a decision rather than an
> omission:
>
> | Not done | Why |
> |---|---|
> | Upload scan output as an artifact | `nhi_inventory.json` is a complete map of every non-human identity, its owners and its permissions. Artifacts are downloadable by anyone with repo read access — on a public repo, everyone. **The scan runs in the pipeline; the data stays there.** |
> | Run `04` (attestation) | It writes records addressed to people. That belongs to a human-initiated quarterly cycle, not a cron job. |
> | Run `99` (lab fixture) | It needs `Application.ReadWrite.All` and `Directory.ReadWrite.All` — the exact permissions `03` reports as **Critical**. The auditor stays read-only. |
> | Hold any write permission | `00b` refuses to continue holding one, so a mis-granted permission **fails the run instead of using it**. |
>
> The job summary publishes the `-Anonymise` report only, and the issue it raises carries
> **counts and a run id, nothing else** — "which identities are unowned" is precisely the
> sentence an attacker would like to read on a public repo.

---

## Notification: why there is no email step

The obvious way to get a weekly report by email is Graph `sendMail`. **It is not used here, and
the reason is the whole argument of the tool.**

`Mail.Send` is a **write** permission. `00b-Connect-Pipeline.ps1` refuses to run holding any
write scope at all, and the workflow is granted none. Adding `Mail.Send` so the scanner can email
you would trade the tool's central claim — *the auditor holds nothing that can change anything* —
for a convenience. A reviewer who noticed that would be right to.

**What is used instead: GitHub's own notifications.** The workflow opens an issue on every run.
Watch the repository and each one reaches your inbox. No new permission, no new infrastructure,
and the notification path is itself auditable.

**An issue is raised on every run, not only on findings**, because an alert-only design cannot
distinguish *"a clean week"* from *"the workflow stopped running"* — both are silence, and the
second is the one that matters. A separate `if: failure()` step raises a distinct issue when the
scan itself breaks, saying plainly that there is **no assessment for that week** and that the
posture is unknown rather than clean. A scheduled control that fails quietly reports a perfect
tenant forever.

---

## Deployment option: Azure Automation instead of GitHub Actions

GitHub Actions is the right choice **for this lab**. It is not automatically the right choice for
a client, and the difference is worth being able to argue.

| | GitHub Actions *(built)* | Azure Automation Account |
|---|---|---|
| Credential | Federated — **no secret exists** | System-assigned managed identity — no secret either |
| Where it runs | GitHub-hosted runner, **outside the tenant** | Inside the client's own subscription |
| Tenant data | Transits a third-party runner, destroyed with it | **Never leaves the tenant boundary** |
| Graph permissions | App roles on the app registration | App roles on the managed identity |
| Source control | Native | Source-control integration, syncs from the same repo |
| Cost | Free | Small, per job-minute |
| Setup | Federated credential + 2 repo variables | Automation account, MI, role assignment script |

**The deciding question is not technical — it is whose infrastructure may read the directory.**
A GitHub-hosted runner holding a Graph token that enumerates every identity in a client's tenant
is a supply-chain exposure some clients will accept and some will refuse outright. Azure
Automation keeps the read inside the subscription they already own.

**So: GitHub Actions for this repository and for the portfolio** — the federated credential is
Phase 6's deliverable and *"no secret exists anywhere in this system"* is the stronger story.
**Azure Automation for a client engagement**, where the answer to "who else sees our directory
data?" needs to be "nobody."

The scripts need no changes either way. They read Graph through whatever session is already
connected, which is exactly why `00` and `00b` are separate files — the authentication model is
swappable and the assessment logic is not involved.

---

## Read this first — it breaks a rule you already made

**A pipeline cannot authenticate interactively.** Phase 0.2b says interactive delegated through
the control-mapping stage, and that decision stands for the lab. This is the **documented client-deployment option**
from the same table — app-only, except the credential is federated instead of a certificate.

**What that costs you, stated plainly:**

| | Interactive delegated (the lab) | App-only federated (the pipeline) |
|---|---|---|
| Lock 1 — consent | Yes | Yes |
| **Lock 2 — the user's role** | **Yes — a real ceiling** | **None. There is no user.** |
| Permission type | Delegated | **Application** |
| Needs admin consent | Yes | Yes |

**The user ceiling disappears.** `Directory.Read.All` as an *application* permission reads the
entire directory with nothing narrowing it. So:

- **Read-only scopes. No exceptions.** The blast radius of this credential is a report, not a change.
- **Run it against your own lab tenant only.** Not a client's, ever, without their explicit setup.
- This is the thing your own tool flags as `EXCESSIVE_SCOPE` if you get it wrong. Do not get it wrong.

---

## Where the files go

> ### CORRECTION — 23 October 2026
>
> An earlier version of this file said *"the point of routing the pipeline through `00`"*, and the
> `-AccessToken` comment in `00-Connect-Lab.ps1` said `00b` *"calls through to here."*
>
> **Neither is true. `00b-Connect-Pipeline.ps1` is fully self-contained** — it does the OIDC
> exchange, decodes the token, checks the roles, and calls `Connect-MgGraph` itself at the end.
> **It never touches `00`.** I wrote that parameter for a design and then built a different one.
>
> **The pipeline does not need `00-Connect-Lab.ps1`.**

### Two entry points, neither calling the other

| Script | Who runs it | Auth model | Reads which claim |
|---|---|---|---|
| **`00-Connect-Lab.ps1`** | **A human, locally** | Interactive, **delegated** | `scp` (scopes) |
| **`00b-Connect-Pipeline.ps1`** | **GitHub Actions** | Federated, **app-only** | `roles` |

**They cannot share verification logic, and that is the reason there are two files.** `00` reads
`$ctx.Scopes`, populated from `scp`. An app-only token has no `scp` — its permissions are in
`roles` — so `00` would report *every required permission missing* on a perfectly valid token.
Routing the pipeline through it would produce a confidently wrong answer.

### What actually goes in the repo

```
your-repo/
├─ .github/
│  └─ workflows/
│     └─ nhi-scan.yml                ← GitHub finds this automatically
├─ scripts/
│  ├─ 00-Connect-Lab.ps1             ← for HUMANS. Not used by the pipeline.
│  ├─ 00b-Connect-Pipeline.ps1       ← what the workflow calls
│  ├─ 01-Get-NHIInventory.ps1
│  ├─ 03-New-OwnershipMap.ps1
│  └─ 05-New-ControlReport.ps1
└─ output/                            ← gitignored. See the trap below.
```

**So: is `00` required? No.** The pipeline needs `00b`, `01`, `03`, `05` and the workflow file.
Nothing else.

**Should it be there anyway? Yes** — but for a reason that has nothing to do with CI:

> **The repo is a tool other people will run.** Almost everyone who clones it will run it by hand
> against their own tenant, from a laptop, with a browser prompt. **`00` is their entry point.**
> `00b` is for the one scheduled job you happen to also run.

Ship both. The pipeline using several of them is not a
reason to publish only four.

**`.github/workflows/` is the only magic path.** Any `.yml` in there is picked up automatically —
there is nothing to register, enable or point at. Commit the file to the default branch and GitHub
starts honouring its triggers.

---

## How the exchange actually runs

```
 1. Cron fires. GitHub starts a runner.
 2. Because the workflow declares  permissions: id-token: write,
    GitHub injects two env vars into the job:
        ACTIONS_ID_TOKEN_REQUEST_URL
        ACTIONS_ID_TOKEN_REQUEST_TOKEN
 3. Your step calls that URL, asking for audience api://AzureADTokenExchange.
    GitHub returns a short-lived JWT describing the run:
        iss = https://token.actions.githubusercontent.com
        sub = repo:OWNER/REPO:ref:refs/heads/main
 4. You POST that JWT to Entra's token endpoint as a client assertion.
 5. Entra checks issuer, audience and subject against the federated
    credential you configured. All three match → it returns a Graph token.
 6. Connect-MgGraph -AccessToken  with that token. Run the scripts.
```

**Nothing is stored at any point.** The GitHub token lives minutes; the Graph token lives an hour.

---

## Entra setup — do this first, it is not optional

**The federated credential solves authentication. It does nothing for authorization.** Skip this
and you will get a token successfully, then 403 on every single Graph call.

| # | Where | What |
|---|---|---|
| 1 | App registration → **API permissions** → Microsoft Graph → **Application permissions** | `Application.Read.All`, `Directory.Read.All`, `AuditLog.Read.All`, `RoleManagement.Read.Directory` |
| 2 | Same page | **Grant admin consent.** All four require it. |
| 3 | **Certificates & secrets → Federated credentials → Add** | Issuer, subject, audience — see below |
| 4 | GitHub → Settings → Secrets and variables → Actions → **Variables** | `AZURE_CLIENT_ID`, `AZURE_TENANT_ID` |

> **Step 1 says APPLICATION permissions, not Delegated.** Same names, different objects. Delegated
> lands in `oauth2PermissionGrants`; application lands in `appRoleAssignments`. Granting the
> delegated version and expecting this to work is the most common failure here, and it fails with a
> 403 that explains nothing.
>
> **Step 2 is where people stop.** Added is not granted. The Status column saying *"Not granted for
> ‹tenant›"* is the tell, and `00b` throws a named error for exactly this case rather than letting
> you discover it as an opaque 403 three scripts later.

---

## The workflow — now four lines, because the logic is in a script

```yaml
name: NHI scan

on:
  schedule:
    - cron: '0 6 * * 1'        # Mondays 06:00 UTC
  workflow_dispatch:            # keep this — you need to run it by hand while building

permissions:
  id-token: write               # REQUIRED. Without it GitHub never mints an OIDC token.
  contents: read

jobs:
  scan:
    runs-on: ubuntu-latest
    environment: lab            # see "Pin the subject" below

    steps:
      - uses: actions/checkout@v4

      - name: Install Graph SDK
        shell: pwsh
        run: Install-Module Microsoft.Graph.Authentication, Microsoft.Graph.Applications -Force -Scope CurrentUser

      - name: Connect, then scan
        shell: pwsh
        run: |
          ./scripts/00b-Connect-Pipeline.ps1 `
              -ClientId '${{ vars.AZURE_CLIENT_ID }}' `
              -TenantId '${{ vars.AZURE_TENANT_ID }}'

          ./scripts/01-Get-NHIInventory.ps1
          ./scripts/03-New-OwnershipMap.ps1
          ./scripts/05-New-ControlReport.ps1

      - name: Fail on Critical findings
        shell: pwsh
        run: |
          $findings = Get-Content ./output/nhi_findings.json -Raw | ConvertFrom-Json
          $critical = @($findings.Findings | Where-Object { $_.TopSeverity -eq 'Critical' })

          if ($critical.Count -gt 0) {
            Write-Host "::error::$($critical.Count) Critical finding(s)"
            foreach ($c in $critical) { Write-Host "::error::  $($c.DisplayName)" }
            exit 1
          }
          Write-Host "No Critical findings."
```

**`vars.` not `secrets.`** — a client ID and a tenant ID are identifiers, not credentials. Putting
them in `secrets` implies they are sensitive and teaches the wrong lesson about what a secret is.

### What `00b-Connect-Pipeline.ps1` does

Five steps, each failing loudly with a named cause rather than a stack trace:

1. **Requests GitHub's OIDC token** — and if the env vars are missing, says *"your workflow is
   missing `permissions: id-token: write`"*, because that is what it always means.
2. **Prints the subject GitHub asserted.** When the exchange fails, the mismatch is visible right
   here. This is the most useful line of output in the whole run.
3. **Exchanges it**, and on failure surfaces Entra's own error body — which names which check failed.
4. **Decodes the returned token locally** and verifies the `roles` claim. Zero roles means consent
   was never granted, and it says so in those words.
5. **Refuses to run if it holds any write permission.** Hard stop, not a warning — see below.

### Why `00b` refuses writes where `00` only warns

`00-Connect-Lab.ps1` warns about write scopes. Correct for interactive use: a delegated token is
still bounded by the signed-in user's role, so a stray write scope is untidy rather than dangerous.

**Here there is no user and no ceiling.**

> An unattended, scheduled credential with directory write access is the exact shape of finding
> this scanner reports. **It should not describe the scanner.**

That refusal is one of the better paragraphs you will have for an interview, and it costs nothing.

---

## Pin the subject — this is the part that matters

On the app registration: **Certificates & secrets → Federated credentials → Add credential**.

| Field | Value |
|---|---|
| Issuer | `https://token.actions.githubusercontent.com` |
| Subject | `repo:OWNER/REPO:ref:refs/heads/main` |
| Audience | `api://AzureADTokenExchange` |

**The subject is the whole control.** Compare:

```
repo:n356-win/scanner:ref:refs/heads/main      one branch
repo:n356-win/scanner:environment:lab          one environment  ← strongest
repo:n356-win/scanner:ref:refs/heads/*         ANY branch       ← the vulnerability
repo:n356-win/*                                any repo you own ← worse
```

**`environment:lab` is the best of these**, because a GitHub environment can require manual approval
and restrict which branches may deploy to it. That turns the subject match into a second gate rather
than a single string comparison. It is why `environment: lab` is in the workflow above.

### The experiment — do this, it is the write-up

1. Pin to `refs/heads/main`. Run the workflow. It works.
2. **Create a branch. Run it from there.** It fails — **capture the exact error**, because it names
   what Entra compared and what it expected.
3. Widen the subject to a wildcard. Run from the branch again. **It works.**
4. Put it back.

> **Two configurations that look nearly identical in the portal, one of which lets anyone who can
> push a branch assume the identity.** Nothing leaks. Nothing alerts. The authentication succeeded
> exactly as configured.

That pair of results, with the error text, is a `TROUBLESHOOTING.md` entry and a publication
paragraph in one.

---

## The trap that would undo every guardrail in this project

**Do not upload scan output as a build artifact in a public repository.**

Build artifacts are downloadable by anyone who can see the repo. `nhi_inventory.json` and
`nhi_ownership.csv` are **real tenant data** — the exact data `.gitignore` exists to keep out.
A helpful `actions/upload-artifact` step defeats the lot, and someone else would find it before you
did.

**Two safe shapes:**

1. **Private repo** for the scheduled run. Simplest.
2. **Public workflow that runs against `samples/` fixtures** and publishes *that*. Better — it
   doubles as a working example anyone can run without a tenant.

The workflow above writes to `output/`, which is gitignored, and uploads nothing. **Keep it that
way.**

### How to implement the protection, rather than relying on remembering

**1. The default is already safe.** There is no `actions/upload-artifact` step in the workflow
above. Artifacts are opt-in — you have to add a step to leak anything. So the first control is
simply: **do not add one.**

**2. Make the repo prove it.** Add this as the last step. It fails the build if anything matching
real tenant output is sitting in the working tree where a later step could pick it up:

```yaml
      - name: Guard - no tenant data may leave this runner
        if: always()                        # runs even when the scan step failed
        shell: pwsh
        run: |
          $leaky = Get-ChildItem -Recurse -File -ErrorAction SilentlyContinue |
              Where-Object { $_.Name -match 'nhi_inventory|nhi_ownership|nhi_findings|attestation_' } |
              Where-Object { $_.FullName -notlike '*/samples/*' }

          # Anything tracked by git is a worse failure - it means .gitignore is not doing its job.
          $tracked = git ls-files | Select-String -Pattern 'output/' -SimpleMatch

          if ($tracked) {
            Write-Host "::error::Tenant output is TRACKED BY GIT. .gitignore is not working."
            $tracked | ForEach-Object { Write-Host "::error::  $_" }
            exit 1
          }
          if ($leaky) {
            Write-Host "::warning::$($leaky.Count) output file(s) present. Confirm no upload step exists."
          }
```

**3. If you ever do want an artifact, scope it to fixtures:**

```yaml
      - uses: actions/upload-artifact@v4
        with:
          name: sample-report
          path: samples/output/      # sanitised fixtures ONLY. Never output/.
```

**4. The structural fix beats all three.** Run the scheduled scan from a **private** repo and keep
the public one for the tool and sanitised samples. Then no single careless step can expose
anything, because there is nothing real in the public repo to expose.

> Controls 1–3 depend on you being careful every time. **Control 4 does not.** Prefer the one that
> does not depend on vigilance — which is the same argument this whole tool makes about credentials.

---

## The `-AccessToken` parameter on `00-Connect-Lab.ps1`

`00` gained an `-AccessToken` parameter on 22 October. **The pipeline does not use it**, and the
earlier claim here that it did was wrong.

**What it is actually good for:** running `00`'s verification against a **delegated** token you
obtained some other way, without a browser prompt.

**Where it will mislead you:** feed it an **app-only** token and `00` will report that every
required permission is missing — on a token that works perfectly. Its checks read `$ctx.Scopes`,
which comes from the `scp` claim; an app-only token has no `scp` at all, only `roles`.

> **That is not a bug to fix. It is two authentication models with two claim names.**
> It is also the precise reason `00b` carries its own verification instead of reusing `00`'s.

Both scripts handle the SDK's `SecureString`-versus-plain-string change at v2, because you do not
control which version a runner installs and discovering that at 06:00 on a Monday is a bad use of a
morning.

**Keep the parameter or remove it — your call.** It is honest now either way. The argument for
keeping it is that the failure mode above is a good thing for a reader to run into once, with the
comment right there explaining it.

---

## Why this is worth the three hours

**One artifact making two claims that reinforce each other:**

- *"I embedded an identity control into a CI/CD pipeline"* — the DevSecOps claim
- *"It holds no secret, because the control it enforces is that secrets are unnecessary"* — the
  identity claim

And **Phase 6.3 reports federated credentials as a positive finding**, so the scanner reports
approvingly on the credential that runs it. Self-referential, provable, and it costs nothing extra.

The build failing on a Critical is what makes it a control rather than a dashboard. **A report
nobody is obliged to read changes nothing.**
