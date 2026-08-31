# Security Scan — Multi-Tenant Authorization Service

**Scan date:** 30 August 2026
**Scanner/operator:** Security Engineer (evidence-gathering pass, executed against the
live service); this report was written by the Documenter from the verified findings
pack, with cheap claims re-checked against the live server where noted.

**Claim under verification:** the CV/README claim of a "self-run penetration pass
(OWASP ZAP or equivalent)". The honest answer, up front: the **automated OWASP ZAP
component could not be executed** in this environment (Docker/registry network
blockage — details in [§3](#3-automated-scan-owasp-zap-not-completed)); the
substantive security evidence is a **manual reproduction pass against the live server**
for the four named threats, plus a substitute passive/probe pass, all of which are
re-runnable from the artifacts listed in [§8](#8-evidence-index). Every claim in this
document is either in the Security Engineer's findings pack, visible in the raw
artifacts, or marked as re-verified by the Documenter.

---

## 1. Scope and test environment

### Target

| Item | Value | Source |
|---|---|---|
| Service | Multi-Tenant Authorization Service (MTAS), Go/PostgreSQL RBAC + session backend | repo |
| Module | `github.com/mcchukwu/multi-tenant-authorization-service` | `go.mod` |
| Repo HEAD at scan time | `bbae28d5438d2db66ed8fb84f7a173d8e6055cd1` ("refactored: remove double health handler dependency in routes and entry", 2026-08-30; no tags) | `git log` |
| Live binary | `/tmp/opencode/mtas-sec/mtas-server`, PID 499381 — built from module version `v0.0.0-20260830121931-bbae28d5438d+dirty` with go1.26.2 | `go version -m` (re-verified by Documenter) |
| Build note | The binary carries a `+dirty` suffix: it was built from HEAD with uncommitted working-tree modifications. The exact uncommitted delta cannot be recovered from the binary. | `go version -m` |
| Base URL | `http://127.0.0.1:8080` (plain HTTP, local) | `state.json`, live checks |
| Database | Postgres 18 container `mtas-sec-pg` on `127.0.0.1:5433`; 10 tables, all migrations applied; server↔DB wiring confirmed empirically | `docker ps` + psql (re-verified by Documenter) |

### Seed state (created via real HTTP, not DB injection)

Seed data was built through the public API (`seed.sh`): five users — **owner, admin,
member, viewer, outsider** — each with their own personal org, plus one business org:

- **Acme Corp:** `86ff6b42-1623-4dac-aed6-c49aa9d73c88` (type `business`;
  name re-verified by Documenter via a fresh owner login; the seed appends a timestamp,
  so the stored name is "Acme Corp `<ts>`").
- admin/member/viewer were added to Acme Corp through the **real invite + accept flow**
  (not direct inserts).

Post-seed row counts measured by the Security Engineer: **5 users, 6 orgs, 9
memberships, 5 sessions, 3 invitations.** Note: the verification scripts themselves
register additional throwaway users/sessions, so the DB has grown since seeding — at
the Documenter's check the counts were 13 users / 14 orgs / 17 memberships / 28
sessions / 6 invitations, all attributable to the pass's own test rows.

### Verification trail (what is in this report)

- **Security Engineer findings pack** — authoritative; every substantive claim in this
  report comes from it.
- **Raw artifacts** — per-request `.status` / `.body` / `.hdr` files (listed in
  §8); the Documenter read the ones cited here.
- **Re-verified by Documenter** (cheap checks only): `/health/ready` returns
  `200 {"success":true,"message":"service ready"}`; PID/process and binary build info;
  `mtas-sec-pg` container; Acme Corp org name/type via fresh login; DB table/row counts;
  and the specific artifact files cited below.
- **Not re-run by the Documenter**: the full verification pass, the ZAP attempts, and
  DB inspection queries (family revocation, audit entries) — those remain the Security
  Engineer's evidence.

---

## 2. Executive summary

**Verdict: the four named threats all hold under live reproduction — no cross-tenant
data breach was found — and the known defects are LOW–MED correctness/integrity gaps,
none of which is a cross-tenant privilege-escalation or data-exfiltration path.**
(Severity assessments are the Security Engineer's.)

| # | Threat | Result | Primary evidence (artifacts + integration test) |
|---|---|---|---|
| T1 | Session fixation | **HELD** (structurally) | `t1a_*`, `t1b_*`, `t1c_*`; `TestAuthLifecycle_RegisterLoginRefreshLogout` (no dedicated fixation test — caveat below) |
| T2 | CSRF on `POST /v1/auth/refresh` | **HELD** | `t2_noheader`, `t2_wronghdr`, `t2_match`; `TestAuthRefresh_CSRFEnforcement` |
| T3 | Token replay → whole-family revocation | **HELD** | `t3_replay`, `t3_gen2`, `t3_acc2` + DB/audit inspection; `TestAuthRefresh_ReplayRevokesWholeFamily` |
| T4 | IDOR / tenant isolation | **HELD** | `t4_del_outsider` vs `t4_del_random`, `t4_get_orga` vs `t4_get_random`, `t4_get_orgb`, `t4_member_del`; `TestIDOR_CrossOrgMemberDeleteIs404`, `TestNonMemberOrgAccess`, `TestCrossOrgIsolation_ListIsScopedToOrg` |

**The automated component did not run.** OWASP ZAP could not be brought up in this
environment (~50 minutes of attempts across 4 routes; Docker Hub pull wedged, GHCR
mirror TLS timeout, mirror registries unreachable, no Java and no sudo for a native
install, ~16 h projected for a manual ZAP tar at ~8 KB/s — see §3). **There are no ZAP
severity counts and no ZAP finding list, and this report does not fabricate any.** The
scanner-equivalent evidence is the manual pass (§4) plus a classified passive/probe
pass (§5, findings F1–F11) that substituted for the scanner: ten of eleven probe
findings were false positives or notes; **one real issue — F7/K6, trust of
`X-Forwarded-For` for rate-limit keys** — is a deployment-config risk and the top
operational recommendation (§7).

**Known defects (K1–K6):** K1–K5 were **fixed after this scan** in the working tree —
registration without `last_name` → 201 (`users.last_name` is nullable), duplicate
invite accept → `409 already_member`, personal orgs → `409 personal_workspace`,
owner-only `AssignRole` in both directions → `403 owner_action_restricted`, and
suspended-user login → `403 user_suspended` (`ErrUserSuspended` now mapped in
`response.HandleError`). The fixes were verified by source inspection during the
documentation reconciliation (not re-run live). Still open: XFF trust for rate-limit
keys (MED, deployment-dependent). Detail in §6.

**Caveats a reviewer must see:** (a) the automated ZAP component is **not** part of the
evidence — the pass is manual verification plus substitute passive/probe; (b) the raw
evidence lives outside the repo in `/tmp/opencode/mtas-sec-r2/` (this document links
it; the repo itself deliberately contains no scan artifacts); (c) there is no dedicated
session-fixation test in the repo — the property holds structurally because no code
path accepts client-supplied session state (§4.1).

---

## 3. Automated scan: OWASP ZAP — NOT COMPLETED

Reported honestly, per the accuracy rules of this contract: **the automated ZAP
component was attempted and failed; no ZAP output of any kind exists.**

### What was attempted

1. **Docker image `zaproxy/zap-stable`** (`docker run --network host ... zap-baseline.py
   -t http://127.0.0.1:8080 -o openapi.yaml ...`). The prepared launcher is preserved at
   `/tmp/opencode/mtas-sec-r2/zap/run_zap.sh` with the target OpenAPI snapshot
   `/tmp/opencode/mtas-sec-r2/zap/openapi-8080.yaml` — but no baseline run ever started.
2. **GHCR mirror `ghcr.io/zaproxy/zaproxy:stable`** — TLS handshake timeout.
3. **Native install** — blocked: no Java runtime and no sudo in the environment.
4. **Manual ZAP distribution download** — projected ~16 h at the observed ~8 KB/s
   transfer rate; abandoned.

### Why it failed

The Docker daemon could not reach the registries: the `zaproxy/zap-stable` pull wedged
on one base layer (daemon could not fetch it), and the GHCR mirror timed out at the TLS
handshake. Pull logs, in chronological order (evidence that the attempts are real):

- `/tmp/opencode/zap-pull.log` (16:19, empty — first attempt)
- `/tmp/opencode/zap-pull2.log`, `zap-pull3.log`, `zap-pull4.log`, `zap-pull5.log`,
  `zap-pull6.log` (16:44–19:57, wedged layer pulls)
- `/tmp/opencode/zap-pull-ghcr.log` (19:47, `net/http: TLS handshake timeout` against
  GHCR)

### Consequence

**No ZAP severity counts, no ZAP finding list, no ZAP report exist. This document
contains no fabricated ZAP numbers.** The claims in §4 and §5 stand on manual
verification and the substitute passive/probe pass.

### What a future run requires

- An environment where Docker Hub (or a mirror) is reachable, **or** a machine with the
  `zaproxy/zap-stable` image pre-seeded (`docker image` present locally, no pull), **or**
  a Java runtime + permissions for a native ZAP install. The prepared launcher
  `run_zap.sh` (unauth and auth modes, `-J` JSON + `-r` HTML reports, WARN alert level)
  is ready to run as-is once an image is available.

---

## 4. Manual verification of the four named threats (the core evidence)

All steps below were executed by the Security Engineer against the live server with
real curl requests; the raw response files are cited per step. Each subsection gives
the reproduction in curl-level terms, the observed result, and the verdict. The
integration tests that cover the same behavior are cited by exact name.

---

### 4.1 Threat 1 — Session fixation — **HELD (structurally)**

**Attack model:** attacker forces a victim's session identifier to a value the attacker
knows, then the victim logs in and the attacker's value becomes the authenticated
session.

**Why it holds:** session tokens are 256-bit `crypto/rand` opaque values, stored only as
SHA-256 hashes (`internal/auth/tokens.go`, `internal/auth/repository.go`). Every
login/register mints a session with a **fresh `token_family_id`**; no endpoint accepts
any session identifier from the client, so there is no client-supplied session state
for an attacker to fix.

**Reproduction (from `verify_threat1_fixation.sh`):**

```bash
# T1.a — attacker pre-sets both cookies to a known value, then tries to refresh:
curl -s -o t1a_pre.body -w 'STATUS:%{http_code}\n' -X POST $BASE/v1/auth/refresh \
  -H "Cookie: refresh_token=$ATT; csrf_token=$ATT" -H "X-CSRF-Token: $ATT"
# -> 401 invalid_token (no session adopts the attacker's value)

# T1.a2 — victim logs in WHILE presenting the attacker's pre-set cookie:
curl -s -D t1a_login.hdr -o t1a_login.body -w 'STATUS:%{http_code}\n' \
  -X POST $BASE/v1/auth/login -H "Cookie: refresh_token=$ATT; csrf_token=$ATT" \
  -d '{"identifier":"<owner email>","password":"..."}'
# -> 200, and the server issues a NEW refresh_token that differs from $ATT
#    (attacker's value is never adopted)

# T1.a3 — attacker's pre-set value is still dead after the victim logged in:
curl -s -o t1a_post.body -w 'STATUS:%{http_code}\n' -X POST $BASE/v1/auth/refresh \
  -H "Cookie: refresh_token=$ATT; csrf_token=$ATT" -H "X-CSRF-Token: $ATT"
# -> 401 invalid_token

# T1.b — logout kills the access token with NO expiry grace:
# register -> 200; logout -> 204; same access token on GET /v1/me/organizations -> 401

# T1.c — register + two logins = 3 sessions, exactly one "current", 3 distinct
# token_family_ids (confirmed in DB via docker exec psql on mtas-sec-pg)
```

**Observed results (artifacts):** `t1a_pre.status` 401, `t1a_login.status` 200 (server
issued a token different from the attacker's), `t1a_post.status` 401, `t1b_logout.status`
204, `t1b_after.status` 401, `t1c_sessions.status` 200 with exactly one `current:true`.

**Verdict: HELD.** Caveat recorded by the Security Engineer and confirmed here: **there
is no dedicated session-fixation test in the repo.** The property is covered indirectly
by `TestAuthLifecycle_RegisterLoginRefreshLogout` (fresh token per login, two live
sessions with exactly one `current`, post-logout rejection) and holds because no code
path accepts client-supplied session state.

---

### 4.2 Threat 2 — CSRF on `POST /v1/auth/refresh` — **HELD**

**Attack model:** a malicious site makes the victim's browser send a state-changing
request that carries the victim's cookies automatically.

**Why it holds:** `/v1/auth/refresh` is the only cookie-authenticated state change, and
it is protected by a **double-submit cookie** check (`verifyCSRF`,
`internal/auth/cookies.go`): the `X-CSRF-Token` header must equal the `csrf_token`
cookie (compared with `subtle.ConstantTimeCompare`), and the check **runs before any
token validation**. Cross-site JavaScript cannot read the cookie, so it cannot produce
the matching header.

**Reproduction (from `verify_threat2_csrf.sh`):**

```bash
# Get a session (register/login), capture cookies to a jar.

# 1. Valid refresh_token cookie, NO X-CSRF-Token header:
curl -i -b jar.txt -X POST $BASE/v1/auth/refresh
# -> 403 {"success":false,"error":{"code":"csrf_check_failed","message":"CSRF validation failed"}}

# 2. Cookie + WRONG header value:
curl -i -b jar.txt -X POST $BASE/v1/auth/refresh -H 'X-CSRF-Token: definitely-not-the-cookie'
# -> 403, code csrf_check_failed

# 3. Cookie + MATCHING header (csrf_token read from the jar):
curl -i -b jar.txt -X POST $BASE/v1/auth/refresh -H "X-CSRF-Token: <value from jar>"
# -> 200, rotation, both cookies re-issued
```

**Observed results (artifacts):** `t2_noheader.status` 403 / body
`csrf_check_failed`; `t2_wronghdr.status` 403 / body `csrf_check_failed` (byte-identical
to the no-header body); `t2_match.status` 200. Header evidence in `t2_match.hdr`
(re-verified by Documenter): re-issued cookies carry `Path=/v1/auth`, `Secure`,
`SameSite=Strict`, and `HttpOnly` on `refresh_token` only (the `csrf_token` cookie is
JS-readable by design — that is what makes double-submit work).

**Verdict: HELD.** Also covered by `TestAuthRefresh_CSRFEnforcement` (no header → 403,
wrong header → 403, matching → 200).

---

### 4.3 Threat 3 — Token replay → whole-family revocation — **HELD**

**Attack model:** a stolen refresh token is used to mint access tokens indefinitely;
replay after logout/rotation is treated as the same class of attack.

**Why it holds:** refresh tokens rotate on every use, and presenting an already-revoked
token triggers **family revocation**: every session sharing the `token_family_id` is
revoked — including the legitimate rotated one — and the event is written to the audit
log as `token.replay_detected` with the family ID. Access tokens are DB-backed rows
(SHA-256 hashes), so a revoked family's access tokens stop working immediately.

**Reproduction (from `verify_threat3_replay.sh`):**

```bash
# 1. login (gen1): capture cookies + access token
curl -s -c jar1.txt -X POST $BASE/v1/auth/login ...            # -> 200 (t3_login)

# 2. refresh once (gen2): both cookies rotate
curl -s -c jar2.txt -b jar1.txt -X POST $BASE/v1/auth/refresh \
  -H "X-CSRF-Token: <gen1 csrf>"                              # -> 200 (t3_ref1)

# 3. replay the gen1 refresh token (gen1 cookie pair)
curl -i -b jar1.txt -X POST $BASE/v1/auth/refresh \
  -H "X-CSRF-Token: <gen1 csrf>"
# -> 401 {"success":false,"error":{"code":"invalid_token",...}}   (t3_replay)

# 4. THE KEY ASSERTION — the LEGITIMATE gen2 refresh token is dead too:
curl -i -b jar2.txt -X POST $BASE/v1/auth/refresh \
  -H "X-CSRF-Token: <gen2 csrf>"
# -> 401 invalid_token                                              (t3_gen2)

# 5. the gen2 access token no longer authenticates:
curl -s -H "Authorization: Bearer <gen2 access>" $BASE/v1/me/organizations
# -> 401                                                          (t3_acc2)
```

**Observed results (artifacts):** `t3_login.status` 200 → `t3_ref1.status` 200 →
`t3_replay.status` 401 (`invalid_token`) → `t3_gen2.status` 401 (`invalid_token`, family
revocation) → `t3_acc2.status` 401. Security Engineer's DB/audit inspection of
`mtas-sec-pg` at the time of the pass: **both family sessions `revoked=true` with
`revoked_at` set, an unrelated session in a different family still active**, and **two
`token.replay_detected` audit entries carrying the family ID** (audit-log evidence is
from the pass's psql inspection, not from a standalone artifact file).

**Verdict: HELD.** Also covered end-to-end by `TestAuthRefresh_ReplayRevokesWholeFamily`
(the exact sequence above, including the family-revocation assertion) and partially by
`TestAuthLifecycle_RegisterLoginRefreshLogout` (post-logout revocation) and
`TestInviteFlow_SingleUseToken` (single-use invitation tokens).

---

### 4.4 Threat 4 — IDOR / tenant isolation — **HELD**

**Attack model:** an authenticated user reaches another tenant's resources by
substituting IDs (org, member, role, invitation).

**Why it holds:** the `Authz` middleware gates **every** `{org_id}` route before any
handler runs; repositories pair `(id, organization_id)` in every org-scoped lookup; and
error handling collapses so that a **foreign target and a nonexistent target return
byte-identical responses** (anti-enumeration). Every decision — allowed and denied — is
recorded to `authz_decisions` (`allowed=false, reason="role lacks permission"` on the
denials below).

**Reproduction (from `verify_threat4_idor.sh`; owner of Acme Corp, outsider = a real
user with an unrelated personal org):**

```bash
# A. owner of org A deletes a user who EXISTS but is not a member of A:
curl -i -X DELETE $BASE/v1/orgs/$ORG_A/members/$OUTSIDER_ID \
  -H "Authorization: Bearer $TOKEN_O"
# -> 404 {"success":false,"error":{"code":"membership_not_found","message":"membership not found"}}

# B. a random UUID gets the IDENTICAL response:
curl -i -X DELETE $BASE/v1/orgs/$ORG_A/members/$RANDOM_UUID \
  -H "Authorization: Bearer $TOKEN_O"
# -> 404, code membership_not_found, same message   (byte-identical body)

# C. control: deleting a REAL member succeeds:
curl -i -X DELETE $BASE/v1/orgs/$ORG_A/members/$REAL_MEMBER \
  -H "Authorization: Bearer $TOKEN_O"
# -> 204

# D. non-member (outsider) tries GET on the real org A and on a random org;
#    the owner of A tries GET on the outsider's personal org B:
curl -i -H "Authorization: Bearer $TOKEN_X" $BASE/v1/orgs/$ORG_A      # -> 403
curl -i -H "Authorization: Bearer $TOKEN_X" $BASE/v1/orgs/$RANDOM_ORG # -> 403
curl -i -H "Authorization: Bearer $TOKEN_O" $BASE/v1/orgs/$ORG_B      # -> 403
# the first two bodies are byte-identical (foreign vs nonexistent org are
# indistinguishable to a non-member); the owner is equally blocked from B
```

**Observed results (artifacts, bodies re-verified by Documenter):**

| Request | Artifact | Status | Body |
|---|---|---|---|
| DELETE member = outsider (exists, other org) | `t4_del_outsider` | 404 | `membership_not_found` |
| DELETE member = random UUID | `t4_del_random` | 404 | `membership_not_found` — **byte-identical to the above** (`cmp -s` in the script) |
| DELETE member = real member (control) | `t4_member_del` | 204 | — |
| GET org A by non-member (outsider) | `t4_get_orga` | 403 | `forbidden` |
| GET random org UUID by non-member | `t4_get_random` | 403 | `forbidden` — **byte-identical to the above** |
| GET outsider's personal org B, by owner of A | `t4_get_orgb` | 403 | `forbidden` — same collapse for a valid-but-foreign org |

The Security Engineer additionally confirmed via psql that the `authz_decisions` trail
records each denial (`allowed=false`, reason `role lacks permission`).

**Verdict: HELD.** Also covered by `TestIDOR_CrossOrgMemberDeleteIs404` (foreign user
and random UUID indistinguishable), `TestNonMemberOrgAccess` (foreign org and random org
identical 403s, incl. PATCH), `TestCrossOrgIsolation_ListIsScopedToOrg`,
`TestInviteFlow_SingleUseToken` (foreign role ID collapses to 404), and
`TestRemoveMember_TakesEffectImmediately`.

---

## 5. Substitute passive/probe findings (scanner-equivalent; classified)

Because the ZAP baseline could not run, the Security Engineer executed a manual
passive/probe sweep of the same attack classes a scanner would flag, against the live
server, and classified each result. Classification is the Security Engineer's.

| ID | Probe / check | Result | Classification & reasoning |
|---|---|---|---|
| F1 | HSTS over plain HTTP | Header present (`Strict-Transport-Security: max-age=63072000; includeSubDomains`) on every response, including plain-HTTP ones | **NOTE / hardening.** Inert over HTTP in dev; correct and active once served over HTTPS. Nothing to fix in code; deployment must serve TLS. |
| F2 | `X-XSS-Protection: 1; mode=block` | Header present | **FALSE POSITIVE** (obsolete header; modern browsers ignore it, and it is noise for a pure JSON API). |
| F3 | Health endpoints bypass middleware stack | `/health`, `/health/live`, `/health/ready` registered on a separate mux | **FALSE POSITIVE / accepted by design.** Static responses, no sensitive data, documented architecture (README). |
| F4 | CORS preflight for disallowed origins | Disallowed origin receives **no** `Access-Control-Allow-Origin` → browser blocks; allowlisted origin works | **FALSE POSITIVE.** CORS only reflects explicitly allowlisted origins; never `*` with credentials. |
| F5 | Reflected-XSS / CSP / clickjacking class | Pure JSON API; no HTML rendering; `X-Content-Type-Options: nosniff`; `X-Frame-Options: DENY`; CSP `default-src 'none'; frame-ancestors 'none'` (all re-verified in `t2_match.hdr`) | **FALSE POSITIVE.** No injection surface for reflected XSS; clickjacking blocked at header level. |
| F6 | SQL/command injection, SSRF, template injection, open redirect, path traversal | All SQL parameterized via pgx `$n` placeholders; no `os/exec`; no outbound HTTP; no templates; no file serving; `..%2f` in `{org_id}` inert | **FALSE POSITIVE.** None of these classes has a reachable sink. |
| F7 | Rate-limit key spoofing via `X-Forwarded-For` | **REAL ISSUE + accepted risk (deployment-config).** Fixed spoofed XFF → 429 `rate_limited` after burst (artifact `bonus_429.body` + `verify_bonus_ratelimit.sh`, re-verified by Documenter); rotating XFF per request → 12/12 pass (reported by Security Engineer; no standalone artifact) | **REAL ISSUE.** Weakens brute-force protection on auth routes in direct-to-server deployments (rate limiter keys on `ClientIP`, which prefers XFF). Org-keyed limiter unaffected; data isolation unaffected. Fix: overwrite (not append) XFF at a trusted proxy, or key on `RemoteAddr`. Same root cause as K6. |
| F8 | Access token in query string | Not honored — token in query string → 401 | **HELD** (defense: tokens only accepted via `Authorization` header). |
| F9 | Unknown route / method; TRACE | Unknown route → 404, unknown method → 405, `TRACE` → 405 | **HELD.** No route leakage or server-info disclosure. |
| F10 | Cookie flags | `refresh_token`: `Path=/v1/auth; HttpOnly; Secure; SameSite=Strict`; `csrf_token`: `Path=/v1/auth; Secure; SameSite=Strict` (JS-readable by design) | **HELD.** Verified live; flags re-verified by Documenter in `t2_match.hdr`. |
| F11 | `X-Request-ID` exposure | Request ID appears in the `X-Request-Id` response header only — not in the response body | **NOTE.** No information leak; header-only is standard practice. |

**Bottom line (Security Engineer):** ten of eleven probes are false positives or notes;
the single real finding is F7 (== K6), a deployment-configuration issue with no impact
on data isolation.

---

## 6. Known defects — security assessment

All six were **reproduced live at scan time** against the then-current build
(`verify_known_defects.sh`). K1–K5 have since been **fixed in the working tree**; the
fixes were verified by source inspection during the documentation reconciliation (and
are covered by the updated integration suite) but were not re-run live. K6 remains as
documented. Severities are the Security Engineer's original assessments.

| ID | Defect | Status (current) | Severity (as assessed) | Original evidence & impact |
|---|---|---|---|---|
| K1 | Registration without `last_name` → 500 | **FIXED.** `users.last_name` is now nullable (`migrations/000001`); an omitted `last_name` is stored as NULL and registration returns 201. | **LOW** | Original: `k1_nolastname` → **500** `internal_server_error` for a well-formed request; no security impact beyond a bad status code. `TestRegisterWithoutLastName_Succeeds` now asserts the success path. |
| K2 | Accepting a duplicate invite (already a member) → 500 | **FIXED.** `CreateMembership` translates the memberships `UNIQUE(user_id, organization_id)` violation (pg 23505) to `ErrAlreadyMember` → **409 `already_member`**. | **LOW-MED** | Original: `k2_accept2` → **500** `internal_server_error`. Correctness defect, no escalation; the intended code was already defined but unmapped. |
| K3 | Personal orgs accept members | **FIXED.** `Service.Invite` blocks `personal` orgs before creating any invitation row → **409 `personal_workspace`**. | **MED** (authorization-relevant) | Original: `k3_invite_personal` → **201** (invite into the owner's personal org succeeded). Breaks the "personal = solo workspace" invariant; inviting still required owner permission — **not** cross-tenant escalation. |
| K4 | Non-owner admin can demote a non-last owner | **FIXED.** `AssignRole` applies the owner-action restriction in both directions (granting *and* revoking owner status) → **403 `owner_action_restricted`**; the last-owner guard (`409 last_owner`) remains. | **MED** (integrity gap) | Original: `k4_demote` → **204** (admin demoted a co-owner to viewer). No privilege escalation (an admin cannot gain owner powers); the last-owner guard already prevented ownerless orgs. |
| K5 | Suspended-user login → 500 | **FIXED.** `response.HandleError` now maps `ErrUserSuspended` (returned by `Login` for any `status != 'active'` account) to **403 `user_suspended`**. | **LOW** | Original: `k5_login` → **500** `internal_server_error`. From the outside it was indistinguishable from a broken login (safe but sloppy); the correct behavior is now a distinct, explicit 403. `TestLogin_SuspendedUserReturns403` asserts the fix. |
| K6 | XFF trust for rate-limit keys | **ACCEPTED RISK (deployment-config).** Unchanged — `utils.ClientIP` prefers `X-Forwarded-For`; spoofable when the server is exposed directly and/or behind a proxy that appends to XFF. | **MED** (deployment-dependent) | Same evidence as F7: fixed XFF → 429 after burst; rotating XFF → passes. Weakens brute-force protection on auth routes only. |

**Security Engineer's bottom line (scan time):** none of K1–K6 is a cross-tenant data
breach; all were LOW–MED correctness/integrity gaps, and each was consistent with the
residual risks documented in THREAT_MODEL.md. The authorization-relevant ones (K3, K4)
were invariant violations, not escalation paths. With K1–K5 fixed, both invariants and
the suspended-login error mapping are now enforced in code; the remaining item is the
K6 deployment-config risk (MED).

---

## 7. Residual risks & recommendations (ranked)

Ranked by the Documenter from the Security Engineer's findings; the fix for #1 is the
Security Engineer's top operational recommendation. The scan-time recommendations for
K3, K4, K1/K2, and K5 have since been implemented in the working tree (see §6); the
remaining items are:

1. **Fix XFF trust for rate limiting (F7 / K6 — MED, deployment-dependent).** Highest
   priority because it is the only real issue found. Two deployment-level fixes, either
   is sufficient: (a) at any trusted reverse proxy, **overwrite** `X-Forwarded-For`
   rather than append, or (b) key the auth-route limiter on `RemoteAddr` behind a
   single trusted proxy. Data isolation is unaffected either way.
2. **Serve over TLS (F1 — hardening note).** HSTS is already emitted; it only becomes
   meaningful once the service is served over HTTPS. No code change needed.
3. **Add a dedicated session-fixation test.** The property holds structurally, but the
   repo has no test that asserts "client-supplied session state is never adopted" — a
   regression guard for the *absence* of a code path (T1 caveat).
4. **Re-run the automated ZAP baseline where the image is reachable.** Use the prepared
   `run_zap.sh` launcher in an environment with Docker Hub access or a pre-seeded
   `zaproxy/zap-stable` image (§3). Until then, the manual pass + substitute probes
   remain the security evidence.

---

## 8. Evidence index

### Raw evidence — `/tmp/opencode/mtas-sec-r2/` (Security Engineer's current pass)

| Artifact | Contents |
|---|---|
| `seed.sh` | Seed script: 5 users, 6 orgs, Acme Corp `86ff6b42-1623-4dac-aed6-c49aa9d73c88`, invite+accept joins, via real HTTP |
| `state.json` | Post-seed state: tokens, user IDs, org IDs, role IDs (tokens expired after the 10-min access TTL — use `seed.sh` to regenerate) |
| `verify_threat1_fixation.sh` | T1 session fixation — pre-set cookie, logout, two-login/family checks |
| `verify_threat2_csrf.sh` | T2 CSRF — no header / wrong header / matching header |
| `verify_threat3_replay.sh` | T3 token replay — rotation → replay → family revocation |
| `verify_threat4_idor.sh` | T4 IDOR — cross-org delete, random UUID, non-member GETs, control |
| `verify_known_defects.sh` | K1–K5 reproduction at scan time (pre-fix; K1–K5 have since been fixed in the working tree — see §6) |
| `verify_bonus_ratelimit.sh` | Fixed-XFF burst → 429 `rate_limited` (artifact `bonus_429.body`) |
| `t1a_*`, `t1b_*`, `t1c_*` | Threat-1 `.status` / `.body` / `.hdr` files (401/200/401/204/401 sequences) |
| `t2_*` | Threat-2 files, incl. `t2_noheader.hdr` / `t2_wronghdr.hdr` (403 + headers) and `t2_match.hdr` (200, cookie flags) |
| `t3_*` | Threat-3 files (200 → 200 → 401 → 401 → 401) |
| `t4_*` | Threat-4 files (404/404/204, 403/403/403) |
| `k1_*` … `k5_*` | Known-defect files at scan time (K1/K2/K5 500s, K3 201, K4 204 — pre-fix behavior for K1–K5) |
| `bonus_429.body` | Rate-limit 429 response body |
| `zap/run_zap.sh`, `zap/openapi-8080.yaml` | Prepared (never executed) ZAP launcher + target OpenAPI snapshot |

### ZAP failure evidence — `/tmp/opencode/zap-pull*.log`

`zap-pull.log` … `zap-pull6.log` (wedged `zaproxy/zap-stable` layer pulls, 16:19–19:57)
and `zap-pull-ghcr.log` (GHCR `TLS handshake timeout`, 19:47). These are the proof that
the automated component was attempted and blocked by registry reachability.

### Not to be cited

`/tmp/opencode/mtas-sec/` is the **historical/superseded** pass — its tokens are dead;
its artifacts must not be cited as evidence for this report. (Note: the currently
running server binary happens to live at `/tmp/opencode/mtas-sec/mtas-server`; that is
a build of HEAD commit `bbae28d` per `go version -m` — binary location is irrelevant to
evidence validity.)

### How a reviewer can re-run the verification

**Option A — live-server reproduction (same method as this pass):**

```bash
# 1. Start Postgres + server (any APP_PORT; scripts use 8080):
docker run --name mtas-sec-pg -p 127.0.0.1:5433:5432 -e POSTGRES_USER=mtas \
  -e POSTGRES_PASSWORD=mtas -e POSTGRES_DB=mtas -d postgres:18
for f in migrations/*.up.sql; do
  docker exec -i mtas-sec-pg psql -U mtas -d mtas < "$f"
done
APP_PORT=8080 go run ./cmd &      # or run the built binary

# 2. Seed and verify (from /tmp/opencode/mtas-sec-r2/):
./seed.sh                        # rebuild the 5-user / Acme Corp fixture
./verify_threat1_fixation.sh     # T1
./verify_threat2_csrf.sh         # T2
./verify_threat3_replay.sh       # T3
./verify_threat4_idor.sh         # T4
./verify_known_defects.sh        # K1–K5 (reproduces the PRE-fix behavior for K1–K5)
./verify_bonus_ratelimit.sh      # F7 fixed-XFF 429
# Inspect the *.status / *.body files each script writes. On the scan-time build a
# clean pass reproduces the status codes tabulated in §4 and §6; against the current
# tree, the K1–K5 steps return the fixed codes (201 / 409 / 409 / 403 / 403) instead.
```

The scripts assume `mtas-sec-pg` on 127.0.0.1:5433 with user/password/db `mtas` (the
DB verification steps use `docker exec mtas-sec-pg psql -U mtas -d mtas`), and each
throws fresh throwaway rows (users, sessions) into the DB.

**Option B — in-repo integration suite** (no external artifacts needed; covers the same
behaviors end-to-end against a throwaway `postgres:18` container):

```bash
go test ./integration/...
```

Specifically: `TestAuthLifecycle_RegisterLoginRefreshLogout` (T1), 
`TestAuthRefresh_CSRFEnforcement` (T2), `TestAuthRefresh_ReplayRevokesWholeFamily`
(T3), `TestIDOR_CrossOrgMemberDeleteIs404` / `TestNonMemberOrgAccess` /
`TestCrossOrgIsolation_ListIsScopedToOrg` / `TestInviteFlow_SingleUseToken` (T4),
`TestPersonalOrgInvariants` / `TestOwnerActionRestricted` /
`TestRegisterWithoutLastName_Succeeds` (K1/K3/K4; the K1 test now asserts the success
path), and
`TestRateLimiting_OrgRouteBurst` / `TestRateLimiting_IsKeyedPerIP` (rate limiting).
The integration suite skips gracefully if Docker is unavailable.

---

## Unverified / uncertain items (explicit)

- **No ZAP output exists** — severity counts, finding lists, and the baseline reports
  were never produced; the launcher prepared for them never ran (§3).
- **The `+dirty` build delta** between the live binary and HEAD commit `bbae28d` is
  unknown; it cannot be recovered from the binary.
- **Audit-log and family-revocation DB rows** (T3) were inspected by the Security
  Engineer during the pass via psql; they are not preserved as standalone artifact
  files and were not re-inspected by the Documenter.
- **The rotating-XFF result (12/12 pass, F7)** was observed during the pass but has no
  standalone artifact; only the fixed-XFF 429 path has one (`bonus_429.body`).
- **Post-seed row counts** (5/6/9/5/3) are the Security Engineer's measurement taken
  immediately after seeding; the DB has since accumulated the pass's own test rows.
- **The K1–K5 fixes** (see §6) were verified by source inspection during the
  documentation reconciliation and are covered by the updated integration suite; they
  were **not** re-run live against the service.
