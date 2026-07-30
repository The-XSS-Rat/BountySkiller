# Uncle Rat Doctrine

House methodology for every agent in this workspace. Derived from The XSS Rat's
published material: `Rat's methodology`, `Main app methodology`,
`HuntingCheckList.md` and the `2026 Practical Bug Bounty Guide`
(github.com/The-XSS-Rat/SecurityTesting).

Every agent reads this before acting. Where an agent's own instructions conflict
with this file, this file wins on *approach*; the agent's file wins on *mechanics*.

---

## 1. The five laws

1. **PoC or GTFO.** No working proof of concept, no report. A vulnerability with
   no demonstrated impact is noise. State what an attacker actually achieves.
2. **Out-think, don't out-race.** Speed hunters pile into the obvious endpoints
   and collect duplicates. Go for the leftovers: the bolted-on import function,
   the legacy API version, the feature nobody reads the docs for.
3. **Every tool lies sometimes.** Scanner output is a hypothesis, never a
   conclusion. Confirm manually, every time, before it becomes a finding.
4. **Know the app before you attack it.** Map it for days, not hours. Read the
   manual, the knowledge base, the API docs, the Swagger. In war, information is
   power and the manual is the blueprint.
5. **Impact is king.** Two bugs of the same class can be worlds apart in
   severity. Always ask: what can an attacker concretely do with this?

## 2. Target selection

Prefer targets that have:

- Self-service registration and free exploration of features
- **Multiple roles / privilege levels** (admin, manager, member, viewer) — this
  is where business logic and access control bugs live
- **Multi-tenant structure** (orgs, workspaces, clients)
- Import/export, webhooks, third-party login, payments — anything built *on top
  of* an existing feature. Integration points are weak points: the original
  feature is usually hardened, the add-on usually is not
- Public API docs, Swagger, OpenAPI — a blueprint handed to you
- A free tier and a paid tier — the delta between plans is a BAC goldmine

Avoid `*.target.com` wildcard scopes as a first target. Recon is not hacking; it
only tells you where to apply the methodology. Fine-tune on a main app first.

**Barriers are friends.** Dutch-only program, non-English docs, mobile-only
onboarding, a paywall: every barrier drops competitors. Push through, or buy the
paid tier — reduced surface on a free account is a real limitation.

VDP before paid. Less competition, less hardening, points convert to private
invites. The money follows the process.

## 3. Phase order

```
PHASE 1 — RECON        find the surface. Not hacking. Do not over-invest.
PHASE 2 — EXPLORE      use the app as a real user, every role, Burp open.
PHASE 3 — BURP DIVE    parameterized requests only. Tamper one thing at a time.
PHASE 4 — TEST         bug classes, cheapest and least-dupe-prone first.
CHAIN → REPORT         combine lows into highs. Prove impact. GDPR multiplier.
```

## 4. The poisoned registration

At account creation and in every editable profile field, plant the combined
XSS + SSTI vector **before** you start testing anything:

```
<img src=x onerror=alert(document.domain)>${{7*7}}{{7*7}}
```

Into username, first name, last name, company, address, bio, preferences,
filenames — everywhere. The payload then travels with you through the whole
application and may fire days later in an admin panel, a generated PDF, an email
template or a backend log viewer. Build your own variants; do not use only this
one. Register a blind-XSS callback (XSS Hunter / interactsh) so late fires are
still attributable.

## 5. The interesting-parameter rule

A parameter is interesting when it **touches business logic** — which is why
knowing the application comes first. `view=week` in a calendar is not
interesting. `PostID` on a like/unlike toggle is.

| Pattern | Test for |
|---|---|
| `url=` `src=` `dest=` `feed=` `webhook=` `callback=` `proxy=` | SSRF |
| `file=` `page=` `template=` `path=` `include=` `module=` | LFI/RFI |
| `id=` `user_id=` `order=` `invoice=` `doc=` `uuid=` | IDOR / BAC |
| `redirect=` `next=` `returnTo=` `goto=` `target=` | Open redirect |
| `q=` `search=` `name=` `title=` `comment=` | XSS / SSTI / SQLi |
| `cmd=` `exec=` `shell=` `ping=` `host=` | Command injection |
| XML body, or upload accepting SVG/DOCX/XLSX | XXE |
| Price, quantity, balance, quota, seats, coupon | Business logic |

## 6. The dupe-avoidance heuristic

Given a feature, list its requests and rank them by how *unglamorous* they are.
The Rat's own example, on a social feed:

```
POST /CreatePost   {Content=text}   ← everyone tests this. Dupes.
POST /comment      {Content=text}   ← everyone tests this. Dupes.
POST /Like         {PostID=id}      ← nobody tests this. Hunt here.
POST /Unlike       {PostID=id}      ← nobody tests this. Hunt here.
```

Send `POST /Like` to Repeater and replay it. If the counter keeps climbing, that
is a finding — and it is yours alone. Apply this ranking on every feature: the
obvious injectable text field is the crowded lane; the state toggle, the counter,
the ordering parameter and the quota check are the empty ones.

## 7. The account matrix (BAC / IDOR)

Never test access control with one account. Build all three pairs:

| Pair | Proves |
|---|---|
| Two separate accounts | Horizontal IDOR across users |
| Two users inside one account, **same** privilege | Horizontal IDOR inside a tenant |
| Two users inside one account, **different** privilege | Vertical BAC |
| Two tenants/orgs | Cross-tenant isolation |
| Anonymous | Unauthenticated access baseline |

Test **every** privilege level the app offers, and if the app lets you define a
custom role, define one and test that too. Roles may be called groups, teams or
plans — same thing.

Method: perform the action as A, capture in Burp, send to Repeater, swap the
session to B, keep A's object identifiers, observe. Then repeat per HTTP method —
`GET` may be blocked while `PUT` is not. Test the API directly: the UI hides
options the API still accepts.

**BAC is not IDOR.** Keep them separate when you test and when you report:

| | Broken Access Control | IDOR |
|---|---|---|
| Level | Function / feature | Object / record |
| Question | *May this role call this at all?* | *May this user touch this specific object?* |
| Enforced by | Application access control on the function | Ownership check on the object |
| Escalation | Vertical (lower-priv calls higher-priv function) | Horizontal (same-level user reaches another's object) |

**Build the permission matrix first.** Before testing, write out roles as columns
(normal user, sales, management, admin, custom) and actions as rows (view
invoice, edit invoice, print invoice, manage users, …). Fill in what the app
*claims* each role can do — from the docs, the UI, the role editor. Every cell
you cannot justify is a test case, and the matrix becomes the report's evidence
table. Property-level BAC (which *fields* of an object a role may write) is a
row set of its own — that is where mass assignment lives.

**Where the identifier hides.** Object references are not only in the URL. Check
all of: GET URL path and query, POST/PUT body, cookies, JWT claims, `Authorization`
and other auth headers, custom headers, OAuth tokens. A user id inside a signed
JWT still counts if the signature is weak or unverified.

**Secondary IDOR.** The identifier you tamper with may not be the one the app
looks up. Change it in one request, then read the *effect* somewhere else — an
export, a summary page, a notification. Bugs hide in the second hop.

**Method swap.** `GET /resource/{id}` blocked does not mean `PUT`, `PATCH`,
`DELETE` or `POST` on the same path is blocked. Walk every verb per endpoint.

**Manual technique ladder** (cheapest first): paste the privileged URL into a
lower-priv session → change POST variables in the page source and resubmit →
call the app's own JS functions from the browser console → intercept and replay
in Repeater with a swapped session.

**Automation, honestly rated.** Burp's **Authorize** extension is semi-automated:
it flags differences but you still interpret every one. OWASP ZAP's **Access
Control** plugin runs the fuller matrix automatically once roles are configured.
Neither replaces the manual ladder; both are for coverage, not for judgement.

**GUID amplification.** A UUID-based IDOR looks low because the ID is
unguessable. Find the endpoint that *lists or leaks* those UUIDs and the pair
becomes a complete, high-severity chain. Always hunt the leak before accepting a
low rating.

**GDPR multiplier.** On an EU target, reading another user's PII is a regulatory
violation on top of the technical bug. Say so in the report; it moves severity.

## 8. Inferring what is not shown to you

- **API version downgrade:** `/api/v2/getInvoices` implies `/api/v1/getInvoices`
  still exists, and the old one is usually less protected. Walk versions down.
- **Alternate path prefixes:** `/api/admin/`, `/internal/`, `/private/`, `/beta/`
- **HTTP method tampering:** if only `GET` is documented, try `POST`, `PUT`,
  `PATCH`, `DELETE`, and `X-HTTP-Method-Override`
- **Hidden parameters on save:** intercept any settings/profile save and add
  `role=admin`, `isAdmin=true`, `status=active`, `plan=enterprise`,
  `verified=true`. Mass assignment is found here constantly
- **JS files:** LinkFinder plus a manual read. Tools miss what a human sees
- **Disabled-by-default modules** in settings — extra surface almost nobody enabled
- **Backup files** on known paths: `.bak`, `.old`, `.zip`, `.tar.gz`

If none of these yield new surface, the target is exhausted — move on.

## 9. Burp discipline

- Scope set correctly before the first click; proxy everything
- Site map → filter → **"Show only parameterized requests"**. That filter is the
  entry point to Phase 3
- Repeater one variable at a time: change the value, remove the parameter,
  duplicate it, send the wrong type, send negative, send enormous
- Watch for *any* delta: status code, body length, error text, timing
- Intruder/ffuf for ID enumeration and rate-limit probing
- Burp Collaborator / interactsh for everything blind: SSRF, XXE, SSTI, OOB SQLi,
  blind command injection

## 10. Chains that pay

- Stored XSS in an admin-visible field → steal admin session → ATO
  (amplifier: session token that never rotates = permanent takeover)
- XSS → read the CSRF token from the DOM → full CSRF bypass
- CSRF on change-email → then trigger password reset → ATO
- Info-leak endpoint listing UUIDs → IDOR on those UUIDs → mass data access
- Open redirect → OAuth `redirect_uri` → authorization code theft
- SSRF → `169.254.169.254` metadata → cloud credentials → RCE
- Subdomain takeover → OAuth redirect target → token theft

An open redirect alone is low. An open redirect inside an OAuth flow is high.
Always ask what the finding combines with before submitting it solo.

## 11. Reporting

Title: `[Severity] Specific thing in specific place enabling specific outcome`.
Structure: Summary (2–3 sentences) → numbered Steps to Reproduce → Impact
(concrete, name the data and whose it is) → PoC (screenshot/recording/Burp
export) → optional Remediation.

Rules:
- No impact articulated = do more work before submitting
- Never write "could potentially" — prove it or drop it
- Self-XSS is out of scope unless you show a real delivery vector
- Admin-only XSS is still valid — demonstrate what admin access buys
- GDPR implications stated explicitly on EU targets
- Chain first, then report — the chained severity is the real one

## 12. Bug shapes proven in the Rat's own labs

The Bug Hunter's Blueprint labs (RatMania webshop, RatPackPark B2B/RBAC SaaS,
RatForum, RatTrack, RatPlay API, RatNews, RatBank) were built around the bugs
that actually pay. Use this as a priority list on any comparable app:

**Access control**
- Admin page reachable with no auth check at all (`rosters.php`, edit-sales page)
- Destructive action missing the admin check (`delete product`)
- Detail view unprotected while the list view is protected (`order details`)
- Cross-tenant purchase / cross-tenant record access in a multi-org app
- Admin username or role name leaked in a JS bundle, then used as the pivot

**Business logic**
- Coupon usable before its start date
- Coupon stacking to a 100% discount
- Negative quantity: ordering `-N` tickets *increases* inventory
- Numeric overflow on a quantity/price field surfacing a DB error

**Auth / tokens**
- Weak or default JWT signing secret (`change-me` class of default)
- Default bearer token left in a deployed build

**Client-side**
- Blind XSS stored in a low-visibility field (email address) that fires later in
  a privileged view (order details, admin panel)
- CSRF on edit-post style endpoints; SSRF via an upload/import URL

The pattern to internalise: the paying bug is rarely on the front page. It is on
the *second* screen of a feature — the detail view, the delete verb, the coupon
edge case, the field nobody renders in the UI.
