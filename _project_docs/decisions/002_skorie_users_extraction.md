# 002 Extract a `skorie-users` layer between `django-users` and the hosts

# Status

proposed (2026-07-06)

# Context

`django-users` is meant to be a **generic**, reusable auth/user library:
login, registration, invitations, password reset, referrals, helpdesk glue.
It is always subclassed by a host app. In principle it should run on any
Django project, skorie or not.

In practice two problems have grown up together:

1. **`django-users` reaches into skorie's domain.** It names the host's
   `web` app and other skorie apps directly — `web.Event`, `web.EventRole`,
   `web.EventTeam`, `web.Entry`, `web.Competitor`, `web.CommsLog`,
   `web.CommsTemplate`, plus `skorie_news.*`, `skorie_payments.*`,
   `rosettes.rosette`, and `skorie.common.middleware.RequestLogMiddleware`.
   Most are deferred `apps.get_model(...)` lookups (fail only when the path
   runs), but two were module-level imports that broke `import django_users`
   outright on a non-skorie host. One (`from web.models import EventRole` in
   `serializers.py`) was already dead and has been removed; the other lives
   in `tools/api_mixins.py`, which nothing in the package imports.

2. **The skorie hosts duplicate each other, not the library.** Every skorie
   host (`skorie1`–`skorie4`, and others) ships its own concrete `users`
   app. Comparing those apps file-by-file shows they are near-copies of each
   other while bearing almost no resemblance to the `django-users` base
   (see Related Information for the similarity matrix). So there is a large
   band of *skorie-specific but cross-host-common* code — admin, signals,
   serializers, notifications, keycloak glue, and the concrete model bodies
   — that has no shared home and is maintained by copy-paste across four+
   repositories.

These are two halves of one boundary problem: `django-users` has skorie
leaking *in*, and the skorie hosts have common skorie code with nowhere to
live. We want `django-users` to be genuinely generic, and we want a single
place for the shared skorie behaviour.

The trigger for looking at this now was a `ModuleNotFoundError` (`email_validator`)
when a **non-skorie** host (`gadget_admin`) tried to install and import
`django-users` — a reminder that the library is supposed to stand alone.

## Related Decisions/Issues

- Decision 001 (Affiliate / Referral System) established the module pattern
  we lean on here: `django-users` ships **abstract** models and hooks; the
  host provides concrete subclasses and business wiring. This decision
  applies the same inversion to the skorie domain coupling.
- `CLAUDE.md` (project) — the many-long-lived-branches rule. Any change here
  must be planned against the fact that consumers pin specific branches and
  a fix must be back-ported to every active consumer branch.

## Related Information

Conversation with Dev on 2026-07-06 in which the shape below was agreed:
`django-users` stays generic; a new `skorie-users` app builds on it and
holds the common skorie functions; each host is then tidied to consume it.

**Cross-host similarity of the `users/` apps** (SequenceMatcher ratio on file
text; `1.00` = identical). skorie3/skorie4 are the current generation;
skorie1/skorie2 are an older pair. None of these files exceed ~0.25
similarity to the `django-users` base — the duplication is host-to-host:

| file | # hosts | best pair | ratio |
|---|---|---|---|
| `signals.py` | 4 | s3~s4 | 1.00 |
| `serializers.py` | 4 | s3~s4 | 1.00 |
| `apps.py` | 4 | s1~s2 | 1.00 |
| `admin.py` | 4 | s3~s4 | 1.00 (0.99 s2~s3) |
| `keycloak.py` | 3 | s1~s2 | 1.00 |
| `notifications.py` | 3 | s3~s4 | 0.98 |
| `models.py` | 4 | s3~s4 | 0.93 |
| `api.py` | 4 | s3~s4 | 0.81 |
| `views.py` | 4 | s3~s4 | 0.74 |
| `urls.py` | 4 | s1~s2 | 0.66 |
| `forms.py` | 4 | s3~s4 | 0.64 |

**Skorie coupling still inside `django-users`** (to be removed as part of
making the library generic):

- `web.*` models (deferred `apps.get_model`): `Event`, `EventRole`,
  `EventTeam`, `Entry`, `Competitor`, `CommsLog`, `CommsTemplate`.
- Other skorie apps: `skorie_news.{Newsletter,Subscription,DirectEmail}`,
  `skorie_payments.{order,Payment}`, `rosettes.rosette`.
- `tools/api_mixins.py` — top-level `from skorie.common.middleware import
  RequestLogMiddleware`; orphaned (nothing in the package imports it).
- Skorie-shaped surface: `SkorieUserCreationForm`, the Event-domain method
  block on `CustomUser` (`footprint`, `is_deleteable`, `get_current_roles`,
  outstanding-teams), the reference-code scheme in `ref.py`, and the root
  `default_roles_and_disciplines.py`.

# Change Proposed

Introduce a three-layer stack:

```
django-users     generic auth / user / invite / referral / helpdesk glue
      ▲ builds on   — NO reference to `web`, `skorie_*`, `rosettes`
skorie-users     skorie domain glue shared by every skorie host      (NEW)
      ▲ builds on
skorie1..N       only genuine per-project divergence remains
```

`skorie-users` is a new reusable app (own repo/package, installed by the
skorie hosts, itself depending on `django-users`). It absorbs the code the
hosts currently copy between each other. `django-users` is simultaneously
cleaned of skorie coupling so it satisfies its original "runs anywhere"
contract (proven by `gadget_admin` importing it with no skorie apps present).

Two shapes were considered for *where* the common skorie code should live.

# Option 1: A "skorie section" inside `django-users`

Keep everything in `django-users`, but gate the skorie-specific parts behind
feature flags / settings and optional sub-modules (e.g.
`django_users/skorie/`). Non-skorie hosts leave the flags off.

## Pros

- One repository, one release to manage.
- No new package for hosts to install.
- Shared code moves out of the hosts immediately.

## Cons

- `django-users` stays conceptually impure — it still *contains* skorie
  domain knowledge, just switched off. The "generic library" claim becomes
  "generic if you set the right flags."
- Every skorie feature change is a `django-users` release, coupling the
  generic library's cadence to skorie's product cadence.
- Flag sprawl: newsletters, payments, rosettes, event-roles each need a
  gate, and the combinations are hard to test.
- Does not give the skorie hosts a natural place for concrete skorie models
  and admin that are clearly *skorie's*, not the generic library's.

# Option 2: A separate `skorie-users` app on top of `django-users`

`django-users` becomes strictly generic (skorie coupling removed / inverted
behind hooks). A new `skorie-users` app depends on `django-users` and holds
the shared skorie behaviour. Hosts install both and subclass `skorie-users`.

## Pros

- Clean separation of concerns: generic library vs skorie domain vs host.
- `django-users` can be released and reasoned about without skorie in view;
  non-skorie hosts (`gadget_admin`) depend on it with zero dead weight.
- The shared skorie code gets a real home with its own tests and release
  cadence, decoupled from the generic library.
- Mirrors the pattern already working elsewhere (thin host over reusable
  abstract app).

## Cons

- A third layer to install and version — hosts pin two libraries, and the
  branch-topology discipline in `CLAUDE.md` now applies to two repos.
- Migration risk if `skorie-users` owns concrete models (AUTH_USER_MODEL).
- Larger up-front move than flag-gating in place.

# Decision

Go with **Option 2 — a separate `skorie-users` app on top of a
skorie-free `django-users`.**

## `django-users` cleanup (make it generic)

`django-users` must stop naming `web`, `skorie_*`, and `rosettes`. Coupling
is inverted the same way Decision 001 handled referrals:

- **Domain model lookups** → a settings-driven resolver, e.g.
  `get_domain_model('eventrole')` reading `settings.DJUSERS_DOMAIN_MODELS`
  (`{'eventrole': 'web.EventRole', ...}`); returns `None` when unwired, and
  callers guard on `None`. Replaces every hardcoded `apps.get_model('web',
  ...)` / `apps.get_model('skorie_*', ...)`.
- **Event-domain methods on `CustomUser`** (`footprint`, `is_deleteable`,
  current-roles, outstanding-teams) → a **usage-provider hook**
  (`settings.DJUSERS_USAGE_PROVIDER`, default a null provider returning
  empty). `django-users` ships the null provider; `skorie-users` ships the
  event-backed one.
- **Skorie-only forms/views/data** (`SkorieUserCreationForm`, newsletter /
  subscription / payment views, `ref.py` event-ref grammar, root
  `default_roles_and_disciplines.py`, `tools/api_mixins.py`) → move to
  `skorie-users`; `django-users` keeps only the generic base
  (`CustomUserCreationForm`) and the hook points.

## `skorie-users` scope

Absorbs the cross-host-common code (evidence in Related Information). The
non-model glue is pure code with no migration cost and is hoisted wholesale;
the models are handled conservatively (see below):

- `admin.py` — `PersonAdmin`, `CustomUserAdmin`, `RoleAdmin`,
  `CommsChannelAdmin`, `VerificationCodeAdmin`, `UserContactAdmin`,
  `OrganisationAdmin`, inlines.
- `signals.py` — `on_user_created_link_subscriptions`.
- `serializers.py` — `UserSerializer`, `UserListSerializer`.
- `notifications.py` — `on_new_user_unverified`, `on_new_user_verified`.
- `api.py` — `CheckEmail`, `MyInternalRoles`, `InternalRoleViewSet`,
  `UserListViewset`.
- `keycloak.py` — `get_access_token` and the shared keycloak glue.
- The event-domain **usage provider** and **domain-model wiring** that
  `django-users` now expects via hooks.
- The skorie forms/views/ref/roles-and-disciplines moved out of
  `django-users`.

## Models: abstract in `skorie-users`, concrete stays in the host

The concrete host models (`CustomUser`, `Person`, `Role`, `Organisation`,
`UserContact`, `CommsChannel`, `VerificationCode`, `PersonOrganisation`,
`DataQualityLog`, helpdesk links) are ~0.93 identical across hosts, so they
are the biggest dedup prize **and** the only piece carrying real risk:
changing `AUTH_USER_MODEL` on an existing production database is a migration
minefield Django is designed to resist.

Therefore, for v1:

- `skorie-users` provides **abstract bases / mixins** carrying the shared
  model body.
- Each host keeps a **thin** concrete `users/models.py` (e.g.
  `class CustomUser(SkorieCustomUserBase): pass`), so hosts keep their own
  tables and `AUTH_USER_MODEL` — **zero migration risk** — while still
  deduplicating ~90% of the body.
- Owning the concrete models in `skorie-users` (hosts drop `users/models.py`
  and point `AUTH_USER_MODEL` at `skorie_users.CustomUser`) is explicitly
  **out of scope for v1** and revisited only if a greenfield host appears.

## Sequencing (tracer bullet)

1. Land the `django-users` de-skorie-ification behind hooks (this is a
   prerequisite and can ship first; `gadget_admin` is the proof it worked).
2. Scaffold `skorie-users` (package, `apps.py`, depends on `django-users`).
3. **Tracer:** hoist the single highest-dup / lowest-risk file
   (`signals.py` or `serializers.py`) into `skorie-users`, wire **one** host
   (skorie3) to import it, delete the local copy, confirm green. Proves the
   layering end-to-end before committing to the full move.
4. Roll the rest of the glue (admin, notifications, api, keycloak).
5. Introduce the abstract model bases; convert hosts to thin subclasses one
   at a time, skorie3/skorie4 first (they are the reference generation).

## Per-host tidy-up (first pass — to be verified per repo before editing)

- **skorie3 / skorie4** — the modern pair; serve as the reference for
  `skorie-users`. After extraction their `users/` apps shrink to thin
  subclasses plus genuine locals (`middleware.py`, `api_keycloak.py` for s3;
  `hooks.py` for s4, which is on the authentik line and has no `keycloak.py`).
- **skorie2** — adopts the hoisted glue; its `keycloak.py` (identical to s1)
  moves up; local `views.py`/`urls.py` reviewed for real divergence.
- **skorie1** — the outlier and heaviest (`views.py` ~1400 lines, `api.py`
  ~514, plus `forms_custom.py` / `views_custom.py`). Biggest cleanup;
  needs the most careful per-file review — much of the bulk may be dead or
  superseded by the shared layer.

## Out of scope for v1

- `skorie-users` owning concrete models / `AUTH_USER_MODEL` swaps.
- Consolidating the hosts' `web` apps (this decision is about the `users`
  layer only).
- A declared registry of domain-model keys (start with a plain settings
  dict; formalise later if typo pain appears).

# Consequences

## Easier

- `django-users` becomes genuinely reusable — a non-skorie host installs and
  imports it with no skorie apps present.
- One place to fix and test shared skorie user behaviour instead of four
  copy-pasted `users/` apps.
- New skorie host = install `skorie-users`, add thin subclasses; no more
  copying an existing host's `users` app as a starting point.
- Generic-library and skorie-domain release cadences decouple.

## Harder

- Hosts now pin two libraries (`django-users` **and** `skorie-users`), and
  the "back-port to every active consumer branch" discipline in `CLAUDE.md`
  now spans two repositories.
- A change touching both the generic hook and its skorie implementation
  crosses a package boundary — needs coordinated releases.
- During the transition, hosts run a mix of local and hoisted code; the
  order of extraction matters to keep each host green.

## Risks

- **AUTH_USER_MODEL migration.** Mitigated by keeping concrete models in the
  hosts for v1 (abstract bases only in `skorie-users`).
- **Hidden per-host divergence** behind high similarity scores — two files
  can be 0.93 similar and differ in exactly the line that matters.
  Mitigation: a per-repo file-by-file review before deleting any host code;
  the similarity matrix guides, it does not authorise deletion.
- **Branch topology.** `django-users` has many long-lived branches; the
  de-skorie-ification must be back-ported to every active consumer branch,
  not just the one in hand. Mitigation: agree the branch scope with Dev up
  front and use worktrees (per `CLAUDE.md`).
- **Two-repo version skew.** A host on an old `django-users` with a new
  `skorie-users` (or vice-versa) could break at the hook boundary.
  Mitigation: `skorie-users` declares a minimum `django-users` version and
  the hook contract is documented in one place.

## Future work created

- Optional v2: `skorie-users` owns concrete models for greenfield hosts.
- A declared domain-model / event-name registry if stringly-typed keys bite.
- Consolidating the hosts' `web` apps (separate, larger decision).
- Applying the same hook inversion to any other domain coupling later found
  in `django-users`.

# Who is involved

| Name | Why/When |
| :---- | :---- |
| Phoebe (Dev) | Vision, approval of this decision, acceptance testing, branch-scope sign-off |
| Claude | Implementation of the de-skorie-ification and `skorie-users` scaffold, tests, docs |
| Host-app owners | Adopt `skorie-users`, convert local `users` apps to thin subclasses, delete duplicated code |
