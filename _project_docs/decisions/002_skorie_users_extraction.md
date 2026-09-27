# 002 A skorie layer between the generic `django-users` and the skorie hosts

# Status

**Accepted in revised form, 27Sep26: one repo, one package.** The skorie
layer is the `django_users.skorie` subpackage, on the same trunk as the
generic code (decision 003). Hosts opt in by **inheriting its mixins**, not by
installing a second library or setting feature flags. Nothing is built yet.

Proposed 2026-07-06 as a separate `skorie-users` package (Option 2 below). That
choice is **corrected in place, not superseded**: see *History*. Wherever this
document or 002a says "`skorie-users`", read "the `django_users.skorie`
subpackage".

# History

| Date | What changed | Why |
| :--- | :--- | :--- |
| 6Jul26 | Proposed: separate `skorie-users` package on a skorie-free `django-users` (Option 2). A skorie section inside `django-users` (Option 1) was rejected, mainly for its feature flags | The library reached into skorie's models; the hosts copied a shared band of skorie code between them |
| 27Sep26 | **Option 1 reshaped and adopted: one repo, one package, `django_users.skorie` opted into by mixins.** Inheritance preferred over settings hooks | Dev. Mixins are opt-in by the host's own class definition, which removes the flag sprawl that sank Option 1. A second package would double the branch-and-pin cost that decision 003 exists to remove, and a change crossing the generic/skorie seam would need two coordinated commits in two repos |

Detail is in git: `git log --follow _project_docs/decisions/002_skorie_users_extraction.md`.

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
holds the common skorie functions; each host is then tidied to consume it. *(Revised 27Sep26: the skorie layer is a subpackage of `django-users`, not a separate app — see History.)*

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

A three-layer stack. The middle layer is the question:

```
django_users            generic auth / user / organisation / invite / referral
      ^ opted into by      NO reference to `web`, `skorie_*`, `rosettes`
django_users.skorie     skorie domain code shared by every skorie host
      ^ inherited by
skorie1..N users app    only genuine per-host divergence remains
```

The generic package must satisfy its "runs anywhere" contract. The proof is
`gadget_admin` importing it with no skorie apps present. Two shapes were
considered for *where* the shared skorie code lives.

# Option 1: A skorie subpackage inside `django-users`, opted into by mixins (adopted 27Sep26)

The skorie code lives in `django_users/skorie/`, in the same package and on the
same trunk. Nothing in the generic code imports it. A skorie host opts in:
- in its own class definition, e.g.
  `class CustomUser(SkorieUserMixin, CustomUserBase)`;
- in its URLs;
- and, only if the subpackage carries templates or commands, in its
  `INSTALLED_APPS`.

A non-skorie host never imports it, so none of it runs.

*As first proposed on 6Jul26 this option gated the skorie code behind feature
flags, and was rejected for that. Opting in by inheritance needs no flags.*

## Pros

- One repository, one package, one trunk, one version sequence. Hosts pin
  one library.
- A change that moves code across the generic/skorie seam is one commit and
  cannot drift between packages.
- No feature flags: opting in is the host's own class definition, so there
  are no flag combinations to test.
- Shared skorie code gets a real home immediately.

## Cons

- The package *contains* skorie domain knowledge, even though a non-skorie
  host never runs it. It ships as dead weight to BuiltAir.
- "Generic code never imports `django_users.skorie`" is enforced by a test,
  not by a package boundary (see *Keeping the boundary*).
- A skorie-only change produces a new release. Hosts pin a tag (003,
  *Versions and pinning*) and the changelog says who a release affects, so a
  non-skorie host skips it knowingly.

# Option 2: A separate `skorie-users` package on top of `django-users` (proposed 6Jul26, not adopted)

`django-users` becomes strictly generic. A new `skorie-users` package, in its
own repo, depends on it and holds the shared skorie behaviour. Hosts install
both and subclass `skorie-users`.

## Pros

- Clean separation enforced by the package boundary itself.
- Non-skorie hosts download nothing skorie.
- Generic and skorie release cadences are independent.

## Cons

- Hosts pin two libraries, and the branch-and-back-port discipline spans two
  repositories. That is the cost decision 003 exists to remove.
- A change touching a generic hook and its skorie implementation needs
  coordinated releases across two repos; version skew breaks at the seam.
- Migration risk if `skorie-users` owns concrete models (`AUTH_USER_MODEL`).

# Decision

**Option 1, as reshaped (27Sep26): one package, with the skorie layer as
`django_users.skorie`, opted into by mixins.**

## Make the generic code generic

The generic code must stop naming `web`, `skorie_*` and `rosettes`. **Plain
inheritance first; a settings hook only where generic code has to call into
skorie behaviour it cannot reach through the user object.**

- **Methods on the user model** (`footprint`, `is_deleteable`,
  `change_names_email`, `current_roles`, `user_roles`, `user_modes_list`,
  `outstanding_event_invites`, `make_order`, `my_paid_orders`,
  `attach_competitor`, `match_user2competitor`):
  - the generic base keeps a neutral default where generic code calls the
    method, e.g. `is_deleteable()` returns `True`;
  - otherwise the method leaves the base altogether;
  - `SkorieUserMixin` overrides or adds them, and may name `web.EventTeam`
    and the rest directly, because it is skorie code.

  No `DJUSERS_USAGE_PROVIDER` setting is needed for these.
- **Views that mix generic and skorie content** (`ManageUser`, `TellUsAbout`)
  gain a small hook such as `get_extra_context()`, and the skorie subclass fills
  it with Competitor, Entry and newsletter data.
- **A settings hook stays only where generic code must reach a domain model
  itself.** Use `get_domain_model()` over `settings.DJUSERS_DOMAIN_MODELS`,
  returning `None` when a host has not wired it. Expect few or none once the
  above is done.
- **Skorie-only code moves into `django_users/skorie/` whole:**
  - `SkorieUserCreationForm`;
  - the newsletter, subscription and payment views;
  - `ref.py`'s event-reference grammar;
  - `default_roles_and_disciplines.py`;
  - `activate_event_timezone` (`tools/decorators.py`), which imports
    `web.models.Event`. On a non-skorie host with its own unrelated `web.Event`,
    it would load the wrong model rather than fail;
  - `tools/api_mixins.py`.

## Keeping the boundary

- A test imports every generic module with only Django's own apps installed.
- A check fails the build if a generic module names `web.`, `skorie_`,
  `rosettes` or `django_users.skorie`.

Without these, the coupling creeps back.

## `django_users.skorie` scope

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

## Models: abstract mixins in `django_users.skorie`, concrete stays in the host

The concrete host models (`CustomUser`, `Person`, `Role`, `Organisation`,
`UserContact`, `CommsChannel`, `VerificationCode`, `PersonOrganisation`,
`DataQualityLog`, helpdesk links) are ~0.93 identical across hosts, so they
are the biggest dedup prize **and** the only piece carrying real risk:
changing `AUTH_USER_MODEL` on an existing production database is a migration
minefield Django is designed to resist.

Therefore, for v1:

- `django_users.skorie` provides **abstract bases / mixins** carrying the shared
  model body.
- Each host keeps a **thin** concrete `users/models.py` (e.g.
  `class CustomUser(SkorieUserMixin, CustomUserBase): pass`), so hosts keep their own
  tables and `AUTH_USER_MODEL` — **zero migration risk** — while still
  deduplicating ~90% of the body.
- Owning concrete skorie models in the package (hosts drop `users/models.py`
  and point `AUTH_USER_MODEL` at a package-owned model) is explicitly
  **out of scope for v1** and revisited only if a greenfield host appears.

## Sequencing (tracer bullet)

*27Sep26, django-users 3.1.1: started.* Moving BuiltAir onto the trunk found
five skorie role mixins in generic `tools/permission_mixins.py` that crashed any
non-skorie host on import. They moved to `django_users/skorie/permission_mixins.py`
with no compatibility shim (Dev), and `tests/test_boundary` holds the line: it
checks the generic import for a generic-roles host, and that no generic module
imports `django_users.skorie`. It covers only that subpackage so far; widen it
to `web.`, `skorie_` and `rosettes` as those references are extracted.

Runs on the trunk agreed in decision 003, after it is brought up to date.

1. Add the boundary test and check (*Keeping the boundary*), marked
   expected-to-fail. They are the measure of steps 2–3.
2. Create `django_users/skorie/`. Move the skorie-only code into it whole,
   and move the Event-domain user methods into `SkorieUserMixin`.
3. **Tracer:** convert **one** host (skorie3) to inherit `SkorieUserMixin` and
   import from `django_users.skorie`, with its tests green. Confirm
   `gadget_admin` imports the generic package with no skorie apps present. The
   boundary test now passes.
4. Hoist the cross-host glue (admin, serializers, signals, notifications, api,
   keycloak glue), highest duplication first.
5. Convert the other hosts to thin subclasses one at a time, skorie3/skorie4
   first (they are the reference generation).

## Per-host tidy-up (first pass — to be verified per repo before editing)

- **skorie3 / skorie4** — the modern pair; serve as the reference for
  `django_users.skorie`. After extraction their `users/` apps shrink to thin
  subclasses plus genuine locals (`middleware.py`, `api_keycloak.py` for s3;
  `hooks.py` for s4, which is on the authentik line and has no `keycloak.py`).
- **skorie2** — adopts the hoisted glue; its `keycloak.py` (identical to s1)
  moves up; local `views.py`/`urls.py` reviewed for real divergence.
- **skorie1** — the outlier and heaviest (`views.py` ~1400 lines, `api.py`
  ~514, plus `forms_custom.py` / `views_custom.py`). Biggest cleanup;
  needs the most careful per-file review — much of the bulk may be dead or
  superseded by the shared layer.

## Out of scope for v1

- The package owning concrete skorie models / `AUTH_USER_MODEL` swaps.
- Consolidating the hosts' `web` apps (this decision is about the `users`
  layer only).
- A declared registry of domain-model keys (start with a plain settings
  dict; formalise later if typo pain appears).

# Consequences

## Easier

- `django-users` becomes genuinely reusable: a non-skorie host installs and
  imports it with no skorie apps present, and never runs the skorie code.
- One place to fix and test shared skorie user behaviour instead of four
  copy-pasted `users/` apps.
- New skorie host = inherit the skorie mixins and add thin subclasses; no more
  copying an existing host's `users` app as a starting point.
- One library to pin, one trunk, one version sequence (003).

## Harder

- The generic/skorie boundary is a rule kept by tests rather than a package
  boundary; it has to be treated as a build failure, not a style point.
- During the transition, hosts run a mix of local and hoisted code; the
  order of extraction matters to keep each host green.

## Risks

- **AUTH_USER_MODEL migration.** Mitigated by keeping concrete models in the
  hosts (abstract mixins only in `django_users.skorie`).
- **Hidden per-host divergence** behind high similarity scores — two files
  can be 0.93 similar and differ in exactly the line that matters.
  Mitigation: a per-repo file-by-file review before deleting any host code;
  the similarity matrix guides, it does not authorise deletion.
- **Boundary erosion.** A convenient import from generic code into
  `django_users.skorie` quietly re-couples the library. Mitigation: the
  boundary test and check fail the build.

## Future work created

- Optional v2: concrete skorie models for greenfield hosts.
- A declared domain-model registry if `DJUSERS_DOMAIN_MODELS` keys bite.
- Consolidating the hosts' `web` apps (separate, larger decision).

# Who is involved

| Name | Why/When |
| :---- | :---- |
| Phoebe (Dev) | Vision, approval of this decision, acceptance testing, branch-scope sign-off |
| Claude | Implementation of the de-skorie-ification and `django_users.skorie`, boundary tests, docs |
| Host-app owners | Inherit the `django_users.skorie` mixins, convert local `users` apps to thin subclasses, delete duplicated code |
