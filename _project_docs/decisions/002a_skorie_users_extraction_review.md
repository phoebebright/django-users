# 002a `skorie-users` extraction — consolidated per-host review

Companion to decision [002 — Extract a `skorie-users` layer](002_skorie_users_extraction.md).
Status: review (2026-07-06). Feeds the extraction tickets.

> **Read with 002 as revised 27Sep26.** The skorie layer is now the
> `django_users.skorie` subpackage on the same trunk, not a separate
> `skorie-users` package. Where this review says "`skorie-users` owns …",
> read "`django_users.skorie` holds …". The rulings, seams and per-host
> findings below are unchanged. Two points are simplified by the revision:
> - seams on the user model become mixin overrides rather than settings
>   hooks (002, *Make the generic code generic*);
> - the "Host model resolution" seam matters only inside the generic code.

This document records the deeper per-project review of the `users/` apps of
skorie1–skorie4 (one reviewer per host), the resulting shared-surface and
seam inventory, and Dev's rulings on the model/behaviour reconciliation
questions.

---

## 1. Cross-host verdict

The same shape holds across all four hosts:

- The **declarative glue** (`admin.py`, `serializers.py`, `signals.py`,
  `notifications.py`, and the `CheckEmail`/`MyInternalRoles` API views) is
  near-identical everywhere → hoist to `skorie-users`.
- **Nothing hoists verbatim.** Every shared file carries a coupling that must
  become a **seam** first (domain models, newsletter, auth external-id,
  internal-API auth class).
- **Models diverge hard per host** — concrete bodies are not safely mergeable
  (skorie1 `Organisation` ≈260 lines of Stripe/AI; skorie3 ≈25; `is_rider`
  means the opposite thing in s1 vs s3). Confirms v1: **abstract bases only,
  concrete models stay in each host**; the base bakes in **zero** host fields.
- **Generation order:** skorie4 is newest (invite/OTP + `hooks.py`), then
  skorie3, then the older skorie1/skorie2 pair; skorie1 is the heavy outlier.
  Seed the **invite** surface from skorie4, the rest from skorie3.
- **Auth spread:** skorie1 = keycloak, **skorie2 → plain Django** (dropping
  keycloak), skorie3 = keycloak, skorie4 = authentik. skorie2 is the proof
  case for the `AUTH_PROVIDER='django'` path.
- **Dead code everywhere:** empty `serializers.py`/`views_custom.py`,
  unimported `keycloak.py`/`utils.py`, large commented blocks, ~15-import
  dead blocks in each `models.py`.

## 2. Shared surface (what `skorie-users` owns)

- `admin.py` — Person/CustomUser/Role/CommsChannel/VerificationCode/
  UserContact/Organisation admins + inlines.
- `serializers.py` — `UserSerializer` (skorie1 shape, see ruling 5),
  `UserListSerializer` (from skorie3, ride badge behind a hook).
- `signals.py` — `on_user_created_link_subscriptions`.
- `notifications.py` — `on_new_user_unverified` / `on_new_user_verified`
  (admin link keyed on `pk`, not the IdP id).
- `api.py` — `CheckEmail`, `MyInternalRoles` (NOT `InternalRoleViewSet`).
- Invite surface (from skorie4) — `AddUserWithInvite`/`AcceptInvite`/
  `EnterOTP` views, `AdminInviteUserForm`, `Invite` abstract base, `hooks.py`
  post-create hook.
- Abstract model bases for CustomUser/Person/Role/Organisation/UserContact/
  CommsChannel/VerificationCode/PersonOrganisation/DataQualityLog/UserHistory
  — hosts keep thin concrete subclasses (v1, no `AUTH_USER_MODEL` change).
- Auth glue behind the provider seam: keycloak `get_access_token` etc. live
  behind the keycloak adapter; authentik behind its adapter.

## 3. Seams `skorie-users` must expose before any hoist

| Seam | Replaces (found in) | Mechanism |
|---|---|---|
| Auth external-id | `keycloak_id` (s1/s3), `authentik_id` (s4) in `notifications.py` + `views.py` lookups | provider-neutral `user.idp_id` via `get_idp()` |
| Auth adapter | `keycloak.py` group (s3), `hooks.py` (s4), none (s2→django) | `AUTH_PROVIDER` interface: access-token / create / verify / find / post-create-invite hook |
| Domain-model resolver | `web.Event/EventRole/EventTeam/Competitor/Entry/Seller` | `settings.DJUSERS_DOMAIN_MODELS` + `get_domain_model()` |
| Name-propagation | `Person.change_name_globally` (all hosts) | overridable no-op hook, host implements |
| Newsletter | `NewsletterUserMixin`, `Subscription`, `get_mail_class` (`skorie_news`) | settings-selected mixin + subscription-linker callable |
| DataQualityMixin | `skorie.common.model_mixins` (all) | move down into shared layer or settings-pathed mixin |
| Internal-API auth | `SignedTokenAuthentication` (`skorie.common`) vs `HasAPIKey` | `settings.INTERNAL_API_AUTH_CLASSES` |
| Serializer badges | ride badge / `county`/`level` overrides | host-overridable `get_status_badges()` |
| Host model resolution | `from users.models import CustomUser, Role…` | `get_user_model()` / `settings.*_MODEL` |

## 4. Reconciliation ledger (Dev rulings, 2026-07-06)

| # | Question | Ruling | Base? |
|---|---|---|---|
| 1 | `is_rider` — s1 explicit `ROLE_COMPETITOR` vs s3 `is_competitor` | **skorie1-only.** Drop from s3 model (`models.py:214`); change s3 template `_client/di/base.html:166` to `user.is_competitor`. s1 keeps it (heavily used: `web/views.py`, `calculator`, ~12 templates). | ❌ |
| 2 | `is_confirmed` — s4 `>= CONFIRMED` vs s3 set-membership | **`status in (CONFIRMED, SUBSCRIBED)`.** skorie4 changes from `>=`; add a test. | ✅ |
| 3 | `CustomUser.save()` behaviour | **Base auto-creates `CommsChannel`** (idempotent / create-only, resolves host concrete model); default-org, confirm-on-country+profile and all other save logic stay in host overrides (call `super().save()`). skorie4 re-gains CommsChannel auto-create. | ✅ partial |
| 4 | `InternalRoleViewSet` contract | **skorie1-only.** s1 keeps its registered copy; s2 keeps its own registered legacy copy (KEEP-LOCAL); s3's is unregistered → likely dead, verify and delete. Shared API = `CheckEmail` + `MyInternalRoles`. | ❌ |
| 5 | `UserSerializer` field set | **Shared = skorie1's shape** (min + `county`/`current_level`); s1 payload unchanged (`web/api.py` imports it). s3 keeps its richer version (`name`/`roles`/`preferred_channel`) as a local override; s4 currently emits the richer shape → keep a local override or accept reduced payload (decide at s4). `UserListSerializer` still sourced from s3. | ✅ (s1 shape) |
| 6 | Canonical invite flow | **skorie4.** `skorie-users` owns the invite/OTP views, `Invite` abstract base, `AdminInviteUserForm`, `hooks.py`. s1/s2/s3 adopt it, retiring older `InviteUser2Event`. | ✅ |
| 7 | Helpdesk/Zammad models (`HelpDeskTicket`/`HelpDeskEntryLink`) | **Drop from base.** Stay host-local where present (s1/s2/s3); subclass `django_users` Zammad bases directly; `HelpDeskEntryLink.entry` FKs `web.Entry`. | ❌ |
| 8 | `UserHistory` base | **Keep in base.** `skorie-users` provides the abstract base; hosts get thin concrete subclasses. | ✅ |

## 5. Migration implications (v1, no `AUTH_USER_MODEL` change)

New concrete tables some hosts gain — each needs a small migration, flagged to
Dev before generation:

- `Invite` (ruling 6) → skorie1, skorie2, skorie3 gain it.
- `UserHistory` (ruling 8) → skorie1, skorie3, skorie4 gain it.

## 6. Per-host action lists

### skorie1 (heaviest; ~⅓ hoist, ½ local, ⅙ dead)
- **Delete:** `views_custom.py` (empty), `utils.py` (unimported), `keycloak.py`
  (unimported), `models.py` dead-import block + duplicate `confirm()` +
  `is_subscribed2newsletter`, ~400 lines commented views/urls.
- **Hoist → thin override:** `admin.py` (keep `ai_credits` override),
  `serializers.py`, `signals.py`, `CheckEmail`/`MyInternalRoles`.
- **Keep local:** `views.py` (~1000 active), `api.py` Internal*/Org viewsets
  (incl. its `InternalRoleViewSet`), `forms.py`, heavy
  `Organisation`/`CustomUser`/`Role` bodies, `is_rider`.

### skorie2 (→ plain Django auth proof case)
- **Delete:** `keycloak.py` (import-time abort under no-keycloak),
  `serializers.py` (empty), `views_custom.py` (empty), `urls.py` dead block
  (incl. `logout_user_from_keycloak_and_django` at line 67 — do NOT
  reintroduce), dead imports.
- **Fix for Django auth:** `notifications.py:14,20` `reverse(..., keycloak_id)`
  → key on `pk` via the neutral seam.
- **Hoist:** `admin.py` (drop extra `@admin.register`), `signals.py`,
  `notifications.py` (reconcile to s3 body), `CheckEmail`/`MyInternalRoles`.
- **Keep local:** `forms.py`, `views.py`, its own `InternalRoleViewSet`,
  `find_dupes` command, tests, thin concrete models.
- Confirmed IdP-neutral (leave alone): `SignedTokenAuthentication` (HMAC, not
  OIDC), VerificationCode magic-link tokens.

### skorie3 (keycloak reference for the non-invite surface)
- **Hoist-but-generalise:** `admin.py`, `serializers.py` (ride badge → hook),
  `CheckEmail`/`MyInternalRoles` (auth class → setting), `signals.py`
  (subscription linker → callable), `notifications.py` (`keycloak_id` →
  neutral id).
- **Fix:** drop `is_rider` (ruling 1); verify/delete unregistered
  `InternalRoleViewSet`.
- **Keep local:** `keycloak.py` (becomes keycloak adapter impl),
  `api_keycloak.py`, `middleware.py`, `views.py`, `forms.py`, `urls.py`.
- **Delete:** `migrations_old/`.

### skorie4 (newest; invite-surface reference)
- **Hoist:** `admin.py`, `serializers.py`, `signals.py`, `apps.py`,
  `notifications.py` (after external-id seam), `CheckEmail`/`MyInternalRoles`
  (richer `ComponentMixin` version), `AdminInviteUserForm`, `hooks.py` (shared
  invite post-create hook), bulk of invite/OTP views.
- **Change:** `is_confirmed` → set-membership (ruling 2); re-gain CommsChannel
  auto-create (ruling 3); decide serializer override (ruling 5).
- **Delete:** `README.txt` (stale), `migrations_old/`.
- **Keep local:** host view subclasses (ComponentMixin/templates), thin
  models, authentik-line tests.

## 7. Sequencing (tracer bullet)

1. Land the `django-users` de-skorie-ification behind the seams (§3);
   `gadget_admin` is the proof it stayed generic.
2. Scaffold `skorie-users` (package, `apps.py`, depends on `django-users`).
3. **Tracer:** hoist one high-dup / low-risk file (`signals.py`) into
   `skorie-users`, wire skorie3 to import it, delete the local copy, confirm
   green.
4. Roll the rest of the glue (admin, notifications, serializers, api duo,
   keycloak adapter, invite surface from skorie4).
5. Introduce abstract model bases (with the ledger rulings baked in); convert
   hosts to thin subclasses one at a time, skorie3/skorie4 first.
