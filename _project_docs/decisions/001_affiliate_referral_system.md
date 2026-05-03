# 001 Affiliate / Referral System

# Status

proposed (2026-04-20)

# Context

Host apps built on `django-users` want to reward existing users for bringing
in new users who eventually pay for credits. The first concrete use case:
when an invited email signs up and completes some tests, the referrer gets
credits; later, when the referee pays, the referrer gets further credits.

`django-users` is a reusable module — it is always subclassed by a host app.
The referral system therefore has to be generic: host apps must be able to
decide what counts as a trigger, what the reward is, and how big it is.
The module owns attribution, fraud mitigation, hold periods, clawback, and
the user-facing dashboard.

We need this designed carefully up front because:

- Referral systems are routinely abused (self-referral, sockpuppets) and
  retrofitting fraud controls is expensive.
- The reward is real economic value (credits), so audit trail matters.
- Hard-coding "trigger = purchase" now would block the "trigger = test
  score" behaviour the first host app needs.

## Related Decisions/Issues

None — this is the first decision document for `django-users`.

## Related Information

- Conversation with Dev on 2026-04-20 where the shape of the feature was
  agreed. Key answers captured below.
- Payment backends under consideration: Stripe (card fingerprint available),
  PayPal (payer id available).

# Change Proposed

Add a referral system to `django-users` as a new app (working name
`django_users.referrals`) with abstract models that the host app subclasses,
matching the pattern already used by `wayfinder.helpdesk`.

The system supports:

- Two-sided rewards (host decides whether referee gets anything).
- Rich reward types (credits / discount code / tier upgrade / custom).
- Event-based triggers — not hardcoded to purchase.
- Attribution via `?ref=CODE` URL parameter with a 30–90 day cookie window.
- Fraud controls: payment-method fingerprint matching (primary block),
  email verification gate, velocity caps, hold period, admin-confirmed
  clawback, flagged-review queue.
- Referrer dashboard and optional opt-in leaderboard.

Two main shapes were considered for how the module exposes trigger points
to the host app.

# Option 1: Hardcoded triggers (signup + purchase)

Module defines two trigger types: "referee signed up" and "referee made a
purchase". Host app implements hooks for each.

## Pros

- Simpler module surface area.
- Easy to document.
- Payment trigger is pre-wired with fraud controls.

## Cons

- Does not support "referee scored tests" — the first host app use case.
- Every new trigger kind needs a module change and release.
- Host apps with different business models (subscriptions, milestones,
  referrals within a team) cannot express their rewards without forking.

# Option 2: Event-based triggers with host-defined `BonusPolicy`

Host app emits named events (`referee_signed_up`, `referee_scored_test`,
`referee_purchased`, anything). The module dispatches each event to a
`BonusPolicy` class the host provides. The policy decides whether the
event yields a reward and returns a `RewardBundle` with optional
`referrer_reward` and `referee_reward`, each of kind credits / discount /
tier / custom.

## Pros

- Supports any trigger the host can name — including the test-score case.
- Host apps can evolve reward logic without module changes.
- Keeps the module free of business-specific assumptions (it doesn't need
  to know what "a purchase" is).
- Reward kinds are extensible via host-registered handlers; module ships
  a default `credits` handler.

## Cons

- Slightly larger host integration surface — host must define event names,
  reward handlers, and the `BonusPolicy` subclass.
- Event names are stringly typed; typos fail silently unless we add a
  declared-events registry.
- Harder to reason about in docs — "it depends on the host" is always the
  answer.

# Decision

Go with **Option 2 (event-based triggers + host `BonusPolicy`)**.

## Module scope

Abstract models the host app subclasses:

- `AbstractReferralCode` — one per user, short unique slug, generated on
  first use. Case-insensitive lookup.
- `AbstractReferral` — links `referrer`, `referee`, `attributed_at`,
  `source` (url / email / manual), `status` (active / flagged /
  disabled), `flag_reason`. First-touch wins on attribution.
- `AbstractReferralBonus` — one per bonus award, linking the Referral,
  the triggering event (`event_name`, `event_ref`), `reward_kind`,
  `amount`, `metadata`, `awarded_at`, `payout_at` (hold-period end),
  `status` (accrued / paid / clawed_back / held_for_review). Unique
  constraint on `(referral, event_ref)` for idempotency.
- `AbstractRewardGrant` — records a reward actually applied to a user
  (e.g. credits added). Separate from `ReferralBonus` so non-referral
  rewards can reuse it later.

Services:

- Code generation + resolution.
- Attribution: cookie → `Referral` row at signup. Self-referral and
  prior-email checks at this point.
- Event dispatch: host calls `referrals.dispatch(event_name, referee,
  event_ref, event_data)` → policy decides → bonus recorded (or
  flagged).
- Hold-period tracker (background task) that moves `accrued` → `paid`
  once `payout_at` passes and the referral is not flagged.
- Clawback: admin action only — reverses a `ReferralBonus` and issues a
  compensating `RewardGrant`. Never silent deletion.
- Velocity caps and review queue.

Host-provided hooks:

- `BonusPolicy` subclass with `calculate_bonus(referral, event_name,
  event_data) -> RewardBundle | None`.
- Reward kind handlers — callables registered against a kind, responsible
  for applying the reward (e.g. the `credits` handler adds credits to the
  user's wallet). The module ships a default `credits` handler that uses
  a configurable "add credits" callable.
- Payment-fingerprint lookup — host provides a function
  `get_payment_fingerprints(user) -> set[str]` because only the host
  knows the payment backend.
- "Established user" predicate — `is_established(user) -> bool`, used
  to gate whether a referrer is eligible to earn.

## Fraud controls

Hard blocks:

1. Email verification required before a `Referral` is eligible to earn.
2. Self-referral by email-history match (referee email ever appeared on
   referrer's account) — block.
3. Payment-method fingerprint match between referrer and referee on the
   triggering purchase — block and flag.

Soft controls:

4. Global hold period (default 14 days, setting
   `REFERRALS_HOLD_PERIOD_DAYS`). One value for all reward kinds —
   keeping it simple for v1.
5. Velocity caps — max N bonuses per referrer per 24h and per calendar
   month. Host-tunable.
6. Flagged-review queue for same-IP / same-device-fingerprint / rapid-
   burst signals. Bonuses hold until admin reviews.

Post-hoc:

7. Clawback on refund / chargeback — **admin-confirmed, not automatic**.
   Host emits a reversal event; module raises a review item; admin
   approves the clawback.

## Settings

```
REFERRALS_HOLD_PERIOD_DAYS = 14
REFERRALS_COOKIE_WINDOW_DAYS = 60
REFERRALS_VELOCITY_PER_DAY = 5
REFERRALS_VELOCITY_PER_MONTH = 30
REFERRALS_ENABLE_LEADERBOARD = False
REFERRALS_BONUS_POLICY = 'myapp.referrals.MyBonusPolicy'
REFERRALS_PAYMENT_FINGERPRINT_LOOKUP = 'myapp.billing.get_fingerprints'
REFERRALS_ESTABLISHED_USER_PREDICATE = 'myapp.users.is_established'
```

## UI

Referrer dashboard at `/account/referrals/`:

- Referral link with copy button + simple "send by email" form
  (prefilled body, host-customisable template).
- Summary: people referred, credits earned, credits pending in hold,
  credits held for review.
- Paginated table of referrals: masked email, status, credits earned,
  date referred.
- Optional leaderboard tab — off by default, host opts in via setting.

Admin:

- Flagged-referral review queue.
- Clawback action on `ReferralBonus`.
- Read-only audit of all `ReferralBonus` and `RewardGrant` records per
  user.

## Out of scope for v1

- Multi-tier referrals (referee's referee earns for the original
  referrer).
- Social-share buttons, graphs, charts on the dashboard.
- Per-reward-kind hold periods.
- Public referrer profile pages.
- Automated clawback.

# Consequences

## Easier

- Any host app can add referral rewards without forking the module.
- Adding a new trigger is a one-line change in the host's `BonusPolicy`.
- Fraud signals are centralised — host apps don't each re-implement
  payment-fingerprint matching.
- Clean audit trail: every credit awarded through referrals has a
  `ReferralBonus` row pointing at its triggering event.

## Harder

- Host integration is slightly heavier than a hardcoded-trigger module —
  host must declare event names, a policy class, reward handlers, and
  the payment-fingerprint lookup.
- Debugging "why didn't my referrer get credits" spans module code and
  host policy code; good logging in the dispatcher is essential.

## Risks

- **Stringly-typed event names.** Mitigation: a declared-events registry
  on the `BonusPolicy` that the module validates against at dispatch
  time, warning on unknown events.
- **Fraud on test-completion trigger.** The first use case awards credits
  before the referee has paid, which is the weakest fraud position.
  Mitigation: host policy should keep the pre-payment bonus small, and
  velocity caps apply. Document this clearly.
- **Payment-fingerprint lookup is host-specific and easy to get wrong.**
  Mitigation: ship a no-op default that blocks nothing but logs a
  warning, so a host that forgets to wire it up gets a visible signal
  in logs rather than silent fraud exposure.
- **Clawback via admin is slower than automatic.** Accepted trade-off for
  simplicity and safety in v1.

## Future work created

- Declared-events registry and dispatcher-level validation.
- Multi-tier referrals if demand appears.
- Automated clawback behind a feature flag, once we have confidence.
- Per-reward-kind hold periods once one host app needs it.

# Who is involved

| Name | Why/When |
| :---- | :---- |
| Phoebe (Dev) | Vision, approval of this decision, acceptance testing |
| Claude | Implementation, tests, docs |
| Host-app owners | Must implement `BonusPolicy`, reward handlers, payment-fingerprint lookup before enabling referrals |

Email distribution list for change of status:
