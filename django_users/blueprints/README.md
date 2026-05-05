# Authentik Blueprints

Declarative Authentik configuration shipped with `django_users`.

## must_change_password.yaml

Despite the filename (kept for compatibility), this blueprint covers
**both** of the Authentik integrations that `django_users` needs:

1. **Must-change-password gate** on the authentication flow. Fires when
   `user.attributes.must_change_password == True` — set automatically by
   `GenerateOTP` when an admin issues a 6-digit OTP. Routes the user
   through a password-prompt + user-write stage on next login, then
   clears the flag.

2. **Recovery flow + brand wiring.** The `GenerateRecoveryLink` API
   calls Authentik's `POST /users/{id}/recovery/`. That endpoint requires
   a recovery flow to exist *and* the brand serving the request to point
   at it via `flow_recovery`. The blueprint creates the flow (slug
   `default-recovery-flow`), reuses the same prompt + user-write stages,
   and patches the default brand.

Both reuse the same prompt and user-write stages — that's why they live
in one file rather than two.

## Two ways to apply

### A. Authentik blueprint loader (preferred for prod)

If your Authentik deployment has the blueprint loader enabled (it does
by default in the official Docker compose / Helm chart), drop the YAML
into the `blueprints/` mount directory:

```bash
cp must_change_password.yaml /path/to/authentik/blueprints/
```

Authentik watches that directory and applies changes within ~30s.
Idempotent.

**Caveat:** the blueprint only patches the *default* brand. If your
runtime traffic hits a non-default brand (because Authentik is on
e.g. `localhost:9000` and a brand exists for that exact domain), the
blueprint won't update it — recovery will still 400 with "No recovery
flow set." Use the management command (Path B) in that case, or patch
the brand manually in **System → Brands**.

### B. Management command (preferred for dev / quick setup, and required
when you have host-specific brands)

Runs from your Django project, talks directly to the Authentik REST API
using the credentials in `settings.AUTHENTIK`. Reads `AUTHENTIK['URL']`,
extracts the host, and patches every brand whose domain matches it
*plus* the default brand:

```bash
python manage.py setup_authentik_must_change
```

Options:

```bash
# Different auth flow slug (default: default-authentication-flow)
python manage.py setup_authentik_must_change --flow-slug your-auth-flow

# Different recovery flow slug (default: default-recovery-flow)
python manage.py setup_authentik_must_change --recovery-slug your-recovery

# Skip the recovery flow entirely (just install the must-change gate)
python manage.py setup_authentik_must_change --skip-recovery

# Tear down the must-change bindings (keeps stages/policies so you can
# re-bind them; does NOT remove the recovery flow)
python manage.py setup_authentik_must_change --remove
```

Idempotent: re-running prints `ok` for unchanged objects and `patched`
where attributes have drifted.

## Customising flow slugs

If your Authentik instance uses non-default slugs, either edit the two
`[slug, default-authentication-flow]` lines in the YAML and the
`slug: default-recovery-flow` block, or pass `--flow-slug` and
`--recovery-slug` to the command.

## What it does NOT do

- Does not modify the recovery flow's prompt/stage configuration on
  re-apply if you've manually edited them in Authentik admin — the
  blueprint only sets fields it knows about.
- Does not delete on update. Re-applying with different attribute
  values updates them in place but won't remove fields you've taken
  out of the YAML. Use `--remove` for partial teardown.
- Does not handle host-specific brands from YAML. See "Caveat" above.
