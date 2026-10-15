# CLAUDE.md — django-users

Guidance for Claude Code when working in this repository.

## What this repo is

`django-users` is a **reusable Django app** providing shared user/auth
functionality (login, registration, invitations, password reset, optional
Keycloak SSO, referrals, helpdesk/Zammad glue). It is consumed as a library by
the Skorie projects (`skorie1`, `skorie2`, `skorie3`) and potentially others.

It is **not a standalone app**: the host project creates its own concrete users
app and subclasses/uses these base models. There is no root `manage.py`; the
code runs inside a host project's Django settings.

Author/maintainer: Phoebe Bright ("Dev"). Claude implements; Dev decides and
signs off. The user-level Django rules in `~/.claude/rules/` apply here too.

## CRITICAL: this repo has many long-lived branches — back-port every fix

There is no single source of truth branch. Consumers pin **specific branches**
via `git+https://github.com/phoebebright/django-users@<branch>` in their
`requirements.txt`, and a reinstall pulls that branch's current HEAD. A fix on
one branch does **not** reach consumers on another branch.

Known branches (verify with `git branch -a` — this list drifts):

| Branch | Role | Keycloak |
|---|---|---|
| `skorie_users` | **What all three skorie projects currently pin.** Fixes here reach production on reinstall. | present |
| `main` | Canonical/default branch. | present |
| `skorie-users2` (2.0.x) | Next-gen line; Keycloak coupling stripped (commit `03cca12`). | removed |
| `skorie1` | clean variant | removed |
| `authentik`, `merge_with_no_keycloak`, `no_keycloak_no_skorie`, ... | experiments | varies |

**Rule:** before claiming a bug is fixed, check which branches still contain it
(`git grep -l "<pattern>" <branch> -- <path>`) and back-port to **every active
consumer branch**, not just the one you happen to be on. Confirm with Dev which
branches are in scope.

**Tip — patch sibling branches without disturbing the working tree:** use
`git worktree` rather than switching branches (Dev often has uncommitted work
and the IDE open):

```bash
git worktree add /tmp/du-main main
# edit /tmp/du-main/..., then:
git -C /tmp/du-main add -A && git -C /tmp/du-main commit -m "..."
git worktree remove /tmp/du-main
```

Each worktree has its own index, so the main checkout and any staged/unstaged
work there are untouched.

## How consumers install it

`requirements.txt` line in host projects:
`git+https://github.com/phoebebright/django-users@skorie_users`

There is no PyPI release in play — the git branch HEAD is the artifact. So
"merged but not on the pinned branch" means "not deployed." `pyproject.toml`
`version` is informational and is not consistent across branches.

## Auth / session convention (important — caused a production 403)

When logging a user in, **record `ModelBackend` as the session's auth backend**,
not a Keycloak backend:

```python
login(request, user, backend='django.contrib.auth.backends.ModelBackend')
# or: backend=settings.AUTHENTICATION_BACKENDS[0]
```

Why: Django's `auth.get_user()` calls the recorded backend's `get_user()` on
every request. The Keycloak backend's `get_user()` returns `None` once the
short-lived OIDC token lapses (or the profile is missing). The Django session
cookie lives a week, so the user silently becomes `AnonymousUser` mid-session —
API writes then return **403 with `user=None`** while the cookie still looks
valid. Keycloak should verify credentials *at login*; the Django session governs
the session afterward. The session auth hash is backend-independent, so swapping
the recorded backend is safe.

Do not reintroduce `login(..., backend='django_keycloak_admin.backends.Keycloak...')`.

## Git workflow

- **Branch topology is fragile and Dev edits it live in PyCharm.** Re-check
  `git status` / `git branch` before acting; don't assume the branch you saw
  last turn is still checked out.
- Commit messages: short imperative subject, a paragraph of *why* (not just
  what), end with:
  `Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>`
- **Claude cannot push from here.** The remote is HTTPS
  (`https://github.com/phoebebright/django-users.git`), there are no cached Git
  credentials in Claude's shell, and `gh` is not installed. Commit locally, then
  ask Dev to push (e.g. `! git -C <repo> push origin <branch>`), or set up SSH /
  `gh` if Dev wants Claude to push.

## Tests

Tests live in `tests/` (`test_models.py`, `test_views.py`, `test_forms.py`,
`test_utily.py`, `test_referrals/`, `test_authentik/`). There is no standalone
runner in this repo — run them from a host project that has this app installed
(e.g. from `skorie1`: `python manage.py test django_users --keepdb`) or via a
test settings module. Confirm the exact command with Dev before relying on it.

## Conventions

- Class-based views; fat models, thin views.
- Optimise queries (`select_related` / `prefetch_related`).
- Don't add hard Keycloak dependencies to code paths that must also run with
  `USE_KEYCLOAK = False` — the app is meant to run with or without Keycloak.
- Ask Dev before introducing new dependencies, migrations, or model fields.
- Surface, don't silently work around, anything that contradicts this file.