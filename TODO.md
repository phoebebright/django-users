# django-users (authentik branch) — TODO

Carry-overs and known gaps from the Keycloak → Authentik conversion. Not a
full backlog — just the items that have already been flagged in flight and
need a home before we forget them.

---

## Problem-signup wizard

The Keycloak-era `ProblemSignup` view (a help page that diagnosed why a
user couldn't sign up — "is this email already in the IdP?", "is the
account active?", "is the email verified?") was **removed** during the
initial Authentik conversion (commit `7f750d9`) along with `Troubleshoot`
and `ProblemLogin`.

Consumer projects (skorie4 today, others later) still link to
`{% url 'users:problem_register' %}` from `login.html`, `register.html`,
`users_narrow_base.html`, and consumer-side templates, so the URL has to
exist or those pages 500. As an interim, skorie4 has stubbed it with a
plain TemplateView pointing at a navigational help page (reset password /
re-send verification / contact us) — see skorie4 commit `fcfa579`.

We should rebuild the diagnostic version upstream against the Authentik
admin API.

### Shape

- New view `ProblemSignupView` (or `SignupHelpWizard`) in
  `django_users/views.py`.
- Form takes the user's email; on submit, the view looks up:
    1. Does a Django `CustomUser` exist for this email?
    2. Does an Authentik user exist? (via `AuthentikIdP.find_by_email`)
    3. Is the user's email channel verified locally? (`CommsChannel.verified_at`)
    4. Are there any open `Invite` rows for this email?
- Renders a result page that explains the situation in plain English and
  offers the next-best action — one of:
    - "We don't see you in our system — go register"
    - "You have an account but haven't verified your email — resend"
    - "You have a pending invitation — re-send the link"
    - "Your account is fine — try the password reset flow"
    - "Something unusual is going on — contact us"
- Permissions: anonymous-accessible. Rate-limit (one lookup per IP per
  minute) to prevent enumeration.
- Replaces the Keycloak-era template
  `templates/admin/users/problem_register_admin.html` (which called
  `email_exists_on_keycloak` — gone on this branch).
- URL name stays `users:problem_register` so existing template links
  resolve without churn.
- Add to the reference `urls.py` so consumer projects can include the
  same path.
- Consumer projects (skorie4, etc.) drop their stub TemplateView once
  this lands.

### Risks / open questions

- **Enumeration**: revealing whether an email is registered is a known
  account-discovery vector. Mitigations: blanket "if your email is on
  file, we've sent further instructions" wording for the public-facing
  result, and put the diagnostic detail behind a magic-link the user
  receives on the email they typed (so only the inbox owner sees it).
- **Rate limiting**: `django-ratelimit` is the obvious choice; check
  what's already in upstream's deps before adding.
- **Authentik API failure**: degrade gracefully — fall back to "we
  couldn't check that right now, please try again or contact us"
  rather than 500.

---

## Other carry-overs

(Add new items below this line — keep entries short, link to the relevant
commit, ticket, or ADR if there is one.)

### `normalise_email` raises out of `LoginView.post` — 500 instead of a form error

`normalise_email` (`utils.py:286`) converts an `EmailNotValidError` into a
Django `ValidationError`, but the callers don't catch it. In
`LoginView.post` (`views.py:615`) it is the very first statement, outside
any try, so a badly-formed address 500s the login page instead of
re-rendering it with "Invalid email or password".

Reproduced on skorie1 (dressagecalculator, 30 Jul 2026): posting
`nosuchuser@example.invalid` to `/users/login/` →
`ValidationError: ['The part after the @-sign is a special-use or reserved
name that cannot be used with email.']`. Any typo'd or reserved domain
(`.invalid`, `.test`, `.local`, a domain that fails the deliverability
check) does it. Real users hit this by mistyping their address.

Fix: wrap the call and fall through to the existing invalid-credentials
path rather than letting it escape:

```python
try:
    email = normalise_email(request.POST.get('email'))
except ValidationError:
    messages.error(request, _('Invalid email or password.'))
    return render(request, self.template_name, {'email': request.POST.get('email')})
```

Deliberately reuse the same generic message as a wrong password — saying
"that email is malformed" is a small enumeration/behaviour tell and the
user's next action is identical either way.

Then audit the other unguarded callers — `views.py` lines 765, 1234, 1236,
1267, 1285, 1333, 1364, 1672. The `form_valid` ones (765, 1267, 1672) are
the next most likely to bite: the form's own `EmailField` validation is
looser than `email_validator`'s deliverability check, so a value can pass
`is_valid()` and still raise here, after the form has been cleaned and with
no form to attach the error to. Those want `form.add_error('email', ...)`
and a `form_invalid(form)` return rather than the message-and-render shape
above.
