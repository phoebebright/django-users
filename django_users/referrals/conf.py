from django.conf import settings


def _get(name, default):
    return getattr(settings, name, default)


def hold_period_days():
    return _get("REFERRALS_HOLD_PERIOD_DAYS", 14)


def cookie_window_days():
    return _get("REFERRALS_COOKIE_WINDOW_DAYS", 60)


def cookie_name():
    return _get("REFERRALS_COOKIE_NAME", "ref")


def query_param():
    return _get("REFERRALS_QUERY_PARAM", "ref")


def velocity_per_day():
    return _get("REFERRALS_VELOCITY_PER_DAY", 5)


def velocity_per_month():
    return _get("REFERRALS_VELOCITY_PER_MONTH", 30)


def enable_leaderboard():
    return _get("REFERRALS_ENABLE_LEADERBOARD", False)


def bonus_policy_path():
    return _get("REFERRALS_BONUS_POLICY", None)


def payment_fingerprint_lookup_path():
    return _get("REFERRALS_PAYMENT_FINGERPRINT_LOOKUP", None)


def established_user_predicate_path():
    return _get("REFERRALS_ESTABLISHED_USER_PREDICATE", None)


def credits_grant_callable_path():
    return _get("REFERRALS_CREDITS_GRANT_CALLABLE", None)


def code_length():
    return _get("REFERRALS_CODE_LENGTH", 8)


def code_alphabet():
    return _get(
        "REFERRALS_CODE_ALPHABET",
        "23456789abcdefghjkmnpqrstuvwxyz",
    )
