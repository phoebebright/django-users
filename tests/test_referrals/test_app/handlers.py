"""Test reward-kind handlers."""

_credits_log: list = []


def grant_credits(user, reward, grant):
    _credits_log.append((user.pk, reward.amount, reward.metadata))


def pop_credits_log():
    log = list(_credits_log)
    _credits_log.clear()
    return log
