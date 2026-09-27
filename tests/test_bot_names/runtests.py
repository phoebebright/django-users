"""Standalone runner for the test_bot_names tests.

Usage (from repo root):

    python -m tests.test_bot_names.runtests
"""

import os
import sys


def main():
    os.environ.setdefault("DJANGO_SETTINGS_MODULE", "tests.test_bot_names.settings")
    import django

    django.setup()

    from django.test.utils import get_runner
    from django.conf import settings

    TestRunner = get_runner(settings)
    runner = TestRunner(verbosity=2, interactive=False)
    failures = runner.run_tests(["tests.test_bot_names"])
    sys.exit(bool(failures))


if __name__ == "__main__":
    main()
