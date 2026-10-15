"""Standalone runner for the reference plain-Django host tests.

Usage (from repo root):

    python -m tests.test_plain_host.runtests
"""

import os
import sys


def main():
    os.environ.setdefault("DJANGO_SETTINGS_MODULE", "tests.test_plain_host.settings")
    import django

    django.setup()

    from django.test.utils import get_runner
    from django.conf import settings

    TestRunner = get_runner(settings)
    runner = TestRunner(verbosity=2, interactive=False)
    failures = runner.run_tests(["tests.test_plain_host"])
    sys.exit(bool(failures))


if __name__ == "__main__":
    main()
