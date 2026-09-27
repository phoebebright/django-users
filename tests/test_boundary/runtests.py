"""Standalone runner for the generic-vs-skorie boundary tests.

Usage (from repo root):

    python -m tests.test_boundary.runtests
"""

import os
import sys


def main():
    os.environ.setdefault("DJANGO_SETTINGS_MODULE", "tests.test_boundary.settings")
    import django

    django.setup()

    from django.test.utils import get_runner
    from django.conf import settings

    TestRunner = get_runner(settings)
    runner = TestRunner(verbosity=2, interactive=False)
    failures = runner.run_tests(["tests.test_boundary"])
    sys.exit(bool(failures))


if __name__ == "__main__":
    main()
