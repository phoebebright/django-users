"""Standalone runner for the release-consistency checks (no Django needed).

Usage (from repo root):

    python -m tests.test_release.runtests
"""
import sys
import unittest


def main():
    suite = unittest.defaultTestLoader.loadTestsFromName("tests.test_release.tests")
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    sys.exit(not result.wasSuccessful())


if __name__ == "__main__":
    main()
