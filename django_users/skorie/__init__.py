"""Skorie-only code (decision 002, revised 27Sep26).

Generic `django_users` code must never import from here. Skorie hosts opt in by
importing from this subpackage; a non-skorie host never does, so nothing here
runs for it.
"""
