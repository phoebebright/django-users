#!/usr/bin/env python
import os
import sys
from pathlib import Path

if __name__ == "__main__":

    BASE_DIR = Path(__file__).resolve().parent
    # Add <repo_root> to sys.path so "import django_users" works
    sys.path.insert(0, str(BASE_DIR.parent))

    os.environ.setdefault("DJANGO_SETTINGS_MODULE", "config.settings")

    from django.core.management import execute_from_command_line

    execute_from_command_line(sys.argv)
