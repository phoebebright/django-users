"""The generic/skorie boundary (decision 002, *Keeping the boundary*).

A non-skorie host - one whose ModelRoles has only generic roles - must be able
to import the generic modules, and no generic module may import
`django_users.skorie`. Widen the naming check to `web.`, `skorie_` and
`rosettes` as 002's extraction removes those references.
"""
import importlib
import re
from pathlib import Path

from django.test import SimpleTestCase

PACKAGE = Path(__file__).resolve().parents[2] / "django_users"
SKORIE_IMPORT = re.compile(r"^\s*(from|import)\s+(django_users\.skorie|\.skorie|\.\.skorie)\b", re.M)


class GenericImportTests(SimpleTestCase):
    def test_generic_permission_mixins_import_without_skorie_roles(self):
        module = importlib.import_module("django_users.tools.permission_mixins")
        self.assertTrue(hasattr(module, "UserCanAdministerMixin"))
        self.assertFalse(hasattr(module, "UserCanJudgeMixin"))

    def test_skorie_mixins_need_skorie_roles(self):
        # The flip side: this host is not skorie, so the skorie module cannot load.
        with self.assertRaises(AttributeError):
            importlib.import_module("django_users.skorie.permission_mixins")

    def test_no_generic_module_imports_the_skorie_subpackage(self):
        offenders = [
            str(path.relative_to(PACKAGE))
            for path in PACKAGE.rglob("*.py")
            if "skorie" not in path.relative_to(PACKAGE).parts
            and SKORIE_IMPORT.search(path.read_text())
        ]
        self.assertEqual(offenders, [])
