"""`looks_like_bot_name`, which silently drops bot registrations and feeds
`drop_bot_users`. It is tuned for precision: a false positive silently loses a
real person's registration, so the real-name cases matter as much as the bots.
"""
from django.test import SimpleTestCase

from django_users.utils import looks_like_bot_name


class LooksLikeBotNameTests(SimpleTestCase):
    def test_machine_generated_names(self):
        for first, last in [
            ("4245a264-f75d-49f4-9e68-79336fa5469", "Smith"),   # UUID-like
            ("Anne", "4245a264f75d49f4"),                       # hex blob
            ("hREsCKna", "Jones"),                               # random casing
            ("Mary", "xkcdqrtw"),                                # consonant run
        ]:
            with self.subTest(first=first, last=last):
                self.assertTrue(looks_like_bot_name(first, last))

    def test_real_names_pass(self):
        for first, last in [
            ("Phoebe", "Bright"),
            ("Seán", "Ó Súilleabháin"),
            ("Mary-Jane", "O'Brien"),
            ("Ronald", "McDonald"),
            ("JOHN", "SMITH"),          # all caps is not random casing
            ("Anne", "van der Berg"),
            ("Li", "Wu"),
            ("", ""),
            (None, None),
        ]:
            with self.subTest(first=first, last=last):
                self.assertFalse(looks_like_bot_name(first, last))
