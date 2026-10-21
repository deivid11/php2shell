import unittest

from php2shell_core import (
    BOUNDARY_619,
    DEFAULT_BOUNDARY_TRIGGER,
    build_rce619_multipart,
    build_trigger_multipart,
    is_vulnerable_php,
    parse_php_version,
)


class TestVersions(unittest.TestCase):
    def test_parse(self):
        self.assertEqual(parse_php_version("PHP/8.4.4"), (8, 4, 4))

    def test_patched(self):
        self.assertFalse(is_vulnerable_php((8, 4, 27)))

    def test_affected(self):
        self.assertTrue(is_vulnerable_php((8, 4, 26)))


class TestMultipart(unittest.TestCase):
    def test_trigger_sizes(self):
        p1, p2, b, total = build_trigger_multipart("abc")
        self.assertIn(b"PHPSESSID", p1)
        self.assertIn(b"PHP_SESSION_UPLOAD_PROGRESS", p1)
        self.assertEqual(len(p1) + len(p2), total)
        self.assertTrue(p1.startswith(b"--" + DEFAULT_BOUNDARY_TRIGGER))

    def test_619_boundary(self):
        p1, p2, meta = build_rce619_multipart("sid", b"id", 0x1000)
        self.assertIn(BOUNDARY_619, p1)
        self.assertGreater(meta["total_len"], len(p1))
        self.assertEqual(len(p1) + len(p2), meta["total_len"])


if __name__ == "__main__":
    unittest.main()
