import tempfile
import unittest
from pathlib import Path

import poc


class TestTargets(unittest.TestCase):
    def test_load_targets(self):
        with tempfile.NamedTemporaryFile("w", suffix=".txt", delete=False, encoding="utf-8") as tf:
            tf.write("# comment\n\nhttps://a.test/\nhttp://b.test\n")
            path = tf.name
        try:
            urls = poc.load_targets(path)
            self.assertEqual(urls, ["https://a.test/", "http://b.test"])
        finally:
            Path(path).unlink(missing_ok=True)


if __name__ == "__main__":
    unittest.main()
