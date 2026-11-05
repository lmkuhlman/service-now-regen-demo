"""Checks that hold however the app's pages change. Add tests for what the app does here."""

import os
import py_compile
import re
import tempfile
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


class TestApp(unittest.TestCase):
    def test_main_page_has_a_title(self):
        with open(os.path.join(ROOT, "index.html"), encoding="utf-8") as f:
            self.assertRegex(f.read(), re.compile(r"<title>\s*\S", re.IGNORECASE))

    def test_server_code_compiles(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            py_compile.compile(os.path.join(ROOT, "app.py"), cfile=os.path.join(temp_dir, "app.pyc"), doraise=True)


if __name__ == "__main__":
    unittest.main()
