from pathlib import Path
import re
import unittest

HTACCESS = Path(__file__).resolve().parents[1] / ".htaccess"


class OriginSecurityHeaderConfigTests(unittest.TestCase):
    def test_headers_are_scoped_to_mod_headers(self):
        text = HTACCESS.read_text(encoding="utf-8")
        self.assertIn("<IfModule mod_headers.c>", text)
        self.assertIn("</IfModule>", text)

    def test_required_origin_headers_are_present(self):
        text = HTACCESS.read_text(encoding="utf-8")
        required = [
            r'Header always set Strict-Transport-Security "max-age=31536000"',
            r'Header always set X-Content-Type-Options "nosniff"',
            r'Header always set X-Frame-Options "DENY"',
            r'Header always set Referrer-Policy "strict-origin-when-cross-origin"',
            r'Header always set Permissions-Policy "camera=\(\), microphone=\(\), geolocation=\(\)"',
            r"Header always set Content-Security-Policy .*frame-ancestors 'none'.*base-uri 'self'.*object-src 'none'",
        ]
        for pattern in required:
            self.assertRegex(text, pattern)

    def test_first_run_runtime_files_are_not_publicly_served(self):
        text = HTACCESS.read_text(encoding="utf-8")
        self.assertRegex(text, r"(?m)^RewriteRule \\^runtime\\(\\?:/\\|\\$\\) - \\[F,L\\]$")

    def test_hsts_does_not_assume_all_subdomains_use_https(self):
        text = HTACCESS.read_text(encoding="utf-8")
        hsts = re.search(r'(?m)^\s*Header always set Strict-Transport-Security "([^"]+)"', text)
        self.assertIsNotNone(hsts)
        self.assertNotIn("includeSubDomains", hsts.group(1))


if __name__ == "__main__":
    unittest.main()
