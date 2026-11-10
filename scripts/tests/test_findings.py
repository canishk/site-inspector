"""Unit tests for finding normalizers (no network)."""
from __future__ import annotations

import json
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from siteassess.findings import (  # noqa: E402
    from_nmap_xml,
    from_testssl_json,
    from_zap_report,
    merge,
)


FIXTURES = Path(__file__).parent / "fixtures"


class FindingsTests(unittest.TestCase):
    def test_zap_normalizer(self):
        data = json.loads((FIXTURES / "zap_sample.json").read_text(encoding="utf-8"))
        findings = from_zap_report(data)
        self.assertGreaterEqual(len(findings), 2)
        sevs = {f.severity for f in findings}
        self.assertIn("Low", sevs)
        self.assertIn("Medium", sevs)

    def test_nmap_normalizer(self):
        xml = (FIXTURES / "nmap_sample.xml").read_text(encoding="utf-8")
        findings = from_nmap_xml(xml)
        titles = " ".join(f.title for f in findings)
        self.assertIn("443", titles)
        self.assertIn("8080", titles)

    def test_testssl_normalizer(self):
        data = json.loads((FIXTURES / "testssl_sample.json").read_text(encoding="utf-8"))
        findings = from_testssl_json(data)
        self.assertTrue(any(f.severity == "High" for f in findings))
        self.assertFalse(any(f.title == "cert_notAfter" for f in findings))  # OK skipped

    def test_merge_dedupe(self):
        data = json.loads((FIXTURES / "zap_sample.json").read_text(encoding="utf-8"))
        a = from_zap_report(data)
        b = from_zap_report(data)
        merged = merge(a + b)
        self.assertEqual(len(merged), len(a))


if __name__ == "__main__":
    unittest.main()
