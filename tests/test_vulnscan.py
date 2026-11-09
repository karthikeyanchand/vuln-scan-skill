"""Run with: python3 -m unittest discover tests"""
import json
import os
import shutil
import stat
import sys
import tempfile
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent / ".agents" / "skills" / "vuln-scan" / "scripts"))
import vulnscan  # noqa: E402

FIXTURE = HERE / "fixture"


class PipelineTest(unittest.TestCase):
    def setUp(self):
        self.out = Path(tempfile.mkdtemp())

    def tearDown(self):
        shutil.rmtree(self.out, ignore_errors=True)

    def test_recon_finds_flask_routes(self):
        recon = vulnscan.stage_recon(FIXTURE, self.out)
        self.assertIn("flask", recon["frameworks"])
        self.assertEqual({e["path"] for e in recon["entry_points"]}, {"/items", "/item/<int:item_id>"})

    def test_norm_cwe(self):
        self.assertEqual(vulnscan.norm_cwe("CWE-89: Improper Neutralization"), "CWE-89")
        self.assertEqual(vulnscan.norm_cwe(78), "CWE-78")
        self.assertIsNone(vulnscan.norm_cwe("n/a"))

    @unittest.skipUnless(shutil.which("semgrep"), "semgrep not installed")
    def test_semgrep_flags_injection_but_not_parameterised_query(self):
        findings = vulnscan.stage_scanners(FIXTURE, self.out, [])
        sqli = [f for f in findings if "CWE-89" in f["cwe"]]
        self.assertEqual(len(sqli), 1)
        self.assertEqual(sqli[0]["line"], 11)

    def test_antares_report_is_parsed_and_merged(self):
        bindir = Path(tempfile.mkdtemp())
        fake = bindir / "antares"
        shutil.copy(HERE / "fake_antares.py", fake)
        fake.chmod(fake.stat().st_mode | stat.S_IEXEC)
        old_path = os.environ["PATH"]
        os.environ["PATH"] = f"{bindir}{os.pathsep}{old_path}"
        try:
            leads = vulnscan.stage_antares(FIXTURE, self.out, None, ["CWE-89", "CWE-78"], 15, 1)
        finally:
            os.environ["PATH"] = old_path
            shutil.rmtree(bindir)
        self.assertEqual([(l["file"], l["cwe"]) for l in leads], [("app/views.py", ["CWE-89"])])
        cands = vulnscan.stage_merge(FIXTURE, self.out)
        self.assertEqual(cands[0]["sources"], ["antares"])

    def test_report_renders_markdown_and_sarif(self):
        triaged = {"triaged_by": "test", "findings": [
            {"file": "app/views.py", "line": 11, "cwe": "CWE-89", "title": "SQL injection",
             "verdict": "true_positive", "severity": "high", "rationale": "f-string SQL",
             "fix": "bind params", "sources": ["semgrep"]},
            {"file": "app/views.py", "line": 17, "cwe": "CWE-89", "title": "Parameterised",
             "verdict": "false_positive", "severity": "info", "rationale": "uses ?"}]}
        (self.out / "triaged.json").write_text(json.dumps(triaged))
        vulnscan.stage_report(FIXTURE, self.out)
        md = (self.out / "report.md").read_text()
        self.assertIn("| High | 1 |", md)
        self.assertIn("Dismissed", md)
        sarif = json.loads((self.out / "report.sarif").read_text())
        self.assertEqual(len(sarif["runs"][0]["results"]), 1)
        self.assertEqual(sarif["runs"][0]["results"][0]["locations"][0]["physicalLocation"]["region"]["startLine"], 11)

    def test_invalid_triage_is_rejected(self):
        errors = vulnscan.validate_triage({"findings": [{"file": "x", "verdict": "maybe"}]})
        self.assertTrue(any("verdict" in e for e in errors))
        self.assertTrue(any("rationale" in e for e in errors))


if __name__ == "__main__":
    unittest.main()
