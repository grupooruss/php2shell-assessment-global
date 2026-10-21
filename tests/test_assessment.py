import json
import io
from contextlib import redirect_stdout
from pathlib import Path
import sys
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, HTTPServer

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from php2shell_assess import classify, load_advisory, normalize_version, web_probe, inventory_probe, save_reports, main

PRE = {"release_status": "pending", "minimum_fixed_versions": {}}
PUBLISHED = {"release_status": "published", "minimum_fixed_versions": {"8.4": "8.4.27"}}


class SampleHandler(BaseHTTPRequestHandler):
    def do_HEAD(self):
        self.send_response(200)
        if self.path == "/php":
            self.send_header("X-Powered-By", "PHP/8.4.26")
        self.end_headers()

    def do_GET(self):
        self.send_response(200)
        if self.path == "/get":
            self.send_header("X-Powered-By", "PHP/8.3.35")
        self.end_headers()
        self.wfile.write(b"Mock host; no sensitive data")

    def log_message(self, *args):
        pass


class AssessmentTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.httpd = HTTPServer(("127.0.0.1", 0), SampleHandler)
        cls.server_thread = threading.Thread(target=cls.httpd.serve_forever, daemon=True)
        cls.server_thread.start()
        cls.base = f"http://127.0.0.1:{cls.httpd.server_port}"

    @classmethod
    def tearDownClass(cls):
        cls.httpd.shutdown()
        cls.server_thread.join(timeout=3)
        cls.httpd.server_close()

    def test_version_parser(self):
        self.assertEqual(normalize_version("PHP/8.4.26"), "8.4.26")
        self.assertIsNone(normalize_version("none"))

    def test_pending_cannot_claim_rce(self):
        self.assertEqual(classify("8.4.26", PRE)[0], "PENDING_VENDOR_MATRIX")
        self.assertEqual(classify("7.4.33", PRE)[0], "EOL_UNSUPPORTED")
        self.assertEqual(classify(None, PRE)[0], "NO_VERSION_OBSERVED")

    def test_official_matrix(self):
        self.assertEqual(classify("8.4.26", PUBLISHED)[0], "BELOW_OFFICIAL_FIX")
        self.assertEqual(classify("8.4.27", PUBLISHED)[0], "MEETS_UPSTREAM_VERSION")
        self.assertEqual(classify("8.4.27-RC1", PUBLISHED)[0], "PRERELEASE_REVIEW")

    def test_detect_http_head(self):
        r = web_probe(self.base + "/php", PRE, 3, False)
        self.assertEqual(r["php_version"], "8.4.26")
        self.assertEqual(r["status"], "PENDING_VENDOR_MATRIX")
        self.assertEqual(r["method"], "http-head")

    def test_detect_http_get_fallback(self):
        r = web_probe(self.base + "/get", PRE, 3, False)
        self.assertEqual(r["php_version"], "8.3.35")
        self.assertEqual(r["method"], "http-get")

    def test_no_header_is_not_safe(self):
        r = web_probe(self.base + "/", PRE, 3, False)
        self.assertEqual(r["status"], "NO_VERSION_OBSERVED")

    def test_advisory_guard_and_inventory_reports(self):
        with tempfile.TemporaryDirectory() as td:
            base = Path(td)
            advisory_path = base / "advisory.json"
            advisory_path.write_text(json.dumps({"schema_version": 1, "release_status": "pending", "minimum_fixed_versions": {"8.4": "8.4.27"}}), encoding="utf-8")
            with self.assertRaises(ValueError):
                load_advisory(advisory_path)
            csv_path = base / "inventory.csv"
            csv_path.write_text("asset,php_version\nbackend-test,8.4.26\n", encoding="utf-8")
            rows = inventory_probe(csv_path, PRE)
            path_csv, path_json = save_reports(base / "results" / "test", rows, PRE)
            self.assertTrue(path_csv.exists())
            self.assertEqual(len(json.loads(path_json.read_text(encoding="utf-8"))["results"]), 1)


    def test_english_cli_and_report(self):
        with tempfile.TemporaryDirectory() as td:
            output = io.StringIO()
            with redirect_stdout(output):
                code = main(["--php-version", "8.4.26", "--asset", "demo-server", "--out", str(Path(td) / "assessment")])
            self.assertEqual(code, 0)
            self.assertIn("1 asset(s)", output.getvalue())
            self.assertIn("Version-based findings do not establish RCE exploitability", output.getvalue())
            report = json.loads((Path(td) / "assessment.json").read_text(encoding="utf-8"))
            self.assertIn("Inventory only", report["disclaimer"])
            self.assertIn("Prioritize inventory", report["results"][0]["recommendation"])
            self.assertIn("Operator-provided version", report["results"][0]["evidence"])


if __name__ == "__main__":
    unittest.main()
