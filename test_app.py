import unittest

from app import analyze, app, analyze_url


class TrapdoorAnalysisTests(unittest.TestCase):
    def setUp(self):
        self.client = app.test_client()

    def test_empty_input_is_rejected(self):
        response = self.client.post("/api/analyze", json={"text": "  "})
        self.assertEqual(response.status_code, 400)

    def test_homepage_and_static_assets_load(self):
        page = self.client.get("/")
        stylesheet = self.client.get("/static/style.css")
        script = self.client.get("/static/script.js")
        self.assertEqual(page.status_code, 200)
        self.assertIn(b"See the clues", page.data)
        self.assertEqual(stylesheet.status_code, 200)
        self.assertEqual(script.status_code, 200)
        stylesheet.close()
        script.close()

    def test_valid_input_returns_structured_report(self):
        response = self.client.post("/api/analyze", json={"text": "Routine library notice. No action needed."})
        self.assertEqual(response.status_code, 200)
        payload = response.get_json()
        self.assertEqual(payload["score_type"], "heuristic")
        self.assertEqual(payload["reputation"]["status"], "not_checked")
        self.assertIn("findings", payload)

    def test_urgent_credential_message_surfaces_evidence(self):
        result = analyze("URGENT: verify your account today at http://paypaI.example.test/login", "sms")
        rules = {item["rule"] for item in result["findings"]}
        self.assertIn("URGENT_LANGUAGE", rules)
        self.assertIn("CREDENTIAL_REQUEST", rules)
        self.assertIn("BRAND_NAME_IN_DOMAIN", rules)
        self.assertEqual(result["verdict"], "HIGH_RISK")

    def test_url_authority_and_ip_signals_are_explained(self):
        findings = analyze_url("http://paypal.com@192.0.2.10/login")
        rules = {item["rule"] for item in findings}
        self.assertIn("AT_SIGN_IN_AUTHORITY", rules)
        self.assertIn("IP_ADDRESS_HOST", rules)
        self.assertIn("NO_HTTPS", rules)

    def test_no_signal_result_does_not_claim_safe(self):
        result = analyze("Please see the community update.")
        self.assertEqual(result["verdict"], "NO_SIGNALS_FOUND")
        self.assertIn("does not confirm", result["summary"])

    def test_long_input_is_rejected(self):
        response = self.client.post("/api/analyze", json={"text": "x" * 20001})
        self.assertEqual(response.status_code, 413)


if __name__ == "__main__":
    unittest.main()

