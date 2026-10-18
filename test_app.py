import json
import os
import unittest
from unittest.mock import patch

from app import analyze, app, analyze_url, _tinyfish_safe_url


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

    def test_hosted_api_requires_the_netlify_proxy_token(self):
        with patch.dict(os.environ, {"TRAPDOOR_PROXY_TOKEN": "deployment-secret"}):
            denied = self.client.post("/api/analyze", json={"text": "hello"})
            allowed = self.client.post(
                "/api/analyze", json={"text": "hello"},
                headers={"Authorization": "Bearer deployment-secret"},
            )
            health = self.client.get("/api/health")
        self.assertEqual(denied.status_code, 403)
        self.assertEqual(allowed.status_code, 200)
        self.assertEqual(health.status_code, 200)

    def test_valid_input_returns_structured_report(self):
        response = self.client.post("/api/analyze", json={"text": "Routine library notice. No action needed."})
        self.assertEqual(response.status_code, 200)
        payload = response.get_json()
        self.assertEqual(payload["score_type"], "heuristic")
        self.assertEqual(payload["reputation"]["status"], "not_checked")
        self.assertIn("findings", payload)

    def test_live_check_without_key_is_explicit_and_makes_no_network_call(self):
        with patch.dict(os.environ, {"TINYFISH_API_KEY": ""}), patch("app.urllib.request.urlopen") as open_url:
            response = self.client.post("/api/analyze", json={
                "text": "https://wikipedia.org/wiki/Phishing plus support@example.org",
                "tinyfish_enabled": True,
            })
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.get_json()["live_inspection"]["status"], "not_configured")
        open_url.assert_not_called()

    def test_key_template_placeholder_is_not_mistaken_for_a_real_key(self):
        with patch.dict(os.environ, {"TINYFISH_API_KEY": "your_tinyfish_api_key_here"}):
            response = self.client.get("/api/health")
        self.assertFalse(response.get_json()["tinyfish_configured"])

    def test_tinyfish_url_filter_skips_local_reserved_and_ambiguous_targets(self):
        for value in (
            "http://127.0.0.1/admin",
            "http://192.0.2.45/login",
            "http://localhost:5000/",
            "https://mail.test/login",
            "https://example.com/contact",
            "https://trusted.example.com@evil.test/login",
            "https://wikipedia.org:8443/",
            "data:text/html,hello",
        ):
            with self.subTest(value=value):
                self.assertIsNone(_tinyfish_safe_url(value))
        self.assertEqual(_tinyfish_safe_url("https://wikipedia.org/wiki/Phishing"), "https://wikipedia.org/wiki/Phishing")

    def test_tinyfish_fetch_contributes_page_evidence_and_sends_only_urls(self):
        payload = {"results": [{
            "url": "https://wikipedia.org/wiki/Phishing",
            "final_url": "https://wikipedia.org/wiki/Phishing",
            "title": "PayPal secure sign in",
            "description": "Sign in to your account",
            "text": "Enter your password to continue.",
        }], "errors": []}

        class FakeResponse:
            def __enter__(self):
                return self
            def __exit__(self, *_args):
                return False
            def read(self):
                return json.dumps(payload).encode("utf-8")

        with patch.dict(os.environ, {"TINYFISH_API_KEY": "test-key"}), patch("app.urllib.request.urlopen", return_value=FakeResponse()) as open_url:
            response = self.client.post("/api/analyze", json={
                "text": "Review https://wikipedia.org/wiki/Phishing. Sender: support@example.org",
                "tinyfish_enabled": True,
            })

        self.assertEqual(response.status_code, 200)
        report = response.get_json()
        self.assertEqual(report["live_inspection"]["status"], "checked")
        self.assertEqual(report["live_inspection"]["pages"][0]["title"], "PayPal secure sign in")
        self.assertIn("TINYFISH_BRAND_LOGIN_TITLE", {item["rule"] for item in report["findings"]})
        sent_body = json.loads(open_url.call_args.args[0].data)
        self.assertEqual(sent_body["urls"], ["https://wikipedia.org/wiki/Phishing"])
        self.assertNotIn("support@example.org", json.dumps(sent_body))

    def test_tinyfish_outage_is_not_a_safety_signal(self):
        with patch.dict(os.environ, {"TINYFISH_API_KEY": "test-key"}), patch("app.urllib.request.urlopen", side_effect=TimeoutError()):
            response = self.client.post("/api/analyze", json={
                "text": "https://wikipedia.org/",
                "tinyfish_enabled": True,
            })
        report = response.get_json()
        self.assertEqual(report["live_inspection"]["status"], "unavailable")
        self.assertIn("not a safe result", report["live_inspection"]["detail"])

    def test_tinyfish_is_not_called_when_user_turns_live_check_off(self):
        with patch.dict(os.environ, {"TINYFISH_API_KEY": "test-key"}), patch("app.urllib.request.urlopen") as open_url:
            response = self.client.post("/api/analyze", json={
                "text": "https://wikipedia.org/",
                "tinyfish_enabled": False,
            })
        self.assertEqual(response.get_json()["live_inspection"]["status"], "not_requested")
        open_url.assert_not_called()

    def test_urgent_credential_message_surfaces_evidence(self):
        result = analyze("URGENT: verify your account today at http://paypaI.example.test/login", "sms")
        rules = {item["rule"] for item in result["findings"]}
        self.assertIn("URGENT_LANGUAGE", rules)
        self.assertIn("CREDENTIAL_REQUEST", rules)
        self.assertIn("BRAND_NAME_IN_DOMAIN", rules)
        self.assertIn(result["verdict"], {"HIGH_RISK", "CRITICAL_RISK"})

    def test_user_safe_url_benchmark_has_no_findings(self):
        safe_urls = [
            "https://www.wikipedia.org/wiki/Phishing",
            "https://docs.python.org/3/library/urllib.html",
            "https://github.com/torvalds/linux",
            "https://www.example.com/contact",
            "https://accounts.example.com/oauth2/authorize?client_id=abc&redirect_uri=https%3A%2F%2Fapp.example.org%2Fcb",
            "https://user:pass@ftp.example.com/files",
            "https://my-company-portal.example.com/login",
        ]
        for value in safe_urls:
            with self.subTest(value=value):
                result = analyze(value, "url")
                self.assertEqual(result["risk_score"], 0)
                self.assertEqual(result["findings"], [])

    def test_user_suspicious_url_benchmark_triggers_signals(self):
        suspicious_urls = [
            "http://192.0.2.45/login/verify-account.php",
            "http://secure-bank-login.example/update-password",
            "http://free-gift-card-winner.test/claim?id=88231",
            "http://account-suspended.example/restore@verify",
            "https://paypa1-secure.example/signin",
            "https://login.microsoft.com.account-verify.test/auth",
            "https://amazon-order-help.example/track?order=112-9981234",
            "https://www.example.com@evil-host.test/login",
            "http://short.example/x7Gh2",
            "https://secure.example.com.verify-session.test/?redirect=//login",
            "https://xn--pypal-4ve.test/login",
            "https://example.com/redirect?url=http%3A%2F%2Fphish-landing.test%2Flogin",
            "https://sites.example.com/forms/d/e/1FAIpQLSd-sample/viewform",
            "http://0xC0.0x00.0x02.0x2D/secure",
            "http://3221225517/account",
            "https://cdn-assets.example/invoice.pdf.html",
            "https://login.example.com.%2e%2e.verify.test/",
            "data:text/html;base64,PGh0bWw+ZmFrZSBsb2dpbjwvaHRtbD4=",
        ]
        for value in suspicious_urls:
            with self.subTest(value=value):
                result = analyze(value, "url")
                self.assertGreater(result["risk_score"], 0)
                self.assertTrue(result["findings"])

    def test_user_safe_email_benchmark_has_no_findings(self):
        safe_emails = [
            "support@example.com",
            "jane.doe@example.org",
            "newsletter@mail.example.com",
            "no-reply+order-8812@shop.example.com",
            "first.last+newsletters@example.org",
            "billing@invoices.example.com",
        ]
        for value in safe_emails:
            with self.subTest(value=value):
                result = analyze(value, "email")
                self.assertEqual(result["risk_score"], 0)
                self.assertEqual(result["findings"], [])

    def test_user_suspicious_email_benchmark_triggers_signals(self):
        suspicious_emails = [
            "winner-lottery-2026@free-prize.test",
            "urgent.security.alert@bank-verify.example",
            "no-reply123456@gmail-support-team.test",
            "security@paypa1-support.example",
            "ceo.john.smith@gmail.example",
            "billing@microsoft-365-renewal.test",
            "admin@yourcompany.com.hr-portal.test",
            "ceo@yourcompany.co",
            "payroll@xn--yourcompny-t7a.test",
            "a.b.c.d+track123@sub.mail-relay.test",
            '"Microsoft Support <support@microsoft.com>"@evil.test',
        ]
        for value in suspicious_emails:
            with self.subTest(value=value):
                result = analyze(value, "email")
                self.assertGreater(result["risk_score"], 0)
                self.assertTrue(result["findings"])

    def test_reply_to_mismatch_and_failed_authentication_headers_are_detected(self):
        message = (
            "From: it-helpdesk@yourcompany.example\n"
            "Reply-To: helpdesk.reply@freemail.test\n"
            "Authentication-Results: mx; spf=fail; dkim=fail; dmarc=fail\n"
            "Subject: Please update payroll\n\n"
            "Please verify your account today."
        )
        result = analyze(message, "email")
        rules = {item["rule"] for item in result["findings"]}
        self.assertIn("REPLY_TO_DOMAIN_MISMATCH", rules)
        self.assertIn("EMAIL_AUTHENTICATION_FAILURE", rules)
        self.assertIn(result["verdict"], {"HIGH_RISK", "CRITICAL_RISK"})

    def test_hard_url_evasion_benchmark(self):
        samples = [
            r"https://\u0430pple-id.test/signin",
            r"https://exa\u200Bmple-login.test/",
            r"https://github\u2215user\u2215repo.evil-host.test/",
            r"https://files.example.test/invoice_\u202Efdp.exe",
            "https://rnicrosoft-support.test/",
            "https://accounts.google.com@login-check.test/",
            r"https://trusted.example.com\@evil-host.test/",
            "https://evil-host.test/#https://www.example.com/login",
            "https://evil-host.test?.example.com/login",
            "//evil-host.test/login",
            "https://www.example.com.secure.login.account.verification.session.update.evil-host.test/",
            "http://0300.0000.0002.0055/login",
            "http://0xC0.0.2.45/login",
            "http://[2001:db8::45]/login",
            "http://192.0.2.45:8080/secure",
            "http://0xC0000245/login",
            "https://example.com/redirect?url=http%253A%252F%252Fphish-landing.test%252Flogin",
            "https://example.com/out?u=aHR0cDovL3BoaXNoLWxhbmRpbmcudGVzdC9sb2dpbg==",
            "https://example.com/r?next=https://example.org/r?next=http://phish-landing.test/",
            "javascript:location='http://phish-landing.test/login'",
            "https://files.example.test/Invoice_8812.pdf.exe",
            "https://files.example.test/Invoice_8812.iso",
            "https://files.example.test/Invoice_8812.lnk",
            "<a href=\"http://phish-landing.test/login\">https://www.example.com/login</a>",
            "https://xn--pypal-4ve.test/login",
            "http://secure-bank-login.example/update-password",
            "http://free-gift-card-winner.test/claim?id=88231",
            "http://account-suspended.example/restore@verify",
        ]
        for value in samples:
            with self.subTest(value=value):
                result = analyze(value, "url")
                self.assertGreater(result["risk_score"], 0)
                self.assertTrue(result["recommended_action"])
        strong_cases = [samples[i] for i in (0, 1, 2, 3, 10, 11, 14, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26)]
        for value in strong_cases:
            with self.subTest(strong_value=value):
                self.assertGreaterEqual(analyze(value, "url")["risk_score"], 50)

    def test_new_safe_context_traps(self):
        safe = [
            "https://münchen.example/rathaus",
            "http://192.168.1.10/admin",
            "http://localhost:3000/",
            "https://example.com/redirect?url=https%3A%2F%2Fexample.com%2Fdashboard",
            "no-reply@accounts.example.com\nSubject: Your password reset code expires in 10 minutes\n\nYour reset code is ready.",
        ]
        for value in safe:
            with self.subTest(value=value):
                self.assertEqual(analyze(value)["risk_score"], 0)

    def test_email_spoof_and_unicode_benchmark(self):
        samples = [
            '"PayPal Service" <noreply@random-mailer.test>',
            "support@microsoft.com.evil-host.test",
            "paypal.com.security.update@random-mailer.test",
            '"admin@yourcompany.com"@evil-host.test',
            "user%yourcompany.com@evil-host.test",
            "admin@[192.0.2.45]",
            r"s\u0443stem-alerts@yourcompany.test",
            "john(promo)@example.test",
        ]
        for value in samples:
            with self.subTest(value=value):
                result = analyze(value, "email")
                self.assertGreater(result["risk_score"], 0)
                self.assertTrue(result["recommended_action"])
        for value in samples[:7]:
            with self.subTest(strong_email=value):
                self.assertGreaterEqual(analyze(value, "email")["risk_score"], 25)

    def test_forwarded_spf_failure_with_dkim_pass_is_not_treated_as_attack(self):
        message = (
            "From: newsletter@example.org\n"
            "Authentication-Results: mx; spf=fail; dkim=pass; dmarc=pass\n\n"
            "Forwarded mailing list update."
        )
        result = analyze(message, "email")
        self.assertNotIn("EMAIL_AUTHENTICATION_FAILURE", {item["rule"] for item in result["findings"]})

    def test_dmarc_pass_prevents_spf_and_dkim_failures_from_being_overstated(self):
        message = (
            "From: newsletter@example.org\n"
            "Authentication-Results: mx; spf=fail; dkim=fail; dmarc=pass\n\n"
            "Forwarded mailing list update."
        )
        result = analyze(message, "email")
        self.assertNotIn("EMAIL_AUTHENTICATION_FAILURE", {item["rule"] for item in result["findings"]})

    def test_reply_to_and_return_path_are_actionable_and_scored(self):
        message = (
            "From: billing@example.com\n"
            "Return-Path: <bounce@mailer-x.test>\n"
            "Reply-To: pay.me@freemail.test\n"
            "Authentication-Results: mx; spf=fail; dkim=fail; dmarc=fail\n\n"
            "Please send payment today."
        )
        result = analyze(message, "email")
        rules = {item["rule"] for item in result["findings"]}
        self.assertIn("REPLY_TO_DOMAIN_MISMATCH", rules)
        self.assertIn("RETURN_PATH_DOMAIN_MISMATCH", rules)
        self.assertIn("EMAIL_AUTHENTICATION_FAILURE", rules)
        self.assertGreaterEqual(result["risk_score"], 75)
        self.assertIn("Do not", result["recommended_action"])

    def test_clean_score_gives_a_useful_conditional_recommendation(self):
        result = analyze("https://www.wikipedia.org/wiki/Phishing", "url")
        self.assertEqual(result["risk_score"], 0)
        self.assertIn("reasonable to open", result["recommended_action"])
        self.assertIn("likely okay", result["action_label"])
        self.assertIn("No obvious warning signs", result["summary"])

    def test_payment_change_and_first_contact_urgency_are_high_risk(self):
        result = analyze(
            "First contact from a new vendor: URGENT, our bank details changed. Send the wire transfer today.",
            "email",
        )
        rules = {item["rule"] for item in result["findings"]}
        self.assertIn("PAYMENT_DESTINATION_CHANGE", rules)
        self.assertIn("FIRST_CONTACT_URGENT_PAYMENT", rules)
        self.assertGreaterEqual(result["risk_score"], 75)
        self.assertIn("Do not", result["recommended_action"])

    def test_sensitive_role_dot_co_gets_a_caution_without_claiming_a_tld_swap(self):
        result = analyze("ceo@yourcompany.co", "email")
        self.assertGreater(result["risk_score"], 0)
        self.assertLess(result["risk_score"], 25)
        self.assertIn("could be confused", result["findings"][0]["title"])
        self.assertIn("POSSIBLE_EXECUTIVE_TLD_SWAP", {item["rule"] for item in result["findings"]})

    def test_executive_display_name_on_free_mail_and_vendor_payment_domain_are_flagged(self):
        display_result = analyze('"Priya Sharma (CFO)" <priya@gmail.com>', "email")
        self.assertIn("EXECUTIVE_DISPLAY_NAME_FREE_MAIL", {item["rule"] for item in display_result["findings"]})
        vendor_result = analyze("payments@yourcompany-vendor-portal.test", "email")
        self.assertIn("PAYMENT_ROLE_VENDOR_DOMAIN", {item["rule"] for item in vendor_result["findings"]})
        self.assertGreaterEqual(analyze("ceo.john.smith@gmail.example", "email")["risk_score"], 50)
        self.assertGreaterEqual(analyze("admin@yourcompany.com.hr-portal.test", "email")["risk_score"], 50)

    def test_url_authority_and_ip_signals_are_explained(self):
        findings = analyze_url("http://paypal.com@192.0.2.10/login")
        rules = {item["rule"] for item in findings}
        self.assertIn("AT_SIGN_IN_AUTHORITY", rules)
        self.assertIn("IP_ADDRESS_HOST", rules)
        self.assertIn("NO_HTTPS", rules)

    def test_no_signal_result_gives_a_clear_conditional_decision(self):
        result = analyze("Please see the community update.")
        self.assertEqual(result["verdict"], "NO_SIGNALS_FOUND")
        self.assertIn("reasonable to continue", result["recommended_action"])
        self.assertIn("did not inspect the live page", result["summary"])

    def test_hard_url_patterns_produce_decisive_actions(self):
        samples = {
            "http://192.0.2.45/login/verify-account.php": ("HIGH_RISK", "do not use it"),
            "https://amazon-order-help.example/track?order=112-9981234": ("HIGH_RISK", "do not use it"),
            "https://login.example.com.%2e%2e.verify.test/": ("CRITICAL_RISK", "Avoid"),
        }
        for value, (verdict, action) in samples.items():
            with self.subTest(value=value):
                result = analyze(value, "url")
                self.assertEqual(result["verdict"], verdict)
                self.assertIn(action.lower(), result["action_label"].lower())

    def test_single_hosted_form_signal_is_caution_not_a_phishing_verdict(self):
        result = analyze("https://sites.example.com/forms/d/e/1FAIpQLSd-sample/viewform", "url")
        self.assertEqual(result["verdict"], "LOW_RISK")
        self.assertIn("may be legitimate", result["recommended_action"])

    def test_long_input_is_rejected(self):
        response = self.client.post("/api/analyze", json={"text": "x" * 20001})
        self.assertEqual(response.status_code, 413)


if __name__ == "__main__":
    unittest.main()

