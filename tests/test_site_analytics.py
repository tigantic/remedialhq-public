from __future__ import annotations

import json
import subprocess
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
ANALYTICS = ROOT / "site" / "analytics.js"


class SiteAnalyticsContractTests(unittest.TestCase):
    def run_node(self, source: str) -> object:
        completed = subprocess.run(
            ["node", "-e", source],
            cwd=ROOT,
            check=True,
            capture_output=True,
            text=True,
        )
        return json.loads(completed.stdout)

    def test_contract_is_disabled_and_consent_denied_by_default(self) -> None:
        result = self.run_node(
            "const a=require('./site/analytics.js');"
            "console.log(JSON.stringify({status:a.status(),result:a.record('youtube_click')}));"
        )
        self.assertEqual(result["status"]["enabled"], False)
        self.assertEqual(result["status"]["consent"], "denied")
        self.assertEqual(result["result"], {"accepted": False, "reason": "disabled"})

    def test_all_seven_approved_events_are_exposed(self) -> None:
        result = self.run_node(
            "const a=require('./site/analytics.js');console.log(JSON.stringify(a.EVENT_NAMES));"
        )
        self.assertEqual(
            result,
            [
                "newsletter_signup",
                "youtube_click",
                "affiliate_click",
                "sponsor_inquiry",
                "article_complete",
                "return_visitor",
                "guide_download",
            ],
        )

    def test_event_requires_enablement_consent_and_an_explicit_sink(self) -> None:
        result = self.run_node(
            "const a=require('./site/analytics.js');"
            "let sent=[];"
            "a.configure({enabled:true,consent:'denied',sink:e=>sent.push(e)});"
            "const denied=a.record('article_complete',{surface:'official_state'});"
            "a.configure({enabled:true,consent:'granted'});"
            "const missing=a.record('article_complete',{surface:'official_state'});"
            "a.configure({enabled:true,consent:'granted',sink:e=>sent.push(e)});"
            "const accepted=a.record('article_complete',{surface:'official_state'});"
            "console.log(JSON.stringify({denied,missing,accepted,sent}));"
        )
        self.assertEqual(result["denied"]["reason"], "consent_required")
        self.assertEqual(result["missing"]["reason"], "sink_unconfigured")
        self.assertEqual(result["accepted"], {"accepted": True, "reason": "dispatched"})
        self.assertEqual(len(result["sent"]), 1)

    def test_sensitive_or_unbounded_parameters_are_rejected(self) -> None:
        result = self.run_node(
            "const a=require('./site/analytics.js');"
            "let errors=[];"
            "for(const p of [{email:'x@example.com'},{surface:'x'.repeat(121)}]){"
            "try{a.record('youtube_click',p)}catch(e){errors.push(e.constructor.name)}}"
            "console.log(JSON.stringify(errors));"
        )
        self.assertEqual(result, ["TypeError", "RangeError"])

    def test_newsletter_signup_requires_provider_confirmation(self) -> None:
        result = self.run_node(
            "const a=require('./site/analytics.js');"
            "let sent=[];a.configure({enabled:true,consent:'granted',sink:e=>sent.push(e)});"
            "const rejected=a.recordConfirmedNewsletterSignup({status:'requested'});"
            "const accepted=a.recordConfirmedNewsletterSignup({"
            "status:'confirmed',providerEventId:'evt_12345678'});"
            "console.log(JSON.stringify({rejected,accepted,sent}));"
        )
        self.assertEqual(result["rejected"]["reason"], "provider_confirmation_required")
        self.assertEqual(result["accepted"]["accepted"], True)
        self.assertEqual(result["sent"][0]["name"], "newsletter_signup")
        self.assertNotIn("providerEventId", result["sent"][0]["params"])

    def test_current_mailto_form_does_not_emit_a_signup(self) -> None:
        app = (ROOT / "site" / "app.js").read_text(encoding="utf-8")
        index = (ROOT / "site" / "index.html").read_text(encoding="utf-8")
        self.assertIn("mailto:support@remedialhq.com", app)
        self.assertNotIn("newsletter_signup", app)
        self.assertLess(index.index('src="analytics.js"'), index.index('src="app.js"'))


if __name__ == "__main__":
    unittest.main()
