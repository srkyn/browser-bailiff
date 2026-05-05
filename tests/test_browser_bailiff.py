import json
import os
import tempfile
import unittest
import zipfile

import browser_bailiff


class VersionTests(unittest.TestCase):
    def test_version_is_defined(self):
        self.assertRegex(browser_bailiff.VERSION, r"^\d+\.\d+\.\d+$")


class RiskScoringTests(unittest.TestCase):
    def test_high_risk_permission_is_explained(self):
        access = browser_bailiff.collect_manifest_access(
            {
                "permissions": ["storage", "cookies"],
                "host_permissions": [],
            }
        )
        risk, reasons = browser_bailiff.score_risk(
            "not-malicious", access, last_modified_days=10
        )
        self.assertEqual(risk, "HIGH")
        self.assertIn("cookies", reasons[0])

    def test_known_malicious_id_scores_high(self):
        access = browser_bailiff.collect_manifest_access({"permissions": []})
        risk, reasons = browser_bailiff.score_risk(
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", access, last_modified_days=10
        )
        self.assertEqual(risk, "HIGH")
        self.assertIn("known malicious", reasons[0])

    def test_stale_extension_scores_high(self):
        access = browser_bailiff.collect_manifest_access({"permissions": ["storage"]})
        risk, reasons = browser_bailiff.score_risk(
            "not-malicious", access, last_modified_days=400
        )
        self.assertEqual(risk, "HIGH")
        self.assertTrue(any("365 days" in r for r in reasons))

    def test_legacy_firefox_scores_high(self):
        access = browser_bailiff.collect_manifest_access({"permissions": []})
        risk, reasons = browser_bailiff.score_risk(
            "legacy@example.com", access, last_modified_days=10, firefox_legacy=True
        )
        self.assertEqual(risk, "HIGH")
        self.assertTrue(any("legacy" in r for r in reasons))

    def test_optional_sensitive_permission_is_medium(self):
        access = browser_bailiff.collect_manifest_access(
            {"permissions": [], "optional_permissions": ["cookies"]}
        )
        risk, reasons = browser_bailiff.score_risk(
            "not-malicious", access, last_modified_days=10
        )
        self.assertEqual(risk, "MEDIUM")
        self.assertIn("optional sensitive permission", reasons[0])

    def test_medium_permission_without_host_control_is_medium(self):
        access = browser_bailiff.collect_manifest_access(
            {"permissions": ["tabs", "storage"]}
        )
        risk, reasons = browser_bailiff.score_risk(
            "not-malicious", access, last_modified_days=10
        )
        self.assertEqual(risk, "MEDIUM")
        self.assertIn("moderate permission", reasons[0])

    def test_minimal_permissions_scores_low(self):
        access = browser_bailiff.collect_manifest_access({"permissions": []})
        risk, reasons = browser_bailiff.score_risk(
            "not-malicious", access, last_modified_days=10
        )
        self.assertEqual(risk, "LOW")
        self.assertIn("minimal", reasons[0])

    def test_medium_permission_with_host_control_does_not_reduce_to_medium(self):
        # tabs + <all_urls> should score HIGH due to <all_urls>, not be capped at MEDIUM
        access = browser_bailiff.collect_manifest_access(
            {"permissions": ["tabs", "<all_urls>"]}
        )
        risk, _ = browser_bailiff.score_risk(
            "not-malicious", access, last_modified_days=10
        )
        self.assertEqual(risk, "HIGH")


class HostControlTests(unittest.TestCase):
    def test_all_urls_is_host_control(self):
        self.assertTrue(browser_bailiff.has_host_control(["<all_urls>"]))

    def test_wildcard_scheme_is_host_control(self):
        self.assertTrue(browser_bailiff.has_host_control(["*://example.com/*"]))

    def test_explicit_url_is_host_control(self):
        self.assertTrue(browser_bailiff.has_host_control(["https://example.com/*"]))

    def test_api_permission_is_not_host_control(self):
        self.assertFalse(browser_bailiff.has_host_control(["tabs", "storage"]))

    def test_empty_permissions_is_not_host_control(self):
        self.assertFalse(browser_bailiff.has_host_control([]))


class ManifestParsingTests(unittest.TestCase):
    def test_content_script_matches_count_as_host_access(self):
        access = browser_bailiff.collect_manifest_access(
            {
                "permissions": ["storage"],
                "content_scripts": [{"matches": ["https://example.com/*"]}],
            }
        )
        self.assertIn("https://example.com/*", access["permissions"])
        self.assertTrue(browser_bailiff.has_host_control(access["permissions"]))

    def test_manifest_name_resolves_locale_message(self):
        with tempfile.TemporaryDirectory() as extension_dir:
            locale_dir = os.path.join(extension_dir, "_locales", "en_US")
            os.makedirs(locale_dir)
            with open(os.path.join(locale_dir, "messages.json"), "w", encoding="utf-8") as handle:
                json.dump({"extensionName": {"message": "Test Extension"}}, handle)
            name = browser_bailiff.manifest_name(
                {"name": "__MSG_extensionName__", "default_locale": "en_US"},
                extension_dir,
            )
        self.assertEqual(name, "Test Extension")

    def test_manifest_name_falls_back_to_unknown(self):
        name = browser_bailiff.manifest_name({})
        self.assertEqual(name, "Unknown")

    def test_manifest_name_returns_literal_name(self):
        name = browser_bailiff.manifest_name({"name": "My Extension"})
        self.assertEqual(name, "My Extension")

    def test_host_permissions_field_collected(self):
        access = browser_bailiff.collect_manifest_access(
            {"permissions": [], "host_permissions": ["https://api.example.com/*"]}
        )
        self.assertIn("https://api.example.com/*", access["permissions"])
        self.assertIn("https://api.example.com/*", access["host_permissions"])

    def test_is_firefox_legacy_without_manifest_version(self):
        self.assertTrue(browser_bailiff.is_firefox_legacy({}))
        self.assertTrue(browser_bailiff.is_firefox_legacy(None))

    def test_is_firefox_legacy_with_manifest_v2(self):
        self.assertFalse(browser_bailiff.is_firefox_legacy({"manifest_version": 2}))

    def test_firefox_extension_id_uses_gecko_id(self):
        manifest = {
            "browser_specific_settings": {"gecko": {"id": "addon@example.com"}}
        }
        ext_id = browser_bailiff.firefox_extension_id("addon@example.com.xpi", manifest)
        self.assertEqual(ext_id, "addon@example.com")

    def test_manifest_update_url_from_gecko(self):
        manifest = {
            "browser_specific_settings": {
                "gecko": {"update_url": "https://updates.example.com/addon.json"}
            }
        }
        url = browser_bailiff.manifest_update_url(manifest)
        self.assertEqual(url, "https://updates.example.com/addon.json")


class XpiTests(unittest.TestCase):
    def test_firefox_xpi_manifest_is_read(self):
        manifest = {
            "manifest_version": 2,
            "name": "Firefox Test",
            "version": "1.0.0",
        }
        with tempfile.TemporaryDirectory() as temp_dir:
            xpi_path = os.path.join(temp_dir, "firefox-test.xpi")
            with zipfile.ZipFile(xpi_path, "w") as archive:
                archive.writestr("manifest.json", json.dumps(manifest))
            loaded = browser_bailiff.read_manifest_from_xpi(xpi_path)
        self.assertEqual(loaded["name"], "Firefox Test")

    def test_corrupted_xpi_returns_none(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            bad_xpi = os.path.join(temp_dir, "corrupt.xpi")
            with open(bad_xpi, "w") as handle:
                handle.write("not a zip file")
            result = browser_bailiff.read_manifest_from_xpi(bad_xpi)
        self.assertIsNone(result)


class JsonOutputTests(unittest.TestCase):
    def test_write_json_output_produces_valid_structure(self):
        results = [{"browser": "Chrome", "name": "Test", "risk": "LOW"}]
        errors = []
        with tempfile.TemporaryDirectory() as temp_dir:
            output_path = os.path.join(temp_dir, "output.json")
            browser_bailiff.write_json_output(output_path, results, errors)
            with open(output_path, encoding="utf-8") as handle:
                payload = json.load(handle)
        self.assertIn("results", payload)
        self.assertIn("errors", payload)
        self.assertIn("generated_at", payload)
        self.assertEqual(len(payload["results"]), 1)

    def test_clipped_truncates_long_text(self):
        long = "a" * 50
        result = browser_bailiff.clipped(long, 20)
        self.assertEqual(len(result), 20)
        self.assertTrue(result.endswith("..."))

    def test_clipped_passes_short_text(self):
        self.assertEqual(browser_bailiff.clipped("short", 20), "short")


if __name__ == "__main__":
    unittest.main()
