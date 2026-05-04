import json
import os
import tempfile
import unittest
import zipfile

import browser_bailiff


class BrowserBailiffTests(unittest.TestCase):
    def test_high_risk_permission_is_explained(self):
        access = browser_bailiff.collect_manifest_access(
            {
                "permissions": ["storage", "cookies"],
                "host_permissions": [],
            }
        )

        risk, reasons = browser_bailiff.score_risk(
            "not-malicious",
            access,
            last_modified_days=10,
        )

        self.assertEqual(risk, "HIGH")
        self.assertIn("cookies", reasons[0])

    def test_content_script_matches_count_as_host_access(self):
        access = browser_bailiff.collect_manifest_access(
            {
                "permissions": ["storage"],
                "content_scripts": [{"matches": ["https://example.com/*"]}],
            }
        )

        self.assertIn("https://example.com/*", access["permissions"])
        self.assertTrue(browser_bailiff.has_host_control(access["permissions"]))

    def test_optional_sensitive_permission_is_medium(self):
        access = browser_bailiff.collect_manifest_access(
            {
                "permissions": [],
                "optional_permissions": ["cookies"],
            }
        )

        risk, reasons = browser_bailiff.score_risk(
            "not-malicious",
            access,
            last_modified_days=10,
        )

        self.assertEqual(risk, "MEDIUM")
        self.assertIn("optional sensitive permission", reasons[0])

    def test_manifest_name_resolves_locale_message(self):
        with tempfile.TemporaryDirectory() as extension_dir:
            locale_dir = os.path.join(extension_dir, "_locales", "en_US")
            os.makedirs(locale_dir)
            with open(os.path.join(locale_dir, "messages.json"), "w", encoding="utf-8") as handle:
                json.dump({"extensionName": {"message": "Test Extension"}}, handle)

            name = browser_bailiff.manifest_name(
                {
                    "name": "__MSG_extensionName__",
                    "default_locale": "en_US",
                },
                extension_dir,
            )

        self.assertEqual(name, "Test Extension")

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


if __name__ == "__main__":
    unittest.main()
