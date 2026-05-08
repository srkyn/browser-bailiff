#!/usr/bin/env python3
"""
Browser Bailiff: audit installed browser extensions for Chrome, Edge, and Firefox.

The bailiff inspects browser profile extension directories, extracts metadata
from manifest.json files, assigns a simple risk level, prints a readable table,
and can optionally write JSON results.
"""

import argparse
import glob
import json
import os
import time
import zipfile


VERSION = "0.2.1"

# Demonstration block-list entries. Replace or extend this set with trusted
# intelligence from your own allow/block lists before using for enforcement.
KNOWN_MALICIOUS_IDS = {
    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
    "cccccccccccccccccccccccccccccccc",
    "malicious-sample@example.com",
}

HIGH_RISK_PERMISSIONS = {
    "cookies",
    "<all_urls>",
    "debugger",
    "webRequest",
    "webRequestBlocking",
    "nativeMessaging",
    "management",
}

MEDIUM_RISK_PERMISSIONS = {
    "bookmarks",
    "clipboardRead",
    "downloads",
    "history",
    "proxy",
    "scripting",
    "storage",
    "tabs",
}

RISK_ORDER = {
    "HIGH": 0,
    "MEDIUM": 1,
    "LOW": 2,
}

BROWSER_PROFILE_ROOTS = {
    "chrome": {
        "windows": r"%LOCALAPPDATA%\Google\Chrome\User Data",
        "macos": "~/Library/Application Support/Google/Chrome",
        "linux": "~/.config/google-chrome",
    },
    "edge": {
        "windows": r"%LOCALAPPDATA%\Microsoft\Edge\User Data",
        "macos": "~/Library/Application Support/Microsoft Edge",
        "linux": "~/.config/microsoft-edge",
    },
    "firefox": {
        "windows": r"%APPDATA%\Mozilla\Firefox\Profiles",
        "macos": "~/Library/Application Support/Firefox/Profiles",
        "linux": "~/.mozilla/firefox",
    },
}


def detect_os():
    """Return a normalized OS name supported by this script."""
    if os.name == "nt":
        return "windows"

    platform = os.uname().sysname.lower()
    if platform == "darwin":
        return "macos"
    if platform == "linux":
        return "linux"
    return "unknown"


def expand_path(path):
    """Expand environment variables and a leading home directory marker."""
    return os.path.expanduser(os.path.expandvars(path))


def browser_profile_root(browser, os_name):
    """Return the profile root directory for a browser on the current OS."""
    path = BROWSER_PROFILE_ROOTS.get(browser, {}).get(os_name)
    if not path:
        return None
    return expand_path(path)


def profile_name_from_extension_path(path):
    """Return the browser profile directory name from an Extensions path."""
    return os.path.basename(os.path.dirname(path)) or "Unknown"


def browser_extension_paths(browser, os_name):
    """Return candidate extension directories for a browser on the current OS."""
    root = browser_profile_root(browser, os_name)
    if not root:
        return []

    if browser in ("chrome", "edge"):
        # Include the requested Default path plus other common Chromium profiles.
        patterns = [
            os.path.join(root, "Default", "Extensions"),
            os.path.join(root, "Profile *", "Extensions"),
        ]
    else:
        # Firefox commonly uses .default-release as well as .default, but
        # profile names vary, so include any profile directory with extensions.
        patterns = [
            os.path.join(root, "*.default", "extensions"),
            os.path.join(root, "*.default-release", "extensions"),
            os.path.join(root, "*", "extensions"),
        ]

    paths = []
    for pattern in patterns:
        matches = glob.glob(pattern) if "*" in pattern else [pattern]
        for match in matches:
            if match not in [item["path"] for item in paths]:
                paths.append(
                    {
                        "path": match,
                        "profile": profile_name_from_extension_path(match),
                    }
                )
    return paths


def read_json_file(path):
    """Read a JSON file, returning None if it cannot be decoded or opened."""
    try:
        with open(path, "r", encoding="utf-8") as handle:
            return json.load(handle)
    except (OSError, json.JSONDecodeError, UnicodeDecodeError):
        return None


def read_manifest_from_xpi(path):
    """Read manifest.json from a Firefox .xpi archive."""
    try:
        with zipfile.ZipFile(path, "r") as archive:
            with archive.open("manifest.json") as manifest_file:
                return json.loads(manifest_file.read().decode("utf-8"))
    except (OSError, KeyError, zipfile.BadZipFile, json.JSONDecodeError, UnicodeDecodeError):
        return None


def read_locale_messages(extension_path, default_locale):
    """Read Chrome/Edge _locales messages for localized manifest names."""
    locale_candidates = []
    if default_locale:
        locale_candidates.append(default_locale)
    locale_candidates.extend(["en_US", "en"])

    seen = set()
    for locale in locale_candidates:
        if locale in seen:
            continue
        seen.add(locale)
        locale_path = os.path.join(extension_path, "_locales", locale, "messages.json")
        messages = read_json_file(locale_path)
        if isinstance(messages, dict):
            return messages
    return {}


def get_last_modified_info(path):
    """Return modification epoch seconds and days elapsed, if available."""
    try:
        modified = os.path.getmtime(path)
    except OSError:
        return None, None
    return int(modified), int((time.time() - modified) // 86400)


def manifest_name(manifest, extension_path=None):
    """Return a readable extension name from a manifest dictionary."""
    name = manifest.get("name") or "Unknown"

    if (
        isinstance(name, str)
        and name.startswith("__MSG_")
        and name.endswith("__")
        and extension_path
    ):
        key = name[6:-2]
        messages = read_locale_messages(extension_path, manifest.get("default_locale"))
        message = messages.get(key, {})
        if isinstance(message, dict) and message.get("message"):
            return str(message["message"])

    return str(name)


def content_script_matches(manifest):
    """Return host matches declared by content scripts."""
    matches = []
    for script in manifest.get("content_scripts") or []:
        if not isinstance(script, dict):
            continue
        for match in script.get("matches") or []:
            if isinstance(match, str) and match not in matches:
                matches.append(match)
    return matches


def collect_manifest_access(manifest):
    """Return permissions, host permissions, content script hosts, and optional permissions."""
    permissions = manifest.get("permissions") or []
    host_permissions = manifest.get("host_permissions") or []
    optional_permissions = manifest.get("optional_permissions") or []
    optional_host_permissions = manifest.get("optional_host_permissions") or []

    if not isinstance(permissions, list):
        permissions = []
    if not isinstance(host_permissions, list):
        host_permissions = []
    if not isinstance(optional_permissions, list):
        optional_permissions = []
    if not isinstance(optional_host_permissions, list):
        optional_host_permissions = []

    combined = []
    content_hosts = content_script_matches(manifest)
    optional_combined = []

    for permission in permissions + host_permissions + content_hosts:
        if isinstance(permission, str) and permission not in combined:
            combined.append(permission)

    for permission in optional_permissions + optional_host_permissions:
        if isinstance(permission, str) and permission not in optional_combined:
            optional_combined.append(permission)

    return {
        "permissions": sorted(combined),
        "declared_permissions": sorted([item for item in permissions if isinstance(item, str)]),
        "host_permissions": sorted([item for item in host_permissions if isinstance(item, str)]),
        "content_script_matches": sorted(content_hosts),
        "optional_permissions": sorted(optional_combined),
    }


def manifest_update_url(manifest):
    """Return update_url from Chrome/Edge or Firefox WebExtension metadata."""
    update_url = manifest.get("update_url")
    if update_url:
        return update_url

    browser_settings = manifest.get("browser_specific_settings") or {}
    gecko_settings = browser_settings.get("gecko") or {}
    return gecko_settings.get("update_url")


def firefox_extension_id(entry_name, manifest):
    """Return Firefox add-on ID from manifest metadata when available."""
    browser_settings = manifest.get("browser_specific_settings") or {}
    gecko_settings = browser_settings.get("gecko") or {}
    return gecko_settings.get("id") or os.path.splitext(entry_name)[0]


def is_firefox_legacy(manifest):
    """Heuristically flag older Firefox extensions that are not WebExtensions."""
    if not manifest:
        return True
    if "manifest_version" not in manifest:
        return True
    return manifest.get("manifest_version") not in (2, 3)


def has_host_control(permissions):
    """Return True if permissions include broad or explicit host access."""
    for permission in permissions:
        if permission == "<all_urls>" or "://" in permission or permission.startswith("*://"):
            return True
    return False


def score_risk(extension_id, access, last_modified_days, firefox_legacy=False):
    """Assign LOW, MEDIUM, or HIGH risk and explain the reasons."""
    permissions = access["permissions"]
    optional_permissions = access["optional_permissions"]
    permission_set = set(permissions)
    optional_permission_set = set(optional_permissions)
    reasons = []

    if extension_id in KNOWN_MALICIOUS_IDS:
        reasons.append("known malicious sample ID")

    risky_permissions = sorted(permission_set.intersection(HIGH_RISK_PERMISSIONS))
    if risky_permissions:
        reasons.append("sensitive permission: " + ", ".join(risky_permissions))

    if last_modified_days is not None and last_modified_days > 365:
        reasons.append("not updated in over 365 days")

    if firefox_legacy:
        reasons.append("legacy Firefox add-on")

    if reasons:
        return "HIGH", reasons

    optional_sensitive = sorted(optional_permission_set.intersection(HIGH_RISK_PERMISSIONS))
    if optional_sensitive:
        return "MEDIUM", ["optional sensitive permission: " + ", ".join(optional_sensitive)]

    medium_permissions = sorted(permission_set.intersection(MEDIUM_RISK_PERMISSIONS))
    if medium_permissions and not has_host_control(permissions):
        return "MEDIUM", ["moderate permission: " + ", ".join(medium_permissions)]

    return "LOW", ["minimal permissions"]


def build_record(browser, profile, extension_id, manifest, target_path, firefox_legacy=False):
    """Create a normalized result record for one extension."""
    access = collect_manifest_access(manifest)
    last_modified_time, last_modified_days = get_last_modified_info(target_path)
    risk, risk_reasons = score_risk(extension_id, access, last_modified_days, firefox_legacy)

    return {
        "browser": browser.title(),
        "profile": profile,
        "extension_id": extension_id,
        "name": manifest_name(manifest, target_path),
        "version": str(manifest.get("version", "Unknown")),
        "permissions": access["permissions"],
        "declared_permissions": access["declared_permissions"],
        "host_permissions": access["host_permissions"],
        "content_script_matches": access["content_script_matches"],
        "optional_permissions": access["optional_permissions"],
        "update_url": manifest_update_url(manifest),
        "last_modified_time": last_modified_time,
        "last_modified_days": last_modified_days,
        "risk": risk,
        "risk_reasons": risk_reasons,
        "path": target_path,
        "firefox_legacy": firefox_legacy,
    }


def safe_mtime(path):
    """Return path modification time, using 0 for inaccessible paths."""
    try:
        return os.path.getmtime(path)
    except OSError:
        return 0


def scan_chromium_browser(browser, extension_root, profile):
    """Scan Chrome or Edge extension directories."""
    results = []
    if not os.path.isdir(extension_root):
        return results

    try:
        extension_ids = os.listdir(extension_root)
    except OSError:
        return results

    for extension_id in extension_ids:
        extension_path = os.path.join(extension_root, extension_id)
        if not os.path.isdir(extension_path):
            continue

        try:
            version_dirs = [
                os.path.join(extension_path, item)
                for item in os.listdir(extension_path)
                if os.path.isdir(os.path.join(extension_path, item))
            ]
        except OSError:
            continue

        if not version_dirs:
            continue

        # Most Chromium extensions are stored as ID/version/manifest.json.
        version_dirs.sort(key=safe_mtime, reverse=True)
        for version_dir in version_dirs:
            manifest_path = os.path.join(version_dir, "manifest.json")
            manifest = read_json_file(manifest_path)
            if manifest:
                results.append(build_record(browser, profile, extension_id, manifest, version_dir))
                break

    return results


def scan_firefox_browser(extension_root, profile):
    """Scan Firefox .xpi files and extracted extension folders."""
    results = []
    if not os.path.isdir(extension_root):
        return results

    try:
        entries = os.listdir(extension_root)
    except OSError:
        return results

    for entry in entries:
        target_path = os.path.join(extension_root, entry)
        manifest = None

        if os.path.isfile(target_path) and entry.lower().endswith(".xpi"):
            manifest = read_manifest_from_xpi(target_path)
        elif os.path.isdir(target_path):
            manifest_path = os.path.join(target_path, "manifest.json")
            manifest = read_json_file(manifest_path)
        else:
            continue

        if not manifest:
            # Non-WebExtension legacy add-ons may lack manifest.json.
            manifest = {"name": entry, "version": "Unknown"}

        extension_id = firefox_extension_id(entry, manifest)
        legacy = is_firefox_legacy(manifest)
        results.append(build_record("firefox", profile, extension_id, manifest, target_path, legacy))

    return results


def scan_browser(browser, os_name):
    """Scan one browser and isolate failures from other browsers."""
    results = []
    errors = []

    for extension_location in browser_extension_paths(browser, os_name):
        extension_path = extension_location["path"]
        profile = extension_location["profile"]
        try:
            if browser in ("chrome", "edge"):
                results.extend(scan_chromium_browser(browser, extension_path, profile))
            elif browser == "firefox":
                results.extend(scan_firefox_browser(extension_path, profile))
        except Exception as exc:  # Keep one broken browser/profile from ending the audit.
            errors.append(
                {
                    "browser": browser,
                    "profile": profile,
                    "path": extension_path,
                    "error": str(exc),
                }
            )

    return results, errors


def clipped(value, max_length):
    """Clip text for stable table output."""
    value = str(value)
    if len(value) <= max_length:
        return value
    return value[: max_length - 3] + "..."


def short_permissions(permissions, max_items=4):
    """Format a compact permission list for table output."""
    if not permissions:
        return "-"
    visible = permissions[:max_items]
    suffix = "" if len(permissions) <= max_items else "..."
    return ", ".join(visible) + suffix


def short_reason(reasons, max_length=38):
    """Format the leading risk reason for compact table output."""
    if not reasons:
        return "-"
    reason = reasons[0]
    if len(reason) <= max_length:
        return reason
    return reason[: max_length - 3] + "..."


def print_table(results):
    """Print a human-readable Browser Bailiff audit table."""
    headers = [
        "Browser",
        "Profile",
        "Extension Name",
        "Version",
        "Permissions",
        "Last Updated",
        "Risk",
        "Finding",
    ]

    rows = []
    sorted_results = sorted(
        results,
        key=lambda item: (
            RISK_ORDER.get(item["risk"], 99),
            -(item["last_modified_days"] or 0),
            item["browser"],
            item["name"].lower(),
        ),
    )
    for result in sorted_results:
        days = result["last_modified_days"]
        day_text = "Unknown" if days is None else f"{days} days"
        rows.append(
            [
                result["browser"],
                clipped(result["profile"], 18),
                clipped(result["name"], 34),
                clipped(result["version"], 14),
                clipped(short_permissions(result["permissions"]), 64),
                day_text,
                result["risk"],
                short_reason(result.get("risk_reasons", [])),
            ]
        )

    widths = [len(header) for header in headers]
    for row in rows:
        for index, value in enumerate(row):
            widths[index] = max(widths[index], len(str(value)))

    header_line = " | ".join(headers[index].ljust(widths[index]) for index in range(len(headers)))
    separator = "-+-".join("-" * width for width in widths)

    print("Browser Bailiff extension audit")
    print(header_line)
    print(separator)
    if not rows:
        print("No extensions found.")
        return

    for row in rows:
        print(" | ".join(str(row[index]).ljust(widths[index]) for index in range(len(headers))))


def write_json_output(path, results, errors):
    """Write audit results and non-fatal scan errors to a JSON file."""
    payload = {
        "generated_at": int(time.time()),
        "results": results,
        "errors": errors,
    }
    try:
        with open(path, "w", encoding="utf-8") as handle:
            json.dump(payload, handle, indent=2, sort_keys=True)
        print(f"\nJSON results written to: {path}")
    except OSError as exc:
        print(f"\nCould not write JSON output to {path}: {exc}")


def parse_args():
    """Parse command-line arguments."""
    parser = argparse.ArgumentParser(
        prog="bb",
        description="Browser Bailiff audits installed Chrome, Edge, and Firefox extensions.",
    )
    parser.add_argument(
        "-o", "--output",
        help="Write JSON audit results to this file.",
    )
    parser.add_argument(
        "-n", "--no-json",
        action="store_true",
        help="Disable JSON output even when --output is supplied.",
    )
    parser.add_argument(
        "-b", "--browser",
        choices=("chrome", "edge", "firefox", "all"),
        default="all",
        help="Browser to scan. Defaults to all.",
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"Browser Bailiff {VERSION}",
    )
    return parser.parse_args()


def main():
    """Run Browser Bailiff."""
    args = parse_args()
    os_name = detect_os()

    if os_name == "unknown":
        print("Unsupported operating system.")
        return 1

    browsers = ["chrome", "edge", "firefox"] if args.browser == "all" else [args.browser]
    all_results = []
    all_errors = []

    for browser in browsers:
        results, errors = scan_browser(browser, os_name)
        all_results.extend(results)
        all_errors.extend(errors)

    print_table(all_results)

    if all_errors:
        print("\nNon-fatal scan errors:")
        for error in all_errors:
            print(f"- {error['browser']} at {error['path']}: {error['error']}")

    if args.output and not args.no_json:
        write_json_output(args.output, all_results, all_errors)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
