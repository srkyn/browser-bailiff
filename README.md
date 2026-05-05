![Browser Bailiff project banner](docs/assets/browser-bailiff-banner.svg)

# Browser Bailiff

Audit browser extensions before their permissions become a problem.

Browser Bailiff is a read-only Python tool for reviewing installed Chrome, Edge,
and Firefox extensions from the command line.

It extracts manifest metadata, summarizes permissions and host access, flags
stale or powerful extensions, prints a human-readable docket, and can write JSON
output for later review.

The theme is a court bailiff: orderly, direct, focused on the record. Extensions
aren't presumed bad — they get a read of their declared access, a risk score,
and a finding the operator can act on.

![Release](https://img.shields.io/github/v/release/srkyn/browser-bailiff?style=flat-square)
![CI](https://img.shields.io/github/actions/workflow/status/srkyn/browser-bailiff/ci.yml?branch=main&style=flat-square)
![Python](https://img.shields.io/badge/python-3.8%2B-1f6feb?style=flat-square)
![License](https://img.shields.io/github/license/srkyn/browser-bailiff?style=flat-square)

## At A Glance

- Read-only audit tool; it does not install, disable, or delete extensions.
- Scans Chrome, Edge, and Firefox extension directories on Windows, macOS, and Linux.
- Reads Chromium `manifest.json` files and Firefox `.xpi` archives.
- Resolves localized Chromium extension names when possible.
- Reports browser profile, extension ID, version, permissions, host access, update URL, path, and age.
- Includes content-script host matches and optional permissions in the JSON output.
- Scores extension risk as `LOW`, `MEDIUM`, or `HIGH` with a finding reason.
- Sorts the terminal docket by risk and age.
- Ships with tests, CI, a security policy, and versioned releases.

## The Docket

For each extension it finds, Browser Bailiff asks what it can access, how long it's been installed, and whether that access makes sense for its stated purpose. A `HIGH` finding isn't a verdict — it's a reason to look more closely at where the extension came from and what it actually needs.

## Why It Exists

Browser extensions sit close to sensitive user activity. Some can read or modify pages, inspect cookies, communicate with native applications, or manage other extensions. Those capabilities may be legitimate, but they deserve visibility.

> Which browser extensions are installed, what can they access, and which ones deserve a closer look?

## What It Checks

On Chromium-based browsers:

- Chrome profile extension folders
- Edge profile extension folders
- Latest version folder for each extension ID
- `manifest.json`, localized names, declared permissions, host permissions, content-script matches, and optional permissions

On Firefox:

- Firefox profile extension folders
- `.xpi` extension archives
- Extracted extension folders
- WebExtension manifests and likely legacy non-WebExtension add-ons

## Usage

```powershell
python .\browser_bailiff.py
python .\browser_bailiff.py --browser edge --no-json
python .\browser_bailiff.py --browser firefox --output results.json
python .\browser_bailiff.py --version
```

Supported browser values are `chrome`, `edge`, `firefox`, and `all`.

## Risk Rules

`HIGH` when:

- Sensitive permissions declared: `cookies`, `<all_urls>`, `webRequest`, `nativeMessaging`, `management`, `debugger`, or `webRequestBlocking`.
- Extension file or folder is older than 365 days.
- Appears to be a legacy Firefox add-on.
- Extension ID matches the built-in sample block list.

`MEDIUM` when:

- Moderate permissions without broad host control: `storage`, `tabs`, `history`, `downloads`, `bookmarks`, `proxy`, `scripting`, or `clipboardRead`.
- Sensitive permissions listed as optional permissions.

Everything else is `LOW`.

These are triage signals, not proof of malicious behavior.

## Output Fields

JSON output includes browser, profile, extension ID, name, version, permissions,
declared permissions, host permissions, content-script matches, optional
permissions, update URL, last modified timestamp, age in days, risk, risk
reasons, path, and Firefox legacy status.

## Files

- `browser_bailiff.py`: the scanner CLI
- `tests/test_browser_bailiff.py`: unit tests for parsing and scoring behavior
- `CHANGELOG.md`: release history
- `SECURITY.md`: vulnerability reporting guidance
- `pyproject.toml`: local package metadata and CLI entry point

## Limitations

- The built-in known-malicious extension IDs are sample placeholders. Replace or extend them with real intelligence before using Browser Bailiff for formal enforcement.
- Does not prove whether an extension is malicious.
- Does not modify browser configuration.
- May miss extensions in profiles the current user cannot read.
- Does not resolve every browser localization edge case.
- Does not inspect extension source code behavior beyond manifest metadata.

## Testing

```bash
python -m py_compile browser_bailiff.py
python -m unittest discover -s tests -v
python browser_bailiff.py --version
python browser_bailiff.py --browser edge --no-json
```
