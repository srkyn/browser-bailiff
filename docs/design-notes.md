# Browser Bailiff: Design Notes

## What It Does

Browser Bailiff is a read-only Python tool for auditing installed browser extensions on Chrome, Edge, and Firefox. It reads manifest files and scored extension metadata locally — no network requests, no browser API access, no modification to browser state.

## Why It Exists

Browser extensions sit close to sensitive user activity. An extension with cookie access, broad host permissions, or native messaging capability has significant reach on the user's machine. That reach may be legitimate, but it deserves visibility — especially for extensions that are old, rarely updated, or have quietly accumulated permissions over time.

## What Gets Checked

For Chromium-based browsers (Chrome, Edge), Browser Bailiff reads the `Extensions` folder inside each browser profile. Each extension stores its files under a version subdirectory. The tool reads `manifest.json` from the most recently modified version folder.

For Firefox, it reads `.xpi` archives and extracted extension folders from Firefox profile directories. It also attempts to resolve localized extension names using `_locales` message files.

For each extension, Browser Bailiff collects:

- Extension ID and name
- Version
- Declared permissions and host permissions
- Content-script host matches
- Optional permissions
- Update URL
- Last modified age
- Risk level and finding reasons

## Risk Scoring

Scoring uses three signal categories:

**HIGH** when any of the following apply:
- Sensitive permissions declared: `cookies`, `<all_urls>`, `webRequest`, `nativeMessaging`, `management`, `debugger`, or `webRequestBlocking`
- Extension file or folder modified more than 365 days ago
- Legacy Firefox add-on (no `manifest_version`, or version not 2 or 3)
- Extension ID matches the built-in sample block list

**MEDIUM** when:
- Optional permissions include a sensitive permission from the HIGH list
- Moderate permissions declared (`tabs`, `storage`, `history`, etc.) without broad host access

**LOW** when no HIGH or MEDIUM conditions apply.

These are triage signals. A HIGH finding is not a verdict.

## Design Decisions

**Read-only.** Browser Bailiff does not install, remove, disable, or reconfigure extensions. Audit tools that can modify state introduce risk. The only safe audit is one that cannot make changes.

**No browser API access.** The tool reads extension directories from the filesystem rather than using browser extension APIs. This means it works without a running browser, without elevated browser permissions, and without browser-version dependencies.

**Single file.** The scanner is a single Python module with no third-party dependencies. This keeps the install surface minimal — useful for tools that run on machines where you want to avoid installing additional packages.

**Profile-aware scanning.** Chromium browsers support multiple profiles, each with their own Extensions directory. Browser Bailiff scans all detected profiles and tags each record with its source profile.

## Limitations

- The built-in known-malicious extension IDs are sample placeholders. Replace or extend with real threat intelligence before using for formal enforcement.
- Does not inspect extension source code or detect runtime behavior.
- May miss extensions in profiles the current user cannot read.
- Does not resolve every browser localization edge case.
- Does not track extension update history, only current state.
- Age is measured from file modification time, not from the extension store's published date.
