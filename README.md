# Browser Bailiff

Browser Bailiff audits installed Chrome, Edge, and Firefox extensions from the
command line. It extracts manifest metadata, summarizes permissions, flags stale
or powerful extensions, and can write JSON results for later review.

## Features

- Detects Windows, macOS, and Linux browser extension locations.
- Scans Chrome, Edge, and Firefox profiles separately.
- Reads Chromium `manifest.json` files and Firefox `.xpi` archives.
- Resolves localized Chromium extension names when possible.
- Reports profile names, permissions, host permissions, content-script matches,
  optional permissions, update URLs, versions, paths, and age.
- Scores extension risk as `LOW`, `MEDIUM`, or `HIGH` with a finding reason.
- Sorts the terminal docket by risk and optionally writes structured JSON.

## Usage

```powershell
python .\browser_bailiff.py
python .\browser_bailiff.py --browser edge --no-json
python .\browser_bailiff.py --browser firefox --output results.json
python .\browser_bailiff.py --version
```

Supported browser values are `chrome`, `edge`, `firefox`, and `all`.

## Notes

The built-in known-malicious extension IDs are sample placeholders. Replace or
extend them with trusted intelligence before using Browser Bailiff for formal
enforcement.

Risk scoring is intentionally conservative and transparent. A `HIGH` finding is
not proof of malicious behavior; it means the extension deserves closer review
because of sensitive permissions, broad host access, age, legacy format, or a
sample block-list match.
