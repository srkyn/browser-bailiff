# Changelog

## Unreleased

### Changed

- Expanded test suite from 5 to 28 tests across risk scoring, host control detection, manifest parsing, XPI handling, and JSON output.
- Fixed `argparse` prog from `browser_bailiff.py` to `browser-bailiff` so `--help` output matches the installed CLI name.
- Added CLI install and entry point verification to CI.
- Added `design-notes.md` documenting risk scoring logic and design decisions.
- Added `.gitattributes` for consistent line endings.
- Bumped development status from Alpha to Beta.

## 0.2.1

- Expanded README with outsider-focused sections for purpose, checks, risk rules, output fields, files, limitations, and validation.
- Added MIT license.
- Added security policy.
- Added Python packaging metadata and `browser-bailiff` console entry point.
- Added GitHub Actions CI workflow.
- Added issue templates for bugs and feature requests.

## 0.2.0

- Added profile names to audit records and table output.
- Added content-script host matches to permission analysis.
- Added optional permission reporting and medium-risk handling.
- Added clearer risk reasons in JSON and terminal output.
- Sorted terminal output by risk, then age.
- Added bounded table columns for more stable terminal output.
- Added `--version`.
- Added unit tests for scoring, localization, and Firefox `.xpi` parsing.

## 0.1.0

- Initial Browser Bailiff release.
