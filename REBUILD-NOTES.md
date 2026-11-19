# SupplyGuard Rebuild Notes

This rebuild applies the supplied role, parser, scan-run, severity, compliance and reporting specification across the application rather than patching isolated pages.

## Main implementation changes

- Enforced separate Developer and Administrator routes and server-side role/ownership checks.
- Rebuilt both workspaces and their navigation; added the Administrator's read-only project detail view.
- Added first-Administrator setup, account activation, last-active-Administrator safeguards and password changes.
- Rebuilt manifest parsing for npm, Packagist and PyPI declarations while preserving declared versions and counting skipped entries.
- Added transactional OSV scanning, shared timestamps per run, rollback with package-specific errors, OSV reference selection and schema-length truncation.
- Added CVSS v3 severity calculation and an `unclassified` fallback.
- Rebuilt scan-run monitoring, latest-run dashboard aggregation, the four compliance checks and consolidated reports.
- Added sample manifests, standalone parser and severity tests, documentation and a manual acceptance checklist.

## Verification performed in this environment

- `php -l` was run on every PHP file in the project: no syntax errors were reported.
- `php tests/parser-check.php`: 10 passed, 0 failed.
- `php tests/severity-check.php`: 8 passed, 0 failed.
- Sample manifest parsing was run and extraction/skipped counts were inspected.

## Verification not performed

This environment does not have the PHP `pdo_mysql` or `curl` extensions enabled, and no XAMPP/MySQL service is available here. Therefore the application was not connected to a database, and live OSV API scans, login/role workflows against MySQL, file upload through Apache, and PDF printing were not integration-tested here. Complete those checks on the target XAMPP installation using `tests/MANUAL-TEST-CHECKLIST.md`.

The existing seven-table schema was retained. The schema does not store failed scan attempts; scan failures are rolled back and reported to the Developer, so a historical failed-scan count cannot be calculated without an approved schema change.
