# SupplyGuard Architecture

## Stack

HTML5, CSS3, Bootstrap 5, Bootstrap Icons, vanilla JavaScript, plain PHP 8.0+, MySQL via PDO, PHP sessions and cURL. OSV is the vulnerability data source. No application framework, Composer package, Node.js, React, Python, AI/ML, penetration testing, malware analysis or source-code auditing is used.

## Seven-table persistence model

The database remains limited to `users`, `projects`, `dependency_files`, `dependencies`, `scans`, `vulnerabilities` and `reports`. No additional tables or columns are required by this implementation. The existing `users.status` column supports account activation. `scans` stores one assessment row per dependency and vulnerability (or one clean row per dependency); rows in a run share the same `scanned_at` timestamp. Runs are grouped by project and timestamp, with the minimum `scan_id` as the run anchor. `reports.scan_id` stores that anchor.

## Request and authorization flow

Every authenticated page loads `includes/bootstrap.php`. `require_login()`, `require_developer()`, `require_admin()`, `project_owned()` and `require_scan_access()` enforce authorization server-side. Developer project data is constrained by `projects.user_id`; administrators can inspect platform-wide data read-only. All POST forms include session CSRF tokens. PDO prepared statements are used for database inputs; HTML output is escaped with `e()`.

## Parsing and scan pipeline

`includes/parser.php` is database-independent and contains `manifest_type()`, `clean_version()`, `is_pinned()` and `parse_manifest()`. `public/upload.php` validates exact filenames, upload size, upload origin, NUL bytes and JSON syntax before writing a random storage filename and inserting file/dependency records. Original declared specifications are stored in `dependencies.version`.

`includes/scan_service.php` applies a 300-second execution limit and scans one manifest in a database transaction. Each package is queried through OSV using the extracted numeric version. If any package query fails, all writes for that run are rolled back. Vulnerability records are upserted by OSV ID. References, OSV IDs and CVEs are truncated to their schema limits. A shared timestamp groups the run.

## Severity classification

`vulnerability_severity()` first maps OSV `database_specific.severity`, translating `MODERATE` to Medium. If absent, `cvss3_base_score()` parses CVSS v3 vectors and calculates the base score. Missing or invalid severity becomes `unclassified`.

## Compliance and monitoring

`scan_runs()` aggregates dependency assessment rows into run summaries. `latest_run_for_project()` selects the latest completed run. `compliance_for_scan()` evaluates four baseline rules from existing manifest and scan data. Dashboards aggregate only each project's latest run. Monitoring is run-based and can be filtered by project.

## Reports

A report row is created once per run anchor. `report.php` renders the full consolidated report from persisted scan, dependency, vulnerability, project and user records. The browser print stylesheet enables print/save-to-PDF without adding a PDF library or generated binary file.

## Known constraints

The existing scans enum cannot persist failed-run records; failed transactions are rolled back and errors are shown to the initiating Developer. OSV lookup for a declared range uses the first numeric version token, not a lockfile-resolved version. Compliance is an internal baseline only. External Google Fonts, Bootstrap CDN assets and Bootstrap Icons are referenced by the existing interface; offline use requires local copies, which are not bundled in this project.
