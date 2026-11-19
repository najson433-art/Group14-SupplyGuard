# SupplyGuard Manual Test Checklist

Run with XAMPP, MySQL, PHP PDO MySQL and cURL enabled. Use a test database and sample manifests. Do not claim OSV tests passed unless the API was actually reachable and returned the expected data.

## Setup and accounts
- [ ] Import `database/schema.sql` after backing up any existing database.
- [ ] Create first Administrator through `public/setup.php` with a password of at least 10 characters.
- [ ] Confirm setup displays “Setup already completed” after an Administrator exists.
- [ ] Delete `public/setup.php` from the deployed server.
- [ ] Register a Developer and confirm registration creates role `user` only.
- [ ] Sign in with correct credentials; verify inactive accounts cannot log in.
- [ ] Change password using current password, new password and confirmation.

## Developer project and manifest workflow
- [ ] Create a project.
- [ ] Attempt a duplicate project name with different letter case; confirm it is blocked.
- [ ] Upload `tests/sample-manifests/package.json`; confirm extracted/skipped counts.
- [ ] Upload `tests/sample-manifests/composer.json`; confirm platform package `php` is skipped.
- [ ] Upload `tests/sample-manifests/requirements.txt`; confirm `>=` declaration is preserved.
- [ ] Upload invalid JSON and confirm a useful validation error.
- [ ] Upload an empty file, NUL-containing file, unsupported filename and file over 1 MB; confirm rejection.
- [ ] Confirm uploaded files have random storage names.
- [ ] Run scan and re-scan each uploaded manifest.
- [ ] Confirm every run shares one timestamp and appears once in Monitoring.
- [ ] Simulate OSV failure; confirm transaction rollback and package-specific error.
- [ ] Confirm declared ranges display with the checked numeric version where different.
- [ ] Verify severity mapping for OSV responses with database severity and CVSS vectors.
- [ ] Specifically query lodash 4.17.20 and axios 0.21.1; compare findings and severity with current OSV response. Results can change as OSV data changes.
- [ ] Confirm unknown severity appears as Unclassified, not Low.
- [ ] Confirm dashboard counts only latest completed scan per project.
- [ ] Confirm compliance evaluates four rules and status changes when rule conditions change.
- [ ] Filter Monitoring by project.
- [ ] Generate a report once; repeat generation and confirm no duplicate report row.
- [ ] Confirm report contains findings, clean dependencies, compliance rules and limitations.
- [ ] Print/save report as PDF.
- [ ] Delete a project and confirm its uploaded files are removed from storage.

## Administrator workflow
- [ ] Confirm Administrator dashboard shows total users, active users, projects, completed scan runs, severity counts and recent scan owners.
- [ ] Confirm All Projects includes owner, scan count, latest scan, compliance, View and Delete.
- [ ] Confirm Administrator cannot create/edit projects, upload manifests or start/re-scan.
- [ ] Confirm Administrator can view all Monitoring, Compliance, Reports and Scan Details with Owner information where applicable.
- [ ] Confirm Administrator cannot generate a report.
- [ ] Confirm Administrator can activate/deactivate Developer accounts.
- [ ] Confirm current Administrator row shows only “Current account”.
- [ ] Confirm last active Administrator cannot be demoted, deactivated or deleted.
- [ ] Remove the Administrator's test project through All Projects.

## Role and ownership enforcement
- [ ] Administrator opens `projects.php`, `project.php`, `scanning.php`, `upload.php` and scan POST action: each must return 403.
- [ ] Developer opens `admin/users.php`, `admin/projects.php`, `admin/project.php`, `admin/overview.php` and `setup.php`: each must return 403 (setup shows completed only when no login is active; delete setup after provisioning).
- [ ] Register a second Developer and confirm the second Developer cannot access the first Developer's project, scan details or reports.
- [ ] Confirm CSRF-protected POST actions reject missing/invalid tokens.
