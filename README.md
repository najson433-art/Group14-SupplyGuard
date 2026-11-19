# SupplyGuard — Software Supply Chain Security Platform

**Project:** Design and Implementation of a Web-Based Software Supply Chain Security Platform for Dependency Scanning, Vulnerability Monitoring and Security Reporting  
**Institution:** Iconic University, Gusau, Zamfara State  
**Runtime:** PHP 8.0+, MySQL/MariaDB, Apache/XAMPP

SupplyGuard supports Developer-owned software projects, dependency manifest parsing, OSV vulnerability checks, scan-run history, a four-rule internal compliance baseline and consolidated printable reports.

## Technology and scope

HTML5, CSS3, Bootstrap 5, Bootstrap Icons, vanilla JavaScript, plain PHP, MySQL through PDO, PHP sessions and cURL. Supported manifests are exactly `package.json`, `composer.json` and `requirements.txt`. Vulnerability data comes from the OSV API. The platform does not perform penetration testing, malware analysis, source-code auditing, AI/ML analysis or certification.

## Installation on XAMPP

1. Copy the project folder into `C:\xampp\htdocs\sscs-platform-improved`.
2. Start Apache and MySQL in XAMPP. Ensure PHP PDO MySQL and cURL extensions are enabled.
3. Open phpMyAdmin and import `database/schema.sql`. The script creates the `supplyguard` database and its seven approved tables. **Warning:** the supplied schema drops existing tables before recreating them; back up any existing database before importing.
4. Check `config/database.php`. The default XAMPP settings are host `127.0.0.1`, database `supplyguard`, user `root`, blank password.
5. Check `config/config.php`. The default `BASE_URL` is `/sscs-platform-improved/public`; change it if your folder name or URL differs.
6. Ensure `storage/uploads` and `storage/reports` are writable by Apache.
7. Visit `http://localhost/sscs-platform-improved/public/setup.php` and create the first Administrator. The password must contain at least 10 characters.
8. **Delete `public/setup.php` from the server after creating the first Administrator.** The page also refuses to create another Administrator once one exists.
9. Sign in. Register Developer accounts through the public registration page. Change the default `admin@example.com` email and password immediately if you use those values during initial setup.

## Page map and permissions

| Page | Developer | Administrator |
|---|---:|---:|
| `index.php`, `login.php`, `register.php`, `logout.php` | Public | Public |
| `dashboard.php` | Own dashboard | Platform dashboard |
| `profile.php` | Own profile/password | Own profile/password |
| `projects.php`, `project.php`, `upload.php`, `scanning.php` | Own project operations | 403 |
| `monitoring.php`, `compliance.php`, `reports.php`, `report.php`, `scan.php?id=` | Own data | All data, read-only |
| `admin/users.php` | 403 | User administration |
| `admin/projects.php`, `admin/project.php` | 403 | Read-only project overview; project deletion is available in All Projects |
| `admin/overview.php` | 403 | System overview |
| `setup.php` | 403 after login; first setup only while no admin exists | First setup only while no admin exists |

The server enforces roles and project ownership; hiding navigation items is not the security boundary. All modifying forms use CSRF tokens. Passwords are stored with `password_hash()` and verified with `password_verify()`. Sessions are regenerated after login and password changes.

## Dependency parsing and OSV assessment

- Original declared versions are retained in `dependencies.version`; version specifications are trimmed to 50 characters.
- A numeric version extracted by `clean_version()` is used only for OSV lookup. The UI and report show the declaration and the checked version when they differ.
- Package manifests read `dependencies`, `devDependencies` and `optionalDependencies`. Composer manifests read `require` and `require-dev`. Requirements files support common PEP 508 version operators while ignoring comments, extras, markers and pip option lines.
- Unsupported, wildcard, URL and non-version declarations are counted as skipped. Uploads are limited to 1 MB, exact filenames and reject NUL bytes. JSON files are validated before storage.
- Every scan run is a single transaction with one shared timestamp. An OSV failure for any package rolls back the whole run and displays the failing package and reason.
- A run is grouped by `(project_id, scanned_at)`; `scan_runs()` returns an anchor scan ID, dependency count, findings and severity counts.
- OSV may not provide a severity. SupplyGuard maps `database_specific.severity`, otherwise evaluates CVSS v3 vectors. Missing/invalid severity is `unclassified`, not Low.

**Version-range limitation:** for a range such as `^4.17.20`, `~1.2` or `>=2.0`, the platform queries OSV using the first numeric version extracted from the declaration. It does not resolve package-manager lockfiles or every version permitted by a range. Interpret range-based findings accordingly.

## Compliance baseline

One status is calculated for each project from its latest completed scan:

1. No critical or high vulnerabilities.
2. All dependencies in the latest uploaded manifest use exact pinned versions.
3. Every dependency in that latest manifest was assessed in the scan.
4. The latest scan is no older than 30 days.

The status is Compliant only when all four rules pass, Non-compliant when a scan exists but any rule fails, and Not assessed when no scan exists. This is an internal baseline, not certification.

## Scan runs and reports

Developers can upload and re-scan each manifest from Project Details or Dependency Scanning. Monitoring shows one row per scan run, with optional project filtering. Scan details show vulnerable dependencies first, followed by dependencies with no known vulnerability. A Developer can generate one consolidated report per scan run; Administrators can view reports but cannot generate them. Use **Print / Save as PDF** in the report page.

## Removing the Administrator's test project

Sign in as Administrator, open **All Projects**, locate the test project and select **Delete**. Confirm the action. Its project, manifests, dependency records, scans and reports are deleted through the database relationships, and stored manifest files are removed from `storage/uploads`.

## Tests

Run parser tests from the project root:

```bash
php tests/parser-check.php
php tests/severity-check.php
```

Sample manifests are in `tests/sample-manifests/`. Follow `tests/MANUAL-TEST-CHECKLIST.md` for the full role, scan, report and ownership test sequence. The parser and severity tests do not require a database or OSV connection.

## Important schema limitation

The approved seven-table schema has no persistent failed-scan state. A failed scan is rolled back and shown to the Developer, but cannot be counted later as a historical failed scan without an approved schema change. The Administrator dashboard explains this limitation.
