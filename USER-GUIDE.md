# SupplyGuard User Guide

## Getting started

An Administrator is created once through `public/setup.php` while the database contains no Administrator. The setup form requires a password of at least 10 characters and a CSRF token. Delete the setup page from the deployed server after first use. Developers register through `register.php`; public registration cannot create Administrator accounts.

## Developer workflow

1. Register and sign in.
2. Open **My Projects** and create a project. Duplicate names are blocked case-insensitively within the same account.
3. Open the project and upload exactly one supported filename: `package.json`, `composer.json` or `requirements.txt` (maximum 1 MB).
4. Review the extraction message: number of dependencies extracted and number skipped because no usable version was found.
5. Use **Re-scan** beside any uploaded manifest. Each run assesses all usable dependencies from that manifest in one transaction.
6. Review **Scan Details**, **Vulnerability Monitoring**, **Compliance Checks** and **Security Reports**.
7. Generate a consolidated report from the run details or report link. Print or save it as PDF from the report page.
8. Edit project details or delete a project from My Projects. Deletion also removes uploaded manifest files from storage.

## Administrator workflow

Administrators see a different dashboard and sidebar. They can manage accounts, activate/deactivate users, change other users' roles subject to last-active-Administrator protection, inspect all projects, view all monitoring/compliance/report records and open scan details. They cannot create projects, upload manifests or initiate scans. All Projects provides a read-only project detail view and a confirmed delete action, useful for removing the Administrator's initial test project.

## Four compliance rules

- No critical/high findings in the latest scan.
- All dependencies in the latest uploaded manifest are pinned to exact versions.
- All dependencies in that latest manifest were assessed in the selected latest scan.
- The latest scan is no older than 30 days.

A project without a scan is **Not assessed**. A project is **Compliant** only if all four rules pass. Otherwise it is **Non-compliant**. This is an internal baseline, not certification.

## Scan history and reports

A scan run is grouped by project and shared timestamp. Monitoring therefore presents one run rather than one row per dependency. Scan details show all dependencies in that run, vulnerable ones first. Reports consolidate the project, owner, date, manifests, dependency count, severity summary, compliance rules, findings, clean dependencies and limitations. Administrators can view reports but only Developers can create them.

## Version ranges

Declared versions are preserved as written. For OSV requests the platform extracts a representative numeric version. For example, `^4.17.20` is stored as declared and checked as `4.17.20`. This is not full dependency resolution and does not inspect lockfiles.
