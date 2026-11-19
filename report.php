
<?php
require_once __DIR__ . '/../includes/bootstrap.php';
require_once __DIR__ . '/../includes/scan_service.php';
require_once __DIR__ . '/../includes/view_helpers.php';

require_login();

$currentUser = current_user();
$admin = ($currentUser['role'] === 'admin');

// Generate a report through a CSRF-protected POST request.
// Only Developers can generate reports.
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['scan_id'])) {
    require_developer();
    verify_csrf();

    $scanId = (int) $_POST['scan_id'];

    $scan = require_scan_access($pdo, $scanId);

    $anchor = run_anchor(
        $pdo,
        (int) $scan['project_id'],
        $scan['scanned_at']
    ) ?? $scanId;

    $reportId = report_for_run(
        $pdo,
        $anchor,
        (int) $currentUser['user_id']
    );

    if (!$reportId) {
        http_response_code(500);
        exit('The security report could not be generated.');
    }

    go('report.php?id=' . (int) $reportId);
}

// Prevent report generation through a GET request.
if (isset($_GET['scan_id'])) {
    http_response_code(405);
    exit('Report generation requires a CSRF-protected POST request.');
}

// Retrieve the requested report.
$reportId = (int) ($_GET['id'] ?? 0);

if ($reportId <= 0) {
    http_response_code(404);
    exit('Report not found.');
}

$q = $pdo->prepare(
    'SELECT
        r.*,
        s.project_id,
        s.scanned_at,
        p.name AS project_name,
        p.user_id,
        u.full_name AS owner
     FROM reports r
     INNER JOIN scans s ON s.scan_id = r.scan_id
     INNER JOIN projects p ON p.project_id = s.project_id
     INNER JOIN users u ON u.user_id = p.user_id
     WHERE r.report_id = ?
     LIMIT 1'
);

$q->execute([$reportId]);
$report = $q->fetch(PDO::FETCH_ASSOC);

if (!$report) {
    http_response_code(404);
    exit('Report not found.');
}

// Developers can only view reports belonging to their own projects.
// Administrators can view reports across the platform.
if (
    !$admin &&
    (int) $report['user_id'] !== (int) $currentUser['user_id']
) {
    http_response_code(404);
    exit('Report not found.');
}

// Retrieve assessment information.
$run = [
    'scanned_at' => $report['scanned_at']
];

$compliance = compliance_for_scan(
    $pdo,
    (int) $report['project_id'],
    $run
);

$rows = run_dependencies(
    $pdo,
    (int) $report['project_id'],
    $report['scanned_at']
);

// Retrieve manifest information.
$manifestsQ = $pdo->prepare(
    'SELECT DISTINCT
        f.file_name,
        f.file_type
     FROM scans s
     INNER JOIN dependencies d ON d.dependency_id = s.dependency_id
     INNER JOIN dependency_files f ON f.file_id = d.file_id
     WHERE s.project_id = ?
       AND s.scanned_at = ?
     ORDER BY f.file_name'
);

$manifestsQ->execute([
    $report['project_id'],
    $report['scanned_at']
]);

$manifests = $manifestsQ->fetchAll(PDO::FETCH_ASSOC);

// Count unique dependencies.
$unique = [];

foreach ($rows as $row) {
    if (!empty($row['dependency_id'])) {
        $unique[$row['dependency_id']] = $row;
    }
}

// Count vulnerability findings by severity.
$counts = [
    'critical' => 0,
    'high' => 0,
    'medium' => 0,
    'low' => 0,
    'unclassified' => 0
];

foreach ($rows as $row) {
    if ($row['status'] === 'vulnerable') {
        $severity = $row['severity'] ?? 'unclassified';

        if (!isset($counts[$severity])) {
            $severity = 'unclassified';
        }

        $counts[$severity]++;
    }
}

page_header('Security Assessment Report');
?>

<div class="d-flex justify-content-between flex-wrap gap-2 mb-3 no-print">
    <a class="btn btn-outline-secondary" href="<?= e(url('reports.php')) ?>">
        <i class="bi bi-arrow-left me-2"></i>Back to reports
    </a>

    <button class="btn btn-primary" onclick="window.print()">
        <i class="bi bi-printer me-2"></i>Print / Save as PDF
    </button>
</div>

<div class="report-sheet">

    <div class="text-center mb-4">
        <div class="brand-mark mx-auto mb-3">
            <i class="bi bi-shield-lock-fill"></i>
        </div>

        <h1 class="h2">Software Supply Chain Security Assessment</h1>
        <p class="text-secondary">SupplyGuard · Iconic University, Gusau</p>
    </div>

    <table class="table table-bordered">
        <tr>
            <th>Project</th>
            <td><?= e($report['project_name']) ?></td>
            <th>Owner</th>
            <td><?= e($report['owner']) ?></td>
        </tr>

        <tr>
            <th>Scan date</th>
            <td><?= e($report['scanned_at']) ?></td>
            <th>Report generated</th>
            <td><?= e($report['created_at']) ?></td>
        </tr>

        <tr>
            <th>Assessment type</th>
            <td>OSV dependency vulnerability assessment</td>
            <th>Dependencies</th>
            <td><?= number_format(count($unique)) ?></td>
        </tr>

        <tr>
            <th>Compliance</th>
            <td colspan="3">
                <?= compliance_badge($compliance['status']) ?>
            </td>
        </tr>
    </table>

    <h2 class="h5 mt-4">Manifests assessed</h2>

    <?php if ($manifests): ?>
        <ul>
            <?php foreach ($manifests as $manifest): ?>
                <li>
                    <?= e($manifest['file_name']) ?>
                    (<?= e($manifest['file_type']) ?>)
                </li>
            <?php endforeach; ?>
        </ul>
    <?php else: ?>
        <p>Manifest metadata is not available for this assessment.</p>
    <?php endif; ?>

    <h2 class="h5 mt-4">Severity summary</h2>

    <div class="row g-2">
        <?php foreach ($counts as $severity => $count): ?>
            <div class="col">
                <div class="border rounded p-3">
                    <div class="small text-secondary">
                        <?= e(ucfirst($severity)) ?>
                    </div>

                    <div class="h4 mb-0">
                        <?= number_format($count) ?>
                    </div>
                </div>
            </div>
        <?php endforeach; ?>
    </div>

    <h2 class="h5 mt-4">Compliance baseline</h2>

    <p>
        Overall result:
        <?= compliance_badge($compliance['status']) ?>
    </p>

    <?php
    $labels = [
        'No critical or high vulnerabilities',
        'All dependencies use pinned exact versions',
        'Every dependency in the latest manifest assessed in this scan',
        'Latest scan is no older than 30 days'
    ];
    ?>

    <ol>
        <?php foreach ($labels as $index => $label): ?>
            <li>
                <?= e($label) ?> —
                <strong>
                    <?= !empty($compliance['rules'][$index]) ? 'PASS' : 'FAIL' ?>
                </strong>
            </li>
        <?php endforeach; ?>
    </ol>

    <h2 class="h5 mt-4">Vulnerability findings</h2>

    <div class="table-responsive">
        <table class="table table-bordered align-middle">
            <thead>
                <tr>
                    <th>Package</th>
                    <th>Declared version</th>
                    <th>OSV ID</th>
                    <th>CVE</th>
                    <th>Severity</th>
                    <th>Summary</th>
                    <th>Reference</th>
                </tr>
            </thead>

            <tbody>
                <?php foreach ($rows as $row): ?>
                    <?php if ($row['status'] !== 'vulnerable') continue; ?>

                    <tr>
                        <td><?= e($row['name']) ?></td>

                        <td>
                            <?= displayed_version(
                                (string) $row['version'],
                                (string) $row['ecosystem']
                            ) ?>
                        </td>

                        <td><?= e($row['osv_id']) ?></td>

                        <td><?= e($row['cve_id'] ?? '—') ?></td>

                        <td>
                            <?= severity_badge(
                                $row['severity'] ?? 'unclassified'
                            ) ?>
                        </td>

                        <td><?= e($row['summary']) ?></td>

                        <td>
                            <?php if (!empty($row['reference_url'])): ?>
                                <a
                                    href="<?= e($row['reference_url']) ?>"
                                    target="_blank"
                                    rel="noopener noreferrer"
                                >Source</a>
                            <?php else: ?>
                                —
                            <?php endif; ?>
                        </td>
                    </tr>
                <?php endforeach; ?>

                <?php if (array_sum($counts) === 0): ?>
                    <tr>
                        <td colspan="7">
                            No vulnerability findings were returned by OSV.
                        </td>
                    </tr>
                <?php endif; ?>
            </tbody>
        </table>
    </div>

    <h2 class="h5 mt-4">Dependencies with no known vulnerability</h2>

    <ul>
        <?php
        $clean = 0;

        foreach ($rows as $row):
            if ($row['status'] === 'vulnerable') {
                continue;
            }

            $clean++;
        ?>
            <li>
                <?= e($row['name']) ?> —
                <?= displayed_version(
                    (string) $row['version'],
                    (string) $row['ecosystem']
                ) ?>
            </li>
        <?php endforeach; ?>

        <?php if ($clean === 0): ?>
            <li>No clean dependency records were returned in this scan run.</li>
        <?php endif; ?>
    </ul>

    <h2 class="h5 mt-4">Assessment limitations</h2>

    <p>
        This assessment queries the OSV database for the numeric version
        extracted from each declared dependency specification. For range
        declarations such as <code>^4.17.20</code>, <code>~1.2</code> or
        <code>&gt;=2.0</code>, the platform checks the extracted representative
        version; it does not resolve a package manager lockfile or calculate
        every version permitted by the range. Results depend on OSV data
        available at scan time. The platform does not perform source-code
        auditing, penetration testing, malware analysis or certification.
    </p>

    <p class="small text-secondary mt-4">
        This report is an internal dependency security assessment, not a
        guarantee that the software is free from vulnerabilities.
    </p>

</div>

<?php require APP_ROOT . '/includes/footer.php'; ?>
