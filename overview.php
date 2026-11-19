
<?php


require_once __DIR__ . '/../../includes/bootstrap.php';

require_admin();

// Count registered and active users.
$users = (int) $pdo->query(
    'SELECT COUNT(*) FROM users'
)->fetchColumn();

$active = (int) $pdo->query(
    "SELECT COUNT(*) FROM users WHERE status = 'active'"
)->fetchColumn();

// Count all registered projects.
$projects = (int) $pdo->query(
    'SELECT COUNT(*) FROM projects'
)->fetchColumn();

// Retrieve all scan runs, ordered from newest to oldest.
$allRuns = scan_runs($pdo);

// Select only the latest completed scan run for each project.
// This prevents older scans from inflating current vulnerability totals.
$latestRuns = [];
$seenProjects = [];

foreach ($allRuns as $run) {
    $projectId = (int) $run['project_id'];

    if (!isset($seenProjects[$projectId])) {
        $latestRuns[] = $run;
        $seenProjects[$projectId] = true;
    }
}

// Calculate platform-wide vulnerability totals using only
// the latest completed scan of each project.
$totals = [
    'critical' => 0,
    'high' => 0,
    'medium' => 0,
    'low' => 0,
    'unclassified' => 0
];

foreach ($latestRuns as $run) {
    foreach ($totals as $severity => $value) {
        $totals[$severity] += (int) ($run[$severity] ?? 0);
    }
}

// The existing scans.status ENUM does not support a failed status.
// Failed scans are rolled back and cannot be counted historically
// without changing the approved database schema.
$failedScans = 0;

// Display the five most recent completed scan runs.
$recentRuns = array_slice($allRuns, 0, 5);

page_header('System Overview');
?>

<div class="page-heading">
    <div>
        <span class="eyebrow">ADMINISTRATION</span>
        <h1>System Overview</h1>
        <p>
            Platform-wide summary based on the latest completed
            scan of each project.
        </p>
    </div>
</div>

<!-- Platform statistics -->
<div class="row g-3 mb-4">

    <?php
    $statistics = [
        ['Total Users', $users],
        ['Active Users', $active],
        ['Total Projects', $projects],
        ['Total Scan Runs', count($allRuns)],
        ['Failed Scans', $failedScans]
    ];
    ?>

    <?php foreach ($statistics as [$label, $number]): ?>
        <div class="col-sm-6 col-xl">
            <div class="stat-card">
                <div class="stat-label">
                    <?= e($label) ?>
                </div>

                <div class="stat-value">
                    <?= number_format((int) $number) ?>
                </div>
            </div>
        </div>
    <?php endforeach; ?>

</div>

<div class="alert alert-info" role="alert">
    Failed scans are rolled back when an assessment fails.
    The current database structure does not retain failed scan
    records, so historical failed scans cannot be counted.
</div>

<!-- Latest vulnerability findings -->
<div class="page-heading mb-3">
    <div>
        <h2 class="h5">Latest Vulnerability Findings</h2>
        <p>
            Findings from the latest completed scan of each project.
        </p>
    </div>
</div>

<div class="row g-3 mb-4">

    <?php foreach ($totals as $severity => $number): ?>

        <div class="col-6 col-lg">
            <div class="stat-card">
                <div class="stat-label">
                    <?= e(ucfirst($severity)) ?> Findings
                </div>

                <div class="stat-value">
                    <?= number_format((int) $number) ?>
                </div>
            </div>
        </div>

    <?php endforeach; ?>

</div>

<!-- Recent scan activities -->
<div class="card">

    <div class="card-header">
        <strong>Five Latest Completed Scans</strong>
    </div>

    <div class="table-responsive">

        <table class="table align-middle">

            <thead>
                <tr>
                    <th>Project</th>
                    <th>Owner</th>
                    <th>Scan Date</th>
                    <th>Dependencies</th>
                    <th>Findings</th>
                    <th>Action</th>
                </tr>
            </thead>

            <tbody>

                <?php if ($recentRuns): ?>

                    <?php foreach ($recentRuns as $run): ?>

                        <tr>
                            <td>
                                <?= e($run['project_name']) ?>
                            </td>

                            <td>
                                <?= e($run['owner']) ?>
                            </td>

                            <td>
                                <?= e($run['scanned_at']) ?>
                            </td>

                            <td>
                                <?= number_format(
                                    (int) $run['dependencies_checked']
                                ) ?>
                            </td>

                            <td>
                                <?= number_format(
                                    (int) $run['findings']
                                ) ?>
                            </td>

                            <td>
                                <a
                                    href="<?= e(url(
                                        'scan.php?id=' .
                                        (int) $run['run_id']
                                    )) ?>"
                                    class="btn btn-sm btn-outline-primary"
                                >
                                    View Details
                                </a>
                            </td>
                        </tr>

                    <?php endforeach; ?>

                <?php else: ?>

                    <tr>
                        <td colspan="6" class="text-center py-4">
                            No completed scans are available.
                        </td>
                    </tr>

                <?php endif; ?>

            </tbody>

        </table>

    </div>

</div>

<?php require APP_ROOT . '/includes/footer.php'; ?>
