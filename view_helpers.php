<?php
declare(strict_types=1);
function run_dependencies(PDO $pdo, int $projectId, string $scannedAt): array {
    $q=$pdo->prepare("SELECT s.scan_id,s.status,s.scanned_at,d.dependency_id,d.name,d.version,d.ecosystem,v.osv_id,v.cve_id,v.summary,v.severity,v.reference_url FROM scans s LEFT JOIN dependencies d ON d.dependency_id=s.dependency_id LEFT JOIN vulnerabilities v ON v.vulnerability_id=s.vulnerability_id WHERE s.project_id=? AND s.scanned_at=? ORDER BY CASE WHEN s.status='vulnerable' THEN 0 ELSE 1 END,d.name,v.severity DESC");
    $q->execute([$projectId,$scannedAt]); return $q->fetchAll();
}
function report_for_run(PDO $pdo, int $anchorId, int $userId): int {
    // Lock the anchor row so simultaneous clicks cannot create duplicate reports.
    $pdo->beginTransaction();
    try {
        $q=$pdo->prepare('SELECT s.project_id,p.name,p.user_id FROM scans s JOIN projects p ON p.project_id=s.project_id WHERE s.scan_id=? FOR UPDATE');
        $q->execute([$anchorId]);$run=$q->fetch();
        if(!$run) throw new RuntimeException('Scan run not found.');
        if((int)$run['user_id']!==$userId) throw new RuntimeException('You cannot generate a report for this project.');
        $q=$pdo->prepare('SELECT report_id FROM reports WHERE scan_id=? LIMIT 1');
        $q->execute([$anchorId]);$existing=(int)$q->fetchColumn();
        if($existing){$pdo->commit();return $existing;}
        $title=substr('Security Assessment - '.$run['name'].' - '.$anchorId,0,150);
        $q=$pdo->prepare('INSERT INTO reports(scan_id,report_title,report_file) VALUES(?,?,?)');
        $q->execute([$anchorId,$title,'browser-print-'.$anchorId.'.html']);$id=(int)$pdo->lastInsertId();
        $pdo->commit();return $id;
    } catch(Throwable $exception) {
        if($pdo->inTransaction())$pdo->rollBack();
        throw $exception;
    }
}

function compliance_badge(string $status): string {
    $class=$status==='Compliant'?'success':($status==='Non-compliant'?'danger':'secondary');
    return '<span class="badge text-bg-'.$class.'">'.e($status).'</span>';
}
function displayed_version(string $declared, string $ecosystem): string {
    $checked=clean_version($declared);
    return e($declared).($checked!==null && $checked!==$declared?' <span class="text-secondary small">(checked as '.e($checked).')</span>':'');
}

/** Render a report link for an existing report or a CSRF-protected Developer generation action. */
function report_action(PDO $pdo, int $anchorId, bool $admin): string {
    $q=$pdo->prepare('SELECT report_id FROM reports WHERE scan_id=? LIMIT 1');
    $q->execute([$anchorId]);$reportId=(int)$q->fetchColumn();
    if($reportId){return '<a class="btn btn-sm btn-outline-secondary" href="'.e(url('report.php?id='.$reportId)).'">Report</a>';}
    if($admin)return '<span class="small text-secondary">Not generated</span>';
    return '<form method="post" action="'.e(url('report.php')).'" class="d-inline">'.csrf_field().'<input type="hidden" name="scan_id" value="'.$anchorId.'"><button class="btn btn-sm btn-outline-secondary">Generate report</button></form>';
}
