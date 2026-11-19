<?php
declare(strict_types=1);
require_once __DIR__ . '/bootstrap.php';

/** Run a complete assessment for one uploaded manifest as a single transaction. */
function scan_manifest(PDO $pdo, int $projectId, int $fileId): array
{
    set_time_limit(300);
    $q = $pdo->prepare('SELECT f.*, p.user_id FROM dependency_files f JOIN projects p ON p.project_id=f.project_id WHERE f.file_id=? AND f.project_id=?');
    $q->execute([$fileId, $projectId]);
    $file = $q->fetch();
    if (!$file) throw new RuntimeException('Manifest not found for this project.');
    if ((int)$file['user_id'] !== (int)current_user()['user_id']) throw new RuntimeException('You do not own this manifest.');

    $q = $pdo->prepare('SELECT * FROM dependencies WHERE file_id=? ORDER BY dependency_id');
    $q->execute([$fileId]);
    $dependencies = $q->fetchAll();
    if (!$dependencies) throw new RuntimeException('This manifest has no usable dependencies to assess.');

    $timestamp = date('Y-m-d H:i:s');
    // DATETIME has one-second precision: avoid merging two rapid runs for one project.
    $collision = $pdo->prepare('SELECT COUNT(*) FROM scans WHERE project_id=? AND scanned_at=?');
    while (true) { $collision->execute([$projectId, $timestamp]); if ((int)$collision->fetchColumn() === 0) break; $timestamp = date('Y-m-d H:i:s', strtotime($timestamp) + 1); }
    $checked = 0; $findings = 0;
    $pdo->beginTransaction();
    try {
        foreach ($dependencies as $dep) {
            $checkedVersion = clean_version((string)$dep['version']);
            if (!$checkedVersion) throw new RuntimeException('Package ' . $dep['name'] . ': no numeric version could be extracted from ' . $dep['version'] . '.');
            try {
                $osv = osv_query([
                    'name' => $dep['name'],
                    'ecosystem' => $dep['ecosystem'],
                    'version' => $dep['version'],
                    'checked_version' => $checkedVersion
                ]);
            } catch (Throwable $apiError) {
                throw new RuntimeException(
                    'Package ' . $dep['name'] . ' (' . $dep['version'] . ') failed: ' . $apiError->getMessage(),
                    0,
                    $apiError
                );
            }
            if (!$osv) {
                $insert = $pdo->prepare("INSERT INTO scans(project_id,dependency_id,vulnerability_id,status,scanned_at) VALUES(?,?,NULL,'no known vulnerability found',?)");
                $insert->execute([$projectId, $dep['dependency_id'], $timestamp]);
            } else {
                foreach ($osv as $vuln) {
                    $osvId = substr((string)($vuln['id'] ?? 'UNKNOWN'), 0, 100);
                    if ($osvId === 'UNKNOWN') throw new RuntimeException('Package ' . $dep['name'] . ': OSV returned a vulnerability without an identifier.');
                    $summary = trim((string)($vuln['summary'] ?? $vuln['details'] ?? 'No summary supplied by OSV.'));
                    $cve = null;
                    foreach (($vuln['aliases'] ?? []) as $alias) {
                        if (preg_match('/^CVE-\d{4}-\d+$/i', (string)$alias)) { $cve = substr((string)$alias, 0, 50); break; }
                    }
                    $reference = null; $fallback = null;
                    foreach (($vuln['references'] ?? []) as $ref) {
                        $candidate = trim((string)($ref['url'] ?? ''));
                        if ($candidate === '') continue;
                        if ($fallback === null) $fallback = $candidate;
                        if (in_array(strtoupper((string)($ref['type'] ?? '')), ['ADVISORY','WEB'], true)) { $reference = $candidate; break; }
                    }
                    $reference = substr($reference ?? $fallback ?? '', 0, 255) ?: null;
                    $severity = vulnerability_severity($vuln);
                    $published = null;
                    if (!empty($vuln['published']) && strtotime($vuln['published'])) $published = date('Y-m-d H:i:s', strtotime($vuln['published']));
                    $upsert = $pdo->prepare('INSERT INTO vulnerabilities(osv_id,cve_id,summary,severity,reference_url,published_at) VALUES(?,?,?,?,?,?) ON DUPLICATE KEY UPDATE cve_id=VALUES(cve_id),summary=VALUES(summary),severity=VALUES(severity),reference_url=VALUES(reference_url),published_at=VALUES(published_at)');
                    $upsert->execute([$osvId, $cve, $summary, $severity, $reference, $published]);
                    $vulnerabilityId = (int)$pdo->lastInsertId();
                    if ($vulnerabilityId === 0) {
                        $find = $pdo->prepare('SELECT vulnerability_id FROM vulnerabilities WHERE osv_id=?');
                        $find->execute([$osvId]);
                        $vulnerabilityId = (int)$find->fetchColumn();
                    }
                    $insert = $pdo->prepare("INSERT INTO scans(project_id,dependency_id,vulnerability_id,status,scanned_at) VALUES(?,?,?,'vulnerable',?)");
                    $insert->execute([$projectId, $dep['dependency_id'], $vulnerabilityId, $timestamp]);
                    $findings++;
                }
            }
            $checked++;
        }
        $pdo->commit();
    } catch (Throwable $exception) {
        if ($pdo->inTransaction()) $pdo->rollBack();
        throw $exception;
    }
    return ['dependencies'=>$checked,'findings'=>$findings,'scanned_at'=>$timestamp];
}

/** Resolve the anchor scan row for a run. */
function run_anchor(PDO $pdo, int $projectId, string $scannedAt): ?int
{
    $q=$pdo->prepare('SELECT MIN(scan_id) FROM scans WHERE project_id=? AND scanned_at=?');
    $q->execute([$projectId,$scannedAt]);
    $id=$q->fetchColumn();
    return $id ? (int)$id : null;
}
