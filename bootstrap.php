<?php
declare(strict_types=1);
require_once __DIR__.'/../config/config.php';
require_once __DIR__.'/parser.php';
require_once __DIR__.'/severity.php';

if (session_status() !== PHP_SESSION_ACTIVE) {
    // Strict cookie-only sessions, HttpOnly and SameSite reduce session theft and CSRF exposure.
    ini_set('session.use_strict_mode', '1');
    ini_set('session.use_only_cookies', '1');
    session_set_cookie_params(['httponly'=>true,'secure'=>!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off','samesite'=>'Lax']);
    session_start();
}
require_once __DIR__.'/../config/database.php';

function e($v): string { return htmlspecialchars((string)$v, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8'); }
function url(string $path=''): string { return rtrim(BASE_URL,'/').'/'.ltrim($path,'/'); }
function go(string $path): void { header('Location: '.url($path)); exit; }
function current_user(): ?array { return $_SESSION['user'] ?? null; }
function require_login(): void { if (!current_user()) { flash('warning','Please sign in to continue.'); go('login.php'); } }
function forbidden(): void { http_response_code(403); page_header('Access denied'); echo '<div class="alert alert-danger"><h1 class="h4">403 — Access denied</h1><p>Your account does not have permission to access this page.</p><a class="btn btn-primary" href="'.e(url('dashboard.php')).'">Return to dashboard</a></div>'; require APP_ROOT.'/includes/footer.php'; exit; }
function require_admin(): void { require_login(); if ((current_user()['role'] ?? '') !== 'admin') forbidden(); }
function require_developer(): void { require_login(); if ((current_user()['role'] ?? '') !== 'user') forbidden(); }
function csrf_token(): string { if (empty($_SESSION['csrf'])) $_SESSION['csrf']=bin2hex(random_bytes(32)); return $_SESSION['csrf']; }
function csrf_field(): string { return '<input type="hidden" name="csrf_token" value="'.e(csrf_token()).'">'; }
/** Reject state-changing requests that do not carry this session's CSRF token. */
function verify_csrf(): void { if (!hash_equals(csrf_token(),(string)($_POST['csrf_token']??''))) { http_response_code(419); exit('Session token invalid. Refresh and try again.'); } }
function flash(string $type,string $message): void { $_SESSION['flash'][]=['type'=>$type,'message'=>$message]; }
function show_flash(): void { foreach($_SESSION['flash']??[] as $f) echo '<div class="alert alert-'.e($f['type']).' alert-dismissible fade show" role="alert">'.e($f['message']).'<button type="button" class="btn-close" data-bs-dismiss="alert"></button></div>'; unset($_SESSION['flash']); }
function page_header(string $title): void { $GLOBALS['pageTitle']=$title; require APP_ROOT.'/includes/header.php'; }
function project_owned(PDO $pdo,int $id): array {
    $q=$pdo->prepare('SELECT p.*,u.full_name owner_name FROM projects p JOIN users u ON u.user_id=p.user_id WHERE p.project_id=?');$q->execute([$id]);$p=$q->fetch();
    if(!$p){http_response_code(404);exit('Project not found.');}
    if((current_user()['role']??'')!=='admin'&&(int)$p['user_id']!==(int)current_user()['user_id']){http_response_code(404);exit('Project not found.');}
    return $p;
}
function require_scan_access(PDO $pdo,int $id): array {
    $q=$pdo->prepare('SELECT s.*,p.name project_name,p.user_id,p.description,u.full_name owner FROM scans s JOIN projects p ON p.project_id=s.project_id JOIN users u ON u.user_id=p.user_id WHERE s.scan_id=?');$q->execute([$id]);$r=$q->fetch();
    if(!$r){http_response_code(404);exit('Scan record not found.');}
    if((current_user()['role']??'')!=='admin'&&(int)$r['user_id']!==(int)current_user()['user_id']){http_response_code(404);exit('Scan record not found.');}
    return $r;
}


function osv_query(array $dep): array {
    if (!function_exists('curl_init')) throw new RuntimeException('PHP cURL extension is not enabled.');
    $payload=json_encode([
        'package'=>['name'=>$dep['name'],'ecosystem'=>$dep['ecosystem']],
        'version'=>$dep['checked_version']??clean_version($dep['version'])
    ], JSON_THROW_ON_ERROR);
    $ch=curl_init(OSV_QUERY_URL);
    if($ch===false)throw new RuntimeException('Could not initialise the OSV HTTP request.');
    curl_setopt_array($ch,[CURLOPT_POST=>true,CURLOPT_POSTFIELDS=>$payload,CURLOPT_HTTPHEADER=>['Content-Type: application/json','Accept: application/json'],CURLOPT_RETURNTRANSFER=>true,CURLOPT_CONNECTTIMEOUT=>10,CURLOPT_TIMEOUT=>30]);
    $body=curl_exec($ch);$err=curl_error($ch);$http=(int)curl_getinfo($ch,CURLINFO_HTTP_CODE);curl_close($ch);
    if($body===false||$http<200||$http>=300)throw new RuntimeException('OSV HTTP '.$http.($err?' — '.$err:''));
    $data=json_decode($body,true);
    if(!is_array($data))throw new RuntimeException('OSV returned invalid JSON.');
    $vulnerabilities=$data['vulns']??[];
    if(!is_array($vulnerabilities))throw new RuntimeException('OSV returned an invalid vulnerability list.');
    return $vulnerabilities;
}
function severity_badge(string $s): string { $c=match($s){'critical'=>'danger','high'=>'warning','medium'=>'info','low'=>'success',default=>'secondary'};return '<span class="badge text-bg-'.$c.'">'.e(ucfirst($s)).'</span>'; }
function truncate_text(string $s,int $max): string { return function_exists('mb_substr') ? mb_substr($s,0,$max,'UTF-8') : substr($s,0,$max); }

/** Each run is a set of dependency rows sharing project_id and scanned_at. */
function scan_runs(PDO $pdo,?int $projectId=null,?int $ownerId=null): array {
    $where=[];$args=[];if($projectId!==null){$where[]='s.project_id=?';$args[]=$projectId;}if($ownerId!==null){$where[]='p.user_id=?';$args[]=$ownerId;}
    $sql="SELECT s.project_id,s.scanned_at,MIN(s.scan_id) run_id,COUNT(DISTINCT s.dependency_id) dependencies_checked,
      COUNT(DISTINCT CASE WHEN s.status='vulnerable' THEN CONCAT(s.dependency_id,':',s.vulnerability_id) END) findings,
      SUM(CASE WHEN v.severity='critical' THEN 1 ELSE 0 END) critical,
      SUM(CASE WHEN v.severity='high' THEN 1 ELSE 0 END) high,
      SUM(CASE WHEN v.severity='medium' THEN 1 ELSE 0 END) medium,
      SUM(CASE WHEN v.severity='low' THEN 1 ELSE 0 END) low,
      SUM(CASE WHEN v.severity='unclassified' THEN 1 ELSE 0 END) unclassified,
      p.name project_name,p.user_id,u.full_name owner
      FROM scans s JOIN projects p ON p.project_id=s.project_id JOIN users u ON u.user_id=p.user_id
      LEFT JOIN vulnerabilities v ON v.vulnerability_id=s.vulnerability_id";
    if($where)$sql.=' WHERE '.implode(' AND ',$where);
    $sql.=' GROUP BY s.project_id,s.scanned_at,p.name,p.user_id,u.full_name ORDER BY s.scanned_at DESC';
    $q=$pdo->prepare($sql);$q->execute($args);return $q->fetchAll();
}
function latest_run_for_project(PDO $pdo,int $projectId): ?array {
    $runs=scan_runs($pdo,$projectId);return $runs[0]??null;
}

/** Return only the latest completed run for each project. */
function latest_project_runs(PDO $pdo, ?int $ownerId=null): array {
    $all=scan_runs($pdo,null,$ownerId);$latest=[];
    foreach($all as $run){$key=(int)$run['project_id'];if(!isset($latest[$key]))$latest[$key]=$run;}
    return array_values($latest);
}
function compliance_for_scan(PDO $pdo,int $projectId,?array $run=null): array {
    if(!$run)$run=latest_run_for_project($pdo,$projectId);
    if(!$run)return ['status'=>'Not assessed','rules'=>[false,false,false,false],'run'=>null];
    $q=$pdo->prepare("SELECT COUNT(*) FROM scans s JOIN vulnerabilities v ON v.vulnerability_id=s.vulnerability_id WHERE s.project_id=? AND s.scanned_at=? AND v.severity IN ('critical','high')");
    $q->execute([$projectId,$run['scanned_at']]);$rule1=(int)$q->fetchColumn()===0;
    $q=$pdo->prepare("SELECT d.version,d.ecosystem FROM dependency_files f JOIN dependencies d ON d.file_id=f.file_id WHERE f.project_id=? AND f.uploaded_at=(SELECT MAX(uploaded_at) FROM dependency_files WHERE project_id=?)");
    $q->execute([$projectId,$projectId]);$latestDeps=$q->fetchAll();$rule2=count($latestDeps)>0;
    foreach($latestDeps as $d)if(!is_pinned($d['version'],$d['ecosystem'])){$rule2=false;break;}
    $q=$pdo->prepare("SELECT COUNT(*) FROM dependency_files WHERE project_id=? AND uploaded_at=(SELECT MAX(uploaded_at) FROM dependency_files WHERE project_id=?)");
    $q->execute([$projectId,$projectId]);$latestFileCount=(int)$q->fetchColumn();
    $q=$pdo->prepare("SELECT COUNT(DISTINCT d.dependency_id) FROM dependency_files f JOIN dependencies d ON d.file_id=f.file_id JOIN scans s ON s.dependency_id=d.dependency_id AND s.project_id=f.project_id AND s.scanned_at=? WHERE f.project_id=? AND f.uploaded_at=(SELECT MAX(uploaded_at) FROM dependency_files WHERE project_id=?)");
    $q->execute([$run['scanned_at'],$projectId,$projectId]);$assessed=(int)$q->fetchColumn();
    $rule3=$latestFileCount>0&&count($latestDeps)>0&&$assessed===count($latestDeps);
    $rule4=(strtotime($run['scanned_at'])>=strtotime('-30 days'));
    $rules=[$rule1,$rule2,$rule3,$rule4];return ['status'=>count(array_filter($rules))===4?'Compliant':'Non-compliant','rules'=>$rules,'run'=>$run];
}
