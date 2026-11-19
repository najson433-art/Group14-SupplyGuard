<?php
require_once __DIR__.'/bootstrap.php';
$pageTitle = $GLOBALS['pageTitle'] ?? APP_NAME;
$u=current_user();$admin=($u['role']??'')==='admin';$current=basename($_SERVER['PHP_SELF']??'');
$groups=$admin?[
 ['label'=>'WORKSPACE','items'=>[['Dashboard','bi-grid-1x2','dashboard.php'],['User Management','bi-people','admin/users.php'],['All Projects','bi-folder2-open','admin/projects.php'],['Vulnerability Monitoring','bi-shield-exclamation','monitoring.php'],['Compliance Checks','bi-clipboard2-check','compliance.php'],['Security Reports','bi-file-earmark-bar-graph','reports.php'],['System Overview','bi-activity','admin/overview.php']]],
 ['label'=>'ACCOUNT','items'=>[['My Profile','bi-person-circle','profile.php']]]
]:[
 ['label'=>'WORKSPACE','items'=>[['Dashboard','bi-grid-1x2','dashboard.php'],['My Projects','bi-folder2-open','projects.php'],['Dependency Scanning','bi-search','scanning.php'],['Vulnerability Monitoring','bi-shield-exclamation','monitoring.php'],['Compliance Checks','bi-clipboard2-check','compliance.php'],['Security Reports','bi-file-earmark-bar-graph','reports.php']]],
 ['label'=>'ACCOUNT','items'=>[['My Profile','bi-person-circle','profile.php']]]
];
?>
<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title><?=e($pageTitle)?> · <?=e(APP_NAME)?></title>
<link rel="preconnect" href="https://fonts.googleapis.com"><link rel="preconnect" href="https://fonts.gstatic.com" crossorigin><link href="https://fonts.googleapis.com/css2?family=DM+Sans:wght@400;500;600;700&family=Manrope:wght@500;600;700;800&display=swap" rel="stylesheet">
<link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css" rel="stylesheet"><link href="https://cdn.jsdelivr.net/npm/bootstrap-icons@1.11.3/font/bootstrap-icons.min.css" rel="stylesheet"><link href="<?=e(url('assets/css/style.css'))?>" rel="stylesheet"></head><body>
<?php if($u):?><aside class="sidebar" id="sidebar"><a class="brand" href="<?=e(url('dashboard.php'))?>"><span class="brand-mark"><i class="bi bi-shield-lock-fill"></i></span><span><b>SUPPLYGUARD</b><small>SECURITY PLATFORM</small></span></a>
<?php foreach($groups as $group):?><div class="nav-caption"><?=e($group['label'])?></div><?php foreach($group['items'] as [$label,$icon,$href]):$active=($current===basename($href));?><a class="side-link <?=$active?'active':''?>" href="<?=e(url($href))?>"><i class="bi <?=e($icon)?>"></i><span><?=e($label)?></span></a><?php endforeach;endforeach;?>
<div class="sidebar-bottom"><div class="user-chip"><div class="avatar"><?=e(strtoupper(substr($u['full_name'],0,1)))?></div><div class="user-meta"><b><?=e($u['full_name'])?></b><small><?=$admin?'Administrator':'Developer'?> account</small></div><a title="Logout" href="<?=e(url('logout.php'))?>"><i class="bi bi-box-arrow-right"></i></a></div></div></aside>
<div class="app-shell"><header class="topbar"><button class="btn btn-light sidebar-toggle" id="sidebarToggle" aria-label="Toggle navigation"><i class="bi bi-list"></i></button><div class="topbar-title"><span class="eyebrow">SECURITY WORKSPACE</span><strong><?=e($pageTitle)?></strong></div><div class="topbar-actions"><span class="system-status"><i></i> Platform workspace</span><div class="top-avatar"><?=e(strtoupper(substr($u['full_name'],0,1)))?></div></div></header><main class="content-area"><?php else:?><main class="auth-shell"><?php endif;?><?php show_flash();?>
