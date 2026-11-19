<?php require_once __DIR__.'/../includes/bootstrap.php'; if(current_user())go('dashboard.php'); page_header('Welcome'); ?>
<div class="auth-card welcome-card"><div class="auth-brand"><span class="brand-mark"><i class="bi bi-shield-lock-fill"></i></span><div><b>SUPPLYGUARD</b><small>SOFTWARE SUPPLY CHAIN SECURITY</small></div></div>
<span class="badge text-bg-primary mb-3">ICONIC UNIVERSITY · GUSAU</span><h1>Secure your software supply chain.</h1><p class="text-secondary">Manage software projects, scan third-party dependencies, review known vulnerabilities and generate security assessment reports from one workspace.</p>
<div class="d-grid gap-2"><a class="btn btn-primary" href="<?=e(url('login.php'))?>">Sign in to workspace</a><a class="btn btn-outline-primary" href="<?=e(url('register.php'))?>">Create Developer account</a></div></div>
<?php require APP_ROOT.'/includes/footer.php'; ?>
