<?php
require_once __DIR__.'/../includes/bootstrap.php';
if(current_user() && (current_user()['role'] ?? '') !== 'admin') forbidden();
$count=(int)$pdo->query("SELECT COUNT(*) FROM users WHERE role='admin'")->fetchColumn();$error='';
if($count>0){page_header('Setup');echo '<div class="auth-card"><h1 class="h3">Setup already completed</h1><p class="text-secondary">An administrator account already exists. The first-administrator setup page is no longer available.</p></div>';require APP_ROOT.'/includes/footer.php';exit;}
if($_SERVER['REQUEST_METHOD']==='POST'){
 verify_csrf();$name=trim((string)($_POST['full_name']??''));$email=strtolower(trim((string)($_POST['email']??'')));$password=(string)($_POST['password']??'');$confirm=(string)($_POST['confirm_password']??'');
 if($name===''||strlen($name)>100||!filter_var($email,FILTER_VALIDATE_EMAIL))$error='Enter a valid name and email address.';
 elseif(strlen($password)<10)$error='Administrator password must contain at least 10 characters.';
 elseif($password!==$confirm)$error='Password confirmation does not match.';
 else{try{$q=$pdo->prepare("INSERT INTO users(full_name,email,password,role,status) VALUES(?,?,?,'admin','active')");$q->execute([$name,$email,password_hash($password,PASSWORD_DEFAULT)]);flash('success','First administrator created. Sign in and remove setup.php from the server.');go('login.php');}catch(PDOException $e){$error='Unable to create administrator. Check whether the email is already registered.';}}
}
page_header('First Administrator Setup');?>
<div class="auth-card"><div class="auth-brand"><span class="brand-mark"><i class="bi bi-shield-lock-fill"></i></span><div><b>SUPPLYGUARD</b><small>INITIAL ADMINISTRATOR</small></div></div><h1 class="h3">Create first administrator</h1><p class="text-secondary">This page is available only while no administrator account exists.</p><?php if($error):?><div class="alert alert-danger"><?=e($error)?></div><?php endif;?><form method="post"><?=csrf_field()?><div class="mb-3"><label class="form-label">Full name</label><input class="form-control" name="full_name" maxlength="100" required></div><div class="mb-3"><label class="form-label">Email address</label><input class="form-control" type="email" name="email" required></div><div class="mb-3"><label class="form-label">Password (minimum 10 characters)</label><input class="form-control" type="password" name="password" minlength="10" required></div><div class="mb-3"><label class="form-label">Confirm password</label><input class="form-control" type="password" name="confirm_password" minlength="10" required></div><button class="btn btn-primary w-100">Create administrator</button></form></div><?php require APP_ROOT.'/includes/footer.php';?>
