<?php
require_once __DIR__.'/../includes/bootstrap.php'; if(current_user())go('dashboard.php'); $error='';
if($_SERVER['REQUEST_METHOD']==='POST'){verify_csrf();$email=strtolower(trim($_POST['email']??''));$password=$_POST['password']??'';
$st=$pdo->prepare("SELECT user_id,full_name,email,password,role,status FROM users WHERE email=?");$st->execute([$email]);$u=$st->fetch();
if($u && $u['status']==='active' && password_verify($password,$u['password'])){
// Rotate the session identifier after authentication to prevent session fixation.
session_regenerate_id(true);unset($u['password'],$u['status']);$_SESSION['user']=$u;$_SESSION['csrf']=bin2hex(random_bytes(32));go('dashboard.php');}
$error='Invalid credentials or inactive account.';}
page_header('Sign in'); ?>
<div class="auth-card"><div class="auth-brand"><span class="brand-mark"><i class="bi bi-shield-lock-fill"></i></span><div><b>SUPPLYGUARD</b><small>SECURE WORKSPACE</small></div></div><h1 class="h3 mb-3">Welcome back</h1>
<?php if($error):?><div class="alert alert-danger"><?=e($error)?></div><?php endif;?>
<form method="post"><?=csrf_field()?><div class="mb-3"><label class="form-label">Email address</label><input class="form-control" type="email" name="email" required autocomplete="username"></div><div class="mb-3"><label class="form-label">Password</label><input class="form-control" type="password" name="password" required autocomplete="current-password"></div><button class="btn btn-primary w-100">Sign in</button></form>
<p class="text-center small mt-3 mb-0">New developer? <a href="<?=e(url('register.php'))?>">Create an account</a></p></div>
<?php require APP_ROOT.'/includes/footer.php'; ?>
