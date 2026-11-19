<?php
require_once __DIR__.'/../includes/bootstrap.php';
require_developer();
$projectId=(int)($_GET['project_id']??$_POST['project_id']??0);
$project=project_owned($pdo,$projectId);$error='';
if($_SERVER['REQUEST_METHOD']==='POST'){
    verify_csrf();
    $stored=null;
    try{
        if(!isset($_FILES['manifest'])||$_FILES['manifest']['error']!==UPLOAD_ERR_OK) throw new RuntimeException('Choose a dependency manifest to upload.');
        $file=$_FILES['manifest'];$name=basename((string)$file['name']);$ecosystem=manifest_type($name);
        if(!$ecosystem) throw new RuntimeException('Use exactly package.json, composer.json or requirements.txt.');
        if((int)$file['size']>1048576) throw new RuntimeException('The manifest must not exceed 1 MB.');
        if(!is_uploaded_file($file['tmp_name'])) throw new RuntimeException('The upload could not be verified.');
        $parsed=parse_manifest($file['tmp_name'],$name);$items=$parsed['dependencies'];
        if(!$items) throw new RuntimeException('No usable dependencies were extracted. Check the manifest format and versions.');
        if(!is_dir(UPLOAD_DIR)&&!mkdir(UPLOAD_DIR,0750,true)) throw new RuntimeException('Upload storage is unavailable.');
        // Random storage names prevent user-controlled paths and filename collisions.
        $stored=bin2hex(random_bytes(20)).'-'.$name;$target=UPLOAD_DIR.'/'.$stored;
        if(!move_uploaded_file($file['tmp_name'],$target)) throw new RuntimeException('Unable to store the uploaded manifest.');
        $pdo->beginTransaction();
        $q=$pdo->prepare('INSERT INTO dependency_files(project_id,file_name,file_type,file_path) VALUES(?,?,?,?)');$q->execute([$projectId,$name,$ecosystem,$stored]);$fileId=(int)$pdo->lastInsertId();
        $insert=$pdo->prepare('INSERT INTO dependencies(file_id,name,version,ecosystem) VALUES(?,?,?,?)');
        foreach($items as $dep)$insert->execute([$fileId,substr($dep['name'],0,100),substr($dep['version'],0,50),$ecosystem]);
        $pdo->commit();
        flash('success',count($items).' dependencies extracted, '.(int)$parsed['skipped'].' skipped (no usable version).');
        go('project.php?id='.$projectId);
    }catch(Throwable $ex){if($pdo->inTransaction())$pdo->rollBack();if($stored && is_file(UPLOAD_DIR.'/'.$stored))@unlink(UPLOAD_DIR.'/'.$stored);$error=$ex->getMessage();}
}
page_header('Dependency Scanning');?>
<div class="page-heading"><div><span class="eyebrow">DEVELOPER WORKSPACE</span><h1>Upload dependency manifest</h1><p>Project: <strong><?=e($project['name'])?></strong></p></div></div>
<div class="row justify-content-center"><div class="col-lg-8"><div class="card"><div class="card-header"><strong>Manifest upload</strong></div><div class="card-body">
<?php if($error):?><div class="alert alert-danger"><?=e($error)?></div><?php endif;?>
<div class="alert alert-info">Supported exact filenames: <strong>package.json</strong>, <strong>composer.json</strong> and <strong>requirements.txt</strong>. Maximum size: 1 MB. Declared version ranges are preserved; a representative numeric version is used for OSV lookup.</div>
<form method="post" enctype="multipart/form-data"><?=csrf_field()?><input type="hidden" name="project_id" value="<?=$projectId?>"><input type="hidden" name="MAX_FILE_SIZE" value="1048576"><div class="mb-3"><label class="form-label">Dependency manifest</label><input class="form-control" type="file" name="manifest" accept=".json,.txt" required></div><button class="btn btn-primary"><i class="bi bi-cloud-upload me-2"></i>Upload manifest</button> <a class="btn btn-light" href="<?=e(url('project.php?id='.$projectId))?>">Cancel</a></form>
</div></div></div></div><?php require APP_ROOT.'/includes/footer.php';?>
