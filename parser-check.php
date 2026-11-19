<?php
declare(strict_types=1);
require_once __DIR__.'/../includes/parser.php';
$passed=0;$failed=0;
function check_case(string $label, callable $fn): void { global $passed,$failed; try{$ok=$fn();if($ok){echo "[PASS] $label\n";$passed++;}else{echo "[FAIL] $label\n";$failed++;}}catch(Throwable $e){echo "[FAIL] $label — ".$e->getMessage()."\n";$failed++;}}
function temp_manifest(string $content): string {$p=tempnam(sys_get_temp_dir(),'sgp');file_put_contents($p,$content);return $p;}
check_case('exact npm version',function(){ $p=temp_manifest('{"dependencies":{"lodash":"4.17.20"}}');$r=parse_manifest($p,'package.json');unlink($p);return $r['dependencies'][0]['version']==='4.17.20'&&$r['dependencies'][0]['checked_version']==='4.17.20'&&$r['dependencies'][0]['pinned'];});
check_case('caret range preserved',function(){ $p=temp_manifest('{"dependencies":{"a":"^4.17.20"}}');$r=parse_manifest($p,'package.json');unlink($p);return $r['dependencies'][0]['version']==='^4.17.20'&&$r['dependencies'][0]['checked_version']==='4.17.20'&&!$r['dependencies'][0]['pinned'];});
check_case('tilde range preserved',function(){ $p=temp_manifest('{"dependencies":{"a":"~1.2"}}');$r=parse_manifest($p,'package.json');unlink($p);return $r['dependencies'][0]['checked_version']==='1.2'&&!$r['dependencies'][0]['pinned'];});
check_case('greater-than range preserved',function(){ $p=temp_manifest('{"dependencies":{"a":">=2.0"}}');$r=parse_manifest($p,'package.json');unlink($p);return $r['dependencies'][0]['checked_version']==='2.0';});
check_case('wildcard skipped',function(){ $p=temp_manifest('{"dependencies":{"a":"*"}}');$r=parse_manifest($p,'package.json');unlink($p);return count($r['dependencies'])===0&&$r['skipped']===1;});
check_case('invalid JSON rejected',function(){ $p=temp_manifest('{invalid');try{parse_manifest($p,'package.json');return false;}catch(RuntimeException $e){return str_contains($e->getMessage(),'Invalid JSON');}finally{unlink($p);}});
check_case('empty file rejected',function(){ $p=temp_manifest('');try{parse_manifest($p,'requirements.txt');return false;}catch(RuntimeException $e){return str_contains($e->getMessage(),'empty');}finally{unlink($p);}});
check_case('requirements comments extras markers',function(){ $p=temp_manifest("# comment\nrequests[security]>=2.20; python_version > '3.8' # inline\nurllib3==1.25.8\n-r other.txt\n");$r=parse_manifest($p,'requirements.txt');unlink($p);return count($r['dependencies'])===2&&$r['dependencies'][0]['name']==='requests'&&$r['dependencies'][0]['version']==='>=2.20';});
check_case('composer platform package skipped',function(){ $p=temp_manifest('{"require":{"php":">=8.0","vendor/pkg":"^1.2"}}');$r=parse_manifest($p,'composer.json');unlink($p);return count($r['dependencies'])===1&&$r['skipped']===1;});
check_case('composer dev branch skipped',function(){ $p=temp_manifest('{"require":{"vendor/pkg":"dev-main","vendor/lib":"^1.2"}}');$r=parse_manifest($p,'composer.json');unlink($p);return count($r['dependencies'])===1&&$r['skipped']===1;});
echo "\nPassed: $passed; Failed: $failed\n";exit($failed?1:0);
