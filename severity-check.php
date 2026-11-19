<?php
declare(strict_types=1);
require_once __DIR__.'/../includes/severity.php';
$passed=0;$failed=0;
function severity_case(string $label, callable $test): void { global $passed,$failed;try{$ok=$test();echo ($ok?'[PASS] ':'[FAIL] ').$label."\n";if($ok)$passed++;else $failed++;}catch(Throwable $e){echo '[FAIL] '.$label.' — '.$e->getMessage()."\n";$failed++;}}
severity_case('database CRITICAL mapping',fn()=>vulnerability_severity(['database_specific'=>['severity'=>'CRITICAL']])==='critical');
severity_case('database HIGH mapping',fn()=>vulnerability_severity(['database_specific'=>['severity'=>'HIGH']])==='high');
severity_case('database MODERATE maps to medium',fn()=>vulnerability_severity(['database_specific'=>['severity'=>'MODERATE']])==='medium');
severity_case('database LOW mapping',fn()=>vulnerability_severity(['database_specific'=>['severity'=>'LOW']])==='low');
severity_case('CVSS v3.1 critical vector scores 9.8',fn()=>cvss3_base_score('CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H')===9.8 && vulnerability_severity(['severity'=>[['type'=>'CVSS_V3','score'=>'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H']]])==='critical');
severity_case('CVSS vector medium score classification',fn()=>vulnerability_severity(['severity'=>[['type'=>'CVSS_V3','score'=>'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N']]])==='medium');
severity_case('unknown severity remains unclassified',fn()=>vulnerability_severity([])==='unclassified');
severity_case('invalid CVSS vector remains unclassified',fn()=>vulnerability_severity(['severity'=>[['type'=>'CVSS_V3','score'=>'not-a-vector']]])==='unclassified');
echo "\nPassed: $passed; Failed: $failed\n";exit($failed?1:0);
