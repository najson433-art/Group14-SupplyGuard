<?php
declare(strict_types=1);

function cvss3_base_score(string $vector): ?float {
    if(!preg_match('/^CVSS:3\\.[01]\\/((?:AV|AC|PR|UI|S|C|I|A):[^\\/]+(?:\\/(?:AV|AC|PR|UI|S|C|I|A):[^\\/]+)*)$/',$vector,$m)) return null;
    $parts=[];foreach(explode('/',$m[1]) as $pair){[$k,$v]=array_pad(explode(':',$pair,2),2,'');$parts[$k]=$v;}
    foreach(['AV','AC','PR','UI','S','C','I','A'] as $k) if(!isset($parts[$k])) return null;
    $av=['N'=>0.85,'A'=>0.62,'L'=>0.55,'P'=>0.2][$parts['AV']]??null;
    $ac=['L'=>0.77,'H'=>0.44][$parts['AC']]??null;
    $ui=['N'=>0.85,'R'=>0.62][$parts['UI']]??null;
    $scope=$parts['S'];
    $prTable=['U'=>['N'=>0.85,'L'=>0.62,'H'=>0.27],'C'=>['N'=>0.85,'L'=>0.68,'H'=>0.5]];
    $pr=$prTable[$scope][$parts['PR']]??null;
    $impact=['H'=>0.56,'L'=>0.22,'N'=>0.0];
    $c=$impact[$parts['C']]??null;$i=$impact[$parts['I']]??null;$a=$impact[$parts['A']]??null;
    if(in_array(null,[$av,$ac,$ui,$pr,$c,$i,$a],true)||!in_array($scope,['U','C'],true)) return null;
    $isc=1-(1-$c)*(1-$i)*(1-$a);
    if($isc<=0) return 0.0;
    $impactSub=$scope==='U'?6.42*$isc:7.52*($isc-0.029)-3.25*pow($isc-0.02,15);
    if($impactSub<=0) return 0.0;
    $exploit=8.22*$av*$ac*$pr*$ui;
    if($scope==='U') $base=min($impactSub+$exploit,10);
    else $base=min(1.08*($impactSub+$exploit),10);
    $round=fn($n)=>ceil($n*10-1e-9)/10;
    return $round($base);
}

function vulnerability_severity(array $v): string {
    $db=strtolower((string)($v['database_specific']['severity']??''));
    if($db==='moderate')return 'medium';
    if(in_array($db,['critical','high','medium','low'],true))return $db;
    foreach(($v['severity']??[]) as $s){
        $type=strtoupper((string)($s['type']??''));$score=(string)($s['score']??'');
        if(str_contains($type,'CVSS_V3')||str_starts_with($score,'CVSS:3.')){
            $n=cvss3_base_score($score);if($n===null)continue;
            if($n>=9)return 'critical';if($n>=7)return 'high';if($n>=4)return 'medium';if($n>=0.1)return 'low';
        }
    }
    return 'unclassified';
}
