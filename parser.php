<?php
declare(strict_types=1);

/** Map only the three manifest filenames accepted by SupplyGuard. */
function manifest_type(string $filename): ?string {
    return match($filename) {
        'package.json' => 'npm',
        'composer.json' => 'Packagist',
        'requirements.txt' => 'PyPI',
        default => null
    };
}

/** Extract the first numeric version token for OSV lookup; never overwrite the declaration. */
function clean_version(string $spec): ?string {
    $spec = trim($spec);
    if ($spec === '') return null;
    $spec = preg_replace('/^(?:===|==|>=|<=|>|<|=|\\^|~|v)/i', '', $spec);
    if (!preg_match('/\\d+(?:\\.\\d+)*(?:[-+][0-9A-Za-z.\\-]+)?/', $spec, $m)) return null;
    return $m[0];
}

/** Exact version pins are used for the compliance baseline; ranges remain declared and are queried using a representative numeric version. */
function is_pinned(string $spec, string $ecosystem): bool {
    $spec = trim($spec);
    if ($ecosystem === 'PyPI') return (bool)preg_match('/^(?:==|===)\\s*\\d+(?:\\.\\d+)*(?:[.+-][0-9A-Za-z.+-]+)?$/', $spec);
    return (bool)preg_match('/^v?\\d+(?:\\.\\d+)*(?:[-+][0-9A-Za-z.\\-]+)?$/i', $spec);
}

/**
 * Returns ['dependencies'=>[['name','version','ecosystem','checked_version','pinned']], 'skipped'=>int].
 * Declared versions are preserved exactly (trimmed and limited to 50 chars).
 */
function parse_manifest(string $path, string $filename): array {
    $ecosystem = manifest_type($filename);
    if (!$ecosystem) throw new RuntimeException('Unsupported filename. Use package.json, composer.json or requirements.txt exactly.');
    $raw = file_get_contents($path);
    if ($raw === false) throw new RuntimeException('The uploaded file could not be read.');
    if ($raw === '') throw new RuntimeException('The uploaded file is empty.');
    if (str_contains($raw, "\0")) throw new RuntimeException('The uploaded file contains a NUL byte and was rejected.');
    $items = []; $skipped = 0;
    if ($filename === 'package.json' || $filename === 'composer.json') {
        try { $data = json_decode($raw, true, 512, JSON_THROW_ON_ERROR); }
        catch (JsonException $e) { throw new RuntimeException('Invalid JSON: '.$e->getMessage()); }
        if (!is_array($data)) throw new RuntimeException('The JSON manifest must contain an object.');
        $sections = $filename === 'package.json'
            ? ['dependencies','devDependencies','optionalDependencies']
            : ['require','require-dev'];
        foreach ($sections as $section) {
            foreach (($data[$section] ?? []) as $name => $spec) {
                if (!is_string($name) || !is_string($spec)) { $skipped++; continue; }
                $name = trim($name); $spec = trim($spec);
                if ($filename === 'composer.json' && (strpos($name, '/') === false || str_starts_with(strtolower($name), 'dev-') || str_starts_with(strtolower($spec), 'dev-'))) { $skipped++; continue; }
                if ($spec === '' || in_array(strtolower($spec), ['*','latest'], true) ||
                    preg_match('/^(?:git\\+|https?:|ssh:|file:|workspace:|link:|path:)/i', $spec)) { $skipped++; continue; }
                $checked = clean_version($spec);
                if (!$checked) { $skipped++; continue; }
                $items[$name.'|'.$spec] = [
                    'name'=>$name, 'version'=>substr($spec,0,50), 'ecosystem'=>$ecosystem,
                    'checked_version'=>$checked, 'pinned'=>is_pinned($spec,$ecosystem)
                ];
            }
        }
    } else {
        foreach (preg_split('/\\R/', $raw) as $line) {
            $line = trim($line);
            if ($line === '' || str_starts_with($line, '#') || str_starts_with($line, '-')) continue;
            $line = explode(';', $line, 2)[0]; // Ignore PEP 508 environment markers.
            $line = trim(preg_replace('/\\s+#.*$/', '', $line));
            if ($line === '') continue;
            if (!preg_match('/^([A-Za-z0-9_.-]+)(?:\\[[^\\]]+\\])?\\s*(===|==|~=|>=|<=|>|<)\\s*([A-Za-z0-9_.+!* -]+)$/', $line, $m)) { $skipped++; continue; }
            $name = trim($m[1]); $operator = $m[2]; $version = trim($m[3]);
            $spec = $operator.$version;
            $checked = clean_version($spec);
            if (!$checked || in_array($version, ['*',''], true)) { $skipped++; continue; }
            $items[$name.'|'.$spec] = [
                'name'=>$name, 'version'=>substr($spec,0,50), 'ecosystem'=>$ecosystem,
                'checked_version'=>$checked, 'pinned'=>is_pinned($spec,$ecosystem)
            ];
        }
    }
    return ['dependencies'=>array_values($items), 'skipped'=>$skipped];
}
