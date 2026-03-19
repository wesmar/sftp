<?php
declare(strict_types=1);

// PHP 7.x polyfills for functions introduced in PHP 8.0
if (!function_exists('str_contains')) {
    function str_contains(string $haystack, string $needle): bool {
        return $needle === '' || strpos($haystack, $needle) !== false;
    }
}
if (!function_exists('str_starts_with')) {
    function str_starts_with(string $haystack, string $needle): bool {
        return $needle === '' || strncmp($haystack, $needle, strlen($needle)) === 0;
    }
}
if (!function_exists('str_ends_with')) {
    function str_ends_with(string $haystack, string $needle): bool {
        return $needle === '' || substr($haystack, -strlen($needle)) === $needle;
    }
}

/**
 * Single-file HTTP file agent for Total Commander plugin backend.
 * Target: unified PHP 7.4+ / 8.x compatibility runtime.
 *
 * Deployment:
 * 1) Upload this file to your server.
 * 2) Prefer setting PSK via environment variable (see AGENT_PSK_ENV_KEYS).
 * 3) For "upload-only deploy" flow, set AGENT_PSK_SALT + AGENT_PSK_SHA256 and keep AGENT_PSK placeholder.
 * 4) Optionally set AGENT_ROOT to the desired jail root.
 */

// ---------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------

const AGENT_NAME = 'TC PHP Agent';
const AGENT_VERSION = '1.0.1';
const AGENT_PSK = 'CHANGE_ME_TO_LONG_RANDOM_SECRET';
const AGENT_PSK_SALT = '';
const AGENT_PSK_SHA256 = '';
const AGENT_PSK_ENV_KEYS = ['TC_SFTP_AGENT_PSK', 'SFTP_AGENT_PSK', 'AGENT_PSK'];
const AGENT_ROOT = __DIR__;
const AGENT_NONCE_TTL = 300; // seconds
const AGENT_REPLAY_DIR = '._sftp_agent_nonce_cache';
const AGENT_DEFAULT_CHUNK = 262144; // 256 KiB
const AGENT_MAX_LIST_ITEMS = 20000;

// ---------------------------------------------------------------------
// Bootstrap
// ---------------------------------------------------------------------

error_reporting(E_ALL);
ini_set('display_errors', '0');
header('X-Agent-Name: ' . AGENT_NAME);
header('X-Agent-Version: ' . AGENT_VERSION);

$method = strtoupper($_SERVER['REQUEST_METHOD'] ?? 'GET');
$op = strtoupper(trim((string)(get_param('op', get_header('x-sftp-op', 'PROBE')))));

if ($op !== 'PROBE') {
    require_auth($method, $op);
}

try {
    switch ($op) {
        case 'PROBE':
            op_probe();
            break;
        case 'LIST':
            op_list();
            break;
        case 'STAT':
            op_stat();
            break;
        case 'GET':
            op_get();
            break;
        case 'PUT':
            op_put();
            break;
        case 'FINALIZE':
            op_finalize();
            break;
        case 'DELETE':
            op_delete();
            break;
        case 'MKDIR':
            op_mkdir();
            break;
        case 'RMDIR':
            op_rmdir();
            break;
        case 'RENAME':
            op_rename();
            break;
        case 'HASH':
            op_hash();
            break;
        case 'SHELL_EXEC':
            op_shell_exec();
            break;
        case 'TAR_STREAM':
            op_tar_stream();
            break;
        case 'TAR_EXTRACT':
            op_tar_extract();
            break;
        default:
            fail(400, 'UNKNOWN_OPERATION', 'Unsupported operation');
    }
} catch (Throwable $e) {
    fail(500, 'INTERNAL_ERROR', $e->getMessage());
}

// ---------------------------------------------------------------------
// Operations
// ---------------------------------------------------------------------

function op_probe(): void
{
    $ini = collect_ini_info();
    $caps = collect_capabilities($ini);
    ok([
        'agent' => [
            'name' => AGENT_NAME,
            'version' => AGENT_VERSION,
        ],
        'runtime' => [
            'php_version' => PHP_VERSION,
            'sapi' => PHP_SAPI,
            'os_family' => PHP_OS_FAMILY,
        ],
        'ini' => $ini,
        'capabilities' => $caps,
    ]);
}

function op_list(): void
{
    $relPath = normalize_rel((string)get_param('path', '.'));
    $scriptName = (string)($_SERVER['SCRIPT_NAME'] ?? '');
    $scriptRel = normalize_rel(ltrim(str_replace('\\', '/', $scriptName), '/'));
    $scriptBase = basename($scriptName);
    if ($relPath === $scriptRel || ($scriptBase !== '' && ($relPath === $scriptBase || str_ends_with($relPath, '/' . $scriptBase)))) {
        // Some clients may accidentally send script URL path as directory path.
        $relPath = '.';
    }
    $absPath = resolve_path($relPath, true);
    if (!is_dir($absPath)) {
        fail(404, 'NOT_A_DIRECTORY', 'Path is not a directory');
    }

    $items = [];
    $count = 0;
    $it = new DirectoryIterator($absPath);
    foreach ($it as $entry) {
        if ($entry->isDot()) {
            continue;
        }
        $count++;
        if ($count > AGENT_MAX_LIST_ITEMS) {
            fail(413, 'TOO_MANY_ITEMS', 'Directory item limit exceeded');
        }
        $items[] = [
            'name' => $entry->getFilename(),
            'is_dir' => $entry->isDir(),
            'size' => $entry->isFile() ? $entry->getSize() : null,
            'mtime' => $entry->getMTime(),
            'perms' => substr(sprintf('%o', $entry->getPerms()), -4),
        ];
    }

    $format = strtolower((string)get_param('format', 'json'));
    if ($format === 'plain') {
        header_remove('Content-Type');
        header('Content-Type: text/plain; charset=utf-8');
        foreach ($items as $it) {
            $type = $it['is_dir'] ? 'D' : 'F';
            $size = (int)($it['size'] ?? 0);
            $mtime = (int)($it['mtime'] ?? 0);
            $name = (string)$it['name'];
            echo $type . "\t" . $size . "\t" . $mtime . "\t" . base64_encode($name) . "\n";
        }
        exit;
    }

    ok(['path' => rel_from_abs($absPath), 'items' => $items]);
}

function op_stat(): void
{
    $relPath = normalize_rel((string)get_param('path', ''));
    $absPath = resolve_path($relPath, false);
    if (!file_exists($absPath)) {
        fail(404, 'NOT_FOUND', 'Path not found');
    }

    $st = @stat($absPath);
    if (!is_array($st)) {
        fail(500, 'STAT_FAILED', 'Unable to stat path');
    }

    ok([
        'path' => rel_from_abs($absPath),
        'exists' => true,
        'is_dir' => is_dir($absPath),
        'is_file' => is_file($absPath),
        'size' => is_file($absPath) ? (int)$st['size'] : null,
        'mtime' => (int)$st['mtime'],
        'atime' => (int)$st['atime'],
        'ctime' => (int)$st['ctime'],
        'mode' => substr(sprintf('%o', $st['mode']), -4),
        'readable' => is_readable($absPath),
        'writable' => is_writable($absPath),
    ]);
}

function op_get(): void
{
    $relPath = normalize_rel((string)get_param('path', ''));
    $absPath = resolve_path($relPath, true);
    if (!is_file($absPath)) {
        fail(404, 'NOT_A_FILE', 'Path is not a file');
    }
    if (!is_readable($absPath)) {
        fail(403, 'READ_DENIED', 'File is not readable');
    }

    $size = (int)filesize($absPath);
    $offset = max(0, (int)get_param('offset', 0));
    $length = (int)get_param('length', 0);
    if ($offset > $size) {
        fail(416, 'INVALID_RANGE', 'Offset beyond end of file');
    }

    $remaining = $size - $offset;
    $toSend = ($length > 0) ? min($length, $remaining) : $remaining;

    $fp = @fopen($absPath, 'rb');
    if ($fp === false) {
        fail(500, 'OPEN_FAILED', 'Failed to open file');
    }

    if ($offset > 0 && fseek($fp, $offset, SEEK_SET) !== 0) {
        fclose($fp);
        fail(500, 'SEEK_FAILED', 'Failed to seek file');
    }

    header_remove('Content-Type');
    header('Content-Type: application/octet-stream');
    header('Content-Length: ' . (string)$toSend);
    header('X-SFTP-File-Size: ' . (string)$size);
    header('X-SFTP-Offset: ' . (string)$offset);
    header('Accept-Ranges: bytes');

    // Disable userland output buffering for streaming.
    while (ob_get_level() > 0) {
        @ob_end_clean();
    }
    @ini_set('zlib.output_compression', '0');
    header('X-Accel-Buffering: no');

    $out = @fopen('php://output', 'wb');
    if ($out === false) {
        fclose($fp);
        fail(500, 'OUTPUT_OPEN_FAILED', 'Failed to open output stream');
    }
    $copied = @stream_copy_to_stream($fp, $out, $toSend);
    if ($copied === false) {
        fclose($out);
        fclose($fp);
        fail(500, 'READ_FAILED', 'Failed during stream copy');
    }
    fclose($out);
    fclose($fp);
    exit;
}

function op_tar_stream(): void
{
    @set_time_limit(0);
    $relPath = normalize_rel((string)get_param('path', '.'));
    $absPath = resolve_path($relPath, true);
    if (!is_dir($absPath)) {
        fail(404, 'NOT_A_DIRECTORY', 'Path is not a directory');
    }

    while (ob_get_level() > 0) {
        @ob_end_clean();
    }
    @ini_set('zlib.output_compression', '0');
    header_remove('Content-Type');
    header('Content-Type: application/x-tar');
    header('X-Accel-Buffering: no');

    $out = @fopen('php://output', 'wb');
    if ($out === false) {
        fail(500, 'OUTPUT_OPEN_FAILED', 'Failed to open output stream');
    }

    if (!tar_stream_dir($absPath, $absPath, $out)) {
        fclose($out);
        exit;
    }

    // End-of-archive: two 512-byte zero blocks
    fwrite($out, str_repeat("\0", 1024));
    fclose($out);
    exit;
}

function tar_stream_dir(string $rootAbs, string $dirAbs, $out): bool
{
    $it = new DirectoryIterator($dirAbs);
    foreach ($it as $entry) {
        if ($entry->isDot()) {
            continue;
        }
        $childAbs = $entry->getPathname();
        // Build relative path from root
        $relPart = ltrim(str_replace(
            str_replace('\\', '/', $rootAbs),
            '',
            str_replace('\\', '/', $childAbs)
        ), '/');

        if ($entry->isDir() && !$entry->isLink()) {
            if (!tar_write_header($relPart . '/', 0, $entry->getMTime(), '5', $out)) {
                return false;
            }
            if (!tar_stream_dir($rootAbs, $childAbs, $out)) {
                return false;
            }
        } elseif ($entry->isFile()) {
            $fp = @fopen($childAbs, 'rb');
            if ($fp === false) {
                return false;
            }
            $size = $entry->getSize();
            $mtime = $entry->getMTime();
            if (!tar_write_header($relPart, $size, $mtime, '0', $out)) {
                fclose($fp);
                return false;
            }
            $written = 0;
            while ($written < $size) {
                $chunk = @fread($fp, 65536);
                if ($chunk === false || $chunk === '') {
                    fclose($fp);
                    return false;
                }
                $fw = fwrite($out, $chunk);
                if ($fw === false || $fw < strlen($chunk)) {
                    fclose($fp);
                    return false;
                }
                $written += strlen($chunk);
            }
            fclose($fp);
            // Pad to 512-byte boundary
            $rem = $size % 512;
            if ($rem > 0) {
                $pad = str_repeat("\0", 512 - $rem);
                $fw = fwrite($out, $pad);
                if ($fw === false || $fw < strlen($pad)) {
                    return false;
                }
            }
        }
    }
    return true;
}

function tar_write_header(string $name, int $size, int $mtime, string $type, $out): bool
{
    // GNU long name extension for names > 99 chars
    if (strlen($name) > 99) {
        $longData = $name . "\0";
        $longSize = strlen($longData);
        $longHdr = tar_build_header('././@LongLink', $longSize, 0, 'L');
        $fw = fwrite($out, $longHdr);
        if ($fw === false || $fw < strlen($longHdr)) {
            return false;
        }
        $fw = fwrite($out, $longData);
        if ($fw === false || $fw < strlen($longData)) {
            return false;
        }
        $rem = $longSize % 512;
        if ($rem > 0) {
            $pad = str_repeat("\0", 512 - $rem);
            $fw = fwrite($out, $pad);
            if ($fw === false || $fw < strlen($pad)) {
                return false;
            }
        }
        $name = substr($name, 0, 99);
    }
    $hdr = tar_build_header($name, $size, $mtime, $type);
    $fw = fwrite($out, $hdr);
    if ($fw === false || $fw < strlen($hdr)) {
        return false;
    }
    return true;
}

function tar_build_header(string $name, int $size, int $mtime, string $type): string
{
    $h = str_repeat("\0", 512);
    $name = substr($name, 0, 99);
    $h = substr_replace($h, $name,                       0,   strlen($name));
    $h = substr_replace($h, sprintf('%07o', 0644),     100,  7);
    $h = substr_replace($h, '0000000',                 108,  7);
    $h = substr_replace($h, '0000000',                 116,  7);
    $h = substr_replace($h, sprintf('%011o', $size),   124, 11);
    $h = substr_replace($h, sprintf('%011o', $mtime),  136, 11);
    $h = substr_replace($h, '        ',                148,  8); // checksum placeholder
    $h = substr_replace($h, $type,                     156,  1);
    $h = substr_replace($h, 'ustar',                   257,  5);
    $h = substr_replace($h, '00',                      263,  2);
    // Calculate checksum (sum of all bytes with placeholder space = 0x20)
    $sum = 0;
    for ($i = 0; $i < 512; $i++) {
        $sum += ord($h[$i]);
    }
    $h = substr_replace($h, sprintf('%06o', $sum) . "\0 ", 148, 8);
    return $h;
}

function op_tar_extract(): void
{
    @set_time_limit(0);
    $relPath = normalize_rel((string)get_param('path', '.'));
    $absPath = resolve_path_for_create($relPath);
    if (!is_dir($absPath) && !@mkdir($absPath, 0775, true)) {
        fail(500, 'MKDIR_FAILED', 'Cannot create target directory');
    }
    $in = @fopen('php://input', 'rb');
    if ($in === false) {
        fail(500, 'INPUT_OPEN_FAILED', 'Failed to open input stream');
    }
    $count = tar_extract_stream($absPath, $in);
    fclose($in);
    ok(['extracted' => $count]);
}

function tar_read_exact($in, int $n)
{
    if ($n <= 0) return '';
    $buf = '';
    $remaining = $n;
    while ($remaining > 0) {
        $chunk = @fread($in, $remaining);
        if ($chunk === false || $chunk === '') return null;
        $buf .= $chunk;
        $remaining -= strlen($chunk);
    }
    return $buf;
}

function tar_skip_exact($in, int $n): bool
{
    if ($n <= 0) return true;
    $remaining = $n;
    while ($remaining > 0) {
        $chunk = @fread($in, min(65536, $remaining));
        if ($chunk === false || $chunk === '') return false;
        $remaining -= strlen($chunk);
    }
    return true;
}

function tar_extract_stream(string $rootAbs, $in): int
{
    $rootAbs = rtrim(str_replace('\\', '/', $rootAbs), '/');
    $pendingLongName = '';
    $count = 0;
    for (;;) {
        $hdr = tar_read_exact($in, 512);
        if ($hdr === null || strlen($hdr) < 512) break;
        if ($hdr === str_repeat("\0", 512)) break;
        $typeflag   = $hdr[156];
        $sizeStr    = trim(substr($hdr, 124, 12), "\0 ");
        $fileSize   = ($sizeStr !== '') ? (int)octdec($sizeStr) : 0;
        $nameRaw    = rtrim(substr($hdr, 0, 100), "\0");
        $prefix     = rtrim(substr($hdr, 345, 155), "\0");
        $entryPath  = ($prefix !== '') ? ($prefix . '/' . $nameRaw) : $nameRaw;
        $paddedSize = (int)(($fileSize + 511) / 512) * 512;
        if ($typeflag === 'L') {
            $longData = ($paddedSize > 0) ? tar_read_exact($in, $paddedSize) : '';
            if ($longData === null) break;
            $pendingLongName = rtrim(substr((string)$longData, 0, $fileSize), "\0");
            continue;
        }
        if ($pendingLongName !== '') {
            $entryPath = $pendingLongName;
            $pendingLongName = '';
        }
        $entryPath = str_replace('\\', '/', trim($entryPath, '/'));
        if ($entryPath === '' || strpos($entryPath, '..') !== false) {
            if ($paddedSize > 0) tar_skip_exact($in, $paddedSize);
            continue;
        }
        $absTarget = $rootAbs . '/' . $entryPath;
        if ($typeflag === '5') {
            @mkdir($absTarget, 0755, true);
            if ($paddedSize > 0) tar_skip_exact($in, $paddedSize);
            continue;
        }
        $parentDir = dirname($absTarget);
        if (!is_dir($parentDir)) @mkdir($parentDir, 0755, true);
        $fp = @fopen($absTarget, 'wb');
        if ($fp === false) {
            if ($paddedSize > 0) tar_skip_exact($in, $paddedSize);
            continue;
        }
        $written     = 0;
        $padConsumed = 0;
        $ok          = true;
        while ($padConsumed < $paddedSize) {
            $want  = (int)min(65536, $paddedSize - $padConsumed);
            $chunk = @fread($in, $want);
            if ($chunk === false || $chunk === '') { $ok = false; break; }
            $got = strlen($chunk);
            if ($written < $fileSize) {
                $toWrite = (int)min($fileSize - $written, $got);
                fwrite($fp, substr($chunk, 0, $toWrite));
                $written += $toWrite;
            }
            $padConsumed += $got;
        }
        fclose($fp);
        if (!$ok) break;
        ++$count;
    }
    return $count;
}

function op_put(): void
{
    if (in_array(strtoupper($_SERVER['REQUEST_METHOD'] ?? ''), ['POST', 'PUT'], true) === false) {
        fail(405, 'METHOD_NOT_ALLOWED', 'PUT operation requires POST or PUT');
    }

    $relPath = normalize_rel((string)get_param('path', ''));
    if ($relPath === '') {
        fail(400, 'INVALID_PATH', 'Path is required');
    }

    $offset = max(0, (int)get_param('offset', 0));
    $usePart = bool_param('part', true);
    $verifyHash = strtolower((string)get_header('x-sftp-content-sha256', ''));

    $targetRel = $usePart ? ($relPath . '.part') : $relPath;
    $absPath = resolve_path_for_create($targetRel);
    ensure_parent_dir($absPath);

    $fp = @fopen($absPath, 'c+b');
    if ($fp === false) {
        fail(500, 'OPEN_FAILED', 'Failed to open target file');
    }

    if (!flock($fp, LOCK_EX)) {
        fclose($fp);
        fail(500, 'LOCK_FAILED', 'Failed to lock target file');
    }

    if ($offset === 0 && !bool_param('append', false)) {
        if (!ftruncate($fp, 0)) {
            flock($fp, LOCK_UN);
            fclose($fp);
            fail(500, 'TRUNCATE_FAILED', 'Failed to truncate file');
        }
    }

    if (fseek($fp, $offset, SEEK_SET) !== 0) {
        flock($fp, LOCK_UN);
        fclose($fp);
        fail(500, 'SEEK_FAILED', 'Failed to seek target file');
    }

    $in = fopen('php://input', 'rb');
    if ($in === false) {
        flock($fp, LOCK_UN);
        fclose($fp);
        fail(500, 'INPUT_OPEN_FAILED', 'Unable to open input stream');
    }

    $ctx = hash_init('sha256');
    $written = 0;
    $chunk = recommended_chunk_size();
    while (!feof($in)) {
        $buf = fread($in, $chunk);
        if ($buf === false) {
            fclose($in);
            flock($fp, LOCK_UN);
            fclose($fp);
            fail(500, 'INPUT_READ_FAILED', 'Read from input failed');
        }
        if ($buf === '') {
            continue;
        }
        hash_update($ctx, $buf);
        $n = fwrite($fp, $buf);
        if ($n === false) {
            fclose($in);
            flock($fp, LOCK_UN);
            fclose($fp);
            fail(500, 'WRITE_FAILED', 'Write to target failed');
        }
        $written += $n;
    }
    fclose($in);

    fflush($fp);
    $newSize = (int)filesize($absPath);
    flock($fp, LOCK_UN);
    fclose($fp);

    $actualHash = hash_final($ctx);
    if ($verifyHash !== '' && !hash_equals($verifyHash, $actualHash)) {
        fail(409, 'HASH_MISMATCH', 'Uploaded content hash mismatch');
    }

    ok([
        'path' => $targetRel,
        'written' => $written,
        'size' => $newSize,
        'sha256' => $actualHash,
        'part' => $usePart,
    ]);
}

function op_finalize(): void
{
    $relPath = normalize_rel((string)get_param('path', ''));
    if ($relPath === '') {
        fail(400, 'INVALID_PATH', 'Path is required');
    }

    $partRel = $relPath . '.part';
    $partAbs = resolve_path($partRel, true);
    $finalAbs = resolve_path_for_create($relPath);
    ensure_parent_dir($finalAbs);

    $overwrite = bool_param('overwrite', true);
    if (file_exists($finalAbs)) {
        if (!$overwrite) {
            fail(409, 'TARGET_EXISTS', 'Target exists and overwrite=false');
        }
        if (is_dir($finalAbs)) {
            fail(409, 'TARGET_IS_DIR', 'Target path is a directory');
        }
        if (!@unlink($finalAbs)) {
            fail(500, 'UNLINK_FAILED', 'Failed to remove existing target');
        }
    }

    if (!@rename($partAbs, $finalAbs)) {
        fail(500, 'RENAME_FAILED', 'Failed to finalize upload');
    }

    ok([
        'path' => $relPath,
        'size' => (int)filesize($finalAbs),
        'finalized' => true,
    ]);
}

function op_delete(): void
{
    $relPath = normalize_rel((string)get_param('path', ''));
    $absPath = resolve_path($relPath, true);
    if (!is_file($absPath)) {
        fail(404, 'NOT_A_FILE', 'Path is not a file');
    }
    if (!@unlink($absPath)) {
        fail(500, 'DELETE_FAILED', 'File deletion failed');
    }
    ok(['deleted' => true, 'path' => $relPath]);
}

function op_mkdir(): void
{
    $relPath = normalize_rel((string)get_param('path', ''));
    if ($relPath === '') {
        fail(400, 'INVALID_PATH', 'Path is required');
    }
    $absPath = resolve_path_for_create($relPath);
    $recursive = bool_param('recursive', true);
    $mode = octdec((string)get_param('mode', '0775'));
    if (is_dir($absPath)) {
        ok(['created' => false, 'exists' => true, 'path' => $relPath]);
    }
    if (!@mkdir($absPath, $mode, $recursive)) {
        fail(500, 'MKDIR_FAILED', 'Directory creation failed');
    }
    ok(['created' => true, 'path' => $relPath]);
}

function op_rmdir(): void
{
    $relPath = normalize_rel((string)get_param('path', ''));
    $absPath = resolve_path($relPath, true);
    if (!is_dir($absPath)) {
        fail(404, 'NOT_A_DIRECTORY', 'Path is not a directory');
    }

    $recursive = bool_param('recursive', false);
    if ($recursive) {
        remove_tree($absPath);
    } else {
        if (!@rmdir($absPath)) {
            fail(500, 'RMDIR_FAILED', 'Directory is not empty or cannot be removed');
        }
    }

    ok(['removed' => true, 'path' => $relPath, 'recursive' => $recursive]);
}

function op_rename(): void
{
    $fromRel = normalize_rel((string)get_param('from', ''));
    $toRel = normalize_rel((string)get_param('to', ''));
    if ($fromRel === '' || $toRel === '') {
        fail(400, 'INVALID_PATH', 'Both from and to are required');
    }

    $fromAbs = resolve_path($fromRel, true);
    $toAbs = resolve_path_for_create($toRel);
    ensure_parent_dir($toAbs);
    $overwrite = bool_param('overwrite', true);
    if (file_exists($toAbs)) {
        if (!$overwrite) {
            fail(409, 'TARGET_EXISTS', 'Target exists and overwrite=false');
        }
        if (is_dir($toAbs)) {
            fail(409, 'TARGET_IS_DIR', 'Target is a directory');
        }
        if (!@unlink($toAbs)) {
            fail(500, 'UNLINK_FAILED', 'Failed to replace target');
        }
    }
    if (!@rename($fromAbs, $toAbs)) {
        fail(500, 'RENAME_FAILED', 'Rename operation failed');
    }

    ok(['renamed' => true, 'from' => $fromRel, 'to' => $toRel]);
}

function op_hash(): void
{
    $relPath = normalize_rel((string)get_param('path', ''));
    $algo = strtolower((string)get_param('algo', 'sha256'));
    if (!in_array($algo, hash_algos(), true)) {
        fail(400, 'UNSUPPORTED_HASH', 'Hash algorithm not supported');
    }

    $absPath = resolve_path($relPath, true);
    if (!is_file($absPath) || !is_readable($absPath)) {
        fail(404, 'NOT_A_FILE', 'Path is not a readable file');
    }

    $hash = @hash_file($algo, $absPath);
    if ($hash === false) {
        fail(500, 'HASH_FAILED', 'Unable to compute hash');
    }
    ok(['path' => $relPath, 'algo' => $algo, 'hash' => $hash]);
}

function op_shell_exec(): void
{
    $cmd = trim((string)get_param('cmd', ''));
    if ($cmd === '') {
        fail(400, 'INVALID_COMMAND', 'Command is required');
    }
    if (strlen($cmd) > 8192) {
        fail(413, 'COMMAND_TOO_LONG', 'Command exceeds maximum length');
    }

    $cwdRaw = (string)get_param('cwd', '.');
    $cwdAbs = resolve_shell_cwd($cwdRaw);
    if (!is_dir($cwdAbs) || !is_readable($cwdAbs)) {
        fail(404, 'INVALID_CWD', 'Working directory is invalid');
    }

    $disabled = disabled_functions_set((string)ini_get('disable_functions'));
    $method = pick_shell_method($disabled);
    if ($method === '') {
        fail(503, 'SHELL_DISABLED', 'No shell execution function is available');
    }

    $prevCwd = @getcwd();
    if (!@chdir($cwdAbs)) {
        fail(500, 'CHDIR_FAILED', 'Unable to switch working directory');
    }

    try {
        $result = execute_shell_command($cmd, $method);
    } finally {
        if (is_string($prevCwd) && $prevCwd !== '') {
            @chdir($prevCwd);
        }
    }

    ok([
        'cwd' => rel_from_abs($cwdAbs),
        'cwd_abs' => $cwdAbs,
        'method' => $method,
        'exit_code' => $result['exit_code'],
        'stdout_b64' => base64_encode($result['stdout']),
        'stderr_b64' => base64_encode($result['stderr']),
    ]);
}

function resolve_shell_cwd(string $cwdRaw): string
{
    $cwdRaw = str_replace("\0", '', trim($cwdRaw));
    $cwdRaw = str_replace('\\', '/', $cwdRaw);
    if ($cwdRaw === '' || $cwdRaw === '.') {
        $cwd = @getcwd();
        if (is_string($cwd) && $cwd !== '') {
            return normalize_abs($cwd);
        }
        return root_realpath();
    }

    // Absolute path for shell mode: allow any existing readable directory.
    if (str_starts_with($cwdRaw, '/')) {
        $real = realpath($cwdRaw);
        if ($real === false) {
            fail(404, 'INVALID_CWD', 'Working directory does not exist');
        }
        $real = normalize_abs($real);
        return $real;
    }

    // Relative path for shell mode: resolve against current working directory.
    $base = @getcwd();
    if (!is_string($base) || $base === '') {
        $base = root_realpath();
    }
    $target = normalize_abs($base . DIRECTORY_SEPARATOR . str_replace('/', DIRECTORY_SEPARATOR, $cwdRaw));
    $real = realpath($target);
    if ($real === false) {
        fail(404, 'INVALID_CWD', 'Working directory does not exist');
    }
    $real = normalize_abs($real);
    if (!is_dir($real) || !is_readable($real)) {
        fail(404, 'INVALID_CWD', 'Working directory is invalid');
    }
    return $real;
}

// ---------------------------------------------------------------------
// Auth and request helpers
// ---------------------------------------------------------------------

function require_auth(string $method, string $op): void
{
    $legacyConfigured = is_legacy_psk_configured();
    $hmacPsk = resolve_agent_psk_for_hmac();
    if (!$legacyConfigured && $hmacPsk === '') {
        fail(503, 'AGENT_NOT_CONFIGURED', 'PSK is not configured (set env var, AGENT_PSK, or AGENT_PSK_SHA256)');
    }

    $legacyAuth = get_header('x-sftp-auth', '');
    if ($legacyAuth !== '' && verify_legacy_auth($legacyAuth)) {
        return;
    }

    $path = normalize_rel((string)get_param('path', ''));
    $tsRaw = get_header('x-sftp-ts', '');
    $nonce = get_header('x-sftp-nonce', '');
    $sig = get_header('x-sftp-signature', '');

    if ($tsRaw === '' || $nonce === '' || $sig === '') {
        fail(401, 'AUTH_REQUIRED', 'Missing auth headers');
    }

    if (!ctype_digit($tsRaw)) {
        fail(401, 'BAD_TIMESTAMP', 'Invalid timestamp');
    }
    $ts = (int)$tsRaw;
    if (abs(time() - $ts) > AGENT_NONCE_TTL) {
        fail(401, 'TIMESTAMP_EXPIRED', 'Timestamp outside allowed window');
    }
    if (!preg_match('/^[A-Za-z0-9._-]{8,128}$/', $nonce)) {
        fail(401, 'BAD_NONCE', 'Invalid nonce format');
    }
    enforce_nonce_once($nonce, $ts);

    $base = strtoupper($method) . "\n" . $op . "\n" . $path . "\n" . $ts . "\n" . $nonce;
    if ($hmacPsk === '') {
        fail(401, 'AUTH_REQUIRED', 'HMAC auth requires plain PSK');
    }
    $expected = hash_hmac('sha256', $base, $hmacPsk);
    if (!hash_equals($expected, strtolower($sig))) {
        fail(401, 'BAD_SIGNATURE', 'Signature mismatch');
    }
}

function resolve_agent_psk_plain(): string
{
    static $cached = null;
    if (is_string($cached)) {
        return $cached;
    }

    foreach (AGENT_PSK_ENV_KEYS as $key) {
        $v = getenv($key);
        if (!is_string($v) || $v === '') {
            if (isset($_ENV[$key]) && is_string($_ENV[$key])) {
                $v = $_ENV[$key];
            } elseif (isset($_SERVER[$key]) && is_string($_SERVER[$key])) {
                $v = $_SERVER[$key];
            } else {
                $v = '';
            }
        }
        $v = trim((string)$v);
        if ($v !== '') {
            $cached = $v;
            return $cached;
        }
    }

    $fallback = trim(AGENT_PSK);
    if ($fallback !== '' && $fallback !== 'CHANGE_ME_TO_LONG_RANDOM_SECRET') {
        $cached = $fallback;
        return $cached;
    }

    $cached = '';
    return $cached;
}

function resolve_agent_psk_for_hmac(): string
{
    return resolve_agent_psk_plain();
}

function resolve_agent_psk_hash(): string
{
    static $cached = null;
    if (is_string($cached)) {
        return $cached;
    }
    $v = strtolower(trim((string)AGENT_PSK_SHA256));
    if ($v !== '' && preg_match('/^[a-f0-9]{64}$/', $v)) {
        $cached = $v;
        return $cached;
    }
    $cached = '';
    return $cached;
}

function resolve_agent_psk_salt(): string
{
    return trim((string)AGENT_PSK_SALT);
}

function is_legacy_psk_configured(): bool
{
    return resolve_agent_psk_plain() !== '' || resolve_agent_psk_hash() !== '';
}

function verify_legacy_auth(string $candidate): bool
{
    $plain = resolve_agent_psk_plain();
    if ($plain !== '' && hash_equals($plain, $candidate)) {
        return true;
    }

    $hash = resolve_agent_psk_hash();
    if ($hash !== '') {
        $salt = resolve_agent_psk_salt();
        $calc = hash('sha256', $salt . ':' . $candidate);
        if (hash_equals($hash, strtolower($calc))) {
            return true;
        }
    }

    return false;
}

function resolve_agent_psk_source(): string
{
    foreach (AGENT_PSK_ENV_KEYS as $key) {
        $v = getenv($key);
        if (!is_string($v) || $v === '') {
            if (isset($_ENV[$key]) && is_string($_ENV[$key])) {
                $v = $_ENV[$key];
            } elseif (isset($_SERVER[$key]) && is_string($_SERVER[$key])) {
                $v = $_SERVER[$key];
            } else {
                $v = '';
            }
        }
        if (trim((string)$v) !== '') {
            return 'env:' . $key;
        }
    }
    $fallback = trim(AGENT_PSK);
    if ($fallback !== '' && $fallback !== 'CHANGE_ME_TO_LONG_RANDOM_SECRET') {
        return 'constant';
    }
    $hash = resolve_agent_psk_hash();
    if ($hash !== '') {
        return 'sha256-constant';
    }
    return 'unset';
}

function get_param(string $name, $default = null)
{
    if (array_key_exists($name, $_GET)) {
        return $_GET[$name];
    }
    if (array_key_exists($name, $_POST)) {
        return $_POST[$name];
    }

    static $jsonBody = null;
    if ($jsonBody === null) {
        $jsonBody = [];
        $ct = strtolower((string)($_SERVER['CONTENT_TYPE'] ?? ''));
        if (str_contains($ct, 'application/json')) {
            $raw = file_get_contents('php://input');
            if (is_string($raw) && $raw !== '') {
                $parsed = json_decode($raw, true);
                if (is_array($parsed)) {
                    $jsonBody = $parsed;
                }
            }
        }
    }
    if (is_array($jsonBody) && array_key_exists($name, $jsonBody)) {
        return $jsonBody[$name];
    }
    return $default;
}

function bool_param(string $name, bool $default): bool
{
    $v = get_param($name, $default ? '1' : '0');
    if (is_bool($v)) {
        return $v;
    }
    $s = strtolower(trim((string)$v));
    return in_array($s, ['1', 'true', 'yes', 'on'], true);
}

function get_header(string $name, string $default = ''): string
{
    $key = 'HTTP_' . strtoupper(str_replace('-', '_', $name));
    $v = $_SERVER[$key] ?? null;
    if ($v === null) {
        return $default;
    }
    return trim((string)$v);
}

function ok(array $payload): void
{
    header('Content-Type: application/json; charset=utf-8');
    echo json_encode(['ok' => true] + $payload, JSON_UNESCAPED_SLASHES);
    exit;
}

function fail(int $status, string $code, string $message): void
{
    http_response_code($status);
    header('Content-Type: application/json; charset=utf-8');
    echo json_encode([
        'ok' => false,
        'error' => [
            'code' => $code,
            'message' => $message,
            'status' => $status,
        ],
    ], JSON_UNESCAPED_SLASHES);
    exit;
}

// ---------------------------------------------------------------------
// Filesystem safety helpers
// ---------------------------------------------------------------------

function normalize_rel(string $path): string
{
    $path = str_replace("\0", '', $path);
    $path = str_replace('\\', '/', trim($path));
    if ($path === '' || $path === '.') {
        return '.';
    }
    $path = ltrim($path, '/');

    $parts = [];
    foreach (explode('/', $path) as $part) {
        if ($part === '' || $part === '.') {
            continue;
        }
        if ($part === '..') {
            if (count($parts) > 0) {
                array_pop($parts);
            }
            continue;
        }
        $parts[] = $part;
    }
    if (!$parts) {
        return '.';
    }
    return implode('/', $parts);
}

function root_realpath(): string
{
    $candidate = AGENT_ROOT;
    if (!is_dir($candidate) && is_file($candidate)) {
        // Be tolerant to accidental file path configuration.
        $candidate = dirname($candidate);
    }
    $root = realpath($candidate);
    if ($root === false) {
        fail(500, 'BAD_ROOT', 'Agent root path is invalid');
    }
    if (!is_dir($root)) {
        fail(500, 'BAD_ROOT', 'Agent root must be a directory');
    }
    return normalize_abs($root);
}

function resolve_path(string $rel, bool $mustExist): string
{
    $root = root_realpath();
    if ($rel === '.' || $rel === '') {
        return $root;
    }
    $target = $root . DIRECTORY_SEPARATOR . str_replace('/', DIRECTORY_SEPARATOR, $rel);
    if ($mustExist) {
        $real = realpath($target);
        if ($real === false) {
            fail(404, 'NOT_FOUND', 'Path not found');
        }
        $real = normalize_abs($real);
        if (!str_starts_with($real, $root)) {
            fail(403, 'PATH_ESCAPE', 'Resolved path escapes root');
        }
        return $real;
    }

    $parent = dirname($target);
    $parentReal = realpath($parent);
    if ($parentReal === false) {
        fail(404, 'PARENT_NOT_FOUND', 'Parent directory not found');
    }
    $parentReal = normalize_abs($parentReal);
    if (!str_starts_with($parentReal, $root)) {
        fail(403, 'PATH_ESCAPE', 'Parent path escapes root');
    }
    return normalize_abs($target);
}

function resolve_path_for_create(string $rel): string
{
    $root = root_realpath();
    if ($rel === '.' || $rel === '') {
        fail(400, 'INVALID_PATH', 'Cannot create root path');
    }
    $target = $root . DIRECTORY_SEPARATOR . str_replace('/', DIRECTORY_SEPARATOR, $rel);
    $target = normalize_abs($target);
    if (!str_starts_with($target, $root)) {
        fail(403, 'PATH_ESCAPE', 'Target path escapes root');
    }

    $parent = dirname($target);
    $parentReal = realpath($parent);
    if ($parentReal !== false) {
        $parentReal = normalize_abs($parentReal);
        if (!str_starts_with($parentReal, $root)) {
            fail(403, 'PATH_ESCAPE', 'Parent path escapes root');
        }
    }
    return $target;
}

function ensure_parent_dir(string $absPath): void
{
    $parent = dirname($absPath);
    if (is_dir($parent)) {
        return;
    }
    if (!@mkdir($parent, 0775, true) && !is_dir($parent)) {
        fail(500, 'MKDIR_FAILED', 'Unable to create parent directory');
    }
}

function normalize_abs(string $path): string
{
    $path = str_replace(['/', '\\'], DIRECTORY_SEPARATOR, $path);
    if (DIRECTORY_SEPARATOR === '\\') {
        if (preg_match('/^[A-Za-z]:[\\\\\/]?$/', $path) === 1) {
            return strtoupper(substr($path, 0, 1)) . ':\\';
        }
        $trimmed = rtrim($path, "\\/");
        return $trimmed === '' ? '\\' : $trimmed;
    }
    $trimmed = rtrim($path, '/');
    return $trimmed === '' ? '/' : $trimmed;
}

function rel_from_abs(string $absPath): string
{
    $root = root_realpath();
    $abs = normalize_abs($absPath);
    if ($abs === $root) {
        return '.';
    }
    $prefix = $root . DIRECTORY_SEPARATOR;
    if (!str_starts_with($abs, $prefix)) {
        return '.';
    }
    $rel = substr($abs, strlen($prefix));
    return str_replace(DIRECTORY_SEPARATOR, '/', $rel);
}

function remove_tree(string $dir): void
{
    $it = new RecursiveIteratorIterator(
        new RecursiveDirectoryIterator($dir, FilesystemIterator::SKIP_DOTS),
        RecursiveIteratorIterator::CHILD_FIRST
    );
    foreach ($it as $entry) {
        $p = $entry->getPathname();
        if ($entry->isDir()) {
            if (!@rmdir($p)) {
                fail(500, 'RMDIR_FAILED', 'Failed to remove directory in tree');
            }
        } else {
            if (!@unlink($p)) {
                fail(500, 'DELETE_FAILED', 'Failed to remove file in tree');
            }
        }
    }
    if (!@rmdir($dir)) {
        fail(500, 'RMDIR_FAILED', 'Failed to remove root directory');
    }
}

// ---------------------------------------------------------------------
// Replay protection
// ---------------------------------------------------------------------

function enforce_nonce_once(string $nonce, int $ts): void
{
    $base = root_realpath() . DIRECTORY_SEPARATOR . AGENT_REPLAY_DIR;
    if (!is_dir($base) && !@mkdir($base, 0700, true) && !is_dir($base)) {
        fail(500, 'NONCE_STORAGE_FAILED', 'Nonce cache directory creation failed');
    }

    // Prune old nonce files opportunistically to reduce per-request I/O.
    if (mt_rand(1, 100) <= 2) {
        $now = time();
        $dh = @opendir($base);
        if ($dh !== false) {
            while (($name = readdir($dh)) !== false) {
                if ($name === '.' || $name === '..') {
                    continue;
                }
                $p = $base . DIRECTORY_SEPARATOR . $name;
                $mtime = @filemtime($p);
                if (is_int($mtime) && ($now - $mtime) > (AGENT_NONCE_TTL * 2)) {
                    @unlink($p);
                }
            }
            closedir($dh);
        }
    }

    $key = hash('sha256', $nonce . '|' . $ts);
    $file = $base . DIRECTORY_SEPARATOR . $key . '.n';
    if (file_exists($file)) {
        fail(401, 'NONCE_REPLAY', 'Nonce already used');
    }
    $ok = @file_put_contents($file, (string)$ts, LOCK_EX);
    if ($ok === false) {
        fail(500, 'NONCE_WRITE_FAILED', 'Failed to persist nonce');
    }
}

// ---------------------------------------------------------------------
// Capability and INI analysis
// ---------------------------------------------------------------------

function collect_ini_info(): array
{
    return [
        'memory_limit' => ini_get('memory_limit'),
        'post_max_size' => ini_get('post_max_size'),
        'upload_max_filesize' => ini_get('upload_max_filesize'),
        'max_execution_time' => (int)ini_get('max_execution_time'),
        'max_input_time' => (int)ini_get('max_input_time'),
        'output_buffering' => (string)ini_get('output_buffering'),
        'zlib_output_compression' => (string)ini_get('zlib.output_compression'),
        'disable_functions' => (string)ini_get('disable_functions'),
        'open_basedir' => (string)ini_get('open_basedir'),
    ];
}

function collect_capabilities(array $ini): array
{
    $disabled = disabled_functions_set((string)$ini['disable_functions']);
    $hashList = hash_algos();
    $preferredHashes = array_values(array_intersect(
        ['sha256', 'sha512', 'blake2b', 'blake2s', 'sha1', 'md5'],
        $hashList
    ));

    $compression = [];
    if (extension_loaded('zstd')) {
        $compression[] = 'zstd';
    }
    if (extension_loaded('brotli')) {
        $compression[] = 'brotli';
    }
    if (extension_loaded('zlib')) {
        $compression[] = 'gzip';
    }

    $ops = [
        'LIST', 'STAT', 'GET', 'PUT', 'FINALIZE', 'DELETE', 'MKDIR', 'RMDIR', 'RENAME', 'HASH'
    ];
    if (pick_shell_method($disabled) !== '') {
        $ops[] = 'SHELL_EXEC';
    }
    $ops[] = 'TAR_STREAM';

    return [
        'recommended_chunk_size' => recommended_chunk_size(),
        'extensions' => [
            'openssl' => extension_loaded('openssl'),
            'zlib' => extension_loaded('zlib'),
            'zstd' => extension_loaded('zstd'),
            'brotli' => extension_loaded('brotli'),
        ],
        'compression' => $compression,
        'hash_algorithms' => $preferredHashes,
        'disabled_functions' => array_keys($disabled),
        'shell_method' => pick_shell_method($disabled),
        'auth' => [
            'probe_public' => true,
            'psk_configured' => is_legacy_psk_configured(),
            'psk_source' => resolve_agent_psk_source(),
            'legacy_header_auth' => true,
            'hmac_auth' => resolve_agent_psk_for_hmac() !== '',
        ],
        'operations' => $ops,
    ];
}

function recommended_chunk_size(): int
{
    static $cached = null;
    if (is_int($cached)) {
        return $cached;
    }

    $postMax = ini_size_to_bytes((string)ini_get('post_max_size'));
    $uploadMax = ini_size_to_bytes((string)ini_get('upload_max_filesize'));
    $memory = ini_size_to_bytes((string)ini_get('memory_limit'));

    $limits = [];
    if ($postMax > 0) {
        $limits[] = $postMax;
    }
    if ($uploadMax > 0) {
        $limits[] = $uploadMax;
    }
    if ($memory > 0) {
        // Keep chunk low relative to memory to avoid pressure.
        $limits[] = (int)floor($memory / 8);
    }

    $limit = $limits ? min($limits) : 0;
    if ($limit <= 0) {
        $cached = AGENT_DEFAULT_CHUNK;
        return $cached;
    }

    $candidate = (int)max(65536, min(1048576, floor($limit / 2)));
    $cached = $candidate;
    return $cached;
}

function ini_size_to_bytes(string $value): int
{
    $v = trim($value);
    if ($v === '' || $v === '-1') {
        return -1;
    }
    if (!preg_match('/^(\d+)([KMGTP]?)/i', $v, $m)) {
        return 0;
    }
    $num = (int)$m[1];
    $unit = strtoupper($m[2] ?? '');
    switch ($unit) {
        case 'P': return $num * 1024 * 1024 * 1024 * 1024 * 1024;
        case 'T': return $num * 1024 * 1024 * 1024 * 1024;
        case 'G': return $num * 1024 * 1024 * 1024;
        case 'M': return $num * 1024 * 1024;
        case 'K': return $num * 1024;
        default:  return $num;
    }
}

function disabled_functions_set(string $raw): array
{
    $set = [];
    foreach (explode(',', $raw) as $fn) {
        $name = strtolower(trim($fn));
        if ($name !== '') {
            $set[$name] = true;
        }
    }
    return $set;
}

function pick_shell_method(array $disabled): string
{
    // Prefer methods that reliably provide exit code across shared hostings.
    $candidates = ['exec', 'proc_open', 'shell_exec', 'system', 'passthru', 'popen'];
    foreach ($candidates as $fn) {
        if (!isset($disabled[$fn]) && function_exists($fn)) {
            return $fn;
        }
    }
    return '';
}

function execute_shell_command(string $cmd, string $method): array
{
    if ($method === 'proc_open') {
        $spec = [
            0 => ['pipe', 'r'],
            1 => ['pipe', 'w'],
            2 => ['pipe', 'w'],
        ];
        $pipes = [];
        $proc = @proc_open($cmd, $spec, $pipes);
        if (!is_resource($proc)) {
            fail(500, 'SHELL_FAILED', 'proc_open failed');
        }
        if (isset($pipes[0]) && is_resource($pipes[0])) {
            fclose($pipes[0]);
        }
        $stdout = isset($pipes[1]) && is_resource($pipes[1]) ? (string)stream_get_contents($pipes[1]) : '';
        $stderr = isset($pipes[2]) && is_resource($pipes[2]) ? (string)stream_get_contents($pipes[2]) : '';
        if (isset($pipes[1]) && is_resource($pipes[1])) {
            fclose($pipes[1]);
        }
        if (isset($pipes[2]) && is_resource($pipes[2])) {
            fclose($pipes[2]);
        }
        $status = @proc_get_status($proc);
        $exit = proc_close($proc);
        if ((!is_int($exit) || $exit < 0) && is_array($status) && isset($status['exitcode']) && is_int($status['exitcode']) && $status['exitcode'] >= 0) {
            $exit = (int)$status['exitcode'];
        }
        return ['stdout' => $stdout, 'stderr' => $stderr, 'exit_code' => is_int($exit) ? $exit : -1];
    }

    if ($method === 'shell_exec') {
        $out = @shell_exec($cmd . ' 2>&1');
        return ['stdout' => (string)($out ?? ''), 'stderr' => '', 'exit_code' => 0];
    }

    if ($method === 'exec') {
        $lines = [];
        $exit = 0;
        @exec($cmd . ' 2>&1', $lines, $exit);
        return ['stdout' => implode("\n", $lines), 'stderr' => '', 'exit_code' => (int)$exit];
    }

    if ($method === 'system') {
        ob_start();
        $exit = 0;
        @system($cmd . ' 2>&1', $exit);
        $stdout = (string)ob_get_clean();
        return ['stdout' => $stdout, 'stderr' => '', 'exit_code' => (int)$exit];
    }

    if ($method === 'passthru') {
        ob_start();
        $exit = 0;
        @passthru($cmd . ' 2>&1', $exit);
        $stdout = (string)ob_get_clean();
        return ['stdout' => $stdout, 'stderr' => '', 'exit_code' => (int)$exit];
    }

    if ($method === 'popen') {
        $h = @popen($cmd . ' 2>&1', 'r');
        if (!is_resource($h)) {
            fail(500, 'SHELL_FAILED', 'popen failed');
        }
        $stdout = (string)stream_get_contents($h);
        $rc = pclose($h);
        return ['stdout' => $stdout, 'stderr' => '', 'exit_code' => is_int($rc) ? $rc : -1];
    }

    fail(500, 'SHELL_FAILED', 'No supported shell method selected');
}
