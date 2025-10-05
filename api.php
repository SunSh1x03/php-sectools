<?php
/**
 * php-sectools - api.php
 * Lightweight PHP backend for attack-map ingestion & visualization.
 *
 * Requirements: PHP 7.4+
 *
 * Save this file in your webroot. Create a writable "storage/" directory.
 *
 * .env (optional) entries:
 *   VT_API_KEY=...
 *   ALLOWED_ORIGIN=https://sunsh1x03.github.io
 *   API_TOKEN=your_token_here
 */

declare(strict_types=1);

// -------------------- bootstrap / config --------------------
error_reporting(E_ALL);
ini_set('display_errors', '0'); // set to 1 for local debug

$BASE_DIR = __DIR__;
$STORAGE_DIR = $BASE_DIR . '/storage';
@mkdir($STORAGE_DIR, 0755, true);
@mkdir($STORAGE_DIR . '/cache', 0755, true);

$DB_FILE = $STORAGE_DIR . '/sectools.sqlite';
$CACHE_DIR = $STORAGE_DIR . '/cache';

// optional .env loader (simple)
$envFile = $BASE_DIR . '/.env';
if (file_exists($envFile)) {
    $lines = file($envFile, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
    foreach ($lines as $line) {
        $line = trim($line);
        if ($line === '' || $line[0] === '#') continue;
        if (!strpos($line, '=')) continue;
        [$k, $v] = array_map('trim', explode('=', $line, 2));
        if ($k !== '') putenv("$k=$v");
    }
}

// envs
$ALLOWED_ORIGIN = getenv('ALLOWED_ORIGIN') ?: '*';
$VT_API_KEY = getenv('VT_API_KEY') ?: null;
$API_TOKEN = getenv('API_TOKEN') ?: null;

// -------------------- helpers --------------------
function jsonResponse($data, int $code = 200): void {
    header('Content-Type: application/json; charset=utf-8');
    http_response_code($code);
    echo json_encode($data, JSON_UNESCAPED_SLASHES | JSON_PRETTY_PRINT);
    exit;
}

function errorJson(string $msg, int $code = 400): void {
    jsonResponse(['error' => $msg], $code);
}

// CORS
header('Access-Control-Allow-Origin: ' . $ALLOWED_ORIGIN);
header('Access-Control-Allow-Methods: GET, POST, OPTIONS');
header('Access-Control-Allow-Headers: Content-Type, Authorization');
if ($_SERVER['REQUEST_METHOD'] === 'OPTIONS') {
    http_response_code(204);
    exit;
}

// basic rate limit per IP (file-backed)
function rateLimit(string $keySuffix, int $limit = 60, int $windowSeconds = 60): bool {
    $ip = $_SERVER['REMOTE_ADDR'] ?? 'unknown';
    $fn = sys_get_temp_dir() . '/php_sectools_rl_' . md5($ip . '|' . $keySuffix) . '.json';
    $data = ['count' => 0, 'ts' => time()];
    if (file_exists($fn)) {
        $raw = @file_get_contents($fn);
        $d = @json_decode($raw, true);
        if (is_array($d) && isset($d['count'], $d['ts'])) $data = $d;
    }
    if (time() - $data['ts'] > $windowSeconds) {
        $data['count'] = 0;
        $data['ts'] = time();
    }
    $data['count']++;
    @file_put_contents($fn, json_encode($data));
    return ($data['count'] <= $limit);
}

// simple cache
function cacheGet(string $key, int $ttl = 300) {
    global $CACHE_DIR;
    $fn = $CACHE_DIR . '/' . md5($key) . '.json';
    if (!file_exists($fn)) return null;
    if (filemtime($fn) + $ttl < time()) { @unlink($fn); return null; }
    $raw = file_get_contents($fn);
    return json_decode($raw, true);
}
function cacheSet(string $key, $value): void {
    global $CACHE_DIR;
    $fn = $CACHE_DIR . '/' . md5($key) . '.json';
    @file_put_contents($fn, json_encode($value));
}

// minimal auth (Bearer)
function requireAuth(): void {
    global $API_TOKEN;
    if (!$API_TOKEN) return; // disabled
    $hdr = $_SERVER['HTTP_AUTHORIZATION'] ?? '';
    if (stripos($hdr, 'Bearer ') !== 0) errorJson('Missing bearer token', 401);
    $token = trim(substr($hdr, 7));
    if (!hash_equals($API_TOKEN, $token)) errorJson('Invalid token', 401);
}

// safe input read
function getJsonBody(): array {
    $body = file_get_contents('php://input');
    if (!$body) return [];
    $data = json_decode($body, true);
    return is_array($data) ? $data : [];
}

/**
 * Validate outbound URL targets to mitigate SSRF.
 */
function validateOutboundUrl(?string $url): string {
    if (!$url) {
        errorJson('Invalid URL', 400);
    }

    $filtered = filter_var($url, FILTER_VALIDATE_URL);
    if (!$filtered) {
        errorJson('Invalid URL', 400);
    }

    $parts = parse_url($filtered);
    $scheme = strtolower($parts['scheme'] ?? '');
    if (!in_array($scheme, ['http', 'https'], true)) {
        errorJson('URL scheme not allowed', 400);
    }

    $host = $parts['host'] ?? '';
    if ($host === '' || strcasecmp($host, 'localhost') === 0) {
        errorJson('URL host not allowed', 400);
    }

    $ips = [];
    if (filter_var($host, FILTER_VALIDATE_IP)) {
        $ips[] = $host;
    } else {
        $records = @dns_get_record($host, DNS_A | DNS_AAAA);
        if (is_array($records)) {
            foreach ($records as $record) {
                if (!empty($record['ip'])) {
                    $ips[] = $record['ip'];
                }
                if (!empty($record['ipv6'])) {
                    $ips[] = $record['ipv6'];
                }
            }
        }
        if (!$ips) {
            $fallback = @gethostbynamel($host);
            if (is_array($fallback)) {
                $ips = array_merge($ips, $fallback);
            }
        }
    }

    if (!$ips) {
        errorJson('Unable to resolve URL host', 400);
    }

    foreach ($ips as $ip) {
        if (!isPublicIp($ip)) {
            errorJson('URL resolves to a private address', 400);
        }
    }

    return $filtered;
}

function isPublicIp(string $ip): bool {
    if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) {
        return filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4 | FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE) !== false;
    }
    if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6)) {
        if (in_array($ip, ['::1'], true)) {
            return false;
        }
        if (stripos($ip, 'fe80:') === 0) { // link-local
            return false;
        }
        return filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6 | FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE) !== false;
    }
    return false;
}

function applySafeCurlDefaults($ch): void {
    if (defined('CURLPROTO_HTTP') && defined('CURLPROTO_HTTPS')) {
        curl_setopt($ch, CURLOPT_PROTOCOLS, CURLPROTO_HTTP | CURLPROTO_HTTPS);
        curl_setopt($ch, CURLOPT_REDIR_PROTOCOLS, CURLPROTO_HTTP | CURLPROTO_HTTPS);
    }
    curl_setopt($ch, CURLOPT_MAXREDIRS, 5);
}

// -------------------- DB init --------------------
function getDb(string $path): PDO {
    if (!file_exists($path)) {
        $pdo = new PDO('sqlite:' . $path);
        $pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
        $schema = "
            CREATE TABLE graphs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT,
                created_at INTEGER
            );
            CREATE TABLE hosts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                graph_id INTEGER,
                ip TEXT,
                hostname TEXT
            );
            CREATE TABLE services (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                host_id INTEGER,
                port INTEGER,
                proto TEXT,
                name TEXT
            );
            CREATE TABLE vulns (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                service_id INTEGER,
                cve TEXT,
                title TEXT,
                severity TEXT,
                description TEXT
            );
            CREATE TABLE edges (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                graph_id INTEGER,
                source TEXT,
                target TEXT,
                relation TEXT
            );
            CREATE INDEX idx_graphs ON graphs(id);
        ";
        $pdo->exec($schema);
        return $pdo;
    } else {
        $pdo = new PDO('sqlite:' . $path);
        $pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
        return $pdo;
    }
}

try {
    $db = getDb($DB_FILE);
} catch (Exception $e) {
    errorJson('DB init error: ' . $e->getMessage(), 500);
}

// -------------------- routing --------------------
$reqPath = parse_url($_SERVER['REQUEST_URI'], PHP_URL_PATH);
$base = rtrim(dirname($_SERVER['SCRIPT_NAME']), '/\\');
$endpoint = '/' . trim(substr($reqPath, strlen($base)), '/');

switch ($endpoint) {

    // ---------- upload scan ----------
    case 'api/upload-scan':
        if ($_SERVER['REQUEST_METHOD'] !== 'POST') errorJson('Method not allowed', 405);
        requireAuth();
        if (!rateLimit('upload_scan', 10, 60)) errorJson('Rate limit exceeded', 429);

        $json = getJsonBody();
        if (empty($json)) errorJson('Empty or invalid JSON', 400);

        $graphName = trim($json['meta']['name'] ?? ('graph_' . time()));
        if (strlen($graphName) > 200) $graphName = substr($graphName, 0, 200);

        $stmt = $db->prepare('INSERT INTO graphs (name, created_at) VALUES (:name, :ts)');
        $stmt->execute([':name' => $graphName, ':ts' => time()]);
        $graphId = (int)$db->lastInsertId();

        $hosts = $json['hosts'] ?? [];
        if (!is_array($hosts)) $hosts = [];

        foreach ($hosts as $h) {
            $ipRaw = $h['ip'] ?? '';
            $ip = filter_var($ipRaw, FILTER_VALIDATE_IP) ?: null;
            if (!$ip) continue;
            $hostname = substr($h['hostname'] ?? '', 0, 200);

            $stmt = $db->prepare('INSERT INTO hosts (graph_id, ip, hostname) VALUES (:g, :ip, :hn)');
            $stmt->execute([':g' => $graphId, ':ip' => $ip, ':hn' => $hostname]);
            $hostId = (int)$db->lastInsertId();

            $services = $h['services'] ?? [];
            if (!is_array($services)) $services = [];
            foreach ($services as $s) {
                $port = intval($s['port'] ?? 0);
                $proto = substr(strtolower($s['proto'] ?? 'tcp'), 0, 10);
                $svcname = substr($s['name'] ?? '', 0, 100);
                $stmt = $db->prepare('INSERT INTO services (host_id, port, proto, name) VALUES (:h, :port, :proto, :name)');
                $stmt->execute([':h' => $hostId, ':port' => $port, ':proto' => $proto, ':name' => $svcname]);
                $svcId = (int)$db->lastInsertId();

                // host -> service edge
                $db->prepare('INSERT INTO edges (graph_id, source, target, relation) VALUES (:g, :s, :t, :r)')
                    ->execute([':g' => $graphId, ':s' => "host:$hostId", ':t' => "service:$svcId", ':r' => 'runs']);

                $vulns = $s['vulns'] ?? [];
                if (!is_array($vulns)) $vulns = [];
                foreach ($vulns as $v) {
                    $cve = substr($v['cve'] ?? '', 0, 64);
                    $title = substr($v['title'] ?? 'vuln', 0, 255);
                    $severity = substr($v['severity'] ?? 'unknown', 0, 20);
                    $desc = substr($v['description'] ?? '', 0, 2000);
                    $stmt = $db->prepare('INSERT INTO vulns (service_id, cve, title, severity, description) VALUES (:s, :cve, :title, :sev, :desc)');
                    $stmt->execute([':s' => $svcId, ':cve' => $cve, ':title' => $title, ':sev' => $severity, ':desc' => $desc]);
                    $vulnId = (int)$db->lastInsertId();

                    $db->prepare('INSERT INTO edges (graph_id, source, target, relation) VALUES (:g, :s, :t, :r)')
                        ->execute([':g' => $graphId, ':s' => "service:$svcId", ':t' => "vuln:$vulnId", ':r' => 'vuln_on']);
                }
            }
        }

        jsonResponse(['ok' => true, 'graph_id' => $graphId], 201);
        break;


    // ---------- list graphs ----------
    case 'api/graphs':
        if ($_SERVER['REQUEST_METHOD'] !== 'GET') errorJson('Method not allowed', 405);
        $rows = $db->query('SELECT id, name, created_at FROM graphs ORDER BY created_at DESC')->fetchAll(PDO::FETCH_ASSOC);
        jsonResponse(['graphs' => $rows]);
        break;


    // ---------- get graph (nodes + edges) ----------
    case 'api/graph':
        if ($_SERVER['REQUEST_METHOD'] !== 'GET') errorJson('Method not allowed', 405);
        $id = intval($_GET['id'] ?? 0);
        if ($id <= 0) errorJson('Missing or invalid id', 400);

        $nodes = [];
        $edges = [];

        // hosts
        $sth = $db->prepare('SELECT id, ip, hostname FROM hosts WHERE graph_id = :g');
        $sth->execute([':g' => $id]);
        $hosts = $sth->fetchAll(PDO::FETCH_ASSOC);
        foreach ($hosts as $h) {
            $nodes[] = [
                'id' => "host:{$h['id']}",
                'label' => $h['hostname'] ? "{$h['hostname']} ({$h['ip']})" : $h['ip'],
                'group' => 'host',
                'meta' => ['ip' => $h['ip'], 'hostname' => $h['hostname']]
            ];
        }

        // services
        $sth = $db->prepare('SELECT s.id, s.host_id, s.port, s.proto, s.name, h.ip FROM services s JOIN hosts h ON h.id = s.host_id WHERE h.graph_id = :g');
        $sth->execute([':g' => $id]);
        $svcs = $sth->fetchAll(PDO::FETCH_ASSOC);
        foreach ($svcs as $s) {
            $nodes[] = [
                'id' => "service:{$s['id']}",
                'label' => "{$s['name']} ({$s['proto']}/{$s['port']})",
                'group' => 'service',
                'meta' => ['port' => $s['port'], 'proto' => $s['proto'], 'host_ip' => $s['ip']]
            ];
            $edges[] = ['from' => "host:{$s['host_id']}", 'to' => "service:{$s['id']}", 'relation' => 'runs'];
        }

        // vulns
        $sth = $db->prepare('SELECT v.id, v.service_id, v.cve, v.title, v.severity FROM vulns v JOIN services s ON s.id = v.service_id JOIN hosts h ON h.id = s.host_id WHERE h.graph_id = :g');
        $sth->execute([':g' => $id]);
        $vulns = $sth->fetchAll(PDO::FETCH_ASSOC);
        foreach ($vulns as $v) {
            $nodes[] = [
                'id' => "vuln:{$v['id']}",
                'label' => ($v['cve'] ? $v['cve'] . ' - ' : '') . $v['title'],
                'group' => 'vuln',
                'meta' => ['severity' => $v['severity']]
            ];
            $edges[] = ['from' => "service:{$v['service_id']}", 'to' => "vuln:{$v['id']}", 'relation' => 'vuln_on'];
        }

        // stored edges
        $sth = $db->prepare('SELECT source, target, relation FROM edges WHERE graph_id = :g');
        $sth->execute([':g' => $id]);
        $savedEdges = $sth->fetchAll(PDO::FETCH_ASSOC);
        foreach ($savedEdges as $e) {
            $edges[] = ['from' => $e['source'], 'to' => $e['target'], 'relation' => $e['relation']];
        }

        jsonResponse(['nodes' => $nodes, 'edges' => $edges]);
        break;


    // ---------- hosts list ----------
    case 'api/hosts':
        if ($_SERVER['REQUEST_METHOD'] !== 'GET') errorJson('Method not allowed', 405);
        $rows = $db->query('SELECT id, ip, hostname, graph_id FROM hosts ORDER BY id DESC')->fetchAll(PDO::FETCH_ASSOC);
        jsonResponse(['hosts' => $rows]);
        break;


    // ---------- vulns list ----------
    case 'api/vulns':
        if ($_SERVER['REQUEST_METHOD'] !== 'GET') errorJson('Method not allowed', 405);
        $rows = $db->query('SELECT v.id, v.cve, v.title, v.severity, s.port, h.ip FROM vulns v JOIN services s ON s.id = v.service_id JOIN hosts h ON h.id = s.host_id ORDER BY v.id DESC')->fetchAll(PDO::FETCH_ASSOC);
        jsonResponse(['vulns' => $rows]);
        break;


    // ---------- headers check ----------
    case 'api/headers/check':
        if ($_SERVER['REQUEST_METHOD'] !== 'POST') errorJson('Method not allowed', 405);
        if (!rateLimit('hdr_check', 40, 60)) errorJson('Rate limit exceeded', 429);

        $body = getJsonBody();
        $url = validateOutboundUrl($body['url'] ?? null);

        // fetch headers (HEAD with fallback to GET)
        $ch = curl_init($url);
        curl_setopt($ch, CURLOPT_NOBODY, true);
        curl_setopt($ch, CURLOPT_FOLLOWLOCATION, true);
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($ch, CURLOPT_TIMEOUT, 10);
        applySafeCurlDefaults($ch);
        $resp = curl_exec($ch);
        $err = curl_error($ch);
        curl_close($ch);
        if ($err) errorJson('Curl error: ' . $err, 502);

        // re-fetch headers explicitly to get header block
        $ch = curl_init();
        curl_setopt($ch, CURLOPT_URL, $url);
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($ch, CURLOPT_HEADER, true);
        curl_setopt($ch, CURLOPT_NOBODY, true);
        curl_setopt($ch, CURLOPT_FOLLOWLOCATION, true);
        curl_setopt($ch, CURLOPT_TIMEOUT, 10);
        applySafeCurlDefaults($ch);
        $resp = curl_exec($ch);
        $err = curl_error($ch);
        curl_close($ch);
        if ($err) errorJson('Curl error: ' . $err, 502);

        $parts = preg_split("/\r\n\r\n/", $resp);
        $lastHeaders = end($parts);
        $lines = preg_split("/\r\n/", $lastHeaders);
        $head = [];
        foreach ($lines as $ln) {
            if (strpos($ln, ':') !== false) {
                [$k, $v] = explode(':', $ln, 2);
                $head[trim($k)] = trim($v);
            }
        }
        $securityHeaders = [
            'Content-Security-Policy',
            'X-Frame-Options',
            'X-Content-Type-Options',
            'Referrer-Policy',
            'Strict-Transport-Security',
            'Permissions-Policy'
        ];
        $report = [];
        foreach ($securityHeaders as $h) {
            $report[$h] = $head[$h] ?? null;
        }
        jsonResponse(['status' => 200, 'headers' => $report]);
        break;


    // ---------- VirusTotal proxy: POST scan URL ----------
    case 'api/vt/scan-url':
        if ($_SERVER['REQUEST_METHOD'] !== 'POST') errorJson('Method not allowed', 405);
        if (!rateLimit('vt_scan', 6, 60)) errorJson('Rate limit exceeded', 429);
        if (!$VT_API_KEY) errorJson('VT_API_KEY not configured', 500);

        $body = getJsonBody();
        $url = validateOutboundUrl($body['url'] ?? null);

        // cache
        $cacheKey = 'vt_scan_' . $url;
        $cached = cacheGet($cacheKey, 30);
        if ($cached) {
            jsonResponse(['cached' => true, 'data' => $cached]);
        }

        $ch = curl_init('https://www.virustotal.com/api/v3/urls');
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($ch, CURLOPT_POST, true);
        curl_setopt($ch, CURLOPT_POSTFIELDS, http_build_query(['url' => $url]));
        curl_setopt($ch, CURLOPT_HTTPHEADER, [
            "x-apikey: {$VT_API_KEY}",
            "Content-Type: application/x-www-form-urlencoded"
        ]);
        curl_setopt($ch, CURLOPT_TIMEOUT, 15);
        applySafeCurlDefaults($ch);
        $resp = curl_exec($ch);
        $err = curl_error($ch);
        $http = curl_getinfo($ch, CURLINFO_HTTP_CODE);
        curl_close($ch);
        if ($err) errorJson('Curl error: ' . $err, 502);

        $data = json_decode($resp, true);
        if ($http >= 400) errorJson('VirusTotal error: ' . ($data['error']['message'] ?? 'unknown'), 502);
        cacheSet($cacheKey, $data);
        jsonResponse(['cached' => false, 'data' => $data]);
        break;


    // ---------- VirusTotal analysis GET ----------
    case 'api/vt/analysis':
        if ($_SERVER['REQUEST_METHOD'] !== 'GET') errorJson('Method not allowed', 405);
        if (!rateLimit('vt_get', 30, 60)) errorJson('Rate limit exceeded', 429);
        if (!$VT_API_KEY) errorJson('VT_API_KEY not configured', 500);

        $id = $_GET['id'] ?? null;
        if (!$id) errorJson('Missing id', 400);
        $cacheKey = 'vt_analysis_' . $id;
        $cached = cacheGet($cacheKey, 30);
        if ($cached) jsonResponse(['cached' => true, 'data' => $cached]);

        $ch = curl_init('https://www.virustotal.com/api/v3/analyses/' . urlencode($id));
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($ch, CURLOPT_HTTPHEADER, ["x-apikey: {$VT_API_KEY}"]);
        curl_setopt($ch, CURLOPT_TIMEOUT, 10);
        applySafeCurlDefaults($ch);
        $resp = curl_exec($ch);
        $err = curl_error($ch);
        $http = curl_getinfo($ch, CURLINFO_HTTP_CODE);
        curl_close($ch);
        if ($err) errorJson('Curl error: ' . $err, 502);

        $data = json_decode($resp, true);
        if ($http >= 400) errorJson('VirusTotal error', 502);
        cacheSet($cacheKey, $data);
        jsonResponse(['cached' => false, 'data' => $data]);
        break;


    // ---------- default/help ----------
    default:
        jsonResponse([
            'msg' => 'php-sectools API',
            'endpoints' => [
                'POST /api/upload-scan' => 'upload structured JSON {hosts:[{ip,hostname,services:[{port,proto,name,vulns:[{cve,title,severity,description}]}]}]}',
                'GET  /api/graphs' => 'list graphs',
                'GET  /api/graph?id=ID' => 'get graph nodes+edges',
                'GET  /api/hosts' => 'list hosts',
                'GET  /api/vulns' => 'list vulns',
                'POST /api/headers/check' => 'check security headers for a URL',
                'POST /api/vt/scan-url' => 'VirusTotal proxy (requires VT_API_KEY)',
                'GET  /api/vt/analysis?id=ID' => 'VirusTotal analysis'
            ]
        ]);
        break;
}

