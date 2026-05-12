<?php
/**
 * خدمة الاستعلام العام عن الإجازات المرضية.
 *
 * الهدف من هذا الملف أن يرجع JSON دائماً إلى index.html حتى لا تظهر رسالة
 * "خطأ الاتصال بالخادم" بسبب تحذير/خطأ PHP أو اختلاف بسيط في مخطط قاعدة البيانات.
 */

ini_set('display_errors', '0');
ini_set('display_startup_errors', '0');
error_reporting(E_ALL);
date_default_timezone_set('Asia/Riyadh');

header('Content-Type: application/json; charset=utf-8');
header('X-Content-Type-Options: nosniff');
header('X-Frame-Options: DENY');
header('Access-Control-Allow-Origin: *');
header('Access-Control-Allow-Methods: POST, GET, OPTIONS');
header('Access-Control-Allow-Headers: Content-Type, X-Requested-With');
header_remove('X-Powered-By');
header_remove('Server');

if (($_SERVER['REQUEST_METHOD'] ?? 'GET') === 'OPTIONS') {
    http_response_code(204);
    exit;
}

define('ERROR_LOG_FILE', __DIR__ . '/error_log.txt');

function write_service_log(string $msg): void {
    $line = date('[Y-m-d H:i:s] ') . $msg . PHP_EOL;
    @file_put_contents(ERROR_LOG_FILE, $line, FILE_APPEND | LOCK_EX);
}

function json_response(array $payload, int $httpCode = 200): void {
    if (!headers_sent()) {
        http_response_code($httpCode);
        header('Content-Type: application/json; charset=utf-8');
    }
    echo json_encode($payload, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);
    exit;
}

set_exception_handler(function (Throwable $e): void {
    write_service_log('Unhandled exception: ' . $e->getMessage() . ' in ' . $e->getFile() . ':' . $e->getLine());
    json_response(['status' => 'error', 'msg' => 'تعذّر إتمام الاستعلام حالياً. حاول مرة أخرى بعد قليل.'], 200);
});

register_shutdown_function(function (): void {
    $error = error_get_last();
    if (!$error || !in_array($error['type'], [E_ERROR, E_PARSE, E_CORE_ERROR, E_COMPILE_ERROR], true)) {
        return;
    }
    write_service_log('Fatal error: ' . $error['message'] . ' in ' . $error['file'] . ':' . $error['line']);
    if (!headers_sent()) {
        http_response_code(200);
        header('Content-Type: application/json; charset=utf-8');
    }
    echo json_encode(['status' => 'error', 'msg' => 'تعذّر الاتصال بالخادم حالياً. حاول مرة أخرى.'], JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);
});

function request_value(array $names): string {
    static $jsonBody = null;
    if ($jsonBody === null) {
        $jsonBody = [];
        $contentType = $_SERVER['CONTENT_TYPE'] ?? $_SERVER['HTTP_CONTENT_TYPE'] ?? '';
        if (stripos($contentType, 'application/json') !== false) {
            $raw = file_get_contents('php://input');
            $decoded = json_decode($raw ?: '', true);
            if (is_array($decoded)) {
                $jsonBody = $decoded;
            }
        }
    }

    foreach ($names as $name) {
        if (isset($_POST[$name])) return trim((string) $_POST[$name]);
        if (isset($_GET[$name])) return trim((string) $_GET[$name]);
        if (isset($jsonBody[$name])) return trim((string) $jsonBody[$name]);
    }
    return '';
}

function env_or_default(string $name, string $default): string {
    $value = getenv($name);
    return ($value === false || $value === '') ? $default : $value;
}

function db_configs(): array {
    return [
        [
            'label' => 'primary',
            'host' => env_or_default('DB_HOST', 'mysql.railway.internal'),
            'port' => (int) env_or_default('DB_PORT', '3306'),
            'dbname' => env_or_default('DB_DATABASE', env_or_default('DB_NAME', 'railway')),
            'user' => env_or_default('DB_USERNAME', env_or_default('DB_USER', 'root')),
            // نفس كلمة مرور لوحة التحكم الحالية حتى لا يفشل الاستعلام من index.html.
            'pass' => env_or_default('DB_PASSWORD', env_or_default('DB_PASS', 'ExvKbuJnGIvDATyXWCHtpjOFluFAgeqQ')),
        ],
        [
            'label' => 'secondary',
            'host' => env_or_default('DB2_HOST', 'c9cujduvu830eexs.cbetxkdyhwsb.us-east-1.rds.amazonaws.com'),
            'port' => (int) env_or_default('DB2_PORT', '3306'),
            'dbname' => env_or_default('DB2_DATABASE', env_or_default('DB2_NAME', 'cdidptf4q81rafg8')),
            'user' => env_or_default('DB2_USERNAME', env_or_default('DB2_USER', 'q2xjpqcepsmd4v12')),
            'pass' => env_or_default('DB2_PASSWORD', env_or_default('DB2_PASS', 'v8lcs6awp4vj9u28')),
        ],
    ];
}

function connect_database(array $config): ?PDO {
    try {
        $dsn = sprintf('mysql:host=%s;port=%d;dbname=%s;charset=utf8mb4', $config['host'], $config['port'], $config['dbname']);
        $pdo = new PDO($dsn, $config['user'], $config['pass'], [
            PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
            PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
            PDO::ATTR_EMULATE_PREPARES => false,
            PDO::ATTR_TIMEOUT => 5,
        ]);
        $pdo->exec("SET time_zone = '+03:00'");
        ensure_leave_queries_table($pdo, $config['label']);
        return $pdo;
    } catch (Throwable $e) {
        write_service_log('DB connection failed [' . $config['label'] . ']: ' . $e->getMessage());
        return null;
    }
}

function table_exists(PDO $pdo, string $table): bool {
    try {
        $stmt = $pdo->prepare('SELECT COUNT(*) FROM information_schema.tables WHERE table_schema = DATABASE() AND table_name = ?');
        $stmt->execute([$table]);
        return (int) $stmt->fetchColumn() > 0;
    } catch (Throwable $e) {
        write_service_log('table_exists failed: ' . $e->getMessage());
        return false;
    }
}

function column_exists(PDO $pdo, string $table, string $column): bool {
    try {
        $stmt = $pdo->prepare('SELECT COUNT(*) FROM information_schema.columns WHERE table_schema = DATABASE() AND table_name = ? AND column_name = ?');
        $stmt->execute([$table, $column]);
        return (int) $stmt->fetchColumn() > 0;
    } catch (Throwable $e) {
        write_service_log('column_exists failed: ' . $e->getMessage());
        return false;
    }
}

function first_existing_column(PDO $pdo, string $table, array $columns, string $fallbackLiteral = "''", string $alias = ''): string {
    foreach ($columns as $column) {
        if (column_exists($pdo, $table, $column)) {
            return ($alias !== '' ? $alias . '.' : '') . $column;
        }
    }
    return $fallbackLiteral;
}

function ensure_leave_queries_table(PDO $pdo, string $label): void {
    try {
        $pdo->exec("CREATE TABLE IF NOT EXISTS leave_queries (
            id INT AUTO_INCREMENT PRIMARY KEY,
            leave_id INT NOT NULL,
            queried_at DATETIME NOT NULL,
            source VARCHAR(20) NOT NULL DEFAULT 'external',
            INDEX idx_leave_queries_leave_id (leave_id)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci");
    } catch (Throwable $e) {
        // تسجيل الاستعلامات ميزة مساندة فقط، ولا يجب أن تكسر البحث العام.
        write_service_log('ensure leave_queries failed [' . $label . ']: ' . $e->getMessage());
    }
}

function search_leave(PDO $pdo, string $code, string $identity, bool $archived): ?array {
    if (!table_exists($pdo, 'sick_leaves') || !table_exists($pdo, 'patients')) {
        write_service_log('Required tables are missing.');
        return null;
    }

    $patientNameExpr = first_existing_column($pdo, 'patients', ['name_ar', 'name'], "''", 'p');
    $patientNameEnExpr = first_existing_column($pdo, 'patients', ['name_en', 'name'], "''", 'p');
    $doctorNameExpr = "''";
    $doctorTitleExpr = "''";
    $doctorJoin = '';
    if (table_exists($pdo, 'doctors')) {
        $doctorNameExpr = first_existing_column($pdo, 'doctors', ['name_ar', 'name'], "''", 'd');
        $doctorTitleExpr = first_existing_column($pdo, 'doctors', ['title_ar', 'title'], "''", 'd');
        $doctorJoin = ' LEFT JOIN doctors AS d ON sl.doctor_id = d.id ';
    }

    $deletedCondition = column_exists($pdo, 'sick_leaves', 'deleted_at')
        ? ($archived ? 'sl.deleted_at IS NOT NULL' : 'sl.deleted_at IS NULL')
        : ($archived ? '1 = 0' : '1 = 1');

    $columns = [
        'sl.id AS leave_id',
        'sl.service_code AS service_code',
        'p.identity_number AS identity_number',
        "COALESCE($patientNameExpr, $patientNameEnExpr, '') AS patient_name",
        column_exists($pdo, 'sick_leaves', 'issue_date') ? 'sl.issue_date AS issue_date' : "'' AS issue_date",
        column_exists($pdo, 'sick_leaves', 'start_date') ? 'sl.start_date AS start_date' : "'' AS start_date",
        column_exists($pdo, 'sick_leaves', 'end_date') ? 'sl.end_date AS end_date' : "'' AS end_date",
        column_exists($pdo, 'sick_leaves', 'days_count') ? 'sl.days_count AS days_count' : "'' AS days_count",
        "COALESCE($doctorNameExpr, '') AS doctor_name",
        "COALESCE($doctorTitleExpr, '') AS doctor_title",
        column_exists($pdo, 'sick_leaves', 'is_companion') ? 'sl.is_companion AS is_companion' : '0 AS is_companion',
        column_exists($pdo, 'sick_leaves', 'companion_name') ? 'sl.companion_name AS companion_name' : "'' AS companion_name",
        column_exists($pdo, 'sick_leaves', 'companion_relation') ? 'sl.companion_relation AS companion_relation' : "'' AS companion_relation",
    ];

    $sql = 'SELECT ' . implode(', ', $columns) . '
            FROM sick_leaves AS sl
            INNER JOIN patients AS p ON sl.patient_id = p.id
            ' . $doctorJoin . '
            WHERE UPPER(sl.service_code) = ?
              AND p.identity_number = ?
              AND ' . $deletedCondition . '
            ORDER BY sl.id DESC
            LIMIT 1';

    try {
        $stmt = $pdo->prepare($sql);
        $stmt->execute([$code, $identity]);
        $row = $stmt->fetch();
        return $row ?: null;
    } catch (Throwable $e) {
        write_service_log('search_leave failed: ' . $e->getMessage());
        return null;
    }
}

function log_leave_query(PDO $pdo, int $leaveId, string $source = 'external'): void {
    try {
        if (!table_exists($pdo, 'leave_queries')) {
            return;
        }
        $stmt = $pdo->prepare('INSERT INTO leave_queries (leave_id, queried_at, source) VALUES (?, NOW(), ?)');
        $stmt->execute([$leaveId, $source]);
    } catch (Throwable $e) {
        // لا نوقف إظهار النتيجة إذا فشل تسجيل الاستعلام.
        write_service_log('log_leave_query failed: ' . $e->getMessage());
    }
}

function e($value): string {
    return htmlspecialchars((string) ($value ?? ''), ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
}

function render_leave_html(array $row): string {
    $serviceCode = e($row['service_code'] ?? '');
    $identityNumber = e($row['identity_number'] ?? '');
    $patientName = e($row['patient_name'] ?? '');
    $issueDate = e($row['issue_date'] ?? '');
    $startDate = e($row['start_date'] ?? '');
    $endDate = e($row['end_date'] ?? '');
    $daysCount = e($row['days_count'] ?? '');
    $doctorName = e($row['doctor_name'] ?? '');
    $doctorTitle = e($row['doctor_title'] ?? '');

    $companionBlock = '';
    if (!empty($row['is_companion']) && !empty($row['companion_name']) && !empty($row['companion_relation'])) {
        $companionBlock = '<div class="col-md-6"><span>اسم المرافق: </span>' . e($row['companion_name']) . '</div>'
            . '<div class="col-md-6"><span>صلة القرابة: </span>' . e($row['companion_relation']) . '</div>';
    }

    return <<<HTML
<div class="row justify-content-center mt-1">
  <div class="col-md-5 p-4">
    <div class="form-group mb-3" style="padding-bottom: 10px;">
      <input type="text" maxlength="20" placeholder="رمز الخدمة" class="form-control" value="{$serviceCode}" readonly>
    </div>
    <div class="form-group mb-3">
      <input type="text" maxlength="20" pattern="[0-9A-Za-z-]*" placeholder="رقم الهوية / الإقامة" class="form-control" value="{$identityNumber}" readonly>
    </div>
    <div class="results-inquiery row">
      <div class="col-md-6"><span>الاسم: </span>{$patientName}</div>
      {$companionBlock}
      <div class="col-md-6"><span>تاريخ إصدار تقرير الإجازة:</span> {$issueDate}</div>
      <div class="col-md-6"><span>تبدأ من:</span> {$startDate}</div>
      <div class="col-md-6"><span>وحتى:</span> {$endDate}</div>
      <div class="col-md-6"><span>المدة بالأيام:</span> {$daysCount}</div>
      <div class="col-md-6"><span>اسم الطبيب:</span> {$doctorName}</div>
      <div class="col-md-6"><span>المسمى الوظيفي:</span> {$doctorTitle}</div>
    </div>
    <a href="index.html" class="btn btn-primary mt-3">استعلام جديد</a>
  </div>
</div>
HTML;
}

$code = request_value(['code', 'service_code', 'serviceCode']);
$identity = request_value(['id', 'identity_number', 'identity', 'national_id', 'iqama']);

if ($code === '') {
    json_response(['status' => 'error', 'msg' => 'فضلاً اكتب رمز الخدمة']);
}
if ($identity === '') {
    json_response(['status' => 'error', 'msg' => 'فضلاً اكتب رقم الهوية / الإقامة']);
}

$code = strtoupper(preg_replace('/\s+/', '', $code));
$identity = preg_replace('/\s+/', '', $identity);

if (!preg_match('/^[A-Z0-9\-]{1,50}$/', $code)) {
    json_response(['status' => 'error', 'msg' => 'رمز الخدمة غير صالح']);
}
if (!preg_match('/^[0-9A-Za-z\-]{1,50}$/', $identity)) {
    json_response(['status' => 'error', 'msg' => 'رقم الهوية / الإقامة غير صالح']);
}

$connected = false;
foreach (db_configs() as $config) {
    $pdo = connect_database($config);
    if (!$pdo) {
        continue;
    }
    $connected = true;

    $active = search_leave($pdo, $code, $identity, false);
    if ($active) {
        log_leave_query($pdo, (int) $active['leave_id'], 'external');
        json_response(['status' => 'ok', 'html' => render_leave_html($active)]);
    }

    $archived = search_leave($pdo, $code, $identity, true);
    if ($archived) {
        log_leave_query($pdo, (int) $archived['leave_id'], 'external');
        json_response(['status' => 'notfound']);
    }
}

if (!$connected) {
    json_response(['status' => 'error', 'msg' => 'تعذّر الاتصال بالخادم حالياً. تأكد من الاتصال ثم حاول مرة أخرى.']);
}

json_response(['status' => 'notfound']);
