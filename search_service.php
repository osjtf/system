<?php
// Search endpoint for sick leave inquiries.
// Keep the response JSON-only so index.html never receives PHP/HTML errors.
ini_set('display_errors', '0');
ini_set('display_startup_errors', '0');
error_reporting(0);
date_default_timezone_set('Asia/Riyadh');

header('Content-Type: application/json; charset=utf-8');
header('X-Content-Type-Options: nosniff');
header('X-Frame-Options: DENY');
header_remove('X-Powered-By');
header_remove('Server');

define('ERROR_LOG_FILE', __DIR__ . '/error_log.txt');

define('DATABASES', [
    [
        'name' => 'primary',
        'host' => 'mysql.railway.internal',
        'port' => 3306,
        'database' => 'railway',
        'username' => 'root',
        'password' => 'ExvKbuJnGIvDATyXWCHtpjOFluFAgeqQ',
    ],
    [
        'name' => 'secondary',
        'host' => 'c9cujduvu830eexs.cbetxkdyhwsb.us-east-1.rds.amazonaws.com',
        'port' => 3306,
        'database' => 'cdidptf4q81rafg8',
        'username' => 'q2xjpqcepsmd4v12',
        'password' => 'v8lcs6awp4vj9u28',
    ],
]);

function log_search_error(string $message): void
{
    @file_put_contents(ERROR_LOG_FILE, date('[Y-m-d H:i:s] ') . $message . PHP_EOL, FILE_APPEND);
}

function json_response(array $payload): void
{
    echo json_encode($payload, JSON_UNESCAPED_UNICODE);
    exit;
}

set_exception_handler(function (Throwable $e): void {
    log_search_error('Unhandled exception: ' . $e->getMessage());
    json_response(['status' => 'error', 'msg' => 'حدث خطأ داخلي أثناء تنفيذ الاستعلام. حاول مرة أخرى.']);
});

set_error_handler(function (int $severity, string $message, string $file, int $line): bool {
    log_search_error("PHP error [$severity] $message in $file:$line");
    return true;
});

function connect_database(array $config): ?PDO
{
    try {
        $dsn = sprintf(
            'mysql:host=%s;port=%d;dbname=%s;charset=utf8mb4',
            $config['host'],
            $config['port'],
            $config['database']
        );
        $pdo = new PDO($dsn, $config['username'], $config['password'], [
            PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
            PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
            PDO::ATTR_EMULATE_PREPARES => false,
            PDO::ATTR_TIMEOUT => 5,
        ]);
        $pdo->exec("SET time_zone = '+03:00'");
        ensure_leave_queries_table($pdo);
        return $pdo;
    } catch (Throwable $e) {
        log_search_error('Connection failed for ' . ($config['name'] ?? 'database') . ': ' . $e->getMessage());
        return null;
    }
}

function ensure_leave_queries_table(PDO $pdo): void
{
    try {
        $pdo->exec("CREATE TABLE IF NOT EXISTS leave_queries (
            id INT AUTO_INCREMENT PRIMARY KEY,
            leave_id INT NOT NULL,
            queried_at DATETIME NOT NULL,
            source VARCHAR(20) NOT NULL DEFAULT 'external',
            INDEX idx_leave_queries_leave (leave_id),
            INDEX idx_leave_queries_queried_at (queried_at),
            CONSTRAINT fk_leave_queries_leave FOREIGN KEY (leave_id) REFERENCES sick_leaves(id) ON DELETE CASCADE
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci");
    } catch (Throwable $e) {
        // Logging the query is helpful but should never block the public inquiry service.
        log_search_error('Unable to ensure leave_queries table: ' . $e->getMessage());
    }
}

function normalize_request_value(string $key, string $fallbackKey = ''): string
{
    $value = $_POST[$key] ?? $_GET[$key] ?? null;
    if (($value === null || $value === '') && $fallbackKey !== '') {
        $value = $_POST[$fallbackKey] ?? $_GET[$fallbackKey] ?? '';
    }
    return trim((string)$value);
}

function normalize_lookup_value(string $value, bool $uppercase = false): string
{
    $value = trim($value);
    // Remove normal and invisible separators that users commonly copy with service codes/IDs.
    $value = preg_replace('/[\s\x{200B}-\x{200D}\x{FEFF}]+/u', '', $value) ?? $value;
    return $uppercase ? strtoupper($value) : $value;
}

function compact_lookup_sql(string $expression): string
{
    // Keep this compatible with older MySQL versions by avoiding REGEXP_REPLACE.
    return "UPPER(REPLACE(REPLACE(REPLACE(REPLACE(REPLACE(TRIM({$expression}), ' ', ''), CHAR(9), ''), CHAR(10), ''), CHAR(13), ''), '-', ''))";
}

function h(?string $value): string
{
    return htmlspecialchars((string)$value, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
}

function first_non_empty(array $row, array $keys): string
{
    foreach ($keys as $key) {
        if (isset($row[$key]) && trim((string)$row[$key]) !== '') {
            return (string)$row[$key];
        }
    }
    return '';
}

function format_date(?string $date): string
{
    if (!$date) {
        return '';
    }
    $dt = DateTime::createFromFormat('Y-m-d', substr($date, 0, 10));
    return $dt ? $dt->format('Y-m-d') : $date;
}


function table_columns(PDO $pdo, string $table): array
{
    static $cache = [];
    $key = spl_object_id($pdo) . ':' . $table;
    if (isset($cache[$key])) {
        return $cache[$key];
    }

    try {
        $stmt = $pdo->prepare('SELECT column_name FROM information_schema.columns WHERE table_schema = DATABASE() AND table_name = :table_name');
        $stmt->execute([':table_name' => $table]);
        $cache[$key] = array_fill_keys($stmt->fetchAll(PDO::FETCH_COLUMN), true);
    } catch (Throwable $e) {
        log_search_error('Unable to inspect columns for ' . $table . ': ' . $e->getMessage());
        $cache[$key] = [];
    }

    return $cache[$key];
}

function has_column(PDO $pdo, string $table, string $column): bool
{
    $columns = table_columns($pdo, $table);
    return isset($columns[$column]);
}

function coalesce_columns(PDO $pdo, string $table, string $alias, array $columns, string $fallback = "''"): string
{
    $parts = [];
    foreach ($columns as $column) {
        if (has_column($pdo, $table, $column)) {
            $parts[] = "NULLIF({$alias}.{$column}, '')";
        }
    }

    if (!$parts) {
        return $fallback;
    }

    $parts[] = $fallback;
    return 'COALESCE(' . implode(', ', $parts) . ')';
}

function search_leave(PDO $pdo, string $code, string $identity, bool $active): ?array
{
    // This query adapts to the schema created by admin.php while keeping
    // compatibility with older databases that still have legacy columns.
    $patientNameExpr = coalesce_columns($pdo, 'patients', 'p', ['name_ar', 'name', 'name_en'], "''");
    $doctorNameParts = [];
    foreach (['name_ar', 'name', 'name_en'] as $column) {
        if (has_column($pdo, 'doctors', $column)) {
            $doctorNameParts[] = "NULLIF(d.{$column}, '')";
        }
    }
    if (has_column($pdo, 'sick_leaves', 'doctor_name_en')) {
        $doctorNameParts[] = "NULLIF(sl.doctor_name_en, '')";
    }
    $doctorNameExpr = $doctorNameParts ? 'COALESCE(' . implode(', ', array_merge($doctorNameParts, ["''"])) . ')' : "''";

    $doctorTitleParts = [];
    foreach (['title_ar', 'title', 'title_en'] as $column) {
        if (has_column($pdo, 'doctors', $column)) {
            $doctorTitleParts[] = "NULLIF(d.{$column}, '')";
        }
    }
    if (has_column($pdo, 'sick_leaves', 'doctor_title_en')) {
        $doctorTitleParts[] = "NULLIF(sl.doctor_title_en, '')";
    }
    $doctorTitleExpr = $doctorTitleParts ? 'COALESCE(' . implode(', ', array_merge($doctorTitleParts, ["''"])) . ')' : "''";

    $companionNameExpr = has_column($pdo, 'sick_leaves', 'companion_name') ? 'sl.companion_name' : "''";
    $companionRelationExpr = has_column($pdo, 'sick_leaves', 'companion_relation') ? 'sl.companion_relation' : "''";
    $isCompanionExpr = has_column($pdo, 'sick_leaves', 'is_companion') ? 'sl.is_companion' : '0';

    $serviceCodeCompactExpr = compact_lookup_sql('sl.service_code');
    $identityCompactExpr = compact_lookup_sql('p.identity_number');

    if (has_column($pdo, 'sick_leaves', 'deleted_at')) {
        $activeCondition = 'sl.deleted_at IS ' . ($active ? 'NULL' : 'NOT NULL');
    } elseif (has_column($pdo, 'sick_leaves', 'is_deleted')) {
        $activeCondition = 'sl.is_deleted = ' . ($active ? '0' : '1');
    } else {
        $activeCondition = $active ? '1 = 1' : '1 = 0';
    }

    $sql = "
        SELECT
            sl.id AS leave_id,
            sl.service_code,
            p.identity_number,
            {$patientNameExpr} AS patient_name,
            sl.issue_date,
            sl.start_date,
            sl.end_date,
            sl.days_count,
            {$doctorNameExpr} AS doctor_name,
            {$doctorTitleExpr} AS doctor_title,
            {$isCompanionExpr} AS is_companion,
            {$companionNameExpr} AS companion_name,
            {$companionRelationExpr} AS companion_relation
        FROM sick_leaves sl
        INNER JOIN patients p ON p.id = sl.patient_id
        LEFT JOIN doctors d ON d.id = sl.doctor_id
        WHERE (UPPER(TRIM(sl.service_code)) = UPPER(:service_code)
               OR {$serviceCodeCompactExpr} = :service_code_compact)
          AND (TRIM(p.identity_number) = :identity_number
               OR {$identityCompactExpr} = :identity_number_compact)
          AND {$activeCondition}
        ORDER BY sl.id DESC
        LIMIT 1
    ";

    $stmt = $pdo->prepare($sql);
    $stmt->execute([
        ':service_code' => $code,
        ':service_code_compact' => normalize_lookup_value(str_replace('-', '', $code), true),
        ':identity_number' => $identity,
        ':identity_number_compact' => normalize_lookup_value(str_replace('-', '', $identity), true),
    ]);
    $row = $stmt->fetch();
    return $row ?: null;
}

function log_leave_query(PDO $pdo, int $leaveId, string $source = 'external'): void
{
    try {
        $stmt = $pdo->prepare('INSERT INTO leave_queries (leave_id, queried_at, source) VALUES (:leave_id, NOW(), :source)');
        $stmt->execute([
            ':leave_id' => $leaveId,
            ':source' => $source,
        ]);
    } catch (Throwable $e) {
        log_search_error('Unable to log leave query for leave #' . $leaveId . ': ' . $e->getMessage());
    }
}

function render_leave_result(array $row): string
{
    $serviceCode = h($row['service_code'] ?? '');
    $identityNumber = h($row['identity_number'] ?? '');
    $patientName = h(first_non_empty($row, ['patient_name']));
    $issueDate = h(format_date($row['issue_date'] ?? ''));
    $startDate = h(format_date($row['start_date'] ?? ''));
    $endDate = h(format_date($row['end_date'] ?? ''));
    $daysCount = h((string)($row['days_count'] ?? ''));
    $doctorName = h(first_non_empty($row, ['doctor_name']));
    $doctorTitle = h(first_non_empty($row, ['doctor_title']));

    $companionBlock = '';
    if (!empty($row['is_companion']) && trim((string)($row['companion_name'] ?? '')) !== '') {
        $companionName = h($row['companion_name'] ?? '');
        $companionRelation = h($row['companion_relation'] ?? '');
        $companionBlock = <<<HTML
          <div class="col-md-6"><span>اسم المرافق: </span>{$companionName}</div>
          <div class="col-md-6"><span>صلة القرابة: </span>{$companionRelation}</div>
HTML;
    }

    return <<<HTML
    <div class="row justify-content-center mt-1">
      <div class="col-md-5 p-4">
        <div class="form-group mb-3" style="padding-bottom: 10px;">
          <input type="text" maxlength="20" placeholder="رمز الخدمة" class="form-control" value="{$serviceCode}" readonly>
        </div>
        <div class="form-group mb-3">
          <input type="text" maxlength="10" pattern="\d*" placeholder="رقم الهوية / الإقامة" class="form-control" value="{$identityNumber}" readonly>
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

$code = normalize_lookup_value(normalize_request_value('code', 'service_code'), true);
$identity = normalize_lookup_value(normalize_request_value('id', 'identity_number'), false);

if ($code === '') {
    json_response(['status' => 'error', 'msg' => 'فضلاً اكتب رمز الخدمة']);
}
if ($identity === '') {
    json_response(['status' => 'error', 'msg' => 'فضلاً اكتب رقم الهوية']);
}
if (!preg_match('/^[A-Za-z0-9-]{1,50}$/', $code)) {
    json_response(['status' => 'error', 'msg' => 'رمز الخدمة غير صالح']);
}
if (!preg_match('/^[0-9A-Za-z-]{1,50}$/', $identity)) {
    json_response(['status' => 'error', 'msg' => 'رقم الهوية غير صالح']);
}

$connected = false;

foreach (DATABASES as $databaseConfig) {
    $pdo = connect_database($databaseConfig);
    if (!$pdo) {
        continue;
    }
    $connected = true;

    try {
        $activeLeave = search_leave($pdo, $code, $identity, true);
        if ($activeLeave) {
            log_leave_query($pdo, (int)$activeLeave['leave_id']);
            json_response(['status' => 'ok', 'html' => render_leave_result($activeLeave)]);
        }

        $archivedLeave = search_leave($pdo, $code, $identity, false);
        if ($archivedLeave) {
            log_leave_query($pdo, (int)$archivedLeave['leave_id']);
            json_response(['status' => 'notfound']);
        }
    } catch (Throwable $e) {
        log_search_error('Search failed for ' . ($databaseConfig['name'] ?? 'database') . ': ' . $e->getMessage());
        continue;
    }
}

if (!$connected) {
    json_response(['status' => 'error', 'msg' => 'تعذّر الاتصال بالخادم حالياً. حاول مرة أخرى لاحقاً.']);
}

json_response(['status' => 'notfound']);
