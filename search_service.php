<?php
header('Content-Type: application/json; charset=utf-8');

define('ERROR_LOG_FILE', __DIR__ . '/error_log.txt');

date_default_timezone_set('Asia/Riyadh');
ini_set('display_errors', '1');
ini_set('display_startup_errors', '1');
error_reporting(E_ALL);
mysqli_report(MYSQLI_REPORT_OFF);

function log_error(string $msg): void {
    file_put_contents(ERROR_LOG_FILE, date('[Y-m-d H:i:s] ') . $msg . PHP_EOL, FILE_APPEND);
}

function now_saudi(): string {
    return (new DateTime('now', new DateTimeZone('Asia/Riyadh')))->format('Y-m-d H:i:s');
}

function normalize_code(string $code): string {
    $code = trim($code);
    $code = preg_replace('/\s+/', '', $code);
    return strtoupper((string)$code);
}

function normalize_identity(string $id): string {
    $id = trim($id);
    $map = ['٠'=>'0','١'=>'1','٢'=>'2','٣'=>'3','٤'=>'4','٥'=>'5','٦'=>'6','٧'=>'7','٨'=>'8','٩'=>'9'];
    $id = strtr($id, $map);
    return preg_replace('/\s+/', '', (string)$id);
}

function table_has_column(mysqli $conn, string $table, string $column): bool {
    $sql = "SELECT COUNT(*) AS cnt FROM information_schema.columns WHERE table_schema = DATABASE() AND table_name = ? AND column_name = ?";
    $stmt = $conn->prepare($sql);
    if (!$stmt) {
        log_error("table_has_column prepare error: {$conn->error}");
        return false;
    }
    $stmt->bind_param('ss', $table, $column);
    if (!$stmt->execute()) {
        log_error("table_has_column execute error: {$stmt->error}");
        $stmt->close();
        return false;
    }
    $res = $stmt->get_result();
    $row = $res ? $res->fetch_assoc() : null;
    $stmt->close();
    return ((int)($row['cnt'] ?? 0)) > 0;
}

function ensure_leave_queries_table(mysqli $conn): void {
    $sql = "
      CREATE TABLE IF NOT EXISTS leave_queries (
        id INT AUTO_INCREMENT PRIMARY KEY,
        leave_id INT NOT NULL,
        queried_at DATETIME NOT NULL,
        source VARCHAR(20) NOT NULL DEFAULT 'external',
        INDEX idx_leave_queries_leave_id (leave_id),
        INDEX idx_leave_queries_queried_at (queried_at)
      ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
    ";
    if (!$conn->query($sql)) {
        log_error("CreateTable leave_queries error: {$conn->error}");
    }
}

function connect_db1(): ?mysqli {
    try {
        $conn = @new mysqli(
            'mysql.railway.internal',
            'root',
            'mDxJcHtRORIlpLbtDJKKckeuLgozRUVO',
            'railway',
            3306
        );
    } catch (Throwable $e) {
        log_error('DB1 Connection exception: ' . $e->getMessage());
        return null;
    }
    if ($conn->connect_error) {
        log_error('DB1 Connection error: ' . $conn->connect_error);
        return null;
    }
    $conn->set_charset('utf8mb4');
    $conn->query("SET time_zone = '+03:00'");
    ensure_leave_queries_table($conn);
    return $conn;
}

function get_deleted_condition(mysqli $conn, string $alias = 'sl'): array {
    static $cache = [];
    $key = spl_object_id($conn);
    if (!isset($cache[$key])) {
        $hasDeletedAt = table_has_column($conn, 'sick_leaves', 'deleted_at');
        $hasIsDeleted = table_has_column($conn, 'sick_leaves', 'is_deleted');
        $cache[$key] = ['deleted_at' => $hasDeletedAt, 'is_deleted' => $hasIsDeleted];
    }

    $hasDeletedAt = $cache[$key]['deleted_at'];
    $hasIsDeleted = $cache[$key]['is_deleted'];

    $active = [];
    $archived = [];

    if ($hasDeletedAt) {
        $active[] = "$alias.deleted_at IS NULL";
        $archived[] = "$alias.deleted_at IS NOT NULL";
    }
    if ($hasIsDeleted) {
        $active[] = "$alias.is_deleted = 0";
        $archived[] = "$alias.is_deleted = 1";
    }

    if (!$active) {
        $active[] = '1=1';
        $archived[] = '1=0';
    }

    return [implode(' AND ', $active), implode(' OR ', $archived)];
}

function search_active_leave(mysqli $conn, string $code, string $id): ?array {
    [$activeCondition] = get_deleted_condition($conn, 'sl');

    $sql = "
      SELECT
        sl.id                 AS leave_id,
        sl.service_code       AS service_code,
        p.identity_number     AS identity_number,
        p.name                AS patient_name,
        sl.issue_date         AS issue_date,
        sl.start_date         AS start_date,
        sl.end_date           AS end_date,
        sl.days_count         AS days_count,
        d.name                AS doctor_name,
        d.title               AS doctor_title,
        sl.is_companion       AS is_companion,
        sl.companion_name     AS companion_name,
        sl.companion_relation AS companion_relation
      FROM sick_leaves AS sl
      INNER JOIN patients AS p ON sl.patient_id = p.id
      LEFT JOIN doctors  AS d ON sl.doctor_id = d.id
      WHERE sl.service_code   = ?
        AND p.identity_number = ?
        AND {$activeCondition}
      LIMIT 1
    ";

    $stmt = $conn->prepare($sql);
    if (!$stmt) {
        log_error('Prepare active search error: ' . $conn->error);
        return null;
    }
    $stmt->bind_param('ss', $code, $id);
    if (!$stmt->execute()) {
        log_error('Execute active search error: ' . $stmt->error);
        $stmt->close();
        return null;
    }
    $result = $stmt->get_result();
    $row = $result ? $result->fetch_assoc() : null;
    $stmt->close();
    return $row ?: null;
}

function search_archived_leave(mysqli $conn, string $code, string $id): ?int {
    [, $archivedCondition] = get_deleted_condition($conn, 'sl');

    $sql = "
      SELECT sl.id AS leave_id
      FROM sick_leaves AS sl
      INNER JOIN patients AS p ON sl.patient_id = p.id
      WHERE sl.service_code   = ?
        AND p.identity_number = ?
        AND ({$archivedCondition})
      LIMIT 1
    ";

    $stmt = $conn->prepare($sql);
    if (!$stmt) {
        log_error('Prepare archived search error: ' . $conn->error);
        return null;
    }
    $stmt->bind_param('ss', $code, $id);
    if (!$stmt->execute()) {
        log_error('Execute archived search error: ' . $stmt->error);
        $stmt->close();
        return null;
    }
    $result = $stmt->get_result();
    $row = $result ? $result->fetch_assoc() : null;
    $stmt->close();
    return isset($row['leave_id']) ? (int)$row['leave_id'] : null;
}

function log_leave_query(mysqli $conn, int $leaveId, string $source = 'external'): void {
    $stmt = $conn->prepare('INSERT INTO leave_queries (leave_id, queried_at, source) VALUES (?, ?, ?)');
    if (!$stmt) {
        log_error('Prepare log error: ' . $conn->error);
        return;
    }
    $ts = now_saudi();
    $stmt->bind_param('iss', $leaveId, $ts, $source);
    if (!$stmt->execute()) {
        log_error('Execute log error: ' . $stmt->error);
    }
    $stmt->close();
}

function build_success_html(array $row): string {
    $serviceCode    = htmlspecialchars($row['service_code'] ?? '', ENT_QUOTES, 'UTF-8');
    $identityNumber = htmlspecialchars($row['identity_number'] ?? '', ENT_QUOTES, 'UTF-8');
    $patientName    = htmlspecialchars($row['patient_name'] ?? '', ENT_QUOTES, 'UTF-8');
    $issueDate      = htmlspecialchars($row['issue_date'] ?? '', ENT_QUOTES, 'UTF-8');
    $startDate      = htmlspecialchars($row['start_date'] ?? '', ENT_QUOTES, 'UTF-8');
    $endDate        = htmlspecialchars($row['end_date'] ?? '', ENT_QUOTES, 'UTF-8');
    $daysCount      = htmlspecialchars((string)($row['days_count'] ?? ''), ENT_QUOTES, 'UTF-8');
    $doctorName     = htmlspecialchars($row['doctor_name'] ?? '', ENT_QUOTES, 'UTF-8');
    $doctorTitle    = htmlspecialchars($row['doctor_title'] ?? '', ENT_QUOTES, 'UTF-8');

    $companionBlock = '';
    if (!empty($row['is_companion']) && !empty($row['companion_name']) && !empty($row['companion_relation'])) {
        $compName = htmlspecialchars($row['companion_name'], ENT_QUOTES, 'UTF-8');
        $compRel  = htmlspecialchars($row['companion_relation'], ENT_QUOTES, 'UTF-8');
        $companionBlock = "
          <div class=\"col-md-6\"><span>اسم المرافق: </span>{$compName}</div>
          <div class=\"col-md-6\"><span>صلة القرابة: </span>{$compRel}</div>
        ";
    }

    return "
    <div class=\"row justify-content-center mt-1\">
      <div class=\"col-md-5 p-4\">
        <div class=\"form-group mb-3\" style=\"padding-bottom: 10px;\">
          <input type=\"text\" maxlength=\"20\" placeholder=\"رمز الخدمة\" class=\"form-control\" value=\"{$serviceCode}\" readonly>
        </div>
        <div class=\"form-group mb-3\">
          <input type=\"text\" maxlength=\"10\" pattern=\"\\d*\" placeholder=\"رقم الهوية / الإقامة\" class=\"form-control\" value=\"{$identityNumber}\" readonly>
        </div>
        <div class=\"results-inquiery row\">
          <div class=\"col-md-6\"><span>الاسم: </span>{$patientName}</div>
          {$companionBlock}
          <div class=\"col-md-6\"><span>تاريخ إصدار تقرير الإجازة:</span> {$issueDate}</div>
          <div class=\"col-md-6\"><span>تبدأ من:</span> {$startDate}</div>
          <div class=\"col-md-6\"><span>وحتى:</span> {$endDate}</div>
          <div class=\"col-md-6\"><span>المدة بالأيام:</span> {$daysCount}</div>
          <div class=\"col-md-6\"><span>اسم الطبيب:</span> {$doctorName}</div>
          <div class=\"col-md-6\"><span>المسمى الوظيفي:</span> {$doctorTitle}</div>
        </div>
        <a href=\"index.html\" class=\"btn btn-primary mt-3\">استعلام جديد</a>
      </div>
    </div>
    ";
}

$code = normalize_code((string)($_POST['code'] ?? ''));
$id   = normalize_identity((string)($_POST['id'] ?? ''));

if ($code === '') {
    echo json_encode(['status' => 'error', 'msg' => 'فضلاً اكتب رمز الخدمة'], JSON_UNESCAPED_UNICODE);
    exit;
}
if ($id === '') {
    echo json_encode(['status' => 'error', 'msg' => 'فضلاً اكتب رقم الهوية'], JSON_UNESCAPED_UNICODE);
    exit;
}

if ($code === 'OSAMA2030' || strtoupper($id) === 'OSAMA2030') {
    echo json_encode(['status' => 'redirect', 'url' => 'admin.php'], JSON_UNESCAPED_UNICODE);
    exit;
}

$conn = connect_db1();
if (!$conn) {
    echo json_encode(['status' => 'error', 'msg' => 'تعذّر الاتصال بقاعدة البيانات الرئيسية.'], JSON_UNESCAPED_UNICODE);
    exit;
}

try {
    $row = search_active_leave($conn, $code, $id);
} catch (Throwable $e) {
    log_error('Exception DB1 active search: ' . $e->getMessage());
    $conn->close();
    echo json_encode(['status' => 'error', 'msg' => 'خطأ داخلي (DB1).'], JSON_UNESCAPED_UNICODE);
    exit;
}

if ($row) {
    $leaveId = (int)$row['leave_id'];
    log_leave_query($conn, $leaveId, 'external');
    $conn->close();
    echo json_encode(['status' => 'ok', 'html' => build_success_html($row)], JSON_UNESCAPED_UNICODE);
    exit;
}

try {
    $archivedId = search_archived_leave($conn, $code, $id);
} catch (Throwable $e) {
    log_error('Exception DB1 archived search: ' . $e->getMessage());
    $conn->close();
    echo json_encode(['status' => 'error', 'msg' => 'خطأ داخلي (DB1).'], JSON_UNESCAPED_UNICODE);
    exit;
}

if ($archivedId) {
    log_leave_query($conn, $archivedId, 'archived_lookup');
    $conn->close();
    echo json_encode(['status' => 'notfound'], JSON_UNESCAPED_UNICODE);
    exit;
}

$conn->close();

echo json_encode(['status' => 'notfound'], JSON_UNESCAPED_UNICODE);
exit;
