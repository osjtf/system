<?php
/**
 * خدمة البحث عن الإجازات (واجهة مستقلة)
 * متوافقة مع منطق admin.php قدر الإمكان بدون تعديل ملف الإدارة.
 */

date_default_timezone_set('Asia/Riyadh');
header('X-Frame-Options: SAMEORIGIN');
header('X-Content-Type-Options: nosniff');
header('Referrer-Policy: strict-origin-when-cross-origin');

$db_host = 'mysql.railway.internal';
$db_user = 'root';
$db_pass = 'mDxJcHtRORIlpLbtDJKKckeuLgozRUVO';
$db_name = 'railway';
$db_port = 3306;

function nowSaudi(): string {
    return (new DateTime('now', new DateTimeZone('Asia/Riyadh')))->format('Y-m-d H:i:s');
}

function normalizeSearchText(string $text): string {
    $text = trim(mb_strtolower($text, 'UTF-8'));
    $replaceMap = [
        'أ' => 'ا', 'إ' => 'ا', 'آ' => 'ا',
        'ى' => 'ي', 'ؤ' => 'و', 'ئ' => 'ي',
        'ة' => 'ه', 'ـ' => '',
        '٠' => '0', '١' => '1', '٢' => '2', '٣' => '3', '٤' => '4',
        '٥' => '5', '٦' => '6', '٧' => '7', '٨' => '8', '٩' => '9',
    ];
    $text = strtr($text, $replaceMap);
    $text = preg_replace('/[\x{064B}-\x{065F}\x{0670}]/u', '', $text);
    $text = preg_replace('/\s+/u', ' ', $text);
    return $text;
}

function jsonResponse(array $payload): void {
    header('Content-Type: application/json; charset=utf-8');
    echo json_encode($payload, JSON_UNESCAPED_UNICODE);
    exit;
}

function getPdo(): PDO {
    global $db_host, $db_user, $db_pass, $db_name, $db_port;
    static $pdo = null;
    if ($pdo instanceof PDO) {
        return $pdo;
    }
    $pdo = new PDO(
        "mysql:host=$db_host;port=$db_port;dbname=$db_name;charset=utf8mb4",
        $db_user,
        $db_pass,
        [
            PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
            PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
            PDO::ATTR_EMULATE_PREPARES => false,
        ]
    );
    $pdo->exec("SET time_zone = '+03:00'");
    return $pdo;
}

function searchLeave(PDO $pdo, string $rawQuery): array {
    $search = normalizeSearchText($rawQuery);
    if ($search === '' || mb_strlen($search, 'UTF-8') < 2) {
        return ['success' => false, 'message' => 'أدخل حرفين على الأقل للبحث.'];
    }

    $stmt = $pdo->prepare(
        "SELECT sl.*, p.name AS patient_name, p.identity_number, p.phone AS patient_phone,
                d.name AS doctor_name, d.title AS doctor_title
         FROM sick_leaves sl
         LEFT JOIN patients p ON p.id = sl.patient_id
         LEFT JOIN doctors d ON d.id = sl.doctor_id
         WHERE (
            LOWER(REPLACE(REPLACE(REPLACE(sl.service_code,'-',''),' ',''),'_','')) LIKE :qCode
            OR LOWER(p.name) LIKE :q
            OR LOWER(p.identity_number) LIKE :q
            OR LOWER(p.phone) LIKE :q
            OR LOWER(d.name) LIKE :q
            OR LOWER(d.title) LIKE :q
            OR LOWER(COALESCE(sl.companion_name,'')) LIKE :q
            OR LOWER(COALESCE(sl.companion_relation,'')) LIKE :q
         )
         ORDER BY sl.created_at DESC
         LIMIT 1"
    );

    $q = '%' . $search . '%';
    $qCode = '%' . preg_replace('/[^a-z0-9]/', '', $search) . '%';
    $stmt->execute([
        ':q' => $q,
        ':qCode' => $qCode,
    ]);

    $leave = $stmt->fetch();
    if (!$leave) {
        return ['success' => false, 'message' => 'لا توجد إجازة مطابقة.'];
    }

    // تسجيل الاستعلام دائماً
    $source = !empty($leave['deleted_at']) ? 'archived_lookup' : 'external';
    $logStmt = $pdo->prepare("INSERT INTO leave_queries (leave_id, queried_at, source) VALUES (?, ?, ?)");
    $logStmt->execute([$leave['id'], nowSaudi(), $source]);

    // الإجازة المؤرشفة تُعامل كغير موجودة
    if (!empty($leave['deleted_at'])) {
        return ['success' => false, 'message' => 'لم يتم العثور على الإجازة.'];
    }

    return ['success' => true, 'leave' => $leave];
}

if (($_SERVER['REQUEST_METHOD'] === 'POST' || isset($_GET['ajax'])) && (($_POST['action'] ?? '') === 'search_leave' || isset($_GET['query']) || isset($_POST['query']))) {
    $query = $_POST['query'] ?? $_GET['query'] ?? '';
    try {
        jsonResponse(searchLeave(getPdo(), (string)$query));
    } catch (Throwable $e) {
        jsonResponse(['success' => false, 'message' => 'فشل الاتصال بقاعدة البيانات.']);
    }
}
?>
<!DOCTYPE html>
<html lang="ar" dir="rtl">
<head>
    <meta charset="UTF-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1.0" />
    <title>الاستعلام عن الإجازة</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.rtl.min.css" rel="stylesheet">
</head>
<body class="bg-light">
<div class="container py-5">
    <div class="card shadow-sm">
        <div class="card-body">
            <h4 class="mb-3">الاستعلام عن الإجازة</h4>
            <div class="input-group mb-3">
                <input id="searchLeaves" class="form-control" placeholder="ابحث برمز الإجازة / اسم المريض / الهوية / الجوال / الطبيب" />
                <button id="btn-search-leaves" class="btn btn-primary">بحث</button>
            </div>
            <div id="leaveSearchResult" class="small"></div>
        </div>
    </div>
</div>

<script>
async function runSearch() {
    const query = document.getElementById('searchLeaves').value.trim();
    const resultBox = document.getElementById('leaveSearchResult');
    if (!query) {
        resultBox.innerHTML = '<div class="alert alert-warning mb-0">اكتب قيمة للبحث.</div>';
        return;
    }

    const fd = new FormData();
    fd.append('action', 'search_leave');
    fd.append('query', query);

    const res = await fetch('search_service.php', { method: 'POST', body: fd, headers: { 'X-Requested-With': 'XMLHttpRequest' }});
    const data = await res.json();

    if (!data.success || !data.leave) {
        resultBox.innerHTML = `<div class="alert alert-danger mb-0">${data.message || 'لم يتم العثور على نتيجة.'}</div>`;
        return;
    }

    const lv = data.leave;
    resultBox.innerHTML = `
        <div class="alert alert-success mb-2">تم العثور على الإجازة.</div>
        <div class="table-responsive">
            <table class="table table-bordered table-sm text-center align-middle">
                <thead>
                    <tr>
                        <th>رمز الخدمة</th><th>المريض</th><th>الهوية</th><th>الجوال</th><th>الطبيب</th><th>تاريخ الإصدار</th><th>البداية</th><th>النهاية</th><th>الأيام</th><th>الحالة</th>
                    </tr>
                </thead>
                <tbody>
                    <tr>
                        <td>${lv.service_code || ''}</td>
                        <td>${lv.patient_name || ''}</td>
                        <td>${lv.identity_number || ''}</td>
                        <td>${lv.patient_phone || ''}</td>
                        <td>${lv.doctor_name || ''} ${lv.doctor_title ? '(' + lv.doctor_title + ')' : ''}</td>
                        <td>${lv.issue_date || ''}</td>
                        <td>${lv.start_date || ''}</td>
                        <td>${lv.end_date || ''}</td>
                        <td>${lv.days_count || 0}</td>
                        <td>${String(lv.is_paid) === '1' ? '<span class="badge bg-success">مدفوعة</span>' : '<span class="badge bg-danger">غير مدفوعة</span>'}</td>
                    </tr>
                </tbody>
            </table>
        </div>`;
}

document.getElementById('btn-search-leaves').addEventListener('click', runSearch);
document.getElementById('searchLeaves').addEventListener('keydown', (e) => {
    if (e.key === 'Enter') {
        e.preventDefault();
        runSearch();
    }
});
</script>
</body>
</html>
