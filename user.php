<?php
/**
 * بوابة المرضى - user.php
 * تصميم احترافي خيالي مع أمان عالي وريسبونسيف كامل
 */

ini_set('session.use_only_cookies', '1');
ini_set('session.cookie_httponly', '1');
ini_set('session.cookie_secure', (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off') ? '1' : '0');
ini_set('session.cookie_samesite', 'Strict');
ini_set('session.use_strict_mode', '1');
session_start();

// إخفاء معلومات الخادم والمسارات
header_remove('X-Powered-By');
header_remove('Server');

date_default_timezone_set('Asia/Riyadh');
header('X-Frame-Options: DENY');
header('X-Content-Type-Options: nosniff');
header('Referrer-Policy: strict-origin-when-cross-origin');
header('Permissions-Policy: geolocation=(), microphone=(), camera=()');
header('Content-Security-Policy: default-src \'self\'; script-src \'self\' \'unsafe-inline\' https://cdn.jsdelivr.net https://cdnjs.cloudflare.com; style-src \'self\' \'unsafe-inline\' https://cdn.jsdelivr.net https://cdnjs.cloudflare.com https://fonts.googleapis.com; font-src \'self\' https://fonts.gstatic.com https://cdnjs.cloudflare.com; img-src \'self\' data: https:; connect-src \'self\';');
header('Strict-Transport-Security: max-age=31536000; includeSubDomains');
header('X-Robots-Tag: noindex, nofollow, noarchive');

// منع عرض أخطاء PHP للمستخدمين
ini_set('display_errors', '0');
ini_set('display_startup_errors', '0');
error_reporting(0);

// ======================== إعدادات قاعدة البيانات ========================
$db_host = 'mysql.railway.internal';
$db_user = 'root';
$db_pass = 'vDUncyqSFYnHULjIOHYltRvPXtbLVIIl';
$db_name = 'railway';
$db_port = 3306;

try {
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
} catch (PDOException $e) {
    die('<div style="font-family:sans-serif;text-align:center;padding:50px;color:red;">فشل الاتصال بقاعدة البيانات</div>');
}

$pdo->exec("SET time_zone = '+03:00'");
try { $pdo->exec("ALTER TABLE hospitals ADD COLUMN deleted_at DATETIME NULL"); } catch (Throwable $e) {}

// ======================== دوال الأمان ========================
function patient_csrf_token(): string {
    if (empty($_SESSION['patient_csrf_token'])) {
        $_SESSION['patient_csrf_token'] = bin2hex(random_bytes(32));
    }
    return $_SESSION['patient_csrf_token'];
}

function patient_csrf_input(): string {
    return '<input type="hidden" name="csrf_token" value="' . patient_csrf_token() . '">';
}

function patient_verify_csrf(string $token): bool {
    return isset($_SESSION['patient_csrf_token']) && hash_equals($_SESSION['patient_csrf_token'], $token);
}

// ======================== دوال مساعدة ========================
function nowSaudiUser(): string {
    return (new DateTime('now', new DateTimeZone('Asia/Riyadh')))->format('Y-m-d H:i:s');
}

function isPatientLoggedIn(): bool {
    return isset($_SESSION['patient_logged_in']) && $_SESSION['patient_logged_in'] === true;
}

function checkPatientActive(PDO $pdo): bool {
    if (!isPatientLoggedIn()) return false;
    $uid = (int)$_SESSION['patient_user_id'];
    $stmt = $pdo->prepare("SELECT is_active FROM admin_users WHERE id = ?");
    $stmt->execute([$uid]);
    $row = $stmt->fetch();
    if (!$row || !$row['is_active']) {
        session_destroy();
        return false;
    }
    return true;
}

function gregorianToHijriUser($gYear, $gMonth, $gDay) {
    $gYear = (int)$gYear; $gMonth = (int)$gMonth; $gDay = (int)$gDay;
    $a = intval((14 - $gMonth) / 12);
    $y = $gYear + 4800 - $a;
    $m = $gMonth + 12 * $a - 3;
    $jdn = $gDay + intval((153 * $m + 2) / 5) + 365 * $y + intval($y / 4) - intval($y / 100) + intval($y / 400) - 32045;
    $epoch = 1948440;
    $days = $jdn - $epoch;
    $hYear = intval(floor(($days - 1) / 354.36667) + 1);
    $leapYears = [2, 5, 7, 10, 13, 16, 18, 21, 24, 26, 29];
    $hijriYearStart = function($year) use ($epoch, $leapYears) {
        $y2 = $year - 1;
        $cycle = intval($y2 / 30);
        $yearInCycle = $y2 % 30;
        $leapCount = 0;
        foreach ($leapYears as $ly) { if ($ly <= $yearInCycle) $leapCount++; }
        return $epoch + $cycle * 10631 + $yearInCycle * 354 + $leapCount;
    };
    while ($hijriYearStart($hYear + 1) <= $jdn) $hYear++;
    while ($hijriYearStart($hYear) > $jdn) $hYear--;
    $dayOfYear = $jdn - $hijriYearStart($hYear) + 1;
    $isLeap = in_array($hYear % 30, $leapYears);
    $hMonth = 1; $remaining = $dayOfYear;
    for ($mn = 1; $mn <= 12; $mn++) {
        $md = ($mn % 2 == 1) ? 30 : 29;
        if ($mn == 12 && $isLeap) $md = 30;
        if ($remaining <= $md) { $hMonth = $mn; $hDay = $remaining; break; }
        $remaining -= $md;
    }
    return ['year' => $hYear, 'month' => $hMonth, 'day' => $hDay ?? $remaining];
}

function toHijriStrUser($d) {
    if (!$d) return '';
    $parts = explode('-', $d);
    if (count($parts) !== 3) return $d;
    $h = gregorianToHijriUser((int)$parts[0], (int)$parts[1], (int)$parts[2]);
    return sprintf('%02d-%02d-%04d', $h['day'], $h['month'], $h['year']);
}

function fmtDateUser($d) {
    if (!$d) return '';
    $dt = DateTime::createFromFormat('Y-m-d', $d);
    return $dt ? $dt->format('d/m/Y') : $d;
}

function fmtDateEnUser($d) {
    if (!$d) return '';
    $dt = DateTime::createFromFormat('Y-m-d', $d);
    return $dt ? $dt->format('d-m-Y') : $d;
}

function getUsedDaysUser(PDO $pdo, int $patientId, int $userId): int {
    $stmt = $pdo->prepare("SELECT COALESCE(SUM(days_count),0) FROM sick_leaves WHERE patient_id = ? AND created_by_user_id = ? AND deleted_at IS NULL");
    $stmt->execute([$patientId, $userId]);
    return (int)$stmt->fetchColumn();
}

function generateServiceCodeUser($pdo, $prefix, $issueDate = null) {
    $prefix = strtoupper(trim($prefix));
    if (!in_array($prefix, ['GSL', 'PSL'])) $prefix = 'GSL';
    $issueDateObj = DateTime::createFromFormat('Y-m-d', (string)$issueDate, new DateTimeZone('Asia/Riyadh'));
    if (!$issueDateObj) $issueDateObj = new DateTime('now', new DateTimeZone('Asia/Riyadh'));
    $datePart = $issueDateObj->format('ymd');
    $stmt = $pdo->query("SELECT service_code FROM sick_leaves ORDER BY id DESC LIMIT 1");
    $last = $stmt->fetchColumn();
    $num = 1;
    if ($last && preg_match('/^(?:GSL|PSL)\d{6}(\d+)$/', $last, $m)) {
        $num = intval($m[1]) + 1;
    }
    return $prefix . $datePart . str_pad((string)$num, 5, '0', STR_PAD_LEFT);
}

function formatHijriDateSpanUser(string $date): string {
    $safeDate = htmlspecialchars($date, ENT_QUOTES);
    return '<span dir="ltr" style="unicode-bidi:isolate;direction:ltr;display:inline-block;">' . $safeDate . '</span>';
}

// ======================== معالجة الطلبات ========================
$action = $_POST['action'] ?? $_GET['action'] ?? '';

// تسجيل الدخول
if ($action === 'patient_login') {
    if (!patient_verify_csrf($_POST['csrf_token'] ?? '')) {
        $loginError = 'طلب غير صالح. يرجى إعادة المحاولة.';
        unset($_SESSION['patient_csrf_token']);
    } else {
        $username = trim($_POST['username'] ?? '');
        $password = $_POST['password'] ?? '';

        $maxAttempts = 5;
        $lockMinutes = 15;
        $_SESSION['patient_login_attempts'] = $_SESSION['patient_login_attempts'] ?? 0;
        $_SESSION['patient_login_lock_until'] = $_SESSION['patient_login_lock_until'] ?? null;

        if (!empty($_SESSION['patient_login_lock_until']) && time() < intval($_SESSION['patient_login_lock_until'])) {
            $remain = ceil((intval($_SESSION['patient_login_lock_until']) - time()) / 60);
            $loginError = "تم قفل تسجيل الدخول مؤقتاً. حاول بعد {$remain} دقيقة.";
        } elseif (empty($username) || empty($password)) {
            $loginError = 'يرجى إدخال اسم المستخدم وكلمة المرور.';
        } else {
            $stmtCheck = $pdo->prepare("SELECT u.*, pa.patient_id, pa.allowed_days, pa.expiry_date FROM admin_users u INNER JOIN patient_accounts pa ON pa.user_id = u.id WHERE u.username = ? AND u.is_active = 1");
            $stmtCheck->execute([$username]);
            $userCheck = $stmtCheck->fetch();

            if ($userCheck && password_verify($password, $userCheck['password_hash'])) {
                if (empty($userCheck['patient_id']) || (int)$userCheck['patient_id'] <= 0) {
                    $_SESSION['patient_login_attempts'] = intval($_SESSION['patient_login_attempts'] ?? 0) + 1;
                    $loginError = 'اسم المستخدم أو كلمة المرور غير صحيحة.';
                } elseif (!$userCheck['is_active']) {
                    $loginError = 'هذا الحساب معطّل. يرجى التواصل مع الإدارة.';
                } elseif (!empty($userCheck['expiry_date']) && $userCheck['expiry_date'] < date('Y-m-d')) {
                    $loginError = 'انتهت صلاحية هذا الحساب. يرجى التواصل مع الإدارة.';
                } else {
                    session_regenerate_id(true);
                    $_SESSION['patient_login_attempts'] = 0;
                    $_SESSION['patient_login_lock_until'] = null;
                    $_SESSION['patient_logged_in'] = true;
                    $_SESSION['patient_user_id'] = $userCheck['id'];
                    $_SESSION['patient_id'] = $userCheck['patient_id'];
                    $_SESSION['patient_display_name'] = $userCheck['display_name'];
                    $_SESSION['patient_username'] = $userCheck['username'];
                    $_SESSION['patient_allowed_days'] = (int)$userCheck['allowed_days'];
                    header('Location: user.php');
                    exit;
                }
            } else {
                $_SESSION['patient_login_attempts'] = intval($_SESSION['patient_login_attempts'] ?? 0) + 1;
                if ($_SESSION['patient_login_attempts'] >= $maxAttempts) {
                    $_SESSION['patient_login_lock_until'] = time() + ($lockMinutes * 60);
                    $_SESSION['patient_login_attempts'] = 0;
                    $loginError = 'تم تجاوز عدد المحاولات المسموح. تم القفل مؤقتاً 15 دقيقة.';
                } else {
                    $loginError = 'اسم المستخدم أو كلمة المرور غير صحيحة.';
                }
            }
        }
    }
}

// تسجيل الخروج
if ($action === 'logout') {
    session_destroy();
    header('Location: user.php');
    exit;
}

// التحقق من حالة الحساب في كل طلب
if (isPatientLoggedIn() && !checkPatientActive($pdo)) {
    header('Location: user.php?disabled=1');
    exit;
}

// جلب إشعارات المستخدم (AJAX)
if ($action === 'get_user_notifications' && isPatientLoggedIn()) {
    header('Content-Type: application/json; charset=utf-8');
    $uid = (int)$_SESSION['patient_user_id'];
    $pdo->exec("CREATE TABLE IF NOT EXISTS user_notifications (
        id INT AUTO_INCREMENT PRIMARY KEY,
        user_id INT NOT NULL,
        message TEXT NOT NULL,
        is_read TINYINT(1) DEFAULT 0,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES admin_users(id) ON DELETE CASCADE
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci");
    $stmt = $pdo->prepare("SELECT * FROM user_notifications WHERE user_id = ? ORDER BY created_at DESC LIMIT 20");
    $stmt->execute([$uid]);
    $notifs = $stmt->fetchAll();
    $unreadStmt = $pdo->prepare("SELECT COUNT(*) FROM user_notifications WHERE user_id = ? AND is_read = 0");
    $unreadStmt->execute([$uid]);
    echo json_encode(['success' => true, 'notifications' => $notifs, 'unread_count' => (int)$unreadStmt->fetchColumn()]);
    exit;
}

// تحديد الإشعارات كمقروءة (AJAX)
if ($action === 'mark_user_notifications_read' && isPatientLoggedIn()) {
    header('Content-Type: application/json; charset=utf-8');
    $uid = (int)$_SESSION['patient_user_id'];
    $pdo->prepare("UPDATE user_notifications SET is_read = 1 WHERE user_id = ?")->execute([$uid]);
    echo json_encode(['success' => true]);
    exit;
}

// جلب الأطباء حسب المستشفى (AJAX)
if ($action === 'get_doctors_by_hospital' && isPatientLoggedIn()) {
    header('Content-Type: application/json; charset=utf-8');
    $hospitalId = (int)($_GET['hospital_id'] ?? 0);
    $stmt = $pdo->prepare("SELECT id, name_ar, title_ar FROM doctors WHERE hospital_id = ? ORDER BY name_ar");
    $stmt->execute([$hospitalId]);
    echo json_encode(['success' => true, 'doctors' => $stmt->fetchAll()]);
    exit;
}

// إنشاء إجازة مرضية حقيقية (AJAX)
if ($action === 'create_sick_leave' && isPatientLoggedIn()) {
    header('Content-Type: application/json; charset=utf-8');

    $patientId = (int)$_SESSION['patient_id'];
    $userId    = (int)$_SESSION['patient_user_id'];

    $paStmt = $pdo->prepare("SELECT allowed_days FROM patient_accounts WHERE user_id = ?");
    $paStmt->execute([$userId]);
    $paRow = $paStmt->fetch();
    $allowedDays = $paRow ? (int)$paRow['allowed_days'] : 0;
    $_SESSION['patient_allowed_days'] = $allowedDays;

    $hospitalId  = (int)($_POST['hospital_id'] ?? 0);
    $doctorId    = (int)($_POST['doctor_id'] ?? 0);
    $startDate   = trim($_POST['start_date'] ?? '');
    $endDate     = trim($_POST['end_date'] ?? '');
    $daysCount   = (int)($_POST['days_count'] ?? 0);
    $timeMode    = in_array($_POST['time_mode'] ?? '', ['auto','random','manual']) ? $_POST['time_mode'] : 'auto';
    $manualTime  = trim($_POST['manual_time'] ?? '');
    $manualPeriod = in_array(strtoupper($_POST['manual_period'] ?? ''), ['AM','PM']) ? strtoupper($_POST['manual_period']) : 'AM';

    if (!$hospitalId || !$doctorId || !$startDate || !$endDate || $daysCount <= 0) {
        echo json_encode(['success' => false, 'message' => 'يرجى تعبئة جميع الحقول المطلوبة.']);
        exit;
    }

    $usedDays = getUsedDaysUser($pdo, $patientId, $userId);
    $remainingDays = $allowedDays - $usedDays;

    if ($daysCount > $remainingDays) {
        echo json_encode(['success' => false, 'message' => "عدد الأيام المطلوبة ($daysCount) يتجاوز الحصة المتبقية ($remainingDays يوم)."]);
        exit;
    }

    $issueTime = null;
    $issuePeriod = null;

    if ($timeMode === 'auto') {
        $now = new DateTime('now', new DateTimeZone('Asia/Riyadh'));
        $h = (int)$now->format('H');
        $issuePeriod = $h >= 12 ? 'PM' : 'AM';
        $h12 = $h > 12 ? $h - 12 : ($h === 0 ? 12 : $h);
        $issueTime = sprintf('%02d:%02d', $h12, (int)$now->format('i'));
    } elseif ($timeMode === 'random') {
        $randomHour = rand(8, 17);
        $randomMin  = rand(0, 59);
        $issuePeriod = $randomHour >= 12 ? 'PM' : 'AM';
        $h12 = $randomHour > 12 ? $randomHour - 12 : ($randomHour === 0 ? 12 : $randomHour);
        $issueTime = sprintf('%02d:%02d', $h12, $randomMin);
    } elseif ($timeMode === 'manual' && $manualTime) {
        $issueTime   = $manualTime;
        $issuePeriod = $manualPeriod;
    }

    $hospStmt = $pdo->prepare("SELECT * FROM hospitals WHERE id = ? AND deleted_at IS NULL");
    $hospStmt->execute([$hospitalId]);
    $hosp = $hospStmt->fetch();

    $docStmt = $pdo->prepare("SELECT * FROM doctors WHERE id = ? AND hospital_id = ?");
    $docStmt->execute([$doctorId, $hospitalId]);
    $doc = $docStmt->fetch();

    $patStmt = $pdo->prepare("SELECT * FROM patients WHERE id = ?");
    $patStmt->execute([$patientId]);
    $pat = $patStmt->fetch();

    if (!$hosp || !$doc || !$pat) {
        echo json_encode(['success' => false, 'message' => 'بيانات غير صالحة. يرجى المحاولة مجدداً.']);
        exit;
    }

    $prefix = $hosp['service_prefix'] ?? 'GSL';
    $serviceCode = generateServiceCodeUser($pdo, $prefix, $startDate);

    // في بوابة المرضى يكون تاريخ الإصدار مطابقاً لتاريخ بداية الإجازة الذي اختاره المريض.
    $issueDate = $startDate;
    $stmt = $pdo->prepare("INSERT INTO sick_leaves 
        (service_code, patient_id, doctor_id, hospital_id, created_by_user_id,
         issue_date, issue_time, issue_period, start_date, end_date, days_count,
         patient_name_en, doctor_name_en, doctor_title_en,
         hospital_name_ar, hospital_name_en, logo_path,
         employer_ar, employer_en, is_paid, payment_amount)
        VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)");
    $stmt->execute([
        $serviceCode,
        $patientId,
        $doctorId,
        $hospitalId,
        $userId,
        $issueDate,
        $issueTime,
        $issuePeriod,
        $startDate,
        $endDate,
        $daysCount,
        $pat['name_en'] ?? '',
        $doc['name_en'] ?? '',
        $doc['title_en'] ?? '',
        $hosp['name_ar'] ?? '',
        $hosp['name_en'] ?? '',
        $hosp['logo_url'] ?? $hosp['logo_path'] ?? '',
        $pat['employer_ar'] ?? '',
        $pat['employer_en'] ?? '',
        1,
        0,
    ]);
    $leaveId = (int)$pdo->lastInsertId();

    echo json_encode([
        'success'        => true,
        'message'        => 'تم إنشاء الإجازة المرضية بنجاح وتوثيقها في السجل.',
        'leave_id'       => $leaveId,
        'service_code'   => $serviceCode,
        'remaining_days' => $remainingDays - $daysCount,
    ]);
    exit;
}

// توليد PDF للإجازة
if ($action === 'generate_pdf' && isPatientLoggedIn()) {
    $baseUrl = (isset($_SERVER['HTTPS']) && $_SERVER['HTTPS'] === 'on' ? 'https' : 'http') . '://' . $_SERVER['HTTP_HOST'] . dirname($_SERVER['SCRIPT_NAME']) . '/';
    $leaveId = (int)($_GET['leave_id'] ?? 0);
    $userId  = (int)$_SESSION['patient_user_id'];
    $patientId = (int)$_SESSION['patient_id'];
    $pdfMode = 'download'; // Patient portal never exposes preview mode, even if the URL is manually changed.
    if (!patient_verify_csrf($_GET['csrf_token'] ?? '')) {
        http_response_code(403);
        exit('Forbidden');
    }

    $stmt = $pdo->prepare("
        SELECT sl.*,
               p.name_ar AS p_name_ar, p.name_en AS p_name_en, p.identity_number,
               p.employer_ar AS p_employer_ar, p.employer_en AS p_employer_en,
               p.nationality_ar AS p_nationality_ar, p.nationality_en AS p_nationality_en,
               d.name_ar AS d_name_ar, d.name_en AS d_name_en,
               d.title_ar AS d_title_ar, d.title_en AS d_title_en,
               h.name_ar AS h_name_ar, h.name_en AS h_name_en,
               h.license_number AS h_license,
               h.logo_data AS h_logo_data, h.logo_url AS h_logo_url, h.logo_path AS h_logo_path,
               h.logo_scale AS h_logo_scale, h.logo_offset_x AS h_logo_offset_x, h.logo_offset_y AS h_logo_offset_y
        FROM sick_leaves sl
        LEFT JOIN patients p ON sl.patient_id = p.id
        LEFT JOIN doctors d ON sl.doctor_id = d.id
        LEFT JOIN hospitals h ON sl.hospital_id = h.id
        WHERE sl.id = ? AND sl.patient_id = ? AND sl.created_by_user_id = ? AND sl.deleted_at IS NULL
    ");
    $stmt->execute([$leaveId, $patientId, $userId]);
    $lv = $stmt->fetch();

    if (!$lv) {
        echo '<h2 style="text-align:center;padding:50px;font-family:sans-serif;">الإجازة غير موجودة</h2>';
        exit;
    }

    $sc       = htmlspecialchars($lv['service_code'] ?? '', ENT_QUOTES);
    $days     = (int)($lv['days_count'] ?? 1);
    $daysEn   = $days . ($days === 1 ? ' day' : ' days');
    $daysAr   = (string)$days;
    $daysArWord = 'يوم';

    $startG = $lv['start_date'] ?? '';
    $endG   = $lv['end_date'] ?? '';
    $issueG = $lv['issue_date'] ?? date('Y-m-d');

    $startEn  = fmtDateEnUser($startG);
    $endEn    = fmtDateEnUser($endG);
    $issueEn  = fmtDateEnUser($issueG);
    // في تقارير بوابة المرضى: تاريخ الخروج يساوي تاريخ الدخول، مع بقاء فترة الإجازة حسب البداية والنهاية.
    $dischargeEn = fmtDateEnUser($startG);
    $startHj  = toHijriStrUser($startG);
    $endHj    = toHijriStrUser($endG);
    $dischargeHj = toHijriStrUser($startG);

    $patNameAr = htmlspecialchars($lv['p_name_ar'] ?? '', ENT_QUOTES);
    $patNameEn = strtoupper(htmlspecialchars($lv['p_name_en'] ?? '', ENT_QUOTES));
    $patId     = htmlspecialchars($lv['identity_number'] ?? '', ENT_QUOTES);
    $natAr     = htmlspecialchars($lv['p_nationality_ar'] ?? '', ENT_QUOTES);
    $natEn     = htmlspecialchars($lv['p_nationality_en'] ?? '', ENT_QUOTES);
    $empArRaw  = $lv['p_employer_ar'] ?? $lv['employer_ar'] ?? '';
    $empEnRaw  = $lv['p_employer_en'] ?? $lv['employer_en'] ?? '';
    $empAr     = htmlspecialchars($empArRaw !== '' ? $empArRaw : 'الى من يهمه الامر', ENT_QUOTES);
    $empEn     = htmlspecialchars($empEnRaw !== '' ? $empEnRaw : 'To Whom It May Concern', ENT_QUOTES);
    $docNameAr = htmlspecialchars($lv['d_name_ar'] ?? '', ENT_QUOTES);
    $docNameEn = strtoupper(htmlspecialchars($lv['d_name_en'] ?? '', ENT_QUOTES));
    $docTitleAr = htmlspecialchars($lv['d_title_ar'] ?? '', ENT_QUOTES);
    $docTitleEn = htmlspecialchars($lv['d_title_en'] ?? '', ENT_QUOTES);
    $hospNameAr = htmlspecialchars($lv['h_name_ar'] ?? '', ENT_QUOTES);
    $hospNameEn = htmlspecialchars($lv['h_name_en'] ?? '', ENT_QUOTES);
    $hospLicense = $lv['h_license'] ?? '';

    $hospLogoData = $lv['h_logo_data'] ?? '';
    $hospLogoUrl  = $lv['h_logo_url'] ?? '';
    $hospLogoPath = $lv['h_logo_path'] ?? '';
    $defaultLogo  = 'https://upload.wikimedia.org/wikipedia/ar/thumb/f/fe/Saudi_Ministry_of_Health_Logo.svg/3840px-Saudi_Ministry_of_Health_Logo.svg.png';
    $logoSrc = $defaultLogo;
    if (!empty($hospLogoData) && strpos($hospLogoData, 'data:image/') === 0) {
        $logoSrc = $hospLogoData;
    } elseif ($hospLogoPath && strpos($hospLogoPath, 'http') === 0) {
        $logoSrc = $hospLogoPath;
    } elseif ($hospLogoUrl && strpos($hospLogoUrl, 'http') === 0) {
        $logoSrc = $hospLogoUrl;
    }
    $hLogoScale = floatval($lv['h_logo_scale'] ?? 1);
    $hLogoOffX  = floatval($lv['h_logo_offset_x'] ?? 0);
    $hLogoOffY  = floatval($lv['h_logo_offset_y'] ?? 0);
    $logoTransform = "transform: translate({$hLogoOffX}px, {$hLogoOffY}px) scale({$hLogoScale});";
    $hospLogoHtml = '<div style="width:120px;height:120px;overflow:hidden;position:relative;"><img src="' . htmlspecialchars($logoSrc) . '" alt="Hospital Logo" style="width:100%;height:100%;object-fit:contain;position:absolute;top:0;left:0;' . $logoTransform . '" /></div>';

    $licenseHtml = '';
    if (!empty($hospLicense)) {
        $licenseHtml = '<span dir="rtl" style="direction:rtl;unicode-bidi:isolate;display:inline-block;font-weight:700;white-space:nowrap;"><span style="font-family: \'Noto Sans Arabic\', sans-serif;">رقم الترخيص:</span> <bdi dir="ltr" style="font-family: \'Times New Roman\', serif; direction:ltr; unicode-bidi:isolate;">' . htmlspecialchars($hospLicense, ENT_QUOTES, 'UTF-8') . '</bdi></span>';
    }

    $issuePeriod = $lv['issue_period'] ?? 'AM';
    $issueTimeRaw = $lv['issue_time'] ?? '09:00';
    if (preg_match('/^(\d{1,2}):(\d{2})/', $issueTimeRaw, $tm)) {
        $h = (int)$tm[1]; $mn = (int)$tm[2];
        if ($h > 12) $h -= 12;
        elseif ($h === 0) $h = 12;
        $issueTimeDisplay = sprintf('%02d:%02d', $h, $mn);
    } else {
        $issueTimeDisplay = $issueTimeRaw;
    }

    $issueDateObj = DateTime::createFromFormat('Y-m-d', $issueG);
    $dayNameEn   = $issueDateObj ? $issueDateObj->format('l') : '';
    $monthNameEn = $issueDateObj ? $issueDateObj->format('F') : '';
    $dayNum      = $issueDateObj ? $issueDateObj->format('d') : '';
    $yearNum     = $issueDateObj ? $issueDateObj->format('Y') : '';
    $timestampLine = $issueTimeDisplay . ' ' . $issuePeriod;
    $dateLine      = $dayNameEn . ', ' . $dayNum . ' ' . $monthNameEn . ' ' . $yearNum;

    $durationEn = $daysEn . ' ( ' . $startEn . ' to ' . $endEn . ' )';
  $durationAr = '<span style="font-family: \'Times New Roman\', serif; font-size: 13.5px; font-weight: 400;">' . $daysAr . '</span> <span style="font-family: \'Noto Sans Arabic\', sans-serif; font-size: 14.5px; font-weight: 400;">' . $daysArWord . '</span> <span style="font-family: \'Times New Roman\', serif; font-size: 13.5px; font-weight: 400;">(</span> <span dir="ltr" style="unicode-bidi:isolate;direction:ltr;display:inline-block;font-family: \'Times New Roman\', serif; font-size: 13.5px; font-weight: 400;">' . htmlspecialchars($startHj, ENT_QUOTES, 'UTF-8') . '</span> <span style="font-family: \'Noto Sans Arabic\', sans-serif; font-size: 13.5px; font-weight: 400;">إلى</span> <span dir="ltr" style="unicode-bidi:isolate;direction:ltr;display:inline-block;font-family: \'Times New Roman\', serif; font-size: 13.5px; font-weight: 400;">' . htmlspecialchars($endHj, ENT_QUOTES, 'UTF-8') . '</span> <span style="font-family: \'Times New Roman\', serif; font-size: 13.5px; font-weight: 400;">)</span>';

    // PDF download mode - use same template as admin
    if ($pdfMode === 'download') {

        $pdfHtml  = '<!DOCTYPE html><html lang="ar"><head><meta charset="utf-8"/>';
        $pdfHtml .= '<title>Sick Leave Report</title>';
        $pdfHtml .= '<link rel="stylesheet" href="https://fonts.googleapis.com/css2?family=Inter:wght@100;200;300;400;500;600;700&display=swap" />';
        $pdfHtml .= '<link rel="stylesheet" href="https://fonts.googleapis.com/css2?family=STIX+Two+Text:ital,wght@0,400;0,600;0,700;1,400&display=swap" />';
        $pdfHtml .= '<link rel="stylesheet" href="https://fonts.googleapis.com/css2?family=Noto+Sans+Arabic:wght@400;600;700&display=swap" />';
        $pdfHtml .= '<style data-tag="reset-style-sheet">html{line-height:1.15}body{margin:0}*{box-sizing:border-box;border-width:0;border-style:solid}p,li,ul,pre,div,h1,h2,h3,h4,h5,h6,figure,blockquote,figcaption{margin:0;padding:0}a{color:inherit;text-decoration:inherit}</style>';
        $pdfHtml .= '<style data-tag="default-style-sheet">html{font-family:Inter,sans-serif;font-size:16px}body{font-weight:400;color:#191818;background:#ffffff;margin:0;padding:0}</style>';
        $pdfHtml .= '<style>';
        $pdfHtml .= '@font-face { font-family: "Times New Roman"; src: url("' . $baseUrl . 'times_regular.otf") format("opentype"); font-weight: 400; font-style: normal; }';
        $pdfHtml .= '@font-face { font-family: "Times New Roman"; src: url("' . $baseUrl . 'times_bold.otf") format("opentype"); font-weight: 700; font-style: normal; }';
        $pdfHtml .= '</style>';
        $pdfHtml .= '<style>';
        $pdfHtml .= '@page { size: 842.25px 1190.25px; margin: 0; }';
        $pdfHtml .= '.group1-container1 { width: 842.25px; height: 1190.25px; position: relative; background-color: transparent; margin: 0; padding: 0; }';
        $pdfHtml .= '.group1-thq-group1-elm { width: 842.25px; height: 1190.25px; position: relative; background-color: white; margin: 0; padding: 0; }';
        $pdfHtml .= '.info-table { position: absolute; top: 242px; left: 36px; width: 770px; border-collapse: separate; border-spacing: 0; border: 1px solid #cccccc; border-radius: 8px; overflow: hidden; background-color: transparent; z-index: 10; }';
        $pdfHtml .= '.info-table td { border-bottom: 1px solid #cccccc; border-right: 1px solid #cccccc; height: 42px; text-align: center; vertical-align: middle; padding: 4px 8px; }';
        $pdfHtml .= '.info-table td:last-child { border-right: none; } .info-table tr:last-child td { border-bottom: none; }';
        $pdfHtml .= '.info-table .en-title { width: 161px; color: rgba(54, 111, 181, 1); font-size: 13.5px; font-weight: 700; text-align: center; font-family: "Times New Roman", serif; }';
        $pdfHtml .= '.info-table .data-cell { width: 240px; color: rgba(44, 62, 119, 1); font-size: 13.5px; font-family: "Times New Roman", serif; font-weight: 400; text-align: center; }';
        $pdfHtml .= '.info-table .date-cell { font-size: 13.9px; } .info-table .data-cell.ar-text { font-family: "Noto Sans Arabic", sans-serif; }';
        $pdfHtml .= '.info-table .ar-title { width: 140px; color: rgba(54, 111, 181, 1); font-size: 13.5px; font-weight: 700; text-align: center; font-family: "Noto Sans Arabic", sans-serif; white-space: nowrap; }';
        $pdfHtml .= '.info-table tr.blue-row td { background-color: #2c3e77; color: #ffffff; }';
        $pdfHtml .= '.info-table .blue-row .data-cell { color: rgba(255, 255, 255, 1); }';
        $pdfHtml .= '.info-table tr.gray-row td { background-color: #f7f7f7; }';
        $pdfHtml .= ':root { --footer-offset: 40px; }';
        $pdfHtml .= '.group1-thq-staticinfo-elm { top: 125px; left: 36.65px; width: 768.35px; height: 811.91px; display: flex; position: absolute; align-items: flex-start; pointer-events: none; }';
        $pdfHtml .= '.top-right-placeholder { position: absolute; top: 36px; left: 543.36px; width: 262.43px; height: 107.22px; display: flex; align-items: center; justify-content: center; z-index: 5; }';
        $pdfHtml .= '.top-left-placeholder { position: absolute; top: 36px; left: 36px; width: 149.96px; height: 65.98px; display: flex; align-items: center; justify-content: center; z-index: 5; }';
        $pdfHtml .= '.bottom-right-placeholder { position: absolute; top: 980px; left: 657.17px; width: 149.96px; height: 71.23px; display: flex; align-items: center; justify-content: center; z-index: 5; }';
        $pdfHtml .= '.header-placeholder { top: -50px; left: 303px; width: 163px; height: 40px; position: absolute; display: flex; align-items: center; justify-content: center; }';
        $pdfHtml .= '.group1-thq-text-elm41 { top: 40px; left: 281px; color: rgba(48, 109, 181, 1); width: 215px; position: absolute; font-size: 22.5px; font-weight: 700; text-align: center; line-height: 30px; }';
        $pdfHtml .= '.group1-thq-text-elm44 { top: -10px; left: 293px; color: rgba(0, 0, 0, 1); position: absolute; font-size: 17.3px; font-weight: 400; font-family: "Times New Roman", serif; }';
        $pdfHtml .= '.group1-thq-hospitallogoandthename-elm { top: 760px; left: 438.94px; width: 403px; height: 202.78px; display: flex; position: absolute; align-items: flex-start; }';
        $pdfHtml .= '.placeholder-logo-hospital { top: -12px; left: 133px; width: 136px; height: 136px; position: absolute; display: flex; align-items: center; justify-content: center; }';
        $pdfHtml .= '.group1-thq-text-elm18 { top: 113px; color: rgba(0, 0, 0, 1); width: 403px; height: auto; position: absolute; font-size: 12.8px; text-align: center; line-height: 22px; }';
        $pdfHtml .= '.group1-thq-thedateofissueandalsotimeofissue-elm { top: calc(950px + var(--footer-offset)); left: 37.37px; width: 250px; height: 56px; display: flex; position: absolute; align-items: flex-start; }';
        $pdfHtml .= '.group1-thq-text-elm22 { color: rgba(0, 0, 0, 1); font-size: 12.5px; font-weight: 700; text-align: left; line-height: 28px; font-family: "Times New Roman", serif; position: absolute; white-space: nowrap; }';
        $pdfHtml .= '.group1-thq-text-elm36 { top: calc(680px + var(--footer-offset)); left: 29.23px; color: rgba(0, 0, 0, 1); position: absolute; font-size: 12px; font-weight: 700; text-align: center; font-family: "Noto Sans Arabic", sans-serif; line-height: 23px; }';
        $pdfHtml .= '.group1-thq-text-elm39 { top: calc(728px + var(--footer-offset)); left: 55px; color: rgba(0, 0, 0, 1); position: absolute; font-size: 12px; font-weight: 700; font-family: "Times New Roman", serif; }';
        $pdfHtml .= '.group1-thq-text-elm40 { top: calc(750px + var(--footer-offset)); left: 108.35px; color: rgba(20, 0, 255, 1); position: absolute; font-size: 11px; font-weight: 700; text-decoration: underline; pointer-events: auto; font-family: "Times New Roman", serif; }';
        $pdfHtml .= '.placeholder-136 { position: absolute; top: 607px; left: 137px; width: 103.9px; height: 103.9px; display: flex; align-items: center; justify-content: center; pointer-events: auto; }';
        $pdfHtml .= '.vertical-divider { position: absolute; top: 723px; left: 431px; width: 1.5px; height: 6cm; background-color: #dddddd; }';
        $pdfHtml .= '.thin-slash { font-weight: 300; font-family: "Inter", sans-serif; margin: 0 3px; display: inline-block; }';
        $pdfHtml .= '</style></head><body>';

        $pdfHtml .= '<div class="group1-container1"><div class="group1-thq-group1-elm">';
        $pdfHtml .= '<div class="top-right-placeholder"><img src="' . $baseUrl . 'sehalogoright.png" style="width:100%;height:100%"/></div>';
        $pdfHtml .= '<div class="top-left-placeholder"><img src="' . $baseUrl . 'sehalogoleft.png" style="width:100%;height:100%"/></div>';
        $pdfHtml .= '<div class="bottom-right-placeholder"><img src="' . $baseUrl . 'bottomright.png" style="width:100%;height:100%"/></div>';
        $pdfHtml .= '<div class="group1-thq-staticinfo-elm">';
        $pdfHtml .= '<div class="header-placeholder"><img src="' . $baseUrl . 'header.png" style="width:100%;height:100%"/></div>';
        $pdfHtml .= '<span class="group1-thq-text-elm41"><span style="font-size:22.5px;font-family:\'Noto Sans Arabic\',sans-serif;font-weight:700;color:#306db5">تقرير إجازة مرضية</span><br/><span style="font-size:18.7px;font-family:\'Times New Roman\',serif;font-weight:700;color:#2c3e77">Sick Leave Report</span></span>';
        $pdfHtml .= '<span class="group1-thq-text-elm44">Kingdom of Saudi Arabia</span>';
        $pdfHtml .= '<div class="placeholder-136"><img src="' . $baseUrl . 'qr.svg" style="width:103.9px;height:103.9px"/></div>';
        $pdfHtml .= '<span class="group1-thq-text-elm36" dir="rtl">للتحقق من بيانات التقرير يرجى التأكد من زيارة موقع منصة صحة<br/>الرسمي</span>';
        $pdfHtml .= '<span class="group1-thq-text-elm39">To check the report please visit Seha\'s official website</span>';
        $pdfHtml .= '<span class="group1-thq-text-elm40"><a href="https://seha-sa-inquiries-slenquiry.up.railway.app/" target="_blank">www.seha.sa/#/inquiries/slenquiry</a></span>';
        $pdfHtml .= '</div>';
        $pdfHtml .= '<table class="info-table" cellpadding="0" cellspacing="0"><tbody>';
        $pdfHtml .= '<tr><td class="en-title">Leave ID</td><td class="data-cell" colspan="2">' . $sc . '</td><td class="ar-title">رمز الإجازة</td></tr>';
        $pdfHtml .= '<tr class="blue-row"><td class="en-title" style="color:white">Leave Duration</td><td class="data-cell">' . $durationEn . '</td><td class="data-cell ar-text" dir="rtl">' . $durationAr . '</td><td class="ar-title" style="color:white">مدة الإجازة</td></tr>';
        $pdfHtml .= '<tr><td class="en-title">Admission Date</td><td class="data-cell date-cell">' . $startEn . '</td><td class="data-cell date-cell" dir="ltr">' . $startHj . '</td><td class="ar-title">تاريخ الدخول</td></tr>';
        $pdfHtml .= '<tr class="gray-row"><td class="en-title">Discharge Date</td><td class="data-cell date-cell">' . $dischargeEn . '</td><td class="data-cell date-cell" dir="ltr">' . $dischargeHj . '</td><td class="ar-title">تاريخ الخروج</td></tr>';
        $pdfHtml .= '<tr><td class="en-title">Issue Date</td><td class="data-cell" colspan="2">' . $issueEn . '</td><td class="ar-title">تاريخ الإصدار</td></tr>';
        $pdfHtml .= '<tr class="gray-row"><td class="en-title">Patient Name</td><td class="data-cell en-spaced">' . $patNameEn . '</td><td class="data-cell ar-text">' . $patNameAr . '</td><td class="ar-title">الاسم</td></tr>';
        $pdfHtml .= '<tr><td class="en-title">National ID / Iqama</td><td class="data-cell" colspan="2">' . $patId . '</td><td class="ar-title">الإقامة<span class="thin-slash">/</span>رقم الهوية</td></tr>';
        $pdfHtml .= '<tr class="gray-row"><td class="en-title">Nationality</td><td class="data-cell en-spaced">' . $natEn . '</td><td class="data-cell ar-text">' . $natAr . '</td><td class="ar-title">الجنسية</td></tr>';
        $pdfHtml .= '<tr><td class="en-title">Employer</td><td class="data-cell en-spaced">' . $empEn . '</td><td class="data-cell ar-text">' . $empAr . '</td><td class="ar-title">جهة العمل</td></tr>';
        $pdfHtml .= '<tr class="gray-row"><td class="en-title">Practitioner Name</td><td class="data-cell en-spaced">' . $docNameEn . '</td><td class="data-cell ar-text">' . $docNameAr . '</td><td class="ar-title">اسم الممارس</td></tr>';
        $pdfHtml .= '<tr><td class="en-title">Position</td><td class="data-cell en-spaced">' . $docTitleEn . '</td><td class="data-cell ar-text">' . $docTitleAr . '</td><td class="ar-title">المسمى الوظيفي</td></tr>';
        $pdfHtml .= '</tbody></table>';
        $pdfHtml .= '<div class="vertical-divider"></div>';
        $pdfHtml .= '<div class="group1-thq-hospitallogoandthename-elm">';
        $pdfHtml .= '<div class="placeholder-logo-hospital">' . $hospLogoHtml . '</div>';
        $pdfHtml .= '<span class="group1-thq-text-elm18"><span style="font-family:\'Noto Sans Arabic\',sans-serif;font-weight:700">' . $hospNameAr . '</span><br/><span style="font-family:\'Times New Roman\',serif;font-weight:700">' . $hospNameEn . '</span><br/>' . $licenseHtml . '</span>';
        $pdfHtml .= '</div>';
        $pdfHtml .= '<div class="group1-thq-thedateofissueandalsotimeofissue-elm"><span class="group1-thq-text-elm22"><span>' . $timestampLine . '</span><br/><span>' . $dateLine . '</span></span></div>';
        $pdfHtml .= '</div></div></body></html>';

        $tmpDir = '/tmp/weasyprint';
        if (!is_dir($tmpDir)) mkdir($tmpDir, 0755, true);
        $htmlFile = $tmpDir . '/leave_' . $leaveId . '_' . time() . '.html';
        $pdfFile  = $tmpDir . '/leave_' . $leaveId . '_' . time() . '.pdf';
        file_put_contents($htmlFile, $pdfHtml);

        $scriptPath = __DIR__ . '/generate_pdf.py';
        $cmd = "python3 " . escapeshellarg($scriptPath) . " " . escapeshellarg($htmlFile) . " " . escapeshellarg($pdfFile) . " 2>&1";
        $output = shell_exec($cmd);

        if (file_exists($pdfFile) && filesize($pdfFile) > 0) {
            header('Content-Type: application/pdf');
            header('Content-Disposition: attachment; filename="sickLeaves.pdf"');
            header('Content-Length: ' . filesize($pdfFile));
            header('Cache-Control: no-store, no-cache, must-revalidate, max-age=0');
            header('Pragma: no-cache');
            header('X-Content-Type-Options: nosniff');
            readfile($pdfFile);
            @unlink($htmlFile);
            @unlink($pdfFile);
        } else {
            echo '<h2 style="text-align:center;padding:50px;font-family:sans-serif;">تعذّر إنشاء ملف PDF</h2>';
            echo '<pre>' . htmlspecialchars($output ?? '') . '</pre>';
        }
        exit;
    }

    // Preview mode - show HTML report with download button
    ?><!DOCTYPE html><html lang="ar"><head><meta charset="utf-8"/><meta name="viewport" content="width=device-width,initial-scale=1"/>
<title>Sick Leave Report - <?= $sc ?></title>
<link rel="stylesheet" href="https://fonts.googleapis.com/css2?family=Inter:wght@100;200;300;400;500;600;700&display=swap"/>
<link rel="stylesheet" href="https://fonts.googleapis.com/css2?family=Noto+Sans+Arabic:wght@400;600;700&display=swap"/>
<style>
*{box-sizing:border-box;margin:0;padding:0}body{background:#1e293b;margin:0;padding:40px 20px;font-family:Inter,sans-serif}
.group1-container1{max-width:842.25px;margin:0 auto;padding:20px 0}
.group1-thq-group1-elm{width:842.25px;height:1190.25px;position:relative;background:white;box-shadow:0 25px 80px rgba(0,0,0,0.4);border-radius:4px;margin:0 auto}
.info-table{position:absolute;top:242px;left:36px;width:770px;border-collapse:separate;border-spacing:0;border:1px solid #ccc;border-radius:8px;overflow:hidden;z-index:10}
.info-table td{border-bottom:1px solid #ccc;border-right:1px solid #ccc;height:42px;text-align:center;vertical-align:middle;padding:4px 8px}
.info-table td:last-child{border-right:none}.info-table tr:last-child td{border-bottom:none}
.info-table .en-title{width:161px;color:rgba(54,111,181,1);font-size:13.5px;font-weight:700;font-family:"Times New Roman",serif}
.info-table .data-cell{width:240px;color:rgba(44,62,119,1);font-size:13.5px;font-family:"Times New Roman",serif;font-weight:400}
.info-table .data-cell.ar-text{font-family:"Noto Sans Arabic",sans-serif}
.info-table .ar-title{width:140px;color:rgba(54,111,181,1);font-size:13.5px;font-weight:700;font-family:"Noto Sans Arabic",sans-serif;white-space:nowrap}
.info-table tr.blue-row td{background:#2c3e77;color:#fff}.info-table .blue-row .data-cell{color:#fff}
.info-table tr.gray-row td{background:#f7f7f7}
:root{--footer-offset:40px}
.group1-thq-staticinfo-elm{top:125px;left:36.65px;width:768.35px;height:811.91px;display:flex;position:absolute;align-items:flex-start;pointer-events:none}
.top-right-placeholder{position:absolute;top:36px;left:543.36px;width:262.43px;height:107.22px;display:flex;align-items:center;justify-content:center;z-index:5}
.top-left-placeholder{position:absolute;top:36px;left:36px;width:149.96px;height:65.98px;display:flex;align-items:center;justify-content:center;z-index:5}
.bottom-right-placeholder{position:absolute;top:1005px;left:657.17px;width:149.96px;height:71.23px;display:flex;align-items:center;justify-content:center;z-index:5}
.header-placeholder{top:-50px;left:312px;width:163px;height:40px;position:absolute;display:flex;align-items:center;justify-content:center}
.group1-thq-text-elm41{top:40px;left:281px;color:rgba(48,109,181,1);width:215px;position:absolute;font-size:22.5px;font-weight:700;text-align:center;line-height:30px}
.group1-thq-text-elm44{top:-10px;left:297px;color:#000;position:absolute;font-size:17.3px;font-weight:400;font-family:"Times New Roman",serif}
.group1-thq-hospitallogoandthename-elm{top:760px;left:438.94px;width:403px;height:202.78px;display:flex;position:absolute;align-items:flex-start}
.placeholder-logo-hospital{top:-12px;left:133px;width:136px;height:136px;position:absolute;display:flex;align-items:center;justify-content:center}
.group1-thq-text-elm18{top:113px;color:#000;width:403px;height:auto;position:absolute;font-size:12.8px;text-align:center;line-height:22px}
.group1-thq-thedateofissueandalsotimeofissue-elm{top:calc(989.85px + var(--footer-offset));left:37.37px;width:250px;height:56px;display:flex;position:absolute;align-items:flex-start}
.group1-thq-text-elm22{color:#000;font-size:12.5px;font-weight:700;text-align:left;line-height:28px;font-family:"Times New Roman",serif;position:absolute;white-space:nowrap}
.group1-thq-text-elm36{top:calc(724.55px + var(--footer-offset));left:29.23px;color:#000;position:absolute;font-size:12px;font-weight:700;text-align:center;font-family:"Noto Sans Arabic",sans-serif;line-height:23px}
.group1-thq-text-elm39{top:calc(770px + var(--footer-offset));left:55px;color:#000;position:absolute;font-size:12px;font-weight:700;font-family:"Times New Roman",serif}
.group1-thq-text-elm40{top:calc(791px + var(--footer-offset));left:108.35px;color:rgba(20,0,255,1);position:absolute;font-size:11px;font-weight:700;text-decoration:underline;pointer-events:auto;font-family:"Times New Roman",serif}
.placeholder-136{position:absolute;top:620px;left:122px;width:136px;height:136px;display:flex;align-items:center;justify-content:center;pointer-events:auto}
.vertical-divider{position:absolute;top:735px;left:431px;width:1px;height:6.8cm;background:#ddd}
.controls{position:fixed;bottom:30px;right:30px;display:flex;gap:15px;z-index:1000}
.download-btn{background:#0d9488;color:#fff;padding:14px 28px;border-radius:12px;border:none;font-size:16px;font-weight:600;cursor:pointer;box-shadow:0 6px 20px rgba(13,148,136,0.3);font-family:Inter,sans-serif;transition:all .3s}
.download-btn:hover{background:#0f766e;transform:translateY(-3px)}
@media screen and (max-width:880px){.group1-container1{padding:10px 0}.group1-thq-group1-elm{transform-origin:top center;transform:scale(calc(100vw / 860));margin-bottom:calc(1190.25px*(100vw/860)-1190.25px)}.controls{bottom:15px;right:15px;left:15px;justify-content:center}.download-btn{width:100%;text-align:center;padding:14px}}
@media print{@page{size:842.25px 1190.25px;margin:0}body{background:white!important}.controls{display:none!important}.group1-container1{padding:0!important}.group1-thq-group1-elm{box-shadow:none!important;margin:0!important;transform:scale(1)!important}}
</style>
<script>
function downloadPDF(){var b=document.getElementById('btnDownloadPDF');b.textContent='جاري التحميل...';b.disabled=true;var u=window.location.href;u=u.indexOf('pdf_mode=')>-1?u.replace(/pdf_mode=[^&]*/,'pdf_mode=download'):u+(u.indexOf('?')>-1?'&':'?')+'pdf_mode=download';var a=document.createElement('a');a.href=u;a.download='';document.body.appendChild(a);a.click();document.body.removeChild(a);setTimeout(function(){b.textContent='تحميل ملف PDF';b.disabled=false},3000)}
</script>
</head><body>
<div class="controls">
  <button id="btnDownloadPDF" class="download-btn" onclick="downloadPDF()">تحميل ملف PDF</button>
  <button class="download-btn" style="background:#1e293b;box-shadow:0 6px 20px rgba(0,0,0,0.2)" onclick="window.print()">طباعة مباشرة</button>
  <button class="download-btn" style="background:#64748b;box-shadow:none" onclick="history.back()">رجوع</button>
</div>
<div class="group1-container1"><div class="group1-thq-group1-elm" id="report-content">
  <div class="top-right-placeholder"><img src="<?= $baseUrl ?>sehalogoright.png" style="width:100%;height:100%" onerror="this.style.display='none'"/></div>
  <div class="top-left-placeholder"><img src="<?= $baseUrl ?>sehalogoleft.png" style="width:100%;height:100%" onerror="this.style.display='none'"/></div>
  <div class="bottom-right-placeholder"><img src="<?= $baseUrl ?>bottomright.png" style="width:100%;height:100%" onerror="this.style.display='none'"/></div>
  <div class="group1-thq-staticinfo-elm">
    <div class="header-placeholder"><img src="<?= $baseUrl ?>header.png" style="width:100%;height:100%" onerror="this.style.display='none'"/></div>
    <span class="group1-thq-text-elm41"><span style="font-size:22.5px;font-family:'Noto Sans Arabic',sans-serif;font-weight:700;color:#0d9488">تقرير إجازة مرضية</span><br/><span style="font-size:18.7px;font-family:'Times New Roman',serif;font-weight:700;color:#1e293b">Sick Leave Report</span></span>
    <span class="group1-thq-text-elm44">Kingdom of Saudi Arabia</span>
    <div class="placeholder-136"><img src="<?= $baseUrl ?>qr.svg" style="width:103.9px;height:103.9px" onerror="this.style.display='none'"/></div>
    <span class="group1-thq-text-elm36" dir="rtl">للتحقق من بيانات التقرير يرجى التأكد من زيارة موقع منصة صحة<br/>الرسمي</span>
    <span class="group1-thq-text-elm39">To check the report please visit Seha's official website</span>
    <span class="group1-thq-text-elm40"><a href="https://seha-sa-inquiries-slenquiry.up.railway.app/" target="_blank">www.seha.sa/#/inquiries/slenquiry</a></span>
  </div>
  <table class="info-table" cellpadding="0" cellspacing="0"><tbody>
    <tr><td class="en-title">Leave ID</td><td class="data-cell" colspan="2"><?= $sc ?></td><td class="ar-title">رمز الإجازة</td></tr>
    <tr class="blue-row"><td class="en-title" style="color:white">Leave Duration</td><td class="data-cell"><?= $durationEn ?></td><td class="data-cell ar-text" dir="rtl"><?= $durationAr ?></td><td class="ar-title" style="color:white">مدة الإجازة</td></tr>
    <tr><td class="en-title">Admission Date</td><td class="data-cell date-cell"><?= $startEn ?></td><td class="data-cell date-cell" dir="ltr"><?= $startHj ?></td><td class="ar-title">تاريخ الدخول</td></tr>
    <tr class="gray-row"><td class="en-title">Discharge Date</td><td class="data-cell date-cell"><?= $dischargeEn ?></td><td class="data-cell date-cell" dir="ltr"><?= $dischargeHj ?></td><td class="ar-title">تاريخ الخروج</td></tr>
    <tr><td class="en-title">Issue Date</td><td class="data-cell" colspan="2"><?= $issueEn ?></td><td class="ar-title">تاريخ الإصدار</td></tr>
    <tr class="gray-row"><td class="en-title">Patient Name</td><td class="data-cell en-spaced"><?= $patNameEn ?></td><td class="data-cell ar-text"><?= $patNameAr ?></td><td class="ar-title">الاسم</td></tr>
    <tr><td class="en-title">National ID / Iqama</td><td class="data-cell" colspan="2"><?= $patId ?></td><td class="ar-title">رقم الهوية / الإقامة</td></tr>
    <tr class="gray-row"><td class="en-title">Nationality</td><td class="data-cell en-spaced"><?= $natEn ?></td><td class="data-cell ar-text"><?= $natAr ?></td><td class="ar-title">الجنسية</td></tr>
    <tr><td class="en-title">Employer</td><td class="data-cell en-spaced"><?= $empEn ?></td><td class="data-cell ar-text"><?= $empAr ?></td><td class="ar-title">جهة العمل</td></tr>
    <tr class="gray-row"><td class="en-title">Practitioner Name</td><td class="data-cell en-spaced"><?= $docNameEn ?></td><td class="data-cell ar-text"><?= $docNameAr ?></td><td class="ar-title">اسم الممارس</td></tr>
    <tr><td class="en-title">Position</td><td class="data-cell en-spaced"><?= $docTitleEn ?></td><td class="data-cell ar-text"><?= $docTitleAr ?></td><td class="ar-title">المسمى الوظيفي</td></tr>
  </tbody></table>
  <div class="vertical-divider"></div>
  <div class="group1-thq-hospitallogoandthename-elm">
    <div class="placeholder-logo-hospital"><?= $hospLogoHtml ?></div>
    <span class="group1-thq-text-elm18"><span style="font-family:'Noto Sans Arabic',sans-serif;font-weight:700"><?= $hospNameAr ?></span><br/><span style="font-family:'Times New Roman',serif;font-weight:700"><?= $hospNameEn ?></span><br/><?php if (!empty($licenseHtml)) echo $licenseHtml; ?></span>
  </div>
  <div class="group1-thq-thedateofissueandalsotimeofissue-elm"><span class="group1-thq-text-elm22"><span><?= $timestampLine ?></span><br/><span><?= $dateLine ?></span></span></div>
</div></div>
</body></html>
<?php
    exit;
}

// ======================== تحميل البيانات للصفحة الرئيسية ========================
$patientData   = null;
$myLeaves      = [];
$hospitals     = [];
$usedDays      = 0;
$allowedDays   = 0;
$remainingDays = 0;

if (isPatientLoggedIn()) {
    $patientId = (int)$_SESSION['patient_id'];
    $userId    = (int)$_SESSION['patient_user_id'];

    $stmt2 = $pdo->prepare("SELECT allowed_days FROM patient_accounts WHERE user_id = ?");
    $stmt2->execute([$userId]);
    $paRow = $stmt2->fetch();
    if ($paRow) {
        $_SESSION['patient_allowed_days'] = (int)$paRow['allowed_days'];
        $allowedDays = (int)$paRow['allowed_days'];
    }

    $stmt = $pdo->prepare("SELECT * FROM patients WHERE id = ?");
    $stmt->execute([$patientId]);
    $patientData = $stmt->fetch();

    $stmt = $pdo->prepare("
        SELECT sl.*, h.name_ar AS h_name_ar, d.name_ar AS d_name_ar, d.title_ar AS d_title_ar
        FROM sick_leaves sl
        LEFT JOIN hospitals h ON sl.hospital_id = h.id
        LEFT JOIN doctors d ON sl.doctor_id = d.id
        WHERE sl.patient_id = ? AND sl.created_by_user_id = ? AND sl.deleted_at IS NULL
        ORDER BY sl.created_at DESC
    ");
    $stmt->execute([$patientId, $userId]);
    $myLeaves = $stmt->fetchAll();

    $hospitals = $pdo->query("SELECT id, name_ar, name_en FROM hospitals WHERE deleted_at IS NULL ORDER BY name_ar")->fetchAll();

    $usedDays = getUsedDaysUser($pdo, $patientId, $userId);
    $remainingDays = max(0, $allowedDays - $usedDays);
}
?>
<!DOCTYPE html>
<html lang="ar" dir="rtl">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<meta name="robots" content="noindex, nofollow">
<title>صحة - Seha</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=Cairo:wght@300;400;500;600;700;800;900&family=Inter:wght@300;400;500;600;700;800&display=swap" rel="stylesheet">
<link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.1/css/all.min.css" crossorigin="anonymous" referrerpolicy="no-referrer">
<script>
(function(){var t=localStorage.getItem('seha-theme')||'light';document.documentElement.setAttribute('data-theme',t)})();
</script>
<style>
/* ═══════════════════════════════════════════════════════════════
   SEHA PATIENT PORTAL - Ultra Modern Design System
   ═══════════════════════════════════════════════════════════════ */

:root {
  --primary: #0d9488;
  --primary-50: #f0fdfa;
  --primary-100: #ccfbf1;
  --primary-200: #99f6e4;
  --primary-300: #5eead4;
  --primary-400: #2dd4bf;
  --primary-500: #14b8a6;
  --primary-600: #0d9488;
  --primary-700: #0f766e;
  --primary-800: #115e59;
  --primary-900: #134e4a;
  --secondary: #6366f1;
  --accent: #8b5cf6;
  --success: #10b981;
  --warning: #f59e0b;
  --danger: #ef4444;
  --bg-base: #f8fafc;
  --bg-surface: #ffffff;
  --bg-elevated: #ffffff;
  --bg-overlay: rgba(15, 23, 42, 0.6);
  --text-primary: #0f172a;
  --text-secondary: #475569;
  --text-muted: #94a3b8;
  --text-inverse: #ffffff;
  --border-light: #e2e8f0;
  --border-default: #cbd5e1;
  --input-bg: #f1f5f9;
  --shadow-xs: 0 1px 2px rgba(0,0,0,0.05);
  --shadow-sm: 0 1px 3px rgba(0,0,0,0.1), 0 1px 2px rgba(0,0,0,0.06);
  --shadow-md: 0 4px 6px -1px rgba(0,0,0,0.1), 0 2px 4px -1px rgba(0,0,0,0.06);
  --shadow-lg: 0 10px 15px -3px rgba(0,0,0,0.1), 0 4px 6px -2px rgba(0,0,0,0.05);
  --shadow-xl: 0 20px 25px -5px rgba(0,0,0,0.1), 0 10px 10px -5px rgba(0,0,0,0.04);
  --shadow-2xl: 0 25px 50px -12px rgba(0,0,0,0.25);
  --shadow-glow: 0 0 40px rgba(13,148,136,0.15);
  --radius-sm: 8px;
  --radius-md: 12px;
  --radius-lg: 16px;
  --radius-xl: 20px;
  --radius-2xl: 24px;
  --radius-full: 9999px;
  --transition-fast: 150ms cubic-bezier(0.4, 0, 0.2, 1);
  --transition-base: 250ms cubic-bezier(0.4, 0, 0.2, 1);
  --transition-slow: 350ms cubic-bezier(0.4, 0, 0.2, 1);
  --transition-spring: 500ms cubic-bezier(0.34, 1.56, 0.64, 1);
  --font-ar: 'Cairo', sans-serif;
  --font-en: 'Inter', sans-serif;
  --nav-height: 72px;
}

[data-theme="dark"] {
  --primary: #14b8a6;
  --primary-50: #042f2e;
  --primary-100: #134e4a;
  --bg-base: #030712;
  --bg-surface: #0f172a;
  --bg-elevated: #1e293b;
  --bg-overlay: rgba(0, 0, 0, 0.75);
  --text-primary: #f1f5f9;
  --text-secondary: #cbd5e1;
  --text-muted: #64748b;
  --border-light: #1e293b;
  --border-default: #334155;
  --input-bg: #1e293b;
  --shadow-xs: 0 1px 2px rgba(0,0,0,0.3);
  --shadow-sm: 0 1px 3px rgba(0,0,0,0.4);
  --shadow-md: 0 4px 6px rgba(0,0,0,0.5);
  --shadow-lg: 0 10px 15px rgba(0,0,0,0.6);
  --shadow-xl: 0 20px 25px rgba(0,0,0,0.7);
  --shadow-2xl: 0 25px 50px rgba(0,0,0,0.8);
  --shadow-glow: 0 0 40px rgba(20,184,166,0.2);
}

/* ═══ Reset & Base ═══ */
*, *::before, *::after { margin:0; padding:0; box-sizing:border-box; }
html { scroll-behavior: smooth; -webkit-text-size-adjust: 100%; }
.fas, .far, .fab, .fa-solid, .fa-regular, .fa-brands {
  display: inline-flex; align-items: center; justify-content: center;
  min-width: 1.1em; line-height: 1; font-style: normal; text-rendering: auto;
  -webkit-font-smoothing: antialiased; -moz-osx-font-smoothing: grayscale;
}
html.fa-fallback .fas::before, html.fa-fallback .far::before, html.fa-fallback .fab::before,
html.fa-fallback .fa-solid::before, html.fa-fallback .fa-regular::before, html.fa-fallback .fa-brands::before { content: attr(data-fallback); font-family: "Apple Color Emoji", "Segoe UI Emoji", "Noto Color Emoji", sans-serif; }
html.fa-fallback .fa-chart-pie::before { content: "📊"; }
html.fa-fallback .fa-chevron-down::before { content: "⌄"; }
html.fa-fallback .fa-chevron-up::before { content: "⌃"; }
html.fa-fallback .fa-eye::before { content: "👁"; }
html.fa-fallback .fa-eye-slash::before { content: "🙈"; }
html.fa-fallback .fa-calendar-check::before { content: "📅"; }
html.fa-fallback .fa-file-medical::before { content: "📄"; }
html.fa-fallback .fa-hourglass-half::before { content: "⏳"; }
html.fa-fallback .fa-battery-quarter::before { content: "🔋"; }
html.fa-fallback .fa-id-card::before { content: "🪪"; }
html.fa-fallback .fa-info-circle::before { content: "ℹ️"; }
html.fa-fallback .fa-plus-circle::before { content: "➕"; }
html.fa-fallback .fa-paper-plane::before { content: "📨"; }
html.fa-fallback .fa-list-alt::before { content: "📋"; }
html.fa-fallback .fa-folder-open::before { content: "📂"; }
html.fa-fallback .fa-download::before { content: "⬇️"; }
html.fa-fallback .fa-heartbeat::before { content: "💓"; }
html.fa-fallback .fa-moon::before { content: "🌙"; }
html.fa-fallback .fa-sun::before { content: "☀️"; }
html.fa-fallback .fa-bell::before { content: "🔔"; }
html.fa-fallback .fa-bell-slash::before { content: "🔕"; }
html.fa-fallback .fa-times::before { content: "×"; }
html.fa-fallback .fa-sign-out-alt::before { content: "🚪"; }
html.fa-fallback .fa-hospital-user::before { content: "🏥"; }
html.fa-fallback .fa-user::before { content: "👤"; }
html.fa-fallback .fa-lock::before { content: "🔒"; }
html.fa-fallback .fa-sign-in-alt::before { content: "➡️"; }
html.fa-fallback .fa-exclamation-circle::before { content: "⚠️"; }
html.fa-fallback .fa-ban::before { content: "⛔"; }
html.fa-fallback .fa-whatsapp::before { content: "☎️"; }
html.fa-fallback .fa-check-circle::before { content: "✅"; }
html.fa-fallback .fa-times-circle::before { content: "❌"; }
html.fa-fallback .fa-exclamation-triangle::before { content: "⚠️"; }
body {
  font-family: var(--font-ar);
  background: var(--bg-base);
  color: var(--text-primary);
  min-height: 100vh;
  direction: rtl;
  -webkit-font-smoothing: antialiased;
  -moz-osx-font-smoothing: grayscale;
  transition: background-color var(--transition-slow), color var(--transition-slow);
  overflow-x: hidden;
}

/* ═══ Animated Background Orbs ═══ */
.bg-orbs {
  position: fixed; top: 0; left: 0; width: 100%; height: 100%;
  pointer-events: none; z-index: 0; overflow: hidden;
}
.bg-orbs .orb {
  position: absolute; border-radius: 50%; filter: blur(80px); opacity: 0.4;
  animation: orbFloat 20s ease-in-out infinite;
}
.bg-orbs .orb:nth-child(1) { width: 400px; height: 400px; background: var(--primary-200); top: -100px; right: -100px; animation-delay: 0s; }
.bg-orbs .orb:nth-child(2) { width: 300px; height: 300px; background: rgba(99,102,241,0.3); bottom: -50px; left: -50px; animation-delay: -7s; }
.bg-orbs .orb:nth-child(3) { width: 250px; height: 250px; background: rgba(139,92,246,0.2); top: 50%; left: 50%; animation-delay: -14s; }
[data-theme="dark"] .bg-orbs .orb { opacity: 0.15; }

@keyframes orbFloat {
  0%, 100% { transform: translate(0, 0) scale(1); }
  25% { transform: translate(30px, -30px) scale(1.05); }
  50% { transform: translate(-20px, 20px) scale(0.95); }
  75% { transform: translate(10px, -10px) scale(1.02); }
}

/* ═══ Login Page ═══ */
.login-page {
  min-height: 100vh; display: flex; align-items: center; justify-content: center;
  padding: 20px; position: relative; overflow: hidden;
  background: linear-gradient(135deg, #0f172a 0%, #134e4a 50%, #0f172a 100%);
}
.login-page::before {
  content: ''; position: absolute; inset: 0;
  background: radial-gradient(ellipse at 30% 20%, rgba(13,148,136,0.3) 0%, transparent 50%),
              radial-gradient(ellipse at 70% 80%, rgba(99,102,241,0.2) 0%, transparent 50%);
  animation: loginGlow 8s ease-in-out infinite alternate;
}
@keyframes loginGlow {
  0% { opacity: 0.6; } 100% { opacity: 1; }
}
.login-particles {
  position: absolute; inset: 0; overflow: hidden;
}
.login-particles span {
  position: absolute; width: 4px; height: 4px; background: rgba(255,255,255,0.3);
  border-radius: 50%; animation: particleRise 6s linear infinite;
}
@keyframes particleRise {
  0% { transform: translateY(100vh) scale(0); opacity: 0; }
  10% { opacity: 1; }
  90% { opacity: 1; }
  100% { transform: translateY(-100px) scale(1); opacity: 0; }
}

.login-card {
  background: rgba(255,255,255,0.05);
  backdrop-filter: blur(20px); -webkit-backdrop-filter: blur(20px);
  border: 1px solid rgba(255,255,255,0.1);
  border-radius: var(--radius-2xl); padding: 48px 40px;
  width: 100%; max-width: 440px;
  box-shadow: 0 30px 80px rgba(0,0,0,0.5), inset 0 1px 0 rgba(255,255,255,0.1);
  animation: cardAppear 0.8s var(--transition-spring) forwards;
  opacity: 0; transform: translateY(30px) scale(0.95);
  position: relative; z-index: 2;
}
@keyframes cardAppear {
  to { opacity: 1; transform: translateY(0) scale(1); }
}

.login-logo {
  width: 80px; height: 80px; margin: 0 auto 24px;
  background: linear-gradient(135deg, var(--primary-600), var(--primary-400));
  border-radius: var(--radius-xl); display: flex; align-items: center; justify-content: center;
  font-size: 36px; color: white;
  box-shadow: 0 10px 30px rgba(13,148,136,0.4);
  animation: logoFloat 4s ease-in-out infinite;
}
@keyframes logoFloat { 0%,100%{transform:translateY(0)} 50%{transform:translateY(-8px)} }

.login-card h2 { text-align: center; font-size: 28px; font-weight: 800; color: #fff; margin-bottom: 8px; }
.login-card .subtitle { text-align: center; color: rgba(255,255,255,0.6); font-size: 14px; margin-bottom: 36px; font-weight: 500; }

.login-card .form-group { margin-bottom: 22px; }
.login-card .form-group label { display: block; font-size: 13px; font-weight: 700; color: rgba(255,255,255,0.8); margin-bottom: 8px; }
.login-card .form-control {
  width: 100%; padding: 16px 20px; border: 1px solid rgba(255,255,255,0.15);
  border-radius: var(--radius-md); font-family: var(--font-ar); font-size: 15px;
  color: #fff; background: rgba(255,255,255,0.08); font-weight: 600;
  transition: var(--transition-base); outline: none;
}
.login-card .form-control::placeholder { color: rgba(255,255,255,0.4); }
.login-card .form-control:focus {
  border-color: var(--primary-400); background: rgba(255,255,255,0.12);
  box-shadow: 0 0 0 4px rgba(13,148,136,0.2);
}

.btn-login {
  width: 100%; padding: 16px; border: none; border-radius: var(--radius-md);
  font-family: var(--font-ar); font-size: 16px; font-weight: 800; cursor: pointer;
  background: linear-gradient(135deg, var(--primary-600), var(--primary-400));
  color: #fff; transition: var(--transition-base);
  box-shadow: 0 8px 25px rgba(13,148,136,0.4);
  position: relative; overflow: hidden;
}
.btn-login::after {
  content: ''; position: absolute; inset: 0;
  background: linear-gradient(135deg, transparent, rgba(255,255,255,0.2), transparent);
  transform: translateX(-100%); transition: transform 0.6s;
}
.btn-login:hover::after { transform: translateX(100%); }
.btn-login:hover { transform: translateY(-2px); box-shadow: 0 12px 35px rgba(13,148,136,0.5); }
.btn-login:active { transform: translateY(0); }

.login-alert {
  padding: 14px 18px; border-radius: var(--radius-md); font-size: 14px; font-weight: 700;
  margin-bottom: 20px; background: rgba(239,68,68,0.15); color: #fca5a5;
  border: 1px solid rgba(239,68,68,0.3); animation: shake 0.5s ease-in-out;
}
@keyframes shake { 0%,100%{transform:translateX(0)} 25%{transform:translateX(-5px)} 75%{transform:translateX(5px)} }

/* ═══ Navbar ═══ */
.navbar {
  position: sticky; top: 0; z-index: 100; height: var(--nav-height);
  background: rgba(255,255,255,0.8); backdrop-filter: blur(20px); -webkit-backdrop-filter: blur(20px);
  border-bottom: 1px solid var(--border-light);
  display: flex; align-items: center; justify-content: space-between;
  padding: 0 32px; transition: var(--transition-base);
  box-shadow: var(--shadow-sm);
}
[data-theme="dark"] .navbar { background: rgba(15,23,42,0.85); }

.nav-brand { display: flex; align-items: center; gap: 14px; }
.nav-brand-icon {
  width: 44px; height: 44px; border-radius: var(--radius-md);
  background: linear-gradient(135deg, var(--primary-600), var(--primary-400));
  display: flex; align-items: center; justify-content: center;
  font-size: 20px; color: white; box-shadow: 0 4px 12px rgba(13,148,136,0.3);
}
.nav-brand-text { font-size: 18px; font-weight: 800; color: var(--text-primary); }
.nav-brand-text small { display: block; font-size: 11px; font-weight: 600; color: var(--text-muted); margin-top: 2px; }

.nav-actions { display: flex; align-items: center; gap: 10px; }
.nav-user-badge {
  display: flex; align-items: center; gap: 10px; padding: 8px 16px;
  background: var(--input-bg); border: 1px solid var(--border-light);
  border-radius: var(--radius-full); font-size: 14px; font-weight: 700; color: var(--text-primary);
}
.nav-user-badge .avatar {
  width: 32px; height: 32px; border-radius: 50%;
  background: linear-gradient(135deg, var(--primary-400), var(--secondary));
  display: flex; align-items: center; justify-content: center;
  font-size: 14px; color: white; font-weight: 800;
}

.nav-btn {
  width: 42px; height: 42px; border-radius: var(--radius-md); border: 1px solid var(--border-light);
  background: var(--input-bg); color: var(--text-secondary); cursor: pointer;
  display: flex; align-items: center; justify-content: center; font-size: 18px;
  transition: var(--transition-fast); position: relative;
}
.nav-btn:hover { background: var(--border-light); transform: scale(1.05); }
.nav-btn i, .btn-logout-nav i, .btn-stats-toggle i, .card-header i, .btn-submit i, .btn-view-leave i, .btn-whatsapp i { flex: 0 0 auto; }
.nav-btn .badge-dot {
  position: absolute; top: 6px; right: 6px; width: 10px; height: 10px;
  background: var(--danger); border-radius: 50%; border: 2px solid var(--bg-surface);
  animation: pulse 2s infinite;
}
@keyframes pulse { 0%,100%{transform:scale(1)} 50%{transform:scale(1.3)} }

.btn-logout-nav {
  padding: 10px 18px; border-radius: var(--radius-md); border: 1px solid rgba(239,68,68,0.2);
  background: rgba(239,68,68,0.08); color: var(--danger); font-family: var(--font-ar);
  font-size: 13px; font-weight: 700; cursor: pointer; transition: var(--transition-fast);
  display: flex; align-items: center; gap: 6px;
}
.btn-logout-nav:hover { background: var(--danger); color: white; border-color: var(--danger); }

/* ═══ Main Content ═══ */
.main-content { max-width: 1200px; margin: 0 auto; padding: 36px 24px; position: relative; z-index: 1; }

/* ═══ Stats Cards ═══ */
.stats-toggle-wrap { text-align: center; margin-bottom: 28px; }
.stats-toggle-hint { display:block; margin-top:10px; color:var(--text-muted); font-size:13px; font-weight:700; }
.btn-stats-toggle {
  display: inline-flex; align-items: center; gap: 10px;
  padding: 14px 32px; border-radius: var(--radius-full);
  background: var(--bg-surface); border: 2px solid var(--border-light);
  color: var(--text-primary); font-family: var(--font-ar); font-size: 15px; font-weight: 800;
  cursor: pointer; transition: var(--transition-base);
  box-shadow: var(--shadow-md);
}
.btn-stats-toggle:hover { border-color: var(--primary); transform: translateY(-2px); box-shadow: var(--shadow-lg); }
.btn-stats-toggle.active { background: var(--primary-50); border-color: var(--primary); color: var(--primary); }
.btn-stats-toggle i { transition: transform var(--transition-base); }
.btn-stats-toggle .toggle-chevron { font-size: 13px; }
.btn-stats-toggle.active .toggle-chevron { transform: none; }

.stats-container, .patient-summary-card {
  margin-bottom: 32px; overflow: hidden; max-height: 1400px; opacity: 1;
  transition: max-height 0.5s ease, opacity 0.3s ease, margin-bottom 0.3s ease, transform 0.3s ease;
}
.stats-container.collapsed, .patient-summary-card.collapsed {
  max-height: 0; opacity: 0; margin-bottom: 0; transform: translateY(-8px); pointer-events: none;
}
.patient-summary-card.collapsed { border-width: 0; }

.stats-grid {
  display: grid; grid-template-columns: repeat(auto-fit, minmax(250px, 1fr)); gap: 20px;
}
.stat-card {
  background: var(--bg-surface); border-radius: var(--radius-xl); padding: 24px;
  border: 1px solid var(--border-light); display: flex; align-items: center; gap: 18px;
  transition: var(--transition-base); box-shadow: var(--shadow-sm);
  position: relative; overflow: hidden;
}
.stat-card::before {
  content: ''; position: absolute; top: 0; right: 0; width: 100px; height: 100px;
  border-radius: 50%; filter: blur(40px); opacity: 0.5; transition: var(--transition-slow);
}
.stat-card:hover { transform: translateY(-4px); box-shadow: var(--shadow-xl); border-color: transparent; }
.stat-card:hover::before { opacity: 0.8; }
.stat-card.teal::before { background: var(--primary-200); }
.stat-card.blue::before { background: rgba(99,102,241,0.3); }
.stat-card.amber::before { background: rgba(245,158,11,0.3); }
.stat-card.rose::before { background: rgba(239,68,68,0.3); }

.stat-icon {
  width: 56px; height: 56px; border-radius: var(--radius-lg);
  display: flex; align-items: center; justify-content: center;
  font-size: 24px; flex-shrink: 0; position: relative; z-index: 1;
}
.stat-icon.teal { background: rgba(13,148,136,0.12); color: var(--primary-600); }
.stat-icon.blue { background: rgba(99,102,241,0.12); color: #6366f1; }
.stat-icon.amber { background: rgba(245,158,11,0.12); color: #f59e0b; }
.stat-icon.rose { background: rgba(239,68,68,0.12); color: #ef4444; }

.stat-info { position: relative; z-index: 1; }
.stat-info .stat-num { font-size: 30px; font-weight: 900; color: var(--text-primary); line-height: 1; font-family: var(--font-en); }
.stat-info .stat-label { font-size: 13px; color: var(--text-muted); margin-top: 6px; font-weight: 700; }

/* ═══ Cards ═══ */
.card {
  background: var(--bg-surface); border-radius: var(--radius-2xl);
  border: 1px solid var(--border-light); overflow: hidden;
  margin-bottom: 28px; transition: var(--transition-base);
  box-shadow: var(--shadow-sm);
}
.card:hover { box-shadow: var(--shadow-lg); }
.card-header {
  padding: 22px 28px; border-bottom: 1px solid var(--border-light);
  display: flex; align-items: center; justify-content: space-between; flex-wrap: wrap; gap: 12px;
  background: var(--bg-base);
}
.card-header h3 {
  font-size: 18px; font-weight: 800; color: var(--text-primary);
  display: flex; align-items: center; gap: 10px;
}
.card-header h3 i { color: var(--primary); }
.card-body { padding: 28px; }

/* ═══ Patient Info Grid ═══ */
.patient-info-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(240px, 1fr)); gap: 16px; }
.info-field {
  background: var(--input-bg); border: 1px solid var(--border-light);
  border-radius: var(--radius-lg); padding: 18px 20px;
  transition: var(--transition-fast); position: relative; overflow: hidden;
}
.info-field::after {
  content: ''; position: absolute; top: 0; right: 0; width: 4px; height: 100%;
  background: var(--primary); opacity: 0; transition: var(--transition-fast);
}
.info-field:hover { border-color: var(--primary-300); }
.info-field:hover::after { opacity: 1; }
.info-field .field-label {
  font-size: 11px; font-weight: 800; color: var(--text-muted);
  text-transform: uppercase; letter-spacing: 0.5px; margin-bottom: 8px;
}
.info-field .field-value { font-size: 16px; font-weight: 700; color: var(--text-primary); }
.info-field .field-value-en { font-size: 12px; color: var(--text-muted); direction: ltr; text-align: left; margin-top: 4px; font-family: var(--font-en); font-weight: 500; }

/* ═══ Quota Bar ═══ */
.quota-section { margin-top: 20px; }
.quota-header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 12px; }
.quota-header .label { font-size: 14px; font-weight: 700; color: var(--text-secondary); }
.quota-header .value { font-size: 14px; font-weight: 800; color: var(--primary); font-family: var(--font-en); }
.quota-bar-track {
  height: 12px; background: var(--input-bg); border-radius: var(--radius-full);
  overflow: hidden; border: 1px solid var(--border-light);
  box-shadow: inset 0 2px 4px rgba(0,0,0,0.05);
}
.quota-bar-fill {
  height: 100%; border-radius: var(--radius-full);
  background: linear-gradient(90deg, var(--primary-600), var(--primary-400));
  transition: width 1.5s cubic-bezier(0.4, 0, 0.2, 1);
  position: relative; overflow: hidden;
}
.quota-bar-fill::after {
  content: ''; position: absolute; inset: 0;
  background: linear-gradient(90deg, transparent, rgba(255,255,255,0.3), transparent);
  animation: shimmer 2s infinite;
}
@keyframes shimmer { 0%{transform:translateX(-100%)} 100%{transform:translateX(100%)} }
.quota-bar-fill.warning { background: linear-gradient(90deg, #f59e0b, #fbbf24); }
.quota-bar-fill.danger { background: linear-gradient(90deg, #ef4444, #f87171); }

.days-summary {
  display: flex; gap: 20px; margin-top: 14px; flex-wrap: wrap;
}
.days-summary .day-item {
  display: flex; align-items: center; gap: 8px; font-size: 14px; font-weight: 700;
}
.days-summary .day-item .dot { width: 10px; height: 10px; border-radius: 50%; }
.days-summary .day-item.used .dot { background: var(--danger); }
.days-summary .day-item.remaining .dot { background: var(--success); }
.days-summary .day-item.total .dot { background: var(--primary); }

/* ═══ Leave Form ═══ */
.leave-form-grid { display: grid; grid-template-columns: 1fr 1fr; gap: 22px; }
.form-group { margin-bottom: 0; }
.form-label { display: block; font-size: 14px; font-weight: 800; color: var(--text-primary); margin-bottom: 10px; }
.form-select, .form-input {
  width: 100%; padding: 14px 18px; border: 2px solid var(--border-light);
  border-radius: var(--radius-md); font-family: var(--font-ar); font-size: 15px;
  color: var(--text-primary); background: var(--input-bg); font-weight: 600;
  transition: var(--transition-base); outline: none; cursor: pointer;
}
.form-select:focus, .form-input:focus {
  border-color: var(--primary); background: var(--bg-surface);
  box-shadow: 0 0 0 4px rgba(13,148,136,0.1);
}

.time-tabs { display: flex; gap: 10px; margin-bottom: 14px; }
.time-tab {
  flex: 1; padding: 12px; border: 2px solid var(--border-light); border-radius: var(--radius-md);
  background: var(--input-bg); font-family: var(--font-ar); font-size: 14px; font-weight: 800;
  cursor: pointer; transition: var(--transition-fast); text-align: center; color: var(--text-muted);
}
.time-tab.active { border-color: var(--primary); background: var(--primary-50); color: var(--primary); }
.time-tab:hover:not(.active) { border-color: var(--text-muted); }

.btn-submit {
  display: inline-flex; align-items: center; justify-content: center; gap: 10px;
  padding: 16px 36px; border: none; border-radius: var(--radius-md);
  font-family: var(--font-ar); font-size: 16px; font-weight: 800; cursor: pointer;
  background: linear-gradient(135deg, var(--primary-700), var(--primary-500));
  color: white; transition: var(--transition-base);
  box-shadow: 0 8px 25px rgba(13,148,136,0.3);
  position: relative; overflow: hidden;
}
.btn-submit::after {
  content: ''; position: absolute; inset: 0;
  background: linear-gradient(135deg, transparent, rgba(255,255,255,0.15), transparent);
  transform: translateX(-100%); transition: transform 0.6s;
}
.btn-submit:hover::after { transform: translateX(100%); }
.btn-submit:hover { transform: translateY(-2px); box-shadow: 0 12px 35px rgba(13,148,136,0.4); }
.btn-submit:disabled { opacity: 0.6; cursor: not-allowed; transform: none; }

/* ═══ Leaves Table ═══ */
.table-responsive { overflow-x: auto; -webkit-overflow-scrolling: touch; }
.leaves-table { width: 100%; border-collapse: collapse; font-size: 14px; }
.leaves-table th {
  padding: 14px 18px; text-align: right; font-weight: 800; color: var(--text-muted);
  font-size: 12px; text-transform: uppercase; letter-spacing: 0.5px;
  border-bottom: 2px solid var(--border-light); white-space: nowrap; background: var(--bg-base);
}
.leaves-table td {
  padding: 16px 18px; border-bottom: 1px solid var(--border-light);
  vertical-align: middle; color: var(--text-primary); font-weight: 600;
}
.leaves-table tr { transition: var(--transition-fast); }
.leaves-table tr:hover td { background: var(--primary-50); }

.btn-view-leave {
  padding: 8px 16px; border-radius: var(--radius-sm); border: 2px solid var(--primary);
  background: transparent; color: var(--primary); font-family: var(--font-ar);
  font-size: 13px; font-weight: 800; cursor: pointer; transition: var(--transition-fast);
  display: inline-flex; align-items: center; gap: 6px;
}
.btn-view-leave:hover { background: var(--primary); color: white; }

/* ═══ Empty State ═══ */
.empty-state { text-align: center; padding: 60px 20px; }
.empty-state .empty-icon { font-size: 64px; margin-bottom: 20px; opacity: 0.6; color: var(--text-muted); }
.empty-state h4 { font-size: 20px; font-weight: 800; color: var(--text-primary); margin-bottom: 10px; }
.empty-state p { font-size: 15px; color: var(--text-muted); font-weight: 600; max-width: 400px; margin: 0 auto; line-height: 1.7; }

/* ═══ Toast Notifications ═══ */
.toast-container {
  position: fixed; top: 90px; left: 50%; transform: translateX(-50%);
  z-index: 9999; display: flex; flex-direction: column; gap: 12px;
  pointer-events: none; width: 90%; max-width: 450px;
}
.toast {
  background: var(--bg-surface); border: 1px solid var(--border-light);
  border-radius: var(--radius-lg); padding: 18px 24px;
  box-shadow: var(--shadow-2xl); font-size: 15px; font-weight: 700;
  display: flex; align-items: center; gap: 14px; width: 100%;
  animation: toastSlide 0.4s var(--transition-spring);
  border-right: 5px solid var(--primary); color: var(--text-primary);
  backdrop-filter: blur(10px); pointer-events: auto;
}
.toast.success { border-color: var(--success); }
.toast.error { border-color: var(--danger); }
.toast.warning { border-color: var(--warning); }
@keyframes toastSlide { from{opacity:0;transform:translateY(-20px)} to{opacity:1;transform:translateY(0)} }

/* ═══ Notification Panel ═══ */
.notif-overlay { position: fixed; inset: 0; background: var(--bg-overlay); z-index: 200; opacity: 0; pointer-events: none; transition: opacity var(--transition-base); }
.notif-overlay.show { opacity: 1; pointer-events: auto; }
.notif-panel {
  position: fixed; top: 0; left: 0; width: 380px; max-width: 90vw; height: 100vh;
  background: var(--bg-surface); z-index: 201; transform: translateX(-100%);
  transition: transform var(--transition-slow); box-shadow: var(--shadow-2xl);
  display: flex; flex-direction: column;
}
.notif-panel.show { transform: translateX(0); }
.notif-panel-header {
  padding: 24px; border-bottom: 1px solid var(--border-light);
  display: flex; align-items: center; justify-content: space-between;
}
.notif-panel-header h3 { font-size: 18px; font-weight: 800; }
.notif-panel-body { flex: 1; overflow-y: auto; padding: 16px; }
.notif-item {
  padding: 16px; border-radius: var(--radius-md); margin-bottom: 8px;
  border: 1px solid var(--border-light); transition: var(--transition-fast);
}
.notif-item:hover { background: var(--primary-50); }
.notif-item.unread { background: var(--primary-50); border-color: var(--primary-200); }
.notif-item .notif-msg { font-size: 14px; font-weight: 600; color: var(--text-primary); line-height: 1.6; }
.notif-item .notif-time { font-size: 12px; color: var(--text-muted); margin-top: 6px; font-family: var(--font-en); }

/* ═══ Spinner ═══ */
.spinner { width: 20px; height: 20px; border: 3px solid rgba(255,255,255,0.3); border-top-color: #fff; border-radius: 50%; animation: spin 0.8s linear infinite; display: inline-block; }
@keyframes spin { to{transform:rotate(360deg)} }

/* ═══ Notice Bar ═══ */
.notice-bar {
  background: linear-gradient(135deg, rgba(245,158,11,0.08), rgba(239,68,68,0.04));
  border: 1px solid rgba(245,158,11,0.2); border-radius: var(--radius-xl);
  padding: 18px 24px; display: flex; align-items: center; justify-content: space-between;
  flex-wrap: wrap; gap: 16px; margin-bottom: 24px;
}
.notice-bar .notice-content { display: flex; align-items: center; gap: 12px; }
.notice-bar .notice-icon { font-size: 22px; color: var(--warning); }
.notice-bar .notice-text .title { font-size: 14px; font-weight: 800; color: var(--text-primary); }
.notice-bar .notice-text .desc { font-size: 13px; font-weight: 600; color: var(--text-muted); margin-top: 2px; }
.btn-whatsapp {
  display: inline-flex; align-items: center; gap: 8px; padding: 10px 20px;
  background: #25d366; color: white; border-radius: var(--radius-md);
  font-size: 13px; font-weight: 800; text-decoration: none;
  box-shadow: 0 4px 15px rgba(37,211,102,0.3); transition: var(--transition-fast);
}
.btn-whatsapp:hover { background: #128c7e; transform: translateY(-2px); }

/* ═══ Responsive ═══ */
@media (max-width: 768px) {
  .leave-form-grid { grid-template-columns: 1fr; }
  .navbar { padding: 0 12px; gap: 10px; }
  .nav-brand { gap: 10px; min-width: 0; }
  .nav-brand-icon { width: 40px; height: 40px; font-size: 18px; flex: 0 0 40px; }
  .nav-brand-text { min-width: 0; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }
  .nav-actions { gap: 6px; flex-shrink: 0; }
  .nav-user-badge { padding: 6px; }
  .nav-user-badge span { display: none; }
  .nav-btn { width: 40px; height: 40px; flex: 0 0 40px; font-size: 17px; }
  .btn-logout-nav { width: 40px; height: 40px; padding: 0; justify-content: center; border-radius: var(--radius-md); }
  .btn-logout-nav span { display: none; }
  .main-content { padding: 24px 16px; }
  .card { border-radius: var(--radius-xl); }
  .card-header { align-items: flex-start; gap: 10px; flex-wrap: wrap; }
  .card-body { padding: 20px; }
  .stats-grid { grid-template-columns: 1fr; }
  .stat-card { padding: 20px; }
  .stat-icon { width: 50px; height: 50px; font-size: 20px; }
  .notice-bar { flex-direction: column; align-items: stretch; }
  .notice-bar .notice-content { align-items: flex-start; }
  .btn-whatsapp { justify-content: center; width: 100%; }
  .time-tabs { flex-direction: column; }
  .leaves-table { min-width: 760px; }
}
@media (max-width: 480px) {
  .navbar { height: auto; min-height: var(--nav-height); padding-top: 8px; padding-bottom: 8px; }
  .nav-brand-text { font-size: 14px; max-width: 120px; }
  .nav-brand-text small { display: none; }
  .nav-user-badge { display: none; }
  .btn-stats-toggle { width: 100%; justify-content: center; font-size: 14px; padding: 12px 16px; gap: 8px; white-space: normal; line-height: 1.5; }
  .stats-toggle-hint { font-size: 12px; line-height: 1.6; }
  .main-content { padding-inline: 12px; }
  .login-card { padding: 36px 24px; }
}
</style>
</head>
<body>

<div class="bg-orbs"><div class="orb"></div><div class="orb"></div><div class="orb"></div></div>

<?php if (!isPatientLoggedIn()): ?>
<!-- ═══════════ صفحة تسجيل الدخول ═══════════ -->
<div class="login-page">
  <div class="login-particles">
    <?php for($i=0;$i<20;$i++): ?><span style="left:<?=rand(0,100)?>%;animation-delay:<?=rand(0,60)/10?>s;animation-duration:<?=rand(40,80)/10?>s"></span><?php endfor; ?>
  </div>
  <div class="login-card">
    <div class="login-logo"><i class="fas fa-hospital-user"></i></div>
    <h2>صحة</h2>
    <p class="subtitle">Seha</p>
    <?php if (!empty($loginError)): ?>
      <div class="login-alert"><i class="fas fa-exclamation-circle"></i> <?= htmlspecialchars($loginError) ?></div>
    <?php endif; ?>
    <?php if (isset($_GET['disabled'])): ?>
      <div class="login-alert"><i class="fas fa-ban"></i> تم تعطيل حسابك. يرجى التواصل مع الإدارة.</div>
    <?php endif; ?>
    <form method="POST" autocomplete="off">
      <input type="hidden" name="action" value="patient_login">
      <?= patient_csrf_input() ?>
      <div class="form-group">
        <label><i class="fas fa-user"></i> اسم المستخدم</label>
        <input type="text" name="username" class="form-control" placeholder="أدخل اسم المستخدم" required autocomplete="username">
      </div>
      <div class="form-group">
        <label><i class="fas fa-lock"></i> كلمة المرور</label>
        <input type="password" name="password" class="form-control" placeholder="أدخل كلمة المرور" required autocomplete="current-password">
      </div>
      <button type="submit" class="btn-login"><i class="fas fa-sign-in-alt"></i> تسجيل الدخول</button>
    </form>
  </div>
</div>

<?php else: ?>
<!-- ═══════════ لوحة التحكم الرئيسية ═══════════ -->
<div class="toast-container" id="toastContainer"></div>

<!-- Notification Panel -->
<div class="notif-overlay" id="notifOverlay" onclick="toggleNotifPanel(false)"></div>
<div class="notif-panel" id="notifPanel">
  <div class="notif-panel-header">
    <h3><i class="fas fa-bell"></i> الإشعارات</h3>
    <button class="nav-btn" onclick="toggleNotifPanel(false)" style="border:none;background:none;font-size:20px;cursor:pointer"><i class="fas fa-times"></i></button>
  </div>
  <div class="notif-panel-body" id="notifList">
    <div class="empty-state" style="padding:40px 10px"><i class="fas fa-bell-slash empty-icon" style="font-size:40px"></i><p>لا توجد إشعارات</p></div>
  </div>
</div>

<!-- Navbar -->
<nav class="navbar">
  <div class="nav-brand">
    <div class="nav-brand-icon"><i class="fas fa-heartbeat"></i></div>
    <div class="nav-brand-text">صحة<small>Seha</small></div>
  </div>
  <div class="nav-actions">
    <div class="nav-user-badge">
      <div class="avatar"><?= mb_substr($_SESSION['patient_display_name'] ?? 'م', 0, 1) ?></div>
      <span><?= htmlspecialchars($_SESSION['patient_display_name'] ?? '') ?></span>
    </div>
    <button class="nav-btn" id="btnThemeToggle" onclick="toggleTheme()" title="تبديل المظهر"><i class="fas fa-moon"></i></button>
    <button class="nav-btn" onclick="toggleNotifPanel(true)" title="الإشعارات"><i class="fas fa-bell"></i><span class="badge-dot" id="notifDot" style="display:none"></span></button>
    <form method="POST" style="display:inline"><input type="hidden" name="action" value="logout"><button type="submit" class="btn-logout-nav"><i class="fas fa-sign-out-alt"></i> <span>خروج</span></button></form>
  </div>
</nav>

<main class="main-content">
  <!-- Stats Toggle -->
  <div class="stats-toggle-wrap">
    <button class="btn-stats-toggle" id="btnToggleStats" onclick="toggleStats()" type="button" aria-expanded="false" aria-controls="statsContainer patientInfoCard">
      <i class="fas fa-eye"></i> <span class="toggle-label">إظهار الإحصائيات وبيانات الشخصية</span> <i class="fas fa-chevron-down toggle-chevron"></i>
    </button>
    <span class="stats-toggle-hint">اهلا بك في بوابتك الالكترونية لإصدار اجازاتك فورياً.</span>
  </div>

  <!-- Stats Grid -->
  <div class="stats-container collapsed" id="statsContainer" aria-hidden="true">
    <div class="stats-grid">
      <div class="stat-card teal">
        <div class="stat-icon teal"><i class="fas fa-calendar-check"></i></div>
        <div class="stat-info"><div class="stat-num"><?= $allowedDays ?></div><div class="stat-label">الأيام المسموحة</div></div>
      </div>
      <div class="stat-card blue">
        <div class="stat-icon blue"><i class="fas fa-file-medical"></i></div>
        <div class="stat-info"><div class="stat-num"><?= count($myLeaves) ?></div><div class="stat-label">عدد الإجازات</div></div>
      </div>
      <div class="stat-card amber">
        <div class="stat-icon amber"><i class="fas fa-hourglass-half"></i></div>
        <div class="stat-info"><div class="stat-num"><?= $usedDays ?></div><div class="stat-label">الأيام المستخدمة</div></div>
      </div>
      <div class="stat-card rose">
        <div class="stat-icon rose"><i class="fas fa-battery-quarter"></i></div>
        <div class="stat-info"><div class="stat-num"><?= $remainingDays ?></div><div class="stat-label">الأيام المتبقية</div></div>
      </div>
    </div>
  </div>

  <!-- Patient Info Card -->
  <div class="card patient-summary-card collapsed" id="patientInfoCard" aria-hidden="true">
    <div class="card-header">
      <h3><i class="fas fa-id-card"></i> بيانات المريض</h3>
    </div>
    <div class="card-body">
      <div class="notice-bar">
        <div class="notice-content">
          <i class="fas fa-info-circle notice-icon"></i>
          <div class="notice-text">
            <span class="title">البيانات ثابتة ولا يمكن تعديلها</span>
            <span class="desc">لتعديل البيانات يرجى التواصل مع الإدارة</span>
          </div>
        </div>
        <a href="https://wa.me/966573436223" target="_blank" class="btn-whatsapp"><i class="fab fa-whatsapp"></i> تواصل معنا</a>
      </div>
      <?php if ($patientData): ?>
      <div class="patient-info-grid">
        <div class="info-field"><span class="field-label">الاسم بالعربي</span><span class="field-value"><?= htmlspecialchars($patientData['name_ar'] ?? '') ?></span></div>
        <div class="info-field"><span class="field-label">الاسم بالإنجليزي</span><span class="field-value" style="direction:ltr;text-align:left;font-family:var(--font-en)"><?= htmlspecialchars($patientData['name_en'] ?? '') ?></span></div>
        <div class="info-field"><span class="field-label">رقم الهوية / الإقامة</span><span class="field-value" style="font-family:var(--font-en)"><?= htmlspecialchars($patientData['identity_number'] ?? '') ?></span></div>
        <div class="info-field"><span class="field-label">الجنسية</span><span class="field-value"><?= htmlspecialchars($patientData['nationality_ar'] ?? '') ?></span><span class="field-value-en"><?= htmlspecialchars($patientData['nationality_en'] ?? '') ?></span></div>
        <div class="info-field"><span class="field-label">جهة العمل</span><span class="field-value"><?= htmlspecialchars($patientData['employer_ar'] ?? '') ?></span><span class="field-value-en"><?= htmlspecialchars($patientData['employer_en'] ?? '') ?></span></div>
      </div>
      <!-- Quota Bar -->
      <div class="quota-section">
        <div class="quota-header">
          <span class="label">حصة الأيام</span>
          <span class="value"><?= $usedDays ?> / <?= $allowedDays ?></span>
        </div>
        <?php
          $pct = $allowedDays > 0 ? round(($usedDays / $allowedDays) * 100) : 0;
          $barClass = $pct > 80 ? 'danger' : ($pct > 60 ? 'warning' : '');
        ?>
        <div class="quota-bar-track"><div class="quota-bar-fill <?= $barClass ?>" style="width:<?= $pct ?>%"></div></div>
        <div class="days-summary">
          <div class="day-item used"><span class="dot"></span> مستخدمة: <?= $usedDays ?></div>
          <div class="day-item remaining"><span class="dot"></span> متبقية: <?= $remainingDays ?></div>
          <div class="day-item total"><span class="dot"></span> الإجمالي: <?= $allowedDays ?></div>
        </div>
      </div>
      <?php endif; ?>
    </div>
  </div>

  <!-- Create Leave Card -->
  <div class="card">
    <div class="card-header">
      <h3><i class="fas fa-plus-circle"></i> إنشاء إجازة مرضية جديدة</h3>
    </div>
    <div class="card-body">
      <?php if ($remainingDays <= 0): ?>
        <div class="empty-state" style="padding:44px 18px;text-align:center">
          <i class="fab fa-whatsapp" style="font-size:58px;color:#25d366;margin-bottom:16px"></i>
          <h3 style="margin-bottom:10px;color:var(--danger);font-weight:900">استنفدت كل رصيدك من الأيام</h3>
          <p style="color:var(--text-muted);font-weight:700;margin-bottom:22px">لإضافة رصيد أيام جديد أو طلب المساعدة، تواصل معنا مباشرة عبر الواتساب.</p>
          <a href="https://wa.me/966573436223" target="_blank" class="btn-whatsapp" style="display:inline-flex;font-size:16px;padding:14px 26px"><i class="fab fa-whatsapp"></i> تواصل معنا على واتساب</a>
        </div>
      <?php else: ?>
      <form id="leaveForm" onsubmit="return submitLeave(event)">
        <div class="leave-form-grid">
          <div class="form-group">
            <label class="form-label">المستشفى</label>
            <input type="text" class="form-input" id="hospitalSearch" placeholder="ابحث باسم المستشفى..." autocomplete="off" style="margin-bottom:8px">
            <select class="form-select" id="hospitalSelect" name="hospital_id" required onchange="loadDoctors(this.value)">
              <option value="">-- اختر المستشفى --</option>
              <?php foreach ($hospitals as $h): ?>
                <option value="<?= $h['id'] ?>"><?= htmlspecialchars($h['name_ar']) ?></option>
              <?php endforeach; ?>
            </select>
          </div>
          <div class="form-group">
            <label class="form-label">الطبيب</label>
            <select class="form-select" id="doctorSelect" name="doctor_id" required disabled>
              <option value="">-- اختر المستشفى أولاً --</option>
            </select>
          </div>
          <div class="form-group">
            <label class="form-label">تاريخ البداية</label>
            <input type="date" class="form-input" id="startDate" name="start_date" required onchange="calcDays()">
          </div>
          <div class="form-group">
            <label class="form-label">تاريخ النهاية</label>
            <input type="date" class="form-input" id="endDate" name="end_date" required onchange="calcDays()">
          </div>
          <div class="form-group">
            <label class="form-label">عدد الأيام</label>
            <input type="number" class="form-input" id="daysCount" name="days_count" min="1" readonly style="background:var(--primary-50);font-weight:900;color:var(--primary)">
          </div>
          <div class="form-group">
            <label class="form-label">وقت الإصدار</label>
            <div class="time-tabs">
              <button type="button" class="time-tab active" data-mode="auto" onclick="setTimeMode('auto',this)">تلقائي</button>
              <button type="button" class="time-tab" data-mode="random" onclick="setTimeMode('random',this)">عشوائي</button>
              <button type="button" class="time-tab" data-mode="manual" onclick="setTimeMode('manual',this)">يدوي</button>
            </div>
            <input type="hidden" name="time_mode" id="timeMode" value="auto">
            <div id="manualTimeWrap" style="display:none;margin-top:10px;display:flex;gap:10px">
              <input type="time" class="form-input" name="manual_time" id="manualTime" style="flex:1">
              <select class="form-select" name="manual_period" id="manualPeriod" style="width:auto;min-width:80px">
                <option value="AM">AM</option>
                <option value="PM">PM</option>
              </select>
            </div>
          </div>
        </div>
        <div style="margin-top:28px;text-align:center">
          <button type="submit" class="btn-submit" id="btnSubmitLeave">
            <i class="fas fa-paper-plane"></i> إنشاء الإجازة
          </button>
        </div>
      </form>
      <?php endif; ?>
    </div>
  </div>

  <!-- Leaves Table Card -->
  <div class="card">
    <div class="card-header">
      <h3><i class="fas fa-list-alt"></i> سجل الإجازات المرضية</h3>
      <span style="font-size:13px;font-weight:700;color:var(--text-muted)"><?= count($myLeaves) ?> إجازة </span>
    </div>
    <div class="card-body" style="padding:0">
      <?php if (empty($myLeaves)): ?>
        <div class="empty-state">
          <i class="fas fa-folder-open empty-icon"></i>
          <h4>لا توجد إجازات بعد</h4>
          <p>قم بإنشاء أول إجازة مرضية من النموذج أعلاه</p>
        </div>
      <?php else: ?>
        <div class="table-responsive">
          <table class="leaves-table">
            <thead><tr>
              <th>رمز الإجازة</th><th>المستشفى</th><th>الطبيب</th><th>المدة</th><th>تاريخ البداية</th><th>الإجراء</th>
            </tr></thead>
            <tbody>
            <?php foreach ($myLeaves as $lv): ?>
              <tr>
                <td style="font-family:var(--font-en);font-weight:800;color:var(--primary)"><?= htmlspecialchars($lv['service_code'] ?? '') ?></td>
                <td><?= htmlspecialchars($lv['h_name_ar'] ?? '') ?></td>
                <td><?= htmlspecialchars($lv['d_name_ar'] ?? '') ?></td>
                <td style="font-family:var(--font-en);font-weight:800"><?= (int)$lv['days_count'] ?> يوم</td>
                <td style="font-family:var(--font-en)"><?= fmtDateUser($lv['start_date'] ?? '') ?></td>
                <td><button class="btn-view-leave" onclick="viewLeave(<?= (int)$lv['id'] ?>)"><i class="fas fa-download"></i> تحميل</button></td>
              </tr>
            <?php endforeach; ?>
            </tbody>
          </table>
        </div>
      <?php endif; ?>
    </div>
  </div>
</main>
<?php endif; ?>

<script>
const PATIENT_CSRF_TOKEN = '<?php echo patient_csrf_token(); ?>';
// ═══ Reliable Icons on all devices ═══
(function ensurePatientIcons(){
  const html = document.documentElement;
  const test = document.createElement('i');
  test.className = 'fas fa-check';
  test.style.cssText = 'position:absolute;left:-9999px;top:-9999px;visibility:hidden';
  document.body.appendChild(test);
  const applyFallback = () => html.classList.add('fa-fallback');
  const verify = () => {
    const family = getComputedStyle(test, '::before').fontFamily || getComputedStyle(test).fontFamily || '';
    const content = getComputedStyle(test, '::before').content || '';
    const ok = /Font Awesome|FontAwesome/i.test(family) && content && content !== 'none' && content !== 'normal';
    if (!ok) applyFallback();
    test.remove();
  };
  if (document.fonts && document.fonts.ready) {
    document.fonts.ready.then(verify).catch(applyFallback);
    setTimeout(() => { if (document.body.contains(test)) verify(); }, 2500);
  } else {
    setTimeout(verify, 1200);
  }
})();
// ═══ Theme Toggle ═══
function toggleTheme() {
  const html = document.documentElement;
  const current = html.getAttribute('data-theme');
  const next = current === 'dark' ? 'light' : 'dark';
  html.setAttribute('data-theme', next);
  localStorage.setItem('seha-theme', next);
  const icon = document.querySelector('#btnThemeToggle i');
  if (icon) icon.className = next === 'dark' ? 'fas fa-sun' : 'fas fa-moon';
}
(function(){
  const t = localStorage.getItem('seha-theme') || 'light';
  const icon = document.querySelector('#btnThemeToggle i');
  if (icon) icon.className = t === 'dark' ? 'fas fa-sun' : 'fas fa-moon';
})();

// ═══ Stats Toggle ═══
function toggleStats(forceShow = null) {
  const stats = document.getElementById('statsContainer');
  const patient = document.getElementById('patientInfoCard');
  const btn = document.getElementById('btnToggleStats');
  if (!stats || !patient || !btn) return;
  const shouldShow = forceShow === null ? stats.classList.contains('collapsed') : Boolean(forceShow);
  [stats, patient].forEach(section => {
    section.classList.toggle('collapsed', !shouldShow);
    section.setAttribute('aria-hidden', shouldShow ? 'false' : 'true');
  });
  btn.classList.toggle('active', shouldShow);
  btn.setAttribute('aria-expanded', shouldShow ? 'true' : 'false');
  const label = btn.querySelector('.toggle-label');
  const mainIcon = btn.querySelector('i:first-child');
  const chevron = btn.querySelector('.toggle-chevron');
  if (label) label.textContent = shouldShow ? 'إخفاء الإحصائيات وبيانات المريض' : 'إظهار الإحصائيات وبيانات المريض';
  if (mainIcon) mainIcon.className = shouldShow ? 'fas fa-eye-slash' : 'fas fa-eye';
  if (chevron) chevron.className = shouldShow ? 'fas fa-chevron-up toggle-chevron' : 'fas fa-chevron-down toggle-chevron';
}
document.addEventListener('DOMContentLoaded', () => toggleStats(false));

// ═══ Notifications ═══
function toggleNotifPanel(show) {
  document.getElementById('notifOverlay').classList.toggle('show', show);
  document.getElementById('notifPanel').classList.toggle('show', show);
  if (show) loadNotifications();
}
function loadNotifications() {
  fetch('user.php?action=get_user_notifications')
    .then(r => r.json()).then(data => {
      if (!data.success) return;
      const list = document.getElementById('notifList');
      const dot = document.getElementById('notifDot');
      if (data.unread_count > 0) { dot.style.display = 'block'; } else { dot.style.display = 'none'; }
      if (data.notifications.length === 0) {
        list.innerHTML = '<div class="empty-state" style="padding:40px 10px"><i class="fas fa-bell-slash" style="font-size:40px;color:var(--text-muted)"></i><p style="margin-top:10px">لا توجد إشعارات</p></div>';
        return;
      }
      list.innerHTML = data.notifications.map(n => `<div class="notif-item ${n.is_read?'':'unread'}"><div class="notif-msg">${n.message}</div><div class="notif-time">${n.created_at}</div></div>`).join('');
      if (data.unread_count > 0) {
        fetch('user.php?action=mark_user_notifications_read');
        setTimeout(() => { dot.style.display = 'none'; }, 2000);
      }
    }).catch(() => {});
}

// ═══ Hospital Quick Search ═══
(function initHospitalQuickSearch(){
  const input = document.getElementById('hospitalSearch');
  const select = document.getElementById('hospitalSelect');
  if (!input || !select) return;
  const normalize = (value) => String(value || '')
    .toLowerCase()
    .replace(/[ً-ٰٟ]/g, '')
    .replace(/[إأآا]/g, 'ا')
    .replace(/[ى]/g, 'ي')
    .replace(/[ؤ]/g, 'و')
    .replace(/[ئ]/g, 'ي')
    .replace(/[ة]/g, 'ه')
    .replace(/[٠-٩]/g, d => String('٠١٢٣٤٥٦٧٨٩'.indexOf(d)))
    .replace(/\s+/g, ' ')
    .trim();
  const allOptions = Array.from(select.options).map(opt => ({ value: opt.value, text: opt.textContent }));
  input.addEventListener('input', () => {
    const selectedValue = select.value;
    const query = normalize(input.value);
    select.innerHTML = '';
    allOptions.forEach(opt => {
      if (opt.value && query && !normalize(opt.text).includes(query)) return;
      const option = document.createElement('option');
      option.value = opt.value;
      option.textContent = opt.text;
      if (opt.value === selectedValue) option.selected = true;
      select.appendChild(option);
    });
  });
})();

// ═══ Load Doctors ═══
function loadDoctors(hospitalId) {
  const sel = document.getElementById('doctorSelect');
  sel.innerHTML = '<option value="">جاري التحميل...</option>';
  sel.disabled = true;
  if (!hospitalId) { sel.innerHTML = '<option value="">-- اختر المستشفى أولاً --</option>'; return; }
  fetch('user.php?action=get_doctors_by_hospital&hospital_id=' + encodeURIComponent(hospitalId))
    .then(r => r.json()).then(data => {
      sel.disabled = false;
      if (!data.success || !data.doctors.length) { sel.innerHTML = '<option value="">لا يوجد أطباء</option>'; return; }
      sel.innerHTML = '<option value="">-- اختر الطبيب --</option>' + data.doctors.map(d => `<option value="${d.id}">${d.name_ar} - ${d.title_ar||''}</option>`).join('');
    }).catch(() => { sel.innerHTML = '<option value="">خطأ في التحميل</option>'; sel.disabled = false; });
}

// ═══ Calculate Days ═══
function calcDays() {
  const s = document.getElementById('startDate').value;
  const e = document.getElementById('endDate').value;
  if (s && e) {
    const diff = Math.ceil((new Date(e) - new Date(s)) / 86400000) + 1;
    document.getElementById('daysCount').value = diff > 0 ? diff : 1;
  }
}

// ═══ Time Mode ═══
function setTimeMode(mode, btn) {
  document.querySelectorAll('.time-tab').forEach(t => t.classList.remove('active'));
  btn.classList.add('active');
  document.getElementById('timeMode').value = mode;
  document.getElementById('manualTimeWrap').style.display = mode === 'manual' ? 'flex' : 'none';
}

// ═══ Submit Leave ═══
function submitLeave(e) {
  e.preventDefault();
  const btn = document.getElementById('btnSubmitLeave');
  btn.disabled = true;
  btn.innerHTML = '<span class="spinner"></span> جاري الإنشاء...';
  const fd = new FormData(document.getElementById('leaveForm'));
  fd.append('action', 'create_sick_leave');
  fetch('user.php', { method: 'POST', body: fd })
    .then(r => r.json()).then(data => {
      btn.disabled = false;
      btn.innerHTML = '<i class="fas fa-paper-plane"></i> إنشاء الإجازة';
      if (data.success) {
        showToast(data.message, 'success');
        setTimeout(() => location.reload(), 1500);
      } else {
        showToast(data.message || 'حدث خطأ', 'error');
      }
    }).catch(() => {
      btn.disabled = false;
      btn.innerHTML = '<i class="fas fa-paper-plane"></i> إنشاء الإجازة';
      showToast('خطأ في الاتصال بالخادم', 'error');
    });
  return false;
}

// ═══ View Leave ═══
function viewLeave(id) {
  const url = 'user.php?action=generate_pdf&leave_id=' + encodeURIComponent(id) + '&pdf_mode=download&csrf_token=' + encodeURIComponent(PATIENT_CSRF_TOKEN);
  let frame = document.getElementById('pdfDownloadFrame');
  if (!frame) {
    frame = document.createElement('iframe');
    frame.id = 'pdfDownloadFrame';
    frame.name = 'pdfDownloadFrame';
    frame.style.display = 'none';
    frame.setAttribute('aria-hidden', 'true');
    document.body.appendChild(frame);
  }
  frame.src = url;
  showToast('بدأ تحميل ملف الإجازة', 'success');
}

// ═══ Toast ═══
function showToast(msg, type) {
  const container = document.getElementById('toastContainer');
  if (!container) return;
  const icons = { success: 'fa-check-circle', error: 'fa-times-circle', warning: 'fa-exclamation-triangle' };
  const toast = document.createElement('div');
  toast.className = 'toast ' + (type || '');
  toast.innerHTML = `<i class="fas ${icons[type]||'fa-info-circle'}" style="font-size:20px"></i><span>${msg}</span>`;
  container.appendChild(toast);
  setTimeout(() => { toast.style.opacity = '0'; toast.style.transform = 'translateY(-10px)'; setTimeout(() => toast.remove(), 300); }, 4000);
}

// ═══ Security: Disable right-click & dev tools ═══
document.addEventListener('contextmenu', e => e.preventDefault());
document.addEventListener('keydown', e => {
  if (e.key === 'F12' || (e.ctrlKey && e.shiftKey && ['I','J','C'].includes(e.key.toUpperCase())) || (e.ctrlKey && e.key.toUpperCase() === 'U')) {
    e.preventDefault();
  }
});
</script>
</body>
</html>
