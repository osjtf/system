<?php
/**
 * بوابة المرضى - user.php
 * المرضى يُنشئون إجازات مرضية حقيقية بنفس قالب لوحة التحكم
 */

ini_set('session.use_only_cookies', '1');
ini_set('session.cookie_httponly', '1');
ini_set('session.cookie_samesite', 'Strict');
session_start();

date_default_timezone_set('Asia/Riyadh');
header('X-Frame-Options: SAMEORIGIN');
header('X-Content-Type-Options: nosniff');

// ======================== إعدادات قاعدة البيانات ========================
$db_host = 'mysql.railway.internal';
$db_user = 'root';
$db_pass = 'ExvKbuJnGIvDATyXWCHtpjOFluFAgeqQ';
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
    // احسب الأيام المستخدمة من الإجازات الحقيقية التي أنشأها هذا المستخدم
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
    $username = trim($_POST['username'] ?? '');
    $password = $_POST['password'] ?? '';

    if (empty($username) || empty($password)) {
        $loginError = 'يرجى إدخال اسم المستخدم وكلمة المرور.';
    } else {
        $stmtCheck = $pdo->prepare("SELECT u.*, pa.patient_id, pa.allowed_days, pa.expiry_date FROM admin_users u LEFT JOIN patient_accounts pa ON pa.user_id = u.id WHERE u.username = ?");
        $stmtCheck->execute([$username]);
        $userCheck = $stmtCheck->fetch();

        if ($userCheck && password_verify($password, $userCheck['password_hash'])) {
            if (!$userCheck['is_active']) {
                $loginError = 'هذا الحساب معطّل. يرجى التواصل مع الإدارة.';
            } elseif (empty($userCheck['patient_id']) || (int)$userCheck['patient_id'] <= 0) {
                $loginError = 'هذا الحساب غير مرتبط بملف مريض. يرجى التواصل مع الإدارة.';
            } elseif (!empty($userCheck['expiry_date']) && $userCheck['expiry_date'] < date('Y-m-d')) {
                $loginError = 'انتهت صلاحية هذا الحساب. يرجى التواصل مع الإدارة.';
            } else {
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
            $loginError = 'اسم المستخدم أو كلمة المرور غير صحيحة.';
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
    // Ensure table exists
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

    // تحديث الحصة من DB
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

    // التحقق من الحصة
    $usedDays = getUsedDaysUser($pdo, $patientId, $userId);
    $remainingDays = $allowedDays - $usedDays;

    if ($daysCount > $remainingDays) {
        echo json_encode(['success' => false, 'message' => "عدد الأيام المطلوبة ($daysCount) يتجاوز الحصة المتبقية ($remainingDays يوم)."]);
        exit;
    }

    // تحديد الوقت
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

    // جلب بيانات المستشفى والطبيب والمريض
    $hospStmt = $pdo->prepare("SELECT * FROM hospitals WHERE id = ?");
    $hospStmt->execute([$hospitalId]);
    $hosp = $hospStmt->fetch();

    $docStmt = $pdo->prepare("SELECT * FROM doctors WHERE id = ?");
    $docStmt->execute([$doctorId]);
    $doc = $docStmt->fetch();

    $patStmt = $pdo->prepare("SELECT * FROM patients WHERE id = ?");
    $patStmt->execute([$patientId]);
    $pat = $patStmt->fetch();

    if (!$hosp || !$doc || !$pat) {
        echo json_encode(['success' => false, 'message' => 'بيانات غير صالحة. يرجى المحاولة مجدداً.']);
        exit;
    }

    // توليد رمز الخدمة
    $prefix = $hosp['service_prefix'] ?? 'GSL';
    $serviceCode = generateServiceCodeUser($pdo, $prefix, $startDate);

    // إدراج الإجازة في sick_leaves
    $issueDate = date('Y-m-d');
    $stmt = $pdo->prepare("INSERT INTO sick_leaves 
        (service_code, patient_id, doctor_id, hospital_id, created_by_user_id,
         issue_date, issue_time, issue_period, start_date, end_date, days_count,
         patient_name_en, doctor_name_en, doctor_title_en,
         hospital_name_ar, hospital_name_en, logo_path,
         employer_ar, employer_en)
        VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)");
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
    ]);
    $leaveId = (int)$pdo->lastInsertId();

    echo json_encode([
        'success'        => true,
        'message'        => 'تم إنشاء الإجازة المرضية بنجاح.',
        'leave_id'       => $leaveId,
        'service_code'   => $serviceCode,
        'remaining_days' => $remainingDays - $daysCount,
    ]);
    exit;
}

// توليد PDF للإجازة (نفس قالب لوحة التحكم)
if ($action === 'generate_pdf' && isPatientLoggedIn()) {
    $leaveId = (int)($_GET['leave_id'] ?? 0);
    $userId  = (int)$_SESSION['patient_user_id'];
    $patientId = (int)$_SESSION['patient_id'];
    $pdfMode = $_GET['pdf_mode'] ?? 'preview';

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

    // ===== نفس منطق handleGeneratePdf من admin.php =====
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
    $startHj  = toHijriStrUser($startG);
    $endHj    = toHijriStrUser($endG);

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

    // شعار المستشفى
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
        $licenseHtml = '<span style="font-family: \'Noto Sans Arabic\', sans-serif; font-weight: 700;">رقم الترخيص :</span> <span style="font-family: \'Times New Roman\', serif; font-weight: 700;">' . htmlspecialchars($hospLicense) . '</span>';
    }

    // الوقت
    $issuePeriod = $lv['issue_period'] ?? 'AM';
    $issueTimeRaw = $lv['issue_time'] ?? '09:00';
    // normalize to 12h
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
    $durationAr = '<span style="font-family: \'Times New Roman\', serif; font-size: 14.5px; font-weight: 400;">' . $daysAr . '</span> <span style="font-family: \'Noto Sans Arabic\', sans-serif; font-size: 14.5px; font-weight: 400;">' . $daysArWord . '</span> ( ' . formatHijriDateSpanUser($startHj) . ' <span style="font-family: \'Noto Sans Arabic\', sans-serif; font-size: 13.5px; font-weight: 400;">إلى</span> ' . formatHijriDateSpanUser($endHj) . ' )';

    // ===== وضع التحميل المباشر (WeasyPrint) =====
    if ($pdfMode === 'download') {
        $baseUrl = (isset($_SERVER['HTTPS']) && $_SERVER['HTTPS'] === 'on' ? 'https' : 'http') . '://' . $_SERVER['HTTP_HOST'] . dirname($_SERVER['SCRIPT_NAME']) . '/';
        $scFile = preg_replace('/[^a-zA-Z0-9_-]/', '_', $sc);

        $pdfHtml  = '<!DOCTYPE html><html lang="ar"><head><meta charset="utf-8"/>';
        $pdfHtml .= '<title>Sick Leave Report</title>';
        $pdfHtml .= '<link rel="stylesheet" href="https://fonts.googleapis.com/css2?family=Inter:wght@100;200;300;400;500;600;700&display=swap" />';
        $pdfHtml .= '<link rel="stylesheet" href="https://fonts.googleapis.com/css2?family=STIX+Two+Text:ital,wght@0,400;0,600;0,700;1,400&display=swap" />';
        $pdfHtml .= '<link rel="stylesheet" href="https://fonts.googleapis.com/css2?family=Noto+Sans+Arabic:wght@400;600;700&display=swap" />';
        $pdfHtml .= '<style>html{line-height:1.15}body{margin:0}*{box-sizing:border-box;border-width:0;border-style:solid}p,li,ul,pre,div,h1,h2,h3,h4,h5,h6,figure,blockquote,figcaption{margin:0;padding:0}a{color:inherit;text-decoration:inherit}</style>';
        $pdfHtml .= '<style>html{font-family:Inter,sans-serif;font-size:16px}body{font-weight:400;color:#191818;background:#ffffff;margin:0;padding:0}</style>';
        $pdfHtml .= '<style>@page{size:842.25px 1190.25px;margin:0}.group1-container1{width:842.25px;height:1190.25px;position:relative;background-color:transparent;margin:0;padding:0}.group1-thq-group1-elm{width:842.25px;height:1190.25px;position:relative;background-color:white;margin:0;padding:0}.info-table{position:absolute;top:242px;left:36px;width:770px;border-collapse:separate;border-spacing:0;border:1px solid #cccccc;border-radius:8px;overflow:hidden;background-color:transparent;z-index:10}.info-table td{border-bottom:1px solid #cccccc;border-right:1px solid #cccccc;height:42px;text-align:center;vertical-align:middle;padding:4px 8px}.info-table td:last-child{border-right:none}.info-table tr:last-child td{border-bottom:none}.info-table .en-title{width:161px;color:rgba(54,111,181,1);font-size:13.5px;font-weight:700;text-align:center;font-family:"Times New Roman",serif}.info-table .data-cell{width:240px;color:rgba(44,62,119,1);font-size:13.5px;font-family:"Times New Roman",serif;font-weight:400;text-align:center}.info-table .date-cell{font-size:13.9px}.info-table .data-cell.ar-text{font-family:"Noto Sans Arabic",sans-serif}.info-table .ar-title{width:140px;color:rgba(54,111,181,1);font-size:13.5px;font-weight:700;text-align:center;font-family:"Noto Sans Arabic",sans-serif;white-space:nowrap}.info-table tr.blue-row td{background-color:#2c3e77;color:#ffffff;border-bottom:1px solid #cccccc;border-right:1px solid #cccccc}.info-table tr.blue-row td:last-child{border-right:none}.info-table .blue-row .data-cell.ar-text{color:rgba(255,255,255,1);font-size:13.5px;font-family:"Times New Roman",serif;font-weight:400}.info-table .blue-row .data-cell{color:rgba(255,255,255,1)}.info-table tr.gray-row td{background-color:#f7f7f7}.en-spaced{letter-spacing:0.3px}:root{--footer-offset:40px}.group1-thq-staticinfo-elm{top:125px;left:36.65px;width:768.35px;height:811.91px;display:flex;position:absolute;align-items:flex-start}.top-right-placeholder{position:absolute;top:36px;left:592px;width:214px;height:107px;display:flex;align-items:center;justify-content:center}.top-left-placeholder{position:absolute;top:36px;left:36px;width:149.96px;height:65.98px;display:flex;align-items:center;justify-content:center}.bottom-right-placeholder{position:absolute;top:1005px;left:657.17px;width:149.96px;height:71.23px;display:flex;align-items:center;justify-content:center}.header-placeholder{top:-55px;left:320px;width:160px;height:50px;position:absolute;display:flex;align-items:center;justify-content:center}.group1-thq-text-elm41{top:40px;left:289px;color:rgba(48,109,181,1);width:215px;position:absolute;font-size:22.5px;font-weight:700;text-align:center;line-height:30px}.group1-thq-text-elm44{top:-10px;left:310px;color:rgba(0,0,0,1);position:absolute;font-size:17.3px;font-weight:400;text-align:left;font-family:"Times New Roman",serif}.group1-thq-hospitallogoandthename-elm{top:760px;left:438.94px;width:403px;height:202.78px;display:flex;position:absolute;align-items:flex-start}.placeholder-logo-hospital{top:-12px;left:133px;width:136px;height:136px;position:absolute;display:flex;align-items:center;justify-content:center}.group1-thq-text-elm18{top:120px;color:rgba(0,0,0,1);width:403px;height:auto;position:absolute;font-size:12.8px;text-align:center;line-height:22px}.group1-thq-thedateofissueandalsotimeofissue-elm{top:calc(989.85px + var(--footer-offset));left:37.37px;width:250px;height:56px;display:flex;position:absolute;align-items:flex-start}.group1-thq-text-elm22{color:rgba(0,0,0,1);font-size:12.5px;font-weight:700;text-align:left;line-height:28px;font-family:"Times New Roman",serif;position:absolute;white-space:nowrap}.group1-thq-text-elm36{top:calc(724.55px + var(--footer-offset));left:29.23px;color:rgba(0,0,0,1);position:absolute;font-size:12px;font-weight:700;text-align:center;font-family:"Noto Sans Arabic",sans-serif;line-height:23px}.group1-thq-text-elm39{top:calc(775.17px + var(--footer-offset));left:55px;color:rgba(0,0,0,1);position:absolute;font-size:12px;font-weight:700;text-align:left;font-family:"Times New Roman",serif}.group1-thq-text-elm40{top:calc(798.91px + var(--footer-offset));left:108.35px;color:rgba(20,0,255,1);position:absolute;font-size:11px;font-weight:700;text-align:left;text-decoration:underline;font-family:"Times New Roman",serif}.placeholder-136{position:absolute;top:620px;left:122px;width:136px;height:136px;display:flex;align-items:center;justify-content:center}.vertical-divider{position:absolute;top:735px;left:436px;width:1px;height:7cm;background-color:#dddddd}.thin-slash{font-weight:300;font-family:"Inter",sans-serif;margin:0 3px;display:inline-block}</style>';
        $pdfHtml .= '</head><body>';

        $reportBodyPdf  = '<div class="group1-container1"><div class="group1-thq-group1-elm">';
        $reportBodyPdf .= '<div class="top-right-placeholder"><img src="' . $baseUrl . 'sehalogoright.svg" style="width:100%;height:100%"/></div>';
        $reportBodyPdf .= '<div class="top-left-placeholder"><img src="' . $baseUrl . 'sehalogoleft.svg" style="width:100%;height:100%"/></div>';
        $reportBodyPdf .= '<div class="bottom-right-placeholder"><img src="' . $baseUrl . 'bottomright.svg" style="width:100%;height:100%"/></div>';
        $reportBodyPdf .= '<div class="group1-thq-staticinfo-elm">';
        $reportBodyPdf .= '<div class="header-placeholder"><img src="' . $baseUrl . 'header.svg" style="width:100%;height:100%"/></div>';
        $reportBodyPdf .= '<span class="group1-thq-text-elm41"><span style="font-size:22.5px;font-family:\'Noto Sans Arabic\',sans-serif;font-weight:700;color:#306db5">تقرير إجازة مرضية</span><br/><span style="font-size:18.7px;font-family:\'Times New Roman\',serif;font-weight:700;color:#2c3e77">Sick Leave Report</span></span>';
        $reportBodyPdf .= '<span class="group1-thq-text-elm44">Kingdom of Saudi Arabia</span>';
        $reportBodyPdf .= '<div class="placeholder-136"><img src="' . $baseUrl . 'qr.svg" style="width:130px;height:130px"/></div>';
        $reportBodyPdf .= '<span class="group1-thq-text-elm36" dir="rtl">للتحقق من بيانات التقرير يرجى التأكد من زيارة موقع منصة صحة<br/>الرسمي</span>';
        $reportBodyPdf .= '<span class="group1-thq-text-elm39">To check the report please visit Seha\'s official website</span>';
        $reportBodyPdf .= '<span class="group1-thq-text-elm40"><a href="https://seha-sa-iniquiries-slenquiry.up.railway.app/" target="_blank">www.seha.sa/#/inquiries/slenquiry</a></span>';
        $reportBodyPdf .= '</div>';
        $reportBodyPdf .= '<table class="info-table" cellpadding="0" cellspacing="0"><tbody>';
        $reportBodyPdf .= '<tr><td class="en-title">Leave ID</td><td class="data-cell" colspan="2">' . $sc . '</td><td class="ar-title">رمز الإجازة</td></tr>';
        $reportBodyPdf .= '<tr class="blue-row"><td class="en-title" style="color:white">Leave Duration</td><td class="data-cell">' . $durationEn . '</td><td class="data-cell ar-text" dir="rtl">' . $durationAr . '</td><td class="ar-title" style="color:white">مدة الإجازة</td></tr>';
        $reportBodyPdf .= '<tr><td class="en-title">Admission Date</td><td class="data-cell date-cell">' . $startEn . '</td><td class="data-cell date-cell" dir="ltr">' . $startHj . '</td><td class="ar-title">تاريخ الدخول</td></tr>';
        $reportBodyPdf .= '<tr class="gray-row"><td class="en-title">Discharge Date</td><td class="data-cell date-cell">' . $endEn . '</td><td class="data-cell date-cell" dir="ltr">' . $endHj . '</td><td class="ar-title">تاريخ الخروج</td></tr>';
        $reportBodyPdf .= '<tr><td class="en-title">Issue Date</td><td class="data-cell" colspan="2">' . $issueEn . '</td><td class="ar-title">تاريخ الإصدار</td></tr>';
        $reportBodyPdf .= '<tr class="gray-row"><td class="en-title">Patient Name</td><td class="data-cell en-spaced">' . $patNameEn . '</td><td class="data-cell ar-text">' . $patNameAr . '</td><td class="ar-title">الاسم</td></tr>';
        $reportBodyPdf .= '<tr><td class="en-title">National ID / Iqama</td><td class="data-cell" colspan="2">' . $patId . '</td><td class="ar-title">رقم الهوية<span class="thin-slash">/</span>الإقامة</td></tr>';
        $reportBodyPdf .= '<tr class="gray-row"><td class="en-title">Nationality</td><td class="data-cell en-spaced">' . $natEn . '</td><td class="data-cell ar-text">' . $natAr . '</td><td class="ar-title">الجنسية</td></tr>';
        $reportBodyPdf .= '<tr><td class="en-title">Employer</td><td class="data-cell en-spaced">' . $empEn . '</td><td class="data-cell ar-text">' . $empAr . '</td><td class="ar-title">جهة العمل</td></tr>';
        $reportBodyPdf .= '<tr class="gray-row"><td class="en-title">Physician Name</td><td class="data-cell en-spaced">' . $docNameEn . '</td><td class="data-cell ar-text">' . $docNameAr . '</td><td class="ar-title">اسم الطبيب المعالج</td></tr>';
        $reportBodyPdf .= '<tr><td class="en-title">Position</td><td class="data-cell en-spaced">' . $docTitleEn . '</td><td class="data-cell ar-text">' . $docTitleAr . '</td><td class="ar-title">المسمى الوظيفي</td></tr>';
        $reportBodyPdf .= '</tbody></table>';
        $reportBodyPdf .= '<div class="vertical-divider"></div>';
        $reportBodyPdf .= '<div class="group1-thq-hospitallogoandthename-elm">';
        $reportBodyPdf .= '<div class="placeholder-logo-hospital">' . $hospLogoHtml . '</div>';
        $reportBodyPdf .= '<span class="group1-thq-text-elm18"><span style="font-family:\'Noto Sans Arabic\',sans-serif;font-weight:700">' . $hospNameAr . '</span><br/><span class="en-spaced" style="font-family:\'Times New Roman\',serif;font-weight:700">' . $hospNameEn . '</span><br/>';
        if (!empty($licenseHtml)) $reportBodyPdf .= $licenseHtml;
        $reportBodyPdf .= '</span></div>';
        $reportBodyPdf .= '<div class="group1-thq-thedateofissueandalsotimeofissue-elm"><span class="group1-thq-text-elm22"><span>' . $timestampLine . '</span><br/><span>' . $dateLine . '</span></span></div>';
        $reportBodyPdf .= '</div></div>';

        $pdfHtml .= $reportBodyPdf;
        $pdfHtml .= '</body></html>';

        @mkdir('/tmp/weasyprint', 0777, true);
        $tmpHtml = '/tmp/weasyprint/user_report_' . uniqid() . '.html';
        $tmpPdf  = '/tmp/weasyprint/user_report_' . uniqid() . '.pdf';
        file_put_contents($tmpHtml, $pdfHtml);

        $scriptPath = __DIR__ . '/generate_pdf.py';
        $pythonBin = 'python3';
        foreach (['/usr/bin/python3.13', '/usr/bin/python3.12', '/usr/bin/python3.11', '/usr/local/bin/python3', '/usr/bin/python3'] as $p) {
            if (is_file($p) && !is_link($p)) { $pythonBin = $p; break; }
            if (is_link($p)) { $real = realpath($p); if ($real && is_file($real)) { $pythonBin = $real; break; } }
        }
        $scFile = preg_replace('/[^a-zA-Z0-9_-]/', '_', $sc);
        $cmd = $pythonBin . ' "' . $scriptPath . '" "' . $tmpHtml . '" "' . $tmpPdf . '" 2>&1';
        $output = shell_exec($cmd);

        if (file_exists($tmpPdf) && filesize($tmpPdf) > 0) {
            header('Content-Type: application/pdf');
            header('Content-Disposition: attachment; filename="SickLeave_' . $scFile . '.pdf"');
            header('Content-Length: ' . filesize($tmpPdf));
            header('Cache-Control: no-cache, no-store, must-revalidate');
            readfile($tmpPdf);
            @unlink($tmpHtml);
            @unlink($tmpPdf);
            exit;
        }
        // إذا فشل WeasyPrint، نكمل بوضع المعاينة
        @unlink($tmpHtml);
    }

    header('Content-Type: text/html; charset=utf-8');
    ?>
<!DOCTYPE html>
<html lang="ar">
<head>
<title>تقرير إجازة مرضية - Sick Leave Report</title>
<meta property="og:title" content="Sick Leave Report" />
<meta name="viewport" content="width=device-width, initial-scale=1.0" />
<meta charset="utf-8" />
<style data-tag="reset-style-sheet">
html { line-height: 1.15; }
body { margin: 0; }
* { box-sizing: border-box; border-width: 0; border-style: solid; -webkit-font-smoothing: antialiased; }
p, li, ul, pre, div, h1, h2, h3, h4, h5, h6, figure, blockquote, figcaption { margin: 0; padding: 0; }
a { color: inherit; text-decoration: inherit; }
html { scroll-behavior: smooth }
</style>
<style data-tag="default-style-sheet">
html { font-family: Inter, sans-serif; font-size: 16px; -webkit-text-size-adjust: 100%; }
body { font-weight: 400; color: #191818; background: #FBFAF9; overflow-x: hidden; }
</style>
<link rel="stylesheet" href="https://fonts.googleapis.com/css2?family=Inter:wght@100;200;300;400;500;600;700&display=swap" />
<link rel="stylesheet" href="https://fonts.googleapis.com/css2?family=STIX+Two+Text:ital,wght@0,400;0,600;0,700;1,400&display=swap" />
<link rel="stylesheet" href="https://fonts.googleapis.com/css2?family=Noto+Sans+Arabic:wght@400;600;700&display=swap" />
<style>
.group1-container1 { width: 100%; display: flex; overflow-x: hidden; min-height: 100vh; align-items: center; flex-direction: column; background-color: #f0f0f0; padding-top: 20px; padding-bottom: 20px; }
.group1-thq-group1-elm { width: 842.25px; height: 1190.25px; display: flex; position: relative; align-items: flex-start; flex-shrink: 0; box-shadow: 0px 4px 15px rgba(0,0,0,0.1); background-color: white; }
.info-table { position: absolute; top: 242px; left: 36px; width: 770px; border-collapse: separate; border-spacing: 0; border: 1px solid #cccccc; border-radius: 8px; overflow: hidden; background-color: transparent; z-index: 10; }
.info-table td { border-bottom: 1px solid #cccccc; border-right: 1px solid #cccccc; height: 42px; text-align: center; vertical-align: middle; padding: 4px 8px; }
.info-table td:last-child { border-right: none; } .info-table tr:last-child td { border-bottom: none; }
.info-table .en-title { width: 161px; color: rgba(54, 111, 181, 1); font-size: 13.5px; font-weight: 700; text-align: center; font-family: "Times New Roman", serif; }
.info-table .data-cell { width: 240px; color: rgba(44, 62, 119, 1); font-size: 13.5px; font-family: "Times New Roman", serif; font-weight: 400; text-align: center; }
.info-table .date-cell { font-size: 13.9px; } .info-table .data-cell.ar-text { font-family: "Noto Sans Arabic", sans-serif; }
.info-table .ar-title { width: 140px; color: rgba(54, 111, 181, 1); font-size: 13.5px; font-weight: 700; text-align: center; font-family: "Noto Sans Arabic", sans-serif; white-space: nowrap; }
.info-table tr.blue-row td { background-color: #2c3e77; color: #ffffff; border-bottom: 1px solid #cccccc; border-right: 1px solid #cccccc; }
.info-table tr.blue-row td:last-child { border-right: none; }
.info-table .blue-row .data-cell.ar-text { color: rgba(255, 255, 255, 1); font-size: 13.5px; font-family: "Times New Roman", serif; font-weight: 400; }
.info-table .blue-row .data-cell { color: rgba(255, 255, 255, 1); }
.info-table tr.gray-row td { background-color: #f7f7f7; }
.en-spaced { letter-spacing: 0.3px; }
:root { --footer-offset: 40px; }
.group1-thq-staticinfo-elm { top: 125px; left: 36.65px; width: 768.35px; height: 811.91px; display: flex; position: absolute; align-items: flex-start; pointer-events: none; }
.top-right-placeholder { position: absolute; top: 36px; left: 592px; width: 214px; height: 107px; display: flex; align-items: center; justify-content: center; font-size: 14px; z-index: 5; }
.top-left-placeholder { position: absolute; top: 36px; left: 36px; width: 149.96px; height: 65.98px; display: flex; align-items: center; justify-content: center; font-size: 14px; z-index: 5; }
.bottom-right-placeholder { position: absolute; top: 1005px; left: 657.17px; width: 149.96px; height: 71.23px; display: flex; align-items: center; justify-content: center; font-size: 12px; z-index: 5; }
.header-placeholder { top: -55px; left: 320px; width: 160px; height: 50px; position: absolute; display: flex; align-items: center; justify-content: center; font-size: 11px; }
.group1-thq-text-elm41 { top: 40px; left: 289px; color: rgba(48, 109, 181, 1); width: 215px; position: absolute; font-size: 22.5px; font-weight: 700; text-align: center; line-height: 30px; }
.group1-thq-text-elm44 { top: -10px; left: 310px; color: rgba(0, 0, 0, 1); position: absolute; font-size: 17.3px; font-weight: 400; text-align: left; font-family: "Times New Roman", serif; }
.group1-thq-hospitallogoandthename-elm { top: 760px; left: 438.94px; width: 403px; height: 202.78px; display: flex; position: absolute; align-items: flex-start; }
.placeholder-logo-hospital { top: -12px; left: 133px; width: 136px; height: 136px; position: absolute; display: flex; align-items: center; justify-content: center; font-size: 12px; }
.group1-thq-text-elm18 { top: 120px; color: rgba(0, 0, 0, 1); width: 403px; height: auto; position: absolute; font-size: 12.8px; text-align: center; line-height: 22px; }
.group1-thq-thedateofissueandalsotimeofissue-elm { top: calc(989.85px + var(--footer-offset)); left: 37.37px; width: 250px; height: 56px; display: flex; position: absolute; align-items: flex-start; }
.group1-thq-text-elm22 { color: rgba(0, 0, 0, 1); font-size: 12.5px; font-weight: 700; text-align: left; line-height: 28px; font-family: "Times New Roman", serif; position: absolute; white-space: nowrap; }
.group1-thq-text-elm36 { top: calc(724.55px + var(--footer-offset)); left: 29.23px; color: rgba(0, 0, 0, 1); position: absolute; font-size: 12px; font-weight: 700; text-align: center; font-family: "Noto Sans Arabic", sans-serif; line-height: 23px; }
.group1-thq-text-elm39 { top: calc(775.17px + var(--footer-offset)); left: 55px; color: rgba(0, 0, 0, 1); position: absolute; font-size: 12px; font-weight: 700; text-align: left; font-family: "Times New Roman", serif; }
.group1-thq-text-elm40 { top: calc(798.91px + var(--footer-offset)); left: 108.35px; color: rgba(20, 0, 255, 1); position: absolute; font-size: 11px; font-weight: 700; text-align: left; text-decoration: underline; pointer-events: auto; font-family: "Times New Roman", serif; }
.placeholder-136 { position: absolute; top: 620px; left: 122px; width: 136px; height: 136px; display: flex; align-items: center; justify-content: center; font-size: 12px; pointer-events: auto; }
.vertical-divider { position: absolute; top: 735px; left: 436px; width: 1px; height: 7cm; background-color: #dddddd; }
.thin-slash { font-weight: 300; font-family: "Inter", sans-serif; margin: 0 3px; display: inline-block; }
.controls { position: fixed; bottom: 30px; right: 30px; display: flex; gap: 15px; z-index: 1000; }
.download-btn { background-color: #306db5; color: white; padding: 14px 28px; border-radius: 10px; border: none; font-size: 16px; font-weight: 600; cursor: pointer; box-shadow: 0px 6px 15px rgba(0,0,0,0.3); font-family: "Inter", sans-serif; transition: all 0.3s; }
.download-btn:hover { background-color: #2c3e77; transform: translateY(-3px); }
@media screen and (max-width: 880px) {
  .group1-container1 { padding-top: 10px; padding-bottom: 10px; }
  .group1-thq-group1-elm { transform-origin: top center; transform: scale(calc(100vw / 860)); margin-bottom: calc(1190.25px * (100vw / 860) - 1190.25px); }
  .controls { bottom: 15px; right: 15px; left: 15px; justify-content: center; }
  .download-btn { width: 100%; text-align: center; font-size: 18px; padding: 16px; }
}
@media print {
  @page { size: 842.25px 1190.25px; margin: 0; }
  body { -webkit-print-color-adjust: exact !important; print-color-adjust: exact !important; background: white !important; }
  .controls { display: none !important; }
  .group1-container1 { padding: 0 !important; background-color: transparent !important; }
  .group1-thq-group1-elm { box-shadow: none !important; margin: 0 !important; transform: scale(1) !important; }
  a { color: rgba(20, 0, 255, 1) !important; text-decoration: underline !important; }
}
</style>
<script>
function downloadPDF() {
  var btn = document.getElementById('btnDownloadPDF');
  btn.textContent = 'جاري التحميل...';
  btn.disabled = true;
  var url = window.location.href;
  if (url.indexOf('pdf_mode=') > -1) {
    url = url.replace(/pdf_mode=[^&]*/, 'pdf_mode=download');
  } else {
    url += (url.indexOf('?') > -1 ? '&' : '?') + 'pdf_mode=download';
  }
  // إزالة autoprint من الرابط إن وجد
  url = url.replace(/[&?]autoprint=\d/, '');
  var a = document.createElement('a');
  a.href = url;
  a.download = '';
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  setTimeout(function() { btn.textContent = 'تحميل ملف PDF'; btn.disabled = false; }, 3000);
}
</script>
</head>
<body>
<div class="controls">
  <button id="btnDownloadPDF" class="download-btn" onclick="downloadPDF()">تحميل ملف PDF</button>
  <button class="download-btn" style="background-color:#2c3e77" onclick="window.print()">طباعة مباشرة</button>
  <button class="download-btn" style="background-color:#475569" onclick="history.back()">← رجوع</button>
</div>
<div class="group1-container1">
  <div class="group1-thq-group1-elm" id="report-content">
    <div class="top-right-placeholder"><img src="sehalogoright.svg" alt="" style="width:100%;height:100%;" onerror="this.style.display='none'" /></div>
    <div class="top-left-placeholder"><img src="sehalogoleft.svg" alt="" style="width:100%;height:100%;" onerror="this.style.display='none'" /></div>
    <div class="bottom-right-placeholder"><img src="bottomright.svg" alt="" style="width:100%;height:100%;" onerror="this.style.display='none'" /></div>
    <div class="group1-thq-staticinfo-elm">
      <div class="header-placeholder"><img src="header.svg" alt="" style="width:100%;height:100%;" onerror="this.style.display='none'" /></div>
      <span class="group1-thq-text-elm41">
        <span style="font-size:22.5px;font-family:'Noto Sans Arabic',sans-serif;font-weight:700;color:#306db5;">تقرير إجازة مرضية</span><br/>
        <span style="font-size:18.7px;font-family:'Times New Roman',serif;font-weight:700;color:#2c3e77;">Sick Leave Report</span>
      </span>
      <span class="group1-thq-text-elm44">Kingdom of Saudi Arabia</span>
      <div class="placeholder-136"><img src="qr.svg" alt="QR" style="width:130px;height:130px;" onerror="this.style.display='none'" /></div>
      <span class="group1-thq-text-elm36" dir="rtl">للتحقق من بيانات التقرير يرجى التأكد من زيارة موقع منصة صحة<br/>الرسمي</span>
      <span class="group1-thq-text-elm39">To check the report please visit Seha's official website</span>
      <span class="group1-thq-text-elm40"><a href="https://seha-sa-iniquiries-slenquiry.up.railway.app/" target="_blank">www.seha.sa/#/inquiries/slenquiry</a></span>
    </div>
    <table class="info-table" cellpadding="0" cellspacing="0"><tbody>
      <tr><td class="en-title">Leave ID</td><td class="data-cell" colspan="2"><?= $sc ?></td><td class="ar-title">رمز الإجازة</td></tr>
      <tr class="blue-row"><td class="en-title" style="color:white;">Leave Duration</td><td class="data-cell"><?= $durationEn ?></td><td class="data-cell ar-text" dir="rtl"><?= $durationAr ?></td><td class="ar-title" style="color:white;">مدة الإجازة</td></tr>
      <tr><td class="en-title">Admission Date</td><td class="data-cell date-cell"><?= $startEn ?></td><td class="data-cell date-cell" dir="ltr"><?= $startHj ?></td><td class="ar-title">تاريخ الدخول</td></tr>
      <tr class="gray-row"><td class="en-title">Discharge Date</td><td class="data-cell date-cell"><?= $endEn ?></td><td class="data-cell date-cell" dir="ltr"><?= $endHj ?></td><td class="ar-title">تاريخ الخروج</td></tr>
      <tr><td class="en-title">Issue Date</td><td class="data-cell" colspan="2"><?= $issueEn ?></td><td class="ar-title">تاريخ الإصدار</td></tr>
      <tr class="gray-row"><td class="en-title">Patient Name</td><td class="data-cell en-spaced"><?= $patNameEn ?></td><td class="data-cell ar-text"><?= $patNameAr ?></td><td class="ar-title">الاسم</td></tr>
      <tr><td class="en-title">National ID / Iqama</td><td class="data-cell" colspan="2"><?= $patId ?></td><td class="ar-title">رقم الهوية<span class="thin-slash">/</span>الإقامة</td></tr>
      <tr class="gray-row"><td class="en-title">Nationality</td><td class="data-cell en-spaced"><?= $natEn ?></td><td class="data-cell ar-text"><?= $natAr ?></td><td class="ar-title">الجنسية</td></tr>
      <tr><td class="en-title">Employer</td><td class="data-cell en-spaced"><?= $empEn ?></td><td class="data-cell ar-text"><?= $empAr ?></td><td class="ar-title">جهة العمل</td></tr>
      <tr class="gray-row"><td class="en-title">Physician Name</td><td class="data-cell en-spaced"><?= $docNameEn ?></td><td class="data-cell ar-text"><?= $docNameAr ?></td><td class="ar-title">اسم الطبيب المعالج</td></tr>
      <tr><td class="en-title">Position</td><td class="data-cell en-spaced"><?= $docTitleEn ?></td><td class="data-cell ar-text"><?= $docTitleAr ?></td><td class="ar-title">المسمى الوظيفي</td></tr>
    </tbody></table>
    <div class="vertical-divider"></div>
    <div class="group1-thq-hospitallogoandthename-elm">
      <div class="placeholder-logo-hospital"><?= $hospLogoHtml ?></div>
      <span class="group1-thq-text-elm18">
        <span style="font-family:'Noto Sans Arabic',sans-serif;font-weight:700;"><?= $hospNameAr ?></span><br/>
        <span class="en-spaced" style="font-family:'Times New Roman',serif;font-weight:700;"><?= $hospNameEn ?></span><br/>
        <?php if (!empty($licenseHtml)) echo $licenseHtml; ?>
      </span>
    </div>
    <div class="group1-thq-thedateofissueandalsotimeofissue-elm">
      <span class="group1-thq-text-elm22">
        <span><?= $timestampLine ?></span><br/>
        <span><?= $dateLine ?></span>
      </span>
    </div>
  </div>
</div>
</body>
</html>
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

    // تحديث الحصة من DB
    $stmt2 = $pdo->prepare("SELECT allowed_days FROM patient_accounts WHERE user_id = ?");
    $stmt2->execute([$userId]);
    $paRow = $stmt2->fetch();
    if ($paRow) {
        $_SESSION['patient_allowed_days'] = (int)$paRow['allowed_days'];
        $allowedDays = (int)$paRow['allowed_days'];
    }

    // بيانات المريض
    $stmt = $pdo->prepare("SELECT * FROM patients WHERE id = ?");
    $stmt->execute([$patientId]);
    $patientData = $stmt->fetch();

    // إجازاتي الحقيقية
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

    // المستشفيات
    $hospitals = $pdo->query("SELECT id, name_ar, name_en FROM hospitals ORDER BY name_ar")->fetchAll();

    // الأيام المستخدمة
    $usedDays = getUsedDaysUser($pdo, $patientId, $userId);
    $remainingDays = max(0, $allowedDays - $usedDays);
}
?>
<!DOCTYPE html>
<html lang="ar" dir="rtl">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>بوابة المرضى - Patient Portal</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link href="https://fonts.googleapis.com/css2?family=Cairo:wght@300;400;500;600;700;800;900&display=swap" rel="stylesheet">
<style>
:root {
  --primary: #1e40af;
  --primary-light: #3b82f6;
  --primary-glow: rgba(59,130,246,0.3);
  --secondary: #0f172a;
  --accent: #06b6d4;
  --success: #10b981;
  --warning: #f59e0b;
  --danger: #ef4444;
  --bg: #f0f4ff;
  --card: #ffffff;
  --text: #1e293b;
  --text-muted: #64748b;
  --border: #e2e8f0;
  --radius: 14px;
  --radius-lg: 20px;
  --shadow: 0 4px 24px rgba(30,64,175,0.08);
  --shadow-lg: 0 12px 48px rgba(30,64,175,0.15);
  --transition: all 0.3s cubic-bezier(0.4,0,0.2,1);
}
* { margin:0; padding:0; box-sizing:border-box; }
body { font-family:'Cairo',sans-serif; background:var(--bg); color:var(--text); min-height:100vh; direction:rtl; }

/* ═══ صفحة تسجيل الدخول ═══ */
.login-page {
  min-height:100vh; display:flex; align-items:center; justify-content:center;
  background:linear-gradient(-45deg,#0f172a,#1e3a8a,#1e40af,#0c4a6e,#0f172a);
  background-size:400% 400%; animation:gradientShift 15s ease infinite;
  padding:20px; position:relative; overflow:hidden;
}
.login-page::before {
  content:''; position:absolute; width:600px; height:600px;
  background:radial-gradient(circle,rgba(59,130,246,0.15) 0%,transparent 70%);
  top:-200px; right:-200px; border-radius:50%; animation:float 8s ease-in-out infinite;
}
.login-card {
  background:rgba(255,255,255,0.95); backdrop-filter:blur(30px);
  border-radius:24px; padding:48px 40px; width:100%; max-width:440px;
  box-shadow:0 40px 100px rgba(0,0,0,0.3); animation:slideUp 0.7s cubic-bezier(0.34,1.56,0.64,1);
  position:relative; z-index:2;
}
.login-icon { text-align:center; font-size:64px; margin-bottom:16px; animation:float 4s ease-in-out infinite; }
.login-card h2 { text-align:center; font-size:26px; font-weight:800; color:var(--primary); margin-bottom:6px; }
.login-card .subtitle { text-align:center; color:var(--text-muted); font-size:14px; margin-bottom:32px; }
.form-group { margin-bottom:18px; }
.form-group label { display:block; font-size:13px; font-weight:600; color:var(--text); margin-bottom:8px; }
.form-control {
  width:100%; padding:12px 16px; border:2px solid var(--border); border-radius:10px;
  font-family:'Cairo',sans-serif; font-size:15px; color:var(--text); background:#f8fafc;
  transition:var(--transition); outline:none;
}
.form-control:focus { border-color:var(--primary-light); background:#fff; box-shadow:0 0 0 4px var(--primary-glow); }
.btn {
  display:inline-flex; align-items:center; justify-content:center; gap:8px;
  padding:12px 24px; border:none; border-radius:10px; font-family:'Cairo',sans-serif;
  font-size:15px; font-weight:700; cursor:pointer; transition:var(--transition); text-decoration:none;
}
.btn-primary { background:linear-gradient(135deg,var(--primary),var(--primary-light)); color:#fff; box-shadow:0 4px 16px var(--primary-glow); }
.btn-primary:hover { transform:translateY(-2px); box-shadow:0 8px 24px var(--primary-glow); }
.btn-full { width:100%; }
.alert { padding:12px 16px; border-radius:10px; font-size:14px; font-weight:600; margin-bottom:16px; }
.alert-danger { background:#fef2f2; color:#dc2626; border:1px solid #fecaca; }
.alert-success { background:#f0fdf4; color:#16a34a; border:1px solid #bbf7d0; }
.alert-warning { background:#fffbeb; color:#d97706; border:1px solid #fde68a; }

/* ═══ الشريط العلوي ═══ */
.navbar {
  background:linear-gradient(135deg,#0f172a,#1e3a8a); padding:14px 28px;
  display:flex; align-items:center; justify-content:space-between;
  box-shadow:0 4px 24px rgba(0,0,0,0.2); position:sticky; top:0; z-index:100;
}
.navbar .brand { display:flex; align-items:center; gap:12px; color:#fff; font-size:18px; font-weight:800; }
.navbar .brand-icon { width:40px; height:40px; background:linear-gradient(135deg,var(--primary-light),var(--accent)); border-radius:10px; display:flex; align-items:center; justify-content:center; font-size:20px; }
.navbar .user-info { display:flex; align-items:center; gap:12px; color:rgba(255,255,255,0.9); font-size:14px; }
.navbar .user-badge { background:rgba(255,255,255,0.1); border:1px solid rgba(255,255,255,0.15); padding:6px 14px; border-radius:50px; display:flex; align-items:center; gap:8px; }
.btn-logout { background:rgba(239,68,68,0.15); color:#fca5a5; border:1px solid rgba(239,68,68,0.3); padding:7px 16px; border-radius:8px; font-family:'Cairo',sans-serif; font-size:13px; font-weight:600; cursor:pointer; transition:var(--transition); }
.btn-logout:hover { background:rgba(239,68,68,0.3); color:#fff; }

/* ═══ المحتوى ═══ */
.main-content { max-width:1100px; margin:0 auto; padding:28px 20px; }
.stats-grid { display:grid; grid-template-columns:repeat(auto-fit,minmax(200px,1fr)); gap:16px; margin-bottom:28px; }
.stat-card { background:var(--card); border-radius:var(--radius); padding:20px 24px; box-shadow:var(--shadow); border:1px solid var(--border); display:flex; align-items:center; gap:16px; transition:var(--transition); animation:cardAppear 0.5s ease both; }
.stat-card:hover { transform:translateY(-3px); box-shadow:var(--shadow-lg); }
.stat-icon { width:52px; height:52px; border-radius:12px; display:flex; align-items:center; justify-content:center; font-size:24px; flex-shrink:0; }
.stat-icon.blue { background:linear-gradient(135deg,#dbeafe,#bfdbfe); }
.stat-icon.green { background:linear-gradient(135deg,#d1fae5,#a7f3d0); }
.stat-icon.orange { background:linear-gradient(135deg,#fef3c7,#fde68a); }
.stat-icon.red { background:linear-gradient(135deg,#fee2e2,#fecaca); }
.stat-info .num { font-size:28px; font-weight:800; color:var(--text); line-height:1; }
.stat-info .label { font-size:13px; color:var(--text-muted); margin-top:4px; }
.card { background:var(--card); border-radius:var(--radius-lg); box-shadow:var(--shadow); border:1px solid var(--border); overflow:hidden; margin-bottom:24px; animation:cardAppear 0.5s ease both; }
.card-header { padding:20px 24px; border-bottom:1px solid var(--border); display:flex; align-items:center; justify-content:space-between; background:linear-gradient(135deg,#f8faff,#eff6ff); }
.card-header h3 { font-size:17px; font-weight:700; color:var(--primary); display:flex; align-items:center; gap:10px; }
.card-body { padding:24px; }
.patient-info-grid { display:grid; grid-template-columns:repeat(auto-fit,minmax(220px,1fr)); gap:14px; }
.info-field { background:#f8fafc; border:1px solid var(--border); border-radius:10px; padding:12px 16px; }
.info-field .field-label { font-size:11px; font-weight:600; color:var(--text-muted); text-transform:uppercase; letter-spacing:0.5px; margin-bottom:6px; }
.info-field .field-value { font-size:15px; font-weight:600; color:var(--text); }
.info-field .field-value-en { font-size:12px; color:var(--text-muted); direction:ltr; text-align:left; margin-top:2px; }
.quota-bar-wrap { background:#f1f5f9; border-radius:50px; height:12px; overflow:hidden; margin:10px 0; }
.quota-bar { height:100%; border-radius:50px; background:linear-gradient(90deg,var(--success),#34d399); transition:width 1s ease; }
.quota-bar.warning { background:linear-gradient(90deg,var(--warning),#fbbf24); }
.quota-bar.danger { background:linear-gradient(90deg,var(--danger),#f87171); }
.leave-form-grid { display:grid; grid-template-columns:1fr 1fr; gap:18px; }
@media (max-width:640px) { .leave-form-grid { grid-template-columns:1fr; } .stats-grid { grid-template-columns:1fr 1fr; } }
.form-label { display:block; font-size:13px; font-weight:600; color:var(--text); margin-bottom:8px; }
.form-select { width:100%; padding:11px 16px; border:2px solid var(--border); border-radius:10px; font-family:'Cairo',sans-serif; font-size:14px; color:var(--text); background:#f8fafc; transition:var(--transition); outline:none; cursor:pointer; }
.form-select:focus { border-color:var(--primary-light); background:#fff; box-shadow:0 0 0 4px var(--primary-glow); }
.time-mode-tabs { display:flex; gap:8px; margin-bottom:12px; }
.time-tab { flex:1; padding:9px; border:2px solid var(--border); border-radius:8px; background:#f8fafc; font-family:'Cairo',sans-serif; font-size:13px; font-weight:600; cursor:pointer; transition:var(--transition); text-align:center; color:var(--text-muted); }
.time-tab.active { border-color:var(--primary-light); background:#eff6ff; color:var(--primary); }
.time-tab:hover:not(.active) { border-color:#94a3b8; background:#f1f5f9; }
.leaves-table { width:100%; border-collapse:collapse; font-size:14px; }
.leaves-table th { background:#f1f5f9; padding:12px 14px; text-align:right; font-weight:700; color:var(--text-muted); font-size:12px; text-transform:uppercase; letter-spacing:0.5px; border-bottom:2px solid var(--border); }
.leaves-table td { padding:14px; border-bottom:1px solid #f1f5f9; vertical-align:middle; }
.leaves-table tr:hover td { background:#f8faff; }
.btn-sm { padding:6px 14px; font-size:13px; border-radius:8px; }
.btn-outline { background:transparent; border:2px solid var(--primary-light); color:var(--primary); }
.btn-outline:hover { background:var(--primary); color:#fff; }
.modal-overlay { position:fixed; inset:0; background:rgba(0,0,0,0.5); backdrop-filter:blur(4px); z-index:1000; display:flex; align-items:center; justify-content:center; padding:20px; opacity:0; pointer-events:none; transition:opacity 0.3s ease; }
.modal-overlay.active { opacity:1; pointer-events:all; }
.modal-box { background:#fff; border-radius:20px; width:100%; max-width:560px; max-height:90vh; overflow-y:auto; box-shadow:0 40px 100px rgba(0,0,0,0.3); transform:scale(0.9) translateY(20px); transition:transform 0.3s cubic-bezier(0.34,1.56,0.64,1); }
.modal-overlay.active .modal-box { transform:scale(1) translateY(0); }
.modal-header { padding:20px 24px; border-bottom:1px solid var(--border); display:flex; align-items:center; justify-content:space-between; background:linear-gradient(135deg,#f8faff,#eff6ff); }
.modal-header h4 { font-size:17px; font-weight:700; color:var(--primary); }
.modal-close { width:32px; height:32px; border:none; background:#f1f5f9; border-radius:8px; cursor:pointer; font-size:18px; display:flex; align-items:center; justify-content:center; transition:var(--transition); color:var(--text-muted); }
.modal-close:hover { background:#fee2e2; color:var(--danger); }
.modal-body { padding:24px; }
.modal-footer { padding:16px 24px; border-top:1px solid var(--border); display:flex; gap:10px; justify-content:flex-end; }
.toast-container { position:fixed; top:80px; left:50%; transform:translateX(-50%); z-index:9999; display:flex; flex-direction:column; gap:10px; pointer-events:none; }
.toast { background:#fff; border-radius:12px; padding:14px 20px; box-shadow:0 8px 32px rgba(0,0,0,0.15); font-size:14px; font-weight:600; display:flex; align-items:center; gap:10px; min-width:280px; max-width:400px; animation:slideDown 0.4s ease; border-right:4px solid var(--primary); }
.toast.success { border-color:var(--success); }
.toast.error { border-color:var(--danger); }
.toast.warning { border-color:var(--warning); }
.spinner { width:20px; height:20px; border:3px solid rgba(255,255,255,0.3); border-top-color:#fff; border-radius:50%; animation:spin 0.8s linear infinite; display:inline-block; }
.empty-state { text-align:center; padding:48px 20px; color:var(--text-muted); }
.empty-state .empty-icon { font-size:56px; margin-bottom:16px; opacity:0.5; }
.empty-state h4 { font-size:17px; font-weight:700; margin-bottom:8px; color:var(--text); }
.empty-state p { font-size:14px; }
.days-counter { display:flex; align-items:center; gap:6px; font-size:13px; font-weight:600; color:var(--text-muted); margin-top:8px; }
.days-counter .used { color:var(--danger); }
.days-counter .remaining { color:var(--success); }
.days-counter .total { color:var(--primary); }
.full-span { grid-column:1 / -1; }
@keyframes gradientShift { 0%{background-position:0% 50%} 50%{background-position:100% 50%} 100%{background-position:0% 50%} }
@keyframes float { 0%,100%{transform:translateY(0)} 50%{transform:translateY(-12px)} }
@keyframes slideUp { from{opacity:0;transform:translateY(40px)} to{opacity:1;transform:translateY(0)} }
@keyframes slideDown { from{opacity:0;transform:translateY(-20px)} to{opacity:1;transform:translateY(0)} }
@keyframes cardAppear { from{opacity:0;transform:translateY(16px)} to{opacity:1;transform:translateY(0)} }
@keyframes spin { to{transform:rotate(360deg)} }
@media (max-width:768px) { .navbar{padding:12px 16px} .main-content{padding:16px 12px} .card-body{padding:16px} .login-card{padding:32px 24px} .leaves-table{font-size:12px} .leaves-table th,.leaves-table td{padding:10px 8px} }
</style>
</head>
<body>

<?php if (!isPatientLoggedIn()): ?>
<!-- صفحة تسجيل الدخول -->
<div class="login-page">
  <div class="login-card">
    <div class="login-icon">🏥</div>
    <h2>بوابة المرضى</h2>
    <p class="subtitle">Patient Portal — سجّل دخولك للوصول إلى ملفك الطبي</p>

    <?php if (!empty($_GET['disabled'])): ?>
    <div class="alert alert-danger">⚠️ تم تعطيل حسابك. يرجى التواصل مع الإدارة.</div>
    <?php endif; ?>

    <?php if (!empty($loginError)): ?>
    <div class="alert alert-danger">⚠️ <?= htmlspecialchars($loginError) ?></div>
    <?php endif; ?>

    <form method="POST" action="user.php">
      <input type="hidden" name="action" value="patient_login">
      <div class="form-group">
        <label for="username">اسم المستخدم</label>
        <input type="text" id="username" name="username" class="form-control"
               placeholder="أدخل اسم المستخدم" autocomplete="username" required
               value="<?= htmlspecialchars($_POST['username'] ?? '') ?>">
      </div>
      <div class="form-group">
        <label for="password">كلمة المرور</label>
        <input type="password" id="password" name="password" class="form-control"
               placeholder="أدخل كلمة المرور" autocomplete="current-password" required>
      </div>
      <button type="submit" class="btn btn-primary btn-full" style="margin-top:8px;">
        🔐 تسجيل الدخول
      </button>
    </form>
    <p style="text-align:center;margin-top:20px;font-size:12px;color:#94a3b8;">
      للحصول على حساب، يرجى التواصل مع الإدارة
    </p>
  </div>
</div>

<?php else: ?>
<!-- لوحة تحكم المريض -->
<nav class="navbar">
  <div class="brand">
    <div class="brand-icon">🏥</div>
    <span>بوابة المرضى</span>
  </div>
  <div class="user-info">
    <!-- زر الإشعارات -->
    <div style="position:relative;">
      <button id="notifBell" onclick="toggleNotifPanel()" style="background:rgba(255,255,255,0.1);border:1px solid rgba(255,255,255,0.2);color:#fff;width:40px;height:40px;border-radius:10px;cursor:pointer;font-size:20px;display:flex;align-items:center;justify-content:center;position:relative;transition:all 0.3s;">
        🔔
        <span id="notifBadge" style="display:none;position:absolute;top:-4px;right:-4px;background:#ef4444;color:#fff;border-radius:50%;width:18px;height:18px;font-size:11px;font-weight:700;align-items:center;justify-content:center;"></span>
      </button>
      <!-- لوحة الإشعارات -->
      <div id="notifPanel" style="display:none;position:absolute;top:50px;left:0;width:320px;background:#fff;border-radius:14px;box-shadow:0 20px 60px rgba(0,0,0,0.3);z-index:999;overflow:hidden;border:1px solid #e2e8f0;">
        <div style="padding:14px 16px;background:linear-gradient(135deg,#1e40af,#3b82f6);color:#fff;display:flex;align-items:center;justify-content:space-between;">
          <span style="font-weight:700;font-size:14px;">🔔 الإشعارات</span>
          <button onclick="markAllRead()" style="background:rgba(255,255,255,0.2);border:none;color:#fff;padding:4px 10px;border-radius:6px;font-size:12px;cursor:pointer;font-family:'Cairo',sans-serif;">تحديد كمقروء</button>
        </div>
        <div id="notifList" style="max-height:300px;overflow-y:auto;padding:8px 0;">
          <div style="text-align:center;padding:20px;color:#94a3b8;font-size:13px;">جاري التحميل...</div>
        </div>
      </div>
    </div>
    <div class="user-badge">
      <span>👤</span>
      <span><?= htmlspecialchars($_SESSION['patient_display_name']) ?></span>
    </div>
    <form method="POST" action="user.php" style="margin:0;">
      <input type="hidden" name="action" value="logout">
      <button type="submit" class="btn-logout">تسجيل الخروج</button>
    </form>
  </div>
</nav>

<div class="main-content">

  <!-- بطاقات الإحصاء -->
  <div class="stats-grid">
    <div class="stat-card">
      <div class="stat-icon blue">📋</div>
      <div class="stat-info">
        <div class="num"><?= $allowedDays ?></div>
        <div class="label">إجمالي الأيام المسموحة</div>
      </div>
    </div>
    <div class="stat-card">
      <div class="stat-icon green">✅</div>
      <div class="stat-info">
        <div class="num"><?= $remainingDays ?></div>
        <div class="label">الأيام المتبقية</div>
      </div>
    </div>
    <div class="stat-card">
      <div class="stat-icon orange">📅</div>
      <div class="stat-info">
        <div class="num"><?= $usedDays ?></div>
        <div class="label">الأيام المستخدمة</div>
      </div>
    </div>
    <div class="stat-card">
      <div class="stat-icon red">📄</div>
      <div class="stat-info">
        <div class="num"><?= count($myLeaves) ?></div>
        <div class="label">إجمالي الإجازات</div>
      </div>
    </div>
  </div>

  <!-- بيانات المريض -->
  <?php if ($patientData): ?>
  <div class="card">
    <div class="card-header">
      <h3>👤 بياناتي الشخصية</h3>
      <span style="font-size:12px;color:var(--text-muted);">للعرض فقط</span>
    </div>
    <div class="card-body">
      <div class="patient-info-grid">
        <div class="info-field">
          <div class="field-label">الاسم بالعربية</div>
          <div class="field-value"><?= htmlspecialchars($patientData['name_ar'] ?? $patientData['name'] ?? '') ?></div>
          <?php if (!empty($patientData['name_en'])): ?>
          <div class="field-value-en"><?= htmlspecialchars($patientData['name_en']) ?></div>
          <?php endif; ?>
        </div>
        <div class="info-field">
          <div class="field-label">رقم الهوية / الإقامة</div>
          <div class="field-value" style="direction:ltr;text-align:right;"><?= htmlspecialchars($patientData['identity_number'] ?? '') ?></div>
        </div>
        <?php if (!empty($patientData['nationality_ar'])): ?>
        <div class="info-field">
          <div class="field-label">الجنسية</div>
          <div class="field-value"><?= htmlspecialchars($patientData['nationality_ar']) ?></div>
          <?php if (!empty($patientData['nationality_en'])): ?><div class="field-value-en"><?= htmlspecialchars($patientData['nationality_en']) ?></div><?php endif; ?>
        </div>
        <?php endif; ?>
        <?php if (!empty($patientData['employer_ar'])): ?>
        <div class="info-field">
          <div class="field-label">جهة العمل</div>
          <div class="field-value"><?= htmlspecialchars($patientData['employer_ar']) ?></div>
          <?php if (!empty($patientData['employer_en'])): ?><div class="field-value-en"><?= htmlspecialchars($patientData['employer_en']) ?></div><?php endif; ?>
        </div>
        <?php endif; ?>
        <?php if (!empty($patientData['phone'])): ?>
        <div class="info-field">
          <div class="field-label">رقم الجوال</div>
          <div class="field-value" style="direction:ltr;text-align:right;"><?= htmlspecialchars($patientData['phone']) ?></div>
        </div>
        <?php endif; ?>
      </div>

      <!-- شريط الحصة -->
      <div style="margin-top:20px;">
        <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:8px;">
          <span style="font-size:13px;font-weight:700;color:var(--text);">حصة الإجازات المرضية</span>
          <span style="font-size:13px;font-weight:700;color:var(--primary);"><?= $usedDays ?> / <?= $allowedDays ?> يوم</span>
        </div>
        <?php
          $pct = $allowedDays > 0 ? min(100, round($usedDays / $allowedDays * 100)) : 0;
          $barClass = $pct >= 90 ? 'danger' : ($pct >= 60 ? 'warning' : '');
        ?>
        <div class="quota-bar-wrap">
          <div class="quota-bar <?= $barClass ?>" style="width:<?= $pct ?>%"></div>
        </div>
        <div class="days-counter">
          <span>مستخدم: <span class="used"><?= $usedDays ?></span></span>
          <span>•</span>
          <span>متبقي: <span class="remaining"><?= $remainingDays ?></span></span>
          <span>•</span>
          <span>المسموح: <span class="total"><?= $allowedDays ?></span></span>
        </div>
      </div>
    </div>
  </div>
  <?php endif; ?>

  <!-- نموذج إنشاء إجازة مرضية -->
  <?php if ($remainingDays > 0): ?>
  <div class="card">
    <div class="card-header">
      <h3>📝 إنشاء إجازة مرضية جديدة</h3>
      <span style="font-size:12px;background:#d1fae5;color:#059669;padding:4px 12px;border-radius:50px;font-weight:700;">
        متبقي: <?= $remainingDays ?> يوم
      </span>
    </div>
    <div class="card-body">
      <form id="leaveForm">
        <div class="leave-form-grid">

          <!-- المستشفى -->
          <div>
            <label class="form-label">🏥 المستشفى / المنشأة <span style="color:red">*</span></label>
            <select class="form-select" id="hospitalSelect" name="hospital_id" required onchange="loadDoctors(this.value)">
              <option value="">-- اختر المستشفى --</option>
              <?php foreach ($hospitals as $h): ?>
              <option value="<?= $h['id'] ?>"><?= htmlspecialchars($h['name_ar']) ?></option>
              <?php endforeach; ?>
            </select>
          </div>

          <!-- الطبيب -->
          <div>
            <label class="form-label">👨‍⚕️ الطبيب <span style="color:red">*</span></label>
            <select class="form-select" id="doctorSelect" name="doctor_id" required>
              <option value="">-- اختر المستشفى أولاً --</option>
            </select>
          </div>

          <!-- تاريخ البداية -->
          <div>
            <label class="form-label">📅 تاريخ بداية الإجازة <span style="color:red">*</span></label>
            <input type="date" class="form-control" id="startDate" name="start_date" required
                   min="<?= date('Y-m-d') ?>" onchange="calcDays()">
          </div>

          <!-- تاريخ النهاية -->
          <div>
            <label class="form-label">📅 تاريخ نهاية الإجازة <span style="color:red">*</span></label>
            <input type="date" class="form-control" id="endDate" name="end_date" required
                   min="<?= date('Y-m-d') ?>" onchange="calcDays()">
          </div>

          <!-- عدد الأيام -->
          <div>
            <label class="form-label">🔢 عدد الأيام</label>
            <input type="number" class="form-control" id="daysDisplay" readonly
                   placeholder="سيُحسب تلقائياً" style="background:#f1f5f9;cursor:not-allowed;">
            <input type="hidden" id="daysCount" name="days_count">
            <div id="daysWarning" style="display:none;margin-top:6px;" class="alert alert-warning"></div>
          </div>

          <!-- وقت الإصدار -->
          <div>
            <label class="form-label">🕐 وقت إصدار الإجازة</label>
            <div class="time-mode-tabs">
              <button type="button" class="time-tab active" onclick="setTimeMode('auto',this)">تلقائي</button>
              <button type="button" class="time-tab" onclick="setTimeMode('random',this)">عشوائي</button>
              <button type="button" class="time-tab" onclick="setTimeMode('manual',this)">يدوي</button>
            </div>
            <input type="hidden" id="timeModeInput" name="time_mode" value="auto">
            <div id="manualTimeFields" style="display:none;">
              <div style="display:flex;gap:8px;align-items:center;">
                <input type="time" class="form-control" id="manualTimeInput" name="manual_time" style="flex:1;">
                <select class="form-select" name="manual_period" style="width:100px;">
                  <option value="AM">صباحاً</option>
                  <option value="PM">مساءً</option>
                </select>
              </div>
            </div>
            <div id="autoTimeInfo" style="font-size:12px;color:var(--text-muted);margin-top:6px;">
              ⏰ سيُستخدم وقت الإنشاء تلقائياً
            </div>
          </div>

        </div>

        <div style="margin-top:20px;display:flex;gap:12px;justify-content:flex-end;">
          <button type="button" class="btn btn-primary" onclick="createLeave()" id="submitBtn">
            📄 إنشاء الإجازة
          </button>
        </div>
      </form>
    </div>
  </div>
  <?php else: ?>
  <div class="card">
    <div class="card-body">
      <div class="empty-state">
        <div class="empty-icon">🚫</div>
        <h4>لا يمكن إنشاء إجازة مرضية</h4>
        <p style="margin-bottom:20px;">
          <?php if ($allowedDays === 0): ?>
            لم يتم تخصيص أيام إجازة لحسابك بعد. يرجى التواصل مع الإدارة لطلب إجازات إضافية.
          <?php else: ?>
            لقد استنفدت جميع أيام الإجازة المسموحة (<?= $allowedDays ?> يوم). لطلب إجازات إضافية يرجى التواصل معنا.
          <?php endif; ?>
        </p>
        <a href="https://wa.me/966573436223" target="_blank"
           style="display:inline-flex;align-items:center;gap:10px;background:linear-gradient(135deg,#25d366,#128c7e);color:#fff;padding:14px 28px;border-radius:12px;font-size:16px;font-weight:700;text-decoration:none;box-shadow:0 4px 16px rgba(37,211,102,0.4);transition:all 0.3s;"
           onmouseover="this.style.transform='translateY(-2px)';this.style.boxShadow='0 8px 24px rgba(37,211,102,0.5)'"
           onmouseout="this.style.transform='translateY(0)';this.style.boxShadow='0 4px 16px rgba(37,211,102,0.4)'">
          <svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="white">
            <path d="M17.472 14.382c-.297-.149-1.758-.867-2.03-.967-.273-.099-.471-.148-.67.15-.197.297-.767.966-.94 1.164-.173.199-.347.223-.644.075-.297-.15-1.255-.463-2.39-1.475-.883-.788-1.48-1.761-1.653-2.059-.173-.297-.018-.458.13-.606.134-.133.298-.347.446-.52.149-.174.198-.298.298-.497.099-.198.05-.371-.025-.52-.075-.149-.669-1.612-.916-2.207-.242-.579-.487-.5-.669-.51-.173-.008-.371-.01-.57-.01-.198 0-.52.074-.792.372-.272.297-1.04 1.016-1.04 2.479 0 1.462 1.065 2.875 1.213 3.074.149.198 2.096 3.2 5.077 4.487.709.306 1.262.489 1.694.625.712.227 1.36.195 1.871.118.571-.085 1.758-.719 2.006-1.413.248-.694.248-1.289.173-1.413-.074-.124-.272-.198-.57-.347m-5.421 7.403h-.004a9.87 9.87 0 01-5.031-1.378l-.361-.214-3.741.982.998-3.648-.235-.374a9.86 9.86 0 01-1.51-5.26c.001-5.45 4.436-9.884 9.888-9.884 2.64 0 5.122 1.03 6.988 2.898a9.825 9.825 0 012.893 6.994c-.003 5.45-4.437 9.884-9.885 9.884m8.413-18.297A11.815 11.815 0 0012.05 0C5.495 0 .16 5.335.157 11.892c0 2.096.547 4.142 1.588 5.945L.057 24l6.305-1.654a11.882 11.882 0 005.683 1.448h.005c6.554 0 11.89-5.335 11.893-11.893a11.821 11.821 0 00-3.48-8.413z"/>
          </svg>
          تواصل معنا على واتساب لطلب إجازات إضافية
        </a>
        <p style="margin-top:12px;font-size:12px;color:#94a3b8;">اضغط على الزر أعلاه للتواصل المباشر عبر واتساب</p>
      </div>
    </div>
  </div>
  <?php endif; ?>

  <!-- سجل الإجازات -->
  <div class="card">
    <div class="card-header">
      <h3>📋 سجل إجازاتي المرضية</h3>
      <span style="font-size:12px;color:var(--text-muted);"><?= count($myLeaves) ?> إجازة</span>
    </div>
    <div class="card-body" style="padding:0;">
      <?php if (empty($myLeaves)): ?>
      <div class="empty-state">
        <div class="empty-icon">📭</div>
        <h4>لا توجد إجازات بعد</h4>
        <p>لم تُنشئ أي إجازة مرضية حتى الآن.</p>
      </div>
      <?php else: ?>
      <div style="overflow-x:auto;">
        <table class="leaves-table">
          <thead>
            <tr>
              <th>#</th>
              <th>رمز الإجازة</th>
              <th>المستشفى</th>
              <th>الطبيب</th>
              <th>من</th>
              <th>إلى</th>
              <th>الأيام</th>
              <th>الوقت</th>
              <th>PDF</th>
            </tr>
          </thead>
          <tbody>
            <?php foreach ($myLeaves as $i => $lv): ?>
            <tr>
              <td style="color:var(--text-muted);font-size:12px;"><?= $i + 1 ?></td>
              <td style="font-weight:700;color:var(--primary);font-size:12px;direction:ltr;text-align:right;"><?= htmlspecialchars($lv['service_code'] ?? '') ?></td>
              <td style="font-weight:600;"><?= htmlspecialchars($lv['h_name_ar'] ?? '') ?></td>
              <td>
                <div style="font-weight:600;"><?= htmlspecialchars($lv['d_name_ar'] ?? '') ?></div>
                <div style="font-size:11px;color:var(--text-muted);"><?= htmlspecialchars($lv['d_title_ar'] ?? '') ?></div>
              </td>
              <td style="direction:ltr;text-align:right;"><?= fmtDateUser($lv['start_date']) ?></td>
              <td style="direction:ltr;text-align:right;"><?= fmtDateUser($lv['end_date']) ?></td>
              <td>
                <span style="background:#eff6ff;color:var(--primary);padding:3px 10px;border-radius:50px;font-weight:700;font-size:13px;">
                  <?= $lv['days_count'] ?>
                </span>
              </td>
              <td style="font-size:12px;direction:ltr;text-align:right;">
                <?= htmlspecialchars($lv['issue_time'] ?? '') ?>
                <?= $lv['issue_period'] === 'AM' ? 'ص' : ($lv['issue_period'] === 'PM' ? 'م' : '') ?>
              </td>
              <td>
                <a href="user.php?action=generate_pdf&leave_id=<?= $lv['id'] ?>"
                   target="_blank" class="btn btn-outline btn-sm">
                  📄 PDF
                </a>
              </td>
            </tr>
            <?php endforeach; ?>
          </tbody>
        </table>
      </div>
      <?php endif; ?>
    </div>
  </div>

</div><!-- /main-content -->

<!-- Toast Container -->
<div class="toast-container" id="toastContainer"></div>

<script>
const MAX_DAYS = <?= $remainingDays ?>;

function loadDoctors(hospitalId) {
  const sel = document.getElementById('doctorSelect');
  sel.innerHTML = '<option value="">جاري التحميل...</option>';
  if (!hospitalId) { sel.innerHTML = '<option value="">-- اختر المستشفى أولاً --</option>'; return; }
  fetch('user.php?action=get_doctors_by_hospital&hospital_id=' + hospitalId)
    .then(r => r.json())
    .then(data => {
      if (data.success && data.doctors.length > 0) {
        sel.innerHTML = '<option value="">-- اختر الطبيب --</option>';
        data.doctors.forEach(d => {
          sel.innerHTML += `<option value="${d.id}">${d.name_ar} — ${d.title_ar}</option>`;
        });
      } else {
        sel.innerHTML = '<option value="">لا يوجد أطباء مرتبطون بهذا المستشفى</option>';
      }
    })
    .catch(() => { sel.innerHTML = '<option value="">خطأ في التحميل</option>'; });
}

function calcDays() {
  const start = document.getElementById('startDate').value;
  const end   = document.getElementById('endDate').value;
  const display = document.getElementById('daysDisplay');
  const hidden  = document.getElementById('daysCount');
  const warning = document.getElementById('daysWarning');
  if (!start || !end) { display.value = ''; hidden.value = ''; return; }
  const s = new Date(start), e = new Date(end);
  if (e < s) {
    display.value = ''; hidden.value = '';
    warning.style.display = 'block';
    warning.textContent = '⚠️ تاريخ النهاية يجب أن يكون بعد تاريخ البداية.';
    return;
  }
  const diff = Math.round((e - s) / (1000 * 60 * 60 * 24)) + 1;
  display.value = diff + ' يوم';
  hidden.value  = diff;
  if (diff > MAX_DAYS) {
    warning.style.display = 'block';
    warning.textContent = `⚠️ عدد الأيام (${diff}) يتجاوز الحصة المتبقية (${MAX_DAYS} يوم).`;
  } else {
    warning.style.display = 'none';
  }
  document.getElementById('endDate').min = start;
}

function setTimeMode(mode, btn) {
  document.querySelectorAll('.time-tab').forEach(t => t.classList.remove('active'));
  btn.classList.add('active');
  document.getElementById('timeModeInput').value = mode;
  const mf = document.getElementById('manualTimeFields');
  const ai = document.getElementById('autoTimeInfo');
  if (mode === 'manual') { mf.style.display = 'block'; ai.style.display = 'none'; }
  else if (mode === 'random') { mf.style.display = 'none'; ai.style.display = 'block'; ai.textContent = '🎲 سيتم اختيار وقت عشوائي بين 8 صباحاً و 5 مساءً'; }
  else { mf.style.display = 'none'; ai.style.display = 'block'; ai.textContent = '⏰ سيُستخدم وقت الإنشاء تلقائياً'; }
}

function createLeave() {
  const hospitalId = document.getElementById('hospitalSelect').value;
  const doctorId   = document.getElementById('doctorSelect').value;
  const startDate  = document.getElementById('startDate').value;
  const endDate    = document.getElementById('endDate').value;
  const daysCount  = document.getElementById('daysCount').value;

  if (!hospitalId) { showToast('يرجى اختيار المستشفى.', 'error'); return; }
  if (!doctorId)   { showToast('يرجى اختيار الطبيب.', 'error'); return; }
  if (!startDate)  { showToast('يرجى تحديد تاريخ البداية.', 'error'); return; }
  if (!endDate)    { showToast('يرجى تحديد تاريخ النهاية.', 'error'); return; }
  if (!daysCount || parseInt(daysCount) <= 0) { showToast('يرجى التحقق من التواريخ.', 'error'); return; }
  if (parseInt(daysCount) > MAX_DAYS) { showToast(`عدد الأيام يتجاوز الحصة المتبقية (${MAX_DAYS} يوم).`, 'error'); return; }

  const btn = document.getElementById('submitBtn');
  btn.disabled = true;
  btn.innerHTML = '<span class="spinner"></span> جاري الإنشاء...';

  const formData = new FormData(document.getElementById('leaveForm'));
  formData.append('action', 'create_sick_leave');

  fetch('user.php', { method: 'POST', body: formData })
    .then(r => r.json())
    .then(data => {
      if (data.success) {
        showToast('✅ ' + data.message + ' — رمز الإجازة: ' + data.service_code, 'success');
        setTimeout(() => {
          // فتح صفحة PDF مع زر التحميل
          window.open('user.php?action=generate_pdf&leave_id=' + data.leave_id, '_blank');
          setTimeout(() => location.reload(), 1000);
        }, 1500);
      } else {
        showToast(data.message || 'حدث خطأ.', 'error');
        btn.disabled = false;
        btn.innerHTML = '📄 إنشاء الإجازة';
      }
    })
    .catch(() => {
      showToast('خطأ في الاتصال. يرجى المحاولة مجدداً.', 'error');
      btn.disabled = false;
      btn.innerHTML = '📄 إنشاء الإجازة';
    });
}

function showToast(msg, type = 'success') {
  const container = document.getElementById('toastContainer');
  const icons = { success: '✅', error: '❌', warning: '⚠️' };
  const toast = document.createElement('div');
  toast.className = `toast ${type}`;
  toast.innerHTML = `<span>${icons[type] || '💬'}</span><span>${msg}</span>`;
  container.appendChild(toast);
  setTimeout(() => {
    toast.style.opacity = '0';
    toast.style.transform = 'translateY(-10px)';
    toast.style.transition = 'all 0.3s ease';
    setTimeout(() => toast.remove(), 300);
  }, 5000);
}

// ===== نظام الإشعارات =====
let notifPanelOpen = false;

function toggleNotifPanel() {
  const panel = document.getElementById('notifPanel');
  notifPanelOpen = !notifPanelOpen;
  panel.style.display = notifPanelOpen ? 'block' : 'none';
  if (notifPanelOpen) loadNotifications();
}

// إغلاق اللوحة عند النقر خارجها
document.addEventListener('click', function(e) {
  const bell = document.getElementById('notifBell');
  const panel = document.getElementById('notifPanel');
  if (panel && bell && !bell.contains(e.target) && !panel.contains(e.target)) {
    panel.style.display = 'none';
    notifPanelOpen = false;
  }
});

async function loadNotifications() {
  try {
    const res = await fetch('user.php?action=get_user_notifications');
    const data = await res.json();
    if (data.success) {
      const list = document.getElementById('notifList');
      const badge = document.getElementById('notifBadge');
      if (data.unread_count > 0) {
        badge.style.display = 'flex';
        badge.textContent = data.unread_count > 9 ? '9+' : data.unread_count;
      } else {
        badge.style.display = 'none';
      }
      if (!data.notifications || data.notifications.length === 0) {
        list.innerHTML = '<div style="text-align:center;padding:24px;color:#94a3b8;font-size:13px;">لا توجد إشعارات</div>';
        return;
      }
      list.innerHTML = data.notifications.map(n => `
        <div style="padding:12px 16px;border-bottom:1px solid #f1f5f9;background:${n.is_read == 0 ? '#eff6ff' : '#fff'};transition:background 0.3s;">
          <div style="font-size:13px;font-weight:${n.is_read == 0 ? '700' : '400'};color:#1e293b;line-height:1.5;">${escapeHtml(n.message)}</div>
          <div style="font-size:11px;color:#94a3b8;margin-top:4px;">${n.created_at}</div>
        </div>
      `).join('');
    }
  } catch(e) {}
}

async function markAllRead() {
  try {
    const fd = new FormData();
    fd.append('action', 'mark_user_notifications_read');
    await fetch('user.php', { method: 'POST', body: fd });
    document.getElementById('notifBadge').style.display = 'none';
    loadNotifications();
  } catch(e) {}
}

function escapeHtml(str) {
  const d = document.createElement('div');
  d.textContent = str;
  return d.innerHTML;
}

// تحميل عدد الإشعارات غير المقروءة عند فتح الصفحة
(async function() {
  try {
    const res = await fetch('user.php?action=get_user_notifications');
    const data = await res.json();
    if (data.success && data.unread_count > 0) {
      const badge = document.getElementById('notifBadge');
      if (badge) {
        badge.style.display = 'flex';
        badge.textContent = data.unread_count > 9 ? '9+' : data.unread_count;
      }
    }
  } catch(e) {}
})();
</script>

<?php endif; ?>
</body>
</html>
