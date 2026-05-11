<?php
/**
 * بوابة المرضى - user.php
 * المرضى يُنشئون إجازات مرضية حقيقية بنفس قالب لوحة التحكم
 * (نسخة مطورة بتصميم احترافي + Dark Mode + بقاء بنفس الصفحة)
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

    $prefix = $hosp['service_prefix'] ?? 'GSL';
    $serviceCode = generateServiceCodeUser($pdo, $prefix, $startDate);

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
        'message'        => 'تم إنشاء الإجازة المرضية بنجاح وتوثيقها في السجل.',
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
    $durationAr = '<span style="font-family: \'Times New Roman\', serif; font-size: 14.5px; font-weight: 400;">' . $daysAr . '</span> <span style="font-family: \'Noto Sans Arabic\', sans-serif; font-size: 14.5px; font-weight: 400;">' . $daysArWord . '</span> ( ' . formatHijriDateSpanUser($startHj) . ' <span style="font-family: \'Noto Sans Arabic\', sans-serif; font-size: 13.5px; font-weight: 400;">إلى</span> ' . formatHijriDateSpanUser($endHj) . ' )';

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
        @unlink($tmpHtml);
    }

    header('Content-Type: text/html; charset=utf-8');
    ?>
<!DOCTYPE html>
<html lang="ar">
<head>
<title>تقرير إجازة مرضية - Sick Leave Report</title>
<meta name="viewport" content="width=device-width, initial-scale=1.0" />
<meta charset="utf-8" />
<style>
html { line-height: 1.15; font-family: Inter, sans-serif; font-size: 16px; }
body { margin: 0; font-weight: 400; color: #191818; background: #FBFAF9; overflow-x: hidden; }
* { box-sizing: border-box; border-width: 0; border-style: solid; -webkit-font-smoothing: antialiased; }
p, li, ul, pre, div, h1, h2, h3, h4, h5, h6 { margin: 0; padding: 0; }
a { color: inherit; text-decoration: inherit; }
</style>
<link rel="stylesheet" href="https://fonts.googleapis.com/css2?family=Inter:wght@100;200;300;400;500;600;700&display=swap" />
<link rel="stylesheet" href="https://fonts.googleapis.com/css2?family=STIX+Two+Text:ital,wght@0,400;0,600;0,700;1,400&display=swap" />
<link rel="stylesheet" href="https://fonts.googleapis.com/css2?family=Noto+Sans+Arabic:wght@400;600;700&display=swap" />
<style>
.group1-container1 { width: 100%; display: flex; overflow-x: hidden; min-height: 100vh; align-items: center; flex-direction: column; background-color: #f0f0f0; padding-top: 20px; padding-bottom: 20px; }
.group1-thq-group1-elm { width: 842.25px; height: 1190.25px; display: flex; position: relative; align-items: flex-start; flex-shrink: 0; box-shadow: 0px 4px 15px rgba(0,0,0,0.1); background-color: white; }
.info-table { position: absolute; top: 242px; left: 36px; width: 770px; border-collapse: separate; border-spacing: 0; border: 1px solid #cccccc; border-radius: 8px; overflow: hidden; z-index: 10; }
.info-table td { border-bottom: 1px solid #cccccc; border-right: 1px solid #cccccc; height: 42px; text-align: center; vertical-align: middle; padding: 4px 8px; }
.info-table td:last-child { border-right: none; } .info-table tr:last-child td { border-bottom: none; }
.info-table .en-title { width: 161px; color: rgba(54, 111, 181, 1); font-size: 13.5px; font-weight: 700; font-family: "Times New Roman", serif; }
.info-table .data-cell { width: 240px; color: rgba(44, 62, 119, 1); font-size: 13.5px; font-family: "Times New Roman", serif; }
.info-table .date-cell { font-size: 13.9px; } .info-table .data-cell.ar-text { font-family: "Noto Sans Arabic", sans-serif; }
.info-table .ar-title { width: 140px; color: rgba(54, 111, 181, 1); font-size: 13.5px; font-weight: 700; font-family: "Noto Sans Arabic", sans-serif; white-space: nowrap; }
.info-table tr.blue-row td { background-color: #2c3e77; color: #ffffff; border-bottom: 1px solid #cccccc; border-right: 1px solid #cccccc; }
.info-table tr.blue-row td:last-child { border-right: none; }
.info-table .blue-row .data-cell.ar-text, .info-table .blue-row .data-cell { color: #ffffff; }
.info-table tr.gray-row td { background-color: #f7f7f7; }
.en-spaced { letter-spacing: 0.3px; }
:root { --footer-offset: 40px; }
.group1-thq-staticinfo-elm { top: 125px; left: 36.65px; width: 768.35px; height: 811.91px; display: flex; position: absolute; align-items: flex-start; pointer-events: none; }
.top-right-placeholder { position: absolute; top: 36px; left: 592px; width: 214px; height: 107px; display: flex; align-items: center; justify-content: center; z-index: 5; }
.top-left-placeholder { position: absolute; top: 36px; left: 36px; width: 149.96px; height: 65.98px; display: flex; align-items: center; justify-content: center; z-index: 5; }
.bottom-right-placeholder { position: absolute; top: 1005px; left: 657.17px; width: 149.96px; height: 71.23px; display: flex; align-items: center; justify-content: center; z-index: 5; }
.header-placeholder { top: -55px; left: 320px; width: 160px; height: 50px; position: absolute; display: flex; align-items: center; justify-content: center; }
.group1-thq-text-elm41 { top: 40px; left: 289px; color: rgba(48, 109, 181, 1); width: 215px; position: absolute; font-size: 22.5px; font-weight: 700; text-align: center; line-height: 30px; }
.group1-thq-text-elm44 { top: -10px; left: 310px; color: rgba(0, 0, 0, 1); position: absolute; font-size: 17.3px; font-family: "Times New Roman", serif; }
.group1-thq-hospitallogoandthename-elm { top: 760px; left: 438.94px; width: 403px; height: 202.78px; display: flex; position: absolute; align-items: flex-start; }
.placeholder-logo-hospital { top: -12px; left: 133px; width: 136px; height: 136px; position: absolute; display: flex; align-items: center; justify-content: center; }
.group1-thq-text-elm18 { top: 120px; color: rgba(0, 0, 0, 1); width: 403px; position: absolute; font-size: 12.8px; text-align: center; line-height: 22px; }
.group1-thq-thedateofissueandalsotimeofissue-elm { top: calc(989.85px + var(--footer-offset)); left: 37.37px; width: 250px; height: 56px; display: flex; position: absolute; align-items: flex-start; }
.group1-thq-text-elm22 { color: rgba(0, 0, 0, 1); font-size: 12.5px; font-weight: 700; line-height: 28px; font-family: "Times New Roman", serif; position: absolute; white-space: nowrap; }
.group1-thq-text-elm36 { top: calc(724.55px + var(--footer-offset)); left: 29.23px; color: rgba(0, 0, 0, 1); position: absolute; font-size: 12px; font-weight: 700; text-align: center; font-family: "Noto Sans Arabic", sans-serif; line-height: 23px; }
.group1-thq-text-elm39 { top: calc(775.17px + var(--footer-offset)); left: 55px; color: rgba(0, 0, 0, 1); position: absolute; font-size: 12px; font-weight: 700; font-family: "Times New Roman", serif; }
.group1-thq-text-elm40 { top: calc(798.91px + var(--footer-offset)); left: 108.35px; color: rgba(20, 0, 255, 1); position: absolute; font-size: 11px; font-weight: 700; text-decoration: underline; pointer-events: auto; font-family: "Times New Roman", serif; }
.placeholder-136 { position: absolute; top: 620px; left: 122px; width: 136px; height: 136px; display: flex; align-items: center; justify-content: center; pointer-events: auto; }
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
  body { background: white !important; }
  .controls { display: none !important; }
  .group1-container1 { padding: 0 !important; background-color: transparent !important; }
  .group1-thq-group1-elm { box-shadow: none !important; margin: 0 !important; transform: scale(1) !important; }
}
</style>
<script>
function downloadPDF() {
  var btn = document.getElementById('btnDownloadPDF');
  btn.textContent = 'جاري التحميل...';
  btn.disabled = true;
  var url = window.location.href;
  if (url.indexOf('pdf_mode=') > -1) { url = url.replace(/pdf_mode=[^&]*/, 'pdf_mode=download'); }
  else { url += (url.indexOf('?') > -1 ? '&' : '?') + 'pdf_mode=download'; }
  var a = document.createElement('a'); a.href = url; a.download = '';
  document.body.appendChild(a); a.click(); document.body.removeChild(a);
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

    $hospitals = $pdo->query("SELECT id, name_ar, name_en FROM hospitals ORDER BY name_ar")->fetchAll();

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
<script>
// تفعيل الوضع الليلي مباشرة قبل تحميل الصفحة لتجنب الوميض الأبيض (FOUC)
(function() {
  const currentTheme = localStorage.getItem('theme') || 'light';
  document.documentElement.setAttribute('data-theme', currentTheme);
})();
</script>
<style>
/* ================= المتغيرات والألوان (نظام احترافي) ================= */
:root {
  --primary: #1e40af;
  --primary-light: #3b82f6;
  --primary-glow: rgba(59,130,246,0.25);
  --secondary: #0f172a;
  --accent: #06b6d4;
  --success: #10b981;
  --success-bg: #d1fae5;
  --success-text: #059669;
  --warning: #f59e0b;
  --danger: #ef4444;
  --bg: #f8fafc;
  --card: #ffffff;
  --text: #0f172a;
  --text-muted: #64748b;
  --border: #e2e8f0;
  --input-bg: #f1f5f9;
  --table-hdr: #f1f5f9;
  --table-hover: #f8faff;
  --radius: 16px;
  --radius-lg: 24px;
  --shadow: 0 4px 20px rgba(0, 0, 0, 0.04);
  --shadow-lg: 0 12px 40px rgba(30, 64, 175, 0.08);
  --transition: all 0.3s cubic-bezier(0.4, 0, 0.2, 1);
  --nav-bg: linear-gradient(135deg, #0f172a, #1e3a8a);
}

[data-theme="dark"] {
  --primary: #3b82f6;
  --primary-light: #60a5fa;
  --primary-glow: rgba(96,165,250,0.15);
  --secondary: #f8fafc;
  --bg: #0b0f19;
  --card: #111827;
  --text: #f1f5f9;
  --text-muted: #94a3b8;
  --border: #1f2937;
  --input-bg: #1f2937;
  --table-hdr: #1f2937;
  --table-hover: #161f33;
  --shadow: 0 4px 20px rgba(0, 0, 0, 0.4);
  --shadow-lg: 0 12px 40px rgba(0, 0, 0, 0.6);
  --success-bg: rgba(16, 185, 129, 0.15);
  --success-text: #34d399;
  --nav-bg: linear-gradient(135deg, #05070c, #0f172a);
}

* { margin:0; padding:0; box-sizing:border-box; }
body { font-family:'Cairo',sans-serif; background:var(--bg); color:var(--text); min-height:100vh; direction:rtl; transition: background-color 0.4s ease, color 0.4s ease; }

/* ═══ صفحة تسجيل الدخول ═══ */
.login-page {
  min-height:100vh; display:flex; align-items:center; justify-content:center;
  background:linear-gradient(-45deg,#0f172a,#1e3a8a,#1e40af,#0c4a6e,#0f172a);
  background-size:400% 400%; animation:gradientShift 15s ease infinite;
  padding:20px; position:relative; overflow:hidden;
}
.login-card {
  background:var(--card); backdrop-filter:blur(30px);
  border-radius:var(--radius-lg); padding:48px 40px; width:100%; max-width:440px;
  box-shadow:0 40px 100px rgba(0,0,0,0.5); animation:slideUp 0.7s cubic-bezier(0.34,1.56,0.64,1);
  border:1px solid var(--border); position:relative; z-index:2;
}
.login-icon { text-align:center; font-size:64px; margin-bottom:16px; animation:float 4s ease-in-out infinite; }
.login-card h2 { text-align:center; font-size:26px; font-weight:800; color:var(--primary); margin-bottom:6px; }
.login-card .subtitle { text-align:center; color:var(--text-muted); font-size:14px; margin-bottom:32px; }
.form-group { margin-bottom:18px; }
.form-group label { display:block; font-size:13px; font-weight:600; color:var(--text); margin-bottom:8px; }
.form-control {
  width:100%; padding:12px 16px; border:2px solid var(--border); border-radius:12px;
  font-family:'Cairo',sans-serif; font-size:15px; color:var(--text); background:var(--input-bg);
  transition:var(--transition); outline:none;
}
.form-control:focus { border-color:var(--primary-light); background:var(--card); box-shadow:0 0 0 4px var(--primary-glow); }

.btn {
  display:inline-flex; align-items:center; justify-content:center; gap:8px;
  padding:12px 24px; border:none; border-radius:12px; font-family:'Cairo',sans-serif;
  font-size:15px; font-weight:700; cursor:pointer; transition:var(--transition); text-decoration:none;
}
.btn-primary { background:linear-gradient(135deg, #1e40af, var(--primary-light)); color:#fff; box-shadow:0 4px 16px var(--primary-glow); }
.btn-primary:hover { transform:translateY(-2px); box-shadow:0 8px 24px var(--primary-glow); filter: brightness(1.1); }
.btn-full { width:100%; }

.alert { padding:12px 16px; border-radius:12px; font-size:14px; font-weight:600; margin-bottom:16px; }
.alert-danger { background:rgba(239, 68, 68, 0.1); color:var(--danger); border:1px solid rgba(239, 68, 68, 0.2); }
.alert-success { background:var(--success-bg); color:var(--success-text); border:1px solid rgba(16, 185, 129, 0.2); }
.alert-warning { background:rgba(245, 158, 11, 0.1); color:var(--warning); border:1px solid rgba(245, 158, 11, 0.2); }

/* ═══ الشريط العلوي ═══ */
.navbar {
  background:var(--nav-bg); padding:14px 28px;
  display:flex; align-items:center; justify-content:space-between;
  box-shadow:0 4px 24px rgba(0,0,0,0.3); position:sticky; top:0; z-index:100;
  transition: var(--transition);
}
.navbar .brand { display:flex; align-items:center; gap:12px; color:#fff; font-size:18px; font-weight:800; }
.navbar .brand-icon { width:40px; height:40px; background:linear-gradient(135deg,var(--primary-light),var(--accent)); border-radius:12px; display:flex; align-items:center; justify-content:center; font-size:20px; }
.navbar .user-actions { display:flex; align-items:center; gap:12px; }
.navbar .user-badge { background:rgba(255,255,255,0.08); border:1px solid rgba(255,255,255,0.15); padding:6px 14px; border-radius:50px; display:flex; align-items:center; gap:8px; color:#fff; font-size:14px; font-weight:600; }
.btn-icon-nav { background:rgba(255,255,255,0.08); border:1px solid rgba(255,255,255,0.15); color:#fff; width:40px; height:40px; border-radius:12px; cursor:pointer; font-size:18px; display:flex; align-items:center; justify-content:center; transition:var(--transition); }
.btn-icon-nav:hover { background:rgba(255,255,255,0.2); transform: scale(1.05); }

.btn-logout { background:rgba(239,68,68,0.15); color:#fca5a5; border:1px solid rgba(239,68,68,0.3); padding:8px 16px; border-radius:12px; font-family:'Cairo',sans-serif; font-size:13px; font-weight:700; cursor:pointer; transition:var(--transition); }
.btn-logout:hover { background:rgba(239,68,68,0.4); color:#fff; }

/* ═══ المحتوى ═══ */
.main-content { max-width:1150px; margin:0 auto; padding:32px 20px; }
.stats-grid { display:grid; grid-template-columns:repeat(auto-fit,minmax(220px,1fr)); gap:20px; margin-bottom:32px; }
.stat-card { background:var(--card); border-radius:var(--radius); padding:20px 24px; box-shadow:var(--shadow); border:1px solid var(--border); display:flex; align-items:center; gap:16px; transition:var(--transition); }
.stat-card:hover { transform:translateY(-4px); box-shadow:var(--shadow-lg); border-color: var(--primary-light); }
.stat-icon { width:56px; height:56px; border-radius:14px; display:flex; align-items:center; justify-content:center; font-size:26px; flex-shrink:0; }
.stat-icon.blue { background:rgba(59, 130, 246, 0.15); color:#3b82f6; }
.stat-icon.green { background:rgba(16, 185, 129, 0.15); color:#10b981; }
.stat-icon.orange { background:rgba(245, 158, 11, 0.15); color:#f59e0b; }
.stat-icon.red { background:rgba(239, 68, 68, 0.15); color:#ef4444; }
.stat-info .num { font-size:30px; font-weight:800; color:var(--text); line-height:1; }
.stat-info .label { font-size:13px; color:var(--text-muted); margin-top:6px; font-weight:600; }

.card { background:var(--card); border-radius:var(--radius-lg); box-shadow:var(--shadow); border:1px solid var(--border); overflow:hidden; margin-bottom:28px; transition:var(--transition); }
.card-header { padding:20px 28px; border-bottom:1px solid var(--border); display:flex; align-items:center; justify-content:space-between; background:var(--table-hdr); }
.card-header h3 { font-size:18px; font-weight:700; color:var(--primary); display:flex; align-items:center; gap:10px; }
.card-body { padding:28px; }

.patient-info-grid { display:grid; grid-template-columns:repeat(auto-fit,minmax(220px,1fr)); gap:16px; }
.info-field { background:var(--input-bg); border:1px solid var(--border); border-radius:12px; padding:14px 18px; transition:var(--transition); }
.info-field:hover { border-color: var(--text-muted); }
.info-field .field-label { font-size:11px; font-weight:700; color:var(--text-muted); text-transform:uppercase; letter-spacing:0.5px; margin-bottom:6px; }
.info-field .field-value { font-size:16px; font-weight:700; color:var(--text); }
.info-field .field-value-en { font-size:12px; color:var(--text-muted); direction:ltr; text-align:left; margin-top:2px; font-family: 'Inter', sans-serif; }

.quota-bar-wrap { background:var(--input-bg); border-radius:50px; height:14px; overflow:hidden; margin:12px 0; border:1px solid var(--border); }
.quota-bar { height:100%; border-radius:50px; background:linear-gradient(90deg,var(--success),#34d399); transition:width 1s cubic-bezier(0.4, 0, 0.2, 1); }
.quota-bar.warning { background:linear-gradient(90deg,var(--warning),#fbbf24); }
.quota-bar.danger { background:linear-gradient(90deg,var(--danger),#f87171); }

.leave-form-grid { display:grid; grid-template-columns:1fr 1fr; gap:20px; }
@media (max-width:768px) { .leave-form-grid { grid-template-columns:1fr; } }
.form-label { display:block; font-size:13px; font-weight:700; color:var(--text); margin-bottom:8px; }
.form-select { width:100%; padding:12px 16px; border:2px solid var(--border); border-radius:12px; font-family:'Cairo',sans-serif; font-size:14px; color:var(--text); background:var(--input-bg); transition:var(--transition); outline:none; cursor:pointer; font-weight:600; }
.form-select:focus { border-color:var(--primary-light); background:var(--card); box-shadow:0 0 0 4px var(--primary-glow); }
.form-select option { background: var(--card); color: var(--text); }

.time-mode-tabs { display:flex; gap:8px; margin-bottom:12px; }
.time-tab { flex:1; padding:10px; border:2px solid var(--border); border-radius:10px; background:var(--input-bg); font-family:'Cairo',sans-serif; font-size:13px; font-weight:700; cursor:pointer; transition:var(--transition); text-align:center; color:var(--text-muted); }
.time-tab.active { border-color:var(--primary-light); background:var(--primary-glow); color:var(--primary); }
.time-tab:hover:not(.active) { border-color:var(--text-muted); }

.leaves-table { width:100%; border-collapse:collapse; font-size:14px; }
.leaves-table th { background:var(--table-hdr); padding:14px 16px; text-align:right; font-weight:700; color:var(--text-muted); font-size:12px; text-transform:uppercase; letter-spacing:0.5px; border-bottom:2px solid var(--border); }
.leaves-table td { padding:16px; border-bottom:1px solid var(--border); vertical-align:middle; color:var(--text); font-weight:600; }
.leaves-table tr:hover td { background:var(--table-hover); }

.btn-sm { padding:8px 16px; font-size:13px; border-radius:10px; }
.btn-outline { background:transparent; border:2px solid var(--primary-light); color:var(--primary); font-weight:700; }
.btn-outline:hover { background:var(--primary-light); color:#fff; border-color:var(--primary-light); }

.toast-container { position:fixed; top:90px; left:50%; transform:translateX(-50%); z-index:9999; display:flex; flex-direction:column; gap:12px; pointer-events:none; }
.toast { background:var(--card); border:1px solid var(--border); border-radius:14px; padding:16px 24px; box-shadow:0 20px 50px rgba(0,0,0,0.3); font-size:15px; font-weight:700; display:flex; align-items:center; gap:12px; min-width:320px; max-width:450px; animation:slideDown 0.4s cubic-bezier(0.34,1.56,0.64,1); border-right:5px solid var(--primary); color:var(--text); }
.toast.success { border-color:var(--success); }
.toast.error { border-color:var(--danger); }
.toast.warning { border-color:var(--warning); }

.spinner { width:20px; height:20px; border:3px solid rgba(255,255,255,0.3); border-top-color:#fff; border-radius:50%; animation:spin 0.8s linear infinite; display:inline-block; vertical-align: middle; }
.empty-state { text-align:center; padding:60px 20px; color:var(--text-muted); }
.empty-state .empty-icon { font-size:64px; margin-bottom:16px; opacity:0.6; }
.empty-state h4 { font-size:18px; font-weight:800; margin-bottom:8px; color:var(--text); }
.empty-state p { font-size:14px; font-weight:600; }

.days-counter { display:flex; align-items:center; gap:8px; font-size:13px; font-weight:700; color:var(--text-muted); margin-top:8px; }
.days-counter .used { color:var(--danger); }
.days-counter .remaining { color:var(--success); }
.days-counter .total { color:var(--primary); }

@keyframes gradientShift { 0%{background-position:0% 50%} 50%{background-position:100% 50%} 100%{background-position:0% 50%} }
@keyframes float { 0%,100%{transform:translateY(0)} 50%{transform:translateY(-10px)} }
@keyframes slideUp { from{opacity:0;transform:translateY(40px)} to{opacity:1;transform:translateY(0)} }
@keyframes slideDown { from{opacity:0;transform:translateY(-20px)} to{opacity:1;transform:translateY(0)} }
@keyframes spin { to{transform:rotate(360deg)} }

/* لوحة الإشعارات */
.notif-panel-box { background:var(--card); border:1px solid var(--border); border-radius:16px; box-shadow:0 20px 60px rgba(0,0,0,0.5); overflow:hidden; }
.notif-item { padding:14px 18px; border-bottom:1px solid var(--border); transition:var(--transition); }
.notif-item:hover { background:var(--table-hover); }
.notif-item.unread { background:var(--primary-glow); }
</style>
</head>
<body>

<?php if (!isPatientLoggedIn()): ?>
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
      <button type="submit" class="btn btn-primary btn-full" style="margin-top:10px;">
        🔐 تسجيل الدخول
      </button>
    </form>
    <p style="text-align:center;margin-top:24px;font-size:13px;color:var(--text-muted);font-weight:600;">
      للحصول على حساب، يرجى التواصل مع الإدارة
    </p>
  </div>
</div>

<?php else: ?>
<nav class="navbar">
  <div class="brand">
    <div class="brand-icon">🏥</div>
    <span>بوابة المرضى</span>
  </div>
  
  <div class="user-actions">
    <button id="themeToggleBtn" class="btn-icon-nav" onclick="toggleTheme()" title="تبديل المظهر">
      <span id="themeIcon">☀️</span>
    </button>

    <div style="position:relative;">
      <button id="notifBell" class="btn-icon-nav" onclick="toggleNotifPanel()" title="الإشعارات" style="position:relative;">
        🔔
        <span id="notifBadge" style="display:none;position:absolute;top:-4px;right:-4px;background:#ef4444;color:#fff;border-radius:50%;width:18px;height:18px;font-size:11px;font-weight:700;align-items:center;justify-content:center;"></span>
      </button>
      
      <div id="notifPanel" class="notif-panel-box" style="display:none;position:absolute;top:54px;left:0;width:340px;z-index:999;">
        <div style="padding:14px 18px;background:linear-gradient(135deg,#1e40af,#3b82f6);color:#fff;display:flex;align-items:center;justify-content:space-between;">
          <span style="font-weight:700;font-size:14px;">🔔 الإشعارات</span>
          <button onclick="markAllRead()" style="background:rgba(255,255,255,0.2);border:none;color:#fff;padding:4px 10px;border-radius:8px;font-size:12px;cursor:pointer;font-family:'Cairo',sans-serif;font-weight:700;">تحديد كمقروء</button>
        </div>
        <div id="notifList" style="max-height:320px;overflow-y:auto;">
          <div style="text-align:center;padding:24px;color:var(--text-muted);font-size:13px;font-weight:600;">جاري التحميل...</div>
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
        <div class="label">الأيام المتبقية الحالية</div>
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
        <div class="label">إجمالي الإجازات المُصدرة</div>
      </div>
    </div>
  </div>

  <?php if ($patientData): ?>
  <div class="card">
    <div class="card-header">
      <h3>👤 بياناتي الشخصية والوظيفية</h3>
      <span style="font-size:12px;color:var(--text-muted);font-weight:700;background:var(--input-bg);padding:4px 12px;border-radius:8px;">للعرض فقط</span>
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

      <div style="margin-top:24px;">
        <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:8px;">
          <span style="font-size:14px;font-weight:700;color:var(--text);">حصة الإجازات المرضية المستهلكة</span>
          <span style="font-size:14px;font-weight:800;color:var(--primary);"><?= $usedDays ?> / <?= $allowedDays ?> يوم</span>
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
          <span>المسموح الكلي: <span class="total"><?= $allowedDays ?></span></span>
        </div>
      </div>
    </div>
  </div>
  <?php endif; ?>

  <?php if ($remainingDays > 0): ?>
  <div class="card">
    <div class="card-header">
      <h3>📝 إصدار إجازة مرضية جديدة (فورية)</h3>
      <span style="font-size:13px;background:var(--success-bg);color:var(--success-text);padding:6px 14px;border-radius:50px;font-weight:800;">
        الرصيد المتاح: <?= $remainingDays ?> يوم
      </span>
    </div>
    <div class="card-body">
      <form id="leaveForm">
        <div class="leave-form-grid">

          <div>
            <label class="form-label">🏥 المستشفى / المنشأة الطبية <span style="color:var(--danger)">*</span></label>
            <select class="form-select" id="hospitalSelect" name="hospital_id" required onchange="loadDoctors(this.value)">
              <option value="">-- يرجى اختيار المنشأة --</option>
              <?php foreach ($hospitals as $h): ?>
              <option value="<?= $h['id'] ?>"><?= htmlspecialchars($h['name_ar']) ?></option>
              <?php endforeach; ?>
            </select>
          </div>

          <div>
            <label class="form-label">👨‍⚕️ الطبيب المعالج <span style="color:var(--danger)">*</span></label>
            <select class="form-select" id="doctorSelect" name="doctor_id" required>
              <option value="">-- اختر المستشفى أولاً --</option>
            </select>
          </div>

          <div>
            <label class="form-label">📅 تاريخ بداية الإجازة <span style="color:var(--danger)">*</span></label>
            <input type="date" class="form-control" id="startDate" name="start_date" required
                   min="<?= date('Y-m-d') ?>" onchange="calcDays()">
          </div>

          <div>
            <label class="form-label">📅 تاريخ نهاية الإجازة <span style="color:var(--danger)">*</span></label>
            <input type="date" class="form-control" id="endDate" name="end_date" required
                   min="<?= date('Y-m-d') ?>" onchange="calcDays()">
          </div>

          <div>
            <label class="form-label">🔢 المدة المحسوبة</label>
            <input type="number" class="form-control" id="daysDisplay" readonly
                   placeholder="تُحسب برمجياً وبشكل تلقائي" style="background:var(--input-bg);cursor:not-allowed;font-weight:700;">
            <input type="hidden" id="daysCount" name="days_count">
            <div id="daysWarning" style="display:none;margin-top:10px;" class="alert alert-warning"></div>
          </div>

          <div>
            <label class="form-label">🕐 توقيت التوثيق والإصدار</label>
            <div class="time-mode-tabs">
              <button type="button" class="time-tab active" onclick="setTimeMode('auto',this)">تلقائي</button>
              <button type="button" class="time-tab" onclick="setTimeMode('random',this)">عشوائي</button>
              <button type="button" class="time-tab" onclick="setTimeMode('manual',this)">تحديد يدوي</button>
            </div>
            <input type="hidden" id="timeModeInput" name="time_mode" value="auto">
            <div id="manualTimeFields" style="display:none;">
              <div style="display:flex;gap:10px;align-items:center;">
                <input type="time" class="form-control" id="manualTimeInput" name="manual_time" style="flex:1;">
                <select class="form-select" name="manual_period" style="width:110px;">
                  <option value="AM">صباحاً</option>
                  <option value="PM">مساءً</option>
                </select>
              </div>
            </div>
            <div id="autoTimeInfo" style="font-size:12px;color:var(--text-muted);margin-top:6px;font-weight:600;">
              ⏰ سيُعتمد التوقيت الفعلي للحظة الضغط على الزر
            </div>
          </div>

        </div>

        <div style="margin-top:28px;display:flex;justify-content:flex-end;">
          <button type="button" class="btn btn-primary" onclick="createLeave()" id="submitBtn" style="padding:14px 32px;font-size:16px;">
            📄 اعتماد وإصدار الإجازة الفورية
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
        <h4>تعذر إصدار إجازات إضافية</h4>
        <p style="margin-bottom:24px;max-width:600px;margin-left:auto;margin-right:auto;">
          <?php if ($allowedDays === 0): ?>
            لم يتم تخصيص رصيد أيام لحسابك حتى الآن. يرجى التواصل مع الإدارة الطبية لتفعيل رصيدك.
          <?php else: ?>
            لقد استنفدت كامل رصيدك المسموح به (<?= $allowedDays ?> يوم). لطلب تمديد أو استثناء يرجى التواصل معنا.
          <?php endif; ?>
        </p>
        <a href="https://wa.me/966573436223" target="_blank"
           style="display:inline-flex;align-items:center;gap:10px;background:linear-gradient(135deg,#25d366,#128c7e);color:#fff;padding:14px 32px;border-radius:14px;font-size:16px;font-weight:800;text-decoration:none;box-shadow:0 8px 24px rgba(37,211,102,0.3);transition:var(--transition);"
           onmouseover="this.style.transform='translateY(-3px)'"
           onmouseout="this.style.transform='translateY(0)'">
          <svg xmlns="http://www.w3.org/2000/svg" width="22" height="22" viewBox="0 0 24 24" fill="white">
            <path d="M17.472 14.382c-.297-.149-1.758-.867-2.03-.967-.273-.099-.471-.148-.67.15-.197.297-.767.966-.94 1.164-.173.199-.347.223-.644.075-.297-.15-1.255-.463-2.39-1.475-.883-.788-1.48-1.761-1.653-2.059-.173-.297-.018-.458.13-.606.134-.133.298-.347.446-.52.149-.174.198-.298.298-.497.099-.198.05-.371-.025-.52-.075-.149-.669-1.612-.916-2.207-.242-.579-.487-.5-.669-.51-.173-.008-.371-.01-.57-.01-.198 0-.52.074-.792.372-.272.297-1.04 1.016-1.04 2.479 0 1.462 1.065 2.875 1.213 3.074.149.198 2.096 3.2 5.077 4.487.709.306 1.262.489 1.694.625.712.227 1.36.195 1.871.118.571-.085 1.758-.719 2.006-1.413.248-.694.248-1.289.173-1.413-.074-.124-.272-.198-.57-.347m-5.421 7.403h-.004a9.87 9.87 0 01-5.031-1.378l-.361-.214-3.741.982.998-3.648-.235-.374a9.86 9.86 0 01-1.51-5.26c.001-5.45 4.436-9.884 9.888-9.884 2.64 0 5.122 1.03 6.988 2.898a9.825 9.825 0 012.893 6.994c-.003 5.45-4.437 9.884-9.885 9.884m8.413-18.297A11.815 11.815 0 0012.05 0C5.495 0 .16 5.335.157 11.892c0 2.096.547 4.142 1.588 5.945L.057 24l6.305-1.654a11.882 11.882 0 005.683 1.448h.005c6.554 0 11.89-5.335 11.893-11.893a11.821 11.821 0 00-3.48-8.413z"/>
          </svg>
          تواصل مع الدعم الفني (واتساب)
        </a>
      </div>
    </div>
  </div>
  <?php endif; ?>

  <div class="card">
    <div class="card-header">
      <h3>📋 السجل التاريخي لإجازاتي المرضية</h3>
      <span style="font-size:13px;color:var(--text-muted);font-weight:700;"><?= count($myLeaves) ?> وثيقة معتمدة</span>
    </div>
    <div class="card-body" style="padding:0;">
      <?php if (empty($myLeaves)): ?>
      <div class="empty-state">
        <div class="empty-icon">📭</div>
        <h4>لا توجد وثائق في السجل</h4>
        <p>لم تقم بإصدار أي إجازة مرضية حتى الآن.</p>
      </div>
      <?php else: ?>
      <div style="overflow-x:auto;">
        <table class="leaves-table">
          <thead>
            <tr>
              <th>#</th>
              <th>الرمز الموحد</th>
              <th>المنشأة الطبية</th>
              <th>الطبيب المعالج</th>
              <th>من تاريخ</th>
              <th>إلى تاريخ</th>
              <th>المدة</th>
              <th>توقيت الإصدار</th>
              <th>الوثيقة (PDF)</th>
            </tr>
          </thead>
          <tbody>
            <?php foreach ($myLeaves as $i => $lv): ?>
            <tr>
              <td style="color:var(--text-muted);font-size:13px;"><?= $i + 1 ?></td>
              <td style="font-weight:800;color:var(--primary);font-size:13px;direction:ltr;text-align:right;"><?= htmlspecialchars($lv['service_code'] ?? '') ?></td>
              <td style="font-weight:700;"><?= htmlspecialchars($lv['h_name_ar'] ?? '') ?></td>
              <td>
                <div style="font-weight:700;color:var(--text);"><?= htmlspecialchars($lv['d_name_ar'] ?? '') ?></div>
                <div style="font-size:11px;color:var(--text-muted);font-weight:600;"><?= htmlspecialchars($lv['d_title_ar'] ?? '') ?></div>
              </td>
              <td style="direction:ltr;text-align:right;font-family:'Inter',sans-serif;"><?= fmtDateUser($lv['start_date']) ?></td>
              <td style="direction:ltr;text-align:right;font-family:'Inter',sans-serif;"><?= fmtDateUser($lv['end_date']) ?></td>
              <td>
                <span style="background:var(--primary-glow);color:var(--primary);padding:4px 12px;border-radius:50px;font-weight:800;font-size:13px;">
                  <?= $lv['days_count'] ?> يوم
                </span>
              </td>
              <td style="font-size:13px;direction:ltr;text-align:right;font-family:'Inter',sans-serif;">
                <?= htmlspecialchars($lv['issue_time'] ?? '') ?>
                <?= $lv['issue_period'] === 'AM' ? 'ص' : ($lv['issue_period'] === 'PM' ? 'م' : '') ?>
              </td>
              <td>
                <a href="user.php?action=generate_pdf&leave_id=<?= $lv['id'] ?>&pdf_mode=download"
                   class="btn btn-outline btn-sm">
                  📄 تحميل PDF
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

</div><div class="toast-container" id="toastContainer"></div>

<script>
const MAX_DAYS = <?= $remainingDays ?>;

// ================= إدارة الوضع الليلي (Dark Mode) =================
function toggleTheme() {
  const root = document.documentElement;
  const current = root.getAttribute('data-theme');
  const newTheme = current === 'dark' ? 'light' : 'dark';
  
  root.setAttribute('data-theme', newTheme);
  localStorage.setItem('theme', newTheme);
  updateThemeIcon(newTheme);
}

function updateThemeIcon(theme) {
  const icon = document.getElementById('themeIcon');
  if (icon) { icon.textContent = theme === 'dark' ? '🌙' : '☀️'; }
}

// ضبط الأيقونة عند التحميل
document.addEventListener('DOMContentLoaded', () => {
  const current = document.documentElement.getAttribute('data-theme') || 'light';
  updateThemeIcon(current);
});

// ================= دوال التحكم بالنموذج والإرسال =================
function loadDoctors(hospitalId) {
  const sel = document.getElementById('doctorSelect');
  sel.innerHTML = '<option value="">جاري جلب الأطباء...</option>';
  if (!hospitalId) { sel.innerHTML = '<option value="">-- اختر المستشفى أولاً --</option>'; return; }
  fetch('user.php?action=get_doctors_by_hospital&hospital_id=' + hospitalId)
    .then(r => r.json())
    .then(data => {
      if (data.success && data.doctors.length > 0) {
        sel.innerHTML = '<option value="">-- يرجى اختيار الطبيب --</option>';
        data.doctors.forEach(d => {
          sel.innerHTML += `<option value="${d.id}">${d.name_ar} — (${d.title_ar})</option>`;
        });
      } else {
        sel.innerHTML = '<option value="">لا يوجد أطباء متاحين حالياً</option>';
      }
    })
    .catch(() => { sel.innerHTML = '<option value="">فشل التحميل</option>'; });
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
    warning.innerHTML = '⚠️ <b>خطأ:</b> تاريخ النهاية يجب أن يكون بعد تاريخ البداية.';
    return;
  }
  const diff = Math.round((e - s) / (1000 * 60 * 60 * 24)) + 1;
  display.value = diff + ' أيام';
  hidden.value  = diff;
  if (diff > MAX_DAYS) {
    warning.style.display = 'block';
    warning.innerHTML = `⚠️ <b>تنبيه:</b> المدة المطلوبة (${diff} أيام) تتجاوز الرصيد المتاح (${MAX_DAYS} يوم).`;
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
  else if (mode === 'random') { mf.style.display = 'none'; ai.style.display = 'block'; ai.textContent = '🎲 سيتم توليد توقيت عشوائي ذكي خلال ساعات الدوام الرسمي'; }
  else { mf.style.display = 'none'; ai.style.display = 'block'; ai.textContent = '⏰ سيُعتمد التوقيت الفعلي للحظة الضغط على الزر'; }
}

function createLeave() {
  const hospitalId = document.getElementById('hospitalSelect').value;
  const doctorId   = document.getElementById('doctorSelect').value;
  const startDate  = document.getElementById('startDate').value;
  const endDate    = document.getElementById('endDate').value;
  const daysCount  = document.getElementById('daysCount').value;

  if (!hospitalId) { showToast('يرجى اختيار المنشأة الطبية أولاً.', 'error'); return; }
  if (!doctorId)   { showToast('يرجى تحديد الطبيب المعالج.', 'error'); return; }
  if (!startDate)  { showToast('تاريخ بداية الإجازة مطلوب.', 'error'); return; }
  if (!endDate)    { showToast('تاريخ نهاية الإجازة مطلوب.', 'error'); return; }
  if (!daysCount || parseInt(daysCount) <= 0) { showToast('يرجى ضبط التواريخ بشكل صحيح.', 'error'); return; }
  if (parseInt(daysCount) > MAX_DAYS) { showToast(`المدة المطلوبة تتجاوز رصيدك الحالي المتبقي (${MAX_DAYS} يوم).`, 'error'); return; }

  const btn = document.getElementById('submitBtn');
  btn.disabled = true;
  btn.innerHTML = '<span class="spinner"></span> جاري التوثيق والإصدار...';

  const formData = new FormData(document.getElementById('leaveForm'));
  formData.append('action', 'create_sick_leave');

  fetch('user.php', { method: 'POST', body: formData })
    .then(r => r.json())
    .then(data => {
      if (data.success) {
        showToast('✅ ' + data.message + ' (الرمز: ' + data.service_code + ')', 'success');
        
        // التعديل المطلوب: تحديث الصفحة فقط وإظهار الإجازة بالجدول بدون فتح نافذة جديدة
        setTimeout(() => {
          location.reload();
        }, 1500);

      } else {
        showToast(data.message || 'حدث خطأ غير متوقع.', 'error');
        btn.disabled = false;
        btn.innerHTML = '📄 اعتماد وإصدار الإجازة الفورية';
      }
    })
    .catch(() => {
      showToast('مشكلة في الاتصال بالخادم. يرجى المحاولة لاحقاً.', 'error');
      btn.disabled = false;
      btn.innerHTML = '📄 اعتماد وإصدار الإجازة الفورية';
    });
}

function showToast(msg, type = 'success') {
  const container = document.getElementById('toastContainer');
  const icons = { success: '✨', error: '❌', warning: '⚠️' };
  const toast = document.createElement('div');
  toast.className = `toast ${type}`;
  toast.innerHTML = `<span style="font-size:18px;">${icons[type] || '💬'}</span><span style="flex:1;">${msg}</span>`;
  container.appendChild(toast);
  setTimeout(() => {
    toast.style.opacity = '0';
    toast.style.transform = 'translateY(-10px)';
    toast.style.transition = 'all 0.4s ease';
    setTimeout(() => toast.remove(), 400);
  }, 5000);
}

// ================= نظام الإشعارات =================
let notifPanelOpen = false;

function toggleNotifPanel() {
  const panel = document.getElementById('notifPanel');
  notifPanelOpen = !notifPanelOpen;
  panel.style.display = notifPanelOpen ? 'block' : 'none';
  if (notifPanelOpen) loadNotifications();
}

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
        list.innerHTML = '<div style="text-align:center;padding:24px;color:var(--text-muted);font-size:13px;font-weight:600;">لا توجد إشعارات حالياً</div>';
        return;
      }
      list.innerHTML = data.notifications.map(n => `
        <div class="notif-item ${n.is_read == 0 ? 'unread' : ''}">
          <div style="font-size:13px;font-weight:${n.is_read == 0 ? '800' : '600'};color:var(--text);line-height:1.5;">${escapeHtml(n.message)}</div>
          <div style="font-size:11px;color:var(--text-muted);margin-top:6px;font-family:'Inter',sans-serif;">${n.created_at}</div>
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
