<?php
/**
 * بوابة المرضى - user.php
 * صفحة تسجيل دخول المرضى وإدارة إجازاتهم المرضية
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

// ======================== إنشاء الجداول الإضافية للمرضى ========================
// إضافة أعمدة لربط المستخدم بالمريض وتحديد الحصة
$pdo->exec("CREATE TABLE IF NOT EXISTS patient_accounts (
    id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT NOT NULL UNIQUE,
    patient_id INT NOT NULL,
    allowed_days INT DEFAULT 0,
    FOREIGN KEY (user_id) REFERENCES admin_users(id) ON DELETE CASCADE,
    FOREIGN KEY (patient_id) REFERENCES patients(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci");

// جدول طلبات الإجازة من المريض
$pdo->exec("CREATE TABLE IF NOT EXISTS patient_leave_requests (
    id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT NOT NULL,
    patient_id INT NOT NULL,
    hospital_id INT NOT NULL,
    doctor_id INT NOT NULL,
    start_date DATE NOT NULL,
    end_date DATE NOT NULL,
    days_count INT NOT NULL,
    issue_time VARCHAR(10) NULL,
    issue_period ENUM('AM','PM') NULL,
    time_mode ENUM('auto','random','manual') DEFAULT 'auto',
    status ENUM('pending','approved','rejected') DEFAULT 'pending',
    pdf_data LONGTEXT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES admin_users(id) ON DELETE CASCADE,
    FOREIGN KEY (patient_id) REFERENCES patients(id) ON DELETE CASCADE,
    FOREIGN KEY (hospital_id) REFERENCES hospitals(id) ON DELETE CASCADE,
    FOREIGN KEY (doctor_id) REFERENCES doctors(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci");

// ======================== دوال مساعدة ========================
function nowSaudiUser(): string {
    return (new DateTime('now', new DateTimeZone('Asia/Riyadh')))->format('Y-m-d H:i:s');
}

function isPatientLoggedIn(): bool {
    return isset($_SESSION['patient_logged_in']) && $_SESSION['patient_logged_in'] === true;
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

function toHijriStr($d) {
    if (!$d) return '';
    $parts = explode('-', $d);
    if (count($parts) !== 3) return $d;
    $h = gregorianToHijriUser((int)$parts[0], (int)$parts[1], (int)$parts[2]);
    return sprintf('%02d-%02d-%04d', $h['day'], $h['month'], $h['year']);
}

function fmtDateAr($d) {
    if (!$d) return '';
    $dt = DateTime::createFromFormat('Y-m-d', $d);
    return $dt ? $dt->format('d/m/Y') : $d;
}

function getUsedDays(PDO $pdo, int $patientId): int {
    // احسب الأيام المستخدمة من الإجازات المعتمدة أو المنشأة
    $stmt = $pdo->prepare("SELECT COALESCE(SUM(days_count),0) FROM patient_leave_requests WHERE patient_id = ? AND status != 'rejected'");
    $stmt->execute([$patientId]);
    return (int)$stmt->fetchColumn();
}

// ======================== معالجة الطلبات ========================
$action = $_POST['action'] ?? $_GET['action'] ?? '';
$response = null;

// تسجيل الدخول
if ($action === 'patient_login') {
    $username = trim($_POST['username'] ?? '');
    $password = $_POST['password'] ?? '';
    
    if (empty($username) || empty($password)) {
        $loginError = 'يرجى إدخال اسم المستخدم وكلمة المرور.';
    } else {
        $stmt = $pdo->prepare("SELECT u.*, pa.patient_id, pa.allowed_days, pa.expiry_date FROM admin_users u LEFT JOIN patient_accounts pa ON pa.user_id = u.id WHERE u.username = ? AND u.is_active = 1");
        $stmt->execute([$username]);
        $user = $stmt->fetch();
        
        if ($user && password_verify($password, $user['password_hash'])) {
            if (empty($user['patient_id'])) {
                $loginError = 'هذا الحساب غير مرتبط بملف مريض. يرجى التواصل مع الإدارة.';
            } elseif (!empty($user['expiry_date']) && $user['expiry_date'] < date('Y-m-d')) {
                $loginError = 'انتهت صلاحية هذا الحساب. يرجى التواصل مع الإدارة.';
            } else {
                $_SESSION['patient_logged_in'] = true;
                $_SESSION['patient_user_id'] = $user['id'];
                $_SESSION['patient_id'] = $user['patient_id'];
                $_SESSION['patient_display_name'] = $user['display_name'];
                $_SESSION['patient_username'] = $user['username'];
                $_SESSION['patient_allowed_days'] = (int)$user['allowed_days'];
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

// معالجة طلب الإجازة (AJAX)
if ($action === 'submit_leave_request' && isPatientLoggedIn()) {
    header('Content-Type: application/json; charset=utf-8');
    
    $patientId = (int)$_SESSION['patient_id'];
    $userId = (int)$_SESSION['patient_user_id'];
    $allowedDays = (int)$_SESSION['patient_allowed_days'];
    
    $hospitalId = (int)($_POST['hospital_id'] ?? 0);
    $doctorId = (int)($_POST['doctor_id'] ?? 0);
    $startDate = trim($_POST['start_date'] ?? '');
    $endDate = trim($_POST['end_date'] ?? '');
    $daysCount = (int)($_POST['days_count'] ?? 0);
    $timeMode = in_array($_POST['time_mode'] ?? '', ['auto','random','manual']) ? $_POST['time_mode'] : 'auto';
    $manualTime = trim($_POST['manual_time'] ?? '');
    $manualPeriod = in_array(strtoupper($_POST['manual_period'] ?? ''), ['AM','PM']) ? strtoupper($_POST['manual_period']) : 'AM';
    
    if (!$hospitalId || !$doctorId || !$startDate || !$endDate || $daysCount <= 0) {
        echo json_encode(['success' => false, 'message' => 'يرجى تعبئة جميع الحقول المطلوبة.']);
        exit;
    }
    
    // التحقق من الحصة
    $usedDays = getUsedDays($pdo, $patientId);
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
        $randomMin = rand(0, 59);
        $issuePeriod = $randomHour >= 12 ? 'PM' : 'AM';
        $h12 = $randomHour > 12 ? $randomHour - 12 : ($randomHour === 0 ? 12 : $randomHour);
        $issueTime = sprintf('%02d:%02d', $h12, $randomMin);
    } elseif ($timeMode === 'manual' && $manualTime) {
        $issueTime = $manualTime;
        $issuePeriod = $manualPeriod;
    }
    
    $stmt = $pdo->prepare("INSERT INTO patient_leave_requests (user_id, patient_id, hospital_id, doctor_id, start_date, end_date, days_count, issue_time, issue_period, time_mode, status) VALUES (?,?,?,?,?,?,?,?,?,?,'pending')");
    $stmt->execute([$userId, $patientId, $hospitalId, $doctorId, $startDate, $endDate, $daysCount, $issueTime, $issuePeriod, $timeMode]);
    $requestId = $pdo->lastInsertId();
    
    echo json_encode([
        'success' => true,
        'message' => 'تم تقديم طلب الإجازة بنجاح. سيتم مراجعته من قِبل الإدارة.',
        'request_id' => $requestId,
        'remaining_days' => $remainingDays - $daysCount
    ]);
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

// توليد PDF للطلب (AJAX)
if ($action === 'generate_request_pdf' && isPatientLoggedIn()) {
    $requestId = (int)($_GET['request_id'] ?? 0);
    $userId = (int)$_SESSION['patient_user_id'];
    
    $stmt = $pdo->prepare("
        SELECT r.*, 
               p.name_ar AS p_name_ar, p.name_en AS p_name_en, p.identity_number,
               p.employer_ar, p.employer_en, p.nationality_ar, p.nationality_en,
               d.name_ar AS d_name_ar, d.name_en AS d_name_en, d.title_ar AS d_title_ar, d.title_en AS d_title_en,
               h.name_ar AS h_name_ar, h.name_en AS h_name_en, h.license_number AS h_license,
               h.logo_data AS h_logo_data, h.logo_url AS h_logo_url, h.logo_path AS h_logo_path
        FROM patient_leave_requests r
        LEFT JOIN patients p ON r.patient_id = p.id
        LEFT JOIN doctors d ON r.doctor_id = d.id
        LEFT JOIN hospitals h ON r.hospital_id = h.id
        WHERE r.id = ? AND r.user_id = ?
    ");
    $stmt->execute([$requestId, $userId]);
    $req = $stmt->fetch();
    
    if (!$req) {
        echo '<h2 style="text-align:center;padding:50px;font-family:sans-serif;">الطلب غير موجود</h2>';
        exit;
    }
    
    // توليد رمز خدمة مؤقت للعرض
    $sc = 'REQ-' . str_pad($requestId, 6, '0', STR_PAD_LEFT);
    $days = (int)$req['days_count'];
    $startG = $req['start_date'];
    $endG = $req['end_date'];
    $issueG = date('Y-m-d');
    
    $fmtEn = function($d) { if (!$d) return ''; $dt = DateTime::createFromFormat('Y-m-d', $d); return $dt ? $dt->format('d-m-Y') : $d; };
    
    $startEn = $fmtEn($startG);
    $endEn = $fmtEn($endG);
    $issueEn = $fmtEn($issueG);
    $startHj = toHijriStr($startG);
    $endHj = toHijriStr($endG);
    
    $patNameAr = htmlspecialchars($req['p_name_ar'] ?? '', ENT_QUOTES);
    $patNameEn = strtoupper(htmlspecialchars($req['p_name_en'] ?? '', ENT_QUOTES));
    $patId = htmlspecialchars($req['identity_number'] ?? '', ENT_QUOTES);
    $natAr = htmlspecialchars($req['nationality_ar'] ?? '', ENT_QUOTES);
    $natEn = htmlspecialchars($req['nationality_en'] ?? '', ENT_QUOTES);
    $empAr = htmlspecialchars($req['employer_ar'] ?: 'الى من يهمه الامر', ENT_QUOTES);
    $empEn = htmlspecialchars($req['employer_en'] ?: 'To Whom It May Concern', ENT_QUOTES);
    $docNameAr = htmlspecialchars($req['d_name_ar'] ?? '', ENT_QUOTES);
    $docNameEn = strtoupper(htmlspecialchars($req['d_name_en'] ?? '', ENT_QUOTES));
    $docTitleAr = htmlspecialchars($req['d_title_ar'] ?? '', ENT_QUOTES);
    $docTitleEn = htmlspecialchars($req['d_title_en'] ?? '', ENT_QUOTES);
    $hospNameAr = htmlspecialchars($req['h_name_ar'] ?? '', ENT_QUOTES);
    $hospNameEn = htmlspecialchars($req['h_name_en'] ?? '', ENT_QUOTES);
    
    $issueTime = $req['issue_time'] ?? '09:00';
    $issuePeriod = $req['issue_period'] ?? 'AM';
    $issueTimeDisplay = $issueTime . ' ' . ($issuePeriod === 'AM' ? 'صباحاً' : 'مساءً');
    
    // شعار المستشفى
    $logoData = $req['h_logo_data'] ?? $req['h_logo_url'] ?? $req['h_logo_path'] ?? '';
    $logoHtml = '';
    if ($logoData) {
        $logoHtml = '<img src="' . htmlspecialchars($logoData, ENT_QUOTES) . '" style="max-height:80px;max-width:200px;object-fit:contain;" />';
    }
    
    $statusLabel = ['pending' => 'قيد المراجعة', 'approved' => 'معتمدة', 'rejected' => 'مرفوضة'][$req['status']] ?? '';
    $statusColor = ['pending' => '#f59e0b', 'approved' => '#10b981', 'rejected' => '#ef4444'][$req['status']] ?? '#6b7280';
    
    // إخراج HTML للـ PDF
    header('Content-Type: text/html; charset=utf-8');
    echo '<!DOCTYPE html>
<html lang="ar" dir="rtl">
<head>
<meta charset="UTF-8">
<title>طلب إجازة مرضية</title>
<style>
  @import url("https://fonts.googleapis.com/css2?family=Cairo:wght@400;600;700;800&display=swap");
  * { margin:0; padding:0; box-sizing:border-box; }
  body { font-family:"Cairo",sans-serif; background:#f8fafc; direction:rtl; }
  .page { width:794px; min-height:1123px; margin:0 auto; background:#fff; padding:40px; position:relative; }
  .header { display:flex; justify-content:space-between; align-items:center; border-bottom:3px solid #1e40af; padding-bottom:20px; margin-bottom:24px; }
  .logo-area { min-width:120px; }
  .title-area { text-align:center; flex:1; }
  .title-area h1 { font-size:22px; font-weight:800; color:#1e40af; }
  .title-area p { font-size:13px; color:#64748b; margin-top:4px; }
  .status-badge { padding:6px 16px; border-radius:20px; font-size:13px; font-weight:700; color:#fff; background:' . $statusColor . '; }
  .section { margin-bottom:20px; }
  .section-title { font-size:14px; font-weight:700; color:#1e40af; border-right:4px solid #1e40af; padding-right:10px; margin-bottom:12px; }
  .info-grid { display:grid; grid-template-columns:1fr 1fr; gap:10px; }
  .info-item { background:#f1f5f9; border-radius:8px; padding:10px 14px; }
  .info-item .label { font-size:11px; color:#64748b; margin-bottom:3px; }
  .info-item .value { font-size:14px; font-weight:600; color:#1e293b; }
  .info-item .value-en { font-size:12px; color:#475569; direction:ltr; text-align:left; }
  .dates-row { display:grid; grid-template-columns:1fr 1fr 1fr; gap:10px; }
  .date-box { background:linear-gradient(135deg,#eff6ff,#dbeafe); border:1px solid #bfdbfe; border-radius:10px; padding:12px; text-align:center; }
  .date-box .dlabel { font-size:11px; color:#3b82f6; font-weight:600; margin-bottom:6px; }
  .date-box .dval { font-size:15px; font-weight:800; color:#1e40af; }
  .date-box .dhijri { font-size:11px; color:#64748b; margin-top:3px; direction:ltr; }
  .days-highlight { background:linear-gradient(135deg,#1e40af,#3b82f6); color:#fff; border-radius:12px; padding:16px; text-align:center; margin:16px 0; }
  .days-highlight .num { font-size:48px; font-weight:800; line-height:1; }
  .days-highlight .txt { font-size:14px; opacity:0.9; margin-top:4px; }
  .time-row { background:#f0fdf4; border:1px solid #bbf7d0; border-radius:8px; padding:12px 16px; display:flex; align-items:center; gap:12px; }
  .time-row .tlabel { font-size:12px; color:#16a34a; font-weight:600; }
  .time-row .tval { font-size:16px; font-weight:700; color:#15803d; }
  .footer { margin-top:40px; border-top:2px solid #e2e8f0; padding-top:20px; display:flex; justify-content:space-between; align-items:flex-end; }
  .sig-box { text-align:center; }
  .sig-line { width:160px; border-bottom:1px solid #94a3b8; margin:40px auto 8px; }
  .sig-label { font-size:12px; color:#64748b; }
  .watermark { position:absolute; top:50%; left:50%; transform:translate(-50%,-50%) rotate(-30deg); font-size:80px; font-weight:900; color:rgba(30,64,175,0.04); pointer-events:none; white-space:nowrap; }
  @media print { body{background:#fff;} .no-print{display:none;} }
</style>
</head>
<body>
<div class="no-print" style="background:#1e40af;color:#fff;padding:12px 20px;display:flex;justify-content:space-between;align-items:center;">
  <span style="font-family:Cairo,sans-serif;font-weight:700;">طلب إجازة مرضية #' . $requestId . '</span>
  <button onclick="window.print()" style="background:#fff;color:#1e40af;border:none;padding:8px 20px;border-radius:8px;font-family:Cairo,sans-serif;font-weight:700;cursor:pointer;">🖨️ طباعة / تحميل PDF</button>
</div>
<div class="page">
  <div class="watermark">طلب إجازة</div>
  <div class="header">
    <div class="logo-area">' . $logoHtml . '</div>
    <div class="title-area">
      <h1>تقرير إجازة مرضية</h1>
      <p>Medical Leave Report</p>
      <p style="font-size:12px;color:#94a3b8;margin-top:4px;">رقم الطلب: ' . $sc . '</p>
    </div>
    <div><span class="status-badge">' . $statusLabel . '</span></div>
  </div>
  
  <div class="section">
    <div class="section-title">بيانات المريض - Patient Information</div>
    <div class="info-grid">
      <div class="info-item">
        <div class="label">الاسم بالعربية</div>
        <div class="value">' . $patNameAr . '</div>
        <div class="value-en">' . $patNameEn . '</div>
      </div>
      <div class="info-item">
        <div class="label">رقم الهوية / الإقامة</div>
        <div class="value" style="direction:ltr;text-align:right;">' . $patId . '</div>
      </div>
      <div class="info-item">
        <div class="label">الجنسية</div>
        <div class="value">' . $natAr . '</div>
        <div class="value-en">' . $natEn . '</div>
      </div>
      <div class="info-item">
        <div class="label">جهة العمل</div>
        <div class="value">' . $empAr . '</div>
        <div class="value-en">' . $empEn . '</div>
      </div>
    </div>
  </div>
  
  <div class="section">
    <div class="section-title">بيانات الطبيب والمستشفى</div>
    <div class="info-grid">
      <div class="info-item">
        <div class="label">اسم الطبيب</div>
        <div class="value">' . $docNameAr . '</div>
        <div class="value-en">' . $docNameEn . '</div>
      </div>
      <div class="info-item">
        <div class="label">التخصص / المسمى</div>
        <div class="value">' . $docTitleAr . '</div>
        <div class="value-en">' . $docTitleEn . '</div>
      </div>
      <div class="info-item">
        <div class="label">المستشفى / المنشأة</div>
        <div class="value">' . $hospNameAr . '</div>
        <div class="value-en">' . $hospNameEn . '</div>
      </div>
      <div class="info-item">
        <div class="label">وقت الإصدار</div>
        <div class="value">' . $issueTimeDisplay . '</div>
      </div>
    </div>
  </div>
  
  <div class="section">
    <div class="section-title">تفاصيل الإجازة</div>
    <div class="days-highlight">
      <div class="num">' . $days . '</div>
      <div class="txt">يوم / ' . $days . ($days === 1 ? ' Day' : ' Days') . '</div>
    </div>
    <div class="dates-row">
      <div class="date-box">
        <div class="dlabel">تاريخ الإصدار</div>
        <div class="dval">' . $issueEn . '</div>
        <div class="dhijri">' . toHijriStr($issueG) . ' هـ</div>
      </div>
      <div class="date-box">
        <div class="dlabel">تاريخ البداية</div>
        <div class="dval">' . $startEn . '</div>
        <div class="dhijri">' . $startHj . ' هـ</div>
      </div>
      <div class="date-box">
        <div class="dlabel">تاريخ النهاية</div>
        <div class="dval">' . $endEn . '</div>
        <div class="dhijri">' . $endHj . ' هـ</div>
      </div>
    </div>
  </div>
  
  <div class="footer">
    <div class="sig-box">
      <div class="sig-line"></div>
      <div class="sig-label">توقيع الطبيب<br>Doctor Signature</div>
    </div>
    <div style="text-align:center;font-size:11px;color:#94a3b8;">
      <p>تم إصدار هذا التقرير بتاريخ: ' . date('d/m/Y') . '</p>
      <p>This report was issued on: ' . date('d/m/Y') . '</p>
    </div>
    <div class="sig-box">
      <div class="sig-line"></div>
      <div class="sig-label">ختم المنشأة<br>Official Stamp</div>
    </div>
  </div>
</div>
</body>
</html>';
    exit;
}

// ======================== تحميل البيانات للصفحة الرئيسية ========================
$patientData = null;
$leaveRequests = [];
$hospitals = [];
$usedDays = 0;
$allowedDays = 0;

if (isPatientLoggedIn()) {
    $patientId = (int)$_SESSION['patient_id'];
    $userId = (int)$_SESSION['patient_user_id'];
    $allowedDays = (int)$_SESSION['patient_allowed_days'];
    
    // بيانات المريض
    $stmt = $pdo->prepare("SELECT * FROM patients WHERE id = ?");
    $stmt->execute([$patientId]);
    $patientData = $stmt->fetch();
    
    // طلبات الإجازة
    $stmt = $pdo->prepare("
        SELECT r.*, h.name_ar AS h_name_ar, d.name_ar AS d_name_ar, d.title_ar AS d_title_ar
        FROM patient_leave_requests r
        LEFT JOIN hospitals h ON r.hospital_id = h.id
        LEFT JOIN doctors d ON r.doctor_id = d.id
        WHERE r.user_id = ?
        ORDER BY r.created_at DESC
    ");
    $stmt->execute([$userId]);
    $leaveRequests = $stmt->fetchAll();
    
    // المستشفيات
    $hospitals = $pdo->query("SELECT id, name_ar, name_en FROM hospitals ORDER BY name_ar")->fetchAll();
    
    // الأيام المستخدمة
    $usedDays = getUsedDays($pdo, $patientId);
    
    // تحديث الجلسة بالحصة الحالية من DB
    $stmt2 = $pdo->prepare("SELECT allowed_days FROM patient_accounts WHERE user_id = ?");
    $stmt2->execute([$userId]);
    $paRow = $stmt2->fetch();
    if ($paRow) {
        $_SESSION['patient_allowed_days'] = (int)$paRow['allowed_days'];
        $allowedDays = (int)$paRow['allowed_days'];
    }
}

$remainingDays = max(0, $allowedDays - $usedDays);
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

body {
  font-family: 'Cairo', sans-serif;
  background: var(--bg);
  color: var(--text);
  min-height: 100vh;
  direction: rtl;
}

/* ═══ صفحة تسجيل الدخول ═══ */
.login-page {
  min-height: 100vh;
  display: flex;
  align-items: center;
  justify-content: center;
  background: linear-gradient(-45deg, #0f172a, #1e3a8a, #1e40af, #0c4a6e, #0f172a);
  background-size: 400% 400%;
  animation: gradientShift 15s ease infinite;
  padding: 20px;
  position: relative;
  overflow: hidden;
}

.login-page::before {
  content: '';
  position: absolute;
  width: 600px; height: 600px;
  background: radial-gradient(circle, rgba(59,130,246,0.15) 0%, transparent 70%);
  top: -200px; right: -200px;
  border-radius: 50%;
  animation: float 8s ease-in-out infinite;
}

.login-page::after {
  content: '';
  position: absolute;
  width: 400px; height: 400px;
  background: radial-gradient(circle, rgba(6,182,212,0.1) 0%, transparent 70%);
  bottom: -100px; left: -100px;
  border-radius: 50%;
  animation: float 6s ease-in-out infinite reverse;
}

.login-card {
  background: rgba(255,255,255,0.95);
  backdrop-filter: blur(30px);
  border-radius: 24px;
  padding: 48px 40px;
  width: 100%;
  max-width: 440px;
  box-shadow: 0 40px 100px rgba(0,0,0,0.3), 0 0 0 1px rgba(255,255,255,0.2) inset;
  animation: slideUp 0.7s cubic-bezier(0.34,1.56,0.64,1);
  position: relative;
  z-index: 2;
}

.login-icon {
  text-align: center;
  font-size: 64px;
  margin-bottom: 16px;
  animation: float 4s ease-in-out infinite;
}

.login-card h2 {
  text-align: center;
  font-size: 26px;
  font-weight: 800;
  color: var(--primary);
  margin-bottom: 6px;
}

.login-card .subtitle {
  text-align: center;
  color: var(--text-muted);
  font-size: 14px;
  margin-bottom: 32px;
}

.form-group { margin-bottom: 18px; }

.form-group label {
  display: block;
  font-size: 13px;
  font-weight: 600;
  color: var(--text);
  margin-bottom: 8px;
}

.form-control {
  width: 100%;
  padding: 12px 16px;
  border: 2px solid var(--border);
  border-radius: 10px;
  font-family: 'Cairo', sans-serif;
  font-size: 15px;
  color: var(--text);
  background: #f8fafc;
  transition: var(--transition);
  outline: none;
}

.form-control:focus {
  border-color: var(--primary-light);
  background: #fff;
  box-shadow: 0 0 0 4px var(--primary-glow);
}

.btn {
  display: inline-flex;
  align-items: center;
  justify-content: center;
  gap: 8px;
  padding: 12px 24px;
  border: none;
  border-radius: 10px;
  font-family: 'Cairo', sans-serif;
  font-size: 15px;
  font-weight: 700;
  cursor: pointer;
  transition: var(--transition);
  text-decoration: none;
}

.btn-primary {
  background: linear-gradient(135deg, var(--primary), var(--primary-light));
  color: #fff;
  box-shadow: 0 4px 16px var(--primary-glow);
}

.btn-primary:hover {
  transform: translateY(-2px);
  box-shadow: 0 8px 24px var(--primary-glow);
}

.btn-primary:active { transform: translateY(0); }

.btn-full { width: 100%; }

.alert {
  padding: 12px 16px;
  border-radius: 10px;
  font-size: 14px;
  font-weight: 600;
  margin-bottom: 16px;
}

.alert-danger { background: #fef2f2; color: #dc2626; border: 1px solid #fecaca; }
.alert-success { background: #f0fdf4; color: #16a34a; border: 1px solid #bbf7d0; }
.alert-warning { background: #fffbeb; color: #d97706; border: 1px solid #fde68a; }

/* ═══ الشريط العلوي ═══ */
.navbar {
  background: linear-gradient(135deg, #0f172a, #1e3a8a);
  padding: 14px 28px;
  display: flex;
  align-items: center;
  justify-content: space-between;
  box-shadow: 0 4px 24px rgba(0,0,0,0.2);
  position: sticky;
  top: 0;
  z-index: 100;
}

.navbar .brand {
  display: flex;
  align-items: center;
  gap: 12px;
  color: #fff;
  font-size: 18px;
  font-weight: 800;
}

.navbar .brand-icon {
  width: 40px; height: 40px;
  background: linear-gradient(135deg, var(--primary-light), var(--accent));
  border-radius: 10px;
  display: flex;
  align-items: center;
  justify-content: center;
  font-size: 20px;
}

.navbar .user-info {
  display: flex;
  align-items: center;
  gap: 12px;
  color: rgba(255,255,255,0.9);
  font-size: 14px;
}

.navbar .user-badge {
  background: rgba(255,255,255,0.1);
  border: 1px solid rgba(255,255,255,0.15);
  padding: 6px 14px;
  border-radius: 50px;
  display: flex;
  align-items: center;
  gap: 8px;
}

.btn-logout {
  background: rgba(239,68,68,0.15);
  color: #fca5a5;
  border: 1px solid rgba(239,68,68,0.3);
  padding: 7px 16px;
  border-radius: 8px;
  font-family: 'Cairo', sans-serif;
  font-size: 13px;
  font-weight: 600;
  cursor: pointer;
  transition: var(--transition);
}

.btn-logout:hover {
  background: rgba(239,68,68,0.3);
  color: #fff;
}

/* ═══ المحتوى الرئيسي ═══ */
.main-content {
  max-width: 1100px;
  margin: 0 auto;
  padding: 28px 20px;
}

/* ═══ بطاقات الإحصاء ═══ */
.stats-grid {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
  gap: 16px;
  margin-bottom: 28px;
}

.stat-card {
  background: var(--card);
  border-radius: var(--radius);
  padding: 20px 24px;
  box-shadow: var(--shadow);
  border: 1px solid var(--border);
  display: flex;
  align-items: center;
  gap: 16px;
  transition: var(--transition);
  animation: cardAppear 0.5s ease both;
}

.stat-card:hover {
  transform: translateY(-3px);
  box-shadow: var(--shadow-lg);
}

.stat-icon {
  width: 52px; height: 52px;
  border-radius: 12px;
  display: flex;
  align-items: center;
  justify-content: center;
  font-size: 24px;
  flex-shrink: 0;
}

.stat-icon.blue { background: linear-gradient(135deg, #dbeafe, #bfdbfe); }
.stat-icon.green { background: linear-gradient(135deg, #d1fae5, #a7f3d0); }
.stat-icon.orange { background: linear-gradient(135deg, #fef3c7, #fde68a); }
.stat-icon.red { background: linear-gradient(135deg, #fee2e2, #fecaca); }

.stat-info .num {
  font-size: 28px;
  font-weight: 800;
  color: var(--text);
  line-height: 1;
}

.stat-info .label {
  font-size: 13px;
  color: var(--text-muted);
  margin-top: 4px;
}

/* ═══ بطاقات المحتوى ═══ */
.card {
  background: var(--card);
  border-radius: var(--radius-lg);
  box-shadow: var(--shadow);
  border: 1px solid var(--border);
  overflow: hidden;
  margin-bottom: 24px;
  animation: cardAppear 0.5s ease both;
}

.card-header {
  padding: 20px 24px;
  border-bottom: 1px solid var(--border);
  display: flex;
  align-items: center;
  justify-content: space-between;
  background: linear-gradient(135deg, #f8faff, #eff6ff);
}

.card-header h3 {
  font-size: 17px;
  font-weight: 700;
  color: var(--primary);
  display: flex;
  align-items: center;
  gap: 10px;
}

.card-body { padding: 24px; }

/* ═══ بيانات المريض ═══ */
.patient-info-grid {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
  gap: 14px;
}

.info-field {
  background: #f8fafc;
  border: 1px solid var(--border);
  border-radius: 10px;
  padding: 12px 16px;
}

.info-field .field-label {
  font-size: 11px;
  font-weight: 600;
  color: var(--text-muted);
  text-transform: uppercase;
  letter-spacing: 0.5px;
  margin-bottom: 6px;
}

.info-field .field-value {
  font-size: 15px;
  font-weight: 600;
  color: var(--text);
}

.info-field .field-value-en {
  font-size: 12px;
  color: var(--text-muted);
  direction: ltr;
  text-align: left;
  margin-top: 2px;
}

/* ═══ شريط الحصة ═══ */
.quota-bar-wrap {
  background: #f1f5f9;
  border-radius: 50px;
  height: 12px;
  overflow: hidden;
  margin: 10px 0;
}

.quota-bar {
  height: 100%;
  border-radius: 50px;
  background: linear-gradient(90deg, var(--success), #34d399);
  transition: width 1s ease;
}

.quota-bar.warning { background: linear-gradient(90deg, var(--warning), #fbbf24); }
.quota-bar.danger { background: linear-gradient(90deg, var(--danger), #f87171); }

/* ═══ نموذج الإجازة ═══ */
.leave-form-grid {
  display: grid;
  grid-template-columns: 1fr 1fr;
  gap: 18px;
}

@media (max-width: 640px) {
  .leave-form-grid { grid-template-columns: 1fr; }
  .stats-grid { grid-template-columns: 1fr 1fr; }
}

.form-label {
  display: block;
  font-size: 13px;
  font-weight: 600;
  color: var(--text);
  margin-bottom: 8px;
}

.form-select {
  width: 100%;
  padding: 11px 16px;
  border: 2px solid var(--border);
  border-radius: 10px;
  font-family: 'Cairo', sans-serif;
  font-size: 14px;
  color: var(--text);
  background: #f8fafc;
  transition: var(--transition);
  outline: none;
  cursor: pointer;
}

.form-select:focus {
  border-color: var(--primary-light);
  background: #fff;
  box-shadow: 0 0 0 4px var(--primary-glow);
}

.time-mode-tabs {
  display: flex;
  gap: 8px;
  margin-bottom: 12px;
}

.time-tab {
  flex: 1;
  padding: 9px;
  border: 2px solid var(--border);
  border-radius: 8px;
  background: #f8fafc;
  font-family: 'Cairo', sans-serif;
  font-size: 13px;
  font-weight: 600;
  cursor: pointer;
  transition: var(--transition);
  text-align: center;
  color: var(--text-muted);
}

.time-tab.active {
  border-color: var(--primary-light);
  background: #eff6ff;
  color: var(--primary);
}

.time-tab:hover:not(.active) {
  border-color: #94a3b8;
  background: #f1f5f9;
}

/* ═══ جدول الطلبات ═══ */
.requests-table {
  width: 100%;
  border-collapse: collapse;
  font-size: 14px;
}

.requests-table th {
  background: #f1f5f9;
  padding: 12px 14px;
  text-align: right;
  font-weight: 700;
  color: var(--text-muted);
  font-size: 12px;
  text-transform: uppercase;
  letter-spacing: 0.5px;
  border-bottom: 2px solid var(--border);
}

.requests-table td {
  padding: 14px;
  border-bottom: 1px solid #f1f5f9;
  vertical-align: middle;
}

.requests-table tr:hover td { background: #f8faff; }

.status-badge {
  display: inline-flex;
  align-items: center;
  gap: 5px;
  padding: 4px 12px;
  border-radius: 50px;
  font-size: 12px;
  font-weight: 700;
}

.status-pending { background: #fef3c7; color: #d97706; }
.status-approved { background: #d1fae5; color: #059669; }
.status-rejected { background: #fee2e2; color: #dc2626; }

.btn-sm {
  padding: 6px 14px;
  font-size: 13px;
  border-radius: 8px;
}

.btn-outline {
  background: transparent;
  border: 2px solid var(--primary-light);
  color: var(--primary);
}

.btn-outline:hover {
  background: var(--primary);
  color: #fff;
}

/* ═══ Modal ═══ */
.modal-overlay {
  position: fixed;
  inset: 0;
  background: rgba(0,0,0,0.5);
  backdrop-filter: blur(4px);
  z-index: 1000;
  display: flex;
  align-items: center;
  justify-content: center;
  padding: 20px;
  opacity: 0;
  pointer-events: none;
  transition: opacity 0.3s ease;
}

.modal-overlay.active {
  opacity: 1;
  pointer-events: all;
}

.modal-box {
  background: #fff;
  border-radius: 20px;
  width: 100%;
  max-width: 560px;
  max-height: 90vh;
  overflow-y: auto;
  box-shadow: 0 40px 100px rgba(0,0,0,0.3);
  transform: scale(0.9) translateY(20px);
  transition: transform 0.3s cubic-bezier(0.34,1.56,0.64,1);
}

.modal-overlay.active .modal-box {
  transform: scale(1) translateY(0);
}

.modal-header {
  padding: 20px 24px;
  border-bottom: 1px solid var(--border);
  display: flex;
  align-items: center;
  justify-content: space-between;
  background: linear-gradient(135deg, #f8faff, #eff6ff);
}

.modal-header h4 {
  font-size: 17px;
  font-weight: 700;
  color: var(--primary);
}

.modal-close {
  width: 32px; height: 32px;
  border: none;
  background: #f1f5f9;
  border-radius: 8px;
  cursor: pointer;
  font-size: 18px;
  display: flex;
  align-items: center;
  justify-content: center;
  transition: var(--transition);
  color: var(--text-muted);
}

.modal-close:hover { background: #fee2e2; color: var(--danger); }

.modal-body { padding: 24px; }

.modal-footer {
  padding: 16px 24px;
  border-top: 1px solid var(--border);
  display: flex;
  gap: 10px;
  justify-content: flex-end;
}

/* ═══ Toast ═══ */
.toast-container {
  position: fixed;
  top: 80px;
  left: 50%;
  transform: translateX(-50%);
  z-index: 9999;
  display: flex;
  flex-direction: column;
  gap: 10px;
  pointer-events: none;
}

.toast {
  background: #fff;
  border-radius: 12px;
  padding: 14px 20px;
  box-shadow: 0 8px 32px rgba(0,0,0,0.15);
  font-size: 14px;
  font-weight: 600;
  display: flex;
  align-items: center;
  gap: 10px;
  min-width: 280px;
  max-width: 400px;
  animation: slideDown 0.4s ease;
  border-right: 4px solid var(--primary);
}

.toast.success { border-color: var(--success); }
.toast.error { border-color: var(--danger); }
.toast.warning { border-color: var(--warning); }

/* ═══ Spinner ═══ */
.spinner {
  width: 20px; height: 20px;
  border: 3px solid rgba(255,255,255,0.3);
  border-top-color: #fff;
  border-radius: 50%;
  animation: spin 0.8s linear infinite;
  display: inline-block;
}

/* ═══ Empty State ═══ */
.empty-state {
  text-align: center;
  padding: 48px 20px;
  color: var(--text-muted);
}

.empty-state .empty-icon { font-size: 56px; margin-bottom: 16px; opacity: 0.5; }
.empty-state h4 { font-size: 17px; font-weight: 700; margin-bottom: 8px; color: var(--text); }
.empty-state p { font-size: 14px; }

/* ═══ Animations ═══ */
@keyframes gradientShift {
  0% { background-position: 0% 50%; }
  50% { background-position: 100% 50%; }
  100% { background-position: 0% 50%; }
}

@keyframes float {
  0%, 100% { transform: translateY(0); }
  50% { transform: translateY(-12px); }
}

@keyframes slideUp {
  from { opacity: 0; transform: translateY(40px); }
  to { opacity: 1; transform: translateY(0); }
}

@keyframes slideDown {
  from { opacity: 0; transform: translateY(-20px); }
  to { opacity: 1; transform: translateY(0); }
}

@keyframes cardAppear {
  from { opacity: 0; transform: translateY(16px); }
  to { opacity: 1; transform: translateY(0); }
}

@keyframes spin { to { transform: rotate(360deg); } }

.card:nth-child(1) { animation-delay: 0.05s; }
.card:nth-child(2) { animation-delay: 0.1s; }
.card:nth-child(3) { animation-delay: 0.15s; }
.stat-card:nth-child(1) { animation-delay: 0.05s; }
.stat-card:nth-child(2) { animation-delay: 0.1s; }
.stat-card:nth-child(3) { animation-delay: 0.15s; }
.stat-card:nth-child(4) { animation-delay: 0.2s; }

/* ═══ Responsive ═══ */
@media (max-width: 768px) {
  .navbar { padding: 12px 16px; }
  .main-content { padding: 16px 12px; }
  .card-body { padding: 16px; }
  .login-card { padding: 32px 24px; }
  .requests-table { font-size: 12px; }
  .requests-table th, .requests-table td { padding: 10px 8px; }
}

.days-counter {
  display: flex;
  align-items: center;
  gap: 6px;
  font-size: 13px;
  font-weight: 600;
  color: var(--text-muted);
  margin-top: 8px;
}

.days-counter .used { color: var(--danger); }
.days-counter .remaining { color: var(--success); }
.days-counter .total { color: var(--primary); }

.section-divider {
  height: 1px;
  background: linear-gradient(90deg, transparent, var(--border), transparent);
  margin: 8px 0 20px;
}

.full-span { grid-column: 1 / -1; }
</style>
</head>
<body>

<?php if (!isPatientLoggedIn()): ?>
<!-- ═══════════════════════════════════════════════════════════ -->
<!--                    صفحة تسجيل الدخول                      -->
<!-- ═══════════════════════════════════════════════════════════ -->
<div class="login-page">
  <div class="login-card">
    <div class="login-icon">🏥</div>
    <h2>بوابة المرضى</h2>
    <p class="subtitle">Patient Portal — سجّل دخولك للوصول إلى ملفك الطبي</p>
    
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
<!-- ═══════════════════════════════════════════════════════════ -->
<!--                    لوحة تحكم المريض                        -->
<!-- ═══════════════════════════════════════════════════════════ -->

<!-- الشريط العلوي -->
<nav class="navbar">
  <div class="brand">
    <div class="brand-icon">🏥</div>
    <span>بوابة المرضى</span>
  </div>
  <div class="user-info">
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

<!-- المحتوى الرئيسي -->
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
        <div class="num"><?= count($leaveRequests) ?></div>
        <div class="label">إجمالي الطلبات</div>
      </div>
    </div>
  </div>

  <!-- بيانات المريض -->
  <?php if ($patientData): ?>
  <div class="card">
    <div class="card-header">
      <h3>👤 بياناتي الشخصية</h3>
      <span style="font-size:12px;color:var(--text-muted);">للعرض فقط — لا يمكن التعديل</span>
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
          <?php if (!empty($patientData['nationality_en'])): ?>
          <div class="field-value-en"><?= htmlspecialchars($patientData['nationality_en']) ?></div>
          <?php endif; ?>
        </div>
        <?php endif; ?>
        <?php if (!empty($patientData['employer_ar'])): ?>
        <div class="info-field">
          <div class="field-label">جهة العمل</div>
          <div class="field-value"><?= htmlspecialchars($patientData['employer_ar']) ?></div>
          <?php if (!empty($patientData['employer_en'])): ?>
          <div class="field-value-en"><?= htmlspecialchars($patientData['employer_en']) ?></div>
          <?php endif; ?>
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

  <!-- نموذج طلب إجازة -->
  <?php if ($remainingDays > 0): ?>
  <div class="card">
    <div class="card-header">
      <h3>📝 طلب إجازة مرضية جديدة</h3>
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
          
          <!-- عدد الأيام (للعرض) -->
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
              <button type="button" class="time-tab active" onclick="setTimeMode('auto', this)">تلقائي</button>
              <button type="button" class="time-tab" onclick="setTimeMode('random', this)">عشوائي</button>
              <button type="button" class="time-tab" onclick="setTimeMode('manual', this)">يدوي</button>
            </div>
            <input type="hidden" id="timeModeInput" name="time_mode" value="auto">
            <div id="manualTimeFields" style="display:none;display:none;">
              <div style="display:flex;gap:8px;align-items:center;">
                <input type="time" class="form-control" id="manualTimeInput" name="manual_time" style="flex:1;">
                <select class="form-select" name="manual_period" style="width:100px;">
                  <option value="AM">صباحاً</option>
                  <option value="PM">مساءً</option>
                </select>
              </div>
            </div>
            <div id="autoTimeInfo" style="font-size:12px;color:var(--text-muted);margin-top:6px;">
              ⏰ سيُستخدم وقت تقديم الطلب تلقائياً
            </div>
          </div>
          
        </div>
        
        <div style="margin-top:20px;display:flex;gap:12px;justify-content:flex-end;">
          <button type="button" class="btn btn-primary" onclick="submitLeaveRequest()" id="submitBtn">
            📤 تقديم الطلب
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
        <h4>لا يمكن تقديم طلب إجازة</h4>
        <p>
          <?php if ($allowedDays === 0): ?>
            لم يتم تخصيص أيام إجازة لحسابك بعد. يرجى التواصل مع الإدارة.
          <?php else: ?>
            لقد استنفدت جميع أيام الإجازة المسموحة (<?= $allowedDays ?> يوم).
          <?php endif; ?>
        </p>
      </div>
    </div>
  </div>
  <?php endif; ?>

  <!-- سجل الطلبات -->
  <div class="card">
    <div class="card-header">
      <h3>📋 سجل طلبات الإجازة</h3>
      <span style="font-size:12px;color:var(--text-muted);"><?= count($leaveRequests) ?> طلب</span>
    </div>
    <div class="card-body" style="padding:0;">
      <?php if (empty($leaveRequests)): ?>
      <div class="empty-state">
        <div class="empty-icon">📭</div>
        <h4>لا توجد طلبات بعد</h4>
        <p>لم تقدّم أي طلب إجازة مرضية حتى الآن.</p>
      </div>
      <?php else: ?>
      <div style="overflow-x:auto;">
        <table class="requests-table">
          <thead>
            <tr>
              <th>#</th>
              <th>المستشفى</th>
              <th>الطبيب</th>
              <th>من</th>
              <th>إلى</th>
              <th>الأيام</th>
              <th>الوقت</th>
              <th>الحالة</th>
              <th>PDF</th>
            </tr>
          </thead>
          <tbody>
            <?php foreach ($leaveRequests as $i => $req): ?>
            <tr>
              <td style="color:var(--text-muted);font-size:12px;"><?= $i + 1 ?></td>
              <td style="font-weight:600;"><?= htmlspecialchars($req['h_name_ar'] ?? '') ?></td>
              <td>
                <div style="font-weight:600;"><?= htmlspecialchars($req['d_name_ar'] ?? '') ?></div>
                <div style="font-size:11px;color:var(--text-muted);"><?= htmlspecialchars($req['d_title_ar'] ?? '') ?></div>
              </td>
              <td style="direction:ltr;text-align:right;"><?= fmtDateAr($req['start_date']) ?></td>
              <td style="direction:ltr;text-align:right;"><?= fmtDateAr($req['end_date']) ?></td>
              <td>
                <span style="background:#eff6ff;color:var(--primary);padding:3px 10px;border-radius:50px;font-weight:700;font-size:13px;">
                  <?= $req['days_count'] ?>
                </span>
              </td>
              <td style="font-size:12px;direction:ltr;text-align:right;">
                <?= htmlspecialchars($req['issue_time'] ?? '') ?>
                <?= $req['issue_period'] === 'AM' ? 'ص' : ($req['issue_period'] === 'PM' ? 'م' : '') ?>
              </td>
              <td>
                <?php
                  $statusMap = ['pending' => ['label' => 'قيد المراجعة', 'class' => 'status-pending'],
                                'approved' => ['label' => 'معتمدة', 'class' => 'status-approved'],
                                'rejected' => ['label' => 'مرفوضة', 'class' => 'status-rejected']];
                  $s = $statusMap[$req['status']] ?? ['label' => $req['status'], 'class' => 'status-pending'];
                ?>
                <span class="status-badge <?= $s['class'] ?>"><?= $s['label'] ?></span>
              </td>
              <td>
                <a href="user.php?action=generate_request_pdf&request_id=<?= $req['id'] ?>" 
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
const ALLOWED_DAYS = <?= $allowedDays ?>;

// ═══ تحميل الأطباء حسب المستشفى ═══
function loadDoctors(hospitalId) {
  const sel = document.getElementById('doctorSelect');
  sel.innerHTML = '<option value="">جاري التحميل...</option>';
  
  if (!hospitalId) {
    sel.innerHTML = '<option value="">-- اختر المستشفى أولاً --</option>';
    return;
  }
  
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
    .catch(() => {
      sel.innerHTML = '<option value="">خطأ في التحميل</option>';
    });
}

// ═══ حساب عدد الأيام ═══
function calcDays() {
  const start = document.getElementById('startDate').value;
  const end = document.getElementById('endDate').value;
  const display = document.getElementById('daysDisplay');
  const hidden = document.getElementById('daysCount');
  const warning = document.getElementById('daysWarning');
  
  if (!start || !end) { display.value = ''; hidden.value = ''; return; }
  
  const s = new Date(start);
  const e = new Date(end);
  
  if (e < s) {
    display.value = '';
    hidden.value = '';
    warning.style.display = 'block';
    warning.textContent = '⚠️ تاريخ النهاية يجب أن يكون بعد تاريخ البداية.';
    return;
  }
  
  const diff = Math.round((e - s) / (1000 * 60 * 60 * 24)) + 1;
  display.value = diff + ' يوم';
  hidden.value = diff;
  
  if (diff > MAX_DAYS) {
    warning.style.display = 'block';
    warning.textContent = `⚠️ عدد الأيام (${diff}) يتجاوز الحصة المتبقية (${MAX_DAYS} يوم).`;
  } else {
    warning.style.display = 'none';
  }
  
  // تحديث تاريخ النهاية الأدنى
  document.getElementById('endDate').min = start;
}

// ═══ وضع الوقت ═══
function setTimeMode(mode, btn) {
  document.querySelectorAll('.time-tab').forEach(t => t.classList.remove('active'));
  btn.classList.add('active');
  document.getElementById('timeModeInput').value = mode;
  
  const manualFields = document.getElementById('manualTimeFields');
  const autoInfo = document.getElementById('autoTimeInfo');
  
  if (mode === 'manual') {
    manualFields.style.display = 'block';
    autoInfo.style.display = 'none';
  } else if (mode === 'random') {
    manualFields.style.display = 'none';
    autoInfo.style.display = 'block';
    autoInfo.textContent = '🎲 سيتم اختيار وقت عشوائي بين 8 صباحاً و 5 مساءً';
  } else {
    manualFields.style.display = 'none';
    autoInfo.style.display = 'block';
    autoInfo.textContent = '⏰ سيُستخدم وقت تقديم الطلب تلقائياً';
  }
}

// ═══ تقديم الطلب ═══
function submitLeaveRequest() {
  const form = document.getElementById('leaveForm');
  const hospitalId = document.getElementById('hospitalSelect').value;
  const doctorId = document.getElementById('doctorSelect').value;
  const startDate = document.getElementById('startDate').value;
  const endDate = document.getElementById('endDate').value;
  const daysCount = document.getElementById('daysCount').value;
  
  if (!hospitalId) { showToast('يرجى اختيار المستشفى.', 'error'); return; }
  if (!doctorId) { showToast('يرجى اختيار الطبيب.', 'error'); return; }
  if (!startDate) { showToast('يرجى تحديد تاريخ البداية.', 'error'); return; }
  if (!endDate) { showToast('يرجى تحديد تاريخ النهاية.', 'error'); return; }
  if (!daysCount || parseInt(daysCount) <= 0) { showToast('يرجى التحقق من التواريخ.', 'error'); return; }
  if (parseInt(daysCount) > MAX_DAYS) { showToast(`عدد الأيام يتجاوز الحصة المتبقية (${MAX_DAYS} يوم).`, 'error'); return; }
  
  const btn = document.getElementById('submitBtn');
  btn.disabled = true;
  btn.innerHTML = '<span class="spinner"></span> جاري الإرسال...';
  
  const formData = new FormData(form);
  formData.append('action', 'submit_leave_request');
  
  fetch('user.php', { method: 'POST', body: formData })
    .then(r => r.json())
    .then(data => {
      if (data.success) {
        showToast(data.message, 'success');
        setTimeout(() => location.reload(), 1800);
      } else {
        showToast(data.message || 'حدث خطأ.', 'error');
        btn.disabled = false;
        btn.innerHTML = '📤 تقديم الطلب';
      }
    })
    .catch(() => {
      showToast('خطأ في الاتصال. يرجى المحاولة مجدداً.', 'error');
      btn.disabled = false;
      btn.innerHTML = '📤 تقديم الطلب';
    });
}

// ═══ Toast ═══
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
  }, 4000);
}
</script>

<?php endif; ?>
</body>
</html>
