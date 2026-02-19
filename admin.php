<?php
/**
 * لوحة تحكم الإجازات المرضية - النسخة المحسّنة v2
 * ملف واحد شامل يحتوي على PHP + HTML + CSS + JavaScript
 * 
 * التحسينات:
 * 1. تحسين التصميم بشكل احترافي
 * 2. إضافة خاصية تغيير الطبيب في التعديل
 * 3. إضافة خاصية تكرار الإجازات
 * 4. إضافة نظام إدارة المستخدمين مع تسجيل الجلسات
 * 5. تحسينات عامة في الأداء والأمان
 */

ini_set('session.use_only_cookies', '1');
ini_set('session.cookie_httponly', '1');
ini_set('session.cookie_secure', (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off') ? '1' : '0');
ini_set('session.cookie_samesite', 'Strict');
ini_set('session.use_strict_mode', '1');
session_start();

date_default_timezone_set('Asia/Riyadh');
header('X-Frame-Options: SAMEORIGIN');
header('X-Content-Type-Options: nosniff');
header('Referrer-Policy: strict-origin-when-cross-origin');
header('Permissions-Policy: geolocation=(), microphone=(), camera=()');

// ======================== إعدادات قاعدة البيانات ========================
$db_host = 'mysql.railway.internal';
$db_user = 'root';
$db_pass = 'mDxJcHtRORIlpLbtDJKKckeuLgozRUVO';
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
    die(json_encode(['success' => false, 'message' => 'فشل الاتصال بقاعدة البيانات: ' . $e->getMessage()]));
}

$pdo->exec("SET time_zone = '+03:00'");

// ======================== إنشاء جداول المستخدمين والجلسات ========================
$pdo->exec("CREATE TABLE IF NOT EXISTS admin_users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(100) NOT NULL UNIQUE,
    password_hash VARCHAR(255) NOT NULL,
    display_name VARCHAR(150) NOT NULL,
    role ENUM('admin','user') DEFAULT 'user',
    is_active TINYINT(1) DEFAULT 1,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci");

$pdo->exec("CREATE TABLE IF NOT EXISTS user_sessions (
    id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT NOT NULL,
    login_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    logout_at DATETIME NULL,
    ip_address VARCHAR(45),
    user_agent TEXT,
    FOREIGN KEY (user_id) REFERENCES admin_users(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci");

$pdo->exec("CREATE TABLE IF NOT EXISTS user_messages (
    id INT AUTO_INCREMENT PRIMARY KEY,
    sender_id INT NOT NULL,
    receiver_id INT NOT NULL,
    message_text TEXT NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    is_read TINYINT(1) DEFAULT 0,
    FOREIGN KEY (sender_id) REFERENCES admin_users(id) ON DELETE CASCADE,
    FOREIGN KEY (receiver_id) REFERENCES admin_users(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci");

function ensureIndex(PDO $pdo, string $table, string $indexName, string $columns): void {
    $check = $pdo->prepare("SELECT COUNT(*) FROM information_schema.statistics WHERE table_schema = DATABASE() AND table_name = ? AND index_name = ?");
    $check->execute([$table, $indexName]);
    if ((int)$check->fetchColumn() === 0) {
        $pdo->exec("CREATE INDEX $indexName ON $table ($columns)");
    }
}

ensureIndex($pdo, 'sick_leaves', 'idx_sick_leaves_deleted_created', 'deleted_at, created_at');
ensureIndex($pdo, 'sick_leaves', 'idx_sick_leaves_paid', 'is_paid');
ensureIndex($pdo, 'sick_leaves', 'idx_sick_leaves_patient', 'patient_id');
ensureIndex($pdo, 'sick_leaves', 'idx_sick_leaves_doctor', 'doctor_id');
ensureIndex($pdo, 'notifications', 'idx_notifications_type_created', 'type, created_at');
ensureIndex($pdo, 'notifications', 'idx_notifications_leave', 'leave_id');
ensureIndex($pdo, 'leave_queries', 'idx_leave_queries_leave', 'leave_id');
ensureIndex($pdo, 'leave_queries', 'idx_leave_queries_queried_at', 'queried_at');
ensureIndex($pdo, 'patients', 'idx_patients_identity_number', 'identity_number');
ensureIndex($pdo, 'patients', 'idx_patients_name', 'name');
ensureIndex($pdo, 'doctors', 'idx_doctors_name', 'name');
ensureIndex($pdo, 'user_messages', 'idx_user_messages_pair_created', 'sender_id, receiver_id, created_at');
ensureIndex($pdo, 'user_messages', 'idx_user_messages_receiver_read', 'receiver_id, is_read');

// إنشاء مستخدم افتراضي إذا لم يوجد أي مستخدم
$stmt = $pdo->query("SELECT COUNT(*) as cnt FROM admin_users");
$userCount = $stmt->fetch()['cnt'];
if ($userCount == 0) {
    $defaultPass = password_hash('admin123', PASSWORD_DEFAULT);
    $pdo->prepare("INSERT INTO admin_users (username, password_hash, display_name, role) VALUES (?, ?, ?, ?)")
        ->execute(['admin', $defaultPass, 'المشرف الرئيسي', 'admin']);
}

// ======================== دوال الأمان ========================
function csrf_token() {
    if (empty($_SESSION['csrf_token'])) {
        $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
    }
    return $_SESSION['csrf_token'];
}

function csrf_input() {
    return '<input type="hidden" name="csrf_token" value="' . csrf_token() . '">';
}

function verify_csrf($token) {
    return isset($_SESSION['csrf_token']) && hash_equals($_SESSION['csrf_token'], $token);
}

function is_logged_in() {
    return isset($_SESSION['admin_logged_in']) && $_SESSION['admin_logged_in'] === true;
}

function require_login() {
    if (!is_logged_in()) {
        if (is_ajax_request()) {
            header('Content-Type: application/json; charset=utf-8');
            echo json_encode(['success' => false, 'message' => 'يرجى تسجيل الدخول أولاً.', 'redirect' => true]);
            exit;
        }
        // لا نعيد التوجيه - نعرض صفحة تسجيل الدخول في نفس الملف
        return false;
    }
    return true;
}

function is_ajax_request() {
    return !empty($_SERVER['HTTP_X_REQUESTED_WITH']) && strtolower($_SERVER['HTTP_X_REQUESTED_WITH']) === 'xmlhttprequest'
        || (isset($_POST['action']) && !empty($_POST['action']));
}

// ======================== دوال مساعدة ========================
function getStats($pdo) {
    $stats = [];
    $stats['total'] = $pdo->query("SELECT COUNT(*) FROM sick_leaves WHERE deleted_at IS NULL")->fetchColumn();
    $stats['active'] = $stats['total'];
    $stats['archived'] = $pdo->query("SELECT COUNT(*) FROM sick_leaves WHERE deleted_at IS NOT NULL")->fetchColumn();
    $stats['patients'] = $pdo->query("SELECT COUNT(*) FROM patients")->fetchColumn();
    $stats['doctors'] = $pdo->query("SELECT COUNT(*) FROM doctors")->fetchColumn();
    $stats['paid'] = $pdo->query("SELECT COUNT(*) FROM sick_leaves WHERE is_paid = 1 AND deleted_at IS NULL")->fetchColumn();
    $stats['unpaid'] = $pdo->query("SELECT COUNT(*) FROM sick_leaves WHERE is_paid = 0 AND deleted_at IS NULL")->fetchColumn();
    $stats['paid_amount'] = $pdo->query("SELECT COALESCE(SUM(payment_amount), 0) FROM sick_leaves WHERE is_paid = 1 AND deleted_at IS NULL")->fetchColumn();
    $stats['unpaid_amount'] = $pdo->query("SELECT COALESCE(SUM(payment_amount), 0) FROM sick_leaves WHERE is_paid = 0 AND deleted_at IS NULL")->fetchColumn();
    return $stats;
}

function nowSaudi(): string {
    return (new DateTime('now', new DateTimeZone('Asia/Riyadh')))->format('Y-m-d H:i:s');
}

function generateServiceCode($pdo, $prefix, $issueDate = null) {
    $prefix = strtoupper(trim($prefix));
    if (!in_array($prefix, ['GSL', 'PSL'])) {
        $prefix = 'GSL';
    }

    $issueDateObj = DateTime::createFromFormat('Y-m-d', (string)$issueDate, new DateTimeZone('Asia/Riyadh'));
    if (!$issueDateObj) {
        $issueDateObj = new DateTime('now', new DateTimeZone('Asia/Riyadh'));
    }
    $datePart = $issueDateObj->format('ymd');

    $stmt = $pdo->prepare("SELECT service_code FROM sick_leaves WHERE service_code LIKE ? ORDER BY id DESC LIMIT 1");
    $stmt->execute([$prefix . $datePart . '%']);
    $last = $stmt->fetchColumn();

    if ($last && preg_match('/^(?:GSL|PSL)\d{6}(\d+)$/', $last, $m)) {
        $num = intval($m[1]) + 1;
    } else {
        $num = 1;
    }

    return $prefix . $datePart . str_pad((string)$num, 4, '0', STR_PAD_LEFT);
}

function fetchAllData($pdo) {
    ensureDelayedUnpaidNotifications($pdo);
    // الإجازات النشطة
    $leaves = $pdo->query(" 
        SELECT sl.*, p.name AS patient_name, p.identity_number, p.phone AS patient_phone,
               d.name AS doctor_name, d.title AS doctor_title, d.note AS doctor_note,
               COALESCE(lq.queries_count, 0) AS queries_count
        FROM sick_leaves sl
        LEFT JOIN patients p ON sl.patient_id = p.id
        LEFT JOIN doctors d ON sl.doctor_id = d.id
        LEFT JOIN (
            SELECT leave_id, COUNT(*) AS queries_count
            FROM leave_queries
            GROUP BY leave_id
        ) lq ON lq.leave_id = sl.id
        WHERE sl.deleted_at IS NULL
        ORDER BY sl.created_at DESC, sl.id DESC
    ")->fetchAll();

    // الإجازات المؤرشفة
    $archived = $pdo->query(" 
        SELECT sl.*, p.name AS patient_name, p.identity_number, p.phone AS patient_phone,
               d.name AS doctor_name, d.title AS doctor_title, d.note AS doctor_note,
               COALESCE(lq.queries_count, 0) AS queries_count
        FROM sick_leaves sl
        LEFT JOIN patients p ON sl.patient_id = p.id
        LEFT JOIN doctors d ON sl.doctor_id = d.id
        LEFT JOIN (
            SELECT leave_id, COUNT(*) AS queries_count
            FROM leave_queries
            GROUP BY leave_id
        ) lq ON lq.leave_id = sl.id
        WHERE sl.deleted_at IS NOT NULL
        ORDER BY sl.deleted_at DESC, sl.id DESC
    ")->fetchAll();

    // سجل الاستعلامات
    $queries = $pdo->query("
        SELECT lq.id AS qid, lq.leave_id, lq.queried_at, lq.source,
               sl.service_code, p.name AS patient_name, p.identity_number
        FROM leave_queries lq
        LEFT JOIN sick_leaves sl ON lq.leave_id = sl.id
        LEFT JOIN patients p ON sl.patient_id = p.id
        ORDER BY lq.queried_at DESC
    ")->fetchAll();

    // إشعارات المدفوعات
    $notifications_payment = $pdo->query("
        SELECT n.*, sl.payment_amount, sl.service_code, sl.patient_id, p.name AS patient_name
        FROM notifications n
        LEFT JOIN sick_leaves sl ON n.leave_id = sl.id
        LEFT JOIN patients p ON sl.patient_id = p.id
        WHERE n.type = 'payment'
        ORDER BY n.created_at DESC
    ")->fetchAll();

    // المدفوعات لكل مريض
    $payments = $pdo->query("
        SELECT p.id, p.name,
               COUNT(sl.id) AS total,
               SUM(CASE WHEN sl.is_paid = 1 THEN 1 ELSE 0 END) AS paid_count,
               SUM(CASE WHEN sl.is_paid = 0 THEN 1 ELSE 0 END) AS unpaid_count,
               COALESCE(SUM(CASE WHEN sl.is_paid = 1 THEN sl.payment_amount ELSE 0 END), 0) AS paid_amount,
               COALESCE(SUM(CASE WHEN sl.is_paid = 0 THEN sl.payment_amount ELSE 0 END), 0) AS unpaid_amount
        FROM patients p
        LEFT JOIN sick_leaves sl ON p.id = sl.patient_id AND sl.deleted_at IS NULL
        GROUP BY p.id, p.name
        ORDER BY p.name
    ")->fetchAll();

    return compact('leaves', 'archived', 'queries', 'notifications_payment', 'payments');
}


function fetchActiveOperationalData($pdo) {
    ensureDelayedUnpaidNotifications($pdo);
    $leaves = $pdo->query(" 
        SELECT sl.*, p.name AS patient_name, p.identity_number, p.phone AS patient_phone,
               d.name AS doctor_name, d.title AS doctor_title, d.note AS doctor_note,
               COALESCE(lq.queries_count, 0) AS queries_count
        FROM sick_leaves sl
        LEFT JOIN patients p ON sl.patient_id = p.id
        LEFT JOIN doctors d ON sl.doctor_id = d.id
        LEFT JOIN (
            SELECT leave_id, COUNT(*) AS queries_count
            FROM leave_queries
            GROUP BY leave_id
        ) lq ON lq.leave_id = sl.id
        WHERE sl.deleted_at IS NULL
        ORDER BY sl.created_at DESC, sl.id DESC
    ")->fetchAll();

    $notifications_payment = $pdo->query(" 
        SELECT n.*, sl.payment_amount, sl.service_code, sl.patient_id, p.name AS patient_name
        FROM notifications n
        LEFT JOIN sick_leaves sl ON n.leave_id = sl.id
        LEFT JOIN patients p ON sl.patient_id = p.id
        WHERE n.type = 'payment'
        ORDER BY n.created_at DESC
    ")->fetchAll();

    $payments = $pdo->query(" 
        SELECT p.id, p.name,
               COUNT(sl.id) AS total,
               SUM(CASE WHEN sl.is_paid = 1 THEN 1 ELSE 0 END) AS paid_count,
               SUM(CASE WHEN sl.is_paid = 0 THEN 1 ELSE 0 END) AS unpaid_count,
               COALESCE(SUM(CASE WHEN sl.is_paid = 1 THEN sl.payment_amount ELSE 0 END), 0) AS paid_amount,
               COALESCE(SUM(CASE WHEN sl.is_paid = 0 THEN sl.payment_amount ELSE 0 END), 0) AS unpaid_amount
        FROM patients p
        LEFT JOIN sick_leaves sl ON p.id = sl.patient_id AND sl.deleted_at IS NULL
        GROUP BY p.id, p.name
        ORDER BY p.name
    ")->fetchAll();

    return compact('leaves', 'payments', 'notifications_payment');
}

function ensureDelayedUnpaidNotifications($pdo): void {
    $stmt = $pdo->prepare("
        SELECT sl.id, sl.service_code, sl.payment_amount
        FROM sick_leaves sl
        LEFT JOIN notifications n ON n.leave_id = sl.id AND n.type = 'payment'
        WHERE sl.deleted_at IS NULL
          AND sl.is_paid = 0
          AND sl.payment_amount > 0
          AND sl.created_at <= (NOW() - INTERVAL 5 MINUTE)
          AND n.id IS NULL
    ");
    $stmt->execute();
    $rows = $stmt->fetchAll();
    if (!$rows) return;

    $ins = $pdo->prepare("INSERT INTO notifications (type, leave_id, message) VALUES ('payment', ?, ?)");
    foreach ($rows as $row) {
        $ins->execute([
            $row['id'],
            "إجازة غير مدفوعة منذ أكثر من 5 دقائق برمز {$row['service_code']} بمبلغ {$row['payment_amount']}"
        ]);
    }
}

// ======================== معالجة تسجيل الدخول والخروج ========================
if (isset($_POST['action']) && $_POST['action'] === 'login') {
    header('Content-Type: application/json; charset=utf-8');

    $maxAttempts = 5;
    $lockMinutes = 15;
    $_SESSION['login_attempts'] = $_SESSION['login_attempts'] ?? 0;
    $_SESSION['login_lock_until'] = $_SESSION['login_lock_until'] ?? null;

    if (!empty($_SESSION['login_lock_until']) && time() < intval($_SESSION['login_lock_until'])) {
        $remain = ceil((intval($_SESSION['login_lock_until']) - time()) / 60);
        echo json_encode(['success' => false, 'message' => "تم قفل تسجيل الدخول مؤقتاً. حاول بعد {$remain} دقيقة."]);
        exit;
    }
    $username = trim($_POST['username'] ?? '');
    $password = $_POST['password'] ?? '';
    
    if (empty($username) || empty($password)) {
        echo json_encode(['success' => false, 'message' => 'يرجى إدخال اسم المستخدم وكلمة المرور.']);
        exit;
    }
    
    $stmt = $pdo->prepare("SELECT * FROM admin_users WHERE username = ? AND is_active = 1");
    $stmt->execute([$username]);
    $user = $stmt->fetch();
    
    if ($user && password_verify($password, $user['password_hash'])) {
        session_regenerate_id(true);
        $_SESSION['login_attempts'] = 0;
        $_SESSION['login_lock_until'] = null;
        $_SESSION['admin_logged_in'] = true;
        $_SESSION['admin_user_id'] = $user['id'];
        $_SESSION['admin_username'] = $user['username'];
        $_SESSION['admin_display_name'] = $user['display_name'];
        $_SESSION['admin_role'] = $user['role'];
        
        // تسجيل الجلسة
        $stmt = $pdo->prepare("INSERT INTO user_sessions (user_id, ip_address, user_agent) VALUES (?, ?, ?)");
        $stmt->execute([$user['id'], $_SERVER['REMOTE_ADDR'] ?? '', $_SERVER['HTTP_USER_AGENT'] ?? '']);
        $_SESSION['session_record_id'] = $pdo->lastInsertId();
        
        echo json_encode(['success' => true, 'message' => 'تم تسجيل الدخول بنجاح.']);
    } else {
        $_SESSION['login_attempts'] = intval($_SESSION['login_attempts'] ?? 0) + 1;
        if ($_SESSION['login_attempts'] >= $maxAttempts) {
            $_SESSION['login_lock_until'] = time() + ($lockMinutes * 60);
            $_SESSION['login_attempts'] = 0;
            echo json_encode(['success' => false, 'message' => 'تم تجاوز عدد المحاولات المسموح. تم القفل مؤقتاً 15 دقيقة.']);
        } else {
            echo json_encode(['success' => false, 'message' => 'اسم المستخدم أو كلمة المرور غير صحيحة.']);
        }
    }
    exit;
}

if (isset($_POST['action']) && $_POST['action'] === 'logout') {
    // تسجيل وقت الخروج
    if (isset($_SESSION['session_record_id'])) {
        $stmt = $pdo->prepare("UPDATE user_sessions SET logout_at = ? WHERE id = ?");
        $stmt->execute([nowSaudi(), $_SESSION['session_record_id']]);
    }
    session_destroy();
    header('Content-Type: application/json; charset=utf-8');
    echo json_encode(['success' => true, 'message' => 'تم تسجيل الخروج بنجاح.']);
    exit;
}

// ======================== معالجة طلبات AJAX ========================
if (isset($_POST['action']) && $_POST['action'] !== 'login' && $_POST['action'] !== 'logout') {
    header('Content-Type: application/json; charset=utf-8');
    
    if (!is_logged_in()) {
        echo json_encode(['success' => false, 'message' => 'يرجى تسجيل الدخول أولاً.', 'redirect' => true]);
        exit;
    }
    
    if (!verify_csrf($_POST['csrf_token'] ?? '')) {
        echo json_encode(['success' => false, 'message' => 'خطأ في التحقق من الأمان (CSRF). يرجى تحديث الصفحة.']);
        exit;
    }
    
    $action = $_POST['action'];

    // ======================== معالجة الإجراءات ========================
    switch ($action) {
        case 'fetch_all_leaves':
            $data = fetchAllData($pdo);
            $data['doctors'] = $pdo->query("SELECT * FROM doctors ORDER BY name")->fetchAll();
            $data['patients'] = $pdo->query("SELECT * FROM patients ORDER BY name")->fetchAll();
            $data['stats'] = getStats($pdo);
            $data['success'] = true;
            echo json_encode($data);
            break;

        case 'add_leave':
            $patient_id = null;
            $doctor_id = null;

            // معالجة المريض
            $patient_select = $_POST['patient_select'] ?? '';
            if ($patient_select === 'manual') {
                $pName = trim($_POST['patient_manual_name'] ?? '');
                $pIdentity = trim($_POST['patient_manual_id'] ?? '');
                $pPhone = trim($_POST['patient_manual_phone'] ?? '');
                if (empty($pName) || empty($pIdentity)) {
                    echo json_encode(['success' => false, 'message' => 'يرجى إدخال اسم المريض ورقم هويته.']);
                    exit;
                }
                $stmt = $pdo->prepare("SELECT id FROM patients WHERE identity_number = ?");
                $stmt->execute([$pIdentity]);
                $existing = $stmt->fetch();
                if ($existing) {
                    $patient_id = $existing['id'];
                } else {
                    $stmt = $pdo->prepare("INSERT INTO patients (name, identity_number, phone) VALUES (?, ?, ?)");
                    $stmt->execute([$pName, $pIdentity, $pPhone]);
                    $patient_id = $pdo->lastInsertId();
                }
            } else {
                $patient_id = intval($patient_select);
            }

            // معالجة الطبيب
            $doctor_select = $_POST['doctor_select'] ?? '';
            if ($doctor_select === 'manual') {
                $dName = trim($_POST['doctor_manual_name'] ?? '');
                $dTitle = trim($_POST['doctor_manual_title'] ?? '');
                $dNote = trim($_POST['doctor_manual_note'] ?? '');
                if (empty($dName) || empty($dTitle)) {
                    echo json_encode(['success' => false, 'message' => 'يرجى إدخال اسم الطبيب ومسمّاه الوظيفي.']);
                    exit;
                }
                $stmt = $pdo->prepare("INSERT INTO doctors (name, title, note) VALUES (?, ?, ?)");
                $stmt->execute([$dName, $dTitle, $dNote]);
                $doctor_id = $pdo->lastInsertId();
            } else {
                $doctor_id = intval($doctor_select);
            }

            $issue_date = $_POST['issue_date'] ?? '';

            // توليد رمز الخدمة
            $service_code_manual = trim($_POST['service_code_manual'] ?? '');
            $service_prefix = $_POST['service_prefix'] ?? 'GSL';
            if (!empty($service_code_manual)) {
                $service_code = strtoupper($service_code_manual);
            } else {
                $service_code = generateServiceCode($pdo, $service_prefix, $issue_date);
            }

            $start_date = $_POST['start_date'] ?? '';
            $end_date = $_POST['end_date'] ?? '';
            $days_count = intval($_POST['days_count'] ?? 0);
            $is_companion = isset($_POST['is_companion']) ? 1 : 0;
            $companion_name = trim($_POST['companion_name'] ?? '');
            $companion_relation = trim($_POST['companion_relation'] ?? '');
            $is_paid = isset($_POST['is_paid']) ? 1 : 0;
            $payment_amount = floatval($_POST['payment_amount'] ?? 0);

            if (empty($issue_date) || empty($start_date) || empty($end_date) || $days_count <= 0 || $patient_id <= 0 || $doctor_id <= 0) {
                echo json_encode(['success' => false, 'message' => 'يرجى تعبئة جميع الحقول المطلوبة.']);
                exit;
            }

            $stmt = $pdo->prepare("INSERT INTO sick_leaves 
                (service_code, patient_id, doctor_id, issue_date, start_date, end_date, days_count, 
                 is_companion, companion_name, companion_relation, is_paid, payment_amount) 
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)");
            $stmt->execute([
                $service_code, $patient_id, $doctor_id, $issue_date, $start_date, $end_date, $days_count,
                $is_companion, $companion_name, $companion_relation, $is_paid, $payment_amount
            ]);

            // إضافة إشعار دفع إذا كانت غير مدفوعة
            if (!$is_paid && $payment_amount > 0) {
                $leaveId = $pdo->lastInsertId();
                $stmt = $pdo->prepare("INSERT INTO notifications (type, leave_id, message) VALUES ('payment', ?, ?)");
                $stmt->execute([$leaveId, "إجازة جديدة غير مدفوعة برمز $service_code بمبلغ $payment_amount"]);
            }

            $data = fetchActiveOperationalData($pdo);
            $data['doctors'] = $pdo->query("SELECT * FROM doctors ORDER BY name")->fetchAll();
            $data['patients'] = $pdo->query("SELECT * FROM patients ORDER BY name")->fetchAll();
            $data['stats'] = getStats($pdo);
            $data['success'] = true;
            $data['message'] = "تمت إضافة الإجازة بنجاح. رمز الخدمة: $service_code";
            echo json_encode($data);
            break;

        case 'edit_leave':
            $leave_id = intval($_POST['leave_id_edit'] ?? 0);
            $service_code = strtoupper(trim($_POST['service_code_edit'] ?? ''));
            $issue_date = $_POST['issue_date_edit'] ?? '';
            $start_date = $_POST['start_date_edit'] ?? '';
            $end_date = $_POST['end_date_edit'] ?? '';
            $days_count = intval($_POST['days_count_edit'] ?? 0);
            $is_companion = isset($_POST['is_companion_edit']) ? 1 : 0;
            $companion_name = trim($_POST['companion_name_edit'] ?? '');
            $companion_relation = trim($_POST['companion_relation_edit'] ?? '');
            $is_paid = isset($_POST['is_paid_edit']) ? 1 : 0;
            $payment_amount = floatval($_POST['payment_amount_edit'] ?? 0);
            
            // خاصية تغيير الطبيب
            $doctor_id_edit_raw = $_POST['doctor_id_edit'] ?? '';
            $doctor_id_edit = null;
            if ($doctor_id_edit_raw === 'manual') {
                $dName = trim($_POST['doctor_manual_name_edit'] ?? '');
                $dTitle = trim($_POST['doctor_manual_title_edit'] ?? '');
                $dNote = trim($_POST['doctor_manual_note_edit'] ?? '');
                if (empty($dName) || empty($dTitle)) {
                    echo json_encode(['success' => false, 'message' => 'يرجى إدخال اسم الطبيب ومسمّاه الوظيفي.']);
                    exit;
                }
                $stmt = $pdo->prepare("INSERT INTO doctors (name, title, note) VALUES (?, ?, ?)");
                $stmt->execute([$dName, $dTitle, $dNote]);
                $doctor_id_edit = intval($pdo->lastInsertId());
            } else {
                $doctor_id_edit = intval($doctor_id_edit_raw ?: 0);
            }

            if ($leave_id <= 0 || empty($service_code) || empty($issue_date) || empty($start_date) || empty($end_date) || $days_count <= 0) {
                echo json_encode(['success' => false, 'message' => 'يرجى تعبئة جميع الحقول المطلوبة.']);
                exit;
            }

            if ($doctor_id_edit && $doctor_id_edit > 0) {
                $stmt = $pdo->prepare("UPDATE sick_leaves SET 
                    service_code = ?, issue_date = ?, start_date = ?, end_date = ?, days_count = ?,
                    is_companion = ?, companion_name = ?, companion_relation = ?,
                    is_paid = ?, payment_amount = ?, doctor_id = ?, updated_at = ?
                    WHERE id = ?");
                $stmt->execute([
                    $service_code, $issue_date, $start_date, $end_date, $days_count,
                    $is_companion, $companion_name, $companion_relation,
                    $is_paid, $payment_amount, $doctor_id_edit, nowSaudi(), $leave_id
                ]);
            } else {
                $stmt = $pdo->prepare("UPDATE sick_leaves SET 
                    service_code = ?, issue_date = ?, start_date = ?, end_date = ?, days_count = ?,
                    is_companion = ?, companion_name = ?, companion_relation = ?,
                    is_paid = ?, payment_amount = ?, updated_at = ?
                    WHERE id = ?");
                $stmt->execute([
                    $service_code, $issue_date, $start_date, $end_date, $days_count,
                    $is_companion, $companion_name, $companion_relation,
                    $is_paid, $payment_amount, nowSaudi(), $leave_id
                ]);
            }

            $data = fetchActiveOperationalData($pdo);
            $data['doctors'] = $pdo->query("SELECT * FROM doctors ORDER BY name")->fetchAll();
            $data['patients'] = $pdo->query("SELECT * FROM patients ORDER BY name")->fetchAll();
            $data['stats'] = getStats($pdo);
            $data['success'] = true;
            $data['message'] = 'تم تعديل الإجازة بنجاح.';
            echo json_encode($data);
            break;

        case 'duplicate_leave':
            // خاصية تكرار الإجازة
            $patient_id = intval($_POST['dup_patient_id'] ?? 0);
            $doctor_select = $_POST['dup_doctor_select'] ?? '';
            $doctor_id = null;

            if ($doctor_select === 'manual') {
                $dName = trim($_POST['dup_doctor_manual_name'] ?? '');
                $dTitle = trim($_POST['dup_doctor_manual_title'] ?? '');
                $dNote = trim($_POST['dup_doctor_manual_note'] ?? '');
                if (empty($dName) || empty($dTitle)) {
                    echo json_encode(['success' => false, 'message' => 'يرجى إدخال اسم الطبيب ومسمّاه الوظيفي.']);
                    exit;
                }
                $stmt = $pdo->prepare("INSERT INTO doctors (name, title, note) VALUES (?, ?, ?)");
                $stmt->execute([$dName, $dTitle, $dNote]);
                $doctor_id = $pdo->lastInsertId();
            } else {
                $doctor_id = intval($doctor_select);
            }

            $issue_date = $_POST['dup_issue_date'] ?? '';

            // توليد رمز الخدمة
            $service_code_manual = trim($_POST['dup_service_code_manual'] ?? '');
            $service_prefix = $_POST['dup_service_prefix'] ?? 'GSL';
            if (!empty($service_code_manual)) {
                $service_code = strtoupper($service_code_manual);
            } else {
                $service_code = generateServiceCode($pdo, $service_prefix, $issue_date);
            }

            $start_date = $_POST['dup_start_date'] ?? '';
            $end_date = $_POST['dup_end_date'] ?? '';
            $days_count = intval($_POST['dup_days_count'] ?? 0);
            $is_companion = isset($_POST['dup_is_companion']) ? 1 : 0;
            $companion_name = trim($_POST['dup_companion_name'] ?? '');
            $companion_relation = trim($_POST['dup_companion_relation'] ?? '');
            $is_paid = isset($_POST['dup_is_paid']) ? 1 : 0;
            $payment_amount = floatval($_POST['dup_payment_amount'] ?? 0);

            if (empty($issue_date) || empty($start_date) || empty($end_date) || $days_count <= 0 || $patient_id <= 0 || $doctor_id <= 0) {
                echo json_encode(['success' => false, 'message' => 'يرجى تعبئة جميع الحقول المطلوبة.']);
                exit;
            }

            $stmt = $pdo->prepare("INSERT INTO sick_leaves 
                (service_code, patient_id, doctor_id, issue_date, start_date, end_date, days_count, 
                 is_companion, companion_name, companion_relation, is_paid, payment_amount) 
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)");
            $stmt->execute([
                $service_code, $patient_id, $doctor_id, $issue_date, $start_date, $end_date, $days_count,
                $is_companion, $companion_name, $companion_relation, $is_paid, $payment_amount
            ]);

            if (!$is_paid && $payment_amount > 0) {
                $leaveId = $pdo->lastInsertId();
                $stmt = $pdo->prepare("INSERT INTO notifications (type, leave_id, message) VALUES ('payment', ?, ?)");
                $stmt->execute([$leaveId, "إجازة مكررة غير مدفوعة برمز $service_code بمبلغ $payment_amount"]);
            }

            $data = fetchActiveOperationalData($pdo);
            $data['doctors'] = $pdo->query("SELECT * FROM doctors ORDER BY name")->fetchAll();
            $data['patients'] = $pdo->query("SELECT * FROM patients ORDER BY name")->fetchAll();
            $data['stats'] = getStats($pdo);
            $data['success'] = true;
            $data['message'] = "تم تكرار الإجازة بنجاح. رمز الخدمة الجديد: $service_code";
            echo json_encode($data);
            break;

        case 'delete_leave':
            $leave_id = intval($_POST['leave_id'] ?? 0);
            $stmt = $pdo->prepare("UPDATE sick_leaves SET deleted_at = ? WHERE id = ? AND deleted_at IS NULL");
            $stmt->execute([nowSaudi(), $leave_id]);
            $data = fetchAllData($pdo);
            $data['stats'] = getStats($pdo);
            $data['success'] = true;
            $data['message'] = 'تمت أرشفة الإجازة بنجاح.';
            echo json_encode($data);
            break;

        case 'restore_leave':
            $leave_id = intval($_POST['leave_id'] ?? 0);
            $stmt = $pdo->prepare("UPDATE sick_leaves SET deleted_at = NULL WHERE id = ?");
            $stmt->execute([$leave_id]);
            $data = fetchAllData($pdo);
            $data['stats'] = getStats($pdo);
            $data['success'] = true;
            $data['message'] = 'تمت استعادة الإجازة بنجاح.';
            echo json_encode($data);
            break;

        case 'force_delete_leave':
            $leave_id = intval($_POST['leave_id'] ?? 0);
            $pdo->prepare("DELETE FROM leave_queries WHERE leave_id = ?")->execute([$leave_id]);
            $pdo->prepare("DELETE FROM notifications WHERE leave_id = ?")->execute([$leave_id]);
            $pdo->prepare("DELETE FROM sick_leaves WHERE id = ?")->execute([$leave_id]);
            $data = fetchAllData($pdo);
            $data['stats'] = getStats($pdo);
            $data['success'] = true;
            $data['message'] = 'تم حذف الإجازة نهائيًا.';
            echo json_encode($data);
            break;

        case 'force_delete_all_archived':
            $archived_ids = $pdo->query("SELECT id FROM sick_leaves WHERE deleted_at IS NOT NULL")->fetchAll(PDO::FETCH_COLUMN);
            if (!empty($archived_ids)) {
                $placeholders = implode(',', array_fill(0, count($archived_ids), '?'));
                $pdo->prepare("DELETE FROM leave_queries WHERE leave_id IN ($placeholders)")->execute($archived_ids);
                $pdo->prepare("DELETE FROM notifications WHERE leave_id IN ($placeholders)")->execute($archived_ids);
                $pdo->prepare("DELETE FROM sick_leaves WHERE id IN ($placeholders)")->execute($archived_ids);
            }
            $data = fetchAllData($pdo);
            $data['stats'] = getStats($pdo);
            $data['success'] = true;
            $data['message'] = 'تم حذف جميع الإجازات المؤرشفة نهائيًا.';
            echo json_encode($data);
            break;

        case 'mark_leave_paid':
            $leave_id = intval($_POST['leave_id'] ?? 0);
            $amount = floatval($_POST['amount'] ?? 0);
            $stmt = $pdo->prepare("UPDATE sick_leaves SET is_paid = 1, payment_amount = ? WHERE id = ?");
            $stmt->execute([$amount, $leave_id]);
            $pdo->prepare("DELETE FROM notifications WHERE leave_id = ? AND type = 'payment'")->execute([$leave_id]);
            $data = fetchActiveOperationalData($pdo);
            $data['doctors'] = $pdo->query("SELECT * FROM doctors ORDER BY name")->fetchAll();
            $data['patients'] = $pdo->query("SELECT * FROM patients ORDER BY name")->fetchAll();
            $data['stats'] = getStats($pdo);
            $data['success'] = true;
            $data['message'] = 'تم تأكيد الدفع بنجاح.';
            echo json_encode($data);
            break;

        case 'add_doctor':
            $name = trim($_POST['doctor_name'] ?? '');
            $title = trim($_POST['doctor_title'] ?? '');
            $note = trim($_POST['doctor_note'] ?? '');
            if (empty($name) || empty($title)) {
                echo json_encode(['success' => false, 'message' => 'يرجى إدخال اسم الطبيب ومسمّاه.']);
                exit;
            }
            $stmt = $pdo->prepare("INSERT INTO doctors (name, title, note) VALUES (?, ?, ?)");
            $stmt->execute([$name, $title, $note]);
            $doctorId = $pdo->lastInsertId();
            $doctor = $pdo->prepare("SELECT * FROM doctors WHERE id = ?")->execute([$doctorId]);
            $doctor = $pdo->prepare("SELECT * FROM doctors WHERE id = ?");
            $doctor->execute([$doctorId]);
            $doctorData = $doctor->fetch();
            $doctors = $pdo->query("SELECT * FROM doctors ORDER BY name")->fetchAll();
            echo json_encode([
                'success' => true,
                'message' => 'تمت إضافة الطبيب بنجاح.',
                'doctor' => $doctorData,
                'doctors' => $doctors,
                'stats' => getStats($pdo)
            ]);
            break;

        case 'edit_doctor':
            $id = intval($_POST['doctor_id'] ?? 0);
            $name = trim($_POST['doctor_name'] ?? '');
            $title = trim($_POST['doctor_title'] ?? '');
            $note = trim($_POST['doctor_note'] ?? '');
            if ($id <= 0 || empty($name) || empty($title)) {
                echo json_encode(['success' => false, 'message' => 'بيانات غير صالحة.']);
                exit;
            }
            $stmt = $pdo->prepare("UPDATE doctors SET name = ?, title = ?, note = ? WHERE id = ?");
            $stmt->execute([$name, $title, $note, $id]);
            $doctor = $pdo->prepare("SELECT * FROM doctors WHERE id = ?");
            $doctor->execute([$id]);
            $doctorData = $doctor->fetch();
            $doctors = $pdo->query("SELECT * FROM doctors ORDER BY name")->fetchAll();
            echo json_encode([
                'success' => true,
                'message' => 'تم تعديل الطبيب بنجاح.',
                'doctor' => $doctorData,
                'doctors' => $doctors,
                'stats' => getStats($pdo)
            ]);
            break;

        case 'delete_doctor':
            $id = intval($_POST['doctor_id'] ?? 0);
            $pdo->prepare("DELETE FROM doctors WHERE id = ?")->execute([$id]);
            $doctors = $pdo->query("SELECT * FROM doctors ORDER BY name")->fetchAll();
            echo json_encode([
                'success' => true,
                'message' => 'تم حذف الطبيب بنجاح.',
                'doctors' => $doctors,
                'stats' => getStats($pdo)
            ]);
            break;

        case 'add_patient':
            $name = trim($_POST['patient_name'] ?? '');
            $identity = trim($_POST['identity_number'] ?? '');
            $phone = trim($_POST['phone'] ?? '');
            if (empty($name) || empty($identity)) {
                echo json_encode(['success' => false, 'message' => 'يرجى إدخال اسم المريض ورقم هويته.']);
                exit;
            }
            $stmt = $pdo->prepare("INSERT INTO patients (name, identity_number, phone) VALUES (?, ?, ?)");
            $stmt->execute([$name, $identity, $phone]);
            $patientId = $pdo->lastInsertId();
            $patient = $pdo->prepare("SELECT * FROM patients WHERE id = ?");
            $patient->execute([$patientId]);
            $patientData = $patient->fetch();
            $patients = $pdo->query("SELECT * FROM patients ORDER BY name")->fetchAll();
            echo json_encode([
                'success' => true,
                'message' => 'تمت إضافة المريض بنجاح.',
                'patient' => $patientData,
                'patients' => $patients,
                'stats' => getStats($pdo)
            ]);
            break;

        case 'edit_patient':
            $id = intval($_POST['patient_id'] ?? 0);
            $name = trim($_POST['patient_name'] ?? '');
            $identity = trim($_POST['identity_number'] ?? '');
            $phone = trim($_POST['phone'] ?? '');
            if ($id <= 0 || empty($name) || empty($identity)) {
                echo json_encode(['success' => false, 'message' => 'بيانات غير صالحة.']);
                exit;
            }
            $stmt = $pdo->prepare("UPDATE patients SET name = ?, identity_number = ?, phone = ? WHERE id = ?");
            $stmt->execute([$name, $identity, $phone, $id]);
            $patient = $pdo->prepare("SELECT * FROM patients WHERE id = ?");
            $patient->execute([$id]);
            $patientData = $patient->fetch();
            $patients = $pdo->query("SELECT * FROM patients ORDER BY name")->fetchAll();
            echo json_encode([
                'success' => true,
                'message' => 'تم تعديل المريض بنجاح.',
                'patient' => $patientData,
                'patients' => $patients,
                'stats' => getStats($pdo)
            ]);
            break;

        case 'delete_patient':
            $id = intval($_POST['patient_id'] ?? 0);
            $pdo->prepare("DELETE FROM patients WHERE id = ?")->execute([$id]);
            $patients = $pdo->query("SELECT * FROM patients ORDER BY name")->fetchAll();
            echo json_encode([
                'success' => true,
                'message' => 'تم حذف المريض بنجاح.',
                'patients' => $patients,
                'stats' => getStats($pdo)
            ]);
            break;

        case 'fetch_queries':
            $leave_id = intval($_POST['leave_id'] ?? 0);
            $stmt = $pdo->prepare("SELECT * FROM leave_queries WHERE leave_id = ? ORDER BY queried_at DESC");
            $stmt->execute([$leave_id]);
            $queries = $stmt->fetchAll();
            echo json_encode(['success' => true, 'queries' => $queries]);
            break;

        case 'delete_query':
            $query_id = intval($_POST['query_id'] ?? 0);
            $pdo->prepare("DELETE FROM leave_queries WHERE id = ?")->execute([$query_id]);
            echo json_encode(['success' => true, 'message' => 'تم حذف سجل الاستعلام.']);
            break;

        case 'delete_all_queries_for_leave':
            $leave_id = intval($_POST['leave_id'] ?? 0);
            $pdo->prepare("DELETE FROM leave_queries WHERE leave_id = ?")->execute([$leave_id]);
            echo json_encode(['success' => true, 'message' => 'تم حذف جميع الاستعلامات لهذه الإجازة.']);
            break;

        case 'delete_all_queries':
            $pdo->exec("DELETE FROM leave_queries");
            $data = fetchAllData($pdo);
            $data['stats'] = getStats($pdo);
            $data['success'] = true;
            $data['message'] = 'تم حذف جميع سجلات الاستعلامات.';
            echo json_encode($data);
            break;

        case 'add_query':
            $leave_id = intval($_POST['leave_id'] ?? 0);
            $stmt = $pdo->prepare("INSERT INTO leave_queries (leave_id, queried_at, source) VALUES (?, ?, 'admin')");
            $stmt->execute([$leave_id, nowSaudi()]);
            $new_count = $pdo->prepare("SELECT COUNT(*) FROM leave_queries WHERE leave_id = ?");
            $new_count->execute([$leave_id]);
            echo json_encode(['success' => true, 'message' => 'تم تسجيل الاستعلام.', 'new_count' => $new_count->fetchColumn()]);
            break;

        case 'fetch_leave_details':
            $leave_id = intval($_POST['leave_id'] ?? 0);

            $statusStmt = $pdo->prepare("SELECT id, deleted_at FROM sick_leaves WHERE id = ? LIMIT 1");
            $statusStmt->execute([$leave_id]);
            $status = $statusStmt->fetch();

            if (!$status) {
                echo json_encode(['success' => false, 'message' => 'لم يتم العثور على الإجازة.']);
                break;
            }

            $source = $status['deleted_at'] ? 'archived_lookup' : 'admin_lookup';
            $pdo->prepare("INSERT INTO leave_queries (leave_id, queried_at, source) VALUES (?, ?, ?)")->execute([$leave_id, nowSaudi(), $source]);

            if ($status['deleted_at']) {
                echo json_encode(['success' => false, 'message' => 'لم يتم العثور على الإجازة.']);
                break;
            }

            $stmt = $pdo->prepare("
                SELECT sl.*, p.name AS patient_name, p.identity_number,
                       d.name AS doctor_name, d.title AS doctor_title, d.note AS doctor_note,
                       (SELECT COUNT(*) FROM leave_queries lq WHERE lq.leave_id = sl.id) AS queries_count
                FROM sick_leaves sl
                LEFT JOIN patients p ON sl.patient_id = p.id
                LEFT JOIN doctors d ON sl.doctor_id = d.id
                WHERE sl.id = ? AND sl.deleted_at IS NULL
            ");
            $stmt->execute([$leave_id]);
            $leave = $stmt->fetch();
            if ($leave) {
                echo json_encode(['success' => true, 'leave' => $leave]);
            } else {
                echo json_encode(['success' => false, 'message' => 'لم يتم العثور على الإجازة.']);
            }
            break;

        case 'fetch_notifications':
            ensureDelayedUnpaidNotifications($pdo);
            $notifications = $pdo->query(" 
                SELECT n.*, sl.payment_amount, sl.service_code, sl.patient_id, p.name AS patient_name
                FROM notifications n
                LEFT JOIN sick_leaves sl ON n.leave_id = sl.id
                LEFT JOIN patients p ON sl.patient_id = p.id
                WHERE n.type = 'payment'
                ORDER BY n.created_at DESC
            ")->fetchAll();
            echo json_encode(['success' => true, 'data' => $notifications]);
            break;

        case 'delete_notification':
            $id = intval($_POST['notification_id'] ?? 0);
            $pdo->prepare("DELETE FROM notifications WHERE id = ?")->execute([$id]);
            echo json_encode(['success' => true, 'message' => 'تم حذف الإشعار.']);
            break;

        case 'fetch_leaves_by_patient':
            $patient_id = intval($_POST['patient_id'] ?? 0);
            $stmt = $pdo->prepare("
                SELECT sl.*, d.name AS doctor_name, d.title AS doctor_title
                FROM sick_leaves sl
                LEFT JOIN doctors d ON sl.doctor_id = d.id
                WHERE sl.patient_id = ? AND sl.deleted_at IS NULL
                ORDER BY sl.created_at DESC
            ");
            $stmt->execute([$patient_id]);
            echo json_encode(['success' => true, 'leaves' => $stmt->fetchAll()]);
            break;

        case 'fetch_doctors':
            $doctors = $pdo->query("SELECT * FROM doctors ORDER BY name")->fetchAll();
            echo json_encode(['success' => true, 'doctors' => $doctors, 'stats' => getStats($pdo)]);
            break;

        case 'fetch_patients':
            $patients = $pdo->query("SELECT * FROM patients ORDER BY name")->fetchAll();
            echo json_encode(['success' => true, 'patients' => $patients, 'stats' => getStats($pdo)]);
            break;


        case 'fetch_chat_users':
            $currentUserId = intval($_SESSION['admin_user_id'] ?? 0);
            if ($_SESSION['admin_role'] === 'admin') {
                $stmt = $pdo->prepare("SELECT id, username, display_name, role FROM admin_users WHERE is_active = 1 AND id <> ? ORDER BY display_name");
                $stmt->execute([$currentUserId]);
            } else {
                $stmt = $pdo->prepare("SELECT id, username, display_name, role FROM admin_users WHERE is_active = 1 AND role = 'admin' ORDER BY display_name");
                $stmt->execute();
            }
            echo json_encode(['success' => true, 'users' => $stmt->fetchAll()]);
            break;

        case 'fetch_messages':
            $peerId = intval($_POST['peer_id'] ?? 0);
            $me = intval($_SESSION['admin_user_id'] ?? 0);
            if ($peerId <= 0 || $me <= 0) {
                echo json_encode(['success' => false, 'message' => 'مستخدم غير صالح.']);
                break;
            }
            $stmt = $pdo->prepare("
                SELECT um.*,
                       s.display_name AS sender_name,
                       r.display_name AS receiver_name
                FROM user_messages um
                LEFT JOIN admin_users s ON um.sender_id = s.id
                LEFT JOIN admin_users r ON um.receiver_id = r.id
                WHERE (um.sender_id = ? AND um.receiver_id = ?)
                   OR (um.sender_id = ? AND um.receiver_id = ?)
                ORDER BY um.created_at ASC, um.id ASC
                LIMIT 500
            ");
            $stmt->execute([$me, $peerId, $peerId, $me]);
            $messages = $stmt->fetchAll();
            $pdo->prepare("UPDATE user_messages SET is_read = 1 WHERE receiver_id = ? AND sender_id = ? AND is_read = 0")
                ->execute([$me, $peerId]);
            echo json_encode(['success' => true, 'messages' => $messages]);
            break;

        case 'send_message':
            $peerId = intval($_POST['peer_id'] ?? 0);
            $messageText = trim($_POST['message_text'] ?? '');
            $me = intval($_SESSION['admin_user_id'] ?? 0);
            if ($peerId <= 0 || $me <= 0 || $messageText === '') {
                echo json_encode(['success' => false, 'message' => 'بيانات الرسالة غير مكتملة.']);
                break;
            }
            $check = $pdo->prepare("SELECT id FROM admin_users WHERE id = ? AND is_active = 1");
            $check->execute([$peerId]);
            if (!$check->fetch()) {
                echo json_encode(['success' => false, 'message' => 'المستخدم غير موجود أو غير مفعل.']);
                break;
            }
            $ins = $pdo->prepare("INSERT INTO user_messages (sender_id, receiver_id, message_text, created_at) VALUES (?, ?, ?, ?)");
            $ins->execute([$me, $peerId, $messageText, nowSaudi()]);
            echo json_encode(['success' => true, 'message' => 'تم إرسال الرسالة.']);
            break;

        // ======================== إدارة المستخدمين ========================
        case 'add_user':
            if ($_SESSION['admin_role'] !== 'admin') {
                echo json_encode(['success' => false, 'message' => 'ليس لديك صلاحية لإضافة مستخدمين.']);
                exit;
            }
            $username = trim($_POST['new_username'] ?? '');
            $password = $_POST['new_password'] ?? '';
            $display_name = trim($_POST['new_display_name'] ?? '');
            $role = $_POST['new_role'] ?? 'user';
            
            if (empty($username) || empty($password) || empty($display_name)) {
                echo json_encode(['success' => false, 'message' => 'يرجى تعبئة جميع الحقول المطلوبة.']);
                exit;
            }
            
            $check = $pdo->prepare("SELECT id FROM admin_users WHERE username = ?");
            $check->execute([$username]);
            if ($check->fetch()) {
                echo json_encode(['success' => false, 'message' => 'اسم المستخدم موجود مسبقاً.']);
                exit;
            }
            
            $hash = password_hash($password, PASSWORD_DEFAULT);
            $stmt = $pdo->prepare("INSERT INTO admin_users (username, password_hash, display_name, role) VALUES (?, ?, ?, ?)");
            $stmt->execute([$username, $hash, $display_name, $role]);
            
            $users = $pdo->query("SELECT id, username, display_name, role, is_active, created_at FROM admin_users ORDER BY created_at DESC")->fetchAll();
            echo json_encode(['success' => true, 'message' => 'تمت إضافة المستخدم بنجاح.', 'users' => $users]);
            break;

        case 'edit_user':
            if ($_SESSION['admin_role'] !== 'admin') {
                echo json_encode(['success' => false, 'message' => 'ليس لديك صلاحية لتعديل المستخدمين.']);
                exit;
            }
            $user_id = intval($_POST['edit_user_id'] ?? 0);
            $display_name = trim($_POST['edit_display_name'] ?? '');
            $role = $_POST['edit_role'] ?? 'user';
            $new_password = $_POST['edit_password'] ?? '';
            $is_active = isset($_POST['edit_is_active']) ? 1 : 0;
            
            if ($user_id <= 0 || empty($display_name)) {
                echo json_encode(['success' => false, 'message' => 'بيانات غير صالحة.']);
                exit;
            }
            
            if (!empty($new_password)) {
                $hash = password_hash($new_password, PASSWORD_DEFAULT);
                $stmt = $pdo->prepare("UPDATE admin_users SET display_name = ?, role = ?, password_hash = ?, is_active = ? WHERE id = ?");
                $stmt->execute([$display_name, $role, $hash, $is_active, $user_id]);
            } else {
                $stmt = $pdo->prepare("UPDATE admin_users SET display_name = ?, role = ?, is_active = ? WHERE id = ?");
                $stmt->execute([$display_name, $role, $is_active, $user_id]);
            }
            
            $users = $pdo->query("SELECT id, username, display_name, role, is_active, created_at FROM admin_users ORDER BY created_at DESC")->fetchAll();
            echo json_encode(['success' => true, 'message' => 'تم تعديل المستخدم بنجاح.', 'users' => $users]);
            break;

        case 'delete_user':
            if ($_SESSION['admin_role'] !== 'admin') {
                echo json_encode(['success' => false, 'message' => 'ليس لديك صلاحية لحذف المستخدمين.']);
                exit;
            }
            $user_id = intval($_POST['user_id'] ?? 0);
            if ($user_id == $_SESSION['admin_user_id']) {
                echo json_encode(['success' => false, 'message' => 'لا يمكنك حذف حسابك الخاص.']);
                exit;
            }
            $pdo->prepare("DELETE FROM user_sessions WHERE user_id = ?")->execute([$user_id]);
            $pdo->prepare("DELETE FROM admin_users WHERE id = ?")->execute([$user_id]);
            $users = $pdo->query("SELECT id, username, display_name, role, is_active, created_at FROM admin_users ORDER BY created_at DESC")->fetchAll();
            echo json_encode(['success' => true, 'message' => 'تم حذف المستخدم بنجاح.', 'users' => $users]);
            break;

        case 'fetch_users':
            if ($_SESSION['admin_role'] !== 'admin') {
                echo json_encode(['success' => false, 'message' => 'ليس لديك صلاحية.']);
                exit;
            }
            $users = $pdo->query("SELECT id, username, display_name, role, is_active, created_at FROM admin_users ORDER BY created_at DESC")->fetchAll();
            echo json_encode(['success' => true, 'users' => $users]);
            break;

        case 'fetch_user_sessions':
            if ($_SESSION['admin_role'] !== 'admin') {
                echo json_encode(['success' => false, 'message' => 'ليس لديك صلاحية.']);
                exit;
            }
            $user_id = intval($_POST['user_id'] ?? 0);
            $stmt = $pdo->prepare("
                SELECT us.*, au.username, au.display_name 
                FROM user_sessions us 
                LEFT JOIN admin_users au ON us.user_id = au.id 
                WHERE us.user_id = ? 
                ORDER BY us.login_at DESC 
                LIMIT 50
            ");
            $stmt->execute([$user_id]);
            echo json_encode(['success' => true, 'sessions' => $stmt->fetchAll()]);
            break;

        case 'delete_user_session':
            if ($_SESSION['admin_role'] !== 'admin') {
                echo json_encode(['success' => false, 'message' => 'ليس لديك صلاحية.']);
                exit;
            }
            $session_id = intval($_POST['session_id'] ?? 0);
            $pdo->prepare("DELETE FROM user_sessions WHERE id = ?")->execute([$session_id]);
            echo json_encode(['success' => true, 'message' => 'تم حذف الجلسة.']);
            break;

        case 'delete_all_user_sessions':
            if ($_SESSION['admin_role'] !== 'admin') {
                echo json_encode(['success' => false, 'message' => 'ليس لديك صلاحية.']);
                exit;
            }
            $user_id = intval($_POST['user_id'] ?? 0);
            $pdo->prepare("DELETE FROM user_sessions WHERE user_id = ?")->execute([$user_id]);
            echo json_encode(['success' => true, 'message' => 'تم حذف جميع جلسات المستخدم.']);
            break;

        case 'mark_all_leaves_paid':
            if ($_SESSION['admin_role'] !== 'admin') {
                echo json_encode(['success' => false, 'message' => 'ليس لديك صلاحية.']);
                exit;
            }
            $pdo->exec("UPDATE sick_leaves SET is_paid = 1 WHERE deleted_at IS NULL");
            $pdo->exec("DELETE FROM notifications WHERE type = 'payment'");
            $data = fetchAllData($pdo);
            $data['stats'] = getStats($pdo);
            $data['success'] = true;
            $data['message'] = 'تم تحويل جميع الإجازات النشطة إلى مدفوعة.';
            echo json_encode($data);
            break;

        case 'reset_all_payments':
            if ($_SESSION['admin_role'] !== 'admin') {
                echo json_encode(['success' => false, 'message' => 'ليس لديك صلاحية.']);
                exit;
            }
            $pdo->exec("UPDATE sick_leaves SET payment_amount = 0 WHERE deleted_at IS NULL");
            $pdo->exec("DELETE FROM notifications WHERE type = 'payment'");
            $data = fetchAllData($pdo);
            $data['stats'] = getStats($pdo);
            $data['success'] = true;
            $data['message'] = 'تم تصفير المدفوعات والمستحقات.';
            echo json_encode($data);
            break;

        default:
            echo json_encode(['success' => false, 'message' => 'إجراء غير معروف: ' . $action]);
            break;
    }
    exit;
}

// ======================== جلب البيانات للعرض الأولي ========================
$loggedIn = is_logged_in();

if ($loggedIn) {
    $doctors = $pdo->query("SELECT * FROM doctors ORDER BY name")->fetchAll();
    $patients = $pdo->query("SELECT * FROM patients ORDER BY name")->fetchAll();
    
    $data = fetchAllData($pdo);
    $leaves = $data['leaves'];
    $archived = $data['archived'];
    $queries = $data['queries'];
    $notifications_payment = $data['notifications_payment'];
    $payments = $data['payments'];
    $stats = getStats($pdo);
    
    $users = [];
    $chat_users_stmt = ($_SESSION['admin_role'] === 'admin')
        ? $pdo->prepare("SELECT id, username, display_name, role FROM admin_users WHERE is_active = 1 AND id <> ? ORDER BY display_name")
        : $pdo->prepare("SELECT id, username, display_name, role FROM admin_users WHERE is_active = 1 AND role = 'admin' ORDER BY display_name");
    if ($_SESSION['admin_role'] === 'admin') { $chat_users_stmt->execute([intval($_SESSION['admin_user_id'])]); } else { $chat_users_stmt->execute(); }
    $chat_users = $chat_users_stmt->fetchAll();
    if ($_SESSION['admin_role'] === 'admin') {
        $users = $pdo->query("SELECT id, username, display_name, role, is_active, created_at FROM admin_users ORDER BY created_at DESC")->fetchAll();
    }
} else {
    $doctors = $patients = $leaves = $archived = $queries = $notifications_payment = $payments = $users = $chat_users = [];
    $stats = ['total' => 0, 'active' => 0, 'archived' => 0, 'patients' => 0, 'doctors' => 0, 'paid' => 0, 'unpaid' => 0, 'paid_amount' => 0, 'unpaid_amount' => 0];
}
?>
<!DOCTYPE html>
<html lang="ar" dir="rtl">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>لوحة تحكم الإجازات المرضية</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.rtl.min.css" rel="stylesheet">
    <link href="https://cdn.jsdelivr.net/npm/bootstrap-icons@1.11.0/font/bootstrap-icons.css" rel="stylesheet">
    <link href="https://fonts.googleapis.com/css2?family=Cairo:wght@300;400;500;600;700;800&display=swap" rel="stylesheet">
    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js"></script>
    <script src="https://cdnjs.cloudflare.com/ajax/libs/jspdf/2.5.1/jspdf.umd.min.js"></script>
    <script src="https://cdnjs.cloudflare.com/ajax/libs/jspdf-autotable/3.5.25/jspdf.plugin.autotable.min.js"></script>

    <style>
        :root {
            --primary-color: #1a73e8;
            --primary-light: #4a9af5;
            --primary-dark: #0d47a1;
            --secondary-color: #2c3e50;
            --success-color: #00c853;
            --success-dark: #009624;
            --danger-color: #ff1744;
            --danger-dark: #d50000;
            --warning-color: #ff9100;
            --warning-dark: #e65100;
            --info-color: #00b0ff;
            --bg-color: #f0f2f5;
            --card-bg: #ffffff;
            --text-color: #1a1a2e;
            --text-muted: #6c757d;
            --border-color: #e0e0e0;
            --border-radius: 12px;
            --shadow: 0 2px 12px rgba(0,0,0,0.08);
            --shadow-hover: 0 8px 25px rgba(0,0,0,0.15);
            --transition: all 0.3s cubic-bezier(0.4, 0, 0.2, 1);
            --gradient-primary: linear-gradient(135deg, #1a73e8, #4a9af5);
            --gradient-success: linear-gradient(135deg, #00c853, #69f0ae);
            --gradient-danger: linear-gradient(135deg, #ff1744, #ff616f);
            --gradient-warning: linear-gradient(135deg, #ff9100, #ffc246);
            --gradient-dark: linear-gradient(135deg, #2c3e50, #34495e);
        }

        .dark-mode {
            --bg-color: #0f1923;
            --card-bg: #1a2332;
            --text-color: #e0e0e0;
            --text-muted: #9e9e9e;
            --border-color: #2d3748;
            --shadow: 0 2px 12px rgba(0,0,0,0.3);
            --shadow-hover: 0 8px 25px rgba(0,0,0,0.4);
        }

        * { box-sizing: border-box; margin: 0; padding: 0; }

        body {
            font-family: 'Cairo', sans-serif;
            background: var(--bg-color);
            color: var(--text-color);
            direction: rtl;
            min-height: 100vh;
            transition: var(--transition);
            font-size: 14px;
            line-height: 1.6;
        }

        /* ======================== صفحة تسجيل الدخول ======================== */
        .login-wrapper {
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
            background: linear-gradient(135deg, #0d1b2a 0%, #1b2838 50%, #1a73e8 100%);
            padding: 20px;
        }

        .login-card {
            background: rgba(255,255,255,0.95);
            backdrop-filter: blur(20px);
            border-radius: 20px;
            padding: 40px;
            width: 100%;
            max-width: 420px;
            box-shadow: 0 20px 60px rgba(0,0,0,0.3);
            animation: slideUp 0.6s ease;
        }

        .dark-mode .login-card {
            background: rgba(26,35,50,0.95);
        }

        .login-card h2 {
            text-align: center;
            margin-bottom: 8px;
            font-weight: 700;
            color: var(--primary-color);
            font-size: 24px;
        }

        .login-card .subtitle {
            text-align: center;
            color: var(--text-muted);
            margin-bottom: 30px;
            font-size: 14px;
        }

        .login-card .login-icon {
            text-align: center;
            font-size: 48px;
            color: var(--primary-color);
            margin-bottom: 16px;
        }

        @keyframes slideUp {
            from { opacity: 0; transform: translateY(30px); }
            to { opacity: 1; transform: translateY(0); }
        }

        /* ======================== شريط التنقل ======================== */
        .top-navbar {
            background: var(--gradient-dark);
            padding: 12px 24px;
            display: flex;
            align-items: center;
            justify-content: space-between;
            flex-wrap: wrap;
            gap: 12px;
            box-shadow: 0 4px 20px rgba(0,0,0,0.15);
            position: sticky;
            top: 0;
            z-index: 1040;
        }

        .top-navbar .brand {
            display: flex;
            align-items: center;
            gap: 10px;
            color: #fff;
            font-weight: 700;
            font-size: 18px;
        }

        .top-navbar .brand i {
            font-size: 24px;
            color: var(--primary-light);
        }

        .top-navbar .nav-actions {
            display: flex;
            align-items: center;
            gap: 8px;
            flex-wrap: wrap;
        }

        .top-navbar .user-info {
            color: rgba(255,255,255,0.8);
            font-size: 13px;
            display: flex;
            align-items: center;
            gap: 6px;
        }

        .top-navbar .user-info i { color: var(--primary-light); }

        /* ======================== الأزرار ======================== */
        .btn {
            border-radius: 8px;
            font-weight: 500;
            font-size: 13px;
            padding: 6px 14px;
            transition: var(--transition);
            border: none;
            display: inline-flex;
            align-items: center;
            gap: 5px;
        }

        .btn:hover { transform: translateY(-1px); box-shadow: var(--shadow); }
        .btn:active { transform: translateY(0); }

        .btn-gradient {
            background: var(--gradient-primary);
            color: #fff;
            border: none;
        }
        .btn-gradient:hover { background: var(--primary-dark); color: #fff; box-shadow: 0 4px 15px rgba(26,115,232,0.4); }

        .btn-success-custom {
            background: var(--gradient-success);
            color: #fff;
            border: none;
        }
        .btn-success-custom:hover { background: var(--success-dark); color: #fff; }

        .btn-danger-custom {
            background: var(--gradient-danger);
            color: #fff;
            border: none;
        }
        .btn-danger-custom:hover { background: var(--danger-dark); color: #fff; }

        .btn-warning-custom {
            background: var(--gradient-warning);
            color: #fff;
            border: none;
        }
        .btn-warning-custom:hover { background: var(--warning-dark); color: #fff; }

        .btn-outline-light { border: 1px solid rgba(255,255,255,0.3); color: #fff; }
        .btn-outline-light:hover { background: rgba(255,255,255,0.1); color: #fff; }

        #darkModeToggle {
            position: fixed;
            bottom: 20px;
            left: 20px;
            z-index: 1050;
            background: var(--gradient-dark);
            color: #fff;
            border-radius: 50px;
            padding: 10px 18px;
            box-shadow: 0 4px 15px rgba(0,0,0,0.3);
            font-size: 13px;
        }
        .dark-mode #darkModeToggle {
            background: var(--gradient-primary);
        }

        /* ======================== البطاقات الإحصائية ======================== */
        .stats-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(160px, 1fr));
            gap: 12px;
            margin-bottom: 20px;
        }

        .stat-card {
            background: var(--card-bg);
            border-radius: var(--border-radius);
            padding: 16px;
            text-align: center;
            box-shadow: var(--shadow);
            transition: var(--transition);
            border: 1px solid var(--border-color);
            position: relative;
            overflow: hidden;
        }

        .stat-card::before {
            content: '';
            position: absolute;
            top: 0;
            right: 0;
            left: 0;
            height: 4px;
        }

        .stat-card:nth-child(1)::before { background: var(--gradient-primary); }
        .stat-card:nth-child(2)::before { background: var(--gradient-success); }
        .stat-card:nth-child(3)::before { background: var(--gradient-danger); }
        .stat-card:nth-child(4)::before { background: var(--gradient-warning); }
        .stat-card:nth-child(5)::before { background: var(--info-color); }
        .stat-card:nth-child(6)::before { background: var(--gradient-success); }
        .stat-card:nth-child(7)::before { background: var(--gradient-danger); }
        .stat-card:nth-child(8)::before { background: var(--gradient-success); }
        .stat-card:nth-child(9)::before { background: var(--gradient-danger); }

        .stat-card:hover {
            transform: translateY(-3px);
            box-shadow: var(--shadow-hover);
        }

        .stat-card .stat-icon {
            font-size: 28px;
            margin-bottom: 6px;
            opacity: 0.7;
        }

        .stat-card .stat-value {
            font-size: 22px;
            font-weight: 700;
            color: var(--text-color);
            line-height: 1.2;
        }

        .stat-card .stat-label {
            font-size: 12px;
            color: var(--text-muted);
            font-weight: 500;
        }

        /* ======================== البطاقات ======================== */
        .card-custom {
            background: var(--card-bg);
            border-radius: var(--border-radius);
            box-shadow: var(--shadow);
            border: 1px solid var(--border-color);
            overflow: hidden;
            transition: var(--transition);
            margin-bottom: 20px;
        }

        .card-custom:hover { box-shadow: var(--shadow-hover); }

        .card-custom .card-header {
            padding: 14px 20px;
            font-weight: 600;
            font-size: 15px;
            border-bottom: 1px solid var(--border-color);
        }

        .card-custom .card-body { padding: 20px; }

        /* ======================== الجداول ======================== */
        .table {
            font-size: 13px;
            margin-bottom: 0;
        }

        .table thead th {
            background: var(--secondary-color);
            color: #fff;
            font-weight: 600;
            font-size: 12px;
            padding: 10px 8px;
            white-space: nowrap;
            border: none;
            position: sticky;
            top: 0;
            z-index: 10;
        }

        .table tbody td {
            padding: 8px;
            vertical-align: middle;
            border-color: var(--border-color);
            color: var(--text-color);
        }

        .table-hover tbody tr:hover {
            background-color: rgba(26, 115, 232, 0.06);
        }

        .table-striped tbody tr:nth-of-type(odd) {
            background-color: rgba(0,0,0,0.02);
        }

        .dark-mode .table-striped tbody tr:nth-of-type(odd) {
            background-color: rgba(255,255,255,0.03);
        }

        .dark-mode .table-hover tbody tr:hover {
            background-color: rgba(26, 115, 232, 0.1);
        }

        /* ======================== النماذج ======================== */
        .form-control, .form-select {
            border-radius: 8px;
            border: 1.5px solid var(--border-color);
            padding: 8px 12px;
            font-size: 13px;
            transition: var(--transition);
            background: var(--card-bg);
            color: var(--text-color);
        }

        .form-control:focus, .form-select:focus {
            border-color: var(--primary-color);
            box-shadow: 0 0 0 3px rgba(26,115,232,0.15);
        }

        label {
            font-weight: 500;
            font-size: 13px;
            margin-bottom: 4px;
            color: var(--text-color);
        }

        .hidden-field { display: none !important; }

        /* ======================== المودال ======================== */
        .modal-content {
            border-radius: 16px;
            border: none;
            box-shadow: 0 20px 60px rgba(0,0,0,0.2);
            background: var(--card-bg);
            color: var(--text-color);
        }

        .modal-header {
            border-bottom: 1px solid var(--border-color);
            padding: 16px 20px;
        }

        .modal-title {
            font-weight: 700;
            font-size: 16px;
        }

        .modal-body { padding: 20px; }
        .modal-footer { border-top: 1px solid var(--border-color); padding: 12px 20px; }

        .modal.modal-stack-active {
            z-index: var(--stack-z, 1060);
        }

        .modal-backdrop.modal-stack-active {
            z-index: var(--stack-backdrop-z, 1055);
        }

        .notif-patient-name {
            font-size: 12px;
            color: var(--primary-color);
            font-weight: 600;
        }

        /* ======================== التنبيهات ======================== */
        #alert-container {
            position: fixed;
            top: 80px;
            left: 50%;
            transform: translateX(-50%);
            z-index: 9999;
            width: 90%;
            max-width: 500px;
        }

        .custom-alert {
            padding: 12px 20px;
            border-radius: 10px;
            margin-bottom: 8px;
            font-weight: 500;
            font-size: 14px;
            display: flex;
            align-items: center;
            gap: 10px;
            animation: slideDown 0.3s ease;
            box-shadow: 0 4px 15px rgba(0,0,0,0.15);
        }

        .custom-alert.alert-success { background: #d4edda; color: #155724; border-right: 4px solid var(--success-color); }
        .custom-alert.alert-danger { background: #f8d7da; color: #721c24; border-right: 4px solid var(--danger-color); }
        .custom-alert.alert-warning { background: #fff3cd; color: #856404; border-right: 4px solid var(--warning-color); }
        .custom-alert.alert-info { background: #d1ecf1; color: #0c5460; border-right: 4px solid var(--info-color); }

        .dark-mode .custom-alert.alert-success { background: rgba(0,200,83,0.15); color: #69f0ae; }
        .dark-mode .custom-alert.alert-danger { background: rgba(255,23,68,0.15); color: #ff616f; }
        .dark-mode .custom-alert.alert-warning { background: rgba(255,145,0,0.15); color: #ffc246; }
        .dark-mode .custom-alert.alert-info { background: rgba(0,176,255,0.15); color: #40c4ff; }

        @keyframes slideDown {
            from { opacity: 0; transform: translateY(-20px); }
            to { opacity: 1; transform: translateY(0); }
        }

        /* ======================== التحميل ======================== */
        .loading-overlay {
            position: fixed;
            top: 0; left: 0; right: 0; bottom: 0;
            background: rgba(0,0,0,0.5);
            backdrop-filter: blur(4px);
            display: none;
            align-items: center;
            justify-content: center;
            z-index: 99999;
        }

        .loading-overlay.active { display: flex; }

        .spinner-custom {
            width: 50px;
            height: 50px;
            border: 4px solid rgba(255,255,255,0.3);
            border-top: 4px solid #fff;
            border-radius: 50%;
            animation: spin 0.8s linear infinite;
        }

        @keyframes spin { to { transform: rotate(360deg); } }

        /* ======================== الشارات ======================== */
        .badge {
            font-size: 11px;
            padding: 4px 8px;
            border-radius: 6px;
            font-weight: 600;
        }

        /* ======================== أزرار الإجراءات ======================== */
        .action-btn {
            font-size: 11px;
            padding: 4px 8px;
            border-radius: 6px;
            margin: 1px;
            white-space: nowrap;
        }

        /* ======================== شريط الأدوات ======================== */
        .toolbar {
            display: flex;
            gap: 8px;
            flex-wrap: wrap;
            align-items: center;
            margin-bottom: 16px;
        }

        /* ======================== قسم الإضافة ======================== */
        .add-section {
            background: var(--card-bg);
            border-radius: var(--border-radius);
            padding: 20px;
            box-shadow: var(--shadow);
            border: 1px solid var(--border-color);
            margin-bottom: 20px;
        }

        .add-section h5 {
            font-weight: 700;
            color: var(--primary-color);
            margin-bottom: 16px;
            display: flex;
            align-items: center;
            gap: 8px;
        }

        .add-section h5 i { font-size: 20px; }

        /* ======================== الاستجابة ======================== */
        @media (max-width: 768px) {
            .stats-grid { grid-template-columns: repeat(2, 1fr); }
            .top-navbar { padding: 10px 16px; }
            .top-navbar .brand { font-size: 15px; }
            .toolbar { justify-content: center; }
            .table { font-size: 11px; }
            .action-btn { font-size: 10px; padding: 3px 6px; }
            #darkModeToggle { bottom: 10px; left: 10px; padding: 8px 14px; font-size: 12px; }
        }

        @media (max-width: 480px) {
            .stats-grid { grid-template-columns: repeat(2, 1fr); gap: 8px; }
            .stat-card { padding: 12px 8px; }
            .stat-card .stat-value { font-size: 18px; }
        }

        /* ======================== تمرير سلس ======================== */
        ::-webkit-scrollbar { width: 8px; height: 8px; }
        ::-webkit-scrollbar-track { background: var(--bg-color); }
        ::-webkit-scrollbar-thumb { background: var(--text-muted); border-radius: 4px; }
        ::-webkit-scrollbar-thumb:hover { background: var(--primary-color); }

        /* ======================== رسوم متحركة ======================== */
        .fade-in { animation: fadeIn 0.4s ease; }
        @keyframes fadeIn { from { opacity: 0; } to { opacity: 1; } }

        .no-results td { color: var(--text-muted); font-style: italic; }

        /* ======================== قسم إدارة المستخدمين ======================== */
        .users-section .user-card {
            background: var(--card-bg);
            border: 1px solid var(--border-color);
            border-radius: 10px;
            padding: 12px;
            margin-bottom: 8px;
            display: flex;
            align-items: center;
            justify-content: space-between;
            transition: var(--transition);
        }

        .users-section .user-card:hover {
            box-shadow: var(--shadow);
        }

        .users-section .user-avatar {
            width: 40px;
            height: 40px;
            border-radius: 50%;
            background: var(--gradient-primary);
            color: #fff;
            display: flex;
            align-items: center;
            justify-content: center;
            font-weight: 700;
            font-size: 16px;
        }

        /* ======================== تحسينات إضافية ======================== */
        .section-title {
            font-weight: 700;
            font-size: 16px;
            color: var(--text-color);
            margin-bottom: 12px;
            display: flex;
            align-items: center;
            gap: 8px;
        }

        .section-title i { color: var(--primary-color); }

        .form-text { font-size: 11px; color: var(--text-muted); }

        .input-group .btn { border-radius: 0 8px 8px 0; }
        .input-group .form-control { border-radius: 8px 0 0 8px; }

        .form-check-label { font-size: 13px; }

        /* تحسين عرض الجداول في الشاشات الصغيرة */
        .table-responsive {
            border-radius: 8px;
            overflow: auto;
        }

        /* تأثير النبض للإشعارات */
        .pulse-badge {
            animation: pulse 2s infinite;
        }

        @keyframes pulse {
            0% { box-shadow: 0 0 0 0 rgba(255,23,68,0.4); }
            70% { box-shadow: 0 0 0 10px rgba(255,23,68,0); }
            100% { box-shadow: 0 0 0 0 rgba(255,23,68,0); }
        }
    </style>
</head>
<body>

<!-- ======================== التحميل ======================== -->
<div class="loading-overlay" id="loadingOverlay">
    <div class="spinner-custom"></div>
</div>

<!-- ======================== التنبيهات ======================== -->
<div id="alert-container"></div>

<?php if (!$loggedIn): ?>
<!-- ======================== صفحة تسجيل الدخول ======================== -->
<div class="login-wrapper" id="loginPage">
    <div class="login-card">
        <div class="login-icon"><i class="bi bi-shield-lock-fill"></i></div>
        <h2>لوحة التحكم</h2>
        <p class="subtitle">الإجازات المرضية - تسجيل الدخول</p>
        <form id="loginForm" method="post" action="" autocomplete="off">
            <div class="mb-3">
                <label for="loginUsername" class="form-label"><i class="bi bi-person"></i> اسم المستخدم</label>
                <input type="text" class="form-control" id="loginUsername" name="username" required autocomplete="username">
            </div>
            <div class="mb-3">
                <label for="loginPassword" class="form-label"><i class="bi bi-lock"></i> كلمة المرور</label>
                <div class="input-group">
                    <input type="password" class="form-control" id="loginPassword" name="password" required autocomplete="current-password">
                    <button type="button" class="btn btn-outline-secondary" id="togglePassword" style="border-radius: 0 8px 8px 0;">
                        <i class="bi bi-eye"></i>
                    </button>
                </div>
            </div>
            <button type="submit" class="btn btn-gradient w-100 py-2 mt-2" style="font-size:15px;">
                <i class="bi bi-box-arrow-in-left"></i> تسجيل الدخول
            </button>
        </form>
        <div class="text-center mt-3">
            <small class="text-muted">المستخدم الافتراضي: admin / admin123</small>
        </div>
    </div>
</div>
<?php else: ?>
<!-- ======================== لوحة التحكم الرئيسية ======================== -->

<!-- شريط التنقل -->
<nav class="top-navbar">
    <div class="brand">
        <i class="bi bi-hospital"></i>
        <span>لوحة تحكم الإجازات المرضية</span>
    </div>
    <div class="nav-actions">
        <div class="user-info">
            <i class="bi bi-person-circle"></i>
            <span><?php echo htmlspecialchars($_SESSION['admin_display_name']); ?></span>
            <span class="badge bg-info"><?php echo $_SESSION['admin_role'] === 'admin' ? 'مشرف' : 'مستخدم'; ?></span>
        </div>
        <button class="btn btn-outline-light btn-sm" id="btn-payment-notifs" title="إشعارات المدفوعات">
            <i class="bi bi-bell"></i>
            <span class="badge bg-danger pulse-badge" id="notifCount">0</span>
        </button>
        <?php if ($_SESSION['admin_role'] === 'admin'): ?>
        <button class="btn btn-outline-light btn-sm" data-bs-toggle="modal" data-bs-target="#addUserModal" id="btnAddUser" title="إدارة المستخدمين">
            <i class="bi bi-people"></i>
        </button>
        <?php endif; ?>
        <button class="btn btn-outline-light btn-sm" id="refreshAll" title="تحديث البيانات">
            <i class="bi bi-arrow-clockwise"></i>
        </button>
        <?php if ($_SESSION['admin_role'] === 'admin'): ?>
        <button class="btn btn-success btn-sm" id="markAllPaidBtn" title="جعل كل الإجازات مدفوعة"><i class="bi bi-check2-all"></i></button>
        <button class="btn btn-warning btn-sm" id="resetAllPaymentsBtn" title="تصفير المدفوعات والمستحقات"><i class="bi bi-eraser"></i></button>
        <?php endif; ?>
        <button class="btn btn-danger-custom btn-sm" id="logoutBtn" title="تسجيل الخروج">
            <i class="bi bi-box-arrow-right"></i> خروج
        </button>
    </div>
</nav>

<div class="container-fluid p-3">
    <!-- ======================== البطاقات الإحصائية ======================== -->
    <div class="stats-grid" id="statsGrid">
        <div class="stat-card">
            <div class="stat-icon"><i class="bi bi-file-earmark-medical"></i></div>
            <div class="stat-value" id="stat-total"><?php echo $stats['total']; ?></div>
            <div class="stat-label">إجمالي الإجازات</div>
        </div>
        <div class="stat-card">
            <div class="stat-icon"><i class="bi bi-check-circle"></i></div>
            <div class="stat-value" id="stat-paid"><?php echo $stats['paid']; ?></div>
            <div class="stat-label">مدفوعة</div>
        </div>
        <div class="stat-card">
            <div class="stat-icon"><i class="bi bi-x-circle"></i></div>
            <div class="stat-value" id="stat-unpaid"><?php echo $stats['unpaid']; ?></div>
            <div class="stat-label">غير مدفوعة</div>
        </div>
        <div class="stat-card">
            <div class="stat-icon"><i class="bi bi-archive"></i></div>
            <div class="stat-value" id="stat-archived"><?php echo $stats['archived']; ?></div>
            <div class="stat-label">مؤرشفة</div>
        </div>
        <div class="stat-card">
            <div class="stat-icon"><i class="bi bi-people"></i></div>
            <div class="stat-value" id="stat-patients"><?php echo $stats['patients']; ?></div>
            <div class="stat-label">المرضى</div>
        </div>
        <div class="stat-card">
            <div class="stat-icon"><i class="bi bi-person-badge"></i></div>
            <div class="stat-value" id="stat-doctors"><?php echo $stats['doctors']; ?></div>
            <div class="stat-label">الأطباء</div>
        </div>
        <div class="stat-card">
            <div class="stat-icon"><i class="bi bi-cash-stack"></i></div>
            <div class="stat-value" id="stat-paid-amount"><?php echo number_format($stats['paid_amount'], 2); ?></div>
            <div class="stat-label">المبالغ المدفوعة</div>
        </div>
        <div class="stat-card">
            <div class="stat-icon"><i class="bi bi-cash"></i></div>
            <div class="stat-value" id="stat-unpaid-amount"><?php echo number_format($stats['unpaid_amount'], 2); ?></div>
            <div class="stat-label">المبالغ المستحقة</div>
        </div>
    </div>

    <!-- ======================== التبويبات ======================== -->
    <ul class="nav nav-tabs mb-3" id="mainTabs" role="tablist">
        <li class="nav-item" role="presentation">
            <button class="nav-link active" id="tab-leaves" data-bs-toggle="tab" data-bs-target="#pane-leaves" type="button" role="tab">
                <i class="bi bi-file-earmark-medical"></i> الإجازات النشطة
            </button>
        </li>
        <li class="nav-item" role="presentation">
            <button class="nav-link" id="tab-add" data-bs-toggle="tab" data-bs-target="#pane-add" type="button" role="tab">
                <i class="bi bi-plus-circle"></i> إضافة إجازة
            </button>
        </li>
        <li class="nav-item" role="presentation">
            <button class="nav-link" id="tab-archived" data-bs-toggle="tab" data-bs-target="#pane-archived" type="button" role="tab">
                <i class="bi bi-archive"></i> الأرشيف
            </button>
        </li>
        <li class="nav-item" role="presentation">
            <button class="nav-link" id="tab-doctors" data-bs-toggle="tab" data-bs-target="#pane-doctors" type="button" role="tab">
                <i class="bi bi-person-badge"></i> الأطباء
            </button>
        </li>
        <li class="nav-item" role="presentation">
            <button class="nav-link" id="tab-patients" data-bs-toggle="tab" data-bs-target="#pane-patients" type="button" role="tab">
                <i class="bi bi-people"></i> المرضى
            </button>
        </li>
        <li class="nav-item" role="presentation">
            <button class="nav-link" id="tab-chat" data-bs-toggle="tab" data-bs-target="#pane-chat" type="button" role="tab">
                <i class="bi bi-chat-dots"></i> المراسلات
            </button>
        </li>
        <li class="nav-item" role="presentation">
            <button class="nav-link" id="tab-queries" data-bs-toggle="tab" data-bs-target="#pane-queries" type="button" role="tab">
                <i class="bi bi-search"></i> سجل الاستعلامات
            </button>
        </li>
        <li class="nav-item" role="presentation">
            <button class="nav-link" id="tab-payments" data-bs-toggle="tab" data-bs-target="#pane-payments" type="button" role="tab">
                <i class="bi bi-wallet2"></i> المدفوعات
            </button>
        </li>
    </ul>

    <div class="tab-content" id="mainTabContent">
        <!-- ======================== تبويب الإجازات النشطة ======================== -->
        <div class="tab-pane fade show active" id="pane-leaves" role="tabpanel">
            <div class="card-custom">
                <div class="card-header d-flex justify-content-between align-items-center flex-wrap gap-2">
                    <span><i class="bi bi-file-earmark-medical text-primary"></i> الإجازات النشطة</span>
                    <div class="d-flex gap-2 flex-wrap">
                        <button class="btn btn-sm btn-gradient" id="exportLeavesPdf"><i class="bi bi-file-pdf"></i> PDF</button>
                        <button class="btn btn-sm btn-success-custom" id="exportLeavesExcel"><i class="bi bi-file-excel"></i> Excel</button>
                        <button class="btn btn-sm btn-outline-secondary" id="printLeaves"><i class="bi bi-printer"></i> طباعة</button>
                    </div>
                </div>
                <div class="card-body">
                    <!-- أدوات البحث والفلترة -->
                    <div class="toolbar">
                        <div class="input-group" style="max-width:280px;">
                            <input type="text" class="form-control" id="searchLeaves" placeholder="بحث...">
                            <button class="btn btn-gradient" id="btn-search-leaves"><i class="bi bi-search"></i></button>
                        </div>
                        <input type="date" class="form-control" id="filterFromDate" style="max-width:150px;" title="من تاريخ">
                        <input type="date" class="form-control" id="filterToDate" style="max-width:150px;" title="إلى تاريخ">
                        <button class="btn btn-sm btn-gradient" id="filterLeavesBtn"><i class="bi bi-funnel"></i> فلترة</button>
                        <button class="btn btn-sm btn-outline-secondary" id="resetFilterBtn"><i class="bi bi-x-lg"></i> إعادة</button>
                        <div class="btn-group btn-group-sm">
                            <button class="btn btn-outline-success" id="showPaidLeaves">مدفوعة</button>
                            <button class="btn btn-outline-danger" id="showUnpaidLeaves">غير مدفوعة</button>
                            <button class="btn btn-outline-secondary" id="showAllLeaves">الكل</button>
                        </div>
                        <select class="form-select form-select-sm" id="filterType" style="max-width:150px;">
                            <option value="">الكل</option>
                            <option value="paid">مدفوعة</option>
                            <option value="unpaid">غير مدفوعة</option>
                        </select>
                        <div class="btn-group btn-group-sm">
                            <button class="btn btn-outline-primary" id="sortLeavesNewest"><i class="bi bi-sort-down"></i> الأحدث</button>
                            <button class="btn btn-outline-primary" id="sortLeavesOldest"><i class="bi bi-sort-up"></i> الأقدم</button>
                            <button class="btn btn-outline-secondary" id="sortLeavesReset"><i class="bi bi-arrow-counterclockwise"></i></button>
                        </div>
                    </div>
                    <div class="table-responsive">
                        <table class="table table-bordered table-hover table-striped text-center" id="leavesTable">
                            <thead>
                                <tr>
                                    <th>#</th>
                                    <th>رمز الخدمة</th>
                                    <th>المريض</th>
                                    <th>الهوية</th>
                                    <th>الطبيب</th>
                                    <th>الإصدار</th>
                                    <th>من</th>
                                    <th>إلى</th>
                                    <th>الأيام</th>
                                    <th>النوع</th>
                                    <th>مدفوعة</th>
                                    <th>المبلغ</th>
                                    <th>استعلامات</th>
                                    <th>التحكم</th>
                                </tr>
                            </thead>
                            <tbody></tbody>
                        </table>
                    </div>
                </div>
            </div>
        </div>

        <!-- ======================== تبويب إضافة إجازة ======================== -->
        <div class="tab-pane fade" id="pane-add" role="tabpanel">
            <div class="add-section">
                <h5><i class="bi bi-plus-circle-fill"></i> إضافة إجازة مرضية جديدة</h5>
                <form id="addLeaveForm">
                    <div class="row g-3">
                        <!-- رمز الخدمة -->
                        <div class="col-md-4">
                            <label class="form-label">بادئة رمز الخدمة</label>
                            <select class="form-select" name="service_prefix" id="service_prefix">
                                <option value="GSL">GSL - حكومي</option>
                                <option value="PSL">PSL - خاص</option>
                            </select>
                        </div>
                        <div class="col-md-4">
                            <label class="form-label">رمز الخدمة (يدوي - اختياري)</label>
                            <input type="text" class="form-control" name="service_code_manual" id="service_code_manual" placeholder="اتركه فارغاً للتوليد التلقائي">
                        </div>
                        <div class="col-md-4"></div>

                        <!-- المريض -->
                        <div class="col-md-6">
                            <label class="form-label">المريض</label>
                            <input type="text" class="form-control form-control-sm mb-2" id="patient_select_search" placeholder="بحث سريع باسم المريض أو الهوية...">
                            <select class="form-select" name="patient_select" id="patient_select">
                                <option value="">-- اختر مريضاً --</option>
                                <?php foreach ($patients as $p): ?>
                                <option value="<?php echo $p['id']; ?>"><?php echo htmlspecialchars($p['name']); ?> (<?php echo htmlspecialchars($p['identity_number']); ?>)</option>
                                <?php endforeach; ?>
                                <option value="manual">+ إدخال يدوي</option>
                            </select>
                        </div>
                        <div class="col-md-6 hidden-field" id="patientManualFields">
                            <div class="row g-2">
                                <div class="col-12"><label class="form-label">اسم المريض</label><input type="text" class="form-control" name="patient_manual_name" id="patient_manual_name"></div>
                                <div class="col-6"><label class="form-label">رقم الهوية</label><input type="text" class="form-control" name="patient_manual_id" id="patient_manual_id"></div>
                                <div class="col-6"><label class="form-label">الهاتف</label><input type="text" class="form-control" name="patient_manual_phone" id="patient_manual_phone"></div>
                            </div>
                        </div>

                        <!-- الطبيب -->
                        <div class="col-md-6">
                            <label class="form-label">الطبيب</label>
                            <input type="text" class="form-control form-control-sm mb-2" id="doctor_select_search" placeholder="بحث سريع باسم الطبيب...">
                            <select class="form-select" name="doctor_select" id="doctor_select">
                                <option value="">-- اختر طبيباً --</option>
                                <?php foreach ($doctors as $d): ?>
                                <option value="<?php echo $d['id']; ?>"><?php echo htmlspecialchars($d['name']); ?> (<?php echo htmlspecialchars($d['title']); ?>) - <?php echo htmlspecialchars($d['note'] ?? ''); ?></option>
                                <?php endforeach; ?>
                                <option value="manual">+ إدخال يدوي</option>
                            </select>
                        </div>
                        <div class="col-md-6 hidden-field" id="doctorManualFields">
                            <div class="row g-2">
                                <div class="col-12"><label class="form-label">اسم الطبيب</label><input type="text" class="form-control" name="doctor_manual_name" id="doctor_manual_name"></div>
                                <div class="col-6"><label class="form-label">المسمى الوظيفي</label><input type="text" class="form-control" name="doctor_manual_title" id="doctor_manual_title"></div>
                                <div class="col-6"><label class="form-label">ملاحظة</label><input type="text" class="form-control" name="doctor_manual_note" id="doctor_manual_note"></div>
                            </div>
                        </div>

                        <!-- التواريخ -->
                        <div class="col-md-3">
                            <label class="form-label">تاريخ الإصدار</label>
                            <input type="date" class="form-control" name="issue_date" id="issue_date" required>
                        </div>
                        <div class="col-md-3">
                            <label class="form-label">بداية الإجازة</label>
                            <input type="date" class="form-control" name="start_date" id="start_date" required>
                        </div>
                        <div class="col-md-3">
                            <label class="form-label">نهاية الإجازة</label>
                            <input type="date" class="form-control" name="end_date" id="end_date" required>
                        </div>
                        <div class="col-md-3">
                            <label class="form-label">عدد الأيام</label>
                            <input type="number" class="form-control" name="days_count" id="days_count" min="1" required>
                        </div>

                        <!-- المرافق -->
                        <div class="col-md-12">
                            <div class="form-check">
                                <input class="form-check-input" type="checkbox" name="is_companion" id="is_companion">
                                <label class="form-check-label" for="is_companion">إجازة مرافق</label>
                            </div>
                        </div>
                        <div class="col-md-6 hidden-field companion-field">
                            <label class="form-label">اسم المرافق</label>
                            <input type="text" class="form-control" name="companion_name" id="companion_name">
                        </div>
                        <div class="col-md-6 hidden-field companion-field">
                            <label class="form-label">صلة القرابة</label>
                            <input type="text" class="form-control" name="companion_relation" id="companion_relation">
                        </div>

                        <!-- الدفع -->
                        <div class="col-md-6">
                            <div class="form-check">
                                <input class="form-check-input" type="checkbox" name="is_paid" id="is_paid">
                                <label class="form-check-label" for="is_paid">مدفوعة</label>
                            </div>
                        </div>
                        <div class="col-md-6">
                            <label class="form-label">المبلغ</label>
                            <input type="number" step="0.01" class="form-control" name="payment_amount" id="payment_amount" value="0">
                        </div>

                        <div class="col-12 mt-3">
                            <button type="submit" class="btn btn-gradient px-4 py-2"><i class="bi bi-plus-circle"></i> إضافة الإجازة</button>
                            <button type="reset" class="btn btn-outline-secondary px-4 py-2"><i class="bi bi-arrow-counterclockwise"></i> إعادة تعيين</button>
                        </div>
                    </div>
                </form>
            </div>
        </div>

        <!-- ======================== تبويب الأرشيف ======================== -->
        <div class="tab-pane fade" id="pane-archived" role="tabpanel">
            <div class="card-custom">
                <div class="card-header d-flex justify-content-between align-items-center flex-wrap gap-2">
                    <span><i class="bi bi-archive text-warning"></i> الإجازات المؤرشفة</span>
                    <button class="btn btn-sm btn-danger-custom" id="deleteAllArchived"><i class="bi bi-trash3"></i> حذف الكل نهائياً</button>
                </div>
                <div class="card-body">
                    <div class="toolbar">
                        <div class="input-group" style="max-width:280px;">
                            <input type="text" class="form-control" id="searchArchived" placeholder="بحث...">
                            <button class="btn btn-gradient" id="btn-search-archived"><i class="bi bi-search"></i></button>
                        </div>
                        <input type="date" class="form-control" id="filter_arch_from_date" style="max-width:150px;">
                        <input type="date" class="form-control" id="filter_arch_to_date" style="max-width:150px;">
                        <button class="btn btn-sm btn-gradient" id="btn-filter-arch-dates"><i class="bi bi-funnel"></i></button>
                        <button class="btn btn-sm btn-outline-secondary" id="btn-reset-arch-dates"><i class="bi bi-x-lg"></i></button>
                        <div class="btn-group btn-group-sm">
                            <button class="btn btn-outline-success" id="showPaidArchived">مدفوعة</button>
                            <button class="btn btn-outline-danger" id="showUnpaidArchived">غير مدفوعة</button>
                            <button class="btn btn-outline-secondary" id="showAllArchived">الكل</button>
                        </div>
                        <div class="btn-group btn-group-sm">
                            <button class="btn btn-outline-primary" id="sortArchivedNewest"><i class="bi bi-sort-down"></i></button>
                            <button class="btn btn-outline-primary" id="sortArchivedOldest"><i class="bi bi-sort-up"></i></button>
                            <button class="btn btn-outline-secondary" id="sortArchivedReset"><i class="bi bi-arrow-counterclockwise"></i></button>
                        </div>
                    </div>
                    <div class="table-responsive">
                        <table class="table table-bordered table-hover table-striped text-center" id="archivedTable">
                            <thead>
                                <tr>
                                    <th>#</th>
                                    <th>رمز الخدمة</th>
                                    <th>المريض</th>
                                    <th>الهوية</th>
                                    <th>الطبيب</th>
                                    <th>من</th>
                                    <th>إلى</th>
                                    <th>الأيام</th>
                                    <th>مدفوعة</th>
                                    <th>المبلغ</th>
                                    <th>تاريخ الأرشفة</th>
                                    <th>الاستعلامات</th>
                                    <th>التحكم</th>
                                </tr>
                            </thead>
                            <tbody></tbody>
                        </table>
                    </div>
                </div>
            </div>
        </div>

        <!-- ======================== تبويب الأطباء ======================== -->
        <div class="tab-pane fade" id="pane-doctors" role="tabpanel">
            <div class="card-custom">
                <div class="card-header"><i class="bi bi-person-badge text-primary"></i> إدارة الأطباء</div>
                <div class="card-body">
                    <div class="toolbar mb-3">
                        <div class="input-group" style="max-width:280px;">
                            <input type="text" class="form-control" id="searchDoctors" placeholder="بحث في الأطباء...">
                            <button class="btn btn-gradient" id="btn-search-doctors"><i class="bi bi-search"></i></button>
                                                    </div>
                    </div>
                    <form id="addDoctorForm" class="row g-2 mb-3">
                        <div class="col-md-3"><input type="text" class="form-control" name="doctor_name" placeholder="اسم الطبيب" required></div>
                        <div class="col-md-3"><input type="text" class="form-control" name="doctor_title" placeholder="المسمى الوظيفي" required></div>
                        <div class="col-md-3"><input type="text" class="form-control" name="doctor_note" placeholder="ملاحظة (اختياري)"></div>
                        <div class="col-md-3"><button type="submit" class="btn btn-gradient w-100"><i class="bi bi-plus"></i> إضافة طبيب</button></div>
                    </form>
                    <div class="table-responsive">
                        <table class="table table-bordered table-hover table-striped text-center" id="doctorsTable">
                            <thead><tr><th>#</th><th>الاسم</th><th>المسمى</th><th>ملاحظة</th><th>التحكم</th></tr></thead>
                            <tbody></tbody>
                        </table>
                    </div>
                </div>
            </div>
        </div>

        <!-- ======================== تبويب المرضى ======================== -->
        <div class="tab-pane fade" id="pane-patients" role="tabpanel">
            <div class="card-custom">
                <div class="card-header"><i class="bi bi-people text-success"></i> إدارة المرضى</div>
                <div class="card-body">
                    <div class="toolbar mb-3">
                        <div class="input-group" style="max-width:280px;">
                            <input type="text" class="form-control" id="searchPatients" placeholder="بحث في المرضى...">
                            <button class="btn btn-gradient" id="btn-search-patients"><i class="bi bi-search"></i></button>
                        </div>
                    </div>
                    <form id="addPatientForm" class="row g-2 mb-3">
                        <div class="col-md-3"><input type="text" class="form-control" name="patient_name" placeholder="اسم المريض" required></div>
                        <div class="col-md-3"><input type="text" class="form-control" name="identity_number" placeholder="رقم الهوية" required></div>
                        <div class="col-md-3"><input type="text" class="form-control" name="phone" placeholder="الهاتف"></div>
                        <div class="col-md-3"><button type="submit" class="btn btn-success-custom w-100"><i class="bi bi-plus"></i> إضافة مريض</button></div>
                    </form>
                    <div class="table-responsive">
                        <table class="table table-bordered table-hover table-striped text-center" id="patientsTable">
                            <thead><tr><th>#</th><th>الاسم</th><th>رقم الهوية</th><th>الهاتف</th><th>التحكم</th></tr></thead>
                            <tbody></tbody>
                        </table>
                    </div>
                </div>
            </div>
        </div>

        <div class="tab-pane fade" id="pane-chat" role="tabpanel">
            <div class="card-custom">
                <div class="card-header"><i class="bi bi-chat-dots text-primary"></i> مراسلة المستخدمين</div>
                <div class="card-body">
                    <div class="row g-3">
                        <div class="col-lg-4">
                            <input type="text" class="form-control mb-2" id="chatUsersSearch" placeholder="بحث مستخدم...">
                            <select class="form-select mb-2" id="chatPeerSelect"></select>
                            <button class="btn btn-sm btn-outline-secondary" id="refreshChatUsersBtn"><i class="bi bi-arrow-repeat"></i> تحديث المستخدمين</button>
                        </div>
                        <div class="col-lg-8">
                            <div id="chatMessagesBox" class="border rounded p-2 mb-2" style="height:320px; overflow:auto; background:#f8f9fa;"></div>
                            <div class="input-group">
                                <input type="text" class="form-control" id="chatMessageInput" placeholder="اكتب رسالتك...">
                                <button class="btn btn-gradient" id="sendChatMessageBtn"><i class="bi bi-send"></i> إرسال</button>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
        </div>

        <!-- ======================== تبويب سجل الاستعلامات ======================== -->
        <div class="tab-pane fade" id="pane-queries" role="tabpanel">
            <div class="card-custom">
                <div class="card-header d-flex justify-content-between align-items-center flex-wrap gap-2">
                    <span><i class="bi bi-search text-info"></i> سجل الاستعلامات</span>
                    <div class="d-flex gap-2 flex-wrap">
                        <button class="btn btn-sm btn-gradient" id="exportQueriesPdf"><i class="bi bi-file-pdf"></i> PDF</button>
                        <button class="btn btn-sm btn-success-custom" id="exportQueriesExcel"><i class="bi bi-file-excel"></i> Excel</button>
                        <button class="btn btn-sm btn-outline-secondary" id="printQueries"><i class="bi bi-printer"></i> طباعة</button>
                        <button class="btn btn-sm btn-danger-custom" id="deleteAllQueries"><i class="bi bi-trash3"></i> حذف الكل</button>
                    </div>
                </div>
                <div class="card-body">
                    <div class="toolbar">
                        <div class="input-group" style="max-width:280px;">
                            <input type="text" class="form-control" id="searchQueries" placeholder="بحث...">
                            <button class="btn btn-gradient" id="btn-search-queries"><i class="bi bi-search"></i></button>
                        </div>
                        <input type="date" class="form-control" id="filterQueriesFrom" style="max-width:150px;">
                        <input type="date" class="form-control" id="filterQueriesTo" style="max-width:150px;">
                        <button class="btn btn-sm btn-gradient" id="filterQueriesBtn"><i class="bi bi-funnel"></i></button>
                        <button class="btn btn-sm btn-outline-secondary" id="resetQueriesFilterBtn"><i class="bi bi-x-lg"></i></button>
                        <button class="btn btn-sm btn-danger-custom" id="deleteAllQueriesBtn"><i class="bi bi-trash3"></i> حذف نهائي</button>
                        <div class="btn-group btn-group-sm">
                            <button class="btn btn-outline-primary" id="sortQueriesNewest"><i class="bi bi-sort-down"></i></button>
                            <button class="btn btn-outline-primary" id="sortQueriesOldest"><i class="bi bi-sort-up"></i></button>
                            <button class="btn btn-outline-secondary" id="sortQueriesReset"><i class="bi bi-arrow-counterclockwise"></i></button>
                        </div>
                    </div>
                    <div class="table-responsive">
                        <table class="table table-bordered table-hover table-striped text-center" id="queriesTable">
                            <thead><tr><th>#</th><th>رمز الخدمة</th><th>المريض</th><th>الهوية</th><th>تاريخ الاستعلام</th><th>المصدر</th><th>التحكم</th></tr></thead>
                            <tbody></tbody>
                        </table>
                    </div>
                </div>
            </div>
        </div>

        <!-- ======================== تبويب المدفوعات ======================== -->
        <div class="tab-pane fade" id="pane-payments" role="tabpanel">
            <div class="card-custom">
                <div class="card-header d-flex justify-content-between align-items-center flex-wrap gap-2">
                    <span><i class="bi bi-wallet2 text-success"></i> المدفوعات لكل مريض</span>
                    <div class="d-flex gap-2 flex-wrap">
                        <button class="btn btn-sm btn-gradient" id="exportPaymentsPdf"><i class="bi bi-file-pdf"></i> PDF</button>
                        <button class="btn btn-sm btn-success-custom" id="exportPaymentsExcel"><i class="bi bi-file-excel"></i> Excel</button>
                        <button class="btn btn-sm btn-outline-secondary" id="printPayments"><i class="bi bi-printer"></i> طباعة</button>
                    </div>
                </div>
                <div class="card-body">
                    <div class="toolbar">
                        <div class="input-group" style="max-width:280px;">
                            <input type="text" class="form-control" id="searchPayments" placeholder="بحث...">
                            <button class="btn btn-gradient" id="btn-search-payments"><i class="bi bi-search"></i></button>
                        </div>
                        <div class="btn-group btn-group-sm">
                            <button class="btn btn-outline-success" id="sortPaymentsPaid">الأكثر دفعاً</button>
                            <button class="btn btn-outline-danger" id="sortPaymentsUnpaid">الأكثر استحقاقاً</button>
                            <button class="btn btn-outline-primary" id="sortPaymentsMostLeaves">الأكثر إجازات</button>
                            <button class="btn btn-outline-primary" id="sortPaymentsLeastLeaves">الأقل إجازات</button>
                            <button class="btn btn-outline-secondary" id="sortPaymentsReset"><i class="bi bi-arrow-counterclockwise"></i></button>
                        </div>
                    </div>
                    <div class="table-responsive">
                        <table class="table table-bordered table-hover table-striped text-center" id="paymentsTable">
                            <thead><tr><th>#</th><th>المريض</th><th>الإجمالي</th><th>مدفوعة</th><th>غير مدفوعة</th><th>مبلغ مدفوع</th><th>مبلغ مستحق</th><th>عرض</th></tr></thead>
                            <tbody></tbody>
                        </table>
                    </div>
                </div>
            </div>
        </div>
    </div>
</div>

<!-- ======================== مودال تعديل الإجازة ======================== -->
<div class="modal fade" id="editLeaveModal" tabindex="-1" aria-hidden="true">
    <div class="modal-dialog modal-lg modal-dialog-centered modal-dialog-scrollable">
        <div class="modal-content">
            <div class="modal-header">
                <h5 class="modal-title"><i class="bi bi-pencil-square text-primary"></i> تعديل الإجازة</h5>
                <button type="button" class="btn-close" data-bs-dismiss="modal"></button>
            </div>
            <div class="modal-body">
                <form id="editLeaveForm">
                    <input type="hidden" name="leave_id_edit" id="leave_id_edit">
                    <div class="row g-3">
                        <div class="col-md-6">
                            <label class="form-label">رمز الخدمة</label>
                            <input type="text" class="form-control" name="service_code_edit" id="service_code_edit" required>
                        </div>
                        <div class="col-md-6">
                            <label class="form-label">الطبيب</label>
                            <input type="text" class="form-control form-control-sm mb-2" id="doctor_id_edit_search" placeholder="بحث سريع باسم الطبيب...">
                            <select class="form-select" name="doctor_id_edit" id="doctor_id_edit">
                                <option value="">-- لا تغيير --</option>
                                <?php foreach ($doctors as $d): ?>
                                <option value="<?php echo $d['id']; ?>"><?php echo htmlspecialchars($d['name']); ?> (<?php echo htmlspecialchars($d['title']); ?>) - <?php echo htmlspecialchars($d['note'] ?? ''); ?></option>
                                <?php endforeach; ?>
                                <option value="manual">+ إدخال يدوي</option>
                            </select>
                            <small class="form-text">اختر طبيباً جديداً أو اتركه لعدم التغيير</small>
                        </div>
                        <div class="col-md-12 hidden-field" id="editDoctorManualFields">
                            <div class="row g-2">
                                <div class="col-4"><label class="form-label">اسم الطبيب</label><input type="text" class="form-control" name="doctor_manual_name_edit" id="doctor_manual_name_edit"></div>
                                <div class="col-4"><label class="form-label">المسمى</label><input type="text" class="form-control" name="doctor_manual_title_edit" id="doctor_manual_title_edit"></div>
                                <div class="col-4"><label class="form-label">ملاحظة</label><input type="text" class="form-control" name="doctor_manual_note_edit" id="doctor_manual_note_edit"></div>
                            </div>
                        </div>
                        <div class="col-md-4">
                            <label class="form-label">تاريخ الإصدار</label>
                            <input type="date" class="form-control" name="issue_date_edit" id="issue_date_edit" required>
                        </div>
                        <div class="col-md-4">
                            <label class="form-label">بداية الإجازة</label>
                            <input type="date" class="form-control" name="start_date_edit" id="start_date_edit" required>
                        </div>
                        <div class="col-md-4">
                            <label class="form-label">نهاية الإجازة</label>
                            <input type="date" class="form-control" name="end_date_edit" id="end_date_edit" required>
                        </div>
                        <div class="col-md-4">
                            <label class="form-label">عدد الأيام</label>
                            <input type="number" class="form-control" name="days_count_edit" id="days_count_edit" min="1" required>
                        </div>
                        <div class="col-md-4">
                            <div class="form-check mt-4">
                                <input class="form-check-input" type="checkbox" name="is_companion_edit" id="is_companion_edit">
                                <label class="form-check-label" for="is_companion_edit">إجازة مرافق</label>
                            </div>
                        </div>
                        <div class="col-md-4">
                            <div class="form-check mt-4">
                                <input class="form-check-input" type="checkbox" name="is_paid_edit" id="is_paid_edit">
                                <label class="form-check-label" for="is_paid_edit">مدفوعة</label>
                            </div>
                        </div>
                        <div class="col-md-6 hidden-field" id="editCompanionFields">
                            <label class="form-label">اسم المرافق</label>
                            <input type="text" class="form-control" name="companion_name_edit" id="companion_name_edit">
                        </div>
                        <div class="col-md-6 hidden-field" id="editCompanionRelField">
                            <label class="form-label">صلة القرابة</label>
                            <input type="text" class="form-control" name="companion_relation_edit" id="companion_relation_edit">
                        </div>
                        <div class="col-md-6">
                            <label class="form-label">المبلغ</label>
                            <input type="number" step="0.01" class="form-control" name="payment_amount_edit" id="payment_amount_edit" value="0">
                        </div>
                    </div>
                </form>
            </div>
            <div class="modal-footer">
                <button type="button" class="btn btn-outline-secondary" data-bs-dismiss="modal">إلغاء</button>
                <button type="button" class="btn btn-gradient" id="saveEditLeave"><i class="bi bi-check-lg"></i> حفظ التعديلات</button>
            </div>
        </div>
    </div>
</div>

<!-- ======================== مودال تكرار الإجازة ======================== -->
<div class="modal fade" id="duplicateLeaveModal" tabindex="-1" aria-hidden="true">
    <div class="modal-dialog modal-lg modal-dialog-centered modal-dialog-scrollable">
        <div class="modal-content">
            <div class="modal-header" style="background: var(--gradient-primary); color: #fff;">
                <h5 class="modal-title"><i class="bi bi-files"></i> تكرار الإجازة</h5>
                <button type="button" class="btn-close btn-close-white" data-bs-dismiss="modal"></button>
            </div>
            <div class="modal-body">
                <div class="alert alert-info py-2 mb-3" style="font-size:13px;">
                    <i class="bi bi-info-circle"></i> سيتم إنشاء إجازة جديدة بنفس بيانات المريض مع إمكانية تعديل باقي البيانات. سيتم توليد رمز خدمة جديد تلقائياً.
                </div>
                <form id="duplicateLeaveForm">
                    <input type="hidden" name="dup_patient_id" id="dup_patient_id">
                    <div class="row g-3">
                        <div class="col-md-6">
                            <label class="form-label">المريض</label>
                            <input type="text" class="form-control" id="dup_patient_name_display" readonly style="background:#f8f9fa;">
                        </div>
                        <div class="col-md-6">
                            <label class="form-label">الطبيب</label>
                            <input type="text" class="form-control form-control-sm mb-2" id="dup_doctor_search" placeholder="بحث سريع باسم الطبيب...">
                            <select class="form-select" name="dup_doctor_select" id="dup_doctor_select">
                                <option value="">-- اختر طبيباً --</option>
                                <?php foreach ($doctors as $d): ?>
                                <option value="<?php echo $d['id']; ?>"><?php echo htmlspecialchars($d['name']); ?> (<?php echo htmlspecialchars($d['title']); ?>) - <?php echo htmlspecialchars($d['note'] ?? ''); ?></option>
                                <?php endforeach; ?>
                                <option value="manual">+ إدخال يدوي</option>
                            </select>
                        </div>
                        <div class="col-md-12 hidden-field" id="dupDoctorManualFields">
                            <div class="row g-2">
                                <div class="col-4"><label class="form-label">اسم الطبيب</label><input type="text" class="form-control" name="dup_doctor_manual_name" id="dup_doctor_manual_name"></div>
                                <div class="col-4"><label class="form-label">المسمى</label><input type="text" class="form-control" name="dup_doctor_manual_title" id="dup_doctor_manual_title"></div>
                                <div class="col-4"><label class="form-label">ملاحظة</label><input type="text" class="form-control" name="dup_doctor_manual_note" id="dup_doctor_manual_note"></div>
                            </div>
                        </div>
                        <div class="col-md-4">
                            <label class="form-label">بادئة رمز الخدمة</label>
                            <select class="form-select" name="dup_service_prefix" id="dup_service_prefix">
                                <option value="GSL">GSL - حكومي</option>
                                <option value="PSL">PSL - خاص</option>
                            </select>
                        </div>
                        <div class="col-md-4">
                            <label class="form-label">رمز الخدمة (يدوي - اختياري)</label>
                            <input type="text" class="form-control" name="dup_service_code_manual" id="dup_service_code_manual" placeholder="تلقائي">
                        </div>
                        <div class="col-md-4"></div>
                        <div class="col-md-4">
                            <label class="form-label">تاريخ الإصدار</label>
                            <input type="date" class="form-control" name="dup_issue_date" id="dup_issue_date" required>
                        </div>
                        <div class="col-md-4">
                            <label class="form-label">بداية الإجازة</label>
                            <input type="date" class="form-control" name="dup_start_date" id="dup_start_date" required>
                        </div>
                        <div class="col-md-4">
                            <label class="form-label">نهاية الإجازة</label>
                            <input type="date" class="form-control" name="dup_end_date" id="dup_end_date" required>
                        </div>
                        <div class="col-md-3">
                            <label class="form-label">عدد الأيام</label>
                            <input type="number" class="form-control" name="dup_days_count" id="dup_days_count" min="1" required>
                        </div>
                        <div class="col-md-3">
                            <div class="form-check mt-4">
                                <input class="form-check-input" type="checkbox" name="dup_is_companion" id="dup_is_companion">
                                <label class="form-check-label" for="dup_is_companion">إجازة مرافق</label>
                            </div>
                        </div>
                        <div class="col-md-3">
                            <div class="form-check mt-4">
                                <input class="form-check-input" type="checkbox" name="dup_is_paid" id="dup_is_paid">
                                <label class="form-check-label" for="dup_is_paid">مدفوعة</label>
                            </div>
                        </div>
                        <div class="col-md-3">
                            <label class="form-label">المبلغ</label>
                            <input type="number" step="0.01" class="form-control" name="dup_payment_amount" id="dup_payment_amount" value="0">
                        </div>
                        <div class="col-md-6 hidden-field" id="dupCompanionFields">
                            <label class="form-label">اسم المرافق</label>
                            <input type="text" class="form-control" name="dup_companion_name" id="dup_companion_name">
                        </div>
                        <div class="col-md-6 hidden-field" id="dupCompanionRelField">
                            <label class="form-label">صلة القرابة</label>
                            <input type="text" class="form-control" name="dup_companion_relation" id="dup_companion_relation">
                        </div>
                    </div>
                </form>
            </div>
            <div class="modal-footer">
                <button type="button" class="btn btn-outline-secondary" data-bs-dismiss="modal">إلغاء</button>
                <button type="button" class="btn btn-gradient" id="saveDuplicateLeave"><i class="bi bi-files"></i> تكرار الإجازة</button>
            </div>
        </div>
    </div>
</div>

<!-- ======================== مودال التأكيد ======================== -->
<div class="modal fade" id="confirmModal" tabindex="-1" aria-hidden="true">
    <div class="modal-dialog modal-dialog-centered">
        <div class="modal-content">
            <div class="modal-header"><h5 class="modal-title"><i class="bi bi-exclamation-triangle text-warning"></i> تأكيد</h5><button type="button" class="btn-close" data-bs-dismiss="modal"></button></div>
            <div class="modal-body"><p id="confirmMessage">هل أنت متأكد؟</p></div>
            <div class="modal-footer">
                <button type="button" class="btn btn-outline-secondary" data-bs-dismiss="modal">إلغاء</button>
                <button type="button" class="btn btn-danger-custom" id="confirmYesBtn">تأكيد</button>
            </div>
        </div>
    </div>
</div>

<!-- ======================== مودال تفاصيل الإجازة ======================== -->
<div class="modal fade" id="leaveDetailsModal" tabindex="-1" aria-hidden="true">
    <div class="modal-dialog modal-dialog-centered">
        <div class="modal-content">
            <div class="modal-header"><h5 class="modal-title"><i class="bi bi-info-circle text-info"></i> تفاصيل الإجازة</h5><button type="button" class="btn-close" data-bs-dismiss="modal"></button></div>
            <div class="modal-body" id="leaveDetailsContainer"></div>
            <div class="modal-footer"><button type="button" class="btn btn-outline-secondary" data-bs-dismiss="modal">إغلاق</button></div>
        </div>
    </div>
</div>

<!-- ======================== مودال تفاصيل الاستعلامات ======================== -->
<div class="modal fade" id="viewQueriesModal" tabindex="-1" aria-hidden="true">
    <div class="modal-dialog modal-lg modal-dialog-centered modal-dialog-scrollable">
        <div class="modal-content">
            <div class="modal-header">
                <h5 class="modal-title"><i class="bi bi-list-ul text-primary"></i> تفاصيل الاستعلامات</h5>
                <button type="button" class="btn-close" data-bs-dismiss="modal"></button>
            </div>
            <div class="modal-body">
                <div class="d-flex gap-2 mb-2">
                    <button class="btn btn-sm btn-outline-primary" id="sortQueriesDetailNewest">الأحدث</button>
                    <button class="btn btn-sm btn-outline-primary" id="sortQueriesDetailOldest">الأقدم</button>
                    <button class="btn btn-sm btn-outline-secondary" id="sortQueriesDetailReset">إعادة</button>
                    <button class="btn btn-sm btn-danger-custom ms-auto" id="btn-delete-all-queries">حذف الكل</button>
                </div>
                <ul class="list-group" id="queriesDetailsContainer"></ul>
            </div>
            <div class="modal-footer"><button type="button" class="btn btn-outline-secondary" data-bs-dismiss="modal">إغلاق</button></div>
        </div>
    </div>
</div>

<!-- ======================== مودال إشعارات المدفوعات ======================== -->
<div class="modal fade" id="paymentNotifsModal" tabindex="-1" aria-hidden="true">
    <div class="modal-dialog modal-lg modal-dialog-centered modal-dialog-scrollable">
        <div class="modal-content">
            <div class="modal-header">
                <h5 class="modal-title"><i class="bi bi-bell text-warning"></i> إشعارات المدفوعات</h5>
                <button type="button" class="btn-close" data-bs-dismiss="modal"></button>
            </div>
            <div class="modal-body">
                <div class="toolbar mb-2">
                    <div class="input-group" style="max-width:280px;">
                        <input type="text" class="form-control" id="searchNotifs" placeholder="بحث باسم المريض أو الرمز...">
                        <button class="btn btn-gradient" id="btn-search-notifs"><i class="bi bi-search"></i></button>
                    </div>
                    <div class="btn-group btn-group-sm">
                        <button class="btn btn-outline-primary" id="sortNotifsNewest">الأحدث</button>
                        <button class="btn btn-outline-primary" id="sortNotifsOldest">الأقدم</button>
                        <button class="btn btn-outline-success" id="sortNotifsMostRepeated">الأكثر تكراراً</button>
                        <button class="btn btn-outline-secondary" id="sortNotifsReset"><i class="bi bi-arrow-counterclockwise"></i></button>
                    </div>
                    <button class="btn btn-sm btn-gradient" id="refreshNotifs"><i class="bi bi-arrow-clockwise"></i> تحديث</button>
                </div>
                <ul class="list-group" id="notifPaymentsList"></ul>
            </div>
            <div class="modal-footer"><button type="button" class="btn btn-outline-secondary" data-bs-dismiss="modal">إغلاق</button></div>
        </div>
    </div>
</div>

<!-- ======================== مودال تأكيد الدفع ======================== -->
<div class="modal fade" id="payConfirmModal" tabindex="-1" aria-hidden="true">
    <div class="modal-dialog modal-dialog-centered">
        <div class="modal-content">
            <div class="modal-header"><h5 class="modal-title"><i class="bi bi-cash-coin text-success"></i> تأكيد الدفع</h5><button type="button" class="btn-close" data-bs-dismiss="modal"></button></div>
            <div class="modal-body">
                <p id="payConfirmMessage"></p>
                <label class="form-label">المبلغ</label>
                <input type="number" step="0.01" class="form-control" id="confirmPayAmount">
            </div>
            <div class="modal-footer">
                <button type="button" class="btn btn-outline-secondary" data-bs-dismiss="modal">إلغاء</button>
                <button type="button" class="btn btn-success-custom" id="confirmPayBtn">تأكيد الدفع</button>
            </div>
        </div>
    </div>
</div>

<!-- ======================== مودال تعديل الطبيب ======================== -->
<div class="modal fade" id="editDoctorModal" tabindex="-1" aria-hidden="true">
    <div class="modal-dialog modal-dialog-centered">
        <div class="modal-content">
            <div class="modal-header"><h5 class="modal-title"><i class="bi bi-pencil text-primary"></i> تعديل الطبيب</h5><button type="button" class="btn-close" data-bs-dismiss="modal"></button></div>
            <div class="modal-body">
                <form id="editDoctorForm">
                    <input type="hidden" name="doctor_id" id="edit_doctor_id">
                    <div class="mb-3"><label class="form-label">الاسم</label><input type="text" class="form-control" name="doctor_name" id="edit_doctor_name" required></div>
                    <div class="mb-3"><label class="form-label">المسمى</label><input type="text" class="form-control" name="doctor_title" id="edit_doctor_title" required></div>
                    <div class="mb-3"><label class="form-label">ملاحظة</label><input type="text" class="form-control" name="doctor_note" id="edit_doctor_note"></div>
                </form>
            </div>
            <div class="modal-footer">
                <button type="button" class="btn btn-outline-secondary" data-bs-dismiss="modal">إلغاء</button>
                <button type="button" class="btn btn-gradient" id="saveEditDoctor">حفظ</button>
            </div>
        </div>
    </div>
</div>

<!-- ======================== مودال تعديل المريض ======================== -->
<div class="modal fade" id="editPatientModal" tabindex="-1" aria-hidden="true">
    <div class="modal-dialog modal-dialog-centered">
        <div class="modal-content">
            <div class="modal-header"><h5 class="modal-title"><i class="bi bi-pencil text-success"></i> تعديل المريض</h5><button type="button" class="btn-close" data-bs-dismiss="modal"></button></div>
            <div class="modal-body">
                <form id="editPatientForm">
                    <input type="hidden" name="patient_id" id="edit_patient_id">
                    <div class="mb-3"><label class="form-label">الاسم</label><input type="text" class="form-control" name="patient_name" id="edit_patient_name" required></div>
                    <div class="mb-3"><label class="form-label">رقم الهوية</label><input type="text" class="form-control" name="identity_number" id="edit_patient_identity" required></div>
                    <div class="mb-3"><label class="form-label">الهاتف</label><input type="text" class="form-control" name="phone" id="edit_patient_phone"></div>
                </form>
            </div>
            <div class="modal-footer">
                <button type="button" class="btn btn-outline-secondary" data-bs-dismiss="modal">إلغاء</button>
                <button type="button" class="btn btn-success-custom" id="saveEditPatient">حفظ</button>
            </div>
        </div>
    </div>
</div>

<?php if ($_SESSION['admin_role'] === 'admin'): ?>
<!-- ======================== مودال إدارة المستخدمين ======================== -->
<div class="modal fade" id="addUserModal" tabindex="-1" aria-hidden="true">
    <div class="modal-dialog modal-xl modal-dialog-centered modal-dialog-scrollable">
        <div class="modal-content">
            <div class="modal-header" style="background: var(--gradient-dark); color: #fff;">
                <h5 class="modal-title"><i class="bi bi-people-fill"></i> إدارة المستخدمين</h5>
                <button type="button" class="btn-close btn-close-white" data-bs-dismiss="modal"></button>
            </div>
            <div class="modal-body users-section">
                <!-- إضافة مستخدم جديد -->
                <div class="card-custom mb-3">
                    <div class="card-header"><i class="bi bi-person-plus text-primary"></i> إضافة مستخدم جديد</div>
                    <div class="card-body">
                        <form id="addUserForm" class="row g-2">
                            <div class="col-md-3"><input type="text" class="form-control" name="new_username" placeholder="اسم المستخدم" required></div>
                            <div class="col-md-3"><input type="password" class="form-control" name="new_password" placeholder="كلمة المرور" required></div>
                            <div class="col-md-3"><input type="text" class="form-control" name="new_display_name" placeholder="الاسم المعروض" required></div>
                            <div class="col-md-2">
                                <select class="form-select" name="new_role">
                                    <option value="user">مستخدم</option>
                                    <option value="admin">مشرف</option>
                                </select>
                            </div>
                            <div class="col-md-1"><button type="button" class="btn btn-gradient w-100" id="saveNewUser"><i class="bi bi-plus"></i></button></div>
                        </form>
                    </div>
                </div>
                <!-- قائمة المستخدمين -->
                <div class="table-responsive">
                    <table class="table table-bordered table-hover table-striped text-center" id="usersTable">
                        <thead><tr><th>#</th><th>اسم المستخدم</th><th>الاسم المعروض</th><th>الدور</th><th>الحالة</th><th>تاريخ الإنشاء</th><th>التحكم</th></tr></thead>
                        <tbody></tbody>
                    </table>
                </div>
            </div>
            <div class="modal-footer"><button type="button" class="btn btn-outline-secondary" data-bs-dismiss="modal">إغلاق</button></div>
        </div>
    </div>
</div>

<!-- ======================== مودال تعديل المستخدم ======================== -->
<div class="modal fade" id="editUserModal" tabindex="-1" aria-hidden="true">
    <div class="modal-dialog modal-dialog-centered">
        <div class="modal-content">
            <div class="modal-header"><h5 class="modal-title"><i class="bi bi-person-gear text-primary"></i> تعديل المستخدم</h5><button type="button" class="btn-close" data-bs-dismiss="modal"></button></div>
            <div class="modal-body">
                <form id="editUserForm">
                    <input type="hidden" name="edit_user_id" id="edit_user_id">
                    <div class="mb-3"><label class="form-label">الاسم المعروض</label><input type="text" class="form-control" name="edit_display_name" id="edit_user_display_name" required></div>
                    <div class="mb-3"><label class="form-label">كلمة المرور الجديدة (اتركها فارغة لعدم التغيير)</label><input type="password" class="form-control" name="edit_password" id="edit_user_password"></div>
                    <div class="mb-3">
                        <label class="form-label">الدور</label>
                        <select class="form-select" name="edit_role" id="edit_user_role">
                            <option value="user">مستخدم</option>
                            <option value="admin">مشرف</option>
                        </select>
                    </div>
                    <div class="form-check">
                        <input class="form-check-input" type="checkbox" name="edit_is_active" id="edit_user_is_active" checked>
                        <label class="form-check-label" for="edit_is_active">نشط</label>
                    </div>
                </form>
            </div>
            <div class="modal-footer">
                <button type="button" class="btn btn-outline-secondary" data-bs-dismiss="modal">إلغاء</button>
                <button type="button" class="btn btn-gradient" id="saveEditUser">حفظ</button>
            </div>
        </div>
    </div>
</div>

<!-- ======================== مودال جلسات المستخدم ======================== -->
<div class="modal fade" id="sessionsModal" tabindex="-1" aria-hidden="true">
    <div class="modal-dialog modal-lg modal-dialog-centered modal-dialog-scrollable">
        <div class="modal-content">
            <div class="modal-header"><h5 class="modal-title"><i class="bi bi-clock-history text-info"></i> سجل الجلسات</h5><button type="button" class="btn-close" data-bs-dismiss="modal"></button></div>
            <div class="modal-body">
                <div class="d-flex justify-content-end mb-2"><button class="btn btn-sm btn-danger-custom" id="btnDeleteAllSessionsForUser"><i class="bi bi-trash3"></i> حذف كل الجلسات</button></div>
                <ul class="list-group" id="sessionsListContainer">
                    <li class="list-group-item text-center text-muted">لا توجد جلسات.</li>
                </ul>
                <div class="table-responsive d-none">
                    <table class="table table-bordered table-hover table-striped text-center" id="sessionsTable">
                        <thead><tr><th>#</th><th>وقت الدخول</th><th>وقت الخروج</th><th>عنوان IP</th><th>المتصفح</th></tr></thead>
                        <tbody></tbody>
                    </table>
                </div>
            </div>
            <div class="modal-footer"><button type="button" class="btn btn-outline-secondary" data-bs-dismiss="modal">إغلاق</button></div>
        </div>
    </div>
</div>
<?php endif; ?>

<!-- ======================== زر الوضع الداكن ======================== -->
<button class="btn" id="darkModeToggle"><i class="bi bi-moon-stars"></i> الوضع الداكن</button>

<?php endif; ?>

<script>
// ======================== البيانات الأولية من PHP ========================
const CSRF_TOKEN = '<?php echo csrf_token(); ?>';
const IS_ADMIN = <?php echo ($loggedIn && $_SESSION['admin_role'] === 'admin') ? 'true' : 'false'; ?>;
const IS_LOGGED_IN = <?php echo $loggedIn ? 'true' : 'false'; ?>;
const REQUEST_URL = window.location.pathname;

<?php if ($loggedIn): ?>
const initialLeaves = <?php echo json_encode($leaves); ?>;
const initialArchived = <?php echo json_encode($archived); ?>;
const initialQueries = <?php echo json_encode($queries); ?>;
const initialDoctors = <?php echo json_encode($doctors); ?>;
const initialPatients = <?php echo json_encode($patients); ?>;
const initialPayments = <?php echo json_encode($payments); ?>;
const initialNotifications = <?php echo json_encode($notifications_payment); ?>;
const initialUsers = <?php echo json_encode($users); ?>;
const initialChatUsers = <?php echo json_encode($chat_users ?? []); ?>;
<?php else: ?>
const initialLeaves = [], initialArchived = [], initialQueries = [], initialDoctors = [], initialPatients = [], initialPayments = [], initialNotifications = [], initialUsers = [], initialChatUsers = [];
<?php endif; ?>

// ======================== دوال مساعدة ========================
function htmlspecialchars(str) {
    if (str === null || str === undefined) return '';
    const div = document.createElement('div');
    div.appendChild(document.createTextNode(String(str)));
    return div.innerHTML;
}

function formatWhatsAppLink(phone) {
    if (!phone) return '';
    let digits = String(phone).replace(/\D/g, '');
    if (!digits) return '';
    if (digits.startsWith('00')) digits = digits.slice(2);
    else if (digits.startsWith('0')) digits = '966' + digits.slice(1);
    return `https://wa.me/${digits}`;
}

function formatSaudiDateTime(dateValue) {
    if (!dateValue) return '';
    const str = String(dateValue).trim();
    const m = str.match(/^(\d{4})-(\d{2})-(\d{2})[ T](\d{2}):(\d{2})(?::(\d{2}))?$/);
    if (!m) return htmlspecialchars(str);
    const dt = new Date(Date.UTC(parseInt(m[1], 10), parseInt(m[2], 10) - 1, parseInt(m[3], 10), parseInt(m[4], 10), parseInt(m[5], 10), parseInt(m[6] || '0', 10)));
    const parts = new Intl.DateTimeFormat('en-GB', {
        timeZone: 'Asia/Riyadh',
        year: 'numeric', month: '2-digit', day: '2-digit',
        hour: '2-digit', minute: '2-digit', second: '2-digit',
        hour12: false
    }).formatToParts(dt).reduce((acc, part) => (acc[part.type] = part.value, acc), {});
    let hour = parseInt(parts.hour || '0', 10);
    const ampm = hour >= 12 ? 'م' : 'ص';
    hour = hour % 12;
    if (hour === 0) hour = 12;
    const hh = String(hour).padStart(2, '0');
    return `${parts.day}/${parts.month}/${parts.year} ${hh}:${parts.minute}:${parts.second} ${ampm} (السعودية)`;
}

function showToast(msg, type = 'success') {
    const container = document.getElementById('alert-container');
    const icons = { success: 'bi-check-circle-fill', danger: 'bi-x-circle-fill', warning: 'bi-exclamation-triangle-fill', info: 'bi-info-circle-fill' };
    const alert = document.createElement('div');
    alert.className = `custom-alert alert-${type}`;
    alert.innerHTML = `<i class="bi ${icons[type] || icons.info}"></i> <span>${msg}</span>`;
    container.appendChild(alert);
    setTimeout(() => { alert.style.opacity = '0'; alert.style.transform = 'translateY(-10px)'; setTimeout(() => alert.remove(), 300); }, 4000);
}

function showLoading() { document.getElementById('loadingOverlay').classList.add('active'); }
function hideLoading() { document.getElementById('loadingOverlay').classList.remove('active'); }

async function sendAjaxRequest(action, data = {}) {
    try {
        const formData = new FormData();
        formData.append('action', action);
        formData.append('csrf_token', CSRF_TOKEN);
        for (const key in data) {
            if (data[key] !== undefined && data[key] !== null) {
                formData.append(key, data[key]);
            }
        }
        const response = await fetch(REQUEST_URL, {
            method: 'POST',
            body: formData,
            headers: { 'X-Requested-With': 'XMLHttpRequest' }
        });
        const result = await response.json();
        if (result.redirect) {
            showToast(result.message || 'يرجى تسجيل الدخول.', 'warning');
            setTimeout(() => location.reload(), 1500);
            return { success: false };
        }
        if (!result.success) {
            showToast(result.message || 'حدث خطأ.', 'danger');
        }
        return result;
    } catch (err) {
        console.error('AJAX Error:', err);
        showToast('خطأ في الاتصال بالخادم.', 'danger');
        return { success: false, message: err.message };
    }
}

function updateTable(tableEl, data, rowGenerator) {
    const tbody = tableEl.querySelector('tbody');
    if (!data || data.length === 0) {
        tbody.innerHTML = `<tr class="no-results"><td colspan="${tableEl.querySelectorAll('thead th').length}" class="text-center py-4"><i class="bi bi-inbox" style="font-size:24px;opacity:0.4;"></i><br>لا توجد بيانات</td></tr>`;
        return;
    }
    tbody.innerHTML = data.map(item => rowGenerator(item)).join('');
    // ترقيم الصفوف
    tbody.querySelectorAll('tr').forEach((row, i) => {
        const numCell = row.querySelector('.row-num');
        if (numCell) numCell.textContent = i + 1;
    });
}

function normalizeSearchText(value) {
    return String(value || '')
        .toLowerCase()
        .replace(/[ً-ٰٟ]/g, '')
        .replace(/[إأآا]/g, 'ا')
        .replace(/[ى]/g, 'ي')
        .replace(/[ؤ]/g, 'و')
        .replace(/[ئ]/g, 'ي')
        .replace(/[ة]/g, 'ه')
        .replace(/[٠-٩]/g, d => String('٠١٢٣٤٥٦٧٨٩'.indexOf(d)))
        .replace(/[^\p{L}\p{N}\s]/gu, ' ')
        .replace(/\s+/g, ' ')
        .trim();
}

function extractSearchText(value, bag = []) {
    if (value === null || value === undefined) return bag;
    if (typeof value === 'object') {
        Object.values(value).forEach(v => extractSearchText(v, bag));
        return bag;
    }
    bag.push(String(value));
    return bag;
}

function matchesSearch(item, query) {
    const normalizedQuery = normalizeSearchText(query);
    if (!normalizedQuery) return true;
    const tokens = normalizedQuery.split(' ').filter(Boolean);
    const haystack = normalizeSearchText(extractSearchText(item).join(' '));
    const compactHaystack = haystack.replace(/\s+/g, '');
    return tokens.every(t => haystack.includes(t) || compactHaystack.includes(t.replace(/\s+/g, '')));
}

function filterAndSortTable(tableEl, data, rowGenerator, filters = {}, sortCol = '', sortOrder = 'desc') {
    let filtered = [...data];

    // البحث
    if (filters.search) {
        const q = normalizeSearchText(filters.search);
        filtered = filtered.filter(item => {
            return matchesSearch(item || {}, q);
        });
    }

    // فلترة التاريخ
    if (filters.fromDate && filters.toDate) {
        const from = new Date(filters.fromDate);
        const to = new Date(filters.toDate);
        to.setHours(23, 59, 59);
        filtered = filtered.filter(item => {
            const d = new Date(item.start_date || item.queried_at || item.created_at);
            return d >= from && d <= to;
        });
    }

    // فلترة الدفع
    if (filters.typeFilter === 'paid') {
        filtered = filtered.filter(item => item.is_paid == 1);
    } else if (filters.typeFilter === 'unpaid') {
        filtered = filtered.filter(item => item.is_paid == 0);
    }

    // الفرز
    if (sortCol) {
        filtered.sort((a, b) => {
            let valA = a[sortCol], valB = b[sortCol];
            if (valA === null || valA === undefined) valA = '';
            if (valB === null || valB === undefined) valB = '';
            if (!isNaN(parseFloat(valA)) && !isNaN(parseFloat(valB))) {
                return sortOrder === 'asc' ? parseFloat(valA) - parseFloat(valB) : parseFloat(valB) - parseFloat(valA);
            }
            const dateA = new Date(valA), dateB = new Date(valB);
            if (!isNaN(dateA) && !isNaN(dateB)) {
                return sortOrder === 'asc' ? dateA - dateB : dateB - dateA;
            }
            return sortOrder === 'asc' ? String(valA).localeCompare(String(valB)) : String(valB).localeCompare(String(valA));
        });
    }

    updateTable(tableEl, filtered, rowGenerator);
}

function debounce(fn, delay = 220) {
    let timer = null;
    return (...args) => {
        clearTimeout(timer);
        timer = setTimeout(() => fn(...args), delay);
    };
}

function refreshSelectQuickSearchData(selectId) {
    const select = document.getElementById(selectId);
    if (!select) return;
    const options = Array.from(select.options).map(opt => ({
        value: opt.value,
        text: opt.textContent
    }));
    select.dataset.fullOptions = JSON.stringify(options);
}

function setupSelectQuickSearch(searchInputId, selectId) {
    const input = document.getElementById(searchInputId);
    const select = document.getElementById(selectId);
    if (!input || !select) return;

    refreshSelectQuickSearchData(selectId);

    const renderOptions = (term = '') => {
        const q = normalizeSearchText(term);
        const selectedValue = select.value;
        const allOptions = JSON.parse(select.dataset.fullOptions || '[]');
        select.innerHTML = '';
        allOptions.forEach(opt => {
            const alwaysKeep = opt.value === '' || opt.value === 'manual';
            const matches = alwaysKeep || !q || normalizeSearchText(opt.text).includes(q);
            if (!matches) return;
            const optionEl = document.createElement('option');
            optionEl.value = opt.value;
            optionEl.textContent = opt.text;
            if (opt.value === selectedValue) optionEl.selected = true;
            select.appendChild(optionEl);
        });
    };

    input.addEventListener('input', debounce((e) => renderOptions(e.target.value), 120));
}

// ======================== دوال التصدير والطباعة ========================
function exportTableToPdf(tableEl, filename, title) {
    try {
        const { jsPDF } = window.jspdf;
        const doc = new jsPDF('l', 'mm', 'a4');
        doc.setFont('helvetica');
        doc.setFontSize(16);
        doc.text(title, doc.internal.pageSize.getWidth() / 2, 15, { align: 'center' });
        doc.autoTable({ html: tableEl, startY: 25, styles: { font: 'helvetica', fontSize: 8, cellPadding: 2, halign: 'center' }, headStyles: { fillColor: [44, 62, 80], textColor: 255 }, alternateRowStyles: { fillColor: [245, 245, 245] } });
        doc.save(filename);
        showToast('تم تصدير PDF بنجاح.', 'success');
    } catch (e) { showToast('فشل تصدير PDF: ' + e.message, 'danger'); }
}

function exportTableToExcel(tableEl, filename) {
    try {
        const rows = [];
        tableEl.querySelectorAll('tr').forEach(tr => {
            const row = [];
            tr.querySelectorAll('th, td').forEach(cell => {
                if (!cell.querySelector('button')) row.push(cell.textContent.trim());
            });
            if (row.length > 0) rows.push(row);
        });
        let csv = '\uFEFF'; // BOM for Arabic
        rows.forEach(row => { csv += row.join(',') + '\n'; });
        const blob = new Blob([csv], { type: 'text/csv;charset=utf-8;' });
        const link = document.createElement('a');
        link.href = URL.createObjectURL(blob);
        link.download = filename;
        link.click();
        showToast('تم تصدير Excel بنجاح.', 'success');
    } catch (e) { showToast('فشل تصدير Excel: ' + e.message, 'danger'); }
}

function printTableContent(tableEl, title) {
    const win = window.open('', '_blank');
    win.document.write(`<html dir="rtl"><head><title>${title}</title><style>body{font-family:Cairo,sans-serif;direction:rtl}table{width:100%;border-collapse:collapse}th,td{border:1px solid #ddd;padding:6px;text-align:center;font-size:12px}th{background:#2c3e50;color:#fff}h2{text-align:center}</style></head><body><h2>${title}</h2>${tableEl.outerHTML}</body></html>`);
    win.document.close();
    win.print();
}

// ======================== دوال توليد الصفوف ========================
function generateLeaveRow(lv) {
    const companionBadge = lv.is_companion == 1 ? `<span class="badge bg-info">مرافق</span>` : `<span class="badge bg-secondary">أساسي</span>`;
    const paidBadge = lv.is_paid == 1 ? `<span class="badge bg-success">مدفوعة</span>` : `<span class="badge bg-danger">غير مدفوعة</span>`;
    return `
        <tr data-id="${lv.id}">
            <td class="row-num"></td>
            <td><strong>${htmlspecialchars(lv.service_code)}</strong></td>
            <td>${htmlspecialchars(lv.patient_name)}</td>
            <td>${htmlspecialchars(lv.identity_number)}</td>
            <td>${htmlspecialchars(lv.doctor_name)}</td>
            <td>${htmlspecialchars(lv.issue_date)}</td>
            <td>${htmlspecialchars(lv.start_date)}</td>
            <td>${htmlspecialchars(lv.end_date)}</td>
            <td>${lv.days_count}</td>
            <td>${companionBadge}</td>
            <td>${paidBadge}</td>
            <td>${parseFloat(lv.payment_amount).toFixed(2)}</td>
            <td class="cell-queries-count">${lv.queries_count || 0}
                <button class="btn btn-sm btn-outline-info action-btn btn-view-queries" data-leave-id="${lv.id}" title="عرض الاستعلامات"><i class="bi bi-eye btn-view-queries" data-leave-id="${lv.id}"></i></button>
            </td>
            <td>
                <div class="d-flex flex-wrap gap-1 justify-content-center">
                    <button class="btn btn-sm btn-gradient action-btn btn-edit-leave" data-id="${lv.id}" title="تعديل"><i class="bi bi-pencil btn-edit-leave" data-id="${lv.id}"></i></button>
                    <button class="btn btn-sm btn-warning-custom action-btn btn-duplicate-leave" data-id="${lv.id}" title="تكرار"><i class="bi bi-files btn-duplicate-leave" data-id="${lv.id}"></i></button>
                    <button class="btn btn-sm btn-outline-primary action-btn btn-add-query" data-leave-id="${lv.id}" title="تسجيل استعلام"><i class="bi bi-plus-circle btn-add-query" data-leave-id="${lv.id}"></i></button>
                    <button class="btn btn-sm btn-danger-custom action-btn btn-delete-leave" data-id="${lv.id}" title="أرشفة"><i class="bi bi-archive btn-delete-leave" data-id="${lv.id}"></i></button>
                </div>
            </td>
        </tr>`;
}

function generateArchivedLeaveRow(lv) {
    const paidBadge = lv.is_paid == 1 ? `<span class="badge bg-success">مدفوعة</span>` : `<span class="badge bg-danger">غير مدفوعة</span>`;
    return `
        <tr data-id="${lv.id}">
            <td class="row-num"></td>
            <td><strong>${htmlspecialchars(lv.service_code)}</strong></td>
            <td>${htmlspecialchars(lv.patient_name)}</td>
            <td>${htmlspecialchars(lv.identity_number)}</td>
            <td>${htmlspecialchars(lv.doctor_name)}</td>
            <td>${htmlspecialchars(lv.start_date)}</td>
            <td>${htmlspecialchars(lv.end_date)}</td>
            <td>${lv.days_count}</td>
            <td>${paidBadge}</td>
            <td>${parseFloat(lv.payment_amount).toFixed(2)}</td>
            <td>${htmlspecialchars(lv.deleted_at)}</td>
            <td class="cell-queries-count">${lv.queries_count || 0}
                <button class="btn btn-sm btn-outline-info action-btn btn-view-queries" data-leave-id="${lv.id}" title="عرض الاستعلامات"><i class="bi bi-eye btn-view-queries" data-leave-id="${lv.id}"></i></button>
            </td>
            <td>
                <button class="btn btn-sm btn-success-custom action-btn btn-restore-leave" data-id="${lv.id}" title="استعادة"><i class="bi bi-arrow-counterclockwise btn-restore-leave" data-id="${lv.id}"></i></button>
                <button class="btn btn-sm btn-danger-custom action-btn btn-force-delete" data-id="${lv.id}" title="حذف نهائي"><i class="bi bi-trash3 btn-force-delete" data-id="${lv.id}"></i></button>
            </td>
        </tr>`;
}

function generateDoctorRow(doc) {
    return `
        <tr data-id="${doc.id}">
            <td class="row-num"></td>
            <td>${htmlspecialchars(doc.name)}</td>
            <td>${htmlspecialchars(doc.title)}</td>
            <td>${htmlspecialchars(doc.note || '')}</td>
            <td>
                <button class="btn btn-sm btn-gradient action-btn btn-edit-doctor" data-id="${doc.id}" data-name="${htmlspecialchars(doc.name)}" data-title="${htmlspecialchars(doc.title)}" data-note="${htmlspecialchars(doc.note || '')}"><i class="bi bi-pencil"></i></button>
                <button class="btn btn-sm btn-danger-custom action-btn btn-delete-doctor" data-id="${doc.id}"><i class="bi bi-trash3"></i></button>
            </td>
        </tr>`;
}

function generatePatientRow(p) {
    return `
        <tr data-id="${p.id}">
            <td class="row-num"></td>
            <td>${htmlspecialchars(p.name)}</td>
            <td>${htmlspecialchars(p.identity_number)}</td>
            <td>${p.phone ? `<a href="${formatWhatsAppLink(p.phone)}" target="_blank" class="text-decoration-none"><i class="bi bi-whatsapp text-success"></i> ${htmlspecialchars(p.phone)}</a>` : ''}</td>
            <td>
                <button class="btn btn-sm btn-gradient action-btn btn-edit-patient" data-id="${p.id}" data-name="${htmlspecialchars(p.name)}" data-identity="${htmlspecialchars(p.identity_number)}" data-phone="${htmlspecialchars(p.phone || '')}"><i class="bi bi-pencil"></i></button>
                <button class="btn btn-sm btn-danger-custom action-btn btn-delete-patient" data-id="${p.id}"><i class="bi bi-trash3"></i></button>
            </td>
        </tr>`;
}

function generateQueryRow(q) {
    return `
        <tr data-id="${q.qid}">
            <td class="row-num"></td>
            <td><strong>${htmlspecialchars(q.service_code)}</strong></td>
            <td>${htmlspecialchars(q.patient_name)}</td>
            <td>${htmlspecialchars(q.identity_number)}</td>
            <td>${formatSaudiDateTime(q.queried_at)}</td>
            <td>${htmlspecialchars(q.source || 'admin')}</td>
            <td>
                <button class="btn btn-sm btn-gradient action-btn btn-view-leave-from-query" data-leave-id="${q.leave_id}"><i class="bi bi-eye btn-view-leave-from-query" data-leave-id="${q.leave_id}"></i></button>
            </td>
        </tr>`;
}

function generatePaymentPatientRow(p) {
    return `
        <tr data-id="${p.id}">
            <td class="row-num"></td>
            <td>${htmlspecialchars(p.name)}</td>
            <td>${p.total}</td>
            <td>${p.paid_count}</td>
            <td>${p.unpaid_count}</td>
            <td>${parseFloat(p.paid_amount).toFixed(2)}</td>
            <td>${parseFloat(p.unpaid_amount).toFixed(2)}</td>
            <td><button class="btn btn-info btn-sm action-btn btn-view-patient-leaves" data-patient-id="${p.id}"><i class="bi bi-eye-fill btn-view-patient-leaves" data-patient-id="${p.id}"></i> عرض</button></td>
        </tr>`;
}

function generateUserRow(u) {
    const roleBadge = u.role === 'admin' ? '<span class="badge bg-danger">مشرف</span>' : '<span class="badge bg-primary">مستخدم</span>';
    const statusBadge = u.is_active == 1 ? '<span class="badge bg-success">نشط</span>' : '<span class="badge bg-secondary">معطل</span>';
    return `
        <tr data-id="${u.id}">
            <td class="row-num"></td>
            <td>${htmlspecialchars(u.username)}</td>
            <td>${htmlspecialchars(u.display_name)}</td>
            <td>${roleBadge}</td>
            <td>${statusBadge}</td>
            <td>${formatSaudiDateTime(u.created_at)}</td>
            <td>
                <button class="btn btn-sm btn-gradient action-btn btn-edit-user" data-id="${u.id}" data-name="${htmlspecialchars(u.display_name)}" data-role="${u.role}" data-active="${u.is_active}"><i class="bi bi-pencil"></i></button>
                <button class="btn btn-sm btn-info action-btn btn-view-sessions" data-id="${u.id}" title="سجل الجلسات"><i class="bi bi-clock-history"></i></button>
                <button class="btn btn-sm btn-danger-custom action-btn btn-delete-user" data-id="${u.id}"><i class="bi bi-trash3"></i></button>
            </td>
        </tr>`;
}

function renderDetailQueries(queries) {
    const container = document.getElementById('queriesDetailsContainer');
    if (!queries || queries.length === 0) {
        container.innerHTML = '<li class="list-group-item text-center text-muted">لا توجد سجلات استعلام.</li>';
        return;
    }
    container.innerHTML = queries.map((q, i) => `
        <li class="list-group-item d-flex justify-content-between align-items-center" data-id="${q.id}">
            <div>
                <strong>#${i + 1}</strong> - ${formatSaudiDateTime(q.queried_at)}
                <span class="badge bg-secondary">${htmlspecialchars(q.source || 'admin')}</span>
            </div>
            <button class="btn btn-sm btn-danger-custom btn-delete-detail-query" data-id="${q.id}"><i class="bi bi-trash3 btn-delete-detail-query" data-id="${q.id}"></i></button>
        </li>
    `).join('');
}

function updatePaymentNotifications(notifications) {
    const list = document.getElementById('notifPaymentsList');
    const countBadge = document.getElementById('notifCount');
    countBadge.textContent = notifications ? notifications.length : 0;

    if (!notifications || notifications.length === 0) {
        list.innerHTML = '<li class="list-group-item text-center text-muted">لا توجد إشعارات.</li>';
        return;
    }

    list.innerHTML = notifications.map(n => `
        <li class="list-group-item d-flex justify-content-between align-items-center flex-wrap gap-2" data-id="${n.id}" data-leave="${n.leave_id}" data-amount="${n.payment_amount || 0}">
            <div>
                <i class="bi bi-bell-fill text-warning"></i>
                <span class="badge bg-light text-dark ms-1">${htmlspecialchars(n.service_code || '-')}</span>
                <span>${htmlspecialchars(n.message)}</span>
                <br><span class="notif-patient-name"><i class="bi bi-person"></i> ${htmlspecialchars(n.patient_name || 'غير معروف')}</span>
                <br><small class="text-muted">${formatSaudiDateTime(n.created_at)}</small>
            </div>
            <div class="d-flex gap-1">
                <button class="btn btn-sm btn-gradient btn-view-leave" title="عرض"><i class="bi bi-eye"></i></button>
                <button class="btn btn-sm btn-success-custom btn-pay-notif" title="تأكيد الدفع"><i class="bi bi-cash-coin"></i></button>
                <button class="btn btn-sm btn-danger-custom btn-del-notif" title="حذف"><i class="bi bi-trash3"></i></button>
            </div>
        </li>
    `).join('');
}

function updateStats(stats) {
    if (!stats) return;
    document.getElementById('stat-total').textContent = stats.total || 0;
    document.getElementById('stat-paid').textContent = stats.paid || 0;
    document.getElementById('stat-unpaid').textContent = stats.unpaid || 0;
    document.getElementById('stat-archived').textContent = stats.archived || 0;
    document.getElementById('stat-patients').textContent = stats.patients || 0;
    document.getElementById('stat-doctors').textContent = stats.doctors || 0;
    document.getElementById('stat-paid-amount').textContent = parseFloat(stats.paid_amount || 0).toFixed(2);
    document.getElementById('stat-unpaid-amount').textContent = parseFloat(stats.unpaid_amount || 0).toFixed(2);
}

function updateDoctorSelects(doctors) {
    const selects = ['doctor_select', 'doctor_id_edit', 'dup_doctor_select'];
    selects.forEach(selId => {
        const sel = document.getElementById(selId);
        if (!sel) return;
        const currentVal = sel.value;
        // حفظ الخيارات الثابتة
        const firstOpt = sel.querySelector('option[value=""]');
        const manualOpt = sel.querySelector('option[value="manual"]');
        sel.innerHTML = '';
        if (firstOpt) sel.appendChild(firstOpt);
        doctors.forEach(d => {
            const opt = document.createElement('option');
            opt.value = d.id;
            opt.textContent = `${d.name} (${d.title}) - ${d.note || ''}`;
            sel.appendChild(opt);
        });
        if (manualOpt) sel.appendChild(manualOpt);
        sel.value = currentVal;
        refreshSelectQuickSearchData(selId);
    });
}

function updatePatientSelects(patients) {
    const sel = document.getElementById('patient_select');
    if (!sel) return;
    const currentVal = sel.value;
    const firstOpt = sel.querySelector('option[value=""]');
    const manualOpt = sel.querySelector('option[value="manual"]');
    sel.innerHTML = '';
    if (firstOpt) sel.appendChild(firstOpt);
    patients.forEach(p => {
        const opt = document.createElement('option');
        opt.value = p.id;
        opt.textContent = `${p.name} (${p.identity_number})`;
        sel.appendChild(opt);
    });
    if (manualOpt) sel.appendChild(manualOpt);
    sel.value = currentVal;
    refreshSelectQuickSearchData('patient_select');
}

// ======================== الأحداث الرئيسية ========================
document.addEventListener('DOMContentLoaded', () => {

    // ====== تسجيل الدخول ======
    if (!IS_LOGGED_IN) {
        const loginForm = document.getElementById('loginForm');
        if (loginForm) {
            loginForm.addEventListener('submit', async (e) => {
                e.preventDefault();
                showLoading();
                const formData = new FormData();
                formData.append('action', 'login');
                formData.append('username', document.getElementById('loginUsername').value);
                formData.append('password', document.getElementById('loginPassword').value);
                try {
                    const res = await fetch(REQUEST_URL, { method: 'POST', body: formData });
                    const result = await res.json();
                    hideLoading();
                    if (result.success) {
                        showToast(result.message, 'success');
                        setTimeout(() => location.reload(), 800);
                    } else {
                        showToast(result.message, 'danger');
                    }
                } catch (err) {
                    hideLoading();
                    showToast('خطأ في الاتصال.', 'danger');
                }
            });

            // إظهار/إخفاء كلمة المرور
            document.getElementById('togglePassword').addEventListener('click', () => {
                const inp = document.getElementById('loginPassword');
                const icon = document.querySelector('#togglePassword i');
                if (inp.type === 'password') { inp.type = 'text'; icon.className = 'bi bi-eye-slash'; }
                else { inp.type = 'password'; icon.className = 'bi bi-eye'; }
            });
        }
        return; // لا نكمل إذا لم يكن مسجل الدخول
    }

    // ====== المتغيرات الرئيسية ======
    const leavesTable = document.getElementById('leavesTable');
    const archivedTable = document.getElementById('archivedTable');
    const doctorsTable = document.getElementById('doctorsTable');
    const patientsTable = document.getElementById('patientsTable');
    const queriesTable = document.getElementById('queriesTable');
    const paymentsTable = document.getElementById('paymentsTable');
    const notifPaymentsList = document.getElementById('notifPaymentsList');
    const leaveDetailsContainer = document.getElementById('leaveDetailsContainer');
    const queriesDetailsContainer = document.getElementById('queriesDetailsContainer');

    const editLeaveModal = new bootstrap.Modal(document.getElementById('editLeaveModal'));
    const duplicateLeaveModal = new bootstrap.Modal(document.getElementById('duplicateLeaveModal'));
    const confirmModal = new bootstrap.Modal(document.getElementById('confirmModal'));
    const leaveDetailsModal = new bootstrap.Modal(document.getElementById('leaveDetailsModal'));
    const viewQueriesModal = new bootstrap.Modal(document.getElementById('viewQueriesModal'));
    const paymentNotifsModal = new bootstrap.Modal(document.getElementById('paymentNotifsModal'));
    const payConfirmModal = new bootstrap.Modal(document.getElementById('payConfirmModal'));
    const editDoctorModal = new bootstrap.Modal(document.getElementById('editDoctorModal'));
    const editPatientModal = new bootstrap.Modal(document.getElementById('editPatientModal'));

    let modalStackLevel = 1060;
    function setupModalStacking(modalId) {
        const modalEl = document.getElementById(modalId);
        if (!modalEl) return;
        modalEl.addEventListener('show.bs.modal', () => {
            modalStackLevel += 20;
            modalEl.classList.add('modal-stack-active');
            modalEl.style.setProperty('--stack-z', String(modalStackLevel));
            setTimeout(() => {
                const backdrops = Array.from(document.querySelectorAll('.modal-backdrop:not(.modal-stack-active)'));
                const topBackdrop = backdrops.pop();
                if (topBackdrop) {
                    topBackdrop.classList.add('modal-stack-active');
                    topBackdrop.style.setProperty('--stack-backdrop-z', String(modalStackLevel - 5));
                }
            }, 0);
        });
        modalEl.addEventListener('hidden.bs.modal', () => {
            modalEl.classList.remove('modal-stack-active');
            if (modalStackLevel > 1060) modalStackLevel -= 20;
        });
    }

    ['editLeaveModal','duplicateLeaveModal','confirmModal','leaveDetailsModal','viewQueriesModal','paymentNotifsModal','payConfirmModal','editDoctorModal','editPatientModal','addUserModal','editUserModal','sessionsModal'].forEach(setupModalStacking);

    const confirmMessage = document.getElementById('confirmMessage');
    const confirmYesBtn = document.getElementById('confirmYesBtn');

    let currentConfirmAction = null;
    let currentConfirmId = null;
    let currentDetailQueries = [];
    let currentSessionsUserId = null;

    const currentTableData = {
        leaves: initialLeaves,
        archived: initialArchived,
        queries: initialQueries,
        doctors: initialDoctors,
        patients: initialPatients,
        payments: initialPayments,
        notifications_payment: initialNotifications,
        users: initialUsers,
        chat_users: initialChatUsers,
        chat_messages: []
    };

    function syncTableDataFromResult(result) {
        const keys = ['leaves', 'archived', 'queries', 'doctors', 'patients', 'payments', 'notifications_payment', 'users', 'chat_users', 'chat_messages'];
        keys.forEach((k) => {
            if (Object.prototype.hasOwnProperty.call(result, k) && Array.isArray(result[k])) {
                currentTableData[k] = result[k];
            }
        });
    }

    // ====== دالة جلب جميع البيانات ======
    async function fetchAllLeaves() {
        const result = await sendAjaxRequest('fetch_all_leaves', {});
        if (result.success) {
            if (Array.isArray(result.leaves)) currentTableData.leaves = result.leaves;
            if (Array.isArray(result.archived)) currentTableData.archived = result.archived;
            if (Array.isArray(result.queries)) currentTableData.queries = result.queries;
            if (Array.isArray(result.payments)) currentTableData.payments = result.payments;
            if (Array.isArray(result.notifications_payment)) currentTableData.notifications_payment = result.notifications_payment;

            applyAllCurrentFilters();

            if (result.doctors) {
                    currentTableData.doctors = result.doctors;
                    applyDoctorsFilters();
                    updateDoctorSelects(currentTableData.doctors);
                }
                if (result.stats) updateStats(result.stats);
        }
    }

    // ====== تسجيل الخروج ======
    document.getElementById('logoutBtn').addEventListener('click', async () => {
        showLoading();
        const formData = new FormData();
        formData.append('action', 'logout');
        try {
            const res = await fetch(REQUEST_URL, { method: 'POST', body: formData });
            const result = await res.json();
            hideLoading();
            if (result.success) {
                showToast(result.message, 'success');
                setTimeout(() => location.reload(), 800);
            }
        } catch (err) { hideLoading(); location.reload(); }
    });

    // ====== تحديث الكل ======
    document.getElementById('refreshAll').addEventListener('click', async () => {
        showLoading();
        await fetchAllLeaves();
        // تحديث الأطباء والمرضى
        const docRes = await sendAjaxRequest('fetch_doctors', {});
        if (docRes.success) {
            currentTableData.doctors = docRes.doctors;
            applyDoctorsFilters();
            updateDoctorSelects(currentTableData.doctors);
        }
        const patRes = await sendAjaxRequest('fetch_patients', {});
        if (patRes.success) {
            currentTableData.patients = patRes.patients;
            applyPatientsFilters();
            updatePatientSelects(currentTableData.patients);
        }
        hideLoading();
        showToast('تم تحديث جميع البيانات.', 'success');
    });

    // ====== الوضع الداكن ======
    const darkToggle = document.getElementById('darkModeToggle');
    if (localStorage.getItem('darkMode') === 'true') {
        document.body.classList.add('dark-mode');
        darkToggle.innerHTML = '<i class="bi bi-sun"></i> الوضع الفاتح';
    }
    darkToggle.addEventListener('click', () => {
        document.body.classList.toggle('dark-mode');
        const isDark = document.body.classList.contains('dark-mode');
        localStorage.setItem('darkMode', isDark);
        darkToggle.innerHTML = isDark ? '<i class="bi bi-sun"></i> الوضع الفاتح' : '<i class="bi bi-moon-stars"></i> الوضع الداكن';
    });

    // ====== إظهار/إخفاء حقول الإدخال اليدوي ======
    function togglePatientManualFields() {
        const sel = document.getElementById('patient_select');
        const fields = document.getElementById('patientManualFields');
        if (sel.value === 'manual') { fields.classList.remove('hidden-field'); }
        else { fields.classList.add('hidden-field'); }
    }

    function toggleDoctorManualFields() {
        const sel = document.getElementById('doctor_select');
        const fields = document.getElementById('doctorManualFields');
        if (sel.value === 'manual') { fields.classList.remove('hidden-field'); }
        else { fields.classList.add('hidden-field'); }
    }

    document.getElementById('patient_select').addEventListener('change', togglePatientManualFields);
    document.getElementById('doctor_select').addEventListener('change', toggleDoctorManualFields);

    setupSelectQuickSearch('patient_select_search', 'patient_select');
    setupSelectQuickSearch('doctor_select_search', 'doctor_select');
    setupSelectQuickSearch('dup_doctor_search', 'dup_doctor_select');
    setupSelectQuickSearch('doctor_id_edit_search', 'doctor_id_edit');

    // حقول المرافق في نموذج الإضافة
    const companionCheckbox = document.getElementById('is_companion');
    const companionFields = document.querySelectorAll('.companion-field');
    companionCheckbox.addEventListener('change', () => {
        companionFields.forEach(f => {
            if (companionCheckbox.checked) f.classList.remove('hidden-field');
            else f.classList.add('hidden-field');
        });
    });

    // حساب عدد الأيام تلقائياً
    function calcDays(startId, endId, daysId) {
        const start = document.getElementById(startId).value;
        const end = document.getElementById(endId).value;
        if (start && end) {
            const diff = Math.ceil((new Date(end) - new Date(start)) / (1000 * 60 * 60 * 24)) + 1;
            if (diff > 0) document.getElementById(daysId).value = diff;
        }
    }
    document.getElementById('start_date').addEventListener('change', () => calcDays('start_date', 'end_date', 'days_count'));
    document.getElementById('end_date').addEventListener('change', () => calcDays('start_date', 'end_date', 'days_count'));
    document.getElementById('start_date_edit').addEventListener('change', () => calcDays('start_date_edit', 'end_date_edit', 'days_count_edit'));
    document.getElementById('end_date_edit').addEventListener('change', () => calcDays('start_date_edit', 'end_date_edit', 'days_count_edit'));
    document.getElementById('dup_start_date').addEventListener('change', () => calcDays('dup_start_date', 'dup_end_date', 'dup_days_count'));
    document.getElementById('dup_end_date').addEventListener('change', () => calcDays('dup_start_date', 'dup_end_date', 'dup_days_count'));

    // ====== إضافة إجازة ======
    document.getElementById('addLeaveForm').addEventListener('submit', async (e) => {
        e.preventDefault();
        showLoading();
        const formData = new FormData(e.target);
        formData.append('action', 'add_leave');
        formData.append('csrf_token', CSRF_TOKEN);
        try {
            const res = await fetch(REQUEST_URL, { method: 'POST', body: formData, headers: { 'X-Requested-With': 'XMLHttpRequest' } });
            const result = await res.json();
            hideLoading();
            if (result.success) {
                showToast(result.message, 'success');
                e.target.reset();
                togglePatientManualFields();
                toggleDoctorManualFields();
                companionFields.forEach(f => f.classList.add('hidden-field'));
                syncTableDataFromResult(result);
                filtersState.leaves = { search: '', fromDate: '', toDate: '', typeFilter: '', sortCol: 'created_at', sortOrder: 'desc' };
                document.getElementById('searchLeaves').value = '';
                document.getElementById('filterFromDate').value = '';
                document.getElementById('filterToDate').value = '';
                document.getElementById('filterType').value = '';
                applyLeavesFilters();
                applyAllCurrentFilters();
                if (result.doctors) updateDoctorSelects(result.doctors);
                if (result.patients) updatePatientSelects(result.patients);
                if (result.stats) updateStats(result.stats);
                // التبديل لتبويب الإجازات
                document.getElementById('tab-leaves').click();
            } else {
                showToast(result.message, 'danger');
            }
        } catch (err) { hideLoading(); showToast('خطأ في الاتصال.', 'danger'); }
    });

    // ====== تعديل الإجازة - فتح المودال ======
    leavesTable.addEventListener('click', (e) => {
        const target = e.target.closest('.btn-edit-leave') || (e.target.classList.contains('btn-edit-leave') ? e.target : null);
        if (!target) return;
        const row = target.closest('tr');
        const leaveId = row.dataset.id;
        const leave = currentTableData.leaves.find(l => l.id == leaveId);
        if (!leave) return;

        document.getElementById('leave_id_edit').value = leave.id;
        document.getElementById('service_code_edit').value = leave.service_code;
        document.getElementById('doctor_id_edit').value = leave.doctor_id || '';
        document.getElementById('doctor_id_edit_search').value = '';
        document.getElementById('editDoctorManualFields').classList.add('hidden-field');
        document.getElementById('issue_date_edit').value = leave.issue_date;
        document.getElementById('start_date_edit').value = leave.start_date;
        document.getElementById('end_date_edit').value = leave.end_date;
        document.getElementById('days_count_edit').value = leave.days_count;
        document.getElementById('is_companion_edit').checked = leave.is_companion == 1;
        document.getElementById('companion_name_edit').value = leave.companion_name || '';
        document.getElementById('companion_relation_edit').value = leave.companion_relation || '';
        document.getElementById('is_paid_edit').checked = leave.is_paid == 1;
        document.getElementById('payment_amount_edit').value = leave.payment_amount;

        // إظهار/إخفاء حقول المرافق
        const editCompFields = document.getElementById('editCompanionFields');
        const editCompRelField = document.getElementById('editCompanionRelField');
        if (leave.is_companion == 1) {
            editCompFields.classList.remove('hidden-field');
            editCompRelField.classList.remove('hidden-field');
        } else {
            editCompFields.classList.add('hidden-field');
            editCompRelField.classList.add('hidden-field');
        }

        editLeaveModal.show();
    });

    document.getElementById('doctor_id_edit').addEventListener('change', function() {
        const fields = document.getElementById('editDoctorManualFields');
        if (this.value === 'manual') fields.classList.remove('hidden-field');
        else fields.classList.add('hidden-field');
    });

    // حقول المرافق في التعديل
    document.getElementById('is_companion_edit').addEventListener('change', function() {
        const editCompFields = document.getElementById('editCompanionFields');
        const editCompRelField = document.getElementById('editCompanionRelField');
        if (this.checked) {
            editCompFields.classList.remove('hidden-field');
            editCompRelField.classList.remove('hidden-field');
        } else {
            editCompFields.classList.add('hidden-field');
            editCompRelField.classList.add('hidden-field');
        }
    });

    // ====== حفظ تعديل الإجازة ======
    document.getElementById('saveEditLeave').addEventListener('click', async () => {
        showLoading();
        const formData = new FormData(document.getElementById('editLeaveForm'));
        formData.append('action', 'edit_leave');
        formData.append('csrf_token', CSRF_TOKEN);
        try {
            const res = await fetch(REQUEST_URL, { method: 'POST', body: formData, headers: { 'X-Requested-With': 'XMLHttpRequest' } });
            const result = await res.json();
            hideLoading();
            if (result.success) {
                showToast(result.message, 'success');
                editLeaveModal.hide();
                syncTableDataFromResult(result);
                filtersState.leaves = { search: '', fromDate: '', toDate: '', typeFilter: '', sortCol: 'created_at', sortOrder: 'desc' };
                document.getElementById('searchLeaves').value = '';
                document.getElementById('filterFromDate').value = '';
                document.getElementById('filterToDate').value = '';
                document.getElementById('filterType').value = '';
                applyAllCurrentFilters();
                if (result.patients) { currentTableData.patients = result.patients; applyPatientsFilters(); updatePatientSelects(currentTableData.patients); }
                if (result.doctors) {
                    currentTableData.doctors = result.doctors;
                    applyDoctorsFilters();
                    updateDoctorSelects(currentTableData.doctors);
                }
                if (result.stats) updateStats(result.stats);
            } else { showToast(result.message, 'danger'); }
        } catch (err) { hideLoading(); showToast('خطأ في الاتصال.', 'danger'); }
    });

    // ====== تكرار الإجازة - فتح المودال ======
    leavesTable.addEventListener('click', (e) => {
        const target = e.target.closest('.btn-duplicate-leave') || (e.target.classList.contains('btn-duplicate-leave') ? e.target : null);
        if (!target) return;
        const row = target.closest('tr');
        const leaveId = row.dataset.id;
        const leave = currentTableData.leaves.find(l => l.id == leaveId);
        if (!leave) return;

        document.getElementById('dup_patient_id').value = leave.patient_id;
        document.getElementById('dup_patient_name_display').value = `${leave.patient_name} (${leave.identity_number})`;
        document.getElementById('dup_doctor_select').value = leave.doctor_id || '';
        document.getElementById('dup_issue_date').value = leave.issue_date;
        document.getElementById('dup_start_date').value = leave.start_date;
        document.getElementById('dup_end_date').value = leave.end_date;
        document.getElementById('dup_days_count').value = leave.days_count;
        document.getElementById('dup_is_companion').checked = leave.is_companion == 1;
        document.getElementById('dup_companion_name').value = leave.companion_name || '';
        document.getElementById('dup_companion_relation').value = leave.companion_relation || '';
        document.getElementById('dup_is_paid').checked = leave.is_paid == 1;
        document.getElementById('dup_payment_amount').value = leave.payment_amount;
        document.getElementById('dup_service_code_manual').value = '';

        // إظهار/إخفاء حقول المرافق
        const dupCompFields = document.getElementById('dupCompanionFields');
        const dupCompRelField = document.getElementById('dupCompanionRelField');
        if (leave.is_companion == 1) {
            dupCompFields.classList.remove('hidden-field');
            dupCompRelField.classList.remove('hidden-field');
        } else {
            dupCompFields.classList.add('hidden-field');
            dupCompRelField.classList.add('hidden-field');
        }

        // إخفاء حقول الطبيب اليدوي
        document.getElementById('dupDoctorManualFields').classList.add('hidden-field');

        duplicateLeaveModal.show();
    });

    // حقول الطبيب اليدوي في التكرار
    document.getElementById('dup_doctor_select').addEventListener('change', function() {
        const fields = document.getElementById('dupDoctorManualFields');
        if (this.value === 'manual') fields.classList.remove('hidden-field');
        else fields.classList.add('hidden-field');
    });

    // حقول المرافق في التكرار
    document.getElementById('dup_is_companion').addEventListener('change', function() {
        const dupCompFields = document.getElementById('dupCompanionFields');
        const dupCompRelField = document.getElementById('dupCompanionRelField');
        if (this.checked) {
            dupCompFields.classList.remove('hidden-field');
            dupCompRelField.classList.remove('hidden-field');
        } else {
            dupCompFields.classList.add('hidden-field');
            dupCompRelField.classList.add('hidden-field');
        }
    });

    // ====== حفظ تكرار الإجازة ======
    document.getElementById('saveDuplicateLeave').addEventListener('click', async () => {
        showLoading();
        const formData = new FormData(document.getElementById('duplicateLeaveForm'));
        formData.append('action', 'duplicate_leave');
        formData.append('csrf_token', CSRF_TOKEN);
        try {
            const res = await fetch(REQUEST_URL, { method: 'POST', body: formData, headers: { 'X-Requested-With': 'XMLHttpRequest' } });
            const result = await res.json();
            hideLoading();
            if (result.success) {
                showToast(result.message, 'success');
                duplicateLeaveModal.hide();
                syncTableDataFromResult(result);
                filtersState.leaves = { search: '', fromDate: '', toDate: '', typeFilter: '', sortCol: 'created_at', sortOrder: 'desc' };
                document.getElementById('searchLeaves').value = '';
                document.getElementById('filterFromDate').value = '';
                document.getElementById('filterToDate').value = '';
                document.getElementById('filterType').value = '';
                applyLeavesFilters();
                applyAllCurrentFilters();
                if (result.patients) { currentTableData.patients = result.patients; applyPatientsFilters(); updatePatientSelects(currentTableData.patients); }
                if (result.doctors) {
                    currentTableData.doctors = result.doctors;
                    applyDoctorsFilters();
                    updateDoctorSelects(currentTableData.doctors);
                }
                if (result.stats) updateStats(result.stats);
            } else { showToast(result.message, 'danger'); }
        } catch (err) { hideLoading(); showToast('خطأ في الاتصال.', 'danger'); }
    });

    // ====== أرشفة إجازة ======
    leavesTable.addEventListener('click', (e) => {
        const target = e.target.closest('.btn-delete-leave') || (e.target.classList.contains('btn-delete-leave') ? e.target : null);
        if (!target) return;
        const row = target.closest('tr');
        const leaveId = row.dataset.id;
        confirmMessage.textContent = 'هل أنت متأكد من أرشفة هذه الإجازة؟';
        confirmYesBtn.textContent = 'نعم، أرشف';
        currentConfirmAction = async () => {
            showLoading();
            const result = await sendAjaxRequest('delete_leave', { leave_id: leaveId });
            hideLoading();
            if (result.success) {
                showToast(result.message, 'success');
                if (Array.isArray(result.leaves)) currentTableData.leaves = result.leaves;
                if (Array.isArray(result.archived)) currentTableData.archived = result.archived;
                if (Array.isArray(result.payments)) currentTableData.payments = result.payments;
                applyLeavesFilters();
                applyArchivedFilters();
                applyPaymentsFilters();
                if (result.stats) updateStats(result.stats);
            }
        };
        confirmModal.show();
    });

    // ====== استعادة إجازة ======
    archivedTable.addEventListener('click', (e) => {
        const target = e.target.closest('.btn-restore-leave') || (e.target.classList.contains('btn-restore-leave') ? e.target : null);
        if (!target) return;
        const row = target.closest('tr');
        const leaveId = row.dataset.id;
        confirmMessage.textContent = 'هل تريد استعادة هذه الإجازة؟';
        confirmYesBtn.textContent = 'نعم، استعد';
        currentConfirmAction = async () => {
            showLoading();
            const result = await sendAjaxRequest('restore_leave', { leave_id: leaveId });
            hideLoading();
            if (result.success) {
                showToast(result.message, 'success');
                if (Array.isArray(result.leaves)) currentTableData.leaves = result.leaves;
                if (Array.isArray(result.archived)) currentTableData.archived = result.archived;
                if (Array.isArray(result.payments)) currentTableData.payments = result.payments;
                applyLeavesFilters();
                applyArchivedFilters();
                applyPaymentsFilters();
                if (result.stats) updateStats(result.stats);
            }
        };
        confirmModal.show();
    });

    // ====== حذف نهائي ======
    archivedTable.addEventListener('click', (e) => {
        const target = e.target.closest('.btn-force-delete') || (e.target.classList.contains('btn-force-delete') ? e.target : null);
        if (!target) return;
        const row = target.closest('tr');
        const leaveId = row.dataset.id;
        confirmMessage.textContent = 'تحذير! سيتم حذف هذه الإجازة نهائياً. لا يمكن التراجع!';
        confirmYesBtn.textContent = 'نعم، احذف نهائياً';
        currentConfirmAction = async () => {
            showLoading();
            const result = await sendAjaxRequest('force_delete_leave', { leave_id: leaveId });
            hideLoading();
            if (result.success) {
                showToast(result.message, 'success');
                if (Array.isArray(result.leaves)) currentTableData.leaves = result.leaves;
                if (Array.isArray(result.archived)) currentTableData.archived = result.archived;
                applyLeavesFilters();
                applyArchivedFilters();
                if (result.stats) updateStats(result.stats);
            }
        };
        confirmModal.show();
    });

    // ====== حذف كل الأرشيف ======
    document.getElementById('deleteAllArchived').addEventListener('click', () => {
        confirmMessage.textContent = 'تحذير! سيتم حذف جميع الإجازات المؤرشفة نهائياً!';
        confirmYesBtn.textContent = 'نعم، احذف الكل';
        currentConfirmAction = async () => {
            showLoading();
            const result = await sendAjaxRequest('force_delete_all_archived', {});
            hideLoading();
            if (result.success) {
                showToast(result.message, 'success');
                if (Array.isArray(result.archived)) currentTableData.archived = result.archived;
                applyArchivedFilters();
                if (result.stats) updateStats(result.stats);
            }
        };
        confirmModal.show();
    });

    // ====== تسجيل استعلام ======
    leavesTable.addEventListener('click', async (e) => {
        const target = e.target.closest('.btn-add-query') || (e.target.classList.contains('btn-add-query') ? e.target : null);
        if (!target) return;
        const row = target.closest('tr');
        const leaveId = target.dataset.leaveId || row.dataset.id;
        const result = await sendAjaxRequest('add_query', { leave_id: leaveId });
        if (result.success) {
            showToast(result.message, 'success');
            const qCell = row.querySelector('.cell-queries-count');
            if (qCell) {
                const btn = qCell.querySelector('button');
                qCell.textContent = result.new_count + ' ';
                if (btn) qCell.appendChild(btn);
            }
            await fetchAllLeaves();
        }
    });

    // ====== عرض تفاصيل الاستعلامات ======
    leavesTable.addEventListener('click', async (e) => {
        const target = e.target.closest('.btn-view-queries') || (e.target.classList.contains('btn-view-queries') ? e.target : null);
        if (!target) return;
        const leaveId = target.dataset.leaveId;
        currentConfirmId = leaveId;
        queriesDetailsContainer.innerHTML = '<li class="list-group-item text-center">جارٍ جلب البيانات...</li>';
        viewQueriesModal.show();
        const result = await sendAjaxRequest('fetch_queries', { leave_id: leaveId });
        if (result.success) {
            currentDetailQueries = result.queries;
            renderDetailQueries(currentDetailQueries);
        } else {
            queriesDetailsContainer.innerHTML = '<li class="list-group-item text-center text-danger">فشل في جلب البيانات.</li>';
        }
    });


    archivedTable.addEventListener('click', async (e) => {
        const target = e.target.closest('.btn-view-queries') || (e.target.classList.contains('btn-view-queries') ? e.target : null);
        if (!target) return;
        const leaveId = target.dataset.leaveId;
        currentConfirmId = leaveId;
        queriesDetailsContainer.innerHTML = '<li class="list-group-item text-center">جارٍ جلب البيانات...</li>';
        viewQueriesModal.show();
        const result = await sendAjaxRequest('fetch_queries', { leave_id: leaveId });
        if (result.success) {
            currentDetailQueries = result.queries;
            renderDetailQueries(currentDetailQueries);
        } else {
            queriesDetailsContainer.innerHTML = '<li class="list-group-item text-center text-danger">فشل في جلب البيانات.</li>';
        }
    });

    // فرز استعلامات المودال
    document.getElementById('sortQueriesDetailNewest').addEventListener('click', () => {
        renderDetailQueries([...currentDetailQueries].sort((a, b) => new Date(b.queried_at) - new Date(a.queried_at)));
    });
    document.getElementById('sortQueriesDetailOldest').addEventListener('click', () => {
        renderDetailQueries([...currentDetailQueries].sort((a, b) => new Date(a.queried_at) - new Date(b.queried_at)));
    });
    document.getElementById('sortQueriesDetailReset').addEventListener('click', () => {
        renderDetailQueries(currentDetailQueries);
    });

    // حذف استعلام من التفاصيل
    queriesDetailsContainer.addEventListener('click', (e) => {
        const target = e.target.closest('.btn-delete-detail-query') || (e.target.classList.contains('btn-delete-detail-query') ? e.target : null);
        if (!target) return;
        const queryId = target.dataset.id;
        confirmMessage.textContent = 'هل أنت متأكد من حذف سجل الاستعلام هذا؟';
        confirmYesBtn.textContent = 'نعم، احذف';
        currentConfirmAction = async () => {
            const result = await sendAjaxRequest('delete_query', { query_id: queryId });
            if (result.success) {
                showToast(result.message, 'success');
                target.closest('li').remove();
                await fetchAllLeaves();
            }
        };
        confirmModal.show();
    });

    // حذف كل الاستعلامات لإجازة
    document.getElementById('btn-delete-all-queries').addEventListener('click', () => {
        const leaveId = currentConfirmId;
        confirmMessage.textContent = 'هل أنت متأكد من حذف جميع الاستعلامات لهذه الإجازة؟';
        confirmYesBtn.textContent = 'نعم، احذف الكل';
        currentConfirmAction = async () => {
            const result = await sendAjaxRequest('delete_all_queries_for_leave', { leave_id: leaveId });
            if (result.success) {
                showToast(result.message, 'success');
                queriesDetailsContainer.innerHTML = '<li class="list-group-item text-center text-muted">لا توجد سجلات.</li>';
                await fetchAllLeaves();
            }
        };
        confirmModal.show();
    });

    // ====== إشعارات المدفوعات ======
    document.getElementById('btn-payment-notifs').addEventListener('click', async () => {
        showLoading();
        const result = await sendAjaxRequest('fetch_notifications', {});
        hideLoading();
        if (result.success) {
            currentTableData.notifications_payment = result.data;
            applyNotificationsFilters();
        }
        paymentNotifsModal.show();
    });

    document.getElementById('refreshNotifs').addEventListener('click', async () => {
        showLoading();
        const result = await sendAjaxRequest('fetch_notifications', {});
        hideLoading();
        if (result.success) {
            currentTableData.notifications_payment = result.data;
            applyNotificationsFilters();
        }
    });

    // أزرار الإشعارات
    notifPaymentsList.addEventListener('click', async (e) => {
        const targetBtn = e.target.closest('.btn');
        if (!targetBtn) return;
        const listItem = targetBtn.closest('li');
        if (!listItem) return;
        const leaveId = listItem.dataset.leave;
        const notificationId = listItem.dataset.id;

        if (targetBtn.classList.contains('btn-view-leave')) {
            showLoading();
            const result = await sendAjaxRequest('fetch_leave_details', { leave_id: leaveId });
            hideLoading();
            if (result.success && result.leave) {
                const lv = result.leave;
                leaveDetailsContainer.innerHTML = `
                    <p><strong>رمز الخدمة:</strong> ${htmlspecialchars(lv.service_code)}</p>
                    <p><strong>المريض:</strong> ${htmlspecialchars(lv.patient_name)} (${htmlspecialchars(lv.identity_number)})</p>
                    <p><strong>الطبيب:</strong> ${htmlspecialchars(lv.doctor_name)} (${htmlspecialchars(lv.doctor_title)})</p>
                    <p><strong>تاريخ الإصدار:</strong> ${htmlspecialchars(lv.issue_date)}</p>
                    <p><strong>بداية الإجازة:</strong> ${htmlspecialchars(lv.start_date)}</p>
                    <p><strong>نهاية الإجازة:</strong> ${htmlspecialchars(lv.end_date)}</p>
                    <p><strong>عدد الأيام:</strong> ${lv.days_count}</p>
                    <p><strong>النوع:</strong> ${lv.is_companion == 1 ? 'مرافق: ' + htmlspecialchars(lv.companion_name) + ' (' + htmlspecialchars(lv.companion_relation) + ')' : 'أساسي'}</p>
                    <p><strong>مدفوعة:</strong> ${lv.is_paid == 1 ? 'نعم' : 'لا'}</p>
                    <p><strong>المبلغ:</strong> ${parseFloat(lv.payment_amount).toFixed(2)}</p>
                    <p><strong>تاريخ الإضافة:</strong> ${formatSaudiDateTime(lv.created_at)}</p>
                    <p><strong>تاريخ التعديل:</strong> ${htmlspecialchars(lv.updated_at || 'غير متوفر')}</p>
                    <p><strong>عدد الاستعلامات:</strong> ${lv.queries_count}</p>`;
                leaveDetailsModal.show();
            }
        } else if (targetBtn.classList.contains('btn-pay-notif')) {
            document.getElementById('payConfirmMessage').textContent = `هل تريد تأكيد دفع الإجازة؟`;
            document.getElementById('confirmPayAmount').value = listItem.dataset.amount;
            currentConfirmAction = async () => {
                const amount = document.getElementById('confirmPayAmount').value;
                showLoading();
                const result = await sendAjaxRequest('mark_leave_paid', { leave_id: leaveId, amount: amount });
                hideLoading();
                if (result.success) {
                    showToast(result.message, 'success');
                    await fetchAllLeaves();
                    const notifs = await sendAjaxRequest('fetch_notifications', {});
                    if (notifs.success) { currentTableData.notifications_payment = notifs.data; applyNotificationsFilters(); }
                }
            };
            payConfirmModal.show();
        } else if (targetBtn.classList.contains('btn-del-notif')) {
            confirmMessage.textContent = 'هل أنت متأكد من حذف هذا الإشعار؟';
            confirmYesBtn.textContent = 'نعم، حذف';
            currentConfirmAction = async () => {
                const result = await sendAjaxRequest('delete_notification', { notification_id: notificationId });
                if (result.success) {
                    showToast(result.message, 'success');
                    listItem.remove();
                    const res = await sendAjaxRequest('fetch_notifications', {});
                    if (res.success) { currentTableData.notifications_payment = res.data; applyNotificationsFilters(); }
                }
            };
            confirmModal.show();
        }
    });

    // تأكيد الدفع
    document.getElementById('confirmPayBtn').addEventListener('click', async () => {
        if (currentConfirmAction) await currentConfirmAction();
        payConfirmModal.hide();
        currentConfirmAction = null;
    });

    // زر التأكيد العام
    confirmYesBtn.addEventListener('click', async () => {
        if (currentConfirmAction) await currentConfirmAction();
        confirmModal.hide();
        currentConfirmAction = null;
        currentConfirmId = null;
        confirmYesBtn.textContent = 'تأكيد';
    });

    // ====== إدارة الأطباء ======
    document.getElementById('addDoctorForm').addEventListener('submit', async (e) => {
        e.preventDefault();
        showLoading();
        const formData = new FormData(e.target);
        formData.append('action', 'add_doctor');
        formData.append('csrf_token', CSRF_TOKEN);
        const res = await fetch(REQUEST_URL, { method: 'POST', body: formData, headers: { 'X-Requested-With': 'XMLHttpRequest' } });
        const result = await res.json();
        hideLoading();
        if (result.success) {
            showToast(result.message, 'success');
            e.target.reset();
            currentTableData.doctors = result.doctors;
            document.getElementById('searchDoctors').value = '';
            applyDoctorsFilters();
            updateDoctorSelects(currentTableData.doctors);
            if (result.stats) updateStats(result.stats);
        } else { showToast(result.message, 'danger'); }
    });

    doctorsTable.addEventListener('click', (e) => {
        const editBtn = e.target.closest('.btn-edit-doctor');
        const delBtn = e.target.closest('.btn-delete-doctor');
        if (editBtn) {
            document.getElementById('edit_doctor_id').value = editBtn.dataset.id;
            document.getElementById('edit_doctor_name').value = editBtn.dataset.name;
            document.getElementById('edit_doctor_title').value = editBtn.dataset.title;
            document.getElementById('edit_doctor_note').value = editBtn.dataset.note;
            editDoctorModal.show();
        }
        if (delBtn) {
            confirmMessage.textContent = 'هل أنت متأكد من حذف هذا الطبيب؟';
            confirmYesBtn.textContent = 'نعم، احذف';
            currentConfirmAction = async () => {
                showLoading();
                const result = await sendAjaxRequest('delete_doctor', { doctor_id: delBtn.dataset.id });
                hideLoading();
                if (result.success) {
                    showToast(result.message, 'success');
                    currentTableData.doctors = result.doctors;
                    applyDoctorsFilters();
                    updateDoctorSelects(currentTableData.doctors);
                    if (result.stats) updateStats(result.stats);
                }
            };
            confirmModal.show();
        }
    });

    document.getElementById('saveEditDoctor').addEventListener('click', async () => {
        showLoading();
        const formData = new FormData(document.getElementById('editDoctorForm'));
        formData.append('action', 'edit_doctor');
        formData.append('csrf_token', CSRF_TOKEN);
        const res = await fetch(REQUEST_URL, { method: 'POST', body: formData, headers: { 'X-Requested-With': 'XMLHttpRequest' } });
        const result = await res.json();
        hideLoading();
        if (result.success) {
            showToast(result.message, 'success');
            editDoctorModal.hide();
            currentTableData.doctors = result.doctors;
            document.getElementById('searchDoctors').value = '';
            applyDoctorsFilters();
            updateDoctorSelects(currentTableData.doctors);
        } else { showToast(result.message, 'danger'); }
    });

    // ====== إدارة المرضى ======
    document.getElementById('addPatientForm').addEventListener('submit', async (e) => {
        e.preventDefault();
        showLoading();
        const formData = new FormData(e.target);
        formData.append('action', 'add_patient');
        formData.append('csrf_token', CSRF_TOKEN);
        const res = await fetch(REQUEST_URL, { method: 'POST', body: formData, headers: { 'X-Requested-With': 'XMLHttpRequest' } });
        const result = await res.json();
        hideLoading();
        if (result.success) {
            showToast(result.message, 'success');
            e.target.reset();
            currentTableData.patients = result.patients;
            document.getElementById('searchPatients').value = '';
            applyPatientsFilters();
            updatePatientSelects(currentTableData.patients);
            if (result.stats) updateStats(result.stats);
        } else { showToast(result.message, 'danger'); }
    });

    patientsTable.addEventListener('click', (e) => {
        const editBtn = e.target.closest('.btn-edit-patient');
        const delBtn = e.target.closest('.btn-delete-patient');
        if (editBtn) {
            document.getElementById('edit_patient_id').value = editBtn.dataset.id;
            document.getElementById('edit_patient_name').value = editBtn.dataset.name;
            document.getElementById('edit_patient_identity').value = editBtn.dataset.identity;
            document.getElementById('edit_patient_phone').value = editBtn.dataset.phone;
            editPatientModal.show();
        }
        if (delBtn) {
            confirmMessage.textContent = 'هل أنت متأكد من حذف هذا المريض؟';
            confirmYesBtn.textContent = 'نعم، احذف';
            currentConfirmAction = async () => {
                showLoading();
                const result = await sendAjaxRequest('delete_patient', { patient_id: delBtn.dataset.id });
                hideLoading();
                if (result.success) {
                    showToast(result.message, 'success');
                    currentTableData.patients = result.patients;
                    applyPatientsFilters();
                    updatePatientSelects(currentTableData.patients);
                    if (result.stats) updateStats(result.stats);
                }
            };
            confirmModal.show();
        }
    });

    document.getElementById('saveEditPatient').addEventListener('click', async () => {
        showLoading();
        const formData = new FormData(document.getElementById('editPatientForm'));
        formData.append('action', 'edit_patient');
        formData.append('csrf_token', CSRF_TOKEN);
        const res = await fetch(REQUEST_URL, { method: 'POST', body: formData, headers: { 'X-Requested-With': 'XMLHttpRequest' } });
        const result = await res.json();
        hideLoading();
        if (result.success) {
            showToast(result.message, 'success');
            editPatientModal.hide();
            currentTableData.patients = result.patients;
            document.getElementById('searchPatients').value = '';
            applyPatientsFilters();
            updatePatientSelects(currentTableData.patients);
        } else { showToast(result.message, 'danger'); }
    });

    // ====== إدارة المستخدمين ======
    if (IS_ADMIN) {
        const usersTable = document.getElementById('usersTable');
        const addUserModal = new bootstrap.Modal(document.getElementById('addUserModal'));
        const editUserModal = new bootstrap.Modal(document.getElementById('editUserModal'));
        const sessionsModal = new bootstrap.Modal(document.getElementById('sessionsModal'));

        updateTable(usersTable, currentTableData.users, generateUserRow);

        // btnAddUser already opens modal via data-bs-toggle attribute

        document.getElementById('saveNewUser').addEventListener('click', async () => {
            showLoading();
            const formData = new FormData(document.getElementById('addUserForm'));
            formData.append('action', 'add_user');
            formData.append('csrf_token', CSRF_TOKEN);
            const res = await fetch(REQUEST_URL, { method: 'POST', body: formData, headers: { 'X-Requested-With': 'XMLHttpRequest' } });
            const result = await res.json();
            hideLoading();
            if (result.success) {
                showToast(result.message, 'success');
                addUserModal.hide();
                currentTableData.users = result.users;
                updateTable(usersTable, currentTableData.users, generateUserRow);
            } else { showToast(result.message, 'danger'); }
        });

        usersTable.addEventListener('click', (e) => {
            const editBtn = e.target.closest('.btn-edit-user');
            const delBtn = e.target.closest('.btn-delete-user');
            const sessBtn = e.target.closest('.btn-view-sessions');

            if (editBtn) {
                document.getElementById('edit_user_id').value = editBtn.dataset.id;
                document.getElementById('edit_user_display_name').value = editBtn.dataset.name;
                document.getElementById('edit_user_role').value = editBtn.dataset.role;
                document.getElementById('edit_user_is_active').checked = editBtn.dataset.active == 1;
                document.getElementById('edit_user_password').value = '';
                editUserModal.show();
            }
            if (delBtn) {
                confirmMessage.textContent = 'هل أنت متأكد من حذف هذا المستخدم؟';
                confirmYesBtn.textContent = 'نعم، احذف';
                currentConfirmAction = async () => {
                    showLoading();
                    const result = await sendAjaxRequest('delete_user', { user_id: delBtn.dataset.id });
                    hideLoading();
                    if (result.success) {
                        showToast(result.message, 'success');
                        currentTableData.users = result.users;
                        updateTable(usersTable, currentTableData.users, generateUserRow);
                    }
                };
                confirmModal.show();
            }
            if (sessBtn) {
                const userId = sessBtn.dataset.id;
                currentSessionsUserId = userId;
                const sessionsList = document.getElementById('sessionsListContainer');
                sessionsList.innerHTML = '<li class="list-group-item text-center">جارٍ جلب البيانات...</li>';
                sessionsModal.show();
                sendAjaxRequest('fetch_user_sessions', { user_id: userId }).then(result => {
                    if (result.success && result.sessions) {
                        if (result.sessions.length === 0) {
                            sessionsList.innerHTML = '<li class="list-group-item text-center text-muted">لا توجد جلسات مسجلة.</li>';
                        } else {
                            sessionsList.innerHTML = result.sessions.map((s, i) => `
                                <li class="list-group-item">
                                    <div class="d-flex justify-content-between align-items-center flex-wrap">
                                        <div>
                                            <strong>#${i + 1}</strong>
                                            <span class="badge bg-success">دخول</span>
                                            ${s.logout_at ? '<span class="badge bg-secondary">خروج</span>' : '<span class="badge bg-warning">نشط</span>'}
                                        </div>
                                        <div class="text-start">
                                            <small class="text-muted"><i class="bi bi-box-arrow-in-right"></i> دخول: ${htmlspecialchars(s.login_at)}</small>
                                            <br><small class="text-muted"><i class="bi bi-box-arrow-right"></i> خروج: ${s.logout_at ? htmlspecialchars(s.logout_at) : 'لم يسجل خروج'}</small>
                                            <br><small class="text-muted"><i class="bi bi-globe"></i> IP: ${htmlspecialchars(s.ip_address || 'غير متوفر')}</small>
                                        </div>
                                        <button class="btn btn-sm btn-outline-danger btn-delete-session" data-session-id="${s.id}" title="حذف الجلسة"><i class="bi bi-trash3"></i></button>
                                    </div>
                                </li>
                            `).join('');
                        }
                    } else {
                        sessionsList.innerHTML = '<li class="list-group-item text-center text-danger">فشل في جلب البيانات.</li>';
                    }
                });
            }
        });


        document.getElementById('sessionsListContainer').addEventListener('click', async (e) => {
            const btn = e.target.closest('.btn-delete-session');
            if (!btn) return;
            const sessionId = btn.dataset.sessionId;
            const result = await sendAjaxRequest('delete_user_session', { session_id: sessionId });
            if (result.success) {
                showToast(result.message, 'success');
                btn.closest('li')?.remove();
            }
        });

        document.getElementById('btnDeleteAllSessionsForUser').addEventListener('click', async () => {
            if (!currentSessionsUserId) return;
            const result = await sendAjaxRequest('delete_all_user_sessions', { user_id: currentSessionsUserId });
            if (result.success) {
                showToast(result.message, 'success');
                document.getElementById('sessionsListContainer').innerHTML = '<li class="list-group-item text-center text-muted">لا توجد جلسات مسجلة.</li>';
            }
        });

        document.getElementById('saveEditUser').addEventListener('click', async () => {
            showLoading();
            const formData = new FormData(document.getElementById('editUserForm'));
            formData.append('action', 'edit_user');
            formData.append('csrf_token', CSRF_TOKEN);
            const res = await fetch(REQUEST_URL, { method: 'POST', body: formData, headers: { 'X-Requested-With': 'XMLHttpRequest' } });
            const result = await res.json();
            hideLoading();
            if (result.success) {
                showToast(result.message, 'success');
                editUserModal.hide();
                currentTableData.users = result.users;
                updateTable(usersTable, currentTableData.users, generateUserRow);
            } else { showToast(result.message, 'danger'); }
        });
    }

    // ====== المراسلات ======
    let activeChatPeerId = null;

    function renderChatUsers(list) {
        const sel = document.getElementById('chatPeerSelect');
        if (!sel) return;
        const users = Array.isArray(list) ? list : [];
        if (users.length === 0) {
            sel.innerHTML = '<option value="">لا يوجد مستخدمون</option>';
            activeChatPeerId = null;
            return;
        }
        const prev = activeChatPeerId || sel.value;
        sel.innerHTML = '<option value="">اختر المستخدم</option>' + users.map(u => `<option value="${u.id}">${htmlspecialchars(u.display_name)} (${htmlspecialchars(u.username)})</option>`).join('');
        if (prev && users.some(u => String(u.id) === String(prev))) {
            sel.value = prev;
            activeChatPeerId = String(prev);
        }
    }

    function renderChatMessages(list) {
        const box = document.getElementById('chatMessagesBox');
        if (!box) return;
        const me = String(<?php echo intval($_SESSION['admin_user_id'] ?? 0); ?>);
        const rows = (list || []).map(m => {
            const mine = String(m.sender_id) === me;
            return `<div class="mb-2 d-flex ${mine ? 'justify-content-start' : 'justify-content-end'}"><div class="p-2 rounded" style="max-width:78%; background:${mine ? '#d1e7dd' : '#e2e3e5'}"><div class="small fw-bold">${htmlspecialchars(m.sender_name || '')}</div><div>${htmlspecialchars(m.message_text || '')}</div><div class="small text-muted">${formatSaudiDateTime(m.created_at)}</div></div></div>`;
        }).join('');
        box.innerHTML = rows || '<div class="text-muted text-center mt-4">لا توجد رسائل بعد.</div>';
        box.scrollTop = box.scrollHeight;
    }

    async function refreshChatUsers() {
        const result = await sendAjaxRequest('fetch_chat_users', {});
        if (result.success) {
            currentTableData.chat_users = result.users || [];
            renderChatUsers(currentTableData.chat_users);
        }
    }

    async function loadChatMessages() {
        if (!activeChatPeerId) return;
        const result = await sendAjaxRequest('fetch_messages', { peer_id: activeChatPeerId });
        if (result.success) {
            currentTableData.chat_messages = result.messages || [];
            renderChatMessages(currentTableData.chat_messages);
        }
    }

    // ====== البحث والفلترة ======
    const filtersState = {
        leaves: { search: '', fromDate: '', toDate: '', typeFilter: '', sortCol: 'created_at', sortOrder: 'desc' },
        archived: { search: '' },
        queries: { search: '', fromDate: '', toDate: '', sortMode: 'newest' },
        doctors: { search: '' },
        patients: { search: '' },
        payments: { search: '', sortCol: '', sortOrder: 'desc' },
        notifications: { search: '', sortMode: 'newest' }
    };

    function applyLeavesFilters() {
        filterAndSortTable(leavesTable, currentTableData.leaves, generateLeaveRow, {
            search: filtersState.leaves.search,
            fromDate: filtersState.leaves.fromDate,
            toDate: filtersState.leaves.toDate,
            typeFilter: filtersState.leaves.typeFilter
        }, filtersState.leaves.sortCol, filtersState.leaves.sortOrder);
    }

    function applyPaymentsFilters() {
        filterAndSortTable(paymentsTable, currentTableData.payments, generatePaymentPatientRow, {
            search: filtersState.payments.search
        }, filtersState.payments.sortCol, filtersState.payments.sortOrder);
    }

    function applyArchivedFilters() {
        filterAndSortTable(archivedTable, currentTableData.archived, generateArchivedLeaveRow, { search: filtersState.archived.search });
    }

    function applyQueriesFilters() {
        let queries = [...(currentTableData.queries || [])];
        const search = normalizeSearchText(filtersState.queries.search || '');
        if (search) {
            queries = queries.filter(q => matchesSearch(q || {}, search));
        }
        if (filtersState.queries.fromDate && filtersState.queries.toDate) {
            const from = new Date(filtersState.queries.fromDate);
            const to = new Date(filtersState.queries.toDate);
            to.setHours(23, 59, 59, 999);
            queries = queries.filter(q => {
                const d = new Date(String(q.queried_at || '').replace(' ', 'T'));
                return !isNaN(d) && d >= from && d <= to;
            });
        }
        if (filtersState.queries.sortMode === 'oldest') {
            queries.sort((a, b) => new Date(String(a.queried_at || '').replace(' ', 'T')) - new Date(String(b.queried_at || '').replace(' ', 'T')));
        } else {
            queries.sort((a, b) => new Date(String(b.queried_at || '').replace(' ', 'T')) - new Date(String(a.queried_at || '').replace(' ', 'T')));
        }
        updateTable(queriesTable, queries, generateQueryRow);
    }

    function applyDoctorsFilters() {
        filterAndSortTable(doctorsTable, currentTableData.doctors, generateDoctorRow, { search: filtersState.doctors.search });
    }

    function applyPatientsFilters() {
        filterAndSortTable(patientsTable, currentTableData.patients, generatePatientRow, { search: filtersState.patients.search });
    }

    function applyAllCurrentFilters() {
        applyLeavesFilters();
        applyArchivedFilters();
        applyQueriesFilters();
        applyDoctorsFilters();
        applyPatientsFilters();
        applyPaymentsFilters();
        applyNotificationsFilters();
    }

    function applyNotificationsFilters() {
        let data = [...(currentTableData.notifications_payment || [])];
        const search = normalizeSearchText(filtersState.notifications.search || '');
        if (search) {
            data = data.filter(n => matchesSearch(n || {}, search));
        }

        if (filtersState.notifications.sortMode === 'oldest') {
            data.sort((a, b) => new Date(a.created_at) - new Date(b.created_at));
        } else if (filtersState.notifications.sortMode === 'mostRepeated') {
            const repeats = currentTableData.leaves.reduce((acc, lv) => {
                const key = lv.patient_id;
                acc[key] = (acc[key] || 0) + 1;
                return acc;
            }, {});
            data.sort((a, b) => {
                const ca = repeats[a.patient_id] || 0;
                const cb = repeats[b.patient_id] || 0;
                return cb - ca || new Date(b.created_at) - new Date(a.created_at);
            });
        } else {
            data.sort((a, b) => new Date(b.created_at) - new Date(a.created_at));
        }

        updatePaymentNotifications(data);
    }

    document.getElementById('searchLeaves').addEventListener('input', debounce(function() {
        filtersState.leaves.search = this.value;
        applyLeavesFilters();
    }));

    document.getElementById('searchArchived').addEventListener('input', debounce(function() {
        filtersState.archived.search = this.value;
        applyArchivedFilters();
    }));

    document.getElementById('searchQueries').addEventListener('input', debounce(function() {
        filtersState.queries.search = this.value;
        applyQueriesFilters();
    }));

    document.getElementById('searchDoctors').addEventListener('input', debounce(function() {
        filtersState.doctors.search = this.value;
        applyDoctorsFilters();
    }));

    document.getElementById('searchPatients').addEventListener('input', debounce(function() {
        filtersState.patients.search = this.value;
        applyPatientsFilters();
    }));

    document.getElementById('searchPayments').addEventListener('input', debounce(function() {
        filtersState.payments.search = this.value;
        applyPaymentsFilters();
    }));

    document.getElementById('showPaidLeaves').addEventListener('click', () => { filtersState.leaves.typeFilter = 'paid'; applyLeavesFilters(); });
    document.getElementById('showUnpaidLeaves').addEventListener('click', () => { filtersState.leaves.typeFilter = 'unpaid'; applyLeavesFilters(); });
    document.getElementById('showAllLeaves').addEventListener('click', () => { filtersState.leaves.typeFilter = ''; applyLeavesFilters(); });
    document.getElementById('sortLeavesNewest').addEventListener('click', () => { filtersState.leaves.sortCol = 'created_at'; filtersState.leaves.sortOrder = 'desc'; applyLeavesFilters(); });
    document.getElementById('sortLeavesOldest').addEventListener('click', () => { filtersState.leaves.sortCol = 'created_at'; filtersState.leaves.sortOrder = 'asc'; applyLeavesFilters(); });
    document.getElementById('sortLeavesReset').addEventListener('click', () => {
        filtersState.leaves = { search: '', fromDate: '', toDate: '', typeFilter: '', sortCol: 'created_at', sortOrder: 'desc' };
        document.getElementById('searchLeaves').value = '';
        document.getElementById('filterFromDate').value = '';
        document.getElementById('filterToDate').value = '';
        document.getElementById('filterType').value = '';
        applyLeavesFilters();
    });

    // فلترة بالتاريخ
    document.getElementById('filterLeavesBtn').addEventListener('click', () => {
        filtersState.leaves.fromDate = document.getElementById('filterFromDate').value;
        filtersState.leaves.toDate = document.getElementById('filterToDate').value;
        filtersState.leaves.typeFilter = document.getElementById('filterType').value;
        filtersState.leaves.search = document.getElementById('searchLeaves').value;
        applyLeavesFilters();
    });

    document.getElementById('resetFilterBtn').addEventListener('click', () => {
        filtersState.leaves = { search: '', fromDate: '', toDate: '', typeFilter: '', sortCol: 'created_at', sortOrder: 'desc' };
        document.getElementById('filterFromDate').value = '';
        document.getElementById('filterToDate').value = '';
        document.getElementById('filterType').value = '';
        document.getElementById('searchLeaves').value = '';
        applyLeavesFilters();
    });

    document.getElementById('sortPaymentsPaid').addEventListener('click', () => {
        filtersState.payments.sortCol = 'paid_amount';
        filtersState.payments.sortOrder = 'desc';
        applyPaymentsFilters();
    });
    document.getElementById('sortPaymentsUnpaid').addEventListener('click', () => {
        filtersState.payments.sortCol = 'unpaid_amount';
        filtersState.payments.sortOrder = 'desc';
        applyPaymentsFilters();
    });
    document.getElementById('sortPaymentsMostLeaves').addEventListener('click', () => {
        filtersState.payments.sortCol = 'total';
        filtersState.payments.sortOrder = 'desc';
        applyPaymentsFilters();
    });
    document.getElementById('sortPaymentsLeastLeaves').addEventListener('click', () => {
        filtersState.payments.sortCol = 'total';
        filtersState.payments.sortOrder = 'asc';
        applyPaymentsFilters();
    });
    document.getElementById('sortPaymentsReset').addEventListener('click', () => {
        filtersState.payments.sortCol = 'total';
        filtersState.payments.sortOrder = 'desc';
        applyPaymentsFilters();
    });

    document.getElementById('sortQueriesNewest').addEventListener('click', () => { filtersState.queries.sortMode = 'newest'; applyQueriesFilters(); });
    document.getElementById('sortQueriesOldest').addEventListener('click', () => { filtersState.queries.sortMode = 'oldest'; applyQueriesFilters(); });
    document.getElementById('sortQueriesReset').addEventListener('click', () => {
        filtersState.queries = { search: '', fromDate: '', toDate: '', sortMode: 'newest' };
        document.getElementById('searchQueries').value = '';
        document.getElementById('filterQueriesFrom').value = '';
        document.getElementById('filterQueriesTo').value = '';
        applyQueriesFilters();
    });

    // فلترة الاستعلامات بالتاريخ
    document.getElementById('filterQueriesBtn').addEventListener('click', () => {
        filtersState.queries.fromDate = document.getElementById('filterQueriesFrom').value;
        filtersState.queries.toDate = document.getElementById('filterQueriesTo').value;
        filtersState.queries.search = document.getElementById('searchQueries').value;
        applyQueriesFilters();
    });

    document.getElementById('resetQueriesFilterBtn').addEventListener('click', () => {
        filtersState.queries = { search: '', fromDate: '', toDate: '', sortMode: 'newest' };
        document.getElementById('filterQueriesFrom').value = '';
        document.getElementById('filterQueriesTo').value = '';
        document.getElementById('searchQueries').value = '';
        applyQueriesFilters();
    });

    document.getElementById('searchNotifs').addEventListener('input', debounce(function() {
        filtersState.notifications.search = this.value;
        applyNotificationsFilters();
    }));
    document.getElementById('sortNotifsNewest').addEventListener('click', () => { filtersState.notifications.sortMode = 'newest'; applyNotificationsFilters(); });
    document.getElementById('sortNotifsOldest').addEventListener('click', () => { filtersState.notifications.sortMode = 'oldest'; applyNotificationsFilters(); });
    document.getElementById('sortNotifsMostRepeated').addEventListener('click', () => { filtersState.notifications.sortMode = 'mostRepeated'; applyNotificationsFilters(); });
    document.getElementById('sortNotifsReset').addEventListener('click', () => {
        filtersState.notifications = { search: '', sortMode: 'newest' };
        document.getElementById('searchNotifs').value = '';
        applyNotificationsFilters();
    });


    document.getElementById('btn-search-leaves').addEventListener('click', () => applyLeavesFilters());
    document.getElementById('btn-search-archived').addEventListener('click', () => {
        filtersState.archived.search = document.getElementById('searchArchived').value;
        applyArchivedFilters();
    });
    document.getElementById('btn-search-queries').addEventListener('click', () => {
        filtersState.queries.search = document.getElementById('searchQueries').value;
        applyQueriesFilters();
    });
    document.getElementById('btn-search-payments').addEventListener('click', () => applyPaymentsFilters());
    document.getElementById('btn-search-notifs').addEventListener('click', () => applyNotificationsFilters());

    document.getElementById('btn-search-doctors')?.addEventListener('click', () => applyDoctorsFilters());
    document.getElementById('btn-search-patients')?.addEventListener('click', () => applyPatientsFilters());

    const deleteAllQueriesBtn = document.getElementById('deleteAllQueriesBtn') || document.getElementById('deleteAllQueries');
    if (deleteAllQueriesBtn) {
        deleteAllQueriesBtn.addEventListener('click', () => {
            confirmMessage.textContent = 'تحذير! سيتم حذف سجل الاستعلامات نهائياً.';
            confirmYesBtn.textContent = 'نعم، احذف الكل';
            currentConfirmAction = async () => {
                const result = await sendAjaxRequest('delete_all_queries', {});
                if (result.success) {
                    showToast(result.message, 'success');
                    syncTableDataFromResult(result);
                    applyQueriesFilters();
                    applyLeavesFilters();
                    applyArchivedFilters();
                }
            };
            confirmModal.show();
        });
    }

    const markAllPaidBtn = document.getElementById('markAllPaidBtn');
    if (markAllPaidBtn) {
        markAllPaidBtn.addEventListener('click', () => {
            confirmMessage.textContent = 'سيتم جعل كل الإجازات النشطة مدفوعة. متابعة؟';
            confirmYesBtn.textContent = 'نعم، نفّذ';
            currentConfirmAction = async () => {
                const result = await sendAjaxRequest('mark_all_leaves_paid', {});
                if (result.success) {
                    showToast(result.message, 'success');
                    syncTableDataFromResult(result);
                    applyAllCurrentFilters();
                    if (result.stats) updateStats(result.stats);
                }
            };
            confirmModal.show();
        });
    }

    const resetAllPaymentsBtn = document.getElementById('resetAllPaymentsBtn');
    if (resetAllPaymentsBtn) {
        resetAllPaymentsBtn.addEventListener('click', () => {
            confirmMessage.textContent = 'سيتم تصفير كل المدفوعات والمستحقات. متابعة؟';
            confirmYesBtn.textContent = 'نعم، صفّر';
            currentConfirmAction = async () => {
                const result = await sendAjaxRequest('reset_all_payments', {});
                if (result.success) {
                    showToast(result.message, 'success');
                    syncTableDataFromResult(result);
                    applyAllCurrentFilters();
                    if (result.stats) updateStats(result.stats);
                }
            };
            confirmModal.show();
        });
    }

    renderChatUsers(currentTableData.chat_users || []);
    document.getElementById('chatUsersSearch')?.addEventListener('input', debounce(function() {
        const q = this.value;
        const filtered = (currentTableData.chat_users || []).filter(u => matchesSearch(u, q));
        renderChatUsers(filtered);
    }, 120));
    document.getElementById('chatPeerSelect')?.addEventListener('change', async function() {
        activeChatPeerId = this.value || null;
        await loadChatMessages();
    });
    document.getElementById('refreshChatUsersBtn')?.addEventListener('click', async () => { await refreshChatUsers(); });
    document.getElementById('sendChatMessageBtn')?.addEventListener('click', async () => {
        const input = document.getElementById('chatMessageInput');
        const text = (input?.value || '').trim();
        if (!activeChatPeerId || !text) return;
        const result = await sendAjaxRequest('send_message', { peer_id: activeChatPeerId, message_text: text });
        if (result.success) {
            input.value = '';
            await loadChatMessages();
        }
    });
    document.getElementById('chatMessageInput')?.addEventListener('keydown', (e) => {
        if (e.key === 'Enter') {
            e.preventDefault();
            document.getElementById('sendChatMessageBtn')?.click();
        }
    });
    setInterval(() => { if (activeChatPeerId) loadChatMessages(); }, 7000);


    // ====== التصدير والطباعة ======
    document.getElementById('exportLeavesPdf').addEventListener('click', () => exportTableToPdf(leavesTable, 'leaves.pdf', 'الإجازات الطبية'));
    document.getElementById('exportLeavesExcel').addEventListener('click', () => exportTableToExcel(leavesTable, 'leaves.csv'));
    document.getElementById('printLeaves').addEventListener('click', () => printTableContent(leavesTable, 'الإجازات الطبية'));
    document.getElementById('exportQueriesPdf').addEventListener('click', () => exportTableToPdf(queriesTable, 'queries.pdf', 'سجل الاستعلامات'));
    document.getElementById('exportQueriesExcel').addEventListener('click', () => exportTableToExcel(queriesTable, 'queries.csv'));
    document.getElementById('printQueries').addEventListener('click', () => printTableContent(queriesTable, 'سجل الاستعلامات'));
    document.getElementById('exportPaymentsPdf').addEventListener('click', () => exportTableToPdf(paymentsTable, 'payments.pdf', 'المدفوعات'));
    document.getElementById('exportPaymentsExcel').addEventListener('click', () => exportTableToExcel(paymentsTable, 'payments.csv'));
    document.getElementById('printPayments').addEventListener('click', () => printTableContent(paymentsTable, 'المدفوعات'));

    // ====== التبويبات ======
    document.querySelectorAll('.tab-link').forEach(tab => {
        tab.addEventListener('click', function(e) {
            e.preventDefault();
            document.querySelectorAll('.tab-link').forEach(t => t.classList.remove('active'));
            this.classList.add('active');
            document.querySelectorAll('.tab-content-section').forEach(s => s.classList.remove('active'));
            const target = this.dataset.tab;
            document.getElementById(target).classList.add('active');
        });
    });

    // ====== عرض إجازات المريض من المدفوعات ======
    paymentsTable.addEventListener('click', async (e) => {
        const target = e.target.closest('.btn-view-patient-leaves') || (e.target.classList.contains('btn-view-patient-leaves') ? e.target : null);
        if (!target) return;
        const patientId = target.dataset.patientId;
        showLoading();
        const result = await sendAjaxRequest('fetch_leaves_by_patient', { patient_id: patientId });
        hideLoading();
        if (result.success && result.leaves) {
            let html = '<div class="table-responsive"><table class="table table-bordered table-sm"><thead><tr><th>رمز الخدمة</th><th>تاريخ البداية</th><th>تاريخ النهاية</th><th>الأيام</th><th>الحالة</th><th>المبلغ</th><th>إجراء</th></tr></thead><tbody>';
            result.leaves.forEach(lv => {
                html += `<tr>
                    <td>${htmlspecialchars(lv.service_code)}</td>
                    <td>${htmlspecialchars(lv.start_date)}</td>
                    <td>${htmlspecialchars(lv.end_date)}</td>
                    <td>${lv.days_count}</td>
                    <td>${lv.is_paid == 1 ? '<span class="badge bg-success">مدفوعة</span>' : '<span class="badge bg-danger">غير مدفوعة</span>'}</td>
                    <td>${parseFloat(lv.payment_amount).toFixed(2)}</td>
                    <td>
                        ${lv.is_paid == 0 ? `<button class="btn btn-sm btn-success-custom btn-mark-paid-inline" data-leave-id="${lv.id}" data-amount="${lv.payment_amount}"><i class="bi bi-cash-coin"></i> تأكيد الدفع</button>` : '<span class="text-success">✓</span>'}
                    </td>
                </tr>`;
            });
            html += '</tbody></table></div>';
            leaveDetailsContainer.innerHTML = html;
            leaveDetailsModal.show();

            // أزرار الدفع المباشر
            leaveDetailsContainer.querySelectorAll('.btn-mark-paid-inline').forEach(btn => {
                btn.addEventListener('click', async () => {
                    showLoading();
                    const res = await sendAjaxRequest('mark_leave_paid', { leave_id: btn.dataset.leaveId, amount: btn.dataset.amount });
                    hideLoading();
                    if (res.success) {
                        showToast(res.message, 'success');
                        leaveDetailsModal.hide();
                        await fetchAllLeaves();
                    }
                });
            });
        }
    });

    // ====== عرض إجازة من الاستعلامات ======
    queriesTable.addEventListener('click', async (e) => {
        const target = e.target.closest('.btn-view-leave-from-query') || (e.target.classList.contains('btn-view-leave-from-query') ? e.target : null);
        if (!target) return;
        const leaveId = target.dataset.leaveId;
        showLoading();
        const result = await sendAjaxRequest('fetch_leave_details', { leave_id: leaveId });
        hideLoading();
        if (result.success && result.leave) {
            const lv = result.leave;
            leaveDetailsContainer.innerHTML = `
                <p><strong>رمز الخدمة:</strong> ${htmlspecialchars(lv.service_code)}</p>
                <p><strong>المريض:</strong> ${htmlspecialchars(lv.patient_name)} (${htmlspecialchars(lv.identity_number)})</p>
                <p><strong>الطبيب:</strong> ${htmlspecialchars(lv.doctor_name)} (${htmlspecialchars(lv.doctor_title)})</p>
                <p><strong>تاريخ الإصدار:</strong> ${htmlspecialchars(lv.issue_date)}</p>
                <p><strong>بداية الإجازة:</strong> ${htmlspecialchars(lv.start_date)}</p>
                <p><strong>نهاية الإجازة:</strong> ${htmlspecialchars(lv.end_date)}</p>
                <p><strong>عدد الأيام:</strong> ${lv.days_count}</p>
                <p><strong>النوع:</strong> ${lv.is_companion == 1 ? 'مرافق' : 'أساسي'}</p>
                <p><strong>مدفوعة:</strong> ${lv.is_paid == 1 ? 'نعم' : 'لا'}</p>
                <p><strong>المبلغ:</strong> ${parseFloat(lv.payment_amount).toFixed(2)}</p>`;
            leaveDetailsModal.show();
        }
    });

    // ====== التحميل الأولي ======
    applyAllCurrentFilters();
    updateDoctorSelects(currentTableData.doctors);
    updatePatientSelects(currentTableData.patients);

    // ====== تحديث تلقائي كل 60 ثانية ======
    setInterval(async () => {
        const result = await sendAjaxRequest('fetch_all_leaves', {});
        if (result.success) {
            if (Array.isArray(result.leaves)) currentTableData.leaves = result.leaves;
            if (Array.isArray(result.archived)) currentTableData.archived = result.archived;
            if (Array.isArray(result.queries)) currentTableData.queries = result.queries;
            if (Array.isArray(result.payments)) currentTableData.payments = result.payments;
            if (Array.isArray(result.notifications_payment)) currentTableData.notifications_payment = result.notifications_payment;
            applyAllCurrentFilters();
            if (result.stats) updateStats(result.stats);
        }
    }, 60000);

}); // نهاية DOMContentLoaded
</script>
</body>
</html>
