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

$pdo->exec("CREATE TABLE IF NOT EXISTS app_settings (
    setting_key VARCHAR(100) PRIMARY KEY,
    setting_value TEXT,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci");

function ensureColumn(PDO $pdo, string $table, string $column, string $definition): void {
    $stmt = $pdo->prepare("SELECT COUNT(*) FROM information_schema.columns WHERE table_schema = DATABASE() AND table_name = ? AND column_name = ?");
    $stmt->execute([$table, $column]);
    if ((int)$stmt->fetchColumn() === 0) {
        $pdo->exec("ALTER TABLE $table ADD COLUMN $column $definition");
    }
}

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
ensureColumn($pdo, 'patients', 'folder_link', "VARCHAR(500) NULL AFTER phone");
ensureIndex($pdo, 'doctors', 'idx_doctors_name', 'name');
ensureIndex($pdo, 'user_messages', 'idx_user_messages_pair_created', 'sender_id, receiver_id, created_at');
ensureIndex($pdo, 'user_messages', 'idx_user_messages_receiver_read', 'receiver_id, is_read');
ensureColumn($pdo, 'user_messages', 'message_type', "ENUM('text','image','file','voice') DEFAULT 'text' AFTER message_text");
ensureColumn($pdo, 'user_messages', 'file_name', "VARCHAR(255) NULL AFTER message_type");
ensureColumn($pdo, 'user_messages', 'file_path', "VARCHAR(500) NULL AFTER file_name");
ensureColumn($pdo, 'user_messages', 'mime_type', "VARCHAR(150) NULL AFTER file_path");
ensureColumn($pdo, 'user_messages', 'file_size', "INT NULL AFTER mime_type");
ensureColumn($pdo, 'user_messages', 'deleted_at', "DATETIME NULL AFTER is_read");
ensureColumn($pdo, 'user_messages', 'reply_to_id', "INT NULL AFTER deleted_at");
ensureColumn($pdo, 'user_messages', 'chat_scope', "ENUM('private','global') DEFAULT 'private' AFTER reply_to_id");
ensureColumn($pdo, 'user_messages', 'broadcast_group_id', "VARCHAR(50) NULL AFTER chat_scope");
ensureIndex($pdo, 'user_messages', 'idx_user_messages_scope_created', 'chat_scope, created_at');
ensureIndex($pdo, 'user_messages', 'idx_user_messages_broadcast', 'broadcast_group_id');
ensureIndex($pdo, 'user_messages', 'idx_user_messages_deleted', 'deleted_at');

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

function getSetting(PDO $pdo, string $key, ?string $default = null): ?string {
    $stmt = $pdo->prepare("SELECT setting_value FROM app_settings WHERE setting_key = ?");
    $stmt->execute([$key]);
    $v = $stmt->fetchColumn();
    return $v === false ? $default : (string)$v;
}

function setSetting(PDO $pdo, string $key, string $value): void {
    $stmt = $pdo->prepare("INSERT INTO app_settings (setting_key, setting_value) VALUES (?, ?) ON DUPLICATE KEY UPDATE setting_value = VALUES(setting_value)");
    $stmt->execute([$key, $value]);
}

function sanitizeHexColor(string $color, string $fallback): string {
    $color = trim($color);
    if (preg_match('/^#([0-9a-fA-F]{6})$/', $color)) return strtolower($color);
    if (preg_match('/^#([0-9a-fA-F]{3})$/', $color)) {
        $c = strtolower($color);
        return '#' . $c[1] . $c[1] . $c[2] . $c[2] . $c[3] . $c[3];
    }
    return $fallback;
}

function getUnreadMessagesCount(PDO $pdo, int $userId): int {
    if ($userId <= 0) return 0;
    $stmt = $pdo->prepare("SELECT COUNT(*) FROM user_messages WHERE receiver_id = ? AND is_read = 0 AND deleted_at IS NULL");
    $stmt->execute([$userId]);
    return intval($stmt->fetchColumn());
}

function purgeExpiredMessages(PDO $pdo): void {
    $hours = intval(getSetting($pdo, 'chat_retention_hours', '0'));
    if ($hours <= 0) return;
    $threshold = (new DateTime('now', new DateTimeZone('Asia/Riyadh')))->modify("-{$hours} hours")->format('Y-m-d H:i:s');
    $stmt = $pdo->prepare("SELECT id, file_path FROM user_messages WHERE deleted_at IS NULL AND created_at <= ?");
    $stmt->execute([$threshold]);
    $rows = $stmt->fetchAll();
    if (!$rows) return;
    foreach ($rows as $r) {
        if (!empty($r['file_path'])) {
            $full = __DIR__ . '/' . ltrim($r['file_path'], '/');
            if (is_file($full)) @unlink($full);
        }
    }
    $pdo->prepare("UPDATE user_messages SET deleted_at = ? WHERE deleted_at IS NULL AND created_at <= ?")->execute([nowSaudi(), $threshold]);
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

    $stmt = $pdo->query("SELECT service_code FROM sick_leaves ORDER BY id DESC LIMIT 1");
    $last = $stmt->fetchColumn();
    $num = 1;
    if ($last && preg_match('/^(?:GSL|PSL)\d{6}(\d+)$/', $last, $m)) {
        $num = intval($m[1]) + 1;
    }

    return $prefix . $datePart . str_pad((string)$num, 5, '0', STR_PAD_LEFT);
}


function fetchAllData($pdo) {
    ensureDelayedUnpaidNotifications($pdo);
    purgeExpiredMessages($pdo);
    // الإجازات النشطة
    $leaves = $pdo->query(" 
        SELECT sl.*, p.name AS patient_name, p.identity_number, p.phone AS patient_phone, p.folder_link AS patient_folder_link,
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
        SELECT sl.*, p.name AS patient_name, p.identity_number, p.phone AS patient_phone, p.folder_link AS patient_folder_link,
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
        SELECT n.*, sl.payment_amount, sl.service_code, sl.patient_id, p.name AS patient_name, p.phone AS patient_phone
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
    purgeExpiredMessages($pdo);
    $leaves = $pdo->query(" 
        SELECT sl.*, p.name AS patient_name, p.identity_number, p.phone AS patient_phone, p.folder_link AS patient_folder_link,
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
        SELECT n.*, sl.payment_amount, sl.service_code, sl.patient_id, p.name AS patient_name, p.phone AS patient_phone
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
          AND sl.created_at <= (NOW() - INTERVAL 5 MINUTE)
          AND n.id IS NULL
    ");
    $stmt->execute();
    $rows = $stmt->fetchAll();
    if (!$rows) return;

    $ins = $pdo->prepare("INSERT INTO notifications (type, leave_id, message, created_at) VALUES ('payment', ?, ?, ?)");
    foreach ($rows as $row) {
        $ins->execute([
            $row['id'],
            "إجازة غير مدفوعة منذ أكثر من 5 دقائق برمز {$row['service_code']} بمبلغ {$row['payment_amount']}",
            nowSaudi()
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
            $data['unread_messages_count'] = getUnreadMessagesCount($pdo, intval($_SESSION['admin_user_id'] ?? 0));
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
                $pFolderLink = trim($_POST['patient_manual_folder_link'] ?? '');
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
                    $stmt = $pdo->prepare("INSERT INTO patients (name, identity_number, phone, folder_link) VALUES (?, ?, ?, ?)");
                    $stmt->execute([$pName, $pIdentity, $pPhone, $pFolderLink]);
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
                $stmt = $pdo->prepare("INSERT INTO notifications (type, leave_id, message, created_at) VALUES ('payment', ?, ?, ?)");
                $stmt->execute([$leaveId, "إجازة جديدة غير مدفوعة برمز $service_code بمبلغ $payment_amount", nowSaudi()]);
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
                $stmt = $pdo->prepare("INSERT INTO notifications (type, leave_id, message, created_at) VALUES ('payment', ?, ?, ?)");
                $stmt->execute([$leaveId, "إجازة مكررة غير مدفوعة برمز $service_code بمبلغ $payment_amount", nowSaudi()]);
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
            $folder_link = trim($_POST['folder_link'] ?? '');
            if (empty($name) || empty($identity)) {
                echo json_encode(['success' => false, 'message' => 'يرجى إدخال اسم المريض ورقم هويته.']);
                exit;
            }
            $stmt = $pdo->prepare("INSERT INTO patients (name, identity_number, phone, folder_link) VALUES (?, ?, ?, ?)");
            $stmt->execute([$name, $identity, $phone, $folder_link]);
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
            $folder_link = trim($_POST['folder_link'] ?? '');
            if ($id <= 0 || empty($name) || empty($identity)) {
                echo json_encode(['success' => false, 'message' => 'بيانات غير صالحة.']);
                exit;
            }
            $stmt = $pdo->prepare("UPDATE patients SET name = ?, identity_number = ?, phone = ?, folder_link = ? WHERE id = ?");
            $stmt->execute([$name, $identity, $phone, $folder_link, $id]);
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
                SELECT sl.*, p.name AS patient_name, p.identity_number, p.folder_link AS patient_folder_link,
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


        case 'fetch_admin_statistics':
            $role = $_SESSION['admin_role'] ?? 'user';
            $canViewFinancial = ($role === 'admin');

            $rangeDays = max(1, min(365, intval($_POST['range_days'] ?? 30)));
            $fromDate = trim($_POST['from_date'] ?? '');
            $toDate = trim($_POST['to_date'] ?? '');
            if (!preg_match('/^\d{4}-\d{2}-\d{2}$/', $fromDate)) {
                $fromDate = date('Y-m-d', strtotime("-" . ($rangeDays - 1) . " days"));
            }
            if (!preg_match('/^\d{4}-\d{2}-\d{2}$/', $toDate)) {
                $toDate = date('Y-m-d');
            }
            if ($fromDate > $toDate) {
                [$fromDate, $toDate] = [$toDate, $fromDate];
            }

            $summary = [
                'can_view_financial' => $canViewFinancial,
                'range_days' => $rangeDays,
                'from_date' => $fromDate,
                'to_date' => $toDate,
                'totals' => getStats($pdo),
                'today_total' => 0,
                'today_paid' => 0,
                'today_unpaid' => 0,
                'avg_daily' => 0,
                'consistency_rate' => 0,
                'top_doctors' => [],
                'top_patients' => [],
                'daily' => []
            ];

            $summary['today_total'] = (int)$pdo->query("SELECT COUNT(*) FROM sick_leaves WHERE deleted_at IS NULL AND DATE(created_at) = CURDATE()")->fetchColumn();
            $summary['today_paid'] = (int)$pdo->query("SELECT COUNT(*) FROM sick_leaves WHERE deleted_at IS NULL AND is_paid = 1 AND DATE(created_at) = CURDATE()")->fetchColumn();
            $summary['today_unpaid'] = (int)$pdo->query("SELECT COUNT(*) FROM sick_leaves WHERE deleted_at IS NULL AND is_paid = 0 AND DATE(created_at) = CURDATE()")->fetchColumn();

            $avgStmt = $pdo->prepare("SELECT COALESCE(AVG(day_count),0) FROM (SELECT DATE(created_at) d, COUNT(*) day_count FROM sick_leaves WHERE deleted_at IS NULL AND DATE(created_at) BETWEEN ? AND ? GROUP BY DATE(created_at)) t");
            $avgStmt->execute([$fromDate, $toDate]);
            $summary['avg_daily'] = (float)$avgStmt->fetchColumn();

            $consistencyStmt = $pdo->prepare("SELECT (COUNT(DISTINCT DATE(created_at)) * 100.0 / GREATEST(DATEDIFF(?, ?) + 1, 1)) FROM sick_leaves WHERE deleted_at IS NULL AND DATE(created_at) BETWEEN ? AND ?");
            $consistencyStmt->execute([$toDate, $fromDate, $fromDate, $toDate]);
            $summary['consistency_rate'] = round((float)$consistencyStmt->fetchColumn(), 2);

            $topDoctorsStmt = $pdo->prepare("SELECT d.name, d.title, COUNT(*) leaves_count FROM sick_leaves sl LEFT JOIN doctors d ON d.id = sl.doctor_id WHERE sl.deleted_at IS NULL AND DATE(sl.created_at) BETWEEN ? AND ? GROUP BY sl.doctor_id ORDER BY leaves_count DESC LIMIT 5");
            $topDoctorsStmt->execute([$fromDate, $toDate]);
            $summary['top_doctors'] = $topDoctorsStmt->fetchAll();

            $topPatientsStmt = $pdo->prepare("SELECT p.name, p.identity_number, COUNT(*) leaves_count, SUM(CASE WHEN sl.is_paid = 1 THEN sl.payment_amount ELSE 0 END) paid_amount, SUM(CASE WHEN sl.is_paid = 0 THEN sl.payment_amount ELSE 0 END) unpaid_amount FROM sick_leaves sl LEFT JOIN patients p ON p.id = sl.patient_id WHERE sl.deleted_at IS NULL AND DATE(sl.created_at) BETWEEN ? AND ? GROUP BY sl.patient_id ORDER BY leaves_count DESC LIMIT 5");
            $topPatientsStmt->execute([$fromDate, $toDate]);
            $summary['top_patients'] = $topPatientsStmt->fetchAll();

            $dailyStmt = $pdo->prepare("SELECT DATE(created_at) day_date, COUNT(*) total_count, SUM(CASE WHEN is_paid = 1 THEN 1 ELSE 0 END) paid_count, SUM(CASE WHEN is_paid = 0 THEN 1 ELSE 0 END) unpaid_count FROM sick_leaves WHERE deleted_at IS NULL AND DATE(created_at) BETWEEN ? AND ? GROUP BY DATE(created_at) ORDER BY day_date DESC");
            $dailyStmt->execute([$fromDate, $toDate]);
            $summary['daily'] = $dailyStmt->fetchAll();

            if (!$canViewFinancial) {
                $summary['totals']['paid_amount'] = null;
                $summary['totals']['unpaid_amount'] = null;
                foreach ($summary['top_patients'] as &$tp) {
                    $tp['paid_amount'] = null;
                    $tp['unpaid_amount'] = null;
                }
                unset($tp);
            }

            echo json_encode(['success' => true, 'data' => $summary]);
            break;

        case 'fetch_notifications':
            ensureDelayedUnpaidNotifications($pdo);
            $notifications = $pdo->query(" 
                SELECT n.*, sl.payment_amount, sl.service_code, sl.patient_id, p.name AS patient_name, p.phone AS patient_phone
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


        case 'fetch_unread_messages_count':
            echo json_encode(['success' => true, 'count' => getUnreadMessagesCount($pdo, intval($_SESSION['admin_user_id'] ?? 0))]);
            break;

        case 'fetch_chat_users':
            $currentUserId = intval($_SESSION['admin_user_id'] ?? 0);
            $stmt = $pdo->prepare("SELECT id, username, display_name, role FROM admin_users WHERE is_active = 1 AND id <> ? ORDER BY display_name");
            $stmt->execute([$currentUserId]);
            $users = $stmt->fetchAll();
            $maxUploadMB = 50;
            echo json_encode([
                'success' => true,
                'users' => $users,
                'chat_retention_hours' => intval(getSetting($pdo, 'chat_retention_hours', '0')),
                'unread_messages_count' => getUnreadMessagesCount($pdo, intval($_SESSION['admin_user_id'] ?? 0)),
                'max_upload_mb' => $maxUploadMB
            ]);
            break;

        case 'fetch_messages':
            $peerRaw = trim((string)($_POST['peer_id'] ?? ''));
            $me = intval($_SESSION['admin_user_id'] ?? 0);
            $isAdmin = (($_SESSION['admin_role'] ?? 'user') === 'admin');
            if ($peerRaw === '' || $me <= 0) {
                echo json_encode(['success' => false, 'message' => 'مستخدم غير صالح.']);
                break;
            }

            if ($peerRaw === '__monitor__') {
                if (!$isAdmin) {
                    echo json_encode(['success' => false, 'message' => 'ليس لديك صلاحية.']);
                    break;
                }
                $stmt = $pdo->query("
                    SELECT um.*,
                           s.display_name AS sender_name,
                           r.display_name AS receiver_name,
                           rp.message_text AS reply_message_text,
                           rp.file_name AS reply_file_name
                    FROM user_messages um
                    LEFT JOIN admin_users s ON um.sender_id = s.id
                    LEFT JOIN admin_users r ON um.receiver_id = r.id
                    LEFT JOIN user_messages rp ON um.reply_to_id = rp.id
                    WHERE um.deleted_at IS NULL
                      AND (um.chat_scope = 'private' OR (um.chat_scope = 'global' AND um.receiver_id = um.sender_id))
                    ORDER BY um.created_at DESC, um.id DESC
                    LIMIT 800
                ");
                $messages = array_reverse($stmt->fetchAll());
                echo json_encode(['success' => true, 'messages' => $messages]);
                break;
            }

            if ($peerRaw === '__all__') {
                $stmt = $pdo->prepare("
                    SELECT um.*,
                           s.display_name AS sender_name,
                           r.display_name AS receiver_name,
                           rp.message_text AS reply_message_text,
                           rp.file_name AS reply_file_name
                    FROM user_messages um
                    LEFT JOIN admin_users s ON um.sender_id = s.id
                    LEFT JOIN admin_users r ON um.receiver_id = r.id
                    LEFT JOIN user_messages rp ON um.reply_to_id = rp.id
                    WHERE um.deleted_at IS NULL
                      AND um.chat_scope = 'global'
                      AND um.receiver_id = ?
                    ORDER BY um.created_at ASC, um.id ASC
                    LIMIT 800
                ");
                $stmt->execute([$me]);
                $messages = $stmt->fetchAll();
                $pdo->prepare("UPDATE user_messages SET is_read = 1 WHERE receiver_id = ? AND chat_scope = 'global' AND is_read = 0")
                    ->execute([$me]);
                echo json_encode(['success' => true, 'messages' => $messages]);
                break;
            }

            $peerId = intval($peerRaw);
            if ($peerId <= 0) {
                echo json_encode(['success' => false, 'message' => 'مستخدم غير صالح.']);
                break;
            }
            $stmt = $pdo->prepare("
                SELECT um.*,
                       s.display_name AS sender_name,
                       r.display_name AS receiver_name,
                       rp.message_text AS reply_message_text,
                       rp.file_name AS reply_file_name
                FROM user_messages um
                LEFT JOIN admin_users s ON um.sender_id = s.id
                LEFT JOIN admin_users r ON um.receiver_id = r.id
                LEFT JOIN user_messages rp ON um.reply_to_id = rp.id
                WHERE um.deleted_at IS NULL AND um.chat_scope = 'private' AND ((um.sender_id = ? AND um.receiver_id = ?)
                   OR (um.sender_id = ? AND um.receiver_id = ?))
                ORDER BY um.created_at ASC, um.id ASC
                LIMIT 500
            ");
            $stmt->execute([$me, $peerId, $peerId, $me]);
            $messages = $stmt->fetchAll();
            $pdo->prepare("UPDATE user_messages SET is_read = 1 WHERE receiver_id = ? AND sender_id = ? AND chat_scope = 'private' AND is_read = 0")
                ->execute([$me, $peerId]);
            echo json_encode(['success' => true, 'messages' => $messages]);
            break;

        case 'send_message':
            $peerRaw = trim((string)($_POST['peer_id'] ?? ''));
            $messageText = trim($_POST['message_text'] ?? '');
            $me = intval($_SESSION['admin_user_id'] ?? 0);
            if ($peerRaw === '' || $me <= 0) {
                echo json_encode(['success' => false, 'message' => 'بيانات الرسالة غير مكتملة.']);
                break;
            }

            $replyToId = intval($_POST['reply_to_id'] ?? 0);
            $messageType = 'text';
            $fileName = null; $filePath = null; $mimeType = null; $fileSize = null;

            if (!empty($_FILES['chat_file'])) {
                $upload = $_FILES['chat_file'];
                $errCode = intval($upload['error'] ?? UPLOAD_ERR_NO_FILE);
                if ($errCode !== UPLOAD_ERR_OK) {
                    $msg = match ($errCode) {
                        UPLOAD_ERR_INI_SIZE, UPLOAD_ERR_FORM_SIZE => 'حجم الملف أكبر من الحد المسموح في الخادم. حاول ملفًا أصغر.',
                        UPLOAD_ERR_PARTIAL => 'تم رفع جزء من الملف فقط. أعد المحاولة.',
                        UPLOAD_ERR_NO_TMP_DIR => 'مجلد الرفع المؤقت غير متاح في الخادم.',
                        UPLOAD_ERR_CANT_WRITE => 'تعذر حفظ الملف على الخادم.',
                        UPLOAD_ERR_EXTENSION => 'تم إيقاف الرفع بسبب إضافة في الخادم.',
                        default => 'تعذر رفع الملف.'
                    };
                    echo json_encode(['success' => false, 'message' => $msg]);
                    break;
                }
                $ext = strtolower(pathinfo($upload['name'] ?? '', PATHINFO_EXTENSION));
                $allowed = ['jpg','jpeg','png','gif','webp','pdf','doc','docx','xls','xlsx','txt','mp3','wav','ogg','m4a','aac','mp4','webm'];
                if (!in_array($ext, $allowed, true)) {
                    echo json_encode(['success' => false, 'message' => 'نوع الملف غير مسموح.']);
                    break;
                }
                $mimeType = mime_content_type($upload['tmp_name']) ?: 'application/octet-stream';
                $fileSize = intval($upload['size'] ?? 0);
                $maxBytes = 50 * 1024 * 1024;
                if ($fileSize > $maxBytes) {
                    echo json_encode(['success' => false, 'message' => 'حجم الملف كبير (الحد 50MB).']);
                    break;
                }
                $dir = __DIR__ . '/uploads/chat';
                if (!is_dir($dir)) { @mkdir($dir, 0775, true); }
                $safe = bin2hex(random_bytes(8)) . '_' . time() . '.' . $ext;
                $target = $dir . '/' . $safe;
                if (!move_uploaded_file($upload['tmp_name'], $target)) {
                    echo json_encode(['success' => false, 'message' => 'تعذر رفع الملف.']);
                    break;
                }
                $fileName = $upload['name'];
                $filePath = 'uploads/chat/' . $safe;
                $messageType = (str_starts_with($mimeType, 'image/')) ? 'image' : ((str_starts_with($mimeType, 'audio/')) ? 'voice' : 'file');
            }

            if ($messageText === '' && !$filePath) {
                echo json_encode(['success' => false, 'message' => 'أدخل نصاً أو أرفق ملفاً.']);
                break;
            }

            if ($peerRaw === '__all__') {
                $usersStmt = $pdo->query("SELECT id FROM admin_users WHERE is_active = 1");
                $userIds = array_map(fn($r) => intval($r['id']), $usersStmt->fetchAll());
                if (!$userIds) {
                    echo json_encode(['success' => false, 'message' => 'لا يوجد مستخدمون متاحون.']);
                    break;
                }
                $broadcastId = 'g_' . date('YmdHis') . '_' . bin2hex(random_bytes(4));
                $ins = $pdo->prepare("INSERT INTO user_messages (sender_id, receiver_id, message_text, message_type, file_name, file_path, mime_type, file_size, reply_to_id, chat_scope, broadcast_group_id, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'global', ?, ?)");
                foreach ($userIds as $uid) {
                    $ins->execute([$me, $uid, $messageText, $messageType, $fileName, $filePath, $mimeType, $fileSize, $replyToId > 0 ? $replyToId : null, $broadcastId, nowSaudi()]);
                }
                echo json_encode(['success' => true, 'message' => 'تم إرسال الرسالة إلى مجموعة الكل.']);
                break;
            }

            $peerId = intval($peerRaw);
            if ($peerId <= 0) {
                echo json_encode(['success' => false, 'message' => 'المستخدم غير صالح.']);
                break;
            }
            $check = $pdo->prepare("SELECT id FROM admin_users WHERE id = ? AND is_active = 1");
            $check->execute([$peerId]);
            if (!$check->fetch()) {
                echo json_encode(['success' => false, 'message' => 'المستخدم غير موجود أو غير مفعل.']);
                break;
            }
            $ins = $pdo->prepare("INSERT INTO user_messages (sender_id, receiver_id, message_text, message_type, file_name, file_path, mime_type, file_size, reply_to_id, chat_scope, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'private', ?)");
            $ins->execute([$me, $peerId, $messageText, $messageType, $fileName, $filePath, $mimeType, $fileSize, $replyToId > 0 ? $replyToId : null, nowSaudi()]);
            echo json_encode(['success' => true, 'message' => 'تم إرسال الرسالة.']);
            break;

        case 'delete_message':
            $messageId = intval($_POST['message_id'] ?? 0);
            $me = intval($_SESSION['admin_user_id'] ?? 0);
            $role = $_SESSION['admin_role'] ?? 'user';
            $stmt = $pdo->prepare("SELECT sender_id, file_path, deleted_at, chat_scope, broadcast_group_id FROM user_messages WHERE id = ? LIMIT 1");
            $stmt->execute([$messageId]);
            $msg = $stmt->fetch();
            if (!$msg || !empty($msg['deleted_at'])) {
                echo json_encode(['success' => false, 'message' => 'الرسالة غير موجودة.']);
                break;
            }
            if ($role !== 'admin' && intval($msg['sender_id']) !== $me) {
                echo json_encode(['success' => false, 'message' => 'لا تملك صلاحية حذف هذه الرسالة.']);
                break;
            }
            if (!empty($msg['file_path'])) {
                $full = __DIR__ . '/' . ltrim($msg['file_path'], '/');
                if (is_file($full)) @unlink($full);
            }
            if (($msg['chat_scope'] ?? 'private') === 'global' && !empty($msg['broadcast_group_id'])) {
                $pdo->prepare("UPDATE user_messages SET deleted_at = ? WHERE broadcast_group_id = ? AND deleted_at IS NULL")
                    ->execute([nowSaudi(), $msg['broadcast_group_id']]);
            } else {
                $pdo->prepare("UPDATE user_messages SET deleted_at = ? WHERE id = ?")->execute([nowSaudi(), $messageId]);
            }
            echo json_encode(['success' => true, 'message' => 'تم حذف الرسالة.']);
            break;

        case 'set_chat_retention':
            if (($_SESSION['admin_role'] ?? 'user') !== 'admin') {
                echo json_encode(['success' => false, 'message' => 'ليس لديك صلاحية.']);
                break;
            }
            $hours = max(0, intval($_POST['hours'] ?? 0));
            setSetting($pdo, 'chat_retention_hours', (string)$hours);
            purgeExpiredMessages($pdo);
            echo json_encode(['success' => true, 'message' => 'تم حفظ مدة الحذف التلقائي.', 'hours' => $hours]);
            break;

        case 'run_chat_cleanup':
            if (($_SESSION['admin_role'] ?? 'user') !== 'admin') {
                echo json_encode(['success' => false, 'message' => 'ليس لديك صلاحية.']);
                break;
            }
            $peerRaw = trim((string)($_POST['peer_id'] ?? ''));
            $me = intval($_SESSION['admin_user_id'] ?? 0);
            if ($me <= 0 || $peerRaw === '') {
                echo json_encode(['success' => false, 'message' => 'حدد المحادثة أولاً.']);
                break;
            }
            if ($peerRaw === '__monitor__') {
                echo json_encode(['success' => false, 'message' => 'لا يمكن تنظيف وضع المراقبة. اختر محادثة فعلية.']);
                break;
            }

            if ($peerRaw === '__all__') {
                $sel = $pdo->prepare("SELECT id, file_path FROM user_messages WHERE deleted_at IS NULL AND chat_scope = 'global' AND receiver_id = ?");
                $sel->execute([$me]);
            } else {
                $peerId = intval($peerRaw);
                if ($peerId <= 0) {
                    echo json_encode(['success' => false, 'message' => 'محادثة غير صالحة.']);
                    break;
                }
                $sel = $pdo->prepare("SELECT id, file_path FROM user_messages WHERE deleted_at IS NULL AND chat_scope = 'private' AND ((sender_id = ? AND receiver_id = ?) OR (sender_id = ? AND receiver_id = ?))");
                $sel->execute([$me, $peerId, $peerId, $me]);
            }

            $rows = $sel->fetchAll();
            if (!$rows) {
                echo json_encode(['success' => true, 'message' => 'لا توجد رسائل للحذف في هذه المحادثة.', 'deleted_count' => 0]);
                break;
            }
            $ids = array_map(fn($r) => intval($r['id']), $rows);
            $files = array_values(array_unique(array_filter(array_map(fn($r) => (string)($r['file_path'] ?? ''), $rows))));

            $in = implode(',', array_fill(0, count($ids), '?'));
            $params = array_merge([nowSaudi()], $ids);
            $pdo->prepare("UPDATE user_messages SET deleted_at = ? WHERE id IN ($in)")->execute($params);

            foreach ($files as $fp) {
                $check = $pdo->prepare("SELECT COUNT(*) FROM user_messages WHERE file_path = ? AND deleted_at IS NULL");
                $check->execute([$fp]);
                if (intval($check->fetchColumn()) === 0) {
                    $full = __DIR__ . '/' . ltrim($fp, '/');
                    if (is_file($full)) @unlink($full);
                }
            }

            echo json_encode(['success' => true, 'message' => 'تم تنظيف المحادثة الحالية بنجاح.', 'deleted_count' => count($ids)]);
            break;


        case 'fetch_ui_preferences':
            echo json_encode([
                'success' => true,
                'preferences' => [
                    'dark_text_color' => getSetting($pdo, 'dark_text_color', '#d8c8ff'),
                    'dark_glow_enabled' => getSetting($pdo, 'dark_glow_enabled', '1'),
                    'dark_glow_color' => getSetting($pdo, 'dark_glow_color', '#8b5cf6'),
                    'font_family' => getSetting($pdo, 'ui_font_family', 'Cairo'),
                    'data_view_mode' => getSetting($pdo, 'ui_data_view_mode', 'table')
                ]
            ]);
            break;

        case 'save_ui_preferences':
            if (($_SESSION['admin_role'] ?? 'user') !== 'admin') {
                echo json_encode(['success' => false, 'message' => 'ليس لديك صلاحية.']);
                break;
            }
            $allowedFonts = ['Cairo','Tajawal','Almarai','Changa','IBM Plex Sans Arabic','Noto Kufi Arabic','Readex Pro','El Messiri','Reem Kufi','Amiri'];
            $fontFamily = trim((string)($_POST['font_family'] ?? 'Cairo'));
            if (!in_array($fontFamily, $allowedFonts, true)) $fontFamily = 'Cairo';
            $darkTextColor = sanitizeHexColor((string)($_POST['dark_text_color'] ?? '#d8c8ff'), '#d8c8ff');
            $darkGlowColor = sanitizeHexColor((string)($_POST['dark_glow_color'] ?? '#8b5cf6'), '#8b5cf6');
            $darkGlowEnabled = (($_POST['dark_glow_enabled'] ?? '1') === '1') ? '1' : '0';
            $allowedViewModes = ['table','compact','cards','zebra'];
            $dataViewMode = trim((string)($_POST['data_view_mode'] ?? 'table'));
            if (!in_array($dataViewMode, $allowedViewModes, true)) $dataViewMode = 'table';

            setSetting($pdo, 'ui_font_family', $fontFamily);
            setSetting($pdo, 'dark_text_color', $darkTextColor);
            setSetting($pdo, 'dark_glow_color', $darkGlowColor);
            setSetting($pdo, 'dark_glow_enabled', $darkGlowEnabled);
            setSetting($pdo, 'ui_data_view_mode', $dataViewMode);

            echo json_encode([
                'success' => true,
                'message' => 'تم حفظ إعدادات المظهر بنجاح.',
                'preferences' => [
                    'dark_text_color' => $darkTextColor,
                    'dark_glow_enabled' => $darkGlowEnabled,
                    'dark_glow_color' => $darkGlowColor,
                    'font_family' => $fontFamily,
                    'data_view_mode' => $dataViewMode
                ]
            ]);
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
    $chat_users_stmt = $pdo->prepare("SELECT id, username, display_name, role FROM admin_users WHERE is_active = 1 AND id <> ? ORDER BY display_name");
    $chat_users_stmt->execute([intval($_SESSION['admin_user_id'])]);
    $chat_users = $chat_users_stmt->fetchAll();
    if ($_SESSION['admin_role'] === 'admin') {
        $users = $pdo->query("SELECT id, username, display_name, role, is_active, created_at FROM admin_users ORDER BY created_at DESC")->fetchAll();
    }
} else {
    $doctors = $patients = $leaves = $archived = $queries = $notifications_payment = $payments = $users = $chat_users = [];
    $stats = ['total' => 0, 'active' => 0, 'archived' => 0, 'patients' => 0, 'doctors' => 0, 'paid' => 0, 'unpaid' => 0, 'paid_amount' => 0, 'unpaid_amount' => 0];
}


$uiFontFamily = getSetting($pdo, 'ui_font_family', 'Cairo');
$allowedUiFonts = ['Cairo','Tajawal','Almarai','Changa','IBM Plex Sans Arabic','Noto Kufi Arabic','Readex Pro','El Messiri','Reem Kufi','Amiri'];
if (!in_array($uiFontFamily, $allowedUiFonts, true)) $uiFontFamily = 'Cairo';
$uiDarkTextColor = sanitizeHexColor(getSetting($pdo, 'dark_text_color', '#d8c8ff') ?? '#d8c8ff', '#d8c8ff');
$uiDarkGlowColor = sanitizeHexColor(getSetting($pdo, 'dark_glow_color', '#8b5cf6') ?? '#8b5cf6', '#8b5cf6');
$uiDarkGlowEnabled = getSetting($pdo, 'dark_glow_enabled', '1') === '1' ? '1' : '0';
$uiDataViewMode = getSetting($pdo, 'ui_data_view_mode', 'table') ?: 'table';
if (!in_array($uiDataViewMode, ['table','compact','cards','zebra'], true)) $uiDataViewMode = 'table';
?>
<!DOCTYPE html>
<html lang="ar" dir="rtl">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>لوحة تحكم الإجازات المرضية</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.rtl.min.css" rel="stylesheet">
    <link href="https://cdn.jsdelivr.net/npm/bootstrap-icons@1.11.0/font/bootstrap-icons.css" rel="stylesheet">
    <link href="https://fonts.googleapis.com/css2?family=Almarai:wght@300;400;700;800&family=Amiri:wght@400;700&family=Cairo:wght@300;400;500;600;700;800&family=Changa:wght@300;400;500;600;700;800&family=El+Messiri:wght@400;500;600;700&family=IBM+Plex+Sans+Arabic:wght@300;400;500;600;700&family=Noto+Kufi+Arabic:wght@300;400;500;600;700&family=Readex+Pro:wght@300;400;500;600;700&family=Reem+Kufi:wght@400;500;600;700&family=Tajawal:wght@300;400;500;700;800&display=swap" rel="stylesheet">
    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js"></script>
    <script src="https://cdnjs.cloudflare.com/ajax/libs/jspdf/2.5.1/jspdf.umd.min.js"></script>
    <script src="https://cdnjs.cloudflare.com/ajax/libs/jspdf-autotable/3.5.25/jspdf.plugin.autotable.min.js"></script>

    <style>
        /* ╔══════════════════════════════════════════════════════════════════╗
           ║     Ultimate Dashboard Design v4.0 - تصميم خورافي نهائي       ║
           ╚══════════════════════════════════════════════════════════════════╝ */

        /* ═══════════════ المتغيرات - لايت مود ═══════════════ */
        :root {
            --primary: #6366f1;
            --primary-light: #818cf8;
            --primary-dark: #4f46e5;
            --primary-glow: rgba(99,102,241,0.4);
            --accent: #8b5cf6;
            --accent-light: #a78bfa;
            --secondary: #1e293b;
            --success: #10b981;
            --success-light: #34d399;
            --success-glow: rgba(16,185,129,0.35);
            --danger: #ef4444;
            --danger-light: #f87171;
            --danger-glow: rgba(239,68,68,0.35);
            --warning: #f59e0b;
            --warning-light: #fbbf24;
            --warning-glow: rgba(245,158,11,0.35);
            --info: #06b6d4;
            --info-light: #22d3ee;
            --info-glow: rgba(6,182,212,0.35);

            --bg: #f0f4ff;
            --bg-alt: #e8edf8;
            --card: #ffffff;
            --card-hover: #fafaff;
            --text: #0f172a;
            --text-secondary: #334155;
            --text-muted: #64748b;
            --border: #e2e8f0;
            --border-light: #f1f5f9;

            --radius: 16px;
            --radius-sm: 10px;
            --radius-lg: 24px;
            --radius-xl: 32px;

            --shadow-xs: 0 1px 2px rgba(15,23,42,0.04);
            --shadow: 0 4px 20px rgba(15,23,42,0.07);
            --shadow-md: 0 8px 32px rgba(15,23,42,0.1);
            --shadow-lg: 0 20px 50px rgba(15,23,42,0.14);
            --shadow-xl: 0 30px 80px rgba(15,23,42,0.18);

            --ease: cubic-bezier(0.4, 0, 0.2, 1);
            --ease-bounce: cubic-bezier(0.34, 1.56, 0.64, 1);
            --ease-out: cubic-bezier(0, 0, 0.2, 1);
            --t-fast: 0.2s;
            --t-normal: 0.35s;
            --t-slow: 0.5s;

            --grad-primary: linear-gradient(135deg, #6366f1, #8b5cf6);
            --grad-success: linear-gradient(135deg, #10b981, #34d399);
            --grad-danger: linear-gradient(135deg, #ef4444, #f87171);
            --grad-warning: linear-gradient(135deg, #f59e0b, #fbbf24);
            --grad-dark: linear-gradient(135deg, #1e293b, #334155, #475569);
            --grad-glass: linear-gradient(135deg, rgba(255,255,255,0.9), rgba(255,255,255,0.7));
            --app-font-family: '<?php echo addslashes($uiFontFamily); ?>', sans-serif;
            --dark-data-color: <?php echo htmlspecialchars($uiDarkTextColor, ENT_QUOTES, 'UTF-8'); ?>;
            --dark-glow-color: <?php echo htmlspecialchars($uiDarkGlowColor, ENT_QUOTES, 'UTF-8'); ?>;
            --dark-glow-shadow: <?php echo ($uiDarkGlowEnabled === '1') ? ('0 0 10px ' . htmlspecialchars($uiDarkGlowColor, ENT_QUOTES, 'UTF-8')) : 'none'; ?>;
        }

        /* ═══════════════ المتغيرات - دارك مود (نصوص واضحة جداً) ═══════════════ */
        .dark-mode {
            --bg: #080d1a;
            --bg-alt: #0e1525;
            --card: #131c2e;
            --card-hover: #182236;
            --text: #f8fafc;
            --text-secondary: #e2e8f0;
            --text-muted: #a1b0c8;
            --border: rgba(148,163,184,0.18);
            --border-light: rgba(148,163,184,0.08);
            --shadow-xs: 0 1px 2px rgba(0,0,0,0.3);
            --shadow: 0 4px 20px rgba(0,0,0,0.35);
            --shadow-md: 0 8px 32px rgba(0,0,0,0.4);
            --shadow-lg: 0 20px 50px rgba(0,0,0,0.45);
            --shadow-xl: 0 30px 80px rgba(0,0,0,0.5);
            --grad-glass: linear-gradient(135deg, rgba(19,28,46,0.95), rgba(19,28,46,0.85));
        }

        /* ═══════════════ الأساسيات ═══════════════ */
        * { box-sizing: border-box; margin: 0; padding: 0; }

        body {
            font-family: var(--app-font-family);
            background: var(--bg);
            color: var(--text);
            direction: rtl;
            min-height: 100vh;
            transition: background var(--t-slow) var(--ease), color var(--t-normal) var(--ease);
            font-size: 14px;
            line-height: 1.7;
            -webkit-font-smoothing: antialiased;
            -moz-osx-font-smoothing: grayscale;
            position: relative;
        }

        /* خلفية mesh ثابتة */
        body::before {
            content: '';
            position: fixed;
            inset: 0;
            background:
                radial-gradient(ellipse at 15% 80%, rgba(99,102,241,0.07) 0%, transparent 50%),
                radial-gradient(ellipse at 85% 20%, rgba(139,92,246,0.06) 0%, transparent 50%),
                radial-gradient(ellipse at 50% 50%, rgba(6,182,212,0.04) 0%, transparent 60%);
            pointer-events: none;
            z-index: 0;
        }

        .dark-mode body::before,
        body.dark-mode::before {
            background:
                radial-gradient(ellipse at 15% 80%, rgba(99,102,241,0.12) 0%, transparent 50%),
                radial-gradient(ellipse at 85% 20%, rgba(139,92,246,0.08) 0%, transparent 50%),
                radial-gradient(ellipse at 50% 50%, rgba(6,182,212,0.06) 0%, transparent 60%);
        }

        body > * { position: relative; z-index: 1; }

        /* ═══════════════ أنيميشنات خورافية ═══════════════ */
        @keyframes slideUp {
            from { opacity: 0; transform: translateY(35px) scale(0.97); }
            to { opacity: 1; transform: translateY(0) scale(1); }
        }
        @keyframes slideDown {
            from { opacity: 0; transform: translateY(-25px); }
            to { opacity: 1; transform: translateY(0); }
        }
        @keyframes fadeIn {
            from { opacity: 0; }
            to { opacity: 1; }
        }
        @keyframes fadeInUp {
            from { opacity: 0; transform: translateY(18px); }
            to { opacity: 1; transform: translateY(0); }
        }
        @keyframes scaleIn {
            from { opacity: 0; transform: scale(0.92); }
            to { opacity: 1; transform: scale(1); }
        }
        @keyframes float {
            0%, 100% { transform: translateY(0); }
            50% { transform: translateY(-10px); }
        }
        @keyframes gradientShift {
            0% { background-position: 0% 50%; }
            50% { background-position: 100% 50%; }
            100% { background-position: 0% 50%; }
        }
        @keyframes spin { to { transform: rotate(360deg); } }
        @keyframes pulse {
            0% { box-shadow: 0 0 0 0 rgba(239,68,68,0.5); }
            70% { box-shadow: 0 0 0 12px rgba(239,68,68,0); }
            100% { box-shadow: 0 0 0 0 rgba(239,68,68,0); }
        }
        @keyframes iconBounce {
            0%, 100% { transform: translateY(0) rotate(0deg); }
            25% { transform: translateY(-4px) rotate(3deg); }
            75% { transform: translateY(2px) rotate(-2deg); }
        }
        @keyframes shimmer {
            0% { background-position: -200% 0; }
            100% { background-position: 200% 0; }
        }
        @keyframes glowPulse {
            0%, 100% { opacity: 0.5; }
            50% { opacity: 1; }
        }
        @keyframes cardAppear {
            from { opacity: 0; transform: translateY(20px) scale(0.96); }
            to { opacity: 1; transform: translateY(0) scale(1); }
        }

        .fade-in { animation: fadeIn 0.5s var(--ease); }

        /* ═══════════════ صفحة تسجيل الدخول - خورافية ═══════════════ */
        .login-wrapper {
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
            background: linear-gradient(-45deg, #0f172a, #1e1b4b, #312e81, #1e293b, #0c4a6e);
            background-size: 500% 500%;
            animation: gradientShift 20s ease infinite;
            padding: 20px;
            position: relative;
            overflow: hidden;
        }

        /* أشكال زخرفية متحركة */
        .login-wrapper::before {
            content: '';
            position: absolute;
            width: 500px;
            height: 500px;
            background: radial-gradient(circle, rgba(99,102,241,0.2) 0%, transparent 70%);
            top: -150px;
            right: -150px;
            border-radius: 50%;
            animation: float 7s ease-in-out infinite;
        }

        .login-wrapper::after {
            content: '';
            position: absolute;
            width: 350px;
            height: 350px;
            background: radial-gradient(circle, rgba(139,92,246,0.15) 0%, transparent 70%);
            bottom: -80px;
            left: -80px;
            border-radius: 50%;
            animation: float 5s ease-in-out infinite reverse;
        }

        .login-card {
            background: rgba(255,255,255,0.92);
            backdrop-filter: blur(30px) saturate(200%);
            -webkit-backdrop-filter: blur(30px) saturate(200%);
            border-radius: var(--radius-xl);
            padding: 48px 40px;
            width: 100%;
            max-width: 440px;
            box-shadow: 0 40px 100px rgba(0,0,0,0.3), 0 0 0 1px rgba(255,255,255,0.15) inset;
            animation: slideUp 0.8s var(--ease-bounce);
            position: relative;
            z-index: 2;
            border: 1px solid rgba(255,255,255,0.25);
        }

        .dark-mode .login-card {
            background: rgba(19,28,46,0.92);
            border-color: rgba(99,102,241,0.25);
            box-shadow: 0 40px 100px rgba(0,0,0,0.6), 0 0 80px rgba(99,102,241,0.08);
        }

        .login-card h2 {
            text-align: center;
            margin-bottom: 8px;
            font-weight: 800;
            font-size: 28px;
            background: var(--grad-primary);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            background-clip: text;
        }

        .login-card .subtitle {
            text-align: center;
            color: var(--text-muted);
            margin-bottom: 32px;
            font-size: 14px;
            font-weight: 500;
        }

        .dark-mode .login-card .subtitle {
            color: #a1b0c8;
        }

        .login-card .login-icon {
            text-align: center;
            font-size: 60px;
            margin-bottom: 20px;
            background: var(--grad-primary);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            background-clip: text;
            filter: drop-shadow(0 6px 16px var(--primary-glow));
            animation: float 4s ease-in-out infinite;
        }

        /* ═══════════════ شريط التنقل ═══════════════ */
        .top-navbar {
            background: linear-gradient(135deg, rgba(15,23,42,0.97), rgba(30,41,59,0.95));
            backdrop-filter: blur(24px) saturate(180%);
            -webkit-backdrop-filter: blur(24px) saturate(180%);
            padding: 14px 28px;
            display: flex;
            align-items: center;
            justify-content: space-between;
            flex-wrap: wrap;
            gap: 12px;
            box-shadow: 0 4px 30px rgba(0,0,0,0.25), inset 0 1px 0 rgba(255,255,255,0.05);
            position: sticky;
            top: 0;
            z-index: 1040;
            border-bottom: 1px solid rgba(255,255,255,0.06);
            animation: slideDown 0.5s var(--ease);
        }

        .dark-mode .top-navbar {
            background: linear-gradient(135deg, rgba(8,13,26,0.98), rgba(14,21,37,0.96));
            border-bottom-color: rgba(99,102,241,0.12);
        }

        .top-navbar .brand {
            display: flex;
            align-items: center;
            gap: 12px;
            color: #fff;
            font-weight: 800;
            font-size: 18px;
            letter-spacing: -0.3px;
        }

        .top-navbar .brand i {
            font-size: 26px;
            background: var(--grad-primary);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            background-clip: text;
            filter: drop-shadow(0 2px 8px var(--primary-glow));
            animation: iconBounce 5s ease-in-out infinite;
        }

        .top-navbar .nav-actions {
            display: flex;
            align-items: center;
            gap: 8px;
            flex-wrap: wrap;
        }

        .top-navbar .user-info {
            color: rgba(255,255,255,0.9);
            font-size: 13px;
            display: flex;
            align-items: center;
            gap: 8px;
            background: rgba(255,255,255,0.07);
            padding: 6px 16px;
            border-radius: 50px;
            border: 1px solid rgba(255,255,255,0.1);
            transition: all var(--t-fast) var(--ease);
        }

        .top-navbar .user-info:hover {
            background: rgba(255,255,255,0.12);
            border-color: rgba(255,255,255,0.15);
        }

        .top-navbar .user-info i {
            color: var(--primary-light);
            font-size: 16px;
        }

        /* ═══════════════ الأزرار ═══════════════ */
        .btn {
            border-radius: var(--radius-sm);
            font-weight: 600;
            font-size: 13px;
            padding: 7px 16px;
            transition: all var(--t-normal) var(--ease);
            border: none;
            display: inline-flex;
            align-items: center;
            gap: 6px;
            position: relative;
            overflow: hidden;
            cursor: pointer;
        }

        .btn::after {
            content: '';
            position: absolute;
            inset: 0;
            background: rgba(255,255,255,0);
            transition: background var(--t-fast) var(--ease);
        }

        .btn:hover::after { background: rgba(255,255,255,0.1); }
        .btn:active::after { background: rgba(0,0,0,0.05); }

        .btn:hover { transform: translateY(-2px); }
        .btn:active { transform: translateY(0) scale(0.98); }

        .btn-gradient {
            background: var(--grad-primary);
            color: #fff;
            box-shadow: 0 4px 16px var(--primary-glow);
        }
        .btn-gradient:hover {
            color: #fff;
            box-shadow: 0 8px 28px var(--primary-glow);
        }

        .btn-success-custom {
            background: var(--grad-success);
            color: #fff;
            box-shadow: 0 4px 16px var(--success-glow);
        }
        .btn-success-custom:hover { color: #fff; box-shadow: 0 8px 28px var(--success-glow); }

        .btn-danger-custom {
            background: var(--grad-danger);
            color: #fff;
            box-shadow: 0 4px 16px var(--danger-glow);
        }
        .btn-danger-custom:hover { color: #fff; box-shadow: 0 8px 28px var(--danger-glow); }

        .btn-warning-custom {
            background: var(--grad-warning);
            color: #fff;
            box-shadow: 0 4px 16px var(--warning-glow);
        }
        .btn-warning-custom:hover { color: #fff; box-shadow: 0 8px 28px var(--warning-glow); }

        .btn-outline-light {
            border: 1px solid rgba(255,255,255,0.2);
            color: #fff;
        }
        .btn-outline-light:hover {
            background: rgba(255,255,255,0.1);
            color: #fff;
            border-color: rgba(255,255,255,0.3);
        }

        .btn-outline-primary { border: 1.5px solid var(--primary); color: var(--primary); background: transparent; }
        .btn-outline-primary:hover { background: var(--primary); color: #fff; box-shadow: 0 4px 16px var(--primary-glow); }

        .btn-outline-success { border: 1.5px solid var(--success); color: var(--success); background: transparent; }
        .btn-outline-success:hover { background: var(--success); color: #fff; box-shadow: 0 4px 16px var(--success-glow); }

        .btn-outline-danger { border: 1.5px solid var(--danger); color: var(--danger); background: transparent; }
        .btn-outline-danger:hover { background: var(--danger); color: #fff; box-shadow: 0 4px 16px var(--danger-glow); }

        .btn-outline-info { border: 1.5px solid var(--info); color: var(--info); background: transparent; }
        .btn-outline-info:hover { background: var(--info); color: #fff; box-shadow: 0 4px 16px var(--info-glow); }

        .btn-outline-secondary { border: 1.5px solid var(--border); color: var(--text-muted); background: transparent; }
        .btn-outline-secondary:hover { background: var(--secondary); color: #fff; border-color: var(--secondary); }

        /* دارك مود - أزرار outline واضحة */
        .dark-mode .btn-outline-primary { color: #a5b4fc; border-color: rgba(165,180,252,0.45); }
        .dark-mode .btn-outline-primary:hover { background: var(--primary); color: #fff; }
        .dark-mode .btn-outline-success { color: #6ee7b7; border-color: rgba(110,231,183,0.45); }
        .dark-mode .btn-outline-success:hover { background: var(--success); color: #fff; }
        .dark-mode .btn-outline-danger { color: #fca5a5; border-color: rgba(252,165,165,0.45); }
        .dark-mode .btn-outline-danger:hover { background: var(--danger); color: #fff; }
        .dark-mode .btn-outline-info { color: #67e8f9; border-color: rgba(103,232,249,0.45); }
        .dark-mode .btn-outline-info:hover { background: var(--info); color: #fff; }
        .dark-mode .btn-outline-secondary { color: #cbd5e1; border-color: rgba(203,213,225,0.3); }
        .dark-mode .btn-outline-secondary:hover { background: #475569; color: #fff; }

        /* ═══════════════ زر الوضع الداكن ═══════════════ */
        #darkModeToggle {
            position: fixed;
            bottom: 24px;
            left: 24px;
            z-index: 1050;
            background: var(--grad-dark);
            color: #fff;
            border-radius: 50px;
            padding: 12px 22px;
            box-shadow: 0 8px 30px rgba(0,0,0,0.35);
            font-size: 13px;
            font-weight: 600;
            transition: all var(--t-normal) var(--ease-bounce);
            border: 1px solid rgba(255,255,255,0.08);
        }

        #darkModeToggle:hover {
            transform: translateY(-4px) scale(1.05);
            box-shadow: 0 14px 40px rgba(0,0,0,0.45);
        }

        .dark-mode #darkModeToggle {
            background: var(--grad-primary);
            box-shadow: 0 8px 30px var(--primary-glow);
        }

        .dark-mode #darkModeToggle:hover {
            box-shadow: 0 14px 40px var(--primary-glow);
        }

        /* ═══════════════ البطاقات الإحصائية ═══════════════ */
        .stats-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(170px, 1fr));
            gap: 16px;
            margin-bottom: 28px;
        }

        .stat-card {
            background: var(--card);
            border-radius: var(--radius);
            padding: 22px 16px 18px;
            text-align: center;
            box-shadow: var(--shadow);
            transition: all var(--t-normal) var(--ease-bounce);
            border: 1px solid var(--border);
            position: relative;
            overflow: hidden;
            animation: cardAppear 0.6s var(--ease) backwards;
        }

        .stat-card:nth-child(1) { animation-delay: 0.05s; }
        .stat-card:nth-child(2) { animation-delay: 0.1s; }
        .stat-card:nth-child(3) { animation-delay: 0.15s; }
        .stat-card:nth-child(4) { animation-delay: 0.2s; }
        .stat-card:nth-child(5) { animation-delay: 0.25s; }
        .stat-card:nth-child(6) { animation-delay: 0.3s; }
        .stat-card:nth-child(7) { animation-delay: 0.35s; }
        .stat-card:nth-child(8) { animation-delay: 0.4s; }
        .stat-card:nth-child(9) { animation-delay: 0.45s; }

        .stat-card::before {
            content: '';
            position: absolute;
            top: 0; right: 0; left: 0;
            height: 4px;
            border-radius: 4px 4px 0 0;
        }

        .stat-card::after {
            content: '';
            position: absolute;
            top: -20px;
            right: -20px;
            width: 90px;
            height: 90px;
            border-radius: 50%;
            opacity: 0.06;
            transition: all var(--t-normal) var(--ease);
        }

        .stat-card:nth-child(1)::before { background: var(--grad-primary); }
        .stat-card:nth-child(2)::before { background: var(--grad-success); }
        .stat-card:nth-child(3)::before { background: var(--grad-danger); }
        .stat-card:nth-child(4)::before { background: var(--grad-warning); }
        .stat-card:nth-child(5)::before { background: linear-gradient(135deg, #06b6d4, #22d3ee); }
        .stat-card:nth-child(6)::before { background: linear-gradient(135deg, #8b5cf6, #a78bfa); }
        .stat-card:nth-child(7)::before { background: linear-gradient(135deg, #ec4899, #f472b6); }
        .stat-card:nth-child(8)::before { background: var(--grad-success); }
        .stat-card:nth-child(9)::before { background: var(--grad-danger); }

        .stat-card:nth-child(1)::after { background: #6366f1; }
        .stat-card:nth-child(2)::after { background: #10b981; }
        .stat-card:nth-child(3)::after { background: #ef4444; }
        .stat-card:nth-child(4)::after { background: #f59e0b; }
        .stat-card:nth-child(5)::after { background: #06b6d4; }
        .stat-card:nth-child(6)::after { background: #8b5cf6; }
        .stat-card:nth-child(7)::after { background: #ec4899; }
        .stat-card:nth-child(8)::after { background: #10b981; }
        .stat-card:nth-child(9)::after { background: #ef4444; }

        .stat-card:hover {
            transform: translateY(-7px) scale(1.03);
            box-shadow: var(--shadow-lg);
        }

        .stat-card:hover::after {
            opacity: 0.1;
            transform: scale(1.6);
        }

        .stat-card .stat-icon {
            font-size: 34px;
            margin-bottom: 8px;
            transition: all var(--t-normal) var(--ease);
        }

        .stat-card:nth-child(1) .stat-icon { color: #6366f1; }
        .stat-card:nth-child(2) .stat-icon { color: #10b981; }
        .stat-card:nth-child(3) .stat-icon { color: #ef4444; }
        .stat-card:nth-child(4) .stat-icon { color: #f59e0b; }
        .stat-card:nth-child(5) .stat-icon { color: #06b6d4; }
        .stat-card:nth-child(6) .stat-icon { color: #8b5cf6; }
        .stat-card:nth-child(7) .stat-icon { color: #ec4899; }
        .stat-card:nth-child(8) .stat-icon { color: #10b981; }
        .stat-card:nth-child(9) .stat-icon { color: #ef4444; }

        .stat-card:hover .stat-icon {
            transform: scale(1.25) rotate(-5deg);
        }

        .stat-card .stat-value {
            font-size: 26px;
            font-weight: 800;
            color: var(--text);
            line-height: 1.2;
            letter-spacing: -0.5px;
        }

        .stat-card .stat-label {
            font-size: 12px;
            color: var(--text-muted);
            font-weight: 600;
            margin-top: 4px;
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }

        /* ═══════════════ الإحصائيات المتقدمة ═══════════════ */
        .stats-lux-card {
            border: 1px solid rgba(99,102,241,0.15);
            background: linear-gradient(180deg, rgba(99,102,241,0.03), rgba(6,182,212,0.02));
            border-radius: var(--radius);
        }

        .dark-mode .stats-lux-card {
            border-color: rgba(99,102,241,0.25);
            background: linear-gradient(180deg, rgba(99,102,241,0.08), rgba(6,182,212,0.04));
        }

        .lux-chart-wrap {
            border: 1px solid rgba(0,0,0,0.06);
            border-radius: var(--radius);
            padding: 20px;
            background: linear-gradient(135deg, rgba(255,255,255,0.95), rgba(248,250,255,0.95));
            box-shadow: inset 0 1px 0 rgba(255,255,255,0.7), var(--shadow-xs);
            transition: all var(--t-normal) var(--ease);
        }

        .dark-mode .lux-chart-wrap {
            background: linear-gradient(135deg, rgba(19,28,46,0.85), rgba(14,21,37,0.9));
            border-color: rgba(148,163,184,0.18);
            box-shadow: inset 0 1px 0 rgba(255,255,255,0.03);
        }

        /* بطاقات الإحصائيات داخل صفحة الإحصائيات المتقدمة */
        #adminStatsCards .col-md-3 .card,
        #adminStatsCards .col-md-4 .card,
        #adminStatsCards .col-6 .card,
        #adminStatsCards > div {
            transition: all var(--t-normal) var(--ease);
        }

        /* ═══════════════ البطاقات ═══════════════ */
        .card-custom {
            background: var(--card);
            border-radius: var(--radius);
            box-shadow: var(--shadow);
            border: 1px solid var(--border);
            overflow: hidden;
            transition: all var(--t-normal) var(--ease);
            margin-bottom: 24px;
            animation: cardAppear 0.5s var(--ease) backwards;
        }

        .card-custom:hover {
            box-shadow: var(--shadow-md);
        }

        .card-custom .card-header {
            padding: 16px 24px;
            font-weight: 700;
            font-size: 15px;
            border-bottom: 1px solid var(--border);
            background: linear-gradient(135deg, rgba(99,102,241,0.04), transparent);
            color: var(--text);
        }

        .dark-mode .card-custom .card-header {
            background: linear-gradient(135deg, rgba(99,102,241,0.08), transparent);
            color: #f8fafc;
        }

        .card-custom .card-body {
            padding: 24px;
            color: var(--text);
        }

        /* ═══════════════ التبويبات ═══════════════ */
        .nav-tabs {
            border-bottom: 2px solid var(--border);
            gap: 4px;
            padding: 0 4px;
            flex-wrap: wrap;
        }

        .nav-tabs .nav-link {
            border: none;
            border-radius: 14px 14px 0 0;
            padding: 10px 22px;
            font-weight: 600;
            font-size: 13px;
            color: var(--text-muted);
            transition: all var(--t-normal) var(--ease);
            position: relative;
            background: transparent;
        }

        .nav-tabs .nav-link:hover {
            color: var(--primary);
            background: rgba(99,102,241,0.06);
        }

        .nav-tabs .nav-link.active {
            color: #fff !important;
            background: var(--grad-primary) !important;
            box-shadow: 0 4px 18px var(--primary-glow);
            border: none;
        }

        .dark-mode .nav-tabs {
            border-bottom-color: rgba(148,163,184,0.15);
        }

        .dark-mode .nav-tabs .nav-link {
            color: #a1b0c8;
        }

        .dark-mode .nav-tabs .nav-link:hover {
            color: var(--primary-light);
            background: rgba(99,102,241,0.1);
        }

        .tab-content { animation: fadeIn 0.4s var(--ease); }
        .tab-pane { animation: fadeInUp 0.4s var(--ease); }

        /* ═══════════════ الجداول ═══════════════ */
        .table {
            font-size: 13px;
            margin-bottom: 0;
            color: var(--text);
        }

        .table thead th {
            background: linear-gradient(135deg, #1e293b, #334155);
            color: #f1f5f9;
            font-weight: 700;
            font-size: 12px;
            padding: 13px 10px;
            white-space: nowrap;
            border: none;
            position: sticky;
            top: 0;
            z-index: 10;
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }

        .dark-mode .table thead th {
            background: linear-gradient(135deg, #0e1525, #1e293b);
            color: #e2e8f0;
        }

        .table tbody td {
            padding: 10px 8px;
            vertical-align: middle;
            border-color: var(--border);
            color: #111827;
            font-weight: 600;
        }

        .table tbody td a,
        .table tbody td .text-dark,
        .table tbody td .text-muted,
        .table tbody td span,
        .table tbody td small {
            color: #0f172a !important;
            text-shadow: none !important;
        }

        .dark-mode .table tbody td {
            color: #111827 !important;
            border-color: rgba(148,163,184,0.25);
            background: rgba(248,250,252,0.96);
            text-shadow: none !important;
        }

        .dark-mode .table tbody td a,
        .dark-mode .table tbody td .btn-link,
        .dark-mode .table tbody td .text-dark,
        .dark-mode .table tbody td .text-muted,
        .dark-mode .table tbody td span,
        .dark-mode .table tbody td small {
            color: #0f172a !important;
            text-shadow: none !important;
        }

        .dark-mode .table .no-results td {
            color: #94a3b8 !important;
        }


        .dark-mode .table,
        .dark-mode .table tbody td,
        .dark-mode .table tbody td *,
        .dark-mode .table-responsive,
        .dark-mode .table-responsive .form-control,
        .dark-mode .table-responsive .form-select {
            color: #111827 !important;
            text-shadow: none !important;
        }

        .dark-mode .table tbody td small,
        .dark-mode .table tbody td .small,
        .dark-mode .table tbody td .text-muted {
            color: #334155 !important;
            text-shadow: none !important;
        }

        .dark-mode .table .btn-outline-secondary {
            color: #dbe7fb;
            border-color: rgba(203,213,225,0.45);
        }

        .dark-mode .table .btn-outline-secondary:hover {
            background: #64748b;
            color: #fff;
        }

        /* تخصيص لون بيانات الدارك مود (من الإعدادات) */
        .dark-mode .stat-value,
        .dark-mode .list-group-item,
        .dark-mode .card-header,
        .dark-mode .modal-title {
            color: var(--dark-data-color) !important;
            text-shadow: var(--dark-glow-shadow);
        }

        .dark-mode .table.mobile-readable td::before,
        .dark-mode .text-muted {
            color: var(--dark-data-color) !important;
        }

        .table-hover tbody tr {
            transition: all var(--t-fast) var(--ease);
        }

        .table-hover tbody tr:hover {
            background-color: rgba(99,102,241,0.06) !important;
        }

        .dark-mode .table-hover tbody tr:hover {
            background-color: rgba(99,102,241,0.12) !important;
        }

        .table-striped tbody tr:nth-of-type(odd) {
            background-color: rgba(99,102,241,0.02);
        }

        .dark-mode .table-striped tbody tr:nth-of-type(odd) {
            background-color: rgba(255,255,255,0.025);
        }

        .table-responsive {
            border-radius: var(--radius-sm);
            overflow: auto;
            border: 1px solid var(--border);
            -webkit-overflow-scrolling: touch;
        }

        .table.mobile-readable td::before {
            content: attr(data-label);
            display: none;
        }

        body.data-view-compact .table thead th { padding: 9px 8px; font-size: 11px; }
        body.data-view-compact .table tbody td { padding: 7px 6px; font-size: 12px; }

        body.data-view-cards .table.mobile-readable thead { display: none; }
        body.data-view-cards .table.mobile-readable,
        body.data-view-cards .table.mobile-readable tbody,
        body.data-view-cards .table.mobile-readable tr,
        body.data-view-cards .table.mobile-readable td {
            display: block;
            width: 100%;
            text-align: right !important;
        }
        body.data-view-cards .table.mobile-readable tr {
            margin-bottom: 10px;
            border: 1px solid var(--border);
            border-radius: 12px;
            background: var(--card);
            box-shadow: 0 8px 20px rgba(15,23,42,0.06);
            padding: 8px;
        }
        body.data-view-cards .table.mobile-readable td {
            border: none !important;
            border-bottom: 1px dashed rgba(148,163,184,0.25) !important;
            padding: 8px 8px 8px 44% !important;
            position: relative;
            min-height: 36px;
        }
        body.data-view-cards .table.mobile-readable td:last-child { border-bottom: none !important; }
        body.data-view-cards .table.mobile-readable td::before {
            display: block;
            position: absolute;
            inset-inline-end: 8px;
            top: 8px;
            width: 40%;
            font-weight: 700;
            color: #334155;
            white-space: nowrap;
            overflow: hidden;
            text-overflow: ellipsis;
        }

        body.data-view-zebra .table tbody tr:nth-child(odd) { background: rgba(15,23,42,0.04); }
        .dark-mode body.data-view-zebra .table tbody tr:nth-child(odd),
        body.dark-mode.data-view-zebra .table tbody tr:nth-child(odd) { background: rgba(255,255,255,0.12); }

        /* ═══════════════ المراسلات بأسلوب تيليجرام ═══════════════ */
        .chat-layout {
            background: linear-gradient(180deg, #f8fafc, #eef2ff);
            border: 1px solid rgba(99,102,241,0.12);
            border-radius: 18px;
            padding: 10px;
        }

        #chatMessagesBox {
            height: 380px;
            overflow: auto;
            border-radius: 14px;
            padding: 14px;
            background:
                radial-gradient(circle at top right, rgba(99,102,241,0.08), transparent 35%),
                radial-gradient(circle at bottom left, rgba(16,185,129,0.08), transparent 35%),
                #f8fafc;
        }

        .chat-empty {
            text-align: center;
            color: var(--text-muted);
            margin-top: 32px;
            font-weight: 600;
        }

        .chat-message-row { display: flex; margin-bottom: 10px; }
        .chat-message-row.mine { justify-content: flex-start; }
        .chat-message-row.other { justify-content: flex-end; }

        .msg-bubble {
            max-width: min(82%, 520px);
            padding: 10px 12px;
            border-radius: 14px;
            box-shadow: 0 8px 18px rgba(15,23,42,0.08);
            position: relative;
            border: 1px solid transparent;
            overflow: hidden;
            word-break: break-word;
        }

        .msg-mine {
            background: linear-gradient(135deg, #ffffff, #f8fafc);
            border-color: rgba(99,102,241,0.15);
            border-bottom-left-radius: 6px;
        }

        .msg-other {
            background: linear-gradient(135deg, #6366f1, #4f46e5);
            color: #fff;
            border-bottom-right-radius: 6px;
        }

        .msg-other .chat-author,
        .msg-other .chat-time,
        .msg-other .chat-reply-preview,
        .msg-other .chat-text {
            color: #f8fafc;
        }

        .chat-author { font-size: 11px; font-weight: 700; margin-bottom: 4px; opacity: 0.88; }
        .chat-text { white-space: pre-wrap; word-break: break-word; }

        .chat-text { color: inherit !important; text-shadow: none !important; }
        .msg-mine .chat-text { color: #111827 !important; }
        .msg-other .chat-text { color: #f8fafc !important; }
        .dark-mode .msg-mine .chat-text { color: #e2e8f0 !important; }
        .dark-mode .msg-other .chat-text { color: #f8fafc !important; }
        .chat-time { font-size: 11px; opacity: 0.75; margin-top: 6px; }
        .chat-actions { display: flex; gap: 6px; margin-top: 8px; }

        .chat-reply-preview {
            border-inline-start: 3px solid rgba(99,102,241,0.45);
            padding-inline-start: 8px;
            margin-bottom: 8px;
            font-size: 11px;
        }

        .chat-media { margin-top: 8px; max-width: 100%; }
        .chat-media img {
            max-width: 100%;
            width: auto;
            max-height: 320px;
            border-radius: 10px;
            display: block;
            object-fit: cover;
            cursor: zoom-in;
            border: 1px solid rgba(148,163,184,0.25);
        }
        .chat-media audio { width: min(300px, 100%); display: block; }
        .chat-media .chat-file-link {
            max-width: 100%;
            display: inline-flex;
            white-space: normal;
            align-items: center;
            gap: 4px;
            text-align: right;
        }

        #chatImageModal .modal-content { background: rgba(2,6,23,0.95); border-color: rgba(148,163,184,0.3); }
        #chatImageModal .modal-body { text-align: center; }
        #chatImageModal img {
            max-width: 100%;
            max-height: 80vh;
            object-fit: contain;
            border-radius: 12px;
        }

        .chat-input-wrap .input-group,
        .chat-input-wrap .input-group-sm {
            border-radius: 12px;
            overflow: hidden;
        }

        .dark-mode .chat-layout {
            background: linear-gradient(180deg, rgba(19,28,46,0.98), rgba(15,23,42,0.95));
            border-color: rgba(148,163,184,0.2);
        }

        .dark-mode #chatMessagesBox {
            background:
                radial-gradient(circle at top right, rgba(99,102,241,0.2), transparent 35%),
                radial-gradient(circle at bottom left, rgba(16,185,129,0.14), transparent 35%),
                #0f172a;
            border-color: rgba(148,163,184,0.2);
        }

        .dark-mode .msg-mine {
            background: linear-gradient(135deg, #1e293b, #111827);
            border-color: rgba(148,163,184,0.25);
            color: #f1f5f9;
        }

        .dark-mode .msg-other {
            background: linear-gradient(135deg, #4f46e5, #4338ca);
            border-color: rgba(165,180,252,0.4);
            color: #fff;
        }


        .dark-mode .chat-time,
        .dark-mode .chat-author,
        .dark-mode .chat-reply-preview,
        .dark-mode #chatReplyPreview {
            color: #cbd5e1 !important;
        }

        .dark-mode .msg-other .chat-time,
        .dark-mode .msg-other .chat-author,
        .dark-mode .msg-other .chat-reply-preview {
            color: #eef2ff !important;
        }

        .no-results td {
            color: var(--text-muted);
            font-style: italic;
            padding: 30px !important;
        }

        /* ═══════════════ النماذج ═══════════════ */
        .form-control, .form-select {
            border-radius: var(--radius-sm);
            border: 1.5px solid var(--border);
            padding: 9px 14px;
            font-size: 13px;
            font-weight: 500;
            transition: all var(--t-normal) var(--ease);
            background: var(--card);
            color: var(--text);
        }

        .form-control:focus, .form-select:focus {
            border-color: var(--primary);
            box-shadow: 0 0 0 4px var(--primary-glow);
            outline: none;
        }

        .dark-mode .form-control, .dark-mode .form-select {
            background: rgba(19,28,46,0.8);
            border-color: rgba(148,163,184,0.25);
            color: #f1f5f9;
        }

        .dark-mode .form-control:focus, .dark-mode .form-select:focus {
            border-color: var(--primary-light);
            box-shadow: 0 0 0 4px rgba(99,102,241,0.25);
        }

        .dark-mode .form-control::placeholder,
        .dark-mode .form-select::placeholder {
            color: #94a3b8 !important;
            opacity: 1;
        }

        label {
            font-weight: 600;
            font-size: 13px;
            margin-bottom: 6px;
            color: var(--text);
        }

        .dark-mode label,
        .dark-mode .form-label {
            color: #e2e8f0 !important;
        }

        .hidden-field { display: none !important; }
        .form-check-label { font-size: 13px; color: var(--text); }
        .dark-mode .form-check-label { color: #e2e8f0; }

        .input-group .btn { border-radius: 0 var(--radius-sm) var(--radius-sm) 0; }
        .input-group .form-control { border-radius: var(--radius-sm) 0 0 var(--radius-sm); }

        .input-group-text {
            background: var(--bg-alt);
            border-color: var(--border);
            color: var(--text-muted);
        }

        .dark-mode .input-group-text {
            background: rgba(19,28,46,0.6);
            border-color: rgba(148,163,184,0.25);
            color: #a1b0c8;
        }

        .form-text { font-size: 11px; color: var(--text-muted); }

        /* ═══════════════ المودالات (تفتح من فوق) ═══════════════ */
        .modal-content {
            border-radius: 22px;
            border: 1px solid var(--border);
            box-shadow: var(--shadow-xl);
            background: var(--card);
            color: var(--text);
            animation: slideDown 0.4s var(--ease-bounce);
        }

        .dark-mode .modal-content {
            background: #131c2e;
            border-color: rgba(99,102,241,0.15);
            box-shadow: 0 30px 80px rgba(0,0,0,0.6), 0 0 0 1px rgba(99,102,241,0.08);
            color: #f1f5f9;
        }

        .modal-header {
            border-bottom: 1px solid var(--border);
            padding: 18px 24px;
            background: linear-gradient(135deg, rgba(99,102,241,0.04), transparent);
        }

        .dark-mode .modal-header {
            border-bottom-color: rgba(148,163,184,0.15);
            background: linear-gradient(135deg, rgba(99,102,241,0.1), transparent);
        }

        .modal-title {
            font-weight: 800;
            font-size: 17px;
            color: var(--text);
        }

        .dark-mode .modal-title { color: #f8fafc; }

        .modal-body {
            padding: 24px;
            color: var(--text);
        }

        .dark-mode .modal-body { color: #e2e8f0; }

        .modal-footer {
            border-top: 1px solid var(--border);
            padding: 14px 24px;
        }

        .dark-mode .modal-footer { border-top-color: rgba(148,163,184,0.15); }

        .modal.modal-stack-active { z-index: var(--stack-z, 1060); }
        .modal-backdrop.modal-stack-active { z-index: var(--stack-backdrop-z, 1055); }

        .dark-mode .btn-close {
            filter: invert(1) grayscale(100%) brightness(200%);
        }

        .modal-backdrop {
            backdrop-filter: blur(6px);
        }

        /* ═══════════════ التنبيهات ═══════════════ */
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
            padding: 14px 22px;
            border-radius: 14px;
            margin-bottom: 10px;
            font-weight: 600;
            font-size: 14px;
            display: flex;
            align-items: center;
            gap: 12px;
            animation: slideDown 0.4s var(--ease-bounce);
            box-shadow: var(--shadow-md);
            backdrop-filter: blur(12px);
            border: 1px solid transparent;
        }

        .custom-alert.alert-success { background: rgba(16,185,129,0.12); color: #065f46; border-right: 4px solid var(--success); border-color: rgba(16,185,129,0.2); }
        .custom-alert.alert-danger { background: rgba(239,68,68,0.12); color: #991b1b; border-right: 4px solid var(--danger); border-color: rgba(239,68,68,0.2); }
        .custom-alert.alert-warning { background: rgba(245,158,11,0.12); color: #92400e; border-right: 4px solid var(--warning); border-color: rgba(245,158,11,0.2); }
        .custom-alert.alert-info { background: rgba(6,182,212,0.12); color: #155e75; border-right: 4px solid var(--info); border-color: rgba(6,182,212,0.2); }

        .dark-mode .custom-alert.alert-success { background: rgba(16,185,129,0.18); color: #6ee7b7; border-color: rgba(16,185,129,0.3); }
        .dark-mode .custom-alert.alert-danger { background: rgba(239,68,68,0.18); color: #fca5a5; border-color: rgba(239,68,68,0.3); }
        .dark-mode .custom-alert.alert-warning { background: rgba(245,158,11,0.18); color: #fcd34d; border-color: rgba(245,158,11,0.3); }
        .dark-mode .custom-alert.alert-info { background: rgba(6,182,212,0.18); color: #67e8f9; border-color: rgba(6,182,212,0.3); }

        /* ═══════════════ التحميل ═══════════════ */
        .loading-overlay {
            position: fixed;
            top: 0; left: 0; right: 0; bottom: 0;
            background: rgba(0,0,0,0.55);
            backdrop-filter: blur(8px);
            display: none;
            align-items: center;
            justify-content: center;
            z-index: 99999;
        }

        .loading-overlay.active { display: flex; }

        .spinner-custom {
            width: 50px;
            height: 50px;
            border: 4px solid rgba(255,255,255,0.2);
            border-top: 4px solid #fff;
            border-radius: 50%;
            animation: spin 0.8s linear infinite;
            box-shadow: 0 0 30px rgba(99,102,241,0.4);
        }

        /* ═══════════════ الشارات ═══════════════ */
        .badge {
            font-size: 11px;
            padding: 5px 10px;
            border-radius: 8px;
            font-weight: 600;
            letter-spacing: 0.3px;
        }

        .badge.bg-success { background: var(--grad-success) !important; box-shadow: 0 2px 8px var(--success-glow); }
        .badge.bg-danger { background: var(--grad-danger) !important; box-shadow: 0 2px 8px var(--danger-glow); }
        .badge.bg-warning { background: var(--grad-warning) !important; color: #fff !important; }
        .badge.bg-info { background: linear-gradient(135deg, #06b6d4, #22d3ee) !important; box-shadow: 0 2px 8px var(--info-glow); }
        .badge.bg-primary { background: var(--grad-primary) !important; box-shadow: 0 2px 8px var(--primary-glow); }
        .badge.bg-secondary { background: linear-gradient(135deg, #64748b, #94a3b8) !important; }

        /* ═══════════════ أزرار الإجراءات ═══════════════ */
        .action-btn {
            font-size: 11px;
            padding: 5px 10px;
            border-radius: 8px;
            margin: 1px;
            white-space: nowrap;
            transition: all var(--t-fast) var(--ease);
        }

        .action-btn:hover {
            transform: translateY(-2px) scale(1.08);
        }

        /* ═══════════════ شريط الأدوات ═══════════════ */
        .toolbar {
            display: flex;
            gap: 10px;
            flex-wrap: wrap;
            align-items: center;
            margin-bottom: 18px;
        }

        /* ═══════════════ قسم الإضافة ═══════════════ */
        .add-section {
            background: var(--card);
            border-radius: var(--radius);
            padding: 24px;
            box-shadow: var(--shadow);
            border: 1px solid var(--border);
            margin-bottom: 24px;
            animation: cardAppear 0.5s var(--ease);
        }

        .add-section h5 {
            font-weight: 800;
            color: var(--primary);
            margin-bottom: 20px;
            display: flex;
            align-items: center;
            gap: 10px;
            font-size: 16px;
        }

        .dark-mode .add-section h5 { color: var(--primary-light); }
        .add-section h5 i { font-size: 22px; }

        /* ═══════════════ إدارة المستخدمين ═══════════════ */
        .users-section .user-card {
            background: var(--card);
            border: 1px solid var(--border);
            border-radius: 14px;
            padding: 14px 16px;
            margin-bottom: 10px;
            display: flex;
            align-items: center;
            justify-content: space-between;
            transition: all var(--t-normal) var(--ease);
        }

        .users-section .user-card:hover {
            box-shadow: var(--shadow-md);
            transform: translateY(-2px);
            border-color: var(--primary);
        }

        .users-section .user-avatar {
            width: 44px;
            height: 44px;
            border-radius: 14px;
            background: var(--grad-primary);
            color: #fff;
            display: flex;
            align-items: center;
            justify-content: center;
            font-weight: 800;
            font-size: 16px;
            box-shadow: 0 4px 14px var(--primary-glow);
        }

        /* ═══════════════ إشعارات ═══════════════ */
        .notif-patient-name {
            font-size: 12px;
            color: var(--primary);
            font-weight: 700;
        }

        .dark-mode .notif-patient-name { color: #a5b4fc; }

        .pulse-badge { animation: pulse 2s infinite; }

        /* ═══════════════ تحسينات إضافية ═══════════════ */
        .section-title {
            font-weight: 700;
            font-size: 16px;
            color: var(--text);
            margin-bottom: 14px;
            display: flex;
            align-items: center;
            gap: 8px;
        }

        .section-title i { color: var(--primary); }
        .dark-mode .section-title { color: #f1f5f9; }
        .dark-mode .section-title i { color: var(--primary-light); }

        /* ═══════════════ list-group ═══════════════ */
        .list-group-item {
            border-color: var(--border);
            background: var(--card);
            color: var(--text);
            transition: all var(--t-fast) var(--ease);
            padding: 10px 16px;
        }

        .list-group-item:hover { background: var(--card-hover); }

        .dark-mode .list-group-item {
            background: rgba(19,28,46,0.6);
            border-color: rgba(148,163,184,0.15);
            color: #e2e8f0;
        }

        .dark-mode .list-group-item:hover {
            background: rgba(19,28,46,0.8);
        }

        /* ═══════════════ تمرير مخصص ═══════════════ */
        ::-webkit-scrollbar { width: 8px; height: 8px; }
        ::-webkit-scrollbar-track { background: var(--bg); border-radius: 4px; }
        ::-webkit-scrollbar-thumb { background: #94a3b8; border-radius: 4px; }
        ::-webkit-scrollbar-thumb:hover { background: var(--primary); }

        .dark-mode ::-webkit-scrollbar-track { background: #080d1a; }
        .dark-mode ::-webkit-scrollbar-thumb { background: #475569; }
        .dark-mode ::-webkit-scrollbar-thumb:hover { background: var(--primary-light); }

        /* ═══════════════ Selection & Placeholder ═══════════════ */
        ::selection { background: rgba(99,102,241,0.2); color: var(--text); }
        .dark-mode ::selection { background: rgba(99,102,241,0.35); color: #fff; }

        ::placeholder { color: var(--text-muted) !important; opacity: 0.7; }

        /* ═══════════════ الروابط ═══════════════ */
        a { color: var(--primary); transition: all var(--t-fast) var(--ease); }
        a:hover { color: var(--primary-dark); }
        .dark-mode a { color: #a5b4fc; }
        .dark-mode a:hover { color: #c7d2fe; }

        /* ═══════════════ الحاوية ═══════════════ */
        .container-fluid.p-3 {
            padding: 24px 28px !important;
            animation: fadeIn 0.5s var(--ease);
        }

        /* ═══════════════════════════════════════════════════════════
           ███  إصلاح شامل للدارك مود - كل النصوص واضحة 100%  ███
           ═══════════════════════════════════════════════════════════ */

        /* النصوص الأساسية */
        .dark-mode,
        .dark-mode body {
            color: #f1f5f9;
        }

        .dark-mode p,
        .dark-mode span:not(.badge):not(.pulse-badge),
        .dark-mode div:not(.stat-icon):not(.login-icon),
        .dark-mode li,
        .dark-mode td,
        .dark-mode th {
            color: #e2e8f0;
        }

        /* العناوين */
        .dark-mode h1, .dark-mode h2, .dark-mode h3,
        .dark-mode h4, .dark-mode h5, .dark-mode h6 {
            color: #f8fafc !important;
        }

        /* النصوص القوية */
        .dark-mode strong, .dark-mode b {
            color: #f8fafc;
        }

        /* النصوص الصغيرة */
        .dark-mode small, .dark-mode .small {
            color: #a1b0c8;
        }

        /* text-muted */
        .dark-mode .text-muted {
            color: #a1b0c8 !important;
        }

        /* ألوان Bootstrap النصية */
        .dark-mode .text-primary { color: #a5b4fc !important; }
        .dark-mode .text-success { color: #6ee7b7 !important; }
        .dark-mode .text-danger { color: #fca5a5 !important; }
        .dark-mode .text-warning { color: #fcd34d !important; }
        .dark-mode .text-info { color: #67e8f9 !important; }
        .dark-mode .text-dark { color: #e2e8f0 !important; }
        .dark-mode .text-body { color: #f1f5f9 !important; }
        .dark-mode .text-black { color: #e2e8f0 !important; }
        .dark-mode .text-secondary { color: #cbd5e1 !important; }

        /* الخلفيات */
        .dark-mode .bg-light { background: rgba(19,28,46,0.6) !important; }
        .dark-mode .bg-white { background: #131c2e !important; }
        .dark-mode .bg-body { background: #080d1a !important; }

        /* الحدود */
        .dark-mode .border { border-color: rgba(148,163,184,0.18) !important; }
        .dark-mode .border-bottom { border-color: rgba(148,163,184,0.15) !important; }
        .dark-mode .border-top { border-color: rgba(148,163,184,0.15) !important; }

        /* alert داخل المودالات */
        .dark-mode .alert {
            color: #e2e8f0;
            border-color: rgba(148,163,184,0.2);
        }

        .dark-mode .alert-info {
            background: rgba(6,182,212,0.15);
            color: #67e8f9;
            border-color: rgba(6,182,212,0.25);
        }

        .dark-mode .alert-warning {
            background: rgba(245,158,11,0.15);
            color: #fcd34d;
            border-color: rgba(245,158,11,0.25);
        }

        .dark-mode .alert-success {
            background: rgba(16,185,129,0.15);
            color: #6ee7b7;
            border-color: rgba(16,185,129,0.25);
        }

        .dark-mode .alert-danger {
            background: rgba(239,68,68,0.15);
            color: #fca5a5;
            border-color: rgba(239,68,68,0.25);
        }

        /* readonly inputs */
        .dark-mode .form-control[readonly],
        .dark-mode input[readonly] {
            background: rgba(19,28,46,0.5) !important;
            color: #a1b0c8 !important;
            border-color: rgba(148,163,184,0.15);
        }

        /* select options */
        .dark-mode option {
            background: #131c2e;
            color: #f1f5f9;
        }

        /* card داخل card */
        .dark-mode .card {
            background: #131c2e;
            border-color: rgba(148,163,184,0.15);
            color: #f1f5f9;
        }

        .dark-mode .card-body {
            color: #e2e8f0;
        }

        .dark-mode .card-header {
            color: #f8fafc;
            border-color: rgba(148,163,184,0.15);
        }


        .dark-mode .list-group-item {
            background: #131c2e;
            border-color: rgba(148,163,184,0.18);
            color: #e2e8f0;
        }

        /* table inside dark mode */
        .dark-mode .table {
            color: #e2e8f0;
        }

        .dark-mode .table > :not(caption) > * > * {
            color: #e2e8f0;
            border-bottom-color: rgba(148,163,184,0.1);
        }

        /* btn-group in dark mode */
        .dark-mode .btn-group .btn {
            border-color: rgba(148,163,184,0.2);
        }

        /* stat-card in dark mode */
        .dark-mode .stat-card {
            background: #131c2e;
            border-color: rgba(148,163,184,0.12);
        }

        .dark-mode .stat-card .stat-value { color: #f8fafc; }
        .dark-mode .stat-card .stat-label { color: #a1b0c8; }

        /* add-section in dark mode */
        .dark-mode .add-section {
            background: #131c2e;
            border-color: rgba(148,163,184,0.15);
        }

        /* ═══════════════ الاستجابة ═══════════════ */
        @media (max-width: 768px) {
            .stats-grid { grid-template-columns: repeat(2, 1fr); gap: 10px; }
            .top-navbar { padding: 10px 16px; }
            .top-navbar .brand { font-size: 15px; }
            .top-navbar .brand i { font-size: 20px; }
            .toolbar { justify-content: center; }
            .table { font-size: 11px; }
            .action-btn { font-size: 10px; padding: 3px 7px; }
            #darkModeToggle { bottom: 14px; left: 14px; padding: 10px 16px; font-size: 12px; }
            .container-fluid.p-3 { padding: 14px !important; }
            .card-custom .card-body { padding: 16px; }
            .modal-content { border-radius: 18px; margin: 8px; }
            .nav-tabs .nav-link { padding: 8px 14px; font-size: 12px; }

            .table.mobile-readable thead {
                display: none;
            }

            .table.mobile-readable,
            .table.mobile-readable tbody,
            .table.mobile-readable tr,
            .table.mobile-readable td {
                display: block;
                width: 100%;
                text-align: right !important;
            }

            .table.mobile-readable tr {
                margin-bottom: 10px;
                border: 1px solid var(--border);
                border-radius: 12px;
                background: var(--card);
                box-shadow: 0 8px 20px rgba(15,23,42,0.05);
                padding: 8px;
            }

            .table.mobile-readable td {
                border: none !important;
                border-bottom: 1px dashed rgba(148,163,184,0.25) !important;
                padding: 8px 8px 8px 44% !important;
                position: relative;
                min-height: 36px;
            }

            .table.mobile-readable td:last-child {
                border-bottom: none !important;
            }

            .table.mobile-readable td::before {
                display: block;
                position: absolute;
                inset-inline-end: 8px;
                top: 8px;
                width: 40%;
                font-weight: 700;
                color: var(--text-muted);
                white-space: nowrap;
                overflow: hidden;
                text-overflow: ellipsis;
            }


            .dark-mode .table.mobile-readable tr {
                background: linear-gradient(145deg, #182337, #111827);
                border-color: rgba(148,163,184,0.35);
            }

            .dark-mode .table.mobile-readable td {
                color: #111827 !important;
                background: #f8fafc;
                border-bottom-color: rgba(148,163,184,0.28) !important;
            }

            .dark-mode .table.mobile-readable td::before {
                color: #334155;
            }

            #chatMessagesBox { height: 320px; }
            .msg-bubble { max-width: 90%; }
            .chat-actions { flex-wrap: wrap; }
            .chat-media img { width: 100%; max-width: 100%; }
            .chat-media .chat-file-link { width: 100%; justify-content: center; }
        }

        @media (max-width: 480px) {
            .stats-grid { grid-template-columns: repeat(2, 1fr); gap: 8px; }
            .stat-card { padding: 14px 10px; }
            .stat-card .stat-value { font-size: 20px; }
            .stat-card .stat-icon { font-size: 26px; }
            .login-card { padding: 32px 24px; }
        }

        /* ═══════════════ الطباعة ═══════════════ */
        @media print {
            .top-navbar, #darkModeToggle, .toolbar, .nav-tabs,
            .action-btn, .btn, .loading-overlay { display: none !important; }
            body { background: #fff !important; color: #000 !important; }
            body::before { display: none !important; }
            .card-custom { box-shadow: none !important; border: 1px solid #ddd !important; }
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
        <button class="btn btn-outline-light btn-sm" data-bs-toggle="modal" data-bs-target="#settingsModal" id="btnSettings" title="الإعدادات">
            <i class="bi bi-gear-fill"></i>
        </button>
        <?php endif; ?>
        <button class="btn btn-outline-light btn-sm" id="refreshAll" title="تحديث البيانات">
            <i class="bi bi-arrow-clockwise"></i>
        </button>
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
        <?php if ($_SESSION['admin_role'] === 'admin'): ?>
        <div class="stat-card">
            <div class="stat-icon"><i class="bi bi-cash-stack"></i></div>
            <div class="stat-value sensitive-value" id="stat-paid-amount" data-raw="<?php echo number_format($stats['paid_amount'], 2, '.', ''); ?>">*****</div>
            <div class="stat-label d-flex align-items-center justify-content-center gap-2">
                <span>المبالغ المدفوعة</span>
                <button type="button" class="btn-sensitive-toggle" id="toggleSensitiveAmounts" title="إظهار/إخفاء"><i class="bi bi-eye"></i></button>
            </div>
        </div>
        <div class="stat-card">
            <div class="stat-icon"><i class="bi bi-cash"></i></div>
            <div class="stat-value sensitive-value" id="stat-unpaid-amount" data-raw="<?php echo number_format($stats['unpaid_amount'], 2, '.', ''); ?>">*****</div>
            <div class="stat-label">المبالغ المستحقة</div>
        </div>
        <?php endif; ?>
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
                <i class="bi bi-chat-dots"></i> المراسلات <span class="badge bg-danger ms-1" id="chatUnreadBadge" style="display:none;">0</span>
            </button>
        </li>
        <li class="nav-item" role="presentation">
            <button class="nav-link" id="tab-queries" data-bs-toggle="tab" data-bs-target="#pane-queries" type="button" role="tab">
                <i class="bi bi-search"></i> سجل الاستعلامات
            </button>
        </li>
        <li class="nav-item" role="presentation">
            <button class="nav-link" id="tab-admin-stats" data-bs-toggle="tab" data-bs-target="#pane-admin-stats" type="button" role="tab">
                <i class="bi bi-bar-chart-line"></i> الإحصائيات
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
                        <table class="table table-bordered table-hover table-striped text-center mobile-readable" id="leavesTable">
                            <thead>
                                <tr>
                                    <th>#</th>
                                    <th>رمز الخدمة</th>
                                    <th>المريض</th>
                                    <th>الهوية</th>
                                    <th>مجلد المريض</th>
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
                                <div class="col-12"><label class="form-label">رابط مجلد المريض</label><input type="url" class="form-control" name="patient_manual_folder_link" id="patient_manual_folder_link" placeholder="https://..."></div>
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
                        <table class="table table-bordered table-hover table-striped text-center mobile-readable" id="archivedTable">
                            <thead>
                                <tr>
                                    <th>#</th>
                                    <th>رمز الخدمة</th>
                                    <th>المريض</th>
                                    <th>الهوية</th>
                                    <th>مجلد المريض</th>
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
                        <table class="table table-bordered table-hover table-striped text-center mobile-readable" id="doctorsTable">
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
                        <div class="btn-group btn-group-sm">
                            <button class="btn btn-outline-success" id="patientSortMostPaid">الأكثر دفعاً</button>
                            <button class="btn btn-outline-danger" id="patientSortMostUnpaid">الأكثر استحقاقاً</button>
                            <button class="btn btn-outline-primary" id="patientSortMostLeaves">الأكثر إجازات</button>
                            <button class="btn btn-outline-primary" id="patientSortLeastLeaves">الأقل عدد إجازات</button>
                            <button class="btn btn-outline-secondary" id="patientSortReset"><i class="bi bi-arrow-counterclockwise"></i></button>
                        </div>
                    </div>
                    <form id="addPatientForm" class="row g-2 mb-3">
                        <div class="col-md-3"><input type="text" class="form-control" name="patient_name" placeholder="اسم المريض" required></div>
                        <div class="col-md-3"><input type="text" class="form-control" name="identity_number" placeholder="رقم الهوية" required></div>
                        <div class="col-md-3"><input type="text" class="form-control" name="phone" placeholder="الهاتف"></div>
                        <div class="col-md-3"><input type="url" class="form-control" name="folder_link" placeholder="رابط مجلد المريض"></div>
                        <div class="col-md-12"><button type="submit" class="btn btn-success-custom w-100"><i class="bi bi-plus"></i> إضافة مريض</button></div>
                    </form>
                    <div class="table-responsive">
                        <table class="table table-bordered table-hover table-striped text-center mobile-readable" id="patientsTable">
                            <thead><tr><th>#</th><th>الاسم</th><th>رقم الهوية</th><th>الهاتف</th><th>المجلد</th><th>عدد الإجازات</th><th>مبلغ مدفوع</th><th>مبلغ مستحق</th><th>إجازات المريض</th><th>التحكم</th></tr></thead>
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
                            <button class="btn btn-sm btn-outline-secondary mb-2" id="refreshChatUsersBtn"><i class="bi bi-arrow-repeat"></i> تحديث المستخدمين</button>
                            <?php if ($_SESSION['admin_role'] === 'admin'): ?>
                            <div class="input-group input-group-sm mb-2">
                                <span class="input-group-text">حذف تلقائي بعد (س)</span>
                                <input type="number" min="0" class="form-control" id="chatRetentionHours" placeholder="0 = تعطيل">
                            </div>
                            <div class="d-flex gap-2">
                                <button class="btn btn-sm btn-warning" id="saveChatRetentionBtn">حفظ المدة</button>
                                <button class="btn btn-sm btn-outline-danger" id="runChatCleanupBtn">تنظيف الآن</button>
                            </div>
                            <?php endif; ?>
                        </div>
                        <div class="col-lg-8">
                            <div class="chat-layout">
                            <div id="chatMessagesBox" class="mb-2"></div>
                            <div id="chatReplyPreview" class="small text-muted mb-2 d-none"></div>
                            <div class="chat-input-wrap">
                            <div class="input-group mb-2">
                                <input type="text" class="form-control" id="chatMessageInput" placeholder="اكتب رسالتك...">
                                <button class="btn btn-gradient" id="sendChatMessageBtn"><i class="bi bi-send"></i> إرسال</button>
                                <button class="btn btn-outline-danger" id="recordVoiceBtn" type="button"><i class="bi bi-mic"></i> فويس</button>
                                <button class="btn btn-outline-secondary d-none" id="stopVoiceBtn" type="button"><i class="bi bi-stop-fill"></i> إيقاف</button>
                            </div>
                            <div class="input-group input-group-sm">
                                <input type="file" class="form-control" id="chatFileInput" accept="image/*,audio/*,.pdf,.doc,.docx,.xls,.xlsx,.txt,.mp4,.webm">
                                <button class="btn btn-outline-secondary" id="clearChatFileBtn" type="button">إلغاء المرفق</button>
                            </div>
                            </div>
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
                        <table class="table table-bordered table-hover table-striped text-center mobile-readable" id="queriesTable">
                            <thead><tr><th>#</th><th>رمز الخدمة</th><th>المريض</th><th>الهوية</th><th>تاريخ الاستعلام</th><th>المصدر</th><th>التحكم</th></tr></thead>
                            <tbody></tbody>
                        </table>
                    </div>
                </div>
            </div>
        </div>


        <div class="tab-pane fade" id="pane-admin-stats" role="tabpanel">
            <div class="card-custom stats-lux-card">
                <div class="card-header d-flex justify-content-between align-items-center flex-wrap gap-2">
                    <span><i class="bi bi-bar-chart-line text-primary"></i> الإحصائيات المتقدمة</span>
                    <div class="d-flex gap-2 flex-wrap align-items-center">
                        <select id="adminStatsRangePreset" class="form-select form-select-sm" style="min-width:130px;">
                            <option value="30">آخر 30 يوم</option>
                            <option value="90">آخر 90 يوم</option>
                            <option value="100">آخر 100 يوم</option>
                            <option value="7">آخر 7 أيام</option>
                            <option value="custom">تاريخ مخصص</option>
                        </select>
                        <input type="date" id="adminStatsFromDate" class="form-control form-control-sm" style="max-width:150px;">
                        <input type="date" id="adminStatsToDate" class="form-control form-control-sm" style="max-width:150px;">
                        <button class="btn btn-sm btn-gradient" id="applyAdminStatsRange"><i class="bi bi-funnel"></i> تطبيق</button>
                        <button class="btn btn-sm btn-outline-secondary" id="refreshAdminStats"><i class="bi bi-arrow-repeat"></i> تحديث</button>
                    </div>
                </div>
                <div class="card-body">
                    <div class="row g-2 mb-3" id="adminStatsCards"></div>

                    <div class="lux-chart-wrap mb-3">
                        <div class="d-flex justify-content-between align-items-center mb-2">
                            <h6 class="mb-0">اتجاه الإجازات اليومي</h6>
                            <small class="text-muted">إجمالي/مدفوع/غير مدفوع</small>
                        </div>
                        <canvas id="adminStatsChart" height="120"></canvas>
                    </div>

                    <h6 class="mt-2">إحصائيات يومية</h6>
                    <div class="table-responsive mb-3">
                        <table class="table table-bordered table-sm text-center" id="adminDailyStatsTable">
                            <thead><tr><th>اليوم</th><th>عدد الإجازات</th><th>مدفوعة</th><th>غير مدفوعة</th></tr></thead>
                            <tbody></tbody>
                        </table>
                    </div>
                    <div class="row g-3">
                        <div class="col-md-6">
                            <h6>أعلى الأطباء (عدد إجازات)</h6>
                            <ul class="list-group" id="adminTopDoctors"></ul>
                        </div>
                        <div class="col-md-6">
                            <h6>أعلى المرضى</h6>
                            <ul class="list-group" id="adminTopPatients"></ul>
                        </div>
                    </div>
                </div>
            </div>
        </div>

        <!-- ======================== تبويب المدفوعات ======================== -->
        <div class="tab-pane fade d-none" id="pane-payments" role="tabpanel">
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
                        <table class="table table-bordered table-hover table-striped text-center mobile-readable" id="paymentsTable">
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
                    <div class="mb-3"><label class="form-label">رابط المجلد</label><input type="url" class="form-control" name="folder_link" id="edit_patient_folder_link"></div>
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
<!-- ======================== مودال الإعدادات ======================== -->
<div class="modal fade" id="settingsModal" tabindex="-1" aria-hidden="true">
    <div class="modal-dialog modal-lg modal-dialog-centered modal-dialog-scrollable">
        <div class="modal-content">
            <div class="modal-header" style="background: var(--grad-dark); color: #fff;">
                <h5 class="modal-title"><i class="bi bi-gear-fill"></i> الإعدادات المتقدمة</h5>
                <button type="button" class="btn-close btn-close-white" data-bs-dismiss="modal"></button>
            </div>
            <div class="modal-body">
                <div class="d-flex justify-content-between align-items-center flex-wrap gap-2 mb-3">
                    <h6 class="mb-0"><i class="bi bi-palette-fill text-primary"></i> تخصيص مظهر الوضع الداكن</h6>
                    <button class="btn btn-sm btn-outline-primary" id="openUsersManagerFromSettings"><i class="bi bi-people"></i> إدارة المستخدمين</button>
                </div>
                <form id="uiAppearanceForm" class="row g-3">
                    <div class="col-12">
                        <div class="card border-0" style="background: var(--bg-alt); border-radius: 12px;">
                            <div class="card-body p-3">
                                <div class="fw-bold mb-2"><i class="bi bi-sliders"></i> إجراءات مالية سريعة</div>
                                <div class="d-flex flex-wrap gap-2">
                                    <button type="button" class="btn btn-success" id="settingsMarkAllPaidBtn"><i class="bi bi-check2-all"></i> جعل كل الإجازات مدفوعة</button>
                                    <button type="button" class="btn btn-warning" id="settingsResetAllPaymentsBtn"><i class="bi bi-eraser"></i> تصفير المدفوعات والمستحقات</button>
                                </div>
                            </div>
                        </div>
                    </div>

                    <div class="col-12">
                        <div class="card border-0" style="background: var(--bg-alt); border-radius: 12px;">
                            <div class="card-body p-3">
                                <div class="fw-bold mb-2"><i class="bi bi-magic"></i> أمزجة جاهزة للمظهر</div>
                                <div class="row g-2">
                                    <div class="col-md-6">
                                        <select class="form-select" id="settingThemePreset">
                                            <option value="">اختر مزيج جاهز...</option>
                                            <option value="classic_violet">بنفسجي كلاسيك</option>
                                            <option value="deep_ocean">أزرق محيطي</option>
                                            <option value="emerald_glow">زمردي مشع</option>
                                            <option value="sunset_gold">غروب ذهبي</option>
                                            <option value="mono_clear">أسود واضح بدون إشعاع</option>
                                        </select>
                                    </div>
                                    <div class="col-md-6 d-flex gap-2 flex-wrap" id="quickColorMixes">
                                        <button type="button" class="btn btn-sm btn-outline-primary btn-color-mix" data-text="#d8c8ff" data-glow="#8b5cf6" data-glow-enabled="1">بنفسجي</button>
                                        <button type="button" class="btn btn-sm btn-outline-info btn-color-mix" data-text="#dbeafe" data-glow="#3b82f6" data-glow-enabled="1">أزرق</button>
                                        <button type="button" class="btn btn-sm btn-outline-success btn-color-mix" data-text="#dcfce7" data-glow="#10b981" data-glow-enabled="1">أخضر</button>
                                        <button type="button" class="btn btn-sm btn-outline-warning btn-color-mix" data-text="#fde68a" data-glow="#f59e0b" data-glow-enabled="1">ذهبي</button>
                                        <button type="button" class="btn btn-sm btn-outline-dark btn-color-mix" data-text="#111827" data-glow="#111827" data-glow-enabled="0">أسود واضح</button>
                                    </div>
                                </div>
                            </div>
                        </div>
                    </div>

                    <div class="col-md-6">
                        <label class="form-label">لون النص في الدارك مود</label>
                        <input type="color" class="form-control form-control-color" id="settingDarkTextColor" value="#d8c8ff">
                    </div>
                    <div class="col-md-6">
                        <label class="form-label">لون الإشعاع</label>
                        <input type="color" class="form-control form-control-color" id="settingDarkGlowColor" value="#8b5cf6">
                    </div>
                    <div class="col-md-6">
                        <label class="form-label">نوع الخط</label>
                        <select class="form-select" id="settingFontFamily">
                            <option value="Cairo">Cairo</option>
                            <option value="Tajawal">Tajawal</option>
                            <option value="Almarai">Almarai</option>
                            <option value="Changa">Changa</option>
                            <option value="IBM Plex Sans Arabic">IBM Plex Sans Arabic</option>
                            <option value="Noto Kufi Arabic">Noto Kufi Arabic</option>
                            <option value="Readex Pro">Readex Pro</option>
                            <option value="El Messiri">El Messiri</option>
                            <option value="Reem Kufi">Reem Kufi</option>
                            <option value="Amiri">Amiri</option>
                        </select>
                    </div>
                    <div class="col-md-6 d-flex align-items-end">
                        <div class="form-check form-switch">
                            <input class="form-check-input" type="checkbox" role="switch" id="settingDarkGlowEnabled" checked>
                            <label class="form-check-label" for="settingDarkGlowEnabled">تفعيل الإشعاع للنص</label>
                        </div>
                    </div>
                    <div class="col-md-6">
                        <label class="form-label">طريقة عرض البيانات في الجداول</label>
                        <select class="form-select" id="settingDataViewMode">
                            <option value="table">جدول كلاسيكي (افتراضي)</option>
                            <option value="compact">جدول مضغوط</option>
                            <option value="cards">بطاقات بيانات</option>
                            <option value="zebra">جدول بخطوط متبادلة واضحة</option>
                        </select>
                    </div>
                    <div class="col-12 d-flex gap-2 justify-content-end">
                        <button type="button" class="btn btn-outline-secondary" id="resetAppearanceSettings"><i class="bi bi-arrow-counterclockwise"></i> افتراضي</button>
                        <button type="submit" class="btn btn-gradient"><i class="bi bi-save2"></i> حفظ الإعدادات</button>
                    </div>
                </form>
            </div>
            <div class="modal-footer"><button type="button" class="btn btn-outline-secondary" data-bs-dismiss="modal">إغلاق</button></div>
        </div>
    </div>
</div>

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
                    <table class="table table-bordered table-hover table-striped text-center mobile-readable" id="usersTable">
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
                    <table class="table table-bordered table-hover table-striped text-center mobile-readable" id="sessionsTable">
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
const INITIAL_UI_PREFERENCES = {
    dark_text_color: <?php echo json_encode($uiDarkTextColor); ?>,
    dark_glow_enabled: <?php echo json_encode($uiDarkGlowEnabled); ?>,
    dark_glow_color: <?php echo json_encode($uiDarkGlowColor); ?>,
    font_family: <?php echo json_encode($uiFontFamily); ?>,
    data_view_mode: <?php echo json_encode($uiDataViewMode); ?>
};
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
    let hour = parseInt(m[4], 10);
    const ampm = hour >= 12 ? 'م' : 'ص';
    hour = hour % 12;
    if (hour === 0) hour = 12;
    const hh = String(hour).padStart(2, '0');
    const ss = m[6] || '00';
    return `${m[3]}/${m[2]}/${m[1]} ${hh}:${m[5]}:${ss} ${ampm} (السعودية)`;
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
    applyTableMobileLabels(tableEl);
    // ترقيم الصفوف
    tbody.querySelectorAll('tr').forEach((row, i) => {
        const numCell = row.querySelector('.row-num');
        if (numCell) numCell.textContent = i + 1;
    });
}

function applyTableMobileLabels(tableEl) {
    if (!tableEl) return;
    const headers = Array.from(tableEl.querySelectorAll('thead th')).map(th => th.textContent.trim());
    tableEl.querySelectorAll('tbody tr').forEach(tr => {
        tr.querySelectorAll('td').forEach((td, idx) => {
            td.setAttribute('data-label', headers[idx] || '');
        });
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
        .replace(/[^a-z0-9\u0600-\u06FF\s]/g, ' ')
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
    win.document.write(`<html dir="rtl"><head><title>${title}</title><style>
        body{font-family:Cairo,sans-serif;direction:rtl;padding:20px;color:#1e293b}
        table{width:100%;border-collapse:collapse;border-radius:8px;overflow:hidden}
        th,td{border:1px solid #e2e8f0;padding:8px;text-align:center;font-size:12px}
        th{background:linear-gradient(135deg,#6366f1,#8b5cf6);color:#fff;font-weight:700}
        h2{text-align:center;color:#1e293b;margin-bottom:20px;font-weight:800}
        tr:nth-child(even){background:#f8fafc}
        tr:hover{background:#eef2ff}
    </style></head><body><h2>${title}</h2>${tableEl.outerHTML}</body></html>`);
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
            <td>${lv.patient_folder_link ? `<a href="${htmlspecialchars(lv.patient_folder_link)}" target="_blank" class="btn btn-sm btn-outline-primary"><i class="bi bi-folder-symlink"></i></a>` : ""}</td>
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
                    <button class="btn btn-sm btn-outline-danger action-btn btn-force-delete-active" data-id="${lv.id}" title="حذف نهائي"><i class="bi bi-trash3 btn-force-delete-active" data-id="${lv.id}"></i></button>
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
            <td>${lv.patient_folder_link ? `<a href="${htmlspecialchars(lv.patient_folder_link)}" target="_blank" class="btn btn-sm btn-outline-primary"><i class="bi bi-folder-symlink"></i></a>` : ""}</td>
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
    const total = parseInt(p.total || 0, 10);
    const paidAmount = parseFloat(p.paid_amount || 0).toFixed(2);
    const unpaidAmount = parseFloat(p.unpaid_amount || 0).toFixed(2);
    return `
        <tr data-id="${p.id}">
            <td class="row-num"></td>
            <td>${htmlspecialchars(p.name)}</td>
            <td>${htmlspecialchars(p.identity_number)}</td>
            <td>${p.phone ? `<a href="${formatWhatsAppLink(p.phone)}" target="_blank" class="text-decoration-none"><i class="bi bi-whatsapp text-success"></i> ${htmlspecialchars(p.phone)}</a>` : ''}</td>
            <td>${p.folder_link ? `<a href="${htmlspecialchars(p.folder_link)}" target="_blank" class="btn btn-sm btn-outline-primary"><i class="bi bi-folder-symlink"></i> فتح</a>` : ''}</td>
            <td><span class="badge bg-primary">${total}</span></td>
            <td><span class="text-success fw-bold">${paidAmount}</span></td>
            <td><span class="text-danger fw-bold">${unpaidAmount}</span></td>
            <td><button class="btn btn-info btn-sm action-btn btn-view-patient-leaves" data-patient-id="${p.id}"><i class="bi bi-eye-fill"></i> عرض</button></td>
            <td>
                <button class="btn btn-sm btn-gradient action-btn btn-edit-patient" data-id="${p.id}" data-name="${htmlspecialchars(p.name)}" data-identity="${htmlspecialchars(p.identity_number)}" data-phone="${htmlspecialchars(p.phone || '')}" data-folder="${htmlspecialchars(p.folder_link || '')}"><i class="bi bi-pencil"></i></button>
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
                <br><span class="notif-patient-name"><i class="bi bi-person"></i> ${htmlspecialchars(n.patient_name || 'غير معروف')} ${n.patient_phone ? `<a href="${formatWhatsAppLink(n.patient_phone)}" target="_blank" class="ms-1" title="واتساب"><i class="bi bi-whatsapp text-success"></i></a>` : ''}</span>
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

function updateChatUnreadBadge(count) {
    const badge = document.getElementById('chatUnreadBadge');
    if (!badge) return;
    const c = parseInt(count || 0, 10);
    badge.textContent = c;
    badge.style.display = c > 0 ? 'inline-block' : 'none';
}


function drawAdminStatsChart(dailyRows) {
    const canvas = document.getElementById('adminStatsChart');
    if (!canvas) return;
    const ctx = canvas.getContext('2d');
    if (!ctx) return;

    const rows = [...(dailyRows || [])].reverse();
    const w = canvas.width = canvas.clientWidth || 900;
    const h = canvas.height = 220;
    ctx.clearRect(0, 0, w, h);

    if (!rows.length) {
        ctx.fillStyle = '#6b7280';
        ctx.font = '14px sans-serif';
        ctx.fillText('لا توجد بيانات للرسم البياني', 20, 40);
        return;
    }

    const pad = { l: 40, r: 12, t: 14, b: 30 };
    const maxY = Math.max(...rows.map(r => parseInt(r.total_count || 0, 10)), 1);
    const stepX = (w - pad.l - pad.r) / Math.max(rows.length - 1, 1);
    const y = val => h - pad.b - ((val / maxY) * (h - pad.t - pad.b));

    ctx.strokeStyle = 'rgba(148,163,184,.35)';
    ctx.lineWidth = 1;
    for (let i = 0; i <= 4; i++) {
        const yy = pad.t + ((h - pad.t - pad.b) * i / 4);
        ctx.beginPath();
        ctx.moveTo(pad.l, yy);
        ctx.lineTo(w - pad.r, yy);
        ctx.stroke();
    }

    function drawLine(field, color) {
        ctx.beginPath();
        rows.forEach((r, i) => {
            const x = pad.l + i * stepX;
            const yy = y(parseInt(r[field] || 0, 10));
            if (i === 0) ctx.moveTo(x, yy); else ctx.lineTo(x, yy);
        });
        ctx.strokeStyle = color;
        ctx.lineWidth = 2.5;
        ctx.stroke();
    }

    drawLine('total_count', '#2563eb');
    drawLine('paid_count', '#059669');
    drawLine('unpaid_count', '#dc2626');

    const legends = [
        ['إجمالي', '#2563eb'],
        ['مدفوع', '#059669'],
        ['غير مدفوع', '#dc2626']
    ];
    legends.forEach((l, i) => {
        const lx = 20 + i * 110;
        const ly = h - 10;
        ctx.fillStyle = l[1];
        ctx.fillRect(lx, ly - 8, 12, 3);
        ctx.fillStyle = '#334155';
        ctx.font = '12px sans-serif';
        ctx.fillText(l[0], lx + 18, ly);
    });
}

function renderAdminStats(data) {
    const cards = document.getElementById('adminStatsCards');
    const dailyTbody = document.querySelector('#adminDailyStatsTable tbody');
    const topDoctors = document.getElementById('adminTopDoctors');
    const topPatients = document.getElementById('adminTopPatients');
    if (!cards || !dailyTbody || !topDoctors || !topPatients || !data) return;

    const t = data.totals || {};
    const canViewFinancial = !!data.can_view_financial;
    const cardItems = [
        ['إجمالي الإجازات النشطة', t.total || 0, 'primary'],
        ['المدفوعة', t.paid || 0, 'success'],
        ['غير المدفوعة', t.unpaid || 0, 'danger'],
        ['إجازات اليوم', data.today_total || 0, 'info'],
        ['مدفوعة اليوم', data.today_paid || 0, 'success'],
        ['غير مدفوعة اليوم', data.today_unpaid || 0, 'warning'],
        ['متوسط يومي', parseFloat(data.avg_daily || 0).toFixed(2), 'secondary'],
        ['ثبات النشاط %', parseFloat(data.consistency_rate || 0).toFixed(1) + '%', 'dark']
    ];
    if (canViewFinancial) {
        cardItems.splice(3, 0,
            ['إجمالي المدفوعات', parseFloat(t.paid_amount || 0).toFixed(2), 'success'],
            ['إجمالي المستحقات', parseFloat(t.unpaid_amount || 0).toFixed(2), 'danger']
        );
    }

    cards.innerHTML = cardItems.map(([label,val,color]) => `
        <div class="col-md-4 col-lg-3">
            <div class="card border-${color} h-100 shadow-sm">
                <div class="card-body py-2">
                    <div class="small text-muted">${label}</div>
                    <div class="h5 mb-0">${val}</div>
                </div>
            </div>
        </div>`).join('');

    dailyTbody.innerHTML = (data.daily || []).map(r => `
        <tr><td>${htmlspecialchars(r.day_date || '')}</td><td>${r.total_count || 0}</td><td>${r.paid_count || 0}</td><td>${r.unpaid_count || 0}</td></tr>
    `).join('') || '<tr><td colspan="4" class="text-muted">لا توجد بيانات</td></tr>';

    topDoctors.innerHTML = (data.top_doctors || []).map(d => `
        <li class="list-group-item d-flex justify-content-between"><span>${htmlspecialchars(d.name || 'غير محدد')} <small class="text-muted">${htmlspecialchars(d.title || '')}</small></span><strong>${d.leaves_count || 0}</strong></li>
    `).join('') || '<li class="list-group-item text-muted">لا توجد بيانات</li>';

    topPatients.innerHTML = (data.top_patients || []).map(p => `
        <li class="list-group-item"><div class="d-flex justify-content-between"><span>${htmlspecialchars(p.name || 'غير محدد')} (${htmlspecialchars(p.identity_number || '-')})</span><strong>${p.leaves_count || 0}</strong></div>${canViewFinancial ? `<small class="text-success">مدفوع: ${parseFloat(p.paid_amount || 0).toFixed(2)}</small> - <small class="text-danger">مستحق: ${parseFloat(p.unpaid_amount || 0).toFixed(2)}</small>` : '<small class="text-muted">البيانات المالية للمشرف فقط</small>'}</li>
    `).join('') || '<li class="list-group-item text-muted">لا توجد بيانات</li>';

    drawAdminStatsChart(data.daily || []);
}

async function fetchAdminStats() {
    const preset = document.getElementById('adminStatsRangePreset')?.value || '30';
    let rangeDays = 30;
    const payload = {};

    if (preset === 'custom') {
        payload.from_date = document.getElementById('adminStatsFromDate')?.value || '';
        payload.to_date = document.getElementById('adminStatsToDate')?.value || '';
    } else {
        rangeDays = parseInt(preset, 10) || 30;
        payload.range_days = rangeDays;
        const to = new Date();
        const from = new Date();
        from.setDate(to.getDate() - (rangeDays - 1));
        const toVal = to.toISOString().slice(0,10);
        const fromVal = from.toISOString().slice(0,10);
        const fromEl = document.getElementById('adminStatsFromDate');
        const toEl = document.getElementById('adminStatsToDate');
        if (fromEl) fromEl.value = fromVal;
        if (toEl) toEl.value = toVal;
    }

    const result = await sendAjaxRequest('fetch_admin_statistics', payload);
    if (result.success) renderAdminStats(result.data);
}

function updateStats(stats) {
    if (!stats) return;
    const setText = (id, val) => {
        const el = document.getElementById(id);
        if (el) el.textContent = val;
    };
    setText('stat-total', stats.total || 0);
    setText('stat-paid', stats.paid || 0);
    setText('stat-unpaid', stats.unpaid || 0);
    setText('stat-archived', stats.archived || 0);
    setText('stat-patients', stats.patients || 0);
    setText('stat-doctors', stats.doctors || 0);

    const paidAmountEl = document.getElementById('stat-paid-amount');
    const unpaidAmountEl = document.getElementById('stat-unpaid-amount');
    if (paidAmountEl) paidAmountEl.dataset.raw = parseFloat(stats.paid_amount || 0).toFixed(2);
    if (unpaidAmountEl) unpaidAmountEl.dataset.raw = parseFloat(stats.unpaid_amount || 0).toFixed(2);
    refreshSensitiveValuesMask();
}

function refreshSensitiveValuesMask() {
    document.querySelectorAll('.sensitive-value').forEach(el => {
        const visible = el.dataset.visible === '1';
        const raw = el.dataset.raw || '0.00';
        el.textContent = visible ? raw : '*****';
    });
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

    ['editLeaveModal','duplicateLeaveModal','confirmModal','leaveDetailsModal','viewQueriesModal','paymentNotifsModal','payConfirmModal','editDoctorModal','editPatientModal','settingsModal','addUserModal','editUserModal','sessionsModal'].forEach(setupModalStacking);

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
                if (result.unread_messages_count !== undefined) updateChatUnreadBadge(result.unread_messages_count);
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

    leavesTable.addEventListener('click', (e) => {
        const target = e.target.closest('.btn-force-delete-active') || (e.target.classList.contains('btn-force-delete-active') ? e.target : null);
        if (!target) return;
        const row = target.closest('tr');
        const leaveId = row.dataset.id;
        confirmMessage.textContent = 'تحذير! سيتم حذف هذه الإجازة نهائياً مباشرة. لا يمكن التراجع!';
        confirmYesBtn.textContent = 'نعم، حذف نهائي';
        currentConfirmAction = async () => {
            showLoading();
            const result = await sendAjaxRequest('force_delete_leave', { leave_id: leaveId });
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
        const viewBtn = e.target.closest('.btn-view-patient-leaves');
        if (viewBtn) {
            openPatientLeaves(viewBtn.dataset.patientId);
            return;
        }
        if (editBtn) {
            document.getElementById('edit_patient_id').value = editBtn.dataset.id;
            document.getElementById('edit_patient_name').value = editBtn.dataset.name;
            document.getElementById('edit_patient_identity').value = editBtn.dataset.identity;
            document.getElementById('edit_patient_phone').value = editBtn.dataset.phone;
            document.getElementById('edit_patient_folder_link').value = editBtn.dataset.folder || '';
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


    // ====== الإعدادات ======
    if (IS_ADMIN) {
        document.getElementById('openUsersManagerFromSettings')?.addEventListener('click', () => {
            const settingsModal = bootstrap.Modal.getInstance(document.getElementById('settingsModal'));
            if (settingsModal) settingsModal.hide();
            const usersModalEl = document.getElementById('addUserModal');
            if (usersModalEl) bootstrap.Modal.getOrCreateInstance(usersModalEl).show();
        });

        document.getElementById('settingsModal')?.addEventListener('show.bs.modal', async () => {
            const result = await sendAjaxRequest('fetch_ui_preferences', {});
            if (result.success && result.preferences) {
                hydrateSettingsForm(result.preferences);
                applyAppearancePreferences(result.preferences);
            } else {
                hydrateSettingsForm(INITIAL_UI_PREFERENCES);
            }
        });

        document.getElementById('resetAppearanceSettings')?.addEventListener('click', () => {
            const defaults = { dark_text_color: '#d8c8ff', dark_glow_color: '#8b5cf6', dark_glow_enabled: '1', font_family: 'Cairo', data_view_mode: 'table' };
            hydrateSettingsForm(defaults);
            applyAppearancePreferences(defaults);
        });

        const presetMap = {
            classic_violet: { dark_text_color: '#d8c8ff', dark_glow_color: '#8b5cf6', dark_glow_enabled: '1', font_family: 'Cairo', data_view_mode: 'table' },
            deep_ocean: { dark_text_color: '#dbeafe', dark_glow_color: '#2563eb', dark_glow_enabled: '1', font_family: 'IBM Plex Sans Arabic', data_view_mode: 'compact' },
            emerald_glow: { dark_text_color: '#dcfce7', dark_glow_color: '#10b981', dark_glow_enabled: '1', font_family: 'Tajawal', data_view_mode: 'cards' },
            sunset_gold: { dark_text_color: '#fde68a', dark_glow_color: '#f59e0b', dark_glow_enabled: '1', font_family: 'Changa', data_view_mode: 'zebra' },
            mono_clear: { dark_text_color: '#111827', dark_glow_color: '#111827', dark_glow_enabled: '0', font_family: 'Noto Kufi Arabic', data_view_mode: 'table' }
        };

        document.getElementById('settingThemePreset')?.addEventListener('change', function() {
            const key = this.value;
            if (!key || !presetMap[key]) return;
            hydrateSettingsForm(presetMap[key]);
            applyAppearancePreferences(presetMap[key]);
        });

        document.getElementById('settingDataViewMode')?.addEventListener('change', function() {
            applyDataViewMode(this.value || 'table');
        });

        document.querySelectorAll('.btn-color-mix').forEach(btn => {
            btn.addEventListener('click', () => {
                const pref = {
                    dark_text_color: btn.dataset.text || '#d8c8ff',
                    dark_glow_color: btn.dataset.glow || '#8b5cf6',
                    dark_glow_enabled: btn.dataset.glowEnabled || '1',
                    font_family: document.getElementById('settingFontFamily')?.value || 'Cairo',
                    data_view_mode: document.getElementById('settingDataViewMode')?.value || 'table'
                };
                hydrateSettingsForm(pref);
                applyAppearancePreferences(pref);
            });
        });

        document.getElementById('uiAppearanceForm')?.addEventListener('submit', async (e) => {
            e.preventDefault();
            const pref = {
                dark_text_color: document.getElementById('settingDarkTextColor')?.value || '#d8c8ff',
                dark_glow_color: document.getElementById('settingDarkGlowColor')?.value || '#8b5cf6',
                dark_glow_enabled: document.getElementById('settingDarkGlowEnabled')?.checked ? '1' : '0',
                font_family: document.getElementById('settingFontFamily')?.value || 'Cairo',
                data_view_mode: document.getElementById('settingDataViewMode')?.value || 'table'
            };
            const result = await sendAjaxRequest('save_ui_preferences', pref);
            if (result.success) {
                applyAppearancePreferences(result.preferences || pref);
                showToast(result.message || 'تم الحفظ.', 'success');
            }
        });
    }

    // ====== المراسلات ======
    let activeChatPeerId = null;
    let currentReplyMessage = null;
    let mediaRecorder = null;
    let voiceChunks = [];
    let chatMaxUploadMB = 50;

    function applyDataViewMode(mode = 'table') {
        const allowed = ['table','compact','cards','zebra'];
        const m = allowed.includes(mode) ? mode : 'table';
        document.body.classList.remove('data-view-table','data-view-compact','data-view-cards','data-view-zebra');
        document.body.classList.add(`data-view-${m}`);
        // إعادة رسم سريعة للتأكد من تطبيق النمط على كل الجداول مباشرة
        try { applyAllCurrentFilters(); } catch (_) {}
        [
            document.getElementById('leavesTable'),
            document.getElementById('archivedTable'),
            document.getElementById('doctorsTable'),
            document.getElementById('patientsTable'),
            document.getElementById('queriesTable'),
            document.getElementById('paymentsTable'),
            document.getElementById('usersTable'),
            document.getElementById('sessionsTable')
        ].forEach(t => { if (t) applyTableMobileLabels(t); });
    }

    function applyAppearancePreferences(pref = {}) {
        const root = document.documentElement;
        const textColor = pref.dark_text_color || '#d8c8ff';
        const glowColor = pref.dark_glow_color || '#8b5cf6';
        const glowEnabled = String(pref.dark_glow_enabled || '1') === '1';
        const fontFamily = pref.font_family || 'Cairo';
        const dataViewMode = pref.data_view_mode || 'table';
        root.style.setProperty('--dark-data-color', textColor);
        root.style.setProperty('--dark-glow-color', glowColor);
        root.style.setProperty('--dark-glow-shadow', glowEnabled ? `0 0 10px ${glowColor}` : 'none');
        root.style.setProperty('--app-font-family', `'${fontFamily}', sans-serif`);
        applyDataViewMode(dataViewMode);
    }

    function hydrateSettingsForm(pref = {}) {
        const text = document.getElementById('settingDarkTextColor');
        const glow = document.getElementById('settingDarkGlowColor');
        const enabled = document.getElementById('settingDarkGlowEnabled');
        const font = document.getElementById('settingFontFamily');
        const dataView = document.getElementById('settingDataViewMode');
        if (text) text.value = pref.dark_text_color || '#d8c8ff';
        if (glow) glow.value = pref.dark_glow_color || '#8b5cf6';
        if (enabled) enabled.checked = String(pref.dark_glow_enabled || '1') === '1';
        if (font) font.value = pref.font_family || 'Cairo';
        if (dataView) dataView.value = pref.data_view_mode || 'table';
    }

    applyAppearancePreferences(INITIAL_UI_PREFERENCES);

    function renderChatUsers(list) {
        const sel = document.getElementById('chatPeerSelect');
        if (!sel) return;
        const users = Array.isArray(list) ? list : [];
        const options = [
            { id: '__all__', label: '💬 مجموعة الكل (جروب عام)' },
            ...(IS_ADMIN ? [{ id: '__monitor__', label: '🛡️ مراقبة كل محادثات المستخدمين' }] : [])
        ];
        users.forEach(u => options.push({ id: String(u.id), label: `${u.display_name} (${u.username})` }));

        const prev = activeChatPeerId || sel.value;
        if (options.length === 0) {
            sel.innerHTML = '<option value="">لا يوجد مستخدمون</option>';
            activeChatPeerId = null;
            return;
        }

        sel.innerHTML = '<option value="">اختر جهة التواصل</option>' + options.map(o => `<option value="${htmlspecialchars(o.id)}">${htmlspecialchars(o.label)}</option>`).join('');
        if (prev && options.some(o => String(o.id) === String(prev))) {
            sel.value = prev;
            activeChatPeerId = String(prev);
        }
    }

    function renderChatMessages(list) {
        const box = document.getElementById('chatMessagesBox');
        if (!box) return;
        const me = String(<?php echo intval($_SESSION['admin_user_id'] ?? 0); ?>);
        const monitorMode = activeChatPeerId === '__monitor__';
        const rows = (list || []).map(m => {
            const mine = String(m.sender_id) === me;
            const rowClass = monitorMode ? 'mine' : (mine ? 'mine' : 'other');
            const bubbleClass = monitorMode ? 'msg-mine' : (mine ? 'msg-mine' : 'msg-other');
            const isGlobal = (m.chat_scope || '') === 'global';
            const scopeBadge = isGlobal ? '<span class="badge bg-info ms-1">مجموعة الكل</span>' : '<span class="badge bg-secondary ms-1">خاص</span>';
            const peerTarget = isGlobal ? 'مجموعة الكل' : (m.receiver_name || '');
            const peerInfo = monitorMode ? `<span class="small text-muted">${htmlspecialchars(m.sender_name || '')} → ${htmlspecialchars(peerTarget)}</span>${scopeBadge}` : '';
            const fileHtml = m.file_path
                ? (m.message_type === 'image'
                    ? `<div class="chat-media"><img class="chat-image-preview" src="${htmlspecialchars(m.file_path)}" alt="مرفق صورة"></div>`
                    : (m.message_type === 'voice'
                        ? `<div class="chat-media"><audio controls preload="metadata" src="${htmlspecialchars(m.file_path)}"></audio></div>`
                        : `<div class="chat-media"><a href="${htmlspecialchars(m.file_path)}" target="_blank" class="btn btn-sm btn-outline-primary chat-file-link"><i class="bi bi-paperclip"></i> ${htmlspecialchars(m.file_name || 'ملف')}</a></div>`))
                : '';
            const replyHtml = m.reply_to_id
                ? `<div class="chat-reply-preview"><i class="bi bi-reply"></i> ${htmlspecialchars(m.reply_message_text || m.reply_file_name || 'رسالة')}</div>`
                : '';
            const delBtn = mine || IS_ADMIN
                ? `<button class="btn btn-sm btn-outline-danger btn-delete-chat-message" data-id="${m.id}" title="حذف"><i class="bi bi-trash3"></i></button>`
                : '';
            const replyBtn = `<button class="btn btn-sm btn-outline-secondary btn-reply-chat-message" data-id="${m.id}" data-text="${htmlspecialchars(m.message_text || m.file_name || 'رسالة')}" title="رد"><i class="bi bi-reply"></i></button>`;
            return `<div class="chat-message-row ${rowClass}"><div class="msg-bubble ${bubbleClass}"><div class="chat-author">${htmlspecialchars(m.sender_name || '')}</div>${peerInfo}${replyHtml}<div class="chat-text">${htmlspecialchars(m.message_text || '')}</div>${fileHtml}<div class="chat-time">${formatSaudiDateTime(m.created_at)}</div><div class="chat-actions">${replyBtn}${delBtn}</div></div></div>`;
        }).join('');
        box.innerHTML = rows || '<div class="chat-empty">لا توجد رسائل بعد. ابدأ محادثة الآن ✨</div>';
        box.scrollTop = box.scrollHeight;
    }

    async function refreshChatUsers() {
        const result = await sendAjaxRequest('fetch_chat_users', {});
        if (result.success) {
            currentTableData.chat_users = result.users || [];
            renderChatUsers(currentTableData.chat_users);
            const rh = document.getElementById('chatRetentionHours'); if (rh && result.chat_retention_hours !== undefined) rh.value = result.chat_retention_hours;
            if (result.max_upload_mb) chatMaxUploadMB = parseInt(result.max_upload_mb, 10) || 50;
            if (result.unread_messages_count !== undefined) updateChatUnreadBadge(result.unread_messages_count);
        }
    }

    async function loadChatMessages() {
        if (!activeChatPeerId) return;
        const result = await sendAjaxRequest('fetch_messages', { peer_id: activeChatPeerId });
        if (result.success) {
            currentTableData.chat_messages = result.messages || [];
            renderChatMessages(currentTableData.chat_messages);
            const unreadRes = await sendAjaxRequest('fetch_unread_messages_count', {});
            if (unreadRes.success) updateChatUnreadBadge(unreadRes.count);
        }
    }

    // ====== البحث والفلترة ======
    const filtersState = {
        leaves: { search: '', fromDate: '', toDate: '', typeFilter: '', sortCol: 'created_at', sortOrder: 'desc' },
        archived: { search: '' },
        queries: { search: '', fromDate: '', toDate: '', sortMode: 'newest' },
        doctors: { search: '' },
        patients: { search: '', sortCol: 'total', sortOrder: 'desc' },
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
        const metricsByPatient = new Map((currentTableData.payments || []).map(p => [String(p.id), p]));
        const mergedPatients = (currentTableData.patients || []).map(p => ({
            ...p,
            ...(metricsByPatient.get(String(p.id)) || { total: 0, paid_amount: 0, unpaid_amount: 0, paid_count: 0, unpaid_count: 0 })
        }));
        filterAndSortTable(patientsTable, mergedPatients, generatePatientRow, { search: filtersState.patients.search }, filtersState.patients.sortCol, filtersState.patients.sortOrder);
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

    document.getElementById('patientSortMostPaid').addEventListener('click', () => {
        filtersState.patients.sortCol = 'paid_amount';
        filtersState.patients.sortOrder = 'desc';
        applyPatientsFilters();
    });
    document.getElementById('patientSortMostUnpaid').addEventListener('click', () => {
        filtersState.patients.sortCol = 'unpaid_amount';
        filtersState.patients.sortOrder = 'desc';
        applyPatientsFilters();
    });
    document.getElementById('patientSortMostLeaves').addEventListener('click', () => {
        filtersState.patients.sortCol = 'total';
        filtersState.patients.sortOrder = 'desc';
        applyPatientsFilters();
    });
    document.getElementById('patientSortLeastLeaves').addEventListener('click', () => {
        filtersState.patients.sortCol = 'total';
        filtersState.patients.sortOrder = 'asc';
        applyPatientsFilters();
    });
    document.getElementById('patientSortReset').addEventListener('click', () => {
        filtersState.patients.sortCol = 'total';
        filtersState.patients.sortOrder = 'desc';
        applyPatientsFilters();
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


    document.getElementById('btn-search-leaves').addEventListener('click', () => { filtersState.leaves.search = document.getElementById('searchLeaves').value; applyLeavesFilters(); });
    document.getElementById('btn-search-archived').addEventListener('click', () => {
        filtersState.archived.search = document.getElementById('searchArchived').value;
        applyArchivedFilters();
    });
    document.getElementById('btn-search-queries').addEventListener('click', () => {
        filtersState.queries.search = document.getElementById('searchQueries').value;
        applyQueriesFilters();
    });
    document.getElementById('btn-search-payments').addEventListener('click', () => { filtersState.payments.search = document.getElementById('searchPayments').value; applyPaymentsFilters(); });
    document.getElementById('btn-search-notifs').addEventListener('click', () => { filtersState.notifications.search = document.getElementById('searchNotifs').value; applyNotificationsFilters(); });

    document.getElementById('btn-search-doctors')?.addEventListener('click', () => { filtersState.doctors.search = document.getElementById('searchDoctors').value; applyDoctorsFilters(); });
    document.getElementById('btn-search-patients')?.addEventListener('click', () => { filtersState.patients.search = document.getElementById('searchPatients').value; applyPatientsFilters(); });

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

    function triggerMarkAllPaidFlow() {
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
    }

    function triggerResetAllPaymentsFlow() {
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
    }

    document.getElementById('settingsMarkAllPaidBtn')?.addEventListener('click', triggerMarkAllPaidFlow);
    document.getElementById('settingsResetAllPaymentsBtn')?.addEventListener('click', triggerResetAllPaymentsFlow);

    renderChatUsers(currentTableData.chat_users || []);
    refreshChatUsers();
    sendAjaxRequest('fetch_unread_messages_count', {}).then(r => { if (r.success) updateChatUnreadBadge(r.count); });
    setInterval(() => { sendAjaxRequest('fetch_unread_messages_count', {}).then(r => { if (r.success) updateChatUnreadBadge(r.count); }); }, 15000);
    document.getElementById('chatUsersSearch')?.addEventListener('input', debounce(function() {
        const q = this.value;
        const filtered = (currentTableData.chat_users || []).filter(u => matchesSearch(u, q));
        renderChatUsers(filtered);
    }, 120));
    document.getElementById('chatPeerSelect')?.addEventListener('change', async function() {
        activeChatPeerId = this.value || null;
        const readOnly = activeChatPeerId === '__monitor__';
        document.getElementById('chatMessageInput')?.toggleAttribute('disabled', readOnly);
        document.getElementById('chatFileInput')?.toggleAttribute('disabled', readOnly);
        document.getElementById('sendChatMessageBtn')?.toggleAttribute('disabled', readOnly);
        document.getElementById('recordVoiceBtn')?.toggleAttribute('disabled', readOnly);
        await loadChatMessages();
    });
    document.getElementById('refreshChatUsersBtn')?.addEventListener('click', async () => { await refreshChatUsers(); });
    document.getElementById('sendChatMessageBtn')?.addEventListener('click', async () => {
        const input = document.getElementById('chatMessageInput');
        const text = (input?.value || '').trim();
        const fileInput = document.getElementById('chatFileInput');
        const file = fileInput?.files?.[0] || null;
        if (!activeChatPeerId || (!text && !file)) return;
        if (activeChatPeerId === '__monitor__') {
            showToast('وضع المراقبة للقراءة فقط.', 'warning');
            return;
        }
        if (file && file.size > (chatMaxUploadMB * 1024 * 1024)) {
            showToast(`حجم الملف أكبر من ${chatMaxUploadMB}MB.`, 'danger');
            return;
        }
        const payload = { peer_id: activeChatPeerId, message_text: text, reply_to_id: currentReplyMessage ? currentReplyMessage.id : '' };
        if (file) payload.chat_file = file;
        const result = await sendAjaxRequest('send_message', payload);
        if (result.success) {
            input.value = '';
            if (fileInput) fileInput.value = '';
            currentReplyMessage = null;
            const rp = document.getElementById('chatReplyPreview'); if (rp) { rp.classList.add('d-none'); rp.textContent = ''; }
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

    
    document.getElementById('recordVoiceBtn')?.addEventListener('click', async () => {
        try {
            if (!window.MediaRecorder || !navigator.mediaDevices?.getUserMedia) {
                showToast('المتصفح لا يدعم تسجيل الفويس مباشرة. يمكنك رفع ملف صوتي يدويًا.', 'warning');
                return;
            }
            // هذا السطر يطلب إذن الميكروفون مباشرة من المتصفح
            const stream = await navigator.mediaDevices.getUserMedia({ audio: { echoCancellation: true, noiseSuppression: true, autoGainControl: true } });
            const mimeCandidates = ['audio/webm;codecs=opus', 'audio/webm', 'audio/ogg;codecs=opus', 'audio/mp4'];
            const selectedMime = mimeCandidates.find(m => MediaRecorder.isTypeSupported(m)) || '';
            mediaRecorder = selectedMime ? new MediaRecorder(stream, { mimeType: selectedMime }) : new MediaRecorder(stream);
            voiceChunks = [];
            mediaRecorder.ondataavailable = e => { if (e.data && e.data.size > 0) voiceChunks.push(e.data); };
            mediaRecorder.onerror = () => { showToast('حدث خطأ أثناء تسجيل الفويس.', 'danger'); };
            mediaRecorder.onstop = () => {
                const mime = mediaRecorder.mimeType || selectedMime || 'audio/webm';
                const ext = mime.includes('ogg') ? 'ogg' : (mime.includes('mp4') ? 'mp4' : 'webm');
                const blob = new Blob(voiceChunks, { type: mime });
                if (!blob.size) {
                    showToast('لم يتم التقاط أي صوت، حاول مرة أخرى.', 'warning');
                    return;
                }
                const file = new File([blob], `voice_${Date.now()}.${ext}`, { type: mime });
                const fileInput = document.getElementById('chatFileInput');
                const dt = new DataTransfer(); dt.items.add(file); fileInput.files = dt.files;
                stream.getTracks().forEach(t => t.stop());
                document.getElementById('recordVoiceBtn')?.classList.remove('d-none');
                document.getElementById('stopVoiceBtn')?.classList.add('d-none');
                showToast('تم تجهيز ملف الفويس، اضغط إرسال.', 'success');
            };
            mediaRecorder.start(250);
            document.getElementById('recordVoiceBtn')?.classList.add('d-none');
            document.getElementById('stopVoiceBtn')?.classList.remove('d-none');
        } catch (e) {
            showToast('تعذر بدء تسجيل الفويس. وافق على إذن الميكروفون ثم أعد المحاولة.', 'danger');
        }
    });
    document.getElementById('stopVoiceBtn')?.addEventListener('click', () => {
        if (mediaRecorder && mediaRecorder.state !== 'inactive') mediaRecorder.stop();
    });

    document.getElementById('clearChatFileBtn')?.addEventListener('click', () => {
        const f = document.getElementById('chatFileInput');
        if (f) f.value = '';
    });
    document.getElementById('chatMessagesBox')?.addEventListener('click', async (e) => {
        const del = e.target.closest('.btn-delete-chat-message');
        if (del) {
            const result = await sendAjaxRequest('delete_message', { message_id: del.dataset.id });
            if (result.success) await loadChatMessages();
            return;
        }
        const rep = e.target.closest('.btn-reply-chat-message');
        if (rep) {
            currentReplyMessage = { id: rep.dataset.id, text: rep.dataset.text };
            const rp = document.getElementById('chatReplyPreview');
            if (rp) { rp.classList.remove('d-none'); rp.textContent = `رد على: ${rep.dataset.text}`; }
            return;
        }
        const img = e.target.closest('.chat-image-preview');
        if (img) {
            const modalEl = document.getElementById('chatImageModal');
            const modalImg = document.getElementById('chatImageModalImg');
            if (modalEl && modalImg) {
                modalImg.src = img.src;
                const modal = bootstrap.Modal.getOrCreateInstance(modalEl);
                modal.show();
            }
        }
    });
    document.getElementById('saveChatRetentionBtn')?.addEventListener('click', async () => {
        const h = document.getElementById('chatRetentionHours')?.value || '0';
        await sendAjaxRequest('set_chat_retention', { hours: h });
    });
    document.getElementById('runChatCleanupBtn')?.addEventListener('click', async () => {
        if (!activeChatPeerId) { showToast('اختر محادثة أولاً.', 'warning'); return; }
        const result = await sendAjaxRequest('run_chat_cleanup', { peer_id: activeChatPeerId });
        if (result.success) await loadChatMessages();
    });


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

    // ====== عرض إجازات المريض ======
    async function openPatientLeaves(patientId) {
        showLoading();
        const result = await sendAjaxRequest('fetch_leaves_by_patient', { patient_id: patientId });
        hideLoading();

        if (!(result.success && result.leaves)) {
            leaveDetailsContainer.innerHTML = '<div class="alert alert-danger text-center mb-0">تعذر جلب إجازات المريض.</div>';
            leaveDetailsModal.show();
            return;
        }

        let html = '<div class="table-responsive"><table class="table table-bordered table-sm align-middle text-center"><thead><tr><th>رمز الخدمة</th><th>الطبيب</th><th>تاريخ الإصدار</th><th>بداية</th><th>نهاية</th><th>الأيام</th><th>النوع</th><th>الحالة</th><th>المبلغ</th><th>تاريخ الإضافة</th><th>إجراء</th></tr></thead><tbody>';
        result.leaves.forEach(lv => {
            html += `<tr>
                <td><strong>${htmlspecialchars(lv.service_code || '')}</strong></td>
                <td>${htmlspecialchars(lv.doctor_name || 'غير محدد')}<br><small class="text-muted">${htmlspecialchars(lv.doctor_title || '')}</small></td>
                <td>${htmlspecialchars(lv.issue_date || '')}</td>
                <td>${htmlspecialchars(lv.start_date || '')}</td>
                <td>${htmlspecialchars(lv.end_date || '')}</td>
                <td>${parseInt(lv.days_count || 0, 10)}</td>
                <td>${lv.is_companion == 1 ? 'مرافق' : 'أساسي'}</td>
                <td>${lv.is_paid == 1 ? '<span class="badge bg-success">مدفوعة</span>' : '<span class="badge bg-danger">غير مدفوعة</span>'}</td>
                <td>${parseFloat(lv.payment_amount || 0).toFixed(2)}</td>
                <td>${formatSaudiDateTime(lv.created_at)}</td>
                <td>
                    ${lv.is_paid == 0 ? `<button class="btn btn-sm btn-success-custom btn-mark-paid-inline" data-leave-id="${lv.id}" data-amount="${lv.payment_amount}"><i class="bi bi-cash-coin"></i> دفع</button>` : '<span class="text-success">✓</span>'}
                </td>
            </tr>`;
        });
        html += '</tbody></table></div>';

        leaveDetailsContainer.innerHTML = html;
        leaveDetailsModal.show();

        leaveDetailsContainer.querySelectorAll('.btn-mark-paid-inline').forEach(btn => {
            btn.addEventListener('click', () => {
                document.getElementById('payConfirmMessage').textContent = 'تأكيد دفع هذه الإجازة؟ يمكنك تعديل السعر قبل التأكيد.';
                document.getElementById('confirmPayAmount').value = btn.dataset.amount;
                currentConfirmAction = async () => {
                    const amount = document.getElementById('confirmPayAmount').value;
                    showLoading();
                    const payRes = await sendAjaxRequest('mark_leave_paid', { leave_id: btn.dataset.leaveId, amount: amount });
                    hideLoading();
                    if (payRes.success) {
                        showToast(payRes.message, 'success');
                        await fetchAllLeaves();
                        await openPatientLeaves(patientId);
                    }
                };
                payConfirmModal.show();
            });
        });
    }

    if (paymentsTable) {
        paymentsTable.addEventListener('click', async (e) => {
            const target = e.target.closest('.btn-view-patient-leaves') || (e.target.classList.contains('btn-view-patient-leaves') ? e.target : null);
            if (!target) return;
            await openPatientLeaves(target.dataset.patientId);
        });
    }

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


    document.getElementById('tab-admin-stats')?.addEventListener('click', () => {
        fetchAdminStats();
    });
    document.getElementById('refreshAdminStats')?.addEventListener('click', () => {
        fetchAdminStats();
    });
    document.getElementById('applyAdminStatsRange')?.addEventListener('click', () => {
        fetchAdminStats();
    });
    document.getElementById('adminStatsRangePreset')?.addEventListener('change', (e) => {
        const custom = e.target.value === 'custom';
        document.getElementById('adminStatsFromDate')?.toggleAttribute('disabled', !custom);
        document.getElementById('adminStatsToDate')?.toggleAttribute('disabled', !custom);
        if (!custom) fetchAdminStats();
    });

    const toDateDefault = new Date();
    const fromDateDefault = new Date();
    fromDateDefault.setDate(toDateDefault.getDate() - 29);
    const fromInput = document.getElementById('adminStatsFromDate');
    const toInput = document.getElementById('adminStatsToDate');
    if (fromInput) fromInput.value = fromDateDefault.toISOString().slice(0, 10);
    if (toInput) toInput.value = toDateDefault.toISOString().slice(0, 10);
    if (fromInput) fromInput.setAttribute('disabled', 'disabled');
    if (toInput) toInput.setAttribute('disabled', 'disabled');

    // ====== التحميل الأولي ======
    applyAllCurrentFilters();
    refreshSensitiveValuesMask();
    document.getElementById('toggleSensitiveAmounts')?.addEventListener('click', (e) => {
        const paidEl = document.getElementById('stat-paid-amount');
        const unpaidEl = document.getElementById('stat-unpaid-amount');
        if (!paidEl || !unpaidEl) return;
        const next = paidEl.dataset.visible === '1' ? '0' : '1';
        paidEl.dataset.visible = next;
        unpaidEl.dataset.visible = next;
        e.currentTarget.innerHTML = next === '1' ? '<i class="bi bi-eye-slash"></i>' : '<i class="bi bi-eye"></i>';
        refreshSensitiveValuesMask();
    });
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

<!-- عرض الصورة بحجم كبير -->
<div class="modal fade" id="chatImageModal" tabindex="-1" aria-hidden="true">
  <div class="modal-dialog modal-dialog-centered modal-xl">
    <div class="modal-content">
      <div class="modal-header">
        <h5 class="modal-title"><i class="bi bi-image"></i> معاينة الصورة</h5>
        <button type="button" class="btn-close" data-bs-dismiss="modal" aria-label="Close"></button>
      </div>
      <div class="modal-body">
        <img id="chatImageModalImg" src="" alt="chat image preview">
      </div>
    </div>
  </div>
</div>

</body>
</html>
