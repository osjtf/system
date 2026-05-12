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
 * 5.تحسينات عامة في الأداء والأمان
 */

// تحميل مكتبات Composer (إن وجدت)
$autoloadPath = __DIR__ . '/vendor/autoload.php';
if (file_exists($autoloadPath)) {
    require_once $autoloadPath;
}

ini_set('session.use_only_cookies', '1');
ini_set('session.cookie_httponly', '1');
ini_set('session.cookie_secure', (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off') ? '1' : '0');
ini_set('session.cookie_samesite', 'Strict');
ini_set('session.use_strict_mode', '1');
session_start();

// إخفاء معلومات الخادم والمسارات
header_remove('X-Powered-By');
header_remove('Server');

// منع عرض أخطاء PHP للمستخدمين
ini_set('display_errors', '0');
ini_set('display_startup_errors', '0');
error_reporting(0);

date_default_timezone_set('Asia/Riyadh');
header('X-Frame-Options: DENY');
header('X-Content-Type-Options: nosniff');
header('Referrer-Policy: strict-origin-when-cross-origin');
header('Permissions-Policy: geolocation=(), microphone=(self), camera=()');
header('X-Robots-Tag: noindex, nofollow, noarchive');
header('Content-Security-Policy: default-src \'self\'; script-src \'self\' \'unsafe-inline\' https://cdn.jsdelivr.net https://cdnjs.cloudflare.com; style-src \'self\' \'unsafe-inline\' https://cdn.jsdelivr.net https://cdnjs.cloudflare.com https://fonts.googleapis.com; font-src \'self\' https://fonts.gstatic.com https://cdnjs.cloudflare.com https://cdn.jsdelivr.net; img-src \'self\' data: https: blob:; connect-src \'self\'; worker-src blob:;');

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


// ======================== جدول المستشفيات ========================
$pdo->exec("CREATE TABLE IF NOT EXISTS hospitals (
    id INT AUTO_INCREMENT PRIMARY KEY,
    name_ar VARCHAR(200) NOT NULL,
    name_en VARCHAR(200) NOT NULL DEFAULT '',
    license_number VARCHAR(50) NULL,
    logo_path VARCHAR(500) NULL,
    logo_url VARCHAR(500) NULL,
    logo_data LONGTEXT NULL,
    service_prefix ENUM('GSL','PSL') DEFAULT 'GSL',
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci");

// Ensure logo_data column exists for existing tables
ensureColumn($pdo, 'hospitals', 'logo_data', "LONGTEXT NULL AFTER logo_url");
ensureColumn($pdo, 'hospitals', 'logo_scale', "FLOAT DEFAULT 1.0 AFTER logo_data");
ensureColumn($pdo, 'hospitals', 'logo_offset_x', "FLOAT DEFAULT 0 AFTER logo_scale");
ensureColumn($pdo, 'hospitals', 'logo_offset_y', "FLOAT DEFAULT 0 AFTER logo_offset_x");
ensureColumn($pdo, 'hospitals', 'deleted_at', "DATETIME NULL AFTER updated_at");
try { ensureIndex($pdo, 'hospitals', 'idx_hospitals_deleted_name', 'deleted_at, name_ar'); } catch(Exception $e) {}

$pdo->exec("CREATE TABLE IF NOT EXISTS doctors (
    id INT AUTO_INCREMENT PRIMARY KEY,
    name VARCHAR(150) DEFAULT '',
    name_ar VARCHAR(200) DEFAULT '',
    name_en VARCHAR(200) DEFAULT '',
    title VARCHAR(150) DEFAULT '',
    title_ar VARCHAR(200) DEFAULT '',
    title_en VARCHAR(200) DEFAULT '',
    hospital_id INT NULL,
    note TEXT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci");

$pdo->exec("CREATE TABLE IF NOT EXISTS patients (
    id INT AUTO_INCREMENT PRIMARY KEY,
    name VARCHAR(150) DEFAULT '',
    name_ar VARCHAR(200) DEFAULT '',
    name_en VARCHAR(200) DEFAULT '',
    identity_number VARCHAR(50) NOT NULL,
    phone VARCHAR(30) NULL,
    folder_link VARCHAR(500) NULL,
    employer_ar VARCHAR(200) DEFAULT '',
    employer_en VARCHAR(200) DEFAULT '',
    nationality_ar VARCHAR(100) DEFAULT '',
    nationality_en VARCHAR(100) DEFAULT '',
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    UNIQUE KEY uniq_patients_identity_number (identity_number)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci");

$pdo->exec("CREATE TABLE IF NOT EXISTS sick_leaves (
    id INT AUTO_INCREMENT PRIMARY KEY,
    service_code VARCHAR(50) NOT NULL,
    patient_id INT NOT NULL,
    doctor_id INT NOT NULL,
    hospital_id INT NULL,
    created_by_user_id INT NULL,
    issue_date DATE NOT NULL,
    issue_time VARCHAR(10) NULL,
    issue_period ENUM('AM','PM') NULL,
    start_date DATE NOT NULL,
    end_date DATE NOT NULL,
    days_count INT NOT NULL,
    patient_name_en VARCHAR(200) DEFAULT '',
    doctor_name_en VARCHAR(200) DEFAULT '',
    doctor_title_en VARCHAR(200) DEFAULT '',
    hospital_name_ar VARCHAR(255) DEFAULT '',
    hospital_name_en VARCHAR(255) DEFAULT '',
    logo_path VARCHAR(500) DEFAULT '',
    employer_ar VARCHAR(200) DEFAULT '',
    employer_en VARCHAR(200) DEFAULT '',
    is_companion TINYINT(1) DEFAULT 0,
    companion_name VARCHAR(150) NULL,
    companion_relation VARCHAR(150) NULL,
    is_paid TINYINT(1) DEFAULT 0,
    payment_amount DECIMAL(10,2) DEFAULT 0,
    deleted_at DATETIME NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    UNIQUE KEY uniq_sick_leaves_service_code (service_code),
    CONSTRAINT fk_sick_leaves_patient FOREIGN KEY (patient_id) REFERENCES patients(id) ON DELETE RESTRICT,
    CONSTRAINT fk_sick_leaves_doctor FOREIGN KEY (doctor_id) REFERENCES doctors(id) ON DELETE RESTRICT
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci");

$pdo->exec("CREATE TABLE IF NOT EXISTS notifications (
    id INT AUTO_INCREMENT PRIMARY KEY,
    type VARCHAR(50) NOT NULL,
    leave_id INT NOT NULL,
    message TEXT NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT fk_notifications_leave FOREIGN KEY (leave_id) REFERENCES sick_leaves(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci");

$pdo->exec("CREATE TABLE IF NOT EXISTS leave_queries (
    id INT AUTO_INCREMENT PRIMARY KEY,
    leave_id INT NOT NULL,
    queried_at DATETIME NOT NULL,
    source VARCHAR(20) NOT NULL DEFAULT 'external',
    CONSTRAINT fk_leave_queries_leave FOREIGN KEY (leave_id) REFERENCES sick_leaves(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci");

function tableExists(PDO $pdo, string $table): bool {
    $stmt = $pdo->prepare("SELECT COUNT(*) FROM information_schema.tables WHERE table_schema = DATABASE() AND table_name = ?");
    $stmt->execute([$table]);
    return (int)$stmt->fetchColumn() > 0;
}

function ensureColumn(PDO $pdo, string $table, string $column, string $definition): void {
    if (!tableExists($pdo, $table)) {
        return;
    }
    $stmt = $pdo->prepare("SELECT COUNT(*) FROM information_schema.columns WHERE table_schema = DATABASE() AND table_name = ? AND column_name = ?");
    $stmt->execute([$table, $column]);
    if ((int)$stmt->fetchColumn() === 0) {
        $pdo->exec("ALTER TABLE $table ADD COLUMN $column $definition");
    }
}

function ensureIndex(PDO $pdo, string $table, string $indexName, string $columns): void {
    if (!tableExists($pdo, $table)) {
        return;
    }
    $check = $pdo->prepare("SELECT COUNT(*) FROM information_schema.statistics WHERE table_schema = DATABASE() AND table_name = ? AND index_name = ?");
    $check->execute([$table, $indexName]);
    if ((int)$check->fetchColumn() === 0) {
        $pdo->exec("CREATE INDEX $indexName ON $table ($columns)");
    }
}

// ======================== إضافة كل الأعمدة أولاً ========================
ensureColumn($pdo, 'sick_leaves', 'created_by_user_id', "INT NULL AFTER doctor_id");
ensureColumn($pdo, 'sick_leaves', 'patient_name_en', "VARCHAR(200) NULL AFTER days_count");
ensureColumn($pdo, 'sick_leaves', 'doctor_name_en', "VARCHAR(200) NULL AFTER patient_name_en");
ensureColumn($pdo, 'sick_leaves', 'doctor_title_en', "VARCHAR(200) NULL AFTER doctor_name_en");
ensureColumn($pdo, 'sick_leaves', 'hospital_name_ar', "VARCHAR(255) NULL AFTER doctor_title_en");
ensureColumn($pdo, 'sick_leaves', 'hospital_name_en', "VARCHAR(255) NULL AFTER hospital_name_ar");
ensureColumn($pdo, 'sick_leaves', 'logo_path', "VARCHAR(500) NULL AFTER hospital_name_en");
ensureColumn($pdo, 'hospitals', 'logo_url', "VARCHAR(500) NULL AFTER logo_path");
ensureColumn($pdo, 'patients', 'folder_link', "VARCHAR(500) NULL AFTER phone");

// ======================== أعمدة جديدة للمستشفيات والأطباء والمرضى ========================
// ضمان وجود الأعمدة الأساسية القديمة (name, title) قبل تعديلها
ensureColumn($pdo, 'doctors', 'name', "VARCHAR(150) NOT NULL DEFAULT ''");
ensureColumn($pdo, 'doctors', 'title', "VARCHAR(150) NOT NULL DEFAULT ''");
ensureColumn($pdo, 'patients', 'name', "VARCHAR(150) NOT NULL DEFAULT ''");
// تعديل الأعمدة القديمة لتكون اختيارية
try { $pdo->exec("ALTER TABLE doctors MODIFY COLUMN name VARCHAR(150) DEFAULT ''"); } catch(Exception $e) {}
try { $pdo->exec("ALTER TABLE doctors MODIFY COLUMN title VARCHAR(150) DEFAULT ''"); } catch(Exception $e) {}
try { $pdo->exec("ALTER TABLE patients MODIFY COLUMN name VARCHAR(150) DEFAULT ''"); } catch(Exception $e) {}

// أعمدة الأطباء الجديدة
ensureColumn($pdo, 'doctors', 'name_ar', "VARCHAR(200) NULL AFTER name");
ensureColumn($pdo, 'doctors', 'name_en', "VARCHAR(200) NULL AFTER name_ar");
ensureColumn($pdo, 'doctors', 'title_ar', "VARCHAR(200) NULL AFTER title");
ensureColumn($pdo, 'doctors', 'title_en', "VARCHAR(200) NULL AFTER title_ar");
ensureColumn($pdo, 'doctors', 'hospital_id', "INT NULL AFTER title_en");

// أعمدة المرضى الجديدة
ensureColumn($pdo, 'patients', 'name_ar', "VARCHAR(200) NULL AFTER name");
ensureColumn($pdo, 'patients', 'name_en', "VARCHAR(200) NULL AFTER name_ar");
ensureColumn($pdo, 'patients', 'employer_ar', "VARCHAR(200) NULL AFTER name_en");
ensureColumn($pdo, 'patients', 'employer_en', "VARCHAR(200) NULL AFTER employer_ar");
ensureColumn($pdo, 'patients', 'nationality_ar', "VARCHAR(100) NULL AFTER employer_en");
ensureColumn($pdo, 'patients', 'nationality_en', "VARCHAR(100) NULL AFTER nationality_ar");

// أعمدة الإجازات الجديدة
ensureColumn($pdo, 'sick_leaves', 'hospital_id', "INT NULL AFTER doctor_id");
ensureColumn($pdo, 'sick_leaves', 'issue_time', "VARCHAR(10) NULL AFTER issue_date");
ensureColumn($pdo, 'sick_leaves', 'issue_period', "ENUM('AM','PM') NULL AFTER issue_time");
ensureColumn($pdo, 'sick_leaves', 'employer_ar', "VARCHAR(200) NULL AFTER logo_path");
ensureColumn($pdo, 'sick_leaves', 'employer_en', "VARCHAR(200) NULL AFTER employer_ar");

// ======================== إنشاء الفهارس بعد التأكد من وجود كل الأعمدة ========================
try { ensureIndex($pdo, 'sick_leaves', 'idx_sick_leaves_deleted_created', 'deleted_at, created_at'); } catch(Exception $e) {}
try { ensureIndex($pdo, 'sick_leaves', 'idx_sick_leaves_paid', 'is_paid'); } catch(Exception $e) {}
try { ensureIndex($pdo, 'sick_leaves', 'idx_sick_leaves_patient', 'patient_id'); } catch(Exception $e) {}
try { ensureIndex($pdo, 'sick_leaves', 'idx_sick_leaves_doctor', 'doctor_id'); } catch(Exception $e) {}
try { ensureIndex($pdo, 'sick_leaves', 'idx_sick_leaves_created_by_user', 'created_by_user_id'); } catch(Exception $e) {}
try { ensureIndex($pdo, 'notifications', 'idx_notifications_type_created', 'type, created_at'); } catch(Exception $e) {}
try { ensureIndex($pdo, 'notifications', 'idx_notifications_leave', 'leave_id'); } catch(Exception $e) {}
try { ensureIndex($pdo, 'leave_queries', 'idx_leave_queries_leave', 'leave_id'); } catch(Exception $e) {}
try { ensureIndex($pdo, 'leave_queries', 'idx_leave_queries_queried_at', 'queried_at'); } catch(Exception $e) {}
try { ensureIndex($pdo, 'patients', 'idx_patients_identity_number', 'identity_number'); } catch(Exception $e) {}
try { ensureIndex($pdo, 'patients', 'idx_patients_name_ar', 'name_ar'); } catch(Exception $e) {}
try { ensureIndex($pdo, 'doctors', 'idx_doctors_name_ar', 'name_ar'); } catch(Exception $e) {}
try { ensureIndex($pdo, 'user_messages', 'idx_user_messages_pair_created', 'sender_id, receiver_id, created_at'); } catch(Exception $e) {}
try { ensureIndex($pdo, 'user_messages', 'idx_user_messages_receiver_read', 'receiver_id, is_read'); } catch(Exception $e) {}
ensureColumn($pdo, 'user_messages', 'message_type', "ENUM('text','image','file','voice') DEFAULT 'text' AFTER message_text");
ensureColumn($pdo, 'user_messages', 'file_name', "VARCHAR(255) NULL AFTER message_type");
ensureColumn($pdo, 'user_messages', 'file_path', "VARCHAR(500) NULL AFTER file_name");
ensureColumn($pdo, 'user_messages', 'mime_type', "VARCHAR(150) NULL AFTER file_path");
ensureColumn($pdo, 'user_messages', 'file_size', "INT NULL AFTER mime_type");
ensureColumn($pdo, 'user_messages', 'deleted_at', "DATETIME NULL AFTER is_read");
ensureColumn($pdo, 'user_messages', 'reply_to_id', "INT NULL AFTER deleted_at");
ensureColumn($pdo, 'user_messages', 'chat_scope', "ENUM('private','global') DEFAULT 'private' AFTER reply_to_id");
ensureColumn($pdo, 'user_messages', 'broadcast_group_id', "VARCHAR(50) NULL AFTER chat_scope");
try { ensureIndex($pdo, 'user_messages', 'idx_user_messages_scope_created', 'chat_scope, created_at'); } catch(Exception $e) {}
try { ensureIndex($pdo, 'user_messages', 'idx_user_messages_broadcast', 'broadcast_group_id'); } catch(Exception $e) {}
try { ensureIndex($pdo, 'user_messages', 'idx_user_messages_deleted', 'deleted_at'); } catch(Exception $e) {}

// ======================== جدول مدفوعات الحسابات ========================
$pdo->exec("CREATE TABLE IF NOT EXISTS account_payments (
    id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT NOT NULL,
    amount DECIMAL(10,2) NOT NULL DEFAULT 0,
    note VARCHAR(500) NULL,
    paid_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    created_by INT NULL,
    FOREIGN KEY (user_id) REFERENCES admin_users(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci");

// ======================== جدول حسابات المرضى (منفصل عن مستخدمي لوحة التحكم) ========================
$pdo->exec("CREATE TABLE IF NOT EXISTS patient_accounts (
    id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT NOT NULL UNIQUE,
    patient_id INT NOT NULL,
    allowed_days INT DEFAULT 0,
    expiry_date DATE NULL,
    notes TEXT NULL,
    FOREIGN KEY (user_id) REFERENCES admin_users(id) ON DELETE CASCADE,
    FOREIGN KEY (patient_id) REFERENCES patients(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci");

// أعمدة patient_accounts الجديدة
ensureColumn($pdo, 'patient_accounts', 'expiry_date', "DATE NULL AFTER allowed_days");
ensureColumn($pdo, 'patient_accounts', 'notes', "TEXT NULL AFTER expiry_date");
ensureColumn($pdo, 'account_payments', 'days_count', "INT NOT NULL DEFAULT 0 AFTER amount");
ensureColumn($pdo, 'account_payments', 'is_paid', "TINYINT(1) NOT NULL DEFAULT 1 AFTER days_count");
ensureColumn($pdo, 'account_payments', 'paid_by', "INT NULL AFTER created_by");
ensureColumn($pdo, 'account_payments', 'updated_at', "DATETIME DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP AFTER paid_at");
try { ensureIndex($pdo, 'account_payments', 'idx_account_payments_user_paid', 'user_id, is_paid, paid_at'); } catch(Exception $e) {}
ensureColumn($pdo, 'notifications', 'account_payment_id', "INT NULL AFTER leave_id");
try { $pdo->exec("ALTER TABLE notifications MODIFY COLUMN leave_id INT NULL"); } catch(Throwable $e) {}
try { ensureIndex($pdo, 'notifications', 'idx_notifications_account_payment', 'account_payment_id'); } catch(Exception $e) {}

// ======================== جدول إشعارات المستخدمين (المرضى) ========================
$pdo->exec("CREATE TABLE IF NOT EXISTS user_notifications (
    id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT NOT NULL,
    message TEXT NOT NULL,
    is_read TINYINT(1) DEFAULT 0,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES admin_users(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci");

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
        || (isset($_POST['action']) && !empty($_POST['action']))
        || (isset($_GET['action']) && !empty($_GET['action']));
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
    $stats['paid_amount'] = $pdo->query("SELECT COALESCE(SUM(amount), 0) FROM (SELECT payment_amount AS amount FROM sick_leaves WHERE is_paid = 1 AND deleted_at IS NULL UNION ALL SELECT amount FROM account_payments WHERE is_paid = 1) paid_totals")->fetchColumn();
    $stats['unpaid_amount'] = $pdo->query("SELECT COALESCE(SUM(amount), 0) FROM (SELECT payment_amount AS amount FROM sick_leaves WHERE is_paid = 0 AND deleted_at IS NULL UNION ALL SELECT amount FROM account_payments WHERE is_paid = 0) unpaid_totals")->fetchColumn();
    $stats['hospitals'] = $pdo->query("SELECT COUNT(*) FROM hospitals WHERE deleted_at IS NULL")->fetchColumn();
    return $stats;
}

function getHospitalsList(PDO $pdo): array {
    return $pdo->query("
        SELECT id, name_ar, name_en, license_number, logo_path, logo_url,
               service_prefix, logo_scale, logo_offset_x, logo_offset_y,
               created_at, updated_at,
               CASE WHEN logo_data IS NOT NULL AND logo_data != '' THEN 'has_logo' ELSE '' END AS has_logo_data
        FROM hospitals
        WHERE deleted_at IS NULL
        ORDER BY name_ar
    ")->fetchAll();
}

function normalizeUsernameText(string $value): string {
    $value = preg_replace('/[^\p{L}\p{N}._-]+/u', '', trim($value));
    if ($value === '') return 'patient';
    return function_exists('mb_strtolower') ? mb_strtolower($value, 'UTF-8') : strtolower($value);
}

function makePatientFirstNameUsername(array $patient): string {
    $source = trim((string)($patient['name_en'] ?? $patient['name_ar'] ?? $patient['name'] ?? 'patient'));
    $parts = preg_split('/\s+/u', $source, -1, PREG_SPLIT_NO_EMPTY);
    return normalizeUsernameText($parts[0] ?? 'patient');
}

function getNextPatientAccountNumber(PDO $pdo): int {
    return ((int)$pdo->query("SELECT COUNT(*) FROM patient_accounts")->fetchColumn()) + 1;
}

function makeUniqueUsername(PDO $pdo, string $baseUsername): string {
    $baseUsername = normalizeUsernameText($baseUsername);
    $candidate = $baseUsername;
    $counter = 2;
    $stmt = $pdo->prepare("SELECT id FROM admin_users WHERE username = ? LIMIT 1");
    while (true) {
        $stmt->execute([$candidate]);
        if (!$stmt->fetch()) return $candidate;
        $candidate = $baseUsername . $counter;
        $counter++;
    }
}

function nowSaudi(): string {
    return (new DateTime('now', new DateTimeZone('Asia/Riyadh')))->format('Y-m-d H:i:s');
}

function getUsedPatientAccountDays(PDO $pdo, int $patientId, int $userId): int {
    $stmt = $pdo->prepare("SELECT COALESCE(SUM(days_count),0) FROM sick_leaves WHERE patient_id = ? AND created_by_user_id = ? AND deleted_at IS NULL");
    $stmt->execute([$patientId, $userId]);
    return (int)$stmt->fetchColumn();
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

function uploadLeaveLogo(array $file): ?string {
    if (empty($file) || ($file['error'] ?? UPLOAD_ERR_NO_FILE) === UPLOAD_ERR_NO_FILE) {
        return null;
    }
    if (($file['error'] ?? UPLOAD_ERR_OK) !== UPLOAD_ERR_OK) {
        return null;
    }
    $tmp = $file['tmp_name'] ?? '';
    if (!$tmp || !is_uploaded_file($tmp)) {
        return null;
    }
    $finfo = new finfo(FILEINFO_MIME_TYPE);
    $mime = (string)$finfo->file($tmp);
    $allowed = [
        'image/png' => 'png',
        'image/jpeg' => 'jpg',
        'image/webp' => 'webp',
        'image/gif' => 'gif',
        'image/svg+xml' => 'svg+xml'
    ];
    if (!isset($allowed[$mime])) {
        return null;
    }
    // Return as base64 data URI (Railway ephemeral filesystem safe)
    $data = file_get_contents($tmp);
    if (!$data) return null;
    return 'data:' . $mime . ';base64,' . base64_encode($data);
}

// ======================== دوال المستشفيات والتواريخ ========================
function uploadHospitalLogo(array $file): ?string {
    if (empty($file) || ($file['error'] ?? UPLOAD_ERR_NO_FILE) === UPLOAD_ERR_NO_FILE) return null;
    if (($file['error'] ?? UPLOAD_ERR_OK) !== UPLOAD_ERR_OK) return null;
    $tmp = $file['tmp_name'] ?? '';
    if (!$tmp || !is_uploaded_file($tmp)) return null;
    $finfo = new finfo(FILEINFO_MIME_TYPE);
    $mime = (string)$finfo->file($tmp);
    $allowed = ['image/png'=>'png','image/jpeg'=>'jpg','image/webp'=>'webp','image/gif'=>'gif','image/svg+xml'=>'svg+xml'];
    if (!isset($allowed[$mime])) return null;
    $data = file_get_contents($tmp);
    if (!$data) return null;
    return 'data:' . $mime . ';base64,' . base64_encode($data);
}

function downloadLogoFromUrl(string $url): ?string {
    $url = trim($url);
    if (empty($url)) return null;
    // If URL is already a data URI, return as-is
    if (strpos($url, 'data:image/') === 0) return $url;
    $ctx = stream_context_create(['http' => ['timeout' => 15, 'user_agent' => 'Mozilla/5.0'], 'ssl' => ['verify_peer' => false]]);
    $data = @file_get_contents($url, false, $ctx);
    if (!$data) return null;
    $finfo = new finfo(FILEINFO_MIME_TYPE);
    $mime = $finfo->buffer($data);
    $allowed = ['image/png'=>'png','image/jpeg'=>'jpg','image/webp'=>'webp','image/gif'=>'gif','image/svg+xml'=>'svg+xml'];
    if (!isset($allowed[$mime])) return null;
    return 'data:' . $mime . ';base64,' . base64_encode($data);
}

function gregorianToHijri($gYear, $gMonth, $gDay) {
    // Tabular Islamic Calendar conversion (accurate to ±1-2 days)
    $gYear = (int)$gYear; $gMonth = (int)$gMonth; $gDay = (int)$gDay;
    
    // Step 1: Gregorian to Julian Day Number
    $a = intval((14 - $gMonth) / 12);
    $y = $gYear + 4800 - $a;
    $m = $gMonth + 12 * $a - 3;
    $jdn = $gDay + intval((153 * $m + 2) / 5) + 365 * $y + intval($y / 4) - intval($y / 100) + intval($y / 400) - 32045;
    
    // Step 2: JDN to Hijri using tabular Islamic calendar
    $epoch = 1948440;
    $days = $jdn - $epoch;
    
    // Approximate year
    $hYear = intval(floor(($days - 1) / 354.36667) + 1);
    
    // Leap years in 30-year cycle
    $leapYears = [2, 5, 7, 10, 13, 16, 18, 21, 24, 26, 29];
    
    // Calculate start of Hijri year
    $hijriYearStart = function($year) use ($epoch, $leapYears) {
        $y2 = $year - 1;
        $cycle = intval($y2 / 30);
        $yearInCycle = $y2 % 30;
        $leapCount = 0;
        foreach ($leapYears as $ly) {
            if ($ly <= $yearInCycle) $leapCount++;
        }
        return $epoch + $cycle * 10631 + $yearInCycle * 354 + $leapCount;
    };
    
    // Adjust year
    while ($hijriYearStart($hYear + 1) <= $jdn) $hYear++;
    while ($hijriYearStart($hYear) > $jdn) $hYear--;
    
    // Day of year
    $dayOfYear = $jdn - $hijriYearStart($hYear) + 1;
    
    // Determine if leap year
    $isLeap = in_array($hYear % 30, $leapYears);
    
    // Calculate month and day
    $hMonth = 1;
    $hDay = $dayOfYear;
    $remaining = $dayOfYear;
    for ($monthNum = 1; $monthNum <= 12; $monthNum++) {
        $monthDays = ($monthNum % 2 == 1) ? 30 : 29;
        if ($monthNum == 12 && $isLeap) $monthDays = 30;
        if ($remaining <= $monthDays) {
            $hMonth = $monthNum;
            $hDay = $remaining;
            break;
        }
        $remaining -= $monthDays;
    }
    
    return ['year' => $hYear, 'month' => $hMonth, 'day' => $hDay];
}

function getHijriMonthName($month) {
    $months = [1=>'\u0645\u062d\u0631\u0645',2=>'\u0635\u0641\u0631',3=>'\u0631\u0628\u064a\u0639 \u0627\u0644\u0623\u0648\u0644',4=>'\u0631\u0628\u064a\u0639 \u0627\u0644\u062b\u0627\u0646\u064a',5=>'\u062c\u0645\u0627\u062f\u0649 \u0627\u0644\u0623\u0648\u0644\u0649',6=>'\u062c\u0645\u0627\u062f\u0649 \u0627\u0644\u062b\u0627\u0646\u064a\u0629',7=>'\u0631\u062c\u0628',8=>'\u0634\u0639\u0628\u0627\u0646',9=>'\u0631\u0645\u0636\u0627\u0646',10=>'\u0634\u0648\u0627\u0644',11=>'\u0630\u0648 \u0627\u0644\u0642\u0639\u062f\u0629',12=>'\u0630\u0648 \u0627\u0644\u062d\u062c\u0629'];
    return $months[(int)$month] ?? '';
}

function getArabicDayName($date) {
    $days = ['Sunday'=>'\u0627\u0644\u0623\u062d\u062f','Monday'=>'\u0627\u0644\u0627\u062b\u0646\u064a\u0646','Tuesday'=>'\u0627\u0644\u062b\u0644\u0627\u062b\u0627\u0621','Wednesday'=>'\u0627\u0644\u0623\u0631\u0628\u0639\u0627\u0621','Thursday'=>'\u0627\u0644\u062e\u0645\u064a\u0633','Friday'=>'\u0627\u0644\u062c\u0645\u0639\u0629','Saturday'=>'\u0627\u0644\u0633\u0628\u062a'];
    $d = new DateTime($date);
    return $days[$d->format('l')] ?? '';
}

function getArabicMonthName($month) {
    $months = [1=>'\u064a\u0646\u0627\u064a\u0631',2=>'\u0641\u0628\u0631\u0627\u064a\u0631',3=>'\u0645\u0627\u0631\u0633',4=>'\u0623\u0628\u0631\u064a\u0644',5=>'\u0645\u0627\u064a\u0648',6=>'\u064a\u0648\u0646\u064a\u0648',7=>'\u064a\u0648\u0644\u064a\u0648',8=>'\u0623\u063a\u0633\u0637\u0633',9=>'\u0633\u0628\u062a\u0645\u0628\u0631',10=>'\u0623\u0643\u062a\u0648\u0628\u0631',11=>'\u0646\u0648\u0641\u0645\u0628\u0631',12=>'\u062f\u064a\u0633\u0645\u0628\u0631'];
    return $months[(int)$month] ?? '';
}

function normalizeIssueTimeForStorage(?string $time, ?string $period = null): ?string {
    $time = trim((string)$time);
    if ($time === '') return null;
    if (preg_match('/^(\d{1,2}):(\d{2})(?::\d{2})?$/', $time, $m)) {
        $hour = max(0, min(23, (int)$m[1]));
        $minute = max(0, min(59, (int)$m[2]));
        if ($hour > 12) {
            $hour -= 12;
        } elseif ($hour === 0) {
            $hour = 12;
        }
        return sprintf('%02d:%02d', $hour, $minute);
    }
    return $time;
}

function formatIssueTimeForDisplay(?string $time, ?string $period = null): string {
    $normalized = normalizeIssueTimeForStorage($time, $period);
    return $normalized ?: '09:00';
}

function formatHijriDateSpan(string $date): string {
    $safeDate = htmlspecialchars($date, ENT_QUOTES);
    return '<span dir="ltr" style="unicode-bidi:isolate;direction:ltr;display:inline-block;">' . $safeDate . '</span>';
}

function formatDaysText($days) {
    $days = (int)$days;
    return $days . ($days === 1 ? ' day' : ' days');
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

function extractFirstJsonObject(string $raw): ?array {
    $trimmed = trim($raw);
    $decoded = json_decode($trimmed, true);
    if (is_array($decoded)) {
        return $decoded;
    }

    if (preg_match('/\{(?:[^{}]|(?R))*\}/s', $trimmed, $m)) {
        $decoded = json_decode($m[0], true);
        if (is_array($decoded)) {
            return $decoded;
        }
    }
    return null;
}

function normalizeAiDraft(array $draft): array {
    $allowed = [
        'patient_name', 'patient_identity', 'patient_phone', 'patient_folder_link',
        'doctor_name', 'doctor_title', 'doctor_note',
        'issue_date', 'start_date', 'end_date', 'days_count',
        'service_prefix', 'service_code_manual',
        'is_companion', 'companion_name', 'companion_relation',
        'is_paid', 'payment_amount'
    ];
    $normalized = [];
    foreach ($allowed as $key) {
        if (array_key_exists($key, $draft)) {
            $normalized[$key] = $draft[$key];
        }
    }
    return $normalized;
}

function buildLeaveAiPrompt(string $userText, array $existingDraft = []): string {
    $schemaHint = [
        'draft' => [
            'patient_name' => 'string',
            'patient_identity' => 'string',
            'patient_phone' => 'string',
            'patient_folder_link' => 'string',
            'doctor_name' => 'string',
            'doctor_title' => 'string',
            'doctor_note' => 'string',
            'issue_date' => 'YYYY-MM-DD',
            'start_date' => 'YYYY-MM-DD',
            'end_date' => 'YYYY-MM-DD',
            'days_count' => 'number',
            'service_prefix' => 'GSL|PSL',
            'service_code_manual' => 'string',
            'is_companion' => 'true|false',
            'companion_name' => 'string',
            'companion_relation' => 'string',
            'is_paid' => 'true|false',
            'payment_amount' => 'number'
        ],
        'missing_fields' => ['array of arabic labels for required missing fields'],
        'assistant_message' => 'short Arabic message'
    ];

    $systemPrompt = "أنت مساعد ذكي لاستخراج بيانات إجازة مرضية من نص عربي/إنجليزي.\n"
        . "يجب أن تعيد JSON فقط بدون أي نص إضافي.\n"
        . "قواعد مهمة:\n"
        . "1) إذا الجهة مستشفى/حكومي => service_prefix=GSL. إذا مركز/عيادة/خاص => PSL.\n"
        . "2) إذا وجدت فترة من-إلى: issue_date=start_date=أول يوم, end_date=آخر يوم, days_count شاملة.\n"
        . "3) إذا يوم واحد: issue_date=start_date=end_date ونفس اليوم, days_count=1.\n"
        . "4) required: patient_name, patient_identity, doctor_name, doctor_title, issue_date, start_date, end_date, days_count.\n"
        . "5) دمج existing_draft مع النص الجديد وحدث القيم الأدق.\n"
        . "6) تنسيق التواريخ دائماً YYYY-MM-DD.\n"
        . "الشكل المطلوب: " . json_encode($schemaHint, JSON_UNESCAPED_UNICODE);

    $userPrompt = json_encode([
        'existing_draft' => $existingDraft,
        'user_text' => $userText
    ], JSON_UNESCAPED_UNICODE);

    return $systemPrompt . "\n\n" . $userPrompt;
}

function parseLeaveWithGemini(string $userText, array $existingDraft = []): array {
    $apiKey = trim($_ENV['GEMINI_API_KEY'] ?? getenv('GEMINI_API_KEY') ?: '');
    if ($apiKey === '') {
        return ['success' => false, 'message' => 'لم يتم ضبط مفتاح GEMINI_API_KEY على الخادم.'];
    }
    if (!function_exists('curl_init')) {
        return ['success' => false, 'message' => 'cURL غير متوفر على الخادم.'];
    }

    $endpoint = "https://generativelanguage.googleapis.com/v1beta/models/gemini-2.0-flash:generateContent?key=" . urlencode($apiKey);
    $prompt = buildLeaveAiPrompt($userText, $existingDraft);
    $payload = [
        'contents' => [
            [
                'role' => 'user',
                'parts' => [['text' => $prompt]]
            ]
        ],
        'generationConfig' => [
            'temperature' => 0.1,
            'maxOutputTokens' => 700
        ]
    ];

    $ch = curl_init($endpoint);
    curl_setopt_array($ch, [
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_POST => true,
        CURLOPT_HTTPHEADER => ['Content-Type: application/json'],
        CURLOPT_POSTFIELDS => json_encode($payload, JSON_UNESCAPED_UNICODE),
        CURLOPT_TIMEOUT => 25
    ]);
    $response = curl_exec($ch);
    $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
    $curlErr = curl_error($ch);
    curl_close($ch);

    if ($response === false || $curlErr) {
        return ['success' => false, 'message' => 'فشل الاتصال بخدمة الذكاء: ' . $curlErr];
    }
    if ($httpCode < 200 || $httpCode >= 300) {
        return ['success' => false, 'message' => 'خدمة الذكاء أعادت خطأ HTTP ' . $httpCode, 'raw' => $response];
    }

    $decoded = json_decode($response, true);
    $textOutput = $decoded['candidates'][0]['content']['parts'][0]['text'] ?? '';
    $json = extractFirstJsonObject((string)$textOutput);
    if (!$json) {
        return ['success' => false, 'message' => 'تعذر فهم استجابة الذكاء الاصطناعي.'];
    }

    $draft = normalizeAiDraft($json['draft'] ?? []);
    $missing = $json['missing_fields'] ?? [];
    if (!is_array($missing)) {
        $missing = [];
    }
    $assistantMessage = trim((string)($json['assistant_message'] ?? ''));

    return [
        'success' => true,
        'provider' => 'gemini',
        'draft' => $draft,
        'missing_fields' => array_values($missing),
        'assistant_message' => $assistantMessage !== '' ? $assistantMessage : 'تم التحليل بنجاح.'
    ];
}

function normalizeDoctorBatchLine(string $line): string {
    $line = trim($line);
    $line = preg_replace('/^\s*(?:[\-\*\•]+|\d+[\)\.\-])\s*/u', '', $line);
    return trim($line);
}

function parseDoctorsBatchInput(string $rawInput): array {
    $rawInput = trim($rawInput);
    if ($rawInput === '') return [];

    $lines = preg_split('/\r\n|\r|\n/u', $rawInput);
    $parsed = [];
    foreach ($lines as $line) {
        $line = normalizeDoctorBatchLine((string)$line);
        if ($line === '') continue;

        $parts = preg_split('/\s*(?:\||;|،|,|(?:\s*-\s*)|(?:\s*—\s*)|(?:\s*:\s*))\s*/u', $line);
        $parts = array_values(array_filter(array_map('trim', $parts), static fn($p) => $p !== ''));
        if (count($parts) < 2) {
            $parts = preg_split('/\s{2,}/u', $line);
            $parts = array_values(array_filter(array_map('trim', $parts), static fn($p) => $p !== ''));
        }
        if (count($parts) < 2) {
            continue;
        }

        $name = $parts[0] ?? '';
        $title = $parts[1] ?? '';
        $note = '';
        if (count($parts) >= 3) {
            $note = implode(' - ', array_slice($parts, 2));
        }
        $parsed[] = ['name' => $name, 'title' => $title, 'note' => $note];
    }
    return $parsed;
}


function fetchAllData($pdo) {
    ensureDelayedUnpaidNotifications($pdo);
    purgeExpiredMessages($pdo);
    // الإجازات النشطة
    $leaves = $pdo->query(" 
        SELECT sl.*, p.name_ar AS patient_name, p.identity_number, p.phone AS patient_phone, p.folder_link AS patient_folder_link,
               d.name_ar AS doctor_name, d.title_ar AS doctor_title, d.note AS doctor_note,
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
        SELECT sl.*, p.name_ar AS patient_name, p.identity_number, p.phone AS patient_phone, p.folder_link AS patient_folder_link,
               d.name_ar AS doctor_name, d.title_ar AS doctor_title, d.note AS doctor_note,
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
               sl.service_code, p.name_ar AS patient_name, p.identity_number
        FROM leave_queries lq
        LEFT JOIN sick_leaves sl ON lq.leave_id = sl.id
        LEFT JOIN patients p ON sl.patient_id = p.id
        ORDER BY lq.queried_at DESC
    ")->fetchAll();

    // إشعارات المدفوعات
    $notifications_payment = $pdo->query("
        SELECT n.*, sl.payment_amount, sl.service_code, sl.patient_id, p.name_ar AS patient_name, p.phone AS patient_phone
        FROM notifications n
        LEFT JOIN sick_leaves sl ON n.leave_id = sl.id
        LEFT JOIN patients p ON sl.patient_id = p.id
        WHERE n.type = 'payment'
        ORDER BY n.created_at DESC
    ")->fetchAll();

    // المدفوعات لكل مريض
    $payments = $pdo->query("
        SELECT p.id, p.name_ar AS name,
               COUNT(sl.id) AS total,
               SUM(CASE WHEN sl.is_paid = 1 THEN 1 ELSE 0 END) AS paid_count,
               SUM(CASE WHEN sl.is_paid = 0 THEN 1 ELSE 0 END) AS unpaid_count,
               COALESCE(SUM(CASE WHEN sl.is_paid = 1 THEN sl.payment_amount ELSE 0 END), 0) AS paid_amount,
               COALESCE(SUM(CASE WHEN sl.is_paid = 0 THEN sl.payment_amount ELSE 0 END), 0) AS unpaid_amount
        FROM patients p
        LEFT JOIN sick_leaves sl ON p.id = sl.patient_id AND sl.deleted_at IS NULL
        GROUP BY p.id, p.name_ar
        ORDER BY p.name_ar
    ")->fetchAll();

    // المستشفيات
    $hospitals_data = getHospitalsList($pdo);

    return compact('leaves', 'archived', 'queries', 'notifications_payment', 'payments', 'hospitals_data');
}


function fetchActiveOperationalData($pdo) {
    ensureDelayedUnpaidNotifications($pdo);
    purgeExpiredMessages($pdo);
    $leaves = $pdo->query(" 
        SELECT sl.*, p.name_ar AS patient_name, p.identity_number, p.phone AS patient_phone, p.folder_link AS patient_folder_link,
               d.name_ar AS doctor_name, d.title_ar AS doctor_title, d.note AS doctor_note,
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
        SELECT n.*, sl.payment_amount, sl.service_code, sl.patient_id, p.name_ar AS patient_name, p.phone AS patient_phone
        FROM notifications n
        LEFT JOIN sick_leaves sl ON n.leave_id = sl.id
        LEFT JOIN patients p ON sl.patient_id = p.id
        WHERE n.type = 'payment'
        ORDER BY n.created_at DESC
    ")->fetchAll();

    $payments = $pdo->query(" 
        SELECT p.id, p.name_ar AS name,
               COUNT(sl.id) AS total,
               SUM(CASE WHEN sl.is_paid = 1 THEN 1 ELSE 0 END) AS paid_count,
               SUM(CASE WHEN sl.is_paid = 0 THEN 1 ELSE 0 END) AS unpaid_count,
               COALESCE(SUM(CASE WHEN sl.is_paid = 1 THEN sl.payment_amount ELSE 0 END), 0) AS paid_amount,
               COALESCE(SUM(CASE WHEN sl.is_paid = 0 THEN sl.payment_amount ELSE 0 END), 0) AS unpaid_amount
        FROM patients p
        LEFT JOIN sick_leaves sl ON p.id = sl.patient_id AND sl.deleted_at IS NULL
        GROUP BY p.id, p.name_ar
        ORDER BY p.name_ar
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

    $accountRows = [];
    if (tableExists($pdo, 'account_payments')) {
        $accountStmt = $pdo->prepare("
            SELECT ap.id, ap.user_id, ap.amount, ap.days_count, COALESCE(u.display_name, u.username, 'مريض') AS account_name
            FROM account_payments ap
            LEFT JOIN admin_users u ON u.id = ap.user_id
            LEFT JOIN notifications n ON n.account_payment_id = ap.id AND n.type = 'payment'
            WHERE ap.is_paid = 0
              AND ap.amount > 0
              AND n.id IS NULL
        ");
        $accountStmt->execute();
        $accountRows = $accountStmt->fetchAll();
    }

    if (!$rows && !$accountRows) return;

    $ins = $pdo->prepare("INSERT INTO notifications (type, leave_id, account_payment_id, message, created_at) VALUES ('payment', ?, ?, ?, ?)");
    foreach ($rows as $row) {
        $ins->execute([
            $row['id'],
            null,
            "إجازة غير مدفوعة منذ أكثر من 5 دقائق برمز {$row['service_code']} بمبلغ {$row['payment_amount']}",
            nowSaudi()
        ]);
    }
    foreach ($accountRows as $row) {
        $ins->execute([
            null,
            $row['id'],
            "إضافة أيام غير مدفوعة لحساب {$row['account_name']} ({$row['days_count']} يوم) بمبلغ {$row['amount']}",
            nowSaudi()
        ]);
    }
}

function fetchPatientAccountRecords(PDO $pdo, int $userId): array {
    $accountStmt = $pdo->prepare("SELECT pa.patient_id FROM patient_accounts pa WHERE pa.user_id = ? LIMIT 1");
    $accountStmt->execute([$userId]);
    $patientId = (int)($accountStmt->fetchColumn() ?: 0);

    $leaves = [];
    if ($patientId > 0) {
        $leaveStmt = $pdo->prepare("
            SELECT sl.*, COALESCE(d.name_ar, d.name, '') AS doctor_name, COALESCE(d.title_ar, d.title, '') AS doctor_title,
                   COALESCE(h.name_ar, sl.hospital_name_ar, '') AS hospital_name
            FROM sick_leaves sl
            LEFT JOIN doctors d ON d.id = sl.doctor_id
            LEFT JOIN hospitals h ON h.id = sl.hospital_id
            WHERE sl.patient_id = ? AND sl.deleted_at IS NULL
            ORDER BY sl.created_at DESC
        ");
        $leaveStmt->execute([$patientId]);
        $leaves = $leaveStmt->fetchAll();
    }

    $paymentStmt = $pdo->prepare("SELECT ap.*, au.display_name AS created_by_name, payer.display_name AS paid_by_name FROM account_payments ap LEFT JOIN admin_users au ON ap.created_by = au.id LEFT JOIN admin_users payer ON ap.paid_by = payer.id WHERE ap.user_id = ? ORDER BY ap.paid_at DESC, ap.id DESC");
    $paymentStmt->execute([$userId]);

    return ['leaves' => $leaves, 'payments' => $paymentStmt->fetchAll()];
}

// ======================== دالة توليد PDF ========================
function handleGeneratePdf($pdo, $leave_id, $pdfMode = 'preview') {
    $stmt = $pdo->prepare("
        SELECT sl.*, 
               p.name_ar AS p_name_ar, p.name_en AS p_name_en, p.identity_number,
               p.employer_ar AS p_employer_ar, p.employer_en AS p_employer_en,
               p.nationality_ar AS p_nationality_ar, p.nationality_en AS p_nationality_en,
               d.name_ar AS d_name_ar, d.name_en AS d_name_en,
               d.title_ar AS d_title_ar, d.title_en AS d_title_en,
               h.name_ar AS h_name_ar, h.name_en AS h_name_en, 
               h.license_number AS h_license, h.logo_path AS h_logo_path, h.logo_url AS h_logo_url,
               h.logo_data AS h_logo_data,
               h.logo_scale AS h_logo_scale, h.logo_offset_x AS h_logo_offset_x, h.logo_offset_y AS h_logo_offset_y
        FROM sick_leaves sl
        LEFT JOIN patients p ON sl.patient_id = p.id
        LEFT JOIN doctors d ON sl.doctor_id = d.id
        LEFT JOIN hospitals h ON sl.hospital_id = h.id
        WHERE sl.id = ?
    ");
    $stmt->execute([$leave_id]);
    $lv = $stmt->fetch();
    if (!$lv) {
        echo '<h2 style="text-align:center;margin-top:50px;font-family:sans-serif;">لم يتم العثور على الإجازة</h2>';
        exit;
    }

    // Prepare all data
    $sc = htmlspecialchars($lv['service_code'] ?? '', ENT_QUOTES);
    $days = (int)($lv['days_count'] ?? 1);
    $daysEn = $days . ($days === 1 ? ' day' : ' days');
    $daysAr = $days == 1 ? '1' : ($days == 2 ? '2' : (string)$days);
    $daysArWord = 'يوم';

    $startG = $lv['start_date'] ?? '';
    $endG = $lv['end_date'] ?? '';
    $issueG = $lv['issue_date'] ?? '';

    $fmtEn = function($d) { if (!$d) return ''; $dt = DateTime::createFromFormat('Y-m-d', $d); return $dt ? $dt->format('d-m-Y') : $d; };
    $toHijriStr = function($d) {
        if (!$d) return '';
        $parts = explode('-', $d);
        if (count($parts) !== 3) return $d;
        $h = gregorianToHijri((int)$parts[0], (int)$parts[1], (int)$parts[2]);
        // Format as DD-MM-YYYY so year appears on the right in RTL display
        return sprintf('%02d-%02d-%04d', $h['day'], $h['month'], $h['year']);
    };

    $startEn = $fmtEn($startG);
    $endEn = $fmtEn($endG);
    $issueEn = $fmtEn($issueG);
    $dischargeEn = $fmtEn($startG);
    $startHj = $toHijriStr($startG);
    $endHj = $toHijriStr($endG);
    $dischargeHj = $toHijriStr($startG);

    $patNameAr = htmlspecialchars($lv['p_name_ar'] ?? '', ENT_QUOTES);
    $patNameEn = strtoupper(htmlspecialchars($lv['p_name_en'] ?? $lv['patient_name_en'] ?? '', ENT_QUOTES));
    $patId = htmlspecialchars($lv['identity_number'] ?? '', ENT_QUOTES);
    $natAr = htmlspecialchars($lv['p_nationality_ar'] ?? '', ENT_QUOTES);
    $natEn = htmlspecialchars($lv['p_nationality_en'] ?? '', ENT_QUOTES);
    $empArRaw = $lv['p_employer_ar'] ?? $lv['employer_ar'] ?? '';
    $empEnRaw = $lv['p_employer_en'] ?? $lv['employer_en'] ?? '';
    $empAr = htmlspecialchars($empArRaw !== '' ? $empArRaw : 'الى من يهمه الامر', ENT_QUOTES);
    $empEn = htmlspecialchars($empEnRaw !== '' ? $empEnRaw : 'To Whom It May Concern', ENT_QUOTES);
    $docNameAr = htmlspecialchars($lv['d_name_ar'] ?? '', ENT_QUOTES);
    $docNameEn = strtoupper(htmlspecialchars($lv['d_name_en'] ?? $lv['doctor_name_en'] ?? '', ENT_QUOTES));
    $docTitleAr = htmlspecialchars($lv['d_title_ar'] ?? '', ENT_QUOTES);
    $docTitleEn = htmlspecialchars($lv['d_title_en'] ?? $lv['doctor_title_en'] ?? '', ENT_QUOTES);

    $hospNameAr = htmlspecialchars($lv['h_name_ar'] ?? $lv['hospital_name_ar'] ?? '', ENT_QUOTES);
    $hospNameEn = htmlspecialchars($lv['h_name_en'] ?? $lv['hospital_name_en'] ?? '', ENT_QUOTES);
    $hospLicense = $lv['h_license'] ?? '';
    $hospLogoPath = $lv['h_logo_path'] ?? $lv['logo_path'] ?? '';

    // Hospital logo - prioritize base64 data from DB (works on Railway ephemeral filesystem)
    $hospLogoData = $lv['h_logo_data'] ?? '';
    $hospLogoUrl = $lv['h_logo_url'] ?? '';
    $defaultLogo = 'https://upload.wikimedia.org/wikipedia/ar/thumb/f/fe/Saudi_Ministry_of_Health_Logo.svg/3840px-Saudi_Ministry_of_Health_Logo.svg.png';
    $logoSrc = $defaultLogo;
    if (!empty($hospLogoData) && strpos($hospLogoData, 'data:image/') === 0) {
        $logoSrc = $hospLogoData;
    } elseif ($hospLogoPath && file_exists(__DIR__ . '/' . $hospLogoPath)) {
        $logoSrc = $hospLogoPath;
    } elseif ($hospLogoPath && strpos($hospLogoPath, 'http') === 0) {
        $logoSrc = $hospLogoPath;
    } elseif ($hospLogoUrl && strpos($hospLogoUrl, 'http') === 0) {
        $logoSrc = $hospLogoUrl;
    }
    $hLogoScale = floatval($lv['h_logo_scale'] ?? 1);
    $hLogoOffX = floatval($lv['h_logo_offset_x'] ?? 0);
    $hLogoOffY = floatval($lv['h_logo_offset_y'] ?? 0);
    $logoTransform = "transform: translate({$hLogoOffX}px, {$hLogoOffY}px) scale({$hLogoScale});";
    $hospLogoHtml = '<div style="width:120px;height:120px;overflow:hidden;position:relative;"><img src="' . htmlspecialchars($logoSrc) . '" alt="Hospital Logo" style="width:100%;height:100%;object-fit:contain;position:absolute;top:0;left:0;' . $logoTransform . '" /></div>';

    // License section
    $licenseHtml = '';
    if (!empty($hospLicense)) {
       $licenseHtml = '<span dir="rtl" style="direction:rtl;unicode-bidi:isolate;display:inline-block;font-weight:700;white-space:nowrap;"><span style="font-family: \'Noto Sans Arabic\', sans-serif;">رقم الترخيص:</span> <bdi dir="ltr" style="font-family: \'Times New Roman\', serif; direction:ltr; unicode-bidi:isolate;">' . htmlspecialchars($hospLicense, ENT_QUOTES, 'UTF-8') . '</bdi></span>';
    }

    // Timestamp
    $issuePeriod = $lv['issue_period'] ?? 'AM';
    $issueTime = formatIssueTimeForDisplay($lv['issue_time'] ?? '09:00', $issuePeriod);
    $issueDateObj = DateTime::createFromFormat('Y-m-d', $issueG);
    $dayNameEn = $issueDateObj ? $issueDateObj->format('l') : '';
    $monthNameEn = $issueDateObj ? $issueDateObj->format('F') : '';
    $dayNum = $issueDateObj ? $issueDateObj->format('d') : '';
    $yearNum = $issueDateObj ? $issueDateObj->format('Y') : '';
    $timestampLine = $issueTime . ' ' . $issuePeriod;
    $dateLine = $dayNameEn . ', ' . $dayNum . ' ' . $monthNameEn . ' ' . $yearNum;

    // Duration lines
    $durationEn = $daysEn . ' ( ' . $startEn . ' to ' . $endEn . ' )';
    $durationAr = '<span style="font-family: \'Times New Roman\', serif; font-size: 13.5px; font-weight: 400;">' . $daysAr . '</span> <span style="font-family: \'Noto Sans Arabic\', sans-serif; font-size: 14.5px; font-weight: 400;">' . $daysArWord . '</span> ( ' . formatHijriDateSpan($startHj) . ' <span style="font-family: \'Noto Sans Arabic\', sans-serif; font-size: 13.5px; font-weight: 400;">إلى</span> ' . formatHijriDateSpan($endHj) . ' )';  // RTL display: start Hijri إلى end Hijri with isolated LTR date numbers

    // ==================== CSS ====================
    $reportCSS = 'html{line-height:1.15}body{margin:0}*{box-sizing:border-box;border-width:0;border-style:solid;-webkit-font-smoothing:antialiased}p,li,ul,pre,div,h1,h2,h3,h4,h5,h6,figure,blockquote,figcaption{margin:0;padding:0}a{color:inherit;text-decoration:inherit}';
    $reportCSS .= '.report-page{width:842px;height:1190px;position:relative;background-color:white;font-family:"Inter",sans-serif;font-size:16px;font-weight:400;color:#191818;overflow:hidden}';
    $reportCSS .= '.info-table{position:absolute;top:242px;left:36px;width:770px;border-collapse:separate;border-spacing:0;border:1px solid #ccc;border-radius:8px;overflow:hidden;background-color:transparent;z-index:10}';
    $reportCSS .= '.info-table td{border-bottom:1px solid #ccc;border-right:1px solid #ccc;height:42px;text-align:center;vertical-align:middle;padding:4px 8px}';
    $reportCSS .= '.info-table td:last-child{border-right:none}.info-table tr:last-child td{border-bottom:none}';
    $reportCSS .= '.info-table .en-title{width:161px;color:rgba(54,111,181,1);font-size:13.5px;font-weight:700;text-align:center;font-family:"Times New Roman",serif}';
    $reportCSS .= '.info-table .data-cell{width:240px;color:rgba(44,62,119,1);font-size:13.5px;font-family:"Times New Roman",serif;font-weight:400;text-align:center}';
    $reportCSS .= '.info-table .date-cell{font-size:13.9px}.info-table .data-cell.ar-text{font-family:"Noto Sans Arabic"}';
    $reportCSS .= '.info-table .ar-title{width:140px;color:rgba(54,111,181,1);font-size:13.5px;font-weight:700;text-align:center;font-family:"Noto Sans Arabic";white-space:nowrap}';
    $reportCSS .= '.info-table tr.blue-row td{background-color:#2c3e77;color:#fff;border-bottom:1px solid #ccc;border-right:1px solid #ccc}';
    $reportCSS .= '.info-table tr.blue-row td:last-child{border-right:none}';
    $reportCSS .= '.info-table .blue-row .data-cell.ar-text{color:rgba(255,255,255,1);font-size:13.5px;font-family:"Times New Roman",serif;font-weight:400}';
    $reportCSS .= '.info-table .blue-row .data-cell{color:rgba(255,255,255,1)}';
    $reportCSS .= '.info-table tr.gray-row td{background-color:#f7f7f7}';
    $reportCSS .= '.en-spaced{letter-spacing:0.3px}';
    $reportCSS .= ':root{--footer-offset:40px}';
    $reportCSS .= '.group1-thq-staticinfo-elm{top:125px;left:36.65px;width:768.35px;height:811.91px;display:flex;position:absolute;align-items:flex-start;pointer-events:none}';
    $reportCSS .= '.top-right-placeholder{position:absolute;top:36px;left:592px;width:214px;height:107px;display:flex;align-items:center;justify-content:center;font-size:14px;z-index:5}';
    $reportCSS .= '.top-left-placeholder{position:absolute;top:36px;left:36px;width:149.96px;height:65.98px;display:flex;align-items:center;justify-content:center;font-size:14px;z-index:5}';
    $reportCSS .= '.bottom-right-placeholder{position:absolute;top:980px;left:657.17px;width:149.96px;height:71.23px;display:flex;align-items:center;justify-content:center;font-size:12px;z-index:5}';
    $reportCSS .= '.header-placeholder{top:-50px;left:303px;width:150px;height:40px;position:absolute;display:flex;align-items:center;justify-content:center;font-size:11px}';
    $reportCSS .= '.group1-thq-text-elm41{top:40px;left:281px;color:rgba(48,109,181,1);width:215px;position:absolute;font-size:22.5px;font-weight:700;text-align:center;line-height:30px}';
    $reportCSS .= '.group1-thq-text-elm44{top:-10px;left:293px;color:rgba(0,0,0,1);position:absolute;font-size:17.3px;font-weight:400;text-align:left;font-family:"Times New Roman",serif}';
    $reportCSS .= '.group1-thq-hospitallogoandthename-elm{top:760px;left:438.94px;width:403px;height:202.78px;display:flex;position:absolute;align-items:flex-start}';
    $reportCSS .= '.placeholder-logo-hospital{top:-12px;left:133px;width:136px;height:136px;position:absolute;display:flex;align-items:center;justify-content:center;font-size:12px}';
    $reportCSS .= '.group1-thq-text-elm18{top:113px;color:rgba(0,0,0,1);width:403px;height:auto;position:absolute;font-size:12.8px;text-align:center;line-height:22px}';
    $reportCSS .= '.group1-thq-thedateofissueandalsotimeofissue-elm{top:calc(950px + var(--footer-offset));left:37.37px;width:250px;height:56px;display:flex;position:absolute;align-items:flex-start}';
    $reportCSS .= '.group1-thq-text-elm22{color:rgba(0,0,0,1);font-size:12.5px;font-weight:700;text-align:left;line-height:28px;font-family:"Times New Roman",serif;font-weight:bold;position:absolute;white-space:nowrap}';
    $reportCSS .= '.group1-thq-text-elm36{top:calc(680px + var(--footer-offset));left:29.23px;color:rgba(0,0,0,1);position:absolute;font-size:12px;font-weight:700;text-align:center;font-family:"Noto Sans Arabic";line-height:23px}';
    $reportCSS .= '.group1-thq-text-elm39{top:calc(728px + var(--footer-offset));left:55px;color:rgba(0,0,0,1);position:absolute;font-size:12px;font-weight:700;text-align:left;font-family:"Times New Roman",serif;font-weight:bold}';
    $reportCSS .= '.group1-thq-text-elm40{top:calc(750px + var(--footer-offset));left:108.35px;color:rgba(20,0,255,1);position:absolute;font-size:11px;font-weight:700;text-align:left;text-decoration:underline;pointer-events:auto;font-family:"Times New Roman",serif;font-weight:bold}';
    $reportCSS .= '.placeholder-136{position:absolute;top:607px;left:137px;width:103.9px;height:103.9px;display:flex;align-items:center;justify-content:center;font-size:12px;pointer-events:auto}';
    $reportCSS .= '.vertical-divider{position:absolute;top:723px;left:436px;width:1.5px;height:6cm;background-color:#ddd}';
    $reportCSS .= '.thin-slash{font-weight:300;font-family:"Inter",sans-serif;margin:0 3px;display:inline-block}';

    // ==================== Report Body HTML ====================
    $reportBody = '<div class="report-page">';
    $reportBody .= '<div class="top-right-placeholder"><img src="sehalogoright.png" style="width:100%;height:100%"/></div>';
    $reportBody .= '<div class="top-left-placeholder"><img src="sehalogoleft.png" style="width:100%;height:100%"/></div>';
    $reportBody .= '<div class="bottom-right-placeholder"><img src="bottomright.png" style="width:100%;height:100%"/></div>';
    $reportBody .= '<div class="group1-thq-staticinfo-elm">';
    $reportBody .= '<div class="header-placeholder"><img src="header.png" style="width:100%;height:100%"/></div>';
    $reportBody .= '<span class="group1-thq-text-elm41"><span style="font-size:22.5px;font-family:\'Noto sans arabic\',serif;font-weight:700;color:#306db5">تقرير إجازة مرضية</span><br/><span style="font-size:18.7px;font-family:\'Times New Roman\',serif;font-weight:700;color:#2c3e77">Sick Leave Report</span></span>';
    $reportBody .= '<span class="group1-thq-text-elm44">Kingdom of Saudi Arabia</span>';
    $reportBody .= '<div class="placeholder-136"><img src="qr.svg" style="width:103.9px;height:103.9px"/></div>';
    $reportBody .= '<span class="group1-thq-text-elm36" dir="rtl">للتحقق من بيانات التقرير يرجى التأكد من زيارة موقع منصة صحة<br/>الرسمي</span>';
    $reportBody .= '<span class="group1-thq-text-elm39">To check the report please visit Seha\'s official website</span>';
    $reportBody .= '<span class="group1-thq-text-elm40"><a href="https://seha-sa-inquiries-slenquiry.up.railway.app/" target="_blank">www.seha.sa/#/inquiries/slenquiry</a></span>';
    $reportBody .= '</div>';
    // Table
    $reportBody .= '<table class="info-table" cellpadding="0" cellspacing="0"><tbody>';
    $reportBody .= '<tr><td class="en-title">Leave ID</td><td class="data-cell" colspan="2">' . $sc . '</td><td class="ar-title">رمز الإجازة</td></tr>';
    $reportBody .= '<tr class="blue-row"><td class="en-title" style="color:white">Leave Duration</td><td class="data-cell">' . $durationEn . '</td><td class="data-cell ar-text" dir="rtl">' . $durationAr . '</td><td class="ar-title" style="color:white">مدة الإجازة</td></tr>';
    $reportBody .= '<tr><td class="en-title">Admission Date</td><td class="data-cell date-cell">' . $startEn . '</td><td class="data-cell date-cell" dir="ltr">' . $startHj . '</td><td class="ar-title">تاريخ الدخول</td></tr>';
    $reportBody .= '<tr class="gray-row"><td class="en-title">Discharge Date</td><td class="data-cell date-cell">' . $dischargeEn . '</td><td class="data-cell date-cell" dir="ltr">' . $dischargeHj . '</td><td class="ar-title">تاريخ الخروج</td></tr>';
    $reportBody .= '<tr><td class="en-title">Issue Date</td><td class="data-cell" colspan="2">' . $issueEn . '</td><td class="ar-title">تاريخ الإصدار</td></tr>';
    $reportBody .= '<tr class="gray-row"><td class="en-title">Patient Name</td><td class="data-cell en-spaced">' . $patNameEn . '</td><td class="data-cell ar-text">' . $patNameAr . '</td><td class="ar-title">الاسم</td></tr>';
    $reportBody .= '<tr><td class="en-title">National ID / Iqama</td><td class="data-cell" colspan="2">' . $patId . '</td><td class="ar-title">الإقامة<span class="thin-slash">/</span>رقم الهوية</td></tr>';
    $reportBody .= '<tr class="gray-row"><td class="en-title">Nationality</td><td class="data-cell en-spaced">' . $natEn . '</td><td class="data-cell ar-text">' . $natAr . '</td><td class="ar-title">الجنسية</td></tr>';
    $reportBody .= '<tr><td class="en-title">Employer</td><td class="data-cell en-spaced">' . $empEn . '</td><td class="data-cell ar-text">' . $empAr . '</td><td class="ar-title">جهة العمل</td></tr>';
    $reportBody .= '<tr class="gray-row"><td class="en-title">Practitioner Name</td><td class="data-cell en-spaced">' . $docNameEn . '</td><td class="data-cell ar-text">' . $docNameAr . '</td><td class="ar-title">اسم الممارس</td></tr>';
    $reportBody .= '<tr><td class="en-title">Position</td><td class="data-cell en-spaced">' . $docTitleEn . '</td><td class="data-cell ar-text">' . $docTitleAr . '</td><td class="ar-title">المسمى الوظيفي</td></tr>';
    $reportBody .= '</tbody></table>';
    $reportBody .= '<div class="vertical-divider"></div>';
    // Hospital section
    $reportBody .= '<div class="group1-thq-hospitallogoandthename-elm">';
    $reportBody .= '<div class="placeholder-logo-hospital">' . $hospLogoHtml . '</div>';
    $reportBody .= '<span class="group1-thq-text-elm18">';
    $reportBody .= '<span style="font-family:\'Noto Sans Arabic\',sans-serif;font-weight:700">' . $hospNameAr . '</span><br/>';
    $reportBody .= '<span class="en-spaced" style="font-family:\'Times New Roman\',serif;font-weight:700">' . $hospNameEn . '</span><br/>';
    if (!empty($licenseHtml)) $reportBody .= $licenseHtml;
    $reportBody .= '</span></div>';
    // Timestamp
    $reportBody .= '<div class="group1-thq-thedateofissueandalsotimeofissue-elm">';
    $reportBody .= '<span class="group1-thq-text-elm22">';
    $reportBody .= '<span>' . $timestampLine . '</span><br/>';
    $reportBody .= '<span>' . $dateLine . '</span>';
    $reportBody .= '</span></div>';
    $reportBody .= '</div>';


    // ==================== DOWNLOAD MODE (WeasyPrint) ====================
if ($pdfMode === 'download') {
    // Build full HTML with embedded SVGs/PNGs and Fonts as absolute URLs
    $baseUrl = (isset($_SERVER['HTTPS']) && $_SERVER['HTTPS'] === 'on' ? 'https' : 'http') . '://' . $_SERVER['HTTP_HOST'] . dirname($_SERVER['SCRIPT_NAME']) . '/';
    
    $pdfHtml = '<!DOCTYPE html><html lang="ar"><head><meta charset="utf-8"/>';
    $pdfHtml .= '<title>Sick Leave Report</title>';
    
    // Google Fonts strictly for Arabic and Inter placeholders
    $pdfHtml .= '<link rel="stylesheet" href="https://fonts.googleapis.com/css2?family=Inter:wght@100;200;300;400;500;600;700&display=swap" />';
    $pdfHtml .= '<link rel="stylesheet" href="https://fonts.googleapis.com/css2?family=Noto+Sans+Arabic:wght@400;600;700&display=swap" />';

    $pdfHtml .= '<style data-tag="reset-style-sheet">';
    $pdfHtml .= 'html { line-height: 1.15; } body { margin: 0; }';
    $pdfHtml .= '* { box-sizing: border-box; border-width: 0; border-style: solid; }';
    $pdfHtml .= 'p, li, ul, pre, div, h1, h2, h3, h4, h5, h6, figure, blockquote, figcaption { margin: 0; padding: 0; }';
    $pdfHtml .= 'a { color: inherit; text-decoration: inherit; }';
    $pdfHtml .= '</style>';

    $pdfHtml .= '<style data-tag="default-style-sheet">';
    $pdfHtml .= 'html { font-family: Inter, sans-serif; font-size: 16px; }';
    $pdfHtml .= 'body { font-weight: 400; color: #191818; background: #ffffff; margin: 0; padding: 0; }';
    $pdfHtml .= '</style>';

    $pdfHtml .= '<style>';
    
    // =========================================================
    // LOAD YOUR LOCAL OPENTYPE (.otf) FILES
    // =========================================================
    $pdfHtml .= '@font-face {';
    $pdfHtml .= '    font-family: "Times New Roman";';
    $pdfHtml .= '    src: url("' . $baseUrl . 'times_regular.otf") format("opentype");';
    $pdfHtml .= '    font-weight: 400;';
    $pdfHtml .= '    font-style: normal;';
    $pdfHtml .= '}';

    $pdfHtml .= '@font-face {';
    $pdfHtml .= '    font-family: "Times New Roman";';
    $pdfHtml .= '    src: url("' . $baseUrl . 'times_bold.otf") format("opentype");';
    $pdfHtml .= '    font-weight: 700;';
    $pdfHtml .= '    font-style: normal;';
    $pdfHtml .= '}';
    // =========================================================

    $pdfHtml .= '@page { size: 842.25px 1190.25px; margin: 0; }';
    $pdfHtml .= '.group1-container1 { width: 842.25px; height: 1190.25px; position: relative; background-color: transparent; margin: 0; padding: 0; }';
    $pdfHtml .= '.group1-thq-group1-elm { width: 842.25px; height: 1190.25px; position: relative; background-color: white; margin: 0; padding: 0; }';
    
    // Tables & Data Cells directly referencing the embedded font
    $pdfHtml .= '.info-table { position: absolute; top: 242px; left: 36px; width: 770px; border-collapse: separate; border-spacing: 0; border: 1px solid #cccccc; border-radius: 8px; overflow: hidden; background-color: transparent; z-index: 10; }';
    $pdfHtml .= '.info-table td { border-bottom: 1px solid #cccccc; border-right: 1px solid #cccccc; height: 42px; text-align: center; vertical-align: middle; padding: 4px 8px; }';
    $pdfHtml .= '.info-table td:last-child { border-right: none; } .info-table tr:last-child td { border-bottom: none; }';
    
    $pdfHtml .= '.info-table .en-title { width: 161px; color: rgba(54, 111, 181, 1); font-size: 13.5px; font-weight: 700; text-align: center; font-family: "Times New Roman", serif; }';
    $pdfHtml .= '.info-table .data-cell { width: 240px; color: rgba(44, 62, 119, 1); font-size: 13.5px; font-family: "Times New Roman", serif; font-weight: 400; text-align: center; }';
    
    $pdfHtml .= '.info-table .date-cell { font-size: 13.9px; } .info-table .data-cell.ar-text { font-family: "Noto Sans Arabic", sans-serif; }';
    $pdfHtml .= '.info-table .ar-title { width: 140px; color: rgba(54, 111, 181, 1); font-size: 13.5px; font-weight: 700; text-align: center; font-family: "Noto Sans Arabic", sans-serif; white-space: nowrap; }';
    $pdfHtml .= '.info-table tr.blue-row td { background-color: #2c3e77; color: #ffffff; border-bottom: 1px solid #cccccc; border-right: 1px solid #cccccc; }';
    $pdfHtml .= '.info-table tr.blue-row td:last-child { border-right: none; }';
    $pdfHtml .= '.info-table .blue-row .data-cell.ar-text { color: rgba(255, 255, 255, 1); font-size: 13.5px; font-family: "Times New Roman", serif; font-weight: 400; }';
    $pdfHtml .= '.info-table .blue-row .data-cell { color: rgba(255, 255, 255, 1); }';
    $pdfHtml .= '.info-table tr.gray-row td { background-color: #f7f7f7; }';
    
    // Layout Placeholders
    $pdfHtml .= '.en-spaced { letter-spacing: 0.3px; }';
    $pdfHtml .= ':root { --footer-offset: 40px; }';
    $pdfHtml .= '.group1-thq-staticinfo-elm { top: 125px; left: 36.65px; width: 768.35px; height: 811.91px; display: flex; position: absolute; align-items: flex-start; pointer-events: none; }';
    
    // Side Placeholders
    $pdfHtml .= '.top-right-placeholder { position: absolute; top: 36px; left: 543.36px; width: 262.43px; height: 107.22px; display: flex; align-items: center; justify-content: center; font-size: 14px; z-index: 5; }';
    $pdfHtml .= '.top-left-placeholder { position: absolute; top: 36px; left: 36px; width: 149.96px; height: 65.98px; display: flex; align-items: center; justify-content: center; font-size: 14px; z-index: 5; }';
    $pdfHtml .= '.bottom-right-placeholder { position: absolute; top: 980px; left: 657.17px; width: 149.96px; height: 71.23px; display: flex; align-items: center; justify-content: center; font-size: 12px; z-index: 5; }';
    $pdfHtml .= '.header-placeholder { top: -50px; left: 303px; width: 163px; height: 40px; position: absolute; display: flex; align-items: center; justify-content: center; font-size: 11px; }';
    
    // Text Elements referencing the embedded font
    $pdfHtml .= '.group1-thq-text-elm41 { top: 40px; left: 281px; color: rgba(48, 109, 181, 1); width: 215px; position: absolute; font-size: 22.5px; font-weight: 700; text-align: center; line-height: 30px; }';
    $pdfHtml .= '.group1-thq-text-elm44 { top: -10px; left: 293px; color: rgba(0, 0, 0, 1); position: absolute; font-size: 17.3px; font-weight: 400; text-align: left; font-family: "Times New Roman", serif; }';
    
    $pdfHtml .= '.group1-thq-hospitallogoandthename-elm { top: 760px; left: 438.94px; width: 403px; height: 202.78px; display: flex; position: absolute; align-items: flex-start; }';
    $pdfHtml .= '.placeholder-logo-hospital { top: -12px; left: 133px; width: 136px; height: 136px; position: absolute; display: flex; align-items: center; justify-content: center; font-size: 12px; }';
    $pdfHtml .= '.group1-thq-text-elm18 { top: 113px; color: rgba(0, 0, 0, 1); width: 403px; height: auto; position: absolute; font-size: 12.8px; text-align: center; line-height: 22px; }';
    
    $pdfHtml .= '.group1-thq-thedateofissueandalsotimeofissue-elm { top: calc(950px + var(--footer-offset)); left: 37.37px; width: 250px; height: 56px; display: flex; position: absolute; align-items: flex-start; }';
    $pdfHtml .= '.group1-thq-text-elm22 { color: rgba(0, 0, 0, 1); font-size: 12.5px; font-weight: 700; text-align: left; line-height: 28px; font-family: "Times New Roman", serif; position: absolute; white-space: nowrap; }';
    
    $pdfHtml .= '.group1-thq-text-elm36 { top: calc(680px + var(--footer-offset)); left: 29.23px; color: rgba(0, 0, 0, 1); position: absolute; font-size: 12px; font-weight: 700; text-align: center; font-family: "Noto Sans Arabic", sans-serif; line-height: 23px; }';
    $pdfHtml .= '.group1-thq-text-elm39 { top: calc(728px + var(--footer-offset)); left: 55px; color: rgba(0, 0, 0, 1); position: absolute; font-size: 12px; font-weight: 700; text-align: left; font-family: "Times New Roman", serif; }';
    $pdfHtml .= '.group1-thq-text-elm40 { top: calc(750px + var(--footer-offset)); left: 108.35px; color: rgba(20, 0, 255, 1); position: absolute; font-size: 11px; font-weight: 700; text-align: left; text-decoration: underline; pointer-events: auto; font-family: "Times New Roman", serif; }';
    
    // Footer & Misc
    $pdfHtml .= '.placeholder-136 { position: absolute; top: 607px; left: 137px; width: 103.9px; height: 103.9px; display: flex; align-items: center; justify-content: center; font-size: 12px; pointer-events: auto; }';
    $pdfHtml .= '.vertical-divider { position: absolute; top: 723px; left: 431px; width: 1.5px; height: 6cm; background-color: #dddddd; }';
    $pdfHtml .= '.thin-slash { font-weight: 300; font-family: "Inter", sans-serif; margin: 0 3px; display: inline-block; }';
    $pdfHtml .= '</style></head><body>';
    
    // Replace relative paths with absolute URLs and update .svg targets to .png
    $pdfBody = str_replace(
        ['src="sehalogoright.png"', 'src="sehalogoleft.png"', 'src="bottomright.png"', 'src="header.png"', 'src="qr.svg"'],
        ['src="' . $baseUrl . 'sehalogoright.png"', 'src="' . $baseUrl . 'sehalogoleft.png"', 'src="' . $baseUrl . 'bottomright.png"', 'src="' . $baseUrl . 'header.png"', 'src="' . $baseUrl . 'qr.svg"'],
        // Also ensure fallback replacement just in case the source HTML still contains the old .svg strings
        str_replace(
            ['src="sehalogoright.png"', 'src="bottomright.png"', 'src="header.png"'],
            ['src="sehalogoright.png"', 'src="bottomright.png"', 'src="header.png"'],
            $reportBody
        )
    );
    $pdfHtml .= $pdfBody;
    $pdfHtml .= '</body></html>';
    
    // Save HTML to temp file safely
    $tmpHtml = '/tmp/weasyprint/report_' . uniqid() . '.html';
    $tmpPdf = '/tmp/weasyprint/report_' . uniqid() . '.pdf';
    
    if (!is_dir('/tmp/weasyprint')) {
        mkdir('/tmp/weasyprint', 0777, true);
    }
    
    file_put_contents($tmpHtml, $pdfHtml);
    
    // Run WeasyPrint via Python script
    $scriptPath = __DIR__ . '/generate_pdf.py';
    $pythonBin = 'python3';
    foreach (['/usr/bin/python3.13', '/usr/bin/python3.12', '/usr/bin/python3.11', '/usr/local/bin/python3', '/usr/bin/python3'] as $p) {
        if (is_file($p) && !is_link($p)) { $pythonBin = $p; break; }
        if (is_link($p)) { $real = realpath($p); if ($real && is_file($real)) { $pythonBin = $real; break; } }
    }
    
    $cmd = escapeshellarg($pythonBin) . ' ' . escapeshellarg($scriptPath) . ' ' . escapeshellarg($tmpHtml) . ' ' . escapeshellarg($tmpPdf) . ' 2>&1';
    $output = shell_exec($cmd);
    
    if (file_exists($tmpPdf) && filesize($tmpPdf) > 0) {
        header('Content-Type: application/pdf');
        header('Content-Disposition: attachment; filename="sickLeaves.pdf"');
        header('Content-Length: ' . filesize($tmpPdf));
        header('Cache-Control: no-cache, no-store, must-revalidate');
        readfile($tmpPdf);
        @unlink($tmpHtml);
        @unlink($tmpPdf);
        exit;
    } else {
        @unlink($tmpHtml);
        error_log('WeasyPrint Error: ' . $output);
    }
    return;
}
    // ==================== PREVIEW MODE ====================
  header('Content-Type: text/html; charset=utf-8');
    
    $html = '<!DOCTYPE html>' . "\n";
    $html .= '<html lang="ar">' . "\n";
    $html .= '<head>' . "\n";
    $html .= '<title>تقرير إجازة مرضية - Sick Leave Report</title>' . "\n";
    $html .= '<meta property="og:title" content="Sick Leave Report" />' . "\n";
    $html .= '<meta name="viewport" content="width=device-width, initial-scale=1.0" />' . "\n";
    $html .= '<meta charset="utf-8" />' . "\n";
    $html .= '<style data-tag="reset-style-sheet">' . "\n";
    $html .= 'html { line-height: 1.15; }' . "\n";
    $html .= 'body { margin: 0; }' . "\n";
    $html .= '* { box-sizing: border-box; border-width: 0; border-style: solid; -webkit-font-smoothing: antialiased; }' . "\n";
    $html .= 'p, li, ul, pre, div, h1, h2, h3, h4, h5, h6, figure, blockquote, figcaption { margin: 0; padding: 0; }' . "\n";
    $html .= 'a { color: inherit; text-decoration: inherit; }' . "\n";
    $html .= 'html { scroll-behavior: smooth }' . "\n";
    $html .= '</style>' . "\n";
    $html .= '<style data-tag="default-style-sheet">' . "\n";
    $html .= 'html { font-family: Inter, sans-serif; font-size: 16px; -webkit-text-size-adjust: 100%; -moz-text-size-adjust: 100%; text-size-adjust: 100%; }' . "\n";
    $html .= 'body { font-weight: 400; color: #191818; background: #FBFAF9; overflow-x: hidden; }' . "\n";
    $html .= '</style>' . "\n";
    $html .= '<link rel="stylesheet" href="https://fonts.googleapis.com/css2?family=Inter:wght@100;200;300;400;500;600;700&display=swap" />' . "\n";
    $html .= '<link rel="stylesheet" href="https://fonts.googleapis.com/css2?family=STIX+Two+Text:ital,wght@0,400;0,600;0,700;1,400&display=swap" />' . "\n";
    $html .= '<link rel="stylesheet" href="https://fonts.googleapis.com/css2?family=Noto+Sans+Arabic:wght@400;600;700&display=swap" />' . "\n";

    $html .= '<style>' . "\n";
    // Layout Container
    $html .= '.group1-container1 { width: 100%; display: flex; overflow-x: hidden; min-height: 100vh; align-items: center; flex-direction: column; background-color: #f0f0f0; padding-top: 20px; padding-bottom: 20px; }' . "\n";
    // Main Document Sheet
    $html .= '.group1-thq-group1-elm { width: 842.25px; height: 1190.25px; display: flex; position: relative; align-items: flex-start; flex-shrink: 0; box-shadow: 0px 4px 15px rgba(0,0,0,0.1); background-color: white; }' . "\n";
    // Table styles
    $html .= '.info-table { position: absolute; top: 242px; left: 36px; width: 770px; border-collapse: separate; border-spacing: 0; border: 1px solid #cccccc; border-radius: 8px; overflow: hidden; background-color: transparent; z-index: 10; }' . "\n";
    $html .= '.info-table td { border-bottom: 1px solid #cccccc; border-right: 1px solid #cccccc; height: 42px; text-align: center; vertical-align: middle; padding: 4px 8px; }' . "\n";
    $html .= '.info-table td:last-child { border-right: none; } .info-table tr:last-child td { border-bottom: none; }' . "\n";
    $html .= '.info-table .en-title { width: 161px; color: rgba(54, 111, 181, 1); font-size: 13.5px; font-weight: 700; text-align: center; font-family: "Times New Roman", serif; }' . "\n";
    $html .= '.info-table .data-cell { width: 240px; color: rgba(44, 62, 119, 1); font-size: 13.5px; font-family: "Times New Roman", serif; font-weight: 400; text-align: center; }' . "\n";
    $html .= '.info-table .date-cell { font-size: 13.9px; } .info-table .data-cell.ar-text { font-family: "Noto Sans Arabic", sans-serif; }' . "\n";
    $html .= '.info-table .ar-title { width: 140px; color: rgba(54, 111, 181, 1); font-size: 13.5px; font-weight: 700; text-align: center; font-family: "Noto Sans Arabic", sans-serif; white-space: nowrap; }' . "\n";
    $html .= '.info-table tr.blue-row td { background-color: #2c3e77; color: #ffffff; border-bottom: 1px solid #cccccc; border-right: 1px solid #cccccc; }' . "\n";
    $html .= '.info-table tr.blue-row td:last-child { border-right: none; }' . "\n";
    $html .= '.info-table .blue-row .data-cell.ar-text { color: rgba(255, 255, 255, 1); font-size: 13.5px; font-family: "Times New Roman", serif; font-weight: 400; }' . "\n";
    $html .= '.info-table .blue-row .data-cell { color: rgba(255, 255, 255, 1); }' . "\n";
    $html .= '.info-table tr.gray-row td { background-color: #f7f7f7; }' . "\n";
    $html .= '.en-spaced { letter-spacing: 0.3px; }' . "\n";
    $html .= ':root { --footer-offset: 40px; }' . "\n";
    // Positioning styles
    $html .= '.group1-thq-staticinfo-elm { top: 125px; left: 36.65px; width: 768.35px; height: 811.91px; display: flex; position: absolute; align-items: flex-start; pointer-events: none; }' . "\n";
    $html .= '.top-right-placeholder { position: absolute; top: 36px; left: 592px; width: 214px; height: 107px; display: flex; align-items: center; justify-content: center; font-size: 14px; z-index: 5; }' . "\n";
    $html .= '.top-left-placeholder { position: absolute; top: 36px; left: 36px; width: 149.96px; height: 65.98px; display: flex; align-items: center; justify-content: center; font-size: 14px; z-index: 5; }' . "\n";
    $html .= '.bottom-right-placeholder { position: absolute; top: 980px; left: 657.17px; width: 149.96px; height: 71.23px; display: flex; align-items: center; justify-content: center; font-size: 12px; z-index: 5; }' . "\n";
    $html .= '.header-placeholder { top: -55px; left: 303px; width: 160px; height: 50px; position: absolute; display: flex; align-items: center; justify-content: center; font-size: 11px; }' . "\n";
    $html .= '.group1-thq-text-elm41 { top: 40px; left: 281px; color: rgba(48, 109, 181, 1); width: 215px; position: absolute; font-size: 22.5px; font-weight: 700; text-align: center; line-height: 30px; }' . "\n";
    $html .= '.group1-thq-text-elm44 { top: -10px; left: 293px; color: rgba(0, 0, 0, 1); position: absolute; font-size: 17.3px; font-weight: 400; text-align: left; font-family: "Times New Roman", serif; }' . "\n";
    $html .= '.group1-thq-hospitallogoandthename-elm { top: 760px; left: 438.94px; width: 403px; height: 202.78px; display: flex; position: absolute; align-items: flex-start; }' . "\n";
    $html .= '.placeholder-logo-hospital { top: -12px; left: 133px; width: 136px; height: 136px; position: absolute; display: flex; align-items: center; justify-content: center; font-size: 12px; }' . "\n";
    $html .= '.group1-thq-text-elm18 { top: 120px; color: rgba(0, 0, 0, 1); width: 403px; height: auto; position: absolute; font-size: 12.8px; text-align: center; line-height: 22px; }' . "\n";
    $html .= '.group1-thq-thedateofissueandalsotimeofissue-elm { top: calc(950px + var(--footer-offset)); left: 37.37px; width: 250px; height: 56px; display: flex; position: absolute; align-items: flex-start; }' . "\n";
    $html .= '.group1-thq-text-elm22 { color: rgba(0, 0, 0, 1); font-size: 12.5px; font-weight: 700; text-align: left; line-height: 28px; font-family: "Times New Roman", serif; position: absolute; white-space: nowrap; }' . "\n";
    $html .= '.group1-thq-text-elm36 { top: calc(680px + var(--footer-offset)); left: 29.23px; color: rgba(0, 0, 0, 1); position: absolute; font-size: 12px; font-weight: 700; text-align: center; font-family: "Noto Sans Arabic", sans-serif; line-height: 23px; }' . "\n";
    $html .= '.group1-thq-text-elm39 { top: calc(728px + var(--footer-offset)); left: 55px; color: rgba(0, 0, 0, 1); position: absolute; font-size: 12px; font-weight: 700; text-align: left; font-family: "Times New Roman", serif; }' . "\n";
    $html .= '.group1-thq-text-elm40 { top: calc(750px + var(--footer-offset)); left: 108.35px; color: rgba(20, 0, 255, 1); position: absolute; font-size: 11px; font-weight: 700; text-align: left; text-decoration: underline; pointer-events: auto; font-family: "Times New Roman", serif; }' . "\n";
    $html .= '.placeholder-136 { position: absolute; top: 607px; left: 137px; width: 103.9px; height: 103.9px; display: flex; align-items: center; justify-content: center; font-size: 12px; pointer-events: auto; }' . "\n";
    $html .= '.vertical-divider { position: absolute; top: 723px; left: 436px; width: 1.5px; height: 6cm; background-color: #dddddd; }' . "\n";
    $html .= '.thin-slash { font-weight: 300; font-family: "Inter", sans-serif; margin: 0 3px; display: inline-block; }' . "\n";
    // Download button styles
    $html .= '.controls { position: fixed; bottom: 30px; right: 30px; display: flex; gap: 15px; z-index: 1000; }' . "\n";
    $html .= '.download-btn { background-color: #306db5; color: white; padding: 14px 28px; border-radius: 10px; border: none; font-size: 16px; font-weight: 600; cursor: pointer; box-shadow: 0px 6px 15px rgba(0,0,0,0.3); font-family: "Inter", sans-serif; transition: all 0.3s cubic-bezier(0.4, 0, 0.2, 1); }' . "\n";
    $html .= '.download-btn:hover { background-color: #2c3e77; transform: translateY(-3px); box-shadow: 0px 8px 20px rgba(0,0,0,0.4); }' . "\n";
    $html .= '.download-btn:active { transform: translateY(-1px); }' . "\n";
    // Mobile scaling CSS
    $html .= '@media screen and (max-width: 880px) {' . "\n";
    $html .= '  .group1-container1 { padding-top: 10px; padding-bottom: 10px; }' . "\n";
    $html .= '  .group1-thq-group1-elm { transform-origin: top center; transform: scale(calc(100vw / 860)); margin-bottom: calc(1190.25px * (100vw / 860) - 1190.25px); }' . "\n";
    $html .= '  .controls { bottom: 15px; right: 15px; left: 15px; justify-content: center; }' . "\n";
    $html .= '  .download-btn { width: 100%; text-align: center; font-size: 18px; padding: 16px; }' . "\n";
    $html .= '}' . "\n";
    // Print CSS
    $html .= '@media print {' . "\n";
    $html .= '  @page { size: 842.25px 1190.25px; margin: 0; }' . "\n";
    $html .= '  body { -webkit-print-color-adjust: exact !important; print-color-adjust: exact !important; background: white !important; }' . "\n";
    $html .= '  .controls { display: none !important; }' . "\n";
    $html .= '  .group1-container1 { padding: 0 !important; background-color: transparent !important; }' . "\n";
    $html .= '  .group1-thq-group1-elm { box-shadow: none !important; margin: 0 !important; transform: scale(1) !important; transform-origin: top left !important; }' . "\n";
    $html .= '  a { color: rgba(20, 0, 255, 1) !important; text-decoration: underline !important; }' . "\n";
    $html .= '}' . "\n";
    $html .= '</style>' . "\n";
    $html .= '</head>' . "\n";
    $html .= '<body>' . "\n";
    // Controls - two buttons
    $html .= '<div class="controls">' . "\n";
    $html .= '  <button id="btnDownloadPDF" class="download-btn" onclick="downloadPDF()">تحميل ملف PDF</button>' . "\n";
    $html .= '  <button class="download-btn" style="background-color:#2c3e77" onclick="window.print()">طباعة مباشرة (جودة كانفا)</button>' . "\n";
    $html .= '</div>' . "\n";
    // Main content
    $html .= '<div class="group1-container1">' . "\n";
    $html .= '  <div class="group1-thq-group1-elm" id="report-content">' . "\n";
    // Side Placeholders
    $html .= '    <div class="top-right-placeholder"><img src="sehalogoright.png" alt="Logo Placeholder" style="width: 100%; height: 100%;" onerror="this.style.display=\'none\'" /></div>' . "\n";
    $html .= '    <div class="top-left-placeholder"><img src="sehalogoleft.png" alt="Logo Placeholder" style="width: 100%; height: 100%;" onerror="this.style.display=\'none\'" /></div>' . "\n";
    $html .= '    <div class="bottom-right-placeholder"><img src="bottomright.png" alt="Signature Placeholder" style="width: 100%; height: 100%;" onerror="this.style.display=\'none\'" /></div>' . "\n";
    // Headers
    $html .= '    <div class="group1-thq-staticinfo-elm">' . "\n";
    $html .= '      <div class="header-placeholder"><img src="header.png" alt="Header Placeholder" style="width: 100%; height: 100%;" onerror="this.style.display=\'none\'" /></div>' . "\n";
    $html .= '      <span class="group1-thq-text-elm41"><span style="font-size: 22.5px; font-family: \'Noto Sans Arabic\', sans-serif; font-weight: 700; color: #306db5;">تقرير إجازة مرضية</span><br /><span style="font-size: 18.7px; font-family: \'Times New Roman\', serif; font-weight: 700; color: #2c3e77;">Sick Leave Report</span></span>' . "\n";
    $html .= '      <span class="group1-thq-text-elm44">Kingdom of Saudi Arabia</span>' . "\n";
    // QR Code
    $html .= '      <div class="placeholder-136"><img src="qr.svg" alt="QR Code" style="width: 103.9px; height: 103.9px;" onerror="this.style.display=\'none\'" /></div>' . "\n";
    // Verification Text
    $html .= '      <span class="group1-thq-text-elm36" dir="rtl">للتحقق من بيانات التقرير يرجى التأكد من زيارة موقع منصة صحة<br />الرسمي</span>' . "\n";
    $html .= '      <span class="group1-thq-text-elm39">To check the report please visit Seha\'s official website</span>' . "\n";
    $html .= '      <span class="group1-thq-text-elm40"><a href="https://seha-sa-inquiries-slenquiry.up.railway.app/" target="_blank">www.seha.sa/#/inquiries/slenquiry</a></span>' . "\n";
    $html .= '    </div>' . "\n";
    // Table
    $html .= '    <table class="info-table" cellpadding="0" cellspacing="0"><tbody>' . "\n";
    $html .= '      <tr><td class="en-title">Leave ID</td><td class="data-cell" colspan="2">' . $sc . '</td><td class="ar-title">رمز الإجازة</td></tr>' . "\n";
    $html .= '      <tr class="blue-row"><td class="en-title" style="color: white;">Leave Duration</td><td class="data-cell">' . $durationEn . '</td><td class="data-cell ar-text" dir="rtl">' . $durationAr . '</td><td class="ar-title" style="color: white;">مدة الإجازة</td></tr>' . "\n";
    $html .= '      <tr><td class="en-title">Admission Date</td><td class="data-cell date-cell">' . $startEn . '</td><td class="data-cell date-cell" dir="ltr">' . $startHj . '</td><td class="ar-title">تاريخ الدخول</td></tr>' . "\n";
    $html .= '      <tr class="gray-row"><td class="en-title">Discharge Date</td><td class="data-cell date-cell">' . $dischargeEn . '</td><td class="data-cell date-cell" dir="ltr">' . $dischargeHj . '</td><td class="ar-title">تاريخ الخروج</td></tr>' . "\n";
    $html .= '      <tr><td class="en-title">Issue Date</td><td class="data-cell" colspan="2">' . $issueEn . '</td><td class="ar-title">تاريخ الإصدار</td></tr>' . "\n";
    $html .= '      <tr class="gray-row"><td class="en-title">Patient Name</td><td class="data-cell en-spaced">' . $patNameEn . '</td><td class="data-cell ar-text">' . $patNameAr . '</td><td class="ar-title">الاسم</td></tr>' . "\n";
    $html .= '      <tr><td class="en-title">National ID / Iqama</td><td class="data-cell" colspan="2">' . $patId . '</td><td class="ar-title">رقم الهوية<span class="thin-slash">/</span>الإقامة</td></tr>' . "\n";
    $html .= '      <tr class="gray-row"><td class="en-title">Nationality</td><td class="data-cell en-spaced">' . $natEn . '</td><td class="data-cell ar-text">' . $natAr . '</td><td class="ar-title">الجنسية</td></tr>' . "\n";
    $html .= '      <tr><td class="en-title">Employer</td><td class="data-cell en-spaced">' . $empEn . '</td><td class="data-cell ar-text">' . $empAr . '</td><td class="ar-title">جهة العمل</td></tr>' . "\n";
    $html .= '      <tr class="gray-row"><td class="en-title">Practitioner Name</td><td class="data-cell en-spaced">' . $docNameEn . '</td><td class="data-cell ar-text">' . $docNameAr . '</td><td class="ar-title">اسم الممارس</td></tr>' . "\n";
    $html .= '      <tr><td class="en-title">Position</td><td class="data-cell en-spaced">' . $docTitleEn . '</td><td class="data-cell ar-text">' . $docTitleAr . '</td><td class="ar-title">المسمى الوظيفي</td></tr>' . "\n";
    $html .= '    </tbody></table>' . "\n";
    // Vertical Divider
    $html .= '    <div class="vertical-divider"></div>' . "\n";
    // Hospital section
    $html .= '    <div class="group1-thq-hospitallogoandthename-elm">' . "\n";
    $html .= '      <div class="placeholder-logo-hospital">' . $hospLogoHtml . '</div>' . "\n";
    $html .= '      <span class="group1-thq-text-elm18">' . "\n";
    $html .= '        <span style="font-family: \'Noto Sans Arabic\', sans-serif; font-weight: 700;">' . $hospNameAr . '</span><br />' . "\n";
    $html .= '        <span class="en-spaced" style="font-family: \'Times New Roman\', serif; font-weight: 700;">' . $hospNameEn . '</span><br />' . "\n";
    if (!empty($licenseHtml)) $html .= '        ' . $licenseHtml . "\n";
    $html .= '      </span>' . "\n";
    $html .= '    </div>' . "\n";
    // Issue Timestamp
    $html .= '    <div class="group1-thq-thedateofissueandalsotimeofissue-elm">' . "\n";
    $html .= '      <span class="group1-thq-text-elm22">' . "\n";
    $html .= '        <span>' . $timestampLine . '</span><br />' . "\n";
    $html .= '        <span>' . $dateLine . '</span>' . "\n";
    $html .= '      </span>' . "\n";
    $html .= '    </div>' . "\n";
    $html .= '  </div>' . "\n";
    $html .= '</div>' . "\n";
    // JavaScript - download PDF via server-side WeasyPrint
    $html .= '<script>' . "\n";
    $html .= 'function downloadPDF() {' . "\n";
    $html .= '  var btn = document.getElementById("btnDownloadPDF");' . "\n";
    $html .= '  btn.textContent = "جاري التحميل...";' . "\n";
    $html .= '  btn.disabled = true;' . "\n";
    $html .= '  var url = window.location.href;' . "\n";
    $html .= '  if (url.indexOf("pdf_mode=") > -1) { url = url.replace(/pdf_mode=[^&]*/, "pdf_mode=download"); }' . "\n";
    $html .= '  else { url += (url.indexOf("?") > -1 ? "&" : "?") + "pdf_mode=download"; }' . "\n";
    $html .= '  var a = document.createElement("a");' . "\n";
    $html .= '  a.href = url;' . "\n";
    $html .= '  a.download = "sickLeaves.pdf";' . "\n";
    $html .= '  document.body.appendChild(a);' . "\n";
    $html .= '  a.click();' . "\n";
    $html .= '  document.body.removeChild(a);' . "\n";
    $html .= '  setTimeout(function() { btn.textContent = "تحميل ملف PDF"; btn.disabled = false; }, 3000);' . "\n";
    $html .= '}' . "\n";
    $html .= '</script>' . "\n";
    $html .= '</body>' . "\n";
    $html .= '</html>';
    echo $html;
    exit;
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
    
    $stmt = $pdo->prepare("SELECT u.* FROM admin_users u LEFT JOIN patient_accounts pa ON pa.user_id = u.id WHERE u.username = ? AND u.is_active = 1");
    $stmt->execute([$username]);
    $user = $stmt->fetch();

    // منع حسابات المرضى من الدخول إلى لوحة التحكم
    if ($user && password_verify($password, $user['password_hash'])) {
        // التحقق من أن المستخدم ليس حساب مريض
        $patientCheckStmt = $pdo->prepare("SELECT COUNT(*) FROM patient_accounts WHERE user_id = ?");
        $patientCheckStmt->execute([$user['id']]);
        $isPatientAccount = (int)$patientCheckStmt->fetchColumn() > 0;

        if ($isPatientAccount) {
            // حساب مريض - لا يُسمح له بالدخول إلى لوحة التحكم
            $_SESSION['login_attempts'] = intval($_SESSION['login_attempts'] ?? 0) + 1;
            echo json_encode(['success' => false, 'message' => 'اسم المستخدم أو كلمة المرور غير صحيحة.']);
            exit;
        }

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

// ======================== معالجة طلب generate_pdf عبر GET ========================
if (isset($_GET['action']) && $_GET['action'] === 'generate_pdf') {
    if (!is_logged_in()) {
        header('Location: ' . $_SERVER['SCRIPT_NAME']);
        exit;
    }
    if (!verify_csrf($_GET['csrf_token'] ?? '')) {
        header('Location: ' . $_SERVER['SCRIPT_NAME']);
        exit;
    }
    $leave_id = intval($_GET['leave_id'] ?? 0);
    $pdfMode = $_GET['pdf_mode'] ?? 'preview';
    handleGeneratePdf($pdo, $leave_id, $pdfMode);
    exit;
}

// ======================== معالجة طلبات AJAX عبر GET ========================
$_GET_AJAX_ACTIONS = ['fetch_accounts_full', 'get_patient_account', 'get_hospital_logo', 'fetch_notifications', 'get_unread_count', 'fetch_user_notifications'];
if (isset($_GET['action']) && in_array($_GET['action'], $_GET_AJAX_ACTIONS) && !isset($_POST['action'])) {
    header('Content-Type: application/json; charset=utf-8');
    if (!is_logged_in()) {
        echo json_encode(['success' => false, 'message' => 'يرجى تسجيل الدخول أولاً.', 'redirect' => true]);
        exit;
    }
    // For GET AJAX actions, allow without CSRF (read-only) or check header
    $action = $_GET['action'];

    set_exception_handler(function(Throwable $e) {
        if (!headers_sent()) { header('Content-Type: application/json; charset=utf-8'); }
        echo json_encode(['success' => false, 'message' => 'تعذّر تنفيذ العملية: ' . $e->getMessage()], JSON_UNESCAPED_UNICODE);
        exit;
    });

    switch ($action) {
        case 'fetch_accounts_full':
            if (($_SESSION['admin_role'] ?? 'user') !== 'admin') { echo json_encode(['success'=>false,'message'=>'ليس لديك صلاحية.']); exit; }
            $pdo->exec("CREATE TABLE IF NOT EXISTS account_payments (
                id INT AUTO_INCREMENT PRIMARY KEY,
                user_id INT NOT NULL,
                amount DECIMAL(10,2) NOT NULL DEFAULT 0,
                note VARCHAR(500) NULL,
                paid_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                created_by INT NULL,
                FOREIGN KEY (user_id) REFERENCES admin_users(id) ON DELETE CASCADE
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci");
            ensureColumn($pdo, 'patient_accounts', 'expiry_date', "DATE NULL AFTER allowed_days");
            ensureColumn($pdo, 'patient_accounts', 'notes', "TEXT NULL AFTER expiry_date");
            $accounts = $pdo->query("
                SELECT u.id, u.username, u.display_name, u.role, u.is_active, u.created_at,
                       pa.patient_id AS linked_patient_id, pa.allowed_days AS patient_allowed_days,
                       pa.expiry_date, pa.notes AS account_notes,
                       p.name_ar AS linked_patient_name, p.identity_number AS patient_identity,
                       COALESCE((SELECT SUM(amount) FROM account_payments WHERE user_id = u.id AND is_paid = 1), 0) AS total_paid,
                       COALESCE((SELECT COUNT(*) FROM account_payments WHERE user_id = u.id), 0) AS payment_count,
                       COALESCE((SELECT COUNT(*) FROM sick_leaves sl WHERE sl.patient_id = pa.patient_id AND sl.deleted_at IS NULL AND sl.created_by_user_id = u.id), 0) AS portal_leave_count,
                       COALESCE((SELECT SUM(sl.days_count) FROM sick_leaves sl WHERE sl.patient_id = pa.patient_id AND sl.deleted_at IS NULL AND sl.created_by_user_id = u.id), 0) AS portal_used_days,
                       GREATEST(pa.allowed_days - COALESCE((SELECT SUM(sl.days_count) FROM sick_leaves sl WHERE sl.patient_id = pa.patient_id AND sl.deleted_at IS NULL AND sl.created_by_user_id = u.id), 0), 0) AS portal_remaining_days,
                       COALESCE((SELECT SUM(CASE WHEN ap.is_paid = 1 THEN 1 ELSE 0 END) FROM account_payments ap WHERE ap.user_id = u.id), 0) AS account_paid_count,
                       COALESCE((SELECT SUM(CASE WHEN ap.is_paid = 0 THEN 1 ELSE 0 END) FROM account_payments ap WHERE ap.user_id = u.id), 0) AS account_unpaid_count,
                       COALESCE((SELECT SUM(CASE WHEN ap.is_paid = 0 THEN ap.amount ELSE 0 END) FROM account_payments ap WHERE ap.user_id = u.id), 0) AS total_unpaid
                FROM admin_users u
                INNER JOIN patient_accounts pa ON pa.user_id = u.id
                LEFT JOIN patients p ON pa.patient_id = p.id
                ORDER BY u.created_at DESC
            ")->fetchAll();
            echo json_encode(['success'=>true,'accounts'=>$accounts]);
            break;

        case 'get_patient_account':
            if (($_SESSION['admin_role'] ?? 'user') !== 'admin') { echo json_encode(['success'=>false,'message'=>'ليس لديك صلاحية.']); exit; }
            $target_user_id = intval($_GET['user_id'] ?? 0);
            $stmt = $pdo->prepare("SELECT pa.*, p.name_ar AS patient_name FROM patient_accounts pa LEFT JOIN patients p ON pa.patient_id = p.id WHERE pa.user_id = ?");
            $stmt->execute([$target_user_id]);
            $pa = $stmt->fetch();
            $patients_list = $pdo->query("SELECT id, name_ar, identity_number FROM patients ORDER BY name_ar")->fetchAll();
            echo json_encode(['success' => true, 'account' => $pa ?: null, 'patients' => $patients_list]);
            break;

        case 'fetch_user_notifications':
            $uid = intval($_SESSION['admin_user_id'] ?? 0);
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
            $unread = $pdo->prepare("SELECT COUNT(*) FROM user_notifications WHERE user_id = ? AND is_read = 0");
            $unread->execute([$uid]);
            echo json_encode(['success'=>true,'notifications'=>$notifs,'unread_count'=>(int)$unread->fetchColumn()]);
            break;

        case 'get_hospital_logo':
            // Return image directly (not JSON)
            $hid = intval($_GET['hospital_id'] ?? 0);
            $stmt = $pdo->prepare("SELECT logo_data, logo_url FROM hospitals WHERE id = ?");
            $stmt->execute([$hid]);
            $hRow = $stmt->fetch();
            if ($hRow && !empty($hRow['logo_data']) && strpos($hRow['logo_data'], 'data:image/') === 0) {
                $parts = explode(',', $hRow['logo_data'], 2);
                preg_match('/data:image\/([a-z+]+);/', $parts[0], $mimeMatch);
                $mime = 'image/' . ($mimeMatch[1] ?? 'png');
                header('Content-Type: ' . $mime);
                echo base64_decode($parts[1] ?? '');
            } elseif ($hRow && !empty($hRow['logo_url'])) {
                header('Location: ' . $hRow['logo_url']);
            } else {
                header('HTTP/1.1 404 Not Found');
                echo 'No logo';
            }
            exit;

        case 'fetch_notifications':
            ensureDelayedUnpaidNotifications($pdo);
            $notifications = $pdo->query("
                SELECT n.*, COALESCE(sl.payment_amount, ap.amount, 0) AS payment_amount,
                       COALESCE(sl.service_code, CONCAT('ACC-', ap.id), '-') AS service_code,
                       sl.patient_id,
                       COALESCE(p.name_ar, p.name, au.display_name, au.username, '') AS patient_name,
                       p.phone AS patient_phone,
                       ap.user_id AS account_user_id,
                       ap.days_count AS account_days_count,
                       ap.is_paid AS account_is_paid
                FROM notifications n
                LEFT JOIN sick_leaves sl ON n.leave_id = sl.id
                LEFT JOIN patients p ON sl.patient_id = p.id
                LEFT JOIN account_payments ap ON n.account_payment_id = ap.id
                LEFT JOIN admin_users au ON ap.user_id = au.id
                WHERE n.type = 'payment'
                ORDER BY n.created_at DESC
            ")->fetchAll();
            echo json_encode(['success' => true, 'data' => $notifications]);
            break;

        case 'get_unread_count':
            echo json_encode(['success' => true, 'count' => getUnreadMessagesCount($pdo, intval($_SESSION['admin_user_id'] ?? 0))]);
            break;

        default:
            echo json_encode(['success'=>false,'message'=>'إجراء غير معروف.']);
    }
    exit;
}

// ======================== معالجة طلبات AJAX ========================
if (isset($_POST['action']) && $_POST['action'] !== 'login' && $_POST['action'] !== 'logout') {
    header('Content-Type: application/json; charset=utf-8');
    
    if (!is_logged_in()) {
        echo json_encode(['success' => false, 'message' => 'يرجى تسجيل الدخول أولاً.', 'redirect' => true]);
        exit;
    }
    
    if (!verify_csrf($_POST['csrf_token'] ?? $_GET['csrf_token'] ?? '')) {
        echo json_encode(['success' => false, 'message' => 'خطأ في التحقق من الأمان (CSRF). يرجى تحديث الصفحة.']);
        exit;
    }
    
    $action = $_POST['action'] ?? $_GET['action'] ?? '';

    set_exception_handler(function(Throwable $e) {
        if (!headers_sent()) {
            header('Content-Type: application/json; charset=utf-8');
            http_response_code(200);
        }
        echo json_encode([
            'success' => false,
            'message' => 'تعذّر تنفيذ العملية: ' . $e->getMessage()
        ], JSON_UNESCAPED_UNICODE);
        exit;
    });

    // ======================== معالجة الإجراءات ========================
    switch ($action) {
        case 'fetch_all_leaves':
            $data = fetchAllData($pdo);
            $data['doctors'] = $pdo->query("SELECT d.*, h.name_ar AS hospital_name_ar FROM doctors d LEFT JOIN hospitals h ON d.hospital_id = h.id ORDER BY d.name_ar")->fetchAll();
            $data['patients'] = $pdo->query("SELECT * FROM patients ORDER BY name_ar")->fetchAll();
            $data['hospitals'] = getHospitalsList($pdo);
            $data['stats'] = getStats($pdo);
            $data['unread_messages_count'] = getUnreadMessagesCount($pdo, intval($_SESSION['admin_user_id'] ?? 0));
            $data['success'] = true;
            echo json_encode($data);
            break;

        // ======================== إدارة المستشفيات ========================
        case 'preview_hospital_logo_url':
            $logo_url = trim($_POST['hospital_logo_url'] ?? '');
            if ($logo_url === '') { echo json_encode(['success'=>false,'message'=>'يرجى إدخال رابط الشعار.']); exit; }
            $logo_data = downloadLogoFromUrl($logo_url);
            if (!$logo_data) { echo json_encode(['success'=>false,'message'=>'تعذّرت معاينة الرابط من الخادم، تأكد أن الرابط مباشر لصورة.']); exit; }
            echo json_encode(['success'=>true,'logo_data'=>$logo_data]);
            break;

        case 'add_hospital':
            $name_ar = trim($_POST['hospital_name_ar'] ?? '');
            $name_en = trim($_POST['hospital_name_en'] ?? '');
            $license = trim($_POST['hospital_license'] ?? '');
            $prefix = in_array(strtoupper(trim($_POST['hospital_prefix'] ?? 'GSL')), ['GSL','PSL']) ? strtoupper(trim($_POST['hospital_prefix'])) : 'GSL';
            $logo_url = trim($_POST['hospital_logo_url'] ?? '');
            if (empty($name_ar)) { echo json_encode(['success'=>false,'message'=>'يرجى إدخال اسم المستشفى بالعربية.']); exit; }
            $logo_data = uploadHospitalLogo($_FILES['hospital_logo'] ?? []);
            if (!$logo_data && !empty($logo_url)) $logo_data = downloadLogoFromUrl($logo_url);
            $stmt = $pdo->prepare("INSERT INTO hospitals (name_ar, name_en, license_number, logo_path, logo_url, logo_data, service_prefix) VALUES (?,?,?,?,?,?,?)");
            $stmt->execute([$name_ar, $name_en, $license ?: null, null, $logo_url ?: null, $logo_data, $prefix]);
            $hospitals = getHospitalsList($pdo);
            echo json_encode(['success'=>true,'message'=>'تمت إضافة المستشفى بنجاح.','hospitals'=>$hospitals,'stats'=>getStats($pdo)]);
            break;

        case 'edit_hospital':
            $id = intval($_POST['hospital_id'] ?? 0);
            $name_ar = trim($_POST['hospital_name_ar'] ?? '');
            $name_en = trim($_POST['hospital_name_en'] ?? '');
            $license = trim($_POST['hospital_license'] ?? '');
            $prefix = in_array(strtoupper(trim($_POST['hospital_prefix'] ?? 'GSL')), ['GSL','PSL']) ? strtoupper(trim($_POST['hospital_prefix'])) : 'GSL';
            $logo_url = trim($_POST['hospital_logo_url'] ?? '');
            $logo_scale = max(0.2, min(3.0, floatval($_POST['logo_scale'] ?? 1.0)));
            $logo_offset_x = max(-500, min(500, floatval($_POST['logo_offset_x'] ?? 0)));
            $logo_offset_y = max(-500, min(500, floatval($_POST['logo_offset_y'] ?? 0)));
            if ($id <= 0 || empty($name_ar)) { echo json_encode(['success'=>false,'message'=>'بيانات غير صالحة.']); exit; }

            $existsStmt = $pdo->prepare("SELECT service_prefix FROM hospitals WHERE id = ? AND deleted_at IS NULL LIMIT 1");
            $existsStmt->execute([$id]);
            $oldPrefix = strtoupper((string)($existsStmt->fetchColumn() ?: ''));
            if ($oldPrefix === '') { echo json_encode(['success'=>false,'message'=>'المستشفى غير موجود أو تم حذفه.']); exit; }

            $logo_data = uploadHospitalLogo($_FILES['hospital_logo'] ?? []);
            if (!$logo_data && !empty($logo_url)) $logo_data = downloadLogoFromUrl($logo_url);

            $pdo->beginTransaction();
            try {
                if ($logo_data) {
                    $stmt = $pdo->prepare("UPDATE hospitals SET name_ar=?, name_en=?, license_number=?, logo_data=?, logo_url=?, service_prefix=?, logo_scale=?, logo_offset_x=?, logo_offset_y=? WHERE id=?");
                    $stmt->execute([$name_ar, $name_en, $license ?: null, $logo_data, $logo_url ?: null, $prefix, $logo_scale, $logo_offset_x, $logo_offset_y, $id]);
                } elseif (!empty($logo_url)) {
                    // عند حفظ رابط جديد ولم نستطع تحويله إلى data-uri نحفظ الرابط كمصدر مباشر
                    // ونمسح logo_data القديم حتى لا يستمر عرض الشعار السابق بدلاً من الرابط الجديد.
                    $stmt = $pdo->prepare("UPDATE hospitals SET name_ar=?, name_en=?, license_number=?, logo_data=NULL, logo_url=?, service_prefix=?, logo_scale=?, logo_offset_x=?, logo_offset_y=? WHERE id=?");
                    $stmt->execute([$name_ar, $name_en, $license ?: null, $logo_url, $prefix, $logo_scale, $logo_offset_x, $logo_offset_y, $id]);
                } else {
                    $stmt = $pdo->prepare("UPDATE hospitals SET name_ar=?, name_en=?, license_number=?, logo_url=NULL, service_prefix=?, logo_scale=?, logo_offset_x=?, logo_offset_y=? WHERE id=?");
                    $stmt->execute([$name_ar, $name_en, $license ?: null, $prefix, $logo_scale, $logo_offset_x, $logo_offset_y, $id]);
                }

                // Update all sick leaves linked to this hospital immediately when hospital details change.
                $cascadeStmt = $pdo->prepare("UPDATE sick_leaves SET hospital_name_ar = ?, hospital_name_en = ? WHERE hospital_id = ?");
                $cascadeStmt->execute([$name_ar, $name_en, $id]);

                if ($oldPrefix !== $prefix) {
                    $codeCascadeStmt = $pdo->prepare("
                        UPDATE sick_leaves
                        SET service_code = CONCAT(?, SUBSTRING(service_code, 4))
                        WHERE hospital_id = ?
                          AND service_code REGEXP '^(GSL|PSL)'
                    ");
                    $codeCascadeStmt->execute([$prefix, $id]);
                }

                $pdo->commit();
            } catch (Throwable $e) {
                if ($pdo->inTransaction()) $pdo->rollBack();
                echo json_encode(['success'=>false,'message'=>'تعذّر تعديل المستشفى: ' . $e->getMessage()]);
                exit;
            }

            $hospitals = getHospitalsList($pdo);
            echo json_encode(['success'=>true,'message'=>'تم تعديل المستشفى بنجاح.','hospitals'=>$hospitals,'stats'=>getStats($pdo)]);
            break;

        case 'delete_hospital':
            $id = intval($_POST['hospital_id'] ?? 0);
            if ($id <= 0) { echo json_encode(['success'=>false,'message'=>'معرّف المستشفى غير صالح.']); exit; }

            $existsStmt = $pdo->prepare("SELECT id FROM hospitals WHERE id = ? AND deleted_at IS NULL LIMIT 1");
            $existsStmt->execute([$id]);
            if (!$existsStmt->fetch()) { echo json_encode(['success'=>false,'message'=>'المستشفى غير موجود أو تم حذفه مسبقاً.']); exit; }

            $deletedPhysically = false;
            $pdo->beginTransaction();
            try {
                // Clear every known hospital_id reference first, so foreign keys cannot block deletion.
                foreach (['doctors', 'sick_leaves'] as $refTable) {
                    if (tableExists($pdo, $refTable)) {
                        $colCheck = $pdo->prepare("SELECT COUNT(*) FROM information_schema.columns WHERE table_schema = DATABASE() AND table_name = ? AND column_name = 'hospital_id'");
                        $colCheck->execute([$refTable]);
                        if ((int)$colCheck->fetchColumn() > 0) {
                            $pdo->prepare("UPDATE {$refTable} SET hospital_id = NULL WHERE hospital_id = ?")->execute([$id]);
                        }
                    }
                }
                $pdo->prepare("DELETE FROM hospitals WHERE id = ?")->execute([$id]);
                $pdo->commit();
                $deletedPhysically = true;
            } catch (Throwable $e) {
                if ($pdo->inTransaction()) $pdo->rollBack();
                // Final guaranteed admin behavior: hide the hospital even if an unknown FK blocks physical deletion.
                try {
                    $softStmt = $pdo->prepare("UPDATE hospitals SET deleted_at = NOW() WHERE id = ?");
                    $softStmt->execute([$id]);
                } catch (Throwable $softDeleteError) {
                    echo json_encode(['success'=>false,'message'=>'تعذّر حذف المستشفى: ' . $softDeleteError->getMessage()]);
                    exit;
                }
            }

            $hospitals = getHospitalsList($pdo);
            echo json_encode(['success'=>true,'message'=>'تم حذف المستشفى بنجاح.','hospitals'=>$hospitals,'stats'=>getStats($pdo)]);
            break;

        case 'fetch_hospitals':
            $hospitals = getHospitalsList($pdo);
            echo json_encode(['success'=>true,'hospitals'=>$hospitals]);
            break;

        case 'get_hospital_logo':
            $hid = intval($_GET['hospital_id'] ?? $_POST['hospital_id'] ?? 0);
            $stmt = $pdo->prepare("SELECT logo_data, logo_url FROM hospitals WHERE id = ?");
            $stmt->execute([$hid]);
            $hRow = $stmt->fetch();
            if ($hRow && !empty($hRow['logo_data']) && strpos($hRow['logo_data'], 'data:image/') === 0) {
                $parts = explode(',', $hRow['logo_data'], 2);
                preg_match('/data:image\/([a-z+]+);/', $parts[0], $mimeMatch);
                $mime = 'image/' . ($mimeMatch[1] ?? 'png');
                header('Content-Type: ' . $mime);
                echo base64_decode($parts[1] ?? '');
            } elseif ($hRow && !empty($hRow['logo_url'])) {
                header('Location: ' . $hRow['logo_url']);
            } else {
                header('HTTP/1.1 404 Not Found');
                echo 'No logo';
            }
            exit;

        case 'get_doctors_by_hospital':
            $hid = intval($_POST['hospital_id'] ?? 0);
            if ($hid > 0) {
                $stmt = $pdo->prepare("SELECT d.*, h.name_ar AS hospital_name_ar FROM doctors d LEFT JOIN hospitals h ON d.hospital_id = h.id WHERE d.hospital_id = ? ORDER BY d.name_ar");
                $stmt->execute([$hid]);
            } else {
                $stmt = $pdo->query("SELECT d.*, h.name_ar AS hospital_name_ar FROM doctors d LEFT JOIN hospitals h ON d.hospital_id = h.id ORDER BY d.name_ar");
            }
            echo json_encode(['success'=>true,'doctors'=>$stmt->fetchAll()]);
            break;

        case 'get_patient_data':
            $pid = intval($_POST['patient_id'] ?? 0);
            $stmt = $pdo->prepare("SELECT * FROM patients WHERE id = ?");
            $stmt->execute([$pid]);
            $patient = $stmt->fetch();
            echo json_encode(['success'=>true,'patient'=>$patient]);
            break;

        case 'assist_parse_ai':
            echo json_encode(['success' => false, 'message' => 'تم تعطيل التحليل السحابي. استخدم التحليل المحلي الذكي من الواجهة.'], JSON_UNESCAPED_UNICODE);
            break;

        case 'add_leave':
            $patient_id = null;
            $doctor_id = null;
            $hospital_id = intval($_POST['hospital_id'] ?? 0) ?: null;

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
                    $stmt = $pdo->prepare("INSERT INTO patients (name, name_ar, identity_number, phone, folder_link) VALUES (?, ?, ?, ?, ?)");
                    $stmt->execute([$pName, $pName, $pIdentity, $pPhone, $pFolderLink]);
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
                $stmt = $pdo->prepare("INSERT INTO doctors (name, name_ar, title, title_ar, note, hospital_id) VALUES (?, ?, ?, ?, ?, ?)");
                $stmt->execute([$dName, $dName, $dTitle, $dTitle, $dNote, $hospital_id]);
                $doctor_id = $pdo->lastInsertId();
            } else {
                $doctor_id = intval($doctor_select);
            }

            $issue_date = $_POST['issue_date'] ?? '';
            $issue_time = trim($_POST['issue_time'] ?? '');
            $issue_period = in_array(strtoupper(trim($_POST['issue_period'] ?? '')), ['AM','PM']) ? strtoupper(trim($_POST['issue_period'])) : null;
            $issue_time = normalizeIssueTimeForStorage($issue_time, $issue_period);

            // توليد رمز الخدمة - الحصول على البادئة من المستشفى
            $service_code_manual = trim($_POST['service_code_manual'] ?? '');
            $service_prefix = $_POST['service_prefix'] ?? 'GSL';
            if ($hospital_id) {
                $hStmt = $pdo->prepare("SELECT service_prefix, name_ar, name_en, logo_path FROM hospitals WHERE id = ?");
                $hStmt->execute([$hospital_id]);
                $hData = $hStmt->fetch();
                if ($hData) {
                    $service_prefix = $hData['service_prefix'] ?: 'GSL';
                }
            }
            if (!empty($service_code_manual)) {
                $service_code = strtoupper($service_code_manual);
            } else {
                $service_code = generateServiceCode($pdo, $service_prefix, $issue_date);
            }

            $start_date = $_POST['start_date'] ?? '';
            $end_date = $_POST['end_date'] ?? '';
            if (!empty($start_date)) {
                $issue_date = $start_date;
                if (empty($service_code_manual)) {
                    $service_code = generateServiceCode($pdo, $service_prefix, $issue_date);
                }
            }
            $days_count = intval($_POST['days_count'] ?? 0);
            $is_companion = isset($_POST['is_companion']) ? 1 : 0;
            $companion_name = trim($_POST['companion_name'] ?? '');
            $companion_relation = trim($_POST['companion_relation'] ?? '');
            $is_paid = isset($_POST['is_paid']) ? 1 : 0;
            $payment_amount = floatval($_POST['payment_amount'] ?? 0);
            $patient_name_en = trim($_POST['patient_name_en'] ?? '');
            $doctor_name_en = trim($_POST['doctor_name_en'] ?? '');
            $doctor_title_en = trim($_POST['doctor_title_en'] ?? '');
            $hospital_name_ar = trim($_POST['hospital_name_ar'] ?? '');
            $hospital_name_en = trim($_POST['hospital_name_en'] ?? '');
            $employer_ar = trim($_POST['employer_ar'] ?? '');
            $employer_en = trim($_POST['employer_en'] ?? '');
            $logo_path = uploadLeaveLogo($_FILES['leave_logo'] ?? []);
            // إذا لم يتم رفع شعار، نأخذه من المستشفى
            if (!$logo_path && $hospital_id && isset($hData) && !empty($hData['logo_path'])) {
                $logo_path = $hData['logo_path'];
            }
            // إذا لم يتم إدخال أسماء المستشفى، نأخذها من المستشفى
            if (empty($hospital_name_ar) && $hospital_id && isset($hData)) {
                $hospital_name_ar = $hData['name_ar'] ?? '';
                $hospital_name_en = $hData['name_en'] ?? '';
            }
            $created_by_user_id = intval($_SESSION['admin_user_id'] ?? 0) ?: null;

            if (empty($issue_date) || empty($start_date) || empty($end_date) || $days_count <= 0 || $patient_id <= 0 || $doctor_id <= 0) {
                echo json_encode(['success' => false, 'message' => 'يرجى تعبئة جميع الحقول المطلوبة.']);
                exit;
            }
            if ($hospital_id && $doctor_select !== 'manual') {
                $doctorHospitalCheck = $pdo->prepare("SELECT hospital_id FROM doctors WHERE id = ? LIMIT 1");
                $doctorHospitalCheck->execute([$doctor_id]);
                if ((string)($doctorHospitalCheck->fetchColumn() ?: '') !== (string)$hospital_id) {
                    echo json_encode(['success' => false, 'message' => 'الطبيب المختار غير مرتبط بالمستشفى المحدد.']);
                    exit;
                }
            }

            $stmt = $pdo->prepare("INSERT INTO sick_leaves 
                (service_code, patient_id, doctor_id, hospital_id, created_by_user_id, issue_date, issue_time, issue_period, start_date, end_date, days_count, 
                 patient_name_en, doctor_name_en, doctor_title_en, hospital_name_ar, hospital_name_en, logo_path, employer_ar, employer_en,
                 is_companion, companion_name, companion_relation, is_paid, payment_amount) 
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)");
            $stmt->execute([
                $service_code, $patient_id, $doctor_id, $hospital_id, $created_by_user_id, $issue_date, $issue_time, $issue_period, $start_date, $end_date, $days_count,
                $patient_name_en, $doctor_name_en, $doctor_title_en, $hospital_name_ar, $hospital_name_en, $logo_path, $employer_ar, $employer_en,
                $is_companion, $companion_name, $companion_relation, $is_paid, $payment_amount
            ]);

            // إضافة إشعار دفع إذا كانت غير مدفوعة
            if (!$is_paid && $payment_amount > 0) {
                $leaveId = $pdo->lastInsertId();
                $stmt = $pdo->prepare("INSERT INTO notifications (type, leave_id, message, created_at) VALUES ('payment', ?, ?, ?)");
                $stmt->execute([$leaveId, "إجازة جديدة غير مدفوعة برمز $service_code بمبلغ $payment_amount", nowSaudi()]);
            }

            $data = fetchActiveOperationalData($pdo);
            $data['doctors'] = $pdo->query("SELECT d.*, h.name_ar AS hospital_name_ar FROM doctors d LEFT JOIN hospitals h ON d.hospital_id = h.id ORDER BY d.name_ar")->fetchAll();
            $data['patients'] = $pdo->query("SELECT * FROM patients ORDER BY name_ar")->fetchAll();
            $data['stats'] = getStats($pdo);
            $data['success'] = true;
            $data['message'] = "تمت إضافة الإجازة بنجاح. رمز الخدمة: $service_code";
            $data['new_service_code'] = $service_code;
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
            $hospital_id_edit = intval($_POST['hospital_id_edit'] ?? 0) ?: null;
            $issue_time = trim($_POST['issue_time_edit'] ?? '');
            $issue_period = in_array(strtoupper(trim($_POST['issue_period_edit'] ?? '')), ['AM','PM']) ? strtoupper(trim($_POST['issue_period_edit'])) : null;
            $issue_time = normalizeIssueTimeForStorage($issue_time, $issue_period);
            
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
                $stmt = $pdo->prepare("INSERT INTO doctors (name, name_ar, title, title_ar, note, hospital_id) VALUES (?, ?, ?, ?, ?, ?)");
                $stmt->execute([$dName, $dName, $dTitle, $dTitle, $dNote, $hospital_id_edit]);
                $doctor_id_edit = intval($pdo->lastInsertId());
            } else {
                $doctor_id_edit = intval($doctor_id_edit_raw ?: 0);
            }

            if (!empty($start_date)) {
                $issue_date = $start_date;
            }
            if ($leave_id <= 0 || empty($service_code) || empty($issue_date) || empty($start_date) || empty($end_date) || $days_count <= 0) {
                echo json_encode(['success' => false, 'message' => 'يرجى تعبئة جميع الحقول المطلوبة.']);
                exit;
            }
            if ($hospital_id_edit && $doctor_id_edit && $doctor_id_edit_raw !== 'manual') {
                $doctorHospitalCheck = $pdo->prepare("SELECT hospital_id FROM doctors WHERE id = ? LIMIT 1");
                $doctorHospitalCheck->execute([$doctor_id_edit]);
                if ((string)($doctorHospitalCheck->fetchColumn() ?: '') !== (string)$hospital_id_edit) {
                    echo json_encode(['success' => false, 'message' => 'الطبيب المختار غير مرتبط بالمستشفى المحدد.']);
                    exit;
                }
            }

            if ($doctor_id_edit && $doctor_id_edit > 0) {
                $stmt = $pdo->prepare("UPDATE sick_leaves SET 
                    service_code = ?, issue_date = ?, start_date = ?, end_date = ?, days_count = ?,
                    is_companion = ?, companion_name = ?, companion_relation = ?,
                    is_paid = ?, payment_amount = ?, doctor_id = ?, hospital_id = COALESCE(?, hospital_id),
                    issue_time = ?, issue_period = ?, updated_at = ?
                    WHERE id = ?");
                $stmt->execute([
                    $service_code, $issue_date, $start_date, $end_date, $days_count,
                    $is_companion, $companion_name, $companion_relation,
                    $is_paid, $payment_amount, $doctor_id_edit, $hospital_id_edit,
                    $issue_time ?: null, $issue_period, nowSaudi(), $leave_id
                ]);
            } else {
                $stmt = $pdo->prepare("UPDATE sick_leaves SET 
                    service_code = ?, issue_date = ?, start_date = ?, end_date = ?, days_count = ?,
                    is_companion = ?, companion_name = ?, companion_relation = ?,
                    is_paid = ?, payment_amount = ?, hospital_id = COALESCE(?, hospital_id),
                    issue_time = ?, issue_period = ?, updated_at = ?
                    WHERE id = ?");
                $stmt->execute([
                    $service_code, $issue_date, $start_date, $end_date, $days_count,
                    $is_companion, $companion_name, $companion_relation,
                    $is_paid, $payment_amount, $hospital_id_edit,
                    $issue_time ?: null, $issue_period, nowSaudi(), $leave_id
                ]);
            }

            $data = fetchActiveOperationalData($pdo);
            $data['doctors'] = $pdo->query("SELECT d.*, h.name_ar AS hospital_name_ar FROM doctors d LEFT JOIN hospitals h ON d.hospital_id = h.id ORDER BY d.name_ar")->fetchAll();
            $data['patients'] = $pdo->query("SELECT * FROM patients ORDER BY name_ar")->fetchAll();
            $data['stats'] = getStats($pdo);
            $data['success'] = true;
            $data['message'] = 'تم تعديل الإجازة بنجاح.';
            echo json_encode($data);
            break;

        case 'duplicate_leave':
            // خاصية تكرار الإجازة
            $patient_id = intval($_POST['dup_patient_id'] ?? 0);
            $hospital_id = intval($_POST['dup_hospital_id'] ?? 0) ?: null;
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
                $stmt = $pdo->prepare("INSERT INTO doctors (name, name_ar, title, title_ar, note, hospital_id) VALUES (?, ?, ?, ?, ?, ?)");
                $stmt->execute([$dName, $dName, $dTitle, $dTitle, $dNote, $hospital_id]);
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
            if (!empty($start_date)) {
                $issue_date = $start_date;
                if (empty($service_code_manual)) {
                    $service_code = generateServiceCode($pdo, $service_prefix, $issue_date);
                }
            }
            $days_count = intval($_POST['dup_days_count'] ?? 0);
            $is_companion = isset($_POST['dup_is_companion']) ? 1 : 0;
            $companion_name = trim($_POST['dup_companion_name'] ?? '');
            $companion_relation = trim($_POST['dup_companion_relation'] ?? '');
            $is_paid = isset($_POST['dup_is_paid']) ? 1 : 0;
            $payment_amount = floatval($_POST['dup_payment_amount'] ?? 0);
            $issue_time = trim($_POST['dup_issue_time'] ?? '');
            $issue_period = in_array(strtoupper(trim($_POST['dup_issue_period'] ?? '')), ['AM','PM']) ? strtoupper(trim($_POST['dup_issue_period'])) : null;
            $issue_time = normalizeIssueTimeForStorage($issue_time, $issue_period);
            
            // Fetch patient data
            $patStmt = $pdo->prepare("SELECT name_en, employer_ar, employer_en FROM patients WHERE id = ?");
            $patStmt->execute([$patient_id]);
            $patData = $patStmt->fetch();
            $patient_name_en = $patData['name_en'] ?? '';
            $employer_ar = $patData['employer_ar'] ?? '';
            $employer_en = $patData['employer_en'] ?? '';
            
            // Fetch doctor data
            $docStmt = $pdo->prepare("SELECT name_en, title_en FROM doctors WHERE id = ?");
            $docStmt->execute([$doctor_id]);
            $docData = $docStmt->fetch();
            $doctor_name_en = $docData['name_en'] ?? '';
            $doctor_title_en = $docData['title_en'] ?? '';
            
            // Fetch hospital data
            $hospital_name_ar = '';
            $hospital_name_en = '';
            $logo_path = '';
            if ($hospital_id) {
                $hStmt = $pdo->prepare("SELECT logo_path, name_ar, name_en FROM hospitals WHERE id = ?");
                $hStmt->execute([$hospital_id]);
                $hData = $hStmt->fetch();
                if ($hData) {
                    $logo_path = $hData['logo_path'] ?? '';
                    $hospital_name_ar = $hData['name_ar'] ?? '';
                    $hospital_name_en = $hData['name_en'] ?? '';
                }
            }
            $created_by_user_id = intval($_SESSION['admin_user_id'] ?? 0) ?: null;

            if (empty($issue_date) || empty($start_date) || empty($end_date) || $days_count <= 0 || $patient_id <= 0 || $doctor_id <= 0) {
                echo json_encode(['success' => false, 'message' => 'يرجى تعبئة جميع الحقول المطلوبة.']);
                exit;
            }
            if ($hospital_id && $doctor_select !== 'manual') {
                $doctorHospitalCheck = $pdo->prepare("SELECT hospital_id FROM doctors WHERE id = ? LIMIT 1");
                $doctorHospitalCheck->execute([$doctor_id]);
                if ((string)($doctorHospitalCheck->fetchColumn() ?: '') !== (string)$hospital_id) {
                    echo json_encode(['success' => false, 'message' => 'الطبيب المختار غير مرتبط بالمستشفى المحدد.']);
                    exit;
                }
            }

            $stmt = $pdo->prepare("INSERT INTO sick_leaves 
                (service_code, patient_id, doctor_id, hospital_id, created_by_user_id, issue_date, issue_time, issue_period, start_date, end_date, days_count, 
                 patient_name_en, doctor_name_en, doctor_title_en, hospital_name_ar, hospital_name_en, logo_path, employer_ar, employer_en,
                 is_companion, companion_name, companion_relation, is_paid, payment_amount) 
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)");
            $stmt->execute([
                $service_code, $patient_id, $doctor_id, $hospital_id, $created_by_user_id, $issue_date, $issue_time, $issue_period, $start_date, $end_date, $days_count,
                $patient_name_en, $doctor_name_en, $doctor_title_en, $hospital_name_ar, $hospital_name_en, $logo_path, $employer_ar, $employer_en,
                $is_companion, $companion_name, $companion_relation, $is_paid, $payment_amount
            ]);

            if (!$is_paid && $payment_amount > 0) {
                $leaveId = $pdo->lastInsertId();
                $stmt = $pdo->prepare("INSERT INTO notifications (type, leave_id, message, created_at) VALUES ('payment', ?, ?, ?)");
                $stmt->execute([$leaveId, "إجازة مكررة غير مدفوعة برمز $service_code بمبلغ $payment_amount", nowSaudi()]);
            }

            $data = fetchActiveOperationalData($pdo);
            $data['doctors'] = $pdo->query("SELECT d.*, h.name_ar AS hospital_name_ar FROM doctors d LEFT JOIN hospitals h ON d.hospital_id = h.id ORDER BY d.name_ar")->fetchAll();
            $data['patients'] = $pdo->query("SELECT * FROM patients ORDER BY name_ar")->fetchAll();
            $data['stats'] = getStats($pdo);
            $data['success'] = true;
            $data['message'] = "تم تكرار الإجازة بنجاح. رمز الخدمة الجديد: $service_code";
            $data['new_service_code'] = $service_code;
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
            $data['doctors'] = $pdo->query("SELECT d.*, h.name_ar AS hospital_name_ar FROM doctors d LEFT JOIN hospitals h ON d.hospital_id = h.id ORDER BY d.name_ar")->fetchAll();
            $data['patients'] = $pdo->query("SELECT * FROM patients ORDER BY name_ar")->fetchAll();
            $data['stats'] = getStats($pdo);
            $data['success'] = true;
            $data['message'] = 'تم تأكيد الدفع بنجاح.';
            echo json_encode($data);
            break;

        case 'add_doctor':
            $name = trim($_POST['doctor_name'] ?? '');
            $title = trim($_POST['doctor_title'] ?? '');
            $note = trim($_POST['doctor_note'] ?? '');
            $name_ar = trim($_POST['doctor_name_ar'] ?? '') ?: $name;
            $name_en = trim($_POST['doctor_name_en'] ?? '');
            $title_ar = trim($_POST['doctor_title_ar'] ?? '') ?: $title;
            $title_en = trim($_POST['doctor_title_en'] ?? '');
            $doc_hospital_id = intval($_POST['doctor_hospital_id'] ?? 0) ?: null;
            if (empty($name_ar)) $name_ar = $name;
            if (empty($title_ar)) $title_ar = $title;
            if (empty($name) && !empty($name_ar)) $name = $name_ar;
            if (empty($title) && !empty($title_ar)) $title = $title_ar;
            if (empty($name) || empty($title)) {
                echo json_encode(['success' => false, 'message' => 'يرجى إدخال اسم الطبيب ومسمّاه.']);
                exit;
            }
            $stmt = $pdo->prepare("INSERT INTO doctors (name, title, note, name_ar, name_en, title_ar, title_en, hospital_id) VALUES (?, ?, ?, ?, ?, ?, ?, ?)");
            $stmt->execute([$name, $title, $note, $name_ar, $name_en, $title_ar, $title_en, $doc_hospital_id]);
            $doctorId = $pdo->lastInsertId();
            $doctor = $pdo->prepare("SELECT * FROM doctors WHERE id = ?");
            $doctor->execute([$doctorId]);
            $doctorData = $doctor->fetch();
            $doctors = $pdo->query("SELECT d.*, h.name_ar AS hospital_name_ar FROM doctors d LEFT JOIN hospitals h ON d.hospital_id = h.id ORDER BY d.name_ar")->fetchAll();
            echo json_encode([
                'success' => true,
                'message' => 'تمت إضافة الطبيب بنجاح.',
                'doctor' => $doctorData,
                'doctors' => $doctors,
                'stats' => getStats($pdo)
            ]);
            break;

       case 'add_doctors_batch':
            $batchText = trim($_POST['doctors_batch_text'] ?? '');
            $batchHospitalId = intval($_POST['batch_hospital_id'] ?? 0) ?: null;
            
            $lines = array_filter(array_map('trim', explode("\n", $batchText)));
            if (empty($lines)) {
                echo json_encode([
                    'success' => false,
                    'message' => 'لم يتم التعرّف على أي طبيب. يرجى كتابة البيانات بشكل صحيح.'
                ]);
                exit;
            }

            $checkStmt = $pdo->prepare("SELECT id FROM doctors WHERE (name_ar = ? OR name = ?) AND (title_ar = ? OR title = ?) LIMIT 1");
            $insertStmt = $pdo->prepare("INSERT INTO doctors (name, name_ar, name_en, title, title_ar, title_en, hospital_id) VALUES (?, ?, ?, ?, ?, ?, ?)");

            $inserted = 0;
            $updated = 0;
            $duplicates = 0;
            $errors = [];

            foreach ($lines as $index => $line) {
                $parts = array_map('trim', explode('|', $line));
                $nameAr = ''; $nameEn = ''; $titleAr = ''; $titleEn = '';

                // الفرز الذكي حسب عدد المعطيات المدخلة
                if (count($parts) === 2) {
                    $nameAr = $parts[0];
                    $titleAr = $parts[1];
                } elseif (count($parts) === 3) {
                    $nameAr = $parts[0];
                    $nameEn = $parts[1];
                    $titleAr = $parts[2];
                } elseif (count($parts) >= 4) {
                    $nameAr = $parts[0];
                    $nameEn = $parts[1];
                    $titleAr = $parts[2];
                    $titleEn = $parts[3];
                } else {
                    $nameAr = $parts[0] ?? '';
                }
                
                if ($nameAr === '' || $titleAr === '') {
                    $errors[] = "السطر " . ($index + 1) . " ناقص البيانات الأساسية (الاسم والمسمى).";
                    continue;
                }

                $checkStmt->execute([$nameAr, $nameAr, $titleAr, $titleAr]);
                if ($checkStmt->fetch()) {
                    $duplicates++;
                    continue;
                }

                $insertStmt->execute([$nameAr, $nameAr, $nameEn, $titleAr, $titleAr, $titleEn, $batchHospitalId]);
                $inserted++;
            }

            $doctors = $pdo->query("SELECT d.*, h.name_ar AS hospital_name_ar FROM doctors d LEFT JOIN hospitals h ON d.hospital_id = h.id ORDER BY d.name_ar")->fetchAll();
            $summaryMessage = "تمت معالجة الدفعة بنجاح: أضيف {$inserted}، مكرّر {$duplicates}.";
            if (!empty($errors)) {
                $summaryMessage .= " أخطاء: " . implode(' | ', array_slice($errors, 0, 3));
            }

            echo json_encode([
                'success' => true,
                'message' => $summaryMessage,
                'inserted' => $inserted,
                'updated' => $updated,
                'duplicates' => $duplicates,
                'errors' => $errors,
                'doctors' => $doctors,
                'stats' => getStats($pdo)
            ]);
            break;

        case 'edit_doctor':
            $id = intval($_POST['doctor_id'] ?? 0);
            $name = trim($_POST['doctor_name'] ?? '');
            $title = trim($_POST['doctor_title'] ?? '');
            $note = trim($_POST['doctor_note'] ?? '');
            $name_ar = trim($_POST['doctor_name_ar'] ?? '') ?: $name;
            $name_en = trim($_POST['doctor_name_en'] ?? '');
            $title_ar = trim($_POST['doctor_title_ar'] ?? '') ?: $title;
            $title_en = trim($_POST['doctor_title_en'] ?? '');
            $doc_hospital_id = intval($_POST['doctor_hospital_id'] ?? 0) ?: null;
            if (empty($name) && !empty($name_ar)) $name = $name_ar;
            if (empty($title) && !empty($title_ar)) $title = $title_ar;
            if ($id <= 0 || empty($name) || empty($title)) {
                echo json_encode(['success' => false, 'message' => 'بيانات غير صالحة.']);
                exit;
            }
            $stmt = $pdo->prepare("UPDATE doctors SET name = ?, title = ?, note = ?, name_ar = ?, name_en = ?, title_ar = ?, title_en = ?, hospital_id = ? WHERE id = ?");
            $stmt->execute([$name, $title, $note, $name_ar, $name_en, $title_ar, $title_en, $doc_hospital_id, $id]);
            // Cascade update to leaves
            $cascadeStmt = $pdo->prepare("UPDATE sick_leaves SET doctor_name_en = ?, doctor_title_en = ? WHERE doctor_id = ?");
            $cascadeStmt->execute([$name_en, $title_en, $id]);
            $doctor = $pdo->prepare("SELECT * FROM doctors WHERE id = ?");
            $doctor->execute([$id]);
            $doctorData = $doctor->fetch();
            $doctors = $pdo->query("SELECT d.*, h.name_ar AS hospital_name_ar FROM doctors d LEFT JOIN hospitals h ON d.hospital_id = h.id ORDER BY d.name_ar")->fetchAll();
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
            $doctors = $pdo->query("SELECT d.*, h.name_ar AS hospital_name_ar FROM doctors d LEFT JOIN hospitals h ON d.hospital_id = h.id ORDER BY d.name_ar")->fetchAll();
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
            $name_ar = trim($_POST['patient_name_ar'] ?? '') ?: $name;
            $name_en = trim($_POST['patient_name_en'] ?? '');
            $employer_ar = trim($_POST['patient_employer_ar'] ?? '');
            $employer_en = trim($_POST['patient_employer_en'] ?? '');
            $nationality_ar = trim($_POST['patient_nationality_ar'] ?? '');
            $nationality_en = trim($_POST['patient_nationality_en'] ?? '');
            if (empty($name) && !empty($name_ar)) $name = $name_ar;
            if (empty($name) || empty($identity)) {
                echo json_encode(['success' => false, 'message' => 'يرجى إدخال اسم المريض ورقم هويته.']);
                exit;
            }
            $existingStmt = $pdo->prepare("SELECT id FROM patients WHERE identity_number = ? LIMIT 1");
            $existingStmt->execute([$identity]);
            $existingPatientId = intval($existingStmt->fetchColumn() ?: 0);
            if ($existingPatientId > 0) {
                $stmt = $pdo->prepare("UPDATE patients SET name = ?, phone = ?, folder_link = ?, name_ar = ?, name_en = ?, employer_ar = ?, employer_en = ?, nationality_ar = ?, nationality_en = ? WHERE id = ?");
                $stmt->execute([$name, $phone, $folder_link, $name_ar, $name_en, $employer_ar, $employer_en, $nationality_ar, $nationality_en, $existingPatientId]);
                $patientId = $existingPatientId;
                $message = 'المريض موجود مسبقاً؛ تم تحديث بياناته واختياره.';
            } else {
                $stmt = $pdo->prepare("INSERT INTO patients (name, identity_number, phone, folder_link, name_ar, name_en, employer_ar, employer_en, nationality_ar, nationality_en) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)");
                $stmt->execute([$name, $identity, $phone, $folder_link, $name_ar, $name_en, $employer_ar, $employer_en, $nationality_ar, $nationality_en]);
                $patientId = $pdo->lastInsertId();
                $message = 'تمت إضافة المريض بنجاح.';
            }
            $patient = $pdo->prepare("SELECT * FROM patients WHERE id = ?");
            $patient->execute([$patientId]);
            $patientData = $patient->fetch();
            $patients = $pdo->query("SELECT * FROM patients ORDER BY name_ar")->fetchAll();
            echo json_encode([
                'success' => true,
                'message' => $message,
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
            $name_ar = trim($_POST['patient_name_ar'] ?? '') ?: $name;
            $name_en = trim($_POST['patient_name_en'] ?? '');
            $employer_ar = trim($_POST['patient_employer_ar'] ?? '');
            $employer_en = trim($_POST['patient_employer_en'] ?? '');
            $nationality_ar = trim($_POST['patient_nationality_ar'] ?? '');
            $nationality_en = trim($_POST['patient_nationality_en'] ?? '');
            if (empty($name) && !empty($name_ar)) $name = $name_ar;
            if ($id <= 0 || empty($name) || empty($identity)) {
                echo json_encode(['success' => false, 'message' => 'بيانات غير صالحة.']);
                exit;
            }
            $duplicateStmt = $pdo->prepare("SELECT id FROM patients WHERE identity_number = ? AND id <> ? LIMIT 1");
            $duplicateStmt->execute([$identity, $id]);
            if ($duplicateStmt->fetchColumn()) {
                echo json_encode(['success' => false, 'message' => 'رقم الهوية مستخدم لمريض آخر.']);
                exit;
            }
            $stmt = $pdo->prepare("UPDATE patients SET name = ?, identity_number = ?, phone = ?, folder_link = ?, name_ar = ?, name_en = ?, employer_ar = ?, employer_en = ?, nationality_ar = ?, nationality_en = ? WHERE id = ?");
            $stmt->execute([$name, $identity, $phone, $folder_link, $name_ar, $name_en, $employer_ar, $employer_en, $nationality_ar, $nationality_en, $id]);
            // Cascade update to leaves
            $cascadeStmt = $pdo->prepare("UPDATE sick_leaves SET patient_name_en = ?, employer_ar = ?, employer_en = ? WHERE patient_id = ?");
            $cascadeStmt->execute([$name_en, $employer_ar, $employer_en, $id]);
            $patient = $pdo->prepare("SELECT * FROM patients WHERE id = ?");
            $patient->execute([$id]);
            $patientData = $patient->fetch();
            $patients = $pdo->query("SELECT * FROM patients ORDER BY name_ar")->fetchAll();
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
            $patients = $pdo->query("SELECT * FROM patients ORDER BY name_ar")->fetchAll();
            echo json_encode([
                'success' => true,
                'message' => 'تم حذف المريض بنجاح.',
                'patients' => $patients,
                'stats' => getStats($pdo)
            ]);
            break;

        case 'add_patients_batch':
            $batchText = trim($_POST['patients_batch_text'] ?? '');
            $lines = array_filter(array_map('trim', explode("\n", $batchText)));
            if (empty($lines)) {
                echo json_encode(['success' => false, 'message' => 'لم يتم التعرّف على أي مريض. استخدم صيغة: اسم عربي | اسم إنجليزي | رقم الهوية | الهاتف | جهة العمل (عربي) | جهة العمل (إنجليزي) | الجنسية (عربي) | الجنسية (إنجليزي)']);
                exit;
            }
            $checkPatStmt = $pdo->prepare("SELECT id FROM patients WHERE identity_number = ? LIMIT 1");
            $insertPatStmt = $pdo->prepare("INSERT INTO patients (name, name_ar, name_en, identity_number, phone, employer_ar, employer_en, nationality_ar, nationality_en) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)");
            $updatePatStmt = $pdo->prepare("UPDATE patients SET name=?, name_ar=?, name_en=?, phone=?, employer_ar=?, employer_en=?, nationality_ar=?, nationality_en=? WHERE identity_number=?");
            $insertedPat = 0; $updatedPat = 0; $errorsPat = [];
            foreach ($lines as $index => $line) {
                $parts = array_map('trim', explode('|', $line));
                $nameAr = $parts[0] ?? '';
                $nameEn = $parts[1] ?? '';
                $identity = $parts[2] ?? '';
                $phone = $parts[3] ?? '';
                $employerAr = $parts[4] ?? '';
                $employerEn = $parts[5] ?? '';
                $nationalityAr = $parts[6] ?? '';
                $nationalityEn = $parts[7] ?? '';
                if ($nameAr === '' || $identity === '') {
                    $errorsPat[] = "السطر " . ($index + 1) . " ناقص البيانات الأساسية (الاسم ورقم الهوية مطلوبان).";
                    continue;
                }
                $checkPatStmt->execute([$identity]);
                $existingId = $checkPatStmt->fetchColumn();
                if ($existingId) {
                    $updatePatStmt->execute([$nameAr, $nameAr, $nameEn, $phone, $employerAr, $employerEn, $nationalityAr, $nationalityEn, $identity]);
                    $updatedPat++;
                } else {
                    $insertPatStmt->execute([$nameAr, $nameAr, $nameEn, $identity, $phone, $employerAr, $employerEn, $nationalityAr, $nationalityEn]);
                    $insertedPat++;
                }
            }
            $patients = $pdo->query("SELECT * FROM patients ORDER BY name_ar")->fetchAll();
            $summaryPat = "تمت معالجة الدفعة: أضيف {$insertedPat}، تم تحديث {$updatedPat}.";
            if (!empty($errorsPat)) $summaryPat .= " أخطاء: " . implode(' | ', array_slice($errorsPat, 0, 3));
            echo json_encode(['success' => true, 'message' => $summaryPat, 'inserted' => $insertedPat, 'updated' => $updatedPat, 'errors' => $errorsPat, 'patients' => $patients, 'stats' => getStats($pdo)]);
            break;

        case 'add_hospitals_batch':
            $batchText = trim($_POST['hospitals_batch_text'] ?? '');
            $lines = array_filter(array_map('trim', explode("\n", $batchText)));
            if (empty($lines)) {
                echo json_encode(['success' => false, 'message' => 'لم يتم التعرّف على أي مستشفى. استخدم صيغة: اسم عربي | اسم إنجليزي | رقم الترخيص | البادئة (GSL/PSL)']);
                exit;
            }
            $checkHospStmt = $pdo->prepare("SELECT id FROM hospitals WHERE name_ar = ? AND deleted_at IS NULL LIMIT 1");
            $insertHospStmt = $pdo->prepare("INSERT INTO hospitals (name_ar, name_en, license_number, service_prefix) VALUES (?, ?, ?, ?)");
            $insertedHosp = 0; $duplicatesHosp = 0; $errorsHosp = [];
            foreach ($lines as $index => $line) {
                $parts = array_map('trim', explode('|', $line));
                $nameAr = $parts[0] ?? '';
                $nameEn = $parts[1] ?? '';
                $license = $parts[2] ?? '';
                $prefix = strtoupper($parts[3] ?? 'GSL');
                if (!in_array($prefix, ['GSL', 'PSL'])) $prefix = 'GSL';
                if ($nameAr === '') {
                    $errorsHosp[] = "السطر " . ($index + 1) . " ناقص الاسم العربي.";
                    continue;
                }
                $checkHospStmt->execute([$nameAr]);
                if ($checkHospStmt->fetchColumn()) {
                    $duplicatesHosp++;
                    continue;
                }
                $insertHospStmt->execute([$nameAr, $nameEn, $license ?: null, $prefix]);
                $insertedHosp++;
            }
            $hospitals = getHospitalsList($pdo);
            $summaryHosp = "تمت معالجة الدفعة: أضيف {$insertedHosp}، مكرّر {$duplicatesHosp}.";
            if (!empty($errorsHosp)) $summaryHosp .= " أخطاء: " . implode(' | ', array_slice($errorsHosp, 0, 3));
            echo json_encode(['success' => true, 'message' => $summaryHosp, 'inserted' => $insertedHosp, 'duplicates' => $duplicatesHosp, 'errors' => $errorsHosp, 'hospitals' => $hospitals, 'stats' => getStats($pdo)]);
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
                SELECT sl.*, COALESCE(p.name_ar, p.name, '') AS patient_name, p.identity_number, p.folder_link AS patient_folder_link,
                       COALESCE(d.name_ar, d.name, '') AS doctor_name, COALESCE(d.title_ar, d.title, '') AS doctor_title, d.note AS doctor_note,
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
            $filterUserId = max(0, intval($_POST['filter_user_id'] ?? 0));
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
                'daily' => [],
                'users_filter' => [],
                'users_productivity' => [],
                'duplicates' => [],
                'filter_user_id' => $filterUserId
            ];

            $summary['users_filter'] = $pdo->query("SELECT id, display_name, username FROM admin_users WHERE is_active = 1 ORDER BY display_name")->fetchAll();

            $rangeFilter = "sl.deleted_at IS NULL AND DATE(sl.created_at) BETWEEN ? AND ? AND (? = 0 OR sl.created_by_user_id = ?)";
            $rangeParams = [$fromDate, $toDate, $filterUserId, $filterUserId];

            $summary['today_total'] = (int)$pdo->query("SELECT COUNT(*) FROM sick_leaves WHERE deleted_at IS NULL AND DATE(created_at) = CURDATE()")->fetchColumn();
            $summary['today_paid'] = (int)$pdo->query("SELECT COUNT(*) FROM sick_leaves WHERE deleted_at IS NULL AND is_paid = 1 AND DATE(created_at) = CURDATE()")->fetchColumn();
            $summary['today_unpaid'] = (int)$pdo->query("SELECT COUNT(*) FROM sick_leaves WHERE deleted_at IS NULL AND is_paid = 0 AND DATE(created_at) = CURDATE()")->fetchColumn();

            $avgStmt = $pdo->prepare("SELECT COALESCE(AVG(day_count),0) FROM (SELECT DATE(sl.created_at) d, COUNT(*) day_count FROM sick_leaves sl WHERE $rangeFilter GROUP BY DATE(sl.created_at)) t");
            $avgStmt->execute($rangeParams);
            $summary['avg_daily'] = (float)$avgStmt->fetchColumn();

            $consistencyStmt = $pdo->prepare("SELECT (COUNT(DISTINCT DATE(sl.created_at)) * 100.0 / GREATEST(DATEDIFF(?, ?) + 1, 1)) FROM sick_leaves sl WHERE $rangeFilter");
            $consistencyStmt->execute(array_merge([$toDate, $fromDate], $rangeParams));
            $summary['consistency_rate'] = round((float)$consistencyStmt->fetchColumn(), 2);

            $topDoctorsStmt = $pdo->prepare("SELECT d.name_ar AS name, d.title_ar AS title, COUNT(*) leaves_count FROM sick_leaves sl LEFT JOIN doctors d ON d.id = sl.doctor_id WHERE $rangeFilter GROUP BY sl.doctor_id ORDER BY leaves_count DESC LIMIT 5");
            $topDoctorsStmt->execute($rangeParams);
            $summary['top_doctors'] = $topDoctorsStmt->fetchAll();

            $topPatientsStmt = $pdo->prepare("SELECT p.name_ar AS name, p.identity_number, COUNT(*) leaves_count, SUM(CASE WHEN sl.is_paid = 1 THEN sl.payment_amount ELSE 0 END) paid_amount, SUM(CASE WHEN sl.is_paid = 0 THEN sl.payment_amount ELSE 0 END) unpaid_amount FROM sick_leaves sl LEFT JOIN patients p ON p.id = sl.patient_id WHERE $rangeFilter GROUP BY sl.patient_id ORDER BY leaves_count DESC LIMIT 5");
            $topPatientsStmt->execute($rangeParams);
            $summary['top_patients'] = $topPatientsStmt->fetchAll();

            $dailyStmt = $pdo->prepare("SELECT DATE(sl.created_at) day_date, COUNT(*) total_count, SUM(CASE WHEN sl.is_paid = 1 THEN 1 ELSE 0 END) paid_count, SUM(CASE WHEN sl.is_paid = 0 THEN 1 ELSE 0 END) unpaid_count FROM sick_leaves sl WHERE $rangeFilter GROUP BY DATE(sl.created_at) ORDER BY day_date DESC");
            $dailyStmt->execute($rangeParams);
            $summary['daily'] = $dailyStmt->fetchAll();

            $usersProductivityStmt = $pdo->prepare("
                SELECT COALESCE(u.display_name, 'غير محدد') AS user_name, COALESCE(u.username, '-') AS username,
                       COUNT(sl.id) AS leaves_count,
                       SUM(CASE WHEN dup.dup_count > 1 THEN 1 ELSE 0 END) AS duplicate_count
                FROM sick_leaves sl
                LEFT JOIN admin_users u ON u.id = sl.created_by_user_id
                LEFT JOIN (
                    SELECT patient_id, start_date, end_date, COUNT(*) AS dup_count
                    FROM sick_leaves
                    WHERE deleted_at IS NULL
                    GROUP BY patient_id, start_date, end_date
                ) dup ON dup.patient_id = sl.patient_id AND dup.start_date = sl.start_date AND dup.end_date = sl.end_date
                WHERE $rangeFilter
                GROUP BY sl.created_by_user_id, u.display_name, u.username
                ORDER BY leaves_count DESC
            ");
            $usersProductivityStmt->execute($rangeParams);
            $summary['users_productivity'] = $usersProductivityStmt->fetchAll();

            $duplicatesStmt = $pdo->prepare("
                SELECT COALESCE(p.name_ar, p.name, '') AS patient_name, p.identity_number, sl.start_date, sl.end_date,
                       COUNT(*) AS repeated_count,
                       GROUP_CONCAT(DISTINCT COALESCE(u.display_name, 'غير محدد') SEPARATOR '، ') AS creators
                FROM sick_leaves sl
                LEFT JOIN patients p ON p.id = sl.patient_id
                LEFT JOIN admin_users u ON u.id = sl.created_by_user_id
                WHERE $rangeFilter
                GROUP BY sl.patient_id, sl.start_date, sl.end_date, p.name_ar, p.identity_number
                HAVING COUNT(*) > 1
                ORDER BY repeated_count DESC, sl.start_date DESC
                LIMIT 50
            ");
            $duplicatesStmt->execute($rangeParams);
            $summary['duplicates'] = $duplicatesStmt->fetchAll();

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
                SELECT n.*, COALESCE(sl.payment_amount, ap.amount, 0) AS payment_amount,
                       COALESCE(sl.service_code, CONCAT('ACC-', ap.id), '-') AS service_code,
                       sl.patient_id,
                       COALESCE(p.name_ar, p.name, au.display_name, au.username, '') AS patient_name,
                       p.phone AS patient_phone,
                       ap.user_id AS account_user_id,
                       ap.days_count AS account_days_count,
                       ap.is_paid AS account_is_paid
                FROM notifications n
                LEFT JOIN sick_leaves sl ON n.leave_id = sl.id
                LEFT JOIN patients p ON sl.patient_id = p.id
                LEFT JOIN account_payments ap ON n.account_payment_id = ap.id
                LEFT JOIN admin_users au ON ap.user_id = au.id
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

        case 'mark_user_notifications_read':
            $uid = intval($_SESSION['admin_user_id'] ?? 0);
            $pdo->prepare("UPDATE user_notifications SET is_read = 1 WHERE user_id = ?")->execute([$uid]);
            echo json_encode(['success' => true]);
            break;

        case 'fetch_leaves_by_patient':
            $patient_id = intval($_POST['patient_id'] ?? 0);
            $stmt = $pdo->prepare("
                SELECT sl.*, COALESCE(d.name_ar, d.name, '') AS doctor_name, COALESCE(d.title_ar, d.title, '') AS doctor_title
                FROM sick_leaves sl
                LEFT JOIN doctors d ON sl.doctor_id = d.id
                WHERE sl.patient_id = ? AND sl.deleted_at IS NULL
                ORDER BY sl.created_at DESC
            ");
            $stmt->execute([$patient_id]);
            echo json_encode(['success' => true, 'leaves' => $stmt->fetchAll()]);
            break;

        case 'fetch_doctors':
            $doctors = $pdo->query("SELECT d.*, h.name_ar AS hospital_name_ar FROM doctors d LEFT JOIN hospitals h ON d.hospital_id = h.id ORDER BY d.name_ar")->fetchAll();
            echo json_encode(['success' => true, 'doctors' => $doctors, 'stats' => getStats($pdo)]);
            break;

        case 'fetch_patients':
            $patients = $pdo->query("SELECT * FROM patients ORDER BY name_ar")->fetchAll();
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
                $audioExts = ['mp3','wav','ogg','m4a','aac','webm'];
                $isAudioByExt = in_array($ext, $audioExts, true);
                $messageType = (str_starts_with($mimeType, 'image/')) ? 'image' : ((str_starts_with($mimeType, 'audio/') || $isAudioByExt) ? 'voice' : 'file');
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
            $allowedViewModes = ['table','compact','cards','zebra','glass','minimal'];
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
            
            $users = $pdo->query("SELECT u.* FROM admin_users u ORDER BY u.created_at DESC")->fetchAll();
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
            // إذا تم التعطيل: أبطل جلسات المستخدم
            if (!$is_active && $user_id != intval($_SESSION['admin_user_id'])) {
                $pdo->prepare("UPDATE user_sessions SET logout_at = NOW() WHERE user_id = ? AND logout_at IS NULL")->execute([$user_id]);
                $sessionSavePath = session_save_path() ?: sys_get_temp_dir();
                if (is_dir($sessionSavePath)) {
                    foreach (glob($sessionSavePath . '/sess_*') as $sessFile) {
                        $sessContent = @file_get_contents($sessFile);
                        if ($sessContent !== false) {
                            if (strpos($sessContent, 'patient_user_id|i:' . $user_id . ';') !== false
                                || strpos($sessContent, 'admin_user_id|i:' . $user_id . ';') !== false) {
                                @unlink($sessFile);
                            }
                        }
                    }
                }
            }
            $users = $pdo->query("SELECT u.* FROM admin_users u ORDER BY u.created_at DESC")->fetchAll();
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
            $users = $pdo->query("SELECT u.* FROM admin_users u ORDER BY u.created_at DESC")->fetchAll();
            echo json_encode(['success' => true, 'message' => 'تم حذف المستخدم بنجاح.', 'users' => $users]);
            break;

        case 'fetch_users':
            if ($_SESSION['admin_role'] !== 'admin') {
                echo json_encode(['success' => false, 'message' => 'ليس لديك صلاحية.']);
                exit;
            }
            $users = $pdo->query("SELECT u.* FROM admin_users u ORDER BY u.created_at DESC")->fetchAll();
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

        case 'mark_hospital_leaves_paid':
            $hospital_id = intval($_POST['hospital_id'] ?? 0);
            $amount = floatval($_POST['amount'] ?? 0);
            if ($hospital_id <= 0) {
                echo json_encode(['success' => false, 'message' => 'يرجى اختيار مستشفى.']);
                exit;
            }
            if ($amount > 0) {
                $stmt = $pdo->prepare("UPDATE sick_leaves SET is_paid = 1, payment_amount = ? WHERE hospital_id = ? AND is_paid = 0 AND deleted_at IS NULL");
                $stmt->execute([$amount, $hospital_id]);
            } else {
                $stmt = $pdo->prepare("UPDATE sick_leaves SET is_paid = 1 WHERE hospital_id = ? AND is_paid = 0 AND deleted_at IS NULL");
                $stmt->execute([$hospital_id]);
            }
            $pdo->prepare("DELETE FROM notifications WHERE type = 'payment' AND leave_id IN (SELECT id FROM sick_leaves WHERE hospital_id = ? AND is_paid = 1)")->execute([$hospital_id]);
            $data = fetchAllData($pdo);
            $data['stats'] = getStats($pdo);
            $data['success'] = true;
            $data['message'] = 'تم تأكيد دفع جميع إجازات المستشفى المحدد.';
            echo json_encode($data);
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

        case 'generate_pdf':
            $leave_id = intval($_POST['leave_id'] ?? 0);
            $pdfMode = $_POST['pdf_mode'] ?? 'preview';
            handleGeneratePdf($pdo, $leave_id, $pdfMode);
            exit;

        // ======================== إدارة حسابات المرضى (بوابة المرضى) ========================
        case 'save_patient_account':
            if ($_SESSION['admin_role'] !== 'admin') {
                echo json_encode(['success' => false, 'message' => 'ليس لديك صلاحية.']);
                exit;
            }
            $target_user_id = intval($_POST['target_user_id'] ?? 0);
            $patient_id = intval($_POST['patient_id'] ?? 0);
            $allowed_days = max(0, intval($_POST['allowed_days'] ?? 0));

            if ($target_user_id <= 0) {
                echo json_encode(['success' => false, 'message' => 'معرّف المستخدم غير صالح.']);
                exit;
            }

            // إنشاء جدول patient_accounts إن لم يكن موجوداً
            $pdo->exec("CREATE TABLE IF NOT EXISTS patient_accounts (
                id INT AUTO_INCREMENT PRIMARY KEY,
                user_id INT NOT NULL UNIQUE,
                patient_id INT NOT NULL,
                allowed_days INT DEFAULT 0,
                expiry_date DATE NULL,
                notes TEXT NULL,
                FOREIGN KEY (user_id) REFERENCES admin_users(id) ON DELETE CASCADE,
                FOREIGN KEY (patient_id) REFERENCES patients(id) ON DELETE CASCADE
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci");

            if ($patient_id > 0) {
                $stmt = $pdo->prepare("INSERT INTO patient_accounts (user_id, patient_id, allowed_days) VALUES (?, ?, ?) ON DUPLICATE KEY UPDATE patient_id = VALUES(patient_id), allowed_days = VALUES(allowed_days)");
                $stmt->execute([$target_user_id, $patient_id, $allowed_days]);
                $msg = 'تم ربط المستخدم بالمريض وتحديد الحصة بنجاح.';
            } else {
                // إزالة الربط
                $pdo->prepare("DELETE FROM patient_accounts WHERE user_id = ?")->execute([$target_user_id]);
                $msg = 'تم إزالة ربط المريض من هذا المستخدم.';
            }

            $users = $pdo->query("SELECT u.* FROM admin_users u ORDER BY u.created_at DESC")->fetchAll();
            echo json_encode(['success' => true, 'message' => $msg, 'users' => $users]);
            break;

        case 'get_patient_account':
            if ($_SESSION['admin_role'] !== 'admin') {
                echo json_encode(['success' => false, 'message' => 'ليس لديك صلاحية.']);
                exit;
            }
            $target_user_id = intval($_GET['user_id'] ?? 0);
            $stmt = $pdo->prepare("SELECT pa.*, p.name_ar AS patient_name FROM patient_accounts pa LEFT JOIN patients p ON pa.patient_id = p.id WHERE pa.user_id = ?");
            $stmt->execute([$target_user_id]);
            $pa = $stmt->fetch();
            $patients_list = $pdo->query("SELECT id, name_ar, identity_number FROM patients ORDER BY name_ar")->fetchAll();
            echo json_encode(['success' => true, 'account' => $pa ?: null, 'patients' => $patients_list]);
            break;

        // ======================== إدارة الحسابات المتقدمة ========================
        case 'fetch_accounts_full':
            if ($_SESSION['admin_role'] !== 'admin') { echo json_encode(['success'=>false,'message'=>'ليس لديك صلاحية.']); exit; }
            // Ensure account_payments table exists
            $pdo->exec("CREATE TABLE IF NOT EXISTS account_payments (
                id INT AUTO_INCREMENT PRIMARY KEY,
                user_id INT NOT NULL,
                amount DECIMAL(10,2) NOT NULL DEFAULT 0,
                note VARCHAR(500) NULL,
                paid_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                created_by INT NULL,
                FOREIGN KEY (user_id) REFERENCES admin_users(id) ON DELETE CASCADE
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci");
            ensureColumn($pdo, 'patient_accounts', 'expiry_date', "DATE NULL AFTER allowed_days");
            ensureColumn($pdo, 'patient_accounts', 'notes', "TEXT NULL AFTER expiry_date");
            // جلب حسابات المرضى فقط (المرتبطة بـ patient_accounts) - منفصلة عن مستخدمي لوحة التحكم
            $accounts = $pdo->query("
                SELECT u.id, u.username, u.display_name, u.role, u.is_active, u.created_at,
                       pa.patient_id AS linked_patient_id, pa.allowed_days AS patient_allowed_days,
                       pa.expiry_date, pa.notes AS account_notes,
                       p.name_ar AS linked_patient_name, p.identity_number AS patient_identity,
                       COALESCE((SELECT SUM(amount) FROM account_payments WHERE user_id = u.id AND is_paid = 1), 0) AS total_paid,
                       COALESCE((SELECT COUNT(*) FROM account_payments WHERE user_id = u.id), 0) AS payment_count,
                       COALESCE((SELECT COUNT(*) FROM sick_leaves sl WHERE sl.patient_id = pa.patient_id AND sl.deleted_at IS NULL AND sl.created_by_user_id = u.id), 0) AS portal_leave_count,
                       COALESCE((SELECT SUM(sl.days_count) FROM sick_leaves sl WHERE sl.patient_id = pa.patient_id AND sl.deleted_at IS NULL AND sl.created_by_user_id = u.id), 0) AS portal_used_days,
                       GREATEST(pa.allowed_days - COALESCE((SELECT SUM(sl.days_count) FROM sick_leaves sl WHERE sl.patient_id = pa.patient_id AND sl.deleted_at IS NULL AND sl.created_by_user_id = u.id), 0), 0) AS portal_remaining_days,
                       COALESCE((SELECT SUM(CASE WHEN ap.is_paid = 1 THEN 1 ELSE 0 END) FROM account_payments ap WHERE ap.user_id = u.id), 0) AS account_paid_count,
                       COALESCE((SELECT SUM(CASE WHEN ap.is_paid = 0 THEN 1 ELSE 0 END) FROM account_payments ap WHERE ap.user_id = u.id), 0) AS account_unpaid_count,
                       COALESCE((SELECT SUM(CASE WHEN ap.is_paid = 0 THEN ap.amount ELSE 0 END) FROM account_payments ap WHERE ap.user_id = u.id), 0) AS total_unpaid
                FROM admin_users u
                INNER JOIN patient_accounts pa ON pa.user_id = u.id
                LEFT JOIN patients p ON pa.patient_id = p.id
                ORDER BY u.created_at DESC
            ")->fetchAll();
            echo json_encode(['success'=>true,'accounts'=>$accounts]);
            break;

        case 'account_add_days':
            if ($_SESSION['admin_role'] !== 'admin') { echo json_encode(['success'=>false,'message'=>'ليس لديك صلاحية.']); exit; }
            ensureColumn($pdo, 'patient_accounts', 'expiry_date', "DATE NULL AFTER allowed_days");
            ensureColumn($pdo, 'patient_accounts', 'notes', "TEXT NULL AFTER expiry_date");
            ensureColumn($pdo, 'account_payments', 'days_count', "INT NOT NULL DEFAULT 0 AFTER amount");
            ensureColumn($pdo, 'account_payments', 'is_paid', "TINYINT(1) NOT NULL DEFAULT 1 AFTER days_count");
            ensureColumn($pdo, 'account_payments', 'paid_by', "INT NULL AFTER created_by");
            ensureColumn($pdo, 'notifications', 'account_payment_id', "INT NULL AFTER leave_id");
            try { $pdo->exec("ALTER TABLE notifications MODIFY COLUMN leave_id INT NULL"); } catch(Throwable $e) {}

            $uid = intval($_POST['user_id'] ?? 0);
            $days = intval($_POST['days'] ?? 0);
            $amount = max(0, floatval($_POST['amount'] ?? 0));
            $note = trim($_POST['note'] ?? '');
            $expiry = trim($_POST['expiry_date'] ?? '');
            $isPaid = intval($_POST['is_paid'] ?? 1) === 1 ? 1 : 0;
            if ($uid <= 0 || $days <= 0) { echo json_encode(['success'=>false,'message'=>'بيانات غير صالحة.']); exit; }

            $pdo->beginTransaction();
            try {
                $checkStmt = $pdo->prepare("SELECT id FROM patient_accounts WHERE user_id = ?");
                $checkStmt->execute([$uid]);
                if ($checkStmt->fetch()) {
                    $updStmt = $pdo->prepare("UPDATE patient_accounts SET allowed_days = allowed_days + ?" . ($expiry ? ", expiry_date = ?" : "") . " WHERE user_id = ?");
                    if ($expiry) { $updStmt->execute([$days, $expiry, $uid]); }
                    else { $updStmt->execute([$days, $uid]); }
                } else {
                    $pdo->prepare("INSERT INTO patient_accounts (user_id, patient_id, allowed_days, expiry_date) VALUES (?, 0, ?, ?)")->execute([$uid, $days, $expiry ?: null]);
                }

                if ($amount > 0) {
                    $payStmt = $pdo->prepare("INSERT INTO account_payments (user_id, amount, days_count, is_paid, note, created_by, paid_by) VALUES (?,?,?,?,?,?,?)");
                    $payStmt->execute([$uid, $amount, $days, $isPaid, $note ?: "إضافة $days يوم", intval($_SESSION['admin_user_id']), $isPaid ? intval($_SESSION['admin_user_id']) : null]);
                    $paymentId = intval($pdo->lastInsertId());
                    if (!$isPaid) {
                        $userNameStmt = $pdo->prepare("SELECT COALESCE(display_name, username, 'مريض') FROM admin_users WHERE id = ?");
                        $userNameStmt->execute([$uid]);
                        $accountName = $userNameStmt->fetchColumn() ?: 'مريض';
                        $notifStmt = $pdo->prepare("INSERT INTO notifications (type, leave_id, account_payment_id, message, created_at) VALUES ('payment', NULL, ?, ?, ?)");
                        $notifStmt->execute([$paymentId, "إضافة أيام غير مدفوعة لحساب {$accountName} ({$days} يوم) بمبلغ {$amount}", nowSaudi()]);
                    }
                }

                $notifMsg = "🎉 تمت إضافة {$days} يوم إجازة مرضية إلى حسابك." . ($expiry ? " تاريخ الانتهاء: {$expiry}." : "") . ($note ? " ملاحظة: {$note}" : "");
                $pdo->prepare("INSERT INTO user_notifications (user_id, message) VALUES (?, ?)")->execute([$uid, $notifMsg]);
                $pdo->commit();
            } catch(Throwable $e) {
                if ($pdo->inTransaction()) $pdo->rollBack();
                echo json_encode(['success'=>false,'message'=>'تعذّرت إضافة الأيام: ' . $e->getMessage()]);
                exit;
            }
            echo json_encode(['success'=>true,'message'=> $isPaid ? "تمت إضافة $days يوم وتسجيلها كمدفوعة." : "تمت إضافة $days يوم ونقل المستحقات إلى إشعارات الدفع.", 'stats'=>getStats($pdo)]);
            break;

        case 'account_fetch_records':
            if ($_SESSION['admin_role'] !== 'admin') { echo json_encode(['success'=>false,'message'=>'ليس لديك صلاحية.']); exit; }
            $uid = intval($_POST['user_id'] ?? $_GET['user_id'] ?? 0);
            if ($uid <= 0) { echo json_encode(['success'=>false,'message'=>'معرّف غير صالح.']); exit; }
            $records = fetchPatientAccountRecords($pdo, $uid);
            echo json_encode(['success'=>true,'leaves'=>$records['leaves'],'payments'=>$records['payments']]);
            break;

        case 'account_mark_payment_paid':
            if ($_SESSION['admin_role'] !== 'admin') { echo json_encode(['success'=>false,'message'=>'ليس لديك صلاحية.']); exit; }
            $pid = intval($_POST['payment_id'] ?? 0);
            $amount = max(0, floatval($_POST['amount'] ?? 0));
            if ($pid <= 0) { echo json_encode(['success'=>false,'message'=>'معرّف الدفع غير صالح.']); exit; }
            $params = [intval($_SESSION['admin_user_id']), $pid];
            $sql = "UPDATE account_payments SET is_paid = 1, paid_by = ?, paid_at = NOW()";
            if ($amount > 0) { $sql .= ", amount = ?"; $params = [intval($_SESSION['admin_user_id']), $amount, $pid]; }
            $sql .= " WHERE id = ?";
            $pdo->prepare($sql)->execute($params);
            $pdo->prepare("DELETE FROM notifications WHERE account_payment_id = ? AND type = 'payment'")->execute([$pid]);
            echo json_encode(['success'=>true,'message'=>'تم تأكيد دفع سجل الأيام بنجاح.','stats'=>getStats($pdo)]);
            break;

        case 'account_create_leave':
            if ($_SESSION['admin_role'] !== 'admin') { echo json_encode(['success'=>false,'message'=>'ليس لديك صلاحية.']); exit; }
            $uid = intval($_POST['user_id'] ?? 0);
            $hospitalId = intval($_POST['hospital_id'] ?? 0);
            $doctorId = intval($_POST['doctor_id'] ?? 0);
            $startDate = trim($_POST['start_date'] ?? '');
            $endDate = trim($_POST['end_date'] ?? '');
            $daysCount = intval($_POST['days_count'] ?? 0);
            $issueTime = normalizeIssueTimeForStorage(trim($_POST['issue_time'] ?? ''), in_array(strtoupper(trim($_POST['issue_period'] ?? '')), ['AM','PM']) ? strtoupper(trim($_POST['issue_period'])) : null);
            $issuePeriod = in_array(strtoupper(trim($_POST['issue_period'] ?? '')), ['AM','PM']) ? strtoupper(trim($_POST['issue_period'])) : null;
            if ($uid <= 0 || $hospitalId <= 0 || $doctorId <= 0 || !$startDate || !$endDate || $daysCount <= 0) {
                echo json_encode(['success'=>false,'message'=>'يرجى تعبئة بيانات الإجازة كاملة.']); exit;
            }
            $acctStmt = $pdo->prepare("SELECT pa.*, p.name_en, p.employer_ar, p.employer_en FROM patient_accounts pa LEFT JOIN patients p ON p.id = pa.patient_id WHERE pa.user_id = ? LIMIT 1");
            $acctStmt->execute([$uid]);
            $acct = $acctStmt->fetch();
            if (!$acct || intval($acct['patient_id']) <= 0) { echo json_encode(['success'=>false,'message'=>'الحساب غير مرتبط بمريض.']); exit; }
            $patientId = intval($acct['patient_id']);
            $usedDays = getUsedPatientAccountDays($pdo, $patientId, $uid);
            $remainingDays = intval($acct['allowed_days'] ?? 0) - $usedDays;
            if ($remainingDays <= 0 || $daysCount > $remainingDays) {
                echo json_encode(['success'=>false,'message'=>"لا يمكن إنشاء الإجازة؛ الأيام المطلوبة ({$daysCount}) تتجاوز المتبقي ({$remainingDays})."]); exit;
            }
            $hStmt = $pdo->prepare("SELECT * FROM hospitals WHERE id = ? AND deleted_at IS NULL LIMIT 1");
            $hStmt->execute([$hospitalId]);
            $hosp = $hStmt->fetch();
            $dStmt = $pdo->prepare("SELECT * FROM doctors WHERE id = ? AND hospital_id = ? LIMIT 1");
            $dStmt->execute([$doctorId, $hospitalId]);
            $doc = $dStmt->fetch();
            if (!$hosp || !$doc) { echo json_encode(['success'=>false,'message'=>'المستشفى أو الطبيب غير صالح، تأكد أن الطبيب تابع للمستشفى.']); exit; }
            $issueDate = $startDate;
            $serviceCode = generateServiceCode($pdo, $hosp['service_prefix'] ?? 'GSL', $issueDate);
            $stmt = $pdo->prepare("INSERT INTO sick_leaves
                (service_code, patient_id, doctor_id, hospital_id, created_by_user_id, issue_date, issue_time, issue_period, start_date, end_date, days_count,
                 patient_name_en, doctor_name_en, doctor_title_en, hospital_name_ar, hospital_name_en, logo_path, employer_ar, employer_en, is_paid, payment_amount)
                VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)");
            $stmt->execute([
                $serviceCode, $patientId, $doctorId, $hospitalId, $uid, $issueDate, $issueTime ?: null, $issuePeriod,
                $startDate, $endDate, $daysCount,
                $acct['name_en'] ?? '', $doc['name_en'] ?? '', $doc['title_en'] ?? '',
                $hosp['name_ar'] ?? '', $hosp['name_en'] ?? '', $hosp['logo_url'] ?? $hosp['logo_path'] ?? '',
                $acct['employer_ar'] ?? '', $acct['employer_en'] ?? '', 1, 0
            ]);
            $records = fetchPatientAccountRecords($pdo, $uid);
            $data = fetchActiveOperationalData($pdo);
            $data['doctors'] = $pdo->query("SELECT d.*, h.name_ar AS hospital_name_ar FROM doctors d LEFT JOIN hospitals h ON d.hospital_id = h.id ORDER BY d.name_ar")->fetchAll();
            $data['patients'] = $pdo->query("SELECT * FROM patients ORDER BY name_ar")->fetchAll();
            $data['stats'] = getStats($pdo);
            $data['account_records'] = $records;
            $data['success'] = true;
            $data['message'] = "تم إنشاء الإجازة للمريض بنجاح. رمز الخدمة: {$serviceCode}";
            echo json_encode($data);
            break;

        case 'account_toggle_status':
            if ($_SESSION['admin_role'] !== 'admin') { echo json_encode(['success'=>false,'message'=>'ليس لديك صلاحية.']); exit; }
            $uid = intval($_POST['user_id'] ?? 0);
            $status = intval($_POST['status'] ?? 0);
            if ($uid == $_SESSION['admin_user_id']) { echo json_encode(['success'=>false,'message'=>'لا يمكنك تعطيل حسابك الخاص.']); exit; }
            $pdo->prepare("UPDATE admin_users SET is_active = ? WHERE id = ?")->execute([$status, $uid]);
            // إذا تم التعطيل: احذف جلسات المستخدم من جدول user_sessions وأبطل ملفات الجلسة
            if (!$status) {
                // حذف سجلات الجلسات من قاعدة البيانات
                $pdo->prepare("UPDATE user_sessions SET logout_at = NOW() WHERE user_id = ? AND logout_at IS NULL")->execute([$uid]);
                // محاولة إبطال ملفات الجلسة المخزنة على الخادم
                $sessionSavePath = session_save_path() ?: sys_get_temp_dir();
                if (is_dir($sessionSavePath)) {
                    foreach (glob($sessionSavePath . '/sess_*') as $sessFile) {
                        $sessContent = @file_get_contents($sessFile);
                        if ($sessContent !== false) {
                            // تحقق إذا كانت الجلسة تخص هذا المستخدم (patient_user_id أو admin_user_id)
                            if (strpos($sessContent, 'patient_user_id|i:' . $uid . ';') !== false
                                || strpos($sessContent, 'admin_user_id|i:' . $uid . ';') !== false) {
                                @unlink($sessFile);
                            }
                        }
                    }
                }
            }
            echo json_encode(['success'=>true,'message'=>$status ? 'تم تفعيل الحساب وأصبح بإمكان المستخدم الدخول.' : 'تم تعطيل الحساب وتسجيل خروجه فوراً.']);
            break;

        case 'account_update_password':
            if ($_SESSION['admin_role'] !== 'admin') { echo json_encode(['success'=>false,'message'=>'ليس لديك صلاحية.']); exit; }
            $uid = intval($_POST['user_id'] ?? 0);
            $newpass = $_POST['new_password'] ?? '';
            if ($uid <= 0 || strlen($newpass) < 4) { echo json_encode(['success'=>false,'message'=>'كلمة المرور يجب أن تكون 4 أحرف على الأقل.']); exit; }
            $pdo->prepare("UPDATE admin_users SET password_hash = ? WHERE id = ?")->execute([password_hash($newpass, PASSWORD_DEFAULT), $uid]);
            echo json_encode(['success'=>true,'message'=>'تم تغيير كلمة المرور بنجاح.']);
            break;

   case 'account_fetch_payments':
            if ($_SESSION['admin_role'] !== 'admin') { echo json_encode(['success'=>false,'message'=>'ليس لديك صلاحية.']); exit; }
            $pdo->exec("CREATE TABLE IF NOT EXISTS account_payments (
                id INT AUTO_INCREMENT PRIMARY KEY,
                user_id INT NOT NULL,
                amount DECIMAL(10,2) NOT NULL DEFAULT 0,
                note VARCHAR(500) NULL,
                paid_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                created_by INT NULL,
                FOREIGN KEY (user_id) REFERENCES admin_users(id) ON DELETE CASCADE
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci");
            
            // التعديل هنا: قراءة الـ user_id من POST
            $uid = intval($_POST['user_id'] ?? $_GET['user_id'] ?? 0);
            
            $records = fetchPatientAccountRecords($pdo, $uid);
            echo json_encode(['success'=>true,'payments'=>$records['payments'],'leaves'=>$records['leaves']]);
            break;

        case 'account_delete_payment':
            if ($_SESSION['admin_role'] !== 'admin') { echo json_encode(['success'=>false,'message'=>'ليس لديك صلاحية.']); exit; }
            $pid = intval($_POST['payment_id'] ?? 0);
            $pdo->prepare("DELETE FROM notifications WHERE account_payment_id = ?")->execute([$pid]);
            $pdo->prepare("DELETE FROM account_payments WHERE id = ?")->execute([$pid]);
            echo json_encode(['success'=>true,'message'=>'تم حذف سجل الدفع.','stats'=>getStats($pdo)]);
            break;

        case 'account_link_patient':
            if ($_SESSION['admin_role'] !== 'admin') { echo json_encode(['success'=>false,'message'=>'ليس لديك صلاحية.']); exit; }
            ensureColumn($pdo, 'patient_accounts', 'expiry_date', "DATE NULL AFTER allowed_days");
            ensureColumn($pdo, 'patient_accounts', 'notes', "TEXT NULL AFTER expiry_date");
            $uid = intval($_POST['user_id'] ?? 0);
            $pid = intval($_POST['patient_id'] ?? 0);
            $allowed = intval($_POST['allowed_days'] ?? 0);
            $expiry = trim($_POST['expiry_date'] ?? '');
            $notes = trim($_POST['notes'] ?? '');
            if ($uid <= 0) { echo json_encode(['success'=>false,'message'=>'معرّف المستخدم غير صالح.']); exit; }
            if ($pid > 0) {
                $pdo->prepare("INSERT INTO patient_accounts (user_id, patient_id, allowed_days, expiry_date, notes) VALUES (?,?,?,?,?) ON DUPLICATE KEY UPDATE patient_id=VALUES(patient_id), allowed_days=VALUES(allowed_days), expiry_date=VALUES(expiry_date), notes=VALUES(notes)")->execute([$uid, $pid, $allowed, $expiry ?: null, $notes]);
            } else {
                $pdo->prepare("DELETE FROM patient_accounts WHERE user_id = ?")->execute([$uid]);
            }
            echo json_encode(['success'=>true,'message'=>'تم تحديث ربط الحساب بالمريض.']);
            break;

        case 'account_add_user':
            if ($_SESSION['admin_role'] !== 'admin') { echo json_encode(['success'=>false,'message'=>'ليس لديك صلاحية.']); exit; }
            $username = trim($_POST['username'] ?? '');
            $password = $_POST['password'] ?? '';
            $display_name = trim($_POST['display_name'] ?? '');
            $role = in_array($_POST['role'] ?? '', ['admin','user']) ? $_POST['role'] : 'user';
            $link_patient_id = intval($_POST['link_patient_id'] ?? 0);
            $link_allowed_days = max(0, intval($_POST['link_allowed_days'] ?? 0));
            if ($link_patient_id > 0) {
                $patientStmt = $pdo->prepare("SELECT name, name_ar, name_en FROM patients WHERE id = ? LIMIT 1");
                $patientStmt->execute([$link_patient_id]);
                $patientForUsername = $patientStmt->fetch();
                if ($patientForUsername) {
                    $patientFirstName = makePatientFirstNameUsername($patientForUsername);
                    $username = makeUniqueUsername($pdo, $patientFirstName . getNextPatientAccountNumber($pdo));
                }
            }
            if (empty($username) || empty($password) || empty($display_name)) { echo json_encode(['success'=>false,'message'=>'يرجى تعبئة جميع الحقول.']); exit; }
            $check = $pdo->prepare("SELECT id FROM admin_users WHERE username = ?"); $check->execute([$username]);
            if ($check->fetch()) { echo json_encode(['success'=>false,'message'=>'اسم المستخدم موجود مسبقاً.']); exit; }
            $pdo->prepare("INSERT INTO admin_users (username, password_hash, display_name, role) VALUES (?,?,?,?)")->execute([$username, password_hash($password, PASSWORD_DEFAULT), $display_name, $role]);
            $newUserId = intval($pdo->lastInsertId());
            // Link to patient if provided
            if ($link_patient_id > 0 && $newUserId > 0) {
                $pdo->exec("CREATE TABLE IF NOT EXISTS patient_accounts (
                    id INT AUTO_INCREMENT PRIMARY KEY,
                    user_id INT NOT NULL UNIQUE,
                    patient_id INT NOT NULL,
                    allowed_days INT DEFAULT 0,
                    expiry_date DATE NULL,
                    notes TEXT NULL,
                    FOREIGN KEY (user_id) REFERENCES admin_users(id) ON DELETE CASCADE,
                    FOREIGN KEY (patient_id) REFERENCES patients(id) ON DELETE CASCADE
                ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci");
                $pdo->prepare("INSERT INTO patient_accounts (user_id, patient_id, allowed_days) VALUES (?,?,?) ON DUPLICATE KEY UPDATE patient_id=VALUES(patient_id), allowed_days=VALUES(allowed_days)")->execute([$newUserId, $link_patient_id, $link_allowed_days]);
            }
            echo json_encode(['success'=>true,'message'=>'تمت إضافة الحساب بنجاح.','username'=>$username]);
            break;

        case 'account_edit_user':
            if ($_SESSION['admin_role'] !== 'admin') { echo json_encode(['success'=>false,'message'=>'ليس لديك صلاحية.']); exit; }
            $uid = intval($_POST['user_id'] ?? 0);
            $display_name = trim($_POST['display_name'] ?? '');
            $new_username = trim($_POST['new_username'] ?? '');
            $new_password = $_POST['new_password'] ?? '';
            if ($uid <= 0 || empty($display_name)) { echo json_encode(['success'=>false,'message'=>'بيانات غير صالحة.']); exit; }
            // Check username uniqueness if changed
            if (!empty($new_username)) {
                $dupCheck = $pdo->prepare("SELECT id FROM admin_users WHERE username = ? AND id <> ?");
                $dupCheck->execute([$new_username, $uid]);
                if ($dupCheck->fetch()) { echo json_encode(['success'=>false,'message'=>'اسم المستخدم موجود مسبقاً.']); exit; }
            }
            if (!empty($new_password) && !empty($new_username)) {
                $pdo->prepare("UPDATE admin_users SET display_name=?, username=?, password_hash=? WHERE id=?")->execute([$display_name, $new_username, password_hash($new_password, PASSWORD_DEFAULT), $uid]);
            } elseif (!empty($new_password)) {
                $pdo->prepare("UPDATE admin_users SET display_name=?, password_hash=? WHERE id=?")->execute([$display_name, password_hash($new_password, PASSWORD_DEFAULT), $uid]);
            } elseif (!empty($new_username)) {
                $pdo->prepare("UPDATE admin_users SET display_name=?, username=? WHERE id=?")->execute([$display_name, $new_username, $uid]);
            } else {
                $pdo->prepare("UPDATE admin_users SET display_name=? WHERE id=?")->execute([$display_name, $uid]);
            }
            echo json_encode(['success'=>true,'message'=>'تم تعديل بيانات الحساب بنجاح.']);
            break;

        case 'account_delete_user':
            if ($_SESSION['admin_role'] !== 'admin') { echo json_encode(['success'=>false,'message'=>'ليس لديك صلاحية.']); exit; }
            $uid = intval($_POST['user_id'] ?? 0);
            if ($uid <= 0) { echo json_encode(['success'=>false,'message'=>'معرّف غير صالح.']); exit; }
            if ($uid == intval($_SESSION['admin_user_id'])) { echo json_encode(['success'=>false,'message'=>'لا يمكنك حذف حسابك الخاص.']); exit; }
            $pdo->prepare("DELETE FROM patient_accounts WHERE user_id = ?")->execute([$uid]);
            $pdo->prepare("DELETE FROM account_payments WHERE user_id = ?")->execute([$uid]);
            $pdo->prepare("DELETE FROM user_sessions WHERE user_id = ?")->execute([$uid]);
            $pdo->prepare("DELETE FROM admin_users WHERE id = ?")->execute([$uid]);
            echo json_encode(['success'=>true,'message'=>'تم حذف الحساب بنجاح.']);
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
    $doctors = $pdo->query("SELECT d.*, h.name_ar AS hospital_name_ar FROM doctors d LEFT JOIN hospitals h ON d.hospital_id = h.id ORDER BY d.name_ar")->fetchAll();
    $patients = $pdo->query("SELECT * FROM patients ORDER BY name_ar")->fetchAll();
    $hospitals = getHospitalsList($pdo);
    
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
        $users = $pdo->query("SELECT u.* FROM admin_users u ORDER BY u.created_at DESC")->fetchAll();
    }
} else {
    $doctors = $patients = $leaves = $archived = $queries = $notifications_payment = $payments = $users = $chat_users = $hospitals = [];
    $stats = ['total' => 0, 'active' => 0, 'archived' => 0, 'patients' => 0, 'doctors' => 0, 'paid' => 0, 'unpaid' => 0, 'paid_amount' => 0, 'unpaid_amount' => 0];
}


$uiFontFamily = getSetting($pdo, 'ui_font_family', 'Cairo');
$allowedUiFonts = ['Cairo','Tajawal','Almarai','Changa','IBM Plex Sans Arabic','Noto Kufi Arabic','Readex Pro','El Messiri','Reem Kufi','Amiri'];
if (!in_array($uiFontFamily, $allowedUiFonts, true)) $uiFontFamily = 'Cairo';
$uiDarkTextColor = sanitizeHexColor(getSetting($pdo, 'dark_text_color', '#d8c8ff') ?? '#d8c8ff', '#d8c8ff');
$uiDarkGlowColor = sanitizeHexColor(getSetting($pdo, 'dark_glow_color', '#8b5cf6') ?? '#8b5cf6', '#8b5cf6');
$uiDarkGlowEnabled = getSetting($pdo, 'dark_glow_enabled', '1') === '1' ? '1' : '0';
$uiDataViewMode = getSetting($pdo, 'ui_data_view_mode', 'table') ?: 'table';
if (!in_array($uiDataViewMode, ['table','compact','cards','zebra','glass','minimal'], true)) $uiDataViewMode = 'table';
?>
<!DOCTYPE html>
<html lang="ar" dir="rtl">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>لوحة تحكم الإجازات المرضية</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.rtl.min.css" rel="stylesheet">
    <link href="https://cdn.jsdelivr.net/npm/bootstrap-icons@1.11.3/font/bootstrap-icons.min.css" rel="stylesheet" crossorigin="anonymous">
    <link href="https://fonts.googleapis.com/css2?family=Almarai:wght@300;400;700;800&family=Amiri:wght@400;700&family=Cairo:wght@300;400;500;600;700;800&family=Changa:wght@300;400;500;600;700;800&family=El+Messiri:wght@400;500;600;700&family=IBM+Plex+Sans+Arabic:wght@300;400;500;600;700&family=Noto+Kufi+Arabic:wght@300;400;500;600;700&family=Readex+Pro:wght@300;400;500;600;700&family=Reem+Kufi:wght@400;500;600;700&family=Tajawal:wght@300;400;500;700;800&display=swap" rel="stylesheet">
    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js"></script>
    <script src="https://cdnjs.cloudflare.com/ajax/libs/jspdf/2.5.1/jspdf.umd.min.js"></script>
    <script src="https://cdnjs.cloudflare.com/ajax/libs/jspdf-autotable/3.5.25/jspdf.plugin.autotable.min.js"></script>
    <script src="https://cdnjs.cloudflare.com/ajax/libs/html2pdf.js/0.10.1/html2pdf.bundle.min.js"></script>

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
            pointer-events: none;
        }
        .btn i, .btn .bi, .action-btn i, .action-btn .bi {
            pointer-events: none;
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

        .stats-pro-card {
            border-radius: 14px;
            overflow: hidden;
            transition: transform .22s ease, box-shadow .22s ease;
            background: linear-gradient(180deg, #ffffff, #f8fbff);
        }
        .stats-pro-card:hover {
            transform: translateY(-3px);
            box-shadow: 0 12px 24px rgba(2,6,23,0.12);
        }
        .dark-mode .stats-pro-card {
            background: linear-gradient(180deg, #0f172a, #111827);
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

        body.data-view-glass .table-responsive {
            background: linear-gradient(135deg, rgba(255,255,255,0.55), rgba(241,245,249,0.75));
            backdrop-filter: blur(10px);
            border-color: rgba(99,102,241,0.25);
        }
        .dark-mode body.data-view-glass .table-responsive,
        body.dark-mode.data-view-glass .table-responsive {
            background: linear-gradient(135deg, rgba(15,23,42,0.55), rgba(30,41,59,0.7));
            border-color: rgba(129,140,248,0.45);
        }

        body.data-view-minimal .table,
        body.data-view-minimal .table th,
        body.data-view-minimal .table td {
            border: none !important;
            box-shadow: none !important;
        }
        body.data-view-minimal .table tbody td { border-bottom: 1px solid rgba(148,163,184,0.2) !important; }

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
        .chat-voice-player {
            display: grid;
            gap: 8px;
            width: min(320px, 100%);
            background: rgba(15,23,42,0.04);
            border: 1px solid rgba(99,102,241,0.18);
            border-radius: 12px;
            padding: 8px;
        }
        .msg-other .chat-voice-player {
            background: rgba(255,255,255,0.14);
            border-color: rgba(255,255,255,0.2);
        }
        .chat-voice-speeds {
            display: inline-flex;
            gap: 6px;
            flex-wrap: wrap;
        }
        .chat-voice-speed {
            border: 1px solid rgba(99,102,241,0.35);
            border-radius: 999px;
            background: transparent;
            padding: 2px 8px;
            font-size: 11px;
            font-weight: 700;
            color: inherit;
            cursor: pointer;
        }
        .chat-voice-speed.active {
            background: rgba(99,102,241,0.18);
            border-color: rgba(99,102,241,0.65);
        }
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

            /* على الجوال: الكروت تتفعّل فقط إذا اخترت وضع cards */
            body.data-view-cards .table.mobile-readable thead {
                display: none;
            }

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
                box-shadow: 0 8px 20px rgba(15,23,42,0.05);
                padding: 8px;
            }

            body.data-view-cards .table.mobile-readable td {
                border: none !important;
                border-bottom: 1px dashed rgba(148,163,184,0.25) !important;
                padding: 8px 8px 8px 44% !important;
                position: relative;
                min-height: 36px;
            }

            body.data-view-cards .table.mobile-readable td:last-child {
                border-bottom: none !important;
            }

            body.data-view-cards .table.mobile-readable td::before {
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

            body.data-view-compact .table tbody td { padding: 6px 5px; font-size: 11px; }

            .dark-mode body.data-view-cards .table.mobile-readable tr,
            body.dark-mode.data-view-cards .table.mobile-readable tr {
                background: linear-gradient(145deg, #182337, #111827);
                border-color: rgba(148,163,184,0.35);
            }

            .dark-mode body.data-view-cards .table.mobile-readable td,
            body.dark-mode.data-view-cards .table.mobile-readable td {
                color: #111827 !important;
                background: #f8fafc;
                border-bottom-color: rgba(148,163,184,0.28) !important;
            }

            .dark-mode body.data-view-cards .table.mobile-readable td::before,
            body.dark-mode.data-view-cards .table.mobile-readable td::before {
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

        /* ═══════════════ إدارة الحسابات ═══════════════ */
        .accounts-mgmt-wrap { padding: 4px 0; }

        /* Stats Cards */
        .acct-stat-card {
            border-radius: var(--radius);
            padding: 20px 16px;
            display: flex;
            flex-direction: column;
            align-items: center;
            gap: 6px;
            text-align: center;
            position: relative;
            overflow: hidden;
            transition: transform var(--t-fast) var(--ease), box-shadow var(--t-fast) var(--ease);
            cursor: default;
        }
        .acct-stat-card:hover { transform: translateY(-3px); box-shadow: var(--shadow-lg); }
        .acct-stat-card::before {
            content: '';
            position: absolute;
            top: -30px; right: -30px;
            width: 100px; height: 100px;
            border-radius: 50%;
            opacity: 0.12;
        }
        .acct-stat-total { background: linear-gradient(135deg, #6366f1, #8b5cf6); color: #fff; box-shadow: 0 8px 24px rgba(99,102,241,0.35); }
        .acct-stat-total::before { background: #fff; }
        .acct-stat-active { background: linear-gradient(135deg, #10b981, #34d399); color: #fff; box-shadow: 0 8px 24px rgba(16,185,129,0.35); }
        .acct-stat-active::before { background: #fff; }
        .acct-stat-disabled { background: linear-gradient(135deg, #ef4444, #f87171); color: #fff; box-shadow: 0 8px 24px rgba(239,68,68,0.35); }
        .acct-stat-disabled::before { background: #fff; }
        .acct-stat-revenue { background: linear-gradient(135deg, #f59e0b, #fbbf24); color: #fff; box-shadow: 0 8px 24px rgba(245,158,11,0.35); }
        .acct-stat-revenue::before { background: #fff; }
        .acct-stat-icon { font-size: 28px; opacity: 0.9; }
        .acct-stat-val { font-size: 28px; font-weight: 800; line-height: 1; }
        .acct-stat-lbl { font-size: 12px; opacity: 0.85; font-weight: 600; }

        /* Toolbar */
        .acct-toolbar {
            display: flex;
            flex-wrap: wrap;
            gap: 10px;
            align-items: center;
        }

        /* Account Card */
        .acct-card {
            background: var(--card);
            border-radius: var(--radius);
            border: 1.5px solid var(--border);
            box-shadow: var(--shadow);
            overflow: hidden;
            transition: transform var(--t-fast) var(--ease), box-shadow var(--t-fast) var(--ease), border-color var(--t-fast);
            position: relative;
        }
        .acct-card:hover { transform: translateY(-4px); box-shadow: var(--shadow-lg); border-color: var(--primary-light); }
        .acct-card.acct-disabled { opacity: 0.72; border-color: var(--danger); }
        .acct-card.acct-expired { border-color: var(--warning); }

        .acct-card-header {
            padding: 16px 18px 12px;
            display: flex;
            align-items: center;
            gap: 12px;
            border-bottom: 1px solid var(--border-light);
            position: relative;
        }
        .acct-avatar {
            width: 48px; height: 48px;
            border-radius: 50%;
            display: flex; align-items: center; justify-content: center;
            font-size: 20px; font-weight: 800;
            flex-shrink: 0;
            color: #fff;
        }
        .acct-avatar.role-admin { background: linear-gradient(135deg, #ef4444, #f87171); }
        .acct-avatar.role-user { background: linear-gradient(135deg, #6366f1, #8b5cf6); }

        .acct-card-title { flex: 1; min-width: 0; }
        .acct-card-title .acct-username { font-size: 15px; font-weight: 700; color: var(--text); white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }
        .acct-card-title .acct-display { font-size: 12px; color: var(--text-muted); }

        .acct-status-dot {
            width: 10px; height: 10px;
            border-radius: 50%;
            flex-shrink: 0;
        }
        .acct-status-dot.active { background: var(--success); box-shadow: 0 0 6px var(--success); }
        .acct-status-dot.inactive { background: var(--danger); }

        .acct-card-body { padding: 14px 18px; }

        .acct-info-row {
            display: flex;
            align-items: center;
            gap: 8px;
            margin-bottom: 8px;
            font-size: 13px;
        }
        .acct-info-row i { color: var(--primary); width: 16px; flex-shrink: 0; }
        .acct-info-row .acct-info-label { color: var(--text-muted); min-width: 80px; }
        .acct-info-row .acct-info-val { color: var(--text); font-weight: 600; }

        /* Days Progress */
        .acct-days-wrap { margin: 12px 0; }
        .acct-days-header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 6px; font-size: 12px; }
        .acct-days-label { color: var(--text-muted); font-weight: 600; }
        .acct-days-count { font-weight: 800; font-size: 14px; }
        .acct-days-count.ok { color: var(--success); }
        .acct-days-count.warn { color: var(--warning); }
        .acct-days-count.empty { color: var(--danger); }
        .acct-progress {
            height: 8px;
            border-radius: 99px;
            background: var(--border);
            overflow: hidden;
        }
        .acct-progress-bar {
            height: 100%;
            border-radius: 99px;
            transition: width 0.6s var(--ease);
        }
        .acct-progress-bar.ok { background: linear-gradient(90deg, #10b981, #34d399); }
        .acct-progress-bar.warn { background: linear-gradient(90deg, #f59e0b, #fbbf24); }
        .acct-progress-bar.empty { background: linear-gradient(90deg, #ef4444, #f87171); }

        /* Payment Badge */
        .acct-payment-badge {
            display: inline-flex;
            align-items: center;
            gap: 5px;
            background: linear-gradient(135deg, rgba(16,185,129,0.12), rgba(52,211,153,0.08));
            border: 1px solid rgba(16,185,129,0.25);
            color: var(--success);
            border-radius: 20px;
            padding: 3px 10px;
            font-size: 12px;
            font-weight: 700;
        }

        /* Expiry Badge */
        .acct-expiry-badge {
            display: inline-flex;
            align-items: center;
            gap: 5px;
            border-radius: 20px;
            padding: 3px 10px;
            font-size: 11px;
            font-weight: 600;
        }
        .acct-expiry-badge.ok { background: rgba(16,185,129,0.1); color: var(--success); border: 1px solid rgba(16,185,129,0.2); }
        .acct-expiry-badge.warn { background: rgba(245,158,11,0.1); color: var(--warning); border: 1px solid rgba(245,158,11,0.2); }
        .acct-expiry-badge.expired { background: rgba(239,68,68,0.1); color: var(--danger); border: 1px solid rgba(239,68,68,0.2); }

        /* Card Actions */
        .acct-card-actions {
            padding: 10px 18px 14px;
            display: flex;
            flex-wrap: wrap;
            gap: 6px;
            border-top: 1px solid var(--border-light);
        }
        .acct-card-actions .btn { font-size: 12px; padding: 5px 10px; border-radius: 8px; }

        /* Role Badge */
        .acct-role-badge {
            position: absolute;
            top: 10px;
            left: 12px;
            font-size: 10px;
            font-weight: 700;
            padding: 2px 8px;
            border-radius: 20px;
        }

        /* Dark mode adjustments */
        .dark-mode .acct-card { background: var(--card); border-color: var(--border); }
        .dark-mode .acct-card:hover { border-color: var(--primary-light); }
        .dark-mode .acct-progress { background: rgba(148,163,184,0.15); }

        /* Payments History List */
        .payment-history-item {
            display: flex;
            align-items: center;
            justify-content: space-between;
            padding: 10px 14px;
            border-radius: 10px;
            background: var(--bg-alt);
            margin-bottom: 8px;
            gap: 10px;
        }
        .payment-history-item .ph-amount { font-size: 16px; font-weight: 800; color: var(--success); }
        .payment-history-item .ph-note { font-size: 12px; color: var(--text-muted); }
        .payment-history-item .ph-date { font-size: 11px; color: var(--text-muted); }
        .dark-mode .payment-history-item { background: rgba(148,163,184,0.08); }
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
            <small class="text-muted">المستخدم الافتراضي: _______</small>
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
            <button class="nav-link" id="tab-hospitals" data-bs-toggle="tab" data-bs-target="#pane-hospitals" type="button" role="tab">
                <i class="bi bi-hospital"></i> المستشفيات
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
        <?php if ($_SESSION['admin_role'] === 'admin'): ?>
        <li class="nav-item" role="presentation">
            <button class="nav-link" id="tab-accounts" data-bs-toggle="tab" data-bs-target="#pane-accounts" type="button" role="tab">
                <i class="bi bi-person-vcard"></i> حسابات المرضى
            </button>
        </li>
        <?php endif; ?>
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
                <form id="addLeaveForm" enctype="multipart/form-data">
                    <div class="row g-3">
                        <!-- رمز الخدمة -->
                        <div class="col-md-4">
                            <label class="form-label">رمز الخدمة (يدوي - اختياري)</label>
                            <input type="text" class="form-control" name="service_code_manual" id="service_code_manual" placeholder="اتركه فارغاً للتوليد التلقائي">
                            <input type="hidden" name="service_prefix" id="service_prefix" value="GSL">
                        </div>

                        <!-- المستشفى -->
                        <div class="col-md-4">
                            <label class="form-label">المستشفى *</label>
                            <input type="text" class="form-control form-control-sm mb-2" id="hospital_id_search" placeholder="بحث سريع باسم المستشفى...">
                            <select class="form-select" name="hospital_id" id="hospital_id" required>
                                <option value="">-- اختر مستشفى --</option>
                                <?php if (isset($hospitals)) foreach ($hospitals as $h): ?>
                                <option value="<?php echo $h['id']; ?>" data-prefix="<?php echo htmlspecialchars($h['service_prefix'] ?? 'GSL'); ?>"><?php echo htmlspecialchars($h['name_ar']); ?></option>
                                <?php endforeach; ?>
                            </select>
                        </div>
                        <div class="col-md-4"></div>

                        <!-- المريض -->
                        <div class="col-md-6">
                            <div class="d-flex justify-content-between align-items-center gap-2 mb-1">
                                <label class="form-label mb-0">المريض</label>
                                <button type="button" class="btn btn-sm btn-outline-success" id="openQuickPatientModal"><i class="bi bi-person-plus"></i> إضافة مريض جديد</button>
                            </div>
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
                            <div class="d-flex justify-content-between align-items-center gap-2 mb-1">
                                <label class="form-label mb-0">الطبيب (يتغير حسب المستشفى)</label>
                                <button type="button" class="btn btn-sm btn-outline-primary" id="openQuickDoctorModal"><i class="bi bi-person-badge"></i> إضافة طبيب جديد</button>
                            </div>
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

                        <!-- جهة العمل -->
                        <div class="col-md-6">
                            <label class="form-label">جهة العمل (عربي)</label>
                            <input type="text" class="form-control" name="employer_ar" id="employer_ar" placeholder="الى من يهمه الامر">
                        </div>
                        <div class="col-md-6">
                            <label class="form-label">Employer (English)</label>
                            <input type="text" class="form-control" name="employer_en" id="employer_en" placeholder="TO WHOM IT MAY CONCERN">
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
                            <input type="number" class="form-control" name="days_count" id="days_count" min="1" required readonly>
                        </div>

                        <!-- الوقت -->
                        <div class="col-md-3">
                            <label class="form-label">وقت الإصدار</label>
                            <input type="time" class="form-control" name="issue_time" id="issue_time" value="09:00">
                        </div>
                        <div class="col-md-3">
                            <label class="form-label">الفترة</label>
                            <select class="form-select" name="issue_period" id="issue_period">
                                <option value="AM">صباحاً (AM)</option>
                                <option value="PM">مساءً (PM)</option>
                            </select>
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

        <!-- ======================== تبويب المستشفيات ======================== -->
       <div class="tab-pane fade" id="pane-hospitals" role="tabpanel">
            <div class="card-custom">
                <div class="card-header"><i class="bi bi-hospital text-primary"></i> إدارة المستشفيات</div>
                <div class="card-body">
                    <form id="addHospitalForm" class="row g-2 mb-3" enctype="multipart/form-data">
                        <div class="col-md-3"><input type="text" class="form-control" name="hospital_name_ar" placeholder="اسم المستشفى (عربي) *" required></div>
                        <div class="col-md-3"><input type="text" class="form-control" name="hospital_name_en" placeholder="Hospital Name (English)"></div>
                        <div class="col-md-2"><input type="text" class="form-control" name="hospital_license" placeholder="رقم الترخيص (اختياري)"></div>
                        <div class="col-md-2">
                            <select class="form-select" name="hospital_prefix">
                                <option value="GSL">GSL (حكومي)</option>
                                <option value="PSL">PSL (خاص)</option>
                            </select>
                        </div>
                        <div class="col-md-2"><input type="file" class="form-control" name="hospital_logo" accept="image/*"></div>
                        <div class="col-md-4"><input type="text" class="form-control" name="hospital_logo_url" placeholder="أو رابط الشعار (اختياري)"></div>
                        <div class="col-md-2"><button type="submit" class="btn btn-gradient w-100"><i class="bi bi-plus"></i> إضافة مستشفى</button></div>
                    </form>
                    <div class="alert alert-light border mb-3">
                        <div class="d-flex flex-wrap justify-content-between align-items-center gap-2 mb-2">
                            <strong><i class="bi bi-hospital-fill text-primary"></i> إضافة دفعة مستشفيات</strong>
                            <small class="text-muted">كل سطر = اسم عربي | اسم إنجليزي | رقم الترخيص | البادئة (GSL/PSL)</small>
                        </div>
                        <form id="addHospitalsBatchForm" class="row g-2">
                            <div class="col-md-12">
                                <label class="form-label">المستشفيات (كل سطر مستشفى واحد)</label>
                                <textarea class="form-control" id="hospitals_batch_text" name="hospitals_batch_text" rows="4" placeholder="مستشفى الملك فهد | King Fahd Hospital | 12345 | GSL&#10;مركز الرعاية الطبية | Medical Care Center | 67890 | PSL"></textarea>
                            </div>
                            <div class="col-md-12 d-grid">
                                <button type="submit" class="btn btn-outline-primary">
                                    <i class="bi bi-hospital-fill"></i> إضافة الدفعة
                                </button>
                            </div>
                        </form>
                    </div>
                    
                    <div class="toolbar mb-3">
                        <div class="input-group" style="max-width:280px;">
                            <input type="text" class="form-control" id="searchHospitals" placeholder="بحث في المستشفيات...">
                            <button class="btn btn-gradient" id="btn-search-hospitals" type="button"><i class="bi bi-search"></i></button>
                        </div>
                    </div>
                    
                    <div class="table-responsive">
                        <table class="table table-bordered table-hover table-striped text-center mobile-readable" id="hospitalsTable">
                            <thead><tr><th>#</th><th>الشعار</th><th>الاسم (عربي)</th><th>الاسم (English)</th><th>الترخيص</th><th>البادئة</th><th>التحكم</th></tr></thead>
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
                        <div class="col-md-2"><input type="text" class="form-control" name="doctor_name" placeholder="اسم الطبيب (عربي) *" required>
                            <input type="hidden" name="doctor_name_ar">
                        </div>
                        <div class="col-md-2"><input type="text" class="form-control" name="doctor_name_en" placeholder="Doctor Name (EN)"></div>
                        <div class="col-md-2"><input type="text" class="form-control" name="doctor_title" placeholder="المسمى (عربي) *" required>
                            <input type="hidden" name="doctor_title_ar">
                        </div>
                        <div class="col-md-2"><input type="text" class="form-control" name="doctor_title_en" placeholder="Title (EN)"></div>
                        <div class="col-md-2">
                            <select class="form-select" name="doctor_hospital_id">
                                <option value="">المستشفى (اختياري)</option>
                            </select>
                        </div>
                        <div class="col-md-2"><button type="submit" class="btn btn-gradient w-100"><i class="bi bi-plus"></i> إضافة طبيب</button></div>
                    </form>
           <div class="alert alert-light border mb-3">
                        <div class="d-flex flex-wrap justify-content-between align-items-center gap-2 mb-2">
                            <strong><i class="bi bi-people-fill text-primary"></i> إضافة دفعة أطباء</strong>
                            <small class="text-muted">كل سطر = اسم عربي | اسم إنجليزي | مسمى عربي | مسمى إنجليزي</small>
                        </div>
                        
                        <form id="addDoctorsBatchForm" class="row g-2">
                            <div class="col-md-4">
                                <label class="form-label">المستشفى</label>
                                <input type="text" class="form-control form-control-sm mb-2" id="batch_hospital_search" placeholder="بحث سريع باسم المستشفى...">
                                <select class="form-select" name="batch_hospital_id" id="batch_hospital_id">
                                    <option value="">اختر مستشفى</option>
                                    <?php foreach ($hospitals_data as $h): ?>
                                    <option value="<?php echo $h['id']; ?>"><?php echo htmlspecialchars($h['name_ar']); ?></option>
                                    <?php endforeach; ?>
                                </select>
                            </div>
                            <div class="col-md-8">
                                <label class="form-label">الأطباء (كل سطر طبيب واحد)</label>
                                <textarea class="form-control" id="doctors_batch_text" name="doctors_batch_text" rows="4" placeholder="د. أحمد علي | Dr. Ahmed Ali | استشاري باطنية | Consultant Internal Medicine&#10;د. نورة خالد | Dr. Noura Khaled | أخصائي أطفال | Pediatric Specialist"></textarea>
                            </div>
                            <div class="col-md-12 d-grid">
                                <button type="submit" class="btn btn-outline-primary">
                                    <i class="bi bi-people-fill"></i> إضافة الدفعة
                                </button>
                            </div>
                        </form>
                    </div>
                    <div class="table-responsive">
                        <table class="table table-bordered table-hover table-striped text-center mobile-readable" id="doctorsTable">
                            <thead><tr><th>#</th><th>الاسم (عربي)</th><th>Name (EN)</th><th>المسمى</th><th>المستشفى</th><th>التحكم</th></tr></thead>
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
                        <div class="col-md-3"><input type="text" class="form-control" name="patient_name" placeholder="اسم المريض (عربي) *" required>
                            <input type="hidden" name="patient_name_ar">
                        </div>
                        <div class="col-md-3"><input type="text" class="form-control" name="patient_name_en" placeholder="Patient Name (EN)"></div>
                        <div class="col-md-2"><input type="text" class="form-control" name="identity_number" placeholder="رقم الهوية *" required></div>
                        <div class="col-md-2"><input type="text" class="form-control" name="phone" placeholder="الهاتف"></div>
                        <div class="col-md-2"><input type="text" class="form-control" name="patient_employer_ar" placeholder="جهة العمل (عربي)"></div>
                        <div class="col-md-2"><input type="text" class="form-control" name="patient_employer_en" placeholder="Employer (EN)"></div>
                        <div class="col-md-2"><input type="text" class="form-control" name="patient_nationality_ar" placeholder="الجنسية (عربي)"></div>
                        <div class="col-md-2"><input type="text" class="form-control" name="patient_nationality_en" placeholder="Nationality (EN)"></div>
                        <div class="col-md-2"><input type="url" class="form-control" name="folder_link" placeholder="رابط المجلد"></div>
                        <div class="col-md-2"><button type="submit" class="btn btn-success-custom w-100"><i class="bi bi-plus"></i> إضافة مريض</button></div>
                    </form>
                    <div class="alert alert-light border mb-3">
                        <div class="d-flex flex-wrap justify-content-between align-items-center gap-2 mb-2">
                            <strong><i class="bi bi-people-fill text-success"></i> إضافة دفعة مرضى</strong>
                            <small class="text-muted">كل سطر = اسم عربي | اسم إنجليزي | رقم الهوية | الهاتف | جهة العمل (عربي) | جهة العمل (إنجليزي) | الجنسية (عربي) | الجنسية (إنجليزي)</small>
                        </div>
                        <form id="addPatientsBatchForm" class="row g-2">
                            <div class="col-md-12">
                                <label class="form-label">المرضى (كل سطر مريض واحد)</label>
                                <textarea class="form-control" id="patients_batch_text" name="patients_batch_text" rows="4" placeholder="أحمد محمد علي | Ahmed Mohammed Ali | 1234567890 | 0501234567 | وزارة الصحة | Ministry of Health | سعودي | Saudi&#10;نورة خالد | Noura Khaled | 0987654321 | 0559876543 | القطاع الخاص | Private Sector | سعودية | Saudi"></textarea>
                            </div>
                            <div class="col-md-12 d-grid">
                                <button type="submit" class="btn btn-outline-success">
                                    <i class="bi bi-people-fill"></i> إضافة الدفعة
                                </button>
                            </div>
                        </form>
                    </div>
                    <div class="table-responsive">
                        <table class="table table-bordered table-hover table-striped text-center mobile-readable" id="patientsTable">
                            <thead><tr><th>#</th><th>الاسم (عربي)</th><th>Name (EN)</th><th>رقم الهوية</th><th>جهة العمل</th><th>الهاتف</th><th>عدد الإجازات</th><th>مبلغ مدفوع</th><th>مبلغ مستحق</th><th>إجازات المريض</th><th>التحكم</th></tr></thead>
                            <tbody></tbody>
                        </table>
                    </div>
                </div>
            </div>
        </div>

        <!-- ======================== تبويب حسابات المرضى ======================== -->
        <?php if ($loggedIn && $_SESSION['admin_role'] === 'admin'): ?>
        <div class="tab-pane fade" id="pane-accounts" role="tabpanel">
            <div class="accounts-mgmt-wrap">
                <div class="alert alert-info mb-3 py-2" style="font-size:13px;">
                    <i class="bi bi-info-circle-fill"></i>
                    <strong>حسابات المرضى:</strong> هذه الحسابات <strong>منفصلة تماماً</strong> عن مستخدمي لوحة التحكم. تُستخدم لتسجيل دخول المرضى في <strong>بوابة المرضى (user.php)</strong> فقط. كل مريض يحتاج حساباً مرتبطاً بملفه لتقديم طلبات الإجازة.
                    <br><i class="bi bi-shield-lock"></i> لإدارة مستخدمي ومشرفي لوحة التحكم، اذهب إلى <strong>الإعدادات ← إدارة المستخدمين</strong>.
                </div>
                <!-- Header Stats Row -->
                <div class="row g-3 mb-4" id="accountsStatsRow">
                    <div class="col-6 col-md-3">
                        <div class="acct-stat-card acct-stat-total">
                            <div class="acct-stat-icon"><i class="bi bi-people-fill"></i></div>
                            <div class="acct-stat-val" id="acctStatTotal">0</div>
                            <div class="acct-stat-lbl">إجمالي الحسابات</div>
                        </div>
                    </div>
                    <div class="col-6 col-md-3">
                        <div class="acct-stat-card acct-stat-active">
                            <div class="acct-stat-icon"><i class="bi bi-check-circle-fill"></i></div>
                            <div class="acct-stat-val" id="acctStatActive">0</div>
                            <div class="acct-stat-lbl">حسابات نشطة</div>
                        </div>
                    </div>
                    <div class="col-6 col-md-3">
                        <div class="acct-stat-card acct-stat-disabled">
                            <div class="acct-stat-icon"><i class="bi bi-slash-circle-fill"></i></div>
                            <div class="acct-stat-val" id="acctStatDisabled">0</div>
                            <div class="acct-stat-lbl">حسابات معطلة</div>
                        </div>
                    </div>
                    <div class="col-6 col-md-3">
                        <div class="acct-stat-card acct-stat-revenue">
                            <div class="acct-stat-icon"><i class="bi bi-cash-coin"></i></div>
                            <div class="acct-stat-val" id="acctStatRevenue">0</div>
                            <div class="acct-stat-lbl">إجمالي المدفوعات</div>
                        </div>
                    </div>
                </div>

                <!-- Toolbar -->
                <div class="acct-toolbar mb-3">
                    <div class="input-group" style="max-width:280px;">
                        <input type="text" class="form-control" id="acctSearch" placeholder="بحث باسم المستخدم أو المريض...">
                        <button class="btn btn-gradient" id="acctSearchBtn"><i class="bi bi-search"></i></button>
                    </div>
                    <div class="btn-group btn-group-sm">
                        <button class="btn btn-outline-success" id="acctFilterActive">نشط</button>
                        <button class="btn btn-outline-danger" id="acctFilterDisabled">معطل</button>
                        <button class="btn btn-outline-secondary active" id="acctFilterAll">الكل</button>
                    </div>
                    <button class="btn btn-gradient btn-sm" id="acctAddUserBtn"><i class="bi bi-person-plus-fill"></i> إضافة حساب مريض جديد</button>
                    <button class="btn btn-outline-secondary btn-sm" id="acctRefreshBtn"><i class="bi bi-arrow-repeat"></i> تحديث</button>
                </div>

                <!-- Accounts Grid -->
                <div class="row g-3" id="accountsGrid">
                    <div class="col-12 text-center py-5 text-muted" id="accountsGridLoading" style="display:none;">
                        <div class="spinner-border text-primary" role="status"></div>
                        <p class="mt-2">جارٍ تحميل الحسابات...</p>
                    </div>
                    <div class="col-12 text-center py-5 text-muted" id="accountsGridEmpty">
                        <i class="bi bi-people" style="font-size:48px;opacity:0.3;"></i>
                        <p class="mt-2">اضغط على تبويب "إدارة الحسابات" لتحميل البيانات</p>
                    </div>
                </div>
            </div>
        </div>
        <?php endif; ?>

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
                        <select id="adminStatsUserFilter" class="form-select form-select-sm" style="min-width:180px;">
                            <option value="0">كل المستخدمين</option>
                        </select>
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

                    <div class="row g-3 mt-1">
                        <div class="col-lg-6">
                            <h6>إنتاجية المستخدمين (من أنشأ الإجازات)</h6>
                            <div class="table-responsive">
                                <table class="table table-bordered table-sm text-center" id="adminUsersProductivityTable">
                                    <thead><tr><th>المستخدم</th><th>الإجازات</th><th>المكرر</th><th>معدل التكرار %</th></tr></thead>
                                    <tbody></tbody>
                                </table>
                            </div>
                        </div>
                        <div class="col-lg-6">
                            <h6>الإجازات المكررة (نفس المريض + نفس التواريخ)</h6>
                            <div class="table-responsive">
                                <table class="table table-bordered table-sm text-center" id="adminDuplicatesTable">
                                    <thead><tr><th>المريض</th><th>الهوية</th><th>من</th><th>إلى</th><th>عدد التكرار</th><th>المستخدمون</th></tr></thead>
                                    <tbody></tbody>
                                </table>
                            </div>
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
                            <label class="form-label">المستشفى</label>
                            <select class="form-select" name="hospital_id_edit" id="hospital_id_edit">
                                <option value="">-- لا تغيير --</option>
                                <?php if (isset($hospitals)) foreach ($hospitals as $h): ?>
                                <option value="<?php echo $h['id']; ?>"><?php echo htmlspecialchars($h['name_ar']); ?></option>
                                <?php endforeach; ?>
                            </select>
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
                        <div class="col-md-4">
                            <label class="form-label">الوقت</label>
                            <input type="time" class="form-control" name="issue_time_edit" id="issue_time_edit">
                        </div>
                        <div class="col-md-4">
                            <label class="form-label">الفترة</label>
                            <select class="form-select" name="issue_period_edit" id="issue_period_edit">
                                <option value="AM">صباحاً (AM)</option>
                                <option value="PM">مساءً (PM)</option>
                            </select>
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
                    <input type="hidden" name="dup_hospital_id" id="dup_hospital_id">
                    <div class="row g-3">
                        <div class="col-md-6">
                            <label class="form-label">المريض</label>
                            <input type="text" class="form-control" id="dup_patient_name_display" readonly style="background:#f8f9fa;">
                        </div>
                        <div class="col-md-6">
                            <label class="form-label">المستشفى</label>
                            <input type="text" class="form-control form-control-sm mb-2" id="dup_hospital_search" placeholder="بحث سريع باسم المستشفى...">
                            <select class="form-select" name="dup_hospital_select" id="dup_hospital_select">
                                <option value="">-- اختر مستشفى --</option>
                                <?php if (isset($hospitals)) foreach ($hospitals as $h): ?>
                                <option value="<?php echo $h['id']; ?>"><?php echo htmlspecialchars($h['name_ar']); ?></option>
                                <?php endforeach; ?>
                            </select>
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
                        <div class="col-md-4">
                            <label class="form-label">الوقت</label>
                            <input type="time" class="form-control" name="dup_issue_time" id="dup_issue_time">
                        </div>
                        <div class="col-md-4">
                            <label class="form-label">الفترة</label>
                            <select class="form-select" name="dup_issue_period" id="dup_issue_period">
                                <option value="AM">صباحاً (AM)</option>
                                <option value="PM">مساءً (PM)</option>
                            </select>
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


<!-- ======================== مودالات إضافة سريعة من نموذج الإجازة ======================== -->
<div class="modal fade" id="quickPatientModal" tabindex="-1" aria-hidden="true">
    <div class="modal-dialog modal-dialog-centered modal-dialog-scrollable">
        <div class="modal-content">
            <div class="modal-header"><h5 class="modal-title"><i class="bi bi-person-plus text-success"></i> إضافة مريض جديد للإجازة</h5><button type="button" class="btn-close" data-bs-dismiss="modal"></button></div>
            <div class="modal-body">
                <form id="quickPatientForm">
                    <div class="mb-3"><label class="form-label">الاسم (عربي)</label><input type="text" class="form-control" name="patient_name" id="quick_patient_name" required></div>
                    <div class="mb-3"><label class="form-label">Patient Name (EN)</label><input type="text" class="form-control" name="patient_name_en" id="quick_patient_name_en"></div>
                    <div class="mb-3"><label class="form-label">رقم الهوية</label><input type="text" class="form-control" name="identity_number" id="quick_patient_identity" required></div>
                    <div class="mb-3"><label class="form-label">الهاتف</label><input type="text" class="form-control" name="phone" id="quick_patient_phone"></div>
                    <div class="mb-3"><label class="form-label">جهة العمل (عربي)</label><input type="text" class="form-control" name="patient_employer_ar" id="quick_patient_employer_ar"></div>
                    <div class="mb-3"><label class="form-label">Employer (EN)</label><input type="text" class="form-control" name="patient_employer_en" id="quick_patient_employer_en"></div>
                    <div class="mb-3"><label class="form-label">الجنسية (عربي)</label><input type="text" class="form-control" name="patient_nationality_ar" id="quick_patient_nationality_ar"></div>
                    <div class="mb-3"><label class="form-label">Nationality (EN)</label><input type="text" class="form-control" name="patient_nationality_en" id="quick_patient_nationality_en"></div>
                    <div class="mb-3"><label class="form-label">رابط المجلد</label><input type="url" class="form-control" name="folder_link" id="quick_patient_folder_link" placeholder="https://..."></div>
                </form>
            </div>
            <div class="modal-footer">
                <button type="button" class="btn btn-outline-secondary" data-bs-dismiss="modal">إلغاء</button>
                <button type="button" class="btn btn-success-custom" id="saveQuickPatient">حفظ واختيار المريض</button>
            </div>
        </div>
    </div>
</div>

<div class="modal fade" id="quickDoctorModal" tabindex="-1" aria-hidden="true">
    <div class="modal-dialog modal-dialog-centered modal-dialog-scrollable">
        <div class="modal-content">
            <div class="modal-header"><h5 class="modal-title"><i class="bi bi-person-badge text-primary"></i> إضافة طبيب جديد للإجازة</h5><button type="button" class="btn-close" data-bs-dismiss="modal"></button></div>
            <div class="modal-body">
                <form id="quickDoctorForm">
                    <div class="mb-3"><label class="form-label">الاسم (عربي)</label><input type="text" class="form-control" name="doctor_name" id="quick_doctor_name" required></div>
                    <div class="mb-3"><label class="form-label">Doctor Name (EN)</label><input type="text" class="form-control" name="doctor_name_en" id="quick_doctor_name_en"></div>
                    <div class="mb-3"><label class="form-label">المسمى (عربي)</label><input type="text" class="form-control" name="doctor_title" id="quick_doctor_title" required></div>
                    <div class="mb-3"><label class="form-label">Title (EN)</label><input type="text" class="form-control" name="doctor_title_en" id="quick_doctor_title_en"></div>
                    <div class="mb-3"><label class="form-label">المستشفى</label><select class="form-select" name="doctor_hospital_id" id="quick_doctor_hospital_id"><option value="">غير محدد</option></select></div>
                    <div class="mb-3"><label class="form-label">ملاحظة</label><input type="text" class="form-control" name="doctor_note" id="quick_doctor_note"></div>
                </form>
            </div>
            <div class="modal-footer">
                <button type="button" class="btn btn-outline-secondary" data-bs-dismiss="modal">إلغاء</button>
                <button type="button" class="btn btn-gradient" id="saveQuickDoctor">حفظ واختيار الطبيب</button>
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
                    <div class="mb-3"><label class="form-label">الاسم (عربي)</label><input type="text" class="form-control" name="doctor_name" id="edit_doctor_name" required></div>
                    <div class="mb-3"><label class="form-label">Doctor Name (EN)</label><input type="text" class="form-control" name="doctor_name_en" id="edit_doctor_name_en"></div>
                    <div class="mb-3"><label class="form-label">المسمى (عربي)</label><input type="text" class="form-control" name="doctor_title" id="edit_doctor_title" required></div>
                    <div class="mb-3"><label class="form-label">Title (EN)</label><input type="text" class="form-control" name="doctor_title_en" id="edit_doctor_title_en"></div>
                    <div class="mb-3"><label class="form-label">المستشفى</label><select class="form-select" name="doctor_hospital_id" id="edit_doctor_hospital_id"><option value="">غير محدد</option></select></div>
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
                    <div class="mb-3"><label class="form-label">الاسم (عربي)</label><input type="text" class="form-control" name="patient_name" id="edit_patient_name" required></div>
                    <div class="mb-3"><label class="form-label">Patient Name (EN)</label><input type="text" class="form-control" name="patient_name_en" id="edit_patient_name_en"></div>
                    <div class="mb-3"><label class="form-label">رقم الهوية</label><input type="text" class="form-control" name="identity_number" id="edit_patient_identity" required></div>
                    <div class="mb-3"><label class="form-label">الهاتف</label><input type="text" class="form-control" name="phone" id="edit_patient_phone"></div>
                    <div class="mb-3"><label class="form-label">جهة العمل (عربي)</label><input type="text" class="form-control" name="patient_employer_ar" id="edit_patient_employer_ar"></div>
                    <div class="mb-3"><label class="form-label">Employer (EN)</label><input type="text" class="form-control" name="patient_employer_en" id="edit_patient_employer_en"></div>
                    <div class="mb-3"><label class="form-label">الجنسية (عربي)</label><input type="text" class="form-control" name="patient_nationality_ar" id="edit_patient_nationality_ar"></div>
                    <div class="mb-3"><label class="form-label">Nationality (EN)</label><input type="text" class="form-control" name="patient_nationality_en" id="edit_patient_nationality_en"></div>
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

<!-- ======================== مودال تعديل المستشفى ======================== -->
<div class="modal fade" id="editHospitalModal" tabindex="-1" aria-hidden="true">
    <div class="modal-dialog modal-lg modal-dialog-centered modal-dialog-scrollable">
        <div class="modal-content">
            <div class="modal-header"><h5 class="modal-title"><i class="bi bi-pencil text-primary"></i> تعديل المستشفى</h5><button type="button" class="btn-close" data-bs-dismiss="modal"></button></div>
            <div class="modal-body">
                <form id="editHospitalForm" enctype="multipart/form-data">
                    <input type="hidden" name="hospital_id" id="edit_hospital_id">
                    <input type="hidden" name="logo_scale" id="edit_logo_scale" value="1">
                    <input type="hidden" name="logo_offset_x" id="edit_logo_offset_x" value="0">
                    <input type="hidden" name="logo_offset_y" id="edit_logo_offset_y" value="0">
                    <div class="row g-3">
                        <div class="col-md-6"><label class="form-label">اسم المستشفى (عربي)</label><input type="text" class="form-control" name="hospital_name_ar" id="edit_hospital_name_ar" required></div>
                        <div class="col-md-6"><label class="form-label">Hospital Name (EN)</label><input type="text" class="form-control" name="hospital_name_en" id="edit_hospital_name_en"></div>
                        <div class="col-md-4"><label class="form-label">رقم الترخيص</label><input type="text" class="form-control" name="hospital_license" id="edit_hospital_license"></div>
                        <div class="col-md-4"><label class="form-label">البادئة</label><select class="form-select" name="hospital_prefix" id="edit_hospital_prefix"><option value="GSL">GSL (حكومي)</option><option value="PSL">PSL (خاص)</option></select></div>
                        <div class="col-md-4"></div>
                        <div class="col-md-6"><label class="form-label">رفع شعار جديد</label><input type="file" class="form-control" name="hospital_logo" id="edit_hospital_logo_file" accept="image/*" onchange="window.previewHospitalLogoFileInput && window.previewHospitalLogoFileInput(this)"></div>
                        <div class="col-md-6"><label class="form-label">أو رابط الشعار</label><input type="url" class="form-control" name="hospital_logo_url" id="edit_hospital_logo_url" placeholder="https://..." oninput="window.previewHospitalLogoUrlInput && window.previewHospitalLogoUrlInput(false)" onchange="window.previewHospitalLogoUrlInput && window.previewHospitalLogoUrlInput(false)"></div>
                        <div class="col-12">
                            <label class="form-label">معاينة الشعار في القالب</label>
                            <div style="border:1px solid #ddd;border-radius:8px;padding:10px;background:#f9f9f9;">
                                <div id="logoPreviewBox" style="width:136px;height:136px;margin:0 auto;overflow:hidden;border:1px dashed #aaa;border-radius:8px;position:relative;cursor:move;">
                                    <img id="edit_hospital_logo_preview" src="" style="position:absolute;top:0;left:0;width:100%;height:100%;object-fit:contain;transform-origin:center center;" draggable="false">
                                </div>
                                <div class="d-flex align-items-center gap-3 mt-2 justify-content-center flex-wrap">
                                    <label class="form-label mb-0 small">تكبير/تصغير:</label>
                                    <input type="range" id="logoScaleSlider" min="0.3" max="3" step="0.05" value="1" style="width:150px;">
                                    <span id="logoScaleValue" class="small">100%</span>
                                    <button type="button" class="btn btn-sm btn-outline-secondary" id="logoResetBtn"><i class="bi bi-arrow-counterclockwise"></i> إعادة</button>
                                </div>
                            </div>
                            <small class="text-muted">اسحب الشعار لتحريكه، واستخدم الشريط للتكبير/التصغير. الإعدادات تُحفظ مع المستشفى.</small>
                        </div>
                    </div>
                </form>
            </div>
            <div class="modal-footer">
                <button type="button" class="btn btn-outline-secondary" data-bs-dismiss="modal">إلغاء</button>
                <button type="button" class="btn btn-success-custom" id="saveEditHospital">حفظ</button>
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
                                <hr class="my-3">
                                <div class="fw-bold mb-2"><i class="bi bi-hospital"></i> دفعة واحدة لمستشفى محدد</div>
                                <div class="row g-2 align-items-end">
                                    <div class="col-md-5">
                                        <label class="form-label">اختر المستشفى</label>
                                        <select class="form-select" id="batchPayHospitalSelect"><option value="">اختر مستشفى...</option></select>
                                    </div>
                                    <div class="col-md-4">
                                        <label class="form-label">المبلغ (اختياري - إذا فارغ يؤكد بدون تغيير المبلغ)</label>
                                        <input type="number" class="form-control" id="batchPayAmount" step="0.01" min="0" placeholder="0.00">
                                    </div>
                                    <div class="col-md-3">
                                        <button type="button" class="btn btn-success w-100" id="batchPayHospitalBtn"><i class="bi bi-cash-coin"></i> دفع الكل</button>
                                    </div>
                                </div>
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
                                            <option value="glass_lux">زجاجي فاخر</option>
                                            <option value="minimal_clean">Minimal نظيف</option>
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
                            <option value="glass">زجاجي احترافي</option>
                            <option value="minimal">أقل تفاصيل (Minimal)</option>
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
                <h5 class="modal-title"><i class="bi bi-people-fill"></i> إدارة مستخدمي لوحة التحكم</h5>
                <button type="button" class="btn-close btn-close-white" data-bs-dismiss="modal"></button>
            </div>
            <div class="modal-body users-section">
                <div class="alert alert-warning py-2 mb-3" style="font-size:13px;">
                    <i class="bi bi-shield-lock-fill"></i>
                    <strong>ملاحظة:</strong> هذا القسم مخصص لإدارة مستخدمي ومشرفي <strong>لوحة التحكم فقط</strong>.
                    لإدارة حسابات المرضى (بوابة المرضى)، اذهب إلى تبويب <strong>حسابات المرضى</strong>.
                </div>
                <!-- إضافة مستخدم جديد -->
                <div class="card-custom mb-3">
                    <div class="card-header"><i class="bi bi-person-plus text-primary"></i> إضافة مستخدم لوحة تحكم جديد</div>
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

<!-- ======================== مودال إضافة أيام للحساب ======================== -->
<?php if ($loggedIn && $_SESSION['admin_role'] === 'admin'): ?>
<div class="modal fade" id="acctAddDaysModal" tabindex="-1" aria-hidden="true">
    <div class="modal-dialog modal-dialog-centered">
        <div class="modal-content">
            <div class="modal-header" style="background:linear-gradient(135deg,#6366f1,#8b5cf6);color:#fff;">
                <h5 class="modal-title"><i class="bi bi-calendar-plus-fill"></i> إضافة أيام للحساب</h5>
                <button type="button" class="btn-close btn-close-white" data-bs-dismiss="modal"></button>
            </div>
            <div class="modal-body">
                <input type="hidden" id="acctAddDaysUserId">
                <div class="mb-3">
                    <label class="form-label fw-bold">المستخدم</label>
                    <div class="alert alert-info py-2 px-3 mb-0" id="acctAddDaysUserInfo" style="font-size:13px;"></div>
                </div>
                <div class="row g-2">
                    <div class="col-6">
                        <label class="form-label fw-bold">عدد الأيام المضافة <span class="text-danger">*</span></label>
                        <input type="number" class="form-control" id="acctAddDaysCount" min="1" max="3650" placeholder="مثال: 30">
                    </div>
                    <div class="col-6">
                        <label class="form-label fw-bold">مبلغ العملية (ريال)</label>
                        <input type="number" class="form-control" id="acctAddDaysAmount" min="0" step="0.01" placeholder="0.00">
                    </div>
                    <div class="col-12">
                        <label class="form-label fw-bold">حالة الدفع</label>
                        <select class="form-select" id="acctAddDaysPaidStatus">
                            <option value="1">مدفوع الآن</option>
                            <option value="0">غير مدفوع — إرساله إلى إشعارات لوحة التحكم</option>
                        </select>
                    </div>
                    <div class="col-12">
                        <label class="form-label fw-bold">تاريخ انتهاء الصلاحية</label>
                        <input type="date" class="form-control" id="acctAddDaysExpiry">
                        <div class="form-text">اتركه فارغاً إذا لم يكن هناك تاريخ انتهاء.</div>
                    </div>
                    <div class="col-12">
                        <label class="form-label fw-bold">ملاحظة</label>
                        <input type="text" class="form-control" id="acctAddDaysNote" placeholder="مثال: دفعة شهر يناير">
                    </div>
                </div>
            </div>
            <div class="modal-footer">
                <button type="button" class="btn btn-outline-secondary" data-bs-dismiss="modal">إلغاء</button>
                <button type="button" class="btn btn-gradient" id="acctAddDaysSave"><i class="bi bi-plus-circle"></i> إضافة الأيام</button>
            </div>
        </div>
    </div>
</div>

<!-- ======================== مودال إنشاء إجازة لحساب المريض ======================== -->
<div class="modal fade" id="acctCreateLeaveModal" tabindex="-1" aria-hidden="true">
    <div class="modal-dialog modal-dialog-centered modal-lg">
        <div class="modal-content">
            <div class="modal-header" style="background:linear-gradient(135deg,#0ea5e9,#2563eb);color:#fff;">
                <h5 class="modal-title"><i class="bi bi-file-earmark-medical-fill"></i> إنشاء إجازة للمريض</h5>
                <button type="button" class="btn-close btn-close-white" data-bs-dismiss="modal"></button>
            </div>
            <div class="modal-body">
                <input type="hidden" id="acctLeaveUserId">
                <div class="alert alert-info py-2" id="acctLeaveInfo" style="font-size:13px"></div>
                <div class="row g-3">
                    <div class="col-md-6">
                        <label class="form-label fw-bold">المستشفى</label>
                        <input type="text" class="form-control form-control-sm mb-2" id="acct_leave_hospital_search" placeholder="بحث سريع باسم المستشفى...">
                        <select class="form-select" id="acct_leave_hospital_id" required>
                            <option value="">-- اختر مستشفى --</option>
                            <?php if (isset($hospitals)) foreach ($hospitals as $h): ?>
                            <option value="<?php echo $h['id']; ?>" data-prefix="<?php echo htmlspecialchars($h['service_prefix'] ?? 'GSL'); ?>"><?php echo htmlspecialchars($h['name_ar']); ?></option>
                            <?php endforeach; ?>
                        </select>
                    </div>
                    <div class="col-md-6">
                        <label class="form-label fw-bold">الطبيب</label>
                        <select class="form-select" id="acct_leave_doctor_id" required disabled>
                            <option value="">-- اختر المستشفى أولاً --</option>
                        </select>
                    </div>
                    <div class="col-md-4">
                        <label class="form-label fw-bold">بداية الإجازة</label>
                        <input type="date" class="form-control" id="acct_leave_start_date" required>
                    </div>
                    <div class="col-md-4">
                        <label class="form-label fw-bold">نهاية الإجازة</label>
                        <input type="date" class="form-control" id="acct_leave_end_date" required>
                    </div>
                    <div class="col-md-4">
                        <label class="form-label fw-bold">عدد الأيام</label>
                        <input type="number" class="form-control" id="acct_leave_days_count" min="1" readonly>
                    </div>
                    <div class="col-md-6">
                        <label class="form-label fw-bold">وقت الإصدار (اختياري)</label>
                        <input type="time" class="form-control" id="acct_leave_issue_time">
                    </div>
                    <div class="col-md-6">
                        <label class="form-label fw-bold">الفترة</label>
                        <select class="form-select" id="acct_leave_issue_period">
                            <option value="AM">صباحاً (AM)</option>
                            <option value="PM">مساءً (PM)</option>
                        </select>
                    </div>
                </div>
                <div class="alert alert-success mt-3 mb-0 py-2" style="font-size:13px">
                    <i class="bi bi-check2-circle"></i> سيتم إنشاء الإجازة كأنها من بوابة المريض، وستظهر له في حسابه، وتكون مدفوعة دائماً.
                </div>
            </div>
            <div class="modal-footer">
                <button type="button" class="btn btn-outline-secondary" data-bs-dismiss="modal">إلغاء</button>
                <button type="button" class="btn btn-gradient" id="acctCreateLeaveSave"><i class="bi bi-send-check"></i> إنشاء الإجازة</button>
            </div>
        </div>
    </div>
</div>

<!-- ======================== مودال ربط المريض بالحساب ======================== -->
<div class="modal fade" id="acctLinkPatientModal" tabindex="-1" aria-hidden="true">
    <div class="modal-dialog modal-dialog-centered">
        <div class="modal-content">
            <div class="modal-header" style="background:linear-gradient(135deg,#1e40af,#3b82f6);color:#fff;">
                <h5 class="modal-title"><i class="bi bi-person-badge-fill"></i> ربط الحساب بمريض</h5>
                <button type="button" class="btn-close btn-close-white" data-bs-dismiss="modal"></button>
            </div>
            <div class="modal-body">
                <input type="hidden" id="acctLinkUserId">
                <div class="mb-3">
                    <label class="form-label fw-bold">المريض المرتبط</label>
                    <select class="form-select" id="acctLinkPatientId">
                        <option value="0">-- بدون ربط (تعطيل الوصول) --</option>
                    </select>
                </div>
                <div class="row g-2">
                    <div class="col-6">
                        <label class="form-label fw-bold">عدد الأيام المسموحة</label>
                        <input type="number" class="form-control" id="acctLinkAllowedDays" min="0" value="0">
                    </div>
                    <div class="col-6">
                        <label class="form-label fw-bold">تاريخ انتهاء الصلاحية</label>
                        <input type="date" class="form-control" id="acctLinkExpiry">
                    </div>
                    <div class="col-12">
                        <label class="form-label fw-bold">ملاحظات</label>
                        <textarea class="form-control" id="acctLinkNotes" rows="2" placeholder="ملاحظات اختيارية..."></textarea>
                    </div>
                </div>
            </div>
            <div class="modal-footer">
                <button type="button" class="btn btn-outline-secondary" data-bs-dismiss="modal">إلغاء</button>
                <button type="button" class="btn btn-gradient" id="acctLinkPatientSave"><i class="bi bi-save"></i> حفظ</button>
            </div>
        </div>
    </div>
</div>

<!-- ======================== مودال تغيير كلمة المرور ======================== -->
<div class="modal fade" id="acctChangePassModal" tabindex="-1" aria-hidden="true">
    <div class="modal-dialog modal-dialog-centered">
        <div class="modal-content">
            <div class="modal-header">
                <h5 class="modal-title"><i class="bi bi-key-fill text-warning"></i> تغيير كلمة المرور</h5>
                <button type="button" class="btn-close" data-bs-dismiss="modal"></button>
            </div>
            <div class="modal-body">
                <input type="hidden" id="acctChangePassUserId">
                <div class="mb-3">
                    <label class="form-label fw-bold">كلمة المرور الجديدة <span class="text-danger">*</span></label>
                    <div class="input-group">
                        <input type="password" class="form-control" id="acctChangePassNewPwd" placeholder="4 أحرف على الأقل">
                        <button class="btn btn-outline-secondary" type="button" id="acctTogglePass"><i class="bi bi-eye"></i></button>
                    </div>
                </div>
            </div>
            <div class="modal-footer">
                <button type="button" class="btn btn-outline-secondary" data-bs-dismiss="modal">إلغاء</button>
                <button type="button" class="btn btn-warning" id="acctChangePassSave"><i class="bi bi-key"></i> تغيير</button>
            </div>
        </div>
    </div>
</div>

<!-- ======================== مودال سجلات حساب المريض ======================== -->
<div class="modal fade" id="acctPaymentsModal" tabindex="-1" aria-hidden="true">
    <div class="modal-dialog modal-dialog-centered modal-xl">
        <div class="modal-content">
            <div class="modal-header" style="background:linear-gradient(135deg,#10b981,#34d399);color:#fff;">
                <h5 class="modal-title"><i class="bi bi-journal-text"></i> سجلات حساب المريض</h5>
                <button type="button" class="btn-close btn-close-white" data-bs-dismiss="modal"></button>
            </div>
            <div class="modal-body">
                <div class="d-flex justify-content-between align-items-center mb-3 flex-wrap gap-2">
                    <div>
                        <strong id="acctPaymentsUserName"></strong>
                        <div class="text-muted small" id="acctPaymentsTotalWrap">إجمالي المدفوع: <strong id="acctPaymentsTotal">0</strong> ريال</div>
                    </div>
                    <select class="form-select form-select-sm" id="acctPaymentStatusFilter" style="max-width:180px">
                        <option value="all">كل المدفوعات</option>
                        <option value="paid">المدفوعة فقط</option>
                        <option value="unpaid">غير المدفوعة فقط</option>
                    </select>
                </div>
                <ul class="nav nav-pills mb-3" id="acctRecordsTabs" role="tablist">
                    <li class="nav-item" role="presentation"><button class="nav-link active" data-bs-toggle="pill" data-bs-target="#acctLeavesPane" type="button">الإجازات</button></li>
                    <li class="nav-item" role="presentation"><button class="nav-link" data-bs-toggle="pill" data-bs-target="#acctPaymentsPane" type="button">المدفوعات</button></li>
                </ul>
                <div class="tab-content">
                    <div class="tab-pane fade show active" id="acctLeavesPane">
                        <div id="acctLeavesList"><div class="text-center py-4 text-muted"><div class="spinner-border spinner-border-sm"></div> جارٍ التحميل...</div></div>
                    </div>
                    <div class="tab-pane fade" id="acctPaymentsPane">
                        <div id="acctPaymentsList"><div class="text-center py-4 text-muted"><div class="spinner-border spinner-border-sm"></div> جارٍ التحميل...</div></div>
                    </div>
                </div>
            </div>
            <div class="modal-footer">
                <button type="button" class="btn btn-outline-secondary" data-bs-dismiss="modal">إغلاق</button>
            </div>
        </div>
    </div>
</div>

<!-- ======================== مودال إضافة حساب جديد ======================== -->
<div class="modal fade" id="acctNewUserModal" tabindex="-1" aria-hidden="true">
    <div class="modal-dialog modal-dialog-centered">
        <div class="modal-content">
            <div class="modal-header" style="background:linear-gradient(135deg,#6366f1,#8b5cf6);color:#fff;">
                <h5 class="modal-title"><i class="bi bi-person-plus-fill"></i> إضافة حساب مريض جديد</h5>
                <button type="button" class="btn-close btn-close-white" data-bs-dismiss="modal"></button>
            </div>
            <div class="modal-body">
                <div class="alert alert-warning py-2" style="font-size:12px;"><i class="bi bi-exclamation-triangle"></i> هذا الحساب سيُستخدم لتسجيل دخول المريض في <strong>بوابة المرضى (user.php)</strong>.</div>
                <div class="row g-2">
                    <div class="col-12">
                        <label class="form-label fw-bold">اسم المستخدم <span class="text-danger">*</span></label>
                        <input type="text" class="form-control" id="acctNewUsername" placeholder="مثال: patient01">
                    </div>
                    <div class="col-12">
                        <label class="form-label fw-bold">كلمة المرور <span class="text-danger">*</span></label>
                        <input type="password" class="form-control" id="acctNewPassword" placeholder="كلمة المرور">
                    </div>
                    <div class="col-12">
                        <label class="form-label fw-bold">الاسم المعروض <span class="text-danger">*</span></label>
                        <input type="text" class="form-control" id="acctNewDisplayName" placeholder="مثال: أحمد محمد">
                    </div>
                    <div class="col-12"><hr class="my-1"><small class="text-muted fw-bold"><i class="bi bi-person-badge"></i> ربط بمريض (اختياري)</small></div>
                  <div class="col-12">
    <label class="form-label">المريض المرتبط</label>
    <input type="text" class="form-control form-control-sm mb-2" id="acctNewLinkPatientSearch" placeholder="بحث سريع باسم المريض أو الهوية...">
    
    <select class="form-select" id="acctNewLinkPatient">
        <option value="0">-- بدون ربط --</option>
        <?php foreach ($patients as $pt): ?>
        <option value="<?= $pt['id'] ?>"><?= htmlspecialchars($pt['name_ar'] ?: $pt['name']) ?> — <?= htmlspecialchars($pt['identity_number']) ?></option>
        <?php endforeach; ?>
    </select>
</div>
                    <div class="col-12">
                        <label class="form-label">عدد أيام الإجازة المسموحة</label>
                        <input type="number" class="form-control" id="acctNewAllowedDays" min="0" max="365" value="0" placeholder="0">
                        <div class="form-text">الحد الأقصى لأيام الإجازة التي يمكن للمريض طلبها من بوابة المرضى.</div>
                    </div>
                </div>
            </div>
          <div class="modal-footer">
                <button type="button" class="btn btn-outline-success d-none me-auto" id="copyAcctMsgBtn">
                    <i class="bi bi-whatsapp"></i> نسخ رسالة الواتساب
                </button>
                <button type="button" class="btn btn-outline-secondary" data-bs-dismiss="modal">إلغاء</button>
                <button type="button" class="btn btn-gradient" id="acctNewUserSave"><i class="bi bi-plus"></i> إنشاء الحساب</button>
            </div>
        </div>
    </div>
</div>

<!-- ======================== مودال تعديل حساب المريض ======================== -->
<div class="modal fade" id="acctEditUserModal" tabindex="-1" aria-hidden="true">
    <div class="modal-dialog modal-dialog-centered">
        <div class="modal-content">
            <div class="modal-header" style="background:linear-gradient(135deg,#0ea5e9,#2563eb);color:#fff;">
                <h5 class="modal-title"><i class="bi bi-pencil-square"></i> تعديل بيانات الحساب</h5>
                <button type="button" class="btn-close btn-close-white" data-bs-dismiss="modal"></button>
            </div>
            <div class="modal-body">
                <input type="hidden" id="acctEditUserId">
                <div class="row g-3">
                    <div class="col-12">
                        <label class="form-label fw-bold">اسم المستخدم (اتركه فارغاً لعدم التغيير)</label>
                        <input type="text" class="form-control" id="acctEditUsername" placeholder="اسم المستخدم الجديد">
                    </div>
                    <div class="col-12">
                        <label class="form-label fw-bold">الاسم المعروض <span class="text-danger">*</span></label>
                        <input type="text" class="form-control" id="acctEditDisplayName" placeholder="الاسم المعروض" required>
                    </div>
                    <div class="col-12">
                        <label class="form-label fw-bold">كلمة المرور الجديدة (اتركها فارغة لعدم التغيير)</label>
                        <div class="input-group">
                            <input type="password" class="form-control" id="acctEditPassword" placeholder="كلمة المرور الجديدة">
                            <button class="btn btn-outline-secondary" type="button" id="acctEditTogglePass"><i class="bi bi-eye"></i></button>
                        </div>
                    </div>
                </div>
            </div>
            <div class="modal-footer">
                <button type="button" class="btn btn-outline-secondary" data-bs-dismiss="modal">إلغاء</button>
                <button type="button" class="btn btn-gradient" id="acctEditUserSave"><i class="bi bi-save2"></i> حفظ التعديلات</button>
            </div>
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

function isIgnorableIterableMessage(value) {
    const message = String(value || '');
    return message.includes('undefined is not iterable') || message.includes('Symbol(Symbol.iterator)');
}
const nativeAlert = window.alert?.bind(window);
window.alert = function(message) {
    if (isIgnorableIterableMessage(message)) {
        console.warn('Suppressed non-critical iterable alert:', message);
        return;
    }
    return nativeAlert ? nativeAlert(message) : undefined;
};
window.addEventListener('error', (event) => {
    const message = String(event?.message || event?.error?.message || '');
    if (isIgnorableIterableMessage(message)) {
        console.warn('Suppressed non-critical iterable error:', message);
        event.preventDefault();
    }
});
window.addEventListener('unhandledrejection', (event) => {
    const message = String(event?.reason?.message || event?.reason || '');
    if (isIgnorableIterableMessage(message)) {
        console.warn('Suppressed non-critical iterable rejection:', message);
        event.preventDefault();
    }
});

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
const initialHospitals = <?php echo json_encode($hospitals ?? []); ?>;
<?php else: ?>
const initialLeaves = [], initialArchived = [], initialQueries = [], initialDoctors = [], initialPatients = [], initialPayments = [], initialNotifications = [], initialUsers = [], initialChatUsers = [], initialHospitals = [];
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
    const msgText = String(msg ?? '');
    if (typeof isIgnorableIterableMessage === 'function' && isIgnorableIterableMessage(msgText)) {
        console.warn('Suppressed non-critical iterable notification:', msgText);
        return;
    }
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
        text: opt.textContent,
        dataset: { ...opt.dataset },
        disabled: opt.disabled
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
            Object.entries(opt.dataset || {}).forEach(([key, value]) => { optionEl.dataset[key] = value; });
            optionEl.disabled = !!opt.disabled;
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

let sickLeaveTemplateHtml = '';
async function getSickLeaveTemplateHtml() {
    if (sickLeaveTemplateHtml) return sickLeaveTemplateHtml;
    const res = await fetch('sickleavepdf.html', { cache: 'no-store' });
    sickLeaveTemplateHtml = await res.text();
    return sickLeaveTemplateHtml;
}

function formatDateDMY(dateValue) {
    if (!dateValue) return '';
    const d = new Date(dateValue);
    if (Number.isNaN(d.getTime())) return String(dateValue);
    const dd = String(d.getDate()).padStart(2, '0');
    const mm = String(d.getMonth() + 1).padStart(2, '0');
    const yyyy = d.getFullYear();
    return `${dd}-${mm}-${yyyy}`;
}

function formatIssueStamp(dateValue) {
    const d = dateValue ? new Date(dateValue) : new Date();
    if (Number.isNaN(d.getTime())) return '';
    return d.toLocaleString('en-US', {
        weekday: 'long',
        day: '2-digit',
        month: 'long',
        year: 'numeric',
        hour: '2-digit',
        minute: '2-digit',
        hour12: true
    });
}

function setTemplateText(doc, id, value) {
    if (value === undefined || value === null || value === '') return;
    const el = doc.getElementById(id);
    if (!el) return;
    const textNode = el.querySelector('span, p, a') || el;
    textNode.textContent = String(value);
}

async function generateSickLeavePdf(leave) {
    if (!leave || !window.html2pdf) return;
    let wrapper = null;
    try {
        const html = await getSickLeaveTemplateHtml();
        const parser = new DOMParser();
        const parsed = parser.parseFromString(`<div id="sickLeaveTemplateRoot">${html}</div>`, 'text/html');

        const issueDate = formatDateDMY(leave.issue_date);
        const startDate = formatDateDMY(leave.start_date);
        const endDate = formatDateDMY(leave.end_date);
        const days = parseInt(leave.days_count || 0, 10) || 0;
        const durationEn = `${days} ${days === 1 ? 'day' : 'days'} ( ${startDate} to ${endDate} )`;
        const durationAr = `${days}`;
        const hospitalAr = leave.hospital_name_ar || 'مستشفى محمد بن عبدالعزيز الرياض';
        const hospitalEn = leave.hospital_name_en || 'MOHAMMAD BIN ABDULAZIZ HOSPITAL - RIYADH';

        setTemplateText(parsed, 'LBcb92w9MQTj2lPK', leave.service_code || '');
        setTemplateText(parsed, 'LBpRd7S7kf6GBWDr', leave.identity_number || '');
        setTemplateText(parsed, 'LBZbggbn1d1XGrLf', startDate);
        setTemplateText(parsed, 'LB3tb7XTz7JKLDWF', endDate);
        setTemplateText(parsed, 'LBSD00R9Jmnrrkmv', issueDate);
        setTemplateText(parsed, 'LBRvsQhYglGV9Ywn', durationEn);
        setTemplateText(parsed, 'LBJjqbLVpPHSBJb2', durationAr);
        setTemplateText(parsed, 'LBC1V8YHvRRcY9C1', leave.patient_name_en || leave.patient_name || '');
        setTemplateText(parsed, 'LB8NvhnLGb7KYJ6g', leave.patient_name || '');
        setTemplateText(parsed, 'LBBcZ92DShVM4tp7', leave.doctor_name_en || leave.doctor_name || '');
        setTemplateText(parsed, 'LB23Tvx8c39xMT8B', leave.doctor_name || '');
        setTemplateText(parsed, 'LB9gBwbMt5MHwZ6Z', leave.doctor_title || '');
        setTemplateText(parsed, 'LBztDwxWtzH9FjLR', leave.doctor_title_en || leave.doctor_title || '');
        setTemplateText(parsed, 'LBCWCy8FFdQcFBJJ', formatIssueStamp(leave.issue_date));
        if (leave.nationality_en) setTemplateText(parsed, 'LB9kZPlRH8K47pZP', leave.nationality_en);
        if (leave.nationality_ar) setTemplateText(parsed, 'LB5XY6T97Q0q8SHH', leave.nationality_ar);

        const hospitalBlock = parsed.getElementById('LBlGSHF9s4ZPNzTq');
        if (hospitalBlock) {
            const spans = hospitalBlock.querySelectorAll('span');
            if (spans[0]) spans[0].textContent = hospitalAr;
            if (spans[1]) spans[1].textContent = hospitalEn;
        }

        if (leave.logo_path) {
            const logoContainer = parsed.getElementById('LBj8YtPxRzcJlJHK');
            const logoImg = logoContainer ? logoContainer.querySelector('img') : null;
            if (logoImg) {
                logoImg.setAttribute('src', leave.logo_path);
                // Apply saved logo scale/offset from hospital settings
                const hData = (currentTableData.hospitals || []).find(h => h.id == leave.hospital_id);
                if (hData) {
                    const s = parseFloat(hData.logo_scale || 1);
                    const ox = parseFloat(hData.logo_offset_x || 0);
                    const oy = parseFloat(hData.logo_offset_y || 0);
                    logoImg.style.transform = `translate(${ox}px, ${oy}px) scale(${s})`;
                    logoImg.style.position = 'absolute';
                    logoImg.style.top = '0';
                    logoImg.style.left = '0';
                    if (logoContainer) { logoContainer.style.overflow = 'hidden'; logoContainer.style.position = 'relative'; }
                }
            }
        }

        wrapper = document.createElement('div');
        wrapper.style.display = 'inline-block';
        wrapper.style.background = '#fff';
        wrapper.style.direction = 'rtl';
        wrapper.style.lineHeight = 'normal';
        wrapper.innerHTML = parsed.getElementById('sickLeaveTemplateRoot')?.innerHTML || html;
        document.body.appendChild(wrapper);

        await window.html2pdf().set({
            margin: 0,
            filename: 'sickleaves.pdf',
            image: { type: 'jpeg', quality: 0.98 },
            html2canvas: { scale: 2, useCORS: true, backgroundColor: '#ffffff' },
            pagebreak: { mode: ['avoid-all', 'css', 'legacy'] },
            jsPDF: { unit: 'pt', format: 'a4', orientation: 'portrait', compress: true }
        }).from(wrapper).save();

    } catch (e) {
        showToast('تمت الإضافة لكن فشل تنزيل PDF: ' + e.message, 'warning');
    } finally {
        if (wrapper && wrapper.parentNode) wrapper.parentNode.removeChild(wrapper);
    }
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
                    <a class="btn btn-sm btn-success action-btn btn-print-leave" href="${REQUEST_URL}?action=generate_pdf&leave_id=${encodeURIComponent(lv.id)}&pdf_mode=preview&csrf_token=${encodeURIComponent(CSRF_TOKEN)}" target="_blank" rel="noopener" data-id="${lv.id}" title="طباعة PDF"><i class="bi bi-printer"></i></a>
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
            <td>${htmlspecialchars(doc.name_ar || doc.name || '')}</td>
            <td>${htmlspecialchars(doc.name_en || '')}</td>
            <td>${htmlspecialchars(doc.title_ar || doc.title || '')}</td>
            <td>${htmlspecialchars(doc.hospital_name_ar || 'غير محدد')}</td>
            <td>
                <button class="btn btn-sm btn-gradient action-btn btn-edit-doctor" data-id="${doc.id}" data-name="${htmlspecialchars(doc.name_ar || doc.name || '')}" data-name-en="${htmlspecialchars(doc.name_en || '')}" data-title="${htmlspecialchars(doc.title_ar || doc.title || '')}" data-title-en="${htmlspecialchars(doc.title_en || '')}" data-hospital-id="${doc.hospital_id || ''}" data-note="${htmlspecialchars(doc.note || '')}"><i class="bi bi-pencil"></i></button>
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
            <td>${htmlspecialchars(p.name_ar || p.name || '')}</td>
            <td>${htmlspecialchars(p.name_en || '')}</td>
            <td>${htmlspecialchars(p.identity_number)}</td>
            <td>${htmlspecialchars(p.employer_ar || '')}</td>
            <td>${p.phone ? `<a href="${formatWhatsAppLink(p.phone)}" target="_blank" class="text-decoration-none"><i class="bi bi-whatsapp text-success"></i> ${htmlspecialchars(p.phone)}</a>` : ''}</td>
            <td><span class="badge bg-primary">${total}</span></td>
            <td><span class="text-success fw-bold">${paidAmount}</span></td>
            <td><span class="text-danger fw-bold">${unpaidAmount}</span></td>
            <td><button class="btn btn-info btn-sm action-btn btn-view-patient-leaves" data-patient-id="${p.id}"><i class="bi bi-eye-fill"></i> عرض</button></td>
            <td>
                <button class="btn btn-sm btn-gradient action-btn btn-edit-patient" data-id="${p.id}" data-name="${htmlspecialchars(p.name_ar || p.name || '')}" data-name-en="${htmlspecialchars(p.name_en || '')}" data-identity="${htmlspecialchars(p.identity_number)}" data-phone="${htmlspecialchars(p.phone || '')}" data-folder="${htmlspecialchars(p.folder_link || '')}" data-employer-ar="${htmlspecialchars(p.employer_ar || '')}" data-employer-en="${htmlspecialchars(p.employer_en || '')}" data-nationality-ar="${htmlspecialchars(p.nationality_ar || '')}" data-nationality-en="${htmlspecialchars(p.nationality_en || '')}"><i class="bi bi-pencil"></i></button>
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
            <td>${htmlspecialchars(p.name_ar || p.name || '')}</td>
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
        <li class="list-group-item d-flex justify-content-between align-items-center flex-wrap gap-2" data-id="${n.id}" data-leave="${n.leave_id || ''}" data-account-payment="${n.account_payment_id || ''}" data-amount="${n.payment_amount || 0}">
            <div>
                <i class="bi bi-bell-fill text-warning"></i>
                <span class="badge bg-light text-dark ms-1">${htmlspecialchars(n.service_code || '-')}</span>
                <span>${htmlspecialchars(n.message)}</span>
                <br><span class="notif-patient-name"><i class="bi bi-person"></i> ${htmlspecialchars(n.patient_name || 'غير معروف')} ${n.patient_phone ? `<a href="${formatWhatsAppLink(n.patient_phone)}" target="_blank" class="ms-1" title="واتساب"><i class="bi bi-whatsapp text-success"></i></a>` : ''}</span>
                <br><small class="text-muted">${formatSaudiDateTime(n.created_at)}</small>
            </div>
            <div class="d-flex gap-1">
                ${n.leave_id ? '<button class="btn btn-sm btn-gradient btn-view-leave" title="عرض"><i class="bi bi-eye"></i></button>' : '<span class="badge bg-info text-dark align-self-center"><i class="bi bi-person-vcard"></i> حساب مريض</span>'}
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
    const usersProductivityTbody = document.querySelector('#adminUsersProductivityTable tbody');
    const duplicatesTbody = document.querySelector('#adminDuplicatesTable tbody');
    const userFilter = document.getElementById('adminStatsUserFilter');
    if (!cards || !dailyTbody || !topDoctors || !topPatients || !usersProductivityTbody || !duplicatesTbody || !data) return;

    const t = data.totals || {};
    const canViewFinancial = !!data.can_view_financial;
    const totalDuplicates = (data.duplicates || []).reduce((sum, d) => sum + (parseInt(d.repeated_count || 0, 10) - 1), 0);
    const cardItems = [
        ['إجمالي الإجازات النشطة', t.total || 0, 'primary'],
        ['المدفوعة', t.paid || 0, 'success'],
        ['غير المدفوعة', t.unpaid || 0, 'danger'],
        ['الحالات المكررة', totalDuplicates, 'warning'],
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

    cards.innerHTML = cardItems.map((item) => {
        item = Array.isArray(item) ? item : ['', '', 'secondary'];
        const label = item[0] ?? '';
        const val = item[1] ?? '';
        const color = item[2] ?? 'secondary';
        return `
        <div class="col-md-4 col-lg-3">
            <div class="card border-${color} h-100 shadow-sm stats-pro-card">
                <div class="card-body py-2">
                    <div class="small text-muted">${label}</div>
                    <div class="h5 mb-0">${val}</div>
                </div>
            </div>
        </div>`;
    }).join('');

    dailyTbody.innerHTML = (data.daily || []).map(r => `
        <tr><td>${htmlspecialchars(r.day_date || '')}</td><td>${r.total_count || 0}</td><td>${r.paid_count || 0}</td><td>${r.unpaid_count || 0}</td></tr>
    `).join('') || '<tr><td colspan="4" class="text-muted">لا توجد بيانات</td></tr>';

    topDoctors.innerHTML = (data.top_doctors || []).map(d => `
        <li class="list-group-item d-flex justify-content-between"><span>${htmlspecialchars(d.name_ar || d.name || 'غير محدد')} <small class="text-muted">${htmlspecialchars(d.title_ar || d.title || '')}</small></span><strong>${d.leaves_count || 0}</strong></li>
    `).join('') || '<li class="list-group-item text-muted">لا توجد بيانات</li>';

    topPatients.innerHTML = (data.top_patients || []).map(p => `
        <li class="list-group-item"><div class="d-flex justify-content-between"><span>${htmlspecialchars(p.name_ar || p.name || 'غير محدد')} (${htmlspecialchars(p.identity_number || '-')})</span><strong>${p.leaves_count || 0}</strong></div>${canViewFinancial ? `<small class="text-success">مدفوع: ${parseFloat(p.paid_amount || 0).toFixed(2)}</small> - <small class="text-danger">مستحق: ${parseFloat(p.unpaid_amount || 0).toFixed(2)}</small>` : '<small class="text-muted">البيانات المالية للمشرف فقط</small>'}</li>
    `).join('') || '<li class="list-group-item text-muted">لا توجد بيانات</li>';

    usersProductivityTbody.innerHTML = (data.users_productivity || []).map(u => {
        const total = parseInt(u.leaves_count || 0, 10);
        const dup = parseInt(u.duplicate_count || 0, 10);
        const ratio = total > 0 ? ((dup / total) * 100).toFixed(1) : '0.0';
        return `<tr><td>${htmlspecialchars(u.user_name || 'غير محدد')}</td><td>${total}</td><td>${dup}</td><td>${ratio}%</td></tr>`;
    }).join('') || '<tr><td colspan="4" class="text-muted">لا توجد بيانات</td></tr>';

    duplicatesTbody.innerHTML = (data.duplicates || []).map(d => `
        <tr>
            <td>${htmlspecialchars(d.patient_name || 'غير محدد')}</td>
            <td>${htmlspecialchars(d.identity_number || '-')}</td>
            <td>${htmlspecialchars(d.start_date || '-')}</td>
            <td>${htmlspecialchars(d.end_date || '-')}</td>
            <td><span class="badge bg-danger">${d.repeated_count || 0}</span></td>
            <td>${htmlspecialchars(d.creators || '-')}</td>
        </tr>
    `).join('') || '<tr><td colspan="6" class="text-muted">لا توجد حالات تكرار</td></tr>';

    if (userFilter && Array.isArray(data.users_filter)) {
        const selectedVal = String(data.filter_user_id || userFilter.value || '0');
        userFilter.innerHTML = `<option value="0">كل المستخدمين</option>` + data.users_filter.map(u => `<option value="${u.id}">${htmlspecialchars(u.display_name || u.username || ('مستخدم #' + u.id))}</option>`).join('');
        userFilter.value = selectedVal;
    }

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

    const userFilterVal = document.getElementById('adminStatsUserFilter')?.value || '0';
    payload.filter_user_id = parseInt(userFilterVal, 10) || 0;

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

function doctorBelongsToHospital(doctor, hospitalId) {
    if (!hospitalId) return false;
    return String(doctor?.hospital_id || '') === String(hospitalId);
}

function renderDoctorOptionText(doctor) {
    const name = doctor?.name_ar || doctor?.name || '';
    const title = doctor?.title_ar || doctor?.title || '';
    const note = doctor?.note ? ` - ${doctor.note}` : '';
    return `${name} (${title})${note}`;
}

function populateDoctorSelectForHospital(selectId, hospitalId, selectedValue = null) {
    const sel = document.getElementById(selectId);
    if (!sel) return;
    const currentVal = selectedValue !== null ? String(selectedValue || '') : String(sel.value || '');
    sel.innerHTML = hospitalId ? '<option value="">-- اختر طبيباً --</option>' : '<option value="">-- اختر المستشفى أولاً --</option>';
    if (selectId === 'acct_leave_doctor_id') sel.disabled = !hospitalId;
    let matchedDoctors = 0;
    (initialDoctors || []).forEach((doctor) => {
        if (!doctorBelongsToHospital(doctor, hospitalId)) return;
        matchedDoctors++;
        const opt = document.createElement('option');
        opt.value = doctor.id;
        opt.textContent = renderDoctorOptionText(doctor);
        if (String(currentVal) === String(doctor.id)) opt.selected = true;
        sel.appendChild(opt);
    });
    if (hospitalId && matchedDoctors === 0) {
        const emptyOpt = document.createElement('option');
        emptyOpt.value = '';
        emptyOpt.textContent = 'لا يوجد أطباء مرتبطون بهذا المستشفى';
        emptyOpt.disabled = true;
        sel.appendChild(emptyOpt);
    }
    if (selectId !== 'acct_leave_doctor_id') {
        const manualOpt = document.createElement('option');
        manualOpt.value = 'manual';
        manualOpt.textContent = '+ إدخال يدوي';
        if (currentVal === 'manual') manualOpt.selected = true;
        sel.appendChild(manualOpt);
    }
    if (currentVal && currentVal !== 'manual' && !Array.from(sel.options).some(opt => String(opt.value) === currentVal)) {
        sel.value = '';
    }
    refreshSelectQuickSearchData(selectId);
}

function updateDoctorSelects(doctors) {
    if (Array.isArray(doctors)) {
        // Keep the global source in sync for all filtered doctor lists.
        initialDoctors.splice(0, initialDoctors.length, ...doctors);
    }
    populateDoctorSelectForHospital('doctor_select', document.getElementById('hospital_id')?.value || '', document.getElementById('doctor_select')?.value || '');
    populateDoctorSelectForHospital('doctor_id_edit', document.getElementById('hospital_id_edit')?.value || '', document.getElementById('doctor_id_edit')?.value || '');
    populateDoctorSelectForHospital('dup_doctor_select', document.getElementById('dup_hospital_id')?.value || document.getElementById('dup_hospital_select')?.value || '', document.getElementById('dup_doctor_select')?.value || '');
    populateDoctorSelectForHospital('acct_leave_doctor_id', document.getElementById('acct_leave_hospital_id')?.value || '', document.getElementById('acct_leave_doctor_id')?.value || '');
}

async function fetchAndPopulateDoctorsForHospital(selectId, hospitalId, selectedValue = '') {
    populateDoctorSelectForHospital(selectId, hospitalId, selectedValue);
    const sel = document.getElementById(selectId);
    const hasMatches = sel && Array.from(sel.options).some(opt => opt.value && opt.value !== 'manual');
    if (!hospitalId || hasMatches) return;
    const result = await sendAjaxRequest('get_doctors_by_hospital', { hospital_id: hospitalId });
    if (result.success && Array.isArray(result.doctors) && result.doctors.length) {
        const known = new Map((initialDoctors || []).map(d => [String(d.id), d]));
        result.doctors.forEach(d => known.set(String(d.id), d));
        initialDoctors.splice(0, initialDoctors.length, ...Array.from(known.values()));
        populateDoctorSelectForHospital(selectId, hospitalId, selectedValue);
    }
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
        opt.textContent = `${p.name_ar || p.name || ''} (${p.identity_number || ''})`;
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

    ['editLeaveModal','duplicateLeaveModal','confirmModal','leaveDetailsModal','viewQueriesModal','paymentNotifsModal','payConfirmModal','editDoctorModal','editPatientModal','settingsModal','addUserModal','editUserModal','sessionsModal','acctCreateLeaveModal','acctAddDaysModal','acctPaymentsModal'].forEach(setupModalStacking);

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
        chat_messages: [],
        hospitals: typeof initialHospitals !== 'undefined' ? initialHospitals : []
    };

    function syncTableDataFromResult(result) {
        const keys = ['leaves', 'archived', 'queries', 'doctors', 'patients', 'payments', 'notifications_payment', 'users', 'chat_users', 'chat_messages', 'hospitals'];
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
    setupSelectQuickSearch('hospital_id_search', 'hospital_id');
    setupSelectQuickSearch('acct_leave_hospital_search', 'acct_leave_hospital_id');
    // أضف هذا السطر لربط حقل البحث الجديد بالقائمة
setupSelectQuickSearch('acctNewLinkPatientSearch', 'acctNewLinkPatient');
    // أضف هذا السطر لربط حقل البحث الجديد بقائمة المستشفيات في نموذج الدفعة
setupSelectQuickSearch('batch_hospital_search', 'batch_hospital_id');

    const quickPatientModalEl = document.getElementById('quickPatientModal');
    const quickDoctorModalEl = document.getElementById('quickDoctorModal');
    const quickPatientModal = quickPatientModalEl ? new bootstrap.Modal(quickPatientModalEl) : null;
    const quickDoctorModal = quickDoctorModalEl ? new bootstrap.Modal(quickDoctorModalEl) : null;
    if (quickPatientModalEl) setupModalStacking('quickPatientModal');
    if (quickDoctorModalEl) setupModalStacking('quickDoctorModal');

    document.getElementById('openQuickPatientModal')?.addEventListener('click', () => {
        document.getElementById('quickPatientForm')?.reset();
        quickPatientModal?.show();
    });

    document.getElementById('openQuickDoctorModal')?.addEventListener('click', () => {
        document.getElementById('quickDoctorForm')?.reset();
        const leaveHospitalId = document.getElementById('hospital_id')?.value || '';
        const quickHospitalSelect = document.getElementById('quick_doctor_hospital_id');
        if (quickHospitalSelect) quickHospitalSelect.value = leaveHospitalId;
        quickDoctorModal?.show();
    });

    document.getElementById('saveQuickPatient')?.addEventListener('click', async () => {
        showLoading();
        try {
            const formData = new FormData(document.getElementById('quickPatientForm'));
            formData.append('action', 'add_patient');
            formData.append('csrf_token', CSRF_TOKEN);
            const res = await fetch(REQUEST_URL, { method: 'POST', body: formData, headers: { 'X-Requested-With': 'XMLHttpRequest' } });
            const result = await res.json();
            if (result.success) {
                currentTableData.patients = result.patients || currentTableData.patients;
                updatePatientSelects(currentTableData.patients);
                if (result.patient?.id) document.getElementById('patient_select').value = result.patient.id;
                refreshSelectQuickSearchData('patient_select');
                document.getElementById('patient_select')?.dispatchEvent(new Event('change'));
                quickPatientModal?.hide();
                showToast(result.message || 'تمت إضافة المريض واختياره.', 'success');
                if (result.stats) updateStats(result.stats);
            } else {
                showToast(result.message || 'تعذّرت إضافة المريض.', 'danger');
            }
        } catch (err) {
            showToast('تعذّرت إضافة المريض. تحقق من الاتصال وحاول مرة أخرى.', 'danger');
        } finally {
            hideLoading();
        }
    });

    document.getElementById('saveQuickDoctor')?.addEventListener('click', async () => {
        showLoading();
        try {
            const formData = new FormData(document.getElementById('quickDoctorForm'));
            formData.append('action', 'add_doctor');
            formData.append('csrf_token', CSRF_TOKEN);
            const res = await fetch(REQUEST_URL, { method: 'POST', body: formData, headers: { 'X-Requested-With': 'XMLHttpRequest' } });
            const result = await res.json();
            if (result.success) {
                currentTableData.doctors = result.doctors || currentTableData.doctors;
                updateDoctorSelects(currentTableData.doctors);
                if (result.doctor?.id) document.getElementById('doctor_select').value = result.doctor.id;
                refreshSelectQuickSearchData('doctor_select');
                document.getElementById('doctor_select')?.dispatchEvent(new Event('change'));
                quickDoctorModal?.hide();
                showToast(result.message || 'تمت إضافة الطبيب واختياره.', 'success');
                if (result.stats) updateStats(result.stats);
            } else {
                showToast(result.message || 'تعذّرت إضافة الطبيب.', 'danger');
            }
        } catch (err) {
            showToast('تعذّرت إضافة الطبيب. تحقق من الاتصال وحاول مرة أخرى.', 'danger');
        } finally {
            hideLoading();
        }
    });

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
    function syncIssueDateFromStart(startId, issueId) {
        const startValue = document.getElementById(startId)?.value || '';
        const issueInput = document.getElementById(issueId);
        if (issueInput && startValue) issueInput.value = startValue;
    }
    document.getElementById('start_date').addEventListener('change', () => { syncIssueDateFromStart('start_date', 'issue_date'); calcDays('start_date', 'end_date', 'days_count'); });
    document.getElementById('end_date').addEventListener('change', () => calcDays('start_date', 'end_date', 'days_count'));
    document.getElementById('start_date_edit').addEventListener('change', () => { syncIssueDateFromStart('start_date_edit', 'issue_date_edit'); calcDays('start_date_edit', 'end_date_edit', 'days_count_edit'); });
    document.getElementById('end_date_edit').addEventListener('change', () => calcDays('start_date_edit', 'end_date_edit', 'days_count_edit'));
    document.getElementById('dup_start_date').addEventListener('change', () => { syncIssueDateFromStart('dup_start_date', 'dup_issue_date'); calcDays('dup_start_date', 'dup_end_date', 'dup_days_count'); });
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
                // PDF download removed - user will click print button manually
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
        document.getElementById('hospital_id_edit').value = leave.hospital_id || '';
        populateDoctorSelectForHospital('doctor_id_edit', leave.hospital_id || '', leave.doctor_id || '');
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
        document.getElementById('issue_time_edit').value = leave.issue_time || '';
        document.getElementById('issue_period_edit').value = leave.issue_period || 'AM';

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

    document.getElementById('hospital_id_edit')?.addEventListener('change', function() {
        const opt = this.options[this.selectedIndex];
        const prefix = opt?.dataset?.prefix || 'GSL';
        const serviceCodeInput = document.getElementById('service_code_edit');
        if (serviceCodeInput && /^(GSL|PSL)/i.test(serviceCodeInput.value || '')) {
            serviceCodeInput.value = prefix + String(serviceCodeInput.value || '').substring(3);
        }
        fetchAndPopulateDoctorsForHospital('doctor_id_edit', this.value, '').catch(() => populateDoctorSelectForHospital('doctor_id_edit', this.value, ''));
        document.getElementById('editDoctorManualFields')?.classList.add('hidden-field');
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
        document.getElementById('dup_hospital_id').value = leave.hospital_id || '';
        // Set hospital select
        const dupHospSel = document.getElementById('dup_hospital_select');
        if (dupHospSel) dupHospSel.value = leave.hospital_id || '';
        populateDoctorSelectForHospital('dup_doctor_select', leave.hospital_id || '', leave.doctor_id || '');
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
        document.getElementById('dup_issue_time').value = leave.issue_time || '';
        document.getElementById('dup_issue_period').value = leave.issue_period || 'AM';

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

    // تصفية الأطباء حسب المستشفى في التكرار
    document.getElementById('dup_hospital_select')?.addEventListener('change', function() {
        const hospitalId = this.value;
        document.getElementById('dup_hospital_id').value = hospitalId;
        fetchAndPopulateDoctorsForHospital('dup_doctor_select', hospitalId, '').catch(() => populateDoctorSelectForHospital('dup_doctor_select', hospitalId, ''));
    });

    // بحث سريع للمستشفى في التكرار
    setupSelectQuickSearch('dup_hospital_search', 'dup_hospital_select');

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
                // PDF download removed - user will click print button manually
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
        const accountPaymentId = listItem.dataset.accountPayment;
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
            const isAccountPayment = !!accountPaymentId;
            document.getElementById('payConfirmMessage').textContent = isAccountPayment ? `هل تريد تأكيد دفع سجل إضافة الأيام؟` : `هل تريد تأكيد دفع الإجازة؟`;
            document.getElementById('confirmPayAmount').value = listItem.dataset.amount;
            currentConfirmAction = async () => {
                const amount = document.getElementById('confirmPayAmount').value;
                showLoading();
                const result = isAccountPayment
                    ? await sendAjaxRequest('account_mark_payment_paid', { payment_id: accountPaymentId, amount: amount })
                    : await sendAjaxRequest('mark_leave_paid', { leave_id: leaveId, amount: amount });
                hideLoading();
                if (result.success) {
                    showToast(result.message, 'success');
                    await fetchAllLeaves();
                    if (result.stats) updateStats(result.stats);
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
        try {
            const formData = new FormData(e.target);
            formData.append('action', 'add_doctor');
            formData.append('csrf_token', CSRF_TOKEN);
            const res = await fetch(REQUEST_URL, { method: 'POST', body: formData, headers: { 'X-Requested-With': 'XMLHttpRequest' } });
            const result = await res.json();
            if (result.success) {
                showToast(result.message, 'success');
                e.target.reset();
                currentTableData.doctors = result.doctors || [];
                document.getElementById('searchDoctors').value = '';
                applyDoctorsFilters();
                updateDoctorSelects(currentTableData.doctors);
                if (result.stats) updateStats(result.stats);
            } else { showToast(result.message || 'تعذّرت إضافة الطبيب.', 'danger'); }
        } catch (err) {
            showToast('تعذّرت إضافة الطبيب. تم إيقاف التحميل؛ تحقق من الاتصال أو بيانات النموذج.', 'danger');
        } finally {
            hideLoading();
        }
    });

    document.getElementById('addDoctorsBatchForm')?.addEventListener('submit', async (e) => {
        e.preventDefault();
        const batchInput = document.getElementById('doctors_batch_text');
        const raw = (batchInput?.value || '').trim();
        const batchHospitalId = document.getElementById('batch_hospital_id')?.value || '';
        if (!raw) {
            showToast('يرجى كتابة الدفعة أولاً.', 'warning');
            return;
        }
        if (!batchHospitalId) {
            showToast('يرجى اختيار المستشفى أولاً.', 'warning');
            return;
        }
        showLoading();
        const result = await sendAjaxRequest('add_doctors_batch', { doctors_batch_text: raw, batch_hospital_id: batchHospitalId });
        hideLoading();
        if (result.success) {
            showToast(result.message, 'success');
            if (batchInput) batchInput.value = '';
            currentTableData.doctors = result.doctors || [];
            document.getElementById('searchDoctors').value = '';
            applyDoctorsFilters();
            updateDoctorSelects(currentTableData.doctors);
            if (result.stats) updateStats(result.stats);
        } else {
            showToast(result.message || 'تعذّر معالجة الدفعة.', 'danger');
        }
    });

    // ======================== دفعة المرضى ========================
    document.getElementById('addPatientsBatchForm')?.addEventListener('submit', async (e) => {
        e.preventDefault();
        const batchInput = document.getElementById('patients_batch_text');
        const raw = (batchInput?.value || '').trim();
        if (!raw) {
            showToast('يرجى كتابة الدفعة أولاً.', 'warning');
            return;
        }
        showLoading();
        const result = await sendAjaxRequest('add_patients_batch', { patients_batch_text: raw });
        hideLoading();
        if (result.success) {
            showToast(result.message, 'success');
            if (batchInput) batchInput.value = '';
            currentTableData.patients = result.patients || [];
            document.getElementById('searchPatients').value = '';
            applyPatientsFilters();
            updatePatientSelects(currentTableData.patients);
            if (result.stats) updateStats(result.stats);
        } else {
            showToast(result.message || 'تعذّر معالجة الدفعة.', 'danger');
        }
    });

    // ======================== دفعة المستشفيات ========================
    document.getElementById('addHospitalsBatchForm')?.addEventListener('submit', async (e) => {
        e.preventDefault();
        const batchInput = document.getElementById('hospitals_batch_text');
        const raw = (batchInput?.value || '').trim();
        if (!raw) {
            showToast('يرجى كتابة الدفعة أولاً.', 'warning');
            return;
        }
        showLoading();
        const result = await sendAjaxRequest('add_hospitals_batch', { hospitals_batch_text: raw });
        hideLoading();
        if (result.success) {
            showToast(result.message, 'success');
            if (batchInput) batchInput.value = '';
            currentTableData.hospitals = result.hospitals || [];
            renderHospitals();
            updateHospitalSelects();
            if (result.stats) updateStats(result.stats);
        } else {
            showToast(result.message || 'تعذّر معالجة الدفعة.', 'danger');
        }
    });

    doctorsTable.addEventListener('click', (e) => {
        const editBtn = e.target.closest('.btn-edit-doctor');
        const delBtn = e.target.closest('.btn-delete-doctor');
        if (editBtn) {
            document.getElementById('edit_doctor_id').value = editBtn.dataset.id;
            document.getElementById('edit_doctor_name').value = editBtn.dataset.name;
            document.getElementById('edit_doctor_name_en').value = editBtn.dataset.nameEn || '';
            document.getElementById('edit_doctor_title').value = editBtn.dataset.title;
            document.getElementById('edit_doctor_title_en').value = editBtn.dataset.titleEn || '';
            document.getElementById('edit_doctor_note').value = editBtn.dataset.note;
            // Populate hospital select
            const hospSelect = document.getElementById('edit_doctor_hospital_id');
            hospSelect.innerHTML = '<option value="">غير محدد</option>';
            if (currentTableData.hospitals) {
                currentTableData.hospitals.forEach(h => {
                    hospSelect.innerHTML += `<option value="${h.id}" ${h.id == editBtn.dataset.hospitalId ? 'selected' : ''}>${htmlspecialchars(h.name_ar || '')}</option>`;
                });
            }
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
        try {
            const formData = new FormData(document.getElementById('editDoctorForm'));
            formData.append('action', 'edit_doctor');
            formData.append('csrf_token', CSRF_TOKEN);
            const res = await fetch(REQUEST_URL, { method: 'POST', body: formData, headers: { 'X-Requested-With': 'XMLHttpRequest' } });
            const result = await res.json();
            if (result.success) {
                showToast(result.message, 'success');
                editDoctorModal.hide();
                currentTableData.doctors = result.doctors || [];
                document.getElementById('searchDoctors').value = '';
                applyDoctorsFilters();
                updateDoctorSelects(currentTableData.doctors);
                if (result.stats) updateStats(result.stats);
            } else { showToast(result.message || 'تعذّر تعديل الطبيب.', 'danger'); }
        } catch (err) {
            showToast('تعذّر تعديل الطبيب. تم إيقاف التحميل؛ تحقق من الاتصال أو بيانات النموذج.', 'danger');
        } finally {
            hideLoading();
        }
    });

    // ====== إدارة المرضى ======
    document.getElementById('addPatientForm').addEventListener('submit', async (e) => {
        e.preventDefault();
        showLoading();
        try {
            const formData = new FormData(e.target);
            formData.append('action', 'add_patient');
            formData.append('csrf_token', CSRF_TOKEN);
            const res = await fetch(REQUEST_URL, { method: 'POST', body: formData, headers: { 'X-Requested-With': 'XMLHttpRequest' } });
            const result = await res.json();
            if (result.success) {
                showToast(result.message, 'success');
                e.target.reset();
                currentTableData.patients = result.patients || [];
                document.getElementById('searchPatients').value = '';
                applyPatientsFilters();
                updatePatientSelects(currentTableData.patients);
                if (result.stats) updateStats(result.stats);
            } else { showToast(result.message || 'تعذّرت إضافة المريض.', 'danger'); }
        } catch (err) {
            showToast('تعذّرت إضافة المريض. تم إيقاف التحميل؛ تحقق من الاتصال أو بيانات النموذج.', 'danger');
        } finally {
            hideLoading();
        }
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
            document.getElementById('edit_patient_name_en').value = editBtn.dataset.nameEn || '';
            document.getElementById('edit_patient_identity').value = editBtn.dataset.identity;
            document.getElementById('edit_patient_phone').value = editBtn.dataset.phone;
            document.getElementById('edit_patient_employer_ar').value = editBtn.dataset.employerAr || '';
            document.getElementById('edit_patient_employer_en').value = editBtn.dataset.employerEn || '';
            document.getElementById('edit_patient_nationality_ar').value = editBtn.dataset.nationalityAr || '';
            document.getElementById('edit_patient_nationality_en').value = editBtn.dataset.nationalityEn || '';
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
        try {
            const formData = new FormData(document.getElementById('editPatientForm'));
            formData.append('action', 'edit_patient');
            formData.append('csrf_token', CSRF_TOKEN);
            const res = await fetch(REQUEST_URL, { method: 'POST', body: formData, headers: { 'X-Requested-With': 'XMLHttpRequest' } });
            const result = await res.json();
            if (result.success) {
                showToast(result.message, 'success');
                editPatientModal.hide();
                currentTableData.patients = result.patients || [];
                document.getElementById('searchPatients').value = '';
                applyPatientsFilters();
                updatePatientSelects(currentTableData.patients);
                if (result.stats) updateStats(result.stats);
            } else { showToast(result.message || 'تعذّر تعديل المريض.', 'danger'); }
        } catch (err) {
            showToast('تعذّر تعديل المريض. تم إيقاف التحميل؛ تحقق من الاتصال أو بيانات النموذج.', 'danger');
        } finally {
            hideLoading();
        }
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

    // ====== إدارة الحسابات (التبويب الجديد) ======
    if (IS_ADMIN) {
        let acctAllData = [];
        let acctFilterMode = 'all';
        let acctSearchTerm = '';
        let acctPatientsCache = [];

        const acctAddDaysModal = new bootstrap.Modal(document.getElementById('acctAddDaysModal'));
        const acctCreateLeaveModal = new bootstrap.Modal(document.getElementById('acctCreateLeaveModal'));
        const acctLinkPatientModal = new bootstrap.Modal(document.getElementById('acctLinkPatientModal'));
        const acctChangePassModal = new bootstrap.Modal(document.getElementById('acctChangePassModal'));
        const acctPaymentsModal = new bootstrap.Modal(document.getElementById('acctPaymentsModal'));
        const acctNewUserModal = new bootstrap.Modal(document.getElementById('acctNewUserModal'));
        const acctEditUserModal = new bootstrap.Modal(document.getElementById('acctEditUserModal'));

        function acctGetExpiryStatus(expiryDate) {
            if (!expiryDate) return null;
            const today = new Date(); today.setHours(0,0,0,0);
            const exp = new Date(expiryDate); exp.setHours(0,0,0,0);
            const diff = Math.ceil((exp - today) / 86400000);
            if (diff < 0) return { cls: 'expired', label: 'منتهية الصلاحية', diff };
            if (diff <= 7) return { cls: 'warn', label: `تنتهي خلال ${diff} يوم`, diff };
            return { cls: 'ok', label: `تنتهي ${expiryDate}`, diff };
        }

        function acctGetDaysStatus(allowed, used) {
            const remaining = (allowed || 0) - (used || 0);
            if (remaining <= 0) return { cls: 'empty', pct: 0, remaining: 0 };
            const pct = Math.min(100, Math.round((remaining / (allowed || 1)) * 100));
            if (pct <= 20) return { cls: 'warn', pct, remaining };
            return { cls: 'ok', pct, remaining };
        }

        function renderAccountCard(u) {
            const isActive = u.is_active == 1;
            const roleClass = u.role === 'admin' ? 'role-admin' : 'role-user';
            const roleLabel = u.role === 'admin' ? 'مشرف' : 'مستخدم';
            const roleBadgeColor = u.role === 'admin' ? 'bg-danger' : 'bg-primary';
            const initials = (u.display_name || u.username || '?').charAt(0).toUpperCase();
            const expiry = acctGetExpiryStatus(u.expiry_date);
            const allowedDays = parseInt(u.patient_allowed_days) || 0;
            const usedDays = parseInt(u.portal_used_days || 0);
            const remainingDays = parseInt(u.portal_remaining_days || Math.max(allowedDays - usedDays, 0));
            const daysStatus = acctGetDaysStatus(allowedDays, usedDays);
            const totalPaid = parseFloat(u.total_paid || 0).toFixed(2);
            const payCount = parseInt(u.payment_count || 0);

            let expiryHtml = '';
            if (expiry) {
                expiryHtml = `<span class="acct-expiry-badge ${expiry.cls}"><i class="bi bi-calendar-event"></i> ${htmlspecialchars(expiry.label)}</span>`;
            }

            let patientHtml = u.linked_patient_id
                ? `<span class="badge bg-info text-dark"><i class="bi bi-person-check"></i> ${htmlspecialchars(u.linked_patient_name || 'مريض')} — ${htmlspecialchars(u.patient_identity || '')}</span>`
                : `<span class="badge bg-light text-muted border">غير مرتبط بمريض</span>`;

            let daysHtml = `
                <div class="acct-days-wrap">
                    <div class="acct-days-header">
                        <span class="acct-days-label"><i class="bi bi-calendar-check"></i> الأيام المتاحة</span>
                        <span class="acct-days-count ${daysStatus.cls}">${remainingDays} / ${allowedDays} يوم</span>
                    </div>
                    <div class="acct-progress">
                        <div class="acct-progress-bar ${daysStatus.cls}" style="width:${daysStatus.pct}%"></div>
                    </div>
                </div>`;

            const disabledClass = !isActive ? ' acct-disabled' : '';
            const expiredClass = (expiry && expiry.cls === 'expired') ? ' acct-expired' : '';

            return `
            <div class="col-12 col-md-6 col-xl-4 acct-card-col" data-id="${u.id}" data-active="${u.is_active}" data-username="${(u.username||'').toLowerCase()}" data-patient="${(u.linked_patient_name||'').toLowerCase()}" data-patient-id="${u.linked_patient_id || ''}" data-remaining-days="${parseInt(u.portal_remaining_days || 0)}" data-display-name="${htmlspecialchars(u.display_name || '')}">
                <div class="acct-card${disabledClass}${expiredClass}">
                    <div class="acct-card-header">
                        <div class="acct-avatar ${roleClass}">${htmlspecialchars(initials)}</div>
                        <div class="acct-card-title">
                            <div class="acct-username">${htmlspecialchars(u.username)}</div>
                            <div class="acct-display">${htmlspecialchars(u.display_name)}</div>
                        </div>
                        <div class="acct-status-dot ${isActive ? 'active' : 'inactive'}" title="${isActive ? 'نشط' : 'معطل'}"></div>
                        <span class="acct-role-badge badge ${roleBadgeColor}">${roleLabel}</span>
                    </div>
                    <div class="acct-card-body">
                        <div class="acct-info-row">
                            <i class="bi bi-person-fill"></i>
                            <span class="acct-info-label">المريض:</span>
                            <span class="acct-info-val">${patientHtml}</span>
                        </div>
                        ${daysHtml}
                        <div class="d-flex flex-wrap gap-2 align-items-center mt-2">
                            <span class="acct-payment-badge"><i class="bi bi-cash-coin"></i> ${totalPaid} ريال (${payCount} عملية)</span>
                            <span class="badge bg-primary-subtle text-primary border"><i class="bi bi-file-earmark-medical"></i> إجازات البوابة: ${parseInt(u.portal_leave_count || 0)}</span>
                            <span class="badge bg-success-subtle text-success border"><i class="bi bi-check2-circle"></i> مدفوعة: ${parseInt(u.account_paid_count || 0)}</span>
                            <span class="badge bg-danger-subtle text-danger border"><i class="bi bi-exclamation-circle"></i> غير مدفوعة: ${parseInt(u.account_unpaid_count || 0)}</span>
                            ${expiryHtml}
                        </div>
                        ${u.account_notes ? `<div class="mt-2 text-muted small"><i class="bi bi-sticky"></i> ${htmlspecialchars(u.account_notes)}</div>` : ''}
                    </div>
                    <div class="acct-card-actions">
                        <button class="btn btn-sm btn-gradient acct-btn-add-days" data-id="${u.id}" data-name="${htmlspecialchars(u.display_name)}" data-username="${htmlspecialchars(u.username)}" title="إضافة أيام">
                            <i class="bi bi-calendar-plus"></i> إضافة أيام
                        </button>
                        <button class="btn btn-sm btn-outline-secondary acct-btn-create-leave" data-id="${u.id}" data-name="${htmlspecialchars(u.display_name)}" data-patient-id="${u.linked_patient_id || ''}" data-remaining="${remainingDays}" title="إنشاء إجازة للمريض" ${remainingDays <= 0 || !u.linked_patient_id ? 'disabled' : ''}>
                            <i class="bi bi-file-earmark-medical"></i> إضافة إجازة
                        </button>
                        <button class="btn btn-sm btn-outline-primary acct-btn-link-patient" data-id="${u.id}" title="ربط بمريض">
                            <i class="bi bi-person-badge"></i> ربط مريض
                        </button>
                        <button class="btn btn-sm btn-outline-success acct-btn-payments" data-id="${u.id}" data-name="${htmlspecialchars(u.display_name)}" title="السجلات">
                            <i class="bi bi-journal-text"></i> السجلات
                        </button>
                        <button class="btn btn-sm btn-outline-info acct-btn-edit" data-id="${u.id}" data-username="${htmlspecialchars(u.username)}" data-display="${htmlspecialchars(u.display_name)}" title="تعديل بيانات الحساب">
                            <i class="bi bi-pencil"></i> تعديل
                        </button>
                        <button class="btn btn-sm btn-outline-warning acct-btn-pass" data-id="${u.id}" title="تغيير كلمة المرور">
                            <i class="bi bi-key"></i>
                        </button>
                        <button class="btn btn-sm ${isActive ? 'btn-outline-danger' : 'btn-outline-success'} acct-btn-toggle" data-id="${u.id}" data-active="${u.is_active}" title="${isActive ? 'تعطيل الحساب' : 'تفعيل الحساب'}">
                            <i class="bi bi-${isActive ? 'slash-circle' : 'check-circle'}"></i> ${isActive ? 'تعطيل' : 'تفعيل'}
                        </button>
                        <button class="btn btn-sm btn-danger acct-btn-delete" data-id="${u.id}" data-name="${htmlspecialchars(u.display_name)}" title="حذف الحساب نهائياً">
                            <i class="bi bi-trash3"></i> حذف
                        </button>
                    </div>
                </div>
            </div>`;
        }

        function acctUpdateStats(data) {
            const total = data.length;
            const active = data.filter(u => u.is_active == 1).length;
            const disabled = total - active;
            const revenue = data.reduce((s, u) => s + parseFloat(u.total_paid || 0), 0);
            document.getElementById('acctStatTotal').textContent = total;
            document.getElementById('acctStatActive').textContent = active;
            document.getElementById('acctStatDisabled').textContent = disabled;
            document.getElementById('acctStatRevenue').textContent = revenue.toFixed(2) + ' ر';
        }

        function acctRenderGrid(data) {
            const grid = document.getElementById('accountsGrid');
            const emptyEl = document.getElementById('accountsGridEmpty');
            if (emptyEl) emptyEl.style.display = 'none';
            let filtered = data;
            if (acctFilterMode === 'active') filtered = data.filter(u => u.is_active == 1);
            else if (acctFilterMode === 'disabled') filtered = data.filter(u => u.is_active != 1);
            if (acctSearchTerm) {
                const s = acctSearchTerm.toLowerCase();
                filtered = filtered.filter(u =>
                    (u.username||'').toLowerCase().includes(s) ||
                    (u.display_name||'').toLowerCase().includes(s) ||
                    (u.linked_patient_name||'').toLowerCase().includes(s) ||
                    (u.patient_identity||'').includes(s)
                );
            }
            if (filtered.length === 0) {
                grid.innerHTML = '<div class="col-12 text-center py-5 text-muted"><i class="bi bi-inbox" style="font-size:48px;opacity:0.3;"></i><p class="mt-2">لا توجد حسابات مطابقة</p></div>';
                return;
            }
            grid.innerHTML = filtered.map(renderAccountCard).join('');
        }

        let acctCurrentRecords = { leaves: [], payments: [] };

        function renderAcctLeaves(leaves) {
            const box = document.getElementById('acctLeavesList');
            if (!box) return;
            if (!leaves || leaves.length === 0) {
                box.innerHTML = '<div class="text-center py-4 text-muted"><i class="bi bi-inbox" style="font-size:36px;opacity:.35"></i><p>لا توجد إجازات لهذا المريض.</p></div>';
                return;
            }
            box.innerHTML = `<div class="table-responsive"><table class="table table-sm align-middle"><thead><tr><th>رمز الخدمة</th><th>المستشفى</th><th>الطبيب</th><th>البداية</th><th>النهاية</th><th>الأيام</th><th>الدفع</th><th>المبلغ</th></tr></thead><tbody>${leaves.map(lv => `
                <tr>
                    <td><span class="badge bg-light text-dark border">${htmlspecialchars(lv.service_code || '-')}</span></td>
                    <td>${htmlspecialchars(lv.hospital_name || lv.hospital_name_ar || '-')}</td>
                    <td>${htmlspecialchars(lv.doctor_name || '-')} <small class="text-muted">${htmlspecialchars(lv.doctor_title || '')}</small></td>
                    <td>${htmlspecialchars(lv.start_date || '')}</td>
                    <td>${htmlspecialchars(lv.end_date || '')}</td>
                    <td>${parseInt(lv.days_count || 0)}</td>
                    <td>${lv.is_paid == 1 ? '<span class="badge bg-success">مدفوعة</span>' : '<span class="badge bg-danger">غير مدفوعة</span>'}</td>
                    <td>${parseFloat(lv.payment_amount || 0).toFixed(2)}</td>
                </tr>`).join('')}</tbody></table></div>`;
        }

        function renderAcctPayments() {
            const box = document.getElementById('acctPaymentsList');
            if (!box) return;
            const mode = document.getElementById('acctPaymentStatusFilter')?.value || 'all';
            let payments = [...(acctCurrentRecords.payments || [])];
            if (mode === 'paid') payments = payments.filter(p => p.is_paid == 1);
            if (mode === 'unpaid') payments = payments.filter(p => p.is_paid == 0);
            const totalPaid = (acctCurrentRecords.payments || []).filter(p => p.is_paid == 1).reduce((sum, p) => sum + parseFloat(p.amount || 0), 0);
            const totalEl = document.getElementById('acctPaymentsTotal');
            if (totalEl) totalEl.textContent = totalPaid.toFixed(2);
            if (payments.length === 0) {
                box.innerHTML = '<div class="text-center py-4 text-muted"><i class="bi bi-inbox" style="font-size:36px;opacity:0.3;"></i><p>لا توجد سجلات مطابقة</p></div>';
                return;
            }
            box.innerHTML = payments.map(p => `
                <div class="payment-history-item">
                    <div>
                        <div class="ph-amount"><i class="bi bi-cash-coin"></i> ${parseFloat(p.amount || 0).toFixed(2)} ريال ${p.is_paid == 1 ? '<span class="badge bg-success ms-1">مدفوع</span>' : '<span class="badge bg-danger ms-1">غير مدفوع</span>'}</div>
                        <div class="ph-note">${parseInt(p.days_count || 0)} يوم — ${htmlspecialchars(p.note || '—')}</div>
                        <div class="ph-date"><i class="bi bi-clock"></i> ${htmlspecialchars(p.paid_at || '')} ${p.created_by_name ? '— أضيف بواسطة: ' + htmlspecialchars(p.created_by_name) : ''} ${p.paid_by_name ? '— دُفع بواسطة: ' + htmlspecialchars(p.paid_by_name) : ''}</div>
                    </div>
                    <div class="d-flex gap-1">
                        ${p.is_paid == 0 ? `<button class="btn btn-sm btn-success acct-pay-account-payment" data-pid="${p.id}" data-amount="${p.amount}"><i class="bi bi-cash-coin"></i> دفع</button>` : ''}
                        <button class="btn btn-sm btn-outline-danger acct-del-payment" data-pid="${p.id}" title="حذف"><i class="bi bi-trash3"></i></button>
                    </div>
                </div>
            `).join('');
        }

        async function acctLoadData() {
            const loadingEl = document.getElementById('accountsGridLoading');
            const emptyEl = document.getElementById('accountsGridEmpty');
            if (loadingEl) loadingEl.style.display = 'block';
            if (emptyEl) emptyEl.style.display = 'none';
            try {
                const res = await fetch(`${REQUEST_URL}?action=fetch_accounts_full`, { headers: { 'X-Requested-With': 'XMLHttpRequest' } });
                const result = await res.json();
                if (result.success) {
                    acctAllData = result.accounts || [];
                    acctUpdateStats(acctAllData);
                    acctRenderGrid(acctAllData);
                }
            } catch(e) { showToast('فشل تحميل الحسابات', 'danger'); }
            finally { if (loadingEl) loadingEl.style.display = 'none'; }
        }

        // Load when tab is shown
        document.getElementById('tab-accounts')?.addEventListener('shown.bs.tab', () => {
            if (acctAllData.length === 0) acctLoadData();
        });

        document.getElementById('acctRefreshBtn')?.addEventListener('click', acctLoadData);

        // Search
        document.getElementById('acctSearch')?.addEventListener('input', function() {
            acctSearchTerm = this.value.trim();
            acctRenderGrid(acctAllData);
        });
        document.getElementById('acctSearchBtn')?.addEventListener('click', () => {
            acctSearchTerm = document.getElementById('acctSearch').value.trim();
            acctRenderGrid(acctAllData);
        });

        // Filter buttons
        document.getElementById('acctFilterAll')?.addEventListener('click', function() {
            acctFilterMode = 'all';
            document.querySelectorAll('#acctFilterAll,#acctFilterActive,#acctFilterDisabled').forEach(b => b.classList.remove('active'));
            this.classList.add('active');
            acctRenderGrid(acctAllData);
        });
        document.getElementById('acctFilterActive')?.addEventListener('click', function() {
            acctFilterMode = 'active';
            document.querySelectorAll('#acctFilterAll,#acctFilterActive,#acctFilterDisabled').forEach(b => b.classList.remove('active'));
            this.classList.add('active');
            acctRenderGrid(acctAllData);
        });
        document.getElementById('acctFilterDisabled')?.addEventListener('click', function() {
            acctFilterMode = 'disabled';
            document.querySelectorAll('#acctFilterAll,#acctFilterActive,#acctFilterDisabled').forEach(b => b.classList.remove('active'));
            this.classList.add('active');
            acctRenderGrid(acctAllData);
        });

        // Add new user
  // 1. دالة توليد كلمات مرور قوية (حروف كبيرة وصغيرة + أرقام + رموز خاصة)
        function generateStrongPassword(length = 10) {
            const upper = 'ABCDEFGHJKLMNPQRSTUVWXYZ';
            const lower = 'abcdefghijkmnpqrstuvwxyz';
            const numbers = '23456789';
            const special = '@#$%&*!';
            const all = upper + lower + numbers + special;

            let pass = '';
            pass += upper.charAt(Math.floor(Math.random() * upper.length));
            pass += lower.charAt(Math.floor(Math.random() * lower.length));
            pass += numbers.charAt(Math.floor(Math.random() * numbers.length));
            pass += special.charAt(Math.floor(Math.random() * special.length));

            for (let i = 4; i < length; i++) {
                pass += all.charAt(Math.floor(Math.random() * all.length));
            }

            return pass.split('').sort(() => 0.5 - Math.random()).join('');
        }

        // 2. تصفير الحقول وإخفاء زر النسخ عند فتح المودال
       document.getElementById('acctAddUserBtn')?.addEventListener('click', () => {
    // تصفير الحقول السابقة
    document.getElementById('acctNewUsername').value = '';
    document.getElementById('acctNewPassword').value = '';
    document.getElementById('acctNewDisplayName').value = '';
    
    // تصفير حقل البحث الجديد وإعادة إظهار كل الخيارات
    const searchInput = document.getElementById('acctNewLinkPatientSearch');
    if (searchInput) {
        searchInput.value = '';
        searchInput.dispatchEvent(new Event('input')); // لتحديث القائمة وإظهار الكل
    }

    if (document.getElementById('acctNewLinkPatient')) document.getElementById('acctNewLinkPatient').value = '0';
    document.getElementById('copyAcctMsgBtn')?.classList.add('d-none');
    acctNewUserModal.show();
});
        // 3. التعبئة التلقائية وإظهار زر النسخ عند اختيار المريض
        document.getElementById('acctNewLinkPatient')?.addEventListener('change', function() {
            const ptId = this.value;
            const copyBtn = document.getElementById('copyAcctMsgBtn');

            if (ptId && ptId !== '0') {
                const pt = (currentTableData.patients || []).find(x => x.id == ptId);
                if (pt) {
                    document.getElementById('acctNewDisplayName').value = pt.name_ar || pt.name || '';

                    const nameSource = (pt.name_en || pt.name_ar || pt.name || 'patient').trim();
                    const firstName = (nameSource.split(/\s+/)[0] || 'patient').replace(/[^\p{L}\p{N}._-]+/gu, '').toLowerCase() || 'patient';
                    const nextAccountNo = (Array.isArray(acctAllData) ? acctAllData.length : 0) + 1;
                    document.getElementById('acctNewUsername').value = `${firstName}${nextAccountNo}`;

                    const passInput = document.getElementById('acctNewPassword');
                    passInput.value = generateStrongPassword(12);
                    passInput.type = 'text';

                    copyBtn?.classList.remove('d-none');
                }
            } else {
                document.getElementById('acctNewPassword').type = 'password';
                copyBtn?.classList.add('d-none');
            }
        });

        // 4. ميزة نسخ رسالة الواتساب الجذابة عند الضغط على الزر
        document.getElementById('copyAcctMsgBtn')?.addEventListener('click', async function() {
            const ptName = document.getElementById('acctNewDisplayName').value.trim();
            const user = document.getElementById('acctNewUsername').value.trim();
            const pass = document.getElementById('acctNewPassword').value;
            
            const portalUrl = window.location.origin + window.location.pathname.replace('admin.php', 'user.php');

            if (!user || !pass) {
                showToast('يرجى توليد أو كتابة اليوزر والباسوورد أولاً.', 'warning');
                return;
            }

            const whatsappMsg = `🎉 *تم تفعيل حساب ${ptName} بنجاح* 🎉\n\n` +
                                `👤 *اليوزر:* ${user}\n` +
                                `🔑 *الباسوورد:* ${pass}\n\n` +
                                `🌐 *سجل الدخول في الموقع الآتي بيوزرك والباسوورد:*\n` +
                                `${portalUrl}\n\n` +
                                `✨ استمتع بالخدمة الفورية لإصدار الاجازات! ولأي استفسار أو دعم وإضافة رصيد أيام لكم، معاكم هنا في الواتس دائماً 💬🤝`;

            try {
                await navigator.clipboard.writeText(whatsappMsg);
                
                const originalHtml = this.innerHTML;
                this.innerHTML = '<i class="bi bi-check2-all"></i> تم النسخ للحافظة بنجاح! ✅';
                this.classList.remove('btn-outline-success');
                this.classList.add('btn-success');
                showToast('تم نسخ رسالة الواتساب! الصقها مباشرة للمريض 📋✨', 'success');

                setTimeout(() => {
                    this.innerHTML = originalHtml;
                    this.classList.remove('btn-success');
                    this.classList.add('btn-outline-success');
                }, 3000);

            } catch (err) {
                showToast('فشل النسخ التلقائي، يرجى نسخ البيانات يدوياً.', 'danger');
            }
        });

        // 5. حفظ الحساب وإرساله للخادم
        document.getElementById('acctNewUserSave')?.addEventListener('click', async () => {
            const username = document.getElementById('acctNewUsername').value.trim();
            const password = document.getElementById('acctNewPassword').value;
            const displayName = document.getElementById('acctNewDisplayName').value.trim();
            const role = 'user';
            const linkPatientId = document.getElementById('acctNewLinkPatient')?.value || '0';
            const allowedDays = document.getElementById('acctNewAllowedDays')?.value || '0';
            if (!username || !password || !displayName) { showToast('يرجى تعبئة جميع الحقول المطلوبة.', 'warning'); return; }
            showLoading();
            const fd = new FormData();
            fd.append('action', 'account_add_user'); fd.append('csrf_token', CSRF_TOKEN);
            fd.append('username', username); fd.append('password', password);
            fd.append('display_name', displayName); fd.append('role', role);
            fd.append('link_patient_id', linkPatientId);
            fd.append('link_allowed_days', allowedDays);
            const res = await fetch(REQUEST_URL, { method: 'POST', body: fd, headers: { 'X-Requested-With': 'XMLHttpRequest' } });
            const result = await res.json(); hideLoading();
            if (result.success) {
                showToast(result.message, 'success');
                acctNewUserModal.hide();
                document.getElementById('acctNewUsername').value = '';
                document.getElementById('acctNewPassword').value = '';
                document.getElementById('acctNewDisplayName').value = '';
                if (document.getElementById('acctNewLinkPatient')) document.getElementById('acctNewLinkPatient').value = '0';
                if (document.getElementById('acctNewAllowedDays')) document.getElementById('acctNewAllowedDays').value = '0';
                acctLoadData();
            } else { showToast(result.message, 'danger'); }
        });
        // Grid click delegation
        document.getElementById('accountsGrid')?.addEventListener('click', async (e) => {
            const addDaysBtn = e.target.closest('.acct-btn-add-days');
            const createLeaveBtn = e.target.closest('.acct-btn-create-leave');
            const linkBtn = e.target.closest('.acct-btn-link-patient');
            const paymentsBtn = e.target.closest('.acct-btn-payments');
            const passBtn = e.target.closest('.acct-btn-pass');
            const toggleBtn = e.target.closest('.acct-btn-toggle');
            const editBtn = e.target.closest('.acct-btn-edit');
            const deleteBtn = e.target.closest('.acct-btn-delete');

            if (addDaysBtn) {
                const uid = addDaysBtn.dataset.id;
                document.getElementById('acctAddDaysUserId').value = uid;
                document.getElementById('acctAddDaysUserInfo').textContent = `${addDaysBtn.dataset.name} (${addDaysBtn.dataset.username})`;
                document.getElementById('acctAddDaysCount').value = '';
                document.getElementById('acctAddDaysAmount').value = '';
                document.getElementById('acctAddDaysNote').value = '';
                document.getElementById('acctAddDaysExpiry').value = '';
                document.getElementById('acctAddDaysPaidStatus').value = '1';
                acctAddDaysModal.show();
            }

            if (createLeaveBtn) {
                const remaining = parseInt(createLeaveBtn.dataset.remaining || 0, 10);
                if (remaining <= 0 || !createLeaveBtn.dataset.patientId) {
                    showToast('لا يمكن إنشاء إجازة قبل ربط المريض وإضافة أيام متاحة.', 'warning');
                    return;
                }
                document.getElementById('acctLeaveUserId').value = createLeaveBtn.dataset.id;
                document.getElementById('acctLeaveInfo').textContent = `${createLeaveBtn.dataset.name} — الأيام المتبقية: ${remaining}`;
                const acctHospitalSearch = document.getElementById('acct_leave_hospital_search');
                if (acctHospitalSearch) {
                    acctHospitalSearch.value = '';
                    acctHospitalSearch.dispatchEvent(new Event('input'));
                }
                refreshSelectQuickSearchData('acct_leave_hospital_id');
                document.getElementById('acct_leave_hospital_id').value = '';
                document.getElementById('acct_leave_doctor_id').innerHTML = '<option value="">-- اختر المستشفى أولاً --</option>';
                document.getElementById('acct_leave_doctor_id').disabled = true;
                document.getElementById('acct_leave_start_date').value = '';
                document.getElementById('acct_leave_end_date').value = '';
                document.getElementById('acct_leave_days_count').value = '';
                document.getElementById('acct_leave_issue_time').value = '';
                document.getElementById('acct_leave_issue_period').value = 'AM';
                acctCreateLeaveModal.show();
            }

            if (linkBtn) {
                const uid = linkBtn.closest('.acct-card-col').dataset.id;
                document.getElementById('acctLinkUserId').value = uid;
                // Load patients
                if (acctPatientsCache.length === 0) {
                    const res = await fetch(`${REQUEST_URL}?action=get_patient_account&user_id=${uid}`, { headers: { 'X-Requested-With': 'XMLHttpRequest' } });
                    const data = await res.json();
                    if (data.success) {
                        acctPatientsCache = data.patients || [];
                        const acct = data.account;
                        const sel = document.getElementById('acctLinkPatientId');
                        sel.innerHTML = '<option value="0">-- بدون ربط --</option>';
                        acctPatientsCache.forEach(p => {
                            sel.innerHTML += `<option value="${p.id}">${htmlspecialchars(p.name_ar)} — ${htmlspecialchars(p.identity_number)}</option>`;
                        });
                        if (acct) {
                            sel.value = acct.patient_id;
                            document.getElementById('acctLinkAllowedDays').value = acct.allowed_days || 0;
                            document.getElementById('acctLinkExpiry').value = acct.expiry_date || '';
                            document.getElementById('acctLinkNotes').value = acct.notes || '';
                        }
                    }
                } else {
                    const sel = document.getElementById('acctLinkPatientId');
                    sel.innerHTML = '<option value="0">-- بدون ربط --</option>';
                    acctPatientsCache.forEach(p => {
                        sel.innerHTML += `<option value="${p.id}">${htmlspecialchars(p.name_ar)} — ${htmlspecialchars(p.identity_number)}</option>`;
                    });
                    // Find current account data
                    const u = acctAllData.find(x => x.id == uid);
                    if (u && u.linked_patient_id) {
                        sel.value = u.linked_patient_id;
                        document.getElementById('acctLinkAllowedDays').value = u.patient_allowed_days || 0;
                        document.getElementById('acctLinkExpiry').value = u.expiry_date || '';
                        document.getElementById('acctLinkNotes').value = u.account_notes || '';
                    }
                }
                acctLinkPatientModal.show();
            }

           if (paymentsBtn) {
                const uid = paymentsBtn.dataset.id;
                document.getElementById('acctPaymentsUserName').textContent = paymentsBtn.dataset.name;
                document.getElementById('acctLeavesList').innerHTML = '<div class="text-center py-4"><div class="spinner-border spinner-border-sm text-success"></div></div>';
                document.getElementById('acctPaymentsList').innerHTML = '<div class="text-center py-4"><div class="spinner-border spinner-border-sm text-success"></div></div>';
                document.getElementById('acctPaymentStatusFilter').value = 'all';
                acctPaymentsModal.show();

                const data = await sendAjaxRequest('account_fetch_records', { user_id: uid });
                if (data.success) {
                    acctCurrentRecords = { leaves: data.leaves || [], payments: data.payments || [] };
                    renderAcctLeaves(acctCurrentRecords.leaves);
                    renderAcctPayments();
                }
            }

            if (passBtn) {
                const uid = passBtn.closest('.acct-card-col').dataset.id;
                document.getElementById('acctChangePassUserId').value = uid;
                document.getElementById('acctChangePassNewPwd').value = '';
                acctChangePassModal.show();
            }

            if (toggleBtn) {
                const uid = toggleBtn.dataset.id;
                const newStatus = toggleBtn.dataset.active == 1 ? 0 : 1;
                showLoading();
                const fd = new FormData();
                fd.append('action', 'account_toggle_status'); fd.append('csrf_token', CSRF_TOKEN);
                fd.append('user_id', uid); fd.append('status', newStatus);
                const res = await fetch(REQUEST_URL, { method: 'POST', body: fd, headers: { 'X-Requested-With': 'XMLHttpRequest' } });
                const result = await res.json(); hideLoading();
                if (result.success) { showToast(result.message, 'success'); acctLoadData(); }
                else { showToast(result.message, 'danger'); }
            }

            if (editBtn) {
                document.getElementById('acctEditUserId').value = editBtn.dataset.id;
                document.getElementById('acctEditUsername').value = '';
                document.getElementById('acctEditDisplayName').value = editBtn.dataset.display || '';
                document.getElementById('acctEditPassword').value = '';
                acctEditUserModal.show();
            }

            if (deleteBtn) {
                const uid = deleteBtn.dataset.id;
                const name = deleteBtn.dataset.name;
                confirmMessage.textContent = `هل أنت متأكد من حذف حساب "${name}" نهائياً؟ لا يمكن التراجع عن هذا الإجراء.`;
                confirmYesBtn.textContent = 'نعم، احذف نهائياً';
                currentConfirmAction = async () => {
                    showLoading();
                    const fd = new FormData();
                    fd.append('action', 'account_delete_user'); fd.append('csrf_token', CSRF_TOKEN);
                    fd.append('user_id', uid);
                    const res = await fetch(REQUEST_URL, { method: 'POST', body: fd, headers: { 'X-Requested-With': 'XMLHttpRequest' } });
                    const result = await res.json(); hideLoading();
                    if (result.success) { showToast(result.message, 'success'); acctLoadData(); }
                    else { showToast(result.message, 'danger'); }
                };
                confirmModal.show();
            }
        });

        document.getElementById('acctPaymentStatusFilter')?.addEventListener('change', renderAcctPayments);

        document.getElementById('acctPaymentsList')?.addEventListener('click', async (e) => {
            const payBtn = e.target.closest('.acct-pay-account-payment');
            if (!payBtn) return;
            document.getElementById('payConfirmMessage').textContent = 'هل تريد تأكيد دفع سجل إضافة الأيام؟';
            document.getElementById('confirmPayAmount').value = payBtn.dataset.amount || 0;
            currentConfirmAction = async () => {
                const amount = document.getElementById('confirmPayAmount').value;
                const result = await sendAjaxRequest('account_mark_payment_paid', { payment_id: payBtn.dataset.pid, amount });
                if (result.success) {
                    showToast(result.message, 'success');
                    if (result.stats) updateStats(result.stats);
                    const uid = document.querySelector('.acct-btn-payments[data-id]')?.dataset?.id;
                    payBtn.closest('.payment-history-item')?.querySelector('.badge')?.classList.remove('bg-danger');
                    payBtn.remove();
                    acctLoadData();
                    const notifs = await sendAjaxRequest('fetch_notifications', {});
                    if (notifs.success) { currentTableData.notifications_payment = notifs.data; applyNotificationsFilters(); }
                }
            };
            payConfirmModal.show();
        });

        // Delete payment from history
        document.getElementById('acctPaymentsList')?.addEventListener('click', async (e) => {
            const btn = e.target.closest('.acct-del-payment');
            if (!btn) return;
            const pid = btn.dataset.pid;
            showLoading();
            const fd = new FormData();
            fd.append('action', 'account_delete_payment'); fd.append('csrf_token', CSRF_TOKEN);
            fd.append('payment_id', pid);
            const res = await fetch(REQUEST_URL, { method: 'POST', body: fd, headers: { 'X-Requested-With': 'XMLHttpRequest' } });
            const result = await res.json(); hideLoading();
            if (result.success) { showToast(result.message, 'success'); if (result.stats) updateStats(result.stats); btn.closest('.payment-history-item')?.remove(); acctLoadData(); }
            else { showToast(result.message, 'danger'); }
        });

        function calcAcctLeaveDays() {
            const s = document.getElementById('acct_leave_start_date')?.value;
            const e = document.getElementById('acct_leave_end_date')?.value;
            const out = document.getElementById('acct_leave_days_count');
            if (!out) return;
            if (s && e) {
                const diff = Math.ceil((new Date(e) - new Date(s)) / 86400000) + 1;
                out.value = diff > 0 ? diff : 1;
            } else {
                out.value = '';
            }
        }

        document.getElementById('acct_leave_hospital_id')?.addEventListener('change', function() {
            fetchAndPopulateDoctorsForHospital('acct_leave_doctor_id', this.value, '').catch(() => populateDoctorSelectForHospital('acct_leave_doctor_id', this.value, ''));
        });
        document.getElementById('acct_leave_start_date')?.addEventListener('change', calcAcctLeaveDays);
        document.getElementById('acct_leave_end_date')?.addEventListener('change', calcAcctLeaveDays);

        document.getElementById('acctCreateLeaveSave')?.addEventListener('click', async () => {
            calcAcctLeaveDays();
            const uid = document.getElementById('acctLeaveUserId').value;
            const hospitalId = document.getElementById('acct_leave_hospital_id').value;
            const doctorId = document.getElementById('acct_leave_doctor_id').value;
            const startDate = document.getElementById('acct_leave_start_date').value;
            const endDate = document.getElementById('acct_leave_end_date').value;
            const days = document.getElementById('acct_leave_days_count').value;
            if (!uid || !hospitalId || !doctorId || !startDate || !endDate || !days) {
                showToast('يرجى تعبئة جميع بيانات الإجازة.', 'warning');
                return;
            }
            showLoading();
            const result = await sendAjaxRequest('account_create_leave', {
                user_id: uid,
                hospital_id: hospitalId,
                doctor_id: doctorId,
                start_date: startDate,
                end_date: endDate,
                days_count: days,
                issue_time: document.getElementById('acct_leave_issue_time').value,
                issue_period: document.getElementById('acct_leave_issue_period').value
            });
            hideLoading();
            if (result.success) {
                showToast(result.message, 'success');
                acctCreateLeaveModal.hide();
                syncTableDataFromResult(result);
                applyAllCurrentFilters();
                if (result.stats) updateStats(result.stats);
                acctLoadData();
            }
        });

        // Save add days
        document.getElementById('acctAddDaysSave')?.addEventListener('click', async () => {
            const uid = document.getElementById('acctAddDaysUserId').value;
            const days = document.getElementById('acctAddDaysCount').value;
            const amount = document.getElementById('acctAddDaysAmount').value;
            const note = document.getElementById('acctAddDaysNote').value;
            const expiry = document.getElementById('acctAddDaysExpiry').value;
            if (!days || parseInt(days) <= 0) { showToast('يرجى إدخال عدد الأيام.', 'warning'); return; }
            showLoading();
            const fd = new FormData();
            fd.append('action', 'account_add_days'); fd.append('csrf_token', CSRF_TOKEN);
            fd.append('user_id', uid); fd.append('days', days);
            fd.append('amount', amount || 0); fd.append('note', note);
            fd.append('expiry_date', expiry);
            fd.append('is_paid', document.getElementById('acctAddDaysPaidStatus')?.value || '1');
            const res = await fetch(REQUEST_URL, { method: 'POST', body: fd, headers: { 'X-Requested-With': 'XMLHttpRequest' } });
            const result = await res.json(); hideLoading();
            if (result.success) { showToast(result.message, 'success'); if (result.stats) updateStats(result.stats); acctAddDaysModal.hide(); acctLoadData(); }
            else { showToast(result.message, 'danger'); }
        });

        // Save link patient
        document.getElementById('acctLinkPatientSave')?.addEventListener('click', async () => {
            const uid = document.getElementById('acctLinkUserId').value;
            const pid = document.getElementById('acctLinkPatientId').value;
            const allowed = document.getElementById('acctLinkAllowedDays').value;
            const expiry = document.getElementById('acctLinkExpiry').value;
            const notes = document.getElementById('acctLinkNotes').value;
            showLoading();
            const fd = new FormData();
            fd.append('action', 'account_link_patient'); fd.append('csrf_token', CSRF_TOKEN);
            fd.append('user_id', uid); fd.append('patient_id', pid);
            fd.append('allowed_days', allowed || 0); fd.append('expiry_date', expiry);
            fd.append('notes', notes);
            const res = await fetch(REQUEST_URL, { method: 'POST', body: fd, headers: { 'X-Requested-With': 'XMLHttpRequest' } });
            const result = await res.json(); hideLoading();
            if (result.success) { showToast(result.message, 'success'); acctLinkPatientModal.hide(); acctPatientsCache = []; acctLoadData(); }
            else { showToast(result.message, 'danger'); }
        });

        // Save edit user
        document.getElementById('acctEditUserSave')?.addEventListener('click', async () => {
            const uid = document.getElementById('acctEditUserId').value;
            const displayName = document.getElementById('acctEditDisplayName').value.trim();
            const newUsername = document.getElementById('acctEditUsername').value.trim();
            const newPassword = document.getElementById('acctEditPassword').value;
            if (!displayName) { showToast('يرجى إدخال الاسم المعروض.', 'warning'); return; }
            showLoading();
            const fd = new FormData();
            fd.append('action', 'account_edit_user'); fd.append('csrf_token', CSRF_TOKEN);
            fd.append('user_id', uid); fd.append('display_name', displayName);
            fd.append('new_username', newUsername); fd.append('new_password', newPassword);
            const res = await fetch(REQUEST_URL, { method: 'POST', body: fd, headers: { 'X-Requested-With': 'XMLHttpRequest' } });
            const result = await res.json(); hideLoading();
            if (result.success) { showToast(result.message, 'success'); acctEditUserModal.hide(); acctLoadData(); }
            else { showToast(result.message, 'danger'); }
        });

        // Toggle password visibility in edit modal
        document.getElementById('acctEditTogglePass')?.addEventListener('click', function() {
            const inp = document.getElementById('acctEditPassword');
            if (inp.type === 'password') { inp.type = 'text'; this.innerHTML = '<i class="bi bi-eye-slash"></i>'; }
            else { inp.type = 'password'; this.innerHTML = '<i class="bi bi-eye"></i>'; }
        });

        // Save change password
        document.getElementById('acctChangePassSave')?.addEventListener('click', async () => {
            const uid = document.getElementById('acctChangePassUserId').value;
            const pass = document.getElementById('acctChangePassNewPwd').value;
            if (!pass || pass.length < 4) { showToast('كلمة المرور يجب أن تكون 4 أحرف على الأقل.', 'warning'); return; }
            showLoading();
            const fd = new FormData();
            fd.append('action', 'account_update_password'); fd.append('csrf_token', CSRF_TOKEN);
            fd.append('user_id', uid); fd.append('new_password', pass);
            const res = await fetch(REQUEST_URL, { method: 'POST', body: fd, headers: { 'X-Requested-With': 'XMLHttpRequest' } });
            const result = await res.json(); hideLoading();
            if (result.success) { showToast(result.message, 'success'); acctChangePassModal.hide(); }
            else { showToast(result.message, 'danger'); }
        });

        // Toggle password visibility
        document.getElementById('acctTogglePass')?.addEventListener('click', function() {
            const inp = document.getElementById('acctChangePassNewPwd');
            if (inp.type === 'password') { inp.type = 'text'; this.innerHTML = '<i class="bi bi-eye-slash"></i>'; }
            else { inp.type = 'password'; this.innerHTML = '<i class="bi bi-eye"></i>'; }
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
            glass_lux: { dark_text_color: '#e2e8f0', dark_glow_color: '#6366f1', dark_glow_enabled: '1', font_family: 'Readex Pro', data_view_mode: 'glass' },
            minimal_clean: { dark_text_color: '#111827', dark_glow_color: '#111827', dark_glow_enabled: '0', font_family: 'Noto Kufi Arabic', data_view_mode: 'minimal' },
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
    let pendingVoiceFile = null;
    let chatMaxUploadMB = 50;

    function applyDataViewMode(mode = 'table') {
        const allowed = ['table','compact','cards','zebra','glass','minimal'];
        const m = allowed.includes(mode) ? mode : 'table';
        document.body.classList.remove('data-view-table','data-view-compact','data-view-cards','data-view-zebra','data-view-glass','data-view-minimal');
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
            const fileExt = (m.file_name || m.file_path || '').split('.').pop().toLowerCase();
            const mime = String(m.mime_type || '').toLowerCase();
            const isImage = m.message_type === 'image';
            const isVoice = m.message_type === 'voice' || mime.startsWith('audio/') || ['mp3','wav','ogg','m4a','aac','webm'].includes(fileExt);
            const fileHtml = m.file_path
                ? (isImage
                    ? `<div class="chat-media"><img class="chat-image-preview" src="${htmlspecialchars(m.file_path)}" alt="مرفق صورة"></div>`
                    : (isVoice
                        ? `<div class="chat-media"><div class="chat-voice-player"><audio controls preload="metadata" playsinline src="${htmlspecialchars(m.file_path)}"></audio><div class="chat-voice-speeds" role="group" aria-label="سرعة تشغيل الفويس"><button type="button" class="chat-voice-speed active" data-rate="1">1x</button><button type="button" class="chat-voice-speed" data-rate="1.5">1.5x</button><button type="button" class="chat-voice-speed" data-rate="2">2x</button></div></div></div>`
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

    // ====== إضافة البحث الفوري للمستشفيات هنا ======
    document.getElementById('searchHospitals')?.addEventListener('input', debounce(function() {
        renderHospitals();
    }));

    document.getElementById('btn-search-hospitals')?.addEventListener('click', () => {
        renderHospitals();
    });

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

    // Populate batch pay hospital select when settings modal opens
    document.getElementById('settingsModal')?.addEventListener('show.bs.modal', () => {
        const sel = document.getElementById('batchPayHospitalSelect');
        if (sel) {
            sel.innerHTML = '<option value="">اختر مستشفى...</option>';
            (currentTableData.hospitals || []).forEach(h => {
                sel.innerHTML += `<option value="${h.id}">${htmlspecialchars(h.name_ar || '')}</option>`;
            });
        }
    });

    // Batch pay for specific hospital
    document.getElementById('batchPayHospitalBtn')?.addEventListener('click', () => {
        const hospitalId = document.getElementById('batchPayHospitalSelect')?.value;
        const amount = document.getElementById('batchPayAmount')?.value || '0';
        if (!hospitalId) { showToast('يرجى اختيار مستشفى.', 'warning'); return; }
        confirmMessage.textContent = 'سيتم تأكيد دفع جميع الإجازات غير المدفوعة لهذا المستشفى. متابعة؟';
        confirmYesBtn.textContent = 'نعم، نفّذ';
        currentConfirmAction = async () => {
            showLoading();
            const result = await sendAjaxRequest('mark_hospital_leaves_paid', { hospital_id: hospitalId, amount: amount });
            hideLoading();
            if (result.success) {
                showToast(result.message, 'success');
                syncTableDataFromResult(result);
                applyAllCurrentFilters();
                if (result.stats) updateStats(result.stats);
            }
        };
        confirmModal.show();
    });

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
        const file = fileInput?.files?.[0] || pendingVoiceFile || null;
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
            pendingVoiceFile = null;
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
                pendingVoiceFile = file;
                const fileInput = document.getElementById('chatFileInput');
                if (fileInput) {
                    try {
                        const dt = new DataTransfer();
                        dt.items.add(file);
                        fileInput.files = dt.files;
                    } catch (_) {
                        // بعض المتصفحات (خصوصًا على بعض أجهزة أندرويد) لا تسمح بتعيين files برمجيًا
                    }
                }
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
        pendingVoiceFile = null;
    });
    document.getElementById('chatFileInput')?.addEventListener('change', () => {
        // إذا اختار المستخدم ملفًا يدويًا نتجاهل الملف الصوتي المؤقت
        pendingVoiceFile = null;
    });
    document.getElementById('chatMessagesBox')?.addEventListener('click', async (e) => {
        const speedBtn = e.target.closest('.chat-voice-speed');
        if (speedBtn) {
            const voiceWrap = speedBtn.closest('.chat-voice-player');
            const audioEl = voiceWrap?.querySelector('audio');
            const nextRate = parseFloat(speedBtn.dataset.rate || '1');
            if (audioEl && Number.isFinite(nextRate) && nextRate > 0) {
                audioEl.playbackRate = nextRate;
                voiceWrap?.querySelectorAll('.chat-voice-speed').forEach(b => b.classList.remove('active'));
                speedBtn.classList.add('active');
            }
            return;
        }

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
    document.getElementById('adminStatsUserFilter')?.addEventListener('change', () => {
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

    // ====== إدارة المستشفيات ======
    const hospitalsTable = document.getElementById('hospitalsTable');
    function generateHospitalRow(h) {
        const hasLogo = h.has_logo_data === 'has_logo';
        const logoImg = hasLogo ? '<span class="badge bg-success"><i class="bi bi-image"></i> موجود</span>' : (h.logo_url ? `<img src="${htmlspecialchars(h.logo_url)}" style="max-height:40px;max-width:80px;" onerror="this.parentElement.innerHTML='افتراضي'">` : 'افتراضي');
        const hid = encodeURIComponent(h.id || '');
        return `<tr data-id="${htmlspecialchars(h.id || '')}"><td class="row-num"></td><td>${logoImg}</td><td>${htmlspecialchars(h.name_ar || '')}</td><td>${htmlspecialchars(h.name_en || '')}</td><td>${htmlspecialchars(h.license_number || '-')}</td><td><span class="badge ${h.service_prefix === 'PSL' ? 'bg-warning' : 'bg-success'}">${htmlspecialchars(h.service_prefix || 'GSL')}</span></td><td><button type="button" class="btn btn-sm btn-gradient action-btn" onclick="window.openEditHospital && window.openEditHospital('${hid}')" title="تعديل"><i class="bi bi-pencil"></i></button> <button type="button" class="btn btn-sm btn-danger-custom action-btn" onclick="window.confirmDeleteHospital && window.confirmDeleteHospital('${hid}')" title="حذف"><i class="bi bi-trash3"></i></button></td></tr>`;
    }
  function renderHospitals() {
        if (hospitalsTable && currentTableData.hospitals) {
            let filtered = [...currentTableData.hospitals];
            const q = normalizeSearchText(document.getElementById('searchHospitals')?.value || '');
            if (q) {
                filtered = filtered.filter(h => matchesSearch(h, q));
            }
            updateTable(hospitalsTable, filtered, generateHospitalRow);
        }
    }
   function updateHospitalSelects() {
        const selects = [
            document.querySelector('#addDoctorForm [name="doctor_hospital_id"]'),
            document.getElementById('hospital_id'),
            document.getElementById('batch_hospital_id'),
            document.getElementById('edit_doctor_hospital_id'),
            document.getElementById('quick_doctor_hospital_id'),
            document.getElementById('dup_hospital_id'),
            document.getElementById('hospital_id_edit'),
            document.getElementById('dup_hospital_select')
        ];
        const seen = new Set();
        selects.forEach(sel => {
            if (!sel || seen.has(sel)) return;
            seen.add(sel);
            const curVal = sel.value;
            const isLeaveForm = sel.id === 'hospital_id';
            const isBatch = sel.id === 'batch_hospital_id';
            const isRequiredLeaveHospital = ['hospital_id', 'dup_hospital_id', 'hospital_id_edit', 'dup_hospital_select', 'acct_leave_hospital_id'].includes(sel.id);
            sel.innerHTML = isRequiredLeaveHospital ? '<option value="">-- اختر مستشفى --</option>' : (isBatch ? '<option value="">اختر مستشفى</option>' : '<option value="">المستشفى (اختياري)</option>');
            (currentTableData.hospitals || []).forEach(h => {
                const opt = document.createElement('option');
                opt.value = h.id;
                opt.textContent = h.name_ar || '';
                if (isLeaveForm || sel.id === 'dup_hospital_id' || sel.id === 'hospital_id_edit' || sel.id === 'acct_leave_hospital_id') opt.dataset.prefix = h.service_prefix || 'GSL';
                if (h.id == curVal) opt.selected = true;
                sel.appendChild(opt);
            });

            // ⚠️ التعديل الأهم: تحديث ذاكرة البحث للقائمة فور تعبئتها بالبيانات
            if (sel.id) {
                refreshSelectQuickSearchData(sel.id);
            }
        });
    }
    renderHospitals();
    updateHospitalSelects();

    // إضافة مستشفى
    document.getElementById('addHospitalForm')?.addEventListener('submit', async (e) => {
        e.preventDefault();
        showLoading();
        const formData = new FormData(e.target);
        formData.append('action', 'add_hospital');
        formData.append('csrf_token', CSRF_TOKEN);
        const res = await fetch(REQUEST_URL, { method: 'POST', body: formData, headers: { 'X-Requested-With': 'XMLHttpRequest' } });
        const result = await res.json();
        hideLoading();
        if (result.success) {
            showToast(result.message, 'success');
            e.target.reset();
            if (result.hospitals) { currentTableData.hospitals = result.hospitals; renderHospitals(); updateHospitalSelects(); }
        } else { showToast(result.message, 'danger'); }
    });

    // حذف/تعديل مستشفى
    const editHospitalModal = new bootstrap.Modal(document.getElementById('editHospitalModal'));
    ['editHospitalModal'].forEach(setupModalStacking);

    // ====== Logo Preview with Drag & Scale ======
    let logoScale = 1, logoOffX = 0, logoOffY = 0, logoDragging = false, logoDragStart = {x:0,y:0};
    const logoImg = document.getElementById('edit_hospital_logo_preview');
    const logoBox = document.getElementById('logoPreviewBox');
    const logoSlider = document.getElementById('logoScaleSlider');
    const logoScaleLabel = document.getElementById('logoScaleValue');

    function setLogoControlState(scale = 1, offsetX = 0, offsetY = 0) {
        logoScale = Number.isFinite(parseFloat(scale)) ? parseFloat(scale) : 1;
        logoOffX = Number.isFinite(parseFloat(offsetX)) ? parseFloat(offsetX) : 0;
        logoOffY = Number.isFinite(parseFloat(offsetY)) ? parseFloat(offsetY) : 0;
        logoScale = Math.max(0.2, Math.min(3, logoScale));
        logoOffX = Math.max(-500, Math.min(500, logoOffX));
        logoOffY = Math.max(-500, Math.min(500, logoOffY));
    }

    function updateLogoTransform() {
        setLogoControlState(logoScale, logoOffX, logoOffY);
        if (logoImg) {
            logoImg.style.transform = `translate(${logoOffX}px, ${logoOffY}px) scale(${logoScale})`;
            logoImg.style.transformOrigin = 'center center';
            logoImg.style.willChange = 'transform';
            logoImg.style.pointerEvents = 'none';
            logoImg.style.userSelect = 'none';
        }
        const scaleInput = document.getElementById('edit_logo_scale');
        const offsetXInput = document.getElementById('edit_logo_offset_x');
        const offsetYInput = document.getElementById('edit_logo_offset_y');
        if (scaleInput) scaleInput.value = logoScale.toFixed(2);
        if (offsetXInput) offsetXInput.value = logoOffX.toFixed(1);
        if (offsetYInput) offsetYInput.value = logoOffY.toFixed(1);
        if (logoSlider) logoSlider.value = logoScale;
        if (logoScaleLabel) logoScaleLabel.textContent = Math.round(logoScale * 100) + '%';
    }

    function beginLogoDrag(clientX, clientY, pointerId = null) {
        if (!logoBox) return;
        logoDragging = true;
        logoDragStart = { x: clientX - logoOffX, y: clientY - logoOffY };
        logoBox.classList.add('dragging');
        if (pointerId !== null && logoBox.setPointerCapture) {
            try { logoBox.setPointerCapture(pointerId); } catch (_) {}
        }
    }

    function moveLogoDrag(clientX, clientY) {
        if (!logoDragging) return;
        logoOffX = clientX - logoDragStart.x;
        logoOffY = clientY - logoDragStart.y;
        updateLogoTransform();
    }

    function endLogoDrag(pointerId = null) {
        logoDragging = false;
        logoBox?.classList.remove('dragging');
        if (pointerId !== null && logoBox?.releasePointerCapture) {
            try { logoBox.releasePointerCapture(pointerId); } catch (_) {}
        }
    }

    logoSlider?.addEventListener('input', function() { logoScale = parseFloat(this.value); updateLogoTransform(); });
    document.getElementById('logoResetBtn')?.addEventListener('click', () => { setLogoControlState(1, 0, 0); updateLogoTransform(); });

    logoBox?.addEventListener('pointerdown', (e) => {
        beginLogoDrag(e.clientX, e.clientY, e.pointerId);
        e.preventDefault();
    });
    logoBox?.addEventListener('pointermove', (e) => moveLogoDrag(e.clientX, e.clientY));
    logoBox?.addEventListener('pointerup', (e) => endLogoDrag(e.pointerId));
    logoBox?.addEventListener('pointercancel', (e) => endLogoDrag(e.pointerId));
    logoBox?.addEventListener('mousedown', (e) => { beginLogoDrag(e.clientX, e.clientY); e.preventDefault(); });
    document.addEventListener('mousemove', (e) => moveLogoDrag(e.clientX, e.clientY));
    document.addEventListener('mouseup', () => endLogoDrag());
    logoBox?.addEventListener('touchstart', (e) => { const t = e.touches[0]; if (t) beginLogoDrag(t.clientX, t.clientY); e.preventDefault(); }, { passive: false });
    document.addEventListener('touchmove', (e) => { const t = e.touches[0]; if (t) moveLogoDrag(t.clientX, t.clientY); }, { passive: false });
    document.addEventListener('touchend', () => endLogoDrag());

    let lastLogoPreviewUrl = '';
    function showLogoPreview(src, { resetControls = false } = {}) {
        if (!logoImg || !src) return;
        if (resetControls) setLogoControlState(1, 0, 0);
        if (!resetControls && /^https?:\/\//i.test(String(src))) lastLogoPreviewUrl = String(src);
        logoImg.style.display = 'block';
        logoImg.removeAttribute('hidden');
        logoImg.style.opacity = '0.75';
        logoImg.onerror = () => { logoImg.style.opacity = '0.35'; };
        logoImg.onload = () => { logoImg.style.opacity = '1'; updateLogoTransform(); };
        logoImg.src = src;
        updateLogoTransform();
    }
    window.showHospitalLogoPreview = showLogoPreview;
    window.syncHospitalLogoTransform = function(scale = logoScale, offsetX = logoOffX, offsetY = logoOffY) {
        setLogoControlState(scale, offsetX, offsetY);
        updateLogoTransform();
    };
    window.syncHospitalLogoHiddenFields = updateLogoTransform;

    function previewSelectedLogoFile(file) {
        if (!file) return;
        const looksLikeImage = /^image\//i.test(file.type || '') || /\.(png|jpe?g|webp|gif|svg)$/i.test(file.name || '');
        if (!looksLikeImage) {
            showToast('يرجى اختيار ملف صورة صالح.', 'warning');
            return;
        }
        const reader = new FileReader();
        reader.onload = (e) => {
            lastLogoPreviewUrl = '';
            showLogoPreview(e.target.result, { resetControls: true });
        };
        reader.onerror = () => showToast('تعذّر قراءة ملف الشعار. جرّب صورة أخرى.', 'danger');
        reader.readAsDataURL(file);
    }

    const logoUrlInput = document.getElementById('edit_hospital_logo_url');
    let logoUrlPreviewRequestId = 0;
    async function requestServerLogoPreview(url) {
        if (!/^https?:\/\//i.test(url)) return;
        const requestId = ++logoUrlPreviewRequestId;
        try {
            const fd = new FormData();
            fd.append('action', 'preview_hospital_logo_url');
            fd.append('csrf_token', CSRF_TOKEN);
            fd.append('hospital_logo_url', url);
            const res = await fetch(REQUEST_URL, { method: 'POST', body: fd, headers: { 'X-Requested-With': 'XMLHttpRequest' } });
            const result = await res.json();
            const currentUrl = (document.getElementById('edit_hospital_logo_url')?.value || '').trim();
            if (requestId !== logoUrlPreviewRequestId || currentUrl !== url || !result.success || !result.logo_data) return;
            // نحافظ على مكان/حجم الشعار الذي عدّله المستخدم، ونبدّل المصدر فقط إلى data-uri موثوق للمعاينة.
            showLogoPreview(result.logo_data, { resetControls: false });
        } catch (_) {}
    }
    const requestServerLogoPreviewDebounced = debounce(requestServerLogoPreview, 450);
    function previewTypedLogoUrl(forceReset = false) {
        const url = (document.getElementById('edit_hospital_logo_url')?.value || '').trim();
        if (!url) return;
        const shouldResetControls = forceReset || url !== lastLogoPreviewUrl;
        lastLogoPreviewUrl = url;
        showLogoPreview(url, { resetControls: shouldResetControls });
        requestServerLogoPreviewDebounced(url);
    }
    const previewLogoUrl = debounce(() => previewTypedLogoUrl(false), 80);
    window.previewHospitalLogoFileInput = (input) => previewSelectedLogoFile(input?.files?.[0]);
    window.previewHospitalLogoUrlInput = (forceReset = false) => previewTypedLogoUrl(Boolean(forceReset));

    // نستخدم الربط المباشر + التفويض على document حتى تعمل المعاينة حتى لو أعيد رسم المودال أو تغيّرت عناصره.
    logoUrlInput?.addEventListener('input', previewLogoUrl);
    logoUrlInput?.addEventListener('paste', () => setTimeout(() => previewTypedLogoUrl(true), 0));
    logoUrlInput?.addEventListener('change', () => previewTypedLogoUrl(false));
    document.addEventListener('change', (e) => {
        if (e.target?.id === 'edit_hospital_logo_file') previewSelectedLogoFile(e.target.files?.[0]);
        if (e.target?.id === 'edit_hospital_logo_url') previewTypedLogoUrl(false);
    }, true);
    document.addEventListener('input', (e) => {
        if (e.target?.id === 'edit_hospital_logo_url') previewLogoUrl();
    }, true);
    document.addEventListener('paste', (e) => {
        if (e.target?.id === 'edit_hospital_logo_url') setTimeout(() => previewTypedLogoUrl(true), 0);
    }, true);

// ====== إجراءات المستشفيات المباشرة: مستقلة عن data-attributes حتى لا تتأثر بالترميز أو إعادة رسم الجدول ======
    window.openEditHospital = function(encodedHospitalId) {
        const hid = decodeURIComponent(String(encodedHospitalId || ''));
        const h = (currentTableData.hospitals || []).find(x => String(x.id) === String(hid));
        if (!h) { showToast('تعذّر العثور على بيانات المستشفى. حدّث الصفحة وحاول مجدداً.', 'danger'); return; }

        const elId = document.getElementById('edit_hospital_id');
        const elNameAr = document.getElementById('edit_hospital_name_ar');
        const elNameEn = document.getElementById('edit_hospital_name_en');
        const elLicense = document.getElementById('edit_hospital_license');
        const elPrefix = document.getElementById('edit_hospital_prefix');
        const elLogoUrl = document.getElementById('edit_hospital_logo_url');
        const elLogoFile = document.getElementById('edit_hospital_logo_file');

        if (elId) elId.value = h.id || '';
        if (elNameAr) elNameAr.value = h.name_ar || '';
        if (elNameEn) elNameEn.value = h.name_en || '';
        if (elLicense) elLicense.value = h.license_number || '';
        if (elPrefix) elPrefix.value = h.service_prefix || 'GSL';
        if (elLogoUrl) elLogoUrl.value = h.logo_url || '';
        if (elLogoFile) elLogoFile.value = '';

        logoScale = parseFloat(h.logo_scale || 1);
        logoOffX = parseFloat(h.logo_offset_x || 0);
        logoOffY = parseFloat(h.logo_offset_y || 0);
        const lSlider = document.getElementById('logoScaleSlider');
        if (lSlider) lSlider.value = logoScale;
        if (typeof updateLogoTransform === 'function') updateLogoTransform();

        if (h.has_logo_data === 'has_logo') {
            lastLogoPreviewUrl = '';
            showLogoPreview(REQUEST_URL + '?action=get_hospital_logo&hospital_id=' + encodeURIComponent(h.id) + '&csrf_token=' + encodeURIComponent(CSRF_TOKEN));
        } else if (h.logo_url) {
            lastLogoPreviewUrl = h.logo_url;
            showLogoPreview(h.logo_url);
        } else {
            const previewImg = document.getElementById('edit_hospital_logo_preview');
            if (previewImg) previewImg.removeAttribute('src');
        }

        bootstrap.Modal.getOrCreateInstance(document.getElementById('editHospitalModal')).show();
    };

    window.confirmDeleteHospital = function(encodedHospitalId) {
        const hid = decodeURIComponent(String(encodedHospitalId || ''));
        if (!hid) { showToast('معرّف المستشفى غير صالح.', 'danger'); return; }
        if (confirmMessage) confirmMessage.textContent = 'هل أنت متأكد من حذف هذا المستشفى نهائياً؟';
        if (confirmYesBtn) confirmYesBtn.textContent = 'نعم، احذف';
        currentConfirmAction = async () => {
            showLoading();
            const result = await sendAjaxRequest('delete_hospital', { hospital_id: hid });
            hideLoading();
            if (result.success) {
                showToast(result.message, 'success');
                if (Array.isArray(result.hospitals)) {
                    currentTableData.hospitals = result.hospitals;
                    renderHospitals();
                    updateHospitalSelects();
                }
                if (result.stats) updateStats(result.stats);
                await fetchAllLeaves();
            }
        };
        confirmModal.show();
    };

// ====== التقاط أحداث أزرار المستشفيات (تعديل وحذف) عبر Event Delegation على مستوى المستند ======
    hospitalsTable?.addEventListener('click', (e) => {
        const editBtn = e.target.closest('.btn-edit-hospital');
        const delBtn = e.target.closest('.btn-delete-hospital');
        
        // 1. معالجة زر التعديل
        if (editBtn) {
            e.preventDefault();
            e.stopPropagation();
            
            const hid = editBtn.dataset.id || '';
            const elId = document.getElementById('edit_hospital_id');
            const elNameAr = document.getElementById('edit_hospital_name_ar');
            const elNameEn = document.getElementById('edit_hospital_name_en');
            const elLicense = document.getElementById('edit_hospital_license');
            const elPrefix = document.getElementById('edit_hospital_prefix');
            const elLogoUrl = document.getElementById('edit_hospital_logo_url');
            const elLogoFile = document.getElementById('edit_hospital_logo_file');
            
            if (elId) elId.value = hid;
            if (elNameAr) elNameAr.value = editBtn.dataset.nameAr || '';
            if (elNameEn) elNameEn.value = editBtn.dataset.nameEn || '';
            if (elLicense) elLicense.value = editBtn.dataset.license || '';
            if (elPrefix) elPrefix.value = editBtn.dataset.prefix || 'GSL';
            if (elLogoUrl) elLogoUrl.value = '';
            if (elLogoFile) elLogoFile.value = '';
            
            // تحميل إعدادات إزاحة وتكبير الشعار المحفوظة للمستشفى
            logoScale = parseFloat(editBtn.dataset.logoScale || 1);
            logoOffX = parseFloat(editBtn.dataset.logoOffsetX || 0);
            logoOffY = parseFloat(editBtn.dataset.logoOffsetY || 0);
            
            const lSlider = document.getElementById('logoScaleSlider');
            if (lSlider) lSlider.value = logoScale;
            
            if (typeof updateLogoTransform === 'function') updateLogoTransform();
            
            const logoData = editBtn.dataset.logo || '';
            if (logoData === 'has_logo') {
                lastLogoPreviewUrl = '';
                if (typeof showLogoPreview === 'function') {
                    showLogoPreview(REQUEST_URL + '?action=get_hospital_logo&hospital_id=' + hid + '&csrf_token=' + encodeURIComponent(CSRF_TOKEN));
                }
            } else if (logoData && logoData.startsWith('http')) {
                lastLogoPreviewUrl = logoData;
                if (typeof showLogoPreview === 'function') showLogoPreview(logoData);
                if (elLogoUrl) elLogoUrl.value = logoData;
            } else {
                const previewImg = document.getElementById('edit_hospital_logo_preview');
                if (previewImg) previewImg.src = '';
            }
            
            if (typeof editHospitalModal !== 'undefined' && editHospitalModal) {
                editHospitalModal.show();
            } else {
                const modalEl = document.getElementById('editHospitalModal');
                if (modalEl) bootstrap.Modal.getOrCreateInstance(modalEl).show();
            }
        }
        
        // 2. معالجة زر الحذف
        if (delBtn) {
            e.preventDefault();
            e.stopPropagation();
            
            const hid = delBtn.dataset.id;
            const confirmMsgEl = document.getElementById('confirmMessage');
            const confirmYesEl = document.getElementById('confirmYesBtn');
            
            if (confirmMsgEl) confirmMsgEl.textContent = 'هل أنت متأكد من حذف هذا المستشفى نهائياً؟';
            if (confirmYesEl) confirmYesEl.textContent = 'نعم، احذف';
            
            currentConfirmAction = async () => {
                if (typeof showLoading === 'function') showLoading();
                try {
                    const result = await sendAjaxRequest('delete_hospital', { hospital_id: hid });
                    if (typeof hideLoading === 'function') hideLoading();
                    if (result.success) {
                        if (typeof showToast === 'function') showToast(result.message, 'success');
                        if (result.hospitals) { 
                            currentTableData.hospitals = result.hospitals; 
                            if (typeof renderHospitals === 'function') renderHospitals(); 
                            if (typeof updateHospitalSelects === 'function') updateHospitalSelects(); 
                        }
                        // تحديث الإحصائيات العلوية فوراً إن وجدت
                        if (result.stats && typeof updateStats === 'function') updateStats(result.stats);
                    } else {
                        if (typeof showToast === 'function') showToast(result.message || 'تعذّر الحذف.', 'danger');
                    }
                } catch (err) {
                    if (typeof hideLoading === 'function') hideLoading();
                    if (typeof showToast === 'function') showToast('حدث خطأ أثناء الحذف.', 'danger');
                }
            };
            
            if (typeof confirmModal !== 'undefined' && confirmModal) {
                confirmModal.show();
            } else {
                const cModalEl = document.getElementById('confirmModal');
                if (cModalEl) bootstrap.Modal.getOrCreateInstance(cModalEl).show();
            }
        }
    });

    // حفظ تعديل المستشفى
    let editHospitalSubmitting = false;
    async function submitEditHospitalForm(formEl) {
        if (!formEl || editHospitalSubmitting) return;
        editHospitalSubmitting = true;
        showLoading();
        try {
            if (typeof window.syncHospitalLogoHiddenFields === 'function') window.syncHospitalLogoHiddenFields();
            const formData = new FormData(formEl);
            formData.append('action', 'edit_hospital');
            formData.append('csrf_token', CSRF_TOKEN);
            const res = await fetch(REQUEST_URL, { method: 'POST', body: formData, headers: { 'X-Requested-With': 'XMLHttpRequest' } });
            const result = await res.json();
            if (result.success) {
                showToast(result.message, 'success');
                if (typeof editHospitalModal !== 'undefined' && editHospitalModal) {
                    editHospitalModal.hide();
                } else {
                    const modalEl = document.getElementById('editHospitalModal');
                    if (modalEl) bootstrap.Modal.getInstance(modalEl)?.hide();
                }
                if (result.hospitals) { currentTableData.hospitals = result.hospitals; renderHospitals(); updateHospitalSelects(); }
                await fetchAllLeaves();
            } else { showToast(result.message || 'تعذّر تعديل المستشفى.', 'danger'); }
        } catch (err) {
            console.error('Edit hospital error:', err);
            showToast('تعذّر تعديل المستشفى أو تحديث الإجازات المرتبطة.', 'danger');
        } finally {
            editHospitalSubmitting = false;
            hideLoading();
        }
    }

    window.saveEditHospitalDirect = async function() {
        await submitEditHospitalForm(document.getElementById('editHospitalForm'));
    };

    document.getElementById('editHospitalForm')?.addEventListener('submit', async (e) => {
        e.preventDefault();
        e.stopImmediatePropagation();
        await submitEditHospitalForm(e.currentTarget);
    });
    document.getElementById('saveEditHospital')?.addEventListener('click', async (e) => {
        e.preventDefault();
        e.stopImmediatePropagation();
        await submitEditHospitalForm(document.getElementById('editHospitalForm'));
    });
    // ====== ربط المستشفى بالأطباء + البادئة ======
    document.getElementById('hospital_id')?.addEventListener('change', function() {
        const opt = this.options[this.selectedIndex];
        const prefix = opt?.dataset?.prefix || 'GSL';
        document.getElementById('service_prefix').value = prefix;
        // تصفية الأطباء حسب المستشفى
        const hospitalId = this.value;
        fetchAndPopulateDoctorsForHospital('doctor_select', hospitalId, '').catch(() => populateDoctorSelectForHospital('doctor_select', hospitalId, ''));
    });

    // calcDays already defined above with parametric version

    // ====== تعبئة بيانات المريض تلقائياً ======
    document.getElementById('patient_select')?.addEventListener('change', function() {
        const patientId = this.value;
        if (patientId && patientId !== 'manual') {
            const p = (currentTableData.patients || []).find(x => x.id == patientId);
            if (p) {
                const ea = document.getElementById('employer_ar');
                const ee = document.getElementById('employer_en');
                if (ea && p.employer_ar) ea.value = p.employer_ar;
                if (ee && p.employer_en) ee.value = p.employer_en;
            }
        }
    });

    // ====== طباعة PDF ======
    document.addEventListener('click', async (e) => {
        const printBtn = e.target.closest('.btn-print-leave');
        if (!printBtn) return;
        if (printBtn.tagName === 'A' && printBtn.href) return; // الرابط المباشر هو المسار الأساسي الموثوق
        const leaveId = printBtn.dataset.id;
        showLoading();
        try {
            if (!leaveId) throw new Error('leave_id مفقود');
            const url = REQUEST_URL + '?action=generate_pdf&leave_id=' + encodeURIComponent(leaveId) + '&pdf_mode=preview&csrf_token=' + encodeURIComponent(CSRF_TOKEN);
            const pdfWindow = window.open('about:blank', '_blank');
            if (pdfWindow) {
                pdfWindow.location.href = url;
            } else {
                window.location.href = url;
            }
            hideLoading();
        } catch(err) {
            hideLoading();
            showToast('حدث خطأ في الطباعة: ' + err.message, 'danger');
        }
    });

    // ====== تحديث تلقائي كل 60 ثانية ======
    setInterval(async () => {
        const result = await sendAjaxRequest('fetch_all_leaves', {});
        if (result.success) {
            if (Array.isArray(result.leaves)) currentTableData.leaves = result.leaves;
            if (Array.isArray(result.archived)) currentTableData.archived = result.archived;
            if (Array.isArray(result.queries)) currentTableData.queries = result.queries;
            if (Array.isArray(result.payments)) currentTableData.payments = result.payments;
            if (Array.isArray(result.notifications_payment)) currentTableData.notifications_payment = result.notifications_payment;
            if (Array.isArray(result.hospitals)) { currentTableData.hospitals = result.hospitals; renderHospitals(); updateHospitalSelects(); }
            applyAllCurrentFilters();
            if (result.stats) updateStats(result.stats);
        }
    }, 60000);

}); // نهاية DOMContentLoaded
</script>


<script>
(function(){
    // مدير مستقل بالكامل لتبويب المستشفيات. لا يعتمد على سكربتات الجدول القديمة.
    const HOSPITAL_SELECT_IDS = [
        'hospital_id', 'batch_hospital_id', 'edit_doctor_hospital_id', 'quick_doctor_hospital_id',
        'dup_hospital_id', 'hospital_id_edit', 'dup_hospital_select', 'batchPayHospitalSelect', 'acct_leave_hospital_id'
    ];
    let hospitalRows = [];
    let editModalInstance = null;
    let editSubmitting = false;

    function ready(fn) {
        if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', fn);
        else fn();
    }
    function esc(value) {
        const div = document.createElement('div');
        div.textContent = value == null ? '' : String(value);
        return div.innerHTML;
    }
    function toast(message, type = 'success') {
        const messageText = String(message ?? '');
        if (typeof isIgnorableIterableMessage === 'function' && isIgnorableIterableMessage(messageText)) {
            console.warn('Suppressed non-critical hospital notification:', messageText);
            return;
        }
        if (typeof showToast === 'function') showToast(messageText, type);
        else alert(messageText);
    }
    function loading(on) {
        if (on && typeof showLoading === 'function') showLoading();
        if (!on && typeof hideLoading === 'function') hideLoading();
    }
    function runLegacySafely(fn) {
        try { if (typeof fn === 'function') fn(); }
        catch (err) {
            // Some older global table/search helpers throw this while the hospital action itself succeeds.
            // Keep the rebuilt hospitals manager authoritative and prevent false danger toasts.
            console.warn('Ignored legacy hospital helper error:', err);
        }
    }
    async function postHospital(action, data = {}, filesForm = null) {
        const fd = filesForm ? new FormData(filesForm) : new FormData();
        fd.set('action', action);
        fd.set('csrf_token', typeof CSRF_TOKEN !== 'undefined' ? CSRF_TOKEN : '');
        if (data && typeof data === 'object') {
            Object.keys(data).forEach((key) => {
                const value = data[key];
                fd.set(key, value == null ? '' : value);
            });
        }
        const response = await fetch(typeof REQUEST_URL !== 'undefined' ? REQUEST_URL : window.location.pathname, {
            method: 'POST',
            body: fd,
            headers: { 'X-Requested-With': 'XMLHttpRequest' }
        });
        const text = await response.text();
        try { return JSON.parse(text); }
        catch (e) { throw new Error('رد الخادم غير صالح: ' + text.slice(0, 180)); }
    }
    function renderHospitalTable() {
        const table = document.getElementById('hospitalsTable');
        if (!table) return;
        const tbody = table.querySelector('tbody');
        const search = (document.getElementById('searchHospitals')?.value || '').trim().toLowerCase();
        const rows = search ? hospitalRows.filter(h => JSON.stringify(h).toLowerCase().includes(search)) : hospitalRows;
        if (!rows.length) {
            tbody.innerHTML = '<tr><td colspan="7" class="text-center py-4 text-muted"><i class="bi bi-inbox"></i><br>لا توجد مستشفيات</td></tr>';
            return;
        }
        tbody.innerHTML = rows.map((h, idx) => {
            const logo = h.has_logo_data === 'has_logo'
                ? '<span class="badge bg-success"><i class="bi bi-image"></i> موجود</span>'
                : (h.logo_url ? `<img src="${esc(h.logo_url)}" style="max-height:40px;max-width:90px" onerror="this.outerHTML='افتراضي'">` : 'افتراضي');
            const prefix = h.service_prefix || 'GSL';
            return `<tr data-hospital-id="${esc(h.id)}">
                <td class="row-num">${idx + 1}</td>
                <td>${logo}</td>
                <td>${esc(h.name_ar)}</td>
                <td>${esc(h.name_en)}</td>
                <td>${esc(h.license_number || '-')}</td>
                <td><span class="badge ${prefix === 'PSL' ? 'bg-warning' : 'bg-success'}">${esc(prefix)}</span></td>
                <td>
                    <button type="button" class="btn btn-sm btn-gradient action-btn" data-hospital-edit="${esc(h.id)}" title="تعديل"><i class="bi bi-pencil"></i></button>
                    <button type="button" class="btn btn-sm btn-danger-custom action-btn" data-hospital-delete="${esc(h.id)}" title="حذف"><i class="bi bi-trash3"></i></button>
                </td>
            </tr>`;
        }).join('');
        runLegacySafely(() => applyTableMobileLabels(table));
    }
    function refreshHospitalSelects() {
        HOSPITAL_SELECT_IDS.forEach(id => {
            const sel = document.getElementById(id);
            if (!sel) return;
            const current = sel.value;
            const required = ['hospital_id', 'dup_hospital_id', 'hospital_id_edit', 'dup_hospital_select'].includes(id);
            sel.innerHTML = required ? '<option value="">-- اختر مستشفى --</option>' : '<option value="">المستشفى (اختياري)</option>';
            hospitalRows.forEach(h => {
                const opt = document.createElement('option');
                opt.value = h.id;
                opt.textContent = h.name_ar || '';
                opt.dataset.prefix = h.service_prefix || 'GSL';
                if (String(current) === String(h.id)) opt.selected = true;
                sel.appendChild(opt);
            });
            runLegacySafely(() => refreshSelectQuickSearchData(id));
        });
        const doctorHospitalSelect = document.querySelector('#addDoctorForm [name="doctor_hospital_id"]');
        if (doctorHospitalSelect) {
            const current = doctorHospitalSelect.value;
            doctorHospitalSelect.innerHTML = '<option value="">المستشفى (اختياري)</option>';
            hospitalRows.forEach(h => {
                const opt = document.createElement('option');
                opt.value = h.id;
                opt.textContent = h.name_ar || '';
                if (String(current) === String(h.id)) opt.selected = true;
                doctorHospitalSelect.appendChild(opt);
            });
        }
    }
    async function loadHospitals() {
        const result = await postHospital('fetch_hospitals');
        if (!result.success) throw new Error(result.message || 'فشل تحميل المستشفيات');
        hospitalRows = Array.isArray(result.hospitals) ? result.hospitals : [];
        renderHospitalTable();
        refreshHospitalSelects();
    }
    function fillEditModal(id) {
        const h = hospitalRows.find(row => String(row.id) === String(id));
        if (!h) { toast('لم يتم العثور على المستشفى، اضغط تحديث وحاول مرة أخرى.', 'danger'); return; }
        document.getElementById('edit_hospital_id').value = h.id || '';
        document.getElementById('edit_hospital_name_ar').value = h.name_ar || '';
        document.getElementById('edit_hospital_name_en').value = h.name_en || '';
        document.getElementById('edit_hospital_license').value = h.license_number || '';
        document.getElementById('edit_hospital_prefix').value = h.service_prefix || 'GSL';
        document.getElementById('edit_hospital_logo_url').value = h.logo_url || '';
        document.getElementById('edit_hospital_logo_file').value = '';
        document.getElementById('edit_logo_scale').value = h.logo_scale || 1;
        document.getElementById('edit_logo_offset_x').value = h.logo_offset_x || 0;
        document.getElementById('edit_logo_offset_y').value = h.logo_offset_y || 0;
        const preview = document.getElementById('edit_hospital_logo_preview');
        if (preview) {
            preview.style.transform = `translate(${parseFloat(h.logo_offset_x || 0)}px, ${parseFloat(h.logo_offset_y || 0)}px) scale(${parseFloat(h.logo_scale || 1)})`;
            const src = h.has_logo_data === 'has_logo'
                ? `${window.location.pathname}?action=get_hospital_logo&hospital_id=${encodeURIComponent(h.id)}&csrf_token=${encodeURIComponent(CSRF_TOKEN)}`
                : (h.logo_url || '');
            if (src) {
                if (typeof window.showHospitalLogoPreview === 'function') window.showHospitalLogoPreview(src);
                else preview.src = src;
            } else {
                preview.removeAttribute('src');
            }
            if (typeof window.syncHospitalLogoTransform === 'function') window.syncHospitalLogoTransform(h.logo_scale || 1, h.logo_offset_x || 0, h.logo_offset_y || 0);
        }
        const slider = document.getElementById('logoScaleSlider');
        if (slider) slider.value = h.logo_scale || 1;
        const label = document.getElementById('logoScaleValue');
        if (label) label.textContent = Math.round(parseFloat(h.logo_scale || 1) * 100) + '%';
        editModalInstance = bootstrap.Modal.getOrCreateInstance(document.getElementById('editHospitalModal'));
        editModalInstance.show();
    }
    async function saveEditHospital() {
        const form = document.getElementById('editHospitalForm');
        if (!form || editSubmitting) return;
        editSubmitting = true;
        loading(true);
        try {
            if (typeof window.syncHospitalLogoHiddenFields === 'function') window.syncHospitalLogoHiddenFields();
            const result = await postHospital('edit_hospital', {}, form);
            if (!result.success) throw new Error(result.message || 'تعذّر تعديل المستشفى');
            toast(result.message || 'تم تعديل المستشفى بنجاح', 'success');
            if (editModalInstance) editModalInstance.hide();
            hospitalRows = Array.isArray(result.hospitals) ? result.hospitals : hospitalRows;
            renderHospitalTable();
            refreshHospitalSelects();
            if (typeof updateStats === 'function' && result.stats) runLegacySafely(() => updateStats(result.stats));
        } catch (e) {
            toast(e.message || 'تعذّر تعديل المستشفى', 'danger');
        } finally {
            editSubmitting = false;
            loading(false);
        }
    }
    async function deleteHospital(id) {
        if (!id || !window.confirm('هل أنت متأكد من حذف هذا المستشفى؟')) return;
        loading(true);
        try {
            const result = await postHospital('delete_hospital', { hospital_id: id });
            if (!result.success) throw new Error(result.message || 'تعذّر حذف المستشفى');
            toast(result.message || 'تم حذف المستشفى', 'success');
            hospitalRows = Array.isArray(result.hospitals) ? result.hospitals : hospitalRows.filter(h => String(h.id) !== String(id));
            renderHospitalTable();
            refreshHospitalSelects();
            if (typeof updateStats === 'function' && result.stats) runLegacySafely(() => updateStats(result.stats));
        } catch (e) {
            toast(e.message || 'تعذّر حذف المستشفى', 'danger');
        } finally {
            loading(false);
        }
    }
    function initHospitalManager() {
        const table = document.getElementById('hospitalsTable');
        if (!table || table.dataset.rebuiltManager === '1') return;
        table.dataset.rebuiltManager = '1';

        const addForm = document.getElementById('addHospitalForm');
        addForm?.addEventListener('submit', async (e) => {
            e.preventDefault();
            e.stopImmediatePropagation();
            loading(true);
            try {
                const result = await postHospital('add_hospital', {}, addForm);
                if (!result.success) throw new Error(result.message || 'تعذّر إضافة المستشفى');
                toast(result.message || 'تمت إضافة المستشفى', 'success');
                addForm.reset();
                hospitalRows = Array.isArray(result.hospitals) ? result.hospitals : hospitalRows;
                renderHospitalTable();
                refreshHospitalSelects();
                if (typeof updateStats === 'function' && result.stats) runLegacySafely(() => updateStats(result.stats));
            } catch (err) { toast(err.message, 'danger'); }
            finally { loading(false); }
        }, true);

        document.getElementById('addHospitalsBatchForm')?.addEventListener('submit', async (e) => {
            e.preventDefault();
            e.stopImmediatePropagation();
            const textarea = document.getElementById('hospitals_batch_text');
            const raw = (textarea?.value || '').trim();
            if (!raw) { toast('يرجى كتابة الدفعة أولاً.', 'warning'); return; }
            loading(true);
            try {
                const result = await postHospital('add_hospitals_batch', { hospitals_batch_text: raw });
                if (!result.success) throw new Error(result.message || 'تعذّر إضافة الدفعة');
                toast(result.message || 'تمت إضافة الدفعة', 'success');
                textarea.value = '';
                hospitalRows = Array.isArray(result.hospitals) ? result.hospitals : hospitalRows;
                renderHospitalTable();
                refreshHospitalSelects();
                if (typeof updateStats === 'function' && result.stats) runLegacySafely(() => updateStats(result.stats));
            } catch (err) { toast(err.message, 'danger'); }
            finally { loading(false); }
        }, true);

        table.addEventListener('click', (e) => {
            const edit = e.target.closest('[data-hospital-edit]');
            const del = e.target.closest('[data-hospital-delete]');
            if (edit) { e.preventDefault(); e.stopImmediatePropagation(); fillEditModal(edit.dataset.hospitalEdit); }
            if (del) { e.preventDefault(); e.stopImmediatePropagation(); deleteHospital(del.dataset.hospitalDelete); }
        }, true);

        document.getElementById('saveEditHospital')?.addEventListener('click', (e) => {
            e.preventDefault();
            e.stopImmediatePropagation();
            saveEditHospital();
        }, true);
        document.getElementById('editHospitalForm')?.addEventListener('submit', (e) => {
            e.preventDefault();
            e.stopImmediatePropagation();
            saveEditHospital();
        }, true);
        document.getElementById('searchHospitals')?.addEventListener('input', renderHospitalTable);
        document.getElementById('btn-search-hospitals')?.addEventListener('click', renderHospitalTable);
        document.getElementById('tab-hospitals')?.addEventListener('shown.bs.tab', () => loadHospitals().catch(e => toast(e.message, 'danger')));
        window.openEditHospital = fillEditModal;
        window.confirmDeleteHospital = deleteHospital;
        window.saveEditHospitalDirect = saveEditHospital;
        loadHospitals().catch(e => toast(e.message, 'danger'));
    }
    ready(initHospitalManager);
})();

</script>

<script>
// محرر شعار المستشفى النهائي: يعمل بعد كل السكربتات القديمة ويعيد ربط المعاينة والتحريك بشكل مستقل.
(function () {
    const STATE = window.__hospitalLogoEditorState || {
        scale: 1,
        x: 0,
        y: 0,
        drag: null,
        previewToken: 0,
        objectUrl: '',
        bound: false
    };
    window.__hospitalLogoEditorState = STATE;

    function $(id) { return document.getElementById(id); }
    function clamp(value, min, max, fallback) {
        const n = parseFloat(value);
        if (!Number.isFinite(n)) return fallback;
        return Math.max(min, Math.min(max, n));
    }
    function toastLogo(message, type = 'warning') {
        if (typeof showToast === 'function') showToast(message, type);
        else console.warn(message);
    }
    function currentEls() {
        return {
            box: $('logoPreviewBox'),
            img: $('edit_hospital_logo_preview'),
            slider: $('logoScaleSlider'),
            label: $('logoScaleValue'),
            scaleInput: $('edit_logo_scale'),
            xInput: $('edit_logo_offset_x'),
            yInput: $('edit_logo_offset_y'),
            fileInput: $('edit_hospital_logo_file'),
            urlInput: $('edit_hospital_logo_url')
        };
    }
    function setState(scale = STATE.scale, x = STATE.x, y = STATE.y) {
        STATE.scale = clamp(scale, 0.3, 3, 1);
        STATE.x = clamp(x, -600, 600, 0);
        STATE.y = clamp(y, -600, 600, 0);
    }
    function syncHospitalLogoUi() {
        const el = currentEls();
        setState();
        if (el.img) {
            el.img.style.display = 'block';
            el.img.style.visibility = 'visible';
            el.img.style.position = 'absolute';
            el.img.style.inset = '0';
            el.img.style.width = '100%';
            el.img.style.height = '100%';
            el.img.style.maxWidth = 'none';
            el.img.style.maxHeight = 'none';
            el.img.style.objectFit = 'contain';
            el.img.style.transformOrigin = 'center center';
            el.img.style.transform = `translate(${STATE.x}px, ${STATE.y}px) scale(${STATE.scale})`;
            el.img.style.pointerEvents = 'none';
            el.img.style.userSelect = 'none';
            el.img.draggable = false;
        }
        if (el.box) {
            el.box.style.touchAction = 'none';
            el.box.style.cursor = 'move';
            el.box.style.overflow = 'hidden';
            el.box.style.position = 'relative';
        }
        if (el.scaleInput) el.scaleInput.value = STATE.scale.toFixed(2);
        if (el.xInput) el.xInput.value = STATE.x.toFixed(1);
        if (el.yInput) el.yInput.value = STATE.y.toFixed(1);
        if (el.slider) el.slider.value = String(STATE.scale);
        if (el.label) el.label.textContent = Math.round(STATE.scale * 100) + '%';
    }
    function revokeOldObjectUrl() {
        if (STATE.objectUrl) {
            try { URL.revokeObjectURL(STATE.objectUrl); } catch (_) {}
            STATE.objectUrl = '';
        }
    }
    function showHospitalLogoPreviewHard(src, options = {}) {
        const el = currentEls();
        if (!el.img || !src) return;
        if (options.resetControls) setState(1, 0, 0);
        syncHospitalLogoUi();
        el.img.onload = function () {
            el.img.style.opacity = '1';
            syncHospitalLogoUi();
        };
        el.img.onerror = function () {
            // نبقي صندوق التحكم ظاهراً حتى يستطيع المستخدم تغيير الرابط أو اختيار ملف آخر.
            el.img.style.opacity = '0.35';
            syncHospitalLogoUi();
        };
        el.img.style.opacity = '0.85';
        el.img.removeAttribute('hidden');
        el.img.setAttribute('alt', 'معاينة شعار المستشفى');
        el.img.src = src;
        syncHospitalLogoUi();
    }
    function previewHospitalLogoFileHard(inputOrFile) {
        const file = inputOrFile instanceof File ? inputOrFile : inputOrFile?.files?.[0];
        if (!file) return;
        const isImage = /^image\//i.test(file.type || '') || /\.(png|jpe?g|gif|webp|svg|bmp|ico)$/i.test(file.name || '');
        if (!isImage) {
            toastLogo('يرجى اختيار ملف صورة صالح للشعار.', 'warning');
            return;
        }
        revokeOldObjectUrl();
        const el = currentEls();
        if (el.urlInput) el.urlInput.value = '';
        try {
            STATE.objectUrl = URL.createObjectURL(file);
            showHospitalLogoPreviewHard(STATE.objectUrl, { resetControls: true });
        } catch (_) {}
        const reader = new FileReader();
        reader.onload = function (event) {
            if (event.target?.result) showHospitalLogoPreviewHard(event.target.result, { resetControls: false });
        };
        reader.onerror = function () { toastLogo('تعذّر قراءة ملف الشعار. جرّب صورة أخرى.', 'danger'); };
        reader.readAsDataURL(file);
    }
    function normalizeLogoUrl(raw) {
        const value = String(raw || '').trim();
        if (!value) return '';
        if (/^https?:\/\//i.test(value) || /^data:image\//i.test(value)) return value;
        if (/^[\w.-]+\.[a-z]{2,}(\/.*)?$/i.test(value)) return 'https://' + value;
        return value;
    }
    async function fetchServerLogoPreview(url, token) {
        if (!/^https?:\/\//i.test(url)) return;
        try {
            const fd = new FormData();
            fd.set('action', 'preview_hospital_logo_url');
            fd.set('csrf_token', typeof CSRF_TOKEN !== 'undefined' ? CSRF_TOKEN : '');
            fd.set('hospital_logo_url', url);
            const res = await fetch(typeof REQUEST_URL !== 'undefined' ? REQUEST_URL : window.location.pathname, {
                method: 'POST',
                body: fd,
                headers: { 'X-Requested-With': 'XMLHttpRequest' }
            });
            const result = await res.json();
            const current = normalizeLogoUrl(currentEls().urlInput?.value || '');
            if (token === STATE.previewToken && current === url && result?.success && result.logo_data) {
                showHospitalLogoPreviewHard(result.logo_data, { resetControls: false });
            }
        } catch (err) {
            console.warn('Hospital logo server preview failed; direct URL preview remains active.', err);
        }
    }
    let urlTimer = null;
    function previewHospitalLogoUrlHard(forceReset = false) {
        const el = currentEls();
        const url = normalizeLogoUrl(el.urlInput?.value || '');
        if (!url) return;
        revokeOldObjectUrl();
        if (el.fileInput) el.fileInput.value = '';
        if (el.urlInput && /^https?:\/\//i.test(url) && el.urlInput.value.trim() !== url) el.urlInput.value = url;
        const token = ++STATE.previewToken;
        showHospitalLogoPreviewHard(url, { resetControls: forceReset });
        clearTimeout(urlTimer);
        urlTimer = setTimeout(() => fetchServerLogoPreview(url, token), 250);
    }
    function bindHospitalLogoEditor() {
        const el = currentEls();
        if (!el.img || !el.box) return;
        if (!STATE.bound) {
            document.addEventListener('change', function (event) {
                if (event.target?.id === 'edit_hospital_logo_file') previewHospitalLogoFileHard(event.target);
                if (event.target?.id === 'edit_hospital_logo_url') previewHospitalLogoUrlHard(true);
            }, true);
            document.addEventListener('input', function (event) {
                if (event.target?.id === 'edit_hospital_logo_url') previewHospitalLogoUrlHard(false);
                if (event.target?.id === 'logoScaleSlider') {
                    setState(event.target.value, STATE.x, STATE.y);
                    syncHospitalLogoUi();
                }
            }, true);
            document.addEventListener('paste', function (event) {
                if (event.target?.id === 'edit_hospital_logo_url') setTimeout(() => previewHospitalLogoUrlHard(true), 0);
            }, true);
            document.addEventListener('click', function (event) {
                if (event.target?.closest('#logoResetBtn')) {
                    setState(1, 0, 0);
                    syncHospitalLogoUi();
                }
            }, true);
            document.addEventListener('submit', function (event) {
                if (event.target?.id === 'editHospitalForm') syncHospitalLogoUi();
            }, true);
            document.addEventListener('pointermove', function (event) {
                if (!STATE.drag) return;
                setState(STATE.scale, event.clientX - STATE.drag.startX, event.clientY - STATE.drag.startY);
                syncHospitalLogoUi();
                event.preventDefault();
            }, true);
            document.addEventListener('pointerup', function () { STATE.drag = null; }, true);
            document.addEventListener('pointercancel', function () { STATE.drag = null; }, true);
            STATE.bound = true;
        }
        if (el.box.dataset.logoEditorBound !== '1') {
            el.box.dataset.logoEditorBound = '1';
            el.box.addEventListener('pointerdown', function (event) {
                STATE.drag = { startX: event.clientX - STATE.x, startY: event.clientY - STATE.y };
                try { el.box.setPointerCapture(event.pointerId); } catch (_) {}
                event.preventDefault();
            }, true);
        }
        syncHospitalLogoUi();
    }

    window.showHospitalLogoPreview = showHospitalLogoPreviewHard;
    window.previewHospitalLogoFileInput = previewHospitalLogoFileHard;
    window.previewHospitalLogoUrlInput = previewHospitalLogoUrlHard;
    window.syncHospitalLogoHiddenFields = syncHospitalLogoUi;
    window.syncHospitalLogoTransform = function (scale = 1, x = 0, y = 0) {
        setState(scale, x, y);
        syncHospitalLogoUi();
    };

    if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', bindHospitalLogoEditor);
    else bindHospitalLogoEditor();
    document.addEventListener('shown.bs.modal', function (event) {
        if (event.target?.id === 'editHospitalModal') bindHospitalLogoEditor();
    });
})();
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

<script>
(function(){
    document.addEventListener('contextmenu', function(e){ e.preventDefault(); });
    document.addEventListener('keydown', function(e){
        if(e.key==='F12'||(e.ctrlKey&&e.shiftKey&&(e.key==='I'||e.key==='J'||e.key==='C'))||(e.ctrlKey&&e.key==='u')||(e.ctrlKey&&e.key==='s')){
            e.preventDefault(); return false;
        }
    });
    document.addEventListener('dragstart', function(e){ e.preventDefault(); });
})();
</script>
</body>
</html>
