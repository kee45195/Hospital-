<?php
require_once '../config/config.php';

// Require doctor login
if (!isset($_SESSION['doctor_id'])) {
    header('Location: login.php');
    exit();
}

$doctor_id = $_SESSION['doctor_id'];
$doctor_name = $_SESSION['doctor_name'] ?? 'Doctor';
$success_message = '';
$error_message = '';

/* =========================
   Helpers
   ========================= */

/**
 * Parse a time string in flexible formats to canonical H:i:s (24h).
 * Accepts: "H:i", "H:i:s", "h:i AM/PM", "h:i:s AM/PM".
 * Returns H:i:s or null on failure.
 */
function parse_time_to_his(?string $t): ?string {
    if ($t === null) return null;
    $t = trim($t);
    if ($t === '') return null;

    // Try strict formats first
    $formats = [
        'H:i:s',
        'H:i',
        'g:i A',
        'g:i a',
        'g:i:s A',
        'g:i:s a'
    ];
    foreach ($formats as $fmt) {
        $dt = DateTime::createFromFormat('!' . $fmt, $t);
        if ($dt && $dt->getLastErrors()['error_count'] === 0 && $dt->getLastErrors()['warning_count'] === 0) {
            return $dt->format('H:i:s');
        }
    }

    // Last resort: strtotime
    $ts = strtotime($t);
    if ($ts !== false) {
        return date('H:i:s', $ts);
    }
    return null;
}

/**
 * Compare two H:i:s times in the same day.
 * Returns true if $end is strictly after $start.
 */
function is_end_after_start(string $start_his, string $end_his): bool {
    $s = DateTime::createFromFormat('!H:i:s', $start_his);
    $e = DateTime::createFromFormat('!H:i:s', $end_his);
    if (!$s || !$e) return false;
    return $e > $s; // same-day windows only (no overnight)
}

/**
 * Convert H:i(:s) to H:i for <input type="time"> values.
 */
function his_to_hi(string $his): string {
    $dt = DateTime::createFromFormat('!H:i:s', strlen($his) === 5 ? $his . ':00' : $his);
    return $dt ? $dt->format('H:i') : $his;
}

/* =========================
   Handle POST actions
   ========================= */

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    if (!validateCSRFToken($_POST['csrf_token'] ?? '')) {
        $error_message = 'Invalid security token. Please try again.';
    } else {
        $action = $_POST['action'] ?? '';

        try {
            if ($action === 'add_availability') {
                $available_day_raw = $_POST['available_day'] ?? '';
                $start_raw = $_POST['start_time'] ?? '';
                $end_raw   = $_POST['end_time'] ?? '';

                $available_day = trim($available_day_raw);
                $start_his = parse_time_to_his($start_raw);
                $end_his   = parse_time_to_his($end_raw);

                if ($available_day === '' || !$start_his || !$end_his) {
                    $error_message = 'Please fill in all required fields (day, start, end).';
                } elseif (!in_array($available_day, ['Monday','Tuesday','Wednesday','Thursday','Friday','Saturday','Sunday'], true)) {
                    $error_message = 'Invalid day selected.';
                } elseif (!is_end_after_start($start_his, $end_his)) {
                    $error_message = 'End time must be after start time (same day). Tip: 12:00 PM = noon, 12:00 AM = midnight.';
                } else {
                    // Ensure no duplicate day entries
                    $stmt = $pdo->prepare("SELECT COUNT(*) FROM doctor_availability WHERE doctor_id = ? AND available_day = ?");
                    $stmt->execute([$doctor_id, $available_day]);
                    if ($stmt->fetchColumn() > 0) {
                        $error_message = 'Availability for this day already exists. Please edit the existing entry.';
                    } else {
                        $stmt = $pdo->prepare("
                            INSERT INTO doctor_availability (doctor_id, available_day, start_time, end_time, is_active)
                            VALUES (?, ?, ?, ?, 1)
                        ");
                        $stmt->execute([$doctor_id, $available_day, $start_his, $end_his]);
                        $success_message = 'Availability added successfully.';
                    }
                }

            } elseif ($action === 'update_availability') {
                $availability_id = (int)($_POST['availability_id'] ?? 0);
                $start_raw = $_POST['start_time'] ?? '';
                $end_raw   = $_POST['end_time'] ?? '';

                $start_his = parse_time_to_his($start_raw);
                $end_his   = parse_time_to_his($end_raw);

                if ($availability_id <= 0) {
                    $error_message = 'Invalid availability item.';
                } elseif (!$start_his || !$end_his) {
                    $error_message = 'Please provide valid times.';
                } elseif (!is_end_after_start($start_his, $end_his)) {
                    $error_message = 'End time must be after start time (same day). Tip: 12:00 PM = noon, 12:00 AM = midnight.';
                } else {
                    $stmt = $pdo->prepare("
                        UPDATE doctor_availability
                           SET start_time = ?, end_time = ?
                         WHERE id = ? AND doctor_id = ?
                    ");
                    $stmt->execute([$start_his, $end_his, $availability_id, $doctor_id]);
                    $success_message = 'Availability updated successfully.';
                }

            } elseif ($action === 'delete_availability') {
                $availability_id = (int)($_POST['availability_id'] ?? 0);
                if ($availability_id <= 0) {
                    $error_message = 'Invalid availability item.';
                } else {
                    $stmt = $pdo->prepare("DELETE FROM doctor_availability WHERE id = ? AND doctor_id = ?");
                    $stmt->execute([$availability_id, $doctor_id]);
                    $success_message = 'Availability deleted successfully.';
                }
            }
        } catch (PDOException $e) {
            $error_message = 'Database error occurred. Please try again.';
        }
    }
}

/* =========================
   Fetch data for view
   ========================= */

try {
    $stmt = $pdo->prepare("
        SELECT * FROM doctor_availability
         WHERE doctor_id = ?
      ORDER BY FIELD(available_day, 'Monday','Tuesday','Wednesday','Thursday','Friday','Saturday','Sunday')
    ");
    $stmt->execute([$doctor_id]);
    $availabilities = $stmt->fetchAll();

    // Upcoming appointments count by day
    $stmt = $pdo->prepare("
        SELECT DAYNAME(appointment_date) AS day_name, COUNT(*) AS appointment_count
          FROM appointments
         WHERE doctor_id = ?
           AND appointment_date >= CURDATE()
           AND LOWER(status) IN ('confirmed','pending')
      GROUP BY DAYNAME(appointment_date)
    ");
    $stmt->execute([$doctor_id]);
    $appointment_counts = [];
    while ($row = $stmt->fetch()) {
        $appointment_counts[$row['day_name']] = (int)$row['appointment_count'];
    }
} catch (PDOException $e) {
    $error_message = 'Database error occurred.';
    $availabilities = [];
}

$csrf_token = generateCSRFToken();
$days_of_week = ['Monday','Tuesday','Wednesday','Thursday','Friday','Saturday','Sunday'];
?>
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Availability Management - <?php echo APP_NAME; ?></title>
<link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
<link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css" rel="stylesheet">
<style>
    :root {
        --primary-color: #00838F;
        --secondary-color: #A5D6A7;
        --accent-color: #7E57C2;
        --background-color: #F4F6F8;
        --text-color: #263238;
    }
    body { background: var(--background-color); color: var(--text-color); font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; }
    .navbar { background-color: var(--primary-color) !important; box-shadow: 0 2px 10px rgba(0,0,0,.1); }
    .navbar-brand { font-weight: 700; font-size: 1.5rem; }
    .main-content { padding: 2rem 0; }
    .page-header { background: linear-gradient(135deg, var(--primary-color) 0%, var(--accent-color) 100%); color: #fff; border-radius: 15px; padding: 2rem; margin-bottom: 2rem; }
    .content-card { background: #fff; border-radius: 15px; padding: 1.5rem; box-shadow: 0 5px 15px rgba(0,0,0,.08); margin-bottom: 2rem; }
    .btn-primary { background: var(--primary-color); border-color: var(--primary-color); }
    .btn-primary:hover { background: #006064; border-color: #006064; }
    .btn-secondary { background: var(--secondary-color); border-color: var(--secondary-color); color: var(--text-color); }
    .btn-accent { background: var(--accent-color); border-color: var(--accent-color); color: #fff; }
    .availability-card { border: 1px solid #e0e0e0; border-radius: 10px; padding: 1.5rem; margin-bottom: 1rem; transition: all .3s ease; }
    .availability-card:hover { box-shadow: 0 5px 15px rgba(0,0,0,.1); transform: translateY(-2px); }
    .day-header { background: var(--primary-color); color: #fff; padding: .75rem 1rem; border-radius: 8px; font-weight: 600; margin-bottom: 1rem; }
    .appointment-count { background: var(--accent-color); color:#fff; padding:.25rem .5rem; border-radius:15px; font-size:.75rem; font-weight:600; }
    .no-availability { text-align:center; padding:3rem; color:#666; }
    .quick-add-form { background: var(--background-color); border-radius: 10px; padding: 1.5rem; }
</style>
</head>
<body>
<nav class="navbar navbar-expand-lg navbar-dark">
    <div class="container">
        <a class="navbar-brand" href="dashboard.php">
            <i class="fas fa-hospital me-2"></i><?php echo APP_NAME; ?> - Doctor
        </a>
        <button class="navbar-toggler" type="button" data-bs-toggle="collapse" data-bs-target="#navbarNav">
            <span class="navbar-toggler-icon"></span>
        </button>
        <div class="collapse navbar-collapse" id="navbarNav">
            <ul class="navbar-nav me-auto">
                <li class="nav-item"><a class="nav-link" href="dashboard.php"><i class="fas fa-tachometer-alt me-1"></i>Dashboard</a></li>
                <li class="nav-item"><a class="nav-link" href="appointments.php"><i class="fas fa-calendar-check me-1"></i>Appointments</a></li>
                <li class="nav-item"><a class="nav-link active" href="availability.php"><i class="fas fa-clock me-1"></i>Availability</a></li>
                <li class="nav-item"><a class="nav-link" href="patients.php"><i class="fas fa-user-injured me-1"></i>Patients</a></li>
                <li class="nav-item"><a class="nav-link" href="feedback.php"><i class="fas fa-star me-1"></i>Feedback</a></li>
            </ul>
            <ul class="navbar-nav">
                <li class="nav-item dropdown">
                    <a class="nav-link dropdown-toggle" href="#" id="navbarDropdown" role="button" data-bs-toggle="dropdown">
                        <i class="fas fa-user-md me-1"></i><?php echo htmlspecialchars($doctor_name); ?>
                    </a>
                    <ul class="dropdown-menu">
                        <li><a class="dropdown-item" href="profile.php"><i class="fas fa-user me-2"></i>Profile</a></li>
                        <li><hr class="dropdown-divider"></li>
                        <li><a class="dropdown-item" href="logout.php"><i class="fas fa-sign-out-alt me-2"></i>Logout</a></li>
                    </ul>
                </li>
            </ul>
        </div>
    </div>
</nav>

<div class="main-content">
    <div class="container">
        <!-- Header -->
        <div class="page-header">
            <div class="row align-items-center">
                <div class="col-md-8">
                    <h1 class="mb-2"><i class="fas fa-clock me-3"></i>Availability Management</h1>
                    <p class="mb-0 opacity-75">Set your working hours and manage appointment time slots</p>
                </div>
                <div class="col-md-4 text-end">
                    <i class="fas fa-calendar-week" style="font-size: 4rem; opacity: .3;"></i>
                </div>
            </div>
        </div>

        <!-- Messages -->
        <?php if ($success_message): ?>
            <div class="alert alert-success alert-dismissible fade show" role="alert">
                <i class="fas fa-check-circle me-2"></i><?php echo htmlspecialchars($success_message); ?>
                <button type="button" class="btn-close" data-bs-dismiss="alert"></button>
            </div>
        <?php endif; ?>
        <?php if ($error_message): ?>
            <div class="alert alert-danger alert-dismissible fade show" role="alert">
                <i class="fas fa-exclamation-circle me-2"></i><?php echo htmlspecialchars($error_message); ?>
                <button type="button" class="btn-close" data-bs-dismiss="alert"></button>
            </div>
        <?php endif; ?>

        <!-- Add Availability -->
        <div class="content-card">
            <div class="d-flex justify-content-between align-items-center mb-3">
                <h3><i class="fas fa-plus me-2"></i>Add New Availability</h3>
            </div>
            <div class="quick-add-form">
                <form method="POST">
                    <input type="hidden" name="csrf_token" value="<?php echo $csrf_token; ?>">
                    <input type="hidden" name="action" value="add_availability">

                    <div class="row g-3">
                        <div class="col-md-3">
                            <label for="available_day" class="form-label">Day of Week</label>
                            <select class="form-select" id="available_day" name="available_day" required>
                                <option value="">Select Day</option>
                                <?php foreach ($days_of_week as $day): ?>
                                    <?php 
                                        $exists = false;
                                        foreach ($availabilities as $a) {
                                            if ($a['available_day'] === $day) { $exists = true; break; }
                                        }
                                    ?>
                                    <?php if (!$exists): ?>
                                        <option value="<?php echo $day; ?>"><?php echo $day; ?></option>
                                    <?php endif; ?>
                                <?php endforeach; ?>
                            </select>
                        </div>
                        <div class="col-md-2">
                            <label for="start_time" class="form-label">Start Time</label>
                            <input type="time" class="form-control" id="start_time" name="start_time" required>
                        </div>
                        <div class="col-md-2">
                            <label for="end_time" class="form-label">End Time</label>
                            <input type="time" class="form-control" id="end_time" name="end_time" required>
                            <small class="text-muted">Use 12:00 PM for noon, 12:00 AM for midnight</small>
                        </div>
                        <div class="col-md-2">
                            <label class="form-label">&nbsp;</label>
                            <div class="d-grid">
                                <button type="submit" class="btn btn-primary">
                                    <i class="fas fa-plus me-1"></i>Add
                                </button>
                            </div>
                        </div>
                    </div>
                </form>
            </div>
        </div>

        <!-- Current Availability -->
        <div class="content-card">
            <div class="d-flex justify-content-between align-items-center mb-4">
                <h3><i class="fas fa-calendar-week me-2"></i>Current Weekly Schedule</h3>
            </div>

            <?php if (empty($availabilities)): ?>
                <div class="no-availability">
                    <i class="fas fa-calendar-times" style="font-size: 4rem; color: #ccc;"></i>
                    <h4 class="mt-3 text-muted">No availability set</h4>
                    <p class="text-muted">Add your working hours above to start receiving appointment bookings.</p>
                </div>
            <?php else: ?>
                <div class="row">
                    <?php foreach ($availabilities as $availability): ?>
                        <div class="col-lg-6 col-xl-4 mb-3">
                            <div class="availability-card">
                                <div class="day-header d-flex justify-content-between align-items-center">
                                    <span><i class="fas fa-calendar-day me-2"></i><?php echo htmlspecialchars($availability['available_day']); ?></span>
                                    <?php if (isset($appointment_counts[$availability['available_day']])): ?>
                                        <span class="appointment-count"><?php echo (int)$appointment_counts[$availability['available_day']]; ?> appointments</span>
                                    <?php endif; ?>
                                </div>
                                <div class="mb-3">
                                    <strong>Working Hours:</strong><br>
                                    <i class="fas fa-clock me-1"></i>
                                    <?php echo date('g:i A', strtotime($availability['start_time'])); ?> -
                                    <?php echo date('g:i A', strtotime($availability['end_time'])); ?>
                                </div>

                                <div class="d-flex gap-2">
                                    <button type="button" class="btn btn-accent btn-sm"
                                        data-bs-toggle="modal" data-bs-target="#editModal"
                                        data-id="<?php echo (int)$availability['id']; ?>"
                                        data-day="<?php echo htmlspecialchars($availability['available_day']); ?>"
                                        data-start="<?php echo his_to_hi($availability['start_time']); ?>"
                                        data-end="<?php echo his_to_hi($availability['end_time']); ?>">
                                        <i class="fas fa-edit me-1"></i>Edit
                                    </button>

                                    <form method="POST" class="d-inline"
                                          onsubmit="return confirm('Delete this availability? This may affect future bookings.')">
                                        <input type="hidden" name="csrf_token" value="<?php echo $csrf_token; ?>">
                                        <input type="hidden" name="action" value="delete_availability">
                                        <input type="hidden" name="availability_id" value="<?php echo (int)$availability['id']; ?>">
                                        <button type="submit" class="btn btn-outline-danger btn-sm">
                                            <i class="fas fa-trash me-1"></i>Delete
                                        </button>
                                    </form>
                                </div>
                            </div>
                        </div>
                    <?php endforeach; ?>
                </div>
            <?php endif; ?>
        </div>
    </div>
</div>

<!-- Edit Modal -->
<div class="modal fade" id="editModal" tabindex="-1">
  <div class="modal-dialog">
    <div class="modal-content">
        <div class="modal-header">
            <h5 class="modal-title"><i class="fas fa-edit me-2"></i>Edit Availability</h5>
            <button type="button" class="btn-close btn-close-white" data-bs-dismiss="modal"></button>
        </div>
        <form method="POST">
            <div class="modal-body">
                <input type="hidden" name="csrf_token" value="<?php echo $csrf_token; ?>">
                <input type="hidden" name="action" value="update_availability">
                <input type="hidden" name="availability_id" id="edit_availability_id">

                <div class="mb-3">
                    <label class="form-label">Day:</label>
                    <p class="fw-bold mb-0" id="edit_day"></p>
                </div>
                <div class="row">
                    <div class="col-md-6">
                        <label for="edit_start_time" class="form-label">Start Time</label>
                        <input type="time" class="form-control" id="edit_start_time" name="start_time" required>
                    </div>
                    <div class="col-md-6">
                        <label for="edit_end_time" class="form-label">End Time</label>
                        <input type="time" class="form-control" id="edit_end_time" name="end_time" required>
                        <small class="text-muted">Use 12:00 PM for noon, 12:00 AM for midnight</small>
                    </div>
                </div>
            </div>
            <div class="modal-footer">
                <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">Cancel</button>
                <button type="submit" class="btn btn-primary">
                    <i class="fas fa-save me-2"></i>Update
                </button>
            </div>
        </form>
    </div>
  </div>
</div>

<script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js"></script>
<script>
document.getElementById('editModal').addEventListener('show.bs.modal', function (event) {
    const button = event.relatedTarget;
    document.getElementById('edit_availability_id').value = button.getAttribute('data-id');
    document.getElementById('edit_day').textContent       = button.getAttribute('data-day');
    // Pre-fill inputs with HH:MM (24h) so the browser time picker displays correctly
    document.getElementById('edit_start_time').value      = button.getAttribute('data-start'); // HH:MM
    document.getElementById('edit_end_time').value        = button.getAttribute('data-end');   // HH:MM
});
</script>

<?php


$__hasPdo = isset($pdo) && $pdo instanceof PDO;
$__hasMysqli = isset($conn) && $conn instanceof mysqli;

if (!$__hasPdo && !$__hasMysqli) {
    $configPaths = [
        __DIR__ . '/config/config.php',
        __DIR__ . '/config.php',
        dirname(__DIR__) . '/config/config.php'
    ];
    foreach ($configPaths as $cp) { if (file_exists($cp)) { @require_once $cp; break; } }
    if (defined('DB_HOST') && defined('DB_NAME') && defined('DB_USER')) {
        try {
            $pdo = new PDO('mysql:host=' . DB_HOST . ';dbname=' . DB_NAME . ';charset=utf8mb4', DB_USER, defined('DB_PASS') ? DB_PASS : '');
            $pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
            $__hasPdo = true;
        } catch (Throwable $e) { /* ignore */ }
    }
}

function __slot_time_range($start = '09:00', $end = '17:00', $stepMinutes = 30) {
    $out = [];
    $t = DateTime::createFromFormat('H:i', $start);
    $endT = DateTime::createFromFormat('H:i', $end);
    if (!$t || !$endT) return $out;
    while ($t <= $endT) {
        $out[] = $t->format('H:i');
        $t->modify('+' . (int)$stepMinutes . ' minutes');
    }
    return $out;
}

if (session_status() !== PHP_SESSION_ACTIVE) { @session_start(); }
$doctorId = null;
if (isset($_GET['doctor_id']) && $_GET['doctor_id'] !== '') {
    $doctorId = (int)$_GET['doctor_id'];
} elseif (isset($_SESSION['doctor_id'])) {
    $doctorId = (int)$_SESSION['doctor_id'];
}

$chosenDate = isset($_GET['date']) && $_GET['date'] !== '' ? $_GET['date'] : date('Y-m-d');

$bookedByTime = [];
$appointmentsList = [];
if ($doctorId) {
    try {
        if (isset($pdo) && $pdo instanceof PDO) {
            $stmt = $pdo->prepare("
                SELECT id, patient_id, doctor_id, `appointment date` AS appt_date, `appointment time` AS appt_time, status, notes, `created-at` AS created_at, `updated at` AS updated_at
                FROM appointments
                WHERE doctor_id = :doc
                  AND `appointment date` = :d
                  AND (status IN ('confirmed','approved','scheduled','pending') OR status IS NULL)
                ORDER BY `appointment time` ASC
            ");
            $stmt->execute([':doc' => $doctorId, ':d' => $chosenDate]);
            $appointmentsList = $stmt->fetchAll(PDO::FETCH_ASSOC);
        } elseif (isset($conn) && $conn instanceof mysqli) {
            $doc = (int)$doctorId;
            $d = $conn->real_escape_string($chosenDate);
            $res = $conn->query("
                SELECT id, patient_id, doctor_id, `appointment date` AS appt_date, `appointment time` AS appt_time, status, notes, `created-at` AS created_at, `updated at` AS updated_at
                FROM appointments
                WHERE doctor_id = {$doc}
                  AND `appointment date` = '{$d}'
                  AND (status IN ('confirmed','approved','scheduled','pending') OR status IS NULL)
                ORDER BY `appointment time` ASC
            ");
            if ($res) { while ($row = $res->fetch_assoc()) { $appointmentsList[] = $row; } }
        }
        foreach ($appointmentsList as $a) {
            $t = $a['appt_time'] ?? ($a['appointment time'] ?? null);
            if ($t) {
                $norm = date('H:i', strtotime($t));
                $bookedByTime[$norm] = $a;
            }
        }
    } catch (Throwable $e) { /* ignore */ }
}
$slots = __slot_time_range('09:00','17:00',30);
?>

<div class="card mb-4">
    <div class="card-header d-flex justify-content-between align-items-center">
        <h3 class="mb-0"><i class="fas fa-calendar-day me-2"></i>Daily Time Slot Grid</h3>
        <form method="get" class="d-flex gap-2 align-items-center" style="gap:.5rem">
            <?php if (isset($_GET['page'])): ?>
                <input type="hidden" name="page" value="<?php echo htmlspecialchars($_GET['page']); ?>">
            <?php endif; ?>
            <div class="form-group mb-0">
                <label class="form-label me-1">Doctor ID</label>
                <input class="form-control" type="number" name="doctor_id" value="<?php echo htmlspecialchars($doctorId ?? ''); ?>" min="1" required style="max-width:120px">
            </div>
            <div class="form-group mb-0">
                <label class="form-label me-1">Date</label>
                <input class="form-control" type="date" name="date" value="<?php echo htmlspecialchars($chosenDate); ?>" required>
            </div>
            <button class="btn btn-dark" type="submit">View</button>
        </form>
    </div>
    <div class="card-body">
        <?php if (!$doctorId): ?>
            <p class="text-muted mb-0">Enter a Doctor ID above to view the time slot grid.</p>
        <?php else: ?>
            <div class="table-responsive mb-3">
                <table class="table table-hover align-middle mb-0">
                    <thead>
                        <tr>
                            <th style="width:160px">Time</th>
                            <th>Status</th>
                            <th>Patient</th>
                            <th>Notes</th>
                        </tr>
                    </thead>
                    <tbody>
                        <?php foreach ($slots as $slot):
                            $label12h = date('g:i a', strtotime($slot));
                            $state = 'free';
                            $badge = '<span class="badge bg-success">Free</span>';
                            $rowClass = 'table-success';
                            $appt = $bookedByTime[$slot] ?? null;
                            if ($appt) {
                                $st = strtolower(trim($appt['status'] ?? 'confirmed'));
                                if (in_array($st, ['pending','awaiting','hold'])) {
                                    $state = 'pending'; $badge = '<span class="badge bg-warning text-dark">Pending</span>'; $rowClass = 'table-warning';
                                } else {
                                    $state = 'booked'; $badge = '<span class="badge bg-danger">Booked</span>'; $rowClass = 'table-danger';
                                }
                            }
                        ?>
                        <tr class="<?php echo $rowClass; ?>">
                            <td><strong><?php echo htmlspecialchars($label12h); ?></strong></td>
                            <td><?php echo $badge; ?></td>
                            <td><?php echo $appt ? htmlspecialchars($appt['patient_id']) : '-'; ?></td>
                            <td><?php echo $appt ? htmlspecialchars($appt['notes'] ?? '') : 'Available'; ?></td>
                        </tr>
                        <?php endforeach; ?>
                    </tbody>
                </table>
            </div>

            <h6 class="mt-3">Appointments for <?php echo htmlspecialchars(date('F j, Y', strtotime($chosenDate))); ?></h6>
            <div class="table-responsive">
                <table class="table table-sm">
                    <thead>
                        <tr>
                            <th>ID</th>
                            <th>Time</th>
                            <th>Patient</th>
                            <th>Status</th>
                            <th>Notes</th>
                        </tr>
                    </thead>
                    <tbody>
                        <?php if (empty($appointmentsList)): ?>
                            <tr><td colspan="5" class="text-muted">No appointments.</td></tr>
                        <?php else: foreach ($appointmentsList as $a): ?>
                            <tr>
                                <td>#<?php echo (int)$a['id']; ?></td>
                                <td><?php echo htmlspecialchars(date('g:i a', strtotime($a['appt_time']))); ?></td>
                                <td><?php echo htmlspecialchars($a['patient_id']); ?></td>
                                <td><?php echo htmlspecialchars($a['status'] ?? 'confirmed'); ?></td>
                                <td><?php echo htmlspecialchars($a['notes'] ?? ''); ?></td>
                            </tr>
                        <?php endforeach; endif; ?>
                    </tbody>
                </table>
            </div>
        <?php endif; ?>
    </div>
</div>
<!-- =================== END DAILY TIME SLOT GRID (inject) =================== -->


</body>
</html>
