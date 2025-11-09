<?php
require_once 'config/config.php';

// Require login
requireLogin();

$patient_id = getCurrentPatientId();
$errors = [];
$success_message = '';

/* =========================
   Helpers & Normalization
   ========================= */

/** Canonical text for statuses (for badges/labels). */
function canon_status_text(string $status): string {
    $s = strtolower(trim($status));
    if ($s === 'canceled') $s = 'cancelled'; // normalize spelling
    return match ($s) {
        'pending'   => 'Pending',
        'confirmed' => 'Confirmed',
        'completed' => 'Completed',
        'cancelled' => 'Cancelled',
        default     => ucwords($s),
    };
}

/** Build a CSS class suffix from status (lowercase, hyphenated). */
function status_class(string $status): string {
    $s = strtolower(trim($status));
    if ($s === 'canceled') $s = 'cancelled';
    return preg_replace('/\s+/', '-', $s);
}

if (!isset($cms) || !is_array($cms)) { $cms = []; }

// Pull CMS content (render as-is)
$cms = [
    'announcements'  => '',
    'services'       => '',
    'visiting_hours' => '',
    'contact_info'   => '',
];
try {
    $stmt = $pdo->prepare("
        SELECT section, content
          FROM site_content
         WHERE section IN ('announcements','services','visiting_hours','contact_info')
    ");
    $stmt->execute();
    foreach ($stmt->fetchAll() as $row) {
        $cms[$row['section']] = (string)$row['content'];
    }
} catch (PDOException $e) {
    // ignore; keep defaults
}

/* =========================
   POST: cancel / reschedule
   ========================= */

if ($_SERVER['REQUEST_METHOD'] == 'POST') {
    $action = sanitizeInput($_POST['action'] ?? '');
    $appointment_id = (int)($_POST['appointment_id'] ?? 0);

    // Validate CSRF token
    if (!validateCSRFToken($_POST['csrf_token'] ?? '')) {
        $errors[] = 'Invalid security token. Please try again.';
    } else {
        // Verify appointment belongs to current patient
        try {
            $stmt = $pdo->prepare("SELECT * FROM appointments WHERE id = ? AND patient_id = ?");
            $stmt->execute([$appointment_id, $patient_id]);
            $appointment = $stmt->fetch();

            if (!$appointment) {
                $errors[] = 'Appointment not found or access denied.';
            } else {
                if ($action === 'cancel') {
                    $stmt = $pdo->prepare("UPDATE appointments SET status = 'Cancelled', updated_at = NOW() WHERE id = ?");
                    $stmt->execute([$appointment_id]);
                    $success_message = 'Appointment cancelled successfully.';

                } elseif ($action === 'reschedule') {
                    $new_date = sanitizeInput($_POST['new_date'] ?? '');
                    $new_time = sanitizeInput($_POST['new_time'] ?? '');

                    if (empty($new_date) || empty($new_time)) {
                        $errors[] = 'Please provide both new date and time.';
                    } elseif (strtotime($new_date) < strtotime(date('Y-m-d'))) {
                        $errors[] = 'New appointment date cannot be in the past.';
                    } else {
                        // Check for conflicts: only Pending/Confirmed block the slot
                        $stmt = $pdo->prepare("
                            SELECT id FROM appointments
                            WHERE doctor_id = ?
                              AND appointment_date = ?
                              AND appointment_time = ?
                              AND LOWER(status) IN ('pending', 'confirmed')
                              AND id != ?
                        ");
                        $stmt->execute([$appointment['doctor_id'], $new_date, $new_time, $appointment_id]);

                        if ($stmt->fetch()) {
                            $errors[] = 'The selected time slot is already booked. Please choose another time.';
                        } else {
                            // Update to new datetime and mark as Pending
                            $stmt = $pdo->prepare("
                                UPDATE appointments
                                SET appointment_date = ?, appointment_time = ?, status = 'Pending', updated_at = NOW()
                                WHERE id = ?
                            ");
                            $stmt->execute([$new_date, $new_time, $appointment_id]);
                            $success_message = 'Appointment rescheduled successfully.';
                        }
                    }
                }
            }
        } catch (PDOException $e) {
            $errors[] = 'Database error. Please try again.';
        }
    }
}

/* =========================
   Fetch appointments (with DB-side "is past" flag)
   IMPORTANT: We compute the full appointment datetime and whether it’s past
   using MySQL’s CURRENT_TIMESTAMP so timezone matches the DB.
   ========================= */

try {
    $stmt = $pdo->prepare("
        SELECT
            a.*,
            d.name AS doctor_name,
            d.specialization,
            d.contact AS doctor_contact,
            d.working_days,
            d.working_hours,
            TIMESTAMP(a.appointment_date, a.appointment_time) AS appt_datetime,
            (TIMESTAMP(a.appointment_date, a.appointment_time) < CURRENT_TIMESTAMP) AS is_past
        FROM appointments a
        JOIN doctors d ON a.doctor_id = d.id
        WHERE a.patient_id = ?
        ORDER BY a.appointment_date DESC, a.appointment_time DESC
    ");
    $stmt->execute([$patient_id]);
    $appointments = $stmt->fetchAll();
} catch (PDOException $e) {
    die('Database error: ' . $e->getMessage());
}

/* =========================
   Bucket: Upcoming / Past / Cancelled
   Using DB-computed is_past to avoid PHP/DB timezone drift.
   ========================= */

$upcoming_appointments = [];
$past_appointments = [];
$cancelled_appointments = [];

$upcoming_statuses = ['pending', 'confirmed'];

foreach ($appointments as $appointment) {
    $status_lc = strtolower(trim($appointment['status'] ?? ''));
    if ($status_lc === 'canceled') $status_lc = 'cancelled';

    // Cancelled tab always
    if ($status_lc === 'cancelled') {
        $cancelled_appointments[] = $appointment;
        continue;
    }

    // Use DB-evaluated flag: '1' for past, '0' for future/now
    $isPast = (int)($appointment['is_past'] ?? 0) === 1;

    if ($isPast) {
        $past_appointments[] = $appointment;
    } elseif (in_array($status_lc, $upcoming_statuses, true)) {
        $upcoming_appointments[] = $appointment;
    } else {
        // Anything else → past
        $past_appointments[] = $appointment;
    }
}

$csrf_token = generateCSRFToken();
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>My Appointments - <?php echo APP_NAME; ?></title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
    <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css" rel="stylesheet">
    <style>
        :root {
            --primary-color: <?php echo COLOR_PRIMARY; ?>;
            --secondary-color: <?php echo COLOR_SECONDARY; ?>;
            --accent-color: <?php echo COLOR_ACCENT; ?>;
            --background-color: <?php echo COLOR_BACKGROUND; ?>;
            --text-color: <?php echo COLOR_TEXT; ?>;
        }

        body { background-color: var(--background-color); color: var(--text-color); font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; }
        .navbar { background: linear-gradient(135deg, var(--primary-color), #00796b) !important; box-shadow: 0 2px 10px rgba(0,0,0,.1); }
        .navbar-brand { font-weight: 700; font-size: 1.5rem; }
        .navbar-nav .nav-link { color: #fff !important; font-weight: 500; margin: 0 10px; transition: all .3s ease; }
        .navbar-nav .nav-link:hover { color: var(--secondary-color) !important; }
        .hospital-card { background: #fff; border-radius: 20px; box-shadow: 0 10px 30px rgba(0,0,0,.1); border: none; transition: all .3s ease; }
        .hospital-card:hover { transform: translateY(-2px); box-shadow: 0 15px 40px rgba(0,0,0,.15); }
        .appointments-header { background: linear-gradient(135deg, var(--primary-color), #00796b); color: #fff; padding: 3rem 0; position: relative; overflow: hidden; }
        .appointments-header::before { content: ''; position: absolute; inset: 0; background: url('https://images.unsplash.com/photo-1551190822-a9333d879b1f?ixlib=rb-4.0.3&auto=format&fit=crop&w=1200&q=80') center/cover; opacity: .1; }
        .header-content { position: relative; z-index: 1; text-align: center; }
        .appointment-card { border-left: 5px solid var(--primary-color); margin-bottom: 1.5rem; }
        .appointment-card.upcoming { border-left-color: var(--secondary-color); }
        .appointment-card.past { border-left-color: #6c757d; }
        .appointment-card.cancelled { border-left-color: var(--accent-color); opacity: 0.9; }
        .appointment-header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 1rem; }
        .doctor-name { color: var(--primary-color); font-weight: 700; font-size: 1.2rem; }
        .appointment-status { padding: .4rem 1rem; border-radius: 20px; font-size: .85rem; font-weight: 600; text-transform: capitalize; }
        .status-pending { background: #17a2b8; color: #fff; }
        .status-confirmed { background: var(--primary-color); color: #fff; }
        .status-completed { background: #28a745; color: #fff; }
        .status-cancelled { background: var(--accent-color); color: #fff; }
        .appointment-details { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px,1fr)); gap: 1rem; margin-bottom: 1rem; }
        .detail-item { display: flex; align-items: center; }
        .detail-icon { color: var(--primary-color); width: 20px; margin-right: 10px; }
        .appointment-actions { display: flex; gap: 10px; flex-wrap: wrap; }
        /* .btn-sm { border-radius: 15px; padding: 5px 15px; }
        .btn-primary { background-color: var(--primary-color); border-color: var(--primary-color); }
        .btn-primary:hover { background-color: #00796b; border-color: #00796b; }
        .btn-warning { background-color: var(--secondary-color); border-color: var(--secondary-color); color: #fff; }
        .btn-danger { background-color: var(--accent-color); border-color: var(--accent-color); } */
        .nav-tabs { border-bottom: 2px solid var(--primary-color); }
        .nav-tabs .nav-link { border: none; color: var(--text-color); font-weight: 600; padding: 1rem 1.5rem; }
        .nav-tabs .nav-link.active { background: var(--primary-color); color: #fff; border-radius: 10px 10px 0 0; }
        .tab-content { padding: 2rem 0; }
        .empty-state { text-align: center; padding: 3rem; color: #6c757d; }
        .empty-state i { font-size: 4rem; margin-bottom: 1rem; color: var(--primary-color); }
        .btn-find-doctor {
            display: inline-flex;
            align-items: center;
            gap: 1.2rem;
            padding: 1rem 1.8rem;
            border-radius: 999px;
            background: linear-gradient(135deg, var(--primary-color), var(--secondary-color));
            background-size: 220% 220%;
            color: #fff;
            font-weight: 600;
            border: none;
            position: relative;
            overflow: hidden;
            text-decoration: none;
            box-shadow: 0 18px 42px rgba(0, 0, 0, 0.16);
            transition: transform 0.3s ease, box-shadow 0.3s ease, background-position 0.4s ease;
        }
        .btn-find-doctor:hover {
            color: #fff;
            transform: translateY(-4px);
            background-position: right center;
            box-shadow: 0 22px 48px rgba(0, 0, 0, 0.2);
        }
        .btn-find-doctor:focus {
            color: #fff;
            outline: none;
            
        }
        .btn-find-doctor .btn-icon {
            width: 48px;
            height: 48px;
            border-radius: 50%;
            display: inline-flex;
            align-items: center;
            justify-content: center;
            flex-shrink: 0;
             margin-top: 15px;
            color: #fff;
            line-height: 1;
        }
        .btn-find-doctor .btn-text {
            display: flex;
            flex-direction: column;
            text-align:center;
            gap: 0.35rem;
            flex: 1;
            min-width: 0;
        }
        .btn-find-doctor .btn-title {
            font-size: 1.05rem;
            text-align: center;
            letter-spacing: 0.02em;
        }
        .btn-find-doctor .btn-caption {
            font-size: 0.78rem;
            font-weight: 400;
            opacity: 0.9;
        }
        .btn-find-doctor .btn-icon i {
            line-height: 1;
        }
        .modal-content { border-radius: 20px; border: none; }
        .modal-header { background: var(--primary-color); color: #fff; border-radius: 20px 20px 0 0; }
        .form-control { border-radius: 10px; border: 2px solid #e0e0e0; }
        .form-control:focus { border-color: var(--primary-color); box-shadow: 0 0 0 .2rem rgba(0,150,136,.25); }

                /* Footer contact cards */
        .footer-bar{position:relative;background:radial-gradient(circle at top left,rgba(255,255,255,.08),rgba(255,255,255,0) 45%),linear-gradient(135deg,var(--primary-color),#0f766e);color:#f3f4f6;overflow:hidden}
        .footer-bar::before{content:"";position:absolute;inset:0;background:linear-gradient(120deg,rgba(255,255,255,.08),transparent 60%);mix-blend-mode:screen;opacity:.35;pointer-events:none}
        .footer-bar a{color:#e0f2f1;text-decoration:none}
        .footer-bar a:hover{color:#ffffff;text-decoration:underline}
        .footer-brand{display:flex;align-items:center;gap:.75rem;font-weight:700;font-size:1.5rem;margin-bottom:1rem}
        .footer-tagline{opacity:.85;max-width:420px}
        .footer-cta{display:inline-flex;align-items:center;gap:.6rem;padding:.7rem 1.1rem;border-radius:999px;background:rgba(255,255,255,.12);color:#fff;font-weight:600;backdrop-filter:blur(6px);margin-bottom:1.2rem;text-decoration:none}
        .footer-cta:hover{background:rgba(255,255,255,.18);color:#fff}
        .footer-social .btn{width:36px;height:36px;border-radius:50%;display:inline-flex;align-items:center;justify-content:center;border:none;background:rgba(255,255,255,.12);color:#fff;transition:.3s}
        .footer-social .btn:hover{background:#fff;color:var(--primary-color);transform:translateY(-3px)}
        .footer-panel{position:relative;border-radius:18px;background:rgba(15,23,42,.4);border:1px solid rgba(255,255,255,.12);padding:1.5rem;height:100%;backdrop-filter:blur(10px);box-shadow:0 10px 30px rgba(15,23,42,.35)}
        .footer-panel .panel-title{font-size:1.1rem;font-weight:700;margin-bottom:1.1rem;color:#fff;text-transform:uppercase;letter-spacing:.08em}
        .contact-card{display:flex;align-items:flex-start;gap:.9rem;padding:.85rem 0;border-bottom:1px solid rgba(255,255,255,.08)}
        .contact-card:last-child{border-bottom:none;padding-bottom:0}
        .contact-card .icon{width:42px;height:42px;border-radius:12px;background:rgba(255,255,255,.12);display:grid;place-items:center;font-size:1.1rem;color:#fff;flex-shrink:0}
        .contact-card .label{font-size:.8rem;letter-spacing:.08em;text-transform:uppercase;opacity:.7;margin-bottom:.25rem}
        .contact-card .value{font-weight:600;color:#fff}
        .footer-links ul{list-style:none;margin:0;padding:0;display:grid;gap:.6rem}
        .footer-links a{display:flex;align-items:center;gap:.5rem;opacity:.85;transition:.3s;font-weight:500}
        .footer-links a:hover{opacity:1;transform:translateX(4px)}
        .footer-bottom{border-top:1px solid rgba(255,255,255,.12);margin-top:2.5rem;padding-top:1.5rem;display:flex;flex-wrap:wrap;gap:1rem;justify-content:space-between;align-items:center;font-size:.9rem;opacity:.85}
        @media (max-width: 767.98px){
            .footer-panel{padding:1.25rem}
            .footer-brand{font-size:1.3rem}
            .footer-bottom{flex-direction:column;align-items:flex-start}
        }
    </style>
</head>
<body>
    <!-- Navigation -->
    <nav class="navbar navbar-expand-lg navbar-dark">
        <div class="container">
            <a class="navbar-brand" href="dashboard.php">
                <i class="fas fa-hospital-alt me-2"></i><?php echo APP_NAME; ?>
            </a>
            <button class="navbar-toggler" type="button" data-bs-toggle="collapse" data-bs-target="#navbarNav">
                <span class="navbar-toggler-icon"></span>
            </button>
            <div class="collapse navbar-collapse" id="navbarNav">
                <ul class="navbar-nav me-auto">
                    <li class="nav-item"><a class="nav-link" href="dashboard.php"><i class="fas fa-home me-1"></i>Home</a></li>
                    <li class="nav-item"><a class="nav-link" href="doctors.php"><i class="fas fa-user-md me-1"></i>Find Doctors</a></li>
                    <li class="nav-item"><a class="nav-link" href="packages.php"><i class="fas fa-medkit me-1"></i>Health Packages</a></li>
                    <li class="nav-item"><a class="nav-link active" href="appointments.php"><i class="fas fa-calendar-check me-1"></i>My Appointments</a></li>
                    <li class="nav-item"><a class="nav-link" href="medical_history.php"><i class="fas fa-history me-1"></i>Medical History</a></li>
                    <li class="nav-item"><a class="nav-link" href="feedback.php"><i class="fas fa-comment-medical me-1"></i>Give Feedback</a></li>
                </ul>
                <ul class="navbar-nav">
                    <li class="nav-item dropdown">
                        <a class="nav-link dropdown-toggle" href="#" id="navbarDropdown" role="button" data-bs-toggle="dropdown">
                            <i class="fas fa-user-circle me-1"></i><?php echo htmlspecialchars($_SESSION['patient_name']); ?>
                        </a>
                        <ul class="dropdown-menu">
                            <li><a class="dropdown-item" href="profile.php"><i class="fas fa-user me-2"></i>My Profile</a></li>
                            <li><hr class="dropdown-divider"></li>
                            <li><a class="dropdown-item" href="logout.php"><i class="fas fa-sign-out-alt me-2"></i>Logout</a></li>
                        </ul>
                    </li>
                </ul>
            </div>
        </div>
    </nav>

    <!-- Header -->
    <div class="appointments-header mt-4">
        <div class="container">
            <div class="header-content">
                <h1 class="display-4 fw-bold mb-3">
                    <i class="fas fa-calendar-check me-3"></i>My Appointments
                </h1>
                <p class="lead">Manage your healthcare appointments and consultations</p>
                <a href="doctors.php" class="btn btn-light btn-lg mt-3">
                    <i class="fas fa-plus me-2"></i>Book New Appointment
                </a>
            </div>
        </div>
    </div>

    <div class="container mt-4">
        <?php if (!empty($errors)): ?>
            <div class="alert alert-danger">
                <i class="fas fa-exclamation-triangle me-2"></i>
                <ul class="mb-0">
                    <?php foreach ($errors as $error): ?>
                        <li><?php echo htmlspecialchars($error); ?></li>
                    <?php endforeach; ?>
                </ul>
            </div>
        <?php endif; ?>

        <?php if ($success_message): ?>
            <div class="alert alert-success">
                <i class="fas fa-check-circle me-2"></i>
                <?php echo htmlspecialchars($success_message); ?>
            </div>
        <?php endif; ?>

        <!-- Tabs -->
        <ul class="nav nav-tabs" id="appointmentTabs" role="tablist">
            <li class="nav-item" role="presentation">
                <button class="nav-link active" id="upcoming-tab" data-bs-toggle="tab" data-bs-target="#upcoming" type="button" role="tab">
                    <i class="fas fa-calendar-plus me-2"></i>Upcoming (<?php echo count($upcoming_appointments); ?>)
                </button>
            </li>
            <li class="nav-item" role="presentation">
                <button class="nav-link" id="past-tab" data-bs-toggle="tab" data-bs-target="#past" type="button" role="tab">
                    <i class="fas fa-history me-2"></i>Past (<?php echo count($past_appointments); ?>)
                </button>
            </li>
            <li class="nav-item" role="presentation">
                <button class="nav-link" id="cancelled-tab" data-bs-toggle="tab" data-bs-target="#cancelled" type="button" role="tab">
                    <i class="fas fa-times-circle me-2"></i>Cancelled (<?php echo count($cancelled_appointments); ?>)
                </button>
            </li>
        </ul>

        <div class="tab-content" id="appointmentTabsContent">
            <!-- Upcoming -->
            <div class="tab-pane fade show active" id="upcoming" role="tabpanel">
                <?php if (empty($upcoming_appointments)): ?>
                    <div class="empty-state">
                        <i class="fas fa-calendar-plus"></i>
                        <h4>No Upcoming Appointments</h4>
                        <p>You don't have any scheduled appointments. Book one now!</p>
                        <a href="doctors.php" class="btn btn-find-doctor mt-3">
                            
                            <span class="btn-text">
                                <span class="btn-title">Find a Doctor</span>
                                <span class="btn-caption">Browse specialists and book instantly</span>
                            </span>
                        
                        </a>
                    </div>
                <?php else: ?>
                    <?php foreach ($upcoming_appointments as $appointment):
                        $statusText = canon_status_text($appointment['status'] ?? '');
                        $statusClass = status_class($appointment['status'] ?? '');
                    ?>
                        <div class="card hospital-card appointment-card upcoming">
                            <div class="card-body">
                                <div class="appointment-header">
                                    <div class="doctor-name"><i class="fas fa-user-md me-2"></i><?php echo htmlspecialchars($appointment['doctor_name']); ?></div>
                                    <span class="appointment-status <?php echo 'status-' . htmlspecialchars($statusClass); ?>"><?php echo htmlspecialchars($statusText); ?></span>
                                </div>

                                <div class="appointment-details">
                                    <div class="detail-item"><i class="fas fa-stethoscope detail-icon"></i><span><?php echo htmlspecialchars($appointment['specialization']); ?></span></div>
                                    <div class="detail-item"><i class="fas fa-calendar detail-icon"></i><span><?php echo formatDate($appointment['appointment_date']); ?></span></div>
                                    <div class="detail-item"><i class="fas fa-clock detail-icon"></i><span><?php echo formatTime($appointment['appointment_time']); ?></span></div>
                                    <div class="detail-item"><i class="fas fa-phone detail-icon"></i><span><?php echo htmlspecialchars($appointment['doctor_contact']); ?></span></div>
                                </div>

                                <?php if (!empty($appointment['reason'])): ?>
                                    <div class="mb-3"><strong>Reason:</strong> <?php echo htmlspecialchars($appointment['reason']); ?></div>
                                <?php endif; ?>

                                <div class="appointment-actions">
                                    <button class="btn btn-warning btn-sm" onclick="openRescheduleModal(<?php echo (int)$appointment['id']; ?>, '<?php echo $appointment['appointment_date']; ?>', '<?php echo $appointment['appointment_time']; ?>')">
                                        <i class="fas fa-edit me-1"></i>Reschedule
                                    </button>
                                    <button class="btn btn-danger btn-sm" onclick="cancelAppointment(<?php echo (int)$appointment['id']; ?>)">
                                        <i class="fas fa-times me-1"></i>Cancel
                                    </button>
                                    <a href="doctor_profile.php?id=<?php echo (int)$appointment['doctor_id']; ?>" class="btn btn-primary btn-sm">
                                        <i class="fas fa-info-circle me-1"></i>Doctor Profile
                                    </a>
                                </div>
                            </div>
                        </div>
                    <?php endforeach; ?>
                <?php endif; ?>
            </div>

            <!-- Past -->
            <div class="tab-pane fade" id="past" role="tabpanel">
                <?php if (empty($past_appointments)): ?>
                    <div class="empty-state">
                        <i class="fas fa-history"></i>
                        <h4>No Past Appointments</h4>
                        <p>Your appointment history will appear here.</p>
                    </div>
                <?php else: ?>
                    <?php foreach ($past_appointments as $appointment):
                        $statusText = canon_status_text($appointment['status'] ?? '');
                        $statusClass = status_class($appointment['status'] ?? '');
                    ?>
                        <div class="card hospital-card appointment-card past">
                            <div class="card-body">
                                <div class="appointment-header">
                                    <div class="doctor-name"><i class="fas fa-user-md me-2"></i><?php echo htmlspecialchars($appointment['doctor_name']); ?></div>
                                    <span class="appointment-status <?php echo 'status-' . htmlspecialchars($statusClass); ?>"><?php echo htmlspecialchars($statusText); ?></span>
                                </div>

                                <div class="appointment-details">
                                    <div class="detail-item"><i class="fas fa-stethoscope detail-icon"></i><span><?php echo htmlspecialchars($appointment['specialization']); ?></span></div>
                                    <div class="detail-item"><i class="fas fa-calendar detail-icon"></i><span><?php echo formatDate($appointment['appointment_date']); ?></span></div>
                                    <div class="detail-item"><i class="fas fa-clock detail-icon"></i><span><?php echo formatTime($appointment['appointment_time']); ?></span></div>
                                </div>

                                <?php if (!empty($appointment['reason'])): ?>
                                    <div class="mb-3"><strong>Reason:</strong> <?php echo htmlspecialchars($appointment['reason']); ?></div>
                                <?php endif; ?>

                                <div class="appointment-actions">
                                    <a href="book_appointment.php?doctor_id=<?php echo (int)$appointment['doctor_id']; ?>" class="btn btn-primary btn-sm">
                                        <i class="fas fa-redo me-1"></i>Book Again
                                    </a>
                                    <?php if (strtolower($appointment['status']) === 'completed'): ?>
                                        <a href="feedback.php?doctor_id=<?php echo (int)$appointment['doctor_id']; ?>&appointment_id=<?php echo (int)$appointment['id']; ?>" class="btn btn-success btn-sm">
                                            <i class="fas fa-comment-medical me-1"></i>Give Feedback
                                        </a>
                                    <?php endif; ?>
                                </div>
                            </div>
                        </div>
                    <?php endforeach; ?>
                <?php endif; ?>
            </div>

            <!-- Cancelled -->
            <div class="tab-pane fade" id="cancelled" role="tabpanel">
                <?php if (empty($cancelled_appointments)): ?>
                    <div class="empty-state">
                        <i class="fas fa-times-circle"></i>
                        <h4>No Cancelled Appointments</h4>
                        <p>Your cancelled appointments will appear here.</p>
                    </div>
                <?php else: ?>
                    <?php foreach ($cancelled_appointments as $appointment):
                        $statusText = canon_status_text($appointment['status'] ?? '');
                        $statusClass = status_class($appointment['status'] ?? '');
                    ?>
                        <div class="card hospital-card appointment-card cancelled">
                            <div class="card-body">
                                <div class="appointment-header">
                                    <div class="doctor-name"><i class="fas fa-user-md me-2"></i><?php echo htmlspecialchars($appointment['doctor_name']); ?></div>
                                    <span class="appointment-status <?php echo 'status-' . htmlspecialchars($statusClass); ?>"><?php echo htmlspecialchars($statusText); ?></span>
                                </div>

                                <div class="appointment-details">
                                    <div class="detail-item"><i class="fas fa-stethoscope detail-icon"></i><span><?php echo htmlspecialchars($appointment['specialization']); ?></span></div>
                                    <div class="detail-item"><i class="fas fa-calendar detail-icon"></i><span><?php echo formatDate($appointment['appointment_date']); ?></span></div>
                                    <div class="detail-item"><i class="fas fa-clock detail-icon"></i><span><?php echo formatTime($appointment['appointment_time']); ?></span></div>
                                </div>

                                <div class="appointment-actions">
                                    <a href="book_appointment.php?doctor_id=<?php echo (int)$appointment['doctor_id']; ?>" class="btn btn-primary btn-sm">
                                        <i class="fas fa-redo me-1"></i>Book Again
                                    </a>
                                </div>
                            </div>
                        </div>
                    <?php endforeach; ?>
                <?php endif; ?>
            </div>
        </div>
    </div>

    <!-- Reschedule Modal -->
    <div class="modal fade" id="rescheduleModal" tabindex="-1">
        <div class="modal-dialog">
            <div class="modal-content">
                <div class="modal-header">
                    <h5 class="modal-title"><i class="fas fa-edit me-2"></i>Reschedule Appointment</h5>
                    <button type="button" class="btn-close btn-close-white" data-bs-dismiss="modal"></button>
                </div>
                <form method="POST" action="">
                    <div class="modal-body">
                        <input type="hidden" name="csrf_token" value="<?php echo $csrf_token; ?>">
                        <input type="hidden" name="action" value="reschedule">
                        <input type="hidden" name="appointment_id" id="reschedule_appointment_id">

                        <div class="mb-3">
                            <label for="new_date" class="form-label">New Date</label>
                            <input type="date" class="form-control" name="new_date" id="new_date" min="<?php echo date('Y-m-d'); ?>" required>
                        </div>
                        <div class="mb-3">
                            <label for="new_time" class="form-label">New Time</label>
                            <input type="time" class="form-control" name="new_time" id="new_time" required>
                        </div>
                    </div>
                    <div class="modal-footer">
                        <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">Cancel</button>
                        <button type="submit" class="btn btn-primary"><i class="fas fa-save me-2"></i>Reschedule</button>
                    </div>
                </form>
            </div>
        </div>
    </div>

    <!-- Cancel Modal -->
    <div class="modal fade" id="cancelModal" tabindex="-1">
        <div class="modal-dialog">
            <div class="modal-content">
                <div class="modal-header bg-danger text-white">
                    <h5 class="modal-title"><i class="fas fa-exclamation-triangle me-2"></i>Cancel Appointment</h5>
                    <button type="button" class="btn-close btn-close-white" data-bs-dismiss="modal"></button>
                </div>
                <form method="POST" action="">
                    <div class="modal-body">
                        <input type="hidden" name="csrf_token" value="<?php echo $csrf_token; ?>">
                        <input type="hidden" name="action" value="cancel">
                        <input type="hidden" name="appointment_id" id="cancel_appointment_id">
                        <p>Are you sure you want to cancel this appointment? This action cannot be undone.</p>
                    </div>
                    <div class="modal-footer">
                        <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">Keep Appointment</button>
                        <button type="submit" class="btn btn-danger"><i class="fas fa-times me-2"></i>Yes, Cancel</button>
                    </div>
                </form>
            </div>
        </div>
    </div>


     <footer class="footer-bar mt-5 text-light">
    <div class="container py-5 position-relative">
        <div class="row g-4">
            <div class="col-lg-5 col-xl-4">
                <div class="footer-brand">
                    <span class="d-inline-flex align-items-center justify-content-center bg-white bg-opacity-10 rounded-circle" style="width:42px;height:42px;">
                        <i class="fas fa-hospital-symbol"></i>
                    </span>
                    <span><?php echo APP_NAME; ?></span>
                    </div>
                     <p class="footer-tagline">Delivering compassionate, patient-first healthcare with innovative digital experiences.</p>
                <a class="footer-cta" href="appointments.php">
                    <i class="fas fa-calendar-plus"></i>
                    <span>Book your next visit</span>
                </a>
                    <div class="footer-social d-flex gap-2">
                    <a href="https://facebook.com" class="btn" aria-label="Facebook"><i class="fab fa-facebook-f"></i></a>
                    <a href="https://twitter.com" class="btn" aria-label="Twitter"><i class="fab fa-twitter"></i></a>
                    <a href="https://instagram.com" class="btn" aria-label="Instagram"><i class="fab fa-instagram"></i></a>
                    <a href="https://www.linkedin.com" class="btn" aria-label="LinkedIn"><i class="fab fa-linkedin-in"></i></a>
                    <a href="https://youtube.com" class="btn" aria-label="YouTube"><i class="fab fa-youtube"></i></a>
                    </div>
                </div>
                 <div class="col-lg-7 col-xl-8">
                <div class="row g-4">
                    <div class="col-md-6">
                        <div class="footer-panel">
                            <div class="panel-title">Connect With Us</div>
                            <?php
                            $addr = $phone = $email = $emergency = '';
                            if (!empty($cms['contact_info'])) {
                                $raw = strip_tags($cms['contact_info']);
                                if (preg_match('/Address\s*:\s*(.+?)(?:Phone|Email|Emergency|$)/is', $raw, $m)) $addr = trim($m[1]);
                                if (preg_match('/Phone\s*:\s*([^\n\r]+)/i', $raw, $m)) $phone = trim($m[1]);
                                if (preg_match('/Email\s*:\s*([^\n\r]+)/i', $raw, $m)) $email = trim($m[1]);
                                if (preg_match('/Emergency\s*:\s*([^\n\r]+)/i', $raw, $m)) $emergency = trim($m[1]);
                            }
                            if (empty($addr)) $addr = '1234 Medical Center Dr, Healthcare City, HC';
                            if (empty($phone)) $phone = '(555) 123-4567';
                            if (empty($email)) $email = 'info@hospital.com';
                            if (empty($emergency)) $emergency = '(555) 911-HELP';
                            ?>
                            <div class="contact-card">
                                <div class="icon"><i class="fas fa-map-marker-alt"></i></div>
                                <div>
                                    <div class="label">Address</div>
                                    <div class="value"><?php echo htmlspecialchars($addr); ?></div>
                                </div>
                            </div>
                            <div class="contact-card">
                                <div class="icon"><i class="fas fa-phone-alt"></i></div>
                                <div>
                                    <div class="label">Phone</div>
                                    <div class="value"><a href="tel:<?php echo preg_replace('/[^0-9+]/','',$phone); ?>"><?php echo htmlspecialchars($phone); ?></a></div>
                                </div>
                            </div>
                            <div class="contact-card">
                                <div class="icon"><i class="fas fa-envelope"></i></div>
                                <div>
                                    <div class="label">Email</div>
                                    <div class="value"><a href="mailto:<?php echo htmlspecialchars($email); ?>"><?php echo htmlspecialchars($email); ?></a></div>
                                </div>
                            </div>
                            <div class="contact-card emergency">
                                <div class="icon"><i class="fas fa-ambulance"></i></div>
                                <div>
                                    <div class="label">Emergency</div>
                                    <div class="value"><a href="tel:<?php echo preg_replace('/[^0-9+]/','',$emergency); ?>"><?php echo htmlspecialchars($emergency); ?></a></div>
                                </div>
                            </div>
                            </div>
                        </div>
                        <div class="col-md-6">
                        <div class="footer-panel footer-links h-100">
                            <div class="panel-title">Quick Links</div>
                            <ul>
                                <li><a href="doctors.php"><i class="fas fa-user-md"></i><span>Find a Specialist</span></a></li>
                                <li><a href="appointments.php"><i class="fas fa-calendar-check"></i><span>Manage Appointments</span></a></li>
                                <li><a href="medical_history.php"><i class="fas fa-file-medical"></i><span>Health Records</span></a></li>
                                <li><a href="packages.php"><i class="fas fa-medkit"></i><span>Health Packages</span></a></li>
                                <li><a href="feedback.php"><i class="fas fa-comment-medical"></i><span>Share Feedback</span></a></li>
                            </ul>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
            <div class="footer-bottom">
                <span>&copy; <?php echo date('Y'); ?> <?php echo APP_NAME; ?>. All rights reserved.</span>
                <span>Powered by <?php echo APP_NAME; ?> Patient Portal</span>
            </div>
        </div>
    </footer>

    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js"></script>
    <script>
        function openRescheduleModal(appointmentId, currentDate, currentTime) {
            document.getElementById('reschedule_appointment_id').value = appointmentId;
            document.getElementById('new_date').value = currentDate;
            document.getElementById('new_time').value = currentTime;
            const modal = new bootstrap.Modal(document.getElementById('rescheduleModal'));
            modal.show();
        }
        function cancelAppointment(appointmentId) {
            document.getElementById('cancel_appointment_id').value = appointmentId;
            const modal = new bootstrap.Modal(document.getElementById('cancelModal'));
            modal.show();
        }
    </script>
</body>
</html>
