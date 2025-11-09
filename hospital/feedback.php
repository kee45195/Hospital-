<?php
require_once 'config/config.php';

// Require login
requireLogin();

$patient_id = getCurrentPatientId();
$current_patient = getCurrentPatient();
$success_message = '';
$error_message = '';

// --- Helpers ---
function safe($v){ return htmlspecialchars((string)$v, ENT_QUOTES, 'UTF-8'); }
function statusBadgeClass($status) {
    $s = strtolower((string)$status);
    return match($s) {
        'completed' => 'success',
        'confirmed' => 'primary',
        'pending'   => 'warning',
        'cancelled' => 'danger',
        default     => 'secondary'
    };
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

/*
|--------------------------------------------------------------------------
| Handle form submission (rating for a specific appointment)
| IMPORTANT: Verify it's YOUR appointment, status Confirmed/Completed,
|            AND the appointment datetime is in the past.
|--------------------------------------------------------------------------
*/
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['submit_feedback'])) {
    $appointment_id = isset($_POST['appointment_id']) ? (int)$_POST['appointment_id'] : 0;
    $feedback_text  = trim($_POST['feedback_text'] ?? '');
    $rating         = isset($_POST['rating']) ? (int)$_POST['rating'] : 0;
    $feedback_date  = date('Y-m-d');

    // Basic validation
    if ($appointment_id <= 0) {
        $error_message = 'Invalid appointment.';
    } elseif ($rating < 1 || $rating > 5) {
        $error_message = 'Please select a valid rating (1-5 stars).';
    } elseif ($feedback_text === '') {
        $error_message = 'Please provide feedback text.';
    } else {
        // Verify appointment belongs to this patient, is Confirmed/Completed, and is in the past
        try {
            $stmt = $pdo->prepare("
                SELECT a.id, a.doctor_id, a.patient_id, a.status,
                       a.appointment_date, a.appointment_time, a.notes AS reason,
                       d.name AS doctor_name
                FROM appointments a
                JOIN doctors d ON d.id = a.doctor_id
                WHERE a.id = ?
                  AND a.patient_id = ?
                  AND a.status IN ('Confirmed', 'Completed')
                  AND TIMESTAMP(a.appointment_date, a.appointment_time) < CURRENT_TIMESTAMP
                LIMIT 1
            ");
            $stmt->execute([$appointment_id, $patient_id]);
            $appt = $stmt->fetch();
        } catch (PDOException $e) {
            $appt = false;
        }

        if (!$appt) {
            $error_message = 'You can only rate your own completed/confirmed appointments that are in the past.';
        } else {
            // Prevent duplicate feedback for the same appointment
            try {
                $stmt = $pdo->prepare("SELECT COUNT(*) FROM feedback WHERE patient_id = ? AND appointment_id = ?");
                $stmt->execute([$patient_id, $appointment_id]);
                $already = (int)$stmt->fetchColumn();
            } catch (PDOException $e) {
                $already = 0;
            }

            if ($already > 0) {
                $error_message = 'You already submitted feedback for this appointment.';
            } else {
                // Insert feedback; doctor_id from verified appointment
                try {
                    $stmt = $pdo->prepare("
                        INSERT INTO feedback (patient_id, doctor_id, appointment_id, feedback_text, rating, feedback_date)
                        VALUES (?, ?, ?, ?, ?, ?)
                    ");
                    $ok = $stmt->execute([$patient_id, (int)$appt['doctor_id'], $appointment_id, $feedback_text, $rating, $feedback_date]);
                    if ($ok) {
                        $success_message = 'Thank you for your feedback! It has been submitted successfully.';
                        $_POST = []; // clear post
                    } else {
                        $error_message = 'Error submitting feedback. Please try again.';
                    }
                } catch (PDOException $e) {
                    $error_message = 'Error submitting feedback. Please try again.';
                }
            }
        }
    }
}

/*
|--------------------------------------------------------------------------
| Get all patient's appointments eligible for feedback
| Only Confirmed/Completed AND strictly in the past
|--------------------------------------------------------------------------
*/
try {
    $stmt = $pdo->prepare("
        SELECT a.id, a.doctor_id, a.appointment_date, a.appointment_time, a.status,
               a.notes AS reason,
               d.name AS doctor_name, d.specialization
        FROM appointments a
        JOIN doctors d ON a.doctor_id = d.id
        WHERE a.patient_id = ?
          AND a.status IN ('Confirmed','Completed')
          AND TIMESTAMP(a.appointment_date, a.appointment_time) < CURRENT_TIMESTAMP
        ORDER BY a.appointment_date DESC, a.appointment_time DESC
    ");
    $stmt->execute([$patient_id]);
    $appointments = $stmt->fetchAll();
} catch (PDOException $e) {
    $appointments = [];
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Give Feedback - <?php echo APP_NAME; ?></title>
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
        .feedback-header { background: linear-gradient(135deg, var(--primary-color), #00796b); color: #fff; padding: 3rem 0; position: relative; overflow: hidden; }
        .feedback-header::before { content: ''; position: absolute; inset: 0; background: url('https://images.unsplash.com/photo-1559757148-5c350d0d3c56?ixlib=rb-4.0.3&auto=format&fit=crop&w=1200&q=80') center/cover; opacity: .1; }
        .header-content { position: relative; z-index: 1; text-align: center; }
        .appt-card { border-left: 5px solid var(--primary-color); margin-bottom: 1rem; }
        .badge { border-radius: 20px; padding: .4rem .8rem; }
        .muted { color:#6c757d; }
        .star-rating { display: flex; flex-direction: row-reverse; justify-content: center; gap: 4px; }
        .star-rating input { display: none; }
        .star-rating label { cursor: pointer; width: 32px; height: 32px; display: block; background: url('data:image/svg+xml,<svg xmlns="http://www.w3.org/2000/svg" fill="%23ddd" viewBox="0 0 24 24"><path d="M12 2l3.09 6.26L22 9.27l-5 4.87 1.18 6.88L12 17.77l-6.18 3.25L7 14.14 2 9.27l6.91-1.01L12 2z"/></svg>') no-repeat center/contain; transition: background .2s; }
        .star-rating input:checked ~ label,
        .star-rating label:hover,
        .star-rating label:hover ~ label {
            background: url('data:image/svg+xml,<svg xmlns="http://www.w3.org/2000/svg" fill="%23ffc107" viewBox="0 0 24 24"><path d="M12 2l3.09 6.26L22 9.27l-5 4.87 1.18 6.88L12 17.77l-6.18 3.25L7 14.14 2 9.27l6.91-1.01L12 2z"/></svg>') no-repeat center/contain;
        }
        /* .btn-primary { background: linear-gradient(135deg, var(--primary-color), #00796b); border: none; border-radius: 25px; padding: 10px 22px; font-weight: 600; }
        .btn-primary:hover { transform: translateY(-1px); box-shadow: 0 8px 25px rgba(0,150,136,.3); } */

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
                    <li class="nav-item"><a class="nav-link" href="appointments.php"><i class="fas fa-calendar-check me-1"></i>My Appointments</a></li>
                    <li class="nav-item"><a class="nav-link" href="medical_history.php"><i class="fas fa-history me-1"></i>Medical History</a></li>
                    <li class="nav-item"><a class="nav-link active" href="feedback.php"><i class="fas fa-comment-medical me-1"></i>Give Feedback</a></li>
                </ul>
                <ul class="navbar-nav">
                    <li class="nav-item dropdown">
                        <a class="nav-link dropdown-toggle" href="#" id="navbarDropdown" role="button" data-bs-toggle="dropdown">
                            <i class="fas fa-user-circle me-1"></i><?php echo safe($current_patient['name']); ?>
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

    <!-- Feedback Header -->
    <div class="feedback-header mt-4">
        <div class="container">
            <div class="header-content">
                <h1 class="display-4 fw-bold mb-3">
                    <i class="fas fa-comment-medical me-3"></i>Give Feedback
                </h1>
                <p class="lead">Rate your completed or confirmed appointments that have already happened</p>
            </div>
        </div>
    </div>

    <div class="container mt-5">
        <div class="row justify-content-center">
            <div class="col-md-10">
                <!-- Alerts -->
                <?php if ($success_message): ?>
                    <div class="alert alert-success alert-dismissible fade show" role="alert">
                        <i class="fas fa-check-circle me-2"></i><?php echo safe($success_message); ?>
                        <button type="button" class="btn-close" data-bs-dismiss="alert"></button>
                    </div>
                <?php endif; ?>
                <?php if ($error_message): ?>
                    <div class="alert alert-danger alert-dismissible fade show" role="alert">
                        <i class="fas fa-exclamation-circle me-2"></i><?php echo safe($error_message); ?>
                        <button type="button" class="btn-close" data-bs-dismiss="alert"></button>
                    </div>
                <?php endif; ?>

                <?php if (empty($appointments)): ?>
                    <div class="card hospital-card">
                        <div class="card-body p-4 text-center">
                            <i class="fas fa-calendar-times" style="font-size:3rem;color:#ccc;"></i>
                            <h5 class="mt-3">No eligible past appointments</h5>
                            <p class="muted mb-3">You can leave feedback only for <strong>Confirmed</strong> or <strong>Completed</strong> appointments that already occurred.</p>
                            <a href="appointments.php" class="btn btn-primary"><i class="fas fa-calendar-plus me-2"></i>View Appointments</a>
                        </div>
                    </div>
                <?php else: ?>
                    <!-- List appointments that can be rated (past only) -->
                    <?php foreach ($appointments as $a): ?>
                        <div class="card hospital-card appt-card">
                            <div class="card-body">
                                <div class="d-flex justify-content-between align-items-start flex-wrap">
                                    <div class="me-3">
                                        <h5 class="mb-1"><?php echo safe($a['doctor_name']); ?></h5>
                                        <div class="muted mb-2"><i class="fas fa-stethoscope me-1"></i><?php echo safe($a['specialization']); ?></div>
                                        <?php if (!empty($a['reason'])): ?>
                                            <div class="mb-2">
                                                <i class="fas fa-notes-medical me-1 text-primary"></i>
                                                <strong>Reason:</strong> <?php echo safe($a['reason']); ?>
                                            </div>
                                        <?php endif; ?>
                                        <div class="muted">
                                            <i class="fas fa-calendar me-1"></i><?php echo formatDate($a['appointment_date']); ?>
                                            <span class="mx-2">•</span>
                                            <i class="fas fa-clock me-1"></i><?php echo formatTime($a['appointment_time']); ?>
                                        </div>
                                    </div>
                                    <div class="text-end">
                                        <span class="badge bg-<?php echo statusBadgeClass($a['status']); ?> mb-2"><?php echo safe($a['status']); ?></span><br>
                                        <button
                                            class="btn btn-primary btn-sm mt-1"
                                            data-bs-toggle="modal"
                                            data-bs-target="#rateModal"
                                            data-appt="<?php echo (int)$a['id']; ?>"
                                            data-doc="<?php echo safe($a['doctor_name']); ?>"
                                            data-date="<?php echo safe(formatDate($a['appointment_date'])); ?>"
                                            data-time="<?php echo safe(formatTime($a['appointment_time'])); ?>"
                                            data-reason="<?php echo safe($a['reason'] ?? ''); ?>"
                                        >
                                            <i class="fas fa-star me-1"></i>Rate this visit
                                        </button>
                                    </div>
                                </div>
                            </div>
                        </div>
                    <?php endforeach; ?>
                <?php endif; ?>
            </div>
        </div>
    </div>

    <!-- Rate Modal -->
    <div class="modal fade" id="rateModal" tabindex="-1" aria-hidden="true">
      <div class="modal-dialog modal-dialog-centered">
        <div class="modal-content">
          <form method="POST" action="feedback.php">
            <div class="modal-header">
              <h5 class="modal-title"><i class="fas fa-star me-2"></i>Rate Appointment</h5>
              <button type="button" class="btn-close" data-bs-dismiss="modal"></button>
            </div>
            <div class="modal-body">
                <input type="hidden" name="appointment_id" id="modal_appointment_id">
                <div class="mb-2">
                    <div class="muted"><strong id="modal_doctor"></strong></div>
                    <div class="muted">
                        <i class="fas fa-calendar me-1"></i><span id="modal_date"></span>
                        <span class="mx-2">•</span>
                        <i class="fas fa-clock me-1"></i><span id="modal_time"></span>
                    </div>
                    <div class="mt-2" id="modal_reason_wrap" style="display:none;">
                        <i class="fas fa-notes-medical me-1 text-primary"></i>
                        <strong>Reason:</strong> <span id="modal_reason"></span>
                    </div>
                </div>
                <hr>
                <div class="mb-3 text-center">
                    <div class="star-rating">
                        <input type="radio" id="mstar5" name="rating" value="5" required><label for="mstar5" title="5 stars"></label>
                        <input type="radio" id="mstar4" name="rating" value="4"><label for="mstar4" title="4 stars"></label>
                        <input type="radio" id="mstar3" name="rating" value="3"><label for="mstar3" title="3 stars"></label>
                        <input type="radio" id="mstar2" name="rating" value="2"><label for="mstar2" title="2 stars"></label>
                        <input type="radio" id="mstar1" name="rating" value="1"><label for="mstar1" title="1 star"></label>
                    </div>
                    <small class="muted d-block mt-1">Tap a star to select (1–5)</small>
                </div>
                <div class="mb-3">
                    <label for="feedback_text" class="form-label"><i class="fas fa-comment me-1"></i>Your Feedback</label>
                    <textarea class="form-control" name="feedback_text" id="feedback_text" rows="4" placeholder="Tell us about your experience..." required></textarea>
                </div>
            </div>
            <div class="modal-footer">
              <button type="button" class="btn btn-outline-secondary" data-bs-dismiss="modal">Cancel</button>
              <button type="submit" name="submit_feedback" class="btn btn-primary"><i class="fas fa-paper-plane me-1"></i>Submit Feedback</button>
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
            <hr class="border-light my-4 opacity-25">
            <div class="d-flex flex-wrap justify-content-between align-items-center small opacity-75">
                <span>&copy; <?php echo date('Y'); ?> <?php echo APP_NAME; ?>. All rights reserved.</span>
                <span>Powered by <?php echo APP_NAME; ?> Patient Portal</span>
            </div>
        </div>
    </footer>


<script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js"></script>
</body>
</html>


    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js"></script>
    <script>
        const rateModal = document.getElementById('rateModal');
        if (rateModal) {
            rateModal.addEventListener('show.bs.modal', function (event) {
                const btn  = event.relatedTarget;
                const appt = btn.getAttribute('data-appt');
                const doc  = btn.getAttribute('data-doc');
                const date = btn.getAttribute('data-date');
                const time = btn.getAttribute('data-time');
                const reason = btn.getAttribute('data-reason') || '';

                document.getElementById('modal_appointment_id').value = appt;
                document.getElementById('modal_doctor').textContent   = doc;
                document.getElementById('modal_date').textContent     = date;
                document.getElementById('modal_time').textContent     = time;

                const wrap = document.getElementById('modal_reason_wrap');
                const span = document.getElementById('modal_reason');
                if (reason.trim() !== '') {
                    span.textContent = reason;
                    wrap.style.display = 'block';
                } else {
                    wrap.style.display = 'none';
                    span.textContent = '';
                }

                // clear previous rating & text when opening
                document.querySelectorAll('#rateModal input[name="rating"]').forEach(r => r.checked = false);
                document.getElementById('feedback_text').value = '';
            });
        }
    </script>
</body>
</html>
