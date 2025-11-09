<?php
require_once 'config/config.php';

/**
 * Public + Patient-aware dashboard.
 * Uses helper functions directly to determine patient context.
 */
$patient_id = null;
$current_patient = null;

try {
    $patient_id = getCurrentPatientId();     // should return null/0/false if no patient logged in
    $current_patient = getCurrentPatient();  // array with patient fields when logged in
} catch (Throwable $e) {
    // If helpers throw, treat as public
    $patient_id = null;
    $current_patient = null;
}

// Consider "logged-in patient" if we have a non-empty id and an array for current patient
$is_patient = !empty($patient_id) && is_array($current_patient);

// Data containers
$recent_appointments = [];
$upcoming_count = 0;
$history_count = 0;

// Patient-only queries
if ($is_patient) {
    // Recent appointments (latest 3 by date+time)
    try {
        $stmt = $pdo->prepare("
            SELECT a.*, d.name AS doctor_name, d.specialization
              FROM appointments a
              JOIN doctors d ON a.doctor_id = d.id
             WHERE a.patient_id = ?
             ORDER BY a.appointment_date DESC, a.appointment_time DESC
             LIMIT 3
        ");
        $stmt->execute([$patient_id]);
        $recent_appointments = $stmt->fetchAll();
    } catch (PDOException $e) {
        $recent_appointments = [];
    }

    // Upcoming appointments count (future, pending/confirmed)
    try {
        $stmt = $pdo->prepare("
            SELECT COUNT(*)
              FROM appointments
             WHERE patient_id = ?
               AND TIMESTAMP(appointment_date, appointment_time) >= NOW()
               AND LOWER(status) IN ('pending','confirmed')
        ");
        $stmt->execute([$patient_id]);
        $upcoming_count = (int)$stmt->fetchColumn();
    } catch (PDOException $e) {
        $upcoming_count = 0;
    }

    // Medical history count
    try {
        $stmt = $pdo->prepare("SELECT COUNT(*) FROM medical_history WHERE patient_id = ?");
        $stmt->execute([$patient_id]);
        $history_count = (int)$stmt->fetchColumn();
    } catch (PDOException $e) {
        $history_count = 0;
    }
}

// Public / shared stats
try { $doctors_count = (int)$pdo->query("SELECT COUNT(*) FROM doctors")->fetchColumn(); }
catch (PDOException $e) { $doctors_count = 0; }

try { $departments_count = (int)$pdo->query("SELECT COUNT(DISTINCT specialization) FROM doctors")->fetchColumn(); }
catch (PDOException $e) { $departments_count = 0; }

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

// Flash
$flash_message = function_exists('getFlashMessage') ? getFlashMessage() : null;

// Local helpers (fallbacks)
if (!function_exists('formatDate')) {
    function formatDate($d){ return date('M j, Y', strtotime($d)); }
}
if (!function_exists('formatTime')) {
    function formatTime($t){ return date('g:i A', strtotime($t)); }
}
if (!function_exists('getStatusBadgeClass')) {
    function getStatusBadgeClass($status){
        $s = strtolower((string)$status);
        return $s === 'confirmed' ? 'success' : ($s === 'pending' ? 'warning' : 'secondary');
    }
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title><?php echo $is_patient ? 'My Dashboard' : 'Welcome'; ?> - MedCare Hospital</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
    <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css" rel="stylesheet">
    <style>
        :root{
            --primary-color: <?php echo COLOR_PRIMARY; ?>;
            --secondary-color: <?php echo COLOR_SECONDARY; ?>;
            --accent-color: <?php echo COLOR_ACCENT; ?>;
            --background-color: <?php echo COLOR_BACKGROUND; ?>;
            --text-color: <?php echo COLOR_TEXT; ?>;
        }
        body{background:var(--background-color);color:var(--text-color);font-family:'Segoe UI', Tahoma, Geneva, Verdana, sans-serif}
        .navbar{background:linear-gradient(135deg,var(--primary-color),#00796b)!important;box-shadow:0 2px 10px rgba(0,0,0,.1)}
        .navbar-brand{font-weight:700;font-size:1.5rem}
        .navbar-nav .nav-link{color:#fff!important;font-weight:500;margin:0 10px;transition:.3s}
        .navbar-nav .nav-link:hover{color:var(--secondary-color)!important;transform:translateY(-2px)}

        .card-lite{background:#fff;border:none;border-radius:16px;box-shadow:0 6px 20px rgba(0,0,0,.08)}
        .section-title{color:var(--primary-color)}
        .stat-card{border-radius:16px;color:#fff;padding:22px;text-align:center;box-shadow:0 6px 20px rgba(0,0,0,.08)}
        .stat-primary{background:linear-gradient(135deg,var(--primary-color),#00796b)}
        .stat-secondary{background:linear-gradient(135deg,var(--secondary-color),#689f38)}
        .stat-accent{background:linear-gradient(135deg,var(--accent-color),#e91e63)}
        .stat-info{background:linear-gradient(135deg,#2196f3,#1976d2)}
        .stat-number{font-size:2.2rem;font-weight:800}
        .stat-label{opacity:.95;margin-top:6px}

        .appointment-item{border-left:4px solid var(--primary-color);background:#fff;border-radius:10px;padding:1rem;margin-bottom:1rem;box-shadow:0 2px 10px rgba(0,0,0,.05)}
        .quick-btn{display:block;width:100%;border-radius:10px;padding:10px 14px;border:1px solid #e5e9f0;background:#fff;text-align:left}
        .quick-btn:hover{background:#f7fbfb;border-color:var(--primary-color)}
        .quick-btn .icon{width:28px;height:28px;display:inline-grid;place-items:center;border-radius:50%;margin-right:8px;background:rgba(0,0,0,.06)}

        .announce-card{background:#fff;border-radius:14px;border:none;box-shadow:0 6px 18px rgba(0,0,0,.07)}
        .announce-header{background:linear-gradient(90deg,var(--primary-color),var(--accent-color));color:#fff;border-radius:14px 14px 0 0;padding:14px 16px}
        .content-block{padding:16px}
        @media (max-width: 575.98px){
            .stat-number{font-size:1.8rem}
        }
        .hero {background:linear-gradient(135deg,var(--primary-color),var(--accent-color)); color:#fff; border-radius:16px}

        /* Responsive tweaks */
        @media (max-width: 992px){ .visit-steps{grid-template-columns:repeat(2,minmax(0,1fr))} }
        @media (max-width: 576px){ .qa-grid{grid-template-columns:1fr} .visit-steps{grid-template-columns:1fr} }

        /* ==== Hospital info enhancements ==== */
        .emergency-strip{background:linear-gradient(90deg,var(--accent-color),#ff8a65);color:#fff;border-radius:12px;padding:10px 14px;display:flex;align-items:center;gap:10px;box-shadow:0 8px 18px rgba(0,0,0,.12)}
        .emergency-strip .badge{background:rgba(255,255,255,.2);backdrop-filter:blur(2px);}

        .feature-grid{display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:14px}
        .feature-card{border-radius:16px;padding:16px;border:1px solid #e5e9f0;background:linear-gradient(180deg,#ffffff,#fafcff);box-shadow:0 6px 18px rgba(0,0,0,.06)}
        .feature-card .icon{width:40px;height:40px;border-radius:12px;display:grid;place-items:center;background:linear-gradient(135deg,var(--secondary-color),#4caf50);color:#fff;margin-bottom:10px}
        .feature-card h6{margin:0 0 6px 0;font-weight:700}
        .feature-card p{margin:0;color:#6b7280;font-size:.95rem}

        .insurance-badges{display:flex;flex-wrap:wrap;gap:8px}
        .insurance-badge{border:1px dashed #dce2ec;border-radius:999px;padding:.35rem .7rem;font-weight:600;background:#fff}

        .testimonial-card{border-left:4px solid var(--secondary-color);border-radius:14px;background:#fff;padding:14px;box-shadow:0 6px 18px rgba(0,0,0,.05)}
        .testimonial-card .who{font-weight:700}

        .accordion-button{font-weight:600}
        @media (max-width: 992px){ .feature-grid{grid-template-columns:repeat(2,minmax(0,1fr))} }
        @media (max-width: 576px){ .feature-grid{grid-template-columns:1fr} }

        /* --- Features block styles (fixed) --- */
        .features-section{padding:5rem 0;background:#fff}
        .features-section .feature-card{border-radius:20px;padding:2.5rem;text-align:center;box-shadow:0 10px 30px rgba(0,0,0,.1);border:none;transition:all .3s ease;height:100%}
        .features-section .feature-card:hover{transform:translateY(-10px);box-shadow:0 20px 40px rgba(0,0,0,.15)}
        .features-section .feature-icon{font-size:3.5rem;margin-bottom:1.5rem}
        .features-section .feature-title{font-size:1.5rem;font-weight:700;margin-bottom:1rem;color:var(--text-color)}
        .features-section .feature-description{color:#6c757d;line-height:1.6}
        .stats-section{background:var(--background-color);padding:4rem 0}
        .stat-item{padding:2rem}
        .stat-number-lg{font-size:3rem;margin-bottom:.5rem}

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
<nav class="navbar navbar-expand-lg navbar-dark">
    <div class="container">
        <a class="navbar-brand" href="dashboard.php"><i class="fas fa-hospital-alt me-2"></i>MedCare Hospital</a>
        <button class="navbar-toggler" type="button" data-bs-toggle="collapse" data-bs-target="#nav" aria-label="Toggle navigation">
            <span class="navbar-toggler-icon"></span>
        </button>
        <div class="collapse navbar-collapse" id="nav">
            <ul class="navbar-nav me-auto">
                <li class="nav-item"><a class="nav-link active" href="dashboard.php"><i class="fas fa-home me-1"></i><?php echo $is_patient ? 'Home' : 'Welcome'; ?></a></li>
                <li class="nav-item"><a class="nav-link" href="doctors.php"><i class="fas fa-user-md me-1"></i>Find Doctors</a></li>
                <li class="nav-item"><a class="nav-link" href="packages.php"><i class="fas fa-medkit me-1"></i>Health Packages</a></li>
                <?php if ($is_patient): ?>
                    <li class="nav-item"><a class="nav-link" href="appointments.php"><i class="fas fa-calendar-check me-1"></i>My Appointments</a></li>
                    <li class="nav-item"><a class="nav-link" href="medical_history.php"><i class="fas fa-history me-1"></i>Medical History</a></li>
                    <li class="nav-item"><a class="nav-link" href="feedback.php"><i class="fas fa-comment-medical me-1"></i>Give Feedback</a></li>
                <?php endif; ?>
            </ul>

            <ul class="navbar-nav">
                <?php if ($is_patient): ?>
                    <li class="nav-item dropdown">
                        <a class="nav-link dropdown-toggle" href="#" role="button" data-bs-toggle="dropdown">
                            <i class="fas fa-user-circle me-1"></i><?php echo htmlspecialchars($current_patient['name']); ?>
                        </a>
                        <ul class="dropdown-menu dropdown-menu-end">
                            <li><a class="dropdown-item" href="profile.php"><i class="fas fa-user me-2"></i>My Profile</a></li>
                            <li><hr class="dropdown-divider"></li>
                            <li><a class="dropdown-item" href="logout.php"><i class="fas fa-sign-out-alt me-2"></i>Logout</a></li>
                        </ul>
                    </li>
                <?php else: ?>
                    <li class="nav-item"><a class="nav-link" href="login.php"><i class="fas fa-sign-in-alt me-1"></i>Login</a></li>
                    <li class="nav-item"><a class="nav-link" href="register.php"><i class="fas fa-user-plus me-1"></i>Register</a></li>
                <?php endif; ?>
            </ul>
        </div>
    </div>
</nav>

<div class="container mt-4">
    <?php if ($flash_message): ?>
        <div class="alert alert-<?php echo htmlspecialchars($flash_message['type']); ?> alert-dismissible fade show" role="alert">
            <i class="fas fa-info-circle me-2"></i><?php echo htmlspecialchars($flash_message['message']); ?>
            <button type="button" class="btn-close" data-bs-dismiss="alert" aria-label="Close"></button>
        </div>
    <?php endif; ?>

    <!-- Public/Patient hero -->
    <div class="hero p-4 p-md-5 mb-4">
        <div class="row align-items-center">
            <div class="col-md-8">
                <h2 class="mb-1">
                    <?php if ($is_patient): ?>
                        Welcome back, <?php echo htmlspecialchars($current_patient['name']); ?>!
                    <?php else: ?>
                        Welcome to <?php echo APP_NAME; ?>
                    <?php endif; ?>
                </h2>
                <p class="mb-0">
                    <?php if ($is_patient): ?>
                        Manage your care—view appointments, records, and connect with specialists.
                    <?php else: ?>
                        Quality healthcare, trusted specialists, and easy online appointments—all in one place.
                    <?php endif; ?>
                </p>
            </div>
            <div class="col-md-4 text-md-end mt-3 mt-md-0">
                <?php if ($is_patient): ?>
                    <a href="appointments.php?action=book" class="btn btn-light"><i class="fas fa-calendar-plus me-2"></i>Book Appointment</a>
                <?php endif; ?>
            </div>
        </div>
    </div>

    <!-- Announcements (from CMS) -->
    <?php if (!empty($cms['announcements'])): ?>
        <div class="announce-card mb-4">
            <div class="announce-header d-flex justify-content-between align-items-center">
                <div class="fw-semibold"><i class="fas fa-bullhorn me-2"></i>Announcements</div>
                <span class="small opacity-75"><?php echo date('M j, Y'); ?></span>
            </div>
            <div class="content-block small">
                <?php echo $cms['announcements']; // trusted admin HTML ?>
            </div>
        </div>
    <?php endif; ?>

    <!-- Stats -->
    <div class="row g-3 mb-3">
        <?php if ($is_patient): ?>
            <div class="col-6 col-md-3">
                <div class="stat-card stat-primary">
                    <div class="stat-number"><?php echo $upcoming_count; ?></div>
                    <div class="stat-label">Upcoming Appointments</div>
                </div>
            </div>
        <?php endif; ?>
        <div class="col-6 <?php echo $is_patient ? 'col-md-3' : 'col-md-4'; ?>">
            <div class="stat-card stat-secondary">
                <div class="stat-number"><?php echo $doctors_count; ?></div>
                <div class="stat-label">Available Doctors</div>
            </div>
        </div>
        <div class="col-6 col-md-4">
            <div class="stat-card stat-accent">
                <div class="stat-number"><?php echo $departments_count; ?></div>
                <div class="stat-label">Departments</div>
            </div>
        </div>
        <?php if (!$is_patient): ?>
            <div class="col-6 col-md-4">
                <div class="stat-card stat-info">
                    <div class="stat-number">24/7</div>
                    <div class="stat-label">Emergency Care</div>
                </div>
            </div>
        <?php endif; ?>
    </div>

    <div class="row">
        <!-- Left column (placeholder for future widgets) -->
        <div class="col-lg-8 mb-4"></div>
    </div>

    <!-- Hospital Highlights -->
    <div class="card-lite mb-4">
        <div class="p-3 border-bottom">
            <h5 class="mb-0 section-title"><i class="fas fa-hospital me-2"></i>Hospital Highlights</h5>
        </div>
        <div class="p-3">
            <div class="row g-4">
                <div class="col-lg-4 col-md-6">
                    <div class="card feature-card">
                        <div class="feature-icon"><i class="fas fa-ambulance"></i></div>
                        <h4 class="feature-title">24/7 Emergency</h4>
                        <p class="feature-description">Round-the-clock emergency and trauma care with rapid response.</p>
                    </div>
                </div>
                <div class="col-lg-4 col-md-6">
                    <div class="card feature-card">
                        <div class="feature-icon"><i class="fas fa-x-ray"></i></div>
                        <h4 class="feature-title">Advanced Imaging</h4>
                        <p class="feature-description">CT, MRI, and Ultrasound with board-certified radiologists.</p>
                    </div>
                </div>
                <div class="col-lg-4 col-md-6">
                    <div class="card feature-card">
                        <div class="feature-icon"><i class="fas fa-vials"></i></div>
                        <h4 class="feature-title">In-House Laboratory</h4>
                        <p class="feature-description">Fast diagnostics for bloodwork and pathology.</p>
                    </div>
                </div>
                <div class="col-lg-4 col-md-6">
                    <div class="card feature-card">
                        <div class="feature-icon"><i class="fas fa-pills"></i></div>
                        <h4 class="feature-title">Pharmacy</h4>
                        <p class="feature-description">On-site pharmacy for convenient medication pickup.</p>
                    </div>
                </div>
                <div class="col-lg-4 col-md-6">
                    <div class="card feature-card">
                        <div class="feature-icon"><i class="fas fa-video"></i></div>
                        <h4 class="feature-title">Telemedicine</h4>
                        <p class="feature-description">Virtual consultations for follow-ups and minor issues.</p>
                    </div>
                </div>
                <div class="col-lg-4 col-md-6">
                    <div class="card feature-card">
                        <div class="feature-icon"><i class="fas fa-parking"></i></div>
                        <h4 class="feature-title">Parking & Accessibility</h4>
                        <p class="feature-description">Ample parking, wheelchair access, and patient assistance.</p>
                    </div>
                </div>
            </div>
        </div>
    </div>

    <section class="features-section mb-5">
        <div class="container">
            <div class="row text-center mb-5">
                <div class="col-12">
                    <h2 class="display-5 fw-bold mb-3" style="color: var(--primary-color);">
                        Why Choose Our Healthcare Platform?
                    </h2>
                    <p class="lead text-muted">
                        Experience modern healthcare management with our comprehensive patient portal
                    </p>
                </div>
            </div>

            <div class="row g-4">
                <div class="col-lg-4 col-md-6">
                    <div class="card feature-card">
                        <div class="feature-icon">
                            <i class="fas fa-calendar-check"></i>
                        </div>
                        <h4 class="feature-title">Easy Appointment Booking</h4>
                        <p class="feature-description">
                            Schedule appointments with your preferred doctors at your convenience. 
                            View available time slots and get instant confirmation.
                        </p>
                    </div>
                </div>

                <div class="col-lg-4 col-md-6">
                    <div class="card feature-card">
                        <div class="feature-icon" style="color: var(--secondary-color);">
                            <i class="fas fa-user-md"></i>
                        </div>
                        <h4 class="feature-title">Expert Medical Team</h4>
                        <p class="feature-description">
                            Connect with experienced doctors across various specializations. 
                            Find the right healthcare professional for your needs.
                        </p>
                    </div>
                </div>

                <div class="col-lg-4 col-md-6">
                    <div class="card feature-card">
                        <div class="feature-icon" style="color: var(--accent-color);">
                            <i class="fas fa-file-medical-alt"></i>
                        </div>
                        <h4 class="feature-title">Digital Health Records</h4>
                        <p class="feature-description">
                            Access your complete medical history, prescriptions, and treatment 
                            records anytime, anywhere. Keep track of your health journey.
                        </p>
                    </div>
                </div>

                <div class="col-lg-4 col-md-6">
                    <div class="card feature-card">
                        <div class="feature-icon">
                            <i class="fas fa-shield-alt"></i>
                        </div>
                        <h4 class="feature-title">Secure & Private</h4>
                        <p class="feature-description">
                            Your health information is protected with industry-standard security 
                            measures. Complete privacy and confidentiality guaranteed.
                        </p>
                    </div>
                </div>

                <div class="col-lg-4 col-md-6">
                    <div class="card feature-card">
                        <div class="feature-icon" style="color: var(--secondary-color);">
                            <i class="fas fa-clock"></i>
                        </div>
                        <h4 class="feature-title">24/7 Access</h4>
                        <p class="feature-description">
                            Manage your healthcare needs around the clock. Book appointments, 
                            view records, and communicate with your healthcare team anytime.
                        </p>
                    </div>
                </div>

                <div class="col-lg-4 col-md-6">
                    <div class="card feature-card">
                        <div class="feature-icon" style="color: var(--accent-color);">
                            <i class="fas fa-mobile-alt"></i>
                        </div>
                        <h4 class="feature-title">Mobile Friendly</h4>
                        <p class="feature-description">
                            Access all features from any device. Our responsive design ensures 
                            a seamless experience on desktop, tablet, and mobile.
                        </p>
                    </div>
                </div>
            </div>
        </div>
    </section>

    <!-- Patient FAQs -->
    <div class="card-lite mb-5">
        <div class="p-3 border-bottom">
            <h5 class="mb-0 section-title"><i class="fas fa-question-circle me-2"></i>Patient FAQs</h5>
        </div>
        <div class="p-3">
            <div class="accordion" id="faqAccordion">
                <div class="accordion-item">
                    <h2 class="accordion-header" id="faq1">
                        <button class="accordion-button collapsed" type="button" data-bs-toggle="collapse" data-bs-target="#faq1c" aria-expanded="false" aria-controls="faq1c">
                            How do I book an appointment?
                        </button>
                    </h2>
                    <div id="faq1c" class="accordion-collapse collapse" data-bs-parent="#faqAccordion">
                        <div class="accordion-body">
                            Use <strong>Find Specialists</strong> to choose a doctor, then click <strong>Book Appointment</strong> and select a time. You’ll receive a confirmation instantly.
                        </div>
                    </div>
                </div>
                <div class="accordion-item">
                    <h2 class="accordion-header" id="faq2">
                        <button class="accordion-button collapsed" type="button" data-bs-toggle="collapse" data-bs-target="#faq2c" aria-expanded="false" aria-controls="faq2c">
                            What should I bring to my visit?
                        </button>
                    </h2>
                    <div id="faq2c" class="accordion-collapse collapse" data-bs-parent="#faqAccordion">
                        <div class="accordion-body">
                            Bring a photo ID, insurance card, and any prior reports or medication lists. Arrive 10 minutes early for check-in.
                        </div>
                    </div>
                </div>
                <div class="accordion-item">
                    <h2 class="accordion-header" id="faq3">
                        <button class="accordion-button collapsed" type="button" data-bs-toggle="collapse" data-bs-target="#faq3c" aria-expanded="false" aria-controls="faq3c">
                            Do you offer telemedicine?
                        </button>
                    </h2>
                    <div id="faq3c" class="accordion-collapse collapse" data-bs-parent="#faqAccordion">
                        <div class="accordion-body">
                            Yes. Many follow-up consultations are available virtually. Schedule from the appointments page and select “Telemedicine” if applicable.
                        </div>
                    </div>
                </div>
            </div>
        </div>
    </div>

    <!-- Visiting Hours (render CMS content as-is) -->
    <?php if (!empty($cms['visiting_hours'])): ?>
        <div class="card-lite mb-4">
            <div class="p-3 border-bottom">
                <h6 class="mb-0 section-title"><i class="fas fa-clock me-2"></i>Visiting Hours</h6>
            </div>
            <div class="content-block small">
                <?php echo $cms['visiting_hours']; // admin HTML as-is ?>
            </div>
        </div>
    <?php endif; ?>
</div>

<!-- Footer -->
<footer class="footer-bar mt-5 text-light">
    <div class="container py-5 position-relative">
        <div class="row g-4">
            <div class="col-lg-5 col-xl-4">
                <div class="footer-brand">
                    <span class="d-inline-flex align-items-center justify-content-center bg-white bg-opacity-10 rounded-circle" style="width:42px;height:42px;">
                        <i class="fas fa-hospital-symbol"></i>
                    </span>
                    <span>MedCare Hospital</span>
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
            <span>&copy; <?php echo date('Y'); ?> MedCare Hospital All rights reserved.</span>
            <span>Powered by <?php echo APP_NAME; ?> Patient Portal</span>
        </div>
    </div>
</footer>

<script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js"></script>
</body>
</html>
