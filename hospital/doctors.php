<?php
require_once 'config/config.php';

// Ensure CMS array exists
if (!isset($cms) || !is_array($cms)) { $cms = []; }
// PUBLIC PAGE — no requireLogin()

// Try to detect a logged-in patient using your helpers
$patient_id = null;
$current_patient = null;
$is_patient = false;
try {
    if (function_exists('getCurrentPatientId')) {
        $patient_id = getCurrentPatientId();
    }
    if (function_exists('getCurrentPatient')) {
        $current_patient = getCurrentPatient();
    }
    $is_patient = !empty($patient_id) && is_array($current_patient);
} catch (Throwable $e) {
    $patient_id = null;
    $current_patient = null;
    $is_patient = false;
}

// Read filters
$search_query = sanitizeInput($_GET['search'] ?? '');
$specialization_filter = isset($_GET['specialization']) && $_GET['specialization'] !== '' ? (int)$_GET['specialization'] : null; // now an ID
$department_filter     = isset($_GET['department']) && $_GET['department'] !== '' ? (int)$_GET['department'] : null;

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

/**
 * MAIN QUERY
 * Only include doctors that are ACTIVE in users table:
 *   users.role = 'doctor'
 *   users.user_id = doctors.id
 *   users.status = 'active'
 *
 * SPECIALIZATIONS:
 *   Join specializations as `spec` and expose spec.name AS specialization_name
 */
$sql = "SELECT d.*,
               dept.name AS department_name,
               spec.name AS specialization_name,
               GROUP_CONCAT(DISTINCT da.available_day
                            ORDER BY FIELD(da.available_day, 'Monday','Tuesday','Wednesday','Thursday','Friday','Saturday','Sunday')
                            SEPARATOR ', ') AS available_days,
               GROUP_CONCAT(DISTINCT CONCAT(da.available_day, ': ', TIME_FORMAT(da.start_time, '%h:%i %p'), ' - ', TIME_FORMAT(da.end_time, '%h:%i %p'))
                            ORDER BY FIELD(da.available_day, 'Monday','Tuesday','Wednesday','Thursday','Friday','Saturday','Sunday')
                            SEPARATOR '<br>') AS availability_schedule
        FROM doctors d
        INNER JOIN users u
            ON u.user_id = d.id
           AND u.role = 'doctor'
           AND LOWER(u.status) = 'active'
        LEFT JOIN doctor_availability da
            ON d.id = da.doctor_id
           AND da.is_active = 1
        LEFT JOIN departments dept
            ON d.department_id = dept.id
        LEFT JOIN specializations spec
            ON d.specialization_id = spec.id
        WHERE 1=1";
$params = [];

// Free-text search: match doctor name OR specialization name
if (!empty($search_query)) {
    $sql .= " AND (d.name LIKE ? OR spec.name LIKE ?)";
    $params[] = "%$search_query%";
    $params[] = "%$search_query%";
}

// Filter by specialization_id (INT)
if ($specialization_filter !== null) {
    $sql .= " AND d.specialization_id = ?";
    $params[] = $specialization_filter;
}

// Filter by department_id (INT)
if ($department_filter !== null) {
    $sql .= " AND d.department_id = ?";
    $params[] = $department_filter;
}

$sql .= " GROUP BY d.id
          ORDER BY d.name ASC";

// Execute the query
try {
    $stmt = $pdo->prepare($sql);
    $stmt->execute($params);
    $doctors = $stmt->fetchAll();
} catch (PDOException $e) {
    // For production, you might want to log this instead
    $doctors = [];
}

/**
 * FILTER DROPDOWNS
 * Specializations: from `specializations` table (id + name)
 */
try {
    $stmt = $pdo->prepare("SELECT id, name FROM specializations WHERE name IS NOT NULL AND name <> '' ORDER BY name ASC");
    $stmt->execute();
    $specializations = $stmt->fetchAll(PDO::FETCH_ASSOC);

    // Build a quick lookup [id => name] for displaying chips and filter summary
    $specializationLookup = [];
    foreach ($specializations as $s) {
        $specializationLookup[(int)$s['id']] = $s['name'];
    }
} catch (PDOException $e) {
    $specializations = [];
    $specializationLookup = [];
}

// Departments (show all; same as before)
try {
    $stmt = $pdo->prepare("SELECT id, name FROM departments ORDER BY name ASC");
    $stmt->execute();
    $departments = $stmt->fetchAll();

    // Dept lookup [id => name] for filter summary
    $departmentLookup = [];
    foreach ($departments as $dep) {
        $departmentLookup[(int)$dep['id']] = $dep['name'];
    }
} catch (PDOException $e) {
    $departments = [];
    $departmentLookup = [];
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Find Doctors - <?php echo APP_NAME; ?></title>
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

        body{background-color:var(--background-color);color:var(--text-color);font-family:'Segoe UI', Tahoma, Geneva, Verdana, sans-serif}

        .navbar{background:linear-gradient(135deg,var(--primary-color),#00796b)!important;box-shadow:0 2px 10px rgba(0,0,0,.1)}
        .navbar-brand{font-weight:700;font-size:1.5rem}
        .navbar-nav .nav-link{color:#fff!important;font-weight:500;margin:0 10px;transition:all .3s ease}
        .navbar-nav .nav-link:hover{color:var(--secondary-color)!important}

        .hospital-card{background:#fff;border-radius:20px;box-shadow:0 10px 30px rgba(0,0,0,.1);border:none;transition:all .3s ease}
        .hospital-card:hover{transform:translateY(-5px);box-shadow:0 15px 40px rgba(0,0,0,.15)}

        .search-section{background:linear-gradient(135deg,var(--primary-color),#00796b);color:#fff;padding:3rem 0;margin-bottom:2rem}
        .search-form{background:rgba(255,255,255,.1);border-radius:20px;padding:2rem;backdrop-filter:blur(10px)}
        .form-control{border-radius:15px;border:2px solid rgba(255,255,255,.3);background:rgba(255,255,255,.9);padding:15px 20px}
        .form-control:focus{border-color:var(--secondary-color);box-shadow:0 0 0 .2rem rgba(139,195,74,.25);background:#fff}
        .btn-outline-primary{color:var(--primary-color);border-color:var(--primary-color);border-radius:25px;padding:8px 20px}
        .btn-outline-primary:hover{background-color:var(--primary-color);border-color:var(--primary-color);color:#fff}

        .doctor-card{height:100%;overflow:hidden}
        .doctor-image{
  height: 250px;                 /* keeps cards consistent */
  display: flex;
  align-items: center;
  justify-content: center;
  background: #f3f4f6;
  border-bottom: 1px solid rgba(0,0,0,.05);
  overflow: hidden;              /* fine with object-fit: contain */
  position: relative;
}
        .doctor-image::before{content:'';position:absolute;inset:0;background:url('https://images.unsplash.com/photo-1612349317150-e413f6a5b16d?ixlib=rb-4.0.3&auto=format&fit=crop&w=800&q=80') center/cover;opacity:.3;transition:opacity .3s ease}
        .doctor-image i{position:relative;z-index:1}
        .doctor-image.has-photo{background:#000}
        .doctor-image.has-photo::before{display:none}
        .doctor-image.has-photo i{display:none}
  .doctor-image img{
  width: 100%;
  height: 100%;
  object-fit: contain;           /* 👈 key: no cropping */
  object-position: center;       /* center inside the box */
  display: block;
  background: transparent;
}


        .specialization-badge{background:var(--primary-color);color:#fff;padding:.5rem 1rem;border-radius:20px;font-size:.85rem;font-weight:600;display:inline-block;margin-bottom:.5rem}
        .department-badge{background:rgba(0,150,136,.12);color:var(--secondary-color);padding:.35rem .75rem;border-radius:14px;font-size:.8rem;font-weight:600;display:inline-block;margin-left:.5rem;vertical-align:middle}
        .doctor-info{padding:1.5rem}
        .doctor-name{color:var(--text-color);font-weight:700;font-size:1.3rem;margin-bottom:.5rem}
        .contact-info{color:#666;margin-bottom:1rem}
        .contact-info i{color:var(--primary-color);width:20px;margin-right:8px}
        .working-hours{background:rgba(0,150,136,.05);border-radius:10px;padding:1rem;margin-bottom:1rem}
        .working-hours h6{color:var(--primary-color);margin-bottom:.5rem;font-size:.9rem}

        .no-results{text-align:center;padding:3rem;color:#666}
        .no-results i{font-size:4rem;color:var(--primary-color);margin-bottom:1rem}
        .results-count{background:rgba(0,150,136,.1);border-radius:15px;padding:1rem;margin-bottom:2rem;text-align:center}
        .results-count h5{color:var(--primary-color);margin:0}

        /* Footer contact cards (same look as dashboard) */
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
            <a class="navbar-brand" href="dashboard.php"><i class="fas fa-hospital-alt me-2"></i>MedCare Hospital</a>
            <button class="navbar-toggler" type="button" data-bs-toggle="collapse" data-bs-target="#nav" aria-label="Toggle navigation">
                <span class="navbar-toggler-icon"></span>
            </button>
            <div class="collapse navbar-collapse" id="nav">
                <ul class="navbar-nav me-auto">
                    <li class="nav-item"><a class="nav-link" href="dashboard.php"><i class="fas fa-home me-1"></i><?php echo $is_patient ? 'Home' : 'Welcome'; ?></a></li>
                    <li class="nav-item"><a class="nav-link active" href="doctors.php"><i class="fas fa-user-md me-1"></i>Find Doctors</a></li>
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

    <!-- Search Section -->
    <div class="search-section mt-4">
        <div class="container">
            <div class="row justify-content-center">
                <div class="col-lg-10">
                    <div class="text-center mb-4">
                        <h1 class="display-5 fw-bold mb-3">
                            <i class="fas fa-stethoscope me-3"></i>Find Your Doctor
                        </h1>
                        <p class="lead">Search for qualified healthcare professionals by name, specialization, or department</p>
                    </div>

                    <div class="search-form">
                        <form method="GET" action="">
                            <div class="row g-3">
                                <div class="col-md-4">
                                    <input type="text" class="form-control" name="search"
                                           placeholder="Search by doctor name or specialization..."
                                           value="<?php echo htmlspecialchars($search_query); ?>">
                                </div>
                                <div class="col-md-4">
                                    <select class="form-control" name="department" aria-label="Filter by department">
                                        <option value="">All Departments</option>
                                        <?php foreach ($departments as $dep): ?>
                                            <?php $depId = (int)$dep['id']; ?>
                                            <option value="<?php echo $depId; ?>" <?php echo ($department_filter === $depId) ? 'selected' : ''; ?>>
                                                <?php echo htmlspecialchars($dep['name']); ?>
                                            </option>
                                        <?php endforeach; ?>
                                    </select>
                                </div>
                                <div class="col-md-4">
                                    <select class="form-control" name="specialization" aria-label="Filter by specialization">
                                        <option value="">All Specializations</option>
                                        <?php foreach ($specializations as $spec): ?>
                                            <?php $specId = (int)$spec['id']; ?>
                                            <option value="<?php echo $specId; ?>" <?php echo ($specialization_filter === $specId) ? 'selected' : ''; ?>>
                                                <?php echo htmlspecialchars($spec['name']); ?>
                                            </option>
                                        <?php endforeach; ?>
                                    </select>
                                </div>

                                <div class="col-12">
                                    <button type="submit" class="btn btn-primary w-100">
                                        <i class="fas fa-search me-2"></i>Search
                                    </button>
                                </div>
                            </div>

                            <?php if (!empty($search_query) || $specialization_filter !== null || $department_filter !== null): ?>
                                <div class="text-center mt-3">
                                    <a href="doctors.php" class="btn btn-outline-light btn-sm active">
                                        <i class="fas fa-times me-1"></i>Clear Filters
                                    </a>
                                </div>
                            <?php endif; ?>
                        </form>
                    </div>
                </div>
            </div>
        </div>
    </div>

    <div class="container">
        <!-- Results Count -->
        <?php if (!empty($search_query) || $specialization_filter !== null || $department_filter !== null): ?>
            <div class="results-count">
                <h5>
                    <i class="fas fa-search me-2"></i>
                    Found <?php echo count($doctors); ?> doctor<?php echo count($doctors) !== 1 ? 's' : ''; ?>
                    <?php if (!empty($search_query)): ?>
                        for "<?php echo htmlspecialchars($search_query); ?>"
                    <?php endif; ?>
                    <?php if ($specialization_filter !== null): ?>
                        in specialization <?php
                            $specName = $specializationLookup[$specialization_filter] ?? '';
                            echo htmlspecialchars($specName ?: 'Unknown');
                        ?>
                    <?php endif; ?>
                    <?php if ($department_filter !== null): ?>
                        <?php
                        $deptName = $departmentLookup[$department_filter] ?? '';
                        ?>
                        <?php if ($deptName): ?> (Department: <?php echo htmlspecialchars($deptName); ?>)<?php endif; ?>
                    <?php endif; ?>
                </h5>
            </div>
        <?php endif; ?>

        <!-- Doctors Grid -->
        <?php if (empty($doctors)): ?>
            <div class="no-results">
                <i class="fas fa-user-md-slash"></i>
                <h3>No Doctors Found</h3>
                <p class="lead">We couldn't find any active doctors matching your search criteria.</p>
                <a href="doctors.php" class="btn btn-primary active">
                    <i class="fas fa-list me-2"></i>View All Active Doctors
                </a>
            </div>
        <?php else: ?>
            <div class="row">
                <?php foreach ($doctors as $doctor): ?>
                    <div class="col-lg-4 col-md-6 mb-4">
                        <div class="card hospital-card doctor-card">
                            <?php $hasDoctorPhoto = !empty($doctor['profile_image']); ?>
                            <div class="doctor-image <?php echo $hasDoctorPhoto ? 'has-photo' : ''; ?>" role="img" aria-label="<?php echo $hasDoctorPhoto ? 'Doctor profile photo' : 'Doctor placeholder image'; ?>">
                                <?php if ($hasDoctorPhoto): ?>
                                    <img src="<?php echo htmlspecialchars($doctor['profile_image']); ?>" alt="Profile photo of <?php echo htmlspecialchars($doctor['name']); ?>">
                                <?php else: ?>
                                    <i class="fas fa-user-md" aria-hidden="true"></i>
                                <?php endif; ?>
                            </div>

                            <div class="doctor-info">
                                <div class="mb-2">
                                    <span class="specialization-badge">
                                        <?php echo htmlspecialchars($doctor['specialization_name'] ?? 'General'); ?>
                                    </span>
                                    <?php if (!empty($doctor['department_name'])): ?>
                                        <span class="department-badge">
                                            <i class="fas fa-building me-1" aria-hidden="true"></i><?php echo htmlspecialchars($doctor['department_name']); ?>
                                        </span>
                                    <?php endif; ?>
                                </div>

                                <h5 class="doctor-name">
                                    <?php echo htmlspecialchars($doctor['name']); ?>
                                </h5>

                                <div class="contact-info">
                                    <div class="mb-2">
                                        <i class="fas fa-phone"></i>
                                        <?php echo htmlspecialchars($doctor['contact']); ?>
                                    </div>
                                    <div class="mb-2">
                                        <i class="fas fa-envelope"></i>
                                        <?php echo htmlspecialchars($doctor['email'] ?? 'Not available'); ?>
                                    </div>
                                </div>

                                <div class="working-hours">
                                    <h6><i class="fas fa-clock me-1"></i>Available Schedule</h6>
                                    <?php if (!empty($doctor['availability_schedule'])): ?>
                                        <small class="text-muted">
                                            <?php echo $doctor['availability_schedule']; ?>
                                        </small>
                                    <?php else: ?>
                                        <small class="text-muted text-center d-block">
                                            <i class="fas fa-exclamation-triangle me-1"></i>
                                            No schedule available
                                        </small>
                                    <?php endif; ?>
                                </div>

                                <div class="d-grid gap-2">
                                    <a href="book_appointment.php?doctor_id=<?php echo (int)$doctor['id']; ?>"
                                       class="btn btn-primary">
                                        <i class="fas fa-calendar-plus me-2"></i>Book Appointment
                                    </a>
                                    <a href="doctor_profile.php?id=<?php echo (int)$doctor['id']; ?>"
                                       class="btn btn-outline-primary">
                                        <i class="fas fa-info-circle me-2"></i>View Profile
                                    </a>
                                </div>
                            </div>
                        </div>
                    </div>
                <?php endforeach; ?>
            </div>
        <?php endif; ?>
    </div>

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
            <hr class="border-light my-4 opacity-25">
            <div class="d-flex flex-wrap justify-content-between align-items-center small opacity-75">
                <span>&copy; <?php echo date('Y'); ?> MedCare Hospital. All rights reserved.</span>
                <span>Powered by <?php echo APP_NAME; ?> Patient Portal</span>
            </div>
        </div>
    </footer>

    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js"></script>
</body>
</html>
