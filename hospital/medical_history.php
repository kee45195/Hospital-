<?php
require_once 'config/config.php';

// Require login
requireLogin();

$patient_id = getCurrentPatientId();

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
// Get patient's medical history with doctor information
try {
    $stmt = $pdo->prepare("
        SELECT mh.*, d.name AS doctor_name, d.specialization, d.contact AS doctor_contact
        FROM medical_history mh
        JOIN doctors d ON mh.doctor_id = d.id
        WHERE mh.patient_id = ?
        ORDER BY mh.consultation_date DESC, mh.created_at DESC
    ");
    $stmt->execute([$patient_id]);
    $medical_records = $stmt->fetchAll();
} catch (PDOException $e) {
    die('Database error: ' . $e->getMessage());
}

// Get patient information for header
try {
    $stmt = $pdo->prepare("SELECT * FROM patients WHERE id = ?");
    $stmt->execute([$patient_id]);
    $patient = $stmt->fetch();
} catch (PDOException $e) {
    die('Database error: ' . $e->getMessage());
}

// Compute age from date_of_birth (if available)
$patient_age = null;
$patient_dob_str = '';
if (!empty($patient['date_of_birth'])) {
    try {
        $dob = new DateTime($patient['date_of_birth']);
        $today = new DateTime('today');
        $patient_age = $dob->diff($today)->y;
        // Human-friendly DOB string (e.g., Jan 05, 1990)
        $patient_dob_str = $dob->format('M d, Y');
    } catch (Exception $e) {
        // Leave age as null if DOB parsing fails
        $patient_age = null;
        $patient_dob_str = htmlspecialchars($patient['date_of_birth']);
    }
}

// Group records by year for better organization
$records_by_year = [];
foreach ($medical_records as $record) {
    $year = date('Y', strtotime($record['consultation_date']));
    if (!isset($records_by_year[$year])) {
        $records_by_year[$year] = [];
    }
    $records_by_year[$year][] = $record;
}

// Sort years in descending order
krsort($records_by_year);
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Medical History - <?php echo APP_NAME; ?></title>
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
        
        body {
            background-color: var(--background-color);
            color: var(--text-color);
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
        }
        
        .navbar {
            background: linear-gradient(135deg, var(--primary-color), #00796b) !important;
            box-shadow: 0 2px 10px rgba(0, 0, 0, 0.1);
        }
        
        .navbar-brand {
            font-weight: 700;
            font-size: 1.5rem;
        }
        
        .navbar-nav .nav-link {
            color: white !important;
            font-weight: 500;
            margin: 0 10px;
            transition: all 0.3s ease;
        }
        
        .navbar-nav .nav-link:hover {
            color: var(--secondary-color) !important;
        }
        
        .hospital-card {
            background: white;
            border-radius: 20px;
            box-shadow: 0 10px 30px rgba(0, 0, 0, 0.1);
            border: none;
            transition: all 0.3s ease;
        }
        
        .hospital-card:hover {
            transform: translateY(-2px);
            box-shadow: 0 15px 40px rgba(0, 0, 0, 0.15);
        }
        
        .medical-header {
            background: linear-gradient(135deg, var(--primary-color), #00796b);
            color: white;
            padding: 3rem 0;
            position: relative;
            overflow: hidden;
        }
        
        .medical-header::before {
            content: '';
            position: absolute;
            top: 0;
            left: 0;
            right: 0;
            bottom: 0;
            background: url('https://images.unsplash.com/photo-1576091160399-112ba8d25d1f?ixlib=rb-4.0.3&auto=format&fit=crop&w=1200&q=80') center/cover;
            opacity: 0.1;
        }
        
        .header-content {
            position: relative;
            z-index: 1;
        }
        
        .patient-info-card {
            background: rgba(255, 255, 255, 0.1);
            backdrop-filter: blur(10px);
            border-radius: 20px;
            padding: 2rem;
            margin-top: 2rem;
        }
        
        .patient-info-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 1.5rem;
        }
        
        .info-item { text-align: center; }
        .info-icon { font-size: 2rem; margin-bottom: 0.5rem; color: var(--secondary-color); }
        .info-label { font-size: 0.9rem; opacity: 0.8; margin-bottom: 0.25rem; }
        .info-value { font-size: 1.1rem; font-weight: 600; }
        
        .year-section { margin-bottom: 3rem; }
        .year-header {
            background: var(--primary-color);
            color: white;
            padding: 1rem 1.5rem;
            border-radius: 15px;
            margin-bottom: 1.5rem;
            display: flex;
            align-items: center;
            justify-content: space-between;
        }
        .year-title { font-size: 1.5rem; font-weight: 700; margin: 0; }
        .year-count { background: rgba(255, 255, 255, 0.2); padding: 0.5rem 1rem; border-radius: 20px; font-size: 0.9rem; }
        
        .medical-record { border-left: 5px solid var(--primary-color); margin-bottom: 1.5rem; position: relative; }
        .record-header {
            background: linear-gradient(135deg, #f8f9fa, #e9ecef);
            padding: 1.5rem;
            border-radius: 15px 15px 0 0;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }
        .record-date { background: var(--primary-color); color: white; padding: 0.5rem 1rem; border-radius: 20px; font-weight: 600; font-size: 0.9rem; }
        .doctor-info { display: flex; align-items: center; }
        .doctor-avatar {
            width: 50px; height: 50px; border-radius: 50%;
            background: var(--secondary-color); display: flex; align-items: center; justify-content: center;
            color: white; font-size: 1.2rem; margin-right: 1rem;
        }
        .doctor-details h6 { margin: 0; color: var(--primary-color); font-weight: 700; }
        .doctor-details small { color: #6c757d; }
        
        .record-body { padding: 1.5rem; }
        .record-section { margin-bottom: 1.5rem; }
        .record-section:last-child { margin-bottom: 0; }
        .section-title { color: var(--primary-color); font-weight: 700; font-size: 1.1rem; margin-bottom: 0.5rem; display: flex; align-items: center; }
        .section-icon { margin-right: 0.5rem; width: 20px; }
        .section-content { background: #f8f9fa; padding: 1rem; border-radius: 10px; border-left: 3px solid var(--secondary-color); }
        .prescription-item { background: white; padding: 0.75rem; border-radius: 8px; margin-bottom: 0.5rem; border: 1px solid #e0e0e0; }
        .prescription-item:last-child { margin-bottom: 0; }
        .medication-name { font-weight: 600; color: var(--primary-color); }
        .medication-details { font-size: 0.9rem; color: #6c757d; margin-top: 0.25rem; }
        
        .empty-state { text-align: center; padding: 4rem 2rem; color: #6c757d; }
        .empty-state i { font-size: 5rem; margin-bottom: 1.5rem; color: var(--primary-color); opacity: 0.5; }
        .empty-state h3 { margin-bottom: 1rem; }
        
        .stats-grid {
            display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 1.5rem; margin-bottom: 2rem;
        }
        .stat-card { background: white; padding: 1.5rem; border-radius: 15px; text-align: center; box-shadow: 0 5px 15px rgba(0, 0, 0, 0.1); }
        .stat-icon { font-size: 2.5rem; margin-bottom: 1rem; }
        .stat-number { font-size: 2rem; font-weight: 700; margin-bottom: 0.5rem; }
        .stat-label { color: #6c757d; font-size: 0.9rem; }
        
        .print-btn { position: fixed; bottom: 2rem; right: 2rem; z-index: 1000; }
        
        @media print {
            .navbar, .print-btn { display: none !important; }
            .medical-header { background: var(--primary-color) !important; -webkit-print-color-adjust: exact; }
        }

                        /* Footer contact cards  */
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
                    <li class="nav-item"><a class="nav-link" href="appointments.php"><i class="fas fa-calendar-check me-1"></i>My Appointments</a></li>
                    <li class="nav-item"><a class="nav-link active" href="medical_history.php"><i class="fas fa-history me-1"></i>Medical History</a></li>
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

    <!-- Medical History Header -->
    <div class="medical-header mt-4">
        <div class="container">
            <div class="header-content">
                <div class="row align-items-center">
                    <div class="col-md-8">
                        <h1 class="display-4 fw-bold mb-3">
                            <i class="fas fa-file-medical-alt me-3"></i>Medical History
                        </h1>
                        <p class="lead">Complete record of your healthcare journey and consultations</p>
                    </div>
                    <div class="col-md-4">
                        <div class="patient-info-card">
                            <div class="patient-info-grid">
                                <div class="info-item">
                                    <div class="info-icon"><i class="fas fa-user"></i></div>
                                    <div class="info-label">Patient</div>
                                    <div class="info-value"><?php echo htmlspecialchars($patient['name']); ?></div>
                                </div>
                                <div class="info-item">
                                    <div class="info-icon"><i class="fas fa-birthday-cake"></i></div>
                                    <div class="info-label">Age</div>
                                    <div class="info-value">
                                        <?php echo ($patient_age !== null) ? ($patient_age . ' years') : 'N/A'; ?>
                                    </div>
                                </div>
                                <div class="info-item">
                                    <div class="info-icon"><i class="fas fa-calendar-day"></i></div>
                                    <div class="info-label">Date of Birth</div>
                                    <div class="info-value">
                                        <?php echo !empty($patient_dob_str) ? htmlspecialchars($patient_dob_str) : 'N/A'; ?>
                                    </div>
                                </div>
                                <div class="info-item">
                                    <div class="info-icon"><i class="fas fa-venus-mars"></i></div>
                                    <div class="info-label">Gender</div>
                                    <div class="info-value">
                                        <?php echo !empty($patient['gender']) ? ucfirst($patient['gender']) : 'N/A'; ?>
                                    </div>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    </div>

    <div class="container mt-4">
        <?php if (!empty($medical_records)): ?>
            <!-- Statistics -->
            <div class="stats-grid">
                <div class="stat-card">
                    <div class="stat-icon" style="color: var(--primary-color);"><i class="fas fa-file-medical"></i></div>
                    <div class="stat-number" style="color: var(--primary-color);"><?php echo count($medical_records); ?></div>
                    <div class="stat-label">Total Records</div>
                </div>
                
                <div class="stat-card">
                    <div class="stat-icon" style="color: var(--secondary-color);"><i class="fas fa-user-md"></i></div>
                    <div class="stat-number" style="color: var(--secondary-color);">
                        <?php 
                        $unique_doctors = array_unique(array_column($medical_records, 'doctor_id'));
                        echo count($unique_doctors);
                        ?>
                    </div>
                    <div class="stat-label">Doctors Consulted</div>
                </div>
                
                <div class="stat-card">
                    <div class="stat-icon" style="color: var(--accent-color);"><i class="fas fa-calendar-alt"></i></div>
                    <div class="stat-number" style="color: var(--accent-color);"><?php echo count($records_by_year); ?></div>
                    <div class="stat-label">Years of Records</div>
                </div>
                
                <div class="stat-card">
                    <div class="stat-icon" style="color: var(--primary-color);"><i class="fas fa-clock"></i></div>
                    <div class="stat-number" style="color: var(--primary-color);">
                        <?php 
                        $latest_record = reset($medical_records);
                        echo $latest_record ? date('M Y', strtotime($latest_record['consultation_date'])) : 'N/A';
                        ?>
                    </div>
                    <div class="stat-label">Latest Visit</div>
                </div>
            </div>

            <!-- Medical Records by Year -->
            <?php foreach ($records_by_year as $year => $records): ?>
                <div class="year-section">
                    <div class="year-header">
                        <h2 class="year-title"><i class="fas fa-calendar me-2"></i><?php echo $year; ?></h2>
                        <div class="year-count"><?php echo count($records); ?> record<?php echo count($records) > 1 ? 's' : ''; ?></div>
                    </div>
                    
                    <?php foreach ($records as $record): ?>
                        <div class="card hospital-card medical-record">
                            <div class="record-header">
                                <div class="doctor-info">
                                    <div class="doctor-avatar"><i class="fas fa-user-md"></i></div>
                                    <div class="doctor-details">
                                        <h6><?php echo htmlspecialchars($record['doctor_name']); ?></h6>
                                        <small><?php echo htmlspecialchars($record['specialization']); ?></small>
                                    </div>
                                </div>
                                <div class="record-date">
                                    <i class="fas fa-calendar me-2"></i>
                                    <?php echo formatDate($record['consultation_date']); ?>
                                </div>
                            </div>
                            
                            <div class="record-body">
                                <?php if (!empty($record['diagnosis'])): ?>
                                    <div class="record-section">
                                        <div class="section-title"><i class="fas fa-stethoscope section-icon"></i>Diagnosis</div>
                                        <div class="section-content"><?php echo nl2br(htmlspecialchars($record['diagnosis'])); ?></div>
                                    </div>
                                <?php endif; ?>
                                
                                <?php if (!empty($record['prescription'])): ?>
                                    <div class="record-section">
                                        <div class="section-title"><i class="fas fa-pills section-icon"></i>Prescription</div>
                                        <div class="section-content">
                                            <?php 
                                            // Split on newlines (handles \r\n, \n, or \r)
                                            $prescriptions = preg_split("/\r\n|\n|\r/", $record['prescription']);
                                            foreach ($prescriptions as $prescription):
                                                $prescription = trim($prescription);
                                                if (!empty($prescription)):
                                            ?>
                                                <div class="prescription-item">
                                                    <?php 
                                                    // Try to parse medication format: "Name - Dosage - Instructions"
                                                    $parts = explode(' - ', $prescription);
                                                    if (count($parts) >= 2):
                                                    ?>
                                                        <div class="medication-name"><?php echo htmlspecialchars($parts[0]); ?></div>
                                                        <div class="medication-details"><?php echo htmlspecialchars(implode(' - ', array_slice($parts, 1))); ?></div>
                                                    <?php else: ?>
                                                        <div class="medication-name"><?php echo htmlspecialchars($prescription); ?></div>
                                                    <?php endif; ?>
                                                </div>
                                            <?php 
                                                endif;
                                            endforeach; 
                                            ?>
                                        </div>
                                    </div>
                                <?php endif; ?>
                                
                                <?php if (!empty($record['notes'])): ?>
                                    <div class="record-section">
                                        <div class="section-title"><i class="fas fa-sticky-note section-icon"></i>Additional Notes</div>
                                        <div class="section-content"><?php echo nl2br(htmlspecialchars($record['notes'])); ?></div>
                                    </div>
                                <?php endif; ?>
                                
                                <div class="record-section">
                                    <div class="section-title"><i class="fas fa-info-circle section-icon"></i>Contact Information</div>
                                    <div class="section-content">
                                        <strong>Doctor:</strong> <?php echo htmlspecialchars($record['doctor_name']); ?><br>
                                        <strong>Specialization:</strong> <?php echo htmlspecialchars($record['specialization']); ?><br>
                                        <strong>Contact:</strong> <?php echo htmlspecialchars($record['doctor_contact']); ?>
                                    </div>
                                </div>
                            </div>
                        </div>
                    <?php endforeach; ?>
                </div>
            <?php endforeach; ?>
            
        <?php else: ?>
            <!-- Empty State -->
            <div class="card hospital-card">
                <div class="card-body">
                    <div class="empty-state">
                        <i class="fas fa-file-medical-alt"></i>
                        <h3>No Medical History Found</h3>
                        <p>Your medical records and consultation history will appear here after your first appointment.</p>
                        
                    </div>
                </div>
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

    <!-- Print Button -->
    <?php if (!empty($medical_records)): ?>
        <button class="btn btn-primary btn-lg print-btn" onclick="window.print()">
            <i class="fas fa-print me-2"></i>Print History
        </button>
    <?php endif; ?>

    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js"></script>
</body>
</html>
