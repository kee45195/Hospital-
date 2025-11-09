<?php
require_once '../config/config.php';

// Check if doctor is logged in
if (!isset($_SESSION['doctor_id'])) {
    header('Location: login.php');
    exit();
}

$doctor_id = $_SESSION['doctor_id'];
$doctor_name = $_SESSION['doctor_name'];
$doctor_specialization = $_SESSION['doctor_specialization'];
$error_message = '';

// Get dashboard statistics
try {
    // Total appointments today
    $stmt = $pdo->prepare("
        SELECT COUNT(*) 
        FROM appointments 
        WHERE doctor_id = ? 
          AND appointment_date = CURDATE() 
          AND status IN ('Confirmed', 'Pending')
    ");
    $stmt->execute([$doctor_id]);
    $today_appointments = (int)$stmt->fetchColumn();
    
    // Total patients
    $stmt = $pdo->prepare("
        SELECT COUNT(DISTINCT patient_id) 
        FROM appointments 
        WHERE doctor_id = ?
    ");
    $stmt->execute([$doctor_id]);
    $total_patients = (int)$stmt->fetchColumn();
    
    // Pending appointments
    $stmt = $pdo->prepare("
        SELECT COUNT(*) 
        FROM appointments 
        WHERE doctor_id = ? 
          AND status = 'Pending'
    ");
    $stmt->execute([$doctor_id]);
    $pending_appointments = (int)$stmt->fetchColumn();
    
    // This week's appointments
    $stmt = $pdo->prepare("
        SELECT COUNT(*) 
        FROM appointments 
        WHERE doctor_id = ? 
          AND YEARWEEK(appointment_date, 1) = YEARWEEK(CURDATE(), 1)
          AND status IN ('Confirmed', 'Pending')
    ");
    $stmt->execute([$doctor_id]);
    $week_appointments = (int)$stmt->fetchColumn();
    
    // Upcoming (next 5) appointments
    $stmt = $pdo->prepare("
        SELECT a.*, p.name AS patient_name, p.phone AS patient_phone 
        FROM appointments a 
        JOIN patients p ON a.patient_id = p.id 
        WHERE a.doctor_id = ? 
          AND (a.appointment_date > CURDATE() 
               OR (a.appointment_date = CURDATE() AND a.appointment_time >= CURTIME()))
          AND a.status IN ('Confirmed', 'Pending')
        ORDER BY a.appointment_date ASC, a.appointment_time ASC 
        LIMIT 5
    ");
    $stmt->execute([$doctor_id]);
    $recent_appointments = $stmt->fetchAll(PDO::FETCH_ASSOC);
    
    // Recent feedback (only those tied to THIS doctor's appointments)
    // We consider only feedback that references an appointment (appointment_id is not null)
    // and that appointment belongs to this doctor.
    $stmt = $pdo->prepare("
        SELECT 
            f.id,
            f.feedback_text,
            f.rating,
            COALESCE(f.feedback_date, f.created_at) AS fb_date,
            p.name AS patient_name,
            a.appointment_date,
            a.appointment_time
        FROM feedback f
        INNER JOIN appointments a ON a.id = f.appointment_id
        INNER JOIN patients p ON p.id = f.patient_id
        WHERE a.doctor_id = ?
        ORDER BY fb_date DESC
        LIMIT 5
    ");
    $stmt->execute([$doctor_id]);
    $recent_feedback = $stmt->fetchAll(PDO::FETCH_ASSOC);
    
} catch (PDOException $e) {
    $error_message = 'Database error occurred.';
}
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Doctor Dashboard - <?php echo APP_NAME; ?></title>
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
        body { background-color: var(--background-color); color: var(--text-color); font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; }
        .navbar { background-color: var(--primary-color) !important; box-shadow: 0 2px 10px rgba(0, 0, 0, 0.1); }
        .navbar-brand { font-weight: 700; font-size: 1.5rem; }
        .nav-link { font-weight: 500; transition: all 0.3s ease; }
        .nav-link:hover { background-color: rgba(255, 255, 255, 0.1); border-radius: 5px; }
        .main-content { padding: 2rem 0; }
        .welcome-card { background: linear-gradient(135deg, var(--primary-color) 0%, var(--accent-color) 100%); color: white; border-radius: 15px; padding: 2rem; margin-bottom: 2rem; }
        .stat-card { background: white; border-radius: 15px; padding: 1.5rem; box-shadow: 0 5px 15px rgba(0, 0, 0, 0.08); transition: transform 0.3s ease, box-shadow 0.3s ease; border-left: 4px solid var(--primary-color); }
        .stat-card:hover { transform: translateY(-5px); box-shadow: 0 10px 25px rgba(0, 0, 0, 0.15); }
        .stat-card.secondary { border-left-color: var(--secondary-color); }
        .stat-card.accent { border-left-color: var(--accent-color); }
        .stat-card.warning { border-left-color: #FF9800; }
        .stat-number { font-size: 2.5rem; font-weight: 700; color: var(--primary-color); }
        .stat-label { font-size: 0.9rem; color: #666; text-transform: uppercase; letter-spacing: 0.5px; }
        .stat-icon { font-size: 2rem; opacity: 0.7; }
        .content-card { background: white; border-radius: 15px; padding: 1.5rem; box-shadow: 0 5px 15px rgba(0, 0, 0, 0.08); margin-bottom: 2rem; }
        .card-header { border-bottom: 2px solid var(--background-color); padding-bottom: 1rem; margin-bottom: 1.5rem; }
        .card-title { color: var(--primary-color); font-weight: 600; margin: 0; }
        .btn-primary { background-color: var(--primary-color); border-color: var(--primary-color); }
        .btn-primary:hover { background-color: #006064; border-color: #006064; }
        .btn-secondary { background-color: var(--secondary-color); border-color: var(--secondary-color); color: var(--text-color); }
        .btn-accent { background-color: var(--accent-color); border-color: var(--accent-color); color: white; }
        .appointment-item { border-left: 3px solid var(--primary-color); padding: 1rem; margin-bottom: 1rem; background: var(--background-color); border-radius: 0 10px 10px 0; }
        .appointment-time { font-weight: 600; color: var(--primary-color); }
        .patient-name { font-weight: 500; margin-bottom: 0.25rem; }
        .status-badge { font-size: 0.75rem; padding: 0.25rem 0.5rem; border-radius: 20px; }
        .status-pending { background-color: #FFF3E0; color: #F57C00; }
        .status-confirmed { background-color: #E8F5E8; color: #2E7D32; }
        .feedback-item { border-bottom: 1px solid #eee; padding: 1rem 0; }
        .feedback-item:last-child { border-bottom: none; }
        .rating-stars i { margin-left: 2px; }
        .quick-actions { display: flex; gap: 1rem; flex-wrap: wrap; }
        .action-btn { flex: 1; min-width: 200px; padding: 1rem; text-align: center; border-radius: 10px; text-decoration: none; transition: all 0.3s ease; }
        .action-btn:hover { transform: translateY(-2px); text-decoration: none; }
    </style>
</head>
<body>
    <!-- Navigation -->
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
                    <li class="nav-item"><a class="nav-link active" href="dashboard.php"><i class="fas fa-tachometer-alt me-1"></i>Dashboard</a></li>
                    <li class="nav-item"><a class="nav-link" href="appointments.php"><i class="fas fa-calendar-check me-1"></i>Appointments</a></li>
                    <li class="nav-item"><a class="nav-link" href="availability.php"><i class="fas fa-clock me-1"></i>Availability</a></li>
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
    
    <!-- Main Content -->
    <div class="main-content">
        <div class="container">
            <!-- Welcome Section -->
            <div class="welcome-card">
                <div class="row align-items-center">
                    <div class="col-md-8">
                        <h1 class="mb-2">Welcome back, <?php echo htmlspecialchars($doctor_name); ?>!</h1>
                        <p class="mb-0 opacity-75"><i class="fas fa-stethoscope me-2"></i><?php echo htmlspecialchars($doctor_specialization); ?> Specialist</p>
                        <p class="mb-0 mt-2 opacity-75"><i class="fas fa-calendar me-2"></i><?php echo date('l, F j, Y'); ?></p>
                    </div>
                    <div class="col-md-4 text-end">
                        <i class="fas fa-user-md" style="font-size: 4rem; opacity: 0.3;"></i>
                    </div>
                </div>
            </div>
            
            <!-- Statistics Cards -->
            <div class="row mb-4">
                <div class="col-lg-3 col-md-6 mb-3">
                    <div class="stat-card">
                        <div class="d-flex justify-content-between align-items-center">
                            <div>
                                <div class="stat-number"><?php echo $today_appointments; ?></div>
                                <div class="stat-label">Today's Appointments</div>
                            </div>
                            <div class="stat-icon text-primary"><i class="fas fa-calendar-day"></i></div>
                        </div>
                    </div>
                </div>
                <div class="col-lg-3 col-md-6 mb-3">
                    <div class="stat-card secondary">
                        <div class="d-flex justify-content-between align-items-center">
                            <div>
                                <div class="stat-number"><?php echo $total_patients; ?></div>
                                <div class="stat-label">Total Patients</div>
                            </div>
                            <div class="stat-icon" style="color: var(--secondary-color);"><i class="fas fa-users"></i></div>
                        </div>
                    </div>
                </div>
                <div class="col-lg-3 col-md-6 mb-3">
                    <div class="stat-card warning">
                        <div class="d-flex justify-content-between align-items-center">
                            <div>
                                <div class="stat-number"><?php echo $pending_appointments; ?></div>
                                <div class="stat-label">Pending Approvals</div>
                            </div>
                            <div class="stat-icon" style="color: #FF9800;"><i class="fas fa-clock"></i></div>
                        </div>
                    </div>
                </div>
                <div class="col-lg-3 col-md-6 mb-3">
                    <div class="stat-card accent">
                        <div class="d-flex justify-content-between align-items-center">
                            <div>
                                <div class="stat-number"><?php echo $week_appointments; ?></div>
                                <div class="stat-label">This Week</div>
                            </div>
                            <div class="stat-icon" style="color: var(--accent-color);"><i class="fas fa-chart-line"></i></div>
                        </div>
                    </div>
                </div>
            </div>
            
            <!-- Quick Actions -->
            <div class="content-card">
                <div class="card-header">
                    <h3 class="card-title"><i class="fas fa-bolt me-2"></i>Quick Actions</h3>
                </div>
                <div class="quick-actions">
                    <a href="appointments.php" class="action-btn btn btn-primary">
                        <i class="fas fa-calendar-check d-block mb-2" style="font-size: 1.5rem;"></i>
                        <strong>Manage Appointments</strong>
                        <small class="d-block mt-1">View and update appointments</small>
                    </a>
                    <a href="availability.php" class="action-btn btn btn-accent">
                        <i class="fas fa-clock d-block mb-2" style="font-size: 1.5rem;"></i>
                        <strong>Set Availability</strong>
                        <small class="d-block mt-1">Manage your schedule</small>
                    </a>
                    <a href="patients.php" class="action-btn btn btn-secondary">
                        <i class="fas fa-user-injured d-block mb-2" style="font-size: 1.5rem;"></i>
                        <strong>Patient Records</strong>
                        <small class="d-block mt-1">View medical history</small>
                    </a>
                </div>
            </div>
            
            <div class="row">
                <!-- Upcoming Appointments -->
                <div class="col-lg-8">
                    <div class="content-card">
                        <div class="card-header d-flex justify-content-between align-items-center">
                            <h3 class="card-title"><i class="fas fa-calendar-alt me-2"></i>Upcoming Appointments</h3>
                            <a href="appointments.php" class="btn btn-sm btn-outline-primary">View All</a>
                        </div>
                        <?php if (empty($recent_appointments)): ?>
                            <div class="text-center py-4">
                                <i class="fas fa-calendar-times" style="font-size: 3rem; color: #ccc;"></i>
                                <p class="mt-3 text-muted">No upcoming appointments</p>
                                <a href="availability.php" class="btn btn-primary">Set Your Availability</a>
                            </div>
                        <?php else: ?>
                            <?php foreach ($recent_appointments as $appointment): ?>
                                <div class="appointment-item">
                                    <div class="d-flex justify-content-between align-items-start">
                                        <div>
                                            <div class="patient-name"><?php echo htmlspecialchars($appointment['patient_name']); ?></div>
                                            <div class="appointment-time">
                                                <i class="fas fa-calendar me-1"></i>
                                                <?php echo date('M j, Y', strtotime($appointment['appointment_date'])); ?> at 
                                                <?php echo date('g:i A', strtotime($appointment['appointment_time'])); ?>
                                            </div>
                                            <div class="text-muted small mt-1">
                                                <i class="fas fa-phone me-1"></i><?php echo htmlspecialchars($appointment['patient_phone']); ?>
                                            </div>
                                        </div>
                                        <span class="status-badge status-<?php echo strtolower($appointment['status']); ?>">
                                            <?php echo htmlspecialchars($appointment['status']); ?>
                                        </span>
                                    </div>
                                </div>
                            <?php endforeach; ?>
                        <?php endif; ?>
                    </div>
                </div>
                
                <!-- Recent Feedback -->
                <div class="col-lg-4">
                    <div class="content-card">
                        <div class="card-header d-flex justify-content-between align-items-center">
                            <h3 class="card-title"><i class="fas fa-star me-2"></i>Recent Feedback</h3>
                            <a href="feedback.php" class="btn btn-sm btn-outline-primary">View All</a>
                        </div>
                        <?php if (empty($recent_feedback)): ?>
                            <div class="text-center py-4">
                                <i class="fas fa-star-half-alt" style="font-size: 2rem; color: #ccc;"></i>
                                <p class="mt-2 text-muted small">No feedback yet</p>
                            </div>
                        <?php else: ?>
                            <?php foreach ($recent_feedback as $f): ?>
                                <div class="feedback-item">
                                    <div class="d-flex justify-content-between align-items-start mb-2">
                                        <strong class="small"><?php echo htmlspecialchars($f['patient_name']); ?></strong>
                                        <div class="rating-stars small">
                                            <?php
                                                $r = max(0, min(5, (int)$f['rating']));
                                                for ($i = 1; $i <= 5; $i++) {
                                                    if ($i <= $r) {
                                                        echo '<i class="fa-solid fa-star"></i>';
                                                    } else {
                                                        echo '<i class="fa-regular fa-star"></i>';
                                                    }
                                                }
                                            ?>
                                        </div>
                                    </div>
                                    <p class="small text-muted mb-1">
                                        <?php echo htmlspecialchars(mb_strimwidth($f['feedback_text'], 0, 120, '…')); ?>
                                    </p>
                                    <small class="text-muted d-block mb-1">
                                        <i class="fa-regular fa-calendar me-1"></i>
                                        <?php echo $f['appointment_date'] ? date('M j, Y', strtotime($f['appointment_date'])) : ''; ?>
                                        <?php echo $f['appointment_time'] ? ' at ' . date('g:i A', strtotime($f['appointment_time'])) : ''; ?>
                                    </small>
                                    <small class="text-muted">
                                        <i class="fa-regular fa-clock me-1"></i>
                                        <?php echo date('M j, Y', strtotime($f['fb_date'])); ?>
                                    </small>
                                </div>
                            <?php endforeach; ?>
                        <?php endif; ?>
                    </div>
                </div>
            </div>
        </div>
    </div>
    
    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js"></script>
</body>
</html>
