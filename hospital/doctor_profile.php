<?php
require_once 'config/config.php';

// PUBLIC PAGE — no requireLogin()

// Detect logged-in patient (for navbar and UX only)
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

// Validate doctor id
$doctor_id = isset($_GET['id']) ? (int)$_GET['id'] : 0;
if ($doctor_id <= 0) {
    header('Location: doctors.php');
    exit();
}

// Get doctor information
try {
    $stmt = $pdo->prepare("SELECT * FROM doctors WHERE id = ?");
    $stmt->execute([$doctor_id]);
    $doctor = $stmt->fetch();
    
    if (!$doctor) {
        header('Location: doctors.php');
        exit();
    }
} catch (PDOException $e) {
    die('Database error: ' . $e->getMessage());
}

// Get doctor's appointment statistics
try {
    $stmt = $pdo->prepare("
        SELECT 
            COUNT(*) as total_appointments,
            COUNT(CASE WHEN status = 'completed' THEN 1 END) as completed_appointments,
            COUNT(CASE WHEN status = 'scheduled' THEN 1 END) as scheduled_appointments
        FROM appointments 
        WHERE doctor_id = ?
    ");
    $stmt->execute([$doctor_id]);
    $stats = $stmt->fetch();
} catch (PDOException $e) {
    $stats = ['total_appointments' => 0, 'completed_appointments' => 0, 'scheduled_appointments' => 0];
}

// Get doctor's availability from doctor_availability table
try {
    $stmt = $pdo->prepare("
        SELECT available_day, start_time, end_time 
        FROM doctor_availability 
        WHERE doctor_id = ? AND is_active = 1
        ORDER BY FIELD(available_day, 'Monday', 'Tuesday', 'Wednesday', 'Thursday', 'Friday', 'Saturday', 'Sunday')
    ");
    $stmt->execute([$doctor_id]);
    $availability_data = $stmt->fetchAll();
    
    // Create arrays for working days and hours
    $working_days_array = [];
    $availability_schedule = [];
    
    foreach ($availability_data as $availability) {
        $working_days_array[] = $availability['available_day'];
        $availability_schedule[$availability['available_day']] = [
            'start_time' => $availability['start_time'],
            'end_time' => $availability['end_time']
        ];
    }
    
    // Format working days and hours for display
    $working_days_display = !empty($working_days_array) ? implode(', ', $working_days_array) : 'Not set';
    
    // General working hours (use first available day's hours as general display)
    $general_hours = 'Not set';
    if (!empty($availability_schedule)) {
        $first_schedule = reset($availability_schedule);
        $start_formatted = date('g:i A', strtotime($first_schedule['start_time']));
        $end_formatted = date('g:i A', strtotime($first_schedule['end_time']));
        $general_hours = $start_formatted . ' - ' . $end_formatted;
    }
    
} catch (PDOException $e) {
    $working_days_array = [];
    $availability_schedule = [];
    $working_days_display = 'Not available';
    $general_hours = 'Not available';
}

// Check if doctor is available today (and right now)
$today = date('l'); // e.g., Monday
$is_available_today = in_array($today, $working_days_array ?? []);
$current_time = date('H:i');
$is_in_working_hours = false;

if ($is_available_today && isset($availability_schedule[$today])) {
    $today_schedule = $availability_schedule[$today];
    $start_24 = date('H:i', strtotime($today_schedule['start_time']));
    $end_24 = date('H:i', strtotime($today_schedule['end_time']));
    $is_in_working_hours = ($current_time >= $start_24 && $current_time <= $end_24);
}

// Helper formatters for new fields
$experience_years = isset($doctor['experience_years']) && $doctor['experience_years'] !== '' ? (int)$doctor['experience_years'] : null;
$experience_label = $experience_years !== null ? $experience_years . ' ' . ($experience_years == 1 ? 'year' : 'years') : 'Not provided';
$qualification = isset($doctor['qualification']) && trim((string)$doctor['qualification']) !== '' ? $doctor['qualification'] : 'Not provided';
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title><?php echo htmlspecialchars($doctor['name']); ?> - <?php echo APP_NAME; ?></title>
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
        }
        
        .doctor-header {
            background: linear-gradient(135deg, var(--primary-color), #00796b);
            color: white;
            padding: 3rem 0;
            position: relative;
            overflow: hidden;
        }
        
        .doctor-header::before {
            content: '';
            position: absolute;
            top: 0;
            left: 0;
            right: 0;
            bottom: 0;
            background: url('https://images.unsplash.com/photo-1559839734-2b71ea197ec2?ixlib=rb-4.0.3&auto=format&fit=crop&w=1200&q=80') center/cover;
            opacity: 0.1;
        }
        
        .doctor-avatar {
            width: 150px;
            height: 150px;
            border-radius: 50%;
            background: rgba(255, 255, 255, 0.2);
            display: flex;
            align-items: center;
            justify-content: center;
            font-size: 4rem;
            margin: 0 auto 2rem;
            position: relative;
            z-index: 1;
            border: 5px solid rgba(255, 255, 255, 0.3);
        }
        
        .doctor-info {
            position: relative;
            z-index: 1;
            text-align: center;
        }
        
        .specialization-badge {
            background: var(--secondary-color);
            color: white;
            padding: 0.7rem 1.5rem;
            border-radius: 25px;
            font-size: 1rem;
            font-weight: 600;
            display: inline-block;
            margin-bottom: 1rem;
        }
        
        .availability-status {
            padding: 0.5rem 1rem;
            border-radius: 20px;
            font-weight: 600;
            display: inline-block;
            margin-top: 1rem;
        }
        
        .available {
            background: var(--secondary-color);
            color: white;
        }
        
        .unavailable {
            background: var(--accent-color);
            color: white;
        }
        
        .stats-card {
            background: rgba(0, 150, 136, 0.05);
            border-radius: 15px;
            padding: 1.5rem;
            text-align: center;
            height: 100%;
        }
        
        .stat-number {
            font-size: 2.5rem;
            font-weight: 700;
            color: var(--primary-color);
            margin-bottom: 0.5rem;
        }
        
        .stat-label {
            color: var(--text-color);
            font-size: 0.9rem;
            font-weight: 500;
        }
        
        .info-section {
            background: white;
            border-radius: 15px;
            padding: 2rem;
            margin-bottom: 2rem;
            box-shadow: 0 5px 15px rgba(0, 0, 0, 0.08);
        }
        
        .info-section h4 {
            color: var(--primary-color);
            margin-bottom: 1.5rem;
            font-weight: 700;
        }
        
        .info-item {
            display: flex;
            align-items: center;
            margin-bottom: 1rem;
            padding: 1rem;
            background: rgba(0, 150, 136, 0.05);
            border-radius: 10px;
        }
        
        .info-icon {
            color: var(--primary-color);
            font-size: 1.2rem;
            width: 30px;
            margin-right: 15px;
        }
        
        .working-schedule {
            background: white;
            border-radius: 15px;
            padding: 2rem;
            box-shadow: 0 5px 15px rgba(0, 0, 0, 0.08);
        }
        
        .schedule-day {
            display: flex;
            justify-content: space-between;
            align-items: center;
            padding: 1rem;
            margin-bottom: 0.5rem;
            border-radius: 10px;
            background: rgba(0, 150, 136, 0.05);
        }
        
        .schedule-day.active {
            background: var(--primary-color);
            color: white;
        }
        
        .day-name {
            font-weight: 600;
        }
        
        .day-hours {
            font-size: 0.9rem;
        }
        
        .btn-primary {
            background-color: var(--primary-color);
            border-color: var(--primary-color);
            border-radius: 25px;
            padding: 12px 30px;
            font-weight: 600;
        }
        
        .btn-primary:hover {
            background-color: #00796b;
            border-color: #00796b;
        }
        
        .btn-secondary {
            background-color: var(--secondary-color);
            border-color: var(--secondary-color);
            border-radius: 25px;
            color: white;
        }
        
        .btn-outline-primary {
            color: var(--primary-color);
            border-color: var(--primary-color);
            border-radius: 25px;
        }
        
        .btn-outline-primary:hover {
            background-color: var(--primary-color);
            border-color: var(--primary-color);
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
                    <li class="nav-item">
                        <a class="nav-link" href="dashboard.php">
                            <i class="fas fa-home me-1"></i><?php echo $is_patient ? 'Home' : 'Welcome'; ?>
                        </a>
                    </li>
                    <li class="nav-item">
                        <a class="nav-link active" href="doctors.php">
                            <i class="fas fa-user-md me-1"></i>Find Doctors
                        </a>
                    </li>
                    <?php if ($is_patient): ?>
                        <li class="nav-item">
                            <a class="nav-link" href="appointments.php">
                                <i class="fas fa-calendar-check me-1"></i>My Appointments
                            </a>
                        </li>
                        <li class="nav-item">
                            <a class="nav-link" href="medical_history.php">
                                <i class="fas fa-history me-1"></i>Medical History
                            </a>
                        </li>
                    <?php endif; ?>
                </ul>
                
                <ul class="navbar-nav">
                    <?php if ($is_patient && !empty($current_patient['name'])): ?>
                        <li class="nav-item dropdown">
                            <a class="nav-link dropdown-toggle" href="#" id="navbarDropdown" role="button" data-bs-toggle="dropdown">
                                <i class="fas fa-user-circle me-1"></i><?php echo htmlspecialchars($current_patient['name']); ?>
                            </a>
                            <ul class="dropdown-menu">
                                <li><a class="dropdown-item" href="profile.php">
                                    <i class="fas fa-user me-2"></i>My Profile
                                </a></li>
                                <li><hr class="dropdown-divider"></li>
                                <li><a class="dropdown-item" href="logout.php">
                                    <i class="fas fa-sign-out-alt me-2"></i>Logout
                                </a></li>
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

    <!-- Doctor Header -->
    <div class="doctor-header">
        <div class="container">
            <div class="doctor-info">
                <div class="doctor-avatar">
                    <i class="fas fa-user-md"></i>
                </div>
                
                <div class="specialization-badge">
                    <?php echo htmlspecialchars($doctor['specialization']); ?>
                </div>
                
                <h1 class="display-4 fw-bold mb-3">
                    <?php echo htmlspecialchars($doctor['name']); ?>
                </h1>
                
                <p class="lead mb-2">
                    <?php if ($qualification !== 'Not provided'): ?>
                        <?php echo htmlspecialchars($qualification); ?>
                        <?php if ($experience_years !== null): ?>
                            • <?php echo htmlspecialchars($experience_label); ?> experience
                        <?php endif; ?>
                    <?php elseif ($experience_years !== null): ?>
                        <?php echo htmlspecialchars($experience_label); ?> experience
                    <?php else: ?>
                        Experienced healthcare professional dedicated to patient care
                    <?php endif; ?>
                </p>
                
                <div class="availability-status <?php echo ($is_available_today && $is_in_working_hours) ? 'available' : 'unavailable'; ?>">
                    <i class="fas fa-<?php echo ($is_available_today && $is_in_working_hours) ? 'check-circle' : 'clock'; ?> me-2"></i>
                    <?php if ($is_available_today && $is_in_working_hours): ?>
                        Available Now
                    <?php elseif ($is_available_today): ?>
                        Available Today (<?php echo htmlspecialchars($doctor['working_hours'] ?? $general_hours); ?>)
                    <?php else: ?>
                        Not Available Today
                    <?php endif; ?>
                </div>
            </div>
        </div>
    </div>

    <div class="container mt-4">
        <!-- Statistics -->
        <div class="row mb-4">
            <div class="col-md-4 mb-3">
                <div class="stats-card">
                    <div class="stat-number"><?php echo (int)$stats['total_appointments']; ?></div>
                    <div class="stat-label">Total Appointments</div>
                </div>
            </div>
            <div class="col-md-4 mb-3">
                <div class="stats-card">
                    <div class="stat-number"><?php echo (int)$stats['completed_appointments']; ?></div>
                    <div class="stat-label">Completed Consultations</div>
                </div>
            </div>
            <div class="col-md-4 mb-3">
                <div class="stats-card">
                    <div class="stat-number"><?php echo (int)$stats['scheduled_appointments']; ?></div>
                    <div class="stat-label">Scheduled Appointments</div>
                </div>
            </div>
        </div>

        <div class="row">
            <!-- Doctor Information -->
            <div class="col-lg-8">
                <div class="info-section">
                    <h4><i class="fas fa-info-circle me-2"></i>Doctor Information</h4>

                    <div class="info-item">
                        <i class="fas fa-award info-icon"></i>
                        <div>
                            <strong>Qualification:</strong><br>
                            <span class="text-muted"><?php echo htmlspecialchars($qualification); ?></span>
                        </div>
                    </div>

                    <div class="info-item">
                        <i class="fas fa-briefcase-medical info-icon"></i>
                        <div>
                            <strong>Experience:</strong><br>
                            <span class="text-muted"><?php echo htmlspecialchars($experience_label); ?></span>
                        </div>
                    </div>
                    
                    <div class="info-item">
                        <i class="fas fa-stethoscope info-icon"></i>
                        <div>
                            <strong>Specialization:</strong><br>
                            <span class="text-muted"><?php echo htmlspecialchars($doctor['specialization']); ?></span>
                        </div>
                    </div>
                    
                    <div class="info-item">
                        <i class="fas fa-phone info-icon"></i>
                        <div>
                            <strong>Contact Number:</strong><br>
                            <span class="text-muted"><?php echo htmlspecialchars($doctor['contact']); ?></span>
                        </div>
                    </div>
                    
                    <div class="info-item">
                        <i class="fas fa-envelope info-icon"></i>
                        <div>
                            <strong>Email Address:</strong><br>
                            <span class="text-muted"><?php echo htmlspecialchars($doctor['email'] ?? 'Not available'); ?></span>
                        </div>
                    </div>
                    
                    <div class="info-item">
                        <i class="fas fa-calendar-alt info-icon"></i>
                        <div>
                            <strong>Working Days:</strong><br>
                            <span class="text-muted"><?php echo htmlspecialchars($working_days_display); ?></span>
                        </div>
                    </div>
                    
                    <div class="info-item">
                        <i class="fas fa-clock info-icon"></i>
                        <div>
                            <strong>Working Hours:</strong><br>
                            <span class="text-muted"><?php echo htmlspecialchars($general_hours); ?></span>
                        </div>
                    </div>
                </div>
                
                <!-- Action Buttons -->
                <div class="d-flex gap-3 mb-4">
                    <a href="book_appointment.php?doctor_id=<?php echo (int)$doctor['id']; ?>" class="btn btn-primary btn-lg">
                        <i class="fas fa-calendar-plus me-2"></i>Book Appointment
                    </a>
                    <a href="doctors.php" class="btn btn-outline-primary d-inline-flex align-items-center">
                        <i class="fas fa-arrow-left me-2"></i>Back to Doctors
                    </a>
                </div>
            </div>

            <!-- Working Schedule -->
            <div class="col-lg-4">
                <div class="working-schedule">
                    <h4 class="mb-4" style="color: var(--primary-color);">
                        <i class="fas fa-calendar-week me-2"></i>Weekly Schedule
                    </h4>
                    
                    <?php 
                    $all_days = ['Monday', 'Tuesday', 'Wednesday', 'Thursday', 'Friday', 'Saturday', 'Sunday'];
                    $today = date('l');
                    
                    foreach ($all_days as $day): 
                        $is_working_day = in_array($day, $working_days_array);
                        $is_today = ($day === $today);
                    ?>
                        <div class="schedule-day <?php echo $is_today ? 'active' : ''; ?>">
                            <div class="day-name">
                                <?php echo $day; ?>
                                <?php if ($is_today): ?>
                                    <small>(Today)</small>
                                <?php endif; ?>
                            </div>
                            <div class="day-hours">
                                <?php if ($is_working_day && isset($availability_schedule[$day])): ?>
                                    <?php 
                                        $day_schedule = $availability_schedule[$day];
                                        $start_formatted = date('g:i A', strtotime($day_schedule['start_time']));
                                        $end_formatted = date('g:i A', strtotime($day_schedule['end_time']));
                                        echo htmlspecialchars($start_formatted . ' - ' . $end_formatted);
                                    ?>
                                <?php else: ?>
                                    <span class="text-muted">Closed</span>
                                <?php endif; ?>
                            </div>
                        </div>
                    <?php endforeach; ?>
                </div>
            </div>
        </div>
    </div>

    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js"></script>
</body>
</html>
