<?php
require_once 'config/config.php';

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
$specialization_filter = sanitizeInput($_GET['specialization'] ?? '');
$department_filter = isset($_GET['department']) && $_GET['department'] !== '' ? (int)$_GET['department'] : null;

// Build the SQL query based on search parameters with availability + department data
$sql = "SELECT d.*,
               dept.name AS department_name,
               GROUP_CONCAT(DISTINCT da.available_day 
                            ORDER BY FIELD(da.available_day, 'Monday', 'Tuesday', 'Wednesday', 'Thursday', 'Friday', 'Saturday', 'Sunday') 
                            SEPARATOR ', ') as available_days,
               GROUP_CONCAT(DISTINCT CONCAT(da.available_day, ': ', TIME_FORMAT(da.start_time, '%h:%i %p'), ' - ', TIME_FORMAT(da.end_time, '%h:%i %p')) 
                            ORDER BY FIELD(da.available_day, 'Monday', 'Tuesday', 'Wednesday', 'Thursday', 'Friday', 'Saturday', 'Sunday') 
                            SEPARATOR '<br>') as availability_schedule
        FROM doctors d
        LEFT JOIN doctor_availability da ON d.id = da.doctor_id AND da.is_active = 1
        LEFT JOIN departments dept ON d.department_id = dept.id
        WHERE 1=1";
$params = [];

if (!empty($search_query)) {
    $sql .= " AND (d.name LIKE ? OR d.specialization LIKE ?)";
    $params[] = "%$search_query%";
    $params[] = "%$search_query%";
}

if (!empty($specialization_filter)) {
    $sql .= " AND d.specialization = ?";
    $params[] = $specialization_filter;
}

if (!empty($department_filter)) {
    $sql .= " AND d.department_id = ?";
    $params[] = $department_filter;
}

$sql .= " GROUP BY d.id ORDER BY d.name ASC";

// Execute the query
try {
    $stmt = $pdo->prepare($sql);
    $stmt->execute($params);
    $doctors = $stmt->fetchAll();
} catch (PDOException $e) {
    // For production, you might want to log this instead
    $doctors = [];
}

// Get all specializations for filter dropdown
try {
    $stmt = $pdo->prepare("SELECT DISTINCT specialization FROM doctors ORDER BY specialization ASC");
    $stmt->execute();
    $specializations = $stmt->fetchAll(PDO::FETCH_COLUMN);
} catch (PDOException $e) {
    $specializations = [];
}

// Get departments for filter dropdown
try {
    $stmt = $pdo->prepare("SELECT id, name FROM departments ORDER BY name ASC");
    $stmt->execute();
    $departments = $stmt->fetchAll();
} catch (PDOException $e) {
    $departments = [];
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
            transform: translateY(-5px);
            box-shadow: 0 15px 40px rgba(0, 0, 0, 0.15);
        }
        
        .search-section {
            background: linear-gradient(135deg, var(--primary-color), #00796b);
            color: white;
            padding: 3rem 0;
            margin-bottom: 2rem;
        }
        
        .search-form {
            background: rgba(255, 255, 255, 0.1);
            border-radius: 20px;
            padding: 2rem;
            backdrop-filter: blur(10px);
        }
        
        .form-control {
            border-radius: 15px;
            border: 2px solid rgba(255, 255, 255, 0.3);
            background: rgba(255, 255, 255, 0.9);
            padding: 15px 20px;
        }
        
        .form-control:focus {
            border-color: var(--secondary-color);
            box-shadow: 0 0 0 0.2rem rgba(139, 195, 74, 0.25);
            background: white;
        }
        
        .btn-primary {
            background-color: var(--secondary-color);
            border-color: var(--secondary-color);
            border-radius: 25px;
            padding: 12px 30px;
            font-weight: 600;
        }
        
        .btn-primary:hover {
            background-color: #7cb342;
            border-color: #7cb342;
        }
        
        .btn-outline-primary {
            color: var(--primary-color);
            border-color: var(--primary-color);
            border-radius: 25px;
            padding: 8px 20px;
        }
        
        .btn-outline-primary:hover {
            background-color: var(--primary-color);
            border-color: var(--primary-color);
        }
        
        .doctor-card {
            height: 100%;
            overflow: hidden;
        }
        
        .doctor-image {
            height: 250px;
            background: linear-gradient(45deg, var(--primary-color), var(--secondary-color));
            display: flex;
            align-items: center;
            justify-content: center;
            color: white;
            font-size: 4rem;
            position: relative;
        }
        
        .doctor-image::before {
            content: '';
            position: absolute;
            top: 0;
            left: 0;
            right: 0;
            bottom: 0;
            background: url('https://images.unsplash.com/photo-1612349317150-e413f6a5b16d?ixlib=rb-4.0.3&auto=format&fit=crop&w=800&q=80') center/cover;
            opacity: 0.3;
        }
        
        .doctor-image i {
            position: relative;
            z-index: 1;
        }
        
        .specialization-badge {
            background: var(--primary-color);
            color: white;
            padding: 0.5rem 1rem;
            border-radius: 20px;
            font-size: 0.85rem;
            font-weight: 600;
            display: inline-block;
            margin-bottom: 0.5rem;
        }

        .department-badge {
            background: rgba(0, 150, 136, 0.12);
            color: var(--secondary-color);
            padding: 0.35rem 0.75rem;
            border-radius: 14px;
            font-size: 0.8rem;
            font-weight: 600;
            display: inline-block;
            margin-left: .5rem;
            vertical-align: middle;
        }
        
        .doctor-info {
            padding: 1.5rem;
        }
        
        .doctor-name {
            color: var(--text-color);
            font-weight: 700;
            font-size: 1.3rem;
            margin-bottom: 0.5rem;
        }
        
        .contact-info {
            color: #666;
            margin-bottom: 1rem;
        }
        
        .contact-info i {
            color: var(--primary-color);
            width: 20px;
            margin-right: 8px;
        }
        
        .working-hours {
            background: rgba(0, 150, 136, 0.05);
            border-radius: 10px;
            padding: 1rem;
            margin-bottom: 1rem;
        }
        
        .working-hours h6 {
            color: var(--primary-color);
            margin-bottom: 0.5rem;
            font-size: 0.9rem;
        }
        
        .no-results {
            text-align: center;
            padding: 3rem;
            color: #666;
        }
        
        .no-results i {
            font-size: 4rem;
            color: var(--primary-color);
            margin-bottom: 1rem;
        }
        
        .results-count {
            background: rgba(0, 150, 136, 0.1);
            border-radius: 15px;
            padding: 1rem;
            margin-bottom: 2rem;
            text-align: center;
        }
        
        .results-count h5 {
            color: var(--primary-color);
            margin: 0;
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
                        <li class="nav-item">
                            <a class="nav-link" href="feedback.php">
                                <i class="fas fa-comment-medical me-1"></i>Give Feedback
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

    <!-- Search Section -->
    <div class="search-section">
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
                                    <select class="form-control" name="department">
                                        <option value="">All Departments</option>
                                        <?php foreach ($departments as $dep): ?>
                                            <option value="<?php echo (int)$dep['id']; ?>"
                                                    <?php echo ($department_filter === (int)$dep['id']) ? 'selected' : ''; ?>>
                                                <?php echo htmlspecialchars($dep['name']); ?>
                                            </option>
                                        <?php endforeach; ?>
                                    </select>
                                </div>
                                <div class="col-md-4">
                                    <select class="form-control" name="specialization">
                                        <option value="">All Specializations</option>
                                        <?php foreach ($specializations as $spec): ?>
                                            <option value="<?php echo htmlspecialchars($spec); ?>"
                                                    <?php echo ($specialization_filter === $spec) ? 'selected' : ''; ?>>
                                                <?php echo htmlspecialchars($spec); ?>
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
                            
                            <?php if (!empty($search_query) || !empty($specialization_filter) || !empty($department_filter)): ?>
                                <div class="text-center mt-3">
                                    <a href="doctors.php" class="btn btn-outline-light btn-sm">
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
        <?php if (!empty($search_query) || !empty($specialization_filter) || !empty($department_filter)): ?>
            <div class="results-count">
                <h5>
                    <i class="fas fa-search me-2"></i>
                    Found <?php echo count($doctors); ?> doctor<?php echo count($doctors) !== 1 ? 's' : ''; ?>
                    <?php if (!empty($search_query)): ?>
                        for "<?php echo htmlspecialchars($search_query); ?>"
                    <?php endif; ?>
                    <?php if (!empty($specialization_filter)): ?>
                        in specialization <?php echo htmlspecialchars($specialization_filter); ?>
                    <?php endif; ?>
                    <?php if (!empty($department_filter)): ?>
                        <?php
                        // show selected department name inline
                        $deptName = '';
                        foreach ($departments as $dep) {
                            if ((int)$dep['id'] === (int)$department_filter) { $deptName = $dep['name']; break; }
                        }
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
                <p class="lead">We couldn't find any doctors matching your search criteria.</p>
                <a href="doctors.php" class="btn btn-primary">
                    <i class="fas fa-list me-2"></i>View All Doctors
                </a>
            </div>
        <?php else: ?>
            <div class="row">
                <?php foreach ($doctors as $doctor): ?>
                    <div class="col-lg-4 col-md-6 mb-4">
                        <div class="card hospital-card doctor-card">
                            <div class="doctor-image">
                                <i class="fas fa-user-md"></i>
                            </div>
                            
                            <div class="doctor-info">
                                <div class="mb-2">
                                    <span class="specialization-badge">
                                        <?php echo htmlspecialchars($doctor['specialization']); ?>
                                    </span>
                                    <?php if (!empty($doctor['department_name'])): ?>
                                        <span class="department-badge">
                                            <i class="fas fa-building me-1"></i><?php echo htmlspecialchars($doctor['department_name']); ?>
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

    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js"></script>
</body>
</html>
