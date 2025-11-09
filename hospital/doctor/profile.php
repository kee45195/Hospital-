<?php
require_once '../config/config.php';

// Check if doctor is logged in
if (!isset($_SESSION['doctor_id'])) {
    header('Location: login.php');
    exit();
}

$doctor_id = $_SESSION['doctor_id'];
$success_message = '';
$error_message = '';

/* -----------------------------
   Load departments (for dropdown)
------------------------------ */
try {
    $stmt = $pdo->prepare("SELECT id, name FROM departments ORDER BY name ASC");
    $stmt->execute();
    $departments = $stmt->fetchAll(PDO::FETCH_ASSOC);
} catch (PDOException $e) {
    $departments = [];
}

/* --------------------------------
   Handle profile update / password
--------------------------------- */
if ($_SERVER['REQUEST_METHOD'] == 'POST') {
    if (!validateCSRFToken($_POST['csrf_token'] ?? '')) {
        $error_message = 'Invalid security token. Please try again.';
    } else {
        $action = $_POST['action'] ?? '';
        
        try {
            if ($action == 'update_profile') {
                $name           = trim($_POST['name'] ?? '');
                $email          = trim($_POST['email'] ?? '');
                $phone          = trim($_POST['phone'] ?? '');
                $specialization = trim($_POST['specialization'] ?? '');
                $department_id  = isset($_POST['department_id']) && $_POST['department_id'] !== '' ? (int)$_POST['department_id'] : null; // NEW
                $working_days   = $_POST['working_days'] ?? [];
                $working_hours  = trim($_POST['working_hours'] ?? '');
                $bio            = trim($_POST['bio'] ?? '');
                
                // Validation
                if (empty($name) || empty($email) || empty($specialization)) {
                    $error_message = 'Name, email, and specialization are required.';
                } elseif (!isValidEmail($email)) {
                    $error_message = 'Please enter a valid email address.';
                } elseif (!empty($phone) && !isValidPhone($phone)) {
                    $error_message = 'Please enter a valid phone number.';
                } else {
                    // If a department was selected, ensure it exists
                    if (!is_null($department_id)) {
                        $stmt = $pdo->prepare("SELECT 1 FROM departments WHERE id = ?");
                        $stmt->execute([$department_id]);
                        if (!$stmt->fetchColumn()) {
                            $error_message = 'Selected department does not exist.';
                        }
                    }

                    if (empty($error_message)) {
                        // Check if email is already taken by another doctor
                        $stmt = $pdo->prepare("SELECT id FROM doctors WHERE email = ? AND id != ?");
                        $stmt->execute([$email, $doctor_id]);
                        
                        if ($stmt->fetch()) {
                            $error_message = 'This email is already registered with another doctor.';
                        } else {
                            // Update profile (INCLUDES department_id)  // NEW
                            $working_days_str = implode(',', $working_days);

                            $stmt = $pdo->prepare("
                                UPDATE doctors 
                                SET name = ?, 
                                    email = ?, 
                                    phone = ?, 
                                    specialization = ?, 
                                    department_id = ?, 
                                    working_days = ?, 
                                    working_hours = ?, 
                                    bio = ?, 
                                    updated_at = NOW()
                                WHERE id = ?
                            ");
                            $stmt->execute([
                                $name, 
                                $email, 
                                $phone, 
                                $specialization, 
                                $department_id, 
                                $working_days_str, 
                                $working_hours, 
                                $bio, 
                                $doctor_id
                            ]);

                            // Update session data
                            $_SESSION['doctor_name']  = $name;
                            $_SESSION['doctor_email'] = $email;
                            
                            $success_message = 'Profile updated successfully.';
                        }
                    }
                }
                
            } elseif ($action == 'change_password') {
                $current_password = $_POST['current_password'] ?? '';
                $new_password     = $_POST['new_password'] ?? '';
                $confirm_password = $_POST['confirm_password'] ?? '';
                
                if (empty($current_password) || empty($new_password) || empty($confirm_password)) {
                    $error_message = 'All password fields are required.';
                } elseif ($new_password !== $confirm_password) {
                    $error_message = 'New passwords do not match.';
                } elseif (strlen($new_password) < 6) {
                    $error_message = 'New password must be at least 6 characters long.';
                } else {
                    // Verify current password
                    $stmt = $pdo->prepare("SELECT password FROM doctors WHERE id = ?");
                    $stmt->execute([$doctor_id]);
                    $doctorPassRow = $stmt->fetch(PDO::FETCH_ASSOC);
                    
                    if (!$doctorPassRow || !verifyPassword($current_password, $doctorPassRow['password'])) {
                        $error_message = 'Current password is incorrect.';
                    } else {
                        // Update password
                        $hashed_password = hashPassword($new_password);
                        $stmt = $pdo->prepare("UPDATE doctors SET password = ?, updated_at = NOW() WHERE id = ?");
                        $stmt->execute([$hashed_password, $doctor_id]);
                        
                        $success_message = 'Password changed successfully.';
                    }
                }
            }
        } catch (PDOException $e) {
            $error_message = 'Database error occurred. Please try again.';
        }
    }
}

/* ---------------------------
   Get doctor profile data
   (Join department for name)
---------------------------- */
try {
    $stmt = $pdo->prepare("
        SELECT d.*,
               dept.name AS department_name,
               COUNT(DISTINCT a.id)                                              AS total_appointments,
               COUNT(DISTINCT CASE WHEN a.status = 'Completed' THEN a.id END)    AS completed_appointments,
               AVG(f.rating)                                                     AS average_rating,
               COUNT(DISTINCT f.id)                                              AS total_reviews
        FROM doctors d
        LEFT JOIN departments dept ON dept.id = d.department_id
        LEFT JOIN appointments a ON d.id = a.doctor_id
        LEFT JOIN feedback f ON d.id = f.doctor_id
        WHERE d.id = ?
        GROUP BY d.id, dept.name
    ");
    $stmt->execute([$doctor_id]);
    $doctor = $stmt->fetch(PDO::FETCH_ASSOC);
    
    if (!$doctor) {
        header('Location: logout.php');
        exit();
    }
    
    // Parse working days
    $working_days_array = !empty($doctor['working_days']) ? explode(',', $doctor['working_days']) : [];
    
} catch (PDOException $e) {
    $error_message = 'Database error occurred.';
    $doctor = null;
}

$csrf_token       = generateCSRFToken();
$specializations  = getMedicalSpecializations();
$days_of_week     = ['Monday', 'Tuesday', 'Wednesday', 'Thursday', 'Friday', 'Saturday', 'Sunday'];
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Doctor Profile - <?php echo APP_NAME; ?></title>
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
        
        body {
            background-color: var(--background-color);
            color: var(--text-color);
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
        }
        
        .navbar {
            background-color: var(--primary-color) !important;
            box-shadow: 0 2px 10px rgba(0, 0, 0, 0.1);
        }
        
        .navbar-brand {
            font-weight: 700;
            font-size: 1.5rem;
        }
        
        .nav-link {
            font-weight: 500;
            transition: all 0.3s ease;
        }
        
        .nav-link:hover {
            background-color: rgba(255, 255, 255, 0.1);
            border-radius: 5px;
        }
        
        .main-content {
            padding: 2rem 0;
        }
        
        .content-card {
            background: white;
            border-radius: 15px;
            padding: 1.5rem;
            box-shadow: 0 5px 15px rgba(0, 0, 0, 0.08);
            margin-bottom: 2rem;
        }
        
        .page-header {
            background: linear-gradient(135deg, var(--primary-color) 0%, var(--accent-color) 100%);
            color: white;
            border-radius: 15px;
            padding: 2rem;
            margin-bottom: 2rem;
        }
        
        .btn-primary {
            background-color: var(--primary-color);
            border-color: var(--primary-color);
        }
        
        .btn-primary:hover {
            background-color: #006064;
            border-color: #006064;
        }
        
        .btn-secondary {
            background-color: var(--secondary-color);
            border-color: var(--secondary-color);
            color: var(--text-color);
        }
        
        .btn-accent {
            background-color: var(--accent-color);
            border-color: var(--accent-color);
            color: white;
        }
        
        .profile-avatar {
            width: 120px;
            height: 120px;
            border-radius: 50%;
            background: var(--primary-color);
            display: flex;
            align-items: center;
            justify-content: center;
            color: white;
            font-size: 3rem;
            font-weight: bold;
            margin: 0 auto 1rem;
        }
        
        .stats-card {
            background: white;
            border-radius: 10px;
            padding: 1.5rem;
            text-align: center;
            box-shadow: 0 3px 10px rgba(0, 0, 0, 0.1);
            transition: transform 0.3s ease;
        }
        
        .stats-card:hover {
            transform: translateY(-5px);
        }
        
        .stats-number {
            font-size: 2rem;
            font-weight: 700;
            color: var(--primary-color);
        }
        
        .stats-label {
            color: #666;
            font-weight: 500;
        }
        
        .form-control:focus, .form-select:focus {
            border-color: var(--primary-color);
            box-shadow: 0 0 0 0.2rem rgba(0, 131, 143, 0.25);
        }
        
        .form-check-input:checked {
            background-color: var(--primary-color);
            border-color: var(--primary-color);
        }
        
        .profile-section {
            border-bottom: 1px solid #e0e0e0;
            padding-bottom: 1.5rem;
            margin-bottom: 1.5rem;
        }
        
        .profile-section:last-child {
            border-bottom: none;
            margin-bottom: 0;
        }
        
        .working-days {
            display: flex;
            flex-wrap: wrap;
            gap: 0.5rem;
        }
        
        .day-badge {
            background: var(--secondary-color);
            color: var(--text-color);
            padding: 0.25rem 0.75rem;
            border-radius: 15px;
            font-size: 0.85rem;
            font-weight: 500;
        }
        
        .modal-header {
            background-color: var(--primary-color);
            color: white;
        }
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
                    <li class="nav-item">
                        <a class="nav-link" href="dashboard.php">
                            <i class="fas fa-tachometer-alt me-1"></i>Dashboard
                        </a>
                    </li>
                    <li class="nav-item">
                        <a class="nav-link" href="appointments.php">
                            <i class="fas fa-calendar-check me-1"></i>Appointments
                        </a>
                    </li>
                    <li class="nav-item">
                        <a class="nav-link" href="availability.php">
                            <i class="fas fa-clock me-1"></i>Availability
                        </a>
                    </li>
                    <li class="nav-item">
                        <a class="nav-link" href="patients.php">
                            <i class="fas fa-user-injured me-1"></i>Patients
                        </a>
                    </li>
                    <li class="nav-item">
                        <a class="nav-link" href="feedback.php">
                            <i class="fas fa-star me-1"></i>Feedback
                        </a>
                    </li>
                </ul>
                
                <ul class="navbar-nav">
                    <li class="nav-item dropdown">
                        <a class="nav-link dropdown-toggle active" href="#" id="navbarDropdown" role="button" data-bs-toggle="dropdown">
                            <i class="fas fa-user-md me-1"></i><?php echo htmlspecialchars($doctor['name']); ?>
                        </a>
                        <ul class="dropdown-menu">
                            <li><a class="dropdown-item active" href="profile.php"><i class="fas fa-user me-2"></i>Profile</a></li>
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
            <!-- Page Header -->
            <div class="page-header">
                <div class="row align-items-center">
                    <div class="col-md-8">
                        <h1 class="mb-2"><i class="fas fa-user-md me-3"></i>Doctor Profile</h1>
                        <p class="mb-0 opacity-75">Manage your professional information and settings</p>
                    </div>
                    <div class="col-md-4 text-end">
                        <i class="fas fa-id-card" style="font-size: 4rem; opacity: 0.3;"></i>
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
            
            <div class="row">
                <!-- Profile Overview -->
                <div class="col-lg-4">
                    <div class="content-card text-center">
                        <div class="profile-avatar">
                            <?php echo strtoupper(substr($doctor['name'], 0, 1)); ?>
                        </div>
                        <h4><?php echo htmlspecialchars($doctor['name']); ?></h4>
                        <p class="text-muted mb-1"><?php echo htmlspecialchars($doctor['specialization']); ?></p>
                        <?php if (!empty($doctor['department_name'])): ?>
                            <p class="text-muted"><i class="fas fa-building me-1"></i><?php echo htmlspecialchars($doctor['department_name']); ?></p>
                        <?php endif; ?>
                        
                        <?php if (!empty($doctor['bio'])): ?>
                            <div class="mb-3">
                                <small class="text-muted"><?php echo nl2br(htmlspecialchars($doctor['bio'])); ?></small>
                            </div>
                        <?php endif; ?>
                        
                        <div class="mb-3">
                            <strong>Working Days:</strong><br>
                            <div class="working-days mt-2">
                                <?php if (!empty($working_days_array)): ?>
                                    <?php foreach ($working_days_array as $day): ?>
                                        <span class="day-badge"><?php echo htmlspecialchars($day); ?></span>
                                    <?php endforeach; ?>
                                <?php else: ?>
                                    <span class="text-muted">Not set</span>
                                <?php endif; ?>
                            </div>
                        </div>
                        
                        <?php if (!empty($doctor['working_hours'])): ?>
                            <div class="mb-3">
                                <strong>Working Hours:</strong><br>
                                <span class="text-muted"><?php echo htmlspecialchars($doctor['working_hours']); ?></span>
                            </div>
                        <?php endif; ?>
                        
                        <div class="d-grid gap-2">
                            <button type="button" class="btn btn-primary" data-bs-toggle="modal" data-bs-target="#editProfileModal">
                                <i class="fas fa-edit me-2"></i>Edit Profile
                            </button>
                            <button type="button" class="btn btn-accent" data-bs-toggle="modal" data-bs-target="#changePasswordModal">
                                <i class="fas fa-key me-2"></i>Change Password
                            </button>
                        </div>
                    </div>
                </div>
                
                <!-- Statistics -->
                <div class="col-lg-8">
                    <div class="row mb-4">
                        <div class="col-md-6 mb-3">
                            <div class="stats-card">
                                <div class="stats-number"><?php echo number_format($doctor['total_appointments']); ?></div>
                                <div class="stats-label">Total Appointments</div>
                            </div>
                        </div>
                        <div class="col-md-6 mb-3">
                            <div class="stats-card">
                                <div class="stats-number"><?php echo number_format($doctor['completed_appointments']); ?></div>
                                <div class="stats-label">Completed</div>
                            </div>
                        </div>
                        <div class="col-md-6 mb-3">
                            <div class="stats-card">
                                <div class="stats-number"><?php echo $doctor['average_rating'] ? number_format($doctor['average_rating'], 1) : 'N/A'; ?></div>
                                <div class="stats-label">Average Rating</div>
                                <?php if ($doctor['average_rating']): ?>
                                    <div class="mt-2">
                                        <?php for ($i = 1; $i <= 5; $i++): ?>
                                            <i class="fas fa-star <?php echo $i <= round($doctor['average_rating']) ? 'text-warning' : 'text-muted'; ?>"></i>
                                        <?php endfor; ?>
                                    </div>
                                <?php endif; ?>
                            </div>
                        </div>
                        <div class="col-md-6 mb-3">
                            <div class="stats-card">
                                <div class="stats-number"><?php echo number_format($doctor['total_reviews']); ?></div>
                                <div class="stats-label">Patient Reviews</div>
                            </div>
                        </div>
                    </div>
                    
                    <!-- Profile Details -->
                    <div class="content-card">
                        <h5 class="mb-4"><i class="fas fa-info-circle me-2"></i>Profile Information</h5>
                        
                        <div class="profile-section">
                            <div class="row">
                                <div class="col-sm-4"><strong>Full Name:</strong></div>
                                <div class="col-sm-8"><?php echo htmlspecialchars($doctor['name']); ?></div>
                            </div>
                        </div>
                        
                        <div class="profile-section">
                            <div class="row">
                                <div class="col-sm-4"><strong>Email:</strong></div>
                                <div class="col-sm-8"><?php echo htmlspecialchars($doctor['email']); ?></div>
                            </div>
                        </div>
                        
                        <div class="profile-section">
                            <div class="row">
                                <div class="col-sm-4"><strong>Phone:</strong></div>
                                <div class="col-sm-8"><?php echo $doctor['phone'] ? htmlspecialchars($doctor['phone']) : 'Not provided'; ?></div>
                            </div>
                        </div>
                        
                        <div class="profile-section">
                            <div class="row">
                                <div class="col-sm-4"><strong>Specialization:</strong></div>
                                <div class="col-sm-8"><?php echo htmlspecialchars($doctor['specialization']); ?></div>
                            </div>
                        </div>

                        <div class="profile-section">
                            <div class="row">
                                <div class="col-sm-4"><strong>Department:</strong></div>
                                <div class="col-sm-8"><?php echo $doctor['department_name'] ? htmlspecialchars($doctor['department_name']) : 'Not assigned'; ?></div>
                            </div>
                        </div>
                        
                        <div class="profile-section">
                            <div class="row">
                                <div class="col-sm-4"><strong>Member Since:</strong></div>
                                <div class="col-sm-8"><?php echo formatDate($doctor['created_at']); ?></div>
                            </div>
                        </div>
                        
                        <div class="profile-section">
                            <div class="row">
                                <div class="col-sm-4"><strong>Last Updated:</strong></div>
                                <div class="col-sm-8"><?php echo $doctor['updated_at'] ? formatDateTime($doctor['updated_at']) : 'Never'; ?></div>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    </div>

    <!-- Edit Profile Modal (includes Department) -->
    <div class="modal fade" id="editProfileModal" tabindex="-1">
        <div class="modal-dialog modal-lg">
            <div class="modal-content">
                <div class="modal-header">
                    <h5 class="modal-title"><i class="fas fa-edit me-2"></i>Edit Profile</h5>
                    <button type="button" class="btn-close btn-close-white" data-bs-dismiss="modal"></button>
                </div>
                <form method="POST">
                    <div class="modal-body">
                        <input type="hidden" name="csrf_token" value="<?php echo $csrf_token; ?>">
                        <input type="hidden" name="action" value="update_profile">
                        
                        <div class="row">
                            <div class="col-md-6">
                                <div class="mb-3">
                                    <label for="name" class="form-label">Full Name *</label>
                                    <input type="text" class="form-control" id="name" name="name" 
                                           value="<?php echo htmlspecialchars($doctor['name']); ?>" required>
                                </div>
                            </div>
                            <div class="col-md-6">
                                <div class="mb-3">
                                    <label for="email" class="form-label">Email Address *</label>
                                    <input type="email" class="form-control" id="email" name="email" 
                                           value="<?php echo htmlspecialchars($doctor['email']); ?>" required>
                                </div>
                            </div>
                        </div>
                        
                        <div class="row">
                            <div class="col-md-6">
                                <div class="mb-3">
                                    <label for="phone" class="form-label">Phone Number</label>
                                    <input type="tel" class="form-control" id="phone" name="phone" 
                                           value="<?php echo htmlspecialchars($doctor['phone']); ?>">
                                </div>
                            </div>
                            <div class="col-md-6">
                                <div class="mb-3">
                                    <label for="specialization" class="form-label">Specialization *</label>
                                    <select class="form-select" id="specialization" name="specialization" required>
                                        <option value="">Select Specialization</option>
                                        <?php foreach ($specializations as $spec => $desc): ?>
                                            <option value="<?php echo htmlspecialchars($spec); ?>" 
                                                    <?php echo $doctor['specialization'] == $spec ? 'selected' : ''; ?>>
                                                <?php echo htmlspecialchars($spec); ?>
                                            </option>
                                        <?php endforeach; ?>
                                    </select>
                                </div>
                            </div>
                        </div>

                        <!-- NEW: Department selector -->
                        <div class="mb-3">
                            <label for="department_id" class="form-label">Department</label>
                            <select class="form-select" id="department_id" name="department_id">
                                <option value="">-- Not assigned --</option>
                                <?php foreach ($departments as $dep): ?>
                                    <option value="<?php echo (int)$dep['id']; ?>"
                                        <?php echo ($doctor['department_id'] && (int)$doctor['department_id'] === (int)$dep['id']) ? 'selected' : ''; ?>>
                                        <?php echo htmlspecialchars($dep['name']); ?>
                                    </option>
                                <?php endforeach; ?>
                            </select>
                        </div>
                        
                        <div class="mb-3">
                            <label class="form-label">Working Days</label>
                            <div class="row">
                                <?php foreach ($days_of_week as $day): ?>
                                    <div class="col-md-3 col-6">
                                        <div class="form-check">
                                            <input class="form-check-input" type="checkbox" 
                                                   id="day_<?php echo strtolower($day); ?>" 
                                                   name="working_days[]" value="<?php echo $day; ?>"
                                                   <?php echo in_array($day, $working_days_array) ? 'checked' : ''; ?>>
                                            <label class="form-check-label" for="day_<?php echo strtolower($day); ?>">
                                                <?php echo $day; ?>
                                            </label>
                                        </div>
                                    </div>
                                <?php endforeach; ?>
                            </div>
                        </div>
                        
                        <div class="mb-3">
                            <label for="working_hours" class="form-label">Working Hours</label>
                            <input type="text" class="form-control" id="working_hours" name="working_hours" 
                                   value="<?php echo htmlspecialchars($doctor['working_hours']); ?>"
                                   placeholder="e.g., 9:00 AM - 5:00 PM">
                        </div>
                        
                        <div class="mb-3">
                            <label for="bio" class="form-label">Professional Bio</label>
                            <textarea class="form-control" id="bio" name="bio" rows="3" 
                                      placeholder="Brief description about yourself and your practice..."><?php echo htmlspecialchars($doctor['bio']); ?></textarea>
                        </div>
                    </div>
                    <div class="modal-footer">
                        <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">Cancel</button>
                        <button type="submit" class="btn btn-primary">
                            <i class="fas fa-save me-2"></i>Update Profile
                        </button>
                    </div>
                </form>
            </div>
        </div>
    </div>
    
    <!-- Change Password Modal -->
    <div class="modal fade" id="changePasswordModal" tabindex="-1">
        <div class="modal-dialog">
            <div class="modal-content">
                <div class="modal-header">
                    <h5 class="modal-title"><i class="fas fa-key me-2"></i>Change Password</h5>
                    <button type="button" class="btn-close btn-close-white" data-bs-dismiss="modal"></button>
                </div>
                <form method="POST">
                    <div class="modal-body">
                        <input type="hidden" name="csrf_token" value="<?php echo $csrf_token; ?>">
                        <input type="hidden" name="action" value="change_password">
                        
                        <div class="mb-3">
                            <label for="current_password" class="form-label">Current Password *</label>
                            <input type="password" class="form-control" id="current_password" name="current_password" required>
                        </div>
                        
                        <div class="mb-3">
                            <label for="new_password" class="form-label">New Password *</label>
                            <input type="password" class="form-control" id="new_password" name="new_password" 
                                   minlength="6" required>
                            <div class="form-text">Password must be at least 6 characters long.</div>
                        </div>
                        
                        <div class="mb-3">
                            <label for="confirm_password" class="form-label">Confirm New Password *</label>
                            <input type="password" class="form-control" id="confirm_password" name="confirm_password" 
                                   minlength="6" required>
                        </div>
                    </div>
                    <div class="modal-footer">
                        <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">Cancel</button>
                        <button type="submit" class="btn btn-primary">
                            <i class="fas fa-save me-2"></i>Change Password
                        </button>
                    </div>
                </form>
            </div>
        </div>
    </div>
    
    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js"></script>
    <script>
        // Password confirmation validation
        document.getElementById('confirm_password').addEventListener('input', function() {
            const newPassword = document.getElementById('new_password').value;
            const confirmPassword = this.value;
            
            if (newPassword !== confirmPassword) {
                this.setCustomValidity('Passwords do not match');
            } else {
                this.setCustomValidity('');
            }
        });
    </script>
</body>
</html>
