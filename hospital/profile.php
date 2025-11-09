<?php
require_once 'config/config.php';

// Require login
requireLogin();

$patient_id = getCurrentPatientId();
$errors = [];
$success_message = '';

// Load departments for dropdown
try {
    $stmt = $pdo->prepare("SELECT id, name FROM departments ORDER BY name ASC");
    $stmt->execute();
    $departments = $stmt->fetchAll(PDO::FETCH_ASSOC);
} catch (PDOException $e) {
    $departments = [];
}

// Get current patient data (with department name)
try {
    $stmt = $pdo->prepare("
        SELECT p.*, d.name AS department_name
        FROM patients p
        LEFT JOIN departments d ON d.id = p.department_id
        WHERE p.id = ?
    ");
    $stmt->execute([$patient_id]);
    $patient = $stmt->fetch(PDO::FETCH_ASSOC);
    
    if (!$patient) {
        header('Location: logout.php');
        exit();
    }
} catch (PDOException $e) {
    die('Database error: ' . $e->getMessage());
}

// Helper: compute age from date_of_birth for display
$computed_age = null;
if (!empty($patient['date_of_birth'])) {
    try {
        $dobObj = new DateTime($patient['date_of_birth']);
        $today  = new DateTime('today');
        $computed_age = $dobObj->diff($today)->y;
    } catch (Exception $e) {
        $computed_age = null;
    }
}

// Handle profile update
if ($_SERVER['REQUEST_METHOD'] == 'POST') {
    // Validate CSRF token
    if (!validateCSRFToken($_POST['csrf_token'] ?? '')) {
        $errors[] = 'Invalid security token. Please try again.';
    } else {
        // Sanitize and validate input
        $name             = sanitizeInput($_POST['name'] ?? '');
        $email            = sanitizeInput($_POST['email'] ?? '');
        $gender           = sanitizeInput($_POST['gender'] ?? '');
        $phone            = sanitizeInput($_POST['phone'] ?? '');
        $address          = sanitizeInput($_POST['address'] ?? '');
        $current_password = $_POST['current_password'] ?? '';
        $new_password     = $_POST['new_password'] ?? '';
        $confirm_password = $_POST['confirm_password'] ?? '';
        // Department (optional)
        $department_id    = isset($_POST['department_id']) && $_POST['department_id'] !== '' ? (int)$_POST['department_id'] : null;
        // Allergy (optional textarea)
        $allergy          = sanitizeInput($_POST['allergy'] ?? '');
        // NEW: Date of Birth (required)
        $dob_raw          = trim($_POST['date_of_birth'] ?? '');
        $date_of_birth    = null;
        
        // Validation
        if (empty($name)) {
            $errors[] = 'Full name is required.';
        }
        
        if (empty($email) || !isValidEmail($email)) {
            $errors[] = 'Valid email address is required.';
        }
        
        if (empty($gender) || !in_array($gender, getGenderOptions())) {
            $errors[] = 'Please select a valid gender.';
        }

        // Validate DOB (required; not in the future; not older than 120 years)
        if (empty($dob_raw)) {
            $errors[] = 'Date of birth is required.';
        } else {
            $dt = DateTime::createFromFormat('Y-m-d', $dob_raw);
            $dt_errors = DateTime::getLastErrors();
            if (!$dt || !empty($dt_errors['warning_count']) || !empty($dt_errors['error_count'])) {
                $errors[] = 'Please enter a valid date of birth (YYYY-MM-DD).';
            } else {
                $today = new DateTime('today');
                if ($dt > $today) {
                    $errors[] = 'Date of birth cannot be in the future.';
                } else {
                    $ageYears = (int)$dt->diff($today)->y;
                    if ($ageYears < 0 || $ageYears > 120) {
                        $errors[] = 'Date of birth must result in an age between 0 and 120.';
                    } else {
                        $date_of_birth = $dt->format('Y-m-d');
                    }
                }
            }
        }
        
        if (empty($phone) || !isValidPhone($phone)) {
            $errors[] = 'Valid phone number is required.';
        }
        
        if (empty($address)) {
            $errors[] = 'Address is required.';
        }

        // If department selected, ensure it exists
        if (!is_null($department_id)) {
            try {
                $chk = $pdo->prepare("SELECT 1 FROM departments WHERE id = ?");
                $chk->execute([$department_id]);
                if (!$chk->fetchColumn()) {
                    $errors[] = 'Selected department does not exist.';
                }
            } catch (PDOException $e) {
                $errors[] = 'Failed to validate department. Please try again.';
            }
        }

        // Allergy length guard (optional)
        if (!empty($allergy) && mb_strlen($allergy) > 2000) {
            $errors[] = 'Allergy text is too long (max 2000 characters).';
        }
        
        // Check if email is already taken by another user
        if (empty($errors) && $email !== $patient['email']) {
            try {
                $stmt = $pdo->prepare("SELECT id FROM patients WHERE email = ? AND id != ?");
                $stmt->execute([$email, $patient_id]);
                if ($stmt->fetch()) {
                    $errors[] = 'Email address is already taken by another user.';
                }
            } catch (PDOException $e) {
                $errors[] = 'Database error. Please try again.';
            }
        }
        
        // Password validation if changing password
        if (!empty($new_password)) {
            if (empty($current_password)) {
                $errors[] = 'Current password is required to change password.';
            } elseif (!verifyPassword($current_password, $patient['password'])) {
                $errors[] = 'Current password is incorrect.';
            } elseif (strlen($new_password) < 6) {
                $errors[] = 'New password must be at least 6 characters long.';
            } elseif ($new_password !== $confirm_password) {
                $errors[] = 'New passwords do not match.';
            }
        }
        
        // Update profile if no errors
        if (empty($errors)) {
            try {
                if (!empty($new_password)) {
                    // Update with new password
                    $hashed_password = hashPassword($new_password);
                    $stmt = $pdo->prepare("
                        UPDATE patients 
                        SET name = ?, email = ?, password = ?, gender = ?, date_of_birth = ?, phone = ?, address = ?, department_id = ?, allergy = ?, updated_at = NOW() 
                        WHERE id = ?
                    ");
                    $stmt->execute([$name, $email, $hashed_password, $gender, $date_of_birth, $phone, $address, $department_id, $allergy, $patient_id]);
                } else {
                    // Update without changing password
                    $stmt = $pdo->prepare("
                        UPDATE patients 
                        SET name = ?, email = ?, gender = ?, date_of_birth = ?, phone = ?, address = ?, department_id = ?, allergy = ?, updated_at = NOW() 
                        WHERE id = ?
                    ");
                    $stmt->execute([$name, $email, $gender, $date_of_birth, $phone, $address, $department_id, $allergy, $patient_id]);
                }
                
                // Update session data
                $_SESSION['patient_name'] = $name;
                $_SESSION['patient_email'] = $email;
                
                // Refresh patient data locally
                $patient['name']           = $name;
                $patient['email']          = $email;
                $patient['gender']         = $gender;
                $patient['date_of_birth']  = $date_of_birth;
                $patient['phone']          = $phone;
                $patient['address']        = $address;
                $patient['department_id']  = $department_id;
                $patient['allergy']        = $allergy;

                // Recompute displayed age
                $computed_age = null;
                if (!empty($patient['date_of_birth'])) {
                    $dobObj = new DateTime($patient['date_of_birth']);
                    $computed_age = $dobObj->diff(new DateTime('today'))->y;
                }

                // Set department_name from loaded $departments
                $patient['department_name'] = null;
                if (!is_null($department_id)) {
                    foreach ($departments as $dep) {
                        if ((int)$dep['id'] === (int)$department_id) {
                            $patient['department_name'] = $dep['name'];
                            break;
                        }
                    }
                }
                
                $success_message = 'Profile updated successfully!';
                
            } catch (PDOException $e) {
                $errors[] = 'Profile update failed. Please try again.';
            }
        }
    }
}

$csrf_token = generateCSRFToken();
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>My Profile - <?php echo APP_NAME; ?></title>
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
            overflow: hidden;
        }
        
        .patient-id-card {
            background: linear-gradient(135deg, var(--primary-color), #00796b);
            color: white;
            padding: 2rem;
            text-align: center;
            position: relative;
        }
        
        .patient-id-card::before {
            content: '';
            position: absolute;
            top: 0;
            left: 0;
            right: 0;
            bottom: 0;
            background: url('https://images.unsplash.com/photo-1576091160399-112ba8d25d1f?ixlib=rb-4.0.3&auto=format&fit=crop&w=1200&q=80') center/cover;
            opacity: 0.1;
        }
        
        .patient-avatar {
            width: 120px;
            height: 120px;
            border-radius: 50%;
            background: rgba(255, 255, 255, 0.2);
            display: flex;
            align-items: center;
            justify-content: center;
            margin: 0 auto 1rem;
            font-size: 3rem;
            position: relative;
            z-index: 1;
        }
        
        .patient-info {
            position: relative;
            z-index: 1;
        }
        
        .patient-id {
            background: rgba(255, 255, 255, 0.2);
            padding: 0.5rem 1rem;
            border-radius: 20px;
            display: inline-block;
            margin-top: 1rem;
        }
        
        .form-control, .form-select {
            border-radius: 15px;
            border: 2px solid #e0e0e0;
            padding: 15px 20px;
        }
        
        .form-control:focus, .form-select:focus {
            border-color: var(--primary-color);
            box-shadow: 0 0 0 0.2rem rgba(0, 150, 136, 0.25);
        }
        
        .form-label {
            font-weight: 600;
            color: var(--text-color);
            margin-bottom: 10px;
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
        
        .medical-icon {
            color: var(--primary-color);
            font-size: 1.2rem;
            margin-right: 10px;
        }
        
        .alert {
            border-radius: 15px;
            border: none;
        }
        
        .profile-stats {
            background: rgba(0, 150, 136, 0.05);
            border-radius: 15px;
            padding: 1.5rem;
        }
        
        .stat-item {
            text-align: center;
            padding: 1rem;
        }
        
        .stat-number {
            font-size: 2rem;
            font-weight: 700;
            color: var(--primary-color);
        }
        
        .stat-label {
            color: var(--text-color);
            font-size: 0.9rem;
        }
        
        .password-section {
            background: #f8f9fa;
            border-radius: 15px;
            padding: 1.5rem;
            margin-top: 2rem;
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
                            <i class="fas fa-home me-1"></i>Home
                        </a>
                    </li>
                    <li class="nav-item">
                        <a class="nav-link" href="doctors.php">
                            <i class="fas fa-user-md me-1"></i>Find Doctors
                        </a>
                    </li>
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
                </ul>
                
                <ul class="navbar-nav">
                    <li class="nav-item dropdown">
                        <a class="nav-link dropdown-toggle active" href="#" id="navbarDropdown" role="button" data-bs-toggle="dropdown">
                            <i class="fas fa-user-circle me-1"></i><?php echo htmlspecialchars($patient['name']); ?>
                        </a>
                        <ul class="dropdown-menu">
                            <li><a class="dropdown-item active" href="profile.php">
                                <i class="fas fa-user me-2"></i>My Profile
                            </a></li>
                            <li><hr class="dropdown-divider"></li>
                            <li><a class="dropdown-item" href="logout.php">
                                <i class="fas fa-sign-out-alt me-2"></i>Logout
                            </a></li>
                        </ul>
                    </li>
                </ul>
            </div>
        </div>
    </nav>

    <div class="container mt-4">
        <div class="row">
            <!-- Patient ID Card -->
            <div class="col-lg-4 mb-4">
                <div class="card hospital-card">
                    <div class="patient-id-card">
                        <div class="patient-avatar">
                            <i class="fas fa-user"></i>
                        </div>
                        <div class="patient-info">
                            <h3 class="mb-2"><?php echo htmlspecialchars($patient['name']); ?></h3>
                            <p class="mb-1"><?php echo htmlspecialchars($patient['email']); ?></p>
                            <?php if (!empty($patient['department_name'])): ?>
                                <p class="mb-1">
                                    <i class="fas fa-building me-1"></i><?php echo htmlspecialchars($patient['department_name']); ?>
                                </p>
                            <?php endif; ?>
                            <div class="patient-id">
                                <small>Patient ID: #<?php echo str_pad($patient['id'], 6, '0', STR_PAD_LEFT); ?></small>
                            </div>
                        </div>
                    </div>
                    
                    <div class="card-body p-0">
                        <div class="profile-stats">
                            <div class="row">
                                <div class="col-6 stat-item">
                                    <div class="stat-number">
                                        <?php echo is_null($computed_age) ? 'N/A' : (int)$computed_age; ?>
                                    </div>
                                    <div class="stat-label">Years Old</div>
                                </div>
                                <div class="col-6 stat-item">
                                    <div class="stat-number">
                                        <i class="fas fa-<?php echo strtolower($patient['gender']) === 'male' ? 'mars' : (strtolower($patient['gender']) === 'female' ? 'venus' : 'genderless'); ?>"></i>
                                    </div>
                                    <div class="stat-label"><?php echo htmlspecialchars($patient['gender']); ?></div>
                                </div>
                            </div>
                        </div>
                        
                        <div class="p-3">
                            <h6 class="mb-2" style="color: var(--primary-color);">Contact Information</h6>
                            <p class="mb-1">
                                <i class="fas fa-phone medical-icon"></i>
                                <?php echo htmlspecialchars($patient['phone']); ?>
                            </p>
                            <p class="mb-1">
                                <i class="fas fa-map-marker-alt medical-icon"></i>
                                <?php echo htmlspecialchars($patient['address']); ?>
                            </p>
                            <?php if (!empty($patient['allergy'])): ?>
                                <p class="mb-0">
                                    <i class="fas fa-notes-medical medical-icon"></i>
                                    <strong>Allergies:</strong> <?php echo nl2br(htmlspecialchars($patient['allergy'])); ?>
                                </p>
                            <?php endif; ?>
                        </div>
                    </div>
                </div>
            </div>

            <!-- Profile Update Form -->
            <div class="col-lg-8">
                <div class="card hospital-card">
                    <div class="card-body p-4">
                        <h4 class="card-title mb-4" style="color: var(--primary-color);">
                            <i class="fas fa-user-edit me-2"></i>Update Profile Information
                        </h4>

                        <?php if (!empty($errors)): ?>
                            <div class="alert d-inline-flex align-items-center alert-danger">
                                <i class="fas fa-exclamation-triangle"></i>
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

                        <form method="POST" action="">
                            <input type="hidden" name="csrf_token" value="<?php echo $csrf_token; ?>">
                            
                            <div class="row">
                                <div class="col-md-6 mb-3">
                                    <label for="name" class="form-label">
                                        <i class="fas fa-user medical-icon"></i>Full Name
                                    </label>
                                    <input type="text" class="form-control" id="name" name="name" 
                                           value="<?php echo htmlspecialchars($patient['name']); ?>" required>
                                </div>
                                
                                <div class="col-md-6 mb-3">
                                    <label for="email" class="form-label">
                                        <i class="fas fa-envelope medical-icon"></i>Email Address
                                    </label>
                                    <input type="email" class="form-control" id="email" name="email" 
                                           value="<?php echo htmlspecialchars($patient['email']); ?>" required>
                                </div>
                            </div>
                            
                            <div class="row">
                                <div class="col-md-4 mb-3">
                                    <label for="gender" class="form-label">
                                        <i class="fas fa-venus-mars medical-icon"></i>Gender
                                    </label>
                                    <select class="form-select" id="gender" name="gender" required>
        <?php foreach (getGenderOptions() as $option): ?>
                                        <option value="<?php echo $option; ?>" <?php echo ($patient['gender'] === $option) ? 'selected' : ''; ?>>
                                            <?php echo $option; ?>
                                        </option>
        <?php endforeach; ?>
                                    </select>
                                </div>
                                
                                <!-- NEW: Date of Birth (required) -->
                                <div class="col-md-4 mb-3">
                                    <label for="date_of_birth" class="form-label">
                                        <i class="fas fa-birthday-cake medical-icon"></i>Date of Birth
                                    </label>
                                    <input
                                        type="date"
                                        class="form-control"
                                        id="date_of_birth"
                                        name="date_of_birth"
                                        value="<?php echo htmlspecialchars($_POST['date_of_birth'] ?? ($patient['date_of_birth'] ?? '')); ?>"
                                        required
                                        max="<?php echo date('Y-m-d'); ?>"
                                        min="<?php echo date('Y-m-d', strtotime('-120 years')); ?>"
                                    >
                                </div>
                                
                                <div class="col-md-4 mb-3">
                                    <label for="phone" class="form-label">
                                        <i class="fas fa-phone medical-icon"></i>Phone Number
                                    </label>
                                    <input type="tel" class="form-control" id="phone" name="phone" 
                                           value="<?php echo htmlspecialchars($patient['phone']); ?>" required>
                                </div>
                            </div>

                            <!-- Department selector (optional) -->
                            <div class="mb-3">
                                <label for="department_id" class="form-label">
                                    <i class="fas fa-building medical-icon"></i>Department (Optional)
                                </label>
                                <select class="form-select" id="department_id" name="department_id">
                                    <option value="">-- Select Department --</option>
                                    <?php foreach ($departments as $dep): ?>
                                        <option value="<?php echo (int)$dep['id']; ?>"
                                            <?php
                                                $selectedDepId = isset($patient['department_id']) ? (int)$patient['department_id'] : null;
                                                echo (!is_null($selectedDepId) && $selectedDepId === (int)$dep['id']) ? 'selected' : '';
                                            ?>>
                                            <?php echo htmlspecialchars($dep['name']); ?>
                                        </option>
                                    <?php endforeach; ?>
                                </select>
                            </div>

                            <!-- Allergy (optional) -->
                            <div class="mb-4">
                                <label for="allergy" class="form-label">
                                    <i class="fas fa-notes-medical medical-icon"></i>Allergies (Optional)
                                </label>
                                <textarea class="form-control" id="allergy" name="allergy" rows="3" placeholder="e.g., Penicillin, Peanuts, Latex"><?php echo htmlspecialchars($patient['allergy'] ?? ''); ?></textarea>
                                <small class="text-muted">Provide any known drug/food/environmental allergies. This helps our staff ensure safe care.</small>
                            </div>
                            
                            <div class="mb-4">
                                <label for="address" class="form-label">
                                    <i class="fas fa-map-marker-alt medical-icon"></i>Address
                                </label>
                                <textarea class="form-control" id="address" name="address" rows="3" required><?php echo htmlspecialchars($patient['address']); ?></textarea>
                            </div>
                            
                            <!-- Password Change Section -->
                            <div class="password-section">
                                <h5 class="mb-3" style="color: var(--primary-color);">
                                    <i class="fas fa-lock me-2"></i>Change Password (Optional)
                                </h5>
                                
                                <div class="row">
                                    <div class="col-md-4 mb-3">
                                        <label for="current_password" class="form-label">Current Password</label>
                                        <input type="password" class="form-control" id="current_password" name="current_password">
                                    </div>
                                    
                                    <div class="col-md-4 mb-3">
                                        <label for="new_password" class="form-label">New Password</label>
                                        <input type="password" class="form-control" id="new_password" name="new_password">
                                    </div>
                                    
                                    <div class="col-md-4 mb-3">
                                        <label for="confirm_password" class="form-label">Confirm New Password</label>
                                        <input type="password" class="form-control" id="confirm_password" name="confirm_password">
                                    </div>
                                </div>
                                
                                <small class="text-muted">
                                    <i class="fas fa-info-circle me-1"></i>
                                    Leave password fields empty if you don't want to change your password.
                                </small>
                            </div>
                            
                            <div class="d-flex gap-3 mt-4">
                                <button type="submit" class="btn btn-primary">
                                    <i class="fas fa-save me-2"></i>Update Profile
                                </button>
                                <a href="dashboard.php" class="btn d-inline-flex align-items-center btn-secondary">
                                    <i class="fas fa-arrow-left me-2"></i>Back to Dashboard
                                </a>
                            </div>
                        </form>
                    </div>
                </div>
            </div>
        </div>
    </div>

    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js"></script>
</body>
</html>
