<?php
require_once '../config/config.php';

// Check if user is logged in as receptionist
if (!isset($_SESSION['receptionist_id']) || $_SESSION['user_type'] !== 'receptionist') {
    header('Location: ../login.php');
    exit();
}

$receptionist_id = $_SESSION['receptionist_id'];
$success_message = '';
$errors = [];

// Handle form submission
if ($_SERVER['REQUEST_METHOD'] == 'POST') {
    // Validate CSRF token
    if (!validateCSRFToken($_POST['csrf_token'] ?? '')) {
        $errors[] = 'Invalid security token. Please try again.';
    } else {
        // Sanitize input
        $name = sanitizeInput($_POST['name'] ?? '');
        $email = sanitizeInput($_POST['email'] ?? '');
        $phone = sanitizeInput($_POST['phone'] ?? '');
        $current_password = $_POST['current_password'] ?? '';
        $new_password = $_POST['new_password'] ?? '';
        $confirm_password = $_POST['confirm_password'] ?? '';
        
        // Validation
        if (empty($name)) {
            $errors[] = 'Name is required.';
        }
        
        if (empty($email) || !isValidEmail($email)) {
            $errors[] = 'Valid email address is required.';
        }
        
        if (empty($phone)) {
            $errors[] = 'Phone number is required.';
        }
        
        // Check if email is already taken by another receptionist
        if (empty($errors)) {
            try {
                $stmt = $pdo->prepare("SELECT id FROM receptionists WHERE email = ? AND id != ?");
                $stmt->execute([$email, $receptionist_id]);
                if ($stmt->fetch()) {
                    $errors[] = 'Email address is already in use.';
                }
            } catch (PDOException $e) {
                $errors[] = 'Database error occurred.';
            }
        }
        
        // Password validation if changing password
        if (!empty($new_password)) {
            if (empty($current_password)) {
                $errors[] = 'Current password is required to change password.';
            }
            
            if (strlen($new_password) < 6) {
                $errors[] = 'New password must be at least 6 characters long.';
            }
            
            if ($new_password !== $confirm_password) {
                $errors[] = 'New password and confirmation do not match.';
            }
            
            // Verify current password
            if (empty($errors)) {
                try {
                    $stmt = $pdo->prepare("SELECT password FROM receptionists WHERE id = ?");
                    $stmt->execute([$receptionist_id]);
                    $current_hash = $stmt->fetch()['password'];
                    
                    if (!verifyPassword($current_password, $current_hash)) {
                        $errors[] = 'Current password is incorrect.';
                    }
                } catch (PDOException $e) {
                    $errors[] = 'Database error occurred.';
                }
            }
        }
        
        // Update profile if no errors
        if (empty($errors)) {
            try {
                if (!empty($new_password)) {
                    // Update with new password
                    $hashed_password = hashPassword($new_password);
                    $stmt = $pdo->prepare("UPDATE receptionists SET name = ?, email = ?, phone = ?, password = ? WHERE id = ?");
                    $stmt->execute([$name, $email, $phone, $hashed_password, $receptionist_id]);
                } else {
                    // Update without password change
                    $stmt = $pdo->prepare("UPDATE receptionists SET name = ?, email = ?, phone = ? WHERE id = ?");
                    $stmt->execute([$name, $email, $phone, $receptionist_id]);
                }
                
                // Update session variables
                $_SESSION['receptionist_name'] = $name;
                $_SESSION['receptionist_email'] = $email;
                
                $success_message = 'Profile updated successfully!';
            } catch (PDOException $e) {
                $errors[] = 'Failed to update profile. Please try again.';
            }
        }
    }
}

// Get current receptionist data
try {
    $stmt = $pdo->prepare("SELECT name, email, phone, created_at FROM receptionists WHERE id = ?");
    $stmt->execute([$receptionist_id]);
    $receptionist = $stmt->fetch();
    
    if (!$receptionist) {
        header('Location: ../admin_logout.php');
        exit();
    }
} catch (PDOException $e) {
    $error_message = 'Failed to load profile data.';
}

$csrf_token = generateCSRFToken();
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Profile - <?php echo APP_NAME; ?></title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
    <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css" rel="stylesheet">
    <style>
        :root {
            --primary-color: #42A5F5; /* Sky Blue */
            --secondary-color: #81C784; /* Light Green */
            --accent-color: #FFB74D; /* Warm Orange */
            --background-color: #FAFAFA; /* Soft White */
            --text-color: #212121; /* Dark Gray */
        }
        
        body {
            background-color: var(--background-color);
            color: var(--text-color);
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
        }
        
        .navbar {
            background: linear-gradient(135deg, var(--primary-color), #1976D2) !important;
            box-shadow: 0 2px 10px rgba(0, 0, 0, 0.1);
        }
        
        .navbar-brand {
            font-weight: 700;
            font-size: 1.5rem;
            color: white !important;
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
        
        .profile-card {
            background: white;
            border-radius: 15px;
            box-shadow: 0 5px 20px rgba(0, 0, 0, 0.08);
            border: none;
            padding: 2rem;
        }
        
        .profile-header {
            background: linear-gradient(135deg, var(--primary-color), #1976D2);
            color: white;
            padding: 2rem;
            border-radius: 15px;
            text-align: center;
            margin-bottom: 2rem;
        }
        
        .profile-avatar {
            width: 100px;
            height: 100px;
            background: rgba(255, 255, 255, 0.2);
            border-radius: 50%;
            display: flex;
            align-items: center;
            justify-content: center;
            margin: 0 auto 1rem;
            font-size: 3rem;
        }
        
        .btn-primary {
            background-color: var(--primary-color);
            border-color: var(--primary-color);
            border-radius: 25px;
            padding: 12px 30px;
            font-weight: 600;
        }
        
        .btn-primary:hover {
            background-color: #1976D2;
            border-color: #1976D2;
        }
        
        .btn-secondary {
            background-color: var(--secondary-color);
            border-color: var(--secondary-color);
            border-radius: 25px;
            padding: 12px 30px;
            font-weight: 600;
            color: white;
        }
        
        .btn-secondary:hover {
            background-color: #66BB6A;
            border-color: #66BB6A;
            color: white;
        }
        
        .form-control {
            border-radius: 10px;
            border: 2px solid #e0e0e0;
            padding: 12px 15px;
        }
        
        .form-control:focus {
            border-color: var(--primary-color);
            box-shadow: 0 0 0 0.2rem rgba(66, 165, 245, 0.25);
        }
        
        .form-label {
            font-weight: 600;
            color: var(--text-color);
            margin-bottom: 8px;
        }
        
        .page-title {
            color: var(--primary-color);
            font-weight: 700;
            margin-bottom: 2rem;
        }
        
        .alert {
            border-radius: 10px;
            border: none;
        }
        
        .alert-success {
            background-color: #e8f5e9;
            color: #2e7d32;
        }
        
        .alert-danger {
            background-color: #ffebee;
            color: #c62828;
        }
        
        .info-item {
            display: flex;
            align-items: center;
            padding: 1rem 0;
            border-bottom: 1px solid #f0f0f0;
        }
        
        .info-item:last-child {
            border-bottom: none;
        }
        
        .info-icon {
            color: var(--primary-color);
            font-size: 1.2rem;
            margin-right: 15px;
            width: 25px;
        }
        
        .password-section {
            background: #f8f9fa;
            border-radius: 10px;
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
                            <i class="fas fa-tachometer-alt me-1"></i>Dashboard
                        </a>
                    </li>
                    <li class="nav-item">
                        <a class="nav-link" href="appointments.php">
                            <i class="fas fa-calendar-check me-1"></i>Appointments
                        </a>
                    </li>
                    <li class="nav-item">
                        <a class="nav-link active" href="profile.php">
                            <i class="fas fa-user me-1"></i>Profile
                        </a>
                    </li>
                </ul>
                
                <ul class="navbar-nav">
                    <li class="nav-item dropdown">
                        <a class="nav-link dropdown-toggle" href="#" id="navbarDropdown" role="button" data-bs-toggle="dropdown">
                            <i class="fas fa-user-circle me-1"></i><?php echo htmlspecialchars($_SESSION['receptionist_name']); ?>
                        </a>
                        <ul class="dropdown-menu">
                            <li><a class="dropdown-item" href="profile.php"><i class="fas fa-user me-2"></i>Profile</a></li>
                            <li><hr class="dropdown-divider"></li>
                            <li><a class="dropdown-item" href="../admin_logout.php"><i class="fas fa-sign-out-alt me-2"></i>Logout</a></li>
                        </ul>
                    </li>
                </ul>
            </div>
        </div>
    </nav>

    <div class="container mt-4">
        <!-- Profile Header -->
        <div class="profile-header">
            <div class="profile-avatar">
                <i class="fas fa-user-tie"></i>
            </div>
            <h2><?php echo htmlspecialchars($receptionist['name']); ?></h2>
            <p class="mb-0">Receptionist</p>
            <small>Member since <?php echo date('F Y', strtotime($receptionist['created_at'])); ?></small>
        </div>

        <div class="row">
            <!-- Profile Information -->
            <div class="col-md-6 mb-4">
                <div class="profile-card">
                    <h4 class="page-title"><i class="fas fa-info-circle me-2"></i>Profile Information</h4>
                    
                    <div class="info-item">
                        <i class="fas fa-user info-icon"></i>
                        <div>
                            <strong>Full Name</strong><br>
                            <span class="text-muted"><?php echo htmlspecialchars($receptionist['name']); ?></span>
                        </div>
                    </div>
                    
                    <div class="info-item">
                        <i class="fas fa-envelope info-icon"></i>
                        <div>
                            <strong>Email Address</strong><br>
                            <span class="text-muted"><?php echo htmlspecialchars($receptionist['email']); ?></span>
                        </div>
                    </div>
                    
                    <div class="info-item">
                        <i class="fas fa-phone info-icon"></i>
                        <div>
                            <strong>Phone Number</strong><br>
                            <span class="text-muted"><?php echo htmlspecialchars($receptionist['phone']); ?></span>
                        </div>
                    </div>
                    
                    <div class="info-item">
                        <i class="fas fa-calendar info-icon"></i>
                        <div>
                            <strong>Joined Date</strong><br>
                            <span class="text-muted"><?php echo date('F d, Y', strtotime($receptionist['created_at'])); ?></span>
                        </div>
                    </div>
                </div>
            </div>

            <!-- Update Profile Form -->
            <div class="col-md-6 mb-4">
                <div class="profile-card">
                    <h4 class="page-title"><i class="fas fa-edit me-2"></i>Update Profile</h4>
                    
                    <?php if ($success_message): ?>
                        <div class="alert alert-success">
                            <i class="fas fa-check-circle me-2"></i><?php echo $success_message; ?>
                        </div>
                    <?php endif; ?>
                    
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
                    
                    <form method="POST" action="">
                        <input type="hidden" name="csrf_token" value="<?php echo $csrf_token; ?>">
                        
                        <div class="mb-3">
                            <label for="name" class="form-label">
                                <i class="fas fa-user me-1"></i>Full Name
                            </label>
                            <input type="text" class="form-control" id="name" name="name" 
                                   value="<?php echo htmlspecialchars($receptionist['name']); ?>" required>
                        </div>
                        
                        <div class="mb-3">
                            <label for="email" class="form-label">
                                <i class="fas fa-envelope me-1"></i>Email Address
                            </label>
                            <input type="email" class="form-control" id="email" name="email" 
                                   value="<?php echo htmlspecialchars($receptionist['email']); ?>" required>
                        </div>
                        
                        <div class="mb-3">
                            <label for="phone" class="form-label">
                                <i class="fas fa-phone me-1"></i>Phone Number
                            </label>
                            <input type="tel" class="form-control" id="phone" name="phone" 
                                   value="<?php echo htmlspecialchars($receptionist['phone']); ?>" required>
                        </div>
                        
                        <!-- Password Change Section -->
                        <div class="password-section">
                            <h6 class="mb-3"><i class="fas fa-lock me-2"></i>Change Password (Optional)</h6>
                            
                            <div class="mb-3">
                                <label for="current_password" class="form-label">Current Password</label>
                                <input type="password" class="form-control" id="current_password" name="current_password">
                            </div>
                            
                            <div class="mb-3">
                                <label for="new_password" class="form-label">New Password</label>
                                <input type="password" class="form-control" id="new_password" name="new_password">
                                <small class="form-text text-muted">Leave blank to keep current password</small>
                            </div>
                            
                            <div class="mb-3">
                                <label for="confirm_password" class="form-label">Confirm New Password</label>
                                <input type="password" class="form-control" id="confirm_password" name="confirm_password">
                            </div>
                        </div>
                        
                        <div class="d-grid gap-2 d-md-flex justify-content-md-end mt-4">
                            <a href="dashboard.php" class="btn d-inline-flex align-items-center btn-secondary me-md-2">
                                <i class="fas fa-arrow-left me-1"></i>Back to Dashboard
                            </a>
                            <button type="submit" class="btn btn-primary">
                                <i class="fas fa-save me-1"></i>Update Profile
                            </button>
                        </div>
                    </form>
                </div>
            </div>
        </div>
    </div>

    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js"></script>
</body>
</html>