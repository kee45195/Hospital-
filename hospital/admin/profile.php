<?php
require_once '../config/config.php';

// Require admin login
if (!isset($_SESSION['admin_id']) || $_SESSION['user_type'] !== 'admin') {
    header('Location: ../login.php?redirect=' . urlencode($_SERVER['REQUEST_URI']));
    exit();
}

$admin_id = $_SESSION['admin_id'];
$success_message = '';
$error_message = '';

// Handle profile update
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['update_profile'])) {
    $name = trim($_POST['name']);
    $email = trim($_POST['email']);
    $phone = trim($_POST['phone']);
    $current_password = $_POST['current_password'];
    $new_password = $_POST['new_password'];
    $confirm_password = $_POST['confirm_password'];
    
    // Validation
    if (empty($name) || empty($email) || empty($phone)) {
        $error_message = 'Name, email, and phone are required.';
    } elseif (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
        $error_message = 'Please enter a valid email address.';
    } elseif (!empty($new_password) && $new_password !== $confirm_password) {
        $error_message = 'New passwords do not match.';
    } elseif (!empty($new_password) && strlen($new_password) < 6) {
        $error_message = 'New password must be at least 6 characters long.';
    } else {
        try {
            // Get current admin data
            $stmt = $pdo->prepare("SELECT * FROM admins WHERE id = ?");
            $stmt->execute([$admin_id]);
            $admin = $stmt->fetch();
            
            if (!$admin) {
                $error_message = 'Admin not found.';
            } else {
                // If changing password, verify current password
                if (!empty($new_password)) {
                    if (empty($current_password)) {
                        $error_message = 'Current password is required to change password.';
                    } elseif (!password_verify($current_password, $admin['password'])) {
                        $error_message = 'Current password is incorrect.';
                    }
                }
                
                if (empty($error_message)) {
                    // Check if email is already taken by another admin
                    $stmt = $pdo->prepare("SELECT id FROM admins WHERE email = ? AND id != ?");
                    $stmt->execute([$email, $admin_id]);
                    if ($stmt->fetch()) {
                        $error_message = 'Email is already taken by another admin.';
                    } else {
                        // Update profile
                        if (!empty($new_password)) {
                            $hashed_password = password_hash($new_password, PASSWORD_DEFAULT);
                            $stmt = $pdo->prepare("UPDATE admins SET name = ?, email = ?, phone = ?, password = ? WHERE id = ?");
                            $stmt->execute([$name, $email, $phone, $hashed_password, $admin_id]);
                        } else {
                            $stmt = $pdo->prepare("UPDATE admins SET name = ?, email = ?, phone = ? WHERE id = ?");
                            $stmt->execute([$name, $email, $phone, $admin_id]);
                        }
                        
                        // Update session
                        $_SESSION['admin_name'] = $name;
                        
                        $success_message = 'Profile updated successfully!';
                    }
                }
            }
        } catch (PDOException $e) {
            $error_message = 'Database error: ' . $e->getMessage();
        }
    }
}

// Get current admin data
try {
    $stmt = $pdo->prepare("SELECT * FROM admins WHERE id = ?");
    $stmt->execute([$admin_id]);
    $admin = $stmt->fetch();
    
    if (!$admin) {
        header('Location: ../logout.php');
        exit();
    }
} catch (PDOException $e) {
    $error_message = 'Error loading profile data.';
    $admin = [];
}
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Admin Profile - <?php echo APP_NAME; ?></title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
    <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css" rel="stylesheet">
    <style>
        :root {
            --primary-color: #2563EB;
            --secondary-color: #334155;
            --accent-color: #7C3AED;
            --background-color: #F9FAFB;
            --text-color: #111827;
        }
        
        body {
            background-color: var(--background-color);
            color: var(--text-color);
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
        }
        
        .sidebar {
            background-color: var(--secondary-color);
            min-height: 100vh;
            width: 250px;
            position: fixed;
            top: 0;
            left: 0;
            z-index: 1000;
            transition: all 0.3s;
        }
        
        .sidebar .nav-link {
            color: white;
            padding: 12px 20px;
            border-radius: 0;
            transition: all 0.3s;
        }
        
        .sidebar .nav-link:hover {
            background-color: var(--primary-color);
            color: white;
        }
        
        .sidebar .nav-link.active {
            background-color: var(--primary-color);
            color: white;
        }
        
        .sidebar .nav-link i {
            width: 20px;
            margin-right: 10px;
        }
        
        .main-content {
            margin-left: 250px;
            padding: 0;
        }
        
        .top-navbar {
            background-color: var(--primary-color);
            color: white;
            padding: 15px 30px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }
        
        .content-area {
            padding: 30px;
        }
        
        .profile-card {
            background: white;
            border-radius: 15px;
            padding: 30px;
            box-shadow: 0 4px 6px rgba(0, 0, 0, 0.05);
            border: none;
        }
        
        .profile-header {
            text-align: center;
            margin-bottom: 30px;
            padding-bottom: 20px;
            border-bottom: 1px solid #E5E7EB;
        }
        
        .profile-avatar {
            width: 120px;
            height: 120px;
            background: linear-gradient(135deg, var(--primary-color), var(--accent-color));
            border-radius: 50%;
            display: flex;
            align-items: center;
            justify-content: center;
            margin: 0 auto 20px;
            font-size: 3rem;
            color: white;
        }
        
        .btn-primary {
            background-color: var(--primary-color);
            border-color: var(--primary-color);
        }
        
        .btn-primary:hover {
            background-color: #1D4ED8;
            border-color: #1D4ED8;
        }
        
        .btn-accent {
            background-color: var(--accent-color);
            border-color: var(--accent-color);
            color: white;
        }
        
        .btn-accent:hover {
            background-color: #6D28D9;
            border-color: #6D28D9;
            color: white;
        }
        
        .logo {
            padding: 20px;
            text-align: center;
            border-bottom: 1px solid #475569;
            margin-bottom: 20px;
        }
        
        .logo h4 {
            color: white;
            margin: 0;
        }
        
        .form-control:focus {
            border-color: var(--primary-color);
            box-shadow: 0 0 0 0.2rem rgba(37, 99, 235, 0.25);
        }
        
        .password-section {
            background-color: #F8FAFC;
            border-radius: 10px;
            padding: 20px;
            margin-top: 20px;
        }
    </style>
</head>
<body>
    <!-- Sidebar -->
    <div class="sidebar">
        <div class="logo">
            <h4><i class="fas fa-hospital-alt me-2"></i><?php echo APP_NAME; ?></h4>
        </div>
        
        <nav class="nav flex-column">
            <a class="nav-link" href="dashboard.php">
                <i class="fas fa-tachometer-alt"></i>Dashboard
            </a>
            <a class="nav-link active" href="profile.php">
                <i class="fas fa-user"></i>Profile
            </a>
            <a class="nav-link" href="users.php">
                <i class="fas fa-users"></i>User Accounts
            </a>
            <a class="nav-link" href="reports.php">
                <i class="fas fa-chart-bar"></i>Reports
            </a>
             <a class="nav-link" href="departments.php"><i class="fas fa-building"></i>Departments</a>
              <a class="nav-link" href="specializations.php"><i class="fas fa-building"></i>Specializations</a>
            <a class="nav-link" href="content.php">
                <i class="fas fa-edit"></i>Content Management
            </a>
           <a class="nav-link" href="../admin_logout.php">
                <i class="fas fa-sign-out-alt"></i>Logout
            </a>
        </nav>
    </div>
    
    <!-- Main Content -->
    <div class="main-content">
        <!-- Top Navbar -->
        <div class="top-navbar d-flex justify-content-between align-items-center">
            <div>
                <h3 class="mb-0"><i class="fas fa-user me-2"></i>Admin Profile</h3>
            </div>
            <div>
                <span class="me-3">Welcome, <?php echo htmlspecialchars($admin['name'] ?? ''); ?></span>
                <span class="badge bg-light text-dark"><?php echo ucfirst($admin['role'] ?? ''); ?></span>
            </div>
        </div>
        
        <!-- Content Area -->
        <div class="content-area">
            <div class="row justify-content-center">
                <div class="col-lg-8">
                    <div class="profile-card">
                        <!-- Profile Header -->
                        <div class="profile-header">
                            <div class="profile-avatar">
                                <i class="fas fa-user-shield"></i>
                            </div>
                            <h4><?php echo htmlspecialchars($admin['name'] ?? ''); ?></h4>
                            <p class="text-muted mb-0"><?php echo ucfirst($admin['role'] ?? ''); ?> Administrator</p>
                            <small class="text-muted">Member since <?php echo date('F Y', strtotime($admin['created_at'] ?? 'now')); ?></small>
                        </div>
                        
                        <!-- Success/Error Messages -->
                        <?php if ($success_message): ?>
                            <div class="alert alert-success alert-dismissible fade show" role="alert">
                                <i class="fas fa-check-circle me-2"></i><?php echo $success_message; ?>
                                <button type="button" class="btn-close" data-bs-dismiss="alert"></button>
                            </div>
                        <?php endif; ?>
                        
                        <?php if ($error_message): ?>
                            <div class="alert alert-danger alert-dismissible fade show" role="alert">
                                <i class="fas fa-exclamation-circle me-2"></i><?php echo $error_message; ?>
                                <button type="button" class="btn-close" data-bs-dismiss="alert"></button>
                            </div>
                        <?php endif; ?>
                        
                        <!-- Profile Form -->
                        <form method="POST" action="">
                            <div class="row">
                                <div class="col-md-6 mb-3">
                                    <label for="name" class="form-label">Full Name *</label>
                                    <input type="text" class="form-control" id="name" name="name" 
                                           value="<?php echo htmlspecialchars($admin['name'] ?? ''); ?>" required>
                                </div>
                                
                                <div class="col-md-6 mb-3">
                                    <label for="email" class="form-label">Email Address *</label>
                                    <input type="email" class="form-control" id="email" name="email" 
                                           value="<?php echo htmlspecialchars($admin['email'] ?? ''); ?>" required>
                                </div>
                            </div>
                            
                            <div class="row">
                                <div class="col-md-6 mb-3">
                                    <label for="phone" class="form-label">Phone Number *</label>
                                    <input type="tel" class="form-control" id="phone" name="phone" 
                                           value="<?php echo htmlspecialchars($admin['phone'] ?? ''); ?>" required>
                                </div>
                                
                                <div class="col-md-6 mb-3">
                                    <label for="role" class="form-label">Role</label>
                                    <input type="text" class="form-control" id="role" 
                                           value="<?php echo ucfirst($admin['role'] ?? ''); ?>" readonly>
                                </div>
                            </div>
                            
                            <!-- Password Change Section -->
                            <div class="password-section">
                                <h6 class="mb-3"><i class="fas fa-lock me-2"></i>Change Password (Optional)</h6>
                                <p class="text-muted small mb-3">Leave password fields empty if you don't want to change your password.</p>
                                
                                <div class="row">
                                    <div class="col-md-4 mb-3">
                                        <label for="current_password" class="form-label">Current Password</label>
                                        <input type="password" class="form-control" id="current_password" name="current_password">
                                    </div>
                                    
                                    <div class="col-md-4 mb-3">
                                        <label for="new_password" class="form-label">New Password</label>
                                        <input type="password" class="form-control" id="new_password" name="new_password" 
                                               minlength="6">
                                    </div>
                                    
                                    <div class="col-md-4 mb-3">
                                        <label for="confirm_password" class="form-label">Confirm New Password</label>
                                        <input type="password" class="form-control" id="confirm_password" name="confirm_password" 
                                               minlength="6">
                                    </div>
                                </div>
                            </div>
                            
                            <div class="text-center mt-4">
                                <button type="submit" name="update_profile" class="btn btn-primary btn-lg px-5">
                                    <i class="fas fa-save me-2"></i>Update Profile
                                </button>
                                <a href="dashboard.php" class="btn d-inline-flex align-items-center btn-outline-secondary btn-lg px-5 ms-3">
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
        
        // Require current password if new password is entered
        document.getElementById('new_password').addEventListener('input', function() {
            const currentPassword = document.getElementById('current_password');
            if (this.value) {
                currentPassword.required = true;
            } else {
                currentPassword.required = false;
            }
        });
    </script>
</body>
</html>