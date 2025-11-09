<?php
require_once 'config/config.php';

// Redirect if already logged in
redirectIfLoggedIn();

$errors = [];
$email = '';

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    // Validate CSRF token
    if (!validateCSRFToken($_POST['csrf_token'] ?? '')) {
        $errors[] = 'Invalid security token. Please try again.';
    } else {
        // Sanitize & normalize input
        $email = sanitizeInput($_POST['email'] ?? '');
        $email = strtolower(trim($email));
        $password = $_POST['password'] ?? '';

        // Validation
        if (empty($email) || !isValidEmail($email)) {
            $errors[] = 'Valid email address is required.';
        }
        if (empty($password)) {
            $errors[] = 'Password is required.';
        }

        // Authenticate
        if (empty($errors)) {
            try {
                // Always fetch as associative arrays
                $fetchMode = PDO::FETCH_ASSOC;

                // 1) patients
                $stmt = $pdo->prepare("
                    SELECT id, name, email, password, 'patient' AS user_type
                    FROM patients
                    WHERE LOWER(email) = ?
                    LIMIT 1
                ");
                $stmt->execute([$email]);
                $user = $stmt->fetch($fetchMode);

                // 2) doctors
                if (!$user) {
                    $stmt = $pdo->prepare("
                        SELECT id, name, email, password, 'doctor' AS user_type
                        FROM doctors
                        WHERE LOWER(email) = ?
                        LIMIT 1
                    ");
                    $stmt->execute([$email]);
                    $user = $stmt->fetch($fetchMode);
                }

                // 3) receptionists
                if (!$user) {
                    $stmt = $pdo->prepare("
                        SELECT id, name, email, password, 'receptionist' AS user_type
                        FROM receptionists
                        WHERE LOWER(email) = ?
                        LIMIT 1
                    ");
                    $stmt->execute([$email]);
                    $user = $stmt->fetch($fetchMode);
                }

                // 4) admins (must be active)
                if (!$user) {
                    $stmt = $pdo->prepare("
                        SELECT id, name, email, password, role, 'admin' AS user_type
                        FROM admins
                        WHERE LOWER(email) = ?
                          AND LOWER(status) = 'active'
                        LIMIT 1
                    ");
                    $stmt->execute([$email]);
                    $user = $stmt->fetch($fetchMode);
                }

                // Verify password using PHP's password_verify
                if ($user && password_verify($password, $user['password'])) {
                    // Regenerate session ID on successful login
                    session_regenerate_id(true);

                    $redirect_url = $_GET['redirect'] ?? 'dashboard.php';

                    switch ($user['user_type']) {
                        case 'patient':
                            // If you already have a helper, keep using it:
                            // loginPatient($user);
                            // If not, set session fields here:
                            loginPatient($user);
                            // Patients default:
                            $redirect_url = $_GET['redirect'] ?? 'dashboard.php';
                            break;

                        case 'doctor':
                            $_SESSION['doctor_id'] = $user['id'];
                            $_SESSION['doctor_name'] = $user['name'];
                            $_SESSION['doctor_email'] = $user['email'];
                            $_SESSION['user_type'] = 'doctor';
                            $redirect_url = $_GET['redirect'] ?? 'doctor/dashboard.php';
                            break;

                        case 'receptionist':
                            $_SESSION['receptionist_id'] = $user['id'];
                            $_SESSION['receptionist_name'] = $user['name'];
                            $_SESSION['receptionist_email'] = $user['email'];
                            $_SESSION['user_type'] = 'receptionist';
                            $redirect_url = $_GET['redirect'] ?? 'receptionist/dashboard.php';
                            break;

                        case 'admin':
                            $_SESSION['admin_id'] = $user['id'];
                            $_SESSION['admin_name'] = $user['name'];
                            $_SESSION['admin_email'] = $user['email'];
                            $_SESSION['admin_role'] = $user['role'] ?? null;
                            $_SESSION['user_type'] = 'admin';
                            $redirect_url = $_GET['redirect'] ?? 'admin/dashboard.php';
                            break;
                    }

                    header('Location: ' . $redirect_url);
                    exit();
                } else {
                    $errors[] = 'Invalid email or password.';
                }
            } catch (PDOException $e) {
                // Temporary: log exact DB error for debugging
                error_log('LOGIN PDO ERROR: ' . $e->getMessage());
                $errors[] = 'Login failed. Please try again.';
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
    <title>Patient Login - <?php echo APP_NAME; ?></title>
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
            background: linear-gradient(135deg, var(--background-color), #e8f5e8);
            color: var(--text-color);
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            min-height: 100vh;
            display: flex;
            align-items: center;
        }
        .hospital-card {
            background: white;
            border-radius: 20px;
            box-shadow: 0 15px 35px rgba(0, 0, 0, 0.1);
            border: none;
            overflow: hidden;
        }
        .login-header {
            background: linear-gradient(135deg, var(--primary-color), #00796b);
            color: white;
            padding: 3rem 2rem;
            text-align: center;
        }
        .hospital-logo { font-size: 4rem; margin-bottom: 1rem; opacity: 0.9; }
        .btn-primary {
            background-color: var(--primary-color);
            border-color: var(--primary-color);
            border-radius: 25px;
            padding: 12px 30px;
            font-weight: 600;
            width: 100%;
        }
        .btn-primary:hover {
            background-color: #00796b;
            border-color: #00796b;
            transform: translateY(-2px);
            transition: all 0.3s ease;
        }
        .btn-secondary {
            background-color: var(--secondary-color);
            border-color: var(--secondary-color);
            border-radius: 25px;
            color: white;
        }
        .form-control {
            border-radius: 15px;
            border: 2px solid #e0e0e0;
            padding: 15px 20px;
            font-size: 1rem;
        }
        .form-control:focus {
            border-color: var(--primary-color);
            box-shadow: 0 0 0 0.2rem rgba(0, 150, 136, 0.25);
        }
        .form-label { font-weight: 600; color: var(--text-color); margin-bottom: 10px; }
        .medical-icon { color: var(--primary-color); font-size: 1.2rem; margin-right: 10px; }
        .alert { border-radius: 15px; border: none; }
        .alert-danger { background-color: #ffebee; color: #c62828; }
        .login-form { padding: 3rem 2rem; }
        .welcome-text { color: var(--primary-color); font-weight: 600; margin-bottom: 2rem; }
        .hospital-features {
            background: rgba(0, 150, 136, 0.05);
            border-radius: 15px;
            padding: 1.5rem; margin-top: 2rem;
        }
        .feature-item { display: flex; align-items: center; margin-bottom: 1rem; }
        .feature-item:last-child { margin-bottom: 0; }
        .feature-icon { color: var(--primary-color); font-size: 1.5rem; margin-right: 15px; width: 30px; text-align: center; }
    </style>
</head>
<body>
<div class="container">
    <div class="row justify-content-center">
        <div class="col-lg-10 col-xl-8">
            <div class="card hospital-card">
                <div class="row g-0">
                    <!-- Left side - Hospital branding -->
                    <div class="col-md-6">
                        <div class="login-header h-100 d-flex flex-column justify-content-center">
                            <div class="hospital-logo">
                                <i class="fas fa-hospital-alt"></i>
                            </div>
                            <h2 class="mb-3"><?php echo APP_NAME; ?></h2>
                            <p class="mb-4 opacity-75">Your Health, Our Priority</p>
                            <div class="hospital-features">
                                <div class="feature-item">
                                    <i class="fas fa-user-md feature-icon"></i>
                                    <span>Expert Medical Care</span>
                                </div>
                                <div class="feature-item">
                                    <i class="fas fa-calendar-check feature-icon"></i>
                                    <span>Easy Appointment Booking</span>
                                </div>
                                <div class="feature-item">
                                    <i class="fas fa-history feature-icon"></i>
                                    <span>Medical History Access</span>
                                </div>
                                <div class="feature-item">
                                    <i class="fas fa-shield-alt feature-icon"></i>
                                    <span>Secure & Confidential</span>
                                </div>
                            </div>
                        </div>
                    </div>

                    <!-- Right side - Login form -->
                    <div class="col-md-6">
                        <div class="login-form">
                            <div class="text-center mb-4">
                                <i class="fas fa-sign-in-alt medical-icon" style="font-size: 3rem;"></i>
                                <h3 class="welcome-text">Welcome Back</h3>
                                <p class="text-muted">Sign in to access your application portal</p>
                            </div>

                            <?php if (!empty($errors)): ?>
                                <div class="alert d-flex align-items-center alert-danger">
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
                                <div class="mb-4">
                                    <label for="email" class="form-label">
                                        <i class="fas fa-envelope medical-icon"></i>Email Address
                                    </label>
                                    <input type="email" class="form-control" id="email" name="email"
                                           value="<?php echo htmlspecialchars($email); ?>"
                                           placeholder="Enter your email" required>
                                </div>

                                <div class="mb-4">
                                    <label for="password" class="form-label">
                                        <i class="fas fa-lock medical-icon"></i>Password
                                    </label>
                                    <input type="password" class="form-control" id="password" name="password"
                                           placeholder="Enter your password" required>
                                </div>

                                <div class="d-grid gap-2 mb-4">
                                    <button type="submit" class="btn btn-primary btn-lg">
                                        <i class="fas fa-sign-in-alt me-2"></i>Sign In
                                    </button>
                                </div>
                            </form>

                            <div class="text-center">
                                <p class="text-muted mb-3">Don't have an account?</p>
                                <a href="register.php" class="btn btn-secondary">
                                    <i class="fas fa-user-plus me-2"></i>Register as New Patient
                                </a>
                            </div>
                        </div>
                    </div>
                </div> <!-- /row -->
            </div> <!-- /card -->
        </div>
    </div>
</div>

<script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js"></script>
</body>
</html>
