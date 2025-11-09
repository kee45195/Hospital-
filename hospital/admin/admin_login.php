<?php
require_once '../config/config.php';


// Redirect if already logged in (your helper from the second snippet)
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

        // Authenticate across roles
        if (empty($errors)) {
            try {
                $fetchMode = PDO::FETCH_ASSOC;
                $user = null;

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

                // 4) admins (active only)
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

                // Verify password
                if ($user && password_verify($password, $user['password'])) {
                    session_regenerate_id(true);

                    // Default redirect allows ?redirect=/foo
                    $redirect_url = $_GET['redirect'] ?? '/hospital/dashboard.php';

                    switch ($user['user_type']) {
                        case 'patient':
                            // If you already have a helper, keep using it:
                            loginPatient($user);
                            $redirect_url = $_GET['redirect'] ?? '/hospital/dashboard.php';
                            break;

                        case 'doctor':
                            $_SESSION['doctor_id']   = $user['id'];
                            $_SESSION['doctor_name'] = $user['name'];
                            $_SESSION['doctor_email']= $user['email'];
                            $_SESSION['user_type']   = 'doctor';
                            $redirect_url = $_GET['redirect'] ?? '/hospital/doctor/dashboard.php';
                            break;

                        case 'receptionist':
                            $_SESSION['receptionist_id']    = $user['id'];
                            $_SESSION['receptionist_name']  = $user['name'];
                            $_SESSION['receptionist_email'] = $user['email'];
                            $_SESSION['user_type']          = 'receptionist';
                            $redirect_url = $_GET['redirect'] ?? '/hospital/receptionist/dashboard.php';
                            break;

                        case 'admin':
                            $_SESSION['admin_id']    = $user['id'];
                            $_SESSION['admin_name']  = $user['name'];
                            $_SESSION['admin_email'] = $user['email'];
                            $_SESSION['admin_role']  = $user['role'] ?? null;
                            $_SESSION['user_type']   = 'admin';
                            $redirect_url = $_GET['redirect'] ?? '/hospital/admin/dashboard.php';
                            break;
                    }

                    header('Location: ' . $redirect_url);
                    exit();
                } else {
                    $errors[] = 'Invalid email or password.';
                }
            } catch (PDOException $e) {
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
    <title>Login - <?php echo APP_NAME; ?></title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
    <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css" rel="stylesheet">
    <style>
        :root {
            /* Use the palette from your "above UI" */
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
            min-height: 100vh;
        }

        .hero-section {
            background: linear-gradient(135deg, var(--primary-color) 0%, var(--accent-color) 100%);
            min-height: 100vh;
            display: flex;
            align-items: center;
        }

        .login-card {
            background: white;
            border-radius: 15px;
            box-shadow: 0 10px 30px rgba(0, 0, 0, 0.1);
            overflow: hidden;
            max-width: 450px;
            margin: 0 auto;
        }

        .login-header {
            background: var(--primary-color);
            color: white;
            padding: 2rem;
            text-align: center;
        }

        .login-header h2 {
            margin: 0;
            font-weight: 600;
        }

        .login-body {
            padding: 2rem;
        }

        .form-control:focus {
            border-color: var(--primary-color);
            box-shadow: 0 0 0 0.2rem rgba(0, 131, 143, 0.25);
        }

        .btn-primary {
            background-color: var(--primary-color);
            border-color: var(--primary-color);
            padding: 12px 30px;
            font-weight: 600;
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

        .btn-secondary:hover {
            background-color: #81C784;
            border-color: #81C784;
            color: var(--text-color);
        }

        .alert-danger {
            background-color: #FFEBEE;
            border-color: #FFCDD2;
            color: #C62828;
        }

        .hero-content {
            color: white;
            text-align: center;
        }

        .hero-content h1 {
            font-size: 3rem;
            font-weight: 700;
            margin-bottom: 1rem;
        }

        .hero-content p {
            font-size: 1.2rem;
            opacity: 0.9;
        }

        .medical-icon {
            font-size: 4rem;
            margin-bottom: 1rem;
            opacity: 0.8;
        }

        .feature-list {
            list-style: none;
            padding: 0;
        }

        .feature-list li {
            padding: 0.35rem 0.75rem;
            font-size: 1.1rem;
            display: inline-flex;
            align-items: center;
            gap: .5rem;
            margin: .25rem .5rem;
            border-radius: 999px;
            background: rgba(255,255,255,.12);
            color:#fff;
        }

        .feature-list i {
            color: var(--secondary-color);
            margin-right: 0.5rem;
        }
    </style>
</head>
<body>
<div class="hero-section">
    <div class="container">
        <div class="row align-items-center">
            <!-- Left: hero copy (kept from your UI) -->
            <div class="col-lg-6">
                <div class="hero-content">
                    <div class="medical-icon">
                        <i class="fas fa-user-shield"></i>
                    </div>
                    <h1>Portal Login</h1>
                    <p>Access patient, doctor, receptionist, or admin dashboards from one secure place.</p>

                    <ul class="feature-list mt-4">
                        <li><i class="fas fa-user-md"></i> Doctors</li>
                        <li><i class="fas fa-building"></i> Departments</li>
                        <li><i class="fas fa-notes-medical me-1"></i> Packages</li>
                        <li><i class="fas fa-calendar-check"></i> Appointments</li>
                        <li><i class="fas fa-newspaper"></i> CMS</li>
                        <li><i class="fas fa-user-shield"></i> Users</li>
                    </ul>
                </div>
            </div>

            <!-- Right: login card (same look as your UI, wired to multi-role logic) -->
            <div class="col-lg-6">
                <div class="login-card">
                    <div class="login-header">
                        <h2><i class="fas fa-sign-in-alt me-2"></i>Sign In</h2>
                    </div>
                    <div class="login-body">
                        <?php if (!empty($errors)): ?>
                            <div class="alert alert-danger">
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
                                <label for="email" class="form-label">
                                    <i class="fas fa-envelope me-2"></i>Email Address
                                </label>
                                <input
                                    type="email"
                                    class="form-control"
                                    id="email"
                                    name="email"
                                    value="<?php echo htmlspecialchars($email); ?>"
                                    placeholder="Enter your email"
                                    required
                                >
                            </div>

                            <div class="mb-3">
                                <label for="password" class="form-label">
                                    <i class="fas fa-lock me-2"></i>Password
                                </label>
                                <input
                                    type="password"
                                    class="form-control"
                                    id="password"
                                    name="password"
                                    placeholder="Enter your password"
                                    required
                                >
                            </div>

                            <div class="d-grid gap-2">
                                <button type="submit" class="btn btn-primary">
                                    <i class="fas fa-sign-in-alt me-2"></i>Login to Dashboard
                                </button>
                            </div>
                        </form>

                        <!-- <div class="text-center mt-3">
                            <p class="text-muted mb-3">New here?</p>
                            <a href="register.php" class="btn btn-secondary">
                                <i class="fas fa-user-plus me-2"></i>Register as New Patient
                            </a>
                        </div> -->
                    </div>
                </div>
            </div>
            <!-- /Right -->
        </div>
    </div>
</div>

<script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js"></script>
</body>
</html>
