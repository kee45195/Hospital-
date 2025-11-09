<?php
require_once '../config/config.php';

// Redirect if already logged in as doctor
if (isset($_SESSION['doctor_id'])) {
    header('Location: dashboard.php');
    exit();
}

$errors = [];
$success_message = '';

if ($_SERVER['REQUEST_METHOD'] == 'POST') {
    // Validate CSRF token
    if (!validateCSRFToken($_POST['csrf_token'] ?? '')) {
        $errors[] = 'Invalid security token. Please try again.';
    } else {
        $email = sanitizeInput($_POST['email'] ?? '');
        $password = $_POST['password'] ?? '';
        $remember_me = isset($_POST['remember_me']);
        
        // Validation
        if (empty($email)) {
            $errors[] = 'Email is required.';
        } elseif (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
            $errors[] = 'Please enter a valid email address.';
        }
        
        if (empty($password)) {
            $errors[] = 'Password is required.';
        }
        
        // Authenticate doctor
        if (empty($errors)) {
            try {
                $stmt = $pdo->prepare("SELECT id, name, email, password, specialization FROM doctors WHERE email = ?");
                $stmt->execute([$email]);
                $doctor = $stmt->fetch();
                
                if ($doctor && password_verify($password, $doctor['password'])) {
                    // Set doctor session
                    $_SESSION['doctor_id'] = $doctor['id'];
                    $_SESSION['doctor_name'] = $doctor['name'];
                    $_SESSION['doctor_email'] = $doctor['email'];
                    $_SESSION['doctor_specialization'] = $doctor['specialization'];
                    $_SESSION['user_type'] = 'doctor';
                    
                    // Set remember me cookie if requested
                    if ($remember_me) {
                        $token = bin2hex(random_bytes(32));
                        setcookie('doctor_remember_token', $token, time() + (86400 * 30), '/', '', true, true); // 30 days
                        
                        // Store token in database (you might want to create a remember_tokens table)
                        // For now, we'll skip this implementation
                    }
                    
                    // Redirect to dashboard
                    header('Location: dashboard.php');
                    exit();
                } else {
                    $errors[] = 'Invalid email or password.';
                }
            } catch (PDOException $e) {
                $errors[] = 'Database error. Please try again.';
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
    <title>Doctor Login - <?php echo APP_NAME; ?></title>
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
        
        .form-check-input:checked {
            background-color: var(--primary-color);
            border-color: var(--primary-color);
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
            padding: 0.5rem 0;
            font-size: 1.1rem;
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
                <div class="col-lg-6">
                    <div class="hero-content">
                        <div class="medical-icon">
                            <i class="fas fa-stethoscope"></i>
                        </div>
                        <h1>Doctor Portal</h1>
                        <p>Access your professional dashboard to manage appointments, patient records, and medical consultations.</p>
                        
                        <ul class="feature-list mt-4">
                            <li><i class="fas fa-calendar-check"></i> Manage Appointments</li>
                            <li><i class="fas fa-user-injured"></i> Patient Records</li>
                            <li><i class="fas fa-prescription-bottle-alt"></i> Medical History</li>
                            <li><i class="fas fa-star"></i> Patient Feedback</li>
                        </ul>
                    </div>
                </div>
                <div class="col-lg-6">
                    <div class="login-card">
                        <div class="login-header">
                            <h2><i class="fas fa-sign-in-alt me-2"></i>Doctor Login</h2>
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
                                    <input type="email" class="form-control" id="email" name="email" 
                                           value="<?php echo htmlspecialchars($_POST['email'] ?? ''); ?>" 
                                           placeholder="Enter your email" required>
                                </div>
                                
                                <div class="mb-3">
                                    <label for="password" class="form-label">
                                        <i class="fas fa-lock me-2"></i>Password
                                    </label>
                                    <input type="password" class="form-control" id="password" name="password" 
                                           placeholder="Enter your password" required>
                                </div>
                                
                                <div class="mb-3 form-check">
                                    <input type="checkbox" class="form-check-input" id="remember_me" name="remember_me">
                                    <label class="form-check-label" for="remember_me">
                                        Remember me for 30 days
                                    </label>
                                </div>
                                
                                <div class="d-grid gap-2">
                                    <button type="submit" class="btn btn-primary">
                                        <i class="fas fa-sign-in-alt me-2"></i>Login to Dashboard
                                    </button>
                                </div>
                                
                                <div class="text-center mt-3">
                                    <!-- <p class="mb-2">Don't have an account? 
                                        <a href="register.php" class="text-decoration-none" style="color: var(--primary-color);">Register here</a>
                                    </p> -->
                                    <p class="mb-0">
                                        <a href="../index.php" class="text-decoration-none" style="color: var(--accent-color);">← Back to Main Site</a>
                                    </p>
                                </div>
                            </form>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    </div>
    
    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js"></script>
</body>
</html>