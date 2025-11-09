<?php
require_once 'config/config.php';

// Redirect if already logged in
redirectIfLoggedIn();

$errors = [];
$success_message = '';

// Load departments for dropdown (OPTIONAL field)
try {
    $stmt = $pdo->prepare("SELECT id, name FROM departments ORDER BY name ASC");
    $stmt->execute();
    $departments = $stmt->fetchAll(PDO::FETCH_ASSOC);
} catch (PDOException $e) {
    $departments = [];
}

if ($_SERVER['REQUEST_METHOD'] == 'POST') {
    // Validate CSRF token
    if (!validateCSRFToken($_POST['csrf_token'] ?? '')) {
        $errors[] = 'Invalid security token. Please try again.';
    } else {
        // Sanitize and validate input
        $name               = sanitizeInput($_POST['name'] ?? '');
        $email              = sanitizeInput($_POST['email'] ?? '');
        $password           = $_POST['password'] ?? '';
        $confirm_password   = $_POST['confirm_password'] ?? '';
        $gender             = sanitizeInput($_POST['gender'] ?? '');
        // NEW: Date of Birth (required, replaces age)
        $dob_raw            = trim($_POST['date_of_birth'] ?? '');
        $phone              = sanitizeInput($_POST['phone'] ?? '');
        $address            = sanitizeInput($_POST['address'] ?? '');
        // Department (OPTIONAL)
        $department_id_raw  = $_POST['department_id'] ?? '';
        $department_id      = ($department_id_raw !== '' ? (int)$department_id_raw : null);
        // Allergy (optional textarea) — maps to `allergy` column (singular)
        $allergy            = sanitizeInput($_POST['allergy'] ?? '');

        // Validation
        if (empty($name)) {
            $errors[] = 'Full name is required.';
        }
        if (empty($email) || !isValidEmail($email)) {
            $errors[] = 'Valid email address is required.';
        }
        if (empty($password) || strlen($password) < 6) {
            $errors[] = 'Password must be at least 6 characters long.';
        }
        if ($password !== $confirm_password) {
            $errors[] = 'Passwords do not match.';
        }
        if (empty($gender) || !in_array($gender, getGenderOptions())) {
            $errors[] = 'Please select a valid gender.';
        }

        // Validate DOB (required; not in the future; not older than 120 years)
        $date_of_birth = null;
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

       
        if (empty($address)) {
            $errors[] = 'Address is required.';
        }

        // Department OPTIONAL validation (only if provided)
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

        // Basic length guard for allergy (optional)
        if (!empty($allergy) && mb_strlen($allergy) > 2000) {
            $errors[] = 'Allergy text is too long (max 2000 characters).';
        }

        // Check if email already exists
        if (empty($errors)) {
            try {
                $stmt = $pdo->prepare("SELECT id FROM patients WHERE email = ?");
                $stmt->execute([$email]);
                if ($stmt->fetch()) {
                    $errors[] = 'Email address is already registered.';
                }
            } catch (PDOException $e) {
                $errors[] = 'Database error. Please try again.';
            }
        }

        // Register patient if no errors
        if (empty($errors)) {
            try {
                $hashed_password = hashPassword($password);

                // Ensure your `patients` table has (per your latest schema):
                //  - date_of_birth DATE NOT NULL (replacing age)
                //  - department_id INT NULL
                //  - allergy TEXT NULL
                //
                // Example migration from age -> date_of_birth:
                // ALTER TABLE patients ADD COLUMN date_of_birth DATE NULL AFTER gender;
                // -- backfill date_of_birth manually if needed
                // ALTER TABLE patients MODIFY date_of_birth DATE NOT NULL;
                // ALTER TABLE patients DROP COLUMN age;

                $stmt = $pdo->prepare("
                    INSERT INTO patients (name, email, password, gender, date_of_birth, phone, address, allergy, department_id)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                ");
                $stmt->execute([
                    $name,
                    $email,
                    $hashed_password,
                    $gender,
                    $date_of_birth,
                    $phone,
                    $address,
                    $allergy,
                    $department_id
                ]);

                $success_message = 'Registration successful! You can now login to your account.';

                // Clear form data
                $name = $email = $gender = $phone = $address = $allergy = '';
                $dob_raw = '';
                $department_id = null;

            } catch (PDOException $e) {
                $errors[] = 'Registration failed. Please try again.';
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
    <title>Patient Registration - <?php echo APP_NAME; ?></title>
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
        
        .hospital-card {
            background: white;
            border-radius: 15px;
            box-shadow: 0 10px 30px rgba(0, 0, 0, 0.1);
            border: none;
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
        
        .form-control, .form-select {
            border-radius: 10px;
            border: 2px solid #e0e0e0;
            padding: 12px 15px;
        }
        
        .form-control:focus, .form-select:focus {
            border-color: var(--primary-color);
            box-shadow: 0 0 0 0.2rem rgba(0, 150, 136, 0.25);
        }
        
        .form-label {
            font-weight: 600;
            color: var(--text-color);
            margin-bottom: 8px;
        }
        
        .hospital-header {
            background: linear-gradient(135deg, var(--primary-color), #00796b);
            color: white;
            padding: 2rem 0;
            margin-bottom: 2rem.
        }
        
        .hospital-logo {
            font-size: 2.5rem;
            margin-bottom: 0.5rem;
        }
        
        .alert {
            border-radius: 10px;
            border: none;
        }
        
        .alert-danger {
            background-color: #ffebee;
            color: #c62828;
        }
        
        .alert-success {
            background-color: #e8f5e8;
            color: #2e7d32;
        }
        
        .medical-icon {
            color: var(--primary-color);
            font-size: 1.2rem;
            margin-right: 10px;
        }
    </style>
</head>
<body>
    <div class="hospital-header text-center">
        <div class="container">
            <div class="hospital-logo">
                <i class="fas fa-hospital"></i>
            </div>
            <h1 class="mb-0"><?php echo APP_NAME; ?></h1>
            <p class="mb-0">Your Health, Our Priority</p>
        </div>
    </div>

    <div class="container">
        <div class="row justify-content-center">
            <div class="col-lg-8 col-md-10">
                <div class="card hospital-card">
                    <div class="card-body p-5">
                        <div class="text-center mb-4">
                            <i class="fas fa-user-plus medical-icon" style="font-size: 3rem;"></i>
                            <h2 class="card-title" style="color: var(--primary-color);">Patient Registration</h2>
                            <p class="text-muted">Join our healthcare community today</p>
                        </div>

                        <?php if (!empty($errors)): ?>
                            <div class="alert d-inline-flex align-items-center  alert-danger">
                                <i class="fas fa-exclamation-triangle "></i>
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
                                           value="<?php echo htmlspecialchars($name ?? ''); ?>" required>
                                </div>
                                
                                <div class="col-md-6 mb-3">
                                    <label for="email" class="form-label">
                                        <i class="fas fa-envelope medical-icon"></i>Email Address
                                    </label>
                                    <input type="email" class="form-control" id="email" name="email" 
                                           value="<?php echo htmlspecialchars($email ?? ''); ?>" required>
                                </div>
                            </div>
                            
                            <div class="row">
                                <div class="col-md-6 mb-3">
                                    <label for="password" class="form-label">
                                        <i class="fas fa-lock medical-icon"></i>Password
                                    </label>
                                    <input type="password" class="form-control" id="password" name="password" required>
                                </div>
                                
                                <div class="col-md-6 mb-3">
                                    <label for="confirm_password" class="form-label">
                                        <i class="fas fa-lock medical-icon"></i>Confirm Password
                                    </label>
                                    <input type="password" class="form-control" id="confirm_password" name="confirm_password" required>
                                </div>
                            </div>
                            
                            <div class="row">
                                <div class="col-md-4 mb-3">
                                    <label for="gender" class="form-label">
                                        <i class="fas fa-venus-mars medical-icon"></i>Gender
                                    </label>
                                    <select class="form-select" id="gender" name="gender" required>
                                        <option value="">Select Gender</option>
                                        <?php foreach (getGenderOptions() as $option): ?>
                                            <option value="<?php echo $option; ?>" 
                                                    <?php echo (isset($gender) && $gender === $option) ? 'selected' : ''; ?>>
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
                                        value="<?php echo htmlspecialchars($dob_raw ?? ''); ?>" 
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
                                           value="<?php echo htmlspecialchars($phone ?? ''); ?>" required>
                                </div>
                            </div>

                            <!-- Department (OPTIONAL) -->
                            <!-- <div class="mb-3">
                                <label for="department_id" class="form-label">
                                    <i class="fas fa-building medical-icon"></i>Department (Optional)
                                </label>
                                <select class="form-select" id="department_id" name="department_id">
                                    <option value="">-- Select Department --</option>
                                    <?php foreach ($departments as $dep): ?>
                                        <option value="<?php echo (int)$dep['id']; ?>"
                                            <?php echo (isset($department_id) && (int)$department_id === (int)$dep['id']) ? 'selected' : ''; ?>>
                                            <?php echo htmlspecialchars($dep['name']); ?>
                                        </option>
                                    <?php endforeach; ?>
                                </select>
                            </div> -->

                            <!-- Allergy (optional) -->
                            <div class="mb-4">
                                <label for="allergy" class="form-label">
                                    <i class="fas fa-notes-medical medical-icon"></i>Allergies (Optional)
                                </label>
                                <textarea class="form-control" id="allergy" name="allergy" rows="3" placeholder="e.g., Penicillin, Peanuts, Latex"><?php echo htmlspecialchars($allergy ?? ''); ?></textarea>
                                <small class="text-muted">Provide any known drug/food/environmental allergies. This helps our staff ensure safe care.</small>
                            </div>
                            
                            <div class="mb-4">
                                <label for="address" class="form-label">
                                    <i class="fas fa-map-marker-alt medical-icon"></i>Address
                                </label>
                                <textarea class="form-control" id="address" name="address" rows="3" required><?php echo htmlspecialchars($address ?? ''); ?></textarea>
                            </div>
                            
                            <div class="d-grid gap-2">
                                <button type="submit" class="btn btn-primary btn-lg">
                                    <i class="fas fa-user-plus me-2"></i>Register as Patient
                                </button>
                            </div>
                        </form>
                        
                        <div class="text-center mt-4">
                            <p class="text-muted">Already have an account?</p>
                            <a href="login.php" class="btn btn-secondary">
                                <i class="fas fa-sign-in-alt me-2"></i>Login Here
                            </a>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    </div>

    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js"></script>
</body>
</html>
