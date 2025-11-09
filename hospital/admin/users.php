<?php
require_once '../config/config.php';

if (!function_exists('upload_doctor_photo')) {
    function upload_doctor_photo(?array $file, string $dest = __DIR__ . '/../uploads/doctors'): ?string {
        if (empty($file) || ($file['error'] ?? UPLOAD_ERR_NO_FILE) !== UPLOAD_ERR_OK) {
            return null;
        }

        if (($file['size'] ?? 0) > 2 * 1024 * 1024) {
            return null;
        }

        $allowed = [
            'image/jpeg' => 'jpg',
            'image/png'  => 'png',
            'image/gif'  => 'gif',
            'image/webp' => 'webp',
        ];
        $finfo = class_exists('finfo') ? new finfo(FILEINFO_MIME_TYPE) : null;
        $mime  = $finfo ? $finfo->file($file['tmp_name']) : (@mime_content_type($file['tmp_name']) ?: '');
        if (!isset($allowed[$mime])) {
            return null;
        }
        if (!@getimagesize($file['tmp_name'])) {
            return null;
        }

        if (!is_dir($dest)) {
            @mkdir($dest, 0755, true);
        }

        $ext      = $allowed[$mime];
        $filename = bin2hex(random_bytes(8)) . '_' . time() . '.' . $ext;
        $destPath = rtrim($dest, '/\\') . DIRECTORY_SEPARATOR . $filename;

        if (!move_uploaded_file($file['tmp_name'], $destPath)) {
            return null;
        }

        return 'uploads/doctors/' . $filename;
    }
}

if (!isset($_SESSION['admin_id']) || $_SESSION['user_type'] !== 'admin') {
    header('Location: ../login.php?redirect=' . urlencode($_SERVER['REQUEST_URI']));
    exit();
}

$admin_id = $_SESSION['admin_id'];
$success_message = '';
$error_message = '';
$action = $_GET['action'] ?? 'list';
$user_id = $_GET['id'] ?? null;

function h($v)
{
    return htmlspecialchars((string) $v, ENT_QUOTES, 'UTF-8');
}

try {
    $deptStmt = $pdo->query('SELECT id, name FROM departments ORDER BY name ASC');
    $departments = $deptStmt->fetchAll();
} catch (PDOException $e) {
    $departments = [];
}

try {
    $specStmt = $pdo->query('SELECT id, name FROM specializations ORDER BY name ASC');
    $specializations = $specStmt->fetchAll();
} catch (PDOException $e) {
    $specializations = [];
}

if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['create_user'])) {
    $name = trim($_POST['name'] ?? '');
    $email = trim($_POST['email'] ?? '');
    $role = $_POST['role'] ?? '';
    $password = $_POST['password'] ?? '';
    $confirm_password = $_POST['confirm_password'] ?? '';

    $address = trim($_POST['address'] ?? '');
    $phone = trim($_POST['phone'] ?? '');

    $specialization_id = isset($_POST['specialization_id']) && $_POST['specialization_id'] !== '' ? (int) $_POST['specialization_id'] : null;
    $contact = trim($_POST['contact'] ?? '');
    $experience_years = isset($_POST['experience_years']) && $_POST['experience_years'] !== '' ? (int) $_POST['experience_years'] : null;
    $qualification = trim($_POST['qualification'] ?? '');

    $department_id = isset($_POST['department_id']) && $_POST['department_id'] !== '' ? (int) $_POST['department_id'] : null;

    if ($name === '' || $email === '' || $role === '' || $password === '') {
        $error_message = 'All required fields must be filled.';
    } elseif (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
        $error_message = 'Please enter a valid email address.';
    } elseif (strlen($password) < 6) {
        $error_message = 'Password must be at least 6 characters long.';
    } elseif ($password !== $confirm_password) {
        $error_message = 'Passwords do not match.';
    } else {
        if ($role === 'doctor') {
            if ($specialization_id === null || $contact === '' || $qualification === '') {
                $error_message = 'For doctors, Specialization, Contact, and Qualification are required.';
            } elseif ($experience_years !== null && ($experience_years < 0 || $experience_years > 60)) {
                $error_message = 'Years of Experience must be between 0 and 60.';
            }
        } elseif ($role !== 'patient') {
            if ($phone !== '' && strlen($phone) > 20) {
                $error_message = 'Phone is too long.';
            }
        }
    }

    if ($error_message === '') {
        try {
            $pdo->beginTransaction();

            $tables = ['patients', 'doctors', 'receptionists', 'admins'];
            $email_exists = false;

            foreach ($tables as $table) {
                $stmt = $pdo->prepare("SELECT id FROM $table WHERE email = ?");
                $stmt->execute([$email]);
                if ($stmt->fetch()) {
                    $email_exists = true;
                    break;
                }
            }

            if ($email_exists) {
                $error_message = 'Email address is already registered.';
                $pdo->rollBack();
            } else {
                $hashed_password = password_hash($password, PASSWORD_DEFAULT);

                switch ($role) {
                    case 'patient':
                        $stmt = $pdo->prepare('
                            INSERT INTO patients (name, email, phone, password, address, department_id)
                            VALUES (?, ?, ?, ?, ?, ?)
                        ');
                        $stmt->execute([$name, $email, $phone, $hashed_password, $address, $department_id]);
                        $new_user_id = $pdo->lastInsertId();
                        break;

                    case 'doctor':
                        $stmt = $pdo->prepare('
                            INSERT INTO doctors (name, email, password, specialization_id, contact, experience_years, qualification, department_id)
                            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                        ');
                        $stmt->execute([
                            $name,
                            $email,
                            $hashed_password,
                            $specialization_id,
                            $contact,
                            $experience_years,
                            $qualification,
                            $department_id,
                        ]);
                        $new_user_id = $pdo->lastInsertId();

                        if (isset($_FILES['profile_image'])) {
                            $profileImagePath = upload_doctor_photo($_FILES['profile_image']);
                            if ($profileImagePath) {
                                $up = $pdo->prepare('UPDATE doctors SET profile_image = ? WHERE id = ?');
                                $up->execute([$profileImagePath, (int) $new_user_id]);
                            }
                        }

                        break;

                    case 'receptionist':
                        $stmt = $pdo->prepare('INSERT INTO receptionists (name, email, phone, password) VALUES (?, ?, ?, ?)');
                        $stmt->execute([$name, $email, $phone, $hashed_password]);
                        $new_user_id = $pdo->lastInsertId();
                        break;

                    case 'admin':
                        $stmt = $pdo->prepare("INSERT INTO admins (name, email, phone, password, role) VALUES (?, ?, ?, ?, 'admin')");
                        $stmt->execute([$name, $email, $phone, $hashed_password]);
                        $new_user_id = $pdo->lastInsertId();
                        break;

                    default:
                        throw new Exception('Invalid role specified.');
                }

                $stmt = $pdo->prepare("INSERT INTO users (role, status, user_id) VALUES (?, 'active', ?)");
                $stmt->execute([$role, $new_user_id]);

                $pdo->commit();
                $success_message = ucfirst($role) . ' account created successfully!';
                $action = 'list';
            }
        } catch (Exception $e) {
            if ($pdo->inTransaction()) {
                $pdo->rollBack();
            }
            $error_message = 'Error creating user: ' . $e->getMessage();
        }
    }
}

if (isset($_GET['toggle_status']) && $user_id) {
    try {
        $stmt = $pdo->prepare('SELECT * FROM users WHERE id = ?');
        $stmt->execute([$user_id]);
        $user = $stmt->fetch();

        if ($user) {
            $new_status = $user['status'] === 'active' ? 'inactive' : 'active';
            $stmt = $pdo->prepare('UPDATE users SET status = ? WHERE id = ?');
            $stmt->execute([$new_status, $user_id]);

            $success_message = 'User status updated successfully!';
        }
    } catch (PDOException $e) {
        $error_message = 'Error updating user status.';
    }
}

try {
    $stmt = $pdo->prepare('
        SELECT u.id, u.role, u.status, u.created_at,
               CASE 
                   WHEN u.role = "patient" THEN p.name
                   WHEN u.role = "doctor" THEN d.name
                   WHEN u.role = "receptionist" THEN r.name
                   WHEN u.role = "admin" THEN a.name
               END as name,
               CASE 
                   WHEN u.role = "patient" THEN p.email
                   WHEN u.role = "doctor" THEN d.email
                   WHEN u.role = "receptionist" THEN r.email
                   WHEN u.role = "admin" THEN a.email
               END as email,
               CASE 
                   WHEN u.role = "patient" THEN p.phone
                   WHEN u.role = "doctor" THEN d.contact
                   WHEN u.role = "receptionist" THEN r.phone
                   WHEN u.role = "admin" THEN a.phone
               END as phone,
               CASE 
                   WHEN u.role = "doctor" THEN spec.name
                   ELSE NULL
               END as specialization,
               CASE
                   WHEN u.role = "doctor" THEN depd.name
                   WHEN u.role = "patient" THEN depp.name
                   ELSE NULL
               END as department_name
        FROM users u
        LEFT JOIN patients p ON u.role = "patient" AND u.user_id = p.id
        LEFT JOIN doctors d ON u.role = "doctor" AND u.user_id = d.id
        LEFT JOIN receptionists r ON u.role = "receptionist" AND u.user_id = r.id
        LEFT JOIN admins a ON u.role = "admin" AND u.user_id = a.id
        LEFT JOIN departments depd ON d.department_id = depd.id
        LEFT JOIN departments depp ON p.department_id = depp.id
        LEFT JOIN specializations spec ON d.specialization_id = spec.id
        ORDER BY u.created_at DESC
    ');
    $stmt->execute();
    $users = $stmt->fetchAll();
} catch (PDOException $e) {
    $users = [];
    $error_message = 'Error loading users data.';
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>User Management - <?php echo APP_NAME; ?></title>
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
        body { background-color: var(--background-color); color: var(--text-color); font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; }
        .sidebar { background-color: var(--secondary-color); min-height: 100vh; width: 250px; position: fixed; top: 0; left: 0; z-index: 1000; transition: all .3s; }
        .sidebar .nav-link { color: #fff; padding: 12px 20px; border-radius: 0; transition: all .3s; }
        .sidebar .nav-link:hover, .sidebar .nav-link.active { background-color: var(--primary-color); color: #fff; }
        .sidebar .nav-link i { width: 20px; margin-right: 10px; }
        .logo { padding: 20px; text-align: center; border-bottom: 1px solid #475569; margin-bottom: 20px; }
        .logo h4 { color: #fff; margin: 0; }
        .main-content { margin-left: 250px; padding: 0; }
        .top-navbar { background-color: var(--primary-color); color: #fff; padding: 15px 30px; box-shadow: 0 2px 4px rgba(0,0,0,.1); }
        .content-area { padding: 30px; }
        .content-card { background: #fff; border-radius: 15px; padding: 30px; box-shadow: 0 4px 6px rgba(0,0,0,.05); border: none; }
        .btn-primary { background-color: var(--primary-color); border-color: var(--primary-color); }
        .btn-primary:hover { background-color: #1D4ED8; border-color: #1D4ED8; }
        .btn-accent { background-color: var(--accent-color); border-color: var(--accent-color); color: #fff; }
        .btn-accent:hover { background-color: #6D28D9; border-color: #6D28D9; color: #fff; }
        .form-control:focus { border-color: var(--primary-color); box-shadow: 0 0 0 .2rem rgba(37, 99, 235, .25); }
        .table th { background-color: var(--background-color); border-top: none; font-weight: 600; }
        .role-badge { display: inline-block; padding: .35rem .6rem; font-size: .75rem; border-radius: 999px; color: #fff; font-weight: 600; }
        .role-badge.role-admin { background: #EF4444; }
        .role-badge.role-doctor { background: #2563EB; }
        .role-badge.role-receptionist { background: #7C3AED; }
        .role-badge.role-patient { background: #10B981; }
        .status-active, .status-inactive {
            display: inline-block;
            padding: .35rem .6rem;
            border-radius: 999px;
            color: #fff;
            font-weight: 600;
        }
        .status-active { background: #10B981; }
        .status-inactive { background: #EF4444; }
        .form-hint { font-size: .85rem; color: #6b7280; }
        #profilePreview { max-height: 200px; object-fit: cover; }
    </style>
</head>
<body>
    <div class="sidebar">
        <div class="logo">
            <h4><i class="fas fa-hospital-alt me-2"></i><?php echo APP_NAME; ?></h4>
        </div>
        <nav class="nav flex-column">
            <a class="nav-link" href="dashboard.php"><i class="fas fa-tachometer-alt"></i>Dashboard</a>
            <a class="nav-link" href="profile.php"><i class="fas fa-user"></i>Profile</a>
            <a class="nav-link active" href="users.php"><i class="fas fa-users"></i>User Accounts</a>
            <a class="nav-link" href="reports.php"><i class="fas fa-chart-bar"></i>Reports</a>
            <a class="nav-link" href="departments.php"><i class="fas fa-building"></i>Departments</a>
            <a class="nav-link" href="specializations.php"><i class="fas fa-stethoscope"></i>Specializations</a>
            <a class="nav-link" href="content.php"><i class="fas fa-edit"></i>Content Management</a>
            <a class="nav-link" href="../admin_logout.php">
                <i class="fas fa-sign-out-alt"></i>Logout
            </a>
        </nav>
    </div>

    <div class="main-content">
        <div class="top-navbar d-flex justify-content-between align-items-center">
            <div>
                <h3 class="mb-0"><i class="fas fa-users me-2"></i><?php echo $action === 'create' ? 'Create New User' : 'User Management'; ?></h3>
            </div>
            <div>
                <?php if ($action === 'list'): ?>
                    <a href="?action=create" class="btn btn-light"><i class="fas fa-user-plus me-2"></i>Create New User</a>
                <?php else: ?>
                    <a href="users.php" class="btn btn-light"><i class="fas fa-arrow-left me-2"></i>Back to List</a>
                <?php endif; ?>
            </div>
        </div>

        <div class="content-area">
            <?php if ($success_message): ?>
                <div class="alert alert-success alert-dismissible fade show" role="alert">
                    <i class="fas fa-check-circle me-2"></i><?php echo h($success_message); ?>
                    <button type="button" class="btn-close" data-bs-dismiss="alert"></button>
                </div>
            <?php endif; ?>
            <?php if ($error_message): ?>
                <div class="alert alert-danger alert-dismissible fade show" role="alert">
                    <i class="fas fa-exclamation-circle me-2"></i><?php echo h($error_message); ?>
                    <button type="button" class="btn-close" data-bs-dismiss="alert"></button>
                </div>
            <?php endif; ?>

            <?php if ($action === 'create'): ?>
                <div class="content-card">
                    <h5 class="mb-4"><i class="fas fa-user-plus me-2"></i>Create New User Account</h5>
                    <form method="POST" action="" enctype="multipart/form-data">
                        <div class="row">
                            <div class="col-md-6 mb-3">
                                <label for="name" class="form-label">Full Name *</label>
                                <input type="text" class="form-control" id="name" name="name" required>
                            </div>
                            <div class="col-md-6 mb-3">
                                <label for="email" class="form-label">Email Address *</label>
                                <input type="email" class="form-control" id="email" name="email" required>
                            </div>
                        </div>

                        <div class="row">
                            <div class="col-md-6 mb-3">
                                <label for="role" class="form-label">Role *</label>
                                <select class="form-control" id="role" name="role" required>
                                    <option value="">Select Role</option>
                                    <option value="doctor">Doctor</option>
                                    <option value="receptionist">Receptionist</option>
                                    <option value="admin">Admin</option>
                                </select>
                            </div>
                            <div class="col-md-3 mb-3">
                                <label for="password" class="form-label">Password *</label>
                                <input type="password" class="form-control" id="password" name="password" minlength="6" required>
                                <div class="form-hint mt-1">Min 6 characters</div>
                            </div>
                            <div class="col-md-3 mb-3">
                                <label for="confirm_password" class="form-label">Confirm Password *</label>
                                <input type="password" class="form-control" id="confirm_password" name="confirm_password" minlength="6" required>
                            </div>
                        </div>

                        <div class="mb-3 doctor-or-patient" style="display:none;">
                            <label for="department_id" class="form-label">Department</label>
                            <select class="form-control" id="department_id" name="department_id">
                                <option value="">-- Select Department --</option>
                                <?php foreach ($departments as $dep): ?>
                                    <option value="<?php echo (int) $dep['id']; ?>"><?php echo h($dep['name']); ?></option>
                                <?php endforeach; ?>
                            </select>
                        </div>

                        <div class="mb-3 patient-only" style="display:none;">
                            <label for="address" class="form-label">Address</label>
                            <textarea class="form-control" id="address" name="address" rows="3"></textarea>
                        </div>

                        <div class="mb-3 non-doctor-phone" style="display:none;">
                            <label for="phone" class="form-label">Phone Number</label>
                            <input type="tel" class="form-control" id="phone" name="phone">
                        </div>

                        <div class="row doctor-only" style="display:none;">
                            <div class="col-md-6 mb-3">
                                <label for="specialization_id" class="form-label">Specialization *</label>
                                <select class="form-control" id="specialization_id" name="specialization_id">
                                    <option value="">Select Specialization</option>
                                    <?php foreach ($specializations as $spec): ?>
                                        <option value="<?php echo (int) $spec['id']; ?>"><?php echo h($spec['name']); ?></option>
                                    <?php endforeach; ?>
                                </select>
                            </div>
                            <div class="col-md-6 mb-3">
                                <label for="doctor_contact" class="form-label">Contact (Phone) *</label>
                                <input type="tel" class="form-control" id="doctor_contact" name="contact">
                            </div>
                        </div>

                        <div class="row doctor-only" style="display:none;">
                            <div class="col-md-6 mb-3">
                                <label for="experience_years" class="form-label">Years of Experience</label>
                                <input type="number" class="form-control" id="experience_years" name="experience_years" min="0" max="60" placeholder="e.g., 5">
                            </div>
                            <div class="col-md-6 mb-3">
                                <label for="qualification" class="form-label">Qualification *</label>
                                <input type="text" class="form-control" id="qualification" name="qualification" placeholder="e.g., MD, MBBS, Specialist Certification">
                            </div>
                        </div>

                        <div class="row doctor-only" style="display:none;">
                            <div class="col-md-12 mb-3">
                                <label for="profile_image" class="form-label">Profile Picture</label>
                                <input type="file" class="form-control" id="profile_image" name="profile_image" accept="image/*">
                                <div class="form-hint mt-1">JPG/PNG/GIF/WEBP up to 2MB.</div>
                                <img id="profilePreview" src="" alt="Doctor profile preview" class="img-thumbnail mt-2" style="display:none;">
                            </div>
                        </div>

                        <div class="text-center">
                            <button type="submit" name="create_user" class="btn btn-primary btn-lg px-5">
                                <i class="fas fa-user-plus me-2"></i>Create User
                            </button>
                            <a href="users.php" class="btn btn-outline-secondary btn-lg px-5 ms-3">
                                <i class="fas fa-times me-2"></i>Cancel
                            </a>
                        </div>
                    </form>
                </div>
            <?php else: ?>
                <div class="content-card">
                    <div class="d-flex justify-content-between align-items-center mb-4">
                        <h5 class="mb-0"><i class="fas fa-list me-2"></i>All Users (<?php echo count($users); ?>)</h5>
                        <div>
                            <input type="text" class="form-control" id="searchUsers" placeholder="Search users..." style="width:250px;">
                        </div>
                    </div>
                    <div class="table-responsive">
                        <table class="table table-hover">
                            <thead>
                                <tr>
                                    <th>Name</th>
                                    <th>Email</th>
                                    <th>Phone</th>
                                    <th>Role</th>
                                    <th>Specialization</th>
                                    <th>Department</th>
                                    <th>Status</th>
                                    <th>Created</th>
                                    <th>Actions</th>
                                </tr>
                            </thead>
                            <tbody id="usersTableBody">
                                <?php if (empty($users)): ?>
                                    <tr>
                                        <td colspan="9" class="text-center py-4">
                                            <i class="fas fa-users fa-3x text-muted mb-3"></i>
                                            <p class="text-muted">No users found.</p>
                                        </td>
                                    </tr>
                                <?php else: ?>
                                    <?php foreach ($users as $user): ?>
                                        <tr>
                                            <td><strong><?php echo h($user['name'] ?? ''); ?></strong></td>
                                            <td><?php echo h($user['email'] ?? ''); ?></td>
                                            <td><?php echo h($user['phone'] ?? ''); ?></td>
                                            <td>
                                                <?php $roleClass = 'role-' . ($user['role'] ?? ''); ?>
                                                <span class="role-badge <?php echo h($roleClass); ?>">
                                                    <?php echo ucfirst(h($user['role'])); ?>
                                                </span>
                                            </td>
                                            <td><?php echo !empty($user['specialization']) ? h($user['specialization']) : '-'; ?></td>
                                            <td><?php echo !empty($user['department_name']) ? h($user['department_name']) : '-'; ?></td>
                                            <td>
                                                <span class="status-<?php echo h($user['status']); ?>">
                                                    <?php echo ucfirst(h($user['status'])); ?>
                                                </span>
                                            </td>
                                            <td><?php echo date('M j, Y', strtotime($user['created_at'])); ?></td>
                                            <td>
                                                <div class="btn-group btn-group-sm">
                                                    <a href="?toggle_status=1&id=<?php echo (int) $user['id']; ?>"
                                                       class="btn btn-outline-<?php echo ($user['status'] === 'active') ? 'warning' : 'success'; ?>"
                                                       onclick="return confirm('Are you sure you want to <?php echo ($user['status'] === 'active') ? 'deactivate' : 'activate'; ?> this user?')">
                                                        <i class="fas fa-<?php echo ($user['status'] === 'active') ? 'pause' : 'play'; ?>"></i>
                                                    </a>
                                                </div>
                                            </td>
                                        </tr>
                                    <?php endforeach; ?>
                                <?php endif; ?>
                            </tbody>
                        </table>
                    </div>
                </div>
            <?php endif; ?>
        </div>
    </div>

    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js"></script>
    <script>
        (function () {
            const roleSel = document.getElementById('role');
            if (!roleSel) return;

            const patientOnlyEls = document.querySelectorAll('.patient-only');
            const doctorOnlyEls = document.querySelectorAll('.doctor-only');
            const nonDoctorPhoneEl = document.querySelector('.non-doctor-phone');
            const doctorOrPatientEl = document.querySelector('.doctor-or-patient');

            const addressInput = document.getElementById('address');
            const specInput = document.getElementById('specialization_id');
            const doctorContactInput = document.getElementById('doctor_contact');
            const experienceYearsInput = document.getElementById('experience_years');
            const qualificationInput = document.getElementById('qualification');
            const departmentInput = document.getElementById('department_id');

            function setDisplay(elements, show) {
                elements.forEach(el => el.style.display = show ? 'block' : 'none');
            }

            function handleRoleChange() {
                const role = roleSel.value;

                const isDoctor = role === 'doctor';
                const isPatient = role === 'patient';

                setDisplay(doctorOnlyEls, isDoctor);
                setDisplay(patientOnlyEls, isPatient);

                if (nonDoctorPhoneEl) {
                    nonDoctorPhoneEl.style.display = (!isDoctor ? 'block' : 'none');
                }

                if (doctorOrPatientEl) doctorOrPatientEl.style.display = (isDoctor || isPatient) ? 'block' : 'none';

                if (addressInput) addressInput.required = isPatient;
                if (specInput) specInput.required = isDoctor;
                if (doctorContactInput) doctorContactInput.required = isDoctor;
                if (qualificationInput) qualificationInput.required = isDoctor;
                if (departmentInput) departmentInput.required = false;
                if (experienceYearsInput) experienceYearsInput.required = false;
            }

            roleSel.addEventListener('change', handleRoleChange);
            handleRoleChange();
        })();

        (function () {
            const searchInput = document.getElementById('searchUsers');
            if (!searchInput) return;
            const tableBody = document.getElementById('usersTableBody');
            searchInput.addEventListener('input', function () {
                const term = this.value.toLowerCase();
                Array.from(tableBody.getElementsByTagName('tr')).forEach(row => {
                    const text = row.textContent.toLowerCase();
                    row.style.display = text.includes(term) ? '' : 'none';
                });
            });
        })();

        document.addEventListener('DOMContentLoaded', function () {
            const input = document.getElementById('profile_image');
            const img = document.getElementById('profilePreview');
            if (!input || !img) return;
            input.addEventListener('change', function (e) {
                const file = e.target.files && e.target.files[0];
                if (!file) {
                    img.style.display = 'none';
                    img.src = '';
                    return;
                }
                const reader = new FileReader();
                reader.onload = function (ev) {
                    img.src = ev.target.result;
                    img.style.display = 'inline-block';
                };
                reader.readAsDataURL(file);
            });
        });
    </script>
</body>
</html>