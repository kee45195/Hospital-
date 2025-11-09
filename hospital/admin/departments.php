<?php
// admin/departments.php
require_once '../config/config.php';
// session_start();

// Require admin login
if (!isset($_SESSION['admin_id']) || ($_SESSION['user_type'] ?? '') !== 'admin') {
    header('Location: ../login.php?redirect=' . urlencode($_SERVER['REQUEST_URI']));
    exit();
}

$success_message = '';
$error_message   = '';
$action          = $_GET['action'] ?? 'list';
$dept_id         = isset($_GET['id']) ? (int)$_GET['id'] : null;

function h($v){ return htmlspecialchars((string)$v, ENT_QUOTES, 'UTF-8'); }

// CSRF
if (empty($_SESSION['csrf_token'])) {
    $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
}
function require_csrf() {
    if (($_POST['csrf_token'] ?? '') !== ($_SESSION['csrf_token'] ?? '')) {
        throw new Exception('Invalid CSRF token.');
    }
}

/* =========================
   CREATE (Name only)
   ========================= */
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['create_department'])) {
    try {
        require_csrf();
        $name = trim($_POST['name'] ?? '');
        if ($name === '') throw new Exception('Department name is required.');

        $check = $pdo->prepare("SELECT id FROM departments WHERE name = ?");
        $check->execute([$name]);
        if ($check->fetch()) throw new Exception('A department with this name already exists.');

        $pdo->prepare("INSERT INTO departments (name) VALUES (?)")->execute([$name]);

        $success_message = 'Department created successfully!';
        $action = 'list';
    } catch (Exception $e) {
        $error_message = $e->getMessage();
        $action = 'create';
    }
}

/* =========================
   UPDATE (Name only)
   ========================= */
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['update_department'], $_POST['id'])) {
    try {
        require_csrf();
        $id   = (int)$_POST['id'];
        $name = trim($_POST['name'] ?? '');
        if ($name === '') throw new Exception('Department name is required.');

        $check = $pdo->prepare("SELECT id FROM departments WHERE name = ? AND id <> ?");
        $check->execute([$name, $id]);
        if ($check->fetch()) throw new Exception('Another department with this name already exists.');

        $pdo->prepare("UPDATE departments SET name = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?")
            ->execute([$name, $id]);

        $success_message = 'Department updated successfully!';
        $action = 'list';
    } catch (Exception $e) {
        $error_message = $e->getMessage();
        $action = 'edit';
        $dept_id = (int)($_POST['id'] ?? 0);
    }
}

/* =========================
   DELETE
   ========================= */
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['delete_department'], $_POST['id'])) {
    try {
        require_csrf();
        $id = (int)$_POST['id'];
        // doctors.department_id has ON DELETE SET NULL FK (per your schema)
        $pdo->prepare("DELETE FROM departments WHERE id = ?")->execute([$id]);

        $success_message = 'Department deleted successfully!';
        $action = 'list';
    } catch (Exception $e) {
        $error_message = 'Error deleting department: ' . $e->getMessage();
        $action = 'list';
    }
}

/* =========================
   Load data
   ========================= */
$departments = [];
$editing     = null;

try {
    if ($action === 'list') {
        $departments = $pdo->query("SELECT id, name FROM departments ORDER BY name ASC")->fetchAll();
    } elseif ($action === 'edit' && $dept_id) {
        $stmt = $pdo->prepare("SELECT id, name FROM departments WHERE id = ?");
        $stmt->execute([$dept_id]);
        $editing = $stmt->fetch();
        if (!$editing) {
            $error_message = 'Department not found.';
            $action = 'list';
        }
    }
} catch (PDOException $e) {
    $error_message = 'Error loading department data.';
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Departments - <?php echo APP_NAME; ?></title>
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
        .sidebar .nav-link i { width: 20px; margin-right: 10px; }
        .main-content { margin-left: 250px; padding: 0; }
        .top-navbar { background-color: var(--primary-color); color: #fff; padding: 15px 30px; box-shadow: 0 2px 4px rgba(0,0,0,.1); }
        .content-area { padding: 30px; }
        .content-card { background: #fff; border-radius: 15px; padding: 30px; box-shadow: 0 4px 6px rgba(0,0,0,.05); border: none; }
        .icon-btn { width: 36px; height: 36px; padding: 0; display: inline-flex; align-items: center; justify-content: center; border-radius: 50%; border: 1px solid transparent; transition: all .15s ease-in-out; box-shadow: 0 1px 2px rgba(0,0,0,.04); background: #fff; }
        .icon-btn.edit { color: #2563EB; border-color: #2563EB; }
        .icon-btn.edit:hover { background: #2563EB; color: #fff; }
        .icon-btn.delete { color: #DC2626; border-color: #DC2626; }
        .icon-btn.delete:hover { background: #DC2626; color: #fff; }
        td.actions-cell { width: 120px; }
    </style>
</head>
<body>
    <!-- Sidebar -->
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
             <a class="nav-link" href="specializations.php"><i class="fas fa-building"></i>Specializations</a>
            <a class="nav-link" href="content.php"><i class="fas fa-edit"></i>Content Management</a>
            <a class="nav-link" href="../admin_logout.php">
                <i class="fas fa-sign-out-alt"></i>Logout
            </a>
        </nav>
    </div>

    <!-- Main Content -->
    <div class="main-content">
        <!-- Top Navbar -->
        <div class="top-navbar d-flex justify-content-between align-items-center">
            <h3 class="mb-0"><i class="fas fa-building me-2"></i><?php echo $action === 'create' ? 'Create Department' : ($action === 'edit' ? 'Edit Department' : 'Departments'); ?></h3>
            <div>
                <?php if ($action === 'list'): ?>
                    <a href="?action=create" class="btn btn-light"><i class="fas fa-plus me-2"></i>Create Department</a>
                <?php else: ?>
                    <a href="departments.php" class="btn btn-light"><i class="fas fa-arrow-left me-2"></i>Back to List</a>
                <?php endif; ?>
            </div>
        </div>

        <!-- Content Area -->
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

            <?php if ($action === 'create' || ($action === 'edit' && $editing)): ?>
                <div class="content-card">
                    <h5 class="mb-4"><i class="fas fa-pen-to-square me-2"></i><?php echo $action === 'create' ? 'New Department' : 'Edit Department'; ?></h5>
                    <form method="POST">
                        <input type="hidden" name="csrf_token" value="<?php echo h($_SESSION['csrf_token']); ?>">
                        <?php if ($action === 'edit'): ?>
                            <input type="hidden" name="id" value="<?php echo (int)$editing['id']; ?>">
                        <?php endif; ?>

                        <div class="mb-3">
                            <label for="name" class="form-label">Department Name *</label>
                            <input type="text" class="form-control" id="name" name="name" required
                                   value="<?php echo h($editing['name'] ?? ''); ?>">
                        </div>

                        <div class="text-center">
                            <?php if ($action === 'create'): ?>
                                <button type="submit" name="create_department" class="btn btn-primary btn-lg px-5">
                                    <i class="fas fa-plus me-2"></i>Create
                                </button>
                            <?php else: ?>
                                <button type="submit" name="update_department" class="btn btn-primary btn-lg px-5">
                                    <i class="fas fa-save me-2"></i>Save Changes
                                </button>
                                <a href="departments.php" class="btn btn-outline-secondary btn-lg px-5 ms-3">
                                    <i class="fas fa-times me-2"></i>Cancel
                                </a>
                            <?php endif; ?>
                        </div>
                    </form>
                </div>
            <?php else: ?>
                <div class="content-card">
                    <div class="d-flex justify-content-between align-items-center mb-4">
                        <h5 class="mb-0"><i class="fas fa-list me-2"></i>All Departments (<?php echo count($departments); ?>)</h5>
                        <input type="text" class="form-control" id="searchDepts" placeholder="Search departments..." style="width:250px;">
                    </div>

                    <div class="table-responsive">
                        <table class="table table-hover align-middle">
                            <thead>
                                <tr>
                                    <th style="width:120px;">ID</th>
                                    <th>Name</th>
                                    <th class="text-end" style="width:140px;">Actions</th>
                                </tr>
                            </thead>
                            <tbody id="deptTableBody">
                                <?php if (empty($departments)): ?>
                                    <tr>
                                        <td colspan="3" class="text-center py-4">
                                            <i class="fas fa-building fa-3x text-muted mb-3"></i>
                                            <p class="text-muted mb-0">No departments found.</p>
                                        </td>
                                    </tr>
                                <?php else: ?>
                                    <?php foreach ($departments as $d): ?>
                                        <tr>
                                            <td><?php echo (int)$d['id']; ?></td>
                                            <td><strong><?php echo h($d['name']); ?></strong></td>
                                            <td class="text-end actions-cell">
                                                <a href="?action=edit&id=<?php echo (int)$d['id']; ?>"
                                                   class="icon-btn edit" data-bs-toggle="tooltip" data-bs-title="Edit">
                                                    <i class="fas fa-pen"></i>
                                                </a>
                                                <form method="POST" action="" class="d-inline"
                                                      onsubmit="return confirm('Delete this department?');">
                                                    <input type="hidden" name="csrf_token" value="<?php echo h($_SESSION['csrf_token']); ?>">
                                                    <input type="hidden" name="id" value="<?php echo (int)$d['id']; ?>">
                                                    <button type="submit" name="delete_department"
                                                            class="icon-btn delete" data-bs-toggle="tooltip" data-bs-title="Delete">
                                                        <i class="fas fa-trash"></i>
                                                    </button>
                                                </form>
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
        // table search
        (function(){
            const searchInput = document.getElementById('searchDepts');
            if (!searchInput) return;
            const tableBody = document.getElementById('deptTableBody');
            searchInput.addEventListener('input', function() {
                const term = this.value.toLowerCase();
                Array.from(tableBody.getElementsByTagName('tr')).forEach(row => {
                    const text = row.textContent.toLowerCase();
                    row.style.display = text.includes(term) ? '' : 'none';
                });
            });
        })();

        // enable tooltips on icon buttons
        const tooltipTriggerList = [].slice.call(document.querySelectorAll('[data-bs-toggle="tooltip"]'));
        tooltipTriggerList.forEach(function (tooltipTriggerEl) {
            new bootstrap.Tooltip(tooltipTriggerEl);
        });
    </script>
</body>
</html>
