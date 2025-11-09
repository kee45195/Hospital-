<?php
require_once '../config/config.php';

// Require admin login
if (!isset($_SESSION['admin_id']) || $_SESSION['user_type'] !== 'admin') {
    header('Location: ../login.php?redirect=' . urlencode($_SERVER['REQUEST_URI']));
    exit();
}

$admin_id = $_SESSION['admin_id'];
$admin_name = $_SESSION['admin_name'];
$admin_role = $_SESSION['admin_role'];

// Get dashboard statistics
try {
    // Total users count
    $stmt = $pdo->prepare("SELECT COUNT(*) as total_users FROM users WHERE status = 'active'");
    $stmt->execute();
    $total_users = $stmt->fetchColumn();
    
    // Total patients
    $stmt = $pdo->prepare("SELECT COUNT(*) as total_patients FROM patients");
    $stmt->execute();
    $total_patients = $stmt->fetchColumn();
    
    // Total doctors
    $stmt = $pdo->prepare("SELECT COUNT(*) as total_doctors FROM doctors");
    $stmt->execute();
    $total_doctors = $stmt->fetchColumn();
    
    // Total appointments today
    $stmt = $pdo->prepare("SELECT COUNT(*) as today_appointments FROM appointments WHERE DATE(appointment_date) = CURDATE()");
    $stmt->execute();
    $today_appointments = $stmt->fetchColumn();
    
    // Recent appointments
    $stmt = $pdo->prepare("
        SELECT a.*, p.name as patient_name, d.name as doctor_name 
        FROM appointments a 
        JOIN patients p ON a.patient_id = p.id 
        JOIN doctors d ON a.doctor_id = d.id 
        ORDER BY a.created_at DESC 
        LIMIT 5
    ");
    $stmt->execute();
    $recent_appointments = $stmt->fetchAll();
    
} catch (PDOException $e) {
    $total_users = $total_patients = $total_doctors = $today_appointments = 0;
    $recent_appointments = [];
}
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Admin Dashboard - <?php echo APP_NAME; ?></title>
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
        
        .sidebar .nav-link:hover,
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
        
        .stat-card {
            background: white;
            border-radius: 15px;
            padding: 25px;
            box-shadow: 0 4px 6px rgba(0, 0, 0, 0.05);
            border: none;
            transition: transform 0.3s;
        }
        
        .stat-card:hover {
            transform: translateY(-5px);
        }
        
        .stat-number {
            font-size: 2.5rem;
            font-weight: 700;
            color: var(--primary-color);
        }
        
        .stat-label {
            color: #6B7280;
            font-size: 0.9rem;
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }
        
        .stat-icon {
            font-size: 2rem;
            color: var(--accent-color);
        }
        
        .recent-activity {
            background: white;
            border-radius: 15px;
            padding: 25px;
            box-shadow: 0 4px 6px rgba(0, 0, 0, 0.05);
        }
        
        .activity-item {
            padding: 15px 0;
            border-bottom: 1px solid #E5E7EB;
        }
        
        .activity-item:last-child {
            border-bottom: none;
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
    </style>
</head>
<body>
    <!-- Sidebar -->
    <div class="sidebar">
        <div class="logo">
            <h4><i class="fas fa-hospital-alt me-2"></i><?php echo APP_NAME; ?></h4>
        </div>
        
        <nav class="nav flex-column">
            <a class="nav-link active" href="dashboard.php">
                <i class="fas fa-tachometer-alt"></i>Dashboard
            </a>
            <a class="nav-link" href="profile.php">
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
                <h3 class="mb-0"><i class="fas fa-tachometer-alt me-2"></i>Admin Dashboard</h3>
            </div>
            <div>
                <span class="me-3">Welcome, <?php echo htmlspecialchars($admin_name); ?></span>
                <span class="badge bg-light text-dark"><?php echo ucfirst($admin_role); ?></span>
            </div>
        </div>
        
        <!-- Content Area -->
        <div class="content-area">
            <!-- Statistics Cards -->
            <div class="row mb-4">
                <div class="col-lg-3 col-md-6 mb-4">
                    <div class="stat-card text-center">
                        <div class="d-flex justify-content-between align-items-center">
                            <div>
                                <div class="stat-number"><?php echo $total_users; ?></div>
                                <div class="stat-label">Total Users</div>
                            </div>
                            <div class="stat-icon">
                                <i class="fas fa-users"></i>
                            </div>
                        </div>
                    </div>
                </div>
                
                <div class="col-lg-3 col-md-6 mb-4">
                    <div class="stat-card text-center">
                        <div class="d-flex justify-content-between align-items-center">
                            <div>
                                <div class="stat-number"><?php echo $total_patients; ?></div>
                                <div class="stat-label">Patients</div>
                            </div>
                            <div class="stat-icon">
                                <i class="fas fa-user-injured"></i>
                            </div>
                        </div>
                    </div>
                </div>
                
                <div class="col-lg-3 col-md-6 mb-4">
                    <div class="stat-card text-center">
                        <div class="d-flex justify-content-between align-items-center">
                            <div>
                                <div class="stat-number"><?php echo $total_doctors; ?></div>
                                <div class="stat-label">Doctors</div>
                            </div>
                            <div class="stat-icon">
                                <i class="fas fa-user-md"></i>
                            </div>
                        </div>
                    </div>
                </div>
                
                <div class="col-lg-3 col-md-6 mb-4">
                    <div class="stat-card text-center">
                        <div class="d-flex justify-content-between align-items-center">
                            <div>
                                <div class="stat-number"><?php echo $today_appointments; ?></div>
                                <div class="stat-label">Today's Appointments</div>
                            </div>
                            <div class="stat-icon">
                                <i class="fas fa-calendar-check"></i>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
            
            <!-- Recent Activity -->
            <div class="row">
                <div class="col-lg-8">
                    <div class="recent-activity">
                        <h5 class="mb-4"><i class="fas fa-clock me-2"></i>Recent Appointments</h5>
                        
                        <?php if (empty($recent_appointments)): ?>
                            <div class="text-center py-4">
                                <i class="fas fa-calendar-times fa-3x text-muted mb-3"></i>
                                <p class="text-muted">No recent appointments found.</p>
                            </div>
                        <?php else: ?>
                            <?php foreach ($recent_appointments as $appointment): ?>
                                <div class="activity-item">
                                    <div class="d-flex justify-content-between align-items-center">
                                        <div>
                                            <strong><?php echo htmlspecialchars($appointment['patient_name']); ?></strong>
                                            <span class="text-muted">with <?php echo htmlspecialchars($appointment['doctor_name']); ?></span>
                                        </div>
                                        <div class="text-end">
                                            <div class="text-muted small">
                                                <?php echo date('M j, Y g:i A', strtotime($appointment['appointment_date'] . ' ' . $appointment['appointment_time'])); ?>
                                            </div>
                                            <span class="badge bg-<?php 
                                                echo $appointment['status'] === 'confirmed' ? 'success' : 
                                                    ($appointment['status'] === 'pending' ? 'warning' : 'secondary'); 
                                            ?>">
                                                <?php echo ucfirst($appointment['status']); ?>
                                            </span>
                                        </div>
                                    </div>
                                </div>
                            <?php endforeach; ?>
                        <?php endif; ?>
                    </div>
                </div>
                
                <div class="col-lg-4">
                    <div class="recent-activity">
                        <h5 class="mb-4"><i class="fas fa-tools me-2"></i>Quick Actions</h5>
                        
                        <div class="d-grid gap-3">
                            <a href="users.php?action=create" class="btn btn-primary">
                                <i class="fas fa-user-plus me-2"></i>Create New User
                            </a>
                            <a href="reports.php" class="btn btn-accent">
                                <i class="fas fa-chart-line me-2"></i>Generate Report
                            </a>
                            <a href="content.php" class="btn btn-outline-primary">
                                <i class="fas fa-edit me-2"></i>Update Content
                            </a>
                        </div>
                        
                        <hr class="my-4">
                        
                        <h6 class="mb-3"><i class="fas fa-info-circle me-2"></i>System Info</h6>
                        <div class="small text-muted">
                            <div class="mb-2">
                                <strong>Server Time:</strong><br>
                                <?php echo date('F j, Y g:i A'); ?>
                            </div>
                            <div class="mb-2">
                                <strong>Your Role:</strong><br>
                                <?php echo ucfirst($admin_role); ?> Administrator
                            </div>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    </div>
    
    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js"></script>
</body>
</html>