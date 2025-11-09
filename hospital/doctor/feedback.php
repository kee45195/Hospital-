<?php
require_once '../config/config.php';

// Check if doctor is logged in
if (!isset($_SESSION['doctor_id'])) {
    header('Location: login.php');
    exit();
}

$doctor_id = $_SESSION['doctor_id'];
$doctor_name = $_SESSION['doctor_name'];

// Get filter parameters
$rating_filter = $_GET['rating'] ?? '';
$date_filter = $_GET['date_filter'] ?? '';
$page = max(1, (int)($_GET['page'] ?? 1));
$per_page = 10;
$offset = ($page - 1) * $per_page;

// Build query conditions
$where_conditions = ['f.doctor_id = ?'];
$params = [$doctor_id];

if (!empty($rating_filter)) {
    $where_conditions[] = 'f.rating = ?';
    $params[] = (int)$rating_filter;
}

if (!empty($date_filter)) {
    switch ($date_filter) {
        case 'today':
            $where_conditions[] = 'DATE(f.created_at) = CURDATE()';
            break;
        case 'week':
            $where_conditions[] = 'f.created_at >= DATE_SUB(NOW(), INTERVAL 7 DAY)';
            break;
        case 'month':
            $where_conditions[] = 'f.created_at >= DATE_SUB(NOW(), INTERVAL 30 DAY)';
            break;
    }
}

$where_clause = implode(' AND ', $where_conditions);

try {
    // Get feedback with patient info
    $stmt = $pdo->prepare("
        SELECT f.*, p.name as patient_name, p.email as patient_email
        FROM feedback f
        INNER JOIN patients p ON f.patient_id = p.id
        WHERE {$where_clause}
        ORDER BY f.created_at DESC
        LIMIT ? OFFSET ?
    ");
    
    $query_params = array_merge($params, [$per_page, $offset]);
    $stmt->execute($query_params);
    $feedback_list = $stmt->fetchAll();
    
    // Get total count for pagination
    $count_stmt = $pdo->prepare("
        SELECT COUNT(*)
        FROM feedback f
        WHERE {$where_clause}
    ");
    $count_stmt->execute($params);
    $total_feedback = $count_stmt->fetchColumn();
    $total_pages = ceil($total_feedback / $per_page);
    
    // Get feedback statistics
    $stats_stmt = $pdo->prepare("
        SELECT 
            COUNT(*) as total_feedback,
            AVG(rating) as average_rating,
            SUM(CASE WHEN rating = 5 THEN 1 ELSE 0 END) as five_star,
            SUM(CASE WHEN rating = 4 THEN 1 ELSE 0 END) as four_star,
            SUM(CASE WHEN rating = 3 THEN 1 ELSE 0 END) as three_star,
            SUM(CASE WHEN rating = 2 THEN 1 ELSE 0 END) as two_star,
            SUM(CASE WHEN rating = 1 THEN 1 ELSE 0 END) as one_star
        FROM feedback 
        WHERE doctor_id = ?
    ");
    $stats_stmt->execute([$doctor_id]);
    $stats = $stats_stmt->fetch();
    
    // Get recent feedback count
    $recent_stmt = $pdo->prepare("
        SELECT COUNT(*) as recent_count
        FROM feedback 
        WHERE doctor_id = ? AND created_at >= DATE_SUB(NOW(), INTERVAL 7 DAY)
    ");
    $recent_stmt->execute([$doctor_id]);
    $recent_count = $recent_stmt->fetchColumn();
    
} catch (PDOException $e) {
    $error_message = 'Database error occurred.';
    $feedback_list = [];
    $total_feedback = 0;
    $total_pages = 0;
    $stats = ['total_feedback' => 0, 'average_rating' => 0];
    $recent_count = 0;
}

// Helper function to generate star rating HTML
function generateStarRating($rating, $size = 'sm') {
    $html = '';
    for ($i = 1; $i <= 5; $i++) {
        if ($i <= $rating) {
            $html .= '<i class="fas fa-star text-warning"></i>';
        } else {
            $html .= '<i class="far fa-star text-muted"></i>';
        }
    }
    return $html;
}
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Patient Feedback - <?php echo APP_NAME; ?></title>
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
        }
        
        .navbar {
            background-color: var(--primary-color) !important;
            box-shadow: 0 2px 10px rgba(0, 0, 0, 0.1);
        }
        
        .navbar-brand {
            font-weight: 700;
            font-size: 1.5rem;
        }
        
        .nav-link {
            font-weight: 500;
            transition: all 0.3s ease;
        }
        
        .nav-link:hover {
            background-color: rgba(255, 255, 255, 0.1);
            border-radius: 5px;
        }
        
        .main-content {
            padding: 2rem 0;
        }
        
        .content-card {
            background: white;
            border-radius: 15px;
            padding: 1.5rem;
            box-shadow: 0 5px 15px rgba(0, 0, 0, 0.08);
            margin-bottom: 2rem;
        }
        
        .page-header {
            background: linear-gradient(135deg, var(--primary-color) 0%, var(--accent-color) 100%);
            color: white;
            border-radius: 15px;
            padding: 2rem;
            margin-bottom: 2rem;
        }
        
        .btn-primary {
            background-color: var(--primary-color);
            border-color: var(--primary-color);
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
        
        .stats-card {
            background: white;
            border-radius: 10px;
            padding: 1.5rem;
            text-align: center;
            box-shadow: 0 3px 10px rgba(0, 0, 0, 0.1);
            transition: transform 0.3s ease;
        }
        
        .stats-card:hover {
            transform: translateY(-5px);
        }
        
        .stats-number {
            font-size: 2.5rem;
            font-weight: 700;
            color: var(--primary-color);
        }
        
        .stats-label {
            color: #666;
            font-weight: 500;
        }
        
        .feedback-card {
            border: 1px solid #e0e0e0;
            border-radius: 10px;
            padding: 1.5rem;
            margin-bottom: 1rem;
            transition: all 0.3s ease;
        }
        
        .feedback-card:hover {
            box-shadow: 0 5px 15px rgba(0, 0, 0, 0.1);
            transform: translateY(-2px);
        }
        
        .feedback-header {
            display: flex;
            justify-content: between;
            align-items: center;
            margin-bottom: 1rem;
        }
        
        .patient-info {
            display: flex;
            align-items: center;
            gap: 1rem;
        }
        
        .patient-avatar {
            width: 50px;
            height: 50px;
            border-radius: 50%;
            background: var(--primary-color);
            display: flex;
            align-items: center;
            justify-content: center;
            color: white;
            font-weight: bold;
        }
        
        .rating-display {
            font-size: 1.2rem;
        }
        
        .feedback-text {
            background: var(--background-color);
            padding: 1rem;
            border-radius: 8px;
            border-left: 4px solid var(--accent-color);
        }
        
        .rating-breakdown {
            background: var(--background-color);
            border-radius: 10px;
            padding: 1.5rem;
        }
        
        .rating-bar {
            display: flex;
            align-items: center;
            margin-bottom: 0.5rem;
        }
        
        .rating-bar-fill {
            height: 8px;
            background: var(--primary-color);
            border-radius: 4px;
            transition: width 0.3s ease;
        }
        
        .rating-bar-bg {
            height: 8px;
            background: #e0e0e0;
            border-radius: 4px;
            flex: 1;
            margin: 0 1rem;
        }
        
        .filters-section {
            background: var(--background-color);
            border-radius: 10px;
            padding: 1.5rem;
            margin-bottom: 1.5rem;
        }
        
        .no-feedback {
            text-align: center;
            padding: 3rem;
            color: #666;
        }
        
        .form-control:focus {
            border-color: var(--primary-color);
            box-shadow: 0 0 0 0.2rem rgba(0, 131, 143, 0.25);
        }
    </style>
</head>
<body>
    <!-- Navigation -->
    <nav class="navbar navbar-expand-lg navbar-dark">
        <div class="container">
            <a class="navbar-brand" href="dashboard.php">
                <i class="fas fa-hospital me-2"></i><?php echo APP_NAME; ?> - Doctor
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
                        <a class="nav-link" href="availability.php">
                            <i class="fas fa-clock me-1"></i>Availability
                        </a>
                    </li>
                    <li class="nav-item">
                        <a class="nav-link" href="patients.php">
                            <i class="fas fa-user-injured me-1"></i>Patients
                        </a>
                    </li>
                    <li class="nav-item">
                        <a class="nav-link active" href="feedback.php">
                            <i class="fas fa-star me-1"></i>Feedback
                        </a>
                    </li>
                </ul>
                
                <ul class="navbar-nav">
                    <li class="nav-item dropdown">
                        <a class="nav-link dropdown-toggle" href="#" id="navbarDropdown" role="button" data-bs-toggle="dropdown">
                            <i class="fas fa-user-md me-1"></i><?php echo htmlspecialchars($doctor_name); ?>
                        </a>
                        <ul class="dropdown-menu">
                            <li><a class="dropdown-item" href="profile.php"><i class="fas fa-user me-2"></i>Profile</a></li>
                            <li><hr class="dropdown-divider"></li>
                            <li><a class="dropdown-item" href="logout.php"><i class="fas fa-sign-out-alt me-2"></i>Logout</a></li>
                        </ul>
                    </li>
                </ul>
            </div>
        </div>
    </nav>
    
    <!-- Main Content -->
    <div class="main-content">
        <div class="container">
            <!-- Page Header -->
            <div class="page-header">
                <div class="row align-items-center">
                    <div class="col-md-8">
                        <h1 class="mb-2"><i class="fas fa-star me-3"></i>Patient Feedback</h1>
                        <p class="mb-0 opacity-75">View and analyze feedback from your patients</p>
                    </div>
                    <div class="col-md-4 text-end">
                        <i class="fas fa-comments" style="font-size: 4rem; opacity: 0.3;"></i>
                    </div>
                </div>
            </div>
            
            <!-- Statistics Cards -->
            <div class="row mb-4">
                <div class="col-md-3 mb-3">
                    <div class="stats-card">
                        <div class="stats-number"><?php echo number_format($stats['total_feedback']); ?></div>
                        <div class="stats-label">Total Reviews</div>
                    </div>
                </div>
                <div class="col-md-3 mb-3">
                    <div class="stats-card">
                        <div class="stats-number"><?php echo number_format($stats['average_rating'], 1); ?></div>
                        <div class="stats-label">Average Rating</div>
                        <div class="mt-2"><?php echo generateStarRating(round($stats['average_rating'])); ?></div>
                    </div>
                </div>
                <div class="col-md-3 mb-3">
                    <div class="stats-card">
                        <div class="stats-number"><?php echo $recent_count; ?></div>
                        <div class="stats-label">This Week</div>
                    </div>
                </div>
                <div class="col-md-3 mb-3">
                    <div class="stats-card">
                        <div class="stats-number"><?php echo $stats['total_feedback'] > 0 ? round(($stats['five_star'] / $stats['total_feedback']) * 100) : 0; ?>%</div>
                        <div class="stats-label">5-Star Reviews</div>
                    </div>
                </div>
            </div>
            
            <!-- Rating Breakdown -->
            <?php if ($stats['total_feedback'] > 0): ?>
                <div class="content-card">
                    <h3 class="mb-4"><i class="fas fa-chart-bar me-2"></i>Rating Breakdown</h3>
                    <div class="rating-breakdown">
                        <?php for ($i = 5; $i >= 1; $i--): ?>
                            <?php 
                            $count = $stats[$i == 5 ? 'five_star' : ($i == 4 ? 'four_star' : ($i == 3 ? 'three_star' : ($i == 2 ? 'two_star' : 'one_star')))];
                            $percentage = $stats['total_feedback'] > 0 ? ($count / $stats['total_feedback']) * 100 : 0;
                            ?>
                            <div class="rating-bar">
                                <span class="me-2"><?php echo $i; ?> <i class="fas fa-star text-warning"></i></span>
                                <div class="rating-bar-bg">
                                    <div class="rating-bar-fill" style="width: <?php echo $percentage; ?>%"></div>
                                </div>
                                <span class="ms-2"><?php echo $count; ?> (<?php echo round($percentage, 1); ?>%)</span>
                            </div>
                        <?php endfor; ?>
                    </div>
                </div>
            <?php endif; ?>
            
            <!-- Filters -->
            <div class="content-card">
                <div class="filters-section">
                    <form method="GET" class="row g-3">
                        <div class="col-md-3">
                            <label for="rating" class="form-label">Filter by Rating</label>
                            <select class="form-select" id="rating" name="rating">
                                <option value="">All Ratings</option>
                                <?php for ($i = 5; $i >= 1; $i--): ?>
                                    <option value="<?php echo $i; ?>" <?php echo $rating_filter == $i ? 'selected' : ''; ?>>
                                        <?php echo $i; ?> Star<?php echo $i > 1 ? 's' : ''; ?>
                                    </option>
                                <?php endfor; ?>
                            </select>
                        </div>
                        <div class="col-md-3">
                            <label for="date_filter" class="form-label">Filter by Date</label>
                            <select class="form-select" id="date_filter" name="date_filter">
                                <option value="">All Time</option>
                                <option value="today" <?php echo $date_filter == 'today' ? 'selected' : ''; ?>>Today</option>
                                <option value="week" <?php echo $date_filter == 'week' ? 'selected' : ''; ?>>This Week</option>
                                <option value="month" <?php echo $date_filter == 'month' ? 'selected' : ''; ?>>This Month</option>
                            </select>
                        </div>
                        <div class="col-md-3">
                            <label class="form-label">&nbsp;</label>
                            <div class="d-grid">
                                <button type="submit" class="btn btn-primary">
                                    <i class="fas fa-filter me-1"></i>Apply Filters
                                </button>
                            </div>
                        </div>
                        <div class="col-md-3">
                            <label class="form-label">&nbsp;</label>
                            <div class="d-grid">
                                <a href="feedback.php" class="btn btn-secondary">
                                    <i class="fas fa-times me-1"></i>Clear
                                </a>
                            </div>
                        </div>
                    </form>
                </div>
            </div>
            
            <!-- Feedback List -->
            <div class="content-card">
                <div class="d-flex justify-content-between align-items-center mb-4">
                    <h3><i class="fas fa-comments me-2"></i>Patient Reviews (<?php echo $total_feedback; ?>)</h3>
                </div>
                
                <?php if (empty($feedback_list)): ?>
                    <div class="no-feedback">
                        <i class="fas fa-star" style="font-size: 4rem; color: #ccc;"></i>
                        <h4 class="mt-3 text-muted">No feedback found</h4>
                        <p class="text-muted">
                            <?php if (!empty($rating_filter) || !empty($date_filter)): ?>
                                Try adjusting your filter criteria.
                            <?php else: ?>
                                Patient feedback will appear here once they leave reviews after appointments.
                            <?php endif; ?>
                        </p>
                    </div>
                <?php else: ?>
                    <?php foreach ($feedback_list as $feedback): ?>
                        <div class="feedback-card">
                            <div class="feedback-header">
                                <div class="patient-info">
                                    <div class="patient-avatar">
                                        <?php echo strtoupper(substr($feedback['patient_name'], 0, 1)); ?>
                                    </div>
                                    <div>
                                        <h6 class="mb-1"><?php echo htmlspecialchars($feedback['patient_name']); ?></h6>
                                        <small class="text-muted"><?php echo htmlspecialchars($feedback['patient_email']); ?></small>
                                    </div>
                                </div>
                                <div class="text-end">
                                    <div class="rating-display mb-1">
                                        <?php echo generateStarRating($feedback['rating']); ?>
                                    </div>
                                    <small class="text-muted">
                                        <i class="fas fa-calendar me-1"></i><?php echo formatDateTime($feedback['created_at']); ?>
                                    </small>
                                </div>
                            </div>
                            
                            <?php if (!empty($feedback['feedback_text'])): ?>
                                <div class="feedback-text">
                                    <i class="fas fa-quote-left me-2 text-muted"></i>
                                    <?php echo nl2br(htmlspecialchars($feedback['feedback_text'])); ?>
                                </div>
                            <?php endif; ?>
                        </div>
                    <?php endforeach; ?>
                    
                    <!-- Pagination -->
                    <?php if ($total_pages > 1): ?>
                        <nav aria-label="Feedback pagination">
                            <ul class="pagination justify-content-center">
                                <?php if ($page > 1): ?>
                                    <li class="page-item">
                                        <a class="page-link" href="?page=<?php echo $page - 1; ?>&rating=<?php echo urlencode($rating_filter); ?>&date_filter=<?php echo urlencode($date_filter); ?>">
                                            <i class="fas fa-chevron-left"></i>
                                        </a>
                                    </li>
                                <?php endif; ?>
                                
                                <?php for ($i = max(1, $page - 2); $i <= min($total_pages, $page + 2); $i++): ?>
                                    <li class="page-item <?php echo $i == $page ? 'active' : ''; ?>">
                                        <a class="page-link" href="?page=<?php echo $i; ?>&rating=<?php echo urlencode($rating_filter); ?>&date_filter=<?php echo urlencode($date_filter); ?>">
                                            <?php echo $i; ?>
                                        </a>
                                    </li>
                                <?php endfor; ?>
                                
                                <?php if ($page < $total_pages): ?>
                                    <li class="page-item">
                                        <a class="page-link" href="?page=<?php echo $page + 1; ?>&rating=<?php echo urlencode($rating_filter); ?>&date_filter=<?php echo urlencode($date_filter); ?>">
                                            <i class="fas fa-chevron-right"></i>
                                        </a>
                                    </li>
                                <?php endif; ?>
                            </ul>
                        </nav>
                    <?php endif; ?>
                <?php endif; ?>
            </div>
        </div>
    </div>
    
    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js"></script>
</body>
</html>