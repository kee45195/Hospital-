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

// Handle content update
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['update_content'])) {
    $section = isset($_POST['section']) ? $_POST['section'] : '';
    // Allow empty content (to clear a section)
    $content = isset($_POST['content']) ? trim($_POST['content']) : '';

    if (empty($section)) {
        $error_message = 'Section is required.';
    } else {
        try {
            // Check if section exists
            $stmt = $pdo->prepare("SELECT id FROM site_content WHERE section = ?");
            $stmt->execute([$section]);
            $existing = $stmt->fetch();

            if ($existing) {
                // Update existing content (can be empty string)
                $stmt = $pdo->prepare("UPDATE site_content SET content = ?, updated_at = NOW() WHERE section = ?");
                $stmt->execute([$content, $section]);
            } else {
                // Insert new content (can be empty string)
                $stmt = $pdo->prepare("INSERT INTO site_content (section, content) VALUES (?, ?)");
                $stmt->execute([$section, $content]);
            }

            $success_message = 'Content updated successfully!';
        } catch (PDOException $e) {
            $error_message = 'Error updating content: ' . $e->getMessage();
        }
    }
}

// Get all site content
try {
    $stmt = $pdo->prepare("SELECT * FROM site_content ORDER BY section");
    $stmt->execute();
    $site_contents = $stmt->fetchAll();

    // Convert to associative array for easier access
    $content_data = [];
    foreach ($site_contents as $content) {
        // store raw value; we’ll decide visibility based on non-empty below
        $content_data[$content['section']] = $content['content'];
    }
} catch (PDOException $e) {
    $content_data = [];
    $error_message = 'Error loading content data.';
}

// Helper: only count sections that actually have non-empty content
$non_empty_content = array_filter(
    $content_data,
    function ($v) {
        return trim((string)$v) !== '';
    }
);
$sections_with_content = count($non_empty_content);
$total_sections        = 8; // keep in sync with $sections below
$empty_sections        = $total_sections - $sections_with_content;
$total_chars           = array_sum(array_map('strlen', $non_empty_content));

// Define available sections
$sections = [
    'about_us' => [
        'title' => 'About Us',
        'description' => 'Information about the hospital, mission, and values',
        'icon' => 'fas fa-info-circle'
    ],
    'contact_info' => [
        'title' => 'Contact Information',
        'description' => 'Hospital address, phone numbers, and contact details',
        'icon' => 'fas fa-phone'
    ],
    'services' => [
        'title' => 'Our Services',
        'description' => 'List of medical services and specialties offered',
        'icon' => 'fas fa-stethoscope'
    ],
    'announcements' => [
        'title' => 'Hospital Announcements',
        'description' => 'Important notices and updates for patients',
        'icon' => 'fas fa-bullhorn'
    ],
    'emergency_info' => [
        'title' => 'Emergency Information',
        'description' => 'Emergency contact numbers and procedures',
        'icon' => 'fas fa-exclamation-triangle'
    ],
    'visiting_hours' => [
        'title' => 'Visiting Hours',
        'description' => 'Patient visiting hours and guidelines',
        'icon' => 'fas fa-clock'
    ],
    'insurance_info' => [
        'title' => 'Insurance Information',
        'description' => 'Accepted insurance plans and payment information',
        'icon' => 'fas fa-shield-alt'
    ],
    'privacy_policy' => [
        'title' => 'Privacy Policy',
        'description' => 'Patient privacy and data protection policy',
        'icon' => 'fas fa-user-shield'
    ]
];
$total_sections = count($sections); // ensure correctness if you add sections later
$empty_sections = $total_sections - $sections_with_content;
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Content Management - <?php echo APP_NAME; ?></title>
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

        .content-card {
            background: white;
            border-radius: 15px;
            padding: 30px;
            box-shadow: 0 4px 6px rgba(0, 0, 0, 0.05);
            border: none;
            margin-bottom: 20px;
        }

        .section-card {
            background: white;
            border-radius: 15px;
            padding: 25px;
            box-shadow: 0 4px 6px rgba(0, 0, 0, 0.05);
            border: none;
            margin-bottom: 20px;
            transition: transform 0.3s;
        }

        .section-card:hover {
            transform: translateY(-2px);
        }

        .section-icon {
            font-size: 2rem;
            color: var(--accent-color);
            margin-bottom: 15px;
        }

        .btn-primary {
            background-color: var(--primary-color);
            border-color: var(--primary-color);
        }

        .btn-primary:hover {
            background-color: #1D4ED8;
            border-color: #1D4ED8;
        }

        .content-preview {
            background-color: #F8FAFC;
            border-radius: 10px;
            padding: 15px;
            margin-top: 15px;
            border-left: 4px solid var(--primary-color);
        }

        .char-counter {
            font-size: 0.8rem;
            color: #6B7280;
        }
           .logo { padding: 20px; text-align: center; border-bottom: 1px solid #475569; margin-bottom: 20px; }
        .logo h4 { color: #fff; margin: 0; }
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
            <a class="nav-link" href="profile.php">
                <i class="fas fa-user"></i>Profile
            </a>
            <a class="nav-link" href="users.php">
                <i class="fas fa-users"></i>User Accounts
            </a>
            <a class="nav-link" href="reports.php">
                <i class="fas fa-chart-bar"></i>Reports
            </a>
            <a class="nav-link" href="specializations.php"><i class="fas fa-building"></i>Specializations</a>
            <a class="nav-link" href="departments.php"><i class="fas fa-building"></i>Departments</a>
            <a class="nav-link active" href="content.php">
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
                <h3 class="mb-0"><i class="fas fa-edit me-2"></i>Content Management</h3>
            </div>
            <div>
                <span class="badge bg-light text-dark">
                    <i class="fas fa-globe me-1"></i>Website Content
                </span>
            </div>
        </div>

        <!-- Content Area -->
        <div class="content-area">
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

            <!-- Content Sections Grid -->
            <div class="row">
                <?php foreach ($sections as $section_key => $section_info): ?>
                    <div class="col-lg-6 col-xl-4 mb-4">
                        <div class="section-card h-100">
                            <div class="text-center">
                                <div class="section-icon">
                                    <i class="<?php echo $section_info['icon']; ?>"></i>
                                </div>
                                <h5 class="mb-2"><?php echo $section_info['title']; ?></h5>
                                <p class="text-muted small mb-3"><?php echo $section_info['description']; ?></p>
                            </div>

                            <?php
                                // Show preview only if content exists AND is non-empty after trim
                                $has_non_empty = array_key_exists($section_key, $content_data) && trim((string)$content_data[$section_key]) !== '';
                            ?>
                            <?php if ($has_non_empty): ?>
                                <div class="content-preview">
                                    <small class="text-muted d-block mb-1">Current Content:</small>
                                    <div class="small">
                                        <?php
                                            $snippet = substr($content_data[$section_key], 0, 100);
                                            echo htmlspecialchars($snippet) . (strlen($content_data[$section_key]) > 100 ? '...' : '');
                                        ?>
                                    </div>
                                </div>
                            <?php else: ?>
                                <div class="text-center text-muted">
                                    <i class="fas fa-plus-circle fa-2x mb-2"></i>
                                    <p class="small">No content added yet</p>
                                </div>
                            <?php endif; ?>

                            <div class="text-center mt-3">
                                <button class="btn btn-primary btn-sm"
                                        onclick="editContent('<?php echo $section_key; ?>', '<?php echo addslashes($section_info['title']); ?>')">
                                    <i class="fas fa-edit me-1"></i>Edit Content
                                </button>
                            </div>
                        </div>
                    </div>
                <?php endforeach; ?>
            </div>

            <!-- Quick Stats -->
            <div class="row mt-4">
                <div class="col-12">
                    <div class="content-card">
                        <h5 class="mb-4"><i class="fas fa-chart-bar me-2"></i>Content Statistics</h5>
                        <div class="row text-center">
                            <div class="col-md-3">
                                <div class="stat-item">
                                    <h3 class="text-primary"><?php echo $sections_with_content; ?></h3>
                                    <p class="text-muted mb-0">Sections with Content</p>
                                </div>
                            </div>
                            <div class="col-md-3">
                                <div class="stat-item">
                                    <h3 class="text-accent"><?php echo $empty_sections; ?></h3>
                                    <p class="text-muted mb-0">Empty Sections</p>
                                </div>
                            </div>
                            <div class="col-md-3">
                                <div class="stat-item">
                                    <h3 class="text-success">
                                        <?php echo $total_chars; ?>
                                    </h3>
                                    <p class="text-muted mb-0">Total Characters</p>
                                </div>
                            </div>
                            <div class="col-md-3">
                                <div class="stat-item">
                                    <h3 class="text-info"><?php echo $total_sections; ?></h3>
                                    <p class="text-muted mb-0">Total Sections</p>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    </div>

    <!-- Edit Content Modal -->
    <div class="modal fade" id="editContentModal" tabindex="-1">
        <div class="modal-dialog modal-lg">
            <div class="modal-content">
                <form method="POST" action="">
                    <div class="modal-header">
                        <h5 class="modal-title"><i class="fas fa-edit me-2"></i>Edit Content</h5>
                        <button type="button" class="btn-close" data-bs-dismiss="modal"></button>
                    </div>
                    <div class="modal-body">
                        <input type="hidden" id="edit_section" name="section">

                        <div class="mb-3">
                            <label for="edit_content" class="form-label">Content</label>
                            <textarea class="form-control" id="edit_content" name="content" rows="10"
                                      placeholder="Enter the content for this section... (leave blank to clear)"></textarea>
                            <div class="d-flex justify-content-between mt-1">
                                <small class="text-muted">You can use HTML tags for formatting</small>
                                <span class="char-counter" id="charCounter">0 characters</span>
                            </div>
                        </div>

                        <div class="alert alert-info">
                            <i class="fas fa-info-circle me-2"></i>
                            <strong>Formatting Tips:</strong>
                            <ul class="mb-0 mt-2">
                                <li>Use &lt;br&gt; for line breaks</li>
                                <li>Use &lt;strong&gt; for bold text</li>
                                <li>Use &lt;em&gt; for italic text</li>
                                <li>Use &lt;ul&gt; and &lt;li&gt; for bullet points</li>
                            </ul>
                        </div>
                    </div>
                    <div class="modal-footer">
                        <button type="button" class="btn btn-outline-secondary" data-bs-dismiss="modal">
                            <i class="fas fa-times me-2"></i>Cancel
                        </button>
                        <button type="submit" name="update_content" class="btn btn-primary">
                            <i class="fas fa-save me-2"></i>Save Content
                        </button>
                    </div>
                </form>
            </div>
        </div>
    </div>

    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js"></script>
    <script>
        const contentData = <?php echo json_encode($content_data); ?>;

        function editContent(section, title) {
            document.getElementById('edit_section').value = section;
            document.getElementById('edit_content').value = (contentData[section] ?? '');
            document.querySelector('#editContentModal .modal-title').innerHTML =
                '<i class="fas fa-edit me-2"></i>Edit ' + title;

            updateCharCounter();

            const modal = new bootstrap.Modal(document.getElementById('editContentModal'));
            modal.show();
        }

        function updateCharCounter() {
            const content = document.getElementById('edit_content').value || '';
            document.getElementById('charCounter').textContent = content.length + ' characters';
        }

        document.getElementById('edit_content').addEventListener('input', updateCharCounter);

        // Auto-resize textarea
        document.getElementById('edit_content').addEventListener('input', function() {
            this.style.height = 'auto';
            this.style.height = (this.scrollHeight) + 'px';
        });
    </script>
</body>
</html>
