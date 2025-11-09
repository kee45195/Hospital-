-- Doctor Side Hospital Management System Database Schema
-- Additional tables for doctor functionality

-- Add password column to doctors table if it doesn't exist
ALTER TABLE doctors ADD COLUMN IF NOT EXISTS password VARCHAR(255) DEFAULT NULL;
ALTER TABLE doctors ADD COLUMN IF NOT EXISTS phone VARCHAR(15) DEFAULT NULL;
ALTER TABLE doctors ADD COLUMN IF NOT EXISTS bio TEXT DEFAULT NULL;

-- Update existing doctors with passwords and phone numbers
UPDATE doctors SET 
    password = '$2y$10$92IXUNpkjO0rOQ5byMi.Ye4oKoEa3Ro9llC/.og/at2.uheWG/igi', -- password: 'password'
    phone = contact
WHERE password IS NULL;

-- Table: doctor_availability
CREATE TABLE doctor_availability (
    id INT AUTO_INCREMENT PRIMARY KEY,
    doctor_id INT NOT NULL,
    available_day ENUM('Monday', 'Tuesday', 'Wednesday', 'Thursday', 'Friday', 'Saturday', 'Sunday') NOT NULL,
    start_time TIME NOT NULL,
    end_time TIME NOT NULL,
    is_active BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    FOREIGN KEY (doctor_id) REFERENCES doctors(id) ON DELETE CASCADE,
    UNIQUE KEY unique_doctor_day_time (doctor_id, available_day, start_time)
);

-- Table: feedback
CREATE TABLE feedback (
    id INT AUTO_INCREMENT PRIMARY KEY,
    patient_id INT NOT NULL,
    doctor_id INT NOT NULL,
    appointment_id INT DEFAULT NULL,
    feedback_text TEXT NOT NULL,
    rating INT NOT NULL CHECK (rating >= 1 AND rating <= 5),
    feedback_date DATE NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    FOREIGN KEY (patient_id) REFERENCES patients(id) ON DELETE CASCADE,
    FOREIGN KEY (doctor_id) REFERENCES doctors(id) ON DELETE CASCADE,
    FOREIGN KEY (appointment_id) REFERENCES appointments(id) ON DELETE SET NULL
);

-- Add indexes for better performance
CREATE INDEX idx_doctor_availability_doctor ON doctor_availability(doctor_id);
CREATE INDEX idx_doctor_availability_day ON doctor_availability(available_day);
CREATE INDEX idx_feedback_doctor ON feedback(doctor_id);
CREATE INDEX idx_feedback_patient ON feedback(patient_id);
CREATE INDEX idx_feedback_rating ON feedback(rating);
CREATE INDEX idx_feedback_date ON feedback(feedback_date);

-- Create a view for doctor statistics
CREATE VIEW doctor_stats AS
SELECT 
    d.id,
    d.name,
    d.specialization,
    COUNT(DISTINCT a.id) as total_appointments,
    COUNT(DISTINCT CASE WHEN a.status = 'Completed' THEN a.id END) as completed_appointments,
    COUNT(DISTINCT CASE WHEN a.appointment_date >= CURDATE() THEN a.id END) as upcoming_appointments,
    COUNT(DISTINCT f.id) as total_feedback,
    ROUND(AVG(f.rating), 1) as average_rating
FROM doctors d
LEFT JOIN appointments a ON d.id = a.doctor_id
LEFT JOIN feedback f ON d.id = f.doctor_id
GROUP BY d.id, d.name, d.specialization;

-- Create a view for doctor schedule
CREATE VIEW doctor_schedule AS
SELECT 
    a.id,
    a.appointment_date,
    a.appointment_time,
    a.status,
    a.notes,
    d.name AS doctor_name,
    p.name AS patient_name,
    p.phone AS patient_phone,
    p.email AS patient_email
FROM appointments a
JOIN doctors d ON a.doctor_id = d.id
JOIN patients p ON a.patient_id = p.id
ORDER BY a.appointment_date DESC, a.appointment_time DESC;