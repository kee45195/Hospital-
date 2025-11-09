-- ===========================
-- Reception / Availability patch (idempotent)
-- ===========================

-- 1) Receptionists
CREATE TABLE IF NOT EXISTS receptionists (
    id INT AUTO_INCREMENT PRIMARY KEY,
    name VARCHAR(100) NOT NULL,
    email VARCHAR(100) UNIQUE NOT NULL,
    password VARCHAR(255) NOT NULL,
    phone VARCHAR(15) NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
);

-- 2) Appointments: extend status enum
ALTER TABLE appointments 
    MODIFY COLUMN status ENUM('Pending', 'Confirmed', 'Completed', 'Cancelled', 'Rejected') DEFAULT 'Pending';

-- 3) Doctor availability
DROP TABLE IF EXISTS doctor_availability;
CREATE TABLE doctor_availability (
    id INT AUTO_INCREMENT PRIMARY KEY,
    doctor_id INT NOT NULL,
    available_day ENUM('Monday', 'Tuesday', 'Wednesday', 'Thursday', 'Friday', 'Saturday', 'Sunday') NOT NULL,
    start_time TIME NOT NULL,
    end_time TIME NOT NULL,
    is_active BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    CONSTRAINT fk_doctor_availability_doctor
        FOREIGN KEY (doctor_id) REFERENCES doctors(id) ON DELETE CASCADE,
    UNIQUE KEY unique_doctor_day_time (doctor_id, available_day, start_time)
);

-- 4) Indexes (drop if exist to avoid duplicate-key errors)
-- Note: IF EXISTS is supported in MySQL 8.0+. If you're on 5.7, remove IF EXISTS and ignore 'can't drop' warnings.

-- appointments.status
DROP INDEX IF EXISTS idx_appointments_status ON appointments;
CREATE INDEX idx_appointments_status ON appointments(status);

-- appointments.appointment_date
-- (You might already have idx_appointment_date from the base schema; this uses a distinct name.)
DROP INDEX IF EXISTS idx_appointments_date ON appointments;
CREATE INDEX idx_appointments_date ON appointments(appointment_date);

-- doctor_availability indexes
DROP INDEX IF EXISTS idx_doctor_availability_doctor ON doctor_availability;
CREATE INDEX idx_doctor_availability_doctor ON doctor_availability(doctor_id);

DROP INDEX IF EXISTS idx_doctor_availability_day ON doctor_availability;
CREATE INDEX idx_doctor_availability_day ON doctor_availability(available_day);
