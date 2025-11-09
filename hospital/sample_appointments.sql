-- Sample appointments to link existing patients with doctors
-- Run this after importing the main database schema

-- Insert sample appointments for existing patients
INSERT IGNORE INTO appointments (patient_id, doctor_id, appointment_date, appointment_time, status, notes) VALUES
(1, 1, '2024-01-15', '09:00:00', 'Completed', 'Regular checkup'),
(2, 1, '2024-01-16', '10:30:00', 'Completed', 'Follow-up consultation'),
(1, 2, '2024-01-18', '11:00:00', 'Completed', 'Dermatology consultation'),
(2, 1, '2024-01-25', '15:30:00', 'Confirmed', 'Upcoming appointment'),
(3, 1, '2024-01-26', '09:30:00', 'Confirmed', 'Routine checkup'),
(1, 3, '2024-02-01', '14:00:00', 'Pending', 'Orthopedic consultation'),
(3, 2, '2024-02-02', '16:00:00', 'Pending', 'Skin examination');

-- Update appointment dates to current/future dates
UPDATE appointments SET 
    appointment_date = CASE 
        WHEN status = 'Completed' THEN DATE_SUB(CURDATE(), INTERVAL FLOOR(RAND() * 30) DAY)
        WHEN status = 'Confirmed' THEN DATE_ADD(CURDATE(), INTERVAL FLOOR(RAND() * 7) + 1 DAY)
        WHEN status = 'Pending' THEN DATE_ADD(CURDATE(), INTERVAL FLOOR(RAND() * 14) + 7 DAY)
        ELSE appointment_date
    END
WHERE id > 0;