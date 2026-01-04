-- Create extensions
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- Indexes for performance
CREATE INDEX IF NOT EXISTS idx_package_name ON package(name);
CREATE INDEX IF NOT EXISTS idx_package_os_version ON package(os_version);
CREATE INDEX IF NOT EXISTS idx_package_severity ON package(severity);
CREATE INDEX IF NOT EXISTS idx_cve_id ON cve(cve_id);
CREATE INDEX IF NOT EXISTS idx_package_cve_package ON package_cve(package_id);
CREATE INDEX IF NOT EXISTS idx_package_cve_cve ON package_cve(cve_id);

-- Sample CVE data
INSERT INTO cve (cve_id, cvss_score, cvss_vector, description, published_date, severity) VALUES
('CVE-2024-0646', 9.1, 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N', 
 'An out-of-bounds memory write flaw was found in the Linux kernel''s Transport Layer Security functionality.', 
 '2024-01-15', 'Critical'),
 
('CVE-2024-21626', 8.6, 'CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:H',
 'A vulnerability was found in runc allowing a container breakout through process.cwd trickery.',
 '2024-01-31', 'Critical'),

('CVE-2024-0727', 7.5, 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H',
 'Processing a maliciously formatted PKCS12 file may lead OpenSSL to crash leading to a potential Denial of Service attack.',
 '2024-02-26', 'Important'),

('CVE-2024-2961', 8.1, 'CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H',
 'The iconv() function in the GNU C Library may overflow the output buffer passed to it by up to 4 bytes.',
 '2024-04-17', 'Important'),

('CVE-2024-3094', 6.5, 'CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:C/C:N/I:N/A:H',
 'A vulnerability was found in systemd-resolved that allows privilege escalation through DNS spoofing.',
 '2024-05-03', 'Moderate');

-- Sample package data
INSERT INTO package (name, version, architecture, os_version, advisory, release_date, severity, size, sha256, package_type) VALUES
('kernel', '4.18.0-513.24.1.el8_9', 'x86_64', 'ol8.10', 'ELSA-2024-0897', '2024-02-20', 'Critical', '52.4 MB', 
 'a1b2c3d4e5f6789012345678901234567890123456789012345678901234567890', 'rpm'),
 
('openssl', '1.1.1k-12.el8_9', 'x86_64', 'ol8.10', 'ELSA-2024-1234', '2024-03-10', 'Important', '1.8 MB',
 'b2c3d4e5f67890123456789012345678901234567890123456789012345678901', 'rpm'),

('glibc', '2.28-251.el8_10', 'x86_64', 'ol8.10', 'ELSA-2024-2567', '2024-04-15', 'Important', '3.7 MB',
 'c3d4e5f678901234567890123456789012345678901234567890123456789012', 'rpm'),

('systemd', '239-82.el8_10', 'x86_64', 'ol8.10', 'ELSA-2024-3456', '2024-05-20', 'Moderate', '4.2 MB',
 'd4e5f6789012345678901234567890123456789012345678901234567890123', 'rpm');

-- Link packages to CVEs
INSERT INTO package_cve (package_id, cve_id) VALUES
(1, 1), (1, 2),  -- kernel has CVE-2024-0646 and CVE-2024-21626
(2, 3),          -- openssl has CVE-2024-0727
(3, 4),          -- glibc has CVE-2024-2961
(4, 5);          -- systemd has CVE-2024-3094

-- Add dependencies
INSERT INTO dependency (package_id, dependency_name) VALUES
(1, 'kernel-core'), (1, 'kernel-modules'), (1, 'linux-firmware'),
(2, 'openssl-libs'), (2, 'ca-certificates'),
(3, 'glibc-common'), (3, 'glibc-langpack-en'),
(4, 'systemd-libs'), (4, 'systemd-pam'), (4, 'dbus');
