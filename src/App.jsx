import React, { useState, useEffect } from 'react';
import { Shield, AlertTriangle, Users, Clock, Target, Award, ChevronRight, Zap, Database, Lock, Wifi, Mail, Server } from 'lucide-react';

const CybersecurityGame = () => {
  const [gameState, setGameState] = useState('setup'); // setup, playing, gameOver
  const [players, setPlayers] = useState([]);
  const [currentRound, setCurrentRound] = useState(1);
  const [maxRounds] = useState(8);
  const [organizationHealth, setOrganizationHealth] = useState(100);
  const [securityScore, setSecurityScore] = useState(0);
  const [currentIncident, setCurrentIncident] = useState(null);
  const [timerSeconds, setTimerSeconds] = useState(90);
  const [isTimerActive, setIsTimerActive] = useState(false);
  const [usedIncidents, setUsedIncidents] = useState([]);
  const [eventLog, setEventLog] = useState([]);

  const roles = [
    { id: 'ciso', name: 'CISO', icon: Shield, color: 'bg-purple-500', description: 'Security strategy & policy' },
    { id: 'analyst', name: 'Security Analyst', icon: Target, color: 'bg-blue-500', description: 'Threat detection & analysis' },
    { id: 'engineer', name: 'Security Engineer', icon: Lock, color: 'bg-green-500', description: 'Technical controls & hardening' },
    { id: 'responder', name: 'Incident Responder', icon: Zap, color: 'bg-red-500', description: 'Emergency response & recovery' },
    { id: 'admin', name: 'System Admin', icon: Server, color: 'bg-yellow-500', description: 'Infrastructure & operations' },
    { id: 'developer', name: 'Dev Team Lead', icon: Database, color: 'bg-indigo-500', description: 'Secure development & patching' },
    { id: 'neteng', name: 'Network Engineer', icon: Wifi, color: 'bg-cyan-500', description: 'Network security & monitoring' },
    { id: 'user', name: 'User Education', icon: Mail, color: 'bg-pink-500', description: 'Training & awareness' }
  ];

  const incidents = [
    {
      id: 1,
      title: 'Phishing Campaign Detected',
      category: 'Social Engineering',
      severity: 'medium',
      description: 'Multiple employees received convincing phishing emails claiming to be from IT.',
      impact: 15,
      timeLimit: 90,
      responses: [
        { text: 'Block sender domains immediately', roles: ['analyst', 'neteng'], success: 70, damage: 5 },
        { text: 'Send organization-wide warning', roles: ['user', 'ciso'], success: 85, damage: 8 },
        { text: 'Isolate affected accounts', roles: ['admin', 'responder'], success: 90, damage: 10 },
        { text: 'Implement email authentication', roles: ['engineer', 'neteng'], success: 95, damage: 3 }
      ]
    },
    {
      id: 2,
      title: 'Ransomware on File Server',
      category: 'Malware',
      severity: 'critical',
      description: 'Encryption detected on a critical file server. Ransom note demands payment.',
      impact: 30,
      timeLimit: 60,
      responses: [
        { text: 'Isolate infected systems immediately', roles: ['responder', 'admin'], success: 95, damage: 15 },
        { text: 'Restore from last backup', roles: ['admin', 'engineer'], success: 80, damage: 20 },
        { text: 'Negotiate with attackers', roles: ['ciso'], success: 30, damage: 30 },
        { text: 'Wipe and rebuild systems', roles: ['admin', 'engineer'], success: 85, damage: 25 }
      ]
    },
    {
      id: 3,
      title: 'SQL Injection Vulnerability',
      category: 'Application Security',
      severity: 'high',
      description: 'Penetration test reveals SQL injection in customer portal allowing data extraction.',
      impact: 20,
      timeLimit: 90,
      responses: [
        { text: 'Deploy emergency patch', roles: ['developer', 'engineer'], success: 90, damage: 5 },
        { text: 'Take application offline', roles: ['ciso', 'admin'], success: 95, damage: 15 },
        { text: 'Implement WAF rules', roles: ['engineer', 'neteng'], success: 75, damage: 10 },
        { text: 'Review all input validation', roles: ['developer', 'analyst'], success: 85, damage: 8 }
      ]
    },
    {
      id: 4,
      title: 'Insider Threat Suspected',
      category: 'Insider Risk',
      severity: 'high',
      description: 'Unusual data access patterns from privileged account during non-business hours.',
      impact: 25,
      timeLimit: 75,
      responses: [
        { text: 'Suspend account immediately', roles: ['ciso', 'admin'], success: 85, damage: 20 },
        { text: 'Review access logs thoroughly', roles: ['analyst', 'responder'], success: 80, damage: 15 },
        { text: 'Engage HR and legal', roles: ['ciso'], success: 70, damage: 12 },
        { text: 'Implement privileged access monitoring', roles: ['engineer', 'analyst'], success: 90, damage: 10 }
      ]
    },
    {
      id: 5,
      title: 'DDoS Attack in Progress',
      category: 'Network Attack',
      severity: 'high',
      description: 'Website experiencing massive traffic spike. Services degrading rapidly.',
      impact: 20,
      timeLimit: 45,
      responses: [
        { text: 'Enable DDoS mitigation service', roles: ['neteng', 'admin'], success: 90, damage: 8 },
        { text: 'Block attacking IP ranges', roles: ['neteng', 'engineer'], success: 60, damage: 15 },
        { text: 'Scale infrastructure', roles: ['admin', 'engineer'], success: 70, damage: 12 },
        { text: 'Engage ISP for upstream filtering', roles: ['neteng', 'ciso'], success: 85, damage: 10 }
      ]
    },
    {
      id: 6,
      title: 'Unpatched Critical Vulnerability',
      category: 'Vulnerability Management',
      severity: 'critical',
      description: 'Zero-day exploit announced for software used across organization. Active exploitation in the wild.',
      impact: 35,
      timeLimit: 60,
      responses: [
        { text: 'Emergency patching campaign', roles: ['admin', 'engineer'], success: 85, damage: 10 },
        { text: 'Disable affected service', roles: ['ciso', 'admin'], success: 95, damage: 20 },
        { text: 'Implement compensating controls', roles: ['engineer', 'neteng'], success: 75, damage: 15 },
        { text: 'Hunt for indicators of compromise', roles: ['analyst', 'responder'], success: 80, damage: 25 }
      ]
    },
    {
      id: 7,
      title: 'Data Breach Discovered',
      category: 'Data Security',
      severity: 'critical',
      description: 'Customer data found for sale on dark web. Breach timeline unclear.',
      impact: 40,
      timeLimit: 90,
      responses: [
        { text: 'Activate incident response plan', roles: ['ciso', 'responder'], success: 95, damage: 20 },
        { text: 'Notify customers immediately', roles: ['ciso', 'user'], success: 85, damage: 25 },
        { text: 'Engage forensics team', roles: ['analyst', 'responder'], success: 90, damage: 15 },
        { text: 'Begin regulatory notifications', roles: ['ciso'], success: 80, damage: 30 }
      ]
    },
    {
      id: 8,
      title: 'Compromised Admin Credentials',
      category: 'Access Control',
      severity: 'critical',
      description: 'Domain admin credentials leaked in credential dump. Potential for full network compromise.',
      impact: 35,
      timeLimit: 45,
      responses: [
        { text: 'Force password reset all admins', roles: ['admin', 'ciso'], success: 95, damage: 15 },
        { text: 'Revoke all active sessions', roles: ['admin', 'engineer'], success: 90, damage: 12 },
        { text: 'Enable MFA immediately', roles: ['engineer', 'admin'], success: 85, damage: 10 },
        { text: 'Hunt for unauthorized access', roles: ['analyst', 'responder'], success: 88, damage: 20 }
      ]
    },
    {
      id: 9,
      title: 'Supply Chain Attack',
      category: 'Third Party Risk',
      severity: 'high',
      description: 'Trusted vendor compromised. Their software update contains backdoor.',
      impact: 25,
      timeLimit: 75,
      responses: [
        { text: 'Block vendor updates immediately', roles: ['admin', 'engineer'], success: 90, damage: 10 },
        { text: 'Audit vendor access', roles: ['analyst', 'ciso'], success: 85, damage: 15 },
        { text: 'Rollback to previous version', roles: ['admin', 'developer'], success: 80, damage: 18 },
        { text: 'Scan for IOCs across environment', roles: ['analyst', 'responder'], success: 88, damage: 12 }
      ]
    },
    {
      id: 10,
      title: 'Misconfigured Cloud Storage',
      category: 'Cloud Security',
      severity: 'high',
      description: 'Public S3 bucket discovered containing sensitive internal documents.',
      impact: 22,
      timeLimit: 60,
      responses: [
        { text: 'Make bucket private immediately', roles: ['admin', 'engineer'], success: 95, damage: 8 },
        { text: 'Audit all cloud resources', roles: ['engineer', 'analyst'], success: 85, damage: 15 },
        { text: 'Implement cloud security policies', roles: ['engineer', 'ciso'], success: 90, damage: 10 },
        { text: 'Investigate data exposure', roles: ['analyst', 'responder'], success: 80, damage: 18 }
      ]
    },
    {
      id: 11,
      title: 'Credential Stuffing Attack',
      category: 'Authentication',
      severity: 'medium',
      description: 'Automated login attempts using leaked credentials from other breaches.',
      impact: 18,
      timeLimit: 90,
      responses: [
        { text: 'Implement rate limiting', roles: ['engineer', 'neteng'], success: 85, damage: 5 },
        { text: 'Force password resets', roles: ['admin', 'user'], success: 80, damage: 12 },
        { text: 'Deploy CAPTCHA', roles: ['developer', 'engineer'], success: 90, damage: 7 },
        { text: 'Enable account monitoring', roles: ['analyst', 'engineer'], success: 88, damage: 8 }
      ]
    },
    {
      id: 12,
      title: 'IoT Device Botnet',
      category: 'IoT Security',
      severity: 'medium',
      description: 'Office smart devices compromised and participating in botnet activities.',
      impact: 15,
      timeLimit: 75,
      responses: [
        { text: 'Isolate IoT network segment', roles: ['neteng', 'admin'], success: 90, damage: 5 },
        { text: 'Reset all IoT devices', roles: ['admin', 'engineer'], success: 85, damage: 10 },
        { text: 'Update firmware', roles: ['engineer', 'admin'], success: 80, damage: 8 },
        { text: 'Implement IoT security policy', roles: ['ciso', 'neteng'], success: 88, damage: 6 }
      ]
    }
  ];
// Additional 50 OWASP Security Incidents for CyberDefense Game
// Add these to the incidents array in App.jsx

{
  id: 13,
  title: 'API Authentication Bypass',
  category: 'API Security',
  severity: 'critical',
  description: 'REST API discovered accepting requests without proper authentication tokens.',
  impact: 30,
  timeLimit: 60,
  responses: [
    { text: 'Implement OAuth 2.0 immediately', roles: ['developer', 'engineer'], success: 90, damage: 8 },
    { text: 'Add API gateway with authentication', roles: ['engineer', 'neteng'], success: 85, damage: 12 },
    { text: 'Disable public API endpoints', roles: ['ciso', 'admin'], success: 95, damage: 20 },
    { text: 'Deploy rate limiting and monitoring', roles: ['analyst', 'engineer'], success: 80, damage: 15 }
  ]
},
{
  id: 14,
  title: 'Cross-Site Scripting (XSS) Attack',
  category: 'Application Security',
  severity: 'high',
  description: 'Malicious JavaScript injected into web application stealing user session cookies.',
  impact: 22,
  timeLimit: 75,
  responses: [
    { text: 'Deploy Content Security Policy', roles: ['developer', 'engineer'], success: 88, damage: 8 },
    { text: 'Sanitize all user inputs', roles: ['developer'], success: 85, damage: 12 },
    { text: 'Invalidate all active sessions', roles: ['admin', 'engineer'], success: 90, damage: 15 },
    { text: 'Enable XSS protection headers', roles: ['engineer', 'neteng'], success: 82, damage: 10 }
  ]
},
{
  id: 15,
  title: 'Unencrypted Database Backup Exposed',
  category: 'Data Security',
  severity: 'critical',
  description: 'Full database backup found on public FTP server containing customer PII.',
  impact: 35,
  timeLimit: 45,
  responses: [
    { text: 'Remove backup and secure FTP immediately', roles: ['admin', 'engineer'], success: 95, damage: 10 },
    { text: 'Enable encryption for all backups', roles: ['engineer', 'admin'], success: 90, damage: 15 },
    { text: 'Audit all backup locations', roles: ['analyst', 'responder'], success: 85, damage: 20 },
    { text: 'Begin breach notification procedures', roles: ['ciso'], success: 80, damage: 30 }
  ]
},
{
  id: 16,
  title: 'Privilege Escalation Exploit',
  category: 'Access Control',
  severity: 'critical',
  description: 'Standard user discovered way to gain admin privileges through URL manipulation.',
  impact: 28,
  timeLimit: 60,
  responses: [
    { text: 'Patch authorization checks', roles: ['developer', 'engineer'], success: 92, damage: 8 },
    { text: 'Implement role-based access control', roles: ['engineer', 'ciso'], success: 88, damage: 12 },
    { text: 'Audit all user permissions', roles: ['admin', 'analyst'], success: 85, damage: 15 },
    { text: 'Add privilege escalation monitoring', roles: ['analyst', 'engineer'], success: 80, damage: 10 }
  ]
},
{
  id: 17,
  title: 'Cryptojacking Malware Detected',
  category: 'Malware',
  severity: 'medium',
  description: 'Cryptocurrency mining software found running on multiple workstations.',
  impact: 15,
  timeLimit: 90,
  responses: [
    { text: 'Quarantine infected systems', roles: ['admin', 'responder'], success: 90, damage: 5 },
    { text: 'Deploy endpoint detection and response', roles: ['engineer', 'analyst'], success: 85, damage: 8 },
    { text: 'Block mining pool domains', roles: ['neteng', 'engineer'], success: 88, damage: 6 },
    { text: 'Scan entire network for IOCs', roles: ['analyst', 'responder'], success: 82, damage: 12 }
  ]
},
{
  id: 18,
  title: 'Session Hijacking Attack',
  category: 'Authentication',
  severity: 'high',
  description: 'Attacker captured session tokens over unencrypted WiFi and accessing user accounts.',
  impact: 24,
  timeLimit: 60,
  responses: [
    { text: 'Force HTTPS on all connections', roles: ['engineer', 'neteng'], success: 95, damage: 6 },
    { text: 'Invalidate all sessions and reset tokens', roles: ['admin', 'developer'], success: 90, damage: 12 },
    { text: 'Implement session timeout controls', roles: ['developer', 'engineer'], success: 85, damage: 10 },
    { text: 'Enable certificate pinning', roles: ['engineer', 'developer'], success: 80, damage: 15 }
  ]
},
{
  id: 19,
  title: 'XML External Entity (XXE) Injection',
  category: 'Application Security',
  severity: 'high',
  description: 'XML parser vulnerability allows reading sensitive files from application server.',
  impact: 26,
  timeLimit: 75,
  responses: [
    { text: 'Disable XML external entity processing', roles: ['developer', 'engineer'], success: 92, damage: 8 },
    { text: 'Update XML parsing libraries', roles: ['developer', 'admin'], success: 88, damage: 12 },
    { text: 'Implement input validation for XML', roles: ['developer'], success: 85, damage: 10 },
    { text: 'Deploy web application firewall rules', roles: ['engineer', 'neteng'], success: 80, damage: 15 }
  ]
},
{
  id: 20,
  title: 'Bluetooth Eavesdropping',
  category: 'Wireless Security',
  severity: 'medium',
  description: 'Unsecured Bluetooth devices in conference rooms allowing audio interception.',
  impact: 18,
  timeLimit: 90,
  responses: [
    { text: 'Disable Bluetooth on all devices', roles: ['admin', 'engineer'], success: 90, damage: 8 },
    { text: 'Implement Bluetooth security policy', roles: ['ciso', 'engineer'], success: 85, damage: 12 },
    { text: 'Deploy Bluetooth monitoring solution', roles: ['neteng', 'analyst'], success: 82, damage: 10 },
    { text: 'Educate users on wireless risks', roles: ['user', 'ciso'], success: 75, damage: 15 }
  ]
},
{
  id: 21,
  title: 'Container Image Vulnerability',
  category: 'DevOps Security',
  severity: 'high',
  description: 'Production Docker containers running with critical vulnerabilities and as root.',
  impact: 25,
  timeLimit: 75,
  responses: [
    { text: 'Rebuild containers with patched base images', roles: ['developer', 'engineer'], success: 90, damage: 10 },
    { text: 'Implement container security scanning', roles: ['engineer', 'developer'], success: 88, damage: 12 },
    { text: 'Run containers as non-root users', roles: ['developer', 'admin'], success: 85, damage: 8 },
    { text: 'Deploy runtime container protection', roles: ['engineer', 'analyst'], success: 80, damage: 15 }
  ]
},
{
  id: 22,
  title: 'DNS Cache Poisoning',
  category: 'Network Attack',
  severity: 'high',
  description: 'DNS server compromised, redirecting users to malicious websites.',
  impact: 27,
  timeLimit: 60,
  responses: [
    { text: 'Flush DNS cache and update servers', roles: ['neteng', 'admin'], success: 92, damage: 10 },
    { text: 'Implement DNSSEC validation', roles: ['neteng', 'engineer'], success: 88, damage: 12 },
    { text: 'Switch to secure DNS providers', roles: ['neteng', 'ciso'], success: 85, damage: 15 },
    { text: 'Monitor DNS queries for anomalies', roles: ['analyst', 'neteng'], success: 80, damage: 18 }
  ]
},
{
  id: 23,
  title: 'Hardcoded Credentials in Code',
  category: 'Secret Management',
  severity: 'critical',
  description: 'Database passwords and API keys found hardcoded in public GitHub repository.',
  impact: 32,
  timeLimit: 45,
  responses: [
    { text: 'Rotate all exposed credentials immediately', roles: ['admin', 'developer'], success: 95, damage: 12 },
    { text: 'Remove secrets from repository history', roles: ['developer', 'ciso'], success: 88, damage: 15 },
    { text: 'Implement secrets management vault', roles: ['engineer', 'developer'], success: 90, damage: 10 },
    { text: 'Scan all repositories for secrets', roles: ['analyst', 'developer'], success: 85, damage: 20 }
  ]
},
{
  id: 24,
  title: 'Business Email Compromise (BEC)',
  category: 'Social Engineering',
  severity: 'high',
  description: 'CFO impersonation email requesting wire transfer to fraudulent account.',
  impact: 28,
  timeLimit: 75,
  responses: [
    { text: 'Verify request through separate channel', roles: ['ciso', 'user'], success: 95, damage: 5 },
    { text: 'Block sender and similar domains', roles: ['analyst', 'neteng'], success: 90, damage: 8 },
    { text: 'Implement email authentication (DMARC)', roles: ['engineer', 'neteng'], success: 88, damage: 12 },
    { text: 'Train staff on BEC tactics', roles: ['user', 'ciso'], success: 80, damage: 25 }
  ]
},
{
  id: 25,
  title: 'Outdated Web Framework Exploit',
  category: 'Vulnerability Management',
  severity: 'critical',
  description: 'Critical remote code execution vulnerability in legacy web framework version.',
  impact: 33,
  timeLimit: 60,
  responses: [
    { text: 'Apply emergency security patches', roles: ['developer', 'admin'], success: 90, damage: 12 },
    { text: 'Upgrade framework to latest version', roles: ['developer', 'engineer'], success: 85, damage: 15 },
    { text: 'Isolate vulnerable applications', roles: ['admin', 'neteng'], success: 92, damage: 10 },
    { text: 'Implement virtual patching via WAF', roles: ['engineer', 'neteng'], success: 82, damage: 18 }
  ]
},
{
  id: 26,
  title: 'Shadow IT Discovery',
  category: 'Governance',
  severity: 'medium',
  description: 'Unapproved cloud services discovered processing customer data without security review.',
  impact: 20,
  timeLimit: 90,
  responses: [
    { text: 'Inventory and assess all shadow IT', roles: ['ciso', 'analyst'], success: 85, damage: 10 },
    { text: 'Block unapproved cloud services', roles: ['neteng', 'engineer'], success: 80, damage: 15 },
    { text: 'Implement cloud access security broker', roles: ['engineer', 'ciso'], success: 88, damage: 8 },
    { text: 'Create approved SaaS list and policy', roles: ['ciso', 'user'], success: 82, damage: 12 }
  ]
},
{
  id: 27,
  title: 'API Rate Limit Abuse',
  category: 'API Security',
  severity: 'medium',
  description: 'Automated scraping tools overwhelming API endpoints and extracting data.',
  impact: 18,
  timeLimit: 75,
  responses: [
    { text: 'Implement aggressive rate limiting', roles: ['engineer', 'developer'], success: 90, damage: 6 },
    { text: 'Require API authentication tokens', roles: ['developer', 'engineer'], success: 88, damage: 10 },
    { text: 'Deploy CAPTCHA for suspicious requests', roles: ['developer', 'engineer'], success: 85, damage: 8 },
    { text: 'Block IP ranges of scrapers', roles: ['neteng', 'analyst'], success: 80, damage: 12 }
  ]
},
{
  id: 28,
  title: 'Watering Hole Attack',
  category: 'Advanced Threats',
  severity: 'high',
  description: 'Industry news site frequented by employees compromised with malware.',
  impact: 26,
  timeLimit: 60,
  responses: [
    { text: 'Block compromised domain immediately', roles: ['neteng', 'analyst'], success: 92, damage: 10 },
    { text: 'Scan endpoints for infection', roles: ['responder', 'analyst'], success: 88, damage: 15 },
    { text: 'Implement URL filtering and sandboxing', roles: ['engineer', 'neteng'], success: 85, damage: 12 },
    { text: 'Issue security advisory to staff', roles: ['user', 'ciso'], success: 80, damage: 18 }
  ]
},
{
  id: 29,
  title: 'Insecure Deserialization',
  category: 'Application Security',
  severity: 'critical',
  description: 'Application deserializes untrusted data allowing remote code execution.',
  impact: 30,
  timeLimit: 60,
  responses: [
    { text: 'Disable unsafe deserialization', roles: ['developer', 'engineer'], success: 92, damage: 8 },
    { text: 'Implement input validation and signing', roles: ['developer'], success: 88, damage: 12 },
    { text: 'Update serialization libraries', roles: ['developer', 'admin'], success: 85, damage: 15 },
    { text: 'Deploy runtime application protection', roles: ['engineer', 'analyst'], success: 80, damage: 18 }
  ]
},
{
  id: 30,
  title: 'VPN Credential Stuffing',
  category: 'Authentication',
  severity: 'high',
  description: 'Thousands of login attempts to VPN using leaked credentials from other breaches.',
  impact: 24,
  timeLimit: 75,
  responses: [
    { text: 'Enable multi-factor authentication', roles: ['engineer', 'admin'], success: 95, damage: 6 },
    { text: 'Implement account lockout policies', roles: ['admin', 'engineer'], success: 90, damage: 10 },
    { text: 'Deploy anomaly detection for logins', roles: ['analyst', 'engineer'], success: 85, damage: 12 },
    { text: 'Force password resets for all users', roles: ['admin', 'user'], success: 88, damage: 15 }
  ]
},
{
  id: 31,
  title: 'Certificate Expiration Crisis',
  category: 'PKI Management',
  severity: 'high',
  description: 'Critical SSL/TLS certificates expired, breaking customer-facing applications.',
  impact: 25,
  timeLimit: 45,
  responses: [
    { text: 'Renew certificates immediately', roles: ['admin', 'engineer'], success: 95, damage: 18 },
    { text: 'Implement automated certificate management', roles: ['engineer', 'admin'], success: 90, damage: 12 },
    { text: 'Deploy certificate monitoring', roles: ['engineer', 'analyst'], success: 85, damage: 15 },
    { text: 'Update certificate inventory', roles: ['admin', 'analyst'], success: 80, damage: 20 }
  ]
},
{
  id: 32,
  title: 'USB Rubber Ducky Attack',
  category: 'Physical Security',
  severity: 'high',
  description: 'Malicious USB device found in parking lot executed payload when plugged in.',
  impact: 22,
  timeLimit: 60,
  responses: [
    { text: 'Isolate compromised workstation', roles: ['responder', 'admin'], success: 95, damage: 8 },
    { text: 'Disable USB ports organization-wide', roles: ['admin', 'engineer'], success: 85, damage: 15 },
    { text: 'Deploy USB device control policy', roles: ['engineer', 'ciso'], success: 90, damage: 10 },
    { text: 'Train staff on physical security', roles: ['user', 'ciso'], success: 80, damage: 18 }
  ]
},
{
  id: 33,
  title: 'Server-Side Request Forgery (SSRF)',
  category: 'Application Security',
  severity: 'high',
  description: 'Application can be tricked into making requests to internal systems.',
  impact: 26,
  timeLimit: 75,
  responses: [
    { text: 'Validate and sanitize all URLs', roles: ['developer', 'engineer'], success: 90, damage: 10 },
    { text: 'Implement network segmentation', roles: ['neteng', 'engineer'], success: 88, damage: 12 },
    { text: 'Whitelist allowed destination hosts', roles: ['developer', 'engineer'], success: 85, damage: 8 },
    { text: 'Deploy egress filtering', roles: ['neteng', 'engineer'], success: 82, damage: 15 }
  ]
},
{
  id: 34,
  title: 'Rogue Access Point',
  category: 'Wireless Security',
  severity: 'high',
  description: 'Unauthorized WiFi access point broadcasting corporate SSID in office.',
  impact: 23,
  timeLimit: 60,
  responses: [
    { text: 'Locate and disable rogue AP', roles: ['neteng', 'admin'], success: 92, damage: 8 },
    { text: 'Deploy wireless intrusion detection', roles: ['neteng', 'engineer'], success: 88, damage: 12 },
    { text: 'Implement 802.1X authentication', roles: ['neteng', 'engineer'], success: 85, damage: 10 },
    { text: 'Conduct wireless site survey', roles: ['neteng', 'analyst'], success: 80, damage: 15 }
  ]
},
{
  id: 35,
  title: 'Log4Shell Vulnerability',
  category: 'Vulnerability Management',
  severity: 'critical',
  description: 'Log4j vulnerability detected in multiple Java applications allowing RCE.',
  impact: 35,
  timeLimit: 45,
  responses: [
    { text: 'Patch Log4j to safe version immediately', roles: ['developer', 'admin'], success: 92, damage: 10 },
    { text: 'Disable JNDI lookup functionality', roles: ['engineer', 'admin'], success: 88, damage: 12 },
    { text: 'Deploy WAF rules to block exploits', roles: ['engineer', 'neteng'], success: 85, damage: 15 },
    { text: 'Scan for exploitation attempts', roles: ['analyst', 'responder'], success: 90, damage: 20 }
  ]
},
{
  id: 36,
  title: 'OAuth Token Leakage',
  category: 'Authentication',
  severity: 'high',
  description: 'OAuth access tokens exposed in browser history and server logs.',
  impact: 24,
  timeLimit: 75,
  responses: [
    { text: 'Revoke all exposed tokens', roles: ['developer', 'admin'], success: 95, damage: 8 },
    { text: 'Implement token rotation policy', roles: ['developer', 'engineer'], success: 90, damage: 10 },
    { text: 'Remove tokens from logs', roles: ['admin', 'analyst'], success: 88, damage: 12 },
    { text: 'Use authorization code flow with PKCE', roles: ['developer', 'engineer'], success: 85, damage: 15 }
  ]
},
{
  id: 37,
  title: 'Malicious Browser Extension',
  category: 'Endpoint Security',
  severity: 'medium',
  description: 'Popular browser extension updated to steal credentials and session data.',
  impact: 20,
  timeLimit: 90,
  responses: [
    { text: 'Block extension via browser policy', roles: ['admin', 'engineer'], success: 92, damage: 6 },
    { text: 'Reset credentials for affected users', roles: ['admin', 'user'], success: 88, damage: 12 },
    { text: 'Implement extension whitelist policy', roles: ['ciso', 'engineer'], success: 85, damage: 10 },
    { text: 'Scan for data exfiltration', roles: ['analyst', 'responder'], success: 80, damage: 15 }
  ]
},
{
  id: 38,
  title: 'GraphQL API Injection',
  category: 'API Security',
  severity: 'high',
  description: 'GraphQL endpoint vulnerable to query injection exposing sensitive data.',
  impact: 25,
  timeLimit: 75,
  responses: [
    { text: 'Implement query complexity limits', roles: ['developer', 'engineer'], success: 90, damage: 10 },
    { text: 'Add input validation and sanitization', roles: ['developer'], success: 88, damage: 12 },
    { text: 'Deploy GraphQL-aware WAF', roles: ['engineer', 'neteng'], success: 85, damage: 8 },
    { text: 'Disable introspection in production', roles: ['developer', 'engineer'], success: 82, damage: 15 }
  ]
},
{
  id: 39,
  title: 'Printer Security Breach',
  category: 'IoT Security',
  severity: 'medium',
  description: 'Network printers compromised, storing copies of sensitive documents.',
  impact: 18,
  timeLimit: 90,
  responses: [
    { text: 'Isolate printers to separate VLAN', roles: ['neteng', 'admin'], success: 90, damage: 8 },
    { text: 'Update printer firmware and passwords', roles: ['admin', 'engineer'], success: 88, damage: 10 },
    { text: 'Disable printer hard drive storage', roles: ['admin', 'engineer'], success: 85, damage: 6 },
    { text: 'Implement secure print release', roles: ['engineer', 'user'], success: 82, damage: 12 }
  ]
},
{
  id: 40,
  title: 'Time-of-Check Time-of-Use (TOCTOU)',
  category: 'Application Security',
  severity: 'high',
  description: 'Race condition in payment processing allows unauthorized transactions.',
  impact: 27,
  timeLimit: 60,
  responses: [
    { text: 'Implement atomic transactions', roles: ['developer', 'engineer'], success: 92, damage: 12 },
    { text: 'Add pessimistic locking mechanism', roles: ['developer'], success: 88, damage: 10 },
    { text: 'Deploy transaction monitoring', roles: ['analyst', 'developer'], success: 85, damage: 15 },
    { text: 'Rollback fraudulent transactions', roles: ['admin', 'responder'], success: 90, damage: 20 }
  ]
},
{
  id: 41,
  title: 'Zoom Bombing Attack',
  category: 'Collaboration Security',
  severity: 'low',
  description: 'Unauthorized participants disrupting virtual meetings with offensive content.',
  impact: 12,
  timeLimit: 90,
  responses: [
    { text: 'Enable waiting room for all meetings', roles: ['user', 'admin'], success: 95, damage: 3 },
    { text: 'Require meeting passwords', roles: ['admin', 'user'], success: 90, damage: 5 },
    { text: 'Disable screen sharing for participants', roles: ['user', 'ciso'], success: 88, damage: 4 },
    { text: 'Train staff on meeting security', roles: ['user', 'ciso'], success: 85, damage: 8 }
  ]
},
{
  id: 42,
  title: 'Typosquatting Attack',
  category: 'Social Engineering',
  severity: 'medium',
  description: 'Fake domain similar to company website collecting employee credentials.',
  impact: 19,
  timeLimit: 75,
  responses: [
    { text: 'Register similar domain variations', roles: ['ciso', 'admin'], success: 85, damage: 10 },
    { text: 'Report to domain registrar and authorities', roles: ['ciso', 'analyst'], success: 80, damage: 12 },
    { text: 'Deploy domain monitoring service', roles: ['analyst', 'engineer'], success: 88, damage: 8 },
    { text: 'Warn employees about fake site', roles: ['user', 'ciso'], success: 90, damage: 15 }
  ]
},
{
  id: 43,
  title: 'IPv6 Tunneling Bypass',
  category: 'Network Attack',
  severity: 'high',
  description: 'Attackers using IPv6 tunnels to bypass firewall rules and filters.',
  impact: 24,
  timeLimit: 60,
  responses: [
    { text: 'Block unauthorized IPv6 traffic', roles: ['neteng', 'engineer'], success: 90, damage: 10 },
    { text: 'Implement IPv6 firewall rules', roles: ['neteng', 'engineer'], success: 88, damage: 12 },
    { text: 'Deploy IPv6 traffic monitoring', roles: ['neteng', 'analyst'], success: 85, damage: 8 },
    { text: 'Disable IPv6 if not needed', roles: ['neteng', 'ciso'], success: 92, damage: 15 }
  ]
},
{
  id: 44,
  title: 'Firmware Backdoor Discovery',
  category: 'Hardware Security',
  severity: 'critical',
  description: 'Undocumented backdoor found in network equipment firmware.',
  impact: 32,
  timeLimit: 60,
  responses: [
    { text: 'Replace compromised hardware', roles: ['admin', 'neteng'], success: 90, damage: 20 },
    { text: 'Update to vendor-patched firmware', roles: ['admin', 'engineer'], success: 88, damage: 15 },
    { text: 'Isolate affected devices', roles: ['neteng', 'admin'], success: 95, damage: 12 },
    { text: 'Implement network segmentation', roles: ['neteng', 'engineer'], success: 85, damage: 18 }
  ]
},
{
  id: 45,
  title: 'Clipboard Hijacking Malware',
  category: 'Malware',
  severity: 'medium',
  description: 'Malware intercepting clipboard to replace cryptocurrency wallet addresses.',
  impact: 17,
  timeLimit: 75,
  responses: [
    { text: 'Deploy endpoint detection and removal', roles: ['responder', 'admin'], success: 92, damage: 6 },
    { text: 'Educate users on clipboard risks', roles: ['user', 'ciso'], success: 85, damage: 10 },
    { text: 'Implement application whitelisting', roles: ['engineer', 'admin'], success: 88, damage: 8 },
    { text: 'Monitor for suspicious processes', roles: ['analyst', 'responder'], success: 80, damage: 12 }
  ]
},
{
  id: 46,
  title: 'LDAP Injection Attack',
  category: 'Application Security',
  severity: 'high',
  description: 'Directory service queries vulnerable to injection, exposing user information.',
  impact: 23,
  timeLimit: 75,
  responses: [
    { text: 'Sanitize LDAP query inputs', roles: ['developer', 'engineer'], success: 90, damage: 8 },
    { text: 'Use parameterized LDAP queries', roles: ['developer'], success: 88, damage: 10 },
    { text: 'Implement least privilege for LDAP access', roles: ['admin', 'engineer'], success: 85, damage: 12 },
    { text: 'Deploy LDAP query monitoring', roles: ['analyst', 'engineer'], success: 82, damage: 15 }
  ]
},
{
  id: 47,
  title: 'Deepfake Voice Phishing',
  category: 'Social Engineering',
  severity: 'high',
  description: 'AI-generated voice of CEO used in phone call requesting urgent fund transfer.',
  impact: 26,
  timeLimit: 60,
  responses: [
    { text: 'Verify through alternate communication channel', roles: ['ciso', 'user'], success: 95, damage: 5 },
    { text: 'Implement voice authentication system', roles: ['engineer', 'ciso'], success: 85, damage: 15 },
    { text: 'Establish verification protocols', roles: ['ciso', 'user'], success: 90, damage: 10 },
    { text: 'Train staff on deepfake threats', roles: ['user', 'ciso'], success: 88, damage: 20 }
  ]
},
{
  id: 48,
  title: 'WebSocket Security Flaw',
  category: 'Application Security',
  severity: 'medium',
  description: 'Real-time WebSocket connections lacking proper authentication and encryption.',
  impact: 20,
  timeLimit: 90,
  responses: [
    { text: 'Implement WebSocket authentication', roles: ['developer', 'engineer'], success: 90, damage: 8 },
    { text: 'Enable WSS (WebSocket over TLS)', roles: ['engineer', 'neteng'], success: 92, damage: 6 },
    { text: 'Add origin validation', roles: ['developer', 'engineer'], success: 88, damage: 10 },
    { text: 'Deploy WebSocket rate limiting', roles: ['engineer', 'developer'], success: 85, damage: 12 }
  ]
},
{
  id: 49,
  title: 'Memory Scraping POS Malware',
  category: 'Malware',
  severity: 'critical',
  description: 'Point-of-sale systems infected with RAM scraper stealing credit card data.',
  impact: 34,
  timeLimit: 45,
  responses: [
    { text: 'Isolate infected POS systems immediately', roles: ['responder', 'admin'], success: 95, damage: 15 },
    { text: 'Deploy endpoint protection on POS', roles: ['engineer', 'admin'], success: 90, damage: 18 },
    { text: 'Implement point-to-point encryption', roles: ['engineer', 'ciso'], success: 88, damage: 12 },
    { text: 'Begin forensic investigation', roles: ['analyst', 'responder'], success: 85, damage: 25 }
  ]
},
{
  id: 50,
  title: 'Kubernetes Misconfiguration',
  category: 'Cloud Security',
  severity: 'critical',
  description: 'Kubernetes dashboard exposed to internet with default credentials.',
  impact: 30,
  timeLimit: 60,
  responses: [
    { text: 'Restrict dashboard access immediately', roles: ['engineer', 'admin'], success: 95, damage: 10 },
    { text: 'Implement RBAC and authentication', roles: ['engineer', 'developer'], success: 90, damage: 12 },
    { text: 'Audit all Kubernetes configurations', roles: ['analyst', 'engineer'], success: 88, damage: 15 },
    { text: 'Deploy Kubernetes security policies', roles: ['engineer', 'ciso'], success: 85, damage: 18 }
  ]
},
{
  id: 51,
  title: 'SMS Phishing (Smishing)',
  category: 'Social Engineering',
  severity: 'medium',
  description: 'Employees receiving fake IT support texts requesting credential verification.',
  impact: 16,
  timeLimit: 90,
  responses: [
    { text: 'Issue company-wide smishing alert', roles: ['user', 'ciso'], success: 90, damage: 5 },
    { text: 'Block sender phone numbers', roles: ['admin', 'neteng'], success: 85, damage: 10 },
    { text: 'Implement SMS authentication warnings', roles: ['engineer', 'user'], success: 88, damage: 8 },
    { text: 'Train employees on SMS threats', roles: ['user', 'ciso'], success: 82, damage: 12 }
  ]
},
{
  id: 52,
  title: 'Subdomain Takeover',
  category: 'DNS Security',
  severity: 'high',
  description: 'Abandoned subdomain pointing to deleted cloud service now serving malicious content.',
  impact: 25,
  timeLimit: 75,
  responses: [
    { text: 'Remove DNS records for subdomain', roles: ['neteng', 'admin'], success: 95, damage: 8 },
    { text: 'Audit all DNS records', roles: ['neteng', 'analyst'], success: 90, damage: 12 },
    { text: 'Reclaim cloud service instance', roles: ['admin', 'engineer'], success: 88, damage: 10 },
    { text: 'Implement DNS monitoring', roles: ['neteng', 'analyst'], success: 85, damage: 15 }
  ]
},
{
  id: 53,
  title: 'Formjacking Attack',
  category: 'Web Security',
  severity: 'critical',
  description: 'Malicious JavaScript injected into payment forms stealing credit card details.',
  impact: 31,
  timeLimit: 60,
  responses: [
    { text: 'Remove malicious code immediately', roles: ['developer', 'responder'], success: 95, damage: 12 },
    { text: 'Implement Content Security Policy', roles: ['developer', 'engineer'], success: 90, damage: 10 },
    { text: 'Deploy Subresource Integrity checks', roles: ['developer', 'engineer'], success: 88, damage: 15 },
    { text: 'Notify affected customers', roles: ['ciso', 'user'], success: 85, damage: 25 }
  ]
},
{
  id: 54,
  title: 'BGP Hijacking Incident',
  category: 'Network Attack',
  severity: 'critical',
  description: 'Border Gateway Protocol routes hijacked, redirecting traffic through attacker infrastructure.',
  impact: 33,
  timeLimit: 45,
  responses: [
    { text: 'Contact ISP to restore correct routes', roles: ['neteng', 'ciso'], success: 90, damage: 20 },
    { text: 'Implement RPKI validation', roles: ['neteng', 'engineer'], success: 85, damage: 18 },
    { text: 'Monitor BGP announcements', roles: ['neteng', 'analyst'], success: 88, damage: 15 },
    { text: 'Enable BGP authentication', roles: ['neteng', 'engineer'], success: 82, damage: 22 }
  ]
},
{
  id: 55,
  title: 'CI/CD Pipeline Compromise',
  category: 'DevOps Security',
  severity: 'critical',
  description: 'Build pipeline credentials stolen, allowing code injection into production deployments.',
  impact: 35,
  timeLimit: 60,
  responses: [
    { text: 'Rotate all pipeline credentials', roles: ['developer', 'admin'], success: 95, damage: 12 },
    { text: 'Audit recent deployments for tampering', roles: ['developer', 'analyst'], success: 90, damage: 18 },
    { text: 'Implement pipeline security scanning', roles: ['engineer', 'developer'], success: 88, damage: 15 },
    { text: 'Enable code signing verification', roles: ['developer', 'engineer'], success: 85, damage: 20 }
  ]
},
{
  id: 56,
  title: 'Juice Jacking at Conference',
  category: 'Physical Security',
  severity: 'medium',
  description: 'Compromised USB charging stations at industry event installing malware on devices.',
  impact: 19,
  timeLimit: 75,
  responses: [
    { text: 'Warn employees about threat', roles: ['user', 'ciso'], success: 90, damage: 8 },
    { text: 'Scan devices used at conference', roles: ['responder', 'admin'], success: 88, damage: 12 },
    { text: 'Distribute USB data blockers', roles: ['admin', 'ciso'], success: 85, damage: 10 },
    { text: 'Implement mobile device management', roles: ['engineer', 'admin'], success: 82, damage: 15 }
  ]
},
{
  id: 57,
  title: 'Open Redirect Exploitation',
  category: 'Application Security',
  severity: 'medium',
  description: 'URL redirect vulnerability used in phishing to make malicious links look legitimate.',
  impact: 17,
  timeLimit: 90,
  responses: [
    { text: 'Validate and whitelist redirect targets', roles: ['developer', 'engineer'], success: 92, damage: 6 },
    { text: 'Remove open redirect functionality', roles: ['developer'], success: 88, damage: 8 },
    { text: 'Implement redirect warnings', roles: ['developer', 'user'], success: 85, damage: 10 },
    { text: 'Block phishing campaign URLs', roles: ['neteng', 'analyst'], success: 90, damage: 12 }
  ]
},
{
  id: 58,
  title: 'Malicious npm Package',
  category: 'Supply Chain',
  severity: 'high',
  description: 'Popular dependency updated with cryptocurrency miner and credential stealer.',
  impact: 27,
  timeLimit: 60,
  responses: [
    { text: 'Remove malicious package version', roles: ['developer', 'admin'], success: 95, damage: 10 },
    { text: 'Scan codebase for compromise', roles: ['developer', 'analyst'], success: 90, damage: 15 },
    { text: 'Implement package integrity checks', roles: ['engineer', 'developer'], success: 88, damage: 12 },
    { text: 'Pin dependency versions', roles: ['developer', 'engineer'], success: 85, damage: 18 }
  ]
},
{
  id: 59,
  title: 'RFID Skimming Attack',
  category: 'Physical Security',
  severity: 'medium',
  description: 'Unauthorized RFID readers cloning employee access badges in parking structure.',
  impact: 18,
  timeLimit: 75,
  responses: [
    { text: 'Deactivate compromised badges', roles: ['admin', 'ciso'], success: 92, damage: 8 },
    { text: 'Issue RFID-blocking badge holders', roles: ['admin', 'ciso'], success: 88, damage: 10 },
    { text: 'Upgrade to encrypted access cards', roles: ['engineer', 'admin'], success: 85, damage: 12 },
    { text: 'Add secondary authentication factor', roles: ['engineer', 'ciso'], success: 90, damage: 6 }
  ]
},
{
  id: 60,
  title: 'HTTP Request Smuggling',
  category: 'Web Security',
  severity: 'high',
  description: 'Request smuggling vulnerability bypassing security controls and cache poisoning.',
  impact: 24,
  timeLimit: 75,
  responses: [
    { text: 'Update web server and proxy configs', roles: ['engineer', 'neteng'], success: 90, damage: 10 },
    { text: 'Normalize HTTP request handling', roles: ['engineer', 'developer'], success: 88, damage: 12 },
    { text: 'Deploy HTTP/2 exclusively', roles: ['engineer', 'neteng'], success: 85, damage: 8 },
    { text: 'Implement strict request validation', roles: ['engineer', 'developer'], success: 82, damage: 15 }
  ]
},
{
  id: 61,
  title: 'Leaked Zoom Recording',
  category: 'Data Leakage',
  severity: 'high',
  description: 'Sensitive executive strategy meeting recording found publicly accessible online.',
  impact: 26,
  timeLimit: 60,
  responses: [
    { text: 'Remove recording from all locations', roles: ['admin', 'ciso'], success: 92, damage: 15 },
    { text: 'Disable auto-recording feature', roles: ['admin', 'user'], success: 88, damage: 10 },
    { text: 'Implement DLP for cloud storage', roles: ['engineer', 'ciso'], success: 85, damage: 12 },
    { text: 'Review access permissions', roles: ['admin', 'analyst'], success: 90, damage: 18 }
  ]
},
{
  id: 62,
  title: 'SIM Swapping Attack',
  category: 'Social Engineering',
  severity: 'high',
  description: 'Executive phone number ported to attacker SIM card, compromising 2FA.',
  impact: 28,
  timeLimit: 60,
  responses: [
    { text: 'Contact carrier to reverse SIM swap', roles: ['ciso', 'admin'], success: 90, damage: 15 },
    { text: 'Switch from SMS to app-based 2FA', roles: ['engineer', 'admin'], success: 95, damage: 8 },
    { text: 'Reset all account credentials', roles: ['admin', 'responder'], success: 88, damage: 20 },
    { text: 'Enable carrier port-out protection', roles: ['ciso', 'admin'], success: 85, damage: 12 }
  ]
}
  useEffect(() => {
    if (isTimerActive && timerSeconds > 0) {
      const timer = setTimeout(() => {
        setTimerSeconds(timerSeconds - 1);
      }, 1000);
      return () => clearTimeout(timer);
    } else if (isTimerActive && timerSeconds === 0) {
      handleTimeout();
    }
  }, [timerSeconds, isTimerActive]);

  const startGame = () => {
    if (players.length < 6) {
      alert('Need at least 6 players to start!');
      return;
    }
    setGameState('playing');
    drawNewIncident();
    addToLog('Game started! Organization under threat...');
  };

  const addPlayer = (roleId) => {
    const role = roles.find(r => r.id === roleId);
    const playerName = prompt(`Enter name for ${role.name}:`);
    if (playerName) {
      setPlayers([...players, { ...role, playerName, actionsThisRound: 0 }]);
    }
  };

  const removePlayer = (index) => {
    setPlayers(players.filter((_, i) => i !== index));
  };

  const drawNewIncident = () => {
    const availableIncidents = incidents.filter(i => !usedIncidents.includes(i.id));
    if (availableIncidents.length === 0) {
      endGame('victory');
      return;
    }
    const randomIncident = availableIncidents[Math.floor(Math.random() * availableIncidents.length)];
    setCurrentIncident(randomIncident);
    setTimerSeconds(randomIncident.timeLimit);
    setIsTimerActive(true);
    setUsedIncidents([...usedIncidents, randomIncident.id]);
    addToLog(`Round ${currentRound}: ${randomIncident.title} - ${randomIncident.category}`);
  };

  const handleResponse = (response) => {
    const playerRoles = players.map(p => p.id);
    const hasRequiredRoles = response.roles.every(role => playerRoles.includes(role));
    
    if (!hasRequiredRoles) {
      alert(`This action requires: ${response.roles.map(r => roles.find(role => role.id === r)?.name).join(', ')}`);
      return;
    }

    const roll = Math.random() * 100;
    const success = roll < response.success;
    
    if (success) {
      setSecurityScore(securityScore + 10);
      setOrganizationHealth(Math.min(100, organizationHealth + 5));
      addToLog(`✓ Success! ${response.text} - Organization health improved`);
    } else {
      const damage = response.damage;
      setOrganizationHealth(organizationHealth - damage);
      addToLog(`✗ Failed! ${response.text} - Took ${damage} damage`);
    }

    setIsTimerActive(false);
    
    if (organizationHealth - (success ? 0 : response.damage) <= 0) {
      endGame('defeat');
    } else if (currentRound >= maxRounds) {
      endGame('victory');
    } else {
      setTimeout(() => {
        setCurrentRound(currentRound + 1);
        drawNewIncident();
      }, 2000);
    }
  };

  const handleTimeout = () => {
    const damage = currentIncident.impact;
    setOrganizationHealth(organizationHealth - damage);
    addToLog(`⏰ Time's up! No action taken - ${damage} damage from ${currentIncident.title}`);
    setIsTimerActive(false);
    
    if (organizationHealth - damage <= 0) {
      endGame('defeat');
    } else if (currentRound >= maxRounds) {
      endGame('victory');
    } else {
      setTimeout(() => {
        setCurrentRound(currentRound + 1);
        drawNewIncident();
      }, 2000);
    }
  };

  const endGame = (result) => {
    setGameState('gameOver');
    setIsTimerActive(false);
    if (result === 'victory') {
      addToLog('🎉 Victory! Organization secured!');
    } else {
      addToLog('💥 Game Over! Organization compromised!');
    }
  };

  const addToLog = (message) => {
    setEventLog(prev => [...prev, { message, timestamp: new Date().toLocaleTimeString() }].slice(-10));
  };

  const resetGame = () => {
    setGameState('setup');
    setPlayers([]);
    setCurrentRound(1);
    setOrganizationHealth(100);
    setSecurityScore(0);
    setCurrentIncident(null);
    setUsedIncidents([]);
    setEventLog([]);
  };

  const getSeverityColor = (severity) => {
    switch(severity) {
      case 'critical': return 'bg-red-600';
      case 'high': return 'bg-orange-500';
      case 'medium': return 'bg-yellow-500';
      default: return 'bg-blue-500';
    }
  };

  if (gameState === 'setup') {
    return (
      <div className="min-h-screen bg-gradient-to-br from-slate-900 via-blue-900 to-slate-900 text-white p-4">
        <div className="max-w-2xl mx-auto">
          <div className="text-center mb-8">
            <Shield className="w-20 h-20 mx-auto mb-4 text-blue-400" />
            <h1 className="text-4xl font-bold mb-2">CyberDefense</h1>
            <p className="text-blue-300">OWASP Tabletop Security Game</p>
          </div>

          <div className="bg-slate-800/50 backdrop-blur rounded-lg p-6 mb-6 border border-blue-500/30">
            <h2 className="text-xl font-bold mb-4 flex items-center gap-2">
              <Users className="w-5 h-5" />
              Team Assembly ({players.length}/8)
            </h2>
            
            {players.length < 6 && (
              <div className="bg-yellow-500/20 border border-yellow-500/50 rounded p-3 mb-4">
                <p className="text-sm text-yellow-200">Need at least 6 players to start</p>
              </div>
            )}

            <div className="space-y-2 mb-4">
              {players.map((player, index) => {
                const RoleIcon = player.icon;
                return (
                  <div key={index} className={`${player.color} rounded p-3 flex items-center justify-between`}>
                    <div className="flex items-center gap-3">
                      <RoleIcon className="w-5 h-5" />
                      <div>
                        <p className="font-semibold">{player.playerName}</p>
                        <p className="text-xs opacity-90">{player.name}</p>
                      </div>
                    </div>
                    <button onClick={() => removePlayer(index)} className="text-white/70 hover:text-white">×</button>
                  </div>
                );
              })}
            </div>

            <div className="grid grid-cols-2 gap-2">
              {roles.filter(role => !players.find(p => p.id === role.id)).map(role => {
                const RoleIcon = role.icon;
                return (
                  <button
                    key={role.id}
                    onClick={() => addPlayer(role.id)}
                    className={`${role.color} hover:opacity-90 rounded p-3 text-left transition-all`}
                  >
                    <div className="flex items-center gap-2 mb-1">
                      <RoleIcon className="w-4 h-4" />
                      <p className="font-semibold text-sm">{role.name}</p>
                    </div>
                    <p className="text-xs opacity-90">{role.description}</p>
                  </button>
                );
              })}
            </div>
          </div>

          <button
            onClick={startGame}
            disabled={players.length < 6}
            className="w-full bg-green-600 hover:bg-green-700 disabled:bg-gray-600 disabled:cursor-not-allowed text-white font-bold py-4 rounded-lg transition-all flex items-center justify-center gap-2"
          >
            <Shield className="w-5 h-5" />
            Start Mission
          </button>

          <div className="mt-6 bg-slate-800/30 rounded-lg p-4 text-sm text-blue-200">
            <h3 className="font-bold mb-2">How to Play:</h3>
            <ul className="space-y-1 list-disc list-inside">
              <li>Work together to respond to security incidents</li>
              <li>Each response requires specific roles</li>
              <li>Choose wisely - success rates and damage vary</li>
              <li>Keep organization health above 0</li>
              <li>Survive {maxRounds} rounds to win!</li>
            </ul>
          </div>
        </div>
      </div>
    );
  }

  if (gameState === 'gameOver') {
    const finalGrade = organizationHealth > 75 ? 'A' : organizationHealth > 50 ? 'B' : organizationHealth > 25 ? 'C' : 'F';
    return (
      <div className="min-h-screen bg-gradient-to-br from-slate-900 via-blue-900 to-slate-900 text-white p-4 flex items-center justify-center">
        <div className="max-w-md w-full bg-slate-800/50 backdrop-blur rounded-lg p-6 border border-blue-500/30">
          <div className="text-center mb-6">
            {organizationHealth > 0 ? (
              <Award className="w-20 h-20 mx-auto mb-4 text-green-400" />
            ) : (
              <AlertTriangle className="w-20 h-20 mx-auto mb-4 text-red-400" />
            )}
            <h1 className="text-3xl font-bold mb-2">
              {organizationHealth > 0 ? 'Mission Complete!' : 'System Compromised'}
            </h1>
          </div>

          <div className="space-y-4 mb-6">
            <div className="bg-slate-700/50 rounded p-4">
              <p className="text-sm text-gray-300 mb-1">Final Health</p>
              <div className="flex items-center gap-3">
                <div className="flex-1 bg-slate-600 rounded-full h-3">
                  <div 
                    className={`h-full rounded-full transition-all ${organizationHealth > 50 ? 'bg-green-500' : organizationHealth > 25 ? 'bg-yellow-500' : 'bg-red-500'}`}
                    style={{width: `${Math.max(0, organizationHealth)}%`}}
                  />
                </div>
                <span className="font-bold text-xl">{Math.max(0, organizationHealth)}%</span>
              </div>
            </div>

            <div className="bg-slate-700/50 rounded p-4">
              <p className="text-sm text-gray-300 mb-1">Security Score</p>
              <p className="text-2xl font-bold text-blue-400">{securityScore}</p>
            </div>

            <div className="bg-slate-700/50 rounded p-4">
              <p className="text-sm text-gray-300 mb-1">Performance Grade</p>
              <p className="text-4xl font-bold text-center">{finalGrade}</p>
            </div>

            <div className="bg-slate-700/50 rounded p-4">
              <p className="text-sm text-gray-300 mb-2">Incidents Handled</p>
              <p className="text-lg font-bold">{currentRound - 1} / {maxRounds}</p>
            </div>
          </div>

          <button
            onClick={resetGame}
            className="w-full bg-blue-600 hover:bg-blue-700 text-white font-bold py-3 rounded-lg transition-all"
          >
            New Game
          </button>
        </div>
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-gradient-to-br from-slate-900 via-blue-900 to-slate-900 text-white p-4 pb-20">
      <div className="max-w-2xl mx-auto">
        {/* Header Stats */}
        <div className="grid grid-cols-3 gap-2 mb-4">
          <div className="bg-slate-800/50 backdrop-blur rounded-lg p-3 border border-blue-500/30">
            <div className="flex items-center gap-2 mb-1">
              <Clock className="w-4 h-4 text-blue-400" />
              <p className="text-xs text-gray-300">Round</p>
            </div>
            <p className="text-xl font-bold">{currentRound}/{maxRounds}</p>
          </div>
          
          <div className="bg-slate-800/50 backdrop-blur rounded-lg p-3 border border-blue-500/30">
            <div className="flex items-center gap-2 mb-1">
              <Shield className="w-4 h-4 text-green-400" />
              <p className="text-xs text-gray-300">Health</p>
            </div>
            <div className="flex items-center gap-2">
              <div className="flex-1 bg-slate-600 rounded-full h-2">
                <div 
                  className={`h-full rounded-full transition-all ${organizationHealth > 50 ? 'bg-green-500' : organizationHealth > 25 ? 'bg-yellow-500' : 'bg-red-500'}`}
                  style={{width: `${organizationHealth}%`}}
                />
              </div>
              <span className="text-sm font-bold">{organizationHealth}%</span>
            </div>
          </div>

          <div className="bg-slate-800/50 backdrop-blur rounded-lg p-3 border border-blue-500/30">
            <div className="flex items-center gap-2 mb-1">
              <Award className="w-4 h-4 text-yellow-400" />
              <p className="text-xs text-gray-300">Score</p>
            </div>
            <p className="text-xl font-bold">{securityScore}</p>
          </div>
        </div>

        {/* Timer */}
        <div className="bg-slate-800/50 backdrop-blur rounded-lg p-4 mb-4 border border-red-500/50">
          <div className="flex items-center justify-between mb-2">
            <p className="font-bold text-red-400">TIME REMAINING</p>
            <Clock className="w-5 h-5 text-red-400" />
          </div>
          <div className="text-4xl font-bold text-center text-red-400">
            {Math.floor(timerSeconds / 60)}:{(timerSeconds % 60).toString().padStart(2, '0')}
          </div>
          <div className="mt-2 bg-slate-600 rounded-full h-2">
            <div 
              className="bg-red-500 h-full rounded-full transition-all"
              style={{width: `${(timerSeconds / currentIncident?.timeLimit) * 100}%`}}
            />
          </div>
        </div>

        {/* Current Incident */}
        {currentIncident && (
          <div className="bg-slate-800/50 backdrop-blur rounded-lg p-4 mb-4 border border-red-500/30">
            <div className="flex items-start justify-between mb-3">
              <div className="flex-1">
                <div className="flex items-center gap-2 mb-2">
                  <span className={`${getSeverityColor(currentIncident.severity)} px-2 py-1 rounded text-xs font-bold uppercase`}>
                    {currentIncident.severity}
                  </span>
                  <span className="bg-blue-500/30 px-2 py-1 rounded text-xs">
                    {currentIncident.category}
                  </span>
                </div>
                <h2 className="text-xl font-bold mb-2">{currentIncident.title}</h2>
                <p className="text-sm text-gray-300">{currentIncident.description}</p>
              </div>
              <AlertTriangle className="w-8 h-8 text-red-400 flex-shrink-0 ml-2" />
            </div>
          </div>
        )}

        {/* Response Options */}
        <div className="space-y-2 mb-4">
          <p className="text-sm font-bold text-gray-300 mb-2">RESPONSE OPTIONS:</p>
          {currentIncident?.responses.map((response, index) => {
            const requiredRoleNames = response.roles.map(r => roles.find(role => role.id === r)?.name);
            const playerRoles = players.map(p => p.id);
            const hasRoles = response.roles.every(role => playerRoles.includes(role));
            
            return (
              <button
                key={index}
                onClick={() => handleResponse(response)}
                disabled={!hasRoles}
                className={`w-full text-left p-4 rounded-lg border transition-all ${
                  hasRoles 
                    ? 'bg-slate-700/50 border-blue-500/50 hover:bg-slate-700 hover:border-blue-500' 
                    : 'bg-slate-800/30 border-gray-600/30 opacity-50'
                }`}
              >
                <div className="flex items-start justify-between mb-2">
                  <p className="font-semibold flex-1">{response.text}</p>
                  <ChevronRight className="w-5 h-5 flex-shrink-0 ml-2" />
                </div>
                <div className="flex items-center justify-between text-xs">
                  <div className="flex flex-wrap gap-1">
                    {requiredRoleNames.map((name, i) => (
                      <span key={i} className="bg-blue-600/30 px-2 py-0.5 rounded">
                        {name}
                      </span>
                    ))}
                  </div>
                  <span className="text-gray-400">Success: {response.success}%</span>
                </div>
              </button>
            );
          })}
        </div>

        {/* Event Log */}
        <div className="bg-slate-800/50 backdrop-blur rounded-lg p-4 border border-blue-500/30">
          <p className="text-sm font-bold text-gray-300 mb-2">EVENT LOG:</p>
          <div className="space-y-1 text-xs max-h-32 overflow-y-auto">
            {eventLog.slice().reverse().map((log, index) => (
              <div key={index} className="text-gray-300">
                <span className="text-blue-400">[{log.timestamp}]</span> {log.message}
              </div>
            ))}
          </div>
        </div>

        {/* Active Team */}
        <div className="mt-4 bg-slate-800/50 backdrop-blur rounded-lg p-4 border border-blue-500/30">
          <p className="text-sm font-bold text-gray-300 mb-2">ACTIVE TEAM:</p>
          <div className="grid grid-cols-2 gap-2">
            {players.map((player, index) => {
              const RoleIcon = player.icon;
              return (
                <div key={index} className={`${player.color} rounded p-2 text-xs`}>
                  <div className="flex items-center gap-2">
                    <RoleIcon className="w-4 h-4" />
                    <div className="flex-1 min-w-0">
                      <p className="font-semibold truncate">{player.playerName}</p>
                      <p className="text-xs opacity-75 truncate">{player.name}</p>
                    </div>
                  </div>
                </div>
              );
            })}
          </div>
        </div>
      </div>
    </div>
  );
};

export default CybersecurityGame;
