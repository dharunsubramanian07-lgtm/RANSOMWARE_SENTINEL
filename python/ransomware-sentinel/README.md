                                   Ransomware Sentinel
                      Behavior-Based Ransomware Detection Prototype

────────────────────────────────────────
Overview
────────────────────────────────────────
Ransomware Sentinel is a lightweight behavior-based detection system designed to identify ransomware activity in real time. Instead of relying on known malware signatures, the system monitors file system behavior and detects suspicious patterns such as sudden increases in file entropy, rapid file modifications, and abnormal extension changes.

When suspicious activity is detected, the system attempts to stop the process responsible, moves affected files to a quarantine folder, and records events in a log file for analysis.

────────────────────────────────────────
Problem
────────────────────────────────────────
Traditional antivirus solutions mainly depend on signature databases, which makes them less effective against new or unknown ransomware variants. Ransomware often encrypts files quickly, causing damage before detection occurs.

This project explores a behavior-based approach that focuses on detecting abnormal file activity rather than known malware signatures.

────────────────────────────────────────
Solution
────────────────────────────────────────
The system continuously monitors a selected directory and applies multiple detection techniques:

• Calculates file entropy to identify encryption-like behavior
• Tracks rapid modifications across many files
• Detects extension changes commonly associated with ransomware
• Correlates multiple behavioral signals to identify potential attacks

Once suspicious behavior crosses defined thresholds, the system performs containment actions including process termination and file quarantine.

────────────────────────────────────────
Key Features
────────────────────────────────────────
• Real-time folder monitoring
• Entropy calculation using Shannon entropy
• Entropy spike detection
• Mass file modification detection (time-window based)
• Rapid extension change detection
• Multiple extension anomaly detection
• Process auto-kill for containment
• File quarantine mechanism
• Structured event logging
• Attack simulation scripts for demonstration

────────────────────────────────────────
Architecture (Conceptual)
────────────────────────────────────────
File System Events
→ Behavioral Analysis (Entropy & Activity Patterns)
→ Decision / Risk Evaluation
→ Containment (Process Kill + Quarantine)
→ Logging & Evidence

────────────────────────────────────────
Technology Used
────────────────────────────────────────
• Python
• watchdog — file monitoring
• psutil — process inspection and termination
• logging — event recording

────────────────────────────────────────
How to Run
────────────────────────────────────────

Install dependencies:

pip install watchdog psutil

Start the sentinel:

python main.py

python sentinel.py


────────────────────────────────────────
Demo
────────────────────────────────────────
• Run any included attack simulation script while the sentinel is running
• The system detects suspicious behavior in real time
• Affected files are moved to quarantine
• Events are recorded in the log file

────────────────────────────────────────
Output
────────────────────────────────────────
When detection occurs, the system may:

• Terminate the suspicious process
• Move the affected file into the quarantine folder
• Store event details inside sentinel_log.txt

────────────────────────────────────────
Use Cases
────────────────────────────────────────
• Cybersecurity learning and demonstrations
• Ransomware behavior research
• Proof-of-concept endpoint protection
• Behavior-based detection experimentation

────────────────────────────────────────
Future Improvements
────────────────────────────────────────
• Risk-scoring based detection
• Multi-directory monitoring
• Simple user interface or dashboard
• Machine learning-based anomaly detection

