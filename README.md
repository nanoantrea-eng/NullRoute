



🌀 NullRoute

High-Performance Multithreaded Network Stress Testing Platform

NullRoute is a professional-grade traffic generator and load testing tool. Built for high-throughput and resource exhaustion testing, it utilizes Node.js Worker Threads to achieve true parallel execution across all CPU cores, bypassing standard JavaScript single-thread limitations.



⚡ Technical Core
Multithreaded Engine: Automatically scales across all available CPU cores, spawning independent worker threads for maximum PPS (Packets Per Second).

Zero-Copy Memory: Uses pre-generated memory slices to push data to the network stack without the overhead of real-time generation.

Layer 7 Power: Features specialized HTTP/1.1 and HTTPS flooding logic to test web server resilience.

Layer 4 Brute: Optimized UDP/TCP engines including "Router Killer" logic designed to stress-test NAT tables and networking hardware.



🚀 Key Features


Real-Time Analytics: Web-based dashboard with live RPS, Bandwidth (MB/s), and Status Code tracking.

Performance Metrics: Automatic calculation of P95 and P99 Latency to identify the exact point of service degradation.

Evasion Suite: Automatic randomization of:

IP Headers: X-Forwarded-For, X-Real-IP, Client-IP.

User-Agents: High-fidelity browser signatures (Chrome, Firefox, Safari).

Referers: Traffic simulation from major domains like Google and Facebook.







🛠 Attack Vectors
Method	Target Layer	Logic
HTTP/HTTPS Flood	Layer 7	High-frequency requests to overwhelm application resources.
UDP Flood	Layer 4	MTU-optimized (1450 bytes) bursts to saturate pipe bandwidth.
TCP SYN/ACK	Layer 4	Protocol-level stress testing for firewall state-tracking.
Router Killer	Hardware	Random high-port cycling to force NAT table overflows.







📥 Quick Start (Installation)
Windows (Recommended)
Ensure Node.js is installed.

Clone the repository or download the folder.

Double-click SERVER-RUN.BAT.

This will automatically install dependencies and launch the backend.

Manual Launch
If you prefer the terminal:

Bash<img width="960" height="540" alt="Capture" src="https://github.com/user-attachments/assets/f827e1da-5c0e-4df4-ae0d-dc0e22c764a3" />

npm install express
node server.js
Accessing the Tool
Once the server is running, open your browser and go to:
http://localhost:3000

📊 Infrastructure Layout
NullRoute operates on a Main -> Worker architecture. The Main thread handles the Express API and statistics aggregation, while the Worker threads execute the attack loops. This ensures that the control panel remains responsive even when the host machine is at 100% CPU utilization.
