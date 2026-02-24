// AEGIS SOC Engine - aegis-soc-engine - Protected by AI 🛡️

const isLocal = window.location.hostname === 'localhost' || window.location.hostname === '127.0.0.1' || window.location.hostname === '';
const API_BASE = isLocal ? 'http://localhost:5000' : 'https://soc-velocity-v-1-1.onrender.com';

let AUTH_TOKEN = localStorage.getItem('AEGIS_TOKEN') || null;

// --- Initialization ---
function init() {
    console.log("🚀 AEGIS MISSION CONTROL INITIALIZED");
    fetchStats();
    updateUserStatus();
    startLiveFeed();
    initCharts();
}

// --- Auth Functions ---
window.toggleModal = (id) => document.getElementById(id).classList.toggle('hidden');

window.toggleAuth = (type) => {
    document.getElementById('login-modal').classList.add('hidden');
    document.getElementById('signup-modal').classList.add('hidden');
    document.getElementById(`${type}-modal`).classList.remove('hidden');
};

async function handleLogin() {
    const email = document.getElementById('login-email').value;
    const password = document.getElementById('login-pass').value;

    try {
        const resp = await fetch(`${API_BASE}/api/auth/login`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ email, password })
        });
        const data = await resp.json();
        if (data.access_token) {
            AUTH_TOKEN = data.access_token;
            localStorage.setItem('AEGIS_TOKEN', AUTH_TOKEN);
            updateUserStatus();
            toggleModal('login-modal');
            alert("✅ Authenticated Successfully");
        } else {
            alert("❌ " + (data.error || "Login Failed"));
        }
    } catch (e) { console.error(e); }
}

async function handleSignup() {
    const email = document.getElementById('signup-email').value;
    const password = document.getElementById('signup-pass').value;

    try {
        const resp = await fetch(`${API_BASE}/api/auth/signup`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ email, password })
        });
        const data = await resp.json();
        if (resp.status === 201) {
            alert("✅ Identity Created. Please Log In.");
            toggleAuth('login');
        } else {
            alert("❌ " + (data.error || "Signup Failed"));
        }
    } catch (e) { console.error(e); }
}

function updateUserStatus() {
    const statusEl = document.getElementById('user-status');
    if (AUTH_TOKEN) {
        statusEl.innerText = "IDENTITY ACTIVE";
        statusEl.style.color = "var(--success)";
        statusEl.onclick = () => {
            if (confirm("Logout?")) {
                AUTH_TOKEN = null;
                localStorage.removeItem('AEGIS_TOKEN');
                updateUserStatus();
            }
        };
    } else {
        statusEl.innerText = "LOG IN";
        statusEl.style.color = "var(--primary)";
        statusEl.onclick = () => toggleModal('login-modal');
    }
}

// --- View Switching ---
window.switchView = (viewName) => {
    document.querySelectorAll('.view').forEach(v => v.classList.add('hidden'));
    document.getElementById(`${viewName} - view`).classList.remove('hidden');

    document.querySelectorAll('nav li').forEach(li => {
        li.classList.toggle('active', li.textContent.toLowerCase().includes(viewName.replace('-', ' ')));
    });
};

// --- Security Scan Logic ---
window.runLiveScan = async () => {
    const target = document.getElementById('live-scan-input').value;
    if (!target) return alert("Enter a target domain");

    const terminal = document.getElementById('scan-terminal');
    const terminalContent = document.getElementById('terminal-content');
    const scanBtn = document.getElementById('scan-btn');

    terminal.style.display = 'block';
    terminalContent.innerHTML = `> INITIALIZING AI SECURITY AUDIT FOR ${target}...<br>`;
    scanBtn.disabled = true;

    const log = (msg) => {
        terminalContent.innerHTML += `> ${msg}<br>`;
        terminal.scrollTop = terminal.scrollHeight;
    };

    setTimeout(() => log("CHECKING AI ANOMALY PATTERNS..."), 800);
    setTimeout(() => log("EXECUTING REAL-TIME NMAP DISCOVERY..."), 1500);

    try {
        const resp = await fetch(`${API_BASE}/api/scan`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'Authorization': AUTH_TOKEN ? `Bearer ${AUTH_TOKEN}` : ''
            },
            body: JSON.stringify({ target })
        });
        const data = await resp.json();

        if (data.error) {
            log(`BLOCK: ${data.message || data.error}`);
            return;
        }

        log(`AUDIT COMPLETE. SCORE: ${data.health_score}%`);
        updateHealthGauge(data.health_score, data.malware_findings.length > 0);
        showScanDetails(data);
    } catch (e) { log(`SYSTEM ERROR: ${e.message}`); }
    finally { scanBtn.disabled = false; }
};

function updateHealthGauge(score, hasMalware) {
    const gauge = document.getElementById('health-score-gauge');
    const text = document.getElementById('health-status-text');
    const mal = document.getElementById('malware-status');

    gauge.innerText = `${score}%`;
    gauge.style.color = score > 80 ? 'var(--success)' : score > 50 ? 'var(--warning)' : 'var(--danger)';
    text.innerText = score > 80 ? 'OPTIMAL' : score > 50 ? 'VULNERABLE' : 'CRITICAL';
    text.style.color = gauge.style.color;

    mal.innerText = hasMalware ? "MALWARE: DETECTED" : "MALWARE: CLEAN";
    mal.style.color = hasMalware ? "var(--danger)" : "#444";
}

function showScanDetails(data) {
    const details = document.getElementById('scan-result-details');
    const content = document.getElementById('result-content');
    details.classList.remove('hidden');

    content.innerHTML = `
        <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 1rem;">
            <div>
                <p><strong>Open Ports:</strong> ${data.open_ports.join(', ') || 'None'}</p>
                <p><strong>Detected Services:</strong> ${data.services.join(', ') || 'None'}</p>
            </div>
            <div>
                <p><strong>Malware Findings:</strong> <span style="color: ${data.malware_findings.length ? 'var(--danger)' : 'var(--success)'}">${data.malware_findings.length || '0 Clean Indicators'}</span></p>
                <ul style="font-size: 0.7rem;">${data.malware_findings.map(f => `<li>${f}</li>`).join('')}</ul>
            </div>
        </div>
        `;
}

// --- Email Breach Checker ---
window.checkEmailBreach = async () => {
    const email = document.getElementById('breach-email-input').value;
    if (!email) return alert("Enter an email");

    const resultDiv = document.getElementById('breach-result');
    resultDiv.classList.remove('hidden');
    resultDiv.innerHTML = `<div style="text-align: center; color: var(--primary);">SCANNING GLOBAL DATABASES...</div>`;

    try {
        const resp = await fetch(`${API_BASE}/api/breach-check`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'Authorization': AUTH_TOKEN ? `Bearer ${AUTH_TOKEN}` : ''
            },
            body: JSON.stringify({ email })
        });
        const data = await resp.json();

        if (data.pwned) {
            resultDiv.innerHTML = `
                <div style="background: rgba(255,0,0,0.1); border: 1px solid var(--danger); padding: 1.5rem; border-radius: 8px;">
                    <h3 style="color: var(--danger);">BREACH DETECTED!</h3>
                    <p>This email was found in <strong>${data.count}</strong> confirmed data breaches.</p>
                    <div style="margin-top: 1rem; display: grid; grid-template-columns: repeat(auto-fill, minmax(150px, 1fr)); gap: 0.5rem;">
                        ${data.breaches.map(b => `<div style="background: #000; padding: 0.5rem; border-radius: 4px; font-size: 0.7rem;">${b.name} (${b.year})</div>`).join('')}
                    </div>
                </div>
            `;
        } else {
            resultDiv.innerHTML = `<div style="color: var(--success); text-align: center;">NO BREACHES DETECTED. IDENTITY IS CLEAN.</div>`;
        }
    } catch (e) { alert("Error checking breach"); }
};

// --- Live Attack Feed ---
function startLiveFeed() {
    const feed = document.getElementById('live-attack-feed');
    setInterval(async () => {
        try {
            const resp = await fetch(`${API_BASE}/api/logs/live`);
            const attacks = await resp.json();

            attacks.forEach(atk => {
                if (feed.children.length === 1 && feed.children[0].textContent.includes("No active")) feed.innerHTML = '';

                const entry = document.createElement('div');
                entry.className = 'attack-entry';
                entry.innerHTML = `
        <div style="display: flex; justify-content: space-between; font-weight: bold; color: var(--danger);">
            <span>${atk.type}</span>
            <span>${atk.timestamp}</span>
        </div>
        <div style="font-size: 0.7rem; color: #666;">Source: ${atk.origin} -> Target: ${atk.origin.split('.')[0]}.*</div>
        `;
                feed.insertBefore(entry, feed.firstChild);
                if (feed.children.length > 5) feed.removeChild(feed.lastChild);
            });
        } catch (e) { }
    }, 5000);
}

async function fetchStats() {
    try {
        const resp = await fetch(`${API_BASE}/api/stats`);
        const data = await resp.json();
        document.getElementById('total-analyzed').innerText = data.total_scans;
        document.getElementById('threats-blocked').innerText = data.threats_blocked;
        document.getElementById('system-health').innerText = `${data.cpu_usage}%`;

        // AEGIS Pro: Update Global Sync Count
        if (data.blacklist_count) {
            document.getElementById('global-sync-count').innerText = data.blacklist_count.toLocaleString();
            document.getElementById('global-intel-status').innerText = "ACTIVE";
            document.getElementById('global-intel-status').style.color = "var(--success)";
        } else {
            document.getElementById('global-intel-status').innerText = "OFFLINE";
            document.getElementById('global-intel-status').style.color = "var(--warning)";
        }
    } catch (e) { }
}

function initCharts() {
    const ctx1 = document.getElementById('threat-chart');
    if (ctx1) {
        new Chart(ctx1, {
            type: 'doughnut',
            data: {
                labels: ['SQLi', 'XSS', 'DDoS', 'Brute Force'],
                datasets: [{
                    data: [12, 19, 3, 5],
                    backgroundColor: ['#00f2ff', '#7000ff', '#ff003c', '#00ff88'],
                    borderWidth: 0
                }]
            },
            options: { plugins: { legend: { position: 'bottom', labels: { color: '#666', font: { size: 10 } } } } }
        });
    }
}

init();
