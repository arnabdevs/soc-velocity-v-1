// AEGIS SOC Engine - aegis-soc-engine - Protected by AI 🛡️

const isLocal = window.location.hostname === 'localhost' || window.location.hostname === '127.0.0.1' || window.location.hostname === '';
const API_BASE = isLocal ? 'http://localhost:5000' : 'https://defence-intelligence.onrender.com';

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
    document.getElementById(`${viewName}-view`).classList.remove('hidden');

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

window._activeTab = 'overview';
window._scanData = null;

function renderTab(tab, data) {
    window._activeTab = tab;
    const ip = data.ip_intel || {};
    const dns = data.dns_records || {};
    const whois = data.whois || {};
    const vt = data.virustotal;
    const abuse = data.abuseipdb;
    const sslColor = data.ssl_grade?.startsWith('A') ? 'var(--success)' : data.ssl_grade === 'N/A' ? '#888' : 'var(--danger)';
    const scoreColor = data.health_score > 80 ? 'var(--success)' : data.health_score > 50 ? 'var(--warning)' : 'var(--danger)';

    const tabs = ['overview', 'network', 'dns', 'reputation', 'whois'];
    const tabBar = tabs.map(t => `
        <button onclick="renderTab('${t}', window._scanData)"
            style="background:${t === tab ? 'rgba(0,242,255,0.15)' : 'transparent'};border:1px solid ${t === tab ? 'var(--primary)' : 'rgba(255,255,255,0.08)'};
            color:${t === tab ? 'var(--primary)' : '#666'};padding:0.4rem 0.9rem;border-radius:6px;cursor:pointer;font-size:0.7rem;font-family:monospace;letter-spacing:1px;">
            ${t.toUpperCase().replace('DNS', 'DNS & CERTS')}
        </button>`).join('');

    let body = '';

    if (tab === 'overview') {
        const findings = data.malware_findings || [];
        body = `
        <div style="display:grid;grid-template-columns:160px 1fr;gap:1.5rem;align-items:start">
            <div style="text-align:center;background:rgba(0,0,0,0.3);border-radius:12px;padding:1.2rem;border:1px solid rgba(255,255,255,0.05)">
                <div style="font-size:0.6rem;color:#555;margin-bottom:0.5rem">THREAT SCORE</div>
                <div style="font-size:2.8rem;font-weight:bold;color:${scoreColor};font-family:monospace">${data.health_score}%</div>
                <div style="font-size:0.65rem;color:${scoreColor};margin-top:0.3rem">${data.status?.toUpperCase()}</div>
                <div style="margin-top:1rem;font-size:0.65rem;color:#555">SSL GRADE</div>
                <div style="font-size:1.6rem;font-weight:bold;color:${sslColor}">${data.ssl_grade || 'N/A'}</div>
            </div>
            <div>
                <div style="font-size:0.7rem;color:#555;margin-bottom:0.6rem">SECURITY FINDINGS (${findings.length})</div>
                ${findings.length === 0
                ? `<div style="color:var(--success);font-size:0.85rem">✅ No security issues detected</div>`
                : findings.map(f => `<div style="background:rgba(255,0,60,0.07);border-left:2px solid var(--danger);padding:0.5rem 0.8rem;margin-bottom:0.4rem;font-size:0.75rem;color:#f88;border-radius:0 4px 4px 0">${f}</div>`).join('')
            }
                <div style="margin-top:1rem;font-size:0.7rem;color:#555">OPEN PORTS & SERVICES</div>
                <div style="margin-top:0.4rem;display:flex;flex-wrap:wrap;gap:0.4rem">
                    ${(data.open_ports || []).map(p => `<span style="background:rgba(0,242,255,0.08);border:1px solid rgba(0,242,255,0.2);padding:2px 8px;border-radius:4px;font-size:0.7rem;color:var(--primary)">${p}</span>`).join('')}
                    ${(data.services || []).map(s => `<span style="background:rgba(112,0,255,0.08);border:1px solid rgba(112,0,255,0.2);padding:2px 8px;border-radius:4px;font-size:0.7rem;color:#a06fff">${s}</span>`).join('')}
                </div>
            </div>
        </div>`;
    }

    if (tab === 'network') {
        const proxyBadge = ip.is_proxy ? `<span style="background:rgba(255,0,60,0.2);border:1px solid var(--danger);padding:2px 8px;border-radius:4px;font-size:0.65rem;color:var(--danger)">⚠ PROXY/VPN/TOR</span>` : `<span style="background:rgba(0,255,136,0.1);border:1px solid var(--success);padding:2px 8px;border-radius:4px;font-size:0.65rem;color:var(--success)">✓ CLEAN</span>`;
        const hostingBadge = ip.is_hosting ? `<span style="background:rgba(0,242,255,0.1);border:1px solid var(--primary);padding:2px 8px;border-radius:4px;font-size:0.65rem;color:var(--primary)">DATACENTER/HOSTING</span>` : '';
        body = `
        <div style="display:grid;grid-template-columns:1fr 1fr;gap:1rem">
            ${[
                ['SERVER IP', ip.ip || 'Unknown'],
                ['COUNTRY', ip.country ? `${ip.country} ${ip.country_code ? '(' + ip.country_code + ')' : ''}` : 'Unknown'],
                ['REGION / CITY', `${ip.region || '?'} / ${ip.city || '?'}`],
                ['ISP', ip.isp || 'Unknown'],
                ['ORGANIZATION', ip.org || 'Unknown'],
                ['ASN', ip.asn || 'Unknown'],
            ].map(([k, v]) => `
                <div style="background:rgba(0,0,0,0.3);padding:0.8rem;border-radius:8px;border:1px solid rgba(255,255,255,0.05)">
                    <div style="font-size:0.6rem;color:#555;margin-bottom:0.3rem">${k}</div>
                    <div style="font-size:0.85rem;color:#ccc">${v}</div>
                </div>`).join('')}
        </div>
        <div style="margin-top:1rem;display:flex;gap:0.5rem;flex-wrap:wrap">
            <span style="font-size:0.7rem;color:#555">IP REPUTATION:</span>
            ${proxyBadge} ${hostingBadge}
        </div>`;
    }

    if (tab === 'dns') {
        const subs = data.subdomains || [];
        body = `
        <div style="display:grid;grid-template-columns:1fr 1fr;gap:1rem">
            <div>
                <div style="font-size:0.7rem;color:#555;margin-bottom:0.6rem">DNS RECORDS</div>
                ${Object.entries(dns).map(([type, vals]) => vals.length ? `
                    <div style="margin-bottom:0.8rem">
                        <span style="background:rgba(0,242,255,0.1);padding:2px 8px;border-radius:4px;font-size:0.65rem;color:var(--primary);font-weight:bold">${type}</span>
                        ${vals.map(v => `<div style="font-size:0.75rem;color:#aaa;padding:0.3rem 0.5rem;border-left:1px solid rgba(255,255,255,0.05);margin-top:0.2rem">${v || '—'}</div>`).join('')}
                    </div>` : '').join('') || '<div style="color:#444;font-size:0.8rem">No DNS records fetched</div>'}
            </div>
            <div>
                <div style="font-size:0.7rem;color:#555;margin-bottom:0.6rem">SUBDOMAINS (${subs.length} via crt.sh)</div>
                <div style="max-height:220px;overflow-y:auto">
                    ${subs.length ? subs.map(s => `<div style="font-size:0.72rem;color:#aaa;padding:0.25rem 0.5rem;border-bottom:1px solid rgba(255,255,255,0.03)">${s}</div>`).join('') : '<div style="color:#444;font-size:0.8rem">No subdomains found</div>'}
                </div>
            </div>
        </div>`;
    }

    if (tab === 'reputation') {
        const vtSection = vt ? `
            <div style="background:rgba(0,0,0,0.3);padding:1rem;border-radius:8px;border:1px solid rgba(255,255,255,0.05)">
                <div style="font-size:0.7rem;color:#555;margin-bottom:0.8rem">VIRUSTOTAL ANALYSIS</div>
                <div style="display:grid;grid-template-columns:repeat(4,1fr);gap:0.5rem;text-align:center">
                    ${[['MALICIOUS', vt.malicious, 'var(--danger)'], ['SUSPICIOUS', vt.suspicious, 'var(--warning)'], ['HARMLESS', vt.harmless, 'var(--success)'], ['UNDETECTED', vt.undetected, '#555']].map(([l, v, c]) => `
                    <div style="background:rgba(0,0,0,0.4);padding:0.5rem;border-radius:6px">
                        <div style="font-size:1.2rem;font-weight:bold;color:${c}">${v}</div>
                        <div style="font-size:0.55rem;color:#555">${l}</div>
                    </div>`).join('')}
                </div>
                <div style="margin-top:0.5rem;font-size:0.65rem;color:#444">Out of ${vt.total} security vendors</div>
            </div>` : `<div style="background:rgba(0,0,0,0.2);padding:1rem;border-radius:8px;font-size:0.8rem;color:#444">VirusTotal: Set VIRUSTOTAL_API_KEY env var on Render to enable</div>`;

        const abScore = abuse ? abuse.abuse_score : null;
        const abColor = abScore > 50 ? 'var(--danger)' : abScore > 15 ? 'var(--warning)' : 'var(--success)';
        const abSection = abuse ? `
            <div style="background:rgba(0,0,0,0.3);padding:1rem;border-radius:8px;border:1px solid rgba(255,255,255,0.05)">
                <div style="font-size:0.7rem;color:#555;margin-bottom:0.8rem">ABUSEIPDB SCORE</div>
                <div style="display:flex;align-items:center;gap:1rem">
                    <div style="font-size:2rem;font-weight:bold;color:${abColor}">${abScore}%</div>
                    <div>
                        <div style="font-size:0.75rem;color:#aaa">Abuse Confidence Score</div>
                        <div style="font-size:0.65rem;color:#555">${abuse.total_reports} reports · ${abuse.usage_type || 'Unknown usage'}</div>
                    </div>
                </div>
                <div style="background:rgba(255,255,255,0.05);border-radius:4px;height:6px;margin-top:0.8rem"><div style="height:100%;width:${abScore}%;background:${abColor};border-radius:4px;transition:width 0.5s"></div></div>
            </div>` : `<div style="background:rgba(0,0,0,0.2);padding:1rem;border-radius:8px;font-size:0.8rem;color:#444">AbuseIPDB: Set ABUSEIPDB_API_KEY env var on Render to enable</div>`;

        body = `<div style="display:flex;flex-direction:column;gap:1rem">${vtSection}${abSection}</div>`;
    }

    if (tab === 'whois') {
        body = `
        <div style="display:grid;grid-template-columns:1fr 1fr;gap:1rem">
            ${[
                ['REGISTRAR', whois.registrar || 'Unknown'],
                ['CREATED', whois.created || 'Unknown'],
                ['EXPIRES', whois.expires || 'Unknown'],
                ['LAST UPDATED', whois.updated || 'Unknown'],
            ].map(([k, v]) => `
                <div style="background:rgba(0,0,0,0.3);padding:0.8rem;border-radius:8px;border:1px solid rgba(255,255,255,0.05)">
                    <div style="font-size:0.6rem;color:#555;margin-bottom:0.3rem">${k}</div>
                    <div style="font-size:0.85rem;color:#ccc">${v}</div>
                </div>`).join('')}
        </div>
        ${whois.status?.length ? `<div style="margin-top:1rem">
            <div style="font-size:0.65rem;color:#555;margin-bottom:0.5rem">DOMAIN STATUS FLAGS</div>
            <div style="display:flex;flex-wrap:wrap;gap:0.3rem">${whois.status.map(s => `<span style="background:rgba(0,242,255,0.06);border:1px solid rgba(0,242,255,0.15);padding:2px 8px;border-radius:4px;font-size:0.65rem;color:#888">${s}</span>`).join('')}</div>
        </div>` : ''}`;
    }

    document.getElementById('result-content').innerHTML = `
        <div style="display:flex;gap:0.5rem;margin-bottom:1rem;flex-wrap:wrap">${tabBar}</div>
        <div style="font-size:0.8rem;color:#aaa">${body}</div>`;
}

function showScanDetails(data) {
    window._scanData = data;
    const details = document.getElementById('scan-result-details');
    details.classList.remove('hidden');
    renderTab('overview', data);
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

    const ctx2 = document.getElementById('accuracy-chart');
    if (ctx2) {
        new Chart(ctx2, {
            type: 'line',
            data: {
                labels: ['Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat', 'Sun'],
                datasets: [{
                    label: 'Model Accuracy %',
                    data: [91, 93, 92, 95, 94, 97, 96],
                    borderColor: '#00f2ff',
                    backgroundColor: 'rgba(0,242,255,0.05)',
                    borderWidth: 2,
                    pointBackgroundColor: '#00f2ff',
                    tension: 0.4,
                    fill: true
                }]
            },
            options: {
                plugins: { legend: { labels: { color: '#666', font: { size: 10 } } } },
                scales: {
                    x: { ticks: { color: '#555' }, grid: { color: 'rgba(255,255,255,0.03)' } },
                    y: { ticks: { color: '#555' }, grid: { color: 'rgba(255,255,255,0.03)' }, min: 85, max: 100 }
                }
            }
        });
    }
}

init();
