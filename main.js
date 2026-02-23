// AEGIS SOC Engine - aegis-soc-engine - Protected by AI 🛡️
// Chart.js loaded via CDN

const alertFeed = document.getElementById('alert-feed');
const mitreContent = document.getElementById('mitre-content');

const isLocal = window.location.hostname === 'localhost' || window.location.hostname === '127.0.0.1' || window.location.hostname === '';

// Production API URL
const PROD_API_BASE = 'https://soc-velocity-v-1-1.onrender.com';
let API_BASE = isLocal ? 'http://localhost:5000' : PROD_API_BASE;

console.log(`🔗 CONNECTING TO API: ${API_BASE}`);

function initDashboard() {
    console.log("🚀 Initializing AEGIS Mission Control...");
    checkBackend();
    fetchStats();
    fetchAlerts();
}

async function checkBackend() {
    try {
        const response = await fetch(`${API_BASE}/api/health`);
        const data = await response.json();
        console.log("✅ Backend connection verified:", data);
        
        document.getElementById('engine-status').textContent = "ACTIVE";
        document.getElementById('engine-status').style.color = "var(--success)";
        
        const nmapEl = document.getElementById('nmap-status');
        if (nmapEl) {
            nmapEl.textContent = data.nmap_available ? "READY" : "MISSING";
            nmapEl.style.color = data.nmap_available ? "var(--success)" : "var(--danger)";
        }
        
        const intelEl = document.getElementById('intel-status');
        if (intelEl) {
            intelEl.textContent = data.whois_available ? "READY" : "LIMITED";
            intelEl.style.color = data.whois_available ? "var(--success)" : "var(--warning)";
        }
    } catch (e) {
        console.error("❌ Backend unreachable:", e);
        document.getElementById('engine-status').textContent = "OFFLINE";
        document.getElementById('engine-status').style.color = "var(--danger)";
    }
}

// Public access - skip auth
initDashboard();

async function fetchStats() {
    try {
        const response = await fetch(`${API_BASE}/api/stats`);
        const data = await response.json();
        document.getElementById('total-analyzed').textContent = data.total_analyzed.toLocaleString();
        document.getElementById('threats-blocked').textContent = data.threats_blocked;
        document.getElementById('active-anomalies').textContent = data.active_anomalies;
        document.getElementById('system-health').textContent = data.system_health;
        document.getElementById('engine-status').textContent = "ACTIVE";
    } catch (error) {
        console.error('Error fetching stats:', error);
    }
}

async function fetchAlerts() {
    try {
        // First try to get recent alerts (new results)
        let response = await fetch(`${API_BASE}/api/alerts/recent`);
        let alerts = await response.json();

        // If no new alerts, populate with history to avoid empty dashboard
        if (alerts.length === 0) {
            const histResp = await fetch(`${API_BASE}/api/logs`);
            const history = await histResp.json();
            alerts = history.slice(0, 5); // Just show the latest 5 in the feed

            // Auto-show the most recent intelligence report if it exists
            if (alerts.length > 0) {
                console.log("📍 Auto-loading most recent security report...");
                showMitreDetails(alerts[0]);
            }
        }

        alerts.forEach(alert => addAlertToFeed(alert));
    } catch (e) { console.error("Error fetching alerts:", e); }
}

function addAlertToFeed(alert) {
    if (!alertFeed) return;
    const item = document.createElement('div');
    item.className = `alert-item ${alert.severity}`;
    item.innerHTML = `
        <div class="alert-header">
            <span class="alert-type">${alert.type} ${alert.alert_id}</span>
            <span class="alert-severity">${alert.severity}</span>
        </div>
        <div class="alert-details">
            Confidence: ${alert.confidence}% | Site: <span style="color: var(--primary)">${alert.target_site}</span>
        </div>
    `;

    item.onclick = () => showMitreDetails(alert);
    alertFeed.insertBefore(item, alertFeed.children[1]);

    if (alertFeed.children.length > 21) {
        alertFeed.removeChild(alertFeed.lastChild);
    }
}

function showMitreDetails(alert) {
    if (!mitreContent) return;

    let findingsHtml = '';

    if (alert.web_security_issues && alert.web_security_issues.length > 0) {
        findingsHtml += `
            <div style="margin-top: 1rem; padding: 1rem; background: rgba(255,204,0,0.05); border-radius: 8px; border: 1px solid rgba(255,204,0,0.2);">
                <h4 style="color: var(--warning); font-size: 0.8rem; margin-bottom: 0.8rem; display: flex; align-items: center; gap: 0.5rem;">
                    <span>⚠️</span> WEB SECURITY GAPS
                </h4>
                <ul style="font-size: 0.85rem; padding-left: 1.2rem; color: #ddd; line-height: 1.5;">
                    ${alert.web_security_issues.map(issue => `<li>${issue}</li>`).join('')}
                </ul>
            </div>
        `;
    }

    if (alert.detected_services && alert.detected_services.length > 0) {
        findingsHtml += `
            <div style="margin-top: 1rem;">
                <h4 style="color: var(--primary); font-size: 0.8rem; margin-bottom: 0.8rem;">DETECTED SERVICES</h4>
                <div style="display: flex; gap: 0.4rem; flex-wrap: wrap;">
                    ${alert.detected_services.map(s => `<span style="background: rgba(0,242,255,0.1); padding: 4px 10px; border-radius: 4px; font-size: 0.75rem; border: 1px solid rgba(0,242,255,0.3); color: white;">${s}</span>`).join('')}
                </div>
            </div>
        `;
    }

    if (alert.domain_info && alert.domain_info.registrar) {
        findingsHtml += `
            <div style="margin-top: 1rem; padding: 1rem; background: rgba(112,0,255,0.05); border-radius: 8px; border: 1px solid rgba(112,0,255,0.2);">
                <h4 style="color: var(--secondary); font-size: 0.8rem; margin-bottom: 0.5rem;">DOMAIN INTELLIGENCE</h4>
                <div style="font-size: 0.8rem; color: #ccc; display: grid; grid-template-columns: 1fr; gap: 0.4rem;">
                    <div>Registrar: <span style="color: white; font-family: monospace;">${alert.domain_info.registrar}</span></div>
                    <div>Status: <span style="color: var(--success);">ACTIVE</span></div>
                </div>
            </div>
        `;
    }

    if (alert.recommendations && alert.recommendations.length > 0) {
        findingsHtml += `
            <div style="margin-top: 1rem; padding: 1rem; background: rgba(0,255,136,0.05); border-radius: 8px; border: 1px solid rgba(0,255,136,0.2);">
                <h4 style="color: var(--success); font-size: 0.8rem; margin-bottom: 0.8rem;">REMEDIATION STRATEGY</h4>
                <ul style="font-size: 0.85rem; padding-left: 1.2rem; color: #ccc; line-height: 1.5;">
                    ${alert.recommendations.map(rec => `<li>${rec}</li>`).join('')}
                </ul>
            </div>
        `;
    }

    mitreContent.innerHTML = `
        <div style="animation: fadeIn 0.5s ease-out;">
            <div style="background: linear-gradient(135deg, rgba(0,242,255,0.1), transparent); padding: 1rem; border-radius: 8px; border-left: 4px solid var(--primary); margin-bottom: 1.5rem;">
                <h2 style="color: white; font-size: 1.1rem; margin-bottom: 0.2rem;">${alert.target_site}</h2>
                <p style="font-family: monospace; color: var(--primary); font-size: 0.75rem;">${alert.alert_id} | CONFIDENCE: ${alert.confidence}%</p>
            </div>
            
            <p style="font-size: 0.9rem; line-height: 1.6; color: #eee; margin-bottom: 1rem;">${alert.description}</p>
            
            ${findingsHtml}
            
            <div style="margin-top: 1.5rem;">
                <h4 style="color: #555; font-size: 0.7rem; margin-bottom: 0.5rem; text-transform: uppercase;">Technical Evidence</h4>
                <pre style="background: #000; color: #0f8; padding: 1rem; border-radius: 6px; font-size: 0.75rem; overflow-x: auto; max-height: 200px; border: 1px solid #222; font-family: 'Courier New', monospace;">${alert.raw_output || 'No technical evidence found.'}</pre>
            </div>
        </div>
    `;

    // Auto-scroll to top of result
    mitreContent.parentElement.scrollTop = 0;
}

window.runLiveScan = async function () {
    const target = document.getElementById('live-scan-input').value;
    if (!target) return alert("Please enter a target domain/IP");

    const terminal = document.getElementById('scan-terminal');
    const terminalContent = document.getElementById('terminal-content');
    const scanBtn = document.getElementById('scan-btn');

    terminal.style.display = 'block';
    terminalContent.innerHTML = '> INITIALIZING REAL-TIME SCAN...<br>';
    scanBtn.disabled = true;
    scanBtn.innerText = 'SCANNING...';

    const log = (msg) => {
        terminalContent.innerHTML += `> ${msg}<br>`;
        terminal.scrollTop = terminal.scrollHeight;
    };

    setTimeout(() => log(`ESTABLISHING CONNECTION TO ${target}...`), 500);
    setTimeout(() => log(`RUNNING NMAP VULNERABILITY ENGINE...`), 1500);

    try {
        const response = await fetch(`${API_BASE}/api/scan`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ target })
        });
        const data = await response.json();

        if (data.error) {
            log(`SCAN ERROR: ${data.error}`);
        } else {
            log(`SCAN COMPLETE. DETECTED ${data.health_score}% HEALTH.`);
            log(`AUTOLOADING DETAILED INTELLIGENCE REPORT...`);
            updateHealthGauge(data.health_score);
            addAlertToFeed(data);
            showMitreDetails(data);
        }
    } catch (e) {
        log(`CRITICAL SYSTEM ERROR: ${e.message}`);
    } finally {
        scanBtn.disabled = false;
        scanBtn.innerText = 'RUN LIVE SCAN';
    }
};

async function fetchLogs() {
    try {
        const response = await fetch(`${API_BASE}/api/logs`);
        const logs = await response.json();
        const body = document.getElementById('log-table-body');
        if (!body) return;
        body.innerHTML = '';
        logs.forEach(log => {
            const tr = document.createElement('tr');
            tr.innerHTML = `
                <td style="padding: 1rem;">${log.timestamp}</td>
                <td style="padding: 1rem;">${log.type}</td>
                <td style="padding: 1rem;"><span class="alert-severity">${log.severity}</span></td>
                <td style="padding: 1rem;">${log.technique_name}</td>
                <td style="padding: 1rem;">${log.confidence}%</td>
            `;
            body.appendChild(tr);
        });
    } catch (e) { console.error(e); }
}

function updateHealthGauge(score) {
    const gauge = document.getElementById('health-score-gauge');
    const statusText = document.getElementById('health-status-text');
    if (!gauge) return;

    gauge.innerText = `${score}%`;

    let color = 'var(--success)';
    let status = 'OPTIMAL';

    if (score < 50) {
        color = 'var(--danger)';
        status = 'CRITICAL';
    } else if (score < 80) {
        color = 'var(--warning)';
        status = 'VULNERABLE';
    }

    gauge.style.borderColor = color;
    gauge.style.color = color;
    gauge.style.boxShadow = `0 0 20px ${color}44`;
    if (statusText) {
        statusText.innerText = status;
        statusText.style.color = color;
    }
}

window.simulateAttack = async function (type) {
    try {
        const response = await fetch(`${API_BASE}/api/simulate`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ type })
        });
        const data = await response.json();
        fetchAlerts();
    } catch (e) { console.error(e); }
};

// Navigation Logic
const navItems = document.querySelectorAll('nav li');
const views = document.querySelectorAll('.view');

navItems.forEach(item => {
    item.addEventListener('click', () => {
        navItems.forEach(nav => nav.classList.remove('active'));
        item.classList.add('active');

        const targetViewId = item.textContent.toLowerCase().replace(/\s/g, '-') + '-view';
        console.log("Switching to view:", targetViewId);

        views.forEach(view => {
            if (view.id === targetViewId) {
                view.classList.remove('hidden');
                if (view.id === 'vulnerability-logs-view') fetchLogs();
                if (view.id === 'threat-hub-view') initMLCharts();
            } else {
                view.classList.add('hidden');
            }
        });
    });
});

// Threat Hub Charts
async function initMLCharts() {
    try {
        const response = await fetch(`${API_BASE}/api/ml/metrics`);
        const data = await response.json();

        const ctx = document.getElementById('feature-chart');
        if (!ctx) return;

        new Chart(ctx, {
            type: 'bar',
            data: {
                labels: data.features,
                datasets: [{
                    label: 'System Load Metrics',
                    data: data.importances,
                    backgroundColor: 'rgba(0, 242, 255, 0.5)',
                    borderColor: 'var(--primary)',
                    borderWidth: 1
                }]
            },
            options: {
                responsive: true,
                indexAxis: 'y',
                scales: { x: { beginAtZero: true, grid: { color: 'rgba(255,255,255,0.05)' } }, y: { grid: { display: false } } },
                plugins: { legend: { display: false } }
            }
        });
    } catch (e) { console.error(e); }
}
