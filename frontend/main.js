// AEGIS SOC Engine - aegis-soc-engine - Protected by AI 🛡️
// Chart.js loaded via CDN

const alertFeed = document.getElementById('alert-feed');
const mitreContent = document.getElementById('mitre-content');

const isLocal = window.location.hostname === 'localhost' || window.location.hostname === '127.0.0.1';

// Production API URL
const PROD_API_BASE = 'https://defence-intelligence.onrender.com';

let API_BASE = isLocal ? 'http://localhost:5000' : PROD_API_BASE;

let API_KEY = localStorage.getItem('AEGIS_KEY');
let isGuest = false;

function checkAuth() {
    // If key exists in storage, bypass portal
    if (API_KEY) {
        document.getElementById('access-portal').classList.add('portal-hidden');
        initDashboard();
    }
}

window.handleLogin = function () {
    const input = document.getElementById('api-key-input').value;
    if (input) {
        API_KEY = input;
        localStorage.setItem('AEGIS_KEY', API_KEY);
        location.reload();
    } else {
        showLoginError();
    }
}

window.enterGuestMode = function () {
    isGuest = true;
    API_KEY = 'GUEST_ACCESS'; // Backend will allow reading with this
    document.getElementById('access-portal').classList.add('portal-hidden');
    initDashboard();
}

function showLoginError() {
    document.getElementById('login-error').style.display = 'block';
}

function initDashboard() {
    console.log("🚀 Initializing AEGIS Mission Control...");
    fetchStats();
    fetchAlerts();
    // Protect simulations
    if (isGuest) {
        document.querySelectorAll('button[onclick*="simulateAttack"]').forEach(btn => {
            btn.disabled = true;
            btn.style.opacity = '0.3';
            btn.title = 'ADMIN ACCESS REQUIRED';
        });
    }
}

checkAuth();

async function fetchStats() {
    try {
        const response = await fetch(`${API_BASE}/api/stats`, {
            headers: { 'X-API-Key': API_KEY }
        });
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
        const response = await fetch(`${API_BASE}/api/alerts/recent`, {
            headers: { 'X-API-Key': API_KEY }
        });
        const alerts = await response.json();

        alerts.forEach(alert => {
            addAlertToFeed(alert);
        });
    } catch (error) {
        console.error('Error fetching alerts:', error);
    }
}

function addAlertToFeed(alert) {
    const item = document.createElement('div');
    item.className = `alert-item ${alert.severity}`;
    item.innerHTML = `
        <div class="alert-header">
            <span class="alert-type">${alert.type}</span>
            <span class="alert-severity">${alert.severity}</span>
        </div>
        <div class="alert-details">
            ID: ${alert.alert_id} | Confidence: ${alert.confidence}% | Site: <span style="color: var(--primary)">${alert.target_site}</span>
        </div>
    `;

    item.onclick = () => showMitreDetails(alert);

    alertFeed.insertBefore(item, alertFeed.children[1]);

    // Keep only last 20 alerts
    if (alertFeed.children.length > 21) {
        alertFeed.removeChild(alertFeed.lastChild);
    }
}

function showMitreDetails(alert) {
    mitreContent.innerHTML = `
        <div style="background: rgba(0, 242, 255, 0.05); padding: 1.5rem; border-radius: 8px; border: 1px solid var(--primary)">
            <h3 style="color: var(--primary); margin-bottom: 0.5rem">${alert.technique_name}</h3>
            <p style="font-family: monospace; color: var(--secondary); margin-bottom: 1rem">${alert.mitre_technique}</p>
            <p style="font-size: 0.9rem; line-height: 1.6">${alert.description}</p>
            <div style="margin-top: 1.5rem; font-size: 0.8rem; color: #666">
                DETECTION MODE: ${alert.type === 'Anomaly' ? 'UNSUPERVISED (Isolation Forest)' : 'SUPERVISED (Random Forest)'}
            </div>
        </div>
    `;
}

window.simulateAttack = async function (type) {
    try {
        const response = await fetch(`${API_BASE}/api/simulate`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'X-API-Key': API_KEY
            },
            body: JSON.stringify({ type })
        });
        const data = await response.json();
        console.log('Simulation started:', data);
        // Instant refresh
        fetchAlerts();
    } catch (e) { console.error(e); }
};


// Global Site Search
const globalSiteSearch = document.getElementById('global-site-search');
if (globalSiteSearch) {
    globalSiteSearch.oninput = (e) => {
        const query = e.target.value.toLowerCase();
        const alertItems = document.querySelectorAll('.alert-item');
        alertItems.forEach(item => {
            const siteText = item.querySelector('.alert-details').textContent.toLowerCase();
            if (siteText.includes(query)) {
                item.style.display = 'block';
            } else {
                item.style.display = 'none';
            }
        });
    };
}

// Threat Hunt Logic
const logSearch = document.getElementById('log-search');
const logTableBody = document.getElementById('log-table-body');

async function fetchLogs(query = '') {
    try {
        const response = await fetch(`${API_BASE}/api/logs?search=${query}`, {
            headers: { 'X-API-Key': API_KEY }
        });
        const logs = await response.json();
        renderLogs(logs);
    } catch (e) { console.error(e); }
}

function renderLogs(logs) {
    logTableBody.innerHTML = '';
    logs.forEach(log => {
        const tr = document.createElement('tr');
        tr.style.borderBottom = "1px solid rgba(255,255,255,0.05)";
        tr.innerHTML = `
            <td style="padding: 1rem;">${log.timestamp}</td>
            <td style="padding: 1rem; color: var(--primary); font-weight: bold;">${log.type}</td>
            <td style="padding: 1rem;"><span class="alert-severity" style="background: ${log.severity === 'High' ? 'var(--danger)' : log.severity === 'Medium' ? 'var(--warning)' : 'var(--success)'}">${log.severity}</span></td>
            <td style="padding: 1rem;">${log.mitre_technique} - ${log.technique_name}</td>
            <td style="padding: 1rem; font-family: monospace;">${log.confidence}%</td>
        `;
        logTableBody.appendChild(tr);
    });
}

if (logSearch) logSearch.oninput = (e) => fetchLogs(e.target.value);

// ML Metrics Logic
let featureChart, trendChart;
async function initMLCharts() {
    try {
        const response = await fetch(`${API_BASE}/api/ml/metrics`, {
            headers: { 'X-API-Key': API_KEY }
        });
        const data = await response.json();

        const ctxF = document.getElementById('feature-chart').getContext('2d');
        featureChart = new Chart(ctxF, {
            type: 'bar',
            data: {
                labels: data.features.slice(0, 8),
                datasets: [{
                    label: 'Importance',
                    data: data.importances.slice(0, 8),
                    backgroundColor: 'rgba(0, 242, 255, 0.5)',
                    borderColor: '#00f2ff',
                    borderWidth: 1
                }]
            },
            options: { indexAxis: 'y', plugins: { legend: { display: false } } }
        });

        const ctxT = document.getElementById('trend-chart').getContext('2d');
        trendChart = new Chart(ctxT, {
            type: 'line',
            data: {
                labels: ['10:00', '11:00', '12:00', '13:00', '14:00', '15:00'],
                datasets: [{
                    label: 'Threats Detected',
                    data: [12, 19, 3, 5, 2, 3],
                    borderColor: '#7000ff',
                    tension: 0.4
                }]
            }
        });
    } catch (e) { console.error(e); }
}

// MITRE Matrix Logic
function initMitreMatrix() {
    const matrixGrid = document.getElementById('mitre-matrix-grid');
    if (!matrixGrid) return;
    const techniques = [
        { id: 'T1046', name: 'Network Service Scanning' },
        { id: 'T1110', name: 'Brute Force' },
        { id: 'T1059', name: 'Command & Scripting' },
        { id: 'T1190', name: 'Exploit Public-Facing App' },
        { id: 'T1133', name: 'External Remote Services' },
        { id: 'T1210', name: 'Exploitation of Remote Services' },
        { id: 'T1021', name: 'Remote Services' },
        { id: 'T1000', name: 'Unknown Anomaly' }
    ];

    matrixGrid.innerHTML = '';
    techniques.forEach(tech => {
        const card = document.createElement('div');
        card.style.cssText = "background: rgba(255,255,255,0.03); padding: 1rem; border-radius: 8px; border: 1px solid rgba(255,255,255,0.1); font-size: 0.8rem;";
        card.innerHTML = `
            <div style="color: #666; margin-bottom: 0.3rem;">${tech.id}</div>
            <div style="color: var(--text); font-weight: bold;">${tech.name}</div>
        `;
        matrixGrid.appendChild(card);
    });
}

// Navigation Logic
const navItems = document.querySelectorAll('nav li');
const views = document.querySelectorAll('.view');

navItems.forEach(item => {
    item.addEventListener('click', () => {
        // Update active nav
        navItems.forEach(nav => nav.classList.remove('active'));
        item.classList.add('active');

        // Update visible view
        const targetViewId = item.textContent.toLowerCase().replace(/\s/g, '-') + '-view';
        views.forEach(view => {
            if (view.id === targetViewId) {
                view.classList.remove('hidden');
                // Trigger view specific init
                if (view.id === 'threat-activity-view') fetchLogs();
                if (view.id === 'data-analytics-view' && !featureChart) initMLCharts();
                if (view.id === 'security-strategy-view') initMitreMatrix();
            } else {
                view.classList.add('hidden');
            }
        });
    });
});

// Uptime Counter
let seconds = 0;
setInterval(() => {
    seconds++;
    const h = Math.floor(seconds / 3600).toString().padStart(2, '0');
    const m = Math.floor((seconds % 3600) / 60).toString().padStart(2, '0');
    const s = (seconds % 60).toString().padStart(2, '0');
    document.getElementById('uptime').textContent = `${h}:${m}:${s}`;
}, 1000);

// Initial Dashboard Load removed from global scope to be manual via checkAuth
