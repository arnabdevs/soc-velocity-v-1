# aegis-soc-engine | AI-Driven Cyber Defense

**AEGIS** is a next-generation Security Operations Center (SOC) Engine that leverages dual-engine Artificial Intelligence to detect, analyze, and neutralize network threats in real-time.

---

## 💎 Executive Summary
Traditional security relying on static rules fails against modern "Zero-Day" attacks. AEGIS solves this by combining **Supervised Learning** (for known patterns) and **Unsupervised Anomaly Detection** (for identifying novel threats).

### Key Business Values:
- **Reduced False Positives**: AI-driven confidence scoring ensures analysts focus only on real risks.
- **Immediate ROI**: Out-of-the-box support for the MITRE ATT&CK framework.
- **Premium Visualization**: High-fidelity "Mission Control" dashboard for executive oversight.

---

## 🛠️ Technology Stack
- **AI Core**: Scikit-learn (Random Forest & Isolation Forest)
- **Backend**: Flask (Python)
- **Frontend**: Mission Control UI (HTML5, Vanilla CSS, Chart.js)
- **Data Source**: Optimized CICIDS-2017 Feature Set

---

## 🚀 Hosting & Deployment

### 1. Backend (API)
The backend is ready for platforms like **Render**, **Heroku**, or **DigitalOcean**.
- **Build Command**: `pip install -r requirements.txt`
- **Start Command**: `python api/app.py` (Waitress will automatically handle production traffic).
- **Env Vars**: Set `HOST=0.0.0.0` and `PORT=5000` (or as required by the host).

### 2. Frontend (Dashboard)
Host on **Vercel** or **Netlify**.
- **Build Command**: `npm run build`
- **Output Directory**: `dist`
- **Note**: The dashboard automatically detects your API if hosted on the same domain or if the API URL follows the heuristic in `main.js`.

### 3. Docker (Recommended)
Run the entire stack with one command:
```bash
docker-compose up --build
```

---

## 🌩️ Free Hosting Recommendations

For a completely free "Mission Control" deployment, use these services:

### 1. Backend: [Render](https://render.com/) (Free Tier)
- **Repo**: Link your GitHub repo.
- **Environment**: Python.
- **Build Command**: `pip install -r requirements.txt`
- **Start Command**: `python api/app.py`
- **Env Var**: Add `AEGIS_API_KEY` with your chosen password.
- *Note: Free instances spin down after inactivity; the first request might take ~30 seconds.*

### 2. Frontend: [Vercel](https://vercel.com/) or [Netlify](https://www.netlify.com/)
- **Repo**: Link the same GitHub repo.
- **Root Directory**: `frontend`
- **Build Command**: None (or `npm run build` if using Vite)
- **Output Directory**: `.` (or `dist`)

---

## 📁 Repository Structure
```text
├── api/             # Flask Backend API
├── data/            # Data Generation & Raw Samples
├── detection/       # Core SOC Alert Logic
├── frontend/        # "Mission Control" Dashboard
├── models/          # Trained AI Models (.joblib)
├── preprocessing/   # Data Cleaning & Scaling
└── results/         # Evaluation Metrics & Graphs
```

Created with 🛡️ by the aegis-soc-engine Security Team.
