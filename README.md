<div align="center">

# 🛡️ NEAP
### Network Email Anti-Phishing

<br/>

![Python](https://img.shields.io/badge/Python-3.11+-3776AB?style=for-the-badge&logo=python&logoColor=white)
![PyWebView](https://img.shields.io/badge/PyWebView-5.0+-00C4CC?style=for-the-badge&logo=python&logoColor=white)
![SQLite](https://img.shields.io/badge/SQLite-003B57?style=for-the-badge&logo=sqlite&logoColor=white)
![scikit-learn](https://img.shields.io/badge/scikit--learn-F7931E?style=for-the-badge&logo=scikit-learn&logoColor=white)
![HTML](https://img.shields.io/badge/HTML5-E34F26?style=for-the-badge&logo=html5&logoColor=white)
![CSS](https://img.shields.io/badge/CSS3-1572B6?style=for-the-badge&logo=css3&logoColor=white)
![JavaScript](https://img.shields.io/badge/JavaScript-F7DF1E?style=for-the-badge&logo=javascript&logoColor=black)
![Status](https://img.shields.io/badge/Status-In%20Development-yellow?style=for-the-badge)

<br/>

> Academic phishing detection and analysis system built with Python, PyWebView, SQLite and Machine Learning.

<br/>

**CTeSP Cibersegurança · ISTEC Porto · 2025/2027**

---

</div>

## 📌 Overview

**NEAP** is an academic project developed for the subject *Introdução às Bases de Dados* at **ISTEC Porto**.

The system detects and analyzes phishing emails through:

- 🔍 **Heuristic text analysis** — suspicious keywords, urgency language
- 🔗 **URL inspection** — malicious link detection
- ✅ **SPF / DKIM / DMARC** — email authenticity verification
- 📊 **Phishing score engine** — automatic risk classification
- 🤖 **Machine Learning** — dataset-trained classification model
- 🗄️ **Relational database** — organized logging and monitoring

---

## 👥 Team — NEAP Team

| Member | Role |
|:---|:---|
| **Bruno Lamela** | 🏗️ Project Coordinator — Database structure, PK/FK, relational integrity |
| **Rafael Costa** | 🔍 Heuristic Analysis — Suspicious keywords, urgency language detection |
| **Pedro Ferreira** | 📊 Score Engine — Phishing score calculation and risk classification |
| **Filipe Soares** | 📋 SQL & Reports — Queries, JOINs, dashboards, visual reports |
| **Francisco Fernandes** | 🧪 Testing & Logs — INSERT data, log organization, SPF/DKIM/DMARC validation |

---

## 🛠️ Tech Stack

| Technology | Purpose |
|:---|:---|
| ![Python](https://img.shields.io/badge/-Python-3776AB?logo=python&logoColor=white) | Core language & backend logic |
| ![PyWebView](https://img.shields.io/badge/-PyWebView-00C4CC?logo=python&logoColor=white) | Native desktop window with HTML/CSS/JS |
| ![SQLite](https://img.shields.io/badge/-SQLite-003B57?logo=sqlite&logoColor=white) | Local relational database |
| ![scikit-learn](https://img.shields.io/badge/-scikit--learn-F7931E?logo=scikit-learn&logoColor=white) | Machine Learning model |
| ![Pandas](https://img.shields.io/badge/-Pandas-150458?logo=pandas&logoColor=white) | Data processing |
| ![HTML5](https://img.shields.io/badge/-HTML5-E34F26?logo=html5&logoColor=white) | Interface structure |
| ![CSS3](https://img.shields.io/badge/-CSS3-1572B6?logo=css3&logoColor=white) | Interface styling |
| ![JavaScript](https://img.shields.io/badge/-JavaScript-F7DF1E?logo=javascript&logoColor=black) | Interface interactivity |
| ![PyInstaller](https://img.shields.io/badge/-PyInstaller-000000?logo=python&logoColor=white) | Generate `.exe` executable |

---

## 🗄️ Database Structure

```
┌─────────────────────┐       ┌─────────────────────┐
│       EMAILS        │       │      ANALISES        │
├─────────────────────┤       ├─────────────────────┤
│ id_email      (PK)  │──────▶│ id_analise    (PK)  │
│ remetente           │       │ id_email      (FK)  │
│ assunto             │       │ score               │
│ corpo               │       │ resultado           │
│ data_hora           │       │ nivel_risco         │
└─────────────────────┘       └─────────────────────┘
                                        │
                                        ▼
                              ┌─────────────────────┐       ┌─────────────────────┐
                              │        LOGS         │       │      ALERTAS        │
                              ├─────────────────────┤       ├─────────────────────┤
                              │ id_log        (PK)  │──────▶│ id_alerta     (PK)  │
                              │ id_analise    (FK)  │       │ id_log        (FK)  │
                              │ data_hora           │       │ tipo_alerta         │
                              │ evento              │       │ estado_alerta       │
                              │ ip_origem           │       └─────────────────────┘
                              │ spf/dkim/dmarc      │
                              └─────────────────────┘
```

---

## 🔁 System Flow

```
📧 Email Received
        │
        ▼
🔍 Text Analysis (Heuristics)
        │
        ▼
✅ SPF / DKIM / DMARC Verification
        │
        ▼
🤖 ML Model Classification
        │
        ▼
📊 Phishing Score Calculation
        │
        ▼
🗄️ Database Storage (SQLite)
        │
        ▼
🚨 Dashboard / Alerts
```

---

## 🚀 Installation

```bash
# 1. Clone the repository
git clone https://github.com/brunolamela47/neap-phishing.git
cd neap-phishing

# 2. Create and activate virtual environment
python -m venv venv
venv\Scripts\activate        # Windows
source venv/bin/activate     # Linux / Mac

# 3. Install dependencies
pip install -r requirements.txt

# 4. Initialize the database
python database/database.py

# 5. Run the application
python main.py
```

---

## 📁 Project Structure

```
neap/
├── 📂 database/
│   └── database.py          # SQLite table creation
├── 📂 ml/
│   ├── model.py             # ML model (scikit-learn)
│   ├── train.py             # Model training
│   └── dataset/             # Phishing dataset (CSV)
├── 📂 interface/
│   ├── main.py              # PyWebView window setup
│   ├── analises.py          # Analysis logic
│   └── logs.py              # Logs logic
├── 📂 utils/
│   ├── heuristic.py         # Heuristic rules engine
│   ├── score.py             # Phishing score engine
│   └── alerts.py            # Alert management
├── 📂 web/                  # Frontend (HTML/CSS/JS)
│   ├── index.html           # Entry point
│   ├── 📂 pages/
│   │   ├── login.html       # Login page
│   │   ├── dashboard.html   # Dashboard page
│   │   ├── emails.html      # Email submission page
│   │   ├── analises.html    # Analysis page
│   │   ├── logs.html        # Logs page
│   │   └── alerts.html      # Alerts page
│   ├── 📂 css/
│   │   └── style.css        # Global styles
│   └── 📂 js/
│       └── app.js           # Frontend logic
├── requirements.txt
├── README.md
├── .gitignore
└── main.py                  # Application entry point
```

---

## 📊 Phishing Score

| Score | Risk Level | Classification |
|:---:|:---:|:---:|
| 0 — 30 | [LOW] | Legitimate |
| 31 — 60 | [MEDIUM] | Suspicious |
| 61 — 85 | [HIGH] | Likely Phishing |
| 86 — 100 | [CRITICAL] | Phishing |

---

## ✅ MVP Checklist

- [x] 4 relational tables (EMAILS, ANALISES, LOGS, ALERTAS)
- [x] PK on all tables
- [x] FK between all tables
- [x] Referential integrity enabled
- [x] Heuristic analysis engine
- [x] Phishing score engine
- [ ] 5+ INSERT statements with test data
- [ ] 5+ SELECT queries
- [ ] 2+ JOIN queries
- [ ] Frontend interface (HTML/CSS/JS)
- [ ] PyWebView desktop window
- [ ] Sensitive data identification
- [ ] Basic access control rules

---

## ⚙️ Extra Features (Post-MVP)

- [ ] ML model trained on phishing dataset
- [ ] Real-time monitoring dashboard
- [ ] SPF/DKIM/DMARC live verification
- [ ] Export reports to PDF / Excel
- [ ] MFA / TOTP authentication
- [ ] Database normalization up to 3NF
- [ ] Generate `.exe` with PyInstaller

---

## 🔐 Sensitive Data Handled

```
✦ Email credentials        ✦ Suspicious URLs
✦ Authentication tokens    ✦ IP addresses
✦ Monitoring logs          ✦ User data
✦ Risk reports             ✦ Authentication info
```

---

<div align="center">

**NEAP DB — organizing, relating, monitoring and identifying real phishing threats.**

<br/>

*Academic project · CTeSP Cibersegurança · ISTEC Porto · 2025/2027*

</div>
