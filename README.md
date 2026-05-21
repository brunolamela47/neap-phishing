<div align="center">

# 🛡️ NEAP
### Network Email Anti-Phishing

<br/>

![Python](https://img.shields.io/badge/Python-3.11+-3776AB?style=for-the-badge&logo=python&logoColor=white)
![PyWebIO](https://img.shields.io/badge/PyWebIO-1.8+-00C4CC?style=for-the-badge&logo=python&logoColor=white)
![SQLite](https://img.shields.io/badge/SQLite-003B57?style=for-the-badge&logo=sqlite&logoColor=white)
![scikit-learn](https://img.shields.io/badge/scikit--learn-F7931E?style=for-the-badge&logo=scikit-learn&logoColor=white)
![Status](https://img.shields.io/badge/Status-In%20Development-yellow?style=for-the-badge)

<br/>

> Academic phishing detection and analysis system built with Python, PyWebIO, SQLite and Machine Learning.

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
| ![Python](https://img.shields.io/badge/-Python-3776AB?logo=python&logoColor=white) | Core language |
| ![PyWebIO](https://img.shields.io/badge/-PyWebIO-00C4CC?logo=python&logoColor=white) | Web interface via Python |
| ![SQLite](https://img.shields.io/badge/-SQLite-003B57?logo=sqlite&logoColor=white) | Local relational database |
| ![scikit-learn](https://img.shields.io/badge/-scikit--learn-F7931E?logo=scikit-learn&logoColor=white) | Machine Learning model |
| ![Pandas](https://img.shields.io/badge/-Pandas-150458?logo=pandas&logoColor=white) | Data processing |
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
│   ├── main.py              # PyWebIO main interface
│   ├── dashboard.py         # Dashboard page
│   ├── emails.py            # Email submission page
│   ├── analises.py          # Analysis page
│   └── logs.py              # Logs page
├── 📂 utils/
│   ├── score.py             # Phishing score engine
│   ├── alerts.py            # Alert management
│   └── heuristic.py         # Heuristic rules
├── requirements.txt
├── README.md
├── .gitignore
└── main.py                  # Application entry point
```

---

## 📊 Phishing Score

| Score | Risk Level | Classification |
|:---:|:---:|:---:|
| 0 — 30 | 🟢 Low | Legitimate |
| 31 — 60 | 🟡 Medium | Suspicious |
| 61 — 85 | 🟠 High | Likely Phishing |
| 86 — 100 | 🔴 Critical | Phishing |

---

## ✅ MVP Checklist

- [x] 4 relational tables (EMAILS, ANALISES, LOGS, ALERTAS)
- [x] PK on all tables
- [x] FK between all tables
- [x] Referential integrity enabled
- [ ] 5+ INSERT statements with test data
- [ ] 5+ SELECT queries
- [ ] 2+ JOIN queries
- [ ] Basic phishing score engine
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
<div align="center">

# 🛡️ NEAP
### Network Email Anti-Phishing

<br/>

![Python](https://img.shields.io/badge/Python-3.11+-3776AB?style=for-the-badge&logo=python&logoColor=white)
![PyWebIO](https://img.shields.io/badge/PyWebIO-1.8+-00C4CC?style=for-the-badge&logo=python&logoColor=white)
![SQLite](https://img.shields.io/badge/SQLite-003B57?style=for-the-badge&logo=sqlite&logoColor=white)
![scikit-learn](https://img.shields.io/badge/scikit--learn-F7931E?style=for-the-badge&logo=scikit-learn&logoColor=white)
![Status](https://img.shields.io/badge/Status-In%20Development-yellow?style=for-the-badge)

<br/>

> Academic phishing detection and analysis system built with Python, PyWebIO, SQLite and Machine Learning.

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
| ![Python](https://img.shields.io/badge/-Python-3776AB?logo=python&logoColor=white) | Core language |
| ![PyWebIO](https://img.shields.io/badge/-PyWebIO-00C4CC?logo=python&logoColor=white) | Web interface via Python |
| ![SQLite](https://img.shields.io/badge/-SQLite-003B57?logo=sqlite&logoColor=white) | Local relational database |
| ![scikit-learn](https://img.shields.io/badge/-scikit--learn-F7931E?logo=scikit-learn&logoColor=white) | Machine Learning model |
| ![Pandas](https://img.shields.io/badge/-Pandas-150458?logo=pandas&logoColor=white) | Data processing |
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
│   ├── main.py              # PyWebIO main interface
│   ├── dashboard.py         # Dashboard page
│   ├── emails.py            # Email submission page
│   ├── analises.py          # Analysis page
│   └── logs.py              # Logs page
├── 📂 utils/
│   ├── score.py             # Phishing score engine
│   ├── alerts.py            # Alert management
│   └── heuristic.py         # Heuristic rules
├── requirements.txt
├── README.md
├── .gitignore
└── main.py                  # Application entry point
```

---

## 📊 Phishing Score

| Score | Risk Level | Classification |
|:---:|:---:|:---:|
| 0 — 30 | 🟢 Low | Legitimate |
| 31 — 60 | 🟡 Medium | Suspicious |
| 61 — 85 | 🟠 High | Likely Phishing |
| 86 — 100 | 🔴 Critical | Phishing |

---

## ✅ MVP Checklist

- [x] 4 relational tables (EMAILS, ANALISES, LOGS, ALERTAS)
- [x] PK on all tables
- [x] FK between all tables
- [x] Referential integrity enabled
- [ ] 5+ INSERT statements with test data
- [ ] 5+ SELECT queries
- [ ] 2+ JOIN queries
- [ ] Basic phishing score engine
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
