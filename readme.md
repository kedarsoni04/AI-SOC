# 🛡️ AI-Powered Cybersecurity SOC

> **An intelligent Security Operations Center for real-time threat detection, incident correlation, AI-assisted investigation, and security response.**

[![Python](https://img.shields.io/badge/Python-3.11+-blue?logo=python)](https://www.python.org/)
[![React](https://img.shields.io/badge/React-TypeScript-61DAFB?logo=react)](https://react.dev/)
[![FastAPI](https://img.shields.io/badge/FastAPI-Backend-009688?logo=fastapi)](https://fastapi.tiangolo.com/)
[![PostgreSQL](https://img.shields.io/badge/PostgreSQL-Database-4169E1?logo=postgresql)](https://www.postgresql.org/)
[![Docker](https://img.shields.io/badge/Docker-Containerized-2496ED?logo=docker)](https://www.docker.com/)
[![AI](https://img.shields.io/badge/AI-LLM%20Assisted-purple)](#-ai-powered-investigation)
[![Live Demo](https://img.shields.io/badge/Live%20Demo-Vercel-black?logo=vercel)](https://ai-soc.vercel.app)

## 🌐 Live Demo

| Service | URL |
|---|---|
| 🖥️ Frontend (Vercel) | **[ai-soc.vercel.app](https://ai-soc-eta.vercel.app)** *(update with your Vercel URL)* |
| ⚙️ Backend API (Render) | **[ai-soc-backend.onrender.com](https://ai-soc-ts2l.onrender.com/docs)** *(update with your Render URL)* |

> **Default credentials**: `admin` / `Admin@123`
> 
> ⚠️ *The backend is hosted on Render's free tier and may take 30–50 seconds to wake up on first visit.*


---

## 📸 Dashboard Preview

![AI-SOC Dashboard](docs/images/dashboard_preview.png)

*Real-time SOC dashboard with live event monitoring, attack simulation engine, incident tracking, and threat analytics.*

---

## 📌 Overview

**AI-Powered Cybersecurity SOC** is a full-stack security monitoring and threat detection platform designed to simulate the core capabilities of a modern **Security Operations Center (SOC)**.

The platform continuously ingests security events, normalizes and analyzes them using a combination of **rule-based detection and machine learning**, correlates related events into incidents, calculates transparent risk scores, and uses an **LLM-powered investigation engine** to explain threats and recommend response actions.

Unlike a simple security dashboard, the system implements an end-to-end security workflow:

```text
Security Events
      ↓
Log Ingestion
      ↓
Log Normalization
      ↓
Rule-Based Detection
      +
ML Anomaly Detection
      ↓
Event Correlation
      ↓
Incident Creation
      ↓
Risk Scoring
      ↓
AI Investigation
      ↓
MITRE ATT&CK Mapping
      ↓
Response Recommendation
      ↓
Analyst Approval
      ↓
Audit Logging
```

---

## 🎯 Problem Statement

Modern organizations generate enormous amounts of security data from:

* Authentication systems
* Web servers
* Applications
* Databases
* Cloud infrastructure
* Network devices
* Endpoints

Manually analyzing these events is time-consuming and makes it difficult for security analysts to identify sophisticated multi-stage attacks.

Traditional rule-based systems can detect known patterns but may struggle with previously unseen behavior.

This project addresses the problem by combining:

* 🔍 Rule-based threat detection
* 🤖 Machine learning anomaly detection
* 🧠 LLM-assisted security investigation
* 🔗 Event correlation
* 📊 Risk-based prioritization
* 🛡️ Controlled response recommendations

---

# 🚀 Key Features

## 🔐 Authentication & RBAC

Secure access control with multiple roles:

* **Admin**
* **SOC Analyst**
* **Viewer**

Includes:

* JWT authentication
* Password hashing
* Protected routes
* Role-based permissions
* Session management

---

## 📡 Real-Time Log Ingestion

The platform accepts security events from different sources and converts them into a standardized event format.

Supported simulated sources include:

* Authentication servers
* Web servers
* Application servers
* Cloud infrastructure
* Network activity

Example event:

```json
{
  "timestamp": "2026-08-29T10:32:04",
  "source_ip": "192.168.1.25",
  "username": "admin",
  "event_type": "LOGIN_FAILED",
  "source": "authentication_server"
}
```

---

# 🚨 Threat Detection Engine

The SOC uses multiple detection mechanisms.

### Rule-Based Detection

Detects known attack patterns such as:

* Brute-force attacks
* SQL injection
* Port scanning
* Privilege escalation
* Suspicious logins
* Data exfiltration
* Impossible travel

Example:

```text
10+ failed login attempts
        +
Same source IP
        +
Within 5 minutes
        ↓
BRUTE FORCE DETECTED
```

---

# 🤖 Machine Learning Detection

The platform uses machine learning to identify anomalous behavior that may not match predefined rules.

### Initial ML approach

**Isolation Forest**

Features may include:

* Requests per minute
* Failed login count
* Successful login count
* Unique destination ports
* Bytes transferred
* Authentication frequency
* Number of accessed endpoints

The system produces an anomaly score for incoming activity.

```text
Normal behavior
       ↓
Feature extraction
       ↓
ML model
       ↓
Anomaly score
       ↓
Potential threat
```

---

# 🧠 AI-Powered Investigation

The LLM is used as an **investigation assistant**, not as the primary detection mechanism.

The deterministic detection and ML layers first generate evidence.

The AI then analyzes that evidence and produces:

### Incident Summary

A concise explanation of what happened.

### Attack Analysis

Possible attack sequence and reasoning.

### Evidence

Important events supporting the investigation.

### MITRE ATT&CK Mapping

Relevant tactics and techniques.

### Recommended Response

Suggested containment and investigation actions.

### Confidence

An estimate of confidence based on available evidence.

Example:

```text
INCIDENT #1042

Type:
Possible Account Compromise

Risk:
94 / 100 — CRITICAL

Evidence:
• 47 failed login attempts
• Successful login immediately afterward
• Privilege escalation
• Large outbound data transfer

AI Assessment:
The observed sequence is consistent with a possible
account compromise followed by privilege escalation
and data exfiltration.

Recommended Actions:
1. Revoke active sessions
2. Reset credentials
3. Investigate affected account
4. Block suspicious source
5. Review transferred data
```

---

# 🔗 Event Correlation

Individual alerts are correlated into meaningful security incidents.

For example:

```text
47 Failed Logins
       ↓
Successful Login
       ↓
Privilege Escalation
       ↓
Database Access
       ↓
Large Data Transfer
       ↓
┌─────────────────────────────┐
│ Possible Account Compromise │
│ + Data Exfiltration         │
└─────────────────────────────┘
```

This prevents analysts from having to investigate hundreds of individual alerts separately.

---

# 🎯 Risk Scoring

Every incident receives a transparent score between **0 and 100**.

Factors include:

* Threat severity
* Asset criticality
* Attack frequency
* User privilege
* Data sensitivity
* ML anomaly score
* Evidence strength

Example:

```text
Threat Severity       +25
Asset Criticality     +20
Attack Frequency      +15
User Privilege        +20
Data Exfiltration     +14
────────────────────────────
Final Risk Score       94/100

Severity: CRITICAL
```

The score is generated using a deterministic scoring system rather than asking the LLM to invent a risk value.

---

# 🧬 MITRE ATT&CK Integration

Detected incidents can be mapped to relevant **MITRE ATT&CK tactics and techniques**.

Example:

```text
Credential Access
        ↓
Brute Force

Persistence / Defense Evasion
        ↓
Valid Accounts

Privilege Escalation
        ↓
Account Manipulation

Discovery
        ↓
Network Service Scanning

Exfiltration
        ↓
Exfiltration Over Web Service
```

This allows analysts to understand attacks using a standardized cybersecurity framework.

---

# 🌍 Threat Intelligence

The platform includes an internal threat-intelligence module for tracking:

* IP addresses
* Domains
* File hashes
* Threat types
* Confidence levels
* First-seen timestamps
* Last-seen timestamps
* Intelligence sources

Analysts can search indicators and associate them with incidents.

The architecture is designed so external threat-intelligence providers can be integrated later.

---

# 🗺️ Attack Map

The SOC provides a visual representation of suspicious activity.

The map can display:

* Source location
* Source IP
* Attack count
* Threat severity
* Geographic distribution

For development and demonstration, simulated geolocation data can be used.

---

# ⏱️ Incident Timeline

Every incident contains a chronological timeline of related events.

Example:

```text
10:31:02
Failed Login

      ↓

10:31:05
15 Failed Login Attempts

      ↓

10:31:21
Successful Login

      ↓

10:32:03
Privilege Escalation

      ↓

10:33:18
Database Access

      ↓

10:34:02
Large Data Transfer
```

Analysts can inspect both the normalized event and its original raw data.

---

# ⚡ Real-Time Monitoring

The dashboard uses **WebSockets** to display security activity in real time.

When a simulated attack occurs:

```text
Attack Generated
      ↓
Event Ingested
      ↓
Threat Detected
      ↓
Alert Generated
      ↓
Incident Created
      ↓
Risk Calculated
      ↓
Dashboard Updated
```

No manual page refresh is required.

---

# 🧪 Attack Simulation

The project includes a security-event simulation engine.

Available simulations:

* 🟢 Normal Traffic
* 🔴 Brute Force
* 🔴 SQL Injection
* 🔴 Port Scan
* 🔴 Account Compromise
* 🔴 Data Exfiltration
* 🔥 Multi-Stage Attack

### Multi-Stage Attack

The primary demonstration scenario:

```text
Brute Force
     ↓
Successful Login
     ↓
Privilege Escalation
     ↓
Database Access
     ↓
Data Exfiltration
```

The SOC should automatically detect and correlate these events into a single incident.

---

# 🛡️ Controlled Response Engine

The response system provides recommended actions such as:

* Block IP
* Disable account
* Revoke session
* Reset credentials
* Isolate endpoint
* Create investigation ticket

The system follows a **human-in-the-loop** approach:

```text
Threat Detected
      ↓
AI Recommendation
      ↓
SOC Analyst Review
      ↓
Approval
      ↓
Response
      ↓
Audit Log
```

The AI is **not permitted to execute arbitrary commands**.

For demonstration purposes, response actions can be simulated.

---

# 📊 SOC Dashboard

The dashboard provides an overview of the security environment.

### Metrics

* Total Events
* Active Incidents
* Critical Incidents
* High-Risk Alerts
* Resolved Incidents
* Blocked IPs
* Threats Detected

### Analytics

* Events over time
* Threat severity
* Attack categories
* Top source IPs
* Top targeted users
* Incident trends
* Detection methods

---

# 🏗️ System Architecture

```text
                        ┌────────────────────┐
                        │    SOC Analyst     │
                        └─────────┬──────────┘
                                  │
                                  ↓
                        ┌────────────────────┐
                        │ React + TypeScript │
                        │    SOC Dashboard   │
                        └─────────┬──────────┘
                                  │
                           REST / WebSocket
                                  │
                                  ↓
                        ┌────────────────────┐
                        │      FastAPI      │
                        │      Backend      │
                        └─────────┬──────────┘
                                  │
              ┌───────────────────┼───────────────────┐
              ↓                   ↓                   ↓
       ┌─────────────┐     ┌─────────────┐     ┌─────────────┐
       │ PostgreSQL  │     │ Detection   │     │ AI Engine   │
       │  Database   │     │   Engine    │     │    LLM      │
       └─────────────┘     └──────┬──────┘     └──────┬──────┘
                                  │                   │
                           ┌──────┴──────┐            │
                           ↓             ↓            │
                     Rule Engine    ML Engine         │
                           │             │             │
                           └──────┬──────┘             │
                                  ↓                   │
                           Event Correlation          │
                                  │                   │
                                  ↓                   │
                              Incidents ──────────────┘
                                  │
                                  ↓
                          Response Engine
                                  │
                                  ↓
                            Audit Logging
```

---

# 🧰 Technology Stack

| Layer              | Technology                        |
| ------------------ | --------------------------------- |
| Frontend           | React 19, TypeScript, Vite        |
| Styling            | Tailwind CSS                      |
| Charts             | Recharts                          |
| Map                | D3-Geo (custom SVG world map)     |
| Icons              | Lucide React                      |
| State              | Zustand                           |
| Backend            | Python 3.11, FastAPI              |
| Database           | PostgreSQL (Supabase)             |
| ORM                | SQLAlchemy (async)                |
| DB Driver          | asyncpg                           |
| Authentication     | JWT (python-jose)                 |
| Machine Learning   | Scikit-learn, XGBoost             |
| AI                 | Google Gemini API                 |
| Real-Time          | WebSockets                        |
| Containers         | Docker + Docker Compose           |
| Frontend Hosting   | Vercel                            |
| Backend Hosting    | Render                            |
| Security Framework | MITRE ATT&CK                      |

---

# 📁 Project Structure

```text
ai-cybersecurity-soc/
│
├── frontend/
│   ├── src/
│   │   ├── components/
│   │   ├── pages/
│   │   ├── hooks/
│   │   ├── services/
│   │   └── types/
│   └── package.json
│
├── backend/
│   ├── app/
│   │   ├── api/
│   │   ├── core/
│   │   ├── models/
│   │   ├── schemas/
│   │   ├── services/
│   │   ├── detection/
│   │   ├── incidents/
│   │   └── main.py
│   ├── migrations/
│   └── requirements.txt
│
├── ml/
│   ├── models/
│   ├── training/
│   ├── preprocessing/
│   └── inference/
│
├── simulation/
│   ├── normal_traffic/
│   ├── attacks/
│   └── simulator.py
│
├── tests/
│   ├── backend/
│   ├── frontend/
│   ├── detection/
│   └── integration/
│
├── docs/
│   ├── architecture.md
│   ├── api.md
│   ├── ml-pipeline.md
│   ├── ai-investigation.md
│   └── security.md
│
├── docker-compose.yml
├── .env.example
├── .gitignore
└── README.md
```

---

# 🗄️ Database

The system uses PostgreSQL with entities including:

```text
Users
  │
  └── Roles

Security Events
  │
  ├── Alerts
  │      │
  │      └── Incidents
  │             │
  │             ├── Incident Events
  │             ├── AI Investigations
  │             └── Response Actions
  │
  └── ML Predictions

Threat Intelligence
      │
      └── Indicators

Audit Logs
```

Main tables:

* `users`
* `roles`
* `security_events`
* `alerts`
* `incidents`
* `incident_events`
* `detection_rules`
* `threat_intelligence`
* `response_actions`
* `audit_logs`
* `ml_predictions`
* `ai_investigations`

---

# 🔌 API

The backend exposes REST APIs through FastAPI.

Examples:

```text
POST   /auth/login

GET    /dashboard/summary

GET    /events
POST   /events
GET    /events/{id}

GET    /alerts
GET    /alerts/{id}
PATCH  /alerts/{id}

GET    /incidents
POST   /incidents
GET    /incidents/{id}
PATCH  /incidents/{id}

POST   /incidents/{id}/investigate
GET    /incidents/{id}/timeline

GET    /threat-intelligence
POST   /threat-intelligence

GET    /ml/performance

POST   /simulation/start
POST   /simulation/stop

GET    /audit-logs
```

Interactive API documentation is available through FastAPI's OpenAPI interface.

---

# 🧪 Machine Learning Pipeline

```text
Raw Security Events
        ↓
Feature Extraction
        ↓
Data Preprocessing
        ↓
Model Training
        ↓
Model Evaluation
        ↓
Model Serialization
        ↓
Real-Time Inference
        ↓
Anomaly Score
        ↓
Threat Detection
```

### Evaluation Metrics

The ML module tracks:

* Accuracy
* Precision
* Recall
* F1 Score
* Confusion Matrix
* False Positive Rate

---

# 🔒 Security Considerations

Security is a core component of the project.

Implemented practices include:

* Password hashing
* JWT expiration
* RBAC
* Input validation
* SQL injection protection through ORM
* CORS configuration
* Rate limiting
* Environment variables
* Secure error handling
* Audit logging
* No secrets committed to source control

Sensitive configuration must be stored using environment variables.

Example:

```env
DATABASE_URL=
JWT_SECRET=
AI_API_KEY=
```

---

# 🐳 Running with Docker

Clone the repository:

```bash
git clone https://github.com/<your-username>/ai-cybersecurity-soc.git

cd ai-cybersecurity-soc
```

Create your environment file:

```bash
cp .env.example .env
```

Configure the required variables.

Start the application:

```bash
docker compose up --build
```

The services will start through Docker Compose.

---

# 💻 Local Development

## Backend

```bash
cd backend

python -m venv venv

# Windows
venv\Scripts\activate

# Linux/macOS
source venv/bin/activate

pip install -r requirements.txt

uvicorn app.main:app --reload
```

## Frontend

```bash
cd frontend

npm install

npm run dev
```

---

# 🧪 Testing

Run backend tests:

```bash
pytest
```

Run frontend tests:

```bash
npm test
```

Run linting:

```bash
npm run lint
```

Integration tests should validate the complete security pipeline:

```text
Event
 ↓
Detection
 ↓
Alert
 ↓
Correlation
 ↓
Incident
 ↓
Risk Score
 ↓
AI Investigation
 ↓
Response
 ↓
Audit Log
```

---

# ☁️ Deployment

This project is deployed using managed cloud services:

| Service | Provider | Purpose |
|---|---|---|
| Frontend | [Vercel](https://vercel.com) | React/Vite static hosting with CDN |
| Backend API | [Render](https://render.com) | Docker-based FastAPI container |
| Database | [Supabase](https://supabase.com) | Managed PostgreSQL (free tier) |

### Deploy Your Own Instance

1. **Database**: Create a free project on [Supabase](https://supabase.com) and grab the **Session Pooler** connection string.
2. **Backend**: Create a new Web Service on [Render](https://render.com), connect your GitHub repo, set Root Directory to `backend`, and add environment variables:
   - `DATABASE_URL` → Supabase connection string
   - `SECRET_KEY` → any long random string
   - `ENVIRONMENT` → `production`
3. **Frontend**: Import your repo into [Vercel](https://vercel.com), set Root Directory to `frontend`, and add:
   - `VITE_API_BASE_URL` → `https://<your-render-url>/api/v1`
   - `VITE_WS_URL` → `wss://<your-render-url>/api/v1/ws`

```text
         Vercel (Frontend)
               │
           REST / WSS
               │
        Render (Backend)
               │
       Supabase (PostgreSQL)
```

---

# 📈 Future Enhancements

Potential future improvements include:

* Real SIEM integrations
* AWS CloudTrail integration
* Endpoint telemetry
* Advanced threat intelligence APIs
* Kafka-based event streaming
* Elasticsearch/OpenSearch integration
* Advanced deep-learning models
* Automated playbooks
* SOAR integration
* Multi-tenant architecture
* Kubernetes deployment
* Advanced UEBA
* Federated learning
* Local LLM deployment
* More sophisticated MITRE ATT&CK coverage

---

# 🎓 Academic Value

This project combines multiple areas of Computer Science:

### Artificial Intelligence

* LLMs
* Machine learning
* Anomaly detection
* AI-assisted reasoning

### Cybersecurity

* Threat detection
* Incident response
* Security monitoring
* MITRE ATT&CK

### Software Engineering

* REST APIs
* Authentication
* Database design
* Testing
* Modular architecture

### Cloud & DevOps

* Docker
* AWS
* CI/CD
* Deployment
* Monitoring

### Data Engineering

* Log ingestion
* Event normalization
* Feature extraction
* Real-time processing

---

# 🎥 Primary Demonstration Scenario

The recommended project demonstration is a simulated multi-stage attack.

```text
                    ATTACK
                      │
                      ↓
              Brute Force Attack
                      │
                      ↓
               Account Compromise
                      │
                      ↓
              Privilege Escalation
                      │
                      ↓
                Database Access
                      │
                      ↓
               Data Exfiltration
                      │
                      ↓
              ┌───────────────┐
              │ SOC Detection │
              └───────┬───────┘
                      ↓
                 Risk: 94/100
                      ↓
              AI Investigation
                      ↓
              MITRE ATT&CK Map
                      ↓
             Response Recommendation
                      ↓
               Analyst Approval
                      ↓
                 Audit Log
```

This demonstrates the complete capability of the platform in a single workflow.

---

# 👨‍💻 Project

**AI-Powered Cybersecurity SOC**

### Developed as a Final Year B.Tech Computer Science Project

**Focus Areas:**

`Artificial Intelligence` · `Cybersecurity` · `Machine Learning` · `Cloud Computing` · `Full-Stack Development` · `DevOps`

---

## ⚠️ Disclaimer

This project is intended for **educational, research, and defensive cybersecurity purposes**.

Attack simulations are designed to demonstrate detection and incident-response capabilities in controlled environments. No unauthorized systems should be targeted or tested.

---

## ⭐ If you find this project interesting

Give the repository a ⭐ and feel free to explore, contribute, or suggest improvements.
