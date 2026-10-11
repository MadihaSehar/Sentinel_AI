# 🛡️ SentinelAI

**Autonomous Multi-Model AI-Powered Web Security Assessment & Vulnerability Intelligence Platform**

[![Python 3.12](https://img.shields.io/badge/Python-3.12%2B-blue.svg)](https://www.python.org/)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.110%2B-009688.svg)](https://fastapi.tiangolo.com/)
[![Next.js](https://img.shields.io/badge/Next.js-14%2B-black.svg)](https://nextjs.org/)
[![Docker](https://img.shields.io/badge/Docker-Ready-2496ED.svg)](https://www.docker.com/)
[![Ollama](https://img.shields.io/badge/Ollama-Local_AI-orange.svg)](https://ollama.ai/)
[![PostgreSQL](https://img.shields.io/badge/PostgreSQL-16-336791.svg)](https://www.postgresql.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

> ⚠️ **Authorized Security Research Only**  
> SentinelAI is purpose-built for penetration testers, bug bounty researchers, CTF challenges, and security auditing. It strictly enforces a cryptographic authorization gate and scope constraints before any network discovery or scanning tool can be executed. Always ensure you have explicit, documented permission before testing any target.

---

## 🌟 Overview

**SentinelAI** combines automated security tooling with multi-model AI consensus to find, verify, and remediate web vulnerabilities with high accuracy and minimal false positives.

Unlike traditional static scanners or single-prompt wrappers:
- It coordinates full-pipeline scanning (Reconnaissance, Port & HTTP Discovery, Crawling, Nuclei).
- It analyzes raw HTTP requests and responses using a dedicated **Response Intelligence Engine**.
- It uses a **Multi-Model AI Consensus Engine** to independently evaluate vulnerabilities across different AI models (Google Gemini, xAI Grok, DeepSeek, or **local models via Ollama**) to verify findings before presenting them.
- It streams real-time scan progress to a **modern Next.js dashboard** via WebSockets.

---

## 🚀 Key Features

- **🛡️ Strict Authorization & Scope Gate**:
  - Requires explicit confirmation (`"I CONFIRM AUTHORIZATION"`) before moving out of `DRAFT` status.
  - Multi-layer CIDR and Domain boundary filtering with automatic SSRF protection.
  - Server-enforced rate-limiting and concurrency admission control.

- **🔍 Full-Lifecycle Security Scanning**:
  - Multi-stage pipeline: Recon $\rightarrow$ DNS $\rightarrow$ HTTP Discovery $\rightarrow$ Port Scan $\rightarrow$ Crawler $\rightarrow$ Directory Scan $\rightarrow$ Nuclei $\rightarrow$ AI Analysis $\rightarrow$ Reporting.
  - Tracks assets, technology stacks, endpoints, and open services.

- **🧠 Response Intelligence Engine**:
  - Automatically captures, normalizes, and fingerprints HTTP requests and responses.
  - Diff comparison engine for detecting reflected parameters, error traces, and header discrepancies.

- **🤖 Multi-Model AI Consensus (Cloud or 100% Local)**:
  - Supports **Google Gemini**, **xAI Grok**, **DeepSeek**, and **Local Ollama** (Llama 3.1, Qwen 2.5, Mistral).
  - Cross-model verification filters out hallucinations and flags high-confidence vulnerabilities.
  - Can run completely offline/air-gapped using Ollama with zero external API fees.

- **⚡ Real-Time Live Scan Streaming**:
  - WebSocket streaming endpoint (`/api/assessments/{id}/events`) provides instant updates to the frontend.
  - Interactive Next.js dashboard displaying live progress, discovered assets, and remediation advice.

---

## 🏗️ Architecture

```text
       ┌────────────────────────┐
       │     Next.js Web UI     │
       └───────────┬────────────┘
                   │ HTTP / WebSocket
                   ▼
       ┌────────────────────────┐
       │   FastAPI Core API     │
       └───────────┬────────────┘
                   │
    ┌──────────────┴──────────────┐
    ▼                             ▼
┌────────────────────────┐   ┌────────────────────────┐
│ Scope & Auth Gate      │   │ Response Intelligence  │
│ (SSRF / Rate Limiter)  │   │ (Diff / Indicators)    │
└───────────┬────────────┘   └───────────┬────────────┘
            │                            │
            ▼                            ▼
┌─────────────────────────────────────────────────────┐
│             Execution & Tool Pipeline               │
│   Recon • DNS • Ports • Crawl • Dirs • Nuclei       │
└──────────────────────────┬──────────────────────────┘
                           │
                           ▼
┌─────────────────────────────────────────────────────┐
│          Multi-Model AI Consensus Engine            │
│  Gemini  │  xAI Grok  │  DeepSeek  │  Local Ollama  │
└─────────────────────────────────────────────────────┘
```

---

## 📁 Repository Structure

```text
sentinel-ai/
├── backend/
│   ├── app/
│   │   ├── api/routes/          # API endpoints (auth, projects, scan, flat assessments, ws)
│   │   ├── ai/                  # AI consensus engine & provider integrations
│   │   │   ├── consensus/       # Multi-model voting & agreement logic
│   │   │   ├── providers/       # Gemini, Grok, DeepSeek, Local (Ollama)
│   │   │   └── prompts/         # Structured security analysis prompts
│   │   ├── core/                # Database engine, security auth, configuration
│   │   ├── models/              # SQLAlchemy 2.0 async models
│   │   ├── schemas/             # Pydantic v2 schemas
│   │   ├── services/            # Business logic & scope enforcement
│   │   └── main.py              # Application entrypoint & middleware
│   ├── tests/                   # Pytest test suite
│   └── requirements.txt
├── frontend/                    # Next.js 14 frontend dashboard
├── docker/
│   ├── backend.Dockerfile       # Backend container definition
│   └── frontend.Dockerfile      # Frontend container definition
├── docker-compose.yml           # Multi-service stack (DB, Redis, Backend, Frontend)
└── README.md
```

---

## ⚡ Quick Start

### Option 1: Docker Compose (Recommended)

1. **Clone the repository**:
   ```bash
   git clone https://github.com/MadihaSehar/Sentinel_AI.git
   cd Sentinel_AI
   ```

2. **Configure environment variables**:
   ```bash
   cp backend/.env.example .env
   ```
   *(Update your `.env` with a secure `SECRET_KEY` and optional AI API keys)*

3. **Start the platform**:
   ```bash
   docker compose up --build
   ```

4. **Access the platform**:
   - 🌐 **Web Dashboard**: [http://localhost:3000](http://localhost:3000)
   - 📖 **Interactive API Docs (Swagger)**: [http://localhost:8000/docs](http://localhost:8000/docs)
   - 🩺 **Health Check**: [http://localhost:8000/health](http://localhost:8000/health)

---

### Option 2: Running with Local Ollama (100% Free & Private)

To run without any cloud API keys:

1. **Install and run Ollama**:
   ```bash
   # Download from https://ollama.ai/ or install via Linux terminal:
   curl -fsSL https://ollama.ai/install.sh | sh
   ollama run llama3.1
   ```

2. SentinelAI's local provider will automatically connect to `http://localhost:11434/v1` to perform security reasoning and consensus completely on your machine.

---

### Option 3: Local Development (Without Docker)

#### 1. Backend Setup
```bash
cd backend
python -m venv venv
source venv/bin/activate  # On Windows: .\venv\Scripts\Activate.ps1
pip install -r requirements.txt

# Start backend server
uvicorn app.main:app --reload --port 8000
```

#### 2. Frontend Setup
```bash
cd frontend
npm install
npm run dev
```

---

## 🔌 API Endpoints Summary

| Method | Endpoint | Description |
|---|---|---|
| `POST` | `/api/auth/register` | Register new researcher account |
| `POST` | `/api/auth/token` | OAuth2 password bearer login |
| `GET` | `/api/projects` | List user projects |
| `GET` | `/api/assessments` | List all user assessments (dashboard view) |
| `POST` | `/api/projects/{id}/assessments` | Create assessment in DRAFT status |
| `POST` | `/api/assessments/{id}/authorize` | Submit authorization confirmation gate |
| `GET` | `/api/assessments/{id}/stages` | Retrieve pipeline execution stages |
| `GET` | `/api/assessments/{id}/assets` | Discovered assets & technologies |
| `GET` | `/api/assessments/{id}/findings` | Verified vulnerability findings |
| `GET` | `/api/assessments/{id}/ai-analysis`| AI decision log & consensus votes |
| `WS` | `/api/assessments/{id}/events` | Live WebSocket event stream |

---

## 🧪 Testing

Run the test suite with `pytest`:

```bash
cd backend
pytest tests/ -v
```

---

## 🤝 Responsible Disclosure & Compliance

SentinelAI is intended strictly for authorized security assessments. Unauthorized scanning of targets without prior written approval is illegal under the Computer Fraud and Abuse Act (CFAA), the UK Computer Misuse Act, and international cyber legislation.

---

## 📄 License

Distributed under the MIT License. See `LICENSE` for details.
