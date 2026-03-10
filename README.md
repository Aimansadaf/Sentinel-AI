# 🛡️ Sentinel-AI — LLM Prompt Firewall

A three-gate security pipeline that protects Large Language Models from prompt injection attacks, PII leakage, and unsafe outputs.

Built with Microsoft Presidio, ProtectAI DeBERTa, and toxicity detection — with full threat logging and a real-time security dashboard.

---

## 🔴 Live Demo

> Run locally — see setup instructions below.

📂 **GitHub:** [github.com/Aimansadaf/Sentinel-AI](https://github.com/Aimansadaf/Sentinel-AI)

---

## 🏗️ Architecture
```
User Prompt
     ↓
┌─────────────────────────────┐
│  GATE 1 — PII Sanitization  │  Microsoft Presidio + 7 custom recognizers
│  Detects and redacts 12     │  Never blocks — only sanitizes
│  types of sensitive data    │
└─────────────────────────────┘
     ↓ Cleaned Prompt
┌─────────────────────────────┐
│  GATE 2 — Injection         │  ProtectAI DeBERTa model
│  Detection                  │  Blocks if confidence > 75%
│  Catches jailbreaks and     │  + Social engineering phrase detection
│  prompt injection attacks   │
└─────────────────────────────┘
     ↓ Safe Prompt
┌─────────────────────────────┐
│       Llama 3 via Groq      │  groq/llama-3.1-8b-instant
└─────────────────────────────┘
     ↓ LLM Response
┌─────────────────────────────┐
│  GATE 3 — Output Safety     │  Toxicity classifier + regex patterns
│  Filter                     │  Blocks toxic content and credential leaks
│  Scans LLM response before  │
│  delivering to user         │
└─────────────────────────────┘
     ↓ Safe Response
   User
```

---

## 🔒 Security Gates

### Gate 1 — PII Sanitization
- Built with **Microsoft Presidio** extended with 7 custom recognizers
- Detects and redacts 12 PII types including Email, Phone, Credit Card, SSN, API Keys, GitHub Tokens, AWS Keys, JWT Tokens, Aadhaar Numbers, Indian phone numbers, Ethereum wallets, and OpenAI keys
- **Never blocks** — sanitizes and passes cleaned prompt forward

### Gate 2 — Prompt Injection Detection
- Built with **ProtectAI/deberta-v3-base-prompt-injection** (738MB pre-trained model)
- Blocks if `label == INJECTION` and `confidence > 75%`
- Additional **social engineering phrase detection** layer catches academic and research framing attacks
- All blocked prompts logged to `logs/threats.json`

### Gate 3 — Output Safety Filter
- Built with **martin-ha/toxic-comment-model**
- Blocks toxic responses with confidence > 80%
- Regex patterns detect credential leaks in LLM output:
  - OpenAI API Keys (`sk-`)
  - GitHub Tokens (`ghp_`)
  - AWS Access Keys (`AKIA`)
  - JWT Tokens (`eyJ`)
  - Private Keys
  - Database URLs
  - Generic secrets

---

## 🧪 Red Team Testing Results

| Attack | Type | Gate | Result |
|--------|------|------|--------|
| "Ignore all previous instructions" | Direct injection | Gate 2 | ✅ Blocked |
| "You are now DAN" | Jailbreak | Gate 2 | ✅ Blocked |
| "Pretend you are an evil AI" | Roleplay attack | Gate 2 | ✅ Blocked |
| Academic research framing | Social engineering | Gate 2 | ✅ Blocked |
| AWS key format request | Credential in prompt | Gate 1 | ✅ Sanitized |
| Tutorial credential generation | Credential in output | Gate 3 | ✅ Blocked |

---

## 📊 Security Dashboard

Real-time sidebar showing:
- Session metrics — prompts scanned and blocked
- All time threat statistics
- Attack type breakdown with percentages
- Recent threat log with confidence scores and timestamps

---

## 🛠️ Tech Stack

| Tool | Purpose |
|------|---------|
| Python 3.12 | Core language |
| Streamlit | Frontend UI |
| LiteLLM | LLM wrapper |
| Groq API | Runs Llama 3.1 |
| Microsoft Presidio | PII detection — Gate 1 |
| ProtectAI DeBERTa | Injection detection — Gate 2 |
| martin-ha toxic-comment-model | Toxicity detection — Gate 3 |
| Loguru | Threat logging |
| PyTorch 2.2.0 | ML backend |

---

## 🚀 Setup & Installation

### Prerequisites
- Python 3.10+
- Groq API key (free at [console.groq.com](https://console.groq.com))

### Installation

**1. Clone the repository:**
```bash
git clone https://github.com/Aimansadaf/Sentinel-AI.git
cd Sentinel-AI
```

**2. Create virtual environment:**
```bash
python -m venv .venv
.venv\Scripts\activate
```

**3. Install dependencies:**
```bash
pip install -r requirements.txt
```

**4. Download spacy model:**
```bash
python -m spacy download en_core_web_lg
```

**5. Create `.env` file:**
```
GROQ_API_KEY=your_groq_api_key_here
```

**6. Run the app:**
```bash
python -m streamlit run app.py
```

Open your browser at `http://localhost:8501`

---

## 📁 Project Structure
```
sentinel-ai/
├── app.py                      # Main Streamlit application
├── gates/
│   ├── gate1_pii.py            # PII detection and sanitization
│   ├── gate2_semantic.py       # Prompt injection detection
│   └── gate3_output.py         # Output safety filtering
├── data/
│   └── attack_signatures.json  # Known attack patterns
├── logs/
│   └── threats.json            # Persistent threat log
├── requirements.txt
├── Dockerfile
└── .env                        # API keys (never commit this)
```

---

## 🎯 OWASP LLM Coverage

This project addresses the following risks from the **OWASP Top 10 for LLM Applications:**

- **LLM01 — Prompt Injection** → Gate 2
- **LLM02 — Sensitive Information Disclosure** → Gate 1 + Gate 3
- **LLM06 — Excessive Agency** → Gate 3 output filtering

---

## 👨‍💻 Author

**Aiman Sadaf**
4th Year Computer Science Engineering Student

---

## 📄 License

MIT License — free to use and modify.
