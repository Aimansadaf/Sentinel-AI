# Sentinel-AI — LLM Prompt Firewall

Sentinel-AI is a three-gate security pipeline that sits between a user and a Large Language Model, protecting against prompt injection attacks, PII leakage, and unsafe outputs. It was built as a practical implementation of LLM security concepts using production-grade tools.

---

## How It Works

Most LLM applications send user input directly to the model with no validation. Sentinel-AI intercepts every prompt before it reaches the LLM and every response before it reaches the user.
```
User Prompt
     |
Gate 1 — PII Sanitization      Detects and redacts sensitive data
     |
Gate 2 — Injection Detection   Blocks jailbreaks and prompt attacks  
     |
Llama 3.1 via Groq
     |
Gate 3 — Output Safety Filter  Scans response before delivery
     |
User
```

---

## The Three Gates

**Gate 1 — PII Sanitization**

Built with Microsoft Presidio extended with seven custom pattern recognizers. Detects and redacts twelve types of sensitive data including email addresses, phone numbers, credit cards, social security numbers, API keys, GitHub tokens, AWS access keys, JWT tokens, Aadhaar numbers, Indian phone numbers, Ethereum wallets, and OpenAI keys. Gate 1 never blocks a prompt — it sanitizes and forwards the cleaned version to Gate 2.

**Gate 2 — Prompt Injection Detection**

Built with the ProtectAI DeBERTa model pre-trained on real jailbreak attacks. Blocks any prompt where the model returns an INJECTION label with confidence above 75%. An additional phrase detection layer catches social engineering attacks that use academic or research framing to bypass the classifier — a vulnerability discovered during red team testing.

**Gate 3 — Output Safety Filter**

Scans the LLM response before it reaches the user. Uses a toxicity classifier to catch harmful content and a set of regex patterns to detect credential leaks including OpenAI keys, GitHub tokens, AWS access keys, JWT tokens, private keys, database connection strings, and generic secrets. If either check fails the response is blocked entirely.

---

## Red Team Testing Results

| Attack | Type | Gate | Result |
|--------|------|------|--------|
| Direct instruction override | Prompt injection | Gate 2 | Blocked |
| DAN jailbreak attempt | Jailbreak | Gate 2 | Blocked |
| Evil AI roleplay framing | Roleplay attack | Gate 2 | Blocked |
| Academic research framing | Social engineering | Gate 2 | Blocked |
| AWS key format in prompt | Credential in input | Gate 1 | Sanitized |
| Tutorial credential generation | Credential in output | Gate 3 | Blocked |

The social engineering bypass was discovered during testing when the ProtectAI model scored a research-framed attack as safe. A phrase detection layer was added as a patch, which is documented in `gate2_semantic.py`.

---

## Security Dashboard

The sidebar shows a live security dashboard with session metrics, all-time threat statistics, attack type breakdown with percentages, and a recent threat log with confidence scores and timestamps. Threat data is written to `logs/threats.json` and persists across sessions.

---

## Tech Stack

| Tool | Purpose |
|------|---------|
| Python 3.12 | Core language |
| Streamlit | Frontend UI |
| LiteLLM | LLM wrapper |
| Groq API | Runs Llama 3.1 |
| Microsoft Presidio | PII detection |
| ProtectAI DeBERTa | Injection detection |
| martin-ha toxic-comment-model | Toxicity detection |
| Loguru | Threat logging |
| PyTorch 2.2.0 | ML backend |

---

## OWASP LLM Coverage

This project addresses the following risks from the OWASP Top 10 for LLM Applications:

- LLM01 Prompt Injection — Gate 2
- LLM02 Sensitive Information Disclosure — Gate 1 and Gate 3
- LLM06 Excessive Agency — Gate 3 output filtering

---

## Setup

**Requirements:** Python 3.10 or higher, Groq API key (free at console.groq.com)

**Clone the repository:**
```bash
git clone https://github.com/Aimansadaf/Sentinel-AI.git
cd Sentinel-AI
```

**Create a virtual environment:**
```bash
python -m venv .venv
.venv\Scripts\activate
```

**Install dependencies:**
```bash
pip install -r requirements.txt
```

**Download the spacy model:**
```bash
python -m spacy download en_core_web_lg
```

**Create a `.env` file in the project root:**
```
GROQ_API_KEY=your_groq_api_key_here
```

**Run the app:**
```bash
python -m streamlit run app.py
```

Open your browser at `http://localhost:8501`

---

## Project Structure
```
sentinel-ai/
├── app.py                      Main Streamlit application
├── gates/
│   ├── gate1_pii.py            PII detection and sanitization
│   ├── gate2_semantic.py       Prompt injection detection
│   └── gate3_output.py         Output safety filtering
├── data/
│   └── attack_signatures.json  Known attack patterns
├── logs/
│   └── threats.json            Persistent threat log
├── requirements.txt
├── Dockerfile
└── .env                        API keys — never commit this
```

---

## Author

Aiman Sadaf — 4th Year Computer Science Engineering Student

---

## License

MIT License