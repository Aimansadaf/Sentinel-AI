# ============================================================
# GATE 3 — Output Safety Filter
# Tool: martin-ha/toxic-comment-model + regex
# Job: Scan LLM response before it reaches the user
# Rule: BLOCKS if toxic OR credentials leaked
# ============================================================

import re
import json
import os
from transformers import pipeline
from loguru import logger
from datetime import datetime

# ── Load toxicity model ONCE at startup ───────────────────
# This model checks if text is toxic or harmful
# Loading once = fast. Loading every request = slow.
print("Loading Gate 3 model...")
toxicity_checker = pipeline(
    "text-classification",
    model="martin-ha/toxic-comment-model"
)
print("Gate 3 model loaded.")

# ── Threat logging setup ───────────────────────────────────
LOG_FILE = os.path.join(
    os.path.dirname(__file__),
    "..",
    "logs",
    "threats.json"
)

# ── Credential patterns to detect ─────────────────────────
# These are regex patterns for common leaked credentials
# Regex is a way to search for specific text patterns
CREDENTIAL_PATTERNS = {
    "OpenAI API Key":   r"sk-[a-zA-Z0-9]{20,}",
    "GitHub Token":     r"ghp_[a-zA-Z0-9]{36}",
    "AWS Access Key":   r"AKIA[0-9A-Z]{16}",
    "JWT Token":        r"eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}",
    "Private Key":      r"-----BEGIN (RSA |EC )?PRIVATE KEY-----",
    "Database URL":     r"(mongodb|postgresql|mysql):\/\/[^\s]+",
    "Generic Secret":   r"(secret|password|passwd|pwd)\s*[:=]\s*\S+",
}


def log_output_threat(
    response: str,
    threat_type: str,
    score: float
):
    """
    Saves a blocked output to the threat log file.

    Args:
        response (str): The LLM response that was blocked
        threat_type (str): What type of threat was found
        score (float): Toxicity score if applicable
    """
    try:
        with open(LOG_FILE, "r") as f:
            threats = json.load(f)
    except Exception:
        threats = []

    threat_entry = {
        "timestamp": datetime.now().strftime(
            "%Y-%m-%d %H:%M:%S"
        ),
        "response_preview": response[:100],
        "threat_type": threat_type,
        "confidence_score": round(score, 4),
        "gate": "Gate 3 — Output Filter"
    }
    threats.append(threat_entry)

    try:
        with open(LOG_FILE, "w") as f:
            json.dump(threats, f, indent=2)
    except Exception as e:
        logger.error(f"Could not save threat log: {e}")


def scan_output(response: str) -> tuple:
    """
    Scans an LLM response for toxic content and
    leaked credentials before it reaches the user.

    Args:
        response (str): The raw LLM response

    Returns:
        is_safe (bool): True if response is safe
        toxicity_score (float): How toxic the response is
        leaked_credentials (bool): True if credentials found
    """

    # ── Step 1: Check for leaked credentials ──────────────
    # We scan the response for patterns that look like
    # API keys, tokens, passwords, database URLs etc.
    # If found — block immediately, don't even check toxicity
    leaked_credentials = False
    leaked_type = None

    for cred_name, pattern in CREDENTIAL_PATTERNS.items():
        if re.search(pattern, response, re.IGNORECASE):
            leaked_credentials = True
            leaked_type = cred_name
            break

    if leaked_credentials:
        logger.warning(
            f"Credential leak detected in output | "
            f"Type: {leaked_type} | "
            f"Preview: {response[:50]}..."
        )
        log_output_threat(response, f"Credential Leak: {leaked_type}", 1.0)
        return False, 0.0, True

    # ── Step 2: Check for toxic content ───────────────────
    # The toxicity model reads the response and returns
    # a label (toxic/non-toxic) and confidence score
    toxicity_result = toxicity_checker(
        response[:512]  # Model has a 512 token limit
    )[0]

    toxicity_label = toxicity_result["label"]
    toxicity_score = toxicity_result["score"]

    # ── Step 3: Apply blocking rule ────────────────────────
    # Block if the model says toxic AND is 80% confident
    # Higher threshold here (0.80) to avoid false positives
    # on responses that discuss security topics
    is_toxic = (
        toxicity_label == "toxic" and
        toxicity_score > 0.80
    )

    if is_toxic:
        logger.warning(
            f"Toxic output detected | "
            f"Score: {toxicity_score:.4f} | "
            f"Preview: {response[:50]}..."
        )
        log_output_threat(
            response,
            "Toxic Content",
            toxicity_score
        )

    # ── Step 4: Return results ─────────────────────────────
    is_safe = not is_toxic and not leaked_credentials
    return is_safe, round(toxicity_score, 4), leaked_credentials


# ============================================================
# TEST — Run this file directly to test Gate 3
# In your terminal: python gates\gate3_output.py
# ============================================================
if __name__ == "__main__":

    test_responses = [
        # Should be SAFE
        "The capital of France is Paris.",
        "Here is a Python function that adds two numbers.",
        "Machine learning is a subset of artificial intelligence.",

        # Should be BLOCKED — credential leak
        "Here is your API key: sk-abc123defgh456ijklmn789opqrst012345",
        "The database connection string is: mongodb://admin:password123@localhost:27017",
        "Your GitHub token is: ghp_abc123def456ghi789jkl012mno345pqr678stu",

        # Should be BLOCKED — toxic content
        "You are stupid and I hate you, go away forever.",
    ]

    print("=" * 55)
    print("GATE 3 — Output Safety Filter Test")
    print("=" * 55)

    for i, response in enumerate(test_responses, 1):
        is_safe, tox_score, leaked = scan_output(response)

        if is_safe:
            status = "🟢 SAFE — delivered to user"
        elif leaked:
            status = "🔴 BLOCKED — credential leak"
        else:
            status = "🔴 BLOCKED — toxic content"

        print(f"\nTest {i}:")
        print(f"  Response    : {response[:55]}...")
        print(f"  Toxic Score : {tox_score}")
        print(f"  Credentials : {leaked}")
        print(f"  Status      : {status}")

    print("\n" + "=" * 55)
    print("Gate 3 test complete.")
    print("=" * 55)