# ============================================================
# GATE 1 — PII Sanitization
# Tool: Microsoft Presidio
# Job: Find and mask private data in user prompts
# Rule: NEVER blocks — only cleans the prompt
# ============================================================

from presidio_analyzer import AnalyzerEngine
from presidio_analyzer import PatternRecognizer
from presidio_analyzer.pattern import Pattern
from presidio_anonymizer import AnonymizerEngine
from presidio_anonymizer.entities import OperatorConfig

# ── Load Presidio engines ONCE at startup ──────────────────
# We load these outside the function so they are not
# reloaded every time someone sends a prompt.
# Loading once = fast. Loading every request = slow.
analyzer = AnalyzerEngine()
anonymizer = AnonymizerEngine()

# ── Custom recognizer for Ethereum Wallets ─────────────────
# Presidio misses Ethereum (0x...) wallets by default
# We teach it the pattern manually using regex
eth_pattern = Pattern(
    name="ethereum_wallet",
    regex=r"0x[a-fA-F0-9]{40}",
    score=0.9
)
eth_recognizer = PatternRecognizer(
    supported_entity="CRYPTO",
    patterns=[eth_pattern]
)
analyzer.registry.add_recognizer(eth_recognizer)

# ── Custom recognizer for OpenAI API Keys ──────────────────
# Detects keys like sk-abc123xxxxxx
api_key_pattern = Pattern(
    name="api_key",
    regex=r"sk-[a-zA-Z0-9]{20,}",
    score=0.9
)
api_key_recognizer = PatternRecognizer(
    supported_entity="API_KEY",
    patterns=[api_key_pattern]
)
analyzer.registry.add_recognizer(api_key_recognizer)

# ── Custom recognizer for GitHub Tokens ────────────────────
# Detects tokens like ghp_xxxxxxxxxxxx
github_pattern = Pattern(
    name="github_token",
    regex=r"ghp_[a-zA-Z0-9]{36}",
    score=0.9
)
github_recognizer = PatternRecognizer(
    supported_entity="GITHUB_TOKEN",
    patterns=[github_pattern]
)
analyzer.registry.add_recognizer(github_recognizer)

# ── Custom recognizer for AWS Access Keys ──────────────────
# Detects keys like AKIA1234567890ABCDEF
aws_pattern = Pattern(
    name="aws_key",
    regex=r"AKIA[0-9A-Z]{16}",
    score=0.9
)
aws_recognizer = PatternRecognizer(
    supported_entity="AWS_KEY",
    patterns=[aws_pattern]
)
analyzer.registry.add_recognizer(aws_recognizer)

# ── Custom recognizer for Indian Phone Numbers ─────────────
# Catches formats like +91 98765 43210 or 9876543210
indian_phone_pattern = Pattern(
    name="indian_phone",
    regex=r"(\+91[\-\s]?)?[6-9]\d{9}",
    score=0.9
)
indian_phone_recognizer = PatternRecognizer(
    supported_entity="PHONE_NUMBER",
    patterns=[indian_phone_pattern]
)
analyzer.registry.add_recognizer(indian_phone_recognizer)

# ── Custom recognizer for US SSN ───────────────────────────
# Catches format like 123-45-6789 more reliably
ssn_pattern = Pattern(
    name="us_ssn_custom",
    regex=r"\b\d{3}-\d{2}-\d{4}\b",
    score=0.85
)
ssn_recognizer = PatternRecognizer(
    supported_entity="US_SSN",
    patterns=[ssn_pattern]
)
analyzer.registry.add_recognizer(ssn_recognizer)

# ── Custom recognizer for JWT Tokens ───────────────────────
# Detects tokens like eyJhbGci...
jwt_pattern = Pattern(
    name="jwt_token",
    regex=r"eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}",
    score=0.9
)
jwt_recognizer = PatternRecognizer(
    supported_entity="JWT_TOKEN",
    patterns=[jwt_pattern]
)
analyzer.registry.add_recognizer(jwt_recognizer)

# ── Custom recognizer for Indian Aadhaar Numbers ───────────
# Detects format like 2345 6789 0123
aadhaar_pattern = Pattern(
    name="aadhaar_number",
    regex=r"[2-9]{1}[0-9]{3}\s[0-9]{4}\s[0-9]{4}",
    score=0.9
)
aadhaar_recognizer = PatternRecognizer(
    supported_entity="AADHAAR_NUMBER",
    patterns=[aadhaar_pattern]
)
analyzer.registry.add_recognizer(aadhaar_recognizer)


def scan_pii(prompt: str) -> tuple:
    """
    Scans a prompt for PII (Personally Identifiable Information)
    and replaces it with safe placeholder tags.

    Args:
        prompt (str): The raw user prompt

    Returns:
        cleaned_prompt (str): Prompt with PII masked
        entities_found (list): List of PII types detected
    """

    # ── Step 1: Define what PII to look for ───────────────
    # These are ALL the types of sensitive data we detect
    # including our custom ones added above
    entities_to_detect = [
        "EMAIL_ADDRESS",
        "PHONE_NUMBER",
        "CREDIT_CARD",
        "CRYPTO",
        "US_SSN",
        "API_KEY",
        "GITHUB_TOKEN",
        "AWS_KEY",
        "INDIAN_PHONE_NUMBER",
        "US_SSN"
        "JWT_TOKEN",
        "AADHAAR_NUMBER"
    ]

    # ── Step 2: Analyze the prompt ─────────────────────────
    # Presidio scans the text and finds all PII matches
    analysis_results = analyzer.analyze(
        text=prompt,
        entities=entities_to_detect,
        language="en"
    )

    # ── Step 3: Build custom replacement tags ──────────────
    # We customize replacements to look like [EMAIL_REDACTED]
    operators = {
        "EMAIL_ADDRESS": OperatorConfig(
            "replace", {"new_value": "[EMAIL_REDACTED]"}
        ),
        "PHONE_NUMBER": OperatorConfig(
            "replace", {"new_value": "[PHONE_REDACTED]"}
        ),
        "CREDIT_CARD": OperatorConfig(
            "replace", {"new_value": "[CREDIT_CARD_REDACTED]"}
        ),
        "CRYPTO": OperatorConfig(
            "replace", {"new_value": "[CRYPTO_REDACTED]"}
        ),
        "US_SSN": OperatorConfig(
            "replace", {"new_value": "[SSN_REDACTED]"}
        ),
        "API_KEY": OperatorConfig(
            "replace", {"new_value": "[API_KEY_REDACTED]"}
        ),
        "GITHUB_TOKEN": OperatorConfig(
            "replace", {"new_value": "[GITHUB_TOKEN_REDACTED]"}
        ),
        "AWS_KEY": OperatorConfig(
            "replace", {"new_value": "[AWS_KEY_REDACTED]"}
        ),
        "JWT_TOKEN": OperatorConfig(
            "replace", {"new_value": "[JWT_TOKEN_REDACTED]"}
        ),
        "AADHAAR_NUMBER": OperatorConfig(
            "replace", {"new_value": "[AADHAAR_REDACTED]"}
        ),
    }

    # ── Step 4: Replace PII with tags ─────────────────────
    # Presidio replaces all detected PII with our custom tags
    anonymized_result = anonymizer.anonymize(
        text=prompt,
        analyzer_results=analysis_results,
        operators=operators
    )

    # ── Step 5: Build list of what was found ───────────────
    # We collect entity types found to show user what
    # was detected and masked
    entities_found = list(
        set([result.entity_type for result in analysis_results])
    )

    # ── Step 6: Return cleaned prompt + findings ───────────
    return anonymized_result.text, entities_found


# ============================================================
# TEST — Run this file directly to test Gate 1
# In your terminal: python gates\gate1_pii.py
# ============================================================
if __name__ == "__main__":

    test_prompts = [
        # Original tests
        "My email is john.doe@gmail.com please contact me",
        "My SSN is 123-45-6789 and phone is 555-867-5309",
        "Charge my card 4111 1111 1111 1111 for the order",
        "This is a completely safe prompt with no PII at all",
        # New tests
        "My crypto wallet is 0xAbC12345DeF67890aBcD12345Ef67890aBCd1234",
        "My OpenAI key is sk-abc123defgh456ijklmn789opqrst012345",
        "GitHub token: ghp_abc123def456ghi789jkl012mno345pqr678stu",
        "AWS Key: AKIA1234567890ABCDEF",
        "My Aadhaar is 2345 6789 0123",
        "My Indian number is +91 98765 43210",
        "Call me on 9876543210",
        "My SSN is 123-45-6789",
    ]

    print("=" * 55)
    print("GATE 1 — PII Sanitization Test")
    print("=" * 55)

    for i, prompt in enumerate(test_prompts, 1):
        cleaned, entities = scan_pii(prompt)
        print(f"\nTest {i}:")
        print(f"  Original : {prompt}")
        print(f"  Cleaned  : {cleaned}")
        print(f"  Found    : {entities if entities else 'None'}")

    print("\n" + "=" * 55)
    print("Gate 1 test complete.")
    print("=" * 55)