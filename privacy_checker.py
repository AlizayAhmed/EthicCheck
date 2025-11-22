"""
Privacy Checker for EthicCheck
Advanced PII detection using Microsoft Presidio and secret detection for code
"""

import subprocess
import sys
import logging
import math
import re
from collections import Counter
from typing import List, Dict, Any, Optional

# Suppress verbose logging
logging.getLogger("presidio-analyzer").setLevel(logging.ERROR)

# =============================================================================
# DEPENDENCY MANAGEMENT
# =============================================================================

def ensure_dependencies():
    """Ensure required dependencies are installed and spaCy model is available."""
    try:
        import spacy
        try:
            spacy.load("en_core_web_lg")
        except OSError:
            print("Downloading spaCy model en_core_web_lg...")
            subprocess.run(
                [sys.executable, "-m", "spacy", "download", "en_core_web_lg"],
                check=True,
                capture_output=True
            )
    except ImportError:
        raise ImportError("spacy is required. Install with: pip install spacy")

# Initialize dependencies on module load
try:
    ensure_dependencies()
    from presidio_analyzer import AnalyzerEngine, RecognizerResult
    from presidio_anonymizer import AnonymizerEngine
    from presidio_anonymizer.entities import OperatorConfig
    PRESIDIO_AVAILABLE = True
except Exception as e:
    PRESIDIO_AVAILABLE = False
    PRESIDIO_ERROR = str(e)

# =============================================================================
# RISK SCORING CONFIGURATION
# =============================================================================

# Severity weights per entity type
ENTITY_SEVERITY = {
    "CREDIT_CARD": 1.0,
    "US_SSN": 0.95,
    "US_PASSPORT": 0.9,
    "US_DRIVER_LICENSE": 0.85,
    "IBAN_CODE": 0.85,
    "US_BANK_NUMBER": 0.8,
    "PHONE_NUMBER": 0.7,
    "EMAIL_ADDRESS": 0.6,
    "IP_ADDRESS": 0.5,
    "DATE_TIME": 0.3,
    "PERSON": 0.5,
    "LOCATION": 0.4,
    "NRP": 0.4,  # Nationality, Religion, Political group
    "MEDICAL_LICENSE": 0.7,
    "URL": 0.2,
}

# Mapping from Presidio entity types to user-friendly names
ENTITY_DISPLAY_NAMES = {
    "CREDIT_CARD": "Credit Card Number",
    "US_SSN": "Social Security Number",
    "US_PASSPORT": "Passport Number",
    "US_DRIVER_LICENSE": "Driver's License",
    "IBAN_CODE": "Bank Account (IBAN)",
    "US_BANK_NUMBER": "Bank Account Number",
    "PHONE_NUMBER": "Phone Number",
    "EMAIL_ADDRESS": "Email Address",
    "IP_ADDRESS": "IP Address",
    "DATE_TIME": "Date/Time",
    "PERSON": "Person Name",
    "LOCATION": "Location/Address",
    "NRP": "Nationality/Religion/Political",
    "MEDICAL_LICENSE": "Medical License",
    "URL": "URL",
}

# =============================================================================
# SECRET DETECTION PATTERNS (for code analysis)
# =============================================================================

# Named secrets in assignments
SECRET_ASSIGN_RE = re.compile(
    r'(?i)\b(password|passwd|pwd|secret|token|api[_-]?key|client[_-]?secret|'
    r'access[_-]?key|private[_-]?key|auth[_-]?token|bearer|credentials?)\b'
    r'\s*[:=]\s*(["\'])(.+?)\2'
)

# AWS-style access key IDs
AWS_ACCESS_KEY_RE = re.compile(r'\bAKIA[0-9A-Z]{16}\b')

# AWS Secret Access Key pattern
AWS_SECRET_KEY_RE = re.compile(r'(?i)aws[_-]?secret[_-]?access[_-]?key\s*[:=]\s*["\']?([A-Za-z0-9/+=]{40})["\']?')

# Private key markers
PRIVATE_KEY_MARKERS = [
    "-----BEGIN PRIVATE KEY-----",
    "-----BEGIN RSA PRIVATE KEY-----",
    "-----BEGIN EC PRIVATE KEY-----",
    "-----BEGIN DSA PRIVATE KEY-----",
    "-----BEGIN OPENSSH PRIVATE KEY-----",
]

# Generic API key patterns
GENERIC_API_KEY_RE = re.compile(
    r'(?i)(api[_-]?key|apikey|api_secret|app[_-]?key|app[_-]?secret|'
    r'client[_-]?id|client[_-]?secret|consumer[_-]?key|consumer[_-]?secret)\s*'
    r'[:=]\s*["\']?([A-Za-z0-9_\-]{20,})["\']?'
)

# JWT token pattern
JWT_RE = re.compile(r'eyJ[A-Za-z0-9_-]*\.eyJ[A-Za-z0-9_-]*\.[A-Za-z0-9_-]*')

# Long token-like string literals
STRING_LITERAL_RE = re.compile(r'["\']([A-Za-z0-9/\+=._-]{20,})["\']')

# =============================================================================
# HELPER FUNCTIONS
# =============================================================================

def _shannon_entropy(s: str) -> float:
    """Calculate Shannon entropy of a string."""
    if not s:
        return 0.0
    counts = Counter(s)
    length = len(s)
    return -sum((c / length) * math.log2(c / length) for c in counts.values())


def _compute_risk(
    pii_results: List[Any],
    secret_count: int = 0,
) -> Dict[str, Any]:
    """
    Compute a risk score in [0, 1] and a human-friendly level.
    """
    if not pii_results and secret_count == 0:
        return {"score": 0.0, "level": "low"}

    total = 0.0
    n = 0

    for r in pii_results:
        entity_type = r.entity_type if hasattr(r, 'entity_type') else r.get('entity_type', '')
        score = r.score if hasattr(r, 'score') else r.get('score', 0.5)
        sev = ENTITY_SEVERITY.get(entity_type, 0.3)
        total += sev * float(score)
        n += 1

    # Each secret finding adds a strong risk bump
    if secret_count:
        total += 0.85 * secret_count
        n += secret_count

    avg = total / max(n, 1)
    score = max(0.0, min(1.0, avg))

    if score < 0.33:
        level = "low"
    elif score < 0.66:
        level = "medium"
    else:
        level = "high"

    return {"score": round(score, 3), "level": level}


def _create_finding(
    severity: str,
    category: str,
    title: str,
    evidence: str,
    location: str,
    recommendation: str,
    suggested_rewrite: Optional[str] = None
) -> Dict:
    """Create a standardized finding dictionary for EthicCheck."""
    return {
        "category": category,
        "severity": severity.lower(),
        "title": title,
        "evidence": evidence,
        "location": location,
        "recommendation": recommendation,
        "suggested_rewrite": suggested_rewrite
    }

# =============================================================================
# CODE SECRET DETECTION
# =============================================================================

def detect_secrets_in_code(code: str) -> List[Dict[str, Any]]:
    """
    Detect secrets and credentials in source code.
    Returns list of secret findings.
    """
    findings: List[Dict[str, Any]] = []
    seen_matches = set()  # Avoid duplicates

    for line_no, line in enumerate(code.splitlines(), start=1):
        # Named secrets in assignments (password, api_key, etc.)
        for m in SECRET_ASSIGN_RE.finditer(line):
            match_text = m.group(0).strip()
            if match_text not in seen_matches:
                seen_matches.add(match_text)
                findings.append({
                    "kind": "secret_assignment",
                    "line": line_no,
                    "match": match_text,
                    "name": m.group(1),
                    "severity": "high"
                })

        # AWS Access Key IDs
        for m in AWS_ACCESS_KEY_RE.finditer(line):
            match_text = m.group(0)
            if match_text not in seen_matches:
                seen_matches.add(match_text)
                findings.append({
                    "kind": "aws_access_key_id",
                    "line": line_no,
                    "match": match_text,
                    "severity": "high"
                })

        # AWS Secret Access Keys
        for m in AWS_SECRET_KEY_RE.finditer(line):
            if m.group(0) not in seen_matches:
                seen_matches.add(m.group(0))
                findings.append({
                    "kind": "aws_secret_key",
                    "line": line_no,
                    "match": "[REDACTED - AWS Secret Key]",
                    "severity": "high"
                })

        # Private key markers
        for marker in PRIVATE_KEY_MARKERS:
            if marker in line:
                if marker not in seen_matches:
                    seen_matches.add(marker)
                    findings.append({
                        "kind": "private_key_marker",
                        "line": line_no,
                        "match": marker,
                        "severity": "high"
                    })

        # JWT tokens
        for m in JWT_RE.finditer(line):
            if "JWT Token" not in seen_matches:
                seen_matches.add("JWT Token")
                findings.append({
                    "kind": "jwt_token",
                    "line": line_no,
                    "match": m.group(0)[:50] + "...",
                    "severity": "high"
                })

        # Generic API keys
        for m in GENERIC_API_KEY_RE.finditer(line):
            key_name = m.group(1)
            if key_name not in seen_matches:
                seen_matches.add(key_name)
                findings.append({
                    "kind": "generic_api_key",
                    "line": line_no,
                    "match": f"{key_name}=[REDACTED]",
                    "name": key_name,
                    "severity": "high"
                })

    # High-entropy string literals (potential tokens)
    for line_no, line in enumerate(code.splitlines(), start=1):
        for m in STRING_LITERAL_RE.finditer(line):
            token = m.group(1)
            # Skip if it looks like a path, URL, or common pattern
            if '/' in token and token.count('/') > 2:
                continue
            if token.startswith('http'):
                continue
            
            entropy = _shannon_entropy(token)
            if entropy >= 4.0 and len(token) >= 32:  # High threshold for entropy
                key = f"entropy_{line_no}_{token[:10]}"
                if key not in seen_matches:
                    seen_matches.add(key)
                    findings.append({
                        "kind": "high_entropy_literal",
                        "line": line_no,
                        "match": token[:40] + "..." if len(token) > 40 else token,
                        "entropy": round(entropy, 2),
                        "severity": "medium"
                    })

    return findings

# =============================================================================
# MAIN PRIVACY ANALYSIS FUNCTIONS
# =============================================================================

def analyze_privacy_text(
    text: str,
    entities: Optional[List[str]] = None,
    language: str = "en",
) -> Dict[str, Any]:
    """
    Analyze free text for PII using Presidio.
    
    Args:
        text: Input text to analyze
        entities: List of specific entity types to detect (None = all)
        language: Language code (default: "en")
    
    Returns:
        Dict with original text, anonymized text, PII findings, and risk assessment
    """
    if not PRESIDIO_AVAILABLE:
        # Fallback to basic regex detection
        return _fallback_text_analysis(text)
    
    try:
        # Initialize engines
        analyzer = AnalyzerEngine()
        anonymizer = AnonymizerEngine()
        
        # Analyze text
        results: List[RecognizerResult] = analyzer.analyze(
            text=text,
            entities=entities,
            language=language,
        )
        
        # Build findings list
        pii_findings: List[Dict[str, Any]] = []
        for r in results:
            snippet = text[r.start:r.end]
            display_name = ENTITY_DISPLAY_NAMES.get(r.entity_type, r.entity_type)
            pii_findings.append({
                "entity_type": r.entity_type,
                "display_name": display_name,
                "score": round(float(r.score), 3),
                "start": int(r.start),
                "end": int(r.end),
                "snippet": snippet,
            })
        
        # Anonymize text
        anonymized_result = anonymizer.anonymize(
            text=text,
            analyzer_results=results,
            operators={
                "DEFAULT": OperatorConfig("replace", {"new_value": "<PII>"})
            },
        )
        
        # Compute risk
        risk = _compute_risk(results, secret_count=0)
        
        return {
            "status": "success",
            "original": text,
            "anonymized": anonymized_result.text,
            "pii_findings": pii_findings,
            "risk": risk,
            "total_pii_found": len(pii_findings)
        }
        
    except Exception as e:
        return {
            "status": "error",
            "error": str(e),
            "pii_findings": [],
            "risk": {"score": 0, "level": "unknown"}
        }


def analyze_privacy_code(
    code: str,
    language: str = "python",
    check_pii: bool = True,
    check_secrets: bool = True,
) -> Dict[str, Any]:
    """
    Analyze source code for PII and secrets/credentials.
    
    Args:
        code: Source code to analyze
        language: Programming language (for context)
        check_pii: Whether to check for PII in strings/comments
        check_secrets: Whether to check for hardcoded secrets
    
    Returns:
        Dict with PII findings, secret findings, and risk assessment
    """
    pii_findings = []
    secret_findings = []
    
    # Check for secrets
    if check_secrets:
        secret_findings = detect_secrets_in_code(code)
    
    # Check for PII in code (strings, comments)
    if check_pii and PRESIDIO_AVAILABLE:
        try:
            analyzer = AnalyzerEngine()
            results = analyzer.analyze(text=code, language="en")
            
            for r in results:
                snippet = code[r.start:r.end]
                display_name = ENTITY_DISPLAY_NAMES.get(r.entity_type, r.entity_type)
                pii_findings.append({
                    "entity_type": r.entity_type,
                    "display_name": display_name,
                    "score": round(float(r.score), 3),
                    "start": int(r.start),
                    "end": int(r.end),
                    "snippet": snippet,
                })
        except Exception:
            pass  # Silently fail PII detection, rely on secrets
    
    # Compute combined risk
    risk = _compute_risk(pii_findings, secret_count=len(secret_findings))
    
    return {
        "status": "success",
        "language": language,
        "pii_findings": pii_findings,
        "secret_findings": secret_findings,
        "risk": risk,
        "total_issues": len(pii_findings) + len(secret_findings)
    }


def _fallback_text_analysis(text: str) -> Dict[str, Any]:
    """
    Fallback PII detection using regex when Presidio is not available.
    """
    findings = []
    
    # Email pattern
    email_pattern = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
    for m in re.finditer(email_pattern, text):
        findings.append({
            "entity_type": "EMAIL_ADDRESS",
            "display_name": "Email Address",
            "score": 0.9,
            "start": m.start(),
            "end": m.end(),
            "snippet": m.group(0),
        })
    
    # Phone pattern
    phone_pattern = r'\b(?:\+?1[-.\s]?)?\(?[0-9]{3}\)?[-.\s]?[0-9]{3}[-.\s]?[0-9]{4}\b'
    for m in re.finditer(phone_pattern, text):
        findings.append({
            "entity_type": "PHONE_NUMBER",
            "display_name": "Phone Number",
            "score": 0.85,
            "start": m.start(),
            "end": m.end(),
            "snippet": m.group(0),
        })
    
    # SSN pattern
    ssn_pattern = r'\b\d{3}-\d{2}-\d{4}\b'
    for m in re.finditer(ssn_pattern, text):
        findings.append({
            "entity_type": "US_SSN",
            "display_name": "Social Security Number",
            "score": 0.95,
            "start": m.start(),
            "end": m.end(),
            "snippet": "XXX-XX-XXXX",
        })
    
    # Credit card pattern (basic)
    cc_pattern = r'\b(?:\d{4}[-\s]?){3}\d{4}\b'
    for m in re.finditer(cc_pattern, text):
        findings.append({
            "entity_type": "CREDIT_CARD",
            "display_name": "Credit Card Number",
            "score": 0.9,
            "start": m.start(),
            "end": m.end(),
            "snippet": "XXXX-XXXX-XXXX-XXXX",
        })
    
    # IP address pattern
    ip_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
    for m in re.finditer(ip_pattern, text):
        findings.append({
            "entity_type": "IP_ADDRESS",
            "display_name": "IP Address",
            "score": 0.8,
            "start": m.start(),
            "end": m.end(),
            "snippet": m.group(0),
        })
    
    # Simple anonymization
    anonymized = text
    for f in sorted(findings, key=lambda x: x['start'], reverse=True):
        anonymized = anonymized[:f['start']] + '<PII>' + anonymized[f['end']:]
    
    risk = _compute_risk(findings, 0)
    
    return {
        "status": "success",
        "original": text,
        "anonymized": anonymized,
        "pii_findings": findings,
        "risk": risk,
        "total_pii_found": len(findings),
        "note": "Using fallback regex detection (Presidio not available)"
    }

# =============================================================================
# ETHICCHECK INTEGRATION FUNCTIONS
# =============================================================================

def run_privacy_check(
    input_data: str,
    input_type: str = "text"
) -> Dict[str, Any]:
    """
    Main entry point for privacy checking in EthicCheck.
    
    Args:
        input_data: Text or code to analyze
        input_type: "text" or "code"
    
    Returns:
        Dict with findings in EthicCheck format
    """
    findings = []
    
    if input_type == "code":
        result = analyze_privacy_code(input_data)
        
        # Convert secret findings to EthicCheck format
        for secret in result.get("secret_findings", []):
            severity = secret.get("severity", "high")
            kind = secret.get("kind", "secret")
            
            title_map = {
                "secret_assignment": "Hardcoded Secret/Credential",
                "aws_access_key_id": "AWS Access Key Exposed",
                "aws_secret_key": "AWS Secret Key Exposed",
                "private_key_marker": "Private Key in Code",
                "jwt_token": "JWT Token Exposed",
                "generic_api_key": "API Key Exposed",
                "high_entropy_literal": "Potential Secret (High Entropy String)",
            }
            
            findings.append(_create_finding(
                severity=severity,
                category="Privacy",
                title=title_map.get(kind, "Potential Secret Detected"),
                evidence=f"Line {secret.get('line', '?')}: {secret.get('match', 'N/A')}",
                location=f"Line {secret.get('line', 'Unknown')}",
                recommendation="Remove hardcoded secrets. Use environment variables (os.getenv()) or a secrets manager instead.",
                suggested_rewrite=f"os.getenv('{secret.get('name', 'SECRET_KEY').upper()}')"
            ))
        
        # Convert PII findings to EthicCheck format
        for pii in result.get("pii_findings", []):
            findings.append(_create_finding(
                severity="medium" if pii.get("score", 0) < 0.8 else "high",
                category="Privacy",
                title=f"PII Detected: {pii.get('display_name', pii.get('entity_type', 'Unknown'))}",
                evidence=f"Found: {pii.get('snippet', 'N/A')}",
                location=f"Position {pii.get('start', '?')}-{pii.get('end', '?')}",
                recommendation="Remove or anonymize personal information from code. Use placeholders or environment variables.",
                suggested_rewrite=f"Replace with placeholder or use secure storage"
            ))
    
    else:  # text
        result = analyze_privacy_text(input_data)
        
        # Group findings by type for cleaner output
        pii_by_type: Dict[str, List] = {}
        for pii in result.get("pii_findings", []):
            entity_type = pii.get("entity_type", "UNKNOWN")
            if entity_type not in pii_by_type:
                pii_by_type[entity_type] = []
            pii_by_type[entity_type].append(pii)
        
        # Create findings for each PII type
        for entity_type, pii_list in pii_by_type.items():
            display_name = ENTITY_DISPLAY_NAMES.get(entity_type, entity_type)
            avg_score = sum(p.get("score", 0) for p in pii_list) / len(pii_list)
            severity = "high" if avg_score >= 0.7 or entity_type in ["US_SSN", "CREDIT_CARD"] else "medium"
            
            # Show up to 3 examples
            examples = [p.get("snippet", "N/A") for p in pii_list[:3]]
            if entity_type in ["US_SSN", "CREDIT_CARD"]:
                examples = ["[REDACTED]"] * len(examples)
            
            findings.append(_create_finding(
                severity=severity,
                category="Privacy",
                title=f"{display_name} Detected ({len(pii_list)} occurrence{'s' if len(pii_list) > 1 else ''})",
                evidence=f"Examples: {', '.join(examples)}{'...' if len(pii_list) > 3 else ''}",
                location="Throughout document",
                recommendation=f"Remove or anonymize {display_name.lower()} information. Replace with placeholders like [{entity_type}].",
                suggested_rewrite=f"Replace with [{entity_type}] or remove entirely"
            ))
    
    # Calculate summary
    risk = result.get("risk", {"score": 0, "level": "low"})
    
    return {
        "status": "success",
        "findings": findings,
        "summary": {
            "high": len([f for f in findings if f["severity"] == "high"]),
            "medium": len([f for f in findings if f["severity"] == "medium"]),
            "low": len([f for f in findings if f["severity"] == "low"]),
        },
        "risk_score": risk.get("score", 0),
        "risk_level": risk.get("level", "unknown"),
        "total_issues": len(findings),
        "anonymized_text": result.get("anonymized", None),
        "presidio_available": PRESIDIO_AVAILABLE
    }


def generate_privacy_summary(result: Dict[str, Any]) -> str:
    """Generate a human-readable summary of privacy findings."""
    if result.get("status") != "success":
        return f"❌ Privacy check failed: {result.get('error', 'Unknown error')}"
    
    findings = result.get("findings", [])
    if not findings:
        return "✅ No privacy issues detected. No PII or secrets found in your content."
    
    summary = result.get("summary", {})
    high = summary.get("high", 0)
    medium = summary.get("medium", 0)
    low = summary.get("low", 0)
    
    text = f"Found {len(findings)} privacy concern(s):\n\n"
    
    if high > 0:
        text += f"🔴 {high} HIGH priority issue(s) - immediate action required\n"
    if medium > 0:
        text += f"🟡 {medium} MEDIUM priority issue(s) - should be reviewed\n"
    if low > 0:
        text += f"🔵 {low} LOW priority issue(s) - for awareness\n"
    
    risk_level = result.get("risk_level", "unknown")
    risk_score = result.get("risk_score", 0)
    
    text += f"\n📊 Overall Privacy Risk: {risk_level.upper()} (Score: {risk_score:.2f})\n"
    
    if not result.get("presidio_available", True):
        text += "\n⚠️ Note: Using basic detection. Install Presidio for advanced PII detection."
    
    text += "\nReview each finding and apply suggested fixes to protect privacy."
    
    return text