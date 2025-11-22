"""
IP & Copyright Checker for EthicCheck
Detects licensing issues, copyright violations, and IP concerns in student projects
"""

import re
from typing import Dict, List, Optional, Tuple

# ==================== LICENSE PATTERNS ====================

LICENSE_PATTERNS = {
    # Permissive licenses (safe to use)
    "MIT": {
        "pattern": r"(?i)MIT\s+License|Permission.*hereby granted.*free",
        "type": "permissive",
        "risk": "low",
        "description": "Permissive open-source license"
    },
    "Apache-2.0": {
        "pattern": r"(?i)Apache\s+License|Licensed.*Apache",
        "type": "permissive", 
        "risk": "low",
        "description": "Permissive with patent grant"
    },
    "BSD": {
        "pattern": r"(?i)BSD\s+\d-Clause|Redistribution.*binary.*permitted",
        "type": "permissive",
        "risk": "low",
        "description": "Simple permissive license"
    },
    "ISC": {
        "pattern": r"(?i)ISC\s+License|Permission.*use.*copy.*modify",
        "type": "permissive",
        "risk": "low",
        "description": "Simplified BSD-like license"
    },
    # Copyleft licenses (require same license for derivatives)
    "GPL": {
        "pattern": r"(?i)GNU\s+General\s+Public|GPL-?\d|General Public License",
        "type": "copyleft",
        "risk": "high",
        "description": "Viral license - derivatives must be GPL"
    },
    "LGPL": {
        "pattern": r"(?i)GNU\s+Lesser\s+General|LGPL",
        "type": "copyleft",
        "risk": "medium",
        "description": "Allows linking with non-GPL code"
    },
    "MPL": {
        "pattern": r"(?i)Mozilla\s+Public\s+License|MPL-?\d",
        "type": "copyleft",
        "risk": "medium",
        "description": "File-level copyleft"
    },
    "AGPL": {
        "pattern": r"(?i)GNU\s+Affero|AGPL",
        "type": "copyleft",
        "risk": "high",
        "description": "Network copyleft - strongest restriction"
    },
    # Creative Commons
    "CC-BY": {
        "pattern": r"(?i)Creative\s+Commons.*Attribution|CC-BY",
        "type": "creative_commons",
        "risk": "low",
        "description": "Requires attribution only"
    },
    "CC-BY-SA": {
        "pattern": r"(?i)Creative\s+Commons.*Share.*Alike|CC-BY-SA",
        "type": "creative_commons",
        "risk": "medium",
        "description": "Requires same license for derivatives"
    },
    "CC-BY-NC": {
        "pattern": r"(?i)Creative\s+Commons.*Non.*Commercial|CC-BY-NC",
        "type": "creative_commons",
        "risk": "medium",
        "description": "No commercial use allowed"
    },
    # Restrictive
    "Proprietary": {
        "pattern": r"(?i)All\s+rights\s+reserved|proprietary|confidential|internal use only",
        "type": "proprietary",
        "risk": "critical",
        "description": "No usage rights granted"
    },
    # SPDX (modern standard)
    "SPDX": {
        "pattern": r"SPDX-License-Identifier:\s*(\S+)",
        "type": "spdx",
        "risk": "info",
        "description": "Modern license identifier"
    }
}

# ==================== RISK PATTERNS ====================

RISK_PATTERNS = {
    "copyright_notice": {
        "pattern": r"(?i)copyright\s*(?:\(c\)|©)?\s*\d{4}",
        "message": "Copyright notice detected - verify usage rights",
        "risk": "medium"
    },
    "third_party": {
        "pattern": r"(?i)third.?party|external\s+library|vendor(?:ed)?",
        "message": "Third-party code reference detected",
        "risk": "low"
    },
    "stackoverflow": {
        "pattern": r"(?i)stackoverflow|stack\s+overflow|SO\s+answer|from\s+SO",
        "message": "Stack Overflow code (CC BY-SA license applies)",
        "risk": "medium"
    },
    "github_snippet": {
        "pattern": r"(?i)from\s+github|github\.com/[^/]+/[^/\s]+",
        "message": "GitHub code reference - verify license",
        "risk": "medium"
    },
    "generated": {
        "pattern": r"(?i)generated\s+by|auto-generated|do\s+not\s+edit",
        "message": "Auto-generated code detected",
        "risk": "info"
    },
    "copilot_chatgpt": {
        "pattern": r"(?i)github\s+copilot|chatgpt|generated\s+with\s+ai",
        "message": "AI-generated code - verify ownership",
        "risk": "low"
    },
    "academic_source": {
        "pattern": r"(?i)adapted\s+from|based\s+on\s+paper|research\s+by",
        "message": "Academic source - ensure proper citation",
        "risk": "medium"
    }
}

# ==================== HELPER FUNCTIONS ====================

def get_context(text: str, match_start: int, match_end: int, window: int = 50) -> str:
    """Extract context around a match for display."""
    start = max(0, match_start - window)
    end = min(len(text), match_end + window)
    prefix = "..." if start > 0 else ""
    suffix = "..." if end < len(text) else ""
    snippet = text[start:end].replace('\n', ' ').strip()
    return f"{prefix}{snippet}{suffix}"

def severity_to_priority(risk: str) -> int:
    """Convert risk level to numeric priority for sorting."""
    priority_map = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    return priority_map.get(risk, 5)

# ==================== MAIN SCANNING FUNCTIONS ====================

def scan_for_licenses(text: str) -> List[Dict]:
    """Scan text for license mentions."""
    licenses_found = []
    
    for license_name, info in LICENSE_PATTERNS.items():
        matches = list(re.finditer(info["pattern"], text))
        
        for match in matches:
            # Check if it's in header (first 1500 chars)
            location = "header" if match.start() < 1500 else "body"
            
            licenses_found.append({
                "license": license_name,
                "type": info["type"],
                "risk": info["risk"],
                "description": info["description"],
                "location": location,
                "context": get_context(text, match.start(), match.end()),
                "match_start": match.start()
            })
    
    return licenses_found

def scan_for_risks(text: str, user_name: Optional[str] = None) -> List[Dict]:
    """Scan text for copyright and IP risk patterns."""
    risks_found = []
    
    for risk_name, info in RISK_PATTERNS.items():
        matches = list(re.finditer(info["pattern"], text))
        
        for match in matches:
            matched_text = match.group(0)
            
            # Skip if it's user's own copyright
            if risk_name == "copyright_notice" and user_name:
                context_window = text[match.start():min(len(text), match.end() + 100)]
                if user_name.lower() in context_window.lower():
                    continue
            
            risks_found.append({
                "risk_type": risk_name,
                "risk_level": info["risk"],
                "message": info["message"],
                "matched_text": matched_text,
                "context": get_context(text, match.start(), match.end()),
                "match_start": match.start()
            })
    
    return risks_found

def check_license_compatibility(licenses: List[Dict]) -> List[Dict]:
    """Check for incompatible license combinations."""
    compatibility_issues = []
    
    # Group licenses by type
    copyleft = [lic for lic in licenses if lic["type"] == "copyleft"]
    proprietary = [lic for lic in licenses if lic["type"] == "proprietary"]
    permissive = [lic for lic in licenses if lic["type"] == "permissive"]
    
    # GPL + Proprietary = CRITICAL
    if copyleft and proprietary:
        compatibility_issues.append({
            "type": "compatibility",
            "risk_level": "critical",
            "title": "Copyleft + Proprietary License Conflict",
            "message": f"GPL/Copyleft code cannot be mixed with proprietary code",
            "details": {
                "copyleft": [lic["license"] for lic in copyleft],
                "proprietary": [lic["license"] for lic in proprietary]
            }
        })
    
    # Multiple copyleft licenses = HIGH
    if len(copyleft) > 1:
        unique_copyleft = list(set([lic["license"] for lic in copyleft]))
        if len(unique_copyleft) > 1:
            compatibility_issues.append({
                "type": "compatibility",
                "risk_level": "high",
                "title": "Multiple Copyleft Licenses Detected",
                "message": f"Different copyleft licenses may be incompatible",
                "details": {
                    "licenses": unique_copyleft
                }
            })
    
    return compatibility_issues

def analyze_ip_copyright(text: str, user_name: Optional[str] = None) -> Dict:
    """
    Main IP & Copyright analysis function.
    
    Args:
        text: The project text/code to analyze
        user_name: Optional user/team name to filter out their own copyright
    
    Returns:
        Structured analysis results
    """
    # Run all scans
    licenses = scan_for_licenses(text)
    risks = scan_for_risks(text, user_name)
    compatibility_issues = check_license_compatibility(licenses)
    
    # Check for missing license
    has_license = len(licenses) > 0
    has_license_header = any(lic["location"] == "header" for lic in licenses)
    
    # Calculate risk counts
    all_items = licenses + risks + compatibility_issues
    risk_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    
    for item in all_items:
        risk = item.get("risk_level") or item.get("risk")
        if risk:
            risk_counts[risk] = risk_counts.get(risk, 0) + 1
    
    # Generate issues in EthicCheck format
    issues = []
    
    # Add compatibility issues first (highest priority)
    for comp_issue in compatibility_issues:
        issues.append({
            "category": "IP & Copyright",
            "severity": comp_issue["risk_level"],
            "title": comp_issue["title"],
            "evidence": comp_issue["message"],
            "location": "Multiple locations",
            "recommendation": "Review license compatibility. Consider removing incompatible dependencies or relicensing your project.",
            "suggested_rewrite": None
        })
    
    # Add license findings
    for lic in licenses:
        severity_map = {"critical": "high", "high": "high", "medium": "medium", "low": "low", "info": "low"}
        severity = severity_map.get(lic["risk"], "medium")
        
        recommendation = ""
        if lic["risk"] == "critical":
            recommendation = "Remove proprietary code or obtain proper licensing."
        elif lic["risk"] == "high":
            recommendation = f"GPL/Copyleft license detected. Ensure your entire project can be licensed under {lic['license']}."
        elif lic["risk"] == "medium":
            recommendation = f"Review {lic['license']} license terms and ensure compliance."
        else:
            recommendation = f"{lic['license']} license is permissive and generally safe to use."
        
        issues.append({
            "category": "IP & Copyright",
            "severity": severity,
            "title": f"{lic['license']} License Detected",
            "evidence": lic["context"],
            "location": f"Found in {lic['location']}",
            "recommendation": recommendation,
            "suggested_rewrite": None
        })
    
    # Add risk findings
    for risk in risks:
        severity_map = {"critical": "high", "high": "high", "medium": "medium", "low": "low", "info": "low"}
        severity = severity_map.get(risk["risk_level"], "medium")
        
        issues.append({
            "category": "IP & Copyright",
            "severity": severity,
            "title": risk["message"],
            "evidence": risk["context"],
            "location": "See evidence",
            "recommendation": f"Verify you have proper rights to use this code. Add attribution if required.",
            "suggested_rewrite": None
        })
    
    # Add missing license warning
    if not has_license:
        issues.append({
            "category": "IP & Copyright",
            "severity": "medium",
            "title": "No License Detected",
            "evidence": "No license information found in project",
            "location": "Project header",
            "recommendation": "Add a LICENSE file to clarify usage rights. Consider MIT, Apache-2.0, or GPL-3.0 for open source projects.",
            "suggested_rewrite": "Add a LICENSE file with your chosen license text."
        })
    elif not has_license_header:
        issues.append({
            "category": "IP & Copyright",
            "severity": "low",
            "title": "Missing License Header",
            "evidence": "License found in body but not in file header",
            "location": "File header",
            "recommendation": "Add license header to the beginning of your main files.",
            "suggested_rewrite": "# Licensed under [LICENSE NAME]\n# Copyright (c) 2024 [YOUR NAME]"
        })
    
    return {
        "status": "success",
        "findings": issues,
        "summary": {
            "total_issues": len(issues),
            "risk_counts": risk_counts,
            "licenses_found": [lic["license"] for lic in licenses],
            "has_license": has_license,
            "has_compatibility_issues": len(compatibility_issues) > 0
        }
    }

# ==================== GROQ FIX GENERATION ====================

def generate_fix_suggestions(issue: Dict, groq_client) -> str:
    """Generate AI-powered fix suggestions using Groq."""
    if not groq_client:
        return "Enable Groq API for AI-powered fix suggestions."
    
    try:
        prompt = f"""You are an IP & Copyright compliance expert. Suggest a specific fix for this issue:

Issue: {issue['title']}
Evidence: {issue['evidence']}
Current Recommendation: {issue['recommendation']}

Provide a concrete, actionable fix in 2-3 sentences. Be specific about what the student should do."""

        response = groq_client.chat.completions.create(
            model="llama-3.3-70b-versatile",
            messages=[
                {"role": "system", "content": "You are a helpful IP & Copyright compliance assistant. Provide clear, actionable advice."},
                {"role": "user", "content": prompt}
            ],
            temperature=0.3,
            max_tokens=200
        )
        
        return response.choices[0].message.content.strip()
    except Exception as e:
        return f"Error generating fix: {str(e)}"

# ==================== EXPORT UTILITIES ====================

def generate_ip_summary(analysis_result: Dict) -> str:
    """Generate a student-friendly summary of IP findings."""
    summary = analysis_result["summary"]
    findings = analysis_result["findings"]
    
    if summary["total_issues"] == 0:
        return "✅ No IP or copyright issues detected. Your project appears to be properly licensed."
    
    text = f"Found {summary['total_issues']} IP/Copyright concern(s):\n\n"
    
    if summary["risk_counts"]["critical"] > 0:
        text += f"🔴 {summary['risk_counts']['critical']} CRITICAL issue(s) - immediate action required\n"
    if summary["risk_counts"]["high"] > 0:
        text += f"🟠 {summary['risk_counts']['high']} HIGH priority issue(s)\n"
    if summary["risk_counts"]["medium"] > 0:
        text += f"🟡 {summary['risk_counts']['medium']} MEDIUM priority issue(s)\n"
    
    if summary["has_compatibility_issues"]:
        text += "\n⚠️ LICENSE COMPATIBILITY ISSUES DETECTED - Review immediately!\n"
    
    if summary["licenses_found"]:
        text += f"\n📜 Licenses detected: {', '.join(summary['licenses_found'])}\n"
    
    text += "\nReview each issue and apply suggested fixes before submission."
    
    return text