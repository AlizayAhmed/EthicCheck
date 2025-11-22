"""
Bias & Fairness Checker for EthicCheck
Advanced bias detection in text, code, and datasets
"""

import re
import pandas as pd
import numpy as np
from typing import List, Dict, Union, Optional, Tuple
import io

# ==============================================================================
# CONFIGURATION - Comprehensive Bias Patterns
# ==============================================================================

BIAS_PATTERNS = {
    # Stereotyping patterns
    "stereotypes": [
        r"\b(men|women|boys|girls)\s+\w*\s*(are|tend to|always|usually|never)\s+\w*\s*(better|worse|smarter|dumb|emotional|logical|weak|strong)",
        r"\b(white|black|asian|hispanic|latino|african)\s+people\s+\w*\s*(are|can't|never|always|don't)",
        r"\b(poor|rich)\s+people\s+(are|don't|can't|never|always)",
        r"\ball\s+(men|women|asians|blacks|whites|muslims|christians)\s+(are|have|lack)",
        r"\b(boys|girls)\s+(can't|cannot|shouldn't)\s+",
        r"\b(typical|naturally|obviously)\s+(male|female|man|woman)",
    ],
    
    # Gendered language that should be replaced
    "gendered_terms": {
        "mankind": "humankind",
        "policeman": "police officer",
        "chairman": "chairperson",
        "fireman": "firefighter",
        "stewardess": "flight attendant",
        "mailman": "mail carrier",
        "manpower": "workforce",
        "freshman": "first-year student",
        "businessman": "businessperson",
        "congressman": "congressperson",
        "spokesman": "spokesperson",
        "manmade": "artificial/synthetic",
        "waitress": "server",
        "actress": "actor",
        "hostess": "host",
    },
    
    # Code-level bias patterns
    "code_patterns": [
        (r"if\s+.*\b(gender|sex|race|ethnicity|religion|age)\s*[=!<>]=", "Hardcoded Demographic Logic"),
        (r"\b(blacklist|whitelist)\b", "Non-Inclusive Terminology → Use allowlist/denylist"),
        (r"\b(master|slave)\b", "Non-Inclusive Terminology → Use primary/replica or main/secondary"),
        (r"\b(crazy|insane|dumb|stupid|retard|idiot|lame|cripple)\b", "Ableist Language"),
        (r"\b(guys)\b\s*[,\)]", "Gendered Team Reference → Use 'folks', 'team', 'everyone'"),
        (r"\b(sanity\s+check|sanity\s+test)\b", "Ableist Term → Use 'validation check' or 'verification test'"),
        (r"\b(grandfathered|grandfather\s+clause)\b", "Problematic Term → Use 'legacy' or 'pre-existing'"),
    ],
    
    # Proxy variables that may encode protected attributes
    "proxy_variables": {
        "zip": "Often correlates with race/income",
        "zipcode": "Often correlates with race/income",
        "postal": "Often correlates with race/income",
        "postalcode": "Often correlates with race/income",
        "surname": "Can indicate ethnicity",
        "lastname": "Can indicate ethnicity",
        "school": "Can correlate with socioeconomic status",
        "neighborhood": "Often correlates with race/income",
        "district": "May correlate with demographics",
        "county": "May correlate with demographics",
        "address": "Can encode socioeconomic information",
    },
    
    # Protected/sensitive attributes
    "sensitive_attributes": [
        "gender", "sex", "race", "ethnicity", "religion", "age", 
        "disability", "national_origin", "nationality", "citizenship",
        "sexual_orientation", "marital_status", "pregnancy", "genetic_info"
    ]
}

# Severity thresholds for imbalance
IMBALANCE_THRESHOLDS = {
    "severe": 0.85,    # >85% majority class = HIGH severity
    "moderate": 0.70,  # >70% majority class = MEDIUM severity
    "warning": 0.60    # >60% majority class = LOW severity
}

# ==============================================================================
# HELPER FUNCTIONS
# ==============================================================================

def _create_finding(
    severity: str,
    category: str,
    title: str,
    evidence: str,
    location: str,
    recommendation: str,
    suggested_rewrite: Optional[str] = None
) -> Dict:
    """Create a standardized finding dictionary."""
    return {
        "category": category,
        "severity": severity.lower(),
        "title": title,
        "evidence": evidence,
        "location": location,
        "recommendation": recommendation,
        "suggested_rewrite": suggested_rewrite
    }

def _extract_context(text: str, match_obj, window: int = 80) -> str:
    """Extract context around a regex match."""
    start = max(0, match_obj.start() - window)
    end = min(len(text), match_obj.end() + window)
    context = text[start:end].strip()
    return f"...{context}..." if start > 0 or end < len(text) else context

# ==============================================================================
# TEXT BIAS SCANNER
# ==============================================================================

def scan_text_bias(text: str) -> List[Dict]:
    """
    Scan text for bias indicators including stereotypes and gendered language.
    
    Args:
        text: Input text to analyze
        
    Returns:
        List of bias findings
    """
    findings = []
    
    if not text or not isinstance(text, str):
        return findings
    
    text_lower = text.lower()
    
    # 1. Detect Stereotyping Language (HIGH SEVERITY)
    for pattern in BIAS_PATTERNS["stereotypes"]:
        for match in re.finditer(pattern, text, re.IGNORECASE):
            matched_text = match.group(0)
            context = _extract_context(text, match)
            
            findings.append(_create_finding(
                severity="high",
                category="Bias",
                title="Stereotyping Language Detected",
                evidence=matched_text,
                location=f"Position {match.start()}-{match.end()}",
                recommendation="Avoid making generalized statements about demographic groups. Rephrase to focus on individual characteristics or provide empirical evidence.",
                suggested_rewrite="Consider rephrasing to avoid generalizations, e.g., 'Some individuals may...' or 'Research shows that...'"
            ))
    
    # 2. Detect Gendered Terms (MEDIUM SEVERITY)
    for term, replacement in BIAS_PATTERNS["gendered_terms"].items():
        pattern = rf"\b{re.escape(term)}\b"
        for match in re.finditer(pattern, text, re.IGNORECASE):
            matched_text = match.group(0)
            context = _extract_context(text, match)
            
            findings.append(_create_finding(
                severity="medium",
                category="Bias",
                title="Gendered Terminology Found",
                evidence=matched_text,
                location=f"Position {match.start()}-{match.end()}",
                recommendation=f"Use gender-neutral language to be more inclusive.",
                suggested_rewrite=f"Replace '{matched_text}' with '{replacement}'"
            ))
    
    # 3. Detect Demographic Keywords (INFO level - for awareness)
    demographic_keywords = {
        'gender': ['male', 'female', 'man', 'woman', 'boy', 'girl'],
        'race': ['white', 'black', 'asian', 'hispanic', 'latino', 'african'],
        'age': ['young', 'old', 'elderly', 'teenager', 'senior'],
        'religion': ['christian', 'muslim', 'jewish', 'hindu', 'buddhist'],
        'disability': ['disabled', 'handicapped', 'wheelchair', 'blind', 'deaf']
    }
    
    detected_categories = set()
    for category, keywords in demographic_keywords.items():
        for keyword in keywords:
            if re.search(rf"\b{keyword}\b", text_lower):
                detected_categories.add(category)
                break
    
    if detected_categories:
        findings.append(_create_finding(
            severity="low",
            category="Bias",
            title="Demographic Categories Mentioned",
            evidence=f"Categories found: {', '.join(detected_categories)}",
            location="Throughout document",
            recommendation="When discussing demographic groups, ensure balanced representation and avoid reinforcing stereotypes. Consider if demographic information is necessary for your analysis.",
            suggested_rewrite=None
        ))
    
    return findings

# ==============================================================================
# CODE BIAS SCANNER
# ==============================================================================

def scan_code_bias(code: str) -> List[Dict]:
    """
    Scan code for bias-related issues including non-inclusive terminology
    and hardcoded demographic logic.
    
    Args:
        code: Source code to analyze
        
    Returns:
        List of bias findings
    """
    findings = []
    
    if not code or not isinstance(code, str):
        return findings
    
    lines = code.split('\n')
    
    for line_num, line in enumerate(lines, 1):
        for pattern, issue_description in BIAS_PATTERNS["code_patterns"]:
            match = re.search(pattern, line, re.IGNORECASE)
            if match:
                matched_text = match.group(0)
                
                # Parse recommendation from issue_description
                if "→" in issue_description:
                    issue_name, suggestion = issue_description.split("→", 1)
                    issue_name = issue_name.strip()
                    suggestion = suggestion.strip()
                else:
                    issue_name = issue_description
                    suggestion = "Refactor to use inclusive terminology"
                
                # Determine severity
                if "Hardcoded Demographic" in issue_name:
                    severity = "high"
                    recommendation = "Remove hardcoded demographic checks. Use data-driven approaches or remove demographic-based logic entirely."
                elif "Ableist" in issue_name:
                    severity = "medium"
                    recommendation = "Replace with neutral terminology. " + suggestion
                else:
                    severity = "medium"
                    recommendation = suggestion
                
                findings.append(_create_finding(
                    severity=severity,
                    category="Bias",
                    title=issue_name,
                    evidence=matched_text,
                    location=f"Line {line_num}",
                    recommendation=recommendation,
                    suggested_rewrite=_suggest_code_rewrite(matched_text)
                ))
    
    return findings

def _suggest_code_rewrite(matched_text: str) -> Optional[str]:
    """Suggest code rewrites for common bias patterns."""
    text_lower = matched_text.lower()
    
    replacements = {
        "blacklist": "denylist",
        "whitelist": "allowlist",
        "master": "main",
        "slave": "replica",
        "guys": "team",
        "sanity check": "validation check",
        "sanity test": "verification test",
        "grandfathered": "legacy",
    }
    
    for old, new in replacements.items():
        if old in text_lower:
            return matched_text.replace(old, new)
    
    return None

# ==============================================================================
# DATASET BIAS SCANNER
# ==============================================================================

def scan_dataset_bias(df: pd.DataFrame) -> List[Dict]:
    """
    Scan dataset for bias indicators including imbalance, proxy variables,
    and sensitive attributes.
    
    Args:
        df: Pandas DataFrame to analyze
        
    Returns:
        List of bias findings
    """
    findings = []
    
    if df is None or df.empty:
        findings.append(_create_finding(
            severity="medium",
            category="Bias",
            title="Empty or Invalid Dataset",
            evidence="No data rows found",
            location="Dataset",
            recommendation="Ensure dataset is loaded correctly and contains data.",
            suggested_rewrite=None
        ))
        return findings
    
    # 1. Sample Size Check
    if len(df) < 50:
        findings.append(_create_finding(
            severity="medium",
            category="Bias",
            title="Small Sample Size",
            evidence=f"Dataset contains only {len(df)} rows",
            location="Dataset",
            recommendation="Small datasets may not be representative. Aim for at least 200-500 samples for reliable bias analysis. Consider collecting more data or using data augmentation techniques.",
            suggested_rewrite=None
        ))
    
    # 2. Class Imbalance Analysis
    categorical_cols = df.select_dtypes(include=['object', 'category', 'bool']).columns
    
    for col in categorical_cols:
        value_counts = df[col].value_counts(normalize=True, dropna=True)
        
        if len(value_counts) >= 2:
            majority_class = value_counts.index[0]
            majority_ratio = value_counts.iloc[0]
            
            if majority_ratio > IMBALANCE_THRESHOLDS["severe"]:
                findings.append(_create_finding(
                    severity="high",
                    category="Bias",
                    title=f"Severe Class Imbalance: '{col}'",
                    evidence=f"Majority class '{majority_class}' represents {majority_ratio*100:.1f}% of data",
                    location=f"Column: {col}",
                    recommendation=f"Severe imbalance can lead to biased models. Consider:\n- SMOTE or other oversampling techniques\n- Undersampling majority class\n- Using class weights in model training\n- Collecting more data for minority classes\n- Stratified train-test splits",
                    suggested_rewrite=f"Apply resampling: from imblearn.over_sampling import SMOTE\nsmote = SMOTE()\nX_resampled, y_resampled = smote.fit_resample(X, y)"
                ))
            elif majority_ratio > IMBALANCE_THRESHOLDS["moderate"]:
                findings.append(_create_finding(
                    severity="medium",
                    category="Bias",
                    title=f"Moderate Class Imbalance: '{col}'",
                    evidence=f"Majority class '{majority_class}' represents {majority_ratio*100:.1f}% of data",
                    location=f"Column: {col}",
                    recommendation=f"Monitor model performance across all classes. Use metrics like F1-score, precision, and recall for each class. Consider stratified sampling.",
                    suggested_rewrite=None
                ))
            elif majority_ratio > IMBALANCE_THRESHOLDS["warning"]:
                findings.append(_create_finding(
                    severity="low",
                    category="Bias",
                    title=f"Minor Class Imbalance: '{col}'",
                    evidence=f"Majority class '{majority_class}' represents {majority_ratio*100:.1f}% of data",
                    location=f"Column: {col}",
                    recommendation="Monitor for potential bias in model predictions. Ensure balanced evaluation metrics.",
                    suggested_rewrite=None
                ))
    
    # 3. Proxy Variable Detection
    for col in df.columns:
        col_lower = col.lower()
        for proxy, reason in BIAS_PATTERNS["proxy_variables"].items():
            if proxy in col_lower:
                findings.append(_create_finding(
                    severity="medium",
                    category="Bias",
                    title=f"Potential Proxy Variable: '{col}'",
                    evidence=reason,
                    location=f"Column: {col}",
                    recommendation=f"This variable may serve as a proxy for protected attributes. Consider:\n- Removing this feature if not essential\n- Using fairness-aware ML techniques\n- Conducting disparate impact analysis\n- Documenting the decision to include/exclude this feature",
                    suggested_rewrite=f"# Consider removing proxy variable:\ndf_filtered = df.drop(columns=['{col}'])"
                ))
                break
    
    # 4. Sensitive Attribute Detection
    sensitive_cols_found = []
    for col in df.columns:
        col_lower = col.lower()
        for sensitive in BIAS_PATTERNS["sensitive_attributes"]:
            if sensitive in col_lower:
                sensitive_cols_found.append(col)
                findings.append(_create_finding(
                    severity="low",
                    category="Bias",
                    title=f"Protected Attribute Detected: '{col}'",
                    evidence=f"Column appears to contain {sensitive} data",
                    location=f"Column: {col}",
                    recommendation=f"Protected attributes require special handling:\n- Ensure compliance with anti-discrimination laws\n- Consider if this feature should be used in modeling\n- Document ethical justification for its use\n- Implement fairness constraints if using this attribute\n- May require IRB approval for research",
                    suggested_rewrite=None
                ))
                break
    
    # 5. Missing Data Analysis (can indicate collection bias)
    for col in df.columns:
        missing_count = df[col].isna().sum()
        missing_pct = (missing_count / len(df)) * 100
        
        if missing_pct > 30:
            findings.append(_create_finding(
                severity="medium",
                category="Bias",
                title=f"High Missing Data Rate: '{col}'",
                evidence=f"{missing_pct:.1f}% ({missing_count}/{len(df)}) values are missing",
                location=f"Column: {col}",
                recommendation=f"High missingness may indicate:\n- Systematic collection bias\n- Differential reporting across groups\n- Data quality issues\n\nInvestigate why data is missing and whether missingness correlates with protected attributes.",
                suggested_rewrite=f"# Analyze missingness patterns:\nprint(df['{col}'].isna().value_counts())\n# Consider imputation or exclusion"
            ))
    
    # 6. Numeric Feature Distribution Analysis
    numeric_cols = df.select_dtypes(include=[np.number]).columns
    
    for col in numeric_cols:
        if col in sensitive_cols_found:
            continue  # Already flagged
        
        # Check for extreme outliers (potential data quality issue)
        q1 = df[col].quantile(0.25)
        q3 = df[col].quantile(0.75)
        iqr = q3 - q1
        lower_bound = q1 - 3 * iqr
        upper_bound = q3 + 3 * iqr
        
        outliers = df[(df[col] < lower_bound) | (df[col] > upper_bound)][col]
        outlier_pct = (len(outliers) / len(df)) * 100
        
        if outlier_pct > 5:
            findings.append(_create_finding(
                severity="low",
                category="Bias",
                title=f"Significant Outliers Detected: '{col}'",
                evidence=f"{outlier_pct:.1f}% of values are extreme outliers",
                location=f"Column: {col}",
                recommendation="Outliers may indicate:\n- Data entry errors\n- Underrepresented subpopulations\n- Natural variation\n\nReview outliers to ensure they don't represent marginalized groups being excluded.",
                suggested_rewrite=None
            ))
    
    return findings

# ==============================================================================
# UNIFIED BIAS SCAN INTERFACE
# ==============================================================================

def run_bias_check(
    input_data: Union[str, pd.DataFrame],
    input_type: str
) -> Dict:
    """
    Main entry point for bias checking.
    
    Args:
        input_data: Text, code, or DataFrame to analyze
        input_type: One of 'text', 'code', or 'dataset'
        
    Returns:
        Dictionary with findings, summary, and metadata
    """
    try:
        findings = []
        
        if input_type == "text":
            findings = scan_text_bias(str(input_data))
        elif input_type == "code":
            findings = scan_code_bias(str(input_data))
        elif input_type == "dataset":
            if isinstance(input_data, pd.DataFrame):
                findings = scan_dataset_bias(input_data)
            else:
                # Try to parse as CSV
                try:
                    df = pd.read_csv(io.StringIO(input_data))
                    findings = scan_dataset_bias(df)
                except Exception as e:
                    return {
                        "status": "error",
                        "findings": [],
                        "summary": {},
                        "error": f"Could not parse dataset: {str(e)}"
                    }
        else:
            return {
                "status": "error",
                "findings": [],
                "summary": {},
                "error": f"Invalid input_type: {input_type}. Use 'text', 'code', or 'dataset'"
            }
        
        # Generate summary statistics
        summary = {
            "high": len([f for f in findings if f["severity"] == "high"]),
            "medium": len([f for f in findings if f["severity"] == "medium"]),
            "low": len([f for f in findings if f["severity"] == "low"])
        }
        
        return {
            "status": "success",
            "findings": findings,
            "summary": summary,
            "total_issues": len(findings),
            "input_type": input_type
        }
        
    except Exception as e:
        return {
            "status": "error",
            "findings": [],
            "summary": {},
            "error": str(e)
        }

# ==============================================================================
# UTILITY FUNCTIONS FOR REPORTING
# ==============================================================================

def generate_bias_summary(findings: List[Dict]) -> str:
    """Generate a human-readable summary of bias findings."""
    if not findings:
        return "✅ No significant bias indicators detected. Great work on inclusive practices!"
    
    high = len([f for f in findings if f["severity"] == "high"])
    medium = len([f for f in findings if f["severity"] == "medium"])
    low = len([f for f in findings if f["severity"] == "low"])
    
    summary = f"Found {len(findings)} potential bias indicator(s):\n"
    
    if high > 0:
        summary += f"🔴 {high} HIGH priority issue(s) - immediate attention required\n"
    if medium > 0:
        summary += f"🟡 {medium} MEDIUM priority issue(s) - should be reviewed\n"
    if low > 0:
        summary += f"🔵 {low} LOW priority issue(s) - for awareness\n"
    
    summary += "\nReview each finding and apply suggested fixes to improve fairness and inclusivity."
    
    return summary

def format_findings_for_display(findings: List[Dict]) -> str:
    """Format findings for console display."""
    if not findings:
        return "✅ No bias issues found!"
    
    output = []
    severity_icons = {"high": "🔴", "medium": "🟡", "low": "🔵"}
    
    for i, finding in enumerate(findings, 1):
        icon = severity_icons.get(finding["severity"], "⚪")
        output.append(f"\n{i}. {icon} [{finding['severity'].upper()}] {finding['title']}")
        output.append(f"   Location: {finding['location']}")
        output.append(f"   Evidence: {finding['evidence']}")
        output.append(f"   💡 {finding['recommendation']}")
        
        if finding.get("suggested_rewrite"):
            output.append(f"   ✏️  Suggested Fix: {finding['suggested_rewrite']}")
    
    return "\n".join(output)

# ==============================================================================
# DATASET PARSING UTILITIES
# ==============================================================================

def parse_uploaded_dataset(uploaded_file) -> Optional[pd.DataFrame]:
    """Parse uploaded dataset file into DataFrame."""
    try:
        if uploaded_file.type == "text/csv":
            return pd.read_csv(uploaded_file)
        elif uploaded_file.type in ["application/vnd.ms-excel", "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"]:
            return pd.read_excel(uploaded_file)
        else:
            return None
    except Exception as e:
        return None