"""
Advanced Analysis Utilities for EthicCheck
Includes specialized detectors and analysis functions
"""

import re
import ast
import json
from typing import List, Dict, Tuple
import numpy as np
from sentence_transformers import SentenceTransformer

# ==================== LICENSE DETECTION ====================

LICENSE_PATTERNS = {
    'MIT': r'MIT\s+License',
    'GPL-3.0': r'GNU\s+GENERAL\s+PUBLIC\s+LICENSE\s+Version\s+3',
    'Apache-2.0': r'Apache\s+License\s+Version\s+2\.0',
    'BSD-3': r'BSD\s+3-Clause',
    'MPL-2.0': r'Mozilla\s+Public\s+License\s+Version\s+2\.0',
    'LGPL': r'GNU\s+LESSER\s+GENERAL\s+PUBLIC\s+LICENSE',
}

def detect_licenses(text: str) -> List[Dict]:
    """Detect license mentions in text"""
    found_licenses = []
    for license_name, pattern in LICENSE_PATTERNS.items():
        matches = re.finditer(pattern, text, re.IGNORECASE)
        for match in matches:
            found_licenses.append({
                'license': license_name,
                'position': match.start(),
                'context': text[max(0, match.start()-50):match.end()+50]
            })
    return found_licenses

# ==================== DATASET DETECTION ====================

KNOWN_DATASETS = {
    'ImageNet': {'risk': 'medium', 'reason': 'May contain biased labels'},
    'COMPAS': {'risk': 'high', 'reason': 'Known algorithmic bias issues'},
    'CelebA': {'risk': 'high', 'reason': 'Privacy concerns with celebrity faces'},
    'YFCC100M': {'risk': 'high', 'reason': 'User-generated content without consent'},
    'CommonCrawl': {'risk': 'medium', 'reason': 'May contain copyrighted material'},
    'C4': {'risk': 'medium', 'reason': 'Web scraping concerns'},
}

def detect_datasets(text: str) -> List[Dict]:
    """Detect known dataset mentions"""
    findings = []
    text_lower = text.lower()
    
    for dataset_name, info in KNOWN_DATASETS.items():
        if dataset_name.lower() in text_lower:
            idx = text_lower.index(dataset_name.lower())
            findings.append({
                'dataset': dataset_name,
                'risk': info['risk'],
                'reason': info['reason'],
                'context': text[max(0, idx-100):idx+100]
            })
    
    return findings

# ==================== CODE ANALYSIS ====================

def analyze_python_code(code: str) -> Dict:
    """Deep analysis of Python code"""
    issues = {
        'security': [],
        'privacy': [],
        'quality': []
    }
    
    try:
        tree = ast.parse(code)
        
        # Check for dangerous imports
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    if alias.name in ['os', 'subprocess', 'eval', 'exec']:
                        issues['security'].append({
                            'type': 'dangerous_import',
                            'module': alias.name,
                            'line': node.lineno
                        })
            
            # Check for hardcoded secrets in assignments
            if isinstance(node, ast.Assign):
                for target in node.targets:
                    if isinstance(target, ast.Name):
                        name_lower = target.id.lower()
                        if any(keyword in name_lower for keyword in ['password', 'secret', 'key', 'token']):
                            if isinstance(node.value, ast.Constant):
                                issues['security'].append({
                                    'type': 'hardcoded_secret',
                                    'variable': target.id,
                                    'line': node.lineno
                                })
            
            # Check for eval/exec calls
            if isinstance(node, ast.Call):
                if isinstance(node.func, ast.Name):
                    if node.func.id in ['eval', 'exec']:
                        issues['security'].append({
                            'type': 'dangerous_function',
                            'function': node.func.id,
                            'line': node.lineno
                        })
    
    except SyntaxError as e:
        issues['quality'].append({
            'type': 'syntax_error',
            'message': str(e)
        })
    
    return issues

# ==================== PII ENHANCED DETECTION ====================

def detect_advanced_pii(text: str) -> Dict:
    """Enhanced PII detection with categorization"""
    pii_findings = {
        'emails': [],
        'phones': [],
        'ssn': [],
        'credit_cards': [],
        'names': [],
        'addresses': []
    }
    
    # Email detection
    email_pattern = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
    pii_findings['emails'] = re.findall(email_pattern, text)
    
    # Phone detection (multiple formats)
    phone_patterns = [
        r'\b\d{3}[-.]?\d{3}[-.]?\d{4}\b',
        r'\(\d{3}\)\s*\d{3}[-.]?\d{4}',
        r'\+\d{1,3}\s?\d{3,4}\s?\d{3,4}\s?\d{3,4}'
    ]
    for pattern in phone_patterns:
        pii_findings['phones'].extend(re.findall(pattern, text))
    
    # SSN detection
    ssn_pattern = r'\b\d{3}-\d{2}-\d{4}\b'
    pii_findings['ssn'] = re.findall(ssn_pattern, text)
    
    # Credit card detection (basic)
    cc_pattern = r'\b\d{4}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}\b'
    pii_findings['credit_cards'] = re.findall(cc_pattern, text)
    
    # Address detection (US format)
    address_pattern = r'\b\d+\s+[A-Z][a-z]+\s+(Street|St|Avenue|Ave|Road|Rd|Boulevard|Blvd)'
    pii_findings['addresses'] = re.findall(address_pattern, text)
    
    # Remove empty categories
    pii_findings = {k: v for k, v in pii_findings.items() if v}
    
    return pii_findings

# ==================== SEMANTIC SIMILARITY (PLAGIARISM) ====================

class SimilarityChecker:
    def __init__(self, model_name='all-MiniLM-L6-v2'):
        self.model = SentenceTransformer(model_name)
        self.reference_corpus = []
        self.reference_embeddings = None
    
    def add_reference_documents(self, documents: List[str]):
        """Add reference documents for comparison"""
        self.reference_corpus.extend(documents)
        self.reference_embeddings = self.model.encode(self.reference_corpus)
    
    def check_similarity(self, query_text: str, threshold=0.75) -> List[Dict]:
        """Check similarity against reference corpus"""
        if not self.reference_corpus:
            return []
        
        query_embedding = self.model.encode([query_text])
        
        # Compute cosine similarity
        similarities = np.dot(query_embedding, self.reference_embeddings.T)[0]
        
        findings = []
        for idx, similarity in enumerate(similarities):
            if similarity > threshold:
                findings.append({
                    'similarity_score': float(similarity),
                    'reference_doc': self.reference_corpus[idx][:200] + '...',
                    'severity': 'high' if similarity > 0.9 else 'medium'
                })
        
        return sorted(findings, key=lambda x: x['similarity_score'], reverse=True)

# ==================== BIAS DETECTION ====================

BIAS_KEYWORDS = {
    'gender': ['male', 'female', 'man', 'woman', 'boy', 'girl'],
    'race': ['white', 'black', 'asian', 'hispanic', 'latino', 'race', 'ethnicity'],
    'age': ['young', 'old', 'elderly', 'teenager', 'senior', 'age'],
    'religion': ['christian', 'muslim', 'jewish', 'hindu', 'buddhist', 'religion'],
    'disability': ['disabled', 'handicapped', 'wheelchair', 'blind', 'deaf']
}

def detect_bias_indicators(text: str) -> Dict:
    """Detect potential bias indicators"""
    findings = {'categories': [], 'warnings': []}
    text_lower = text.lower()
    
    for category, keywords in BIAS_KEYWORDS.items():
        mentions = [kw for kw in keywords if kw in text_lower]
        if mentions:
            findings['categories'].append({
                'category': category,
                'mentions': mentions,
                'count': sum(text_lower.count(kw) for kw in mentions)
            })
    
    # Check for imbalanced representation
    if len(findings['categories']) > 0:
        findings['warnings'].append(
            "Dataset may contain demographic categories. Ensure balanced representation."
        )
    
    return findings

# ==================== HARMFUL USE DETECTION ====================

HARMFUL_PATTERNS = {
    'surveillance': ['track', 'monitor', 'surveil', 'spy', 'follow', 'stalk'],
    'deception': ['fake', 'manipulate', 'deceive', 'trick', 'scam', 'phishing'],
    'weapons': ['weapon', 'bomb', 'explosive', 'attack', 'harm'],
    'illegal': ['hack', 'crack', 'bypass', 'circumvent', 'pirate', 'steal'],
    'discrimination': ['discriminate', 'exclude', 'deny access', 'segregate']
}

def detect_harmful_use(text: str) -> List[Dict]:
    """Detect potentially harmful use cases"""
    findings = []
    text_lower = text.lower()
    
    for category, keywords in HARMFUL_PATTERNS.items():
        for keyword in keywords:
            if keyword in text_lower:
                # Get context
                idx = text_lower.index(keyword)
                context = text[max(0, idx-100):min(len(text), idx+100)]
                
                findings.append({
                    'category': category,
                    'keyword': keyword,
                    'severity': 'high' if category in ['weapons', 'illegal'] else 'medium',
                    'context': context
                })
    
    return findings

# ==================== REPORT GENERATION ====================

def generate_student_summary(issues: List[Dict]) -> str:
    """Generate student-friendly summary"""
    if not issues:
        return "✅ Great work! No significant ethical issues detected in your project."
    
    high_count = len([i for i in issues if i.get('severity') == 'high'])
    medium_count = len([i for i in issues if i.get('severity') == 'medium'])
    
    summary = f"Your project has {len(issues)} ethical considerations to address:\n\n"
    
    if high_count > 0:
        summary += f"🔴 {high_count} high-priority issue(s) requiring immediate attention\n"
    if medium_count > 0:
        summary += f"🟡 {medium_count} medium-priority issue(s) to review\n"
    
    summary += "\nPlease review each issue and apply the suggested fixes. "
    summary += "If you have questions, discuss with your instructor."
    
    return summary

def generate_instructor_notes(issues: List[Dict], artifact_type: str) -> str:
    """Generate instructor-specific notes"""
    notes = f"Analysis of {artifact_type}:\n\n"
    
    high_severity = [i for i in issues if i.get('severity') == 'high']
    
    if high_severity:
        notes += "⚠️ HIGH PRIORITY FINDINGS:\n"
        for issue in high_severity[:3]:  # Top 3
            notes += f"  - {issue.get('category', 'Unknown')}: {issue.get('title', 'Issue detected')}\n"
        notes += "\n"
    
    notes += "RECOMMENDATIONS:\n"
    notes += "  - Review high-severity issues with student\n"
    notes += "  - Consider IRB/ethics board if human subjects involved\n"
    notes += "  - Verify dataset licenses and permissions\n"
    notes += "  - Check for proper consent mechanisms\n"
    
    return notes

# ==================== EXPORT UTILITIES ====================

def export_to_json(results: Dict) -> str:
    """Export results as JSON"""
    return json.dumps(results, indent=2)

def export_to_markdown(results: Dict) -> str:
    """Export results as Markdown report"""
    md = f"# EthicCheck Analysis Report\n\n"
    md += f"**Overall Risk**: {results.get('overall_score', 'N/A').upper()}\n\n"
    
    md += f"## Summary\n\n{results.get('student_summary', '')}\n\n"
    
    md += f"## Issues ({len(results.get('issues', []))})\n\n"
    
    for idx, issue in enumerate(results.get('issues', []), 1):
        md += f"### {idx}. {issue['title']} [{issue['severity'].upper()}]\n\n"
        md += f"**Category**: {issue['category']}\n\n"
        md += f"**Evidence**: {issue['evidence']}\n\n"
        md += f"**Recommendation**: {issue['recommendation']}\n\n"
        if issue.get('suggested_rewrite'):
            md += f"**Suggested Fix**:\n```\n{issue['suggested_rewrite']}\n```\n\n"
        md += "---\n\n"
    
    return md
