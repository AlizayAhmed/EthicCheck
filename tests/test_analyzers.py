"""
Unit tests for EthicCheck analyzers
Run with: pytest tests/test_analyzers.py -v
"""

import pytest
import sys
import os

# Add parent directory to path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from utils.analyzers import (
    detect_licenses,
    detect_datasets,
    analyze_python_code,
    detect_advanced_pii,
    detect_bias_indicators,
    detect_harmful_use,
    generate_student_summary,
    generate_instructor_notes
)

# ==================== PII DETECTION TESTS ====================

def test_email_detection():
    text = "Contact me at john.doe@example.com or jane@test.org"
    result = detect_advanced_pii(text)
    assert 'emails' in result
    assert len(result['emails']) == 2
    assert 'john.doe@example.com' in result['emails']

def test_phone_detection():
    text = "Call me at 123-456-7890 or (555) 123-4567"
    result = detect_advanced_pii(text)
    assert 'phones' in result
    assert len(result['phones']) >= 1

def test_ssn_detection():
    text = "SSN: 123-45-6789"
    result = detect_advanced_pii(text)
    assert 'ssn' in result
    assert len(result['ssn']) == 1

def test_no_pii():
    text = "This is a clean text with no personal information."
    result = detect_advanced_pii(text)
    assert len(result) == 0

# ==================== LICENSE DETECTION TESTS ====================

def test_mit_license_detection():
    text = """
    MIT License
    
    Copyright (c) 2024 John Doe
    """
    result = detect_licenses(text)
    assert len(result) > 0
    assert result[0]['license'] == 'MIT'

def test_gpl_license_detection():
    text = "This project is licensed under GNU GENERAL PUBLIC LICENSE Version 3"
    result = detect_licenses(text)
    assert len(result) > 0
    assert result[0]['license'] == 'GPL-3.0'

def test_no_license():
    text = "This is code without any license"
    result = detect_licenses(text)
    assert len(result) == 0

# ==================== DATASET DETECTION TESTS ====================

def test_imagenet_detection():
    text = "We use ImageNet dataset for training"
    result = detect_datasets(text)
    assert len(result) > 0
    assert result[0]['dataset'] == 'ImageNet'
    assert result[0]['risk'] in ['low', 'medium', 'high']

def test_compas_detection():
    text = "Analysis using COMPAS dataset"
    result = detect_datasets(text)
    assert len(result) > 0
    assert result[0]['dataset'] == 'COMPAS'
    assert result[0]['risk'] == 'high'

def test_multiple_datasets():
    text = "We compare results from ImageNet and CelebA datasets"
    result = detect_datasets(text)
    assert len(result) >= 2

# ==================== CODE ANALYSIS TESTS ====================

def test_hardcoded_password():
    code = """
    import requests
    
    password = "mySecretPass123"
    api_key = "sk-1234567890"
    """
    result = analyze_python_code(code)
    assert len(result['security']) > 0
    assert any('hardcoded_secret' in issue['type'] for issue in result['security'])

def test_dangerous_imports():
    code = """
    import os
    import subprocess
    
    os.system('rm -rf /')
    """
    result = analyze_python_code(code)
    assert len(result['security']) > 0
    assert any('dangerous_import' in issue['type'] for issue in result['security'])

def test_eval_usage():
    code = """
    user_input = input("Enter code: ")
    eval(user_input)
    """
    result = analyze_python_code(code)
    assert len(result['security']) > 0
    assert any('dangerous_function' in issue['type'] for issue in result['security'])

def test_clean_code():
    code = """
    import numpy as np
    
    def calculate_mean(data):
        return np.mean(data)
    """
    result = analyze_python_code(code)
    assert len(result['security']) == 0

def test_syntax_error():
    code = "def broken_function(:"
    result = analyze_python_code(code)
    assert len(result['quality']) > 0

# ==================== BIAS DETECTION TESTS ====================

def test_gender_bias_detection():
    text = "We analyze data from male and female participants"
    result = detect_bias_indicators(text)
    assert len(result['categories']) > 0
    assert any(cat['category'] == 'gender' for cat in result['categories'])

def test_race_bias_detection():
    text = "Dataset includes white, black, and asian subjects"
    result = detect_bias_indicators(text)
    assert len(result['categories']) > 0
    assert any(cat['category'] == 'race' for cat in result['categories'])

def test_multiple_bias_categories():
    text = "Study of young and elderly male and female participants of various races"
    result = detect_bias_indicators(text)
    assert len(result['categories']) >= 2

def test_no_bias_indicators():
    text = "This is a technical description without demographic mentions"
    result = detect_bias_indicators(text)
    assert len(result['categories']) == 0

# ==================== HARMFUL USE DETECTION TESTS ====================

def test_surveillance_detection():
    text = "We will track and monitor user behavior without their knowledge"
    result = detect_harmful_use(text)
    assert len(result) > 0
    assert any(finding['category'] == 'surveillance' for finding in result)

def test_deception_detection():
    text = "Creating fake news articles to manipulate public opinion"
    result = detect_harmful_use(text)
    assert len(result) > 0
    assert any(finding['category'] == 'deception' for finding in result)

def test_illegal_activity_detection():
    text = "Tool to hack into systems and bypass security"
    result = detect_harmful_use(text)
    assert len(result) > 0
    assert any(finding['severity'] == 'high' for finding in result)

def test_no_harmful_use():
    text = "Educational tool for learning programming concepts"
    result = detect_harmful_use(text)
    # Should be empty or low severity
    high_severity = [f for f in result if f['severity'] == 'high']
    assert len(high_severity) == 0

# ==================== REPORT GENERATION TESTS ====================

def test_student_summary_no_issues():
    issues = []
    summary = generate_student_summary(issues)
    assert "no significant ethical issues" in summary.lower()
    assert "great work" in summary.lower()

def test_student_summary_with_issues():
    issues = [
        {'severity': 'high', 'title': 'Privacy issue'},
        {'severity': 'medium', 'title': 'License issue'},
        {'severity': 'low', 'title': 'Minor concern'}
    ]
    summary = generate_student_summary(issues)
    assert "3" in summary or "three" in summary.lower()
    assert "high-priority" in summary.lower()

def test_instructor_notes_generation():
    issues = [
        {
            'severity': 'high',
            'category': 'Privacy',
            'title': 'PII Exposure'
        }
    ]
    notes = generate_instructor_notes(issues, 'Proposal')
    assert 'HIGH PRIORITY' in notes
    assert 'Privacy' in notes
    assert 'RECOMMENDATIONS' in notes

# ==================== INTEGRATION TESTS ====================

def test_full_pipeline_with_issues():
    """Test complete analysis pipeline"""
    text = """
    Project Proposal: Facial Recognition System
    
    We will scrape Facebook photos including names and locations.
    Dataset: CelebA (celebrity faces)
    Contact: admin@example.com
    Password: admin123
    
    We'll use this to track people without their consent.
    """
    
    # PII detection
    pii = detect_advanced_pii(text)
    assert len(pii) > 0
    
    # Dataset detection
    datasets = detect_datasets(text)
    assert len(datasets) > 0
    
    # Harmful use detection
    harmful = detect_harmful_use(text)
    assert len(harmful) > 0
    
    # Bias detection
    bias = detect_bias_indicators(text)
    # May or may not have bias indicators
    
def test_full_pipeline_clean_project():
    """Test with ethical project"""
    text = """
    Project: Machine Learning Tutorial
    
    We will create educational examples using synthetic data.
    All code will be open source under MIT License.
    No personal data will be collected.
    """
    
    # Should have minimal issues
    pii = detect_advanced_pii(text)
    harmful = detect_harmful_use(text)
    
    high_severity_harmful = [h for h in harmful if h['severity'] == 'high']
    assert len(high_severity_harmful) == 0

# ==================== EDGE CASES ====================

def test_empty_input():
    """Test with empty strings"""
    assert len(detect_advanced_pii("")) == 0
    assert len(detect_licenses("")) == 0
    assert len(detect_datasets("")) == 0

def test_very_long_input():
    """Test with very long text"""
    long_text = "word " * 10000
    result = detect_advanced_pii(long_text)
    # Should handle without crashing
    assert isinstance(result, dict)

def test_special_characters():
    """Test with special characters"""
    text = "Test @#$%^&*()_+-=[]{}|;':\",./<>?"
    result = detect_advanced_pii(text)
    # Should handle gracefully
    assert isinstance(result, dict)

def test_unicode_text():
    """Test with unicode characters"""
    text = "测试 тест परीक्षण test@example.com"
    result = detect_advanced_pii(text)
    assert 'emails' in result

# ==================== PYTEST FIXTURES ====================

@pytest.fixture
def sample_proposal():
    return """
    Research Proposal: AI Ethics Study
    
    We will analyze bias in AI systems using public datasets.
    All data will be anonymized and consent will be obtained.
    Project licensed under MIT.
    """

@pytest.fixture
def sample_code():
    return """
    import pandas as pd
    import numpy as np
    
    def load_data(filepath):
        return pd.read_csv(filepath)
    
    def analyze(data):
        return data.describe()
    """

def test_with_sample_proposal(sample_proposal):
    """Test using fixture"""
    licenses = detect_licenses(sample_proposal)
    assert len(licenses) > 0

def test_with_sample_code(sample_code):
    """Test using fixture"""
    result = analyze_python_code(sample_code)
    assert len(result['security']) == 0  # Clean code

# ==================== PERFORMANCE TESTS ====================

def test_pii_detection_performance():
    """Test PII detection speed"""
    import time
    text = "email@test.com " * 1000
    
    start = time.time()
    result = detect_advanced_pii(text)
    elapsed = time.time() - start
    
    assert elapsed < 1.0  # Should complete in under 1 second

def test_code_analysis_performance():
    """Test code analysis speed"""
    import time
    code = "import numpy as np\n" * 100
    
    start = time.time()
    result = analyze_python_code(code)
    elapsed = time.time() - start
    
    assert elapsed < 2.0  # Should complete in under 2 seconds

# ==================== MAIN ====================

if __name__ == '__main__':
    pytest.main([__file__, '-v', '--tb=short'])
