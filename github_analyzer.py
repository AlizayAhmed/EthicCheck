"""
GitHub Repository Analyzer for EthicCheck
Extracts and analyzes code from GitHub repositories
"""

import os
import shutil
import tempfile
import subprocess
from typing import Dict, List, Optional, Tuple
import re
from pathlib import Path

# =============================================================================
# CONFIGURATION
# =============================================================================

MAX_REPO_SIZE_MB = 50  # Maximum repository size in MB
MAX_FILES = 500  # Maximum number of files to process
EXCLUDED_DIRS = {'.git', 'node_modules', '__pycache__', '.venv', 'venv', 'env', 
                 'dist', 'build', '.idea', '.vscode', 'target', 'bin', 'obj'}
EXCLUDED_EXTENSIONS = {'.pyc', '.pyo', '.so', '.dll', '.exe', '.bin', '.o', 
                       '.a', '.lib', '.dylib', '.jar', '.war', '.class', 
                       '.min.js', '.min.css', '.map'}

# Code file extensions to analyze
CODE_EXTENSIONS = {
    '.py': 'Python',
    '.js': 'JavaScript',
    '.ts': 'TypeScript',
    '.java': 'Java',
    '.cpp': 'C++',
    '.c': 'C',
    '.cs': 'C#',
    '.rb': 'Ruby',
    '.go': 'Go',
    '.rs': 'Rust',
    '.php': 'PHP',
    '.swift': 'Swift',
    '.kt': 'Kotlin',
    '.scala': 'Scala',
    '.r': 'R',
    '.m': 'MATLAB',
    '.sh': 'Shell',
    '.sql': 'SQL',
    '.html': 'HTML',
    '.css': 'CSS',
    '.jsx': 'React',
    '.tsx': 'React TypeScript',
    '.vue': 'Vue',
}

# Documentation file extensions
DOC_EXTENSIONS = {'.md', '.txt', '.rst', '.adoc', '.pdf', '.docx'}

# License file patterns
LICENSE_PATTERNS = [
    r'license',
    r'licence',
    r'copying',
    r'copyright',
]

# =============================================================================
# HELPER FUNCTIONS
# =============================================================================

def is_valid_github_url(url: str) -> bool:
    """Validate GitHub URL format."""
    patterns = [
        r'^https://github\.com/[\w-]+/[\w.-]+/?$',
        r'^git@github\.com:[\w-]+/[\w.-]+\.git$',
    ]
    return any(re.match(pattern, url.strip()) for pattern in patterns)


def normalize_github_url(url: str) -> str:
    """Normalize GitHub URL to HTTPS format."""
    url = url.strip()
    
    # Convert SSH to HTTPS
    if url.startswith('git@github.com:'):
        url = url.replace('git@github.com:', 'https://github.com/')
        url = url.replace('.git', '')
    
    # Remove trailing slash
    url = url.rstrip('/')
    
    return url


def get_repo_name(url: str) -> str:
    """Extract repository name from URL."""
    url = normalize_github_url(url)
    parts = url.rstrip('/').split('/')
    return parts[-1] if parts else 'unknown'


def get_dir_size_mb(path: str) -> float:
    """Calculate directory size in MB."""
    total = 0
    try:
        for entry in os.scandir(path):
            if entry.is_file():
                total += entry.stat().st_size
            elif entry.is_dir() and entry.name not in EXCLUDED_DIRS:
                total += get_dir_size_mb(entry.path)
    except Exception:
        pass
    return total / (1024 * 1024)


def should_process_file(file_path: str) -> bool:
    """Check if file should be processed."""
    path = Path(file_path)
    
    # Check if any parent directory is excluded
    if any(excluded in path.parts for excluded in EXCLUDED_DIRS):
        return False
    
    # Check file extension
    if path.suffix in EXCLUDED_EXTENSIONS:
        return False
    
    return True


def detect_license(repo_path: str) -> Optional[str]:
    """Detect license file in repository."""
    try:
        for root, dirs, files in os.walk(repo_path):
            # Only check root directory
            if root != repo_path:
                break
            
            for file in files:
                file_lower = file.lower()
                if any(re.search(pattern, file_lower) for pattern in LICENSE_PATTERNS):
                    license_path = os.path.join(root, file)
                    try:
                        with open(license_path, 'r', encoding='utf-8', errors='ignore') as f:
                            content = f.read(1000)  # Read first 1000 chars
                            
                            # Try to identify license type
                            content_lower = content.lower()
                            if 'mit license' in content_lower:
                                return 'MIT'
                            elif 'apache' in content_lower:
                                return 'Apache-2.0'
                            elif 'gpl' in content_lower:
                                return 'GPL'
                            elif 'bsd' in content_lower:
                                return 'BSD'
                            else:
                                return 'Custom License'
                    except Exception:
                        return 'License File Found'
    except Exception:
        pass
    return None

# =============================================================================
# MAIN ANALYSIS FUNCTIONS
# =============================================================================

def clone_repository(url: str, progress_callback=None) -> Tuple[bool, str, Optional[str]]:
    """
    Clone GitHub repository to temporary directory.
    
    Args:
        url: GitHub repository URL
        progress_callback: Optional callback for progress updates
        
    Returns:
        Tuple of (success, message, temp_dir_path)
    """
    # Validate URL
    if not is_valid_github_url(url):
        return False, "Invalid GitHub URL format. Use: https://github.com/user/repo", None
    
    url = normalize_github_url(url)
    repo_name = get_repo_name(url)
    
    # Create temporary directory
    temp_dir = tempfile.mkdtemp(prefix='ethiccheck_')
    
    try:
        if progress_callback:
            progress_callback("Cloning repository...")
        
        # Clone repository
        result = subprocess.run(
            ['git', 'clone', '--depth', '1', url, temp_dir],
            capture_output=True,
            text=True,
            timeout=120  # 2 minute timeout
        )
        
        if result.returncode != 0:
            error_msg = result.stderr or "Failed to clone repository"
            shutil.rmtree(temp_dir, ignore_errors=True)
            
            if 'not found' in error_msg.lower():
                return False, f"Repository not found: {repo_name}", None
            elif 'authentication' in error_msg.lower():
                return False, f"Authentication failed. Repository may be private: {repo_name}", None
            else:
                return False, f"Git clone failed: {error_msg[:200]}", None
        
        # Check repository size
        repo_size = get_dir_size_mb(temp_dir)
        if repo_size > MAX_REPO_SIZE_MB:
            shutil.rmtree(temp_dir, ignore_errors=True)
            return False, f"Repository too large ({repo_size:.1f} MB). Maximum size: {MAX_REPO_SIZE_MB} MB", None
        
        if progress_callback:
            progress_callback(f"Repository cloned successfully ({repo_size:.2f} MB)")
        
        return True, f"Successfully cloned {repo_name}", temp_dir
        
    except subprocess.TimeoutExpired:
        shutil.rmtree(temp_dir, ignore_errors=True)
        return False, "Clone operation timed out. Repository may be too large.", None
    
    except FileNotFoundError:
        shutil.rmtree(temp_dir, ignore_errors=True)
        return False, "Git is not installed. Please install Git to analyze repositories.", None
    
    except Exception as e:
        shutil.rmtree(temp_dir, ignore_errors=True)
        return False, f"Unexpected error: {str(e)}", None


def extract_repository_content(repo_path: str, progress_callback=None) -> Dict:
    """
    Extract and analyze repository content.
    
    Args:
        repo_path: Path to cloned repository
        progress_callback: Optional callback for progress updates
        
    Returns:
        Dictionary with repository analysis
    """
    result = {
        'files': [],
        'languages': {},
        'total_files': 0,
        'code_files': 0,
        'doc_files': 0,
        'total_lines': 0,
        'license': None,
        'readme': None,
        'combined_code': '',
        'combined_docs': '',
        'file_list': [],
    }
    
    try:
        # Detect license
        result['license'] = detect_license(repo_path)
        
        if progress_callback:
            progress_callback("Scanning repository files...")
        
        # Walk through repository
        file_count = 0
        for root, dirs, files in os.walk(repo_path):
            # Remove excluded directories
            dirs[:] = [d for d in dirs if d not in EXCLUDED_DIRS]
            
            for file in files:
                if file_count >= MAX_FILES:
                    break
                
                file_path = os.path.join(root, file)
                rel_path = os.path.relpath(file_path, repo_path)
                
                if not should_process_file(file_path):
                    continue
                
                file_ext = Path(file).suffix.lower()
                
                # Check for README
                if file.lower().startswith('readme'):
                    try:
                        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                            result['readme'] = f.read()
                    except Exception:
                        pass
                
                # Process code files
                if file_ext in CODE_EXTENSIONS:
                    language = CODE_EXTENSIONS[file_ext]
                    result['languages'][language] = result['languages'].get(language, 0) + 1
                    result['code_files'] += 1
                    
                    try:
                        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                            content = f.read()
                            line_count = content.count('\n') + 1
                            result['total_lines'] += line_count
                            
                            # Add to combined code
                            result['combined_code'] += f"\n\n# ===== {rel_path} =====\n\n{content}"
                            
                            result['files'].append({
                                'path': rel_path,
                                'language': language,
                                'lines': line_count,
                                'size': len(content)
                            })
                    except Exception:
                        pass
                
                # Process documentation files
                elif file_ext in DOC_EXTENSIONS:
                    result['doc_files'] += 1
                    
                    try:
                        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                            content = f.read()
                            result['combined_docs'] += f"\n\n# ===== {rel_path} =====\n\n{content}"
                    except Exception:
                        pass
                
                result['file_list'].append(rel_path)
                file_count += 1
        
        result['total_files'] = len(result['file_list'])
        
        if progress_callback:
            progress_callback(f"Extracted {result['total_files']} files")
        
        return result
        
    except Exception as e:
        return {
            'error': f"Failed to extract repository content: {str(e)}",
            'files': [],
            'languages': {},
            'total_files': 0,
        }


def cleanup_repository(repo_path: str):
    """Clean up temporary repository directory."""
    try:
        if repo_path and os.path.exists(repo_path):
            shutil.rmtree(repo_path, ignore_errors=True)
    except Exception:
        pass


def analyze_github_repository(url: str, progress_callback=None) -> Dict:
    """
    Main function to analyze a GitHub repository.
    
    Args:
        url: GitHub repository URL
        progress_callback: Optional callback for progress updates
        
    Returns:
        Dictionary with repository analysis and extracted content
    """
    temp_dir = None
    
    try:
        # Clone repository
        success, message, temp_dir = clone_repository(url, progress_callback)
        
        if not success:
            return {
                'status': 'error',
                'error': message,
                'repo_info': None,
                'content': None
            }
        
        # Extract content
        repo_content = extract_repository_content(temp_dir, progress_callback)
        
        if 'error' in repo_content:
            return {
                'status': 'error',
                'error': repo_content['error'],
                'repo_info': None,
                'content': None
            }
        
        # Calculate repository size
        repo_size_mb = get_dir_size_mb(temp_dir)
        
        # Prepare repository info
        repo_info = {
            'name': get_repo_name(url),
            'url': url,
            'files_analyzed': repo_content['total_files'],
            'code_files': repo_content['code_files'],
            'doc_files': repo_content['doc_files'],
            'size_mb': round(repo_size_mb, 2),
            'languages': list(repo_content['languages'].keys()),
            'language_count': len(repo_content['languages']),
            'license': repo_content['license'],
            'total_lines': repo_content['total_lines'],
        }
        
        # Prepare content for analysis
        analysis_content = {
            'code': repo_content['combined_code'],
            'docs': repo_content['combined_docs'],
            'readme': repo_content['readme'],
            'files': repo_content['files'],
        }
        
        return {
            'status': 'success',
            'message': f"Successfully analyzed {repo_info['name']}",
            'repo_info': repo_info,
            'content': analysis_content
        }
        
    except Exception as e:
        return {
            'status': 'error',
            'error': f"Unexpected error during analysis: {str(e)}",
            'repo_info': None,
            'content': None
        }
    
    finally:
        # Always cleanup
        if temp_dir:
            cleanup_repository(temp_dir)


def format_repo_info_display(repo_info: Dict) -> str:
    """Format repository info for display."""
    if not repo_info:
        return ""
    
    license_icon = "✅" if repo_info.get('license') else "❌"
    license_text = repo_info.get('license', 'Not Found')
    
    languages_str = ', '.join(repo_info.get('languages', []))
    
    return f"""
**📦 Repository Information**

- **Files Analyzed:** {repo_info.get('files_analyzed', 0)}
- **Repository Size:** {repo_info.get('size_mb', 0)} MB
- **Languages:** {repo_info.get('language_count', 0)}
- **License:** {license_icon} {license_text}
- **Total Code Lines:** {repo_info.get('total_lines', 0):,}

**Languages detected:** {languages_str or 'None'}
"""