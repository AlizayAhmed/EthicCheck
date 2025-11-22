"""
Plagiarism Checker for EthicCheck
Internet-based plagiarism detection using multiple search engines
"""

import re
import time
import requests
from bs4 import BeautifulSoup
from urllib.parse import quote_plus
from typing import List, Dict, Any, Optional
import logging

# Suppress request warnings
logging.getLogger("urllib3").setLevel(logging.WARNING)

# =============================================================================
# CONFIGURATION
# =============================================================================

MIN_WORDS_PER_PHRASE = 6
MAX_WORDS_PER_PHRASE = 12
MAX_PHRASES_TO_CHECK = 10  # Reduced for web app performance
SEARCH_DELAY = 2  # Seconds between searches to avoid rate limiting
REQUEST_TIMEOUT = 10

# Severity thresholds
SEVERITY_THRESHOLDS = {
    "critical": 60,  # >= 60% = CRITICAL
    "high": 40,      # >= 40% = HIGH
    "medium": 20,    # >= 20% = MEDIUM
    "low": 10,       # >= 10% = LOW
}

# User agent for requests
USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"

# =============================================================================
# TEXT PROCESSING
# =============================================================================

def clean_text(text: str) -> str:
    """Clean and normalize text."""
    if not text:
        return ""
    text = re.sub(r'\s+', ' ', text)
    text = re.sub(r'[^\w\s.,!?;:\'"()-]', '', text)
    return text.strip()


def extract_sentences(text: str) -> List[str]:
    """Extract meaningful sentences from text."""
    text = clean_text(text)
    
    # Split by sentence endings
    sentences = re.split(r'(?<=[.!?])\s+', text)
    
    valid = []
    for s in sentences:
        s = s.strip()
        # Remove quotes and special chars from start/end
        s = s.strip('"\'')
        words = s.split()
        
        if len(words) >= MIN_WORDS_PER_PHRASE:
            # Limit phrase length for better search results
            if len(words) > MAX_WORDS_PER_PHRASE:
                s = ' '.join(words[:MAX_WORDS_PER_PHRASE])
            valid.append(s)
    
    return valid


def get_search_phrases(text: str, max_phrases: int = MAX_PHRASES_TO_CHECK) -> List[str]:
    """Get unique phrases to search for plagiarism."""
    sentences = extract_sentences(text)
    
    # If no sentences found, try splitting by newlines
    if not sentences:
        paragraphs = text.split('\n')
        for p in paragraphs:
            words = p.split()
            if len(words) >= MIN_WORDS_PER_PHRASE:
                phrase = ' '.join(words[:MAX_WORDS_PER_PHRASE])
                sentences.append(phrase)
    
    # Return unique phrases
    seen = set()
    unique = []
    for s in sentences:
        normalized = s.lower().strip()
        if normalized not in seen and len(normalized) > 20:
            seen.add(normalized)
            unique.append(s)
    
    # Distribute phrases evenly through document
    if len(unique) > max_phrases:
        step = len(unique) // max_phrases
        unique = [unique[i] for i in range(0, len(unique), step)][:max_phrases]
    
    return unique[:max_phrases]

# =============================================================================
# SEARCH FUNCTIONS
# =============================================================================

def search_duckduckgo(query: str) -> List[Dict[str, Any]]:
    """Search DuckDuckGo for phrase matches."""
    headers = {
        "User-Agent": USER_AGENT,
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.5",
        "Accept-Encoding": "gzip, deflate",
        "Connection": "keep-alive",
    }
    # Use exact phrase search
    search_url = f"https://html.duckduckgo.com/html/?q={quote_plus(query)}"
    
    try:
        resp = requests.get(search_url, headers=headers, timeout=REQUEST_TIMEOUT)
        soup = BeautifulSoup(resp.text, 'html.parser')
        
        results = []
        # Try multiple selectors for DuckDuckGo results
        result_divs = soup.find_all('div', class_='result') or soup.find_all('div', class_='results_links')
        
        for item in result_divs[:5]:
            title_tag = item.find('a', class_='result__a') or item.find('a')
            snippet_tag = item.find('a', class_='result__snippet') or item.find('div', class_='result__snippet')
            
            if title_tag:
                title = title_tag.get_text(strip=True)
                url = title_tag.get('href', '')
                snippet = snippet_tag.get_text(strip=True) if snippet_tag else title
                
                # Calculate word overlap - more lenient threshold
                query_words = set(query.lower().split())
                snippet_words = set(snippet.lower().split())
                title_words = set(title.lower().split())
                all_result_words = snippet_words | title_words
                overlap = len(query_words & all_result_words) / max(len(query_words), 1)
                
                if overlap > 0.2 or len(query_words & all_result_words) >= 3:
                    results.append({
                        'title': title[:100],
                        'url': url,
                        'snippet': snippet[:200],
                        'relevance': round(overlap, 2)
                    })
        
        return results
    except Exception as e:
        logging.debug(f"DuckDuckGo search error: {e}")
        return []


def search_bing(query: str) -> List[Dict[str, Any]]:
    """Search Bing for phrase matches."""
    headers = {"User-Agent": USER_AGENT}
    search_url = f"https://www.bing.com/search?q={quote_plus(query)}"
    
    try:
        resp = requests.get(search_url, headers=headers, timeout=REQUEST_TIMEOUT)
        soup = BeautifulSoup(resp.text, 'html.parser')
        
        results = []
        for item in soup.find_all('li', class_='b_algo')[:5]:
            title_tag = item.find('h2')
            link_tag = item.find('a')
            snippet_tag = item.find('p')
            
            if title_tag and link_tag:
                title = title_tag.get_text(strip=True)
                url = link_tag.get('href', '')
                snippet = snippet_tag.get_text(strip=True) if snippet_tag else ''
                
                query_words = set(query.lower().split())
                snippet_words = set(snippet.lower().split())
                overlap = len(query_words & snippet_words) / max(len(query_words), 1)
                
                if overlap > 0.3:
                    results.append({
                        'title': title[:100],
                        'url': url,
                        'snippet': snippet[:200],
                        'relevance': round(overlap, 2)
                    })
        
        return results
    except Exception:
        return []


def search_phrase(phrase: str) -> List[Dict[str, Any]]:
    """Search for a phrase using multiple search engines."""
    # Try DuckDuckGo first
    results = search_duckduckgo(f'"{phrase}"')
    
    # Try Bing as fallback
    if not results:
        results = search_bing(f'"{phrase}"')
    
    return results

# =============================================================================
# MAIN PLAGIARISM CHECK
# =============================================================================

def check_plagiarism(
    text: str,
    max_phrases: int = MAX_PHRASES_TO_CHECK,
    progress_callback: Optional[callable] = None
) -> Dict[str, Any]:
    """
    Check text for plagiarism against the internet.
    
    Args:
        text: Text to check
        max_phrases: Maximum number of phrases to check
        progress_callback: Optional callback(current, total, phrase) for progress updates
    
    Returns:
        Dict with plagiarism results and statistics
    """
    if not text or len(text.strip()) < 50:
        return {
            "status": "error",
            "error": "Text too short for plagiarism check",
            "plagiarism_percentage": 0,
            "severity": "unknown"
        }
    
    # Extract phrases to check
    phrases = get_search_phrases(text, max_phrases)
    
    if not phrases:
        return {
            "status": "error",
            "error": "Could not extract meaningful phrases from document",
            "plagiarism_percentage": 0,
            "severity": "unknown"
        }
    
    # Check each phrase
    results = []
    found_count = 0
    all_sources = {}
    
    for i, phrase in enumerate(phrases):
        if progress_callback:
            progress_callback(i + 1, len(phrases), phrase)
        
        matches = search_phrase(phrase)
        is_found = len(matches) > 0
        
        if is_found:
            found_count += 1
            
            # Track unique sources
            for m in matches[:2]:
                url = m.get('url', '')
                if url and url not in all_sources:
                    all_sources[url] = {
                        'url': url,
                        'title': m.get('title', 'Unknown'),
                        'phrases_matched': []
                    }
                if url:
                    all_sources[url]['phrases_matched'].append(phrase[:50])
        
        results.append({
            'phrase': phrase,
            'found': is_found,
            'sources': matches[:3]
        })
        
        # Delay between searches
        if i < len(phrases) - 1:
            time.sleep(SEARCH_DELAY)
    
    # Calculate statistics
    total = len(phrases)
    plagiarism_pct = round((found_count / total) * 100, 1) if total > 0 else 0
    
    # Determine severity
    if plagiarism_pct >= SEVERITY_THRESHOLDS["critical"]:
        severity = "critical"
    elif plagiarism_pct >= SEVERITY_THRESHOLDS["high"]:
        severity = "high"
    elif plagiarism_pct >= SEVERITY_THRESHOLDS["medium"]:
        severity = "medium"
    elif plagiarism_pct >= SEVERITY_THRESHOLDS["low"]:
        severity = "low"
    else:
        severity = "minimal"
    
    return {
        "status": "success",
        "plagiarism_percentage": plagiarism_pct,
        "severity": severity,
        "total_checked": total,
        "found_online": found_count,
        "original_count": total - found_count,
        "sources": list(all_sources.values()),
        "detailed_results": results
    }

# =============================================================================
# ETHICCHECK INTEGRATION
# =============================================================================

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


def run_plagiarism_check(
    text: str,
    max_phrases: int = MAX_PHRASES_TO_CHECK,
    progress_callback: Optional[callable] = None
) -> Dict[str, Any]:
    """
    Main entry point for plagiarism checking in EthicCheck.
    
    Args:
        text: Text to check for plagiarism
        max_phrases: Maximum phrases to check (default: 10)
        progress_callback: Optional progress callback
    
    Returns:
        Dict with findings in EthicCheck format
    """
    findings = []
    
    # Run plagiarism check
    result = check_plagiarism(text, max_phrases, progress_callback)
    
    if result.get("status") != "success":
        return {
            "status": "error",
            "error": result.get("error", "Unknown error"),
            "findings": [],
            "summary": {"high": 0, "medium": 0, "low": 0},
            "plagiarism_percentage": 0
        }
    
    plag_pct = result.get("plagiarism_percentage", 0)
    severity = result.get("severity", "minimal")
    sources = result.get("sources", [])
    flagged = [r for r in result.get("detailed_results", []) if r.get("found")]
    
    # Map severity levels
    severity_map = {
        "critical": "high",
        "high": "high",
        "medium": "medium",
        "low": "low",
        "minimal": "low"
    }
    ethic_severity = severity_map.get(severity, "medium")
    
    # Only create findings if plagiarism detected
    if plag_pct >= SEVERITY_THRESHOLDS["low"]:
        # Main plagiarism finding
        findings.append(_create_finding(
            severity=ethic_severity,
            category="Plagiarism",
            title=f"Potential Plagiarism Detected ({plag_pct}%)",
            evidence=f"Found {result.get('found_online', 0)} of {result.get('total_checked', 0)} phrases matching online sources",
            location="Throughout document",
            recommendation="Review flagged phrases and either rewrite in your own words, add proper citations, or use quotation marks with attribution.",
            suggested_rewrite="Paraphrase the content using your own words and cite original sources"
        ))
        
        # Add source findings
        for source in sources[:5]:
            url = source.get('url', 'Unknown URL')
            title = source.get('title', 'Unknown Source')
            matched_count = len(source.get('phrases_matched', []))
            
            findings.append(_create_finding(
                severity="medium" if matched_count > 1 else "low",
                category="Plagiarism",
                title=f"Matching Source Found",
                evidence=f"Source: {title[:80]}\nURL: {url[:100]}\nMatched phrases: {matched_count}",
                location="See source URL",
                recommendation=f"If using content from this source, add proper citation: '{title[:50]}...'",
                suggested_rewrite=f'Add citation: [Source: {title[:40]}...]'
            ))
        
        # Add flagged phrase findings (top 3)
        for item in flagged[:3]:
            phrase = item.get('phrase', '')
            source_url = item['sources'][0]['url'] if item.get('sources') else 'Unknown'
            
            findings.append(_create_finding(
                severity="medium",
                category="Plagiarism",
                title="Flagged Phrase",
                evidence=f'"{phrase[:100]}..."',
                location="Document body",
                recommendation="Rewrite this phrase in your own words or add quotation marks with proper citation.",
                suggested_rewrite=f"Paraphrase or cite: According to [Source], '{phrase[:50]}...'"
            ))
    
    # Calculate summary
    summary = {
        "high": len([f for f in findings if f["severity"] == "high"]),
        "medium": len([f for f in findings if f["severity"] == "medium"]),
        "low": len([f for f in findings if f["severity"] == "low"]),
    }
    
    return {
        "status": "success",
        "findings": findings,
        "summary": summary,
        "plagiarism_percentage": plag_pct,
        "severity": severity,
        "total_checked": result.get("total_checked", 0),
        "found_online": result.get("found_online", 0),
        "sources": sources,
        "detailed_results": result.get("detailed_results", [])
    }


def generate_plagiarism_summary(result: Dict[str, Any]) -> str:
    """Generate a human-readable summary of plagiarism findings."""
    if result.get("status") != "success":
        return f"❌ Plagiarism check failed: {result.get('error', 'Unknown error')}"
    
    plag_pct = result.get("plagiarism_percentage", 0)
    severity = result.get("severity", "minimal")
    total = result.get("total_checked", 0)
    found = result.get("found_online", 0)
    sources = result.get("sources", [])
    
    # Severity emoji
    emoji_map = {
        "critical": "🔴",
        "high": "🟠",
        "medium": "🟡",
        "low": "🟢",
        "minimal": "✅"
    }
    emoji = emoji_map.get(severity, "⚪")
    
    if plag_pct < SEVERITY_THRESHOLDS["low"]:
        return f"✅ Minimal plagiarism detected ({plag_pct}%). Your content appears to be largely original."
    
    text = f"{emoji} Plagiarism Level: {severity.upper()} ({plag_pct}%)\n\n"
    text += f"📊 Statistics:\n"
    text += f"   • Phrases checked: {total}\n"
    text += f"   • Found online: {found}\n"
    text += f"   • Original: {total - found}\n"
    
    if sources:
        text += f"\n🌐 Sources Found: {len(sources)}\n"
        for s in sources[:3]:
            text += f"   • {s.get('title', 'Unknown')[:50]}...\n"
    
    text += "\n💡 Recommendation: Review flagged phrases and add proper citations or rewrite in your own words."
    
    return text