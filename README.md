# EthicCheck 🛡️

**AI-Powered Ethical Analysis for Student Projects**

Automated detection of privacy, bias, copyright, and plagiarism issues in academic projects using Groq AI and advanced NLP.

---

## Features

- **🔒 Privacy Check** - Detects PII and hardcoded secrets using Microsoft Presidio
- **📜 IP & Copyright** - Identifies licensing conflicts and compliance issues
- **⚖️ Bias & Fairness** - Analyzes datasets and text for demographic imbalance
- **🔍 Plagiarism Detection** - Internet-based verification via search engines
- **📦 GitHub Integration** - Direct repository analysis (max 50MB, 500 files)
- **📄 PDF Reports** - Professional export with findings and recommendations

---

**Working Link:** https://ethiccheck.streamlit.app/

---
## Usage

1. **Upload** your project (PDF/DOCX/TXT/CSV/PY) or paste text or enter GitHub URL
2. **Select** analysis options (Copyright, Privacy, Bias, Plagiarism)
3. **Analyze** - Get results in under 60 seconds
4. **Review** issues with AI-powered fix suggestions
5. **Export** PDF report

---

## Tech Stack

|    Component   |                 Technology                  |
|----------------|---------------------------------------------|
| **Frontend**   | Streamlit                                   |
| **AI/ML**      | Groq (Llama 3.3 70B), Sentence Transformers |
| **Privacy**    | Microsoft Presidio, spaCy                   |
| **Plagiarism** | BeautifulSoup, DuckDuckGo/Bing APIs         |
| **Export**     | FPDF, python-docx                           |

---

## Project Structure

```
ethiccheck/
├── app.py                      # Main Streamlit app
├── bias_fairness_checker.py    # Bias detection engine
├── ip_copyright_checker.py     # License compliance
├── privacy_checker.py          # PII & secret detection
├── plagiarism_checker.py       # Internet verification
├── github_analyzer.py          # Repository analysis
├── utils/analyzers.py          # Helper functions
├── requirements.txt            # Dependencies
└── tests/                      # Unit tests
```

---

## Limitations

- Repository size: Max 50MB, 500 files
- Plagiarism: Limited to 10 phrases, web search accuracy dependent
- Language: Primarily English support
- PII Detection: Regex fallback if Presidio unavailable

---

## Acknowledgments

- Groq for Llama 3 API access
- Microsoft Presidio for PII detection
- Streamlit for rapid web development

---

**Built with ❤️ for ethical AI development**
