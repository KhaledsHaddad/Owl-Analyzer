# 🦉 Server Response Analyzer

**Version:** 1.0  
**Author:** khaled.s.haddad  
**Website:** [khaledhaddad.tech](https://khaledhaddad.tech)  

---

## 📌 Description

**Server Response Analyzer** is a Python + Tkinter GUI tool that analyzes server responses.  
It sends HTTP requests to a specified URL and returns:

- HTTP status code  
- Response time  
- Headers  
- Basic content keyword detection  
- First 1000 characters of the page body  

This tool is useful for detecting possible **blocks or restrictions** such as firewalls or forbidden access pages.

---

## ⚙️ Features

- Dark terminal-style GUI  
- Sends GET requests to target URLs  
- Displays:
  - HTTP status code
  - Response time
  - Response headers
  - Basic content keyword detection
  - First 1000 characters of the body
- Save full report to a text file  
- Multi-threaded for smooth UI performance  

---

## 🛠️ Requirements

- Python 3.x  
- `requests` library  

Install dependencies:
```bash
pip install requests
