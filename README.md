╔════════════════════════════════════════════════════════════════════════╗
║                        🦉 Server Response Analyzer                     ║
║                          Version 1.0                                  ║
║             by khaled.s.haddad | khaledhaddad.tech                    ║
╠════════════════════════════════════════════════════════════════════════╣
║ 📌 Description                                                         ║
║ ───────────────────────────────────────────────────────────────────── ║
║ A GUI tool built with Python and Tkinter that analyzes server         ║
║ responses. It sends HTTP requests to a specified URL, and returns     ║
║ the HTTP status code, response time, headers, and basic content       ║
║ analysis. It helps detect possible blocks or restrictions such as     ║
║ firewalls or forbidden access pages.                                  ║
╠════════════════════════════════════════════════════════════════════════╣
║ ⚙️ Features                                                            ║
║ ───────────────────────────────────────────────────────────────────── ║
║ • GUI interface with dark terminal-like theme                         ║
║ • Sends GET requests to target URLs                                   ║
║ • Displays:                                                           ║
║   - HTTP status code                                                  ║
║   - Response time                                                     ║
║   - Response headers                                                  ║
║   - Basic content keyword detection                                   ║
║   - First 1000 characters of the body                                 ║
║ • Save full report to a text file                                     ║
╠════════════════════════════════════════════════════════════════════════╣
║ 🛠️ Requirements                                                       ║
║ ───────────────────────────────────────────────────────────────────── ║
║ • Python 3.x                                                          ║
║ • requests                                                            ║
╠════════════════════════════════════════════════════════════════════════╣
║ ▶️ How to Run                                                         ║
║ ───────────────────────────────────────────────────────────────────── ║
║ 1. Install dependencies (if needed):                                  ║
║    pip install requests                                               ║
║                                                                        ║
║ 2. Run the tool:                                                      ║
║    python3 server_response_analyzer.py                                ║
║                                                                        ║
║ 3. Enter the URL and click "Analyze".                                 ║
║ 4. View the output or save it using "Save Report".                    ║
╠════════════════════════════════════════════════════════════════════════╣
║ 🧠 Notes                                                              ║
║ ───────────────────────────────────────────────────────────────────── ║
║ • Automatically adds http:// if no scheme provided                    ║
║ • Detects keywords like 'blocked', 'denied', 'firewall', etc.        ║
║ • Multi-threaded to keep UI responsive during analysis                ║
╠════════════════════════════════════════════════════════════════════════╣
║ 🐍 Author                                                             ║
║ ───────────────────────────────────────────────────────────────────── ║
║ khaled.s.haddad                                                      ║
║ 🌐 https://khaledhaddad.tech                                          ║
╚════════════════════════════════════════════════════════════════════════╝

