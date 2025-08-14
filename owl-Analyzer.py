import tkinter as tk
from tkinter import ttk, scrolledtext, filedialog, messagebox
import requests
import threading
import time

BG_COLOR = "#000000"
FG_COLOR = "#00FF00"
FONT = ("Courier New", 11)

class ServerResponseAnalyzer(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("🦉 Server Response Analyzer")
        self.geometry("750x600")
        self.configure(bg=BG_COLOR)
        self.protocol("WM_DELETE_WINDOW", self.on_close)

        style = ttk.Style()
        style.theme_use('default')
        style.configure('TButton', background="#111111", foreground=FG_COLOR, font=FONT)
        style.configure('TLabel', background=BG_COLOR, foreground=FG_COLOR, font=FONT)
        style.configure('TEntry', fieldbackground="#111111", foreground=FG_COLOR, font=FONT)

        frame = ttk.Frame(self)
        frame.pack(padx=10, pady=10, fill='x')

        ttk.Label(frame, text="Target URL:").grid(row=0, column=0, sticky='w')
        self.url_entry = ttk.Entry(frame, width=60)
        self.url_entry.grid(row=0, column=1, sticky='w')

        self.analyze_btn = ttk.Button(frame, text="Analyze", command=self.start_analysis)
        self.analyze_btn.grid(row=0, column=2, padx=10)

        self.save_btn = ttk.Button(frame, text="Save Report", command=self.save_report, state='disabled')
        self.save_btn.grid(row=0, column=3)

        self.output = scrolledtext.ScrolledText(self, height=30, bg="#111111", fg=FG_COLOR, font=FONT)
        self.output.pack(padx=10, pady=10, fill='both', expand=True)

        self._running = False
        self._thread = None
        self.report_data = ""

    def analyze_server(self, url):
        self.output.delete("1.0", tk.END)
        self.output.insert(tk.END, f"Starting analysis on: {url}\n\n")
        self.output.see(tk.END)
        session = requests.Session()
        self._running = True

        try:
            start_time = time.time()
            response = session.get(url, timeout=15)
            latency = time.time() - start_time

            self.output.insert(tk.END, f"HTTP Status Code: {response.status_code}\n")
            self.output.insert(tk.END, f"Response Time: {latency:.2f} seconds\n\n")

            self.output.insert(tk.END, "Response Headers:\n")
            for k, v in response.headers.items():
                self.output.insert(tk.END, f"  {k}: {v}\n")

            self.output.insert(tk.END, "\nContent Analysis:\n")
            content_lower = response.text.lower()

            keywords_block = ["forbidden", "blocked", "denied", "not allowed", "unauthorized", "error 403", "error 404", "firewall"]
            found_block = [word for word in keywords_block if word in content_lower]

            if response.status_code >= 400 or found_block:
                self.output.insert(tk.END, "Possible blocking or error detected!\n")
                if found_block:
                    self.output.insert(tk.END, f"Keywords found in content: {', '.join(found_block)}\n")
            else:
                self.output.insert(tk.END, "No obvious blocking detected.\n")

            self.output.insert(tk.END, "\nFirst 1000 chars of content:\n")
            self.output.insert(tk.END, response.text[:1000] + ("\n...[truncated]" if len(response.text) > 1000 else ""))

            self.report_data = self.output.get("1.0", tk.END)
            self.save_btn.config(state='normal')

        except Exception as e:
            self.output.insert(tk.END, f"Error: {e}\n")
            self.report_data = self.output.get("1.0", tk.END)
            self.save_btn.config(state='normal')

        self._running = False
        self.analyze_btn.config(state='normal')

    def start_analysis(self):
        if self._running:
            messagebox.showwarning("Warning", "Analysis is already running!")
            return
        url = self.url_entry.get().strip()
        if not url:
            messagebox.showerror("Error", "Please enter a URL.")
            return
        if not (url.startswith("http://") or url.startswith("https://")):
            url = "http://" + url
        self.analyze_btn.config(state='disabled')
        self.output.delete("1.0", tk.END)
        self._thread = threading.Thread(target=self.analyze_server, args=(url,), daemon=True)
        self._thread.start()

    def save_report(self):
        if not self.report_data.strip():
            messagebox.showinfo("Info", "No report data to save.")
            return
        filepath = filedialog.asksaveasfilename(
            defaultextension=".txt",
            filetypes=[("Text Files", "*.txt"), ("All Files", "*.*")],
            title="Save Report As"
        )
        if filepath:
            try:
                with open(filepath, "w", encoding="utf-8") as f:
                    f.write(self.report_data)
                messagebox.showinfo("Success", f"Report saved to {filepath}")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to save report: {e}")

    def on_close(self):
        self._running = False
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=2)
        self.destroy()

if __name__ == "__main__":
    app = ServerResponseAnalyzer()
    app.mainloop()

