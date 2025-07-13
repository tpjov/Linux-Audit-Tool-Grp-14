#!/usr/bin/env python3
"""
Ubuntu CIS Benchmark Audit Tool  –  GUI + Matplotlib Pie Chart
Dark-/Light-mode, adjustable font size + Sidebar with chapter list and PDF download
"""
import os
import subprocess
import webbrowser
import tkinter as tk
from tkinter import scrolledtext, filedialog, messagebox

import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg

# ── CONFIGURATION ────────────────────────────────────────────────
CHAPTER_SCRIPTS = {
    "Chapter 1":  "chapter1.sh",
    "Chapter 2":  "chapter2.sh",
    "Chapter 3":  "chapter3.sh",
    "Chapter 4":  "chapter4.sh",
    "Chapter 5":  "chapter5.sh",
    "Chapter 6":  "chapter6.sh",
    "Chapter 7":  "chapter7.sh",
    "Chapter 8":  "chapter8.sh",
    "Chapter 9":  "chapter9.sh",
    "Chapter 10": "chapter10.sh",
    "Chapter 11": "chapter11.sh",
    "Chapter 12": "chapter12.sh",
    "Chapter 13": "chapter13.sh",
    "All Chapters": "allchapters.sh",
}

chapter_names = [
    "1 Patching and Software Updates",
    "2 Filesystem Configuration",
    "3 Secure Boot Settings",
    "4 Additional Process Hardening",
    "5 OS Services",
    "5.1 Ensure Legacy Services are Not Enabled",
    "6 Special Purpose Services",
    "7 Network Configuration and Firewalls",
    "7.1 Modify Network Parameters (Host Only)",
    "7.2 Modify Network Parameters (Host and Router)",
    "7.3 Configure IPv6",
    "7.4 Install TCP Wrappers",
    "7.5 Uncommon Network Protocols",
    "8 Logging and Auditing",
    "8.1 Configure System Accounting (auditd)",
    "8.2 Configure rsyslog",
    "8.3 Advanced Intrusion Detection Environment (AIDE)",
    "9 System Access, Authentication and Authorization",
    "9.1 Configure cron",
    "9.2 Configure PAM",
    "9.3 Configure SSH",
    "10 User Accounts and Environment",
    "10.1 Set Shadow Password Suite Parameters",
    "11 Warning Banners",
    "12 Verify System File Permissions",
    "13 Review User and Group Settings"
]

THEMES = {
    "light": {
        "bg": "#f0f2f5",
        "fg": "black",
        "button_bg": "#45A049",
        "button_fg": "white",
        "text_bg": "#FAFAFA",
        "text_fg": "black"
    },
    "dark": {
        "bg": "#121212",
        "fg": "white",
        "button_bg": "#333333",
        "button_fg": "white",
        "text_bg": "#1e1e1e",
        "text_fg": "white"
    }
}

current_theme = "light"
current_font_size = 11

# ── HELPER FUNCTIONS ────────────────────────────────────────────
def parse_summary(output: str) -> tuple[int, int, int]:
    passed = failed_scored = failed_not_scored = 0
    for ln in output.splitlines():
        line = ln.strip()
        try:
            if "Passed Audits" in line:
                passed = int(line.split(":")[1].strip())
            elif "- Scored" in line:
                failed_scored = int(line.split(":")[1].strip())
            elif "- Not Scored" in line:
                failed_not_scored = int(line.split(":")[1].strip())
        except (IndexError, ValueError):
            continue
    return passed, failed_scored, failed_not_scored

def autopct_fmt(values):
    total = sum(values)
    def inner(pct):
        if pct == 0 or total == 0:
            return ""
        count = int(round(pct * total / 100.0))
        return f"{count} ({pct:.1f}%)"
    return inner

def apply_theme(window):
    theme = THEMES[current_theme]
    window.configure(bg=theme["bg"])
    for widget in window.winfo_children():
        if isinstance(widget, tk.Button):
            widget.configure(bg=theme["button_bg"], fg=theme["button_fg"])
        elif isinstance(widget, tk.Label):
            widget.configure(bg=theme["bg"], fg=theme["fg"])
        elif isinstance(widget, scrolledtext.ScrolledText):
            widget.configure(bg=theme["text_bg"], fg=theme["text_fg"])
        elif isinstance(widget, tk.Frame):
            apply_theme(widget)

def toggle_theme():
    global current_theme
    current_theme = "dark" if current_theme == "light" else "light"
    apply_theme(root)

def change_font_size(delta: int):
    global current_font_size
    current_font_size = max(8, current_font_size + delta)
    for widget in root.winfo_children():
        if isinstance(widget, (tk.Label, tk.Button)):
            widget.configure(font=("Helvetica", current_font_size))
        elif isinstance(widget, tk.Frame):
            for sub in widget.winfo_children():
                if isinstance(sub, tk.Button):
                    sub.configure(font=("Helvetica", current_font_size))

def download_pdf_guide():
    pdf_url = "https://drive.google.com/drive/folders/1wAfgRmcssjifdEPScS9K1Kr2u8_DUnfv?usp=drive_link"
    messagebox.showinfo("Download PDF", f"Open the following link in your browser:\n\n{pdf_url}")

def create_run_function(chapter_name: str, script_path: str):
    def run_script():
        popup = tk.Toplevel(root)
        popup.title(f"{chapter_name} Audit Results")
        popup.geometry("820x720")

        tk.Label(popup, text=f"{chapter_name} Audit Results", font=("Helvetica", current_font_size + 3, "bold")).pack(pady=10)
        out_box = scrolledtext.ScrolledText(popup, width=95, height=22, font=("Courier New", current_font_size))
        out_box.pack(padx=15, pady=10)

        if not os.path.isfile(script_path):
            out_box.insert(tk.END, f"Error: script not found → {script_path}\n")
            return

        result = subprocess.run(["bash", script_path], capture_output=True, text=True)
        output = result.stdout
        out_box.insert(tk.END, output)

        if result.stderr:
            out_box.insert(tk.END, "\n[ERROR OUTPUT]\n" + result.stderr)

        passed, failed_scored, failed_not_scored = parse_summary(output)

        def show_chart():
            if passed == failed_scored == failed_not_scored == 0:
                messagebox.showinfo("No Data", "Pie chart cannot be displayed because all values are zero.")
                return
            chart_win = tk.Toplevel(popup)
            chart_win.title("Audit Result Pie Chart")
            chart_win.geometry("800x600")

            labels = ["Passed", "Failed (Scored)", "Failed (Not Scored)"]
            values = [passed, failed_scored, failed_not_scored]
            colors = ["#4CAF50", "#F44336", "#FF9800"]

            fig, ax = plt.subplots(figsize=(6, 5))
            wedges, _, _ = ax.pie(
                values,
                labels=None,
                autopct=autopct_fmt(values),
                startangle=140,
                colors=colors,
                textprops={"color": "white", "fontsize": 9},
            )
            ax.axis("equal")
            ax.legend(wedges, labels, title="Audit Result", loc="center left", bbox_to_anchor=(1.05, 0.5))
            fig.tight_layout()

            frame = tk.Frame(chart_win)
            frame.pack(pady=20)
            canvas = FigureCanvasTkAgg(fig, master=frame)
            canvas.draw()
            canvas.get_tk_widget().pack()

            tk.Button(chart_win, text="Close", command=chart_win.destroy, bg="#D32F2F", fg="white").pack(pady=10)
            apply_theme(chart_win)

        def save_output():
            file_path = filedialog.asksaveasfilename(defaultextension=".txt", filetypes=[("Text Files", "*.txt"), ("All Files", "*.*")], title="Save Audit Output")
            if file_path:
                try:
                    with open(file_path, "w") as f:
                        f.write(output)
                    messagebox.showinfo("Success", f"Audit output saved to:\n{file_path}")
                except Exception as e:
                    messagebox.showerror("Error", f"Failed to save file:\n{e}")

        btn_frame = tk.Frame(popup)
        btn_frame.pack(pady=10)
        tk.Button(btn_frame, text="Show Pie Chart", command=show_chart).grid(row=0, column=0, padx=5)
        tk.Button(btn_frame, text="Download Output", command=save_output).grid(row=0, column=1, padx=5)
        tk.Button(btn_frame, text="Close", command=popup.destroy).grid(row=0, column=2, padx=5)

        apply_theme(popup)

    return run_script

# ── MAIN WINDOW ─────────────────────────────────────────────────
root = tk.Tk()
root.title("Ubuntu CIS Benchmark Audit Tool")
root.geometry("1100x720")

# Side list panel
chapter_list_frame = tk.Frame(root, width=240)
chapter_list_frame.pack(side=tk.LEFT, fill=tk.Y, padx=(10, 0), pady=10)

tk.Label(chapter_list_frame, text="Chapter List", font=("Helvetica", current_font_size + 1, "bold")).pack(anchor="w", pady=(0, 5))
chapter_listbox = tk.Listbox(chapter_list_frame, width=50, height=30, font=("Helvetica", current_font_size))
for chapter in chapter_names:
    chapter_listbox.insert(tk.END, chapter)
chapter_listbox.pack(side=tk.LEFT, fill=tk.Y)

tk.Button(chapter_list_frame, text="Download PDF Guide", command=download_pdf_guide).pack(pady=13)

main_frame = tk.Frame(root)
main_frame.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True)

tk.Label(main_frame, text="Ubuntu CIS Benchmark Audit Tool", font=("Helvetica", current_font_size + 7, "bold")).pack(pady=(14, 4))
tk.Label(main_frame, text="Select a chapter to audit:", font=("Helvetica", current_font_size + 1)).pack(pady=(3, 10))

ctrl_frame = tk.Frame(main_frame)
ctrl_frame.pack()
tk.Button(ctrl_frame, text="Toggle Theme", command=toggle_theme).grid(row=0, column=0, padx=5)
tk.Button(ctrl_frame, text="Increase Font", command=lambda: change_font_size(1)).grid(row=0, column=1, padx=5)
tk.Button(ctrl_frame, text="Decrease Font", command=lambda: change_font_size(-1)).grid(row=0, column=2, padx=5)

button_frame = tk.Frame(main_frame)
button_frame.pack()
BUTTONS_PER_ROW = 4
row = col = 0
for chap, script in CHAPTER_SCRIPTS.items():
    btn = tk.Button(button_frame, text=chap, command=create_run_function(chap, script), width=20, height=2)
    btn.grid(row=row, column=col, padx=10, pady=10)
    col += 1
    if col >= BUTTONS_PER_ROW:
        col = 0
        row += 1

# Close app button
tk.Button(main_frame, text="Close App", command=root.destroy).pack(pady=12)

apply_theme(root)
root.mainloop()
