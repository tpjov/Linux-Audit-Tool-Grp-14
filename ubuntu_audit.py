#!/usr/bin/env python3
"""
Ubuntu CIS Benchmark Audit Tool – GUI + Matplotlib Pie Chart
Dark-/Light-mode toggle, adjustable font size, responsive layout
"""

import os
import subprocess
import webbrowser
import tkinter as tk
from tkinter import scrolledtext, filedialog, messagebox
import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
from datetime import datetime
from PIL import Image, ImageTk

# ── CONFIGURATION ────────────────────────────────────────────────

dark_mode = False  # Set to True for dark mode
current_font_size = 10

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

# ── HELPER FUNCTIONS ────────────────────────────────────────

def apply_theme(widget):
    bg_color = "black" if dark_mode else "white"
    fg_color = "white" if dark_mode else "black"
    widget.configure(bg=bg_color)

    for child in widget.winfo_children():
        try:
            if isinstance(child, tk.Label) or isinstance(child, tk.Listbox):
                child.configure(bg=bg_color, fg=fg_color)
            elif isinstance(child, tk.Button):
                text = child.cget("text")
                if "Close" in text:
                    child.configure(bg="dark red", fg="white")
                elif text in CHAPTER_SCRIPTS:
                    child.configure(bg=fg_color, fg=bg_color)
                else:
                    child.configure(bg="#1E90FF", fg="white")
            elif isinstance(child, tk.Frame):
                apply_theme(child)
            elif isinstance(child, scrolledtext.ScrolledText):
                child.configure(bg=bg_color, fg=fg_color, insertbackground=fg_color)
        except:
            continue

def toggle_theme():
    global dark_mode
    dark_mode = not dark_mode
    apply_theme(root)

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

def download_pdf_guide():
    pdf_url = "https://drive.google.com/drive/folders/1wAfgRmcssjifdEPScS9K1Kr2u8_DUnfv?usp=drive_link"
    try:
        subprocess.run(
            ["xdg-open", pdf_url],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=False
        )

        with open("audit_history.log", "a") as log:
            timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            log.write(f"{timestamp} Auditor accessed PDF guide at: {pdf_url}\n")

    except Exception:
        try:
            root.clipboard_clear()
            root.clipboard_append(pdf_url)
            root.update()
            messagebox.showinfo("Manual Download", f"Link copied to clipboard:\n\n{pdf_url}")
        except:
            pass

def open_about_us():
    github_url = "https://github.com/tpjov/Linux-Audit-Tool-Grp-14"
    try:
        subprocess.run(["xdg-open", github_url], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

        with open("audit_history.log", "a") as log:
            timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            log.write(f"{timestamp} Auditor accessed About Us (GitHub) link at: {github_url}\n")

    except Exception:
        try:
            root.clipboard_clear()
            root.clipboard_append(github_url)
            root.update()
        except:
            pass

def show_history_page():
    try:
        with open("audit_history.log", "r") as f:
            contents = f.read()
    except FileNotFoundError:
        contents = "No history yet."

    history_box.delete(1.0, tk.END)
    history_box.insert(tk.END, contents)
    history_container.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

def clear_history():
    with open("audit_history.log", "w") as f:
        f.write("")
    update_history_log()
    messagebox.showinfo("History Cleared", "Audit history log has been cleared.")

def create_run_function(chapter_name: str, script_path: str):
    def run_script():
        popup = tk.Toplevel(root)
        popup.title(f"{chapter_name} Audit Results")
        popup.geometry("820x720")

        tk.Label(popup, text=f"{chapter_name} Audit Results", font=("Helvetica", current_font_size + 3, "bold")).pack(pady=10)
        out_box = scrolledtext.ScrolledText(popup, width=95, height=35, font=("Courier New", current_font_size))
        out_box.pack(padx=15, pady=10)

        if not os.path.isfile(script_path):
            out_box.insert(tk.END, f"Error: script not found → {script_path}\n")
            return

        result = subprocess.run(["bash", script_path], capture_output=True, text=True)
        output = result.stdout
        out_box.insert(tk.END, output)
        out_box.configure(state="normal")

        if result.stderr:
            out_box.insert(tk.END, "\n[ERROR OUTPUT]\n" + result.stderr)

        passed, failed_scored, failed_not_scored = parse_summary(output)

        # Log to history file
        with open("audit_history.log", "a") as log:
            log.write(f"{datetime.now():%Y-%m-%d %H:%M:%S} - {chapter_name} audit ran.\n")

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
            wedges, _, _ = ax.pie(values, labels=None, autopct=autopct_fmt(values), startangle=140, colors=colors, textprops={"color": "white", "fontsize": 9})
            ax.axis("equal")
            ax.legend(wedges, labels, title="Audit Result", loc="center left", bbox_to_anchor=(1.05, 0.5))
            fig.tight_layout()

            frame = tk.Frame(chart_win)
            frame.pack(pady=20)
            canvas = FigureCanvasTkAgg(fig, master=frame)
            canvas.draw()
            canvas.get_tk_widget().pack()

            btn_row = tk.Frame(chart_win)
            btn_row.pack(pady=10)
            tk.Button(btn_row, text="Close", command=chart_win.destroy, font=("Bodoni")).pack(side=tk.LEFT, padx=10)

            apply_theme(chart_win)
        
        def save_output(results):
            file_path = filedialog.asksaveasfilename(defaultextension=".txt", filetypes=[("Text Files", "*.txt"), ("All Files", "*.*")])
            if file_path:
                with open(file_path, "w") as f:
                    f.write(results)

                with open("audit_history.log", "a") as log:
                    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                    log.write(f"{timestamp} Audit results saved to: {file_path}\n")
 
                    messagebox.showinfo("Saved", f"Audit results saved to:\n{file_path}")


        btn_frame = tk.Frame(popup)
        btn_frame.pack(pady=10)

        tk.Button(btn_frame, text="Show Pie Chart", command=show_chart, font=("Bodoni")).grid(row=0, column=0, padx=5)
        tk.Button(btn_frame, text="Download Output", command=lambda: save_output(output), font=("Bodoni")).grid(row=0, column=1, padx=5)
        tk.Button(btn_frame, text="Close", command=popup.destroy, font=("Bodoni")).grid(row=0, column=2, padx=5)

        apply_theme(popup)

    return run_script

# ── MAIN WINDOW ────────────────────────────────────────

root = tk.Tk()
root.title("Ubuntu CIS Benchmark Audit Tool")
root.geometry("1100x720")
root.configure(bg="black" if dark_mode else "white")

# Side list panel
chapter_list_frame = tk.Frame(root, width=240)
chapter_list_frame.pack(side=tk.LEFT, fill=tk.Y, padx=(10, 0), pady=10)
tk.Label(chapter_list_frame, text="Chapter List", font=("Bodoni", current_font_size + 1, "bold")).pack(anchor="w", pady=(0, 5))
chapter_listbox = tk.Listbox(chapter_list_frame, width=50, height=30, font=("Bodoni", current_font_size + 4))
for chapter in chapter_names:
    indent = "   " if "." in chapter.split()[0] else ""
    chapter_listbox.insert(tk.END, indent + chapter)
chapter_listbox.pack(side=tk.LEFT, fill=tk.Y)

# Main panel
main_frame = tk.Frame(root)
main_frame.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True)
header_frame = tk.Frame(main_frame)
header_frame.pack(pady=(14, 4))
logo_path = "ubuntu_audit_logo.png"
try:
    logo_img = Image.open(logo_path)
    logo_img = logo_img.resize((60, 60), Image.Resampling.LANCZOS)
    logo_photo = ImageTk.PhotoImage(logo_img)
    logo_label = tk.Label(header_frame, image=logo_photo)
    logo_label.image = logo_photo
    logo_label.pack(side=tk.LEFT, padx=10)
except Exception as e:
    print("Failed to load logo:", e)

tk.Label(header_frame, text="Ubuntu CIS Benchmark Audit Tool", font=("Bodoni", current_font_size + 7, "bold")).pack(side=tk.LEFT)
tk.Label(main_frame, text="Select a chapter to audit:", font=("Bodoni", current_font_size + 2)).pack(pady=(3, 10))

ctrl_frame = tk.Frame(main_frame)
ctrl_frame.pack()
tk.Button(ctrl_frame, text="Toggle Theme", command=toggle_theme, font=("Bodoni")).grid(row=0, column=0, padx=5)
tk.Button(ctrl_frame, text="Download PDF Guide", command=download_pdf_guide, font=("Bodoni")).grid(row=0, column=1, padx=5)
tk.Button(ctrl_frame, text="About Us", command=open_about_us, font=("Bodoni")).grid(row=0, column=2, padx=5)

button_frame = tk.Frame(main_frame)
button_frame.pack()
BUTTONS_PER_ROW = 4
row = col = 0
for chap, script in CHAPTER_SCRIPTS.items():
    btn = tk.Button(button_frame, text=chap, command=create_run_function(chap, script), width=19, height=2, font=("Bodoni"))
    btn.configure(bg="white" if dark_mode else "black", fg="black" if dark_mode else "white")
    btn.grid(row=row, column=col, padx=10, pady=10)
    col += 1
    if col >= BUTTONS_PER_ROW:
        col = 0
        row += 1

# Real-time History Container
history_container = tk.LabelFrame(main_frame, text="Audit History Log", font=("Bodoni", current_font_size, "bold"))
history_container.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

history_box = scrolledtext.ScrolledText(history_container, wrap=tk.WORD, font=("Bodoni", current_font_size), height=10)
history_box.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

tk.Button(history_container, text="Clear History", command=clear_history, bg="dark red", fg="white", font=("Bodoni", current_font_size + 1)).pack(pady=5)

def update_history_log():
    try:
        with open("audit_history.log", "r") as f:
            contents = f.read()
    except FileNotFoundError:
        contents = "No history yet."

    history_box.delete(1.0, tk.END)
    history_box.insert(tk.END, contents)
    history_box.see(tk.END)  # auto-scroll to bottom
    history_box.after(1000, update_history_log)  # refresh every second

update_history_log()  # start the loop

tk.Button(main_frame, text="Close App", command=root.destroy, width=19, height=2, font=("Bodoni")).pack(side="bottom", pady=12)

apply_theme(root)
root.mainloop()
