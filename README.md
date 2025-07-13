# Linux-Audit-Tool-Grp-14

This is a user-friendly Python-based GUI tool for running Ubuntu CIS Benchmark audit scripts with real-time results, pie chart visualization, and downloadable output.

It strictly follows the CIS Ubuntu 12.04 LTS Server Benchmark (v1.1.0  -   01 - 07 - 2015)

---

## Features

- ✅ All chapters (Ch1-13) are covered
- 📊 Pie chart summary of results using Matplotlib
- 🌓 Light/Dark Mode toggle
- 🔠 Adjustable font size
- 📥 Save audit output to file
- 🔗 PDF Guide download link
  
---

## Downloads

You can download the entire tool (scripts + GUI + CIS Benchmark) using this ZIP link:

🔗 **[Download Audit Tool ZIP](https://github.com/tpjov/Linux-Audit-Tool-Grp-14/archive/refs/heads/main.zip)**

---

## Requirements

- Ensure the following packages are installed on your **Ubuntu system**:

- Python 3 (`python3`)
- `tkinter`  
- `matplotlib`

Install the following using: 
```bash
sudo apt update
sudo apt install -y python3 python3-pip python3-tk git
pip3 install matplotlib
```

---

## How to run

*Ensure all chapterX.sh scripts are placed in the same folder as the Python script.*

Make them executable in the case that they aren't.

```bash
chmod +x chapter*.sh allchapters.sh
```
The '*' stands for the chapter number, so e.g. 
```bash
chmod +x chapter1.sh allchapters.sh
```
To run: 

```bash
python3 ubuntu_audit.py
```
---

## CIS Benchmark PDF

You can view or download the official CIS Benchmark PDF here:

[Download CIS Benchmark (Ubuntu 12.04 LTS v1.1.0)](./CIS_Ubuntu_12.04_LTS_Server_Benchmark_v1.1.0_ARCHIVE.pdf)

## Authors

Group 14 - Temasek Polytechnic
Year 3 students of Cybersecurity & Digital Forensics

## Disclaimer

This tool is intended for educational use only.
