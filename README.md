# Linux-Audit-Tool-Grp-14

This is a user-friendly Python-based GUI tool for running Ubuntu CIS Benchmark audit scripts with real-time results, pie chart visualization, and downloadable output.

It strictly follows the CIS Ubuntu 12.04 LTS Server Benchmark (v1.1.0  -   01 - 07 - 2015)

---

## Features

- ✅ Automated; the script runs everything for you, all you have to do is click the button
- 📊 Pie chart summary of results using Matplotlib
- 🌓 Light/Dark Mode toggle
- 🔠 Adjustable font size
- 📥 Save audit output to file
- 🔗 PDF Guide download link
  
---

## Downloads

---

You can download the official CIS Benchmark used by this audit tool:

[📄 Download CIS Benchmark](./CIS_Ubuntu_12.04_LTS_Server_Benchmark_v1.1.0_ARCHIVE.pdf)

## Requirements

- Ensure the following packages are installed on your **Ubuntu system**:

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

To run: 



```bash
python3 ubuntu_audit_gui.py
```


