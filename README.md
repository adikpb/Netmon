# 📡 Network Traffic Analysis Dashboard

This is a simple and interactive Network Traffic Analysis Dashboard built using **Python**, **Scapy**, **Dash**, and **SQLite**. It helps students and beginners capture, log, and visualize network packets in real time.

---

## 📋 Table of Contents

- [About the Project](#about-the-project)
- [Features](#features)
- [Installation](#installation)
- [How to Run](#how-to-run)
- [Screenshots](#screenshots)
- [Project Structure](#project-structure)
- [References](#references)

---

## 📖 About the Project

This tool is mainly created for educational purposes. It captures live packets from your network interface using **Scapy**, stores them in an **SQLite** database, and then displays useful information through a user-friendly **Dash** web interface. You can also filter traffic, flag suspicious IPs, and download packet logs as CSV files.

---

## ✨ Features

- 📡 Real-time packet sniffing
- 🗂️ Packet logging to SQLite database
- 📊 Live dashboard using Dash and Plotly
- 🔎 Filter by protocol (TCP, UDP, ICMP, etc.)
- 🚩 Flag suspicious IPs with risk scoring
- 📈 Graphs for protocol distribution and packet sizes
- 📁 Export logs to CSV

---

## 🛠️ Installation

> Tested on Python 3.12+

Clone the repo and install the required packages:

```bash
git clone https://github.com/yourusername/network-traffic-dashboard.git
cd network-traffic-dashboard
pip install scapy dash pandas sqlalchemy plotly
```

Obtain an api key from https://www.abuseipdb.com/
Create a .env file with the following key=value pair
```
ABUSEIPDB_API_KEY=REPLACEWITHYOURKEY
```

Run with: 
```bash
python src
```

The Dashboard will be present at http://127.0.0.1:8050
