# 🚀 NetMon - Network Traffic Analysis Dashboard

This project is a **real-time network traffic analysis dashboard** built using **Dash, Scapy, SQLite, and Plotly**. It captures and visualizes network packets, showing useful insights such as protocol distribution and packet lengths.

---

## 📌 Features
- **Real-time Packet Capturing** using Scapy
- **SQLite Database Logging** for network packets
- **Interactive Dashboard** with:
  - Live **Data Table** of captured packets
  - **Pie Chart** for protocol distribution
  - **Bar Chart** for packet size per protocol
- **CSV Export** for saving captured network logs

---

## 🛠️ Installation

### 1️⃣ **Clone the Repository**
```bash
git clone https://github.com/adikpb/NetMon.git
cd NetMon
```

### 2️⃣ **Install Dependencies**
Make sure you have Python installed (>=3.8). Then run:
```bash
pip install dash scapy pandas plotly sqlite3
```

---

## ▶️ Running the Dashboard
Run the script:
```bash
python main.py
```

After running, open your browser and go to:
```
http://127.0.0.1:8050/
```

---

## 📊 How It Works
1. **Captures Network Traffic** using Scapy
2. **Stores Data** in `network_traffic.db` (SQLite)
3. **Displays Data** in a Dash-based web interface
4. **Updates Every 5 Seconds** with latest traffic logs
5. **Exports Logs as CSV** for analysis

---

## 🛑 Stopping the Script
Press **Ctrl + C** in the terminal.

---

## ⚠️ Troubleshooting
1. **Permission Denied (Linux/macOS)?** Run with `sudo`:
   ```bash
   sudo python main.py
   ```
2. **Port Already in Use?** Change the port in `app.run_server()`:
   ```python
   app.run_server(debug=True, port=8080)
   ```
3. **Missing Dependencies?** Install them using `pip`.

---

## 📜 License
This project is licensed under the **MIT License**.

---

## 🤝 Contributing
Pull requests are welcome! Feel free to improve performance, add features, or enhance UI.

---

## 🌟 Acknowledgments
- **Dash** for interactive web applications
- **Scapy** for network packet analysis
- **Plotly** for data visualization

---

### 📧 Contact
For any queries, reach out via GitHub issues.

