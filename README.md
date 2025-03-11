# NetMon - Network Traffic Analyzer & Threat Detection

## 📌 Overview
NetMon is an advanced **Network Traffic Analysis Dashboard** built using **Dash (Plotly), mitmproxy, and SQLite**. It provides real-time monitoring, data visualizations, and security insights to detect suspicious activities in network traffic.

## 🚀 Features
✅ **Real-time Traffic Monitoring** - Captures live network requests using mitmproxy  
✅ **Interactive Data Visualizations** - Pie charts, bar graphs, and tables for analysis  
✅ **Threat Alerts Panel** - Flags suspicious activities in the traffic  
✅ **Search & Filter Logs** - Easily find specific network requests  
✅ **SQLite Database Logging** - Stores captured traffic for persistence  
✅ **Export Data** - Download traffic logs in CSV format  

## 🛠️ Installation
### 1️⃣ **Clone the Repository**
```sh
git clone https://github.com/yourusername/NetMon.git
cd NetMon
```

### 2️⃣ **Install Dependencies**
```sh
pip install dash pandas plotly mitmproxy
```
⚠️ **Note:** `sqlite3` is built into Python, so no need to install it separately.

### 3️⃣ **Run the Application**
#### **Method 1: Running as a mitmproxy script**
Start mitmproxy and run the script:
```sh
mitmproxy -s src/main.py
```
Then open your browser at **http://127.0.0.1:8050/** to view the dashboard.

#### **Method 2: Running with mitmdump in Python**
Run the script directly:
```sh
python src/main.py
```

## 📊 Dashboard Preview
- **Live Network Table** - Displays real-time HTTP requests
- **Pie Chart** - HTTP Method Distribution (GET, POST, etc.)
- **Bar Chart** - Status Code Distribution (200, 404, etc.)
- **Threat Detection** - Alerts when suspicious activity is detected
- **Download Logs** - Export logs as CSV for analysis

## 🛡️ Security Considerations
- Ensure mitmproxy runs in a **trusted environment** to prevent misuse.
- If analyzing real-world traffic, **obtain necessary permissions**.

## 📜 License
This project is licensed under the MIT License.

## 📞 Contact
For any queries or contributions, feel free to reach out via GitHub Issues!

