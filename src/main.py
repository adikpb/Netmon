import sqlite3
import threading

import dash
import pandas as pd
import plotly.express as px
from dash import Input, Output, dash_table, dcc, html
from scapy.all import sniff
from scapy.contrib.igmp import IGMP
from scapy.layers.inet import ICMP, IP, TCP, UDP

# Initialize Dash app
app = dash.Dash(__name__)

# Scapy Packet Sniffer
class TrafficLogger:
    def __init__(self):
        self.conn = None
        self.cursor = None

    def packet_sniffer(self, packet):
        if packet.haslayer(IP):
            protocol = "IP"
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
            if packet.haslayer(TCP):
                protocol = "TCP"
                src_port = packet[TCP].sport
                dst_port = packet[TCP].dport
            elif packet.haslayer(UDP):
                protocol = "UDP"
                src_port = packet[UDP].sport
                dst_port = packet[UDP].dport
            elif packet.haslayer(ICMP):
                protocol = "ICMP"
                src_port = None
                dst_port = None
            elif packet.haslayer(IGMP):
                protocol = "IGMP"
                src_port = None
                dst_port = None
            else:
                src_port = None
                dst_port = None
        else:
            protocol = "Unknown"
            src_ip = None
            dst_ip = None
            src_port = None
            dst_port = None

        packet_length = len(packet)

        self.cursor.execute("INSERT INTO traffic (protocol, src_ip, dst_ip, src_port, dst_port, packet_length, timestamp) VALUES (?, ?, ?, ?, ?, ?, datetime('now'))",
                           (protocol, src_ip, dst_ip, src_port, dst_port, packet_length))
        self.conn.commit()

    def start_sniffer(self):
        # Create SQLite connection and cursor in the same thread
        self.conn = sqlite3.connect("network_traffic.db")
        self.cursor = self.conn.cursor()
        self.cursor.execute("""
            CREATE TABLE IF NOT EXISTS traffic (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                protocol TEXT, src_ip TEXT, dst_ip TEXT, src_port INTEGER, dst_port INTEGER,
                packet_length INTEGER, timestamp TEXT
            )
        """)
        self.conn.commit()

        sniff(prn=self.packet_sniffer, store=False)

# Fetch data from database
def fetch_data():
    conn = sqlite3.connect("network_traffic.db")
    df = pd.read_sql("SELECT * FROM traffic ORDER BY timestamp DESC LIMIT 100", conn)
    conn.close()
    return df

# Layout for Dash App
app.layout = html.Div([
    html.H1("Network Traffic Analysis Dashboard"),
    dcc.Interval(id='interval-component', interval=5000, n_intervals=0),
    
    dash_table.DataTable(
        id='traffic-table',
        columns=[
            {"name": "Timestamp", "id": "timestamp"},
            {"name": "Protocol", "id": "protocol"},
            {"name": "Source IP", "id": "src_ip"},
            {"name": "Destination IP", "id": "dst_ip"},
            {"name": "Source Port", "id": "src_port"},
            {"name": "Destination Port", "id": "dst_port"},
            {"name": "Packet Length", "id": "packet_length"},
        ],
        style_table={'overflowX': 'auto'},
    ),
    
    dcc.Graph(id='traffic-pie-chart'),
    dcc.Graph(id='traffic-bar-chart'),
    
    html.Button("Export CSV", id='export-button'),
    dcc.Download(id="download-dataframe-csv")
])

# Callbacks to Update Dashboard
@app.callback(
    [Output('traffic-table', 'data'),
     Output('traffic-pie-chart', 'figure'),
     Output('traffic-bar-chart', 'figure')],
    [Input('interval-component', 'n_intervals')]
)
def update_dashboard(n):
    df = fetch_data()
    table_data = df.to_dict('records')
    
    pie_chart = px.pie(df, names='protocol', title='Protocol Distribution')
    bar_chart = px.bar(df, x='protocol', y='packet_length', title='Packet Length by Protocol')
    
    return table_data, pie_chart, bar_chart

# Export Data as CSV
@app.callback(
    Output("download-dataframe-csv", "data"),
    Input("export-button", "n_clicks"),
    prevent_initial_call=True,
)
def export_data(n3_clicks):
    df = fetch_data()
    return dcc.send_data_frame(df.to_csv, "network_logs.csv")

if __name__ == '__main__':
    traffic_logger = TrafficLogger()
    threading.Thread(target=traffic_logger.start_sniffer).start()
    app.run_server(debug=True, use_reloader=False)

