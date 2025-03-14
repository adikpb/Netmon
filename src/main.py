
import sqlite3
import threading
import time

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
        self.start_time = time.time()  # Capture start time
        self.capture_count = 0

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

        if self.cursor:
            self.cursor.execute("INSERT INTO traffic (protocol, src_ip, dst_ip, src_port, dst_port, packet_length, timestamp) VALUES (?, ?, ?, ?, ?, ?, datetime('now'))",
                               (protocol, src_ip, dst_ip, src_port, dst_port, packet_length))
        if self.conn:
            self.conn.commit()

    def start_sniffer(self):
        # Create SQLite connection and cursor in the same thread
        self.conn = sqlite3.connect("network_traffic.db")
        self.cursor = self.conn.cursor()
        self.cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS traffic (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                protocol TEXT, src_ip TEXT, dst_ip TEXT, src_port INTEGER, dst_port INTEGER,
                packet_length INTEGER, timestamp TEXT
            )
        """
        )
        self.conn.commit()

        sniff(prn=self.packet_sniffer, store=False)

    def get_capture_duration(self):
        return time.time() - self.start_time

    def get_capture_count(self):
        return self.capture_count

# Fetch data from database
def fetch_data():
    conn = sqlite3.connect("network_traffic.db")
    df = pd.read_sql("SELECT * FROM traffic ORDER BY timestamp DESC LIMIT 100", conn)
    conn.close()
    return df

# Layout for Dash App
# Layout for Dash App
app.layout = html.Div(
    style={
        "background": "linear-gradient(to right, #e0f2f7, #b2ebf2)",
        "fontFamily": "Segoe UI, Tahoma, Geneva, Verdana, sans-serif",
    },
    children=[
        html.H1(
            "Network Traffic Analysis Dashboard",
            style={"textAlign": "center", "color": "#333"},
        ),
        html.Div(
            [
                html.Div(id="capture-duration", style={"display": "inline-block", "margin": "10px"}),
                html.Div(id="capture-count", style={"display": "inline-block", "margin": "10px"}),
            ],
            style={"textAlign": "center"},
        ),
        dcc.Interval(id="interval-component", interval=5000, n_intervals=0),
        dcc.Dropdown(
            id="protocol-dropdown-filter",  # ID for the dropdown
            options=[
                {"label": "All", "value": "All"},
                {"label": "TCP", "value": "TCP"},
                {"label": "UDP", "value": "UDP"},
                {"label": "ICMP", "value": "ICMP"},
                {"label": "IGMP", "value": "IGMP"},
                {"label": "Unknown", "value": "Unknown"},
            ],
            value="All",
            style={"width": "200px", "margin": "10px"},
        ),
        dash_table.DataTable(
            id="traffic-table",
            columns=[
                {"name": "Timestamp", "id": "timestamp"},
                {"name": "Protocol", "id": "protocol"}, #remove filter_options
                {"name": "Source IP", "id": "src_ip"},
                {"name": "Destination IP", "id": "dst_ip"},
                {"name": "Source Port", "id": "src_port"},
                {"name": "Destination Port", "id": "dst_port"},
                {"name": "Packet Length", "id": "packet_length"},
            ],
            style_table={
                "overflowX": "auto",
                "borderRadius": "8px",
                "boxShadow": "0 2px 5px rgba(0, 0, 0, 0.1)",
                "border": "none",
            },
            style_header={
                "backgroundColor": "#f8f9fa",
                "fontWeight": "600",
                "borderBottom": "1px solid #dee2e6",
            },
            style_cell={
                "textAlign": "left",
                "padding": "10px 15px",
                "border": "none",
            },
            style_data_conditional=[
                {
                    "if": {"row_index": "odd"},
                    "backgroundColor": "#f2f2f2",
                },
                {
                    "if": {"filter_query": "{protocol} = 'TCP'"},
                    "backgroundColor": "#e0f7fa",
                },
                {
                    "if": {"filter_query": "{protocol} = 'UDP'"},
                    "backgroundColor": "#e8f5e9",
                },
                {
                    "if": {"filter_query": "{protocol} = 'ICMP'"},
                    "backgroundColor": "#fff3e0",
                },
                {
                    "if": {"filter_query": "{protocol} = 'IGMP'"},
                    "backgroundColor": "#f3e5f5",
                },
                {
                    "if": {"filter_query": "{protocol} = 'Unknown'"},
                    "backgroundColor": "#f5f5f5",
                },
            ],
        ),
        html.Div(
            [
                dcc.Graph(id="traffic-pie-chart", style={"width": "48%", "display": "inline-block"}),
                dcc.Graph(id="traffic-bar-chart", style={"width": "48%", "display": "inline-block"}),
            ]
        ),
        html.Div(
            [
                html.Button(
                    "Export CSV",
                    id="export-button",
                    style={
                        "margin": "20px auto",
                        "display": "block",
                        "borderRadius": "5px",
                        "padding": "12px 25px",
                        "backgroundColor": "#007bff",
                        "color": "white",
                        "border": "none",
                        "boxShadow": "0 2px 4px rgba(0, 0, 0, 0.2)",
                    },
                ),
                dcc.Download(id="download-dataframe-csv"),
            ],
            style={"textAlign": "center"},
        ),
    ],
)

@app.callback(
    [
        Output("traffic-table", "data"),
        Output("traffic-pie-chart", "figure"),
        Output("traffic-bar-chart", "figure"),
        Output("capture-duration", "children"),
        Output("capture-count", "children"),
    ],
    [Input("interval-component", "n_intervals"), Input("protocol-dropdown-filter", "value")],
)
def update_dashboard(n, protocol_filter):
    df = fetch_data()  # Corrected line: Fetch data from the database
    if protocol_filter != "All":
        df = df[df["protocol"] == protocol_filter]

    table_data = df.to_dict("records")

    pie_chart = px.pie(df, names="protocol", title="Protocol Distribution")
    bar_chart = px.bar(
        df, x="protocol", y="packet_length", title="Packet Length by Protocol"
    )

    pie_chart.update_layout(
        plot_bgcolor="rgba(0,0,0,0)", paper_bgcolor="rgba(0,0,0,0)"
    )
    bar_chart.update_layout(
        plot_bgcolor="rgba(0,0,0,0)", paper_bgcolor="rgba(0,0,0,0)"
    )

    capture_duration = traffic_logger.get_capture_duration()
    capture_count = traffic_logger.get_capture_count()

    return (
        table_data,
        pie_chart,
        bar_chart,
        f"Capture Duration: {capture_duration:.2f} seconds",
        f"Total Captures: {capture_count}",
    )

if __name__ == '__main__':
    traffic_logger = TrafficLogger()
    threading.Thread(target=traffic_logger.start_sniffer).start()
    app.run_server(debug=True, use_reloader=False)
