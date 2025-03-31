import logging
import signal
import sqlite3
import sys

import dash
import pandas as pd
import plotly.express as px
from dash import Input, Output, dash_table, dcc, html

from capture import TrafficLogger
from utils import lighten_hex_color_for_light_mode, string_to_hex_color

app = dash.Dash(__name__)
traffic_logger = TrafficLogger()
logging.basicConfig(
    level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s"
)


def signal_handler(sig, frame):
    logging.info("Gracefully shutting down...")
    traffic_logger.stop_sniffer()
    sys.exit(0)


signal.signal(signal.SIGINT, signal_handler)


def fetch_data(protocol_filter=None):
    try:
        conn = sqlite3.connect("network_traffic.db")
        if protocol_filter != "All":
            df = pd.read_sql(
                f"SELECT * FROM traffic WHERE protocol = '{protocol_filter}' ORDER BY timestamp DESC LIMIT 100",
                conn,
            )
        else:
            df = pd.read_sql(
                "SELECT * FROM traffic ORDER BY timestamp DESC LIMIT 100", conn
            )
        conn.close()
        return df
    except Exception as e:
        logging.error(f"Error: {e}")
        return pd.DataFrame()


def get_protocol_types():
    try:
        conn = sqlite3.connect("network_traffic.db")
        cursor = conn.cursor()
        cursor.execute(
            """CREATE TABLE IF NOT EXISTS traffic (id INTEGER PRIMARY KEY AUTOINCREMENT, protocol TEXT, src_ip TEXT, dst_ip TEXT, src_port INTEGER, dst_port INTEGER, packet_length INTEGER, timestamp TEXT)"""
        )
        cursor.execute("SELECT DISTINCT protocol FROM traffic")
        protocol_types = [row[0] for row in cursor.fetchall()]
        conn.close()
        return protocol_types
    except Exception as e:
        logging.error(f"Error: {e}")
        return []


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
                html.Div(
                    id="capture-duration",
                    style={"display": "inline-block", "margin": "10px"},
                ),
                html.Div(
                    id="capture-count",
                    style={"display": "inline-block", "margin": "10px"},
                ),
            ],
            style={"textAlign": "center"},
        ),
        dcc.Interval(id="interval-component", interval=5000, n_intervals=0),
        dcc.Dropdown(
            id="protocol-dropdown-filter",
            options=[
                {"label": "All", "value": "All"},
                {"label": "Unknown", "value": "Unknown"},
            ]
            + [
                {"label": protocol, "value": protocol}
                for protocol in get_protocol_types()
            ],
            value="All",
            style={"width": "200px", "margin": "10px"},
        ),
        dash_table.DataTable(
            id="traffic-table",
            columns=[
                {"name": "Timestamp", "id": "timestamp"},
                {"name": "Protocol", "id": "protocol"},
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
            style_cell={"textAlign": "left", "padding": "10px 15px", "border": "none"},
            style_data_conditional=[
                {"if": {"row_index": "odd"}, "backgroundColor": "#f2f2f2"}
            ]
            + [
                {
                    "if": {"filter_query": "{protocol} = " + f"'{protocol}'"},
                    "backgroundColor": lighten_hex_color_for_light_mode(
                        string_to_hex_color(protocol), 0.3
                    ),
                }
                for protocol in get_protocol_types()
            ],
        ),
        html.Div(
            [
                dcc.Graph(
                    id="traffic-pie-chart",
                    style={"width": "48%", "display": "inline-block"},
                ),
                dcc.Graph(
                    id="traffic-bar-chart",
                    style={"width": "48%", "display": "inline-block"},
                ),
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
        Output("traffic-table", "style_data_conditional"),
        Output("protocol-dropdown-filter", "options"),
    ],
    [
        Input("traffic-table", "data"),
        Input("protocol-dropdown-filter", "options"),
        Input("traffic-table", "style_data_conditional"),
    ],
)
def update_protocols(data, protocols, style):
    try:
        conn = sqlite3.connect("network_traffic.db")
        cursor = conn.cursor()
        cursor.execute(
            """CREATE TABLE IF NOT EXISTS traffic (id INTEGER PRIMARY KEY AUTOINCREMENT, protocol TEXT, src_ip TEXT, dst_ip TEXT, src_port INTEGER, dst_port INTEGER, packet_length INTEGER, timestamp TEXT)"""
        )
        cursor.execute("SELECT DISTINCT protocol FROM traffic")
        protocol_types = set([row[0] for row in cursor.fetchall()])
        conn.close()
        currently_distinct_protocols = set(i["label"] for i in protocols)
        return style + [
            {
                "if": {"filter_query": "{protocol} = " + f"'{protocol}'"},
                "backgroundColor": lighten_hex_color_for_light_mode(
                    string_to_hex_color(protocol), 0.3
                ),
            }
            for protocol in protocol_types - currently_distinct_protocols
        ], protocols + [
            {"label": protocol, "value": protocol}
            for protocol in protocol_types - currently_distinct_protocols
        ]
    except Exception as e:
        logging.error(f"Error: {e}")
        return [], []


@app.callback(
    [
        Output("traffic-table", "data"),
        Output("traffic-pie-chart", "figure"),
        Output("traffic-bar-chart", "figure"),
        Output("capture-duration", "children"),
        Output("capture-count", "children"),
    ],
    [
        Input("interval-component", "n_intervals"),
        Input("protocol-dropdown-filter", "value"),
    ],
)
def update_dashboard(n, protocol_filter):
    try:
        df = fetch_data(protocol_filter)
        table_data = df.to_dict("records") if df is not None else None
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
    except Exception as e:
        logging.error(f"Error: {e}")
        return None, {}, {}, "", ""


@app.callback(
    Output("download-dataframe-csv", "data"),
    Input("export-button", "n_clicks"),
    prevent_initial_call=True,
)
def export_csv(n_clicks):
    try:
        df = fetch_data()
        return dcc.send_data_frame(
            df.to_csv if df is not None else None, "traffic_data.csv"
        )
    except Exception as e:
        logging.error(f"Error: {e}")
        return None


if __name__ == "__main__":
    traffic_logger.start_sniffer()
    app.run(debug=True, use_reloader=True)
