import logging
import signal
import sys
from datetime import datetime, timedelta

import dash
import plotly.express as px
from dash import Input, Output, dash_table, dcc, html
from dash.exceptions import PreventUpdate

from capture import TrafficLogger
from database import DatabaseManager
from utils import lighten_hex_color_for_light_mode, string_to_hex_color

# Initialize application
app = dash.Dash(__name__)
app.title = "Network Traffic Analysis Dashboard"

# Initialize components
traffic_logger = TrafficLogger()
db_manager = DatabaseManager()

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    handlers=[logging.FileHandler("network_monitor.log"), logging.StreamHandler()],
)
logger = logging.getLogger(__name__)


def signal_handler(sig, frame):
    """Handle graceful shutdown."""
    logger.info("Gracefully shutting down...")
    traffic_logger.stop_sniffer()
    sys.exit(0)


signal.signal(signal.SIGINT, signal_handler)

# Define the layout
app.layout = html.Div(
    style={
        "background": "linear-gradient(to right, #e0f2f7, #b2ebf2)",
        "fontFamily": "Segoe UI, Tahoma, Geneva, Verdana, sans-serif",
        "minHeight": "100vh",
        "padding": "20px",
    },
    children=[
        # Header
        html.Div(
            [
                html.H1(
                    "Network Traffic Analysis Dashboard",
                    style={
                        "textAlign": "center",
                        "color": "#333",
                        "marginBottom": "20px",
                    },
                ),
                html.Div(
                    id="status-indicator",
                    style={
                        "textAlign": "center",
                        "marginBottom": "20px",
                        "padding": "10px",
                        "borderRadius": "5px",
                        "backgroundColor": "#e8f5e9",
                    },
                ),
            ]
        ),
        # Controls
        html.Div(
            [
                html.Div(
                    [
                        html.Label("Protocol Filter:"),
                        dcc.Dropdown(
                            id="protocol-dropdown-filter",
                            options=[{"label": "All", "value": "All"}]
                            + [
                                {"label": protocol, "value": protocol}
                                for protocol in db_manager.get_protocol_types()
                            ],
                            value="All",
                            style={"width": "200px"},
                        ),
                    ],
                    style={"display": "inline-block", "marginRight": "20px"},
                ),
                html.Div(
                    [
                        html.Label("Time Range:"),
                        dcc.DatePickerRange(
                            id="time-range",
                            start_date=datetime.now() - timedelta(hours=1),
                            end_date=datetime.now(),
                            style={"width": "300px"},
                        ),
                    ],
                    style={"display": "inline-block", "marginRight": "20px"},
                ),
                html.Div(
                    [
                        html.Label("Refresh Rate:"),
                        dcc.Dropdown(
                            id="refresh-rate",
                            options=[
                                {"label": "1 second", "value": 1000},
                                {"label": "5 seconds", "value": 5000},
                                {"label": "10 seconds", "value": 10000},
                            ],
                            value=5000,
                            style={"width": "150px"},
                        ),
                    ],
                    style={"display": "inline-block"},
                ),
            ],
            style={"marginBottom": "20px"},
        ),
        # Statistics Cards
        html.Div(
            [
                html.Div(id="total-packets", className="stat-card"),
                html.Div(id="total-bytes", className="stat-card"),
                html.Div(id="unique-ips", className="stat-card"),
                html.Div(id="packets-per-second", className="stat-card"),
            ],
            style={
                "display": "flex",
                "justifyContent": "space-between",
                "marginBottom": "20px",
            },
        ),
        # Main Content
        html.Div(
            [
                # Traffic Table
                html.Div(
                    [
                        html.H3("Recent Traffic", style={"marginBottom": "10px"}),
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
                                {"name": "TTL", "id": "ttl"},
                            ],
                            style_table={
                                "overflowX": "auto",
                                "borderRadius": "8px",
                                "boxShadow": "0 2px 5px rgba(0, 0, 0, 0.1)",
                                "border": "none",
                                "backgroundColor": "white",
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
                                }
                            ]
                            + [
                                {
                                    "if": {
                                        "filter_query": "{protocol} = "
                                        + f"'{protocol}'"
                                    },
                                    "backgroundColor": lighten_hex_color_for_light_mode(
                                        string_to_hex_color(protocol), 0.3
                                    ),
                                }
                                for protocol in db_manager.get_protocol_types()
                            ],
                        ),
                    ],
                    style={"width": "100%", "marginBottom": "20px"},
                ),
                # Charts
                html.Div(
                    [
                        html.Div(
                            [
                                html.H3(
                                    "Protocol Distribution",
                                    style={"marginBottom": "10px"},
                                ),
                                dcc.Graph(id="traffic-pie-chart"),
                            ],
                            style={"width": "48%", "display": "inline-block"},
                        ),
                        html.Div(
                            [
                                html.H3(
                                    "Packet Length by Protocol",
                                    style={"marginBottom": "10px"},
                                ),
                                dcc.Graph(id="traffic-bar-chart"),
                            ],
                            style={"width": "48%", "display": "inline-block"},
                        ),
                    ]
                ),
            ]
        ),
        # Export Controls
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
        # Update interval
        dcc.Interval(id="interval-component", interval=5000, n_intervals=0),
    ],
)


# Callbacks
@app.callback(
    [Output("interval-component", "interval")],
    [Input("refresh-rate", "value")],
)
def update_interval(refresh_rate):
    return [refresh_rate]


@app.callback(
    [
        Output("traffic-table", "data"),
        Output("traffic-pie-chart", "figure"),
        Output("traffic-bar-chart", "figure"),
        Output("total-packets", "children"),
        Output("total-bytes", "children"),
        Output("unique-ips", "children"),
        Output("packets-per-second", "children"),
        Output("status-indicator", "children"),
    ],
    [
        Input("interval-component", "n_intervals"),
        Input("protocol-dropdown-filter", "value"),
        Input("time-range", "start_date"),
        Input("time-range", "end_date"),
    ],
)
def update_dashboard(n, protocol_filter, start_date, end_date):
    try:
        # Fetch data
        df = db_manager.fetch_traffic(protocol_filter)
        stats = db_manager.get_traffic_statistics()
        capture_stats = traffic_logger.get_capture_stats()

        # Format statistics
        total_packets = f"Total Packets: {stats.get('total_packets', 0):,}"
        total_bytes = f"Total Bytes: {stats.get('total_bytes', 0):,}"
        unique_ips = f"Unique IPs: {stats.get('unique_ips', 0):,}"
        packets_per_second = f"Packets/sec: {capture_stats['packets_per_second']:.2f}"

        # Create visualizations
        pie_chart = px.pie(
            df,
            names="protocol",
            title="Protocol Distribution",
            color_discrete_sequence=px.colors.qualitative.Set3,
        )
        bar_chart = px.bar(
            df,
            x="protocol",
            y="packet_length",
            title="Packet Length by Protocol",
            color="protocol",
            color_discrete_sequence=px.colors.qualitative.Set3,
        )

        # Update chart layouts
        for chart in [pie_chart, bar_chart]:
            chart.update_layout(
                plot_bgcolor="rgba(0,0,0,0)",
                paper_bgcolor="rgba(0,0,0,0)",
                font=dict(size=12),
            )

        # Status indicator
        status = f"Capture Duration: {capture_stats['duration']:.1f}s | "
        status += f"Active Connections: {len(df['src_ip'].unique())}"

        return (
            df.to_dict("records"),
            pie_chart,
            bar_chart,
            total_packets,
            total_bytes,
            unique_ips,
            packets_per_second,
            status,
        )
    except Exception as e:
        logger.error(f"Error updating dashboard: {e}")
        raise PreventUpdate


@app.callback(
    Output("download-dataframe-csv", "data"),
    Input("export-button", "n_clicks"),
    prevent_initial_call=True,
)
def export_csv(n_clicks):
    try:
        df = db_manager.fetch_traffic()
        return dcc.send_data_frame(df.to_csv, "traffic_data.csv")
    except Exception as e:
        logger.error(f"Error exporting CSV: {e}")
        return None


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
        protocol_types = set(db_manager.get_protocol_types())
        currently_distinct_protocols = set(i["label"] for i in protocols)
        return style + [
            {
                "if": {"filter_query": "{protocol} = " + f"'{protocol}'"},
                "backgroundColor": lighten_hex_color_for_light_mode(
                    string_to_hex_color(protocol)
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


if __name__ == "__main__":
    traffic_logger.start_sniffer()
    app.run(debug=True, use_reloader=False)
