import logging
import os
import signal
import sys

import dash
import plotly.express as px
from dash import Input, Output, State, callback_context, dash_table, dcc, html
from dash.exceptions import PreventUpdate
from dotenv import load_dotenv

from capture import TrafficLogger
from database import DatabaseManager
from utils import lighten_hex_color_for_light_mode, string_to_hex_color

# Configure logging first, before any other operations
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    handlers=[
        logging.FileHandler("network_monitor.log"),
        logging.StreamHandler(),
    ],
)
logger = logging.getLogger(__name__)

# Load environment variables
logger.info("Loading environment variables")
load_dotenv()
ABUSEIPDB_API_KEY = os.getenv("ABUSEIPDB_API_KEY")
if not ABUSEIPDB_API_KEY:
    logger.warning("AbuseIPDB API key not found in environment variables")
else:
    logger.info("AbuseIPDB API key loaded successfully")

# Initialize application
logger.info("Initializing Dash application")
app = dash.Dash(
    __name__,
    assets_folder="assets",  # Explicitly set assets folder
    serve_locally=True,  # Ensure assets are served locally
)
app.title = "Network Traffic Analysis Dashboard"

# Initialize components
logger.info("Initializing TrafficLogger and DatabaseManager")
traffic_logger = TrafficLogger()
db_manager = DatabaseManager(abuseipdb_key=ABUSEIPDB_API_KEY)


def signal_handler(sig, frame):
    """Handle graceful shutdown."""
    logger.info("Received shutdown signal - initiating graceful shutdown")
    traffic_logger.stop_sniffer()
    logger.info("Traffic logger stopped")
    sys.exit(0)


signal.signal(signal.SIGINT, signal_handler)

# Define the layout
app.layout = html.Div(
    className="dashboard-container",
    children=[
        # Header
        html.Div(
            className="dashboard-header",
            children=[
                html.H1(
                    "Network Traffic Analysis Dashboard",
                ),
                html.Div(
                    id="status-indicator",
                    className="status-indicator",
                ),
            ],
        ),
        # Controls
        html.Div(
            className="controls-container",
            children=[
                html.Div(
                    className="control-group",
                    children=[
                        html.Label("Protocol Filter:"),
                        dcc.Dropdown(
                            id="protocol-dropdown-filter",
                            options=[{"label": "All", "value": "All"}]
                            + [
                                {"label": protocol, "value": protocol}
                                for protocol in db_manager.get_protocol_types()
                            ],
                            value="All",
                            className="dropdown-container",
                        ),
                    ],
                ),
                html.Div(
                    className="control-group right-aligned",
                    children=[
                        html.Label("Refresh Rate:"),
                        dcc.Dropdown(
                            id="refresh-rate",
                            options=[
                                {"label": "1 second", "value": 1000},
                                {"label": "5 seconds", "value": 5000},
                                {"label": "10 seconds", "value": 10000},
                            ],
                            value=5000,
                            className="refresh-dropdown",
                        ),
                    ],
                ),
            ],
        ),
        # Statistics Cards
        html.Div(
            className="stat-cards-container",
            children=[
                html.Div(id="total-packets", className="stat-card"),
                html.Div(id="total-bytes", className="stat-card"),
                html.Div(id="unique-ips", className="stat-card"),
                html.Div(id="packets-per-second", className="stat-card"),
            ],
        ),
        # Main Content
        html.Div(
            children=[
                # Traffic Table
                html.Div(
                    className="table-container",
                    children=[
                        html.H3("Recent Traffic", className="table-title"),
                        dash_table.DataTable(
                            id="traffic-table",
                            columns=[
                                {"name": "Timestamp", "id": "timestamp"},
                                {"name": "Protocol", "id": "protocol"},
                                {
                                    "name": "Source IP",
                                    "id": "src_ip",
                                    "presentation": "dropdown",
                                },
                                {
                                    "name": "Destination IP",
                                    "id": "dst_ip",
                                    "presentation": "dropdown",
                                },
                                {"name": "Source Port", "id": "src_port"},
                                {"name": "Destination Port", "id": "dst_port"},
                                {"name": "Packet Length", "id": "packet_length"},
                                {"name": "TTL", "id": "ttl"},
                            ],
                            data=[],
                            row_selectable=None,
                            cell_selectable=True,
                            dropdown={
                                "src_ip": {
                                    "options": [
                                        {"label": "Flag Source IP", "value": "flag_src"}
                                    ]
                                },
                                "dst_ip": {
                                    "options": [
                                        {
                                            "label": "Flag Destination IP",
                                            "value": "flag_dst",
                                        }
                                    ]
                                },
                            },
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
                                "padding": "10px 15px",
                            },
                            style_cell={
                                "textAlign": "left",
                                "padding": "10px 15px",
                                "border": "none",
                            },
                            style_data={
                                "backgroundColor": "white",
                            },
                            style_data_conditional=[
                                {
                                    "if": {"row_index": "odd"},
                                    "backgroundColor": "#f2f2f2",
                                }
                            ],
                        ),
                        html.Button(
                            "Unflag IP",
                            id="unflag-ip-button",
                            className="action-button unflag-button",
                        ),
                    ],
                ),
                # Flagged IPs Table
                html.Div(
                    className="table-container",
                    children=[
                        html.H3("Flagged IPs", className="table-title"),
                        dash_table.DataTable(
                            id="flagged-ips-table",
                            columns=[
                                {"name": "IP Address", "id": "ip"},
                                {"name": "Timestamp", "id": "timestamp"},
                                {
                                    "name": "Abuse Score",
                                    "id": "confidence_score",
                                    "type": "numeric",
                                },
                                {"name": "Action", "id": "action"},
                            ],
                            tooltip_data=[],
                            tooltip_duration=None,
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
                                "padding": "10px 15px",
                            },
                            style_cell={
                                "textAlign": "left",
                                "padding": "10px 15px",
                                "border": "none",
                            },
                            style_data_conditional=[
                                {
                                    "if": {"column_id": "action"},
                                    "cursor": "pointer",
                                    "color": "white",
                                    "backgroundColor": "#dc3545",
                                    "fontWeight": "bold",
                                    "textAlign": "center",
                                    "borderRadius": "4px",
                                    "padding": "5px 10px",
                                },
                                {
                                    "if": {
                                        "column_id": "confidence_score",
                                        "filter_query": "{confidence_score} > 80",
                                    },
                                    "backgroundColor": "#dc3545",
                                    "color": "white",
                                },
                                {
                                    "if": {
                                        "column_id": "confidence_score",
                                        "filter_query": "{confidence_score} > 50",
                                    },
                                    "backgroundColor": "#ffc107",
                                },
                                {
                                    "if": {
                                        "column_id": "confidence_score",
                                        "filter_query": "{confidence_score} <= 50",
                                    },
                                    "backgroundColor": "#28a745",
                                    "color": "white",
                                },
                            ],
                            cell_selectable=True,
                            style_as_list_view=True,
                        ),
                    ],
                ),
                # Charts
                html.Div(
                    className="charts-container",
                    children=[
                        html.Div(
                            className="chart-wrapper",
                            children=[
                                html.H3(
                                    "Protocol Distribution",
                                    className="chart-title",
                                ),
                                dcc.Graph(id="traffic-pie-chart"),
                            ],
                        ),
                        html.Div(
                            className="chart-wrapper",
                            children=[
                                html.H3(
                                    "Packet Length by Protocol",
                                    className="chart-title",
                                ),
                                dcc.Graph(id="traffic-bar-chart"),
                            ],
                        ),
                    ],
                ),
            ]
        ),
        # Export Controls
        html.Div(
            children=[
                html.Button(
                    "Export CSV",
                    id="export-button",
                    className="export-button",
                ),
                dcc.Download(id="download-dataframe-csv"),
            ],
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
    logger.debug(f"Updating refresh interval to {refresh_rate}ms")
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
        Output("flagged-ips-table", "data"),
    ],
    [
        Input("interval-component", "n_intervals"),
        Input("protocol-dropdown-filter", "value"),
    ],
)
def update_dashboard(n, protocol_filter):
    try:
        logger.debug(
            f"Updating dashboard - Interval: {n}, Protocol Filter: {protocol_filter}"
        )

        # Fetch data
        df = db_manager.fetch_traffic(protocol_filter=protocol_filter)
        stats = db_manager.get_traffic_statistics()
        capture_stats = traffic_logger.get_capture_stats()

        logger.debug(
            f"Dashboard stats - Packets: {stats.get('total_packets', 0)}, "
            f"Bytes: {stats.get('total_bytes', 0)}, "
            f"Unique IPs: {stats.get('unique_ips', 0)}, "
            f"PPS: {capture_stats['packets_per_second']:.2f}"
        )

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
        status = f"Capture Duration: {capture_stats['duration']:.1f}s"

        # Get flagged IPs
        flagged_ips = db_manager.get_flagged_ips()
        logger.debug(f"Retrieved {len(flagged_ips)} flagged IPs")

        return (
            df.to_dict("records"),
            pie_chart,
            bar_chart,
            total_packets,
            total_bytes,
            unique_ips,
            packets_per_second,
            status,
            flagged_ips,
        )
    except Exception as e:
        logger.error(f"Error updating dashboard: {e}", exc_info=True)
        raise PreventUpdate


@app.callback(
    Output("download-dataframe-csv", "data"),
    Input("export-button", "n_clicks"),
    prevent_initial_call=True,
)
def export_csv(n_clicks):
    try:
        logger.info("Exporting traffic data to CSV")
        df = db_manager.fetch_traffic()
        logger.info(f"Exported {len(df)} records to CSV")
        return dcc.send_data_frame(df.to_csv, "traffic_data.csv")
    except Exception as e:
        logger.error(f"Error exporting CSV: {e}", exc_info=True)
        return None


@app.callback(
    [Output("traffic-table", "style_data_conditional")],
    [Input("interval-component", "n_intervals")],
)
def update_traffic_table_styles(n):
    """Update traffic table styles for protocols and flagged IPs."""
    try:
        logger.debug("Updating traffic table styles")
        styles = [
            {
                "if": {"row_index": "odd"},
                "backgroundColor": "#f2f2f2",
            }
        ]

        # Get all unique protocols
        protocol_types = set(db_manager.get_protocol_types())
        logger.debug(f"Found {len(protocol_types)} unique protocols")

        # Add protocol-based styling
        for protocol in protocol_types:
            color = lighten_hex_color_for_light_mode(string_to_hex_color(protocol))
            styles.append(
                {
                    "if": {"filter_query": f"{{protocol}} = '{protocol}'"},
                    "backgroundColor": color,
                }
            )

        # Add flagged IP styling
        flagged_ips = db_manager.get_flagged_ips()
        logger.debug(f"Applying styles for {len(flagged_ips)} flagged IPs")
        for ip_data in flagged_ips:
            ip = ip_data["ip"]
            styles.extend(
                [
                    {
                        "if": {
                            "filter_query": f"{{src_ip}} = '{ip}' || {{dst_ip}} = '{ip}'"
                        },
                        "backgroundColor": "#ffebee",
                        "color": "#c62828",
                        "fontWeight": "bold",
                        "border": "2px solid #ef5350",
                    },
                    {
                        "if": {
                            "filter_query": f"{{src_ip}} = '{ip}' || {{dst_ip}} = '{ip}'",
                            "column_id": "src_ip",
                        },
                        "backgroundColor": "#ef5350",
                        "color": "white",
                        "fontWeight": "bold",
                        "textDecoration": "underline",
                    },
                    {
                        "if": {
                            "filter_query": f"{{src_ip}} = '{ip}' || {{dst_ip}} = '{ip}'",
                            "column_id": "dst_ip",
                        },
                        "backgroundColor": "#ef5350",
                        "color": "white",
                        "fontWeight": "bold",
                        "textDecoration": "underline",
                    },
                ]
            )

        return [styles]
    except Exception as e:
        logger.error(f"Error updating table styles: {e}", exc_info=True)
        return [styles]


@app.callback(
    [
        Output("flagged-ips-table", "data", allow_duplicate=True),
        Output("flagged-ips-table", "tooltip_data"),
    ],
    [
        Input("traffic-table", "active_cell"),
        Input("unflag-ip-button", "n_clicks"),
        Input("interval-component", "n_intervals"),
        Input("flagged-ips-table", "active_cell"),
    ],
    [State("traffic-table", "data"), State("flagged-ips-table", "data")],
    prevent_initial_call=True,
)
def handle_ip_flagging(
    active_cell,
    unflag_clicks,
    n_intervals,
    flagged_active_cell,
    table_data,
    flagged_data,
):
    ctx = callback_context
    if not ctx.triggered:
        raise PreventUpdate

    triggered_id = ctx.triggered[0]["prop_id"].split(".")[0]
    logger.debug(f"IP flagging callback triggered by: {triggered_id}")

    try:
        if triggered_id == "flagged-ips-table" and flagged_active_cell:
            if flagged_active_cell["column_id"] == "action":
                ip = flagged_data[flagged_active_cell["row"]]["ip"]
                logger.info(f"Unflagging IP from table: {ip}")
                db_manager.unflag_ip(ip)
        elif triggered_id == "traffic-table" and active_cell:
            row = table_data[active_cell["row"]]
            column_id = active_cell["column_id"]

            if column_id == "src_ip":
                ip = row["src_ip"]
                logger.info(f"Flagging source IP: {ip}")
                db_manager.flag_ip(ip)
            elif column_id == "dst_ip":
                ip = row["dst_ip"]
                logger.info(f"Flagging destination IP: {ip}")
                db_manager.flag_ip(ip)

        # Get updated flagged IPs and add unflag button text
        flagged_ips = db_manager.get_flagged_ips()
        for item in flagged_ips:
            item["action"] = "Unflag"

        # Create tooltips for abuse reports
        tooltips = []
        for item in flagged_ips:
            try:
                abuse_report = (
                    eval(item["abuse_report"])
                    if item["abuse_report"] != "API key not configured"
                    else []
                )
                if isinstance(abuse_report, list) and abuse_report:
                    recent_reports = abuse_report[:3]
                    report_text = "\n".join(
                        [
                            f"• {report.get('comment', 'No comment')} "
                            f"({report.get('reportedAt', 'Unknown date')})"
                            for report in recent_reports
                        ]
                    )
                    if len(abuse_report) > 3:
                        report_text += f"\n\n(+{len(abuse_report) - 3} more reports)"
                    logger.debug(
                        f"Processed {len(recent_reports)} reports for IP {item['ip']}"
                    )
                else:
                    report_text = (
                        str(abuse_report) if abuse_report else "No abuse reports"
                    )

                tooltip = {
                    "ip": {"value": item["ip"], "type": "text"},
                    "timestamp": {"value": item["timestamp"], "type": "text"},
                    "confidence_score": {
                        "value": f"Score: {item['confidence_score']}%\n\nRecent Reports:\n{report_text}",
                        "type": "markdown",
                    },
                    "action": {"value": "Click to unflag", "type": "text"},
                }
                tooltips.append(tooltip)
            except Exception as e:
                logger.error(
                    f"Error processing tooltip for IP {item['ip']}: {e}", exc_info=True
                )
                tooltips.append({})

        return [flagged_ips, tooltips]
    except Exception as e:
        logger.error(f"Error in IP flagging callback: {e}", exc_info=True)
        raise PreventUpdate


@app.callback(
    [Output("traffic-table", "data", allow_duplicate=True)],
    [Input("interval-component", "n_intervals")],
    prevent_initial_call=True,
)
def update_traffic_table(n):
    df = db_manager.fetch_traffic()
    return [df.to_dict("records")]


@app.callback(
    [
        Output("traffic-pie-chart", "figure", allow_duplicate=True),
        Output("traffic-bar-chart", "figure", allow_duplicate=True),
        Output("total-packets", "children", allow_duplicate=True),
        Output("total-bytes", "children", allow_duplicate=True),
        Output("unique-ips", "children", allow_duplicate=True),
        Output("packets-per-second", "children", allow_duplicate=True),
        Output("status-indicator", "children", allow_duplicate=True),
    ],
    [Input("interval-component", "n_intervals")],
    prevent_initial_call=True,
)
def update_dashboard_stats(n):
    try:
        # Fetch data
        df = db_manager.fetch_traffic()
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
        status = f"Capture Duration: {capture_stats['duration']:.1f}s"

        return (
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


if __name__ == "__main__":
    logger.info("Starting Network Traffic Analysis Dashboard")
    traffic_logger.start_sniffer()
    logger.info("Traffic sniffer started")
    app.run(debug=True, use_reloader=False)
