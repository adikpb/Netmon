import logging
import os
import signal
import sys

import dash
import plotly.express as px
from dash import Input, Output, State, callback_context, dcc
from dash.exceptions import PreventUpdate
from dotenv import load_dotenv

from layout import LAYOUT
from capture import TrafficLogger
from database import DatabaseManager
from utils import lighten_hex_color_for_light_mode, string_to_hex_color

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    handlers=[
        logging.FileHandler("network_monitor.log"),
        logging.StreamHandler(),
    ],
)
logger = logging.getLogger(__name__)

logger.info("Loading environment variables")
load_dotenv()
ABUSEIPDB_API_KEY = os.getenv("ABUSEIPDB_API_KEY")
if not ABUSEIPDB_API_KEY:
    logger.warning("AbuseIPDB API key not found in environment variables")
else:
    logger.info("AbuseIPDB API key loaded successfully")

logger.info("Initializing Dash application")
app = dash.Dash(
    __name__,
    assets_folder="assets",
    serve_locally=True,
)
app.title = "Network Traffic Analysis Dashboard"

logger.info("Initializing TrafficLogger and DatabaseManager")
traffic_logger = TrafficLogger()
db_manager = DatabaseManager(abuseipdb_key=ABUSEIPDB_API_KEY)


def signal_handler(sig, frame):
    logger.info("Received shutdown signal - initiating graceful shutdown")
    traffic_logger.stop_sniffer()
    logger.info("Traffic logger stopped")
    sys.exit(0)


signal.signal(signal.SIGINT, signal_handler)

app.layout = LAYOUT


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

        df = db_manager.fetch_traffic(protocol_filter=protocol_filter)
        stats = db_manager.get_traffic_statistics()
        capture_stats = traffic_logger.get_capture_stats()

        logger.debug(
            f"Dashboard stats - Packets: {stats.get('total_packets', 0)}, "
            f"Bytes: {stats.get('total_bytes', 0)}, "
            f"Unique IPs: {stats.get('unique_ips', 0)}, "
            f"PPS: {capture_stats['packets_per_second']:.2f}"
        )

        total_packets = f"Total Packets: {stats.get('total_packets', 0):,}"
        total_bytes = f"Total Bytes: {stats.get('total_bytes', 0):,}"
        unique_ips = f"Unique IPs: {stats.get('unique_ips', 0):,}"
        packets_per_second = f"Packets/sec: {capture_stats['packets_per_second']:.2f}"

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

        for chart in [pie_chart, bar_chart]:
            chart.update_layout(
                plot_bgcolor="rgba(0,0,0,0)",
                paper_bgcolor="rgba(0,0,0,0)",
                font=dict(size=12),
            )

        status = f"Capture Duration: {capture_stats['duration']:.1f}s"

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
    [
        Output("traffic-table", "style_data_conditional"),
        Output("protocol-dropdown-filter", "options"),
    ],
    [Input("interval-component", "n_intervals")],
)
def update_traffic_table_styles(n):
    options = [{"label": "All", "value": "All"}]
    styles = [
        {
            "if": {"row_index": "odd"},
            "backgroundColor": "#f2f2f2",
        }
    ]
    try:
        logger.debug("Updating traffic table styles")

        protocol_types = set(db_manager.get_protocol_types())
        logger.debug(f"Found {len(protocol_types)} unique protocols")

        for protocol in protocol_types:
            color = lighten_hex_color_for_light_mode(string_to_hex_color(protocol))
            styles.append(
                {
                    "if": {"filter_query": f"{{protocol}} = '{protocol}'"},
                    "backgroundColor": color,
                }
            )
            options.append({"label": protocol, "value": protocol})

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
    except Exception as e:
        logger.error(f"Error updating table styles: {e}", exc_info=True)
    finally:
        return styles, options


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
    prevent_initial_call="initial_duplicate",
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

        flagged_ips = db_manager.get_flagged_ips()
        for item in flagged_ips:
            item["action"] = "Unflag"

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


if __name__ == "__main__":
    logger.info("Starting Network Traffic Analysis Dashboard")
    traffic_logger.start_sniffer()
    logger.info("Traffic sniffer started")
    app.run(debug=True, use_reloader=False)
