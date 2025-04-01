from dash import dash_table, dcc, html

LAYOUT = html.Div(
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
                            options=[{"label": "All", "value": "All"}],
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
