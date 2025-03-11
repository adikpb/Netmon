import dash
from dash import dcc, html, dash_table, Input, Output
import sqlite3
import pandas as pd
import plotly.express as px
import threading
import mitmproxy.http
import time
from mitmproxy.tools.main import mitmdump
# Initialize Dash app
app = dash.Dash(__name__)

# SQLite Database Setup
def init_db():
    conn = sqlite3.connect("network_traffic.db")
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS traffic (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            url TEXT, method TEXT, status_code INTEGER,
            content_length INTEGER, timestamp TEXT
        )
    """)
    conn.commit()
    conn.close()

init_db()

# mitmproxy Addon for Capturing Traffic
class TrafficLogger:
    def request(self, flow: mitmproxy.http.HTTPFlow):
        conn = sqlite3.connect("network_traffic.db")
        cursor = conn.cursor()
        cursor.execute("""
            INSERT INTO traffic (url, method, status_code, content_length, timestamp)
            VALUES (?, ?, ?, ?, datetime('now'))
        """, (flow.request.url, flow.request.method, flow.response.status_code if flow.response else None,
              len(flow.response.content) if flow.response else 0))
        conn.commit()
        conn.close()

addons = [TrafficLogger()]

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
            {"name": "URL", "id": "url"},
            {"name": "Method", "id": "method"},
            {"name": "Status Code", "id": "status_code"},
            {"name": "Content Length", "id": "content_length"},
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
    
    pie_chart = px.pie(df, names='method', title='HTTP Method Distribution')
    bar_chart = px.bar(df, x='status_code', title='Status Code Distribution')
    
    return table_data, pie_chart, bar_chart

# Export Data as CSV
@app.callback(
    Output("download-dataframe-csv", "data"),
    Input("export-button", "n_clicks"),
    prevent_initial_call=True,
)
def export_data(n_clicks):
    df = fetch_data()
    return dcc.send_data_frame(df.to_csv, "network_logs.csv")

if __name__ == '__main__':
    threading.Thread(target=lambda: app.run_server(debug=True, use_reloader=False)).start()
    
    mitmdump()

