import asyncio
import dash
import mitmproxy.http
import pandas as pd
import plotly.express as px
import sqlite3
import threading
from dash import dcc, html, dash_table, Input, Output
from mitmproxy.addons import default_addons, script
from mitmproxy.master import Master
from mitmproxy.options import Options
from typing import Any, Callable, Self

# Initialize Dash app
app = dash.Dash(__name__)

# SQLite Database Setup
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


# mitmproxy Addon for Capturing Traffic
class TrafficLogger:
    def request(self, flow: mitmproxy.http.HTTPFlow):
        conn = sqlite3.connect("network_traffic.db")
        cursor = conn.cursor()

        content_length = 0
        status_code = None
        if flow.response:
            status_code = flow.response.status_code
            if flow.response.content:
                content_length = len(flow.response.content)

        cursor.execute("INSERT INTO traffic (url, method, status_code, content_length, timestamp) VALUES (?, ?, ?, ?, datetime('now'))", 
                       (flow.request.url, flow.request.method, status_code, content_length))
        conn.commit()
        conn.close()

class ThreadedMitmProxy(threading.Thread):
    def __init__(self, user_addon: Callable, **options: Any) -> None:
        self.loop = asyncio.new_event_loop()
        self.master = Master(Options(), event_loop=self.loop)
        # replace the ScriptLoader with the user addon
        self.master.addons.add(
            *(
                user_addon() if isinstance(addon, script.ScriptLoader) else addon
                for addon in default_addons()
            )
        )
        # set the options after the addons since some options depend on addons
        self.master.options.update(**options)
        super().__init__()

    def run(self) -> None:
        self.loop.run_until_complete(self.master.run())

    def __enter__(self) -> Self:
        self.start()
        return self

    def __exit__(self, *_) -> None:
        self.master.shutdown()
        self.join()

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
    with ThreadedMitmProxy(TrafficLogger, listen_host="127.0.0.1", listen_port=8080):
        threading.Thread(target=lambda: app.run_server(debug=True, use_reloader=False)).start()
        input("hit <Enter> to quit")
        print("shutdown mitmproxy")

