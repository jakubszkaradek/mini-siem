"""Test pobierania logów Windows."""
from app import create_app
from app.services.win_client import WinClient
from app.services.log_collector import LogCollector

app = create_app()

with app.app_context():
    print('Testing Windows log collection...')
    with WinClient() as wc:
        logs = LogCollector.get_windows_logs(wc, None)
        print(f'Collected {len(logs)} logs')
        for log in logs[:5]:
            print(f'  - User: {log["user"]}, IP: {log["source_ip"]}')
