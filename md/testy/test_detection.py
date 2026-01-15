"""
Test detekcji zagrożeń (ETAP 5.3)
Symuluje failed login i sprawdza czy alerty się tworzą.
"""
from datetime import datetime, timezone
from app import create_app, db
from app.models import Host, Alert, IPRegistry, LogArchive
from app.services.data_manager import DataManager
from app.services.log_analyzer import LogAnalyzer

app = create_app()

with app.app_context():
    # 1. Upewnij się, że host istnieje
    host = Host.query.first()
    if not host:
        host = Host(hostname='TestHost', ip_address='127.0.0.1', os_type='WINDOWS')
        db.session.add(host)
        db.session.commit()
        print(f"✅ Utworzono hosta: {host.hostname}")
    else:
        print(f"ℹ️  Używam istniejącego hosta: {host.hostname}")
    
    # 2. Symuluj logi z failed login
    fake_logs = [
        {
            'timestamp': datetime.now(),
            'alert_type': 'FAILED_LOGIN',
            'source_ip': '192.168.1.100',
            'user': 'hacker1',
            'message': 'Failed password for hacker1 from 192.168.1.100',
            'raw_log': 'test log 1'
        },
        {
            'timestamp': datetime.now(),
            'alert_type': 'INVALID_USER',
            'source_ip': '10.0.0.50',
            'user': 'nieznany',
            'message': 'Invalid user nieznany from 10.0.0.50',
            'raw_log': 'test log 2'
        },
        {
            'timestamp': datetime.now(),
            'alert_type': 'WIN_FAILED_LOGIN',
            'source_ip': '172.16.0.1',
            'user': 'admin',
            'message': 'Windows Logon Failure for user: admin',
            'raw_log': 'test log 3'
        },
    ]
    
    print(f"\n📝 Symulowanie {len(fake_logs)} logów z atakami...")
    
    # 3. Zapisz do Parquet (wymagane przez OCENA.md!)
    filename, count = DataManager.save_logs_to_parquet(fake_logs, host.id)
    print(f"💾 Zapisano do Parquet: {filename} ({count} rekordów)")
    
    # 4. Dodaj do LogArchive
    archive = LogArchive(host_id=host.id, filename=filename, record_count=count)
    db.session.add(archive)
    db.session.commit()
    
    # 5. Uruchom analizator (Threat Intelligence)
    alerts_before = Alert.query.count()
    print(f"\n🔍 Alertów przed analizą: {alerts_before}")
    
    alerts_created = LogAnalyzer.analyze_parquet(filename, host.id)
    
    alerts_after = Alert.query.count()
    print(f"🚨 Alertów po analizie: {alerts_after}")
    print(f"✅ Nowych alertów: {alerts_created}")
    
    # 6. Pokaż utworzone alerty
    print("\n--- OSTATNIE ALERTY ---")
    for alert in Alert.query.order_by(Alert.timestamp.desc()).limit(5):
        print(f"  [{alert.severity}] {alert.source_ip} → {alert.message[:50]}...")
    
    # 7. Pokaż IP Registry
    print("\n--- IP REGISTRY ---")
    for ip in IPRegistry.query.all():
        print(f"  {ip.ip_address}: {ip.status} (last: {ip.last_seen})")
    
    print("\n✅ Test detekcji zakończony!")
