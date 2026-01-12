"""
Test wszystkich typow alertow Mini-SIEM
========================================
Testuje detekcje alertow dla:
- FAILED_LOGIN (Linux SSH)
- INVALID_USER (Linux SSH)
- WIN_FAILED_LOGIN (Windows Event 4625)

Oraz rozne statusy IP:
- UNKNOWN -> severity WARNING
- BANNED -> severity CRITICAL
- TRUSTED -> brak alertu

Uruchom: python test_all_alerts.py
"""
from datetime import datetime, timezone
from app import create_app, db
from app.models import Host, Alert, IPRegistry, LogArchive
from app.services.data_manager import DataManager
from app.services.log_analyzer import LogAnalyzer

# Kolory terminal (ANSI)
GREEN = "\033[92m"
RED = "\033[91m"
YELLOW = "\033[93m"
RESET = "\033[0m"
BOLD = "\033[1m"

def print_header(text):
    print(f"\n{BOLD}{'='*60}{RESET}")
    print(f"{BOLD}{text}{RESET}")
    print(f"{BOLD}{'='*60}{RESET}")

def print_result(test_name, passed, details=""):
    status = f"{GREEN}[PASS]{RESET}" if passed else f"{RED}[FAIL]{RESET}"
    print(f"  {status} {test_name}")
    if details:
        print(f"         {details}")

app = create_app()

with app.app_context():
    print_header("🧪 TEST WSZYSTKICH TYPÓW ALERTÓW")
    
    # === PRZYGOTOWANIE ===
    print("\n📦 Przygotowanie środowiska testowego...")
    
    # Wyczyść poprzednie dane testowe
    Alert.query.filter(Alert.source_ip.like('10.0.0.%')).delete()
    IPRegistry.query.filter(IPRegistry.ip_address.like('10.0.0.%')).delete()
    db.session.commit()
    
    # Utwórz hosta testowego
    host = Host.query.filter_by(hostname='TestHost').first()
    if not host:
        host = Host(hostname='TestHost', ip_address='10.255.255.1', os_type='LINUX')
        db.session.add(host)
        db.session.commit()
    
    # === DEFINIOWANIE PRZYPADKÓW TESTOWYCH ===
    test_cases = [
        # TC1-3: FAILED_LOGIN z różnymi statusami IP
        {"id": "TC1", "alert_type": "FAILED_LOGIN", "ip": "10.0.0.1", "ip_status": None, "user": "ubuntu", "expected_severity": "WARNING"},
        {"id": "TC2", "alert_type": "FAILED_LOGIN", "ip": "10.0.0.2", "ip_status": "BANNED", "user": "admin", "expected_severity": "CRITICAL"},
        {"id": "TC3", "alert_type": "FAILED_LOGIN", "ip": "10.0.0.3", "ip_status": "TRUSTED", "user": "user1", "expected_severity": None},  # Brak alertu
        
        # TC4-5: INVALID_USER
        {"id": "TC4", "alert_type": "INVALID_USER", "ip": "10.0.0.4", "ip_status": None, "user": "hacker", "expected_severity": "WARNING"},
        {"id": "TC5", "alert_type": "INVALID_USER", "ip": "10.0.0.5", "ip_status": "BANNED", "user": "attacker", "expected_severity": "CRITICAL"},
        
        # TC6-7: WIN_FAILED_LOGIN
        {"id": "TC6", "alert_type": "WIN_FAILED_LOGIN", "ip": "10.0.0.6", "ip_status": None, "user": "Administrator", "expected_severity": "WARNING"},
        {"id": "TC7", "alert_type": "WIN_FAILED_LOGIN", "ip": "10.0.0.7", "ip_status": "BANNED", "user": "Guest", "expected_severity": "CRITICAL"},
    ]
    
    # === PRE-KONFIGURACJA IP REGISTRY ===
    print("\n🔧 Konfiguracja IP Registry (BANNED/TRUSTED)...")
    for tc in test_cases:
        if tc["ip_status"]:
            ip_entry = IPRegistry(
                ip_address=tc["ip"],
                status=tc["ip_status"],
                last_seen=datetime.now(timezone.utc)
            )
            db.session.add(ip_entry)
            print(f"   → {tc['ip']}: {tc['ip_status']}")
    db.session.commit()
    
    # === GENEROWANIE LOGÓW ===
    print("\n📝 Generowanie syntetycznych logów...")
    fake_logs = []
    for tc in test_cases:
        log = {
            'timestamp': datetime.now(),
            'alert_type': tc["alert_type"],
            'source_ip': tc["ip"],
            'user': tc["user"],
            'message': f"Test {tc['id']}: {tc['alert_type']} from {tc['ip']}",
            'raw_log': f"synthetic_log_{tc['id']}"
        }
        fake_logs.append(log)
        print(f"   → {tc['id']}: {tc['alert_type']} | IP: {tc['ip']} | User: {tc['user']}")
    
    # === ZAPIS DO PARQUET ===
    print("\n💾 Zapisywanie do Parquet...")
    filename, record_count = DataManager.save_logs_to_parquet(fake_logs, host.id)
    print(f"   → Plik: {filename}")
    print(f"   → Rekordów: {record_count}")
    
    # Dodaj do LogArchive
    archive = LogArchive(host_id=host.id, filename=filename, record_count=record_count)
    db.session.add(archive)
    db.session.commit()
    
    # === ANALIZA (THREAT INTELLIGENCE) ===
    print("\n🔍 Uruchamianie LogAnalyzer...")
    alerts_before = Alert.query.count()
    alerts_created = LogAnalyzer.analyze_parquet(filename, host.id)
    alerts_after = Alert.query.count()
    print(f"   → Alertów przed: {alerts_before}")
    print(f"   → Alertów utworzonych: {alerts_created}")
    print(f"   → Alertów po: {alerts_after}")
    
    # === WERYFIKACJA ===
    print_header("📊 WYNIKI TESTÓW")
    
    passed_count = 0
    failed_count = 0
    
    for tc in test_cases:
        alert = Alert.query.filter_by(source_ip=tc["ip"]).first()
        
        if tc["expected_severity"] is None:
            # TRUSTED - nie powinno być alertu
            if alert is None:
                passed_count += 1
                print_result(f"{tc['id']}: {tc['alert_type']} + {tc['ip_status'] or 'NEW'} IP", True, "Brak alertu (poprawnie)")
            else:
                failed_count += 1
                print_result(f"{tc['id']}: {tc['alert_type']} + {tc['ip_status']} IP", False, f"Alert istnieje (nie powinien!)")
        else:
            # Powinien być alert z określonym severity
            if alert and alert.severity == tc["expected_severity"]:
                passed_count += 1
                print_result(f"{tc['id']}: {tc['alert_type']} + {tc['ip_status'] or 'NEW'} IP", True, f"Severity: {alert.severity}")
            elif alert:
                failed_count += 1
                print_result(f"{tc['id']}: {tc['alert_type']} + {tc['ip_status'] or 'NEW'} IP", False, 
                           f"Oczekiwano: {tc['expected_severity']}, Otrzymano: {alert.severity}")
            else:
                failed_count += 1
                print_result(f"{tc['id']}: {tc['alert_type']} + {tc['ip_status'] or 'NEW'} IP", False, "Brak alertu!")
    
    # === SPRAWDZENIE IP REGISTRY ===
    print_header("🌐 WERYFIKACJA IP REGISTRY")
    
    for tc in test_cases:
        if tc["ip_status"] is None:
            # Nowe IP powinno być dodane jako UNKNOWN
            ip_entry = IPRegistry.query.filter_by(ip_address=tc["ip"]).first()
            if ip_entry and ip_entry.status == "UNKNOWN":
                passed_count += 1
                print_result(f"{tc['ip']} dodane jako UNKNOWN", True)
            else:
                failed_count += 1
                status = ip_entry.status if ip_entry else "BRAK"
                print_result(f"{tc['ip']} dodane jako UNKNOWN", False, f"Status: {status}")
    
    # === PODSUMOWANIE ===
    print_header("📈 PODSUMOWANIE")
    total = passed_count + failed_count
    print(f"\n   {GREEN}Passed: {passed_count}/{total}{RESET}")
    print(f"   {RED if failed_count > 0 else GREEN}Failed: {failed_count}/{total}{RESET}")
    
    if failed_count == 0:
        print(f"\n   {GREEN}{BOLD}🎉 WSZYSTKIE TESTY ZALICZONE!{RESET}")
    else:
        print(f"\n   {RED}{BOLD}⚠️ NIEKTÓRE TESTY NIE PRZESZŁY{RESET}")
    
    # === CZYSZCZENIE (opcjonalne) ===
    print("\n🧹 Dane testowe pozostawione do inspekcji.")
    print("   Uruchom cleanup_test_data.py aby wyczyścić.")
