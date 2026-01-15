import pandas as pd
# [NAPRAWIONO BUG] Dodano timedelta do detekcji duplikatów
from datetime import datetime, timezone, timedelta
from app.extensions import db
from app.models import Alert, IPRegistry, Host
from app.services.data_manager import DataManager

class LogAnalyzer:
    """
    Serce systemu SIEM. Analizuje pliki logów przy użyciu Pandas
    i generuje alerty w bazie danych.
    """

    @staticmethod
    def analyze_parquet(filename, host_id):
        """
        Główna funkcja analityczna.
        """
        # 1. Wczytanie danych (To masz gotowe)
        df = DataManager.load_logs(filename)
        
        if df.empty:
            return 0 
            
        # Zabezpieczenie przed brakiem kolumn
        if 'alert_type' not in df.columns or 'source_ip' not in df.columns:
            return 0

        # [ZMODYFIKOWANO] Filtrowanie tylko typów ataków
        attack_pattern = ['FAILED_LOGIN', 'INVALID_USER', 'WIN_FAILED_LOGIN']
        threats = df[df['alert_type'].isin(attack_pattern)]
        
        if threats.empty:
            return 0

        alerts_created = 0
        
        # 3. Iteracja po zagrożeniach
        for index, row in threats.iterrows():
            ip = row['source_ip']
            user = row.get('user', 'unknown')
            
            # # Ignorujemy lokalne
            # if ip in ['LOCAL', 'LOCAL_CONSOLE', '127.0.0.1', '::1']:
            #     continue
            
            # [NAPRAWIONO BUG] Pobranie oryginalnego timestampa z logu (nie datetime.now)
            log_timestamp = row.get('timestamp', datetime.now(timezone.utc))
            if isinstance(log_timestamp, str):
                try:
                    log_timestamp = datetime.strptime(log_timestamp, '%Y-%m-%d %H:%M:%S')
                except:
                    log_timestamp = datetime.now(timezone.utc)
            
            # [NAPRAWIONO BUG] Detekcja duplikatów - unikamy powtórzonych alertów
            existing_alert = Alert.query.filter_by(
                host_id=host_id,
                source_ip=ip,
                alert_type=row['alert_type']
            ).filter(
                Alert.timestamp >= log_timestamp - timedelta(seconds=5),
                Alert.timestamp <= log_timestamp + timedelta(seconds=5)
            ).first()
            
            if existing_alert:
                continue  # Pomijamy duplikaty

            # =======================================================
            # LOGIKA SIEM (THREAT INTELLIGENCE)
            # =======================================================
            
            # [ZMODYFIKOWANO] Sprawdzenie IP w rejestrze reputacji
            ip_entry = IPRegistry.query.filter_by(ip_address=ip).first()
            
            if not ip_entry:
                # 2. Nowe IP - dodaj ze statusem UNKNOWN
                ip_entry = IPRegistry(
                    ip_address=ip,
                    status='UNKNOWN',
                    last_seen=datetime.now(timezone.utc)
                )
                db.session.add(ip_entry)
            else:
                # 3. Istniejące IP - aktualizuj last_seen
                ip_entry.last_seen = datetime.now(timezone.utc)
            
            # [ZMODYFIKOWANO] Ustalanie severity na podstawie statusu IP
            if ip_entry.status == 'BANNED':
                severity = 'CRITICAL'
                message = f"BANNED IP {ip} próbował się zalogować jako '{user}'"
            elif ip_entry.status == 'TRUSTED':
                # Pomijamy alerty dla zaufanych IP
                continue
            else:
                severity = 'WARNING'
                message = f"Nieudana próba logowania z {ip} (user: {user})"
            
            # [ZMODYFIKOWANO] Tworzenie alertu w bazie
            new_alert = Alert(
                host_id=host_id,
                alert_type=row['alert_type'],
                source_ip=ip,
                severity=severity,
                message=message,
                # [NAPRAWIONO BUG] Używamy oryginalnego timestampa z logu!
                timestamp=log_timestamp
            )
            
            # 6. Dodaj do sesji i zwiększ licznik
            db.session.add(new_alert)
            alerts_created += 1

        # Zatwierdzenie zmian w bazie
        db.session.commit()
        return alerts_created