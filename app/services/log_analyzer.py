import pandas as pd
from datetime import datetime, timezone
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

        # 2. Filtrowanie: Interesują nas tylko ataki
        attack_pattern = ['FAILED_LOGIN', 'INVALID_USER', 'WIN_FAILED_LOGIN']
        threats = df[df['alert_type'].isin(attack_pattern)]
        
        if threats.empty:
            return 0

        alerts_created = 0
        
        # 3. Iteracja po zagrożeniach
        for index, row in threats.iterrows():
            ip = row['source_ip']
            user = row.get('user', 'unknown')
            
            # Ignorujemy lokalne
            if ip in ['LOCAL', 'LOCAL_CONSOLE', '127.0.0.1', '::1']:
                continue

            # =======================================================
            # LOGIKA SIEM (THREAT INTELLIGENCE)
            # =======================================================
            
            # 1. Sprawdź IP w rejestrze
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
            
            # 4. Ustal severity i message na podstawie statusu IP
            if ip_entry.status == 'BANNED':
                severity = 'CRITICAL'
                message = f"🚨 BANNED IP {ip} próbował się zalogować jako '{user}'"
            elif ip_entry.status == 'TRUSTED':
                # Pomijamy alerty dla zaufanych IP
                continue
            else:
                severity = 'WARNING'
                message = f"⚠️ Nieudana próba logowania z {ip} (user: {user})"
            
            # 5. Stwórz Alert
            new_alert = Alert(
                host_id=host_id,
                alert_type=row['alert_type'],
                source_ip=ip,
                severity=severity,
                message=message,
                timestamp=datetime.now(timezone.utc)
            )
            
            # 6. Dodaj do sesji i zwiększ licznik
            db.session.add(new_alert)
            alerts_created += 1

        # Zatwierdzenie zmian w bazie
        db.session.commit()
        return alerts_created