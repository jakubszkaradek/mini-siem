"""
Skrypt czyszczący testowe dane.
Uruchom: python cleanup_test_data.py
"""
from app import create_app, db
from app.models import Alert, IPRegistry, LogArchive
import os
import shutil

app = create_app()

with app.app_context():
    # Usuń alerty
    alerts = Alert.query.delete()
    print(f'✅ Usunięto alertów: {alerts}')
    
    # Usuń IP Registry
    ips = IPRegistry.query.delete()
    print(f'✅ Usunięto wpisów IP: {ips}')
    
    # Usuń LogArchive
    archives = LogArchive.query.delete()
    print(f'✅ Usunięto archiwów: {archives}')
    
    db.session.commit()
    print('💾 Baza danych wyczyszczona!')

# Usuń pliki Parquet
if os.path.exists('storage'):
    shutil.rmtree('storage')
    print('🗑️  Folder storage/ usunięty')
else:
    print('ℹ️  Folder storage/ nie istnieje')

print('\n✅ Czyszczenie zakończone!')
