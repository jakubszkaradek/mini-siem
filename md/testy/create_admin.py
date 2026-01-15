"""
Skrypt do utworzenia użytkownika testowego.
Uruchom: python create_admin.py
"""
from app import create_app, db
from app.models import User

app = create_app()

with app.app_context():
    # Sprawdź czy użytkownik już istnieje
    existing = User.query.filter_by(username='admin').first()
    if existing:
        print("⚠️  Użytkownik 'admin' już istnieje!")
        print(f"   ID: {existing.id}")
        print(f"   Hash hasła: {existing.password_hash[:30]}...")
    else:
        # Utwórz nowego użytkownika
        user = User(username='admin')
        user.set_password('haslo123')
        db.session.add(user)
        db.session.commit()
        print("✅ Utworzono użytkownika testowego:")
        print("   Login: admin")
        print("   Hasło: haslo123")
        print(f"   Hash: {user.password_hash[:30]}...")
