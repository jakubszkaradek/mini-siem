# 🗺️ ROADMAP Implementacji Mini-SIEM

**Data utworzenia:** 2026-01-11  
**Bazuje na:** ANALIZA_PROJEKTU.md

---

## [ ] ETAP 1: Security Hardening 🔐

> **Priorytet:** KRYTYCZNY (40% oceny)  
> **Cel:** Zabezpieczenie systemu przed nieautoryzowanym dostępem

---

### [ ] 1.1 Zmodyfikuj `models.py` - hashowanie haseł

**Plik:** `app/models.py`

**Co zostanie zmienione:**
- Funkcja `set_password()` (linia 13-17) - implementacja hashowania
- Funkcja `check_password()` (linia 19-25) - implementacja weryfikacji

**Zaangażowane funkcje/klasy:**
- `User.set_password(self, password)`
- `User.check_password(self, password)`

**Wymagane importy:**
```python
from werkzeug.security import generate_password_hash, check_password_hash
# Import już istnieje w pliku (linia 3)
```

**Implementacja:**
```python
def set_password(self, password):
    self.password_hash = generate_password_hash(password)

def check_password(self, password):
    return check_password_hash(self.password_hash, password)
```

**Testy:**
```python
# W Flask shell:
from app.models import User
u = User(username='test')
u.set_password('haslo123')
print(u.password_hash)  # Powinien być hash, nie plain text
print(u.check_password('haslo123'))  # True
print(u.check_password('zlehaslo'))  # False
```

---

### [ ] 1.2 Zmodyfikuj `auth.py` - logika logowania

**Plik:** `app/blueprints/auth.py`

**Co zostanie zmienione:**
- Funkcja `login()` (linie 16-26) - pełna logika uwierzytelniania

**Zaangażowane funkcje/klasy:**
- `login()` - route handler
- `User.query.filter_by()` - zapytanie do bazy
- `login_user()` - funkcja Flask-Login

**Wymagane importy:**
```python
# Już istnieją w pliku:
from flask_login import login_user
from app.models import User
```

**Implementacja:**
```python
if form.validate_on_submit():
    user = User.query.filter_by(username=form.username.data).first()
    if user and user.check_password(form.password.data):
        login_user(user)
        flash('Zalogowano pomyślnie!', 'success')
        return redirect(url_for('ui.config'))
    else:
        # WAŻNE: Ogólny komunikat (nie zdradzamy czy login czy hasło złe)
        flash('Nieprawidłowy login lub hasło.', 'danger')
```

**Testy:**
1. Próba logowania z poprawnym login/hasło → przekierowanie do /config
2. Próba logowania z błędnym hasłem → komunikat "Nieprawidłowy login lub hasło"
3. Próba logowania z nieistniejącym użytkownikiem → ten sam komunikat

---

### [ ] 1.3 Sprawdź/stwórz `templates/login.html`

**Plik:** `app/templates/login.html`

**Co zostanie zmienione:**
- Sprawdzenie czy szablon istnieje
- Jeśli nie - utworzenie na bazie Bootstrap + WTForms

**Zaangażowane elementy:**
- `{% extends 'base.html' %}`
- `{{ form.hidden_tag() }}` - token CSRF
- `{{ form.username }}`, `{{ form.password }}`

**Wymagane importy:** Brak (szablon Jinja2)

**Struktura szablonu:**
```html
{% extends 'base.html' %}
{% block content %}
<div class="container mt-5">
    <div class="row justify-content-center">
        <div class="col-md-4">
            <div class="card">
                <div class="card-header">🔐 Logowanie</div>
                <div class="card-body">
                    <form method="POST">
                        {{ form.hidden_tag() }}
                        <div class="mb-3">
                            {{ form.username.label(class="form-label") }}
                            {{ form.username(class="form-control") }}
                        </div>
                        <div class="mb-3">
                            {{ form.password.label(class="form-label") }}
                            {{ form.password(class="form-control") }}
                        </div>
                        {{ form.submit(class="btn btn-primary w-100") }}
                    </form>
                </div>
            </div>
        </div>
    </div>
</div>
{% endblock %}
```

**Testy:**
- Otwarcie `/login` w przeglądarce → formularz się wyświetla
- Sprawdzenie źródła HTML → token CSRF jest obecny

---

### [ ] 1.4 Zmodyfikuj `ui.py` - ochrona `/config`

**Plik:** `app/blueprints/ui.py`

**Co zostanie zmienione:**
- Funkcja `config()` (linia 12-15) - dodanie dekoratora

**Zaangażowane funkcje/klasy:**
- `@login_required` - dekorator Flask-Login

**Wymagane importy:**
```python
from flask_login import login_required
# Import już istnieje w pliku (linia 3)
```

**Implementacja:**
```python
@ui_bp.route('/config')
@login_required  # <-- DODAJ TĘ LINIĘ
def config():
    return render_template('config.html')
```

**Testy:**
1. Bez logowania, wejście na `/config` → redirect do `/login`
2. Po zalogowaniu, wejście na `/config` → strona się wyświetla

---

### [ ] 1.5 Zabezpiecz API - `@login_required` na wszystkich endpointach

**Plik:** `app/blueprints/api/hosts.py`

**Co zostanie zmienione:**
- WSZYSTKIE funkcje route (7+ endpointów)

**Zaangażowane funkcje/klasy:**
| Funkcja | Linia | Metoda |
|---------|-------|--------|
| `get_hosts()` | 18 | GET |
| `add_host()` | 23 | POST |
| `delete_host()` | 34 | DELETE |
| `update_host()` | 41 | PUT |
| `get_ssh_info()` | 53 | GET |
| `get_windows_info()` | 82 | GET |
| `fetch_logs()` | 112 | POST |

**Wymagane importy:**
```python
from flask_login import login_required
# DODAJ do importów na górze pliku
```

**Implementacja (dla każdego endpointu):**
```python
@api_bp.route("/hosts", methods=["GET"])
@login_required  # <-- DODAJ
def get_hosts():
    ...
```

**Testy:**
```bash
# Bez logowania:
curl http://localhost:5000/api/hosts
# Oczekiwany wynik: 401 Unauthorized lub redirect

# Z sesją (przez przeglądarkę):
# Po zalogowaniu, fetch() powinien działać
```

---

## [ ] ETAP 2: Backend Logic - Log Collection 📥

> **Priorytet:** WYSOKI (30% oceny - Forensics)  
> **Cel:** Pobieranie i archiwizacja logów z hostów

---

### [ ] 2.1 Zmodyfikuj `api/hosts.py` - endpoint `fetch_logs`

**Plik:** `app/blueprints/api/hosts.py`

**Co zostanie zmienione:**
- Funkcja `fetch_logs()` (linie 112-138) - pełna implementacja

**Zaangażowane funkcje/klasy:**
- `Host.query.get_or_404()`
- `LogSource.query.filter_by()`
- `RemoteClient` / `WinClient`
- `LogCollector.get_linux_logs()` / `get_windows_logs()`
- `DataManager.save_logs_to_parquet()`
- `LogAnalyzer.analyze_parquet()`

**Wymagane importy:**
```python
# Już istnieją:
from app.services.remote_client import RemoteClient
from app.services.win_client import WinClient
from app.services.log_collector import LogCollector
from app.services.data_manager import DataManager
from app.services.log_analyzer import LogAnalyzer
from datetime import timezone, datetime
```

**Implementacja (schemat):**
```python
@api_bp.route("/hosts/<int:host_id>/logs", methods=["POST"])
@login_required
def fetch_logs(host_id):
    host = Host.query.get_or_404(host_id)
    
    # 1. Pobierz lub utwórz LogSource
    log_source = LogSource.query.filter_by(host_id=host.id).first()
    if not log_source:
        log_source = LogSource(host_id=host.id, log_type='security')
        db.session.add(log_source)
        db.session.commit()
    
    logs = []
    
    # 2. Rozgałęzienie według OS
    if host.os_type == "LINUX":
        ssh_config = {
            'host': host.ip_address,
            'user': current_app.config.get('SSH_DEFAULT_USER', 'vagrant'),
            'port': current_app.config.get('SSH_DEFAULT_PORT', 2222),
            'key_file': current_app.config.get('SSH_KEY_FILE')
        }
        with RemoteClient(**ssh_config) as remote:
            logs = LogCollector.get_linux_logs(remote, log_source.last_fetch)
    
    elif host.os_type == "WINDOWS":
        with WinClient() as win:
            logs = LogCollector.get_windows_logs(win, log_source.last_fetch)
    
    if not logs:
        return jsonify({"message": "Brak nowych logów", "alerts": 0}), 200
    
    # 3. Zapis do Parquet (FORENSICS!)
    filename, record_count = DataManager.save_logs_to_parquet(logs, host.id)
    
    # 4. Aktualizacja LogSource
    log_source.last_fetch = datetime.now(timezone.utc)
    
    # 5. Wpis do LogArchive
    archive = LogArchive(
        host_id=host.id,
        filename=filename,
        record_count=record_count
    )
    db.session.add(archive)
    
    # 6. Analiza zagrożeń
    alerts_count = LogAnalyzer.analyze_parquet(filename, host.id)
    
    db.session.commit()
    
    return jsonify({
        "message": f"Pobrano {record_count} logów",
        "alerts": alerts_count,
        "filename": filename
    }), 200
```

**Testy:**
1. Sprawdź czy folder `storage/` się tworzy
2. Sprawdź czy pliki `.parquet` się zapisują
3. Sprawdź w DB czy `LogArchive` ma wpisy

---

### [ ] 2.2 Obsługa `log_sources` (tworzenie, `last_fetch`)

**Plik:** `app/blueprints/api/hosts.py` (część `fetch_logs`)

**Co zostanie zmienione:**
- Logika tworzenia/aktualizacji `LogSource`

**Zaangażowane funkcje/klasy:**
- `LogSource` model
- `db.session.add()`, `db.session.commit()`

**Wymagane importy:**
```python
from app.models import LogSource
# Już istnieje
```

**Implementacja:** (zawarte w 2.1)

**Testy:**
```python
# W Flask shell:
from app.models import LogSource
ls = LogSource.query.first()
print(ls.last_fetch)  # Powinien być timestamp ostatniego pobrania
```

---

### [ ] 2.3 Integracja z `LogCollector` + `DataManager`

**Plik:** `app/blueprints/api/hosts.py`

**Co zostanie zmienione:**
- Wywołania do serwisów w `fetch_logs()`

**Zaangażowane funkcje/klasy:**
- `LogCollector.get_linux_logs(ssh_client, last_fetch)`
- `LogCollector.get_windows_logs(win_client, last_fetch)`
- `DataManager.save_logs_to_parquet(logs, host_id)`

**Wymagane importy:** (już istnieją)

**Testy:**
```bash
# Sprawdź pliki Parquet:
ls storage/
# Oczekiwany format: logs_1_20260111_142637.parquet
```

---

### [ ] 2.4 Integracja z `LogAnalyzer`

**Plik:** `app/blueprints/api/hosts.py`

**Co zostanie zmienione:**
- Wywołanie `LogAnalyzer.analyze_parquet()` po zapisie

**Zaangażowane funkcje/klasy:**
- `LogAnalyzer.analyze_parquet(filename, host_id)`

**Wymagane importy:** (już istnieją)

**Testy:**
- Po pobraniu logów sprawdź czy alerty się tworzą (wymaga ETAPU 3)

---

## [ ] ETAP 3: Threat Intelligence 🧠

> **Priorytet:** WYSOKI (część 30% oceny)  
> **Cel:** Korelacja IP z bazą zagrożeń i generowanie alertów

---

### [ ] 3.1 Zmodyfikuj `log_analyzer.py` - logika `IPRegistry`

**Plik:** `app/services/log_analyzer.py`

**Co zostanie zmienione:**
- Funkcja `analyze_parquet()` (linie 46-73) - implementacja TODO

**Zaangażowane funkcje/klasy:**
- `IPRegistry.query.filter_by()`
- `Alert()` - tworzenie alertów
- `db.session.add()`, `db.session.commit()`

**Wymagane importy:**
```python
# Już istnieją:
from app.models import Alert, IPRegistry
from app.extensions import db
from datetime import datetime, timezone
```

**Implementacja:**
```python
for index, row in threats.iterrows():
    ip = row['source_ip']
    user = row.get('user', 'unknown')
    
    # Ignorujemy lokalne
    if ip in ['LOCAL', 'LOCAL_CONSOLE', '127.0.0.1', '::1']:
        continue
    
    # 1. Sprawdź IP w rejestrze
    ip_entry = IPRegistry.query.filter_by(ip_address=ip).first()
    
    if not ip_entry:
        # 2. Dodaj nowe IP ze statusem UNKNOWN
        ip_entry = IPRegistry(
            ip_address=ip,
            status='UNKNOWN',
            last_seen=datetime.now(timezone.utc)
        )
        db.session.add(ip_entry)
    else:
        # 3. Aktualizuj last_seen
        ip_entry.last_seen = datetime.now(timezone.utc)
    
    # 4. Ustal severity na podstawie statusu
    if ip_entry.status == 'BANNED':
        severity = 'CRITICAL'
        message = f"🚨 BANNED IP {ip} próbował się zalogować jako {user}"
    elif ip_entry.status == 'TRUSTED':
        continue  # Pomijamy zaufane IP
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
    db.session.add(new_alert)
    alerts_created += 1
```

**Testy:**
```python
# W Flask shell:
from app.models import Alert, IPRegistry
print(Alert.query.count())  # Liczba alertów
print(IPRegistry.query.all())  # Lista IP w rejestrze
```

---

### [ ] 3.2 Dodaj endpointy `IPRegistry` do `api/hosts.py`

**Plik:** `app/blueprints/api/hosts.py`

**Co zostanie zmienione:**
- Odblokowanie zakomentowanych endpointów (linie 145-164)
- Implementacja logiki CRUD

**Zaangażowane funkcje/klasy:**
- `IPRegistry.query`
- `db.session.add()`, `db.session.delete()`, `db.session.commit()`

**Wymagane importy:**
```python
from app.models import IPRegistry
# Już istnieje
```

**Implementacja:**
```python
@api_bp.route("/ips", methods=["GET"])
@login_required
def get_ips():
    ips = IPRegistry.query.order_by(IPRegistry.last_seen.desc()).all()
    return jsonify([{
        'id': ip.id,
        'ip_address': ip.ip_address,
        'status': ip.status,
        'last_seen': ip.last_seen.strftime('%Y-%m-%d %H:%M:%S') if ip.last_seen else None
    } for ip in ips])

@api_bp.route("/ips", methods=["POST"])
@login_required
def add_ip():
    data = request.get_json()
    if not data or not data.get('ip_address'):
        return jsonify({"error": "Brak adresu IP"}), 400
    
    if IPRegistry.query.filter_by(ip_address=data['ip_address']).first():
        return jsonify({"error": "IP już istnieje"}), 409
    
    new_ip = IPRegistry(
        ip_address=data['ip_address'],
        status=data.get('status', 'UNKNOWN')
    )
    db.session.add(new_ip)
    db.session.commit()
    return jsonify({"message": "Dodano IP", "id": new_ip.id}), 201

@api_bp.route("/ips/<int:ip_id>", methods=["PUT"])
@login_required
def update_ip(ip_id):
    ip_entry = IPRegistry.query.get_or_404(ip_id)
    data = request.get_json()
    if 'status' in data:
        ip_entry.status = data['status']
    db.session.commit()
    return jsonify({"message": "Zaktualizowano"}), 200

@api_bp.route("/ips/<int:ip_id>", methods=["DELETE"])
@login_required
def delete_ip(ip_id):
    ip_entry = IPRegistry.query.get_or_404(ip_id)
    db.session.delete(ip_entry)
    db.session.commit()
    return jsonify({"message": "Usunięto"}), 200
```

**Testy:**
```bash
# Po zalogowaniu (przez przeglądarkę DevTools):
fetch('/api/ips').then(r => r.json()).then(console.log)
```

---

### [ ] 3.3 Endpoint alertów

**Plik:** `app/blueprints/api/hosts.py`

**Co zostanie zmienione:**
- Odblokowanie `GET /api/alerts` (linie 166-169)

**Zaangażowane funkcje/klasy:**
- `Alert.query.order_by().limit()`
- `Alert.to_dict()`

**Wymagane importy:**
```python
from app.models import Alert
# Już istnieje
```

**Implementacja:**
```python
@api_bp.route("/alerts", methods=["GET"])
@login_required
def get_recent_alerts():
    alerts = Alert.query.order_by(Alert.timestamp.desc()).limit(20).all()
    return jsonify([a.to_dict() for a in alerts])
```

**Testy:**
```bash
fetch('/api/alerts').then(r => r.json()).then(console.log)
```

---

## [ ] ETAP 4: Frontend Integration 🖥️

> **Priorytet:** ŚREDNI (20% oceny)  
> **Cel:** Połączenie UI z nowymi endpointami

---

### [ ] 4.1 Odkomentuj sekcje IP w `config.html`

**Plik:** `app/templates/config.html`

**Co zostanie zmienione:**
- Sekcje zarządzania IP Registry (jeśli zakomentowane)
- Tabela IP z przyciskami akcji

**Zaangażowane elementy:**
- HTML tabela
- Przyciski CRUD

**Testy:**
- Strona `/config` wyświetla sekcję "IP Registry"

---

### [ ] 4.2 Implementuj funkcje w `admin.js` (CRUD IP)

**Plik:** `app/static/js/admin.js` (lub inny plik JS)

**Co zostanie zmienione:**
- Funkcje `fetchIPs()`, `addIP()`, `updateIPStatus()`, `deleteIP()`

**Zaangażowane funkcje:**
- `fetch('/api/ips', {...})`
- Event listeners dla formularzy/przycisków

**Implementacja (przykład):**
```javascript
async function fetchIPs() {
    try {
        const response = await fetch('/api/ips');
        if (!response.ok) throw new Error('Błąd API');
        const ips = await response.json();
        renderIPTable(ips);
    } catch (error) {
        showError('Nie udało się pobrać listy IP: ' + error.message);
    }
}

async function updateIPStatus(ipId, newStatus) {
    try {
        const response = await fetch(`/api/ips/${ipId}`, {
            method: 'PUT',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({status: newStatus})
        });
        if (!response.ok) throw new Error('Błąd aktualizacji');
        fetchIPs();  // Odśwież tabelę
    } catch (error) {
        showError(error.message);
    }
}
```

**Testy:**
1. Dodanie IP → pojawia się w tabeli
2. Zmiana statusu → aktualizacja w tabeli
3. Usunięcie → znika z tabeli

---

### [ ] 4.3 Implementuj funkcje w `api.js` (fetch alertów)

**Plik:** `app/static/js/api.js` (lub inny plik JS)

**Co zostanie zmienione:**
- Funkcja pobierania alertów

**Implementacja:**
```javascript
async function fetchAlerts() {
    try {
        const response = await fetch('/api/alerts');
        if (!response.ok) {
            if (response.status === 401) {
                window.location.href = '/login';
                return;
            }
            throw new Error(`HTTP ${response.status}`);
        }
        return await response.json();
    } catch (error) {
        console.error('Błąd pobierania alertów:', error);
        showError('Backend nie odpowiada');
        return [];
    }
}
```

**Testy:**
- Konsola nie pokazuje błędów 500
- Użytkownik widzi komunikat przy błędzie (nie ciszę)

---

### [ ] 4.4 Popraw `dashboard.js` - odświeżanie alertów

**Plik:** `app/static/js/dashboard.js` (lub index.js)

**Co zostanie zmienione:**
- Automatyczne odświeżanie co X sekund
- Renderowanie tabeli alertów

**Implementacja:**
```javascript
function renderAlerts(alerts) {
    const tbody = document.querySelector('#alerts-table tbody');
    tbody.innerHTML = '';
    
    alerts.forEach(alert => {
        const row = document.createElement('tr');
        row.className = alert.severity === 'CRITICAL' ? 'table-danger' : 'table-warning';
        row.innerHTML = `
            <td>${alert.timestamp}</td>
            <td>${alert.host_name}</td>
            <td><span class="badge bg-${alert.severity === 'CRITICAL' ? 'danger' : 'warning'}">${alert.severity}</span></td>
            <td>${alert.source_ip}</td>
            <td>${alert.message}</td>
        `;
        tbody.appendChild(row);
    });
}

// Auto-refresh co 30 sekund
setInterval(async () => {
    const alerts = await fetchAlerts();
    renderAlerts(alerts);
}, 30000);
```

**Testy:**
- Alerty się wyświetlają
- Tabela odświeża się automatycznie
- Alerty CRITICAL są czerwone

---

## [ ] ETAP 5: Testing & Validation ✅

> **Priorytet:** OBOWIĄZKOWY  
> **Cel:** Potwierdzenie poprawności implementacji

---

### [ ] 5.1 Test logowania

**Scenariusze:**

| Test | Dane | Oczekiwany wynik |
|------|------|------------------|
| Poprawne logowanie | admin / haslo123 | Redirect do /config |
| Złe hasło | admin / zle | Flash "Nieprawidłowy login lub hasło" |
| Nieistniejący user | haker / cokolwiek | Flash "Nieprawidłowy login lub hasło" |
| Dostęp do /config bez logowania | - | Redirect do /login |
| API bez logowania | curl /api/hosts | 401 lub redirect |

**Jak przygotować użytkownika testowego:**
```python
# W Flask shell:
from app import create_app, db
from app.models import User

app = create_app()
with app.app_context():
    u = User(username='admin')
    u.set_password('haslo123')
    db.session.add(u)
    db.session.commit()
    print("Utworzono użytkownika admin")
```

---

### [ ] 5.2 Test pobierania logów

**Scenariusze:**

| Test | Warunek | Oczekiwany wynik |
|------|---------|------------------|
| Linux host | SSH działa | Pliki .parquet w storage/ |
| Windows host | PowerShell działa | Pliki .parquet w storage/ |
| Brak połączenia | Host offline | Graceful error, nie crash |

**Sprawdzenie:**
```bash
# Po wywołaniu fetch_logs:
dir storage\
# Powinny być pliki: logs_1_20260111_*.parquet

# Sprawdzenie zawartości:
python -c "import pandas as pd; print(pd.read_parquet('storage/logs_1_20260111_142637.parquet').head())"
```

---

### [ ] 5.3 Test detekcji zagrożeń

**Scenariusze:**

| Test | Warunek | Oczekiwany wynik |
|------|---------|------------------|
| Failed login z nowego IP | IP nie w bazie | Alert WARNING + IP dodane jako UNKNOWN |
| Failed login z banned IP | IP w bazie jako BANNED | Alert CRITICAL |
| Failed login z trusted IP | IP w bazie jako TRUSTED | Brak alertu |

**Sprawdzenie:**
```python
# W Flask shell:
from app.models import Alert, IPRegistry

# Sprawdź alerty:
for a in Alert.query.order_by(Alert.timestamp.desc()).limit(5):
    print(f"{a.severity}: {a.source_ip} - {a.message}")

# Sprawdź IP registry:
for ip in IPRegistry.query.all():
    print(f"{ip.ip_address}: {ip.status}")
```

---

## 📊 Podsumowanie

| Etap | Pliki do modyfikacji | Szacowany czas |
|------|---------------------|----------------|
| **ETAP 1** | models.py, auth.py, ui.py, api/hosts.py, login.html | 1-2h |
| **ETAP 2** | api/hosts.py | 1-2h |
| **ETAP 3** | log_analyzer.py, api/hosts.py | 1-2h |
| **ETAP 4** | config.html, admin.js, api.js, dashboard.js | 1-2h |
| **ETAP 5** | - (tylko testy) | 30min |

**Całkowity szacowany czas:** 5-8 godzin

---

## ⚠️ Checklisty przed oddaniem

- [ ] Hasła są hashowane (`generate_password_hash`)
- [ ] Hasła są weryfikowane (`check_password_hash`)
- [ ] `/config` wymaga logowania
- [ ] Wszystkie endpointy API mają `@login_required`
- [ ] Logi zapisują się do Parquet przed analizą
- [ ] Alerty tworzą się w bazie
- [ ] IP Registry się aktualizuje
- [ ] Frontend nie pokazuje "ciszy" przy błędach API
- [ ] Komunikaty błędów logowania są ogólne

---

*ROADMAP wygenerowany na podstawie ANALIZA_PROJEKTU.md*
