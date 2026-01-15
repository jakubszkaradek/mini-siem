# 📚 Nauka Zmian w Projekcie Mini-SIEM

**Autor:** Wygenerowane przez Claude AI  
**Data:** Styczeń 2026  
**Cel:** Po przeczytaniu tego dokumentu zrozumiesz każdą linię kodu w projekcie jak profesjonalista.

---

## 📋 Spis Treści

1. [Wprowadzenie](#wprowadzenie)
2. [Backend - Python/Flask](#backend---pythonflask)
   - [models.py - Modele bazy danych](#modelespy---modele-bazy-danych)
   - [auth.py - Logowanie użytkownika](#authpy---logowanie-uzytkownika)
   - [ui.py - Ochrona stron](#uipy---ochrona-stron)
   - [hosts.py - Główne API](#hostspy---glowne-api)
   - [log_analyzer.py - Serce SIEM](#log_analyzerpy---serce-siem)
3. [Frontend - JavaScript](#frontend---javascript)
   - [api.js - Komunikacja z backendem](#apijs---komunikacja-z-backendem)
   - [admin.js - Panel administracyjny](#adminjs---panel-administracyjny)
   - [dashboard.js - Główny widok](#dashboardjs---glowny-widok)
4. [Szablony HTML](#szablony-html)
   - [config.html - Panel konfiguracyjny](#confightml---panel-konfiguracyjny)
5. [Skrypty pomocnicze](#skrypty-pomocnicze)
   - [create_admin.py](#create_adminpy)
   - [test_detection.py](#test_detectionpy)
   - [cleanup_test_data.py](#cleanup_test_datapy)
   - [test_all_alerts.py](#test_all_alertspy)
   - [test_win_logs.py](#test_win_logspy)
6. [Konfiguracja](#konfiguracja)
   - [.env - Zmienne środowiskowe](#env---zmienne-srodowiskowe)

---

## Wprowadzenie

### Co to jest SIEM?
**SIEM** (Security Information and Event Management) to system, który:
- **Zbiera logi** z różnych hostów (Windows, Linux)
- **Analizuje** je pod kątem zagrożeń
- **Generuje alerty** gdy wykryje podejrzaną aktywność
- **Przechowuje dowody** do analizy forensycznej

### Architektura projektu
```
mini-siem/
├── app/
│   ├── blueprints/       # Endpointy (API + widoki)
│   │   ├── api/hosts.py  # REST API
│   │   ├── auth.py       # Logowanie
│   │   └── ui.py         # Strony HTML
│   ├── services/         # Logika biznesowa
│   │   ├── log_analyzer.py  # 🔥 SERCE SIEM
│   │   ├── log_collector.py
│   │   └── data_manager.py
│   ├── static/js/        # Frontend JavaScript
│   └── templates/        # Szablony HTML
├── storage/              # Pliki Parquet (logi)
└── instance/lab7.db      # Baza SQLite
```

---

## Backend - Python/Flask

---

### models.py - Modele bazy danych

**Plik:** `app/models.py`  
**Typ zmiany:** ✏️ ZMODYFIKOWANO (dodano 2 metody)

#### Co zrobiłem?
Dodałem dwie metody do klasy `User`:

```python
# PRZED (było puste - tylko pass lub TODO)
class User(UserMixin, db.Model):
    # ... pola ...
    def set_password(self, password):
        pass  # TODO
    def check_password(self, password):
        pass  # TODO

# PO (moja implementacja)
def set_password(self, password):
    """Hashuje hasło i zapisuje do password_hash."""
    self.password_hash = generate_password_hash(password)

def check_password(self, password):
    """Weryfikuje hasło przeciwko zapisanemu hashowi."""
    return check_password_hash(self.password_hash, password)
```

#### 🧠 Dlaczego to ważne?

1. **NIGDY nie przechowujemy haseł jako tekst!**
   - Gdyby baza wyciekła, atakujący nie zobaczy prawdziwych haseł
   - `generate_password_hash()` zamienia "haslo123" w coś takiego: `pbkdf2:sha256:260000$abc...xyz`

2. **Weryfikacja hasła**
   - Użytkownik wpisuje "haslo123"
   - `check_password_hash()` hashuje to samo i porównuje z przechowywanym hashem
   - Zwraca `True` lub `False`

3. **Wymagane przez prowadzącego** (patrz OCENA.md: "Hashowanie haseł (-5 punktów)")

---

### auth.py - Logowanie użytkownika

**Plik:** `app/blueprints/auth.py`  
**Typ zmiany:** ✏️ ZMODYFIKOWANO (napisano logikę logowania)

#### Przed vs Po

```python
# PRZED (pusty if)
if form.validate_on_submit():
    # TODO: implementacja logowania
    pass

# PO (moja implementacja)
if form.validate_on_submit():
    # 1. Pobierz użytkownika z bazy
    user = User.query.filter_by(username=form.username.data).first()
    
    # 2. Sprawdź czy użytkownik istnieje i hasło jest poprawne
    if user and user.check_password(form.password.data):
        login_user(user)  # Flask-Login zapisuje sesję
        flash('Zalogowano pomyślnie!', 'success')
        return redirect(url_for('ui.config'))
    else:
        # WAŻNE: Ogólny komunikat - nie zdradzamy czy login czy hasło złe
        flash('Nieprawidłowy login lub hasło.', 'danger')
```

#### 🧠 Dlaczego to ważne?

1. **Ogólny komunikat błędu** - "Nieprawidłowy login lub hasło"
   - NIE mówimy "Użytkownik nie istnieje" ani "Złe hasło"
   - Atakujący nie może zgadywać które loginy istnieją (enumeration attack)

2. **`login_user(user)`** - funkcja Flask-Login
   - Zapisuje ID użytkownika w sesji (ciasteczko)
   - Następne requesty będą pamiętać, że jesteś zalogowany

3. **OCENA.md:** "Defense in Depth" - wiele warstw zabezpieczeń

---

### ui.py - Ochrona stron

**Plik:** `app/blueprints/ui.py`  
**Typ zmiany:** ✏️ ZMODYFIKOWANO (dodano dekorator)

#### Zmiana
```python
# PRZED
@ui_bp.route('/config')
def config():
    return render_template('config.html')

# PO
@ui_bp.route('/config')
@login_required  # ← DODAŁEM TEN DEKORATOR
def config():
    return render_template('config.html')
```

#### 🧠 Dlaczego to ważne?

1. **`@login_required`** to dekorator Flask-Login
   - Bez logowania → przekierowanie do `/login`
   - Po zalogowaniu → dostęp do strony

2. **Panel admina musi być chroniony!**
   - Bez tego każdy mógłby wejść na `/config` i zarządzać hostami

3. **Dashboard (`/`) jest publiczny** - celowo
   - Pokazuje status monitoringu
   - Nie wymaga logowania do przeglądania alertów

---

### hosts.py - Główne API

**Plik:** `app/blueprints/api/hosts.py`  
**Typ zmiany:** ✏️ ZMODYFIKOWANO (implementacja endpointów)

#### Kluczowe zmiany

**1. Ochrona API dekoratorem @login_required:**
```python
@api_bp.route("/hosts/<int:host_id>/logs", methods=["POST"])
@login_required  # ← KAŻDY ENDPOINT MA TEN DEKORATOR
def fetch_logs(host_id):
    # ...
```

**2. Główna funkcja `fetch_logs()` - pobieranie i analiza logów:**

```python
def fetch_logs(host_id):
    """Pobiera logi z hosta, zapisuje do Parquet i analizuje zagrożenia."""
    host = Host.query.get_or_404(host_id)
    
    # KROK 1: Rozgałęzienie według OS
    if host.os_type == "LINUX":
        with RemoteClient(**ssh_config) as remote:
            logs = LogCollector.get_linux_logs(remote, log_source.last_fetch)
    
    elif host.os_type == "WINDOWS":
        with WinClient() as win:
            logs = LogCollector.get_windows_logs(win, log_source.last_fetch)
    
    # KROK 2: FORENSICS - Zapis do Parquet PRZED analizą
    filename, record_count = DataManager.save_logs_to_parquet(logs, host.id)
    
    # KROK 3: Aktualizacja last_fetch (przyrostowe pobieranie)
    log_source.last_fetch = datetime.now(timezone.utc)
    
    # KROK 4: Analiza zagrożeń (Threat Intelligence)
    alerts_count = LogAnalyzer.analyze_parquet(filename, host.id)
```

#### 🧠 Dlaczego to ważne?

1. **Forensics** - logi zapisywane do Parquet PRZED analizą
   - Nawet jeśli analiza się zepsuje, mamy surowe dane
   - Format Parquet: szybki, kompaktowy, obsługiwany przez Pandas

2. **Przyrostowe pobieranie** - `last_fetch`
   - Nie pobieramy tych samych logów wielokrotnie
   - Oszczędność czasu i zasobów

3. **Rozdzielenie logiki Windows/Linux**
   - Linux: SSH + journalctl
   - Windows: PowerShell + Event Log

---

### log_analyzer.py - Serce SIEM

**Plik:** `app/services/log_analyzer.py`  
**Typ zmiany:** ✏️ NAPISANO OD ZERA (cała logika Threat Intelligence)

To jest **najważniejszy plik** w projekcie! Tutaj dzieje się magia detekcji zagrożeń.

#### Pełna implementacja z wyjaśnieniami

```python
class LogAnalyzer:
    @staticmethod
    def analyze_parquet(filename, host_id):
        """Główna funkcja analityczna."""
        
        # 1. Wczytaj dane z Parquet (Pandas DataFrame)
        df = DataManager.load_logs(filename)
        
        # 2. Filtruj tylko ataki (nie wszystkie logi!)
        attack_pattern = ['FAILED_LOGIN', 'INVALID_USER', 'WIN_FAILED_LOGIN']
        threats = df[df['alert_type'].isin(attack_pattern)]
        
        # 3. Dla każdego zagrożenia...
        for index, row in threats.iterrows():
            ip = row['source_ip']
            user = row.get('user', 'unknown')
            
            # 4. Pobierz oryginalny timestamp z logu (NIE datetime.now()!)
            log_timestamp = row.get('timestamp', datetime.now(timezone.utc))
            
            # 5. Sprawdź czy to duplikat (unikaj powtórzonych alertów)
            existing_alert = Alert.query.filter_by(
                host_id=host_id,
                source_ip=ip,
                alert_type=row['alert_type']
            ).filter(
                Alert.timestamp >= log_timestamp - timedelta(seconds=5),
                Alert.timestamp <= log_timestamp + timedelta(seconds=5)
            ).first()
            
            if existing_alert:
                continue  # Pomiń - już mamy taki alert
            
            # =============================================
            # THREAT INTELLIGENCE - serce SIEM
            # =============================================
            
            # 6. Sprawdź IP w rejestrze reputacji
            ip_entry = IPRegistry.query.filter_by(ip_address=ip).first()
            
            if not ip_entry:
                # Nowe IP - dodaj ze statusem UNKNOWN
                ip_entry = IPRegistry(
                    ip_address=ip,
                    status='UNKNOWN',
                    last_seen=datetime.now(timezone.utc)
                )
                db.session.add(ip_entry)
            else:
                # Istniejące IP - aktualizuj last_seen
                ip_entry.last_seen = datetime.now(timezone.utc)
            
            # 7. Ustal severity na podstawie statusu IP
            if ip_entry.status == 'BANNED':
                severity = 'CRITICAL'
                message = f"🚨 BANNED IP {ip} próbował się zalogować jako '{user}'"
            elif ip_entry.status == 'TRUSTED':
                continue  # Zaufane IP - nie twórz alertu
            else:
                severity = 'WARNING'
                message = f"⚠️ Nieudana próba logowania z {ip} (user: {user})"
            
            # 8. Utwórz alert w bazie
            new_alert = Alert(
                host_id=host_id,
                alert_type=row['alert_type'],
                source_ip=ip,
                severity=severity,
                message=message,
                timestamp=log_timestamp  # Oryginalny czas zdarzenia!
            )
            db.session.add(new_alert)
            alerts_created += 1
        
        db.session.commit()
        return alerts_created
```

#### 🧠 Dlaczego każdy krok jest ważny?

| Krok | Co robi | Dlaczego ważne |
|------|---------|----------------|
| 2 | Filtruje ataki | Nie wszystkie logi są zagrożeniem |
| 5 | Sprawdza duplikaty | Jeden atak = jeden alert |
| 6-7 | Threat Intelligence | IP BANNED = CRITICAL, TRUSTED = brak alertu |
| 8 | Oryginalny timestamp | Pokazuje KIEDY był atak, nie kiedy go wykryliśmy |

---

## Frontend - JavaScript

---

### api.js - Komunikacja z backendem

**Plik:** `app/static/js/api.js`  
**Typ zmiany:** 🔓 ODKOMENTOWANO (funkcje były zakomentowane)

#### Co odkomentowałem?

```javascript
// === IP REGISTRY API (BYŁO ZAKOMENTOWANE) ===
export async function fetchIPs() {
    const res = await fetch('/api/ips');
    if (!res.ok) throw new Error('Błąd pobierania IP');
    return await res.json();
}

export async function createIP(data) { /* ... */ }
export async function updateIP(id, data) { /* ... */ }
export async function removeIP(id) { /* ... */ }

// === ALERTS API (BYŁO ZAKOMENTOWANE) ===
export async function fetchAlerts() {
    const res = await fetch('/api/alerts');
    if (!res.ok) throw new Error('Błąd pobierania alertów');
    return await res.json();
}
```

#### 🧠 Dlaczego?
- Funkcje były przygotowane przez autora projektu
- Wystarczyło je "włączyć" usuwając komentarze
- Komunikują się z backendem przez REST API

---

### admin.js - Panel administracyjny

**Plik:** `app/static/js/admin.js`  
**Typ zmiany:** 🔓 ODKOMENTOWANO + ✏️ ZMODYFIKOWANO

#### 1. Odkomentowane importy:
```javascript
// BYŁO:
// import { fetchIPs, createIP, updateIP, removeIP } from './api.js';

// PO:
import { fetchIPs, createIP, updateIP, removeIP } from './api.js';
```

#### 2. Odkomentowana sekcja IP Registry (cała logika)

#### 3. Usunięcie dialogu potwierdzenia usuwania:
```javascript
// PRZED (wymagało kliknięcia "OK"):
delBtn.addEventListener('click', async () => {
    if (confirm(`Usunąć hosta ${host.hostname}?`)) {
        await removeHost(host.id);
        await refreshHosts();
    }
});

// PO (usuwa od razu):
delBtn.addEventListener('click', async () => {
    await removeHost(host.id);
    await refreshHosts();
});
```

#### 🧠 Dlaczego usunąłem confirm()?
- Użytkownik prosił o szybsze usuwanie
- Dialog `confirm()` mógł się "chować" za innymi oknami
- To zmiana UX, nie bezpieczeństwa

---

### dashboard.js - Główny widok

**Plik:** `app/static/js/dashboard.js`  
**Typ zmiany:** 🔓 ODKOMENTOWANO + 🐛 NAPRAWIONO BUG

#### 1. Odkomentowane pobieranie alertów:
```javascript
// BYŁO:
// const alerts = await fetchAlerts();

// PO:
const alerts = await fetchAlerts();
```

#### 2. Naprawiony bug ze strefą czasową:
```javascript
// PRZED (błąd +1 godzina!):
const utcDate = new Date(alert.timestamp.replace(" ", "T") + "Z");
//                                                          ↑ To "Z" oznacza UTC!

// PO (poprawnie):
// Timestamp jest już czasem lokalnym - nie dodajemy 'Z' (UTC)
const localDate = new Date(alert.timestamp.replace(" ", "T"));
```

#### 🧠 Dlaczego był bug?
- Backend zwraca czas lokalny (np. 15:40)
- Dodanie `"Z"` mówi przeglądarce: "to jest UTC"
- Przeglądarka konwertuje UTC → lokalny (+1h w Polsce)
- Wynik: 16:40 zamiast 15:40

---

## Szablony HTML

---

### config.html - Panel konfiguracyjny

**Plik:** `app/templates/config.html`  
**Typ zmiany:** 🔓 ODKOMENTOWANO

#### Co odkomentowałem?
Cała sekcja "Rejestr IP (Threat Intel)" była zakomentowana:

```html
<!-- PRZED (zakomentowane) -->
<!--
<div class="card border-primary mb-3">
    <div class="card-header bg-primary text-white d-flex justify-content-between">
        <span>Rejestr IP (Threat Intel)</span>
        ...
    </div>
    ...
</div>
-->

<!-- PO (odkomentowane - działa) -->
<div class="card border-primary mb-3">
    <div class="card-header bg-primary text-white d-flex justify-content-between">
        <span>Rejestr IP (Threat Intel)</span>
        ...
    </div>
    ...
</div>
```

---

## Skrypty pomocnicze

Te pliki **napisałem od zera** do testowania i zarządzania projektem.

---

### create_admin.py

**Cel:** Utworzenie użytkownika testowego  
**Uruchomienie:** `python create_admin.py`

```python
# Sprawdza czy admin istnieje, jeśli nie - tworzy
user = User(username='admin')
user.set_password('haslo123')  # ← Używa naszej metody hashującej!
db.session.add(user)
db.session.commit()
```

**Dane logowania:** admin / haslo123

---

### test_detection.py

**Cel:** Test czy SIEM wykrywa zagrożenia  
**Uruchomienie:** `python test_detection.py`

```python
# Symuluje 3 typy ataków:
fake_logs = [
    {'alert_type': 'FAILED_LOGIN', 'source_ip': '192.168.1.100', 'user': 'hacker1'},
    {'alert_type': 'INVALID_USER', 'source_ip': '10.0.0.50', 'user': 'nieznany'},
    {'alert_type': 'WIN_FAILED_LOGIN', 'source_ip': '172.16.0.1', 'user': 'admin'},
]

# Zapisuje do Parquet i uruchamia LogAnalyzer
# Powinny powstać 3 alerty w bazie
```

---

### cleanup_test_data.py

**Cel:** Czyszczenie danych testowych  
**Uruchomienie:** `python cleanup_test_data.py`

```python
Alert.query.delete()      # Usuwa wszystkie alerty
IPRegistry.query.delete() # Usuwa wszystkie wpisy IP
LogArchive.query.delete() # Usuwa historię pobrań
shutil.rmtree('storage')  # Usuwa pliki Parquet
```

---

### test_all_alerts.py

**Cel:** Kompleksowy test wszystkich typów alertów i statusów IP  
**Uruchomienie:** `python test_all_alerts.py`

Testuje macierz:
| Alert Type | IP Status | Expected |
|------------|-----------|----------|
| FAILED_LOGIN | UNKNOWN | WARNING |
| FAILED_LOGIN | BANNED | CRITICAL |
| FAILED_LOGIN | TRUSTED | (brak) |
| ... | ... | ... |

---

### test_win_logs.py

**Cel:** Debug pobierania logów Windows  
**Uruchomienie:** `python test_win_logs.py` (wymaga Admin!)

```python
with WinClient() as wc:
    logs = LogCollector.get_windows_logs(wc, None)
    print(f'Collected {len(logs)} logs')
```

**Uwaga:** PowerShell musi działać jako Administrator aby odczytać Security Log!

---

## Konfiguracja

---

### .env - Zmienne środowiskowe

**Plik:** `.env`  
**Typ zmiany:** ✏️ ZMODYFIKOWANO

#### Moje zmiany:
```ini
# BYŁO (domyślne Vagrant):
SSH_DEFAULT_USER = "vagrant"
SSH_DEFAULT_PORT = 2222
SSH_KEY_FILE = "c:/Mirek/cyber-lab/vagrant-ok/.vagrant/..."

# PO (konfiguracja Multipass VM):
SSH_DEFAULT_USER = "ubuntu"
SSH_DEFAULT_PORT = 22
SSH_KEY_FILE = "C:/Users/kalab/.ssh/siem_vm_key"
```

#### 🧠 Dlaczego?
- Używamy Multipass zamiast Vagrant
- User w Multipass to `ubuntu`
- Port SSH to standardowy `22`
- Klucz SSH wygenerowany specjalnie dla tego projektu

---

## 🎓 Podsumowanie

### Co powinieneś teraz wiedzieć:

1. **Hashowanie haseł** - `werkzeug.security` + metody `set_password()`/`check_password()`
2. **Ochrona endpointów** - dekorator `@login_required`
3. **Ogólne komunikaty błędów** - "Nieprawidłowy login lub hasło"
4. **Forensics** - logi do Parquet PRZED analizą
5. **Threat Intelligence** - IPRegistry (TRUSTED/BANNED/UNKNOWN)
6. **Przyrostowe pobieranie** - `last_fetch` zapobiega duplikatom

### Częste pytania prowadzącego:

| Pytanie | Odpowiedź |
|---------|-----------|
| "Dlaczego ogólny komunikat błędu?" | Aby uniemożliwić enumeration attack |
| "Po co Parquet?" | Format forensyczny - szybki, kompaktowy, zawiera surowe dane |
| "Co to Threat Intelligence?" | Sprawdzanie IP w rejestrze reputacji |
| "Jak działa @login_required?" | Przekierowuje niezalogowanych do /login |

---

**Powodzenia na obronie projektu! 🚀**
