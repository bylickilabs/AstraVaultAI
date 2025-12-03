import os
import sys
import json
import base64
import hashlib
import sqlite3
from dataclasses import dataclass
from typing import Dict, Any, List, Tuple, Optional
from datetime import datetime, timezone

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from PySide6.QtCore import Qt, QTimer, QEvent, QUrl
from PySide6.QtGui import QDesktopServices, QAction, QIcon, QPixmap
from PySide6.QtWidgets import (
    QApplication,
    QMainWindow,
    QWidget,
    QVBoxLayout,
    QHBoxLayout,
    QLabel,
    QTableWidget,
    QTableWidgetItem,
    QFileDialog,
    QMessageBox,
    QComboBox,
    QToolBar,
    QStyle,
    QAbstractItemView,
    QInputDialog,
    QLineEdit,
    QDialog,
    QPushButton,
    QTextEdit,
    QGridLayout,
    QSpacerItem,
    QSizePolicy,
)


APP_NAME        = "AstraVaultAI"
APP_TITLE       = "Intelligent Encrypted Data Vault"
APP_VERSION     = "1.0.0 - FINAL"
APP_COMPANY     = "BYLICKILABS – Intelligence Systems & Communications"
APP_AUTHOR      = "Thorsten Bylicki"
GITHUB_URL      = "https://github.com/bylickilabs"

CONFIG_FILENAME     = "config.json"
CHECK_FILENAME      = "check.bin"
DATA_DIRNAME        = "data"
INDEX_FILENAME      = "index.json"
AUDIT_LOG_FILENAME  = "audit_log.json"
DB_FILENAME         = "vault_meta.db"


GITHUB_ICON_SVG = """
<svg width="20" height="20" viewBox="0 0 24 24" xmlns="http://www.w3.org/2000/svg">
  <circle cx="12" cy="12" r="11" fill="#0b0c10" stroke="#4b2cff" stroke-width="1.6"/>
  
  <path fill="#ffffff" d="M12 .5C5.7.5.5 5.7.5 12c0 5.1 3.3 9.4 7.9 10.9
    .6.1.8-.3.8-.6v-2c-3.2.7-3.9-1.4-3.9-1.4-.6-1.5-1.4-1.9-1.4-1.9
    -1.2-.9.1-.9.1-.9 1.3.1 2 .7 2.3 1 .7 1.3 2.1.9 2.6.7
    .1-.5.3-.9.5-1.1-2.6-.3-5.3-1.3-5.3-6 0-1.3.5-2.4 1.2-3.3
    -.1-.3-.5-1.5.1-3 0 0 1-.3 3.3 1.3.9-.3 1.8-.4 2.8-.4
    .9 0 1.9.1 2.8.4 2.3-1.6 3.3-1.3 3.3-1.3.6 1.5.2 2.7.1 3
    .7.9 1.2 2 1.2 3.3 0 4.8-2.7 5.6-5.3 6 .3.2.6.7.6 1.5v2.3
    c0 .3.2.7.8.6 4.6-1.5 7.9-5.8 7.9-10.9C23.5 5.7 18.3.5 12 .5z"/>
</svg>
"""


TRANSLATIONS: Dict[str, Dict[str, str]] = {
    "de": {
        "app_title_full": f"{APP_NAME} – KI-gestützter Datentresor",
        "btn_create_vault": "Tresor erstellen",
        "btn_open_vault": "Tresor öffnen",
        "btn_lock_vault": "Tresor schließen",
        "btn_add_file": "Datei hinzufügen",
        "btn_extract_file": "Datei exportieren",
        "btn_details": "Details",
        "btn_github": "GitHub",
        "btn_info": "Info",

        "label_vault_closed": "Tresor: GESCHLOSSEN",
        "label_vault_open": "Tresor: GEÖFFNET",
        "label_auto_lock_prefix": "Auto-Lock in:",
        "label_auto_lock_locked": "Auto-Lock: Tresor gesperrt",

        "col_enc_name": "Datei-ID",
        "col_logical_name": "Name",
        "col_classification": "Sensitivität",

        "classification_public": "Öffentlich",
        "classification_internal": "Intern",
        "classification_confidential": "Vertraulich",
        "classification_secret": "Streng vertraulich",

        "msg_no_vault": "Es ist noch kein Tresor vorhanden. Bitte zuerst einen Tresor erstellen.",
        "msg_select_file": "Bitte wähle eine Datei in der Liste aus.",
        "msg_vault_created_title": "Tresor erstellt",
        "msg_vault_created_text": "Der Tresor wurde erfolgreich erstellt.",
        "msg_open_vault_title": "Tresor öffnen",
        "msg_open_vault_pwd": "Bitte Master-Passwort eingeben:",
        "msg_create_vault_title": "Neuen Tresor erstellen",
        "msg_create_vault_pwd1": "Master-Passwort festlegen:",
        "msg_create_vault_pwd2": "Master-Passwort wiederholen:",
        "msg_pwd_mismatch": "Die eingegebenen Passwörter stimmen nicht überein.",
        "msg_invalid_pwd": "Das Passwort ist ungültig oder der Tresor ist beschädigt.",
        "msg_vault_opened_title": "Tresor geöffnet",
        "msg_vault_opened_text": "Der Tresor wurde erfolgreich geöffnet.",
        "msg_add_file_error": "Fehler beim Hinzufügen der Datei:",
        "msg_extract_target": "Ziel-Datei auswählen",
        "msg_vault_locked_title": "Tresor gesperrt",
        "msg_vault_locked_text": "Der Tresor wurde automatisch gesperrt (Inaktivität oder auffällige Aktivität).",
        "msg_error_title": "Fehler",
        "msg_info_title": "Informationen",

        "info_text": (
            f"{APP_NAME} {APP_VERSION}\n\n"
            f"{APP_TITLE}\n"
            f"{APP_COMPANY}\n\n"
            f"Entwickelt von {APP_AUTHOR}\n\n"
            "Sicherheits- & KI-Features:\n"
            "- AES-256-GCM (authentifizierte Verschlüsselung)\n"
            "- PBKDF2-HMAC-SHA256 Key Derivation\n"
            "- Heuristische Erkennung sensibler Inhalte\n"
            "- Anomalie-Detektion bei Datei-Exporten\n"
            "- Passwort-Stärkeanalyse (offline)\n"
            "- Integritätsprüfung via MD5/SHA1/SHA256\n"
        ),

        "language_label": "Sprache:",
        "lang_de": "Deutsch",
        "lang_en": "English",
        "status_ready": "Bereit.",
        "status_drag_drop": "Dateien per Drag & Drop hierher ziehen.",
        "status_vault_locked": "Tresor ist geschlossen.",
        "status_vault_open": "Tresor ist geöffnet.",

        "pwd_strength_weak": "Passwort-Stärke: Schwach",
        "pwd_strength_medium": "Passwort-Stärke: Mittel",
        "pwd_strength_strong": "Passwort-Stärke: Stark",
        "pwd_too_weak_title": "Schwaches Passwort",
        "pwd_too_weak_text": "Das gewählte Passwort ist sehr schwach.\nFür einen sicheren Tresor wird ein längeres, komplexeres Passwort empfohlen.",

        "ai_hint_public": "Die Datei wirkt wenig sensibel. Verschlüsselung ist optional, aber empfohlen.",
        "ai_hint_confidential": "Die Datei enthält vermutlich vertrauliche Inhalte. Verschlüsselung ist dringend empfohlen.",
        "ai_hint_secret": "Die Datei scheint hochsensible Daten zu enthalten. Exportiere sie nur in vertrauenswürdige Ziele.",

        "ai_anomaly_many_exports": "Ungewöhnlich viele Datei-Exporte in kurzer Zeit erkannt. Tresor wird vorsorglich gesperrt.",
        "ai_hint_title": "AI-Hinweis",
        "ai_anomaly_title": "AI-Anomalie",

        "details_title": "Datei- & Hash-Details",
        "details_section_file": "Datei",
        "details_section_security": "Security & AI",
        "details_section_hashes": "Hashwerte",
        "details_name": "Name:",
        "details_enc": "Verschlüsselte ID:",
        "details_class": "Klassifikation:",
        "details_score": "AI-Score:",
        "details_size": "Größe:",
        "details_added": "Hinzugefügt am:",
        "details_integrity": "Integrität:",
        "details_integrity_ok": "🟢 Gültig (Hashwerte stimmen überein)",
        "details_integrity_unknown": "⚪ Noch nicht geprüft",
        "details_integrity_fail": "🔴 FEHLER – Hashwerte abweichend",
        "details_btn_copy_md5": "MD5 kopieren",
        "details_btn_copy_sha1": "SHA-1 kopieren",
        "details_btn_copy_sha256": "SHA-256 kopieren",
        "details_btn_export_txt": "Metadaten als TXT exportieren",
        "details_btn_export_json": "Metadaten als JSON exportieren",
        "details_btn_check_integrity": "Integrität jetzt prüfen",
        "details_msg_no_hash": "Für diese Datei sind keine Hashinformationen vorhanden.",
        "details_msg_export_done": "Metadaten wurden exportiert.",
        "details_msg_integrity_ok": "Integritätsprüfung erfolgreich.",
        "details_msg_integrity_fail": "Integritätsprüfung fehlgeschlagen – Datei möglicherweise beschädigt oder manipuliert.",
        "details_msg_need_key": "Integritätsprüfung ist nur möglich, wenn der Tresor geöffnet ist.",

    },
    "en": {
        "app_title_full": f"{APP_NAME} – AI-assisted Encrypted Vault",
        "btn_create_vault": "Create Vault",
        "btn_open_vault": "Open Vault",
        "btn_lock_vault": "Lock Vault",
        "btn_add_file": "Add File",
        "btn_extract_file": "Export File",
        "btn_details": "Details",
        "btn_github": "GitHub",
        "btn_info": "Info",

        "label_vault_closed": "Vault: LOCKED",
        "label_vault_open": "Vault: UNLOCKED",
        "label_auto_lock_prefix": "Auto-lock in:",
        "label_auto_lock_locked": "Auto-lock: Vault locked",

        "col_enc_name": "File ID",
        "col_logical_name": "Name",
        "col_classification": "Sensitivity",

        "classification_public": "Public",
        "classification_internal": "Internal",
        "classification_confidential": "Confidential",
        "classification_secret": "Highly Confidential",

        "msg_no_vault": "No vault exists yet. Please create a vault first.",
        "msg_select_file": "Please select a file in the list.",
        "msg_vault_created_title": "Vault created",
        "msg_vault_created_text": "The vault has been created successfully.",
        "msg_open_vault_title": "Open Vault",
        "msg_open_vault_pwd": "Please enter the master password:",
        "msg_create_vault_title": "Create new vault",
        "msg_create_vault_pwd1": "Set master password:",
        "msg_create_vault_pwd2": "Repeat master password:",
        "msg_pwd_mismatch": "The entered passwords do not match.",
        "msg_invalid_pwd": "The password is invalid or the vault is damaged.",
        "msg_vault_opened_title": "Vault opened",
        "msg_vault_opened_text": "The vault has been opened successfully.",
        "msg_add_file_error": "Error while adding file:",
        "msg_extract_target": "Select target file",
        "msg_vault_locked_title": "Vault locked",
        "msg_vault_locked_text": "The vault has been locked automatically (inactivity or suspicious activity).",
        "msg_error_title": "Error",
        "msg_info_title": "Information",

        "info_text": (
            f"{APP_NAME} {APP_VERSION}\n\n"
            f"{APP_TITLE}\n"
            f"{APP_COMPANY}\n\n"
            f"Developed by {APP_AUTHOR}\n\n"
            "Security & AI features:\n"
            "- AES-256-GCM (authenticated encryption)\n"
            "- PBKDF2-HMAC-SHA256 key derivation\n"
            "- Heuristic detection of sensitive content\n"
            "- Anomaly detection on file exports\n"
            "- Offline password strength analysis\n"
            "- Integrity verification via MD5/SHA1/SHA256\n"
        ),

        "language_label": "Language:",
        "lang_de": "Deutsch",
        "lang_en": "English",
        "status_ready": "Ready.",
        "status_drag_drop": "Drag & drop files here.",
        "status_vault_locked": "Vault is locked.",
        "status_vault_open": "Vault is open.",

        "pwd_strength_weak": "Password strength: Weak",
        "pwd_strength_medium": "Password strength: Medium",
        "pwd_strength_strong": "Password strength: Strong",
        "pwd_too_weak_title": "Weak password",
        "pwd_too_weak_text": "The chosen password is very weak.\nFor a secure vault, a longer, more complex password is recommended.",

        "ai_hint_public": "The file does not look very sensitive. Encryption is optional but still recommended.",
        "ai_hint_confidential": "The file seems to contain confidential content. Encryption is strongly recommended.",
        "ai_hint_secret": "The file appears to contain highly sensitive data. Only export to trusted locations.",

        "ai_anomaly_many_exports": "Unusually many file exports in a short time detected. Vault will be locked as a precaution.",
        "ai_hint_title": "AI Hint",
        "ai_anomaly_title": "AI Anomaly",

        "details_title": "File & Hash Details",
        "details_section_file": "File",
        "details_section_security": "Security & AI",
        "details_section_hashes": "Hashes",
        "details_name": "Name:",
        "details_enc": "Encrypted ID:",
        "details_class": "Classification:",
        "details_score": "AI Score:",
        "details_size": "Size:",
        "details_added": "Added at:",
        "details_integrity": "Integrity:",
        "details_integrity_ok": "🟢 Valid (hash values match)",
        "details_integrity_unknown": "⚪ Not checked yet",
        "details_integrity_fail": "🔴 ERROR – hash values differ",
        "details_btn_copy_md5": "Copy MD5",
        "details_btn_copy_sha1": "Copy SHA-1",
        "details_btn_copy_sha256": "Copy SHA-256",
        "details_btn_export_txt": "Export metadata as TXT",
        "details_btn_export_json": "Export metadata as JSON",
        "details_btn_check_integrity": "Check integrity now",
        "details_msg_no_hash": "No hash information available for this file.",
        "details_msg_export_done": "Metadata exported.",
        "details_msg_integrity_ok": "Integrity check successful.",
        "details_msg_integrity_fail": "Integrity check failed – file may be damaged or tampered with.",
        "details_msg_need_key": "Integrity check is only possible while the vault is open.",
    },
}

SENSITIVE_KEYWORDS_DE = [
    "passwort", "geheim", "vertrag", "vertraulich", "kunde", "kundendaten",
    "rechnung", "iban", "kontonummer", "personalausweis", "ausweisnummer",
]
SENSITIVE_KEYWORDS_EN = [
    "password", "secret", "contract", "confidential", "customer", "credentials",
    "invoice", "iban", "account number", "passport", "id number",
]


@dataclass
class VaultConfig:
    salt: bytes
    iterations: int = 200_000
    key_length: int = 32

    @staticmethod
    def from_dict(d: Dict[str, Any]) -> "VaultConfig":
        return VaultConfig(
            salt=base64.b64decode(d["salt"]),
            iterations=d["iterations"],
            key_length=d["key_length"],
        )

    def to_dict(self) -> Dict[str, Any]:
        return {
            "salt": base64.b64encode(self.salt).decode("utf-8"),
            "iterations": self.iterations,
            "key_length": self.key_length,
        }


def derive_key(password: str, config: VaultConfig) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=config.key_length,
        salt=config.salt,
        iterations=config.iterations,
    )
    return kdf.derive(password.encode("utf-8"))


def encrypt_bytes(key: bytes, plaintext: bytes, associated_data: bytes = None) -> bytes:
    aesgcm = AESGCM(key)
    nonce = os.urandom(12)
    ct = aesgcm.encrypt(nonce, plaintext, associated_data)
    return nonce + ct


def decrypt_bytes(key: bytes, data: bytes, associated_data: bytes = None) -> bytes:
    if len(data) < 12 + 16:
        raise ValueError("Ciphertext too short")
    nonce = data[:12]
    ct = data[12:]
    aesgcm = AESGCM(key)
    return aesgcm.decrypt(nonce, ct, associated_data)


def get_data_dir(vault_path: str) -> str:
    data_dir = os.path.join(vault_path, DATA_DIRNAME)
    if not os.path.isdir(data_dir):
        os.makedirs(data_dir, exist_ok=True)
    return data_dir


def load_vault_config(vault_path: str) -> VaultConfig:
    with open(os.path.join(vault_path, CONFIG_FILENAME), "r", encoding="utf-8") as f:
        d = json.load(f)
    return VaultConfig.from_dict(d)


def compute_hashes(data: bytes) -> Dict[str, str]:
    md5 = hashlib.md5()
    sha1 = hashlib.sha1()
    sha256 = hashlib.sha256()
    md5.update(data)
    sha1.update(data)
    sha256.update(data)
    return {
        "md5": md5.hexdigest(),
        "sha1": sha1.hexdigest(),
        "sha256": sha256.hexdigest(),
    }


def get_db_path(vault_path: str) -> str:
    return os.path.join(vault_path, DB_FILENAME)


def init_db(vault_path: str) -> None:
    db_path = get_db_path(vault_path)
    conn = sqlite3.connect(db_path)
    try:
        cur = conn.cursor()
        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS files (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                enc_name TEXT UNIQUE NOT NULL,
                logical_name TEXT NOT NULL,
                md5 TEXT NOT NULL,
                sha1 TEXT NOT NULL,
                sha256 TEXT NOT NULL,
                size INTEGER NOT NULL,
                classification TEXT,
                score REAL,
                added_at TEXT NOT NULL
            )
            """
        )
        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS exports (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                enc_name TEXT NOT NULL,
                target_path TEXT NOT NULL,
                exported_at TEXT NOT NULL
            )
            """
        )
        conn.commit()
    finally:
        conn.close()


def insert_file_meta(
    vault_path: str,
    enc_name: str,
    logical_name: str,
    hashes: Dict[str, str],
    size: int,
    classification: str,
    score: float,
    added_at: str,
) -> None:
    db_path = get_db_path(vault_path)
    conn = sqlite3.connect(db_path)
    try:
        cur = conn.cursor()
        cur.execute(
            """
            INSERT OR REPLACE INTO files
            (enc_name, logical_name, md5, sha1, sha256, size,
             classification, score, added_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                enc_name,
                logical_name,
                hashes["md5"],
                hashes["sha1"],
                hashes["sha256"],
                size,
                classification,
                score,
                added_at,
            ),
        )
        conn.commit()
    finally:
        conn.close()


def get_file_meta(vault_path: str, enc_name: str) -> Optional[Dict[str, Any]]:
    db_path = get_db_path(vault_path)
    if not os.path.isfile(db_path):
        return None
    conn = sqlite3.connect(db_path)
    try:
        cur = conn.cursor()
        cur.execute(
            """
            SELECT logical_name, md5, sha1, sha256, size, classification, score, added_at
            FROM files
            WHERE enc_name = ?
            """,
            (enc_name,),
        )
        row = cur.fetchone()
        if not row:
            return None
        return {
            "logical_name": row[0],
            "md5": row[1],
            "sha1": row[2],
            "sha256": row[3],
            "size": row[4],
            "classification": row[5],
            "score": row[6],
            "added_at": row[7],
        }
    finally:
        conn.close()


def get_file_hashes_for_enc(vault_path: str, enc_name: str) -> Optional[Dict[str, str]]:
    meta = get_file_meta(vault_path, enc_name)
    if not meta:
        return None
    return {"md5": meta["md5"], "sha1": meta["sha1"], "sha256": meta["sha256"]}


def insert_export_event(vault_path: str, enc_name: str, target_path: str, ts_iso: str) -> None:
    db_path = get_db_path(vault_path)
    conn = sqlite3.connect(db_path)
    try:
        cur = conn.cursor()
        cur.execute(
            """
            INSERT INTO exports (enc_name, target_path, exported_at)
            VALUES (?, ?, ?)
            """,
            (enc_name, target_path, ts_iso),
        )
        conn.commit()
    finally:
        conn.close()


def log_event(vault_path: str, event_type: str, details: Dict[str, Any]) -> None:
    path = os.path.join(vault_path, AUDIT_LOG_FILENAME)
    try:
        if os.path.isfile(path):
            with open(path, "r", encoding="utf-8") as f:
                events = json.load(f)
        else:
            events = []
    except Exception:
        events = []

    events.append(
        {
            "ts": datetime.now(timezone.utc).isoformat(),
            "type": event_type,
            "details": details,
        }
    )

    with open(path, "w", encoding="utf-8") as f:
        json.dump(events, f, indent=4, ensure_ascii=False)


def detect_anomaly_many_exports(
    vault_path: str, window_seconds: int = 60, max_exports: int = 5
) -> bool:
    path = os.path.join(vault_path, AUDIT_LOG_FILENAME)
    if not os.path.isfile(path):
        return False
    try:
        with open(path, "r", encoding="utf-8") as f:
            events = json.load(f)
    except Exception:
        return False
    now = datetime.now(timezone.utc)
    count = 0
    for ev in reversed(events):
        if ev.get("type") != "export":
            continue
        try:
            ts = datetime.fromisoformat(ev.get("ts"))
        except Exception:
            continue
        if (now - ts).total_seconds() <= window_seconds:
            count += 1
            if count >= max_exports:
                return True
        else:
            break
    return False


def load_index(vault_path: str) -> Dict[str, Any]:
    path = os.path.join(vault_path, INDEX_FILENAME)
    if not os.path.isfile(path):
        return {}
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def save_index(vault_path: str, index: Dict[str, Any]) -> None:
    path = os.path.join(vault_path, INDEX_FILENAME)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(index, f, indent=4, ensure_ascii=False)


def analyze_file_sensitivity(path: str) -> Dict[str, Any]:
    try:
        size = os.path.getsize(path)
    except OSError:
        size = 0

    try:
        with open(path, "rb") as f:
            sample = f.read(8192)
    except Exception:
        sample = b""

    try:
        text = sample.decode("utf-8", errors="ignore").lower()
    except Exception:
        text = ""

    score = 0.0
    tags: List[str] = []

    if "@" in text:
        score += 0.15
        tags.append("email_like")

    keywords = SENSITIVE_KEYWORDS_DE + SENSITIVE_KEYWORDS_EN
    hits = [kw for kw in keywords if kw in text]
    if hits:
        score += 0.2 + 0.05 * min(len(hits), 5)
        tags.extend(f"kw:{h}" for h in hits)

    if "iban" in text:
        score += 0.25
        tags.append("iban")

    fn = os.path.basename(path).lower()
    if any(
        word in fn
        for word in ["vertrag", "contract", "login", "credential", "passwort", "password"]
    ):
        score += 0.2
        tags.append("name_sensitive")

    if size > 5 * 1024 * 1024:
        score -= 0.05

    score = max(0.0, min(score, 1.0))

    if score < 0.2:
        classification = "public"
    elif score < 0.45:
        classification = "internal"
    elif score < 0.75:
        classification = "confidential"
    else:
        classification = "secret"

    return {
        "score": score,
        "classification": classification,
        "tags": tags,
        "size": size,
    }


def classification_label(lang: str, classification: str) -> str:
    tr = TRANSLATIONS.get(lang, TRANSLATIONS["de"])
    mapping = {
        "public": tr["classification_public"],
        "internal": tr["classification_internal"],
        "confidential": tr["classification_confidential"],
        "secret": tr["classification_secret"],
    }
    return mapping.get(classification, classification)


def classification_ai_hint(lang: str, classification: str) -> Optional[str]:
    tr = TRANSLATIONS.get(lang, TRANSLATIONS["de"])
    if classification == "public":
        return tr["ai_hint_public"]
    if classification == "confidential":
        return tr["ai_hint_confidential"]
    if classification == "secret":
        return tr["ai_hint_secret"]
    return None


def estimate_password_strength(password: str) -> int:
    if not password:
        return 0
    length = len(password)
    score = length * 4

    classes = 0
    if any(c.islower() for c in password):
        classes += 1
    if any(c.isupper() for c in password):
        classes += 1
    if any(c.isdigit() for c in password):
        classes += 1
    if any(not c.isalnum() for c in password):
        classes += 1
    score += (classes - 1) * 10

    common = ["password", "passwort", "1234", "admin", "qwerty"]
    lower = password.lower()
    if any(c in lower for c in common):
        score -= 30

    return max(0, min(score, 100))


def password_strength_label(lang: str, score: int) -> str:
    tr = TRANSLATIONS.get(lang, TRANSLATIONS["de"])
    if score < 40:
        return tr["pwd_strength_weak"]
    elif score < 75:
        return tr["pwd_strength_medium"]
    else:
        return tr["pwd_strength_strong"]


def init_vault(vault_path: str, password: str, password_repeat: str) -> None:
    if password != password_repeat:
        raise ValueError("Passwords do not match.")

    if not os.path.exists(vault_path):
        os.makedirs(vault_path)
    else:
        if os.listdir(vault_path):
            raise RuntimeError(f"Vault directory '{vault_path}' is not empty.")

    data_dir = get_data_dir(vault_path)

    salt = os.urandom(16)
    cfg = VaultConfig(salt=salt)
    key = derive_key(password, cfg)

    check_plain = b"SECURE_CONTAINER_CHECK_V1"
    encrypted_check = encrypt_bytes(key, check_plain)

    with open(os.path.join(vault_path, CONFIG_FILENAME), "w", encoding="utf-8") as f:
        json.dump(cfg.to_dict(), f, indent=4)

    with open(os.path.join(vault_path, CHECK_FILENAME), "wb") as f:
        f.write(encrypted_check)

    with open(os.path.join(vault_path, INDEX_FILENAME), "w", encoding="utf-8") as f:
        json.dump({}, f, indent=4, ensure_ascii=False)

    with open(os.path.join(vault_path, AUDIT_LOG_FILENAME), "w", encoding="utf-8") as f:
        json.dump([], f, indent=4, ensure_ascii=False)

    init_db(vault_path)
    _ = data_dir


def verify_password(vault_path: str, password: str) -> bytes:
    cfg = load_vault_config(vault_path)
    key = derive_key(password, cfg)
    with open(os.path.join(vault_path, CHECK_FILENAME), "rb") as f:
        enc = f.read()
    plain = decrypt_bytes(key, enc)
    if plain != b"SECURE_CONTAINER_CHECK_V1":
        raise RuntimeError("Password verification failed.")
    return key


def add_file_to_vault(
    vault_path: str, key: bytes, source_file: str, language: str
) -> str:
    init_db(vault_path)

    data_dir = get_data_dir(vault_path)
    if not os.path.isfile(source_file):
        raise RuntimeError(f"Source file '{source_file}' does not exist.")

    with open(source_file, "rb") as f:
        plain = f.read()

    hashes = compute_hashes(plain)
    size = len(plain)

    enc = encrypt_bytes(key, plain)

    existing = [f for f in os.listdir(data_dir) if f.endswith(".enc")]
    next_id = len(existing) + 1
    enc_name = f"{next_id:04d}.enc"
    enc_path = os.path.join(data_dir, enc_name)
    with open(enc_path, "wb") as f:
        f.write(enc)

    analysis = analyze_file_sensitivity(source_file)
    logical_name = os.path.basename(source_file)
    added_at = datetime.now(timezone.utc).isoformat()

    index = load_index(vault_path)
    entry = {
        "enc": enc_name,
        "classification": analysis["classification"],
        "score": analysis["score"],
        "tags": analysis["tags"],
        "added_at": added_at,
    }
    index[logical_name] = entry
    save_index(vault_path, index)

    insert_file_meta(
        vault_path=vault_path,
        enc_name=enc_name,
        logical_name=logical_name,
        hashes=hashes,
        size=size,
        classification=analysis["classification"],
        score=analysis["score"],
        added_at=added_at,
    )

    log_event(
        vault_path,
        "add",
        {
            "enc": enc_name,
            "logical_name": logical_name,
            "classification": analysis["classification"],
        },
    )

    return enc_name


def list_vault_entries(vault_path: str) -> List[Tuple[str, str, str]]:
    data_dir = get_data_dir(vault_path)
    index = load_index(vault_path)
    reverse: Dict[str, Dict[str, Any]] = {}
    for logical, value in index.items():
        if isinstance(value, str):
            enc = value
            classification = "public"
        elif isinstance(value, dict):
            enc = value.get("enc")
            classification = value.get("classification", "public")
        else:
            continue
        if not enc:
            continue
        info = reverse.setdefault(enc, {"names": [], "classification": classification})
        info["names"].append(logical)

    files = sorted(f for f in os.listdir(data_dir) if f.endswith(".enc"))
    result: List[Tuple[str, str, str]] = []
    for fname in files:
        info = reverse.get(fname, {"names": [], "classification": "public"})
        logical_name = ", ".join(info["names"]) if info["names"] else ""
        classification = info["classification"]
        result.append((fname, logical_name, classification))
    return result


def extract_file_from_vault(
    vault_path: str, key: bytes, enc_name: str, target_path: str
) -> None:
    init_db(vault_path)

    data_dir = get_data_dir(vault_path)
    enc_path = os.path.join(data_dir, enc_name)
    if not os.path.isfile(enc_path):
        raise RuntimeError(f"Encrypted file '{enc_name}' does not exist.")

    with open(enc_path, "rb") as f:
        enc = f.read()
    plain = decrypt_bytes(key, enc)

    ref_hashes = get_file_hashes_for_enc(vault_path, enc_name)
    if ref_hashes is not None:
        current = compute_hashes(plain)
        if (
            current["md5"] != ref_hashes["md5"]
            or current["sha1"] != ref_hashes["sha1"]
            or current["sha256"] != ref_hashes["sha256"]
        ):
            raise RuntimeError(
                "Integritätsprüfung fehlgeschlagen – Hashwerte stimmen nicht überein."
            )

    with open(target_path, "wb") as f:
        f.write(plain)

    ts_iso = datetime.now(timezone.utc).isoformat()
    insert_export_event(vault_path, enc_name, target_path, ts_iso)
    log_event(vault_path, "export", {"enc": enc_name, "target": target_path})


class HashDetailsDialog(QDialog):
    def __init__(
        self,
        parent: QWidget,
        language: str,
        vault_path: str,
        enc_name: str,
        key: Optional[bytes],
    ):
        super().__init__(parent)
        self.language = language
        self.vault_path = vault_path
        self.enc_name = enc_name
        self.key = key
        self.meta = get_file_meta(vault_path, enc_name)
        self.integrity_state = "unknown"  # "unknown" | "ok" | "fail"

        self.setWindowTitle(self.t("details_title"))
        self.resize(650, 450)
        self.setModal(True)
        self._build_ui()
        self._apply_theme()
        self._populate_fields()

    def t(self, key: str) -> str:
        return TRANSLATIONS.get(self.language, TRANSLATIONS["de"]).get(key, key)

    def _build_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(12, 12, 12, 12)
        layout.setSpacing(10)

        title_label = QLabel(self.t("details_title"), self)
        title_label.setStyleSheet("font-size: 14pt; font-weight: bold;")
        layout.addWidget(title_label)

        grid = QGridLayout()
        grid.setHorizontalSpacing(10)
        grid.setVerticalSpacing(6)

        row = 0
        section_file = QLabel(self.t("details_section_file"), self)
        section_file.setStyleSheet("font-weight: bold;")
        grid.addWidget(section_file, row, 0, 1, 4)
        row += 1

        self.lbl_name = QLabel(self)
        self.lbl_enc = QLabel(self)
        self.lbl_size = QLabel(self)
        self.lbl_added = QLabel(self)

        grid.addWidget(QLabel(self.t("details_name"), self), row, 0)
        grid.addWidget(self.lbl_name, row, 1, 1, 3)
        row += 1

        grid.addWidget(QLabel(self.t("details_enc"), self), row, 0)
        grid.addWidget(self.lbl_enc, row, 1, 1, 3)
        row += 1

        grid.addWidget(QLabel(self.t("details_size"), self), row, 0)
        grid.addWidget(self.lbl_size, row, 1, 1, 3)
        row += 1

        grid.addWidget(QLabel(self.t("details_added"), self), row, 0)
        grid.addWidget(self.lbl_added, row, 1, 1, 3)
        row += 1

        row += 1
        section_sec = QLabel(self.t("details_section_security"), self)
        section_sec.setStyleSheet("font-weight: bold;")
        grid.addWidget(section_sec, row, 0, 1, 4)
        row += 1

        self.lbl_class = QLabel(self)
        self.lbl_score = QLabel(self)
        self.lbl_integrity = QLabel(self)

        grid.addWidget(QLabel(self.t("details_class"), self), row, 0)
        grid.addWidget(self.lbl_class, row, 1, 1, 3)
        row += 1

        grid.addWidget(QLabel(self.t("details_score"), self), row, 0)
        grid.addWidget(self.lbl_score, row, 1, 1, 3)
        row += 1

        grid.addWidget(QLabel(self.t("details_integrity"), self), row, 0)
        grid.addWidget(self.lbl_integrity, row, 1, 1, 3)
        row += 1

        row += 1
        section_hash = QLabel(self.t("details_section_hashes"), self)
        section_hash.setStyleSheet("font-weight: bold;")
        grid.addWidget(section_hash, row, 0, 1, 4)
        row += 1

        self.txt_md5 = QLineEdit(self)
        self.txt_sha1 = QLineEdit(self)
        self.txt_sha256 = QLineEdit(self)
        for w in (self.txt_md5, self.txt_sha1, self.txt_sha256):
            w.setReadOnly(True)

        self.btn_copy_md5 = QPushButton(self.t("details_btn_copy_md5"), self)
        self.btn_copy_sha1 = QPushButton(self.t("details_btn_copy_sha1"), self)
        self.btn_copy_sha256 = QPushButton(self.t("details_btn_copy_sha256"), self)

        self.btn_copy_md5.clicked.connect(lambda: self._copy_to_clipboard(self.txt_md5.text()))
        self.btn_copy_sha1.clicked.connect(lambda: self._copy_to_clipboard(self.txt_sha1.text()))
        self.btn_copy_sha256.clicked.connect(lambda: self._copy_to_clipboard(self.txt_sha256.text()))

        grid.addWidget(QLabel("MD5:", self), row, 0)
        grid.addWidget(self.txt_md5, row, 1, 1, 2)
        grid.addWidget(self.btn_copy_md5, row, 3)
        row += 1

        grid.addWidget(QLabel("SHA-1:", self), row, 0)
        grid.addWidget(self.txt_sha1, row, 1, 1, 2)
        grid.addWidget(self.btn_copy_sha1, row, 3)
        row += 1

        grid.addWidget(QLabel("SHA-256:", self), row, 0)
        grid.addWidget(self.txt_sha256, row, 1, 1, 2)
        grid.addWidget(self.btn_copy_sha256, row, 3)
        row += 1

        layout.addLayout(grid)

        layout.addItem(QSpacerItem(0, 10, QSizePolicy.Minimum, QSizePolicy.Expanding))

        btn_bar = QHBoxLayout()
        btn_bar.addStretch(1)

        self.btn_check_integrity = QPushButton(self.t("details_btn_check_integrity"), self)
        self.btn_export_txt = QPushButton(self.t("details_btn_export_txt"), self)
        self.btn_export_json = QPushButton(self.t("details_btn_export_json"), self)
        self.btn_close = QPushButton("Close" if self.language == "en" else "Schließen", self)

        self.btn_check_integrity.clicked.connect(self._on_check_integrity)
        self.btn_export_txt.clicked.connect(self._on_export_txt)
        self.btn_export_json.clicked.connect(self._on_export_json)
        self.btn_close.clicked.connect(self.accept)

        btn_bar.addWidget(self.btn_check_integrity)
        btn_bar.addWidget(self.btn_export_txt)
        btn_bar.addWidget(self.btn_export_json)
        btn_bar.addWidget(self.btn_close)

        layout.addLayout(btn_bar)

    def _apply_theme(self):
        self.setStyleSheet("""
            QDialog {
                background-color: #0b0c10;
                color: #e5e5e5;
            }
            QLabel {
                background-color: transparent;
            }
            QLineEdit {
                background-color: #11131c;
                border-radius: 4px;
                padding: 4px 6px;
                border: 1px solid #242849;
            }
            QPushButton {
                background-color: #171a26;
                border-radius: 6px;
                padding: 6px 12px;
                border: 1px solid #4b2cff;
            }
            QPushButton:hover {
                background-color: #242849;
            }
        """)

    def _populate_fields(self):
        if not self.meta:
            self.lbl_name.setText("-")
            self.lbl_enc.setText(self.enc_name)
            self.lbl_size.setText("-")
            self.lbl_added.setText("-")
            self.lbl_class.setText("-")
            self.lbl_score.setText("-")
            self.lbl_integrity.setText(self.t("details_integrity_unknown"))
            self.txt_md5.setText("")
            self.txt_sha1.setText("")
            self.txt_sha256.setText("")
            return

        self.lbl_name.setText(self.meta["logical_name"])
        self.lbl_enc.setText(self.enc_name)
        self.lbl_size.setText(f"{self.meta['size']} bytes")
        self.lbl_added.setText(self.meta["added_at"])

        clabel = classification_label(self.language, self.meta.get("classification", "public"))
        self.lbl_class.setText(clabel)

        score = self.meta.get("score")
        if score is None:
            self.lbl_score.setText("-")
        else:
            self.lbl_score.setText(f"{score:.2f}")

        self.lbl_integrity.setText(self.t("details_integrity_unknown"))
        self.txt_md5.setText(self.meta["md5"])
        self.txt_sha1.setText(self.meta["sha1"])
        self.txt_sha256.setText(self.meta["sha256"])

    def _copy_to_clipboard(self, value: str):
        if not value:
            return
        QApplication.clipboard().setText(value)

    def _export_metadata(self) -> Dict[str, Any]:
        return {
            "enc_name": self.enc_name,
            "logical_name": self.meta["logical_name"] if self.meta else None,
            "size": self.meta["size"] if self.meta else None,
            "classification": self.meta["classification"] if self.meta else None,
            "score": self.meta["score"] if self.meta else None,
            "added_at": self.meta["added_at"] if self.meta else None,
            "md5": self.meta["md5"] if self.meta else None,
            "sha1": self.meta["sha1"] if self.meta else None,
            "sha256": self.meta["sha256"] if self.meta else None,
            "integrity_state": self.integrity_state,
        }

    def _on_export_txt(self):
        if not self.meta:
            QMessageBox.information(self, self.t("msg_info_title"), self.t("details_msg_no_hash"))
            return
        meta = self._export_metadata()
        default_name = f"{meta['logical_name'] or self.enc_name}_meta.txt"
        path, _ = QFileDialog.getSaveFileName(
            self,
            self.t("details_btn_export_txt"),
            default_name,
            "Text Files (*.txt);;All Files (*.*)",
        )
        if not path:
            return
        lines = [
            f"Name: {meta['logical_name']}",
            f"Encrypted ID: {meta['enc_name']}",
            f"Size: {meta['size']} bytes",
            f"Classification: {meta['classification']}",
            f"AI Score: {meta['score']}",
            f"Added at: {meta['added_at']}",
            f"Integrity state: {meta['integrity_state']}",
            "",
            f"MD5: {meta['md5']}",
            f"SHA-1: {meta['sha1']}",
            f"SHA-256: {meta['sha256']}",
            "",
        ]
        with open(path, "w", encoding="utf-8") as f:
            f.write("\n".join(lines))
        QMessageBox.information(self, self.t("msg_info_title"), self.t("details_msg_export_done"))

    def _on_export_json(self):
        if not self.meta:
            QMessageBox.information(self, self.t("msg_info_title"), self.t("details_msg_no_hash"))
            return
        meta = self._export_metadata()
        default_name = f"{meta['logical_name'] or self.enc_name}_meta.json"
        path, _ = QFileDialog.getSaveFileName(
            self,
            self.t("details_btn_export_json"),
            default_name,
            "JSON Files (*.json);;All Files (*.*)",
        )
        if not path:
            return
        with open(path, "w", encoding="utf-8") as f:
            json.dump(meta, f, indent=4, ensure_ascii=False)
        QMessageBox.information(self, self.t("msg_info_title"), self.t("details_msg_export_done"))

    def _on_check_integrity(self):
        if self.key is None:
            QMessageBox.information(self, self.t("msg_info_title"), self.t("details_msg_need_key"))
            return
        data_dir = get_data_dir(self.vault_path)
        enc_path = os.path.join(data_dir, self.enc_name)
        if not os.path.isfile(enc_path):
            QMessageBox.critical(self, self.t("msg_error_title"), f"{self.enc_name} not found.")
            self.integrity_state = "fail"
            self.lbl_integrity.setText(self.t("details_integrity_fail"))
            return
        with open(enc_path, "rb") as f:
            enc = f.read()
        try:
            plain = decrypt_bytes(self.key, enc)
        except Exception:
            self.integrity_state = "fail"
            self.lbl_integrity.setText(self.t("details_integrity_fail"))
            QMessageBox.critical(
                self, self.t("msg_error_title"), self.t("details_msg_integrity_fail")
            )
            return
        current = compute_hashes(plain)
        ref = get_file_hashes_for_enc(self.vault_path, self.enc_name)
        if not ref:
            QMessageBox.information(self, self.t("msg_info_title"), self.t("details_msg_no_hash"))
            return
        if (
            current["md5"] == ref["md5"]
            and current["sha1"] == ref["sha1"]
            and current["sha256"] == ref["sha256"]
        ):
            self.integrity_state = "ok"
            self.lbl_integrity.setText(self.t("details_integrity_ok"))
            QMessageBox.information(
                self, self.t("msg_info_title"), self.t("details_msg_integrity_ok")
            )
        else:
            self.integrity_state = "fail"
            self.lbl_integrity.setText(self.t("details_integrity_fail"))
            QMessageBox.critical(
                self, self.t("msg_error_title"), self.t("details_msg_integrity_fail")
            )


class SecureContainerWindow(QMainWindow):
    def __init__(self):
        super().__init__()

        self.vault_path = os.path.join(os.getcwd(), "AstraVaultAI_Vault")
        self.key: Optional[bytes] = None
        self.language = self.load_language()

        self.idle_timeout_secs = 300
        self.seconds_since_activity = 0

        self._build_ui()
        self._apply_dark_cyberpunk_theme()
        self._install_activity_filter()

        self.timer = QTimer(self)
        self.timer.timeout.connect(self._on_timer_tick)
        self.timer.start(1000)

        self.update_vault_status(locked=True)
        self.update_auto_lock_label()
        self.set_status(self.t("status_ready"))


    def t(self, key: str) -> str:
        return TRANSLATIONS.get(self.language, TRANSLATIONS["de"]).get(key, key)

    def load_language(self) -> str:
        cfg_dir = os.path.join(os.path.expanduser("~"), f".{APP_NAME.lower()}")
        os.makedirs(cfg_dir, exist_ok=True)
        lang_file = os.path.join(cfg_dir, "settings.json")
        if os.path.isfile(lang_file):
            try:
                with open(lang_file, "r", encoding="utf-8") as f:
                    d = json.load(f)
                return d.get("language", "de")
            except Exception:
                return "de"
        return "de"

    def save_language(self):
        cfg_dir = os.path.join(os.path.expanduser("~"), f".{APP_NAME.lower()}")
        os.makedirs(cfg_dir, exist_ok=True)
        lang_file = os.path.join(cfg_dir, "settings.json")
        try:
            with open(lang_file, "w", encoding="utf-8") as f:
                json.dump({"language": self.language}, f, indent=4)
        except Exception:
            pass


    def _build_ui(self):
        self.setWindowTitle(self.t("app_title_full"))
        self.resize(1100, 700)
        self.setMinimumSize(850, 550)

        central = QWidget(self)
        main_layout = QVBoxLayout(central)
        main_layout.setContentsMargins(10, 10, 10, 10)
        main_layout.setSpacing(10)

        toolbar = QToolBar(self)
        toolbar.setMovable(False)
        self.addToolBar(Qt.TopToolBarArea, toolbar)

        self.action_create_vault = QAction(self)
        self.action_create_vault.triggered.connect(self.on_create_vault)
        toolbar.addAction(self.action_create_vault)

        self.action_open_vault = QAction(self)
        self.action_open_vault.triggered.connect(self.on_open_vault)
        toolbar.addAction(self.action_open_vault)

        self.action_lock_vault = QAction(self)
        self.action_lock_vault.triggered.connect(
            lambda: self.lock_vault(auto=False, reason="manual")
        )
        toolbar.addAction(self.action_lock_vault)

        toolbar.addSeparator()

        self.action_add_file = QAction(self)
        self.action_add_file.triggered.connect(self.on_add_file)
        toolbar.addAction(self.action_add_file)

        self.action_extract_file = QAction(self)
        self.action_extract_file.triggered.connect(self.on_extract_file)
        toolbar.addAction(self.action_extract_file)

        self.action_details = QAction(self)
        self.action_details.triggered.connect(self.on_show_details)
        toolbar.addAction(self.action_details)

        toolbar.addSeparator()

        self.action_github = QAction(self)
        self.action_github.triggered.connect(self.on_open_github)
        toolbar.addAction(self.action_github)

        self.action_info = QAction(self)
        self.action_info.triggered.connect(self.on_show_info)
        toolbar.addAction(self.action_info)

        toolbar.addSeparator()

        self.label_language = QLabel(self)
        toolbar.addWidget(self.label_language)

        self.language_combo = QComboBox(self)
        self.language_combo.addItem("Deutsch", "de")
        self.language_combo.addItem("English", "en")
        idx = 0 if self.language == "de" else 1
        self.language_combo.setCurrentIndex(idx)
        self.language_combo.currentIndexChanged.connect(self.on_language_changed)
        toolbar.addWidget(self.language_combo)

        toolbar.addSeparator()

        self.auto_lock_label = QLabel(self)
        toolbar.addWidget(self.auto_lock_label)

        status_layout = QHBoxLayout()
        self.vault_status_label = QLabel(self)
        self.vault_status_label.setObjectName("VaultStatusLabel")
        status_layout.addWidget(self.vault_status_label)
        status_layout.addStretch(1)
        main_layout.addLayout(status_layout)

        self.table = QTableWidget(self)
        self.table.setColumnCount(3)
        self.table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.table.setSelectionMode(QAbstractItemView.SingleSelection)
        self.table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.table.setAcceptDrops(True)
        self.table.setDragDropMode(QAbstractItemView.DropOnly)
        self.table.viewport().setAcceptDrops(True)
        self.table.setShowGrid(False)
        self.table.setAlternatingRowColors(True)

        self.table.dragEnterEvent = self._drag_enter_event
        self.table.dragMoveEvent = self._drag_move_event
        self.table.dropEvent = self._drop_event

        self.table.itemDoubleClicked.connect(self.on_show_details)

        main_layout.addWidget(self.table)

        self.status_label = QLabel(self)
        main_layout.addWidget(self.status_label)

        self.setCentralWidget(central)
        self.retranslate_ui()

        style = self.style()
        self.action_create_vault.setIcon(style.standardIcon(QStyle.SP_DialogSaveButton))
        self.action_open_vault.setIcon(style.standardIcon(QStyle.SP_DialogOpenButton))
        self.action_lock_vault.setIcon(style.standardIcon(QStyle.SP_DialogCancelButton))
        self.action_add_file.setIcon(style.standardIcon(QStyle.SP_FileDialogNewFolder))
        self.action_extract_file.setIcon(style.standardIcon(QStyle.SP_DialogOpenButton))


        pix = QPixmap()
        pix.loadFromData(GITHUB_ICON_SVG.encode(), "SVG")
        self.action_github.setIcon(QIcon(pix))


        self.action_info.setIcon(style.standardIcon(QStyle.SP_MessageBoxInformation))

        self.action_add_file.setEnabled(False)
        self.action_extract_file.setEnabled(False)
        self.action_lock_vault.setEnabled(False)
        self.action_details.setEnabled(False)

    def retranslate_ui(self):
        self.setWindowTitle(self.t("app_title_full"))
        self.action_create_vault.setText(self.t("btn_create_vault"))
        self.action_open_vault.setText(self.t("btn_open_vault"))
        self.action_lock_vault.setText(self.t("btn_lock_vault"))
        self.action_add_file.setText(self.t("btn_add_file"))
        self.action_extract_file.setText(self.t("btn_extract_file"))
        self.action_details.setText(self.t("btn_details"))
        self.action_github.setText(self.t("btn_github"))
        self.action_info.setText(self.t("btn_info"))

        self.label_language.setText(self.t("language_label") + " ")
        self.table.setHorizontalHeaderLabels(
            [
                self.t("col_enc_name"),
                self.t("col_logical_name"),
                self.t("col_classification"),
            ]
        )

        self.language_combo.setItemText(0, self.t("lang_de"))
        self.language_combo.setItemText(1, self.t("lang_en"))

        self.update_vault_status(self.key is None)
        self.update_auto_lock_label()
        self.set_status(self.t("status_drag_drop"))



    def _apply_dark_cyberpunk_theme(self):
        self.setStyleSheet("""
            QMainWindow {
                background-color: #0b0c10;
            }
            QWidget {
                color: #e5e5e5;
                background-color: #0b0c10;
                font-family: "Segoe UI", "Roboto", sans-serif;
                font-size: 10pt;
            }
            QToolBar {
                background: #0f111a;
                spacing: 8px;
                padding: 6px;
                border-bottom: 1px solid #242849;
            }
            QToolBar QToolButton {
                background-color: #171a26;
                border-radius: 6px;
                padding: 6px 10px;
            }
            QToolBar QToolButton:hover {
                background-color: #242849;
            }
            QLabel#VaultStatusLabel {
                font-weight: bold;
            }
            QTableWidget {
                background-color: #11131c;
                gridline-color: #1f2233;
                border: 1px solid #242849;
                border-radius: 8px;
            }
            QHeaderView::section {
                background-color: #151728;
                color: #e5e5e5;
                padding: 4px;
                border: none;
                border-bottom: 1px solid #242849;
            }
            QTableWidget::item:selected {
                background-color: #4b2cff;
            }
            QComboBox {
                background-color: #171a26;
                border: 1px solid #4b2cff;
                border-radius: 6px;
                padding: 2px 6px;
            }
            QComboBox QAbstractItemView {
                background-color: #11131c;
                selection-background-color: #4b2cff;
            }
            QLabel {
                background-color: transparent;
            }
            QMessageBox {
                background-color: #0b0c10;
            }
            QPushButton {
                background-color: #171a26;
                border-radius: 6px;
                padding: 6px 12px;
                border: 1px solid #4b2cff;
            }
            QPushButton:hover {
                background-color: #242849;
            }
        """)

    def _install_activity_filter(self):
        QApplication.instance().installEventFilter(self)

    def eventFilter(self, obj, event):
        if event.type() in (
            QEvent.MouseMove,
            QEvent.MouseButtonPress,
            QEvent.KeyPress,
            QEvent.Wheel,
        ):
            self.register_activity()
        return super().eventFilter(obj, event)

    def register_activity(self):
        self.seconds_since_activity = 0
        self.update_auto_lock_label()

    def _on_timer_tick(self):
        if self.key is None:
            return
        self.seconds_since_activity += 1
        remaining = max(self.idle_timeout_secs - self.seconds_since_activity, 0)
        if remaining <= 0:
            self.lock_vault(auto=True, reason="idle")
        else:
            self.update_auto_lock_label()

    def update_auto_lock_label(self):
        if self.key is None:
            self.auto_lock_label.setText(self.t("label_auto_lock_locked"))
        else:
            remaining = max(self.idle_timeout_secs - self.seconds_since_activity, 0)
            self.auto_lock_label.setText(
                f"{self.t('label_auto_lock_prefix')} {remaining}s"
            )

    def lock_vault(self, auto: bool = False, reason: str = "idle"):
        if self.key is not None:
            try:
                ba = bytearray(self.key)
                for i in range(len(ba)):
                    ba[i] = 0
            except Exception:
                pass
        self.key = None
        self.seconds_since_activity = 0
        self.update_vault_status(locked=True)
        self.update_auto_lock_label()
        self.table.setRowCount(0)
        self.action_add_file.setEnabled(False)
        self.action_extract_file.setEnabled(False)
        self.action_lock_vault.setEnabled(False)
        self.action_details.setEnabled(False)
        self.set_status(self.t("status_vault_locked"))
        if auto:
            QMessageBox.information(
                self,
                self.t("msg_vault_locked_title"),
                self.t("msg_vault_locked_text"),
            )


    def update_vault_status(self, locked: bool):
        if locked:
            self.vault_status_label.setText(self.t("label_vault_closed"))
            self.vault_status_label.setStyleSheet("color: #ff4b81;")
        else:
            self.vault_status_label.setText(self.t("label_vault_open"))
            self.vault_status_label.setStyleSheet("color: #4bffb5;")

    def set_status(self, text: str):
        self.status_label.setText(text)

    def refresh_table(self):
        if self.key is None:
            self.table.setRowCount(0)
            return
        try:
            entries = list_vault_entries(self.vault_path)
        except Exception as e:
            self.table.setRowCount(0)
            self.set_status(f"Error: {e}")
            return
        self.table.setRowCount(len(entries))
        for row, (enc_name, logical_name, classification) in enumerate(entries):
            self.table.setItem(row, 0, QTableWidgetItem(enc_name))
            self.table.setItem(row, 1, QTableWidgetItem(logical_name))
            item_class = QTableWidgetItem(
                classification_label(self.language, classification)
            )
            if classification == "confidential":
                item_class.setForeground(Qt.yellow)
            elif classification == "secret":
                item_class.setForeground(Qt.red)
            self.table.setItem(row, 2, item_class)
        self.table.resizeColumnsToContents()


    def _drag_enter_event(self, event):
        if event.mimeData().hasUrls() and self.key is not None:
            event.acceptProposedAction()
        else:
            event.ignore()

    def _drag_move_event(self, event):
        if event.mimeData().hasUrls() and self.key is not None:
            event.acceptProposedAction()
        else:
            event.ignore()

    def _drop_event(self, event):
        if self.key is None:
            event.ignore()
            return
        urls = event.mimeData().urls()
        paths = [u.toLocalFile() for u in urls if u.isLocalFile()]
        if not paths:
            event.ignore()
            return
        for p in paths:
            try:
                enc_name = add_file_to_vault(self.vault_path, self.key, p, self.language)
                analysis = analyze_file_sensitivity(p)
                hint = classification_ai_hint(self.language, analysis["classification"])
                if hint:
                    QMessageBox.information(self, self.t("ai_hint_title"), hint)
                self.set_status(f"Added: {os.path.basename(p)} -> {enc_name}")
            except Exception as e:
                QMessageBox.critical(
                    self,
                    self.t("msg_error_title"),
                    f"{self.t('msg_add_file_error')} {e}",
                )
        self.refresh_table()
        event.acceptProposedAction()


    def on_create_vault(self):
        pwd1, ok1 = QInputDialog.getText(
            self,
            self.t("msg_create_vault_title"),
            self.t("msg_create_vault_pwd1"),
            echo=QLineEdit.Password,
        )
        if not ok1 or not pwd1:
            return
        score = estimate_password_strength(pwd1)
        lbl = password_strength_label(self.language, score)
        QMessageBox.information(self, "Password Strength", lbl)
        if score < 40:
            QMessageBox.warning(
                self,
                self.t("pwd_too_weak_title"),
                self.t("pwd_too_weak_text"),
            )
        pwd2, ok2 = QInputDialog.getText(
            self,
            self.t("msg_create_vault_title"),
            self.t("msg_create_vault_pwd2"),
            echo=QLineEdit.Password,
        )
        if not ok2 or not pwd2:
            return
        try:
            init_vault(self.vault_path, pwd1, pwd2)
        except ValueError:
            QMessageBox.warning(
                self,
                self.t("msg_error_title"),
                self.t("msg_pwd_mismatch"),
            )
            return
        except Exception as e:
            QMessageBox.critical(self, self.t("msg_error_title"), str(e))
            return
        QMessageBox.information(
            self,
            self.t("msg_vault_created_title"),
            self.t("msg_vault_created_text"),
        )

    def on_open_vault(self):
        if not os.path.isdir(self.vault_path):
            QMessageBox.information(
                self,
                self.t("msg_error_title"),
                self.t("msg_no_vault"),
            )
            return
        pwd, ok = QInputDialog.getText(
            self,
            self.t("msg_open_vault_title"),
            self.t("msg_open_vault_pwd"),
            echo=QLineEdit.Password,
        )
        if not ok or not pwd:
            return
        try:
            key = verify_password(self.vault_path, pwd)
        except Exception:
            QMessageBox.critical(
                self,
                self.t("msg_error_title"),
                self.t("msg_invalid_pwd"),
            )
            return
        self.key = key
        self.seconds_since_activity = 0
        self.update_vault_status(locked=False)
        self.update_auto_lock_label()
        self.action_add_file.setEnabled(True)
        self.action_extract_file.setEnabled(True)
        self.action_lock_vault.setEnabled(True)
        self.action_details.setEnabled(True)
        self.refresh_table()
        self.set_status(self.t("status_vault_open"))
        QMessageBox.information(
            self,
            self.t("msg_vault_opened_title"),
            self.t("msg_vault_opened_text"),
        )

    def on_add_file(self):
        if self.key is None:
            QMessageBox.information(
                self,
                self.t("msg_error_title"),
                self.t("msg_no_vault"),
            )
            return
        files, _ = QFileDialog.getOpenFileNames(
            self,
            self.t("btn_add_file"),
            "",
            "All Files (*.*)",
        )
        if not files:
            return
        for fpath in files:
            try:
                enc_name = add_file_to_vault(self.vault_path, self.key, fpath, self.language)
                analysis = analyze_file_sensitivity(fpath)
                hint = classification_ai_hint(self.language, analysis["classification"])
                if hint:
                    QMessageBox.information(self, self.t("ai_hint_title"), hint)
                self.set_status(f"Added: {os.path.basename(fpath)} -> {enc_name}")
            except Exception as e:
                QMessageBox.critical(
                    self,
                    self.t("msg_error_title"),
                    f"{self.t('msg_add_file_error')} {e}",
                )
        self.refresh_table()

    def on_extract_file(self):
        if self.key is None:
            QMessageBox.information(
                self,
                self.t("msg_error_title"),
                self.t("msg_no_vault"),
            )
            return
        row = self.table.currentRow()
        if row < 0:
            QMessageBox.information(
                self,
                self.t("msg_error_title"),
                self.t("msg_select_file"),
            )
            return
        enc_name_item = self.table.item(row, 0)
        if not enc_name_item:
            return
        enc_name = enc_name_item.text()
        target_path, _ = QFileDialog.getSaveFileName(
            self,
            self.t("msg_extract_target"),
            enc_name.replace(".enc", ""),
            "All Files (*.*)",
        )
        if not target_path:
            return
        try:
            extract_file_from_vault(self.vault_path, self.key, enc_name, target_path)
            if detect_anomaly_many_exports(self.vault_path):
                QMessageBox.warning(
                    self,
                    self.t("ai_anomaly_title"),
                    self.t("ai_anomaly_many_exports"),
                )
                self.lock_vault(auto=True, reason="anomaly")
                return
            self.set_status(f"Exported: {enc_name} -> {target_path}")
        except Exception as e:
            QMessageBox.critical(
                self,
                self.t("msg_error_title"),
                str(e),
            )

    def on_show_details(self, *args):
        if self.key is None:
            QMessageBox.information(
                self,
                self.t("msg_error_title"),
                self.t("msg_no_vault"),
            )
            return
        row = self.table.currentRow()
        if row < 0:
            QMessageBox.information(
                self,
                self.t("msg_error_title"),
                self.t("msg_select_file"),
            )
            return
        enc_name_item = self.table.item(row, 0)
        if not enc_name_item:
            return
        enc_name = enc_name_item.text()
        dlg = HashDetailsDialog(self, self.language, self.vault_path, enc_name, self.key)
        dlg.exec()

    def on_open_github(self):
        QDesktopServices.openUrl(QUrl(GITHUB_URL))

    def on_show_info(self):
        QMessageBox.information(
            self,
            self.t("msg_info_title"),
            self.t("info_text"),
        )

    def on_language_changed(self, index: int):
        lang_code = self.language_combo.itemData(index)
        if lang_code not in ("de", "en"):
            return
        self.language = lang_code
        self.save_language()
        self.retranslate_ui()
        self.refresh_table()

    def closeEvent(self, event):
        self.lock_vault(auto=False, reason="close")
        super().closeEvent(event)


def main():
    app = QApplication(sys.argv)
    win = SecureContainerWindow()
    win.show()
    sys.exit(app.exec())


if __name__ == "__main__":
    main()