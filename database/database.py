# database/database.py

# ─────────────────────────────────────────
# NEAP — Network Email Anti-Phishing
# SQLite Database
# ─────────────────────────────────────────

import sqlite3
import os

DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'neap.db')

def get_connection():
    conn = sqlite3.connect(DB_PATH, timeout=30)
    conn.execute("PRAGMA foreign_keys = ON")
    conn.execute("PRAGMA journal_mode=WAL")
    return conn

def create_tables():
    conn = get_connection()
    cursor = conn.cursor()

    cursor.executescript("""
        CREATE TABLE IF NOT EXISTS USERS (
            id_user    INTEGER PRIMARY KEY AUTOINCREMENT,
            username   TEXT NOT NULL UNIQUE,
            email      TEXT NOT NULL UNIQUE,
            password   TEXT NOT NULL,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP
        );

        CREATE TABLE IF NOT EXISTS SESSIONS (
            id_session INTEGER PRIMARY KEY AUTOINCREMENT,
            id_user    INTEGER NOT NULL,
            token      TEXT NOT NULL UNIQUE,
            expires_at DATETIME NOT NULL,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (id_user) REFERENCES USERS(id_user)
        );

        CREATE TABLE IF NOT EXISTS EMAILS (
            id_email   INTEGER PRIMARY KEY AUTOINCREMENT,
            remetente  TEXT NOT NULL,
            assunto    TEXT NOT NULL,
            corpo      TEXT,
            data_hora  DATETIME DEFAULT CURRENT_TIMESTAMP
        );

        CREATE TABLE IF NOT EXISTS ANALISES (
            id_analise           INTEGER PRIMARY KEY AUTOINCREMENT,
            id_email             INTEGER NOT NULL,
            score                INTEGER NOT NULL,
            resultado            TEXT NOT NULL,
            nivel_risco          TEXT NOT NULL,
            ai_verdict           TEXT,
            ai_confidence        INTEGER,
            ai_reasons           TEXT,
            impersonated_company TEXT,
            official_domain      TEXT,
            sender_domain        TEXT,
            domain_match         INTEGER,
            FOREIGN KEY (id_email) REFERENCES EMAILS(id_email)
        );
        
        CREATE TABLE IF NOT EXISTS WEBHOOK_SETTINGS (
    id_webhook      INTEGER PRIMARY KEY AUTOINCREMENT,
    id_user         INTEGER NOT NULL,
    discord_url     TEXT,
    slack_url       TEXT,
    telegram_token  TEXT,
    telegram_chat_id TEXT,
    active          INTEGER DEFAULT 1,
    FOREIGN KEY (id_user) REFERENCES USERS(id_user)
);

        CREATE TABLE IF NOT EXISTS LOGS (
            id_log     INTEGER PRIMARY KEY AUTOINCREMENT,
            id_analise INTEGER NOT NULL,
            data_hora  DATETIME DEFAULT CURRENT_TIMESTAMP,
            evento     TEXT NOT NULL,
            ip_origem  TEXT,
            spf        TEXT,
            dkim       TEXT,
            dmarc      TEXT,
            FOREIGN KEY (id_analise) REFERENCES ANALISES(id_analise)
        );

        CREATE TABLE IF NOT EXISTS ALERTAS (
            id_alerta    INTEGER PRIMARY KEY AUTOINCREMENT,
            id_log       INTEGER NOT NULL,
            tipo_alerta  TEXT NOT NULL,
            estado_alerta TEXT NOT NULL,
            FOREIGN KEY (id_log) REFERENCES LOGS(id_log)
        );

        CREATE TABLE IF NOT EXISTS BLOCKED_SENDERS (
            id_blocked INTEGER PRIMARY KEY AUTOINCREMENT,
            sender     TEXT NOT NULL UNIQUE,
            blocked_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            reason     TEXT
        );

        CREATE TABLE IF NOT EXISTS IMAP_CREDENTIALS (
            id_cred    INTEGER PRIMARY KEY AUTOINCREMENT,
            id_user    INTEGER NOT NULL,
            email      TEXT NOT NULL,
            password   TEXT NOT NULL,
            auto_check INTEGER DEFAULT 1,
            interval   INTEGER DEFAULT 30,
            last_check DATETIME,
            FOREIGN KEY (id_user) REFERENCES USERS(id_user)
        );
    """)

    conn.commit()
    conn.close()
    print("Tabelas criadas!")

if __name__ == "__main__":
    create_tables()