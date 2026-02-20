import sqlite3
from datetime import datetime
import os
import time

DB_FILE = "aegis_storage.db"

class DatabaseManager:
    def __init__(self):
        self.conn = None
        self.cursor = None
        self.fast_connect()

    def fast_connect(self):
        """
        Instant connection mode.
        Skips schema creation checks if the DB already exists.
        """
        # 1. Connect (Timeout set to 5s just in case)
        self.conn = sqlite3.connect(DB_FILE, check_same_thread=False, timeout=5.0)
        self.conn.row_factory = sqlite3.Row
        self.cursor = self.conn.cursor()
        
        # 2. Enable WAL (Write-Ahead Logging) for Speed + Concurrency
        try:
            self.conn.execute("PRAGMA journal_mode=WAL")
            self.conn.execute("PRAGMA synchronous=NORMAL") 
        except: pass

        # 3. SMART CHECK: Only run schema init if DB is empty/missing
        if not os.path.exists(DB_FILE) or os.path.getsize(DB_FILE) == 0:
            self._initialize_schema()
        else:
            try:
                self.conn.execute("SELECT id FROM targets LIMIT 1")
            except sqlite3.OperationalError:
                self._initialize_schema()

    def _initialize_schema(self):
        """Creates tables. Only runs once per install."""
        try:
            self.cursor.execute('''
                CREATE TABLE IF NOT EXISTS targets (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    domain TEXT UNIQUE,
                    ip TEXT,
                    os_info TEXT,
                    waf_status TEXT,
                    last_scanned DATETIME
                )
            ''')
            self.cursor.execute('''
                CREATE TABLE IF NOT EXISTS ports (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    target_id INTEGER,
                    port INTEGER,
                    service TEXT,
                    banner TEXT,
                    UNIQUE(target_id, port)
                )
            ''')
            self.cursor.execute('''
                CREATE TABLE IF NOT EXISTS technologies (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    target_id INTEGER,
                    component TEXT,
                    name TEXT,
                    version TEXT,
                    source TEXT,
                    UNIQUE(target_id, name, version)
                )
            ''')
            self.cursor.execute('''
                CREATE TABLE IF NOT EXISTS vulns (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    target_id INTEGER,
                    risk TEXT,
                    vuln_type TEXT,
                    issue TEXT,
                    evidence TEXT,
                    tool_source TEXT,
                    UNIQUE(target_id, issue)
                )
            ''')
            self.cursor.execute('''
                CREATE TABLE IF NOT EXISTS secrets (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    target_id INTEGER,
                    secret_type TEXT,
                    location TEXT,
                    value TEXT,
                    UNIQUE(target_id, value)
                )
            ''')
            self.conn.commit()
        except:
            pass

    # --- PUBLIC API ---

    def get_or_create_target(self, domain):
        try:
            self.cursor.execute("SELECT id FROM targets WHERE domain = ?", (domain,))
            result = self.cursor.fetchone()
            if result: return result[0]
            
            self.cursor.execute("INSERT INTO targets (domain, last_scanned) VALUES (?, ?)", 
                                (domain, datetime.now()))
            self.conn.commit()
            return self.cursor.lastrowid
        except: return None

    def add_tech(self, domain, component, name, version="Unknown", source="Detected"):
        tid = self.get_or_create_target(domain)
        if not tid: return
        try:
            self.cursor.execute('''
                INSERT INTO technologies (target_id, component, name, version, source) 
                VALUES (?, ?, ?, ?, ?)
                ON CONFLICT(target_id, name, version) DO NOTHING
            ''', (tid, component, name, version, source))
            self.conn.commit()
        except: pass

    def add_port(self, domain, port, service, banner):
        tid = self.get_or_create_target(domain)
        if not tid: return
        try:
            self.cursor.execute('''
                INSERT INTO ports (target_id, port, service, banner) 
                VALUES (?, ?, ?, ?)
                ON CONFLICT(target_id, port) DO UPDATE SET
                service=excluded.service, banner=excluded.banner
            ''', (tid, port, service, banner))
            self.conn.commit()
        except: pass

    def add_vuln(self, domain, risk, vtype, issue, evidence="", tool="Aegis"):
        tid = self.get_or_create_target(domain)
        if not tid: return
        try:
            self.cursor.execute('''
                INSERT INTO vulns (target_id, risk, vuln_type, issue, evidence, tool_source) 
                VALUES (?, ?, ?, ?, ?, ?)
                ON CONFLICT(target_id, issue) DO NOTHING
            ''', (tid, risk, vtype, issue, evidence, tool))
            self.conn.commit()
        except: pass

    def add_secret(self, domain, stype, location, value):
        tid = self.get_or_create_target(domain)
        if not tid: return
        try:
            self.cursor.execute('''
                INSERT INTO secrets (target_id, secret_type, location, value) 
                VALUES (?, ?, ?, ?)
                ON CONFLICT(target_id, value) DO NOTHING
            ''', (tid, stype, location, value))
            self.conn.commit()
        except: pass

    def update_target_info(self, domain, ip=None, os=None, waf=None):
        tid = self.get_or_create_target(domain)
        if not tid: return
        if ip: self.cursor.execute("UPDATE targets SET ip=? WHERE id=?", (ip, tid))
        if os: self.cursor.execute("UPDATE targets SET os_info=? WHERE id=?", (os, tid))
        if waf: self.cursor.execute("UPDATE targets SET waf_status=? WHERE id=?", (waf, tid))
        self.conn.commit()

# Init module-level instance
db = DatabaseManager()
