import json
import sqlite3
import threading
import os
import logging

class SetEncoder(json.JSONEncoder):
    def default(self, obj):
        if isinstance(obj, set):
            return list(obj)
        return super().default(obj)

class KnowledgeBase:
    def __init__(self, db_file="aegis_session.db", load_existing=True):
        self.db_file = db_file
        self.lock = threading.Lock()
        self.logger = logging.getLogger("aegis.kb")
        self._init_db()
        
        self.data = {}
        if load_existing:
            self.data = self._load_from_db()
        else:
            self.logger.info("Skipping DB load (Fresh Session)")

    def _init_db(self):
        """Initialize SQLite database with WAL mode."""
        with self.lock:
            # Increased timeout to 20s for safety
            conn = sqlite3.connect(self.db_file, check_same_thread=False, timeout=20.0)
            conn.execute("PRAGMA journal_mode=WAL;") 
            conn.execute("PRAGMA synchronous=NORMAL;")
            
            cursor = conn.cursor()
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS kb_store (
                    key TEXT PRIMARY KEY,
                    value TEXT
                )
            ''')
            conn.commit()
            conn.close()

    def _load_from_db(self):
        data = {}
        try:
            if os.path.exists(self.db_file):
                with sqlite3.connect(self.db_file, timeout=20.0) as conn:
                    cursor = conn.cursor()
                    cursor.execute("SELECT key, value FROM kb_store")
                    rows = cursor.fetchall()
                    for key, val in rows:
                        try:
                            data[key] = json.loads(val)
                        except:
                            data[key] = val
                self.logger.info(f"Restored {len(data)} keys from session.")
        except Exception as e:
            self.logger.error(f"Failed to load DB: {e}")
        return data

    def _save_to_db(self, key, value):
        try:
            with sqlite3.connect(self.db_file, timeout=20.0) as conn:
                cursor = conn.cursor()
                json_val = json.dumps(value, cls=SetEncoder)
                cursor.execute("INSERT OR REPLACE INTO kb_store (key, value) VALUES (?, ?)", (key, json_val))
                conn.commit()
        except Exception as e:
            self.logger.error(f"DB Write Error ({key}): {e}")

    def update(self, key, value):
        with self.lock:
            if key in self.data:
                if isinstance(self.data[key], list) and isinstance(value, list):
                    current_set = set(json.dumps(x, sort_keys=True, cls=SetEncoder) for x in self.data[key])
                    for item in value:
                        item_str = json.dumps(item, sort_keys=True, cls=SetEncoder)
                        if item_str not in current_set:
                            self.data[key].append(item)
                            current_set.add(item_str)
                elif isinstance(self.data[key], dict) and isinstance(value, dict):
                    self.data[key].update(value)
                else:
                    self.data[key] = value
            else:
                self.data[key] = value

            self._save_to_db(key, self.data[key])

    def get(self, key, default=None):
        return self.data.get(key, default)

    def get_all(self):
        self.data = self._load_from_db()
        return self.data

    def reset(self):
        with self.lock:
            self.data = {}
            try:
                # Fix: Removed VACUUM to prevent locking. 
                # DELETE is sufficient to clear the session data.
                with sqlite3.connect(self.db_file, timeout=20.0, isolation_level=None) as conn:
                    conn.execute("DELETE FROM kb_store")
                self.logger.info("KnowledgeBase wiped (SQL Truncate).")
            except Exception as e:
                self.logger.error(f"Reset failed: {e}")
