import sqlite3

DB_NAME = "vulnscan.db"


def get_connection():
    return sqlite3.connect(DB_NAME)


def init_db():
    conn = get_connection()
    cursor = conn.cursor()

    # Users table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email TEXT UNIQUE,
            password TEXT
        )
    """)

    # Scans table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS scans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            target TEXT,
            score INTEGER,
            grade TEXT,
            findings TEXT,
            completed_at TEXT
        )
    """)

    conn.commit()
    conn.close()
    import json


def save_scan(user_id, target, score, grade, findings, completed_at):
    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute("""
        INSERT INTO scans (user_id, target, score, grade, findings, completed_at)
        VALUES (?, ?, ?, ?, ?, ?)
    """, (
        user_id,
        target,
        score,
        grade,
        json.dumps(findings),
        completed_at
    ))

    conn.commit()
    conn.close()

import json
def get_all_scans():
    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute("""
        SELECT id, user_id, target, score, grade, findings, completed_at
        FROM scans
        ORDER BY id DESC
    """)

    rows = cursor.fetchall()
    conn.close()
    return rows
def create_user(email, password):
    conn = get_connection()
    cursor = conn.cursor()

    try:
        cursor.execute("""
            INSERT INTO users (email, password)
            VALUES (?, ?)
        """, (email, password))
        conn.commit()
        user_id = cursor.lastrowid
        conn.close()
        return {"id": user_id, "email": email}
    except sqlite3.IntegrityError:
        conn.close()
        return None


def get_user_by_email(email):
    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute("""
        SELECT id, email, password
        FROM users
        WHERE email = ?
    """, (email,))

    row = cursor.fetchone()
    conn.close()
    return row
def get_scans_by_user(user_id):
    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute("""
        SELECT id, user_id, target, score, grade, findings, completed_at
        FROM scans
        WHERE user_id = ?
        ORDER BY id DESC
    """, (user_id,))

    rows = cursor.fetchall()
    conn.close()
    return rows