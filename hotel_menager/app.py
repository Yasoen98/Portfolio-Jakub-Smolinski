# Zaktualizowany app.py - Dodajemy API do zarządzania użytkownikami

from flask import Flask, request, jsonify, render_template, session, redirect, url_for
from flask_cors import CORS
from flask_session import Session  # Do obsługi sesji
import sqlite3
import os
from datetime import datetime  # Do timestampów logów

app = Flask(__name__)
CORS(app)
app.secret_key = 'super_secret_key'  # Klucz do sesji (zmień w produkcji)
app.config['SESSION_TYPE'] = 'filesystem'
Session(app)

# Database setup
DB_NAME = 'hotel.db'

def init_db():
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    
    # Tabela users z rolami
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            role TEXT NOT NULL DEFAULT 'user'
        )
    ''')
    cursor.execute("INSERT OR IGNORE INTO users (username, password, role) VALUES ('admin', 'haslo123', 'admin')")
    cursor.execute("INSERT OR IGNORE INTO users (username, password, role) VALUES ('user', 'haslo123', 'user')")
    
    # Tabela rooms
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS rooms (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            number TEXT NOT NULL,
            type TEXT NOT NULL,
            status TEXT NOT NULL DEFAULT 'free',
            cleanliness TEXT NOT NULL DEFAULT 'clean'
        )
    ''')
    
    # Tabela reservations
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS reservations (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            room_id INTEGER,
            check_in DATE,
            check_out DATE,
            FOREIGN KEY (user_id) REFERENCES users(id),
            FOREIGN KEY (room_id) REFERENCES rooms(id)
        )
    ''')
    cursor.execute("INSERT OR IGNORE INTO reservations (user_id, room_id, check_in, check_out) VALUES (2, 1, '2025-08-20', '2025-08-25')")
    
    # Tabela logs
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            action_type TEXT NOT NULL,
            room_id INTEGER,
            details TEXT,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    
    conn.commit()
    conn.close()

init_db()

def log_action(user_id, action_type, room_id=None, details=None):
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    cursor.execute("INSERT INTO logs (user_id, action_type, room_id, details) VALUES (?, ?, ?, ?)",
                   (user_id, action_type, room_id, details))
    conn.commit()
    conn.close()

@app.route('/')
def index():
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
    return render_template('index.html')

@app.route('/login', methods=['POST'])
def login():
    data = request.json
    username = data.get('username')
    password = data.get('password')
    
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    cursor.execute("SELECT id, role FROM users WHERE username = ? AND password = ?", (username, password))
    user = cursor.fetchone()
    conn.close()
    
    if user:
        session['user_id'] = user[0]
        session['role'] = user[1]
        log_action(user[0], 'login')  # Loguj logowanie
        return jsonify({'success': True})
    else:
        return jsonify({'success': False, 'message': 'Błędna nazwa użytkownika lub hasło.'})

@app.route('/logout')
def logout():
    if 'user_id' in session:
        log_action(session['user_id'], 'logout')  # Loguj wylogowanie
    session.clear()
    return redirect(url_for('index'))

@app.route('/dashboard')
def dashboard():
    if 'user_id' not in session:
        return redirect(url_for('index'))
    
    role = session.get('role')
    if role == 'admin':
        return render_template('dashboard_admin.html')
    else:
        return render_template('dashboard_user.html')

# API do pobierania pokoi
@app.route('/api/rooms', methods=['GET'])
def get_rooms():
    if 'user_id' not in session:
        return jsonify({'error': 'Unauthorized'}), 401
    
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM rooms")
    rooms = cursor.fetchall()
    conn.close()
    return jsonify([{'id': r[0], 'number': r[1], 'type': r[2], 'status': r[3], 'cleanliness': r[4]} for r in rooms])

# API do dodawania pokoju (tylko admin)
@app.route('/api/rooms', methods=['POST'])
def add_room():
    if 'user_id' not in session or session.get('role') != 'admin':
        return jsonify({'error': 'Unauthorized'}), 401
    
    data = request.json
    number = data.get('number')
    room_type = data.get('type')
    
    if not number or not room_type:
        return jsonify({'error': 'Missing fields'}), 400
    
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    cursor.execute("INSERT INTO rooms (number, type, status, cleanliness) VALUES (?, ?, 'free', 'clean')", (number, room_type))
    room_id = cursor.lastrowid
    conn.commit()
    conn.close()
    log_action(session['user_id'], 'add_room', room_id, f"Added room {number} ({room_type})")
    return jsonify({'success': True})

# API do usuwania pokoju (tylko admin)
@app.route('/api/room/<int:room_id>', methods=['DELETE'])
def delete_room(room_id):
    if 'user_id' not in session or session.get('role') != 'admin':
        return jsonify({'error': 'Unauthorized'}), 401
    
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    cursor.execute("DELETE FROM rooms WHERE id = ?", (room_id,))
    conn.commit()
    conn.close()
    log_action(session['user_id'], 'delete_room', room_id, f"Deleted room ID {room_id}")
    return jsonify({'success': True})

# API do aktualizacji statusu pokoju (tylko admin)
@app.route('/api/room/<int:room_id>', methods=['PUT'])
def update_room(room_id):
    if 'user_id' not in session or session.get('role') != 'admin':
        return jsonify({'error': 'Unauthorized'}), 401
    
    data = request.json
    status = data.get('status')
    
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    cursor.execute("SELECT cleanliness FROM rooms WHERE id = ?", (room_id,))
    prev_clean = cursor.fetchone()[0]
    cursor.execute("UPDATE rooms SET status = ? WHERE id = ?", (status, room_id))
    conn.commit()
    conn.close()
    if status == 'occupied':
        log_action(session['user_id'], 'update_status', room_id, f"Previous: {prev_clean} New: {status}")
    return jsonify({'success': True})

# API do aktualizacji cleanliness (dla wszystkich)
@app.route('/api/room/<int:room_id>/cleanliness', methods=['PUT'])
def update_cleanliness(room_id):
    if 'user_id' not in session:
        return jsonify({'error': 'Unauthorized'}), 401
    
    data = request.json
    cleanliness = data.get('cleanliness')
    
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    cursor.execute("SELECT cleanliness FROM rooms WHERE id = ?", (room_id,))
    prev_cleanliness = cursor.fetchone()[0]
    cursor.execute("UPDATE rooms SET cleanliness = ? WHERE id = ?", (cleanliness, room_id))
    conn.commit()
    conn.close()
    log_action(session['user_id'], 'update_cleanliness', room_id, f"Previous: {prev_cleanliness} New: {cleanliness}")
    return jsonify({'success': True})

# API do pobierania logów (tylko admin, zmiany statusu pokoju)
@app.route('/api/logs', methods=['GET'])
def get_logs():
    if 'user_id' not in session or session.get('role') != 'admin':
        return jsonify({'error': 'Unauthorized'}), 401
    
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    cursor.execute("""
        SELECT logs.timestamp, rooms.number, users.username, logs.details
        FROM logs
        JOIN users ON logs.user_id = users.id
        JOIN rooms ON logs.room_id = rooms.id
        WHERE action_type IN ('update_status', 'update_cleanliness')
        ORDER BY logs.timestamp DESC
    """)
    logs = cursor.fetchall()
    conn.close()
    formatted_logs = []
    for log in logs:
        timestamp = log[0]
        date, time = timestamp.split(' ')
        prev_new = log[3].split(' New: ')
        prev = prev_new[0].replace('Previous: ', '')
        new = prev_new[1]
        formatted_logs.append({'date': date, 'time': time, 'room_number': log[1], 'username': log[2], 'previous': prev, 'new': new})
    return jsonify(formatted_logs)

# API do pobierania rezerwacji użytkownika (dla usera)
@app.route('/api/reservations', methods=['GET'])
def get_reservations():
    if 'user_id' not in session:
        return jsonify({'error': 'Unauthorized'}), 401
    
    user_id = session['user_id']
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    cursor.execute("""
        SELECT r.id, rooms.number, rooms.type, r.check_in, r.check_out 
        FROM reservations r 
        JOIN rooms ON r.room_id = rooms.id 
        WHERE r.user_id = ?
    """, (user_id,))
    reservations = cursor.fetchall()
    conn.close()
    return jsonify([{'id': res[0], 'room_number': res[1], 'type': res[2], 'check_in': res[3], 'check_out': res[4]} for res in reservations])

# API do pobierania użytkowników (tylko admin)
@app.route('/api/users', methods=['GET'])
def get_users():
    if 'user_id' not in session or session.get('role') != 'admin':
        return jsonify({'error': 'Unauthorized'}), 401
    
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    cursor.execute("SELECT id, username, role FROM users")
    users = cursor.fetchall()
    conn.close()
    return jsonify([{'id': u[0], 'username': u[1], 'role': u[2]} for u in users])

# API do dodawania użytkownika (tylko admin)
@app.route('/api/users', methods=['POST'])
def add_user():
    if 'user_id' not in session or session.get('role') != 'admin':
        return jsonify({'error': 'Unauthorized'}), 401
    
    data = request.json
    username = data.get('username')
    password = data.get('password')
    role = data.get('role')
    
    if not username or not password or not role:
        return jsonify({'error': 'Missing fields'}), 400
    
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    try:
        cursor.execute("INSERT INTO users (username, password, role) VALUES (?, ?, ?)", (username, password, role))
        conn.commit()
    except sqlite3.IntegrityError:
        conn.close()
        return jsonify({'error': 'Username already exists'}), 400
    conn.close()
    log_action(session['user_id'], 'add_user', details=f"Added user {username} ({role})")
    return jsonify({'success': True})

# API do usuwania użytkownika (tylko admin, nie można usunąć siebie)
@app.route('/api/user/<int:user_id>', methods=['DELETE'])
def delete_user(user_id):
    if 'user_id' not in session or session.get('role') != 'admin':
        return jsonify({'error': 'Unauthorized'}), 401
    
    if user_id == session['user_id']:
        return jsonify({'error': 'Cannot delete yourself'}), 403
    
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    cursor.execute("DELETE FROM users WHERE id = ?", (user_id,))
    conn.commit()
    conn.close()
    log_action(session['user_id'], 'delete_user', details=f"Deleted user ID {user_id}")
    return jsonify({'success': True})

# API do zmiany hasła użytkownika (tylko admin)
@app.route('/api/user/<int:user_id>/password', methods=['PUT'])
def change_password(user_id):
    if 'user_id' not in session or session.get('role') != 'admin':
        return jsonify({'error': 'Unauthorized'}), 401
    
    data = request.json
    password = data.get('password')
    
    if not password:
        return jsonify({'error': 'Missing password'}), 400
    
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    cursor.execute("UPDATE users SET password = ? WHERE id = ?", (password, user_id))
    conn.commit()
    conn.close()
    log_action(session['user_id'], 'change_password', details=f"Changed password for user ID {user_id}")
    return jsonify({'success': True})

if __name__ == '__main__':
    app.run(debug=True)