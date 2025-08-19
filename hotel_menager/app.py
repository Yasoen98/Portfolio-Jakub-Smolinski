# Zaktualizowany app.py - Pozwalamy użytkownikom na aktualizację cleanliness (z dirty na clean)

from flask import Flask, request, jsonify, render_template, session, redirect, url_for
from flask_cors import CORS
from flask_session import Session  # Do obsługi sesji
import sqlite3
import os

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
    
    # Tabela rooms (z nową kolumną cleanliness)
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS rooms (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            number TEXT NOT NULL,
            type TEXT NOT NULL,
            status TEXT NOT NULL DEFAULT 'free',
            cleanliness TEXT NOT NULL DEFAULT 'clean'  -- 'clean' lub 'dirty'
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
    
    conn.commit()
    conn.close()

init_db()

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
        return jsonify({'success': True})
    else:
        return jsonify({'success': False, 'message': 'Błędna nazwa użytkownika lub hasło.'})

@app.route('/logout')
def logout():
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

# API do pobierania pokoi (dla admina i użytkowników - wszyscy mogą czytać)
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
    room_type = data.get('type')  # 'single' or 'double'
    
    if not number or not room_type:
        return jsonify({'error': 'Missing fields'}), 400
    
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    cursor.execute("INSERT INTO rooms (number, type, status, cleanliness) VALUES (?, ?, 'free', 'clean')", (number, room_type))
    conn.commit()
    conn.close()
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
    return jsonify({'success': True})

# API do aktualizacji statusu pokoju (zajętość, tylko admin)
@app.route('/api/room/<int:room_id>', methods=['PUT'])
def update_room(room_id):
    if 'user_id' not in session or session.get('role') != 'admin':
        return jsonify({'error': 'Unauthorized'}), 401
    
    data = request.json
    status = data.get('status')
    
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    cursor.execute("UPDATE rooms SET status = ? WHERE id = ?", (status, room_id))
    conn.commit()
    conn.close()
    return jsonify({'success': True})

# API do aktualizacji cleanliness (dla wszystkich zalogowanych użytkowników)
@app.route('/api/room/<int:room_id>/cleanliness', methods=['PUT'])
def update_cleanliness(room_id):
    if 'user_id' not in session:
        return jsonify({'error': 'Unauthorized'}), 401
    
    data = request.json
    cleanliness = data.get('cleanliness')
    
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    cursor.execute("UPDATE rooms SET cleanliness = ? WHERE id = ?", (cleanliness, room_id))
    conn.commit()
    conn.close()
    return jsonify({'success': True})

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

if __name__ == '__main__':
    app.run(debug=True)