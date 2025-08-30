# app.py — HSK System (Imię/Nazwisko, Check-in/Check-out, statusy rezerwacji, role)
from flask import Flask, request, jsonify, render_template, session, redirect, url_for
from flask_cors import CORS
from flask_session import Session
import sqlite3
from datetime import datetime

app = Flask(__name__)
CORS(app)
app.secret_key = 'super_secret_key'  # ZMIEŃ w produkcji
app.config['SESSION_TYPE'] = 'filesystem'
Session(app)

DB_NAME = 'hotel.db'

# --------------------- DB INIT ---------------------
def init_db():
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()

    # Users
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            role TEXT NOT NULL DEFAULT 'user'
        )
    ''')
    cursor.execute("INSERT OR IGNORE INTO users (username, password, role) VALUES ('admin', 'haslo123', 'admin')")


    # Rooms
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS rooms (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            number TEXT NOT NULL,
            type TEXT NOT NULL,
            status TEXT NOT NULL DEFAULT 'free',
            cleanliness TEXT NOT NULL DEFAULT 'clean'
        )
    ''')
    cursor.execute("PRAGMA table_info(rooms)")
    room_columns = [c[1] for c in cursor.fetchall()]
    if "priority" not in room_columns:
        cursor.execute("ALTER TABLE rooms ADD COLUMN priority INTEGER DEFAULT 0")
    if "guest_name" not in room_columns:
        cursor.execute("ALTER TABLE rooms ADD COLUMN guest_name TEXT")
    # NEW: komentarz do karty pokoju
    if "comment" not in room_columns:
        cursor.execute("ALTER TABLE rooms ADD COLUMN comment TEXT")
    # Reservations (rozszerzone o status i metryki check-in/out + imię/nazwisko)
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
    cursor.execute("PRAGMA table_info(reservations)")
    res_cols = [c[1] for c in cursor.fetchall()]
    if "guest_first_name" not in res_cols:
        cursor.execute("ALTER TABLE reservations ADD COLUMN guest_first_name TEXT")
    if "guest_last_name" not in res_cols:
        cursor.execute("ALTER TABLE reservations ADD COLUMN guest_last_name TEXT")
    if "status" not in res_cols:
        cursor.execute("ALTER TABLE reservations ADD COLUMN status TEXT DEFAULT 'booked'")  # booked|checked_in|closed
    if "checked_in_at" not in res_cols:
        cursor.execute("ALTER TABLE reservations ADD COLUMN checked_in_at DATETIME")
    if "checked_out_at" not in res_cols:
        cursor.execute("ALTER TABLE reservations ADD COLUMN checked_out_at DATETIME")

    cursor.execute("""INSERT OR IGNORE INTO reservations
        (id, user_id, room_id, check_in, check_out, guest_first_name, guest_last_name, status)
        VALUES (1, NULL, 1, '2025-08-20', '2025-08-25', 'Jan', 'Kowalski', 'booked')""")

    # Logs
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

    # Tickets
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS tickets (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            room_id INTEGER,
            reason TEXT,
            status TEXT DEFAULT 'open',
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users(id),
            FOREIGN KEY (room_id) REFERENCES rooms(id)
        )
    ''')
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS ticket_messages (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ticket_id INTEGER,
            sender TEXT,
            message TEXT,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (ticket_id) REFERENCES tickets(id)
        )
    ''')

    conn.commit()
    conn.close()

init_db()

# --------------------- HELPERS ---------------------
def log_action(user_id, action_type, room_id=None, details=None):
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    cursor.execute(
        "INSERT INTO logs (user_id, action_type, room_id, details) VALUES (?, ?, ?, ?)",
        (user_id, action_type, room_id, details)
    )
    conn.commit()
    conn.close()

def require_login():
    return 'user_id' in session

def has_role(*roles):
    return session.get('role') in roles

def room_available(room_id, check_in, check_out, exclude_res_id=None):
    """
    Pokój uznajemy za zajęty tylko przez rezerwacje aktywne:
      - status IN ('booked', 'checked_in')
    Rezerwacje 'closed' są ignorowane (np. wcześniejsze wymeldowanie).
    Warunek nakładania: [check_in, check_out) koliduje z istniejącym zakresem.
    """
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()

    base_sql = '''
        SELECT COUNT(*) FROM reservations
        WHERE room_id = ?
          AND status IN ('booked', 'checked_in')
          AND date(?) < date(check_out)
          AND date(?) > date(check_in)
    '''

    params = [room_id, check_out, check_in]

    if exclude_res_id:
        base_sql += ' AND id != ?'
        params.append(exclude_res_id)

    cursor.execute(base_sql, params)
    overlap = cursor.fetchone()[0]
    conn.close()
    return overlap == 0


# --------------------- ROUTES ---------------------
@app.route('/')
def index():
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
    return render_template('index.html')

@app.route('/login', methods=['POST'])
def login():
    data = request.json
    username = data.get('username'); password = data.get('password')
    conn = sqlite3.connect(DB_NAME); cursor = conn.cursor()
    cursor.execute("SELECT id, role FROM users WHERE username = ? AND password = ?", (username, password))
    user = cursor.fetchone(); conn.close()
    if user:
        session['user_id'] = user[0]
        session['role'] = user[1]
        session['username'] = username
        log_action(user[0], 'login')
        return jsonify({'success': True})
    return jsonify({'success': False, 'message': 'Błędna nazwa użytkownika lub hasło.'})

@app.route('/logout')
def logout():
    if 'user_id' in session:
        log_action(session['user_id'], 'logout')
    session.clear()
    return redirect(url_for('index'))

@app.route('/dashboard')
def dashboard():
    if not require_login():
        return redirect(url_for('index'))
    role = session.get('role')
    if role in ('admin', 'manager', 'recepcjonista'):
        return render_template('dashboard_admin.html')
    return render_template('dashboard_user.html')

# --------------------- ROOMS ---------------------
@app.route('/api/rooms', methods=['GET'])
def get_rooms():
    if not require_login():
        return jsonify({'error': 'Unauthorized'}), 401
    conn = sqlite3.connect(DB_NAME); cursor = conn.cursor()
    cursor.execute("SELECT id, number, type, status, cleanliness, priority, guest_name, comment FROM rooms")
    rows = cursor.fetchall(); conn.close()
    return jsonify([{
        'id': r[0], 'number': r[1], 'type': r[2], 'status': r[3],
        'cleanliness': r[4], 'priority': r[5], 'guest_name': r[6],
        'comment': r[7]
    } for r in rows])

@app.route('/api/rooms', methods=['POST'])
def add_room():
    if not require_login() or not has_role('admin', 'manager'):
        return jsonify({'error': 'Unauthorized'}), 401
    data = request.json
    number = data.get('number'); room_type = data.get('type')
    if not number or not room_type:
        return jsonify({'error': 'Missing fields'}), 400
    conn = sqlite3.connect(DB_NAME); cursor = conn.cursor()
    cursor.execute("INSERT INTO rooms (number, type, status) VALUES (?, ?, 'clean')", (number, room_type))
    room_id = cursor.lastrowid; conn.commit(); conn.close()
    log_action(session['user_id'], 'add_room', room_id, f"Added room {number} ({room_type})")
    return jsonify({'success': True})

@app.route('/api/room/<int:room_id>', methods=['DELETE'])
def delete_room(room_id):
    if not require_login() or not has_role('admin', 'manager'):
        return jsonify({'error': 'Unauthorized'}), 401
    conn = sqlite3.connect(DB_NAME); cursor = conn.cursor()
    cursor.execute("DELETE FROM rooms WHERE id = ?", (room_id,))
    conn.commit(); conn.close()
    log_action(session['user_id'], 'delete_room', room_id, f"Deleted room ID {room_id}")
    return jsonify({'success': True})

@app.route('/api/room/<int:room_id>', methods=['PUT'])
def update_room(room_id):
    if not require_login():
        return jsonify({'error': 'Unauthorized'}), 401
    role = session.get('role')
    status = (request.json or {}).get('status')
    if status not in ('clean', 'dirty', 'occupied'):
        return jsonify({'error': 'Invalid status'}), 400

    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    # Pobierz obecny status i priorytet
    cursor.execute("SELECT status, priority FROM rooms WHERE id=?", (room_id,))
    row = cursor.fetchone()
    if not row:
        conn.close()
        return jsonify({'error': 'Room not found'}), 404
    current_status, current_priority = row

    # Ograniczenia ról jak było
    if role in ('user', 'housekeeping'):
        if current_status not in ('dirty', 'clean') or status not in ('dirty', 'clean'):
            conn.close()
            return jsonify({'error': 'Unauthorized'}), 401

    # Logika zmiany + czyszczenie komentarza przy occupied
    if current_status == 'dirty' and status == 'clean':
        cursor.execute("UPDATE rooms SET status=?, priority=0 WHERE id=?", (status, room_id))
        action_details = f"Previous: {current_status} New: {status} (priority cleared)"
    else:
        if status == 'occupied':
            cursor.execute("UPDATE rooms SET status=?, comment=NULL WHERE id=?", (status, room_id))
            action_details = f"Previous: {current_status} New: {status} (comment cleared)"
        else:
            cursor.execute("UPDATE rooms SET status=? WHERE id=?", (status, room_id))
            action_details = f"Previous: {current_status} New: {status}"

    conn.commit()
    conn.close()
    log_action(session['user_id'], 'update_status', room_id, action_details)
    return jsonify({'success': True})

@app.route('/api/room/<int:room_id>/comment', methods=['PUT'])
def set_room_comment(room_id):
    if not require_login() or not has_role('admin', 'manager', 'recepcjonista'):
        return jsonify({'error': 'Unauthorized'}), 401
    comment = ((request.json or {}).get('comment') or '').strip()
    conn = sqlite3.connect(DB_NAME); cursor = conn.cursor()
    cursor.execute("SELECT id FROM rooms WHERE id=?", (room_id,))
    if not cursor.fetchone():
        conn.close(); return jsonify({'error': 'Room not found'}), 404
    cursor.execute("UPDATE rooms SET comment=? WHERE id=?", (comment if comment else None, room_id))
    conn.commit(); conn.close()
    log_action(session['user_id'], 'update_room_comment', room_id, f"comment='{comment}'")
    return jsonify({'success': True})


@app.route('/api/room/<int:room_id>/cleanliness', methods=['PUT'])
def update_cleanliness(room_id):
    if not require_login():
        return jsonify({'error': 'Unauthorized'}), 401
    cleanliness = (request.json or {}).get('cleanliness')
    conn = sqlite3.connect(DB_NAME); cursor = conn.cursor()
    cursor.execute("SELECT cleanliness FROM rooms WHERE id=?", (room_id,))
    prev = cursor.fetchone()
    if not prev:
        conn.close(); return jsonify({'error': 'Room not found'}), 404
    cursor.execute("UPDATE rooms SET cleanliness=? WHERE id=?", (cleanliness, room_id))
    conn.commit(); conn.close()
    log_action(session['user_id'], 'update_cleanliness', room_id, f"Previous: {prev[0]} New: {cleanliness}")
    return jsonify({'success': True})

@app.route('/api/room/<int:room_id>/priority', methods=['PUT'])
def toggle_priority(room_id):
    if not require_login() or not has_role('admin', 'manager', 'recepcjonista'):
        return jsonify({'error': 'Unauthorized'}), 401
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    cursor.execute("SELECT priority FROM rooms WHERE id=?", (room_id,))
    row = cursor.fetchone()
    if not row:
        conn.close()
        return jsonify({'error': 'Room not found'}), 404
    new_priority = 0 if row[0] == 1 else 1
    cursor.execute("UPDATE rooms SET priority=? WHERE id=?", (new_priority, room_id))
    conn.commit()
    conn.close()
    log_action(session['user_id'], 'update_priority', room_id, f"Priority set to {new_priority}")
    return jsonify({'success': True, 'priority': new_priority})


@app.route('/api/room/<int:room_id>/guest', methods=['PUT'])
def set_room_guest(room_id):
    if not require_login() or not has_role('admin', 'manager', 'recepcjonista'):
        return jsonify({'error': 'Unauthorized'}), 401
    guest_name = ((request.json or {}).get('guest_name') or '').strip()
    conn = sqlite3.connect(DB_NAME); cursor = conn.cursor()
    cursor.execute("SELECT id FROM rooms WHERE id=?", (room_id,))
    if not cursor.fetchone():
        conn.close(); return jsonify({'error': 'Room not found'}), 404
    cursor.execute("UPDATE rooms SET guest_name=? WHERE id=?", (guest_name if guest_name else None, room_id))
    conn.commit(); conn.close()
    log_action(session['user_id'], 'update_room_guest', room_id, f"guest_name='{guest_name}'")
    return jsonify({'success': True})

# --------------------- LOGS ---------------------
@app.route('/api/logs', methods=['GET'])
def get_logs():
    if not require_login() or not has_role('admin', 'manager'):
        return jsonify({'error': 'Unauthorized'}), 401
    conn = sqlite3.connect(DB_NAME); cursor = conn.cursor()
    cursor.execute("""
        SELECT logs.timestamp, rooms.number, users.username, logs.details
        FROM logs
        LEFT JOIN users ON logs.user_id = users.id
        LEFT JOIN rooms ON logs.room_id = rooms.id
        WHERE action_type IN (
            'update_status', 'update_cleanliness', 'add_room', 'delete_room',
            'add_user', 'delete_user', 'change_password',
            'create_reservation', 'update_reservation', 'delete_reservation',
            'update_priority', 'checkin_reservation', 'checkout_reservation',
            'update_room_guest', 'update_room_comment'
        )
        ORDER BY logs.timestamp DESC
    """)
    rows = cursor.fetchall(); conn.close()
    formatted = []
    for ts, room_number, username, details in rows:
        date, time = ts.split(" ")
        formatted.append({
            "date": date,
            "time": time,
            "room_number": room_number if room_number else "-",
            "username": username if username else "SYSTEM",
            "previous": details or "-",
            "new": "-"
        })
    return jsonify(formatted)


# --------------------- USERS ---------------------
@app.route('/api/users', methods=['GET'])
def get_users():
    if not require_login() or not has_role('admin', 'manager'):
        return jsonify({'error': 'Unauthorized'}), 401
    conn = sqlite3.connect(DB_NAME); cursor = conn.cursor()
    cursor.execute("SELECT id, username, role FROM users")
    rows = cursor.fetchall(); conn.close()
    return jsonify([{'id': r[0], 'username': r[1], 'role': r[2]} for r in rows])

@app.route('/api/users', methods=['POST'])
def add_user():
    if not require_login() or not has_role('admin', 'manager'):
        return jsonify({'error': 'Unauthorized'}), 401
    data = request.json or {}
    username = data.get('username'); password = data.get('password'); role = data.get('role')
    if not username or not password or not role:
        return jsonify({'error': 'Missing fields'}), 400
    conn = sqlite3.connect(DB_NAME); cursor = conn.cursor()
    try:
        cursor.execute("INSERT INTO users (username, password, role) VALUES (?, ?, ?)", (username, password, role))
        conn.commit()
    except sqlite3.IntegrityError:
        conn.close(); return jsonify({'error': 'Username already exists'}), 400
    conn.close()
    log_action(session['user_id'], 'add_user', details=f"Added user {username} ({role})")
    return jsonify({'success': True})

@app.route('/api/user/<int:user_id>', methods=['DELETE'])
def delete_user(user_id):
    if not require_login() or not has_role('admin'):
        return jsonify({'error': 'Unauthorized'}), 401
    if user_id == session['user_id']:
        return jsonify({'error': 'Cannot delete yourself'}), 403
    conn = sqlite3.connect(DB_NAME); cursor = conn.cursor()
    cursor.execute("DELETE FROM users WHERE id=?", (user_id,))
    conn.commit(); conn.close()
    log_action(session['user_id'], 'delete_user', details=f"Deleted user ID {user_id}")
    return jsonify({'success': True})

@app.route('/api/user/<int:user_id>/password', methods=['PUT'])
def change_password(user_id):
    if not require_login() or not has_role('admin', 'manager'):
        return jsonify({'error': 'Unauthorized'}), 401
    password = (request.json or {}).get('password')
    if not password:
        return jsonify({'error': 'Missing password'}), 400
    conn = sqlite3.connect(DB_NAME); cursor = conn.cursor()
    cursor.execute("UPDATE users SET password=? WHERE id=?", (password, user_id))
    conn.commit(); conn.close()
    log_action(session['user_id'], 'change_password', details=f"Changed password for user ID {user_id}")
    return jsonify({'success': True})

# --------------------- TICKETS ---------------------
@app.route('/api/tickets', methods=['POST'])
def create_ticket():
    if not require_login():
        return jsonify({'error': 'Unauthorized'}), 401
    data = request.json or {}
    room_id = data.get('room_id'); reason = data.get('reason')
    if not room_id or not reason:
        return jsonify({'error': 'Missing fields'}), 400
    uid = session['user_id']
    conn = sqlite3.connect(DB_NAME); cursor = conn.cursor()
    cursor.execute("INSERT INTO tickets (user_id, room_id, reason) VALUES (?, ?, ?)", (uid, room_id, reason))
    ticket_id = cursor.lastrowid
    cursor.execute("SELECT username FROM users WHERE id=?", (uid,))
    username = cursor.fetchone()[0]
    cursor.execute("INSERT INTO ticket_messages (ticket_id, sender, message) VALUES (?, ?, ?)",
                   (ticket_id, username, reason))
    conn.commit(); conn.close()
    log_action(uid, 'create_ticket', room_id, f"Reason: {reason}")
    return jsonify({'success': True, 'ticket_id': ticket_id})

@app.route('/api/tickets', methods=['GET'])
def get_tickets():
    if not require_login():
        return jsonify({'error': 'Unauthorized'}), 401
    role = session.get('role')
    conn = sqlite3.connect(DB_NAME); cursor = conn.cursor()
    if role in ('admin', 'manager', 'recepcjonista'):
        cursor.execute('''
            SELECT t.id, t.room_id, r.number, t.status, u.username, t.created_at, t.reason
            FROM tickets t
            JOIN users u ON t.user_id = u.id
            JOIN rooms r ON t.room_id = r.id
            ORDER BY t.created_at DESC
        ''')
    else:
        cursor.execute('''
            SELECT t.id, t.room_id, r.number, t.status, u.username, t.created_at, t.reason
            FROM tickets t
            JOIN users u ON t.user_id = u.id
            JOIN rooms r ON t.room_id = r.id
            WHERE t.user_id = ?
            ORDER BY t.created_at DESC
        ''', (session['user_id'],))
    rows = cursor.fetchall(); conn.close()
    return jsonify([{
        'id': r[0], 'room_id': r[1], 'room_number': r[2],
        'status': r[3], 'username': r[4], 'created_at': r[5], 'reason': r[6]
    } for r in rows])

@app.route('/api/tickets/<int:ticket_id>/messages', methods=['GET'])
def get_ticket_messages(ticket_id):
    if not require_login():
        return jsonify({'error': 'Unauthorized'}), 401
    conn = sqlite3.connect(DB_NAME); cursor = conn.cursor()
    cursor.execute("""
        SELECT sender, message, timestamp FROM ticket_messages
        WHERE ticket_id=? ORDER BY timestamp ASC
    """, (ticket_id,))
    rows = cursor.fetchall(); conn.close()
    return jsonify([{'sender': r[0], 'message': r[1], 'timestamp': r[2]} for r in rows])

@app.route('/api/tickets/<int:ticket_id>/messages', methods=['POST'])
def send_ticket_message(ticket_id):
    if not require_login():
        return jsonify({'error': 'Unauthorized'}), 401
    message = (request.json or {}).get('message')
    if not message:
        return jsonify({'error': 'Missing message'}), 400
    conn = sqlite3.connect(DB_NAME); cursor = conn.cursor()
    cursor.execute("SELECT username FROM users WHERE id=?", (session['user_id'],))
    sender = cursor.fetchone()[0]
    cursor.execute("INSERT INTO ticket_messages (ticket_id, sender, message) VALUES (?, ?, ?)",
                   (ticket_id, sender, message))
    conn.commit(); conn.close()
    return jsonify({'success': True})

@app.route('/api/tickets/<int:ticket_id>/close', methods=['PUT'])
def close_ticket(ticket_id):
    if not require_login() or not has_role('admin', 'manager', 'recepcjonista'):
        return jsonify({'error': 'Unauthorized'}), 401
    conn = sqlite3.connect(DB_NAME); cursor = conn.cursor()
    cursor.execute("SELECT status FROM tickets WHERE id=?", (ticket_id,))
    t = cursor.fetchone()
    if not t:
        conn.close(); return jsonify({'error': 'Ticket not found'}), 404
    if t[0] == 'closed':
        conn.close(); return jsonify({'error': 'Ticket already closed'}), 400
    cursor.execute("UPDATE tickets SET status='closed' WHERE id=?", (ticket_id,))
    conn.commit(); conn.close()
    log_action(session['user_id'], 'close_ticket', details=f"Closed ticket ID {ticket_id}")
    return jsonify({'success': True})

@app.route('/api/tickets/<int:ticket_id>', methods=['DELETE'])
def delete_ticket(ticket_id):
    if not require_login() or not has_role('admin', 'manager', 'recepcjonista'):
        return jsonify({'error': 'Unauthorized'}), 401
    conn = sqlite3.connect(DB_NAME); cursor = conn.cursor()
    cursor.execute("SELECT status FROM tickets WHERE id=?", (ticket_id,))
    t = cursor.fetchone()
    if not t:
        conn.close(); return jsonify({'error': 'Ticket not found'}), 404
    if t[0] != 'closed':
        conn.close(); return jsonify({'error': 'Only closed tickets can be deleted'}), 400
    cursor.execute("DELETE FROM tickets WHERE id=?", (ticket_id,))
    cursor.execute("DELETE FROM ticket_messages WHERE ticket_id=?", (ticket_id,))
    conn.commit(); conn.close()
    log_action(session['user_id'], 'delete_ticket', details=f"Deleted ticket ID {ticket_id}")
    return jsonify({'success': True})

# --------------------- RESERVATIONS ---------------------
@app.route('/api/reservations', methods=['GET'])
def reservations_list():
    if not require_login():
        return jsonify({'error': 'Unauthorized'}), 401
    role = session.get('role')
    conn = sqlite3.connect(DB_NAME); cursor = conn.cursor()
    # Admin/manager/recepcjonista – wszystkie rezerwacje
    cursor.execute("""
        SELECT r.id, r.user_id, r.room_id, rooms.number, rooms.type,
               r.check_in, r.check_out, r.guest_first_name, r.guest_last_name,
               r.status, r.checked_in_at, r.checked_out_at
        FROM reservations r
        JOIN rooms ON r.room_id = rooms.id
        ORDER BY r.check_in ASC
    """)
    rows = cursor.fetchall(); conn.close()
    return jsonify([{
        'id': r[0], 'user_id': r[1], 'room_id': r[2],
        'room_number': r[3], 'room_type': r[4],
        'check_in': r[5], 'check_out': r[6],
        'guest_first_name': r[7], 'guest_last_name': r[8],
        'status': r[9], 'checked_in_at': r[10], 'checked_out_at': r[11],
    } for r in rows])

@app.route('/api/reservations', methods=['POST'])
def reservations_create():
    if not require_login() or not has_role('admin', 'manager', 'recepcjonista'):
        return jsonify({'error': 'Unauthorized'}), 401
    d = request.json or {}
    first = (d.get('guest_first_name') or '').strip()
    last  = (d.get('guest_last_name') or '').strip()
    room_id = d.get('room_id'); check_in = d.get('check_in'); check_out = d.get('check_out')
    if not first or not last or not room_id or not check_in or not check_out:
        return jsonify({'error': 'Missing fields (guest_first_name, guest_last_name, room_id, check_in, check_out)'}), 400
    try:
        ci = datetime.strptime(check_in, "%Y-%m-%d").date()
        co = datetime.strptime(check_out, "%Y-%m-%d").date()
        if ci >= co:
            return jsonify({'error': 'check_out must be after check_in'}), 400
    except ValueError:
        return jsonify({'error': 'Invalid date format, use YYYY-MM-DD'}), 400
    if not room_available(room_id, check_in, check_out):
        return jsonify({'error': 'Room is not available in this date range'}), 400

    conn = sqlite3.connect(DB_NAME); cursor = conn.cursor()
    cursor.execute("""
        INSERT INTO reservations (user_id, room_id, check_in, check_out, guest_first_name, guest_last_name, status)
        VALUES (NULL, ?, ?, ?, ?, ?, 'booked')
    """, (room_id, check_in, check_out, first, last))
    res_id = cursor.lastrowid; conn.commit(); conn.close()
    log_action(session['user_id'], 'create_reservation', room_id,
               f"res_id={res_id} guest='{first} {last}' {check_in}->{check_out}")
    return jsonify({'success': True, 'id': res_id})

@app.route('/api/reservations/<int:res_id>', methods=['PUT'])
def reservations_update(res_id):
    if not require_login() or not has_role('admin', 'manager', 'recepcjonista'):
        return jsonify({'error': 'Unauthorized'}), 401
    d = request.json or {}
    first = (d.get('guest_first_name') or '').strip()
    last  = (d.get('guest_last_name') or '').strip()
    room_id = d.get('room_id'); check_in = d.get('check_in'); check_out = d.get('check_out')
    if not first or not last or not room_id or not check_in or not check_out:
        return jsonify({'error': 'Missing fields (guest_first_name, guest_last_name, room_id, check_in, check_out)'}), 400
    try:
        ci = datetime.strptime(check_in, "%Y-%m-%d").date()
        co = datetime.strptime(check_out, "%Y-%m-%d").date()
        if ci >= co:
            return jsonify({'error': 'check_out must be after check_in'}), 400
    except ValueError:
        return jsonify({'error': 'Invalid date format, use YYYY-MM-DD'}), 400
    if not room_available(room_id, check_in, check_out, exclude_res_id=res_id):
        return jsonify({'error': 'Room is not available in this date range'}), 400

    conn = sqlite3.connect(DB_NAME); cursor = conn.cursor()
    cursor.execute("""
        UPDATE reservations
        SET user_id=NULL, room_id=?, check_in=?, check_out=?, guest_first_name=?, guest_last_name=?
        WHERE id=?
    """, (room_id, check_in, check_out, first, last, res_id))
    if cursor.rowcount == 0:
        conn.close(); return jsonify({'error': 'Reservation not found'}), 404
    conn.commit(); conn.close()
    log_action(session['user_id'], 'update_reservation', room_id,
               f"res_id={res_id} guest='{first} {last}' {check_in}->{check_out}")
    return jsonify({'success': True})

@app.route('/api/reservations/<int:res_id>', methods=['DELETE'])
def reservations_delete(res_id):
    if not require_login() or not has_role('admin', 'manager', 'recepcjonista'):
        return jsonify({'error': 'Unauthorized'}), 401
    conn = sqlite3.connect(DB_NAME); cursor = conn.cursor()
    cursor.execute("SELECT room_id FROM reservations WHERE id=?", (res_id,))
    row = cursor.fetchone()
    if not row:
        conn.close(); return jsonify({'error': 'Reservation not found'}), 404
    room_id = row[0]
    cursor.execute("DELETE FROM reservations WHERE id=?", (res_id,))
    conn.commit(); conn.close()
    log_action(session['user_id'], 'delete_reservation', room_id, f"res_id={res_id}")
    return jsonify({'success': True})

# CHECK-IN
# CHECK-IN
@app.route('/api/reservations/<int:res_id>/checkin', methods=['POST'])
def reservations_checkin(res_id):
    if not require_login() or not has_role('admin', 'manager', 'recepcjonista'):
        return jsonify({'error': 'Unauthorized'}), 401

    conn = sqlite3.connect(DB_NAME); cursor = conn.cursor()
    cursor.execute("""
        SELECT r.room_id, r.guest_first_name, r.guest_last_name, r.status, r.check_in
        FROM reservations r WHERE r.id=?
    """, (res_id,))
    row = cursor.fetchone()
    if not row:
        conn.close(); return jsonify({'error': 'Reservation not found'}), 404

    room_id, first, last, status, check_in_date = row

    if status == 'checked_in':
        conn.close(); return jsonify({'error': 'Already checked-in'}), 400

    # sprawdzenie daty
    today = datetime.today().date()
    try:
        ci = datetime.strptime(check_in_date, "%Y-%m-%d").date()
    except Exception:
        conn.close(); return jsonify({'error': 'Invalid check-in date in DB'}), 500

    if ci != today:
        conn.close(); return jsonify({'error': f'Check-in allowed only on {ci}'}), 400

    guest_name = f"{(first or '').strip()} {(last or '').strip()}".strip()
    if not guest_name:
        conn.close(); return jsonify({'error': 'Reservation has no guest name'}), 400

    # room -> occupied + guest_name + clear comment (jeśli istnieje kolumna comment)
    cursor.execute("PRAGMA table_info(rooms)")
    cols = [c[1] for c in cursor.fetchall()]
    if "comment" in cols:
        cursor.execute("UPDATE rooms SET status='occupied', guest_name=?, comment=NULL WHERE id=?", (guest_name, room_id))
    else:
        cursor.execute("UPDATE rooms SET status='occupied', guest_name=? WHERE id=?", (guest_name, room_id))

    # reservation -> checked_in
    cursor.execute("UPDATE reservations SET status='checked_in', checked_in_at=CURRENT_TIMESTAMP WHERE id=?", (res_id,))
    conn.commit(); conn.close()

    log_action(session['user_id'], 'checkin_reservation', room_id, f"res_id={res_id} guest='{guest_name}'")
    return jsonify({'success': True})


# CHECK-OUT
@app.route('/api/reservations/<int:res_id>/checkout', methods=['POST'])
def reservations_checkout(res_id):
    if not require_login() or not has_role('admin', 'manager', 'recepcjonista'):
        return jsonify({'error': 'Unauthorized'}), 401
    conn = sqlite3.connect(DB_NAME); cursor = conn.cursor()
    cursor.execute("""
        SELECT r.room_id, r.status FROM reservations r WHERE r.id=?
    """, (res_id,))
    row = cursor.fetchone()
    if not row:
        conn.close(); return jsonify({'error': 'Reservation not found'}), 404
    room_id, status = row
    if status != 'checked_in':
        conn.close(); return jsonify({'error': 'Reservation is not checked-in'}), 400

    # room -> dirty + clear guest
    cursor.execute("UPDATE rooms SET status='dirty', guest_name=NULL WHERE id=?", (room_id,))
    # reservation -> closed
    cursor.execute("UPDATE reservations SET status='closed', checked_out_at=CURRENT_TIMESTAMP WHERE id=?", (res_id,))
    conn.commit(); conn.close()
    log_action(session['user_id'], 'checkout_reservation', room_id, f"res_id={res_id}")
    return jsonify({'success': True})

# --------------------- CURRENT USER ---------------------
@app.route('/api/me', methods=['GET'])
def get_current_user():
    if not require_login():
        return jsonify({'error': 'Unauthorized'}), 401
    conn = sqlite3.connect(DB_NAME); cursor = conn.cursor()
    cursor.execute("SELECT username, role, id FROM users WHERE id=?", (session['user_id'],))
    u = cursor.fetchone(); conn.close()
    return jsonify({'username': u[0], 'role': u[1], 'id': u[2]})

if __name__ == '__main__':
    app.run(debug=True)
