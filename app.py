from flask import Flask, render_template, request, redirect, url_for, flash, session, jsonify
from flask_cors import CORS  # CORS 추가
import sqlite3
import bcrypt
from datetime import datetime, timedelta
import uuid
from functools import wraps
from cryptography.fernet import Fernet
import json
import os

app = Flask(__name__)
app.secret_key = 'super_secret_key'
CORS(app, supports_credentials=True)  # CORS 설정, 세션 쿠키 지원

# Fernet 키 생성/로드
key_file = 'encryption_key.key'
if not os.path.exists(key_file):
    key = Fernet.generate_key()
    with open(key_file, 'wb') as f:
        f.write(key)
with open(key_file, 'rb') as f:
    key = f.read()
cipher = Fernet(key)

# 관리자 계정 파일 초기화
admin_file = 'admin.json'
if not os.path.exists(admin_file):
    admin_data = [
        {
            'admin_id': str(uuid.uuid4()),
            'username': 'admin',
            'password': bcrypt.hashpw('admin123'.encode(), bcrypt.gensalt()).decode()
        }
    ]
    encrypted_data = cipher.encrypt(json.dumps(admin_data).encode())
    with open(admin_file, 'wb') as f:
        f.write(encrypted_data)

# 데이터베이스 초기화 및 마이그레이션
def init_db():
    conn = sqlite3.connect("users.db")
    cursor = conn.cursor()
    
    # groups 테이블 생성
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS groups (
            group_id TEXT PRIMARY KEY,
            group_name TEXT UNIQUE NOT NULL
        )
    """)
    
    # users 테이블 생성 (name, contact 포함)
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            user_id TEXT PRIMARY KEY,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            allowed_ip TEXT,
            expiry_date TEXT,
            is_active BOOLEAN DEFAULT 1,
            group_id TEXT,
            name TEXT,
            contact TEXT,
            FOREIGN KEY (group_id) REFERENCES groups (group_id)
        )
    """)
    
    # users 테이블에 새 열 추가 (마이그레이션)
    try:
        cursor.execute("ALTER TABLE users ADD COLUMN group_id TEXT")
    except sqlite3.OperationalError:
        pass
    try:
        cursor.execute("ALTER TABLE users ADD COLUMN name TEXT")
    except sqlite3.OperationalError:
        pass
    try:
        cursor.execute("ALTER TABLE users ADD COLUMN contact TEXT")
    except sqlite3.OperationalError:
        pass
    
    # access_logs 테이블 생성
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS access_logs (
            log_id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id TEXT,
            ip_address TEXT,
            access_time TEXT,
            FOREIGN KEY (user_id) REFERENCES users (user_id)
        )
    """)
    
    conn.commit()
    conn.close()

# 로그인 체크 데코레이터
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'admin_id' not in session:
            flash("로그인이 필요합니다.", "danger")
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

# 관리자 계정 로드
def load_admins():
    with open(admin_file, 'rb') as f:
        encrypted_data = f.read()
    decrypted_data = cipher.decrypt(encrypted_data).decode()
    return json.loads(decrypted_data)

# 관리자 계정 저장
def save_admins(admins):
    encrypted_data = cipher.encrypt(json.dumps(admins).encode())
    with open(admin_file, 'wb') as f:
        f.write(encrypted_data)

# JSON 파싱 안전하게 처리
def safe_json_loads(data):
    if not data:
        return []
    try:
        return json.loads(data)
    except json.JSONDecodeError:
        return [data] if data else []

# 로그인 페이지
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        admins = load_admins()
        for admin in admins:
            if admin['username'] == username and bcrypt.checkpw(password.encode(), admin['password'].encode()):
                session['admin_id'] = admin['admin_id']
                flash("로그인 성공!", "success")
                return redirect(url_for('home'))
        
        return render_template('login.html', error="아이디 또는 비밀번호가 잘못되었습니다.")
    
    return render_template('login.html', error=None)

# 로그아웃
@app.route('/logout')
def logout():
    session.pop('admin_id', None)
    flash("로그아웃되었습니다.", "success")
    return redirect(url_for('login'))

# 인증 상태 확인 API
@app.route('/check-auth', methods=['GET'])
def check_auth():
    if 'admin_id' in session:
        return jsonify({"authenticated": True}), 200
    return jsonify({"authenticated": False}), 401

# 관리자 설정 페이지
@app.route('/admin_settings', methods=['GET', 'POST'])
@login_required
def admin_settings():
    admins = load_admins()
    current_admin = next((admin for admin in admins if admin['admin_id'] == session['admin_id']), None)
    
    if not current_admin:
        flash("관리자 계정을 찾을 수 없습니다.", "danger")
        return redirect(url_for('home'))

    if request.method == 'POST':
        new_username = request.form['username']
        new_password = request.form['password']
        
        try:
            if not new_username:
                raise ValueError("아이디를 입력해야 합니다.")
            if not new_password:
                raise ValueError("비밀번호를 입력해야 합니다.")
            if len(new_password) < 8:
                raise ValueError("비밀번호는 최소 8자 이상이어야 합니다.")
            
            current_admin['username'] = new_username
            current_admin['password'] = bcrypt.hashpw(new_password.encode(), bcrypt.gensalt()).decode()
            
            save_admins(admins)
            flash("관리자 계정 정보가 변경되었습니다. 다시 로그인해주세요.", "success")
            session.pop('admin_id', None)
            return redirect(url_for('login'))
        except ValueError as e:
            return render_template('admin_settings.html', error=str(e), username=current_admin['username'])
    
    return render_template('admin_settings.html', error=None, username=current_admin['username'])

# 그룹 관리 페이지
@app.route('/groups', methods=['GET', 'POST'])
@login_required
def manage_groups():
    conn = sqlite3.connect("users.db")
    cursor = conn.cursor()
    
    if request.method == 'POST':
        if 'add' in request.form:
            group_name = request.form['group_name']
            if not group_name:
                flash("그룹 이름을 입력하세요.", "danger")
            else:
                try:
                    group_id = str(uuid.uuid4())
                    cursor.execute(
                        "INSERT INTO groups (group_id, group_name) VALUES (?, ?)",
                        (group_id, group_name)
                    )
                    conn.commit()
                    flash(f"그룹 '{group_name}' 추가 완료!", "success")
                except sqlite3.IntegrityError:
                    flash("이미 존재하는 그룹 이름입니다.", "danger")
        
        elif 'delete' in request.form:
            group_id = request.form['group_id']
            cursor.execute("SELECT group_name FROM groups WHERE group_id = ?", (group_id,))
            group = cursor.fetchone()
            if not group:
                flash("그룹을 찾을 수 없습니다.", "danger")
            else:
                # 그룹에 속한 사용자들의 group_id를 NULL로 설정
                cursor.execute("UPDATE users SET group_id = NULL WHERE group_id = ?", (group_id,))
                cursor.execute("DELETE FROM groups WHERE group_id = ?", (group_id,))
                conn.commit()
                flash(f"그룹 '{group[0]}' 삭제 완료!", "success")
    
    cursor.execute("SELECT group_id, group_name FROM groups")
    groups = cursor.fetchall()
    conn.close()
    return render_template('groups.html', groups=groups)

# 홈 페이지
@app.route('/', methods=['GET', 'POST'])
@login_required
def home():
    conn = sqlite3.connect("users.db")
    cursor = conn.cursor()
    
    # 그룹 목록 가져오기
    cursor.execute("SELECT group_id, group_name FROM groups")
    groups = cursor.fetchall()
    
    # 선택된 그룹 및 검색어
    selected_group_id = request.form.get('group_id', 'all') if request.method == 'POST' else 'all'
    search_term = request.form.get('search_term', '').strip()
    
    # 사용자 목록 가져오기
    query = "SELECT user_id, username, allowed_ip, expiry_date, is_active, group_id, name, contact FROM users WHERE is_active = 1"
    params = []
    
    if search_term:
        query += " AND username LIKE ?"
        params.append(f"%{search_term}%")
    
    if selected_group_id != 'all':
        query += " AND group_id = ?"
        params.append(selected_group_id)
    
    cursor.execute(query, params)
    users = cursor.fetchall()
    # allowed_ip와 group_id 처리
    users = [(u[0], u[1], safe_json_loads(u[2]), u[3], u[4], u[5], u[6], u[7]) for u in users]
    
    conn.close()
    return render_template('index.html', users=users, groups=groups, selected_group_id=selected_group_id, search_term=search_term)

# 사용자 추가 페이지
@app.route('/add', methods=['GET', 'POST'])
@login_required
def add_user():
    conn = sqlite3.connect("users.db")
    cursor = conn.cursor()
    cursor.execute("SELECT group_id, group_name FROM groups")
    groups = cursor.fetchall()
    
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        allowed_ip = request.form['allowed_ip'] or None
        days_valid = request.form['days_valid'] or 30
        group_id = request.form['group_id'] or None
        name = request.form['name'] or None
        contact = request.form['contact'] or None

        try:
            days_valid = int(days_valid)
            if days_valid <= 0:
                raise ValueError("유효 기간은 0보다 커야 합니다.")
            hashed_password = bcrypt.hashpw(password.encode(), bcrypt.gensalt())
            expiry_date = (datetime.now() + timedelta(days=days_valid)).isoformat()
            user_id = str(uuid.uuid4())
            
            # 여러 IP 처리
            allowed_ip_list = [ip.strip() for ip in allowed_ip.split(',')] if allowed_ip else []
            allowed_ip_json = json.dumps(allowed_ip_list)

            cursor.execute(
                "INSERT INTO users (user_id, username, password, allowed_ip, expiry_date, is_active, group_id, name, contact) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (user_id, username, hashed_password, allowed_ip_json, expiry_date, True, group_id, name, contact)
            )
            conn.commit()
            flash(f"사용자 '{username}' 추가 완료!", "success")
            conn.close()
            return redirect(url_for('home'))
        except sqlite3.IntegrityError:
            conn.close()
            return render_template('add.html', error="이미 존재하는 사용자 이름입니다.", groups=groups)
        except ValueError as e:
            conn.close()
            return render_template('add.html', error=str(e), groups=groups)
    
    conn.close()
    return render_template('add.html', error=None, groups=groups)

# 사용자 삭제
@app.route('/delete/<user_id>')
@login_required
def delete_user(user_id):
    conn = sqlite3.connect("users.db")
    cursor = conn.cursor()
    cursor.execute("UPDATE users SET is_active = 0 WHERE user_id = ? AND is_active = 1", (user_id,))
    if cursor.rowcount == 0:
        flash("삭제 실패: 사용자를 찾을 수 없거나 이미 비활성화되었습니다.", "danger")
    else:
        flash("사용자 삭제 완료!", "success")
    conn.commit()
    conn.close()
    return redirect(url_for('home'))

# 사용자 편집 페이지
@app.route('/edit/<user_id>', methods=['GET', 'POST'])
@login_required
def edit_user(user_id):
    conn = sqlite3.connect("users.db")
    cursor = conn.cursor()
    cursor.execute("SELECT user_id, username, allowed_ip, expiry_date, group_id, name, contact FROM users WHERE user_id = ?", (user_id,))
    user = cursor.fetchone()
    
    if not user:
        flash("사용자를 찾을 수 없습니다.", "danger")
        conn.close()
        return redirect(url_for('home'))

    allowed_ip_list = safe_json_loads(user[2])
    allowed_ip_str = ', '.join(allowed_ip_list)
    cursor.execute("SELECT group_id, group_name FROM groups")
    groups = cursor.fetchall()

    if request.method == 'POST':
        allowed_ip = request.form['allowed_ip'] or None
        expiry_date = request.form['expiry_date']
        password = request.form.get('password')
        group_id = request.form['group_id'] or None
        name = request.form['name'] or None
        contact = request.form['contact'] or None

        try:
            expiry_dt = datetime.fromisoformat(expiry_date)
            if expiry_dt < datetime.now():
                raise ValueError("만료일은 현재 시간보다 미래여야 합니다.")
            
            allowed_ip_list = [ip.strip() for ip in allowed_ip.split(',')] if allowed_ip else []
            allowed_ip_json = json.dumps(allowed_ip_list)
            
            updates = {"allowed_ip": allowed_ip_json, "expiry_date": expiry_date, "group_id": group_id, "name": name, "contact": contact}
            if password:
                hashed_password = bcrypt.hashpw(password.encode(), bcrypt.gensalt())
                updates["password"] = hashed_password

            cursor.execute(
                "UPDATE users SET allowed_ip = ?, expiry_date = ?, group_id = ?, name = ?, contact = ?" + (", password = ?" if password else "") + 
                " WHERE user_id = ?",
                ([updates["allowed_ip"], updates["expiry_date"], updates["group_id"], updates["name"], updates["contact"]] + ([hashed_password] if password else []) + [user_id])
            )
            conn.commit()
            flash(f"사용자 '{user[1]}' 정보 수정 완료!", "success")
            conn.close()
            return redirect(url_for('home'))
        except ValueError as e:
            conn.close()
            return render_template('edit.html', user=user, allowed_ip=allowed_ip_str, groups=groups, error=str(e))
    
    conn.close()
    return render_template('edit.html', user=user, allowed_ip=allowed_ip_str, groups=groups, error=None)

# 접속 테스트 (IP 자동 감지)
@app.route('/test_access/<user_id>')
@login_required
def test_access(user_id):
    conn = sqlite3.connect("users.db")
    cursor = conn.cursor()
    cursor.execute("SELECT username, is_active, expiry_date, allowed_ip FROM users WHERE user_id = ?", (user_id,))
    user = cursor.fetchone()
    
    if not user:
        flash("사용자를 찾을 수 없습니다.", "danger")
        conn.close()
        return redirect(url_for('home'))
    
    username, is_active, expiry_date, allowed_ip = user
    ip_address = request.remote_addr or 'unknown'
    allowed_ip_list = safe_json_loads(allowed_ip)
    
    if not is_active:
        flash("비활성화된 사용자입니다.", "danger")
        conn.close()
        return redirect(url_for('home'))
    
    if datetime.fromisoformat(expiry_date) < datetime.now():
        flash("사용자 계정이 만료되었습니다.", "danger")
        conn.close()
        return redirect(url_for('home'))
    
    if allowed_ip_list and ip_address not in allowed_ip_list:
        flash(f"허용되지 않은 IP ({ip_address})입니다.", "danger")
        conn.close()
        return redirect(url_for('home'))
    
    cursor.execute(
        "INSERT INTO access_logs (user_id, ip_address, access_time) VALUES (?, ?, ?)",
        (user_id, ip_address, datetime.now().isoformat())
    )
    conn.commit()
    flash(f"'{username}' 접속 기록 완료: {ip_address}", "success")
    conn.close()
    return redirect(url_for('home'))

# 접속 로그 확인
@app.route('/logs/<user_id>', methods=['GET'])
@login_required
def view_logs(user_id):
    conn = sqlite3.connect("users.db")
    cursor = conn.cursor()
    cursor.execute("SELECT username FROM users WHERE user_id = ?", (user_id,))
    user = cursor.fetchone()
    
    if not user:
        flash("사용자를 찾을 수 없습니다.", "danger")
        conn.close()
        return redirect(url_for('home'))
    
    username = user[0]
    cursor.execute("SELECT log_id, access_time, ip_address FROM access_logs WHERE user_id = ? ORDER BY access_time DESC", (user_id,))
    logs = cursor.fetchall()
    conn.close()
    return render_template('logs.html', username=username, logs=logs, user_id=user_id)

# 개별 로그 삭제
@app.route('/delete_log/<log_id>/<user_id>')
@login_required
def delete_log(log_id, user_id):
    conn = sqlite3.connect("users.db")
    cursor = conn.cursor()
    cursor.execute("DELETE FROM access_logs WHERE log_id = ? AND user_id = ?", (log_id, user_id))
    if cursor.rowcount == 0:
        flash("로그를 찾을 수 없습니다.", "danger")
    else:
        flash("로그 삭제 완료!", "success")
    conn.commit()
    conn.close()
    return redirect(url_for('view_logs', user_id=user_id))

# 전체 로그 삭제
@app.route('/delete_all_logs/<user_id>')
@login_required
def delete_all_logs(user_id):
    conn = sqlite3.connect("users.db")
    cursor = conn.cursor()
    cursor.execute("DELETE FROM access_logs WHERE user_id = ?", (user_id,))
    flash("모든 로그 삭제 완료!", "success")
    conn.commit()
    conn.close()
    return redirect(url_for('view_logs', user_id=user_id))

if __name__ == '__main__':
    init_db()
    port = int(os.getenv("PORT", 5000))
    app.run(host='0.0.0.0', port=port, debug=False)