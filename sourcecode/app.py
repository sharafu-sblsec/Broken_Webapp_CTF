from flask import Flask, render_template, request, redirect,jsonify
import sqlite3
import hashlib
import os
import random
import base64

app = Flask(__name__)
app.secret_key = os.urandom(24)  

DATABASE = 'bank.db'

def get_db():
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    create_tables_if_not_exist(conn)
    return conn

def create_tables_if_not_exist(conn):
    conn.execute("""
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        fullname TEXT NOT NULL,
        username TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        account_number TEXT UNIQUE NOT NULL,
        balance REAL DEFAULT 0.0,
        is_admin INTEGER DEFAULT 0
    );
    """)
    
    conn.execute("""
    CREATE TABLE IF NOT EXISTS transactions (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        sender_id INTEGER,
        receiver_id INTEGER,
        amount REAL,
        timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
    );
    """)

    conn.execute("""
    CREATE TABLE IF NOT EXISTS closure_requests (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        request_time DATETIME DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES users(id)
    );
    """)
    conn.commit()


def generate_token(userid, is_admin):
    token_data = f"{userid}:admin={is_admin}"
    token_hash = hashlib.sha1(token_data.encode()).hexdigest()
    raw_token = f"{token_data}:{token_hash}"
    return base64.b64encode(raw_token.encode()).decode()

def verify_token(token):
    try:
       
        decoded = base64.b64decode(token).decode()
        parts = decoded.split(':')
        if len(parts) != 3:
            return None

        userid, admin_part, signature = parts
        data = f"{userid}:{admin_part}"
        expected_sig = hashlib.sha1(data.encode()).hexdigest()
        if signature != expected_sig:
            return None
        return {"user_id": int(userid), "is_admin": int(admin_part.split('=')[1])}
    except:
        return None

@app.route('/')
def home():
    return redirect('/login')

@app.route('/login', methods=['GET', 'POST'])
def login():
    db = get_db()

    
    user_count = db.execute("SELECT COUNT(*) FROM users").fetchone()[0]
    if user_count == 0:
        default_users = [
            {
                "fullname": "VajraPoocha",
                "username": "admin",
                "password": "$0n4Poocha",
                "account_number": "ADM0001",
                "balance": 0.0,
                "is_admin": 1
            },
            {
                "fullname": "APT2002D",
                "username": "sharafu",
                "password": "sharafu@poocha755",
                "account_number": "1010201000",
                "balance": 2567888.0,
                "is_admin": 0
            },
            {
                "fullname": "Michael de santa",
                "username": "michael",
                "password": "michael987654321",
                "account_number": "2020102020",
                "balance": 4567888.0,
                "is_admin": 0
            }
        ]

        for user in default_users:
            password_hash = hashlib.sha256(user['password'].encode()).hexdigest()
            db.execute("""
                INSERT INTO users (fullname, username, password_hash, account_number, balance, is_admin)
                VALUES (?, ?, ?, ?, ?, ?)
            """, (
                user['fullname'],
                user['username'],
                password_hash,
                user['account_number'],
                user['balance'],
                user['is_admin']
            ))
        db.commit()

    
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')

        
        if not username or not password:
            return render_template('login.html', error="Both fields are required.")
        if not username.replace('_', '').isalnum():
            return render_template('login.html', error="Invalid username format.")
        if len(password) < 6 or len(password) > 50:
            return render_template('login.html', error="Invalid password length.")

        hashed_pw = hashlib.sha256(password.encode()).hexdigest()
        user = db.execute("SELECT * FROM users WHERE username = ? AND password_hash = ?",
                          (username, hashed_pw)).fetchone()

        if user:
            token = generate_token(user['id'], user['is_admin'])
             
            redirect_url = f'/admin?id={user["id"]}' if user['is_admin'] else f'/dashboard?id={user["id"]}'
            response = redirect(redirect_url)
            response.set_cookie('token', token)  
            return response
        else:
            return render_template('login.html', error=True)

    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        fullname = request.form.get('fullname', '').strip()
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '').strip()

        
        if not fullname or not username or not password:
            return render_template('register.html', registered=False, username_taken=False)

        
        if '<' in fullname or '>' in fullname or '<' in username or '>' in username:
            return render_template('register.html', registered=False, username_taken=False, invalid_username=True)
        
        if len(password) < 6 or len(password) > 50:
           return render_template('register.html', registered=False, username_taken=False, weak_password=True)

        
        if '<' in fullname or '>' in fullname or '<' in username or '>' in username:
           return render_template('register.html', registered=False, username_taken=False, invalid_username=True)
        
        if not fullname or not username or not password:
           return render_template('register.html', registered=False, username_taken=False, missing_fields=True)
        

        db = get_db()

        
        existing_user = db.execute("SELECT id FROM users WHERE username = ?", (username,)).fetchone()
        if existing_user:
            return render_template('register.html', username_taken=True, registered=False)

        
        while True:
            account_number = str(random.randint(1000000000, 9999999999))  # 10 digit mathi
            existing_acc = db.execute("SELECT id FROM users WHERE account_number = ?", (account_number,)).fetchone()
            if not existing_acc:
                break

        
        hashed_pw = hashlib.sha256(password.encode()).hexdigest()

         
        db.execute("""
            INSERT INTO users (fullname, username, password_hash, account_number, is_admin)
            VALUES (?, ?, ?, ?, 0)
        """, (fullname, username, hashed_pw, account_number))
        db.commit()

        
        return render_template('register.html', registered=True, username_taken=False)

    
    return render_template('register.html', registered=False, username_taken=False)



@app.route('/dashboard')
def dashboard():
    db = get_db()

    user_id = request.args.get('id')
    token = request.cookies.get('token')

    if not user_id or not token:
        return redirect('/login')

    try:
        decoded = base64.b64decode(token).decode()
        token_user_id, token_admin, token_hash = decoded.split(':')
    except Exception:
        return redirect('/login')

    
    token_base = f"{token_user_id}:{token_admin}"
    expected_hash = hashlib.sha1(token_base.encode()).hexdigest()

    if expected_hash != token_hash:
        return redirect('/login')

    if token_user_id != user_id:
        return redirect('/login')

    user = db.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
    if not user:
        return redirect('/login')

    return render_template('dashboard.html',
                           fullname=user['fullname'],
                           account_number=user['account_number'],
                           balance=user['balance'],
                           user_id=user_id)

@app.route('/admin')
def admin_dashboard():
    db = get_db()

    token = request.cookies.get('token')
    user_id = request.args.get('id')

    if not token or not user_id:
        return redirect('/login')

    try:
        decoded = base64.b64decode(token).decode()
        token_user_id, token_admin, token_hash = decoded.split(':')
    except Exception:
        return redirect('/login')

    
    token_base = f"{token_user_id}:{token_admin}"
    expected_hash = hashlib.sha1(token_base.encode()).hexdigest()

    if expected_hash != token_hash:
        return redirect('/login')

    
    if token_user_id != user_id:
        return redirect('/login')

    
    if token_admin != "admin=1":
        return redirect('/login')

    admin_info = db.execute("SELECT * FROM users WHERE id = ? AND is_admin = 1", (user_id,)).fetchone()
    if not admin_info:
        return redirect('/login')

    users = db.execute("SELECT * FROM users WHERE is_admin = 0").fetchall()
    closure_requests = db.execute("""
        SELECT cr.user_id, cr.request_time, u.fullname, u.account_number
        FROM closure_requests cr
        JOIN users u ON cr.user_id = u.id
    """).fetchall()

    return render_template('admindashboard.html',
                           fullname=admin_info['fullname'],
                           account_number=admin_info['account_number'],
                           users=users,
                           closure_requests=closure_requests)


@app.route('/close_account', methods=['POST'])
def close_account_request():
    db = get_db()

    token = request.cookies.get('token')
    if not token:
        return redirect('/login')

    try:
        decoded = base64.b64decode(token).decode()
        token_user_id, token_admin, token_hash = decoded.split(':')
    except Exception:
        return redirect('/login')

    
    token_base = f"{token_user_id}:{token_admin}"
    expected_hash = hashlib.sha1(token_base.encode()).hexdigest()

    if expected_hash != token_hash:
        return redirect('/login')

    
    user_id = token_user_id

    
    existing = db.execute("SELECT * FROM closure_requests WHERE user_id = ?", (user_id,)).fetchone()
    if existing:
        return redirect(f'/dashboard?id={user_id}')  

    
    db.execute("INSERT INTO closure_requests (user_id) VALUES (?)", (user_id,))
    db.commit()

    return redirect(f'/dashboard?id={user_id}')


@app.route('/transfer', methods=['GET'])
def transfer():
    db = get_db()

    user_id = request.args.get('id')
    token = request.cookies.get('token')

    if not user_id or not token:
        return redirect('/login')

    try:
        decoded = base64.b64decode(token).decode()
        token_user_id, token_admin, token_hash = decoded.split(':')
    except Exception:
        return redirect('/login')

    
    token_base = f"{token_user_id}:{token_admin}"
    expected_hash = hashlib.sha1(token_base.encode()).hexdigest()

    if expected_hash != token_hash:
        return redirect('/login')

    if token_user_id != user_id:
        return redirect('/login')

    
    user = db.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
    if not user:
        return redirect('/login')

    return render_template('transfer.html',
                           fullname=user['fullname'],
                           account_number=user['account_number'],
                           balance=user['balance'],
                           user_id=user['id'])

@app.route('/moneytransfer', methods=['POST'])
def moneytransfer():
    db = get_db()
    token = request.cookies.get('token')

    if not token:
        return redirect('/login')

    
    try:
        decoded = base64.b64decode(token).decode()
        token_user_id, token_admin, token_hash = decoded.split(':')
    except Exception:
        return redirect('/login')

    token_base = f"{token_user_id}:{token_admin}"
    expected_hash = hashlib.sha1(token_base.encode()).hexdigest()

    if expected_hash != token_hash:
        return redirect('/login')

    user_id = token_user_id  

    
    recipient_account = request.form.get('recipient_account', '').strip()
    amount_str = request.form.get('amount', '').strip()

    
    if not recipient_account.isdigit():
        return jsonify({"error": "Invalid account number."}), 400

    
    try:
        amount = float(amount_str)
        if amount <= 0:
            return jsonify({"error": "Amount must be greater than zero."}), 400
    except ValueError:
        return jsonify({"error": "Please enter a valid amount."}), 400

    
    sender = db.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
    if not sender:
        return redirect('/login')

    
    if sender['balance'] < amount:
        return jsonify({"error": "Insufficient funds."}), 400

    
    recipient = db.execute("SELECT * FROM users WHERE account_number = ?", (recipient_account,)).fetchone()
    if not recipient:
        return jsonify({"error": "Recipient account not found."}), 400

    
    try:
        db.execute("UPDATE users SET balance = balance - ? WHERE id = ?", (amount, sender['id']))
        db.execute("UPDATE users SET balance = balance + ? WHERE id = ?", (amount, recipient['id']))
        db.execute("INSERT INTO transactions (sender_id, receiver_id, amount) VALUES (?, ?, ?)",
                   (sender['id'], recipient['id'], amount))
        db.commit()
    except Exception as e:
        return jsonify({"error": "Transfer failed. Please try again."}), 500

    return jsonify({"success": f"Transferred ${amount:.2f} to {recipient_account}"})


@app.route('/admin/user/<int:user_id>')
def view_user(user_id):
    db = get_db()
    token = request.cookies.get('token')

    
    if not token:
        return redirect('/login')

     
    try:
        decoded = base64.b64decode(token).decode()
        token_user_id, token_admin, token_hash = decoded.split(':')
    except Exception:
        return redirect('/login')

    token_base = f"{token_user_id}:{token_admin}"
    expected_hash = hashlib.sha1(token_base.encode()).hexdigest()

    if expected_hash != token_hash:
        return redirect('/login')

    
    admin_user = db.execute("SELECT * FROM users WHERE id = ?", (token_user_id,)).fetchone()
    if not admin_user or admin_user['is_admin'] != 1:
        return redirect('/login')  

    
    user = db.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
    if not user:
        return render_template("error.html", message="User not found.")  

    return render_template("view_user.html", user=user)


@app.route('/admin/add-money/<int:user_id>', methods=['GET', 'POST'])
def add_money(user_id):
    db = get_db()
    token = request.cookies.get('token')

    
    if not token:
        return redirect('/login')

    
    try:
        decoded = base64.b64decode(token).decode()
        token_user_id, token_admin, token_hash = decoded.split(':')
    except Exception:
        return redirect('/login')

    token_base = f"{token_user_id}:{token_admin}"
    expected_hash = hashlib.sha1(token_base.encode()).hexdigest()

    if expected_hash != token_hash:
        return redirect('/login')

    admin = db.execute("SELECT * FROM users WHERE id = ?", (token_user_id,)).fetchone()
    if not admin or admin['is_admin'] != 1:
        return redirect('/login')

    
    user = db.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
    if not user:
        return render_template("error.html", message="User not found.")

    
    if request.method == 'POST':
        amount_str = request.form.get('amount', '').strip()
        try:
            amount = float(amount_str)
            if amount <= 0:
                return render_template("addmoney.html", user=user, error="Enter a positive amount.")
        except ValueError:
            return render_template("addmoney.html", user=user, error="Invalid amount.")

        
        db.execute("UPDATE users SET balance = balance + ? WHERE id = ?", (amount, user_id))
        db.commit()

        
        return render_template("addmoney.html", user=user, success=f"${amount:.2f} added to {user['fullname']}!")

    return render_template("addmoney.html", user=user)


@app.route('/admin/delete-user/<int:user_id>', methods=['GET', 'POST'])
def delete_user(user_id):
    db = get_db()
    token = request.cookies.get('token')

    
    if not token:
        return redirect('/login')
    
    
    try:
        decoded = base64.b64decode(token).decode()
        token_user_id, token_admin, token_hash = decoded.split(':')
    except Exception:
        return redirect('/login')

    token_base = f"{token_user_id}:{token_admin}"
    expected_hash = hashlib.sha1(token_base.encode()).hexdigest()

    if expected_hash != token_hash:
        return redirect('/login')

    admin = db.execute("SELECT * FROM users WHERE id = ?", (token_user_id,)).fetchone()
    if not admin or admin['is_admin'] != 1:
        return redirect('/login')

    
    user = db.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
    if not user:
        return render_template("error.html", message="User not found.")

    if request.method == 'POST':
        
        db.execute("DELETE FROM users WHERE id = ?", (user_id,))
        db.commit()

        
        return render_template("deleteuser.html", user=user, deleted=True)

    return render_template("deleteuser.html", user=user)


@app.route('/admin/closure/<int:user_id>')
def view_closure_request(user_id):
    db = get_db()
    token = request.cookies.get('token')

    
    if not token:
        return redirect('/login')

    try:
        decoded = base64.b64decode(token).decode()
        token_user_id, token_admin, token_hash = decoded.split(':')
    except Exception:
        return redirect('/login')

    token_base = f"{token_user_id}:{token_admin}"
    expected_hash = hashlib.sha1(token_base.encode()).hexdigest()

    if expected_hash != token_hash:
        return redirect('/login')

    admin = db.execute("SELECT * FROM users WHERE id = ?", (token_user_id,)).fetchone()
    if not admin or admin['is_admin'] != 1:
        return redirect('/login')

    
    closure_request = db.execute(
        "SELECT * FROM closure_requests WHERE user_id = ?", (user_id,)
    ).fetchone()

    if not closure_request:
        return render_template("error.html", message="No closure request found for this user.")

    
    user = db.execute(
        "SELECT fullname, account_number FROM users WHERE id = ?", (user_id,)
    ).fetchone()

    if not user:
        return render_template("error.html", message="User not found.")

    return render_template(
        "accountclose.html",
        user_id=user_id,
        fullname=user['fullname'],
        account_number=user['account_number']
    )


@app.route('/logout')
def logout():
    response = redirect('/login')
    response.set_cookie('token', '', expires=0, path='/')
    return response

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000,debug=True)