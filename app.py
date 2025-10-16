from flask import Flask, request, jsonify
from flask_cors import CORS
import psycopg2
from psycopg2 import errors
from werkzeug.security import generate_password_hash, check_password_hash
import jwt
import datetime
from functools import wraps
import os

app = Flask(__name__)
CORS(app)

# --- Secret key for JWT ---
SECRET_KEY = os.environ.get('SECRET_KEY', 'fallback_secret_key')

# --- PostgreSQL connection ---
def get_db_connection():
    conn = psycopg2.connect(
        host=os.environ.get('PG_HOST'),
        database=os.environ.get('PG_DB'),
        user=os.environ.get('PG_USER'),
        password=os.environ.get('PG_PASSWORD'),
        sslmode='require'  # Required for Render PostgreSQL
    )
    return conn

# --- Initialize database ---
def init_db():
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id SERIAL PRIMARY KEY,
            phone VARCHAR(50) UNIQUE NOT NULL,
            password VARCHAR(255) NOT NULL
        )
    ''')
    conn.commit()
    cursor.close()
    conn.close()

init_db()

# --- JWT Token Verification ---
def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.headers.get('x-access-token')
        if not token:
            return jsonify({'status': 'error', 'message': 'Token is missing'}), 401
        try:
            data = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
            current_user = data['phone']
        except jwt.ExpiredSignatureError:
            return jsonify({'status': 'error', 'message': 'Token has expired'}), 401
        except Exception:
            return jsonify({'status': 'error', 'message': 'Token is invalid'}), 401
        return f(current_user, *args, **kwargs)
    return decorated

# --- Signup Route ---
@app.route('/signup', methods=['POST'])
def signup():
    data = request.json
    phone = data.get('phone')
    password = data.get('password')

    if not phone or not password:
        return jsonify({'status': 'error', 'message': 'Missing phone or password'}), 400

    hashed_pw = generate_password_hash(password)
    conn = get_db_connection()
    cursor = conn.cursor()

    try:
        cursor.execute('INSERT INTO users (phone, password) VALUES (%s, %s)', (phone, hashed_pw))
        conn.commit()
        return jsonify({'status': 'success', 'message': 'Account created successfully'})
    except errors.UniqueViolation:
        conn.rollback()
        return jsonify({'status': 'error', 'message': 'Phone already registered'}), 409
    except Exception as e:
        conn.rollback()
        return jsonify({'status': 'error', 'message': str(e)}), 500
    finally:
        cursor.close()
        conn.close()

# --- Login Route ---
@app.route('/login', methods=['POST'])
def login():
    data = request.json
    phone = data.get('phone')
    password = data.get('password')

    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('SELECT password FROM users WHERE phone=%s', (phone,))
    user = cursor.fetchone()
    cursor.close()
    conn.close()

    if not user:
        return jsonify({'status': 'error', 'message': 'User not found'}), 404

    if check_password_hash(user[0], password):
        token = jwt.encode({
            'phone': phone,
            'exp': datetime.datetime.utcnow() + datetime.timedelta(days=1)
        }, SECRET_KEY, algorithm="HS256")
        return jsonify({'status': 'success', 'token': token})
    else:
        return jsonify({'status': 'error', 'message': 'Invalid password'}), 401

# --- Protected Profile Route ---
@app.route('/profile', methods=['GET'])
@token_required
def profile(current_user):
    return jsonify({'status': 'success', 'phone': current_user})

# --- Home Route ---
@app.route('/')
def home():
    return jsonify({'message': 'Flask backend with PostgreSQL is running successfully!'})

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=10000)
