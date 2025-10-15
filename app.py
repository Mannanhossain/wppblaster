from flask import Flask, request, jsonify
from flask_cors import CORS
import psycopg2
from psycopg2.extras import RealDictCursor
from werkzeug.security import generate_password_hash, check_password_hash
import jwt
import datetime
from functools import wraps
import os

app = Flask(__name__)
CORS(app)

SECRET_KEY = os.environ.get('SECRET_KEY')

# --- PostgreSQL connection ---
def get_db_connection():
    conn = psycopg2.connect(
        host=os.environ.get('PG_HOST'),
        database=os.environ.get('PG_DB'),
        user=os.environ.get('PG_USER'),
        password=os.environ.get('PG_PASSWORD')
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

# --- JWT token decorator ---
def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.headers.get('x-access-token')
        if not token:
            return jsonify({'status': 'error', 'message': 'Token is missing'}), 401
        try:
            data = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
            current_user = data['phone']
        except:
            return jsonify({'status': 'error', 'message': 'Token is invalid'}), 401
        return f(current_user, *args, **kwargs)
    return decorated

# --- Signup route ---
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
    except psycopg2.errors.UniqueViolation:
        conn.rollback()
        return jsonify({'status': 'error', 'message': 'Phone already registered'}), 409
    finally:
        cursor.close()
        conn.close()

# --- Login route ---
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

# --- Protected route ---
@app.route('/profile')
@token_required
def profile(current_user):
    return jsonify({'status': 'success', 'phone': current_user})

@app.route('/')
def home():
    return jsonify({'message': 'Flask backend is running'})

if __name__ == '__main__':
    app.run(host='0.0.0.0')
