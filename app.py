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
# Enable CORS for all domains, adjust this for security in a final production environment
CORS(app) 

# --- Secret key for JWT ---
# Use the environment variable, or a secure default if necessary (though environment is better)
SECRET_KEY = os.environ.get('SECRET_KEY', 'a_very_secure_fallback_secret_key_if_env_is_missing')

# --- PostgreSQL connection ---
def get_db_connection():
    # 1. Get the full URI from the environment variable (e.g., DATABASE_URL)
    db_uri = os.environ.get('DATABASE_URL')
    
    if not db_uri:
        raise Exception("DATABASE_URL environment variable is not set. Cannot connect to database.")

    # 2. Fix the scheme if necessary (psycopg2 often needs 'postgresql://' instead of 'postgres://')
    if db_uri.startswith("postgres://"):
        db_uri = db_uri.replace("postgres://", "postgresql://", 1)
    
    # 3. Connect using the single URI string, including sslmode for Render
    # The connection string now contains the host, database, user, and password
    conn = psycopg2.connect(db_uri, sslmode='require')
    
    return conn

# --- Initialize database ---
# This runs immediately when Gunicorn loads the application
def init_db():
    try:
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
        print("Database initialized successfully.")
    except Exception as e:
        # It's okay if this fails on a running deployment, but critical to debug a new deploy
        print(f"Error initializing database: {e}") 
        # For deployment, if this fails, the app will exit, leading to the deployment timeout.
        # This confirms why fixing the connection in get_db_connection was crucial.

# The function call to initialize the database
init_db()

# --- JWT Token Verification ---
def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.headers.get('x-access-token')
        if not token:
            return jsonify({'status': 'error', 'message': 'Token is missing'}), 401
        try:
            # Note: Ensure the SECRET_KEY for encoding matches the one used here
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
    conn = None
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute('INSERT INTO users (phone, password) VALUES (%s, %s)', (phone, hashed_pw))
        conn.commit()
        return jsonify({'status': 'success', 'message': 'Account created successfully'})
    except errors.UniqueViolation:
        if conn: conn.rollback()
        return jsonify({'status': 'error', 'message': 'Phone already registered'}), 409
    except Exception as e:
        if conn: conn.rollback()
        return jsonify({'status': 'error', 'message': str(e)}), 500
    finally:
        if conn: 
            cursor.close()
            conn.close()

# --- Login Route ---
@app.route('/login', methods=['POST'])
def login():
    data = request.json
    phone = data.get('phone')
    password = data.get('password')

    conn = None
    user = None
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute('SELECT password FROM users WHERE phone=%s', (phone,))
        user = cursor.fetchone()
    finally:
        if conn:
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

# ❌ The local development server startup has been removed.
# Gunicorn will handle the production startup by running: gunicorn --bind 0.0.0.0:$PORT app:app