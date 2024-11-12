from flask import Flask, render_template, request, redirect, url_for, session, flash
from flask_session import Session
import sqlite3
import re
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your_secret_key'
app.config['SESSION_TYPE'] = 'filesystem'
Session(app)

DATABASE = 'campus_board.db'

# Database setup
def init_db():
    with sqlite3.connect(DATABASE) as conn:
        cursor = conn.cursor()
        cursor.execute('''CREATE TABLE IF NOT EXISTS users (
                            id INTEGER PRIMARY KEY AUTOINCREMENT,
                            nickname TEXT UNIQUE NOT NULL,
                            email TEXT UNIQUE NOT NULL,
                            password TEXT NOT NULL
                        )''')
        cursor.execute('''CREATE TABLE IF NOT EXISTS posts (
                            id INTEGER PRIMARY KEY AUTOINCREMENT,
                            nickname TEXT NOT NULL,
                            content TEXT NOT NULL,
                            tag TEXT NOT NULL,
                            created_at DATETIME DEFAULT CURRENT_TIMESTAMP
                        )''')
        cursor.execute('''CREATE TABLE IF NOT EXISTS votes (
                            id INTEGER PRIMARY KEY AUTOINCREMENT,
                            post_id INTEGER,
                            nickname TEXT,
                            vote_type INTEGER
                        )''')
        cursor.execute('''CREATE TABLE IF NOT EXISTS comments (
                            id INTEGER PRIMARY KEY AUTOINCREMENT,
                            post_id INTEGER,
                            nickname TEXT,
                            content TEXT NOT NULL,
                            created_at DATETIME DEFAULT CURRENT_TIMESTAMP
                        )''')
init_db()

# Registration validation
def is_valid_email(email):
    return re.match(r'^[\w\.-]+@poornima\.org$', email)

def is_valid_password(password):
    return len(password) >= 8 and \
           re.search(r'[A-Z]', password) and \
           re.search(r'[a-z]', password) and \
           re.search(r'[0-9]', password) and \
           re.search(r'[@$!%*?&]', password)

# Routes
@app.route('/')
def index():
    if 'nickname' not in session:
        return redirect(url_for('login'))
    
    nickname = session['nickname']
    with sqlite3.connect(DATABASE) as conn:
        cursor = conn.cursor()
        cursor.execute('SELECT DISTINCT DATE(created_at) AS post_date FROM posts ORDER BY post_date DESC')
        distinct_dates = [{'post_date': row[0]} for row in cursor.fetchall()]
        
        cursor.execute('SELECT * FROM posts ORDER BY created_at DESC')
        posts = [{'id': row[0], 'nickname': row[1], 'content': row[2], 'tag': row[3],
                  'created_at': row[4], 'upvotes': 0, 'downvotes': 0, 'comments': [], 'user_vote_type': 0} 
                 for row in cursor.fetchall()]

    return render_template('index.html', distinct_dates=distinct_dates, posts=posts)

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        nickname = request.form['nickname']
        email = request.form['email']
        password = request.form['password']
        
        if not is_valid_email(email):
            flash('Invalid email. Must be @poornima.org', 'error')
            return redirect(url_for('register'))
        
        if not is_valid_password(password):
            flash('Password must be at least 8 characters and contain uppercase, lowercase, numbers, and symbols.', 'error')
            return redirect(url_for('register'))
        
        hashed_password = generate_password_hash(password)
        
        with sqlite3.connect(DATABASE) as conn:
            cursor = conn.cursor()
            try:
                cursor.execute('INSERT INTO users (nickname, email, password) VALUES (?, ?, ?)',
                               (nickname, email, hashed_password))
                conn.commit()
                flash('Registration successful! Please log in.', 'success')
                return redirect(url_for('login'))
            except sqlite3.IntegrityError:
                flash('Nickname or email already taken.', 'error')
                return redirect(url_for('register'))
    
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        nickname = request.form['nickname']
        password = request.form['password']
        
        with sqlite3.connect(DATABASE) as conn:
            cursor = conn.cursor()
            cursor.execute('SELECT password FROM users WHERE nickname = ?', (nickname,))
            row = cursor.fetchone()
            
            if row and check_password_hash(row[0], password):
                session['nickname'] = nickname
                flash('Login successful!', 'success')
                return redirect(url_for('index'))
            else:
                flash('Invalid nickname or password.', 'error')
                return redirect(url_for('login'))
    
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.pop('nickname', None)
    flash('Logged out successfully.', 'success')
    return redirect(url_for('login'))

@app.route('/create_post', methods=['POST'])
def create_post():
    if 'nickname' not in session:
        return redirect(url_for('login'))
    
    content = request.form['content']
    tag = request.form['tag']
    nickname = session['nickname']
    
    with sqlite3.connect(DATABASE) as conn:
        cursor = conn.cursor()
        cursor.execute('INSERT INTO posts (nickname, content, tag) VALUES (?, ?, ?)', (nickname, content, tag))
        conn.commit()
    
    flash('Post created successfully.', 'success')
    return redirect(url_for('index'))

@app.route('/posts_by_date/<date>')
def posts_by_date(date):
    with sqlite3.connect(DATABASE) as conn:
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM posts WHERE DATE(created_at) = ?', (date,))
        posts = [{'id': row[0], 'nickname': row[1], 'content': row[2], 'tag': row[3], 'created_at': row[4]} 
                 for row in cursor.fetchall()]
    
    return render_template('posts_by_date.html', date=date, posts=posts)

@app.route('/vote', methods=['POST'])
def vote():
    if 'nickname' not in session:
        return redirect(url_for('login'))
    
    post_id = request.form['post_id']
    vote_type = int(request.form['vote_type'])
    nickname = session['nickname']
    
    with sqlite3.connect(DATABASE) as conn:
        cursor = conn.cursor()
        cursor.execute('SELECT vote_type FROM votes WHERE post_id = ? AND nickname = ?', (post_id, nickname))
        existing_vote = cursor.fetchone()
        
        if existing_vote:
            flash('You have already voted on this post.', 'error')
            return redirect(url_for('index'))
        
        cursor.execute('INSERT INTO votes (post_id, nickname, vote_type) VALUES (?, ?, ?)', 
                       (post_id, nickname, vote_type))
        conn.commit()
    
    flash('Vote submitted.', 'success')
    return redirect(url_for('index'))

@app.route('/add_comment', methods=['POST'])
def add_comment():
    if 'nickname' not in session:
        return redirect(url_for('login'))
    
    post_id = request.form['post_id']
    content = request.form['comment_content']
    nickname = session['nickname']
    
    with sqlite3.connect(DATABASE) as conn:
        cursor = conn.cursor()
        cursor.execute('INSERT INTO comments (post_id, nickname, content) VALUES (?, ?, ?)', 
                       (post_id, nickname, content))
        conn.commit()
    
    flash('Comment added.', 'success')
    return redirect(url_for('index'))

# Utility filter to format dates
@app.template_filter('format_date')
def format_date(value):
    return datetime.strptime(value, "%Y-%m-%d %H:%M:%S").strftime("%d %B %Y")

if __name__ == '__main__':
    app.run(debug=True)
