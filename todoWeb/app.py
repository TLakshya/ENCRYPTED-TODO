from flask import Flask, render_template, redirect, url_for, request, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, login_user, logout_user, login_required, UserMixin, current_user
from werkzeug.security import generate_password_hash, check_password_hash

from cryptography.fernet import Fernet
import base64

app = Flask(__name__)
app.config['SECRET_KEY'] = 'secret123'  
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///todo.db'
db = SQLAlchemy(app)

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# === Encryption setup ===
# Use a 32-byte key, base64-encoded. Replace with your own secure key!
from cryptography.fernet import Fernet

key = b'_jLwUpyAUhV5yOgUwNqD6csp8mKuN6NoDk1yURjkiGI='  # replace with your generated key
fernet = Fernet(key)


def encrypt_text(plain_text):
    return fernet.encrypt(plain_text.encode()).decode()

def decrypt_text(enc_text):
    return fernet.decrypt(enc_text.encode()).decode()

# === Models ===
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), unique=True)
    password = db.Column(db.String(200))

class ToDo(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    content = db.Column(db.String(1000))  # Encrypted content
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        if User.query.filter_by(username=username).first():
            flash('Username already exists!')
            return redirect(url_for('register'))
        hashed_pw = generate_password_hash(password)
        new_user = User(username=username, password=hashed_pw)
        db.session.add(new_user)
        db.session.commit()
        flash('Registration successful! Please login.')
        return redirect(url_for('login'))
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()
        if user and check_password_hash(user.password, password):
            login_user(user)
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid username or password!')
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))

@app.route('/dashboard', methods=['GET', 'POST'])
@login_required
def dashboard():
    if request.method == 'POST':
        content = request.form['content']
        enc_content = encrypt_text(content)
        new_todo = ToDo(content=enc_content, user_id=current_user.id)
        db.session.add(new_todo)
        db.session.commit()
        return redirect(url_for('dashboard'))

    todos_raw = ToDo.query.filter_by(user_id=current_user.id).all()
    todos = []
    for t in todos_raw:
        try:
            decrypted = decrypt_text(t.content)
        except Exception:
            decrypted = "[Decryption error]"
        todos.append({'id': t.id, 'content': decrypted})

    return render_template('dashboard.html', todos=todos)

@app.route('/delete/<int:todo_id>')
@login_required
def delete(todo_id):
    todo = ToDo.query.get_or_404(todo_id)
    if todo.user_id != current_user.id:
        flash("You can't delete this item.")
        return redirect(url_for('dashboard'))
    db.session.delete(todo)
    db.session.commit()
    return redirect(url_for('dashboard'))

@app.route('/profile')
@login_required
def profile():
    return render_template('profile.html', user=current_user)

if __name__ == "__main__":
    with app.app_context():
        db.create_all()
    app.run(debug=True)
