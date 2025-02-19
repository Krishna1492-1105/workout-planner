from flask import Flask, render_template, request, redirect, flash, url_for
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user, login_manager
from werkzeug.security import generate_password_hash, check_password_hash
import sqlite3

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///workout.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = 'your_secret_key'  # Change this to a random secret key
db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

# Define the Exercise model
class Exercise(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String, nullable=False)
    sets = db.Column(db.Integer, nullable=False)
    reps = db.Column(db.Integer, nullable=False)
    completed = db.Column(db.Boolean, default=False)

# User model
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(150), nullable=False)

# Load user
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Initialize Database
with app.app_context():
    db.create_all()

@app.route('/')
@login_required
def index():
    exercises = Exercise.query.all()
    return render_template("index.html", exercises=exercises)

@app.route('/add', methods=['POST'])
def add_exercise():
    name = request.form['name']
    sets = int(request.form['sets'])
    reps = int(request.form['reps'])

    # Validate that reps is not negative
    if reps < 0:
        flash('Reps cannot be negative!', 'danger')  # Flash message for error
        return redirect('/')  # Redirect back to the index if validation fails

    new_exercise = Exercise(name=name, sets=sets, reps=reps)
    db.session.add(new_exercise)
    db.session.commit()
    return redirect('/')

@app.route('/complete/<int:exercise_id>')
def complete_exercise(exercise_id):
    exercise = Exercise.query.get(exercise_id)
    if exercise:
        exercise.completed = True
        db.session.commit()
    return redirect('/')

@app.route('/delete/<int:exercise_id>')
def delete_exercise(exercise_id):
    exercise = Exercise.query.get(exercise_id)
    if exercise:
        db.session.delete(exercise)
        db.session.commit()
    return redirect('/')

# Routes for login and signup
@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        # Check if the username already exists
        existing_user = User.query.filter_by(username=username).first()
        if existing_user:
            flash('Username already exists. Please choose a different one.', 'danger')
            return redirect(url_for('signup'))

        hashed_password = generate_password_hash(password)  # Use the default method
        new_user = User(username=username, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()
        flash('Signup successful! You can now log in.', 'success')
        return redirect(url_for('login'))
    return render_template('signup.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()
        if user and check_password_hash(user.password, password):
            login_user(user)
            return redirect(url_for('index'))  # Redirect to the main page after login
        flash('Login failed. Check your username and/or password.', 'danger')
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

if __name__ == '__main__':
    app.run(debug=True)
