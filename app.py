from flask import Flask, request, render_template, redirect, url_for, session, flash
import joblib
import numpy as np
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
import os

app = Flask(__name__)

# Session Configuration
app.secret_key = 'my_secret_key_for_testing'  # Static key for consistent sessions
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)

# Load the trained model
try:
    model = joblib.load("model.pkl")
except Exception as e:
    print(f"Error loading model: {e}")
    model = None

# User Model
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(256), nullable=False)

# Create Database
with app.app_context():
    db.create_all()

# Home Route
@app.route('/')
def home():
    if 'user' in session:
        return redirect(url_for('dashboard'))
    return redirect(url_for('login'))

# Register Route
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        existing_user = User.query.filter_by(username=username).first()
        if existing_user:
            flash("❌ User already exists. Please choose a different username.", "danger")
            return redirect(url_for('register'))

        hashed_password = generate_password_hash(password, method='pbkdf2:sha256')
        new_user = User(username=username, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()
        flash("✅ Registration successful. Please log in.", "success")
        return redirect(url_for('login'))
    return render_template('register.html')

# Login Route
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()

        if user and check_password_hash(user.password, password):
            session['user'] = username
            flash(f"✅ Welcome, {username}!", "success")
            return redirect(url_for('dashboard'))
        else:
            flash("❌ Invalid credentials. Please try again.", "danger")
    return render_template('login.html')

# Dashboard Route (Protected)
@app.route('/dashboard', methods=['GET', 'POST'])
def dashboard():
    if 'user' not in session:
        flash("❌ Please log in to access the dashboard.", "warning")
        return redirect(url_for('login'))

    prediction_text = ""
    color_class = ""

    if request.method == 'POST':
        try:
            features = [
                float(request.form['Quantity_Available']),
                float(request.form['Reorder_Level']),
                float(request.form['Safety_Stock']),
                float(request.form['Lead_Time']),
                float(request.form['Daily_Sales']),
                float(request.form['Customer_Demand']),
                float(request.form['Stockout_History']),
                float(request.form['Supplier_Delivery_Time']),
                float(request.form['Price_Per_Unit'])
            ]

            final_features = np.array([features]).reshape(1, -1)
            prediction = model.predict(final_features)[0] if model else 0

            if prediction < 50:
                prediction_text = "⚠️ Reorder Needed! Stock is low."
                color_class = "alert-danger"
            elif 50 <= prediction <= 150:
                prediction_text = "✅ Sufficient Stock Available."
                color_class = "alert-success"
            else:
                prediction_text = "⚠️ Overstock Warning! Reduce orders."
                color_class = "alert-warning"

        except Exception as e:
            flash(f"❌ Error during prediction: {e}", "danger")

    return render_template('dashboard.html', prediction_text=prediction_text, color_class=color_class)

# Logout Route
@app.route('/logout')
def logout():
    session.pop('user', None)
    flash("🚪 You have been logged out.", "info")
    return redirect(url_for('login'))

if __name__ == "__main__":
    app.run(host='0.0.0.0', debug=True)
