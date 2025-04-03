from flask import Flask, request, render_template, redirect, url_for, session
import joblib
import numpy as np
import pandas as pd
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
app = Flask(__name__)
import os
app.secret_key = os.urandom(24)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)

# Load the trained model
model = joblib.load("model.pkl")

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

        # Check if user exists
        existing_user = User.query.filter_by(username=username).first()
        if existing_user:
            return "❌ User already exists. Please choose a different username."

        # ✅ Correct hash method
        hashed_password = generate_password_hash(password, method='pbkdf2:sha256')
        new_user = User(username=username, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()
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
            return redirect(url_for('dashboard'))
        # else:
        #     return 'Invalid Credentials'
    return render_template('login.html')

# Dashboard Route (Protected)
@app.route('/dashboard', methods=['GET', 'POST'])
def dashboard():
    if 'user' not in session:
        return redirect(url_for('login'))
    
    prediction_text = ""
    color_class = ""
    if request.method == 'POST':
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

        final_features = np.array([features]).reshape(1, -1)  # Ensure it's a 2D array
        prediction = model.predict(final_features)[0]

        # Define threshold-based categories
        if prediction < 50:  
            prediction_text = "⚠️ Reorder Needed! Stock is low."
            color_class = "alert-danger"
        elif 50 <= prediction <= 150:
            prediction_text = "✅ Sufficient Stock Available."
            color_class = "alert-success"
        else:
            prediction_text = "⚠️ Overstock Warning! Reduce orders."
            color_class = "alert-warning"
    
    return render_template('dashboard.html', prediction_text=prediction_text, color_class=color_class)

# Logout Route
@app.route('/logout')
def logout():
    session.pop('user', None)
    return redirect(url_for('login'))

if __name__ == "__main__":
    app.run(host='0.0.0.0')
