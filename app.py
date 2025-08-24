from flask import Flask, render_template, request, redirect, url_for, flash, session
import sqlite3
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.secret_key = 'your_secret_key'

def get_db_connection():
    conn = sqlite3.connect("C:/Users/fortn/OneDrive/Desktop/MiniProject2/mini_project.db")
    conn.row_factory = sqlite3.Row
    return conn
def create_tables():
    print("Creating tables...")
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL
    )
    ''')

    cursor.execute('''
    CREATE TABLE IF NOT EXISTS drugs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        drug_name TEXT NOT NULL,
        manufacturer TEXT NOT NULL,
        quantity INTEGER NOT NULL,
        expiry_date TEXT NOT NULL,
        FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
    )
    ''')

    conn.commit()
    conn.close()
create_tables()
@app.route('/')
def home():
    return render_template('home.html')
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        hashed_password = generate_password_hash(password)       
        conn = get_db_connection()
        try:
            conn.execute('INSERT INTO users (username, password) VALUES (?, ?)', (username, hashed_password))
            conn.commit()
            flash('Registration successful! Please log in.', 'success')
            print("Data inserted successfully")
        except sqlite3.IntegrityError as e:
            print(f"Error occurred: {e}")
            flash('Username already exists!', 'danger')
        finally:
            conn.close()

    return render_template('register.html')
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        conn = get_db_connection()
        user = conn.execute('SELECT * FROM users WHERE username = ?', (username,)).fetchone()
        conn.close()
        
        if user and check_password_hash(user['password'], password):
            session['user_id'] = user['id']  # Stores user ID for later use?
            session['username'] = user['username']
            flash('Login successful!', 'success')
            next_page=request.args.get('next')
            if next_page:
                return redirect(url_for(next_page))
            return redirect(url_for('inventory'))
        else:
            flash('Invalid username or password!', 'danger')
    
    return render_template('login.html')
@app.route('/logout')
def logout():
    session.pop('user_id', None)
    session.pop('username', None)
    flash('You have been logged out.', 'info')
    return redirect(url_for('login'))

@app.route('/inventory', methods=['GET', 'POST'])
def inventory():
    if 'user_id' not in session:
        return redirect(url_for('login'))  # Redirect to login if not logged in

    conn = get_db_connection()
    cursor = conn.cursor()
    
    if request.method == 'POST':
        action = request.form.get('action')
        
        if action == 'add':
            drug_name = request.form['drug_name']
            manufacturer = request.form['manufacturer']
            quantity = request.form['quantity']
            expiry_date = request.form['expiry_date']
            cursor.execute('INSERT INTO drugs (user_id, drug_name, manufacturer, quantity, expiry_date) VALUES (?, ?, ?, ?, ?)', 
                           (session['user_id'], drug_name, manufacturer, quantity, expiry_date))
            conn.commit()
            flash('Drug added successfully!', 'success')
        
        elif action == 'edit':
            drug_id = request.form['drug_id']
            drug_name = request.form['drug_name']
            manufacturer = request.form['manufacturer']
            quantity = request.form['quantity']
            expiry_date = request.form['expiry_date']
            cursor.execute('UPDATE drugs SET drug_name = ?, manufacturer = ?, quantity = ?, expiry_date = ? WHERE id = ? AND user_id = ?', 
                           (drug_name, manufacturer, quantity, expiry_date, drug_id, session['user_id']))
            conn.commit()
            flash('Drug updated successfully!', 'success')
        
        elif action == 'delete':
            drug_id = request.form['drug_id']
            cursor.execute('DELETE FROM drugs WHERE id = ?', (drug_id,))
            conn.commit()
            flash('Drug deleted successfully!', 'success')

    drugs = cursor.execute('SELECT * FROM drugs WHERE user_id = ?', (session['user_id'],)).fetchall()
    conn.close()
    return render_template('inventory.html', drugs=drugs)
@app.route('/exec_office', methods=['GET', 'POST'])
def exec_office():
    conn = get_db_connection()
    users = conn.execute('SELECT * FROM users').fetchall()#fetches all users
    drugs = []
    selected_user = None

    if request.method == 'POST':
        user_id = request.form['user_id']
        selected_user = conn.execute('SELECT username FROM users WHERE id = ?', (user_id,)).fetchone()
        selected_user = selected_user['username'] if selected_user else None
        drugs = conn.execute('SELECT * FROM drugs WHERE user_id = ?', (user_id,)).fetchall()  # Get the drugs for the selected user

    conn.close()
    return render_template('exec_office.html', users=users, drugs=drugs, selected_user=selected_user)

# Run the Flask app
if __name__ == '__main__':
    app.run(debug=True)
