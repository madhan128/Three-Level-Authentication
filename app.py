from flask import Flask, render_template, request, redirect, url_for, session, flash
from flask_session import Session
from werkzeug.security import generate_password_hash, check_password_hash
import smtplib, ssl, random, re
from email.message import EmailMessage

app = Flask(__name__)
app.secret_key = 'your_secret_key_here'
app.config['SESSION_TYPE'] = 'filesystem'
Session(app)

EMAIL_ADDRESS = 'madhanpreethi2407@gmail.com'  # Your Gmail address
EMAIL_PASSWORD = 'etty humo bxvs mzvn'    # Use Gmail App Password if 2FA is enabled

# In-memory user database
users = {}

def send_email_otp(to_email, otp):
    msg = EmailMessage()
    msg.set_content(f'Your verification OTP is: {otp}')
    msg['Subject'] = 'Your Login OTP'
    msg['From'] = EMAIL_ADDRESS
    msg['To'] = to_email

    context = ssl.create_default_context()
    with smtplib.SMTP_SSL('smtp.gmail.com', 465, context=context) as server:
        server.login(EMAIL_ADDRESS, EMAIL_PASSWORD)
        server.send_message(msg)

@app.route('/', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username').strip()
        password = request.form.get('password')

        user = users.get(username)
        if user and check_password_hash(user['password_hash'], password):
            otp = str(random.randint(100000, 999999))
            session['otp'] = otp
            session['username'] = username
            send_email_otp(user['email'], otp)
            flash('OTP sent to your email.')
            return redirect(url_for('otp'))
        else:
            flash('Invalid username or password.')

    return render_template('login.html')

@app.route('/otp', methods=['GET', 'POST'])
def otp():
    if 'otp' not in session:
        flash('Session expired. Please login again.')
        return redirect(url_for('login'))

    if request.method == 'POST':
        entered_otp = request.form.get('otp')
        if entered_otp == session['otp']:
            return redirect(url_for('security_question'))
        else:
            flash('Invalid OTP. Try again.')

    return render_template('otp.html')

@app.route('/security_question', methods=['GET', 'POST'])
def security_question():
    username = session.get('username')
    if not username:
        flash('Session expired. Please login again.')
        return redirect(url_for('login'))

    user = users.get(username)
    question = user.get('security_question')

    if request.method == 'POST':
        answer = request.form.get('answer').strip()
        if check_password_hash(user['security_answer_hash'], answer):
            flash('Login successful!')
            return redirect(url_for('dashboard'))
        else:
            flash('Incorrect answer.')

    return render_template('security.html', question=question)

@app.route('/dashboard')
def dashboard():
    if 'username' not in session:
        flash('Please login first.')
        return redirect(url_for('login'))
    return render_template('dashboard.html', username=session['username'])

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username').strip()
        password = request.form.get('password')
        confirm = request.form.get('confirm')
        email = request.form.get('email').strip()
        question = request.form.get('question').strip()
        answer = request.form.get('answer').strip()

        if username in users:
            flash('Username already exists.')
        elif password != confirm:
            flash('Passwords do not match.')
        else:
            users[username] = {
                'password_hash': generate_password_hash(password),
                'email': email,
                'security_question': question,
                'security_answer_hash': generate_password_hash(answer)
            }
            flash('Registered successfully. Please login.')
            return redirect(url_for('login'))

    return render_template('register.html')

@app.route('/reset_password', methods=['GET', 'POST'])
def reset_password():
    if request.method == 'POST':
        username = request.form.get('username')
        new_password = request.form.get('new_password')
        confirm_password = request.form.get('confirm_password')

        if username not in users:
            flash('User not found.')
        elif new_password != confirm_password:
            flash('Passwords do not match.')
        else:
            users[username]['password_hash'] = generate_password_hash(new_password)
            flash('Password updated.')
            return redirect(url_for('login'))

    return render_template('reset_password.html')

@app.route('/reset_security', methods=['GET', 'POST'])
def reset_security():
    if request.method == 'POST':
        username = request.form.get('username')
        question = request.form.get('security_question')
        answer = request.form.get('security_answer')

        if username not in users:
            flash('User not found.')
        else:
            users[username]['security_question'] = question
            users[username]['security_answer_hash'] = generate_password_hash(answer)
            flash('Security question updated.')
            return redirect(url_for('login'))

    return render_template('reset_security.html')

@app.route('/logout')
def logout():
    session.clear()
    flash('Logged out.')
    return redirect(url_for('login'))

if __name__ == '__main__':
    app.run(debug=True)
