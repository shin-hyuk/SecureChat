from flask import Flask, render_template, request, redirect, url_for, session, jsonify, abort, flash
from flask_mysqldb import MySQL
from flask_session import Session
import yaml
from flask_bcrypt import Bcrypt
from Crypto.Cipher import AES
from helpers import AESencrypt, AESdecrypt, get_totp_uri, verify_totp, check_password_strength, generate_captcha_image, validate_form
from base64 import b64encode, b64decode
import os
import base64
from io import BytesIO
import pyqrcode
import onetimepass
import io
import requests
from datetime import timedelta

app = Flask(__name__)

# Configure secret key and Flask-Session
app.config['SECRET_KEY'] = b'9\x13\x07j\xf9\x19\xff\x94\xb6\x04\x91\xf31T\x96c'
app.config['SESSION_TYPE'] = 'filesystem'  # Options: 'filesystem', 'redis', 'memcached', etc.
app.config['SESSION_PERMANENT'] = True
app.config['SESSION_USE_SIGNER'] = True  # To sign session cookies for extra security
app.config['SESSION_FILE_DIR'] = './sessions'  # Needed if using filesystem type
app.config['SESSION_COOKIE_SECURE'] = True  # Enable for production on HTTPS
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Strict'  # Mitigate CSRF attacks
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(minutes=120 )

# Load database configuration from db.yaml or configure directly here
db_config = yaml.load(open('db.yaml'), Loader=yaml.FullLoader)
app.config.update(
    MYSQL_DB=db_config['mysql_db'],
    MYSQL_USER=db_config['mysql_user'],
    MYSQL_PASSWORD=db_config['mysql_password'],
    MYSQL_HOST=db_config['mysql_host']
)

mysql = MySQL(app)
# print(mysql.connect)

# Initialize the Flask-Session
Session(app)

MAX_USERNAME_LEN = 255


@app.route('/')
def index():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    sender_id = session['user_id']
    return render_template('chat.html', sender_id=sender_id)


@app.route('/users')
def users():
    if 'user_id' not in session:
        abort(403)

    cur = mysql.connection.cursor()
    cur.execute("SELECT user_id, username FROM users")
    user_data = cur.fetchall()
    cur.close()

    filtered_users = [[user[0], user[1]] for user in user_data if user[0] != session['user_id']]
    return {'users': filtered_users}


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':

        form = validate_form(request.form)

        username = form['username']
        username = username[:MAX_USERNAME_LEN] if len(username) > MAX_USERNAME_LEN else username
        password = form['password']
        text_captcha = form['captcha_input']
        recaptcha_response = form['g-recaptcha-response']

        cur = mysql.connection.cursor()
        cur.execute("SELECT user_id, password FROM users WHERE username = %s", [username])
        account = cur.fetchone()
        cur.close()

        # 向 reCAPTCHA 服务器发送验证请求
        data = {
            'secret': '6LeMXbQpAAAAAP0CTcYJcAk16IhutPwNVF5dnOs-',
            'response': recaptcha_response
        }
        response = requests.post('https://www.google.com/recaptcha/api/siteverify', data=data)
        result = response.json()

        if session['captcha'] == text_captcha and result['success']:
            # reCAPTCHA 验证成功
            if account and bcrypt.check_password_hash(account[1], password):
                session['user_id_temp'] = account[0]  # Temporarily store user ID
                session['username_password_verified'] = True
                return redirect(url_for('verify_totp'))  # Redirect to TOTP verification
            else:
                error = 'Invalid username or password or token.'
                flash(error, 'danger')
                pass
        else:
            error = 'Do the human machine authentication again.'
            flash(error, 'danger')
            # reCAPTCHA 验证失败
            return render_template('login.html')

    # Show login form
    return render_template('login.html')


@app.route('/recover', methods=['GET', 'POST'])
def recover_account():
    # If implementing account recovery, use security questions to verify user identity before allowing password reset.
    pass


@app.route('/fetch_messages')
def fetch_messages():
    try:
        peer_id = request.args.get('peer_id')
        last_message_id = request.args.get('last_message_id', 0)

        # Ensure the user is authenticated
        if 'user_id' not in session:
            return jsonify({'error': 'Unauthorized'}), 401

        # Fetch messages from the database
        messages = fetch_messages_from_db(peer_id, last_message_id)

        # Return the messages as JSON
        return jsonify({'messages': messages}), 200
    except Exception as e:
        # Log the exception details for debugging
        print(f"Error fetching messages: {e}")
        # Return a JSON error response
        return jsonify({'error': 'Internal Server Error'}), 500


def fetch_messages_from_db(peer_id, last_message_id):
    query = """
    SELECT message_id, sender_id, receiver_id, ciphertext, iv, hmac, aad, created_at 
    FROM messages 
    WHERE 
        (sender_id = %s AND receiver_id = %s OR sender_id = %s AND receiver_id = %s) 
        AND message_id > %s
    ORDER BY message_id ASC
    """
    # It's assumed that session['user_id'] is securely set and valid
    values = (session['user_id'], peer_id, peer_id, session['user_id'], last_message_id)

    cur = mysql.connection.cursor()
    cur.execute(query, values)
    messages = cur.fetchall()
    cur.close()

    # Formatting the messages for JSON response
    return [{
        'message_id': msg[0],
        'sender_id': msg[1],
        'receiver_id': msg[2],
        'ciphertext': msg[3],
        'iv': msg[4],  # Assuming the IV is stored in Base64
        'hmac': msg[5],  # Assuming the HMAC is stored in Base64
        'aad': msg[6],  # AAD added to the output
        'created_at': msg[7].strftime("%Y-%m-%d %H:%M:%S"),
    } for msg in messages]


@app.route('/api/send_message', methods=['POST'])
def send_message():
    # Ensure the request has the necessary encrypted components and AAD
    required_fields = ['ciphertext', 'iv', 'hmac', 'aad']
    if not request.json or not all(field in request.json for field in required_fields):
        abort(400)  # Bad request if missing any required fields

    if 'user_id' not in session:
        abort(403)  # Forbidden if the user isn't logged in

    # Extract encrypted data and AAD from the request
    sender_id = session['user_id']
    receiver_id = request.json['peer_id']
    ciphertext = request.json['ciphertext']
    iv_base64 = request.json['iv']
    hmac_base64 = request.json['hmac']
    aad = request.json['aad']  # Extracting AAD sent from the client

    save_encrypted_message(sender_id, receiver_id, ciphertext, iv_base64, hmac_base64, aad)

    return jsonify({'status': 'success', 'message': 'Encrypted message sent'}), 200


def save_encrypted_message(sender_id, receiver_id, ciphertext, iv, hmac, aad):
    try:
        query = '''INSERT INTO messages 
                   (sender_id, receiver_id, ciphertext, iv, hmac, aad) 
                   VALUES (%s, %s, %s, %s, %s, %s)'''
        values = (sender_id, receiver_id, ciphertext, iv, hmac, aad)

        cur = mysql.connection.cursor()
        cur.execute(query, values)
        mysql.connection.commit()
        cur.close()
        return True
    except Exception as e:
        print(f"Failed to save message: {e}")
        return False


@app.route('/api/latest_iv/<int:peer_id>')
def get_latest_iv(peer_id):
    user_id = session.get('user_id')
    if not user_id:
        return jsonify({'error': 'Authentication required'}), 403

    try:
        cur = mysql.connection.cursor()
        query = """
            SELECT iv
            FROM messages
            WHERE (sender_id = %s AND receiver_id = %s) OR (sender_id = %s AND receiver_id = %s)
            ORDER BY message_id DESC
            LIMIT 1
        """
        cur.execute(query, (user_id, peer_id, peer_id, user_id))
        result = cur.fetchone()
        cur.close()

        # If a message is found, return its IV, otherwise return the base64-encoded initial IV
        latest_iv_base64 = result[0] if result else "AAAAAAAAAAAAAAAAAAAAAA=="
        return jsonify({'iv': latest_iv_base64}), 200
    except Exception as e:
        print(f"Error fetching the latest IV: {e}")
        return jsonify({'error': 'Internal Server Error'}), 500


@app.route('/erase_chat', methods=['POST'])
def erase_chat():
    if 'user_id' not in session:
        abort(403)

    peer_id = request.json['peer_id']
    cur = mysql.connection.cursor()
    query = "DELETE FROM messages WHERE ((sender_id = %s AND receiver_id = %s) OR (sender_id = %s AND receiver_id = %s))"
    cur.execute(query, (peer_id, session['user_id'], session['user_id'], peer_id))
    mysql.connection.commit()

    # Check if the operation was successful by evaluating affected rows
    if cur.rowcount > 0:
        return jsonify({'status': 'success'}), 200
    else:
        return jsonify({'status': 'failure'}), 200


@app.route('/logout')
def logout():
    session.clear()
    flash('You have been successfully logged out.', 'info')  # Flash a logout success message
    return redirect(url_for('index'))


@app.route('/register', methods=['GET', 'POST'])
def register():
    print(request)
    if request.method == 'GET':
        # Display the registration form
        return render_template('register.html')
    else:
        # Process the form data and register the user

        form = validate_form(request.form)

        username = form['username']
        username = username[:MAX_USERNAME_LEN] if len(username) > MAX_USERNAME_LEN else username
        password = form['password']
        public_key = form['public_key']
        security_question = form['securityQuestion']
        retyped_password = form["retyped_password"]
        security_answer = form['securityAnswer']
        memorized_secret = form['memorizedSecret']
        ### memorizedSecret ???

        if password != retyped_password:
            flash("Different passwords, please input again", 'danger')
            return render_template('register.html')

        recaptcha_response = form['g-recaptcha-response']
        # 向 reCAPTCHA 服务器发送验证请求
        data = {
            'secret': '6LeMXbQpAAAAAP0CTcYJcAk16IhutPwNVF5dnOs-',
            'response': recaptcha_response
        }
        response = requests.post('https://www.google.com/recaptcha/api/siteverify', data=data)
        result = response.json()
        print("received post from google api")
        if not result['success']:
            error = 'Do the human machine authentication again.'
            flash(error, 'danger')
            return redirect(url_for('register'))

        # password strengh check
        error_message = check_password_strength(password)
        if error_message is not None:
            flash(error_message, "danger")
            return redirect(url_for('register'))

        # Hash the password
        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')

        # encrypt question and answer
        cur = mysql.connection.cursor()
        cur.execute("SELECT iv FROM users ORDER BY user_id DESC LIMIT 1")
        result = cur.fetchone()
        cur.close()
        if result:
            length = len(result[0])
            iv = bytes((int.from_bytes(result[0], byteorder='big') + 1).to_bytes(length, byteorder='big'))
        else:
            iv = os.urandom(16)
        cur.close()
        encrypted_question = AESencrypt(app.config['SECRET_KEY'], iv, security_question.encode())
        # decrypted_question = AESdecrypt(app.config['SECRET_KEY'], iv, security_question)
        encrypted_answer = AESencrypt(app.config['SECRET_KEY'], iv, security_answer.encode())
        # decrypted_answer = AESdecrypt(app.config['SECRET_KEY'], iv, security_answer)
        encrypted_secret = AESencrypt(app.config['SECRET_KEY'], iv, memorized_secret.encode())

        try:
            cur = mysql.connection.cursor()
            totp_secret = base64.b32encode(os.urandom(10)).decode('utf-8')  ### ?

            # protect the indexing
            username = username[:MAX_USERNAME_LEN] if len(username) > MAX_USERNAME_LEN else username
            cur.execute(
                "SELECT user_id FROM users WHERE username=%s",
                [username])  ## !
            the_user = cur.fetchone()
            user_exist = the_user is not None

            if user_exist:
                flash('Username already exists. Try another one.', 'success')
                return redirect(url_for('register'))

            cur.execute(
                "INSERT INTO users (username, password, security_question, security_answer, public_key, iv, totp_secret,memorized_secret) VALUES (%s, %s, %s, %s, %s, %s, %s,%s)",
                (username, hashed_password, encrypted_question, encrypted_answer, public_key, iv, totp_secret,
                 encrypted_secret))
            mysql.connection.commit()

            session['username_password_verified'] = True

            cur.execute(
                "SELECT user_id  FROM users WHERE username = %s",
                [username])
            account = cur.fetchone()
            cur.close()
            session['user_id_temp'] = account[0]

            flash('You are now registered.', 'success')
            session['username'] = username
            return redirect(url_for('qr'))

        except Exception as e:
            flash(f"Unexpected server errors:{str(e)}", "danger")

        return redirect(url_for('register'))


@app.route('/update_public_key', methods=['POST'])
def update_public_key():
    print(request.json)
    # Ensure the user is authenticated
    user_id = session.get('user_id')
    if not user_id:
        return jsonify({'error': 'Authentication required'}), 403

    # Obtain the public key from the request
    public_key = request.json.get('public_key')
    if not public_key:
        return jsonify({'error': 'No public key provided'}), 400

    # Update the user's public key in the database
    try:
        cur = mysql.connection.cursor()
        cur.execute("UPDATE users SET public_key=%s WHERE user_id=%s", (public_key, user_id))
        mysql.connection.commit()
        cur.close()
        return jsonify({'message': 'Public key updated successfully'}), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/get_public_key/<user_id>', methods=['GET'])
def get_public_key(user_id):
    # Retrieve a user's public key
    cur = mysql.connection.cursor()
    cur.execute("SELECT public_key FROM users WHERE user_id=%s", [user_id])
    result = cur.fetchone()
    cur.close()
    if result:
        return jsonify({'public_key': result[0]})
    else:
        return jsonify({'error': 'User not found'}), 404


@app.route('/qr')
def qr():
    if 'username' not in session:
        return redirect(url_for('register'))
    username = session['username']
    cur = mysql.connection.cursor()
    username = username[:MAX_USERNAME_LEN] if len(username) > MAX_USERNAME_LEN else username
    cur.execute("SELECT user_id FROM users WHERE username = %s", [username])
    account = cur.fetchone()
    cur.close()

    if account:
        return render_template('qr.html'), 200, {
            'Cache-Control': 'no-cache, no-store, must-revalidate',
            'Pragma': 'no-cache',
            'Expires': '0'}
    else:
        abort(404)


@app.route('/qr_code', methods=['GET', 'POST'])
def qr_code():
    if 'username' not in session:
        return redirect(url_for('register'))
    username = session['username']
    username = username[:MAX_USERNAME_LEN] if len(username) > MAX_USERNAME_LEN else username
    # user = User.query.filter_by(username=username).first()
    # if user is None:
    #     abort(404)

    # del session['username']

    cur = mysql.connection.cursor()
    cur.execute("SELECT user_id, totp_secret FROM users WHERE username = %s", [username])
    account = cur.fetchone()
    cur.close()
    if account:
        url = pyqrcode.create(get_totp_uri(username, account[1]))
        stream = BytesIO()
        url.svg(stream, scale=5)
        return stream.getvalue(), 200, {
            'Content-Type': 'image/svg+xml',
            'Cache-Control': 'no-cache, no-store, must-revalidate',
            'Pragma': 'no-cache',
            'Expires': '0'}
    else:
        abort(404)


@app.route('/reset_password', methods=["GET", "POST"])
def reset_password():
    if request.method == "POST":

        form = validate_form(request.form)

        new_password = form['password']

        # password strengh check
        error_message = check_password_strength(new_password)
        if error_message is not None:
            flash(error_message, "danger")
            return redirect(url_for("reset_password"))

        hashed_password = bcrypt.generate_password_hash(new_password).decode('utf-8')

        try:
            cur = mysql.connection.cursor()
            user_id = session.get("user_id")
            cur.execute("UPDATE users SET password=%s WHERE user_id=%s", (hashed_password, user_id))
            mysql.connection.commit()
            cur.close()

        except Exception:
            flash("Unexpected Error", "danger")
            return redirect(url_for("login"))

        flash("You need to do the authentication again.", "success")
        return redirect(url_for('qr'))

    return render_template('reset_password.html')


@app.route('/forgot-password', methods=["GET", "POST"])
def forgot_password():
    ## implement here
    if request.method == "POST":

        form = validate_form(request.form)

        # get the input message.
        username = form['username']
        username = username[:MAX_USERNAME_LEN] if len(username) > MAX_USERNAME_LEN else username
        security_question = form['securityQuestion']
        security_answer = form['securityAnswer']
        memorized_secret = form['memorizedSecret']
        recaptcha_response = form['g-recaptcha-response']
        #recaptcha send request
        data = {
            'secret': '6LeMXbQpAAAAAP0CTcYJcAk16IhutPwNVF5dnOs-',
            'response': recaptcha_response
        }
        response = requests.post('https://www.google.com/recaptcha/api/siteverify', data=data)
        result = response.json()
        if not result['success']:
            error = 'Do the human machine authentication again.'
            flash(error, 'danger')
            return redirect(url_for('forgot_password'))

        # retrieve the stored message:
        cur = mysql.connection.cursor()
        cur.execute(
            "SELECT security_question,security_answer,iv,memorized_secret,user_id  FROM users WHERE username = %s",
            [username])
        account = cur.fetchone()
        cur.close()

        if account is None:
            flash("Can not find your information.", "danger")
            return redirect(url_for('forgot_password'))

        user_id = account[4]
        session['user_id'] = user_id

        iv = account[2]  # bytes iv -> %s
        encrypted_question = AESencrypt(app.config['SECRET_KEY'], iv, security_question.encode())
        encrypted_answer = AESencrypt(app.config['SECRET_KEY'], iv, security_answer.encode())
        encrypted_secret = AESencrypt(app.config['SECRET_KEY'], iv, memorized_secret.encode())

        ### optimization: answer allow some format errors
        valid = account[0] == encrypted_question and account[1] == encrypted_answer and account[3] == encrypted_secret
        if valid:
            return redirect(url_for('reset_password'))
        else:
            flash("Invalid. Try Again! ", 'danger')
            pass

    return render_template('forgot-password.html')


@app.route('/verify_totp', methods=['GET', 'POST'])
def verify_totp():
    if not session.get('username_password_verified'):
        return redirect(url_for('login'))  # Redirect back if the initial check wasn't passed

    if request.method == 'POST':

        user_totp_token = request.form['token']
        user_id_temp = session.get('user_id_temp')

        cur = mysql.connection.cursor()
        cur.execute("SELECT totp_secret FROM users WHERE user_id = %s", [user_id_temp])
        account = cur.fetchone()

        if account and onetimepass.valid_totp(token=user_totp_token, secret=account[0]):
            # TOTP is correct, complete login
            session['user_id'] = user_id_temp  # Now officially logged in
            del session['user_id_temp']  # Clean up
            del session['username_password_verified']
            return redirect(url_for('index'))  
        else:

            pass
    # Show TOTP verification form
    return render_template('verify_totp.html')

@app.route('/captcha')
def captcha():
    image, captcha_text = generate_captcha_image()
    session['captcha'] = captcha_text

    buf = io.BytesIO()
    image.save(buf, format='PNG')
    buf.seek(0)
    return buf.getvalue(), 200, {
        'Content-Type': 'image/png',
        'Content-Length': str(len(buf.getvalue()))
    }


@app.route('/api/sessionReset', methods=['GET'])
def handle_inactivity_notice():
    if 'user_id' in session:
        # print('Received inactivity notice for user:', session['user_id'])
        # return jsonify({'message': 'Inactivity registered'}), 200
        redirect((url_for("/session_time_out")))
    else:
        return jsonify({'error': 'Session not active'}), 401

@app.route('/session_time_out')
def session_time_out():
    session.clear()
    flash('Your session has expired. ', 'danger')  # Flash a logout success message
    return redirect(url_for('index'))

bcrypt = Bcrypt(app)
if __name__ == '__main__':
    app.run(debug=True)
