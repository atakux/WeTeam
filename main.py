import os
import bcrypt
import smtplib, ssl
from flask import Flask, redirect, jsonify, request, render_template, url_for, flash, session
from flask_mail import Mail, Message
from itsdangerous import URLSafeTimedSerializer, SignatureExpired


# set up database stuff here


app = Flask(__name__)

EMAIL_ADDRESS = 'weteam@gmail.com'
EMAIL_PASSWORD = os.environ['EMAIL_PASSWORD']

app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 465
app.config['MAIL_USERNAME'] = EMAIL_ADDRESS
app.config['MAIL_PASSWORD'] = EMAIL_PASSWORD
app.config['MAIL_USE_TLS'] = False
app.config['MAIL_USE_SSL'] = True

mailbox = Mail(app)
timed_token = URLSafeTimedSerializer('secretcode')


@app.route('/', methods=['POST', 'GET'])
@app.route('/home', methods=['POST', 'GET'])
def home():
    return render_template('home.html')


@app.route('/create_account', methods=['POST', 'GET'])
def create_account():
    """account creation function"""

    # check if user is logged in before next blocks

    if request.method == 'POST':
        username = request.form.get('username', 'default value name')
        email = request.form.get('email', 'default value email')

        duplicate_email = False
        duplicate_user = False

        # check for duplicates in the database here

        # security checks as well as result of duplicates
        if '@csu.fullerton.edu' not in email:
            print("invalid email")
            flash("You must be a CSUF student to create an account !")
            return render_template('create_account.html')
        elif duplicate_email:
            print("Duplicate Email Address")
            flash(f"An account with email '{email}' already exists. Try using a different email address")
            return render_template('create_account.html')
        elif duplicate_user:
            print("Duplicate Username")
            flash(f"Username '{username}' is taken. Choose a different username.")
            return render_template('create_account.html')
        # email verification and password security
        else:
            # confirm email using timed token link
            token = timed_token.dumps(email, salt='email-confirm')

            message = Message('Titan Seller Email Confirmation', sender=EMAIL_ADDRESS, recipients=[email])

            confirm_link = url_for('confirm_email', token=token, _external=True)
            message.body = 'Welcome to Titan Seller ! \n\n Hit this link to verify your account: {} \n\n\n ' \
                           'Thank you!'.format(confirm_link)

            mailbox.send(message)

            # hash and salt password
            password = request.form.get('password', 'default value password')
            salt = bcrypt.gensalt()
            hashed_pass = bcrypt.hashpw(bytes(password, encoding='utf8'), salt)

            # add user info to database here


            flash(f"Verification email sent to '{email}'")
            return redirect(url_for('login'))

    return render_template('create_account.html')


@app.route('/confirm_email/<token>', methods=['POST', 'GET'])
def confirm_email(token):
    try:
        email = timed_token.loads(token, salt='email-confirm', max_age=3600)
        # check if user is logged in
        # update database to show user is verified
        flash(f"Your email, '{email}', is verified", category="success")
        return redirect(url_for('login'))
    except SignatureExpired:
        print("yo token expired bro")
    finally:
        return redirect(url_for('login'))


@app.route('/login', methods=['POST', 'GET'])
def login(next_path=None):

    # check if user is logged in already

    # let user log in
    if request.method == 'POST':
        email = request.form.get('email', 'default value email')
        password = request.form.get('password', 'default value password')

        # check email and password by comparing it to password stored in database
        return redirect(url_for('home'))
    return render_template('login.html')


if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0')