import os
import bcrypt
import smtplib, ssl
import sqlalchemy as db
from flask import Flask, redirect, jsonify, request, render_template, url_for, flash, session
from flask_mail import Mail, Message
from sqlalchemy import text, create_engine, MetaData
from sqlalchemy.orm import sessionmaker
from sqlalchemy.ext.declarative import declarative_base
from itsdangerous import URLSafeTimedSerializer, SignatureExpired


# set up database stuff hereBase = declarative_base()
DATABASE_URL = os.environ['DATABASE_URL']
if DATABASE_URL != "sqlite:///database.sql":
    DATABASE_URL = DATABASE_URL.replace("postgres://", "postgresql://")
engine = db.create_engine(DATABASE_URL)

meta = MetaData()
meta.reflect(bind=engine, views=True)
inspector = db.inspect(engine)


def create_tables():
    if not inspector.has_table("user_database"):
        engine.execute(
            "CREATE TABLE user_database ("
            "user_id INTEGER NOT NULL PRIMARY KEY,"
            "user_name TEXT NOT NULL,"
            "user_email TEXT NOT NULL,"
            "user_password TEXT NOT NULL,"
            "user_status INTEGER NOT NULL DEFAULT 0,"
            "user_score INTEGER NOT NULL DEFAULT 0"
            ")")

    if not inspector.has_table("item"):
        engine.execute(
            "CREATE TABLE item ("
            "item_id INTEGER NOT NULL PRIMARY KEY,"
            "item_name TEXT NOT NULL,"
            "item_price TEXT NOT NULL,"
            "item_description TEXT NOT NULL,"
            "seller_id INTEGER NOT NULL,"
            "active INTEGER NOT NULL,"
            "FOREIGN KEY (seller_id)"
            "   REFERENCES user_database (user_id)"
            ")")

    if not inspector.has_table("review"):
        engine.execute(
            "CREATE TABLE review ("
            "review_id INTEGER NOT NULL PRIMARY KEY,"
            "review_score INTEGER NOT NULL,"
            "review_text TEXT NOT NULL,"
            "seller_id INTEGER NOT NULL,"
            "user_id INTEGER NOT NULL,"
            "FOREIGN KEY (user_id) REFERENCES user_database (user_id),"
            "FOREIGN KEY (seller_id) REFERENCES user_database (user_id)"
            ")")

    if not inspector.has_table("message"):
        engine.execute(
            "CREATE TABLE message ("
            "message_id INTEGER NOT NULL PRIMARY KEY,"
            "sender_id INTEGER NOT NULL,"
            "receiver_id INTEGER NOT NULL,"
            "message_content STRING NOT NULL,"
            "FOREIGN KEY (receiver_id) REFERENCES user_database (user_id),"
            "FOREIGN KEY (sender_id) REFERENCES user_database (user_id)"
            ")")


# create tables
if DATABASE_URL == "sqlite:///database.sql":
    create_tables()

app = Flask(__name__)

EMAIL_ADDRESS = 'weteam@gmail.com'
EMAIL_PASSWORD = os.environ['EMAIL_PASSWORD']

app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 465
app.config['MAIL_USERNAME'] = EMAIL_ADDRESS
app.config['MAIL_PASSWORD'] = EMAIL_PASSWORD
app.config['MAIL_USE_TLS'] = False
app.config['MAIL_USE_SSL'] = True

sql_session = sessionmaker(engine)

mailbox = Mail(app)
timed_token = URLSafeTimedSerializer('secretcode')


@app.route('/', methods=['POST', 'GET'])
@app.route('/home', methods=['POST', 'GET'])
def home():
    """
    use render template to load the data into whatever the template is
    This is the list of items page where each item is on display
    """
    # Get User Data if Logged in
    user_data = get_login_user_data()

    # Get item data
    results = None
    data = []
    with sql_session.begin() as generated_session:
        results = generated_session.execute(text("SELECT * FROM item JOIN user_database ON user_id=seller_id WHERE "
        "active=1 AND user_status=1 ORDER BY item_id DESC LIMIT 9"))
        for r in results:
            data.append(dict(r))     
    return render_template('home.html', item_list=data, user_data=user_data, search_query=None)    


@app.route('/sign_up', methods=['POST', 'GET'])
def sign_up():
    """
    Will be using a template. Likely will not need any input
    will need an output from the template in order to add the new user_database to the database
    """
    user_data = get_login_user_data()
    if user_data == "Banned":
        return redirect(url_for('logout'))
    if user_data is None:
        if 'next' in session:
            session.pop('next')
        if request.method == 'POST':
            user_name = request.form.get('userName', 'default value name')
            email = request.form.get('email', 'default value email')
            address = request.form.get('address', 'default address')
            dup_email = False
            dup_user_name = False

            #Check for Duplicates
            with sql_session.begin() as generated_session:
                user_results = generated_session.execute('SELECT * FROM user_database WHERE user_email="{}";'.format(email))
                for ur in user_results:
                    dup_email = True
                user_results = generated_session.execute('SELECT * FROM user_database WHERE user_name="{}";'.format(user_name))
                for ur in user_results:
                    dup_user_name = True
        
            # Check edu
            if '.fullerton.edu' not in email:
                print("invalid email")
                flash("You must input a CSUF email.")
                return render_template('signup.html')
            elif dup_email == True: #Check Email
                print("Duplicate Email")
                flash(f"There is already an account with email {email}. Please login or use different email.")
                return render_template('signup.html')
            elif dup_user_name == True: #Check Username
                print("Duplicate Username")
                flash(f"Username {user_name} is taken, please choose different username.")
                return render_template('signup.html')
            else:
                #Send Verification Email
                token = timed_token.dumps(email, salt='email-confirm')
                
                msg = Message('Titan Seller - Confirm Email', sender=EMAIL_ADDRESS, recipients=[email])

                link = url_for('confirm_email', token=token, _external=True)
                msg.body = 'Welcome to Titan Seller !! \n\n\n Click this link to verify your account: {} ' \
                        '\n\n\nThank you! \nHappy shopping,\nTitan Seller ' \
                        'Team'.format(link)

                mailbox.send(msg)

                # Hash Password
                password = request.form.get('password', 'default value password')
                salt = bcrypt.gensalt()
                hashed_pass = bcrypt.hashpw(bytes(password, encoding='utf8'), salt)

                engine.execute("INSERT INTO user_database (user_name, user_email, user_zip, "
                               "user_password) VALUES (?, ?, ?, ?);",
                               (user_name, email, address, hashed_pass))
                flash(f'Verification Email Sent to {email}')
                return redirect(url_for('login'))
        return render_template('signup.html')
    else:
        return redirect(url_for('home'))


@app.route('/confirm_email/<token>', methods=['POST', 'GET'])
def confirm_email(token):
    try:
        email = timed_token.loads(token, salt='email-confirm', max_age=3600)
        user_data = get_login_user_data()
        if user_data is not None:
            engine.execute("UPDATE user_database SET user_status = (?) WHERE user_id = (?);", (1, user_data['user_id']))
        flash(f"Your email, '{email}', is verified", category="success")
        return redirect(url_for('login'))
    except SignatureExpired:
        display_error()
    finally:
        return redirect(url_for('login'))


@app.route('/login', methods=['POST', 'GET'])
def login(next_path=None):
    user_data = get_login_user_data()
    if user_data == "Banned":
        return redirect(url_for('logout'))
    if user_data is None:
        if request.method == 'POST':
            email = request.form.get('email', 'default value email')
            password = request.form.get('password', 'default value password')
            try:
                user_results = None
                with sql_session.begin() as generated_session:
                    user_results = generated_session.execute(text("select * from user_database where user_email='{}'".format(str(email))))
                    for r in user_results:
                        user_data = dict(r)
                if bcrypt.checkpw(bytes(password, encoding='utf8'), user_data['user_password']):
                    if user_data['user_status'] == 2:
                        redirect(url_for('login'))
                        flash("You have been banned!", category="is-danger")
                    else:
                        session['user_id'] = user_data['user_id']
                        print("successful login")
                        if 'next' in session:
                            url = session['next']
                            session.pop('next')
                            return redirect(url)
                        else:
                            return redirect(url_for('home'))
                else:
                    redirect(url_for('login'))
                    flash("The username and/or password is incorrect, please try again.", category="is-danger")
            except Exception as ex:
                redirect(url_for('login'))
                flash("The username and/or password is incorrect, please try again.", category="is-danger")
                print("error" + str(ex))
        return render_template('signin.html')
    else:
        return redirect(url_for('home'))


@app.route('/logout')
def logout():
    user_data = get_login_user_data()
    if user_data is not None:
        session.pop('user_id')
    return redirect(url_for('login'))


@app.route('/error')
def display_error():
    return render_template('error.html')


def get_login_user_data():
    """Checks to see if user is logged in. If so, returns true. If not, returns false"""
    try:
        user_data = get_user_data_by_id(session['user_id'])
        #Check for ban
        if user_data['user_status'] == 2:
            return "Banned"
        return user_data
    except:
        return None


def get_user_data_by_id(id):
    with sql_session.begin() as generated_session:
        user_results = generated_session.execute(text('select * from user_database where user_id={}'.format(id)))
        for ur in user_results:
            return ur


if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0')