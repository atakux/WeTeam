import os
import bcrypt
import smtplib, ssl, json
import sqlalchemy as db
from flask import Flask, redirect, jsonify, request, render_template, url_for, flash, session
from flask_mail import Mail, Message
from sqlalchemy import text, create_engine, MetaData
from sqlalchemy.orm import sessionmaker
from sqlalchemy.ext.declarative import declarative_base
from itsdangerous import URLSafeTimedSerializer, SignatureExpired

# set up database stuff hereBase = declarative_base()
Base = declarative_base()
DATABASE_URL = os.environ['DATABASE_URL']
if DATABASE_URL != "sqlite:///database.sql":
  DATABASE_URL = DATABASE_URL.replace("postgres://", "postgresql://")
engine = db.create_engine(DATABASE_URL)

meta = MetaData()
meta.reflect(bind=engine, views=True)
inspector = db.inspect(engine)


def create_tables():
  if not inspector.has_table("user_database"):
    engine.execute("CREATE TABLE user_database ("
                   "user_id INTEGER NOT NULL PRIMARY KEY,"
                   "user_name TEXT NOT NULL,"
                   "user_email TEXT NOT NULL,"
                   "user_password TEXT NOT NULL,"
                   "user_status INTEGER NOT NULL DEFAULT 0,"
                   "user_score INTEGER NOT NULL DEFAULT 0"
                   ")")

  if not inspector.has_table("item"):
    engine.execute("CREATE TABLE item ("
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
    engine.execute("CREATE TABLE review ("
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

EMAIL_ADDRESS = 'titan.seller02@gmail.com'
EMAIL_PASSWORD = os.environ['EMAIL_PASSWORD']

app.config['SECRET_KEY'] = os.environ['SECRET_KEY']
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
    results = generated_session.execute(
      text("SELECT * FROM item JOIN user_database ON user_id=seller_id WHERE "
           "active=1 AND user_status=1 ORDER BY item_id DESC LIMIT 9"))
    for r in results:
      data.append(dict(r))
  return render_template('home.html',
                         item_list=data,
                         user_data=user_data,
                         search_query=None)


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
      dup_email = False
      dup_user_name = False

      #Check for Duplicates
      with sql_session.begin() as generated_session:
        user_results = generated_session.execute(
          'SELECT * FROM user_database WHERE user_email="{}";'.format(email))
        for ur in user_results:
          dup_email = True
        user_results = generated_session.execute(
          'SELECT * FROM user_database WHERE user_name="{}";'.format(
            user_name))
        for ur in user_results:
          dup_user_name = True

      # Check edu
      if '.fullerton.edu' not in email:
        print("invalid email")
        flash("You must input a CSUF email.")
        return render_template('signup.html')
      elif dup_email == True:  #Check Email
        print("Duplicate Email")
        flash(
          f"There is already an account with email {email}. Please login or use different email."
        )
        return render_template('signup.html')
      elif dup_user_name == True:  #Check Username
        print("Duplicate Username")
        flash(
          f"Username {user_name} is taken, please choose different username.")
        return render_template('signup.html')
      else:
        #Send Verification Email
        token = timed_token.dumps(email, salt='email-confirm')

        msg = Message('Titan Seller - Confirm Email',
                      sender=EMAIL_ADDRESS,
                      recipients=[email])

        link = url_for('confirm_email', token=token, _external=True)
        msg.body = 'Welcome to Titan Seller !! \n\n\n Click this link to verify your account: {} ' \
                '\n\n\nThank you! \nHappy shopping,\nTitan Seller ' \
                'Team'.format(link)

        mailbox.send(msg)

        # Hash Password
        password = request.form.get('password', 'default value password')
        salt = bcrypt.gensalt()
        hashed_pass = bcrypt.hashpw(bytes(password, encoding='utf8'), salt)

        engine.execute(
          "INSERT INTO user_database (user_name, user_email, "
          "user_password) VALUES (?, ?, ?);",
          (user_name, email, hashed_pass))
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
      engine.execute(
        "UPDATE user_database SET user_status = (?) WHERE user_id = (?);",
        (1, user_data['user_id']))
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
          user_results = generated_session.execute(
            text("select * from user_database where user_email='{}'".format(
              str(email))))
          for r in user_results:
            user_data = dict(r)
        if bcrypt.checkpw(bytes(password, encoding='utf8'),
                          user_data['user_password']):
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
          flash("The username and/or password is incorrect, please try again.",
                category="is-danger")
      except Exception as ex:
        redirect(url_for('login'))
        flash("The username and/or password is incorrect, please try again.",
              category="is-danger")
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


@app.route('/search')
@app.route('/search/')
@app.route('/search/<query>')
def search(query=""):
  #Get User Data if Logged in
  user_data = get_login_user_data()
  if user_data == "Banned":
    return redirect(url_for('logout'))
  #Get item data
  results = None
  data = []
  with sql_session.begin() as generated_session:
    results = generated_session.execute(
      text("SELECT * FROM item JOIN user_database ON user_id=seller_id WHERE "
           "active=1 AND user_status=1 ORDER BY item_id DESC LIMIT 9"))
    for r in results:
      r_dict = dict(r)

      #Check Query
      if query.lower() in r_dict['item_name'].lower():
        data.append(r_dict)

  return render_template('home.html',
                         item_list=data,
                         user_data=user_data,
                         search_query=query)


@app.route('/item/<int:id>')
def get_item(id: int):
  user_data = get_login_user_data()
  item_data = {}
  seller_data = {}

  if user_data == "Banned":
    return redirect(url_for('logout'))
  if user_data is not None:
    with sql_session.begin() as generated_session:
      item_results = generated_session.execute(
        text('select * from item where item_id={}'.format(id)))
      for ir in item_results:
        item_data = dict(ir)
    seller_data = get_user_data_by_id(item_data['seller_id'])


    return render_template('itempage.html',
                           item=item_data,
                           seller=seller_data,
                           user_id=user_data['user_id'])
  else:
    flash("You must Login to view this page")
    return redirect(url_for('login'))


@app.route('/review/<int:id>', methods=["GET", "POST"])
def submit_review(id: int):
  user_data = get_login_user_data()
  if user_data == "Banned":
    return redirect(url_for('logout'))
  if user_data is not None:
    if user_data['user_status'] == 1:
      connection = None
      id_num = 0
      if user_data is None:
        return redirect(url_for('error'))
      if request.method == 'POST':
        score = request.form.get('score', 'default score')
        rev_content = request.form.get('reviewContent', 'default content')
        engine.execute(
          "INSERT INTO review (review_score, review_text, seller_id, user_id) "
          "VALUES (?, ?, ?, ?);",
          (int(score), rev_content, id, user_data["user_id"]))
      return render_template('review.html')
    elif user_data['user_status'] == 0:
      flash('You must verify your email to do this action!')
      return redirect(url_for('home'))
  else:
    session['next'] = url_for('submit_review', id=id)
    flash("You must Login to view this page")
    return redirect(url_for('login'))


@app.route('/sell', methods=['POST', 'GET'])
def sell_item():
  user_data = get_login_user_data()
  connection = None

  if user_data == "Banned":
    return redirect(url_for('logout'))
  if user_data is not None:
    if user_data['user_status'] == 1:
      if not 'POST' in session:
        if request.method == 'POST':
          session['POST'] = True
          # Get Data
          item_name = request.form.get('name', 'default item name')
          price = request.form.get('price', 'default price')
          correct_price = "{:.2f}".format(float(price))
          description = request.form.get('itemDesc', 'default description')

          # Commit to Databse
          engine.execute(
            "INSERT INTO item (item_name, item_price, item_description, seller_id, active) "
            "VALUES (?, ?, ?, ?, ?);",
            (item_name, correct_price, description, user_data['user_id'], 1))

          id_num = 0
          try:
            connection = engine.connect()
            cursor = connection.execute("SELECT count(*) from item;")
            result = cursor.scalar()
            id_num = int(result)
          except:
            print("something went wrong")
          finally:
            if not connection.closed:
              cursor.close()
              connection.close()

          print(id_num)

          photo = request.files['photo']
          print(photo)
          filename = '{}.png'.format(id_num)

          photo.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
          session.pop('POST')
          return redirect(url_for('get_item', id=id_num))
      return render_template('post_item.html')
    elif user_data['user_status'] == 0:
      flash('You must verify your email to do this action!')
      return redirect(url_for('home'))
  else:
    session['next'] = url_for('sell_item')
    flash("You must Login to view this page")
    return redirect(url_for('login'))


@app.route('/manage', methods=['POST', 'GET'])
def manage():
  user_data = get_login_user_data()
  data = []
  if user_data == "Banned":
    return redirect(url_for('logout'))
  if user_data is not None:
    #Get Data
    with sql_session.begin() as generated_session:
      results = generated_session.execute(
        text(
          'SELECT * FROM item WHERE seller_id={} ORDER BY item_id DESC'.format(
            user_data['user_id'])))
      for r in results:
        r_dict = dict(r)
        data.append(r_dict)

    #Post
    if request.method == 'POST':
      item_name = request.form.get('name')
      price = request.form.get('price')
      description = request.form.get('itemDesc')
      status = request.form.get('status')
      item_id = request.form.get('itemId')

      #Update
      engine.execute(
        f"UPDATE item SET item_name='{item_name}', item_price={price}, item_description='{description}', active={status} WHERE item_id={item_id}"
      )
      return redirect(url_for('manage'))

    return render_template('manage_item.html', item_list=data)
  else:
    session['next'] = url_for('manage')
    flash("You must Login to view this page")
    return redirect(url_for('login'))


@app.route('/user/<int:id>', methods=['POST', 'GET'])
def user_profile(id: int):
  review_data = []
  users = []
  user_data = get_login_user_data()
  item_data = []

  if user_data == "Banned":
    return redirect(url_for('logout'))
  if user_data is not None:

    with sql_session.begin() as generated_session:
      review_results = generated_session.execute(
        text(
          "SELECT * FROM review JOIN user_database ON user_database.user_id=review.user_id "
          "WHERE seller_id={} ORDER BY review_id DESC".format(id)))
      for review in review_results:
        review_data.append(dict(review))

    seller_data = get_user_data_by_id(id)

    with sql_session.begin() as generated_session:
      item_results = generated_session.execute(
        text("SELECT * FROM item"
             " WHERE seller_id={} ORDER BY item_id DESC".format(id)))
      for item in item_results:
        item_data.append(dict(item))

    if request.method == 'POST':
      score = request.form.get('score', 'default score')
      rev_content = request.form.get('reviewContent', 'default content')
      engine.execute(
        "INSERT INTO review (review_score, review_text, seller_id, user_id) "
        "VALUES (?, ?, ?, ?);",
        (int(score), rev_content, id, user_data["user_id"]))

      #Set Score
      reviewed_user = get_user_data_by_id(id)
      new_score = 0
      review_count = 0
      with sql_session.begin() as generated_session:
        user_reviews = generated_session.execute(
          text("SELECT * FROM review WHERE seller_id={}".format(id)))
        for review in user_reviews:
          r = dict(review)
          review_count += 1
          new_score += r['review_score']

      new_score = round(new_score / review_count, 1)
      engine.execute(
        f"UPDATE user_database SET user_score='{new_score}' WHERE user_id={id}"
      )

      return redirect(url_for('user_profile', id=id))
    return render_template('user.html',
                           item_list=item_data,
                           review_list=review_data,
                           seller_data=seller_data,
                           user_data=user_data)
  else:
    session['next'] = url_for('sell_item')
    flash("You must Login to view this page")
    return redirect(url_for('login'))


@app.route('/chat', methods=['POST', 'GET'])
@app.route('/chat/', methods=['POST', 'GET'])
@app.route('/chat/<int:id>', methods=['POST', 'GET'])
def message(id: int = 0):
  data = []
  msg_data = {}
  sent_to_data = []
  got_from_data = []
  combined_with = []

  other_user_data = {}
  list_of_messages = []
  user_data = get_login_user_data()
  
  if user_data == "Banned":
    return redirect(url_for('logout'))
  
  if user_data is not None:
    if user_data['user_status'] == 1:
      #Left Signature
      with sql_session.begin() as generated_session:
        sent_to_results = generated_session.execute(
          text(
            "SELECT receiver_id AS important_id, "
            "max(message_id) AS message_num, message_content, user_name FROM (SELECT receiver_id, message_id, sender_id,"
            " message_content, user_name FROM message JOIN user_database ON receiver_id=user_id WHERE sender_id={}) z "
            " GROUP BY important_id "
            "ORDER BY message_id desc".format(user_data["user_id"])))
        for sent_to_str in sent_to_results:
          sent_to_data.append(dict(sent_to_str))

      with sql_session.begin() as generated_session:
        got_from_results = generated_session.execute(
          text(
            "SELECT sender_id AS important_id, "
            "max(message_id) AS message_num, message_content, user_name FROM (SELECT receiver_id, message_id, sender_id,"
            " message_content, user_name FROM message JOIN user_database ON sender_id=user_id WHERE receiver_id={}) z"
            " GROUP BY important_id "
            "ORDER BY message_id desc".format(user_data["user_id"])))
        for got_from_str in got_from_results:
          got_from_data.append(dict(got_from_str))

      combined_with.extend(sent_to_data)
      combined_with.extend(got_from_data)
      data = sorted(combined_with,
                    key=lambda x: x['message_num'],
                    reverse=True)
      data_dict = {}
      dupe_indices = []
      for index in range(len(data)):
        if data[index]['important_id'] in data_dict.keys():
          dupe_indices.append(index)
        else:
          data_dict[data[index]['important_id']] = data[index]['message_num']
      dupe_list = reversed(dupe_indices)
      for dupe in dupe_list:
        data.pop(dupe)

      #Get Current Data
      if id != 0:
        if user_data["user_id"] == id:
          return redirect('/home')

        #Get other user data
        with sql_session.begin() as generated_session:
          other_user_results = generated_session.execute(
            text('select * from user_database where user_id={}'.format(id)))
          for oud in other_user_results:
            other_user_data = dict(oud)

        #Send back if user doesn't exist
        if len(other_user_data) < 1:
          return redirect(url_for("message"))

        #Get List of Messages
        with sql_session.begin() as generated_session:
          message_results = generated_session.execute(
            text(
              "select * from message where "
              "(sender_id={} and receiver_id={}) or (sender_id={} and receiver_id={})"
              .format(user_data['user_id'], other_user_data['user_id'],
                      other_user_data['user_id'], user_data['user_id'])))
          for mr in message_results:
            list_of_messages.append(dict(mr))

        #Post
        if request.method == 'POST':
          msg_content = request.form.get('messageContent', 'default content')
          engine.execute(
            "INSERT INTO message (sender_id, receiver_id, message_content) VALUES (?, ?, ?);",
            (user_data["user_id"], id, msg_content))
          return redirect(url_for('message', id=id))
      return render_template('message.html',
                             sender=user_data,
                             receiver=other_user_data,
                             message_list=list_of_messages,
                             users_list=data)
    elif user_data['user_status'] == 0:
      flash("You must verify your email to do this action!")
      return redirect(url_for('home'))
  else:
    flash("You must Login to view this page")
    return redirect('/login')


@app.route('/chat/update/<sender_id>', methods=['GET'])
@app.route('/chat/update/<sender_id>/', methods=['GET'])
def update_chat(sender_id):
  if request.method == 'GET':
    # retrieve user data 
    user_data = get_user_data_by_id(sender_id)
    sent_to_data = []
    got_from_data = []
    combined_with = []
    data = []
    
    with sql_session.begin() as generated_session:
      sent_to_results = generated_session.execute(
        text(
          "SELECT receiver_id AS important_id, "
          "max(message_id) AS message_num, message_content, user_name FROM (SELECT receiver_id, message_id, sender_id,"
          " message_content, user_name FROM message JOIN user_database ON receiver_id=user_id WHERE sender_id={}) z "
          " GROUP BY important_id "
          "ORDER BY message_id desc".format(user_data["user_id"])))
      for sent_to_str in sent_to_results:
        sent_to_data.append(dict(sent_to_str))

    with sql_session.begin() as generated_session:
      got_from_results = generated_session.execute(
        text(
          "SELECT sender_id AS important_id, "
          "max(message_id) AS message_num, message_content, user_name FROM (SELECT receiver_id, message_id, sender_id,"
          " message_content, user_name FROM message JOIN user_database ON sender_id=user_id WHERE receiver_id={}) z"
          " GROUP BY important_id "
          "ORDER BY message_id desc".format(user_data["user_id"])))
      for got_from_str in got_from_results:
        got_from_data.append(dict(got_from_data))

    combined_with.extend(sent_to_data)
    combined_with.extend(got_from_data)
    data = sorted(combined_with,
                  key=lambda x: x['message_num'],
                  reverse=True)
    data_dict = {}
    dupe_indices = []
    for index in range(len(data)):
      if data[index]['important_id'] in data_dict.keys():
        dupe_indices.append(index)
      else:
        data_dict[data[index]['important_id']] = data[index]['message_num']
    dupe_list = reversed(dupe_indices)
    for dupe in dupe_list:
      data.pop(dupe)

    final_data = []
    for d in range(0, len(data)):
      print(data[d]['message_num'])
      final_data.append(data[d]['message_num'])

    #Return
    return json.dumps(final_data)

  return "stinky"


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
    user_results = generated_session.execute(
      text('select * from user_database where user_id={}'.format(id)))
    for ur in user_results:
      return ur


if __name__ == '__main__':
  app.run(debug=True, host='0.0.0.0')
