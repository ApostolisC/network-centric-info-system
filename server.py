import base64
from flask import Flask, abort, json, request, jsonify, render_template, redirect, make_response
from flask_cors import CORS
from flask_restful import Resource, Api
import mysql.connector
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError
import jwt
import datetime

# import Session from flask
from flask import session

app = Flask(__name__)
app.secret_key = 'super_secret_key'
api = Api(app)

# Configure CORS
CORS(app, supports_credentials=True, origins=["http://localhost:5000"])

database = mysql.connector.connect(
    host="localhost",
    user="root",
    password="",
    database="central_networks"
)
cursor = database.cursor()

# Generate JWT Token
def generate_token(username, exp=None):
    payload = {
        'username': username,
        'exp': exp if exp else datetime.datetime.now(datetime.UTC) + datetime.timedelta(hours=1)  # Token expires in 1 hour
    }
    return jwt.encode(payload, app.secret_key, algorithm='HS256')

# Verify JWT Token
def verify_token(token):
    try:
        payload = jwt.decode(token, app.secret_key, algorithms=['HS256'])
        return payload['username']
    except jwt.ExpiredSignatureError:
        return None
    except jwt.InvalidTokenError:
        return None

def change_username_in_token(token, new_username):
    try:
        payload = jwt.decode(token, app.secret_key, algorithms=['HS256'])
        exp = payload['exp']
        session["token"] = generate_token(new_username, exp=exp)
    except jwt.ExpiredSignatureError:
        return None
    except jwt.InvalidTokenError:
        return None

def get_user(token):
    try:
        payload = jwt.decode(token, app.secret_key, algorithms=['HS256'])
        return payload['username']
    except jwt.ExpiredSignatureError:
        return None
    except jwt.InvalidTokenError:
        return None

def check_token():
    if 'token' in session:
        token = session['token']
        username = verify_token(token)
        if username:
            return True
    return False

def check_admin():
    if 'role' in session:
        role = session['role']
        if role == 'admin':
            return True
    return False

class Login(Resource):
    def post(self):
        data = request.get_json(force=True)
        username = data.get('username')
        password = data.get('password')

        sql_query = "SELECT USERNAME, PASSWORD, ROLE FROM ACCOUNTS WHERE USERNAME=%s"
        cursor.execute(sql_query, (username,))
        result = cursor.fetchone()

        if not result:
            abort(401, "User not found")

        if not result[2]:
            abort(401, "Account not approved yet")

        user_password = result[1]
        ph = PasswordHasher()

        try:
            ph.verify(user_password, password)
        except VerifyMismatchError:
            abort(401, "Incorrect password")


        token = generate_token(username)
        session["token"] = token
        session["role"] = result[2]

        return 200

    def get(self):
        headers = {'Content-Type': 'text/html'}
        return make_response(render_template('login.html'),200, headers)
class Logout(Resource):
    def post(self):
        session.pop('token', None)
        return redirect('/')
class Signup(Resource):
    def post(self):
        data = request.get_json(force=True)
        name = data.get('name')
        lastname = data.get('lastname')
        country = data.get('country')
        city = data.get('city')
        address = data.get('address')
        phone = data.get('phone')
        email = data.get('email')  # also username
        password = data.get('password')

        ph = PasswordHasher()
        hashed_password = ph.hash(password)
        print("hashed_password", hashed_password)

        try:

            # check if the email is already in use
            sql_query = "SELECT * FROM ACCOUNTS WHERE USERNAME=%s"
            cursor.execute(sql_query, (email,))
            result = cursor.fetchone()
            if result:
                return jsonify({'message': 'Email already in use'}), 400
            # insert into accounts the new account and also into users with username as foreign key

            sql_query = "INSERT INTO ACCOUNTS (USERNAME, PASSWORD) VALUES (%s, %s)"
            cursor.execute(sql_query, (email, hashed_password))
            print("added to accounts")

            sql_query = "INSERT INTO USERS (USERNAME, NAME, SURNAME, COUNTRY, CITY, ADDRESS, EMAIL, PHONE) VALUES (%s, %s, %s, %s, %s, %s, %s, %s)"
            cursor.execute(sql_query, (email, name, lastname, country, city, address, email, phone))

            print("added to users")


            database.commit()

            return 200
        except Exception as e:
            database.rollback()
            print(e)
            abort(400)

    def get(self):
        # Serve signup template
        headers = {'Content-Type': 'text/html'}
        return make_response(render_template('signup.html'), 200, headers)

###################
# Authentication Routes
api.add_resource(Login, '/login/')
api.add_resource(Logout, '/logout/')
api.add_resource(Signup, '/signup/')
###################



class Dashboard(Resource):
    def get(self):
        if not check_token():
            return redirect('/login/')

        if not check_admin():
            abort(401)


        return make_response(render_template('dashboard.html'))
class ChangeAccountRole(Resource):
    def post(self):
        if not check_token() or not check_admin():
            return jsonify({'message': 'Unauthorized'}), 401

        data = request.get_json(force=True)
        username = data.get('username')
        role = data.get('role')

        if role not in ('admin', 'user', 'rejected'):
            return jsonify({'message': 'Invalid role'}), 400

        if role == 'rejected':
            print("\n\nRejecting new account %s\n\n"%username)
            # remove the account from the database (tables accounts and users)
            try:
                sql_query = "DELETE FROM ACCOUNTS WHERE USERNAME=%s"
                cursor.execute(sql_query, (username,))
                database.commit()

                return 200
            except Exception as e:
                database.rollback()
                print(f"Error deleting account: {e}")
                return jsonify({'message': 'Failed to delete account'}), 500

        try:
            # Update the role of the account in the ACCOUNTS table
            sql_query = "UPDATE ACCOUNTS SET ROLE=%s WHERE USERNAME=%s"
            cursor.execute(sql_query, (role, username))
            database.commit()

            return 200
        except Exception as e:
            database.rollback()
            return jsonify({'message': 'Failed to change account role'}), 500
class UpdateUserInfo(Resource):

    # update user info for users table and also accept role for accounts table
    def post(self):
        if not check_token() or not check_admin():
            return jsonify({'message': 'Unauthorized'}), 401

        data = request.get_json(force=True)
        username = data.get('username')
        name = data.get('name')
        surname = data.get('surname')
        country = data.get('country')
        city = data.get('city')
        address = data.get('address')
        email = data.get('email')
        phone = data.get('phone')
        role = data.get('role')

        if role not in ('admin', 'user'):
            return jsonify({'message': 'Invalid role'}), 400

        try:
            # Update the user's information in the USERS table
            sql_query = "UPDATE USERS SET NAME=%s, SURNAME=%s, COUNTRY=%s, CITY=%s, ADDRESS=%s, EMAIL=%s, PHONE=%s WHERE USERNAME=%s"
            cursor.execute(sql_query, (name, surname, country, city, address, email, phone, username))

            # Update the role of the account in the ACCOUNTS table
            sql_query = "UPDATE ACCOUNTS SET ROLE=%s WHERE USERNAME=%s"
            cursor.execute(sql_query, (role, username))

            database.commit()

            return 200
        except Exception as e:
            database.rollback()
            return jsonify({'message': 'Failed to update user info'}), 500
class FetchDashboardData(Resource):
    # fetch new accounts under key newAccounts
    # fetch existing accounts under key accounts
    # fetch trainers under key trainers
    # fetch programmes under key programmes
    # fetch program schedule under programmeSchedule
    def get(self):
        if not check_token() or not check_admin():
            return jsonify({'message': 'Unauthorized'}), 401

        try:
            # Fetch new accounts
            sql_query = """
                SELECT u.USERNAME, u.NAME, u.SURNAME, u.COUNTRY, u.CITY, u.ADDRESS, u.EMAIL, u.PHONE
                FROM USERS u
                JOIN ACCOUNTS a ON u.USERNAME = a.USERNAME
                WHERE a.ROLE IS NULL
            """
            cursor.execute(sql_query)
            new_accounts = cursor.fetchall()

            new_accounts_list = []
            for account in new_accounts:
                account_data = {
                    'username': account[0],
                    'name': account[1],
                    'surname': account[2],
                    'country': account[3],
                    'city': account[4],
                    'address': account[5],
                    'email': account[6],
                    'phone': account[7]
                }
                new_accounts_list.append(account_data)

            # Fetch existing accounts
            sql_query = """
                SELECT u.USERNAME, u.NAME, u.SURNAME, u.COUNTRY, u.CITY, u.ADDRESS, u.EMAIL, u.PHONE, a.ROLE
                FROM USERS u
                JOIN ACCOUNTS a ON u.USERNAME = a.USERNAME
                WHERE a.ROLE IS NOT NULL
            """
            cursor.execute(sql_query)
            existing_accounts = cursor.fetchall()

            existing_accounts_list = []
            for account in existing_accounts:
                account_data = {
                    'username': account[0],
                    'name': account[1],
                    'surname': account[2],
                    'country': account[3],
                    'city': account[4],
                    'address': account[5],
                    'email': account[6],
                    'phone': account[7],
                    'role': account[8]
                }
                existing_accounts_list.append(account_data)

            # Fetch trainers
            sql_query = "SELECT * FROM TRAINERS"
            cursor.execute(sql_query)
            trainers = cursor.fetchall()

            trainers_list = []
            for trainer in trainers:
                trainer_data = {
                    'id': trainer[0],
                    'name': trainer[1],
                    'surname': trainer[2],
                    'address': trainer[3],
                    'phone': trainer[4],
                    'email': trainer[5]
                }
                trainers_list.append(trainer_data)

            # Fetch programmes
            sql_query = "SELECT * FROM GYMNASTIC_PROGRAMMES"
            cursor.execute(sql_query)
            programmes = cursor.fetchall()

            programmes_list = []
            for programme in programmes:
                programme_data = {
                    'id': programme[0],
                    'title': programme[1],
                    'type': programme[2],
                    'description': programme[3],
                    'goal': programme[4],
                    'difficulty': programme[5]
                }
                programmes_list.append(programme_data)

            # Fetch programme schedule
            # change the sql query so it fetches the trainer based on trainer id (foreign key)
            # also select program name from programmes table based on programme column in programme_schedule
            sql_query = """
                SELECT
                    ps.ID,
                    t.TITLE,
                    ps.DAY,
                    ps.HOUR,
                    CONCAT(tr.NAME, ' ', tr.SURNAME) AS TRAINER_NAME,
                    ps.MAX_NUM
                FROM
                    PROGRAMME_SCHEDULE ps
                JOIN
                    GYMNASTIC_PROGRAMMES t
                    ON ps.PROGRAMME = t.ID
                JOIN
                    trainers tr
                    ON ps.TRAINER = tr.ID

            """
            cursor.execute(sql_query)
            programme_schedule = cursor.fetchall()

            programme_schedule_list = []
            for schedule in programme_schedule:
                print(schedule)
                schedule_data = {
                    'id': schedule[0],
                    'title': schedule[1],
                    'day': schedule[2],
                    'hour': str(schedule[3]),
                    'trainer': schedule[4],
                    'capacity': schedule[5]
                }
                programme_schedule_list.append(schedule_data)

            response_data = {
                'newAccounts': new_accounts_list,
                'accounts': existing_accounts_list,
                'trainers': trainers_list,
                'programmes': programmes_list,
                'programmeSchedule': programme_schedule_list
            }

            return app.response_class(
                        response=json.dumps(response_data),
                        status=200,
                        mimetype='application/json'
                    )

        except Exception as e:
            print(f"Error fetching dashboard data: {e}")
            return jsonify({'message': 'Failed to fetch dashboard data'}), 500

class UpdateTrainer(Resource):
    def post(self):
        if not check_token() or not check_admin():
            return jsonify({'message': 'Unauthorized'}), 401

        data = request.get_json(force=True)
        trainer_id = data.get('id')
        name = data.get('name')
        surname = data.get('surname')
        address = data.get('address')
        phone = data.get('phone')
        email = data.get('email')

        try:
            sql_query = "UPDATE TRAINERS SET NAME=%s, SURNAME=%s, ADDRESS=%s, PHONE=%s, EMAIL=%s WHERE ID=%s"
            cursor.execute(sql_query, (name, surname, address, phone, email, trainer_id))
            database.commit()

            return 200
        except Exception as e:
            database.rollback()
            return jsonify({'message': 'Failed to update trainer'}), 500

class UpdateProgramme(Resource):
    def post(self):
        if not check_token() or not check_admin():
            return jsonify({'message': 'Unauthorized'}), 401

        data = request.get_json(force=True)
        programme_id = data.get('id')
        title = data.get('title')
        type = data.get('type')
        description = data.get('description')
        goal = data.get('goal')
        difficulty = data.get('difficulty')

        try:
            sql_query = "UPDATE GYMNASTIC_PROGRAMMES SET TITLE=%s, TYPE=%s, DESCRIPTION=%s, GOAL=%s, DIFFICULTY=%s WHERE ID=%s"
            cursor.execute(sql_query, (title, type, description, goal, difficulty, programme_id))
            database.commit()

            return 200
        except Exception as e:
            database.rollback()
            return jsonify({'message': 'Failed to update programme'}), 500

class UpdateProgrammeSchedule(Resource):
    """
    We receive id, title, day, hour, trainer, capacity

    The id is the id of the schedule
    The title is the TITLE of the programme from GYMNASTIC_PROGRAMMES TITLE
    the trainer is the concatenation of the name and surname of the trainer from TRAINERS NAME and SURNAME

    We should first try and parse the id of the program based on the title and check if it exists (else abort)
    We should also try and parse the id of the trainer based on the name and surname and check if it exists (else abort)
    """
    def post(Self):
        if not check_token() or not check_admin():
            return jsonify({'message': 'Unauthorized'}), 401

        data = request.get_json(force=True)
        schedule_id = data.get('id')
        title = data.get('title')
        day = data.get('day')
        hour = data.get('hour')
        trainer = data.get('trainer')
        capacity = data.get('capacity')

        print(schedule_id, title, day, hour, trainer, capacity)

        try:
            # Fetch the programme id based on the title
            sql_query = "SELECT ID FROM GYMNASTIC_PROGRAMMES WHERE TITLE=%s"
            cursor.execute(sql_query, (title,))
            programme_id = cursor.fetchone()

            if not programme_id:
                return jsonify({'message': 'Programme not found'}), 404

            # Fetch the trainer id based on the name and surname
            trainer_name, trainer_surname = trainer.split(' ')
            sql_query = "SELECT ID FROM TRAINERS WHERE NAME=%s AND SURNAME=%s"
            cursor.execute(sql_query, (trainer_name, trainer_surname))
            trainer_id = cursor.fetchone()

            if not trainer_id:
                return jsonify({'message': 'Trainer not found'}), 404

            sql_query = "UPDATE PROGRAMME_SCHEDULE SET PROGRAMME=%s, DAY=%s, HOUR=%s, TRAINER=%s, MAX_NUM=%s WHERE ID=%s"
            cursor.execute(sql_query, (programme_id[0], day, hour, trainer_id[0], capacity, schedule_id))
            database.commit()

            return 200
        except Exception as e:
            database.rollback()
            return jsonify({'message': 'Failed to update programme schedule'}), 500

class CreateTrainer(Resource):
    def post(self):
        if not check_token() or not check_admin():
            return jsonify({'message': 'Unauthorized'}), 401

        data = request.get_json(force=True)
        name = data.get('name')
        surname = data.get('surname')
        address = data.get('address')
        phone = data.get('phone')
        email = data.get('email')

        try:
            sql_query = "INSERT INTO TRAINERS (NAME, SURNAME, ADDRESS, PHONE, EMAIL) VALUES (%s, %s, %s, %s, %s)"
            cursor.execute(sql_query, (name, surname, address, phone, email))
            database.commit()

            return 200
        except Exception as e:
            database.rollback()
            return jsonify({'message': 'Failed to create trainer'}), 500

class CreateProgramme(Resource):
    def post(self):
        if not check_token() or not check_admin():
            return jsonify({'message': 'Unauthorized'}), 401

        data = request.get_json(force=True)
        title = data.get('title')
        type = data.get('type')
        description = data.get('description')
        goal = data.get('goal')
        difficulty = data.get('difficulty')

        try:
            sql_query = "INSERT INTO GYMNASTIC_PROGRAMMES (TITLE, TYPE, DESCRIPTION, GOAL, DIFFICULTY) VALUES (%s, %s, %s, %s, %s)"
            cursor.execute(sql_query, (title, type, description, goal, difficulty))
            database.commit()

            return 200
        except Exception as e:
            database.rollback()
            return jsonify({'message': 'Failed to create programme'}), 500

class CreateProgrammeSchedule(Resource):
    def post(self):
        if not check_token() or not check_admin():
            return jsonify({'message': 'Unauthorized'}), 401

        data = request.get_json(force=True)
        title = data.get('title')
        day = data.get('day')
        hour = data.get('hour')
        trainer = data.get('trainer')
        capacity = data.get('capacity')

        """
        get id for title from PROGRAMMES.TITLE
        get id for trainer from trainers.NAME and trainers.SURNAME

        if one of the above is not found return 404
        """
        try:
            # Fetch the programme id based on the title
            sql_query = "SELECT ID FROM GYMNASTIC_PROGRAMMES WHERE TITLE=%s"
            cursor.execute(sql_query, (title,))
            programme_id = cursor.fetchone()

            if not programme_id:
                return jsonify({'message': 'Programme not found'}), 404

            # Fetch the trainer id based on the name and surname
            trainer_name, trainer_surname = trainer.split(' ')
            sql_query = "SELECT ID FROM TRAINERS WHERE NAME=%s AND SURNAME=%s"
            cursor.execute(sql_query, (trainer_name, trainer_surname))
            trainer_id = cursor.fetchone()

            if not trainer_id:
                return jsonify({'message': 'Trainer not found'}), 404

            sql_query = "INSERT INTO PROGRAMME_SCHEDULE (PROGRAMME, DAY, HOUR, TRAINER, MAX_NUM) VALUES (%s, %s, %s, %s, %s)"
            cursor.execute(sql_query, (programme_id[0], day, hour, trainer_id[0], capacity))
            database.commit()


            return 200
        except Exception as e:
            database.rollback()
            return jsonify({'message': 'Failed to create programme schedule'}), 500


class DeleteTrainer(Resource):
    def post(self):
        if not check_token() or not check_admin():
            return jsonify({'message': 'Unauthorized'}), 401

        data = request.get_json(force=True)
        trainer_id = data.get('id')

        try:
            sql_query = "DELETE FROM TRAINERS WHERE ID=%s"
            cursor.execute(sql_query, (trainer_id,))
            database.commit()

            return 200
        except Exception as e:
            database.rollback()
            return jsonify({'message': 'Failed to delete trainer'}), 500

class DeleteProgramme(Resource):
    def post(self):
        if not check_token() or not check_admin():
            return jsonify({'message': 'Unauthorized'}), 401

        data = request.get_json(force=True)
        programme_id = data.get('id')

        try:
            sql_query = "DELETE FROM GYMNASTIC_PROGRAMMES WHERE ID=%s"
            cursor.execute(sql_query, (programme_id,))
            database.commit()

            return 200
        except Exception as e:
            database.rollback()
            return jsonify({'message': 'Failed to delete programme'}), 500

class DeleteProgrammeSchedule(Resource):
    def post(self):
        if not check_token() or not check_admin():
            return jsonify({'message': 'Unauthorized'}), 401

        data = request.get_json(force=True)
        schedule_id = data.get('id')

        try:
            sql_query = "DELETE FROM PROGRAMME_SCHEDULE WHERE ID=%s"
            cursor.execute(sql_query, (schedule_id,))
            database.commit()

            return 200
        except Exception as e:
            database.rollback()
            return jsonify({'message': 'Failed to delete programme schedule'}), 500

class DeleteUser(Resource):
    def post(self):
        if not check_token() or not check_admin():
            return jsonify({'message': 'Unauthorized'}), 401

        data = request.get_json(force=True)
        username = data.get('username')

        try:
            sql_query = "DELETE FROM USERS WHERE USERNAME=%s"
            cursor.execute(sql_query, (username,))
            database.commit()

            sql_query = "DELETE FROM ACCOUNTS WHERE USERNAME=%s"
            cursor.execute(sql_query, (username,))
            database.commit()

            return 200
        except Exception as e:
            database.rollback()
            return jsonify({'message': 'Failed to delete user'}), 500

class CreateUser(Resource):
    def post(self):
        if not check_token() or not check_admin():
            return jsonify({'message': 'Unauthorized'}), 401

        data = request.get_json(force=True)
        print("new user:",data)
        name = data.get('name')
        surname = data.get('surname')
        country = data.get('country')
        city = data.get('city')
        address = data.get('address')
        email = data.get('email')
        phone = data.get('phone')
        role = data.get('role')
        password = data.get('password')

        ph = PasswordHasher()
        hashed_password = ph.hash(password)

        try:
            # check if the email is already in use
            sql_query = "SELECT * FROM ACCOUNTS WHERE USERNAME=%s"
            cursor.execute(sql_query, (email,))
            result = cursor.fetchone()
            if result:
                return jsonify({'message': 'Email already in use'}), 400

            # insert into accounts the new account and also into users with username as foreign key
            sql_query = "INSERT INTO ACCOUNTS (USERNAME, PASSWORD, ROLE) VALUES (%s, %s, %s)"
            cursor.execute(sql_query, (email, hashed_password, role))

            database.commit()

            sql_query = "INSERT INTO USERS (USERNAME, NAME, SURNAME, COUNTRY, CITY, ADDRESS, EMAIL, PHONE) VALUES (%s, %s, %s, %s, %s, %s, %s, %s)"
            cursor.execute(sql_query, (email, name, surname, country, city, address, email, phone))

            database.commit()

            return 200
        except Exception as e:
            print(e)
            database.rollback()
            return jsonify({'message': 'Failed to create user'}), 500

class AdminNews(Resource):
    def get(self):
        if not check_token() or not check_admin():
            return jsonify({'message': 'Unauthorized'}),

        return make_response(render_template('admin_news.html'))

class AdminGetNews(Resource):
    def get(self):
        if not check_token() or not check_admin():
            return jsonify({'message': 'Unauthorized'}), 401
        try:
            sql_query = "SELECT * FROM NEWS"
            cursor.execute(sql_query)
            news = cursor.fetchall()

            news_list = []
            for news_item in news:
                news_data = {
                    'id': news_item[0],
                    'title': news_item[1],
                    'date': news_item[2],
                    'content': news_item[3],
                    'author': news_item[4],
                    'image': f"data:image/jpeg;base64,{base64.b64encode(news_item[5]).decode('utf-8')}" if news_item[5] else None,
                    'visible': news_item[6],
                }
                news_list.append(news_data)

            return jsonify(news_list)
        except Exception as e:
            return jsonify({'message': 'Failed to fetch news'}), 500

class EditNews(Resource):
    def post(self):
        if not check_token() or not check_admin():
            return jsonify({'message': 'Unauthorized'}), 401

        data = request.get_json(force=True)

        print("got data:",data)
        # get data from data
        news_id = data.get('id')
        title = data.get('title')
        date = data.get('date')
        content = data.get('content')
        author = data.get('author')


        print(news_id, title, date, author, content)

        try:
            sql_query = "UPDATE NEWS SET TITLE=%s, DATE=%s, CONTENT=%s, AUTHOR=%s WHERE ID=%s"
            print("sql_query:",sql_query%(title, date, content, author, news_id))
            cursor.execute(sql_query, (title, date, content, author, news_id))
            database.commit()

            print("updated news")

            return 200
        except Exception as e:
            database.rollback()
            abort(500)

class CreateNews(Resource):
    def post(self):
        if not check_token() or not check_admin():
            return jsonify({'message': 'Unauthorized'}), 401

        data = request.get_json(force=True)
        title = data.get('title')
        content = data.get('content')
        author = data.get('author')

        try:
            sql_query = "INSERT INTO NEWS (TITLE, CONTENT, AUTHOR) VALUES (%s, %s, %s)"
            cursor.execute(sql_query, (title, content, author))
            database.commit()

            return 200
        except Exception as e:
            database.rollback()
            return jsonify({'message': 'Failed to create news'}), 500

class DeleteNews(Resource):
    def post(self):
        if not check_token() or not check_admin():
            return jsonify({'message': 'Unauthorized'}), 401

        data = request.get_json(force=True)
        news_id = data.get('id')

        try:
            sql_query = "DELETE FROM NEWS WHERE ID=%s"
            cursor.execute(sql_query, (news_id,))
            database.commit()

            return 200
        except Exception as e:
            database.rollback()
            return jsonify({'message': 'Failed to delete news'}), 500



class createOffer(Resource):
    """
    offer will have a title, description, price, start_date, end_date
    """
    def post(self):
        if not check_token():
            return jsonify({'message': 'Unauthorized'}), 401
        
        data = request.get_json(force=True)
        title = data.get('title')
        description = data.get('description')
        price = data.get('price')
        start_date = data.get('start_date')
        end_date = data.get('end_date')

        try:
            sql_query = "INSERT INTO OFFERS (TITLE, DESCRIPTION, PRICE, START_DATE, END_DATE) VALUES (%s, %s, %s, %s, %s)"
            cursor.execute(sql_query, (title, description, price, start_date, end_date))
            database.commit()

            return 200
        except Exception as e:
            database.rollback()
            return jsonify({'message': 'Failed to create offer'}), 500

class deleteOffer(Resource):
    def post(self):
        if not check_token():
            return jsonify({'message': 'Unauthorized'}), 401

        data = request.get_json(force=True)
        offer_id = data.get('id')

        try:
            sql_query = "DELETE FROM OFFERS WHERE ID=%s"
            cursor.execute(sql_query, (offer_id,))
            database.commit()

            return 200
        except Exception as e:
            database.rollback()
            return jsonify({'message': 'Failed to delete offer'}), 500

class updateOffer(Resource):
    def post(self):
        if not check_token():
            return jsonify({'message': 'Unauthorized'}), 401

        data = request.get_json(force=True)
        offer_id = data.get('id')
        title = data.get('title')
        description = data.get('description')
        price = data.get('price')
        start_date = data.get('start_date')
        end_date = data.get('end_date')

        try:
            sql_query = "UPDATE OFFERS SET TITLE=%s, DESCRIPTION=%s, PRICE=%s, START_DATE=%s, END_DATE=%s WHERE ID=%s"
            cursor.execute(sql_query, (title, description, price, start_date, end_date, offer_id))
            database.commit()

            return 200
        except Exception as e:
            database.rollback()
            return jsonify({'message': 'Failed to update offer'}), 500


###################
# Admin Routes
api.add_resource(Dashboard, '/dashboard/')
api.add_resource(ChangeAccountRole, '/admin/change-account-role')
api.add_resource(UpdateUserInfo, '/admin/update-user-info')
api.add_resource(FetchDashboardData, '/admin/fetch-dashboard-data')
api.add_resource(UpdateTrainer, '/admin/update-trainer-info')
api.add_resource(UpdateProgramme, '/admin/update-programme-info')
api.add_resource(UpdateProgrammeSchedule, '/admin/update-programme-schedule')
api.add_resource(CreateTrainer, '/admin/create-trainer')
api.add_resource(CreateProgramme, '/admin/create-programme')
api.add_resource(CreateProgrammeSchedule, '/admin/create-programme-schedule')
api.add_resource(DeleteTrainer, '/admin/delete-trainer')
api.add_resource(DeleteProgramme, '/admin/delete-programme')
api.add_resource(DeleteProgrammeSchedule, '/admin/delete-programme-schedule')
api.add_resource(DeleteUser, '/admin/delete-user')
api.add_resource(CreateUser, '/admin/create-user')
api.add_resource(AdminNews, "/dashboard/news")
api.add_resource(AdminGetNews, '/admin/get-news')
api.add_resource(CreateNews, '/admin/create-news')
api.add_resource(DeleteNews, '/admin/delete-news')
api.add_resource(EditNews, '/admin/update-news')

###################



class Index(Resource):
    def get(self):
        return make_response(render_template('index.html'))
class Services(Resource):
    def get(self):
        return make_response(render_template('services.html'))
    
class GetServices(Resource):
    def get(self):
        try:
            sql_query = "SELECT * FROM SERVICES"
            cursor.execute(sql_query)
            services = cursor.fetchall()
            print("services:", services)

            services_list = []
            for service in services:
                service_data = {
                    'id': service[0],
                    'title': service[1],
                    'description': service[2],
                    'image': f"data:image/jpeg;base64,{base64.b64encode(service[3]).decode('utf-8')}" if service[3] else None,
                }
                services_list.append(service_data)

            print("returning:",jsonify(services_list))

            return jsonify(services_list)
        except Exception as e:
            return jsonify({'message': 'Failed to fetch services'}), 500
class Bookings(Resource):
    def get(self):
        if not check_token():
            return redirect('/login/')

        return make_response(render_template('bookings.html'))
class GetProgrammes(Resource):
    def get(self):
        try:
            sql_query = "SELECT * FROM GYMNASTIC_PROGRAMMES"
            cursor.execute(sql_query)
            programmes = cursor.fetchall()
            print(programmes)

            programmes_list = []
            for programme in programmes:
                programme_data = {
                    'id': programme[0],
                    'title': programme[1],
                    'type': programme[2],
                    'description': programme[3],
                    'goal': programme[4],
                    'difficulty': programme[5]
                }
                programmes_list.append(programme_data)

            return jsonify(programmes_list)
        except Exception as e:
            return jsonify({'message': 'Failed to fetch programmes'}), 500
class GetSchedule(Resource):
    def post(self):
        # extract program_name and date from json data
        data = request.get_json(force=True)
        program_name = data.get('program')
        date = data.get('date')

        try:
            sql_query = """
                SELECT
                    ps.ID,
                    t.TITLE,
                    ps.DAY,
                    ps.HOUR,
                    CONCAT(tr.NAME, ' ', tr.SURNAME) AS TRAINER_NAME,
                    ps.MAX_NUM
                FROM
                    PROGRAMME_SCHEDULE ps
                JOIN
                    GYMNASTIC_PROGRAMMES t
                    ON ps.PROGRAMME = t.ID
                JOIN
                    trainers tr
                    ON ps.TRAINER = tr.ID
                WHERE
                    t.TITLE=%s AND ps.DAY=%s
            """
            cursor.execute(sql_query, (program_name, date))
            programme_schedule = cursor.fetchall()

            print("found schedule results:", programme_schedule)

            programme_schedule_list = []
            for schedule in programme_schedule:
                schedule_data = {
                    'id': schedule[0],
                    'title': schedule[1],
                    'day': schedule[2],
                    'hour': str(schedule[3]),
                    'trainer': schedule[4],
                    'capacity': schedule[5]
                }
                programme_schedule_list.append(schedule_data)

            return jsonify(programme_schedule_list)
        except Exception as e:
            return jsonify({'message': 'Failed to fetch programme schedule'}), 500

class GetBookings(Resource):
    def get(self):
        if not check_token():
            return jsonify({'message': 'Unauthorized'}), 401

        username = get_user(session['token'])
        if not username:
            return jsonify({'message': 'Unauthorized'}), 401

        try:
            sql_query = """
                SELECT * FROM BOOKINGS WHERE USER=%s
            """
            cursor.execute(sql_query, (username,))
            bookings = cursor.fetchall()

            bookings_list = []
            for booking in bookings:
                booking_data = {
                    'id': booking[0],
                    'user': booking[1],
                    'programme': booking[2],
                    'type': str(booking[3]),
                    'day': booking[4],
                    "hour": booking[5],
                    "trainer": booking[6]
                }
                bookings_list.append(booking_data)

            return jsonify(bookings_list)
        except Exception as e:
            return jsonify({'message': 'Failed to fetch bookings'}), 500
class GetHistory(Resource):
    def get(self):
        if not check_token():
            abort(401)

        username = get_user(session['token'])
        if not username:
            abort(401)

        try:
            sql_query = """
                SELECT * FROM BOOKINGS_HISTORY WHERE USER=%s
            """
            cursor.execute(sql_query, (username,))
            history = cursor.fetchall()

            history_list = []
            for record in history:
                record_data = {
                    'id': record[0],
                    'user': record[1],
                    'programme': record[2],
                    'type': str(record[3]),
                    'day': record[4],
                    "hour": record[5],
                    "trainer": record[6]
                }
                history_list.append(record_data)

            return jsonify(history_list)
        except Exception as e:
            return jsonify({'message': 'Failed to fetch history'}), 500
class History(Resource):
    def get(self):
        if not check_token():
            return redirect('/login/')

        return make_response(render_template('history.html'))
class News(Resource):
    def get(self):
        return make_response(render_template('news.html'))
class Profile(Resource):
    def get(self):
        if not check_token():
            return redirect('/login/')

        return make_response(render_template('profile.html'))
class UserProfile(Resource):
    def get(self):
        if not check_token():
            abort(401)

        # Assuming `get_current_user()` retrieves the current user's username from the session or token
        username = get_user(session['token'])
        if not username:
            abort(401)

        # Fetch user profile data from the database
        sql_query = "SELECT * FROM users WHERE USERNAME=%s"
        cursor.execute(sql_query, (username,))
        user_data = cursor.fetchone()

        if not user_data:
            return jsonify({'message': 'User not found'}), 404

        # Structure the data as needed
        response_data = {
            'username': user_data[0],
            'name': user_data[1],
            'surname': user_data[2],
            'country': user_data[3],
            'city': user_data[4],
            'address': user_data[5],
            'email': user_data[6],
            'phone': user_data[7]
        }

        return jsonify(response_data)
class UpdateProfile(Resource):
    def post(self):
        if not check_token():
            abort(401)

        data = request.get_json(force=True)
        username = get_user(session['token'])
        name = data.get('name')
        lastname = data.get('surname')
        country = data.get('country')
        city = data.get('city')
        address = data.get('address')
        phone = data.get('phone')
        email = data.get('email')

        try:
            """
            Because the email is also the username, when the user updates
            his email, the username will also change.
            But the username is a foreign key in the USERS table, so we need to update it.
            Also we need to check if the email is already in use.

            steps:
            1. Check if the email is already in use
            2. Update the username in the ACCOUNTS table so it can cascade to the USERS table
            3. Update the user's information in the USERS table, that contains the updated username (if changed)
            """

            print(username, name, lastname, country, city, address, phone, email)

            if username != email:
                # user changed email so we need to update the username in the ACCOUNTS table
                sql_query = "SELECT * FROM ACCOUNTS WHERE USERNAME=%s"
                cursor.execute(sql_query, (email,))
                result = cursor.fetchone()

                if result:
                    return jsonify({'message': 'Email already in use'}), 400

                sql_query = "UPDATE ACCOUNTS SET USERNAME=%s WHERE USERNAME=%s"
                cursor.execute(sql_query, (email, username))

            sql_query = "UPDATE USERS SET NAME=%s, SURNAME=%s, COUNTRY=%s, CITY=%s, ADDRESS=%s, EMAIL=%s, PHONE=%s WHERE USERNAME=%s"
            cursor.execute(sql_query, (name, lastname, country, city, address, email, phone, email))

            database.commit()

            if username != email:
                change_username_in_token(session['token'], email)

            return 200
        except Exception as e:
            database.rollback()
            print(e)
            abort(400)
class PasswordReset(Resource):
    def post(self):
        if not check_token():
            abort(401, "Unauthorized")

        data = request.get_json(force=True)
        username = data.get('username')
        current_password= data.get('current_password')
        new_password = data.get('new_password')
        confirm_password = data.get('confirm_password')

        print(username, current_password, new_password, confirm_password)


        if new_password != confirm_password:
            abort(400, "Passwords do not match")


        # Check if email exists
        sql_query = "SELECT * FROM ACCOUNTS WHERE USERNAME=%s"
        cursor.execute(sql_query, (username,))
        result = cursor.fetchone()
        if not result:
            abort(400, "User not found")

        user_password = result[1]
        # validate current password
        ph = PasswordHasher()
        try:
            ph.verify(user_password, current_password)
        except VerifyMismatchError:
            abort(400, "Incorrect password")

        hashed_password = ph.hash(new_password)

        # Update the password
        sql_query = "UPDATE ACCOUNTS SET PASSWORD=%s WHERE USERNAME=%s"
        cursor.execute(sql_query, (hashed_password, username))

        database.commit()

        return 200

###################
# User Routes
api.add_resource(Index, '/')
api.add_resource(Services, '/services/')
api.add_resource(GetServices, '/get-services/')
api.add_resource(GetSchedule, '/get-schedule/')
api.add_resource(Bookings, '/bookings/')
api.add_resource(GetBookings, '/get-bookings/')
api.add_resource(GetProgrammes, '/get-programmes/')
api.add_resource(History, '/history/')
api.add_resource(GetHistory, '/get-history/')
api.add_resource(News, '/news/')
api.add_resource(Profile, '/profile/')
api.add_resource(UserProfile, '/user-profile/')
api.add_resource(UpdateProfile, '/update-profile/')
api.add_resource(PasswordReset, '/password-reset/')
###################

class checkIfAdmin(Resource):
    def get(self):
        if check_token() and check_admin():
            return jsonify({'message': 'True'})
        else:
            return jsonify({'message': 'False'})


api.add_resource(checkIfAdmin, '/check-if-admin')

if __name__ == '__main__':
    app.config['JSON_AS_ASCII'] = False
    app.run(debug=True)
