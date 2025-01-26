from flask import Flask, json, jsonify, redirect, request
from flask_sqlalchemy import SQLAlchemy
from datetime import date, datetime, timedelta
from sqlalchemy import func
from flask_cors import CORS
import logging
import bcrypt
from flask_jwt_extended import JWTManager, create_access_token, create_refresh_token, get_jwt_identity, jwt_required
import sqlite3



handler = logging.FileHandler('access.log')  # Logs to a file named 'access.log'
handler.setLevel(logging.INFO)  # Set log level to INFO
formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')  # Log format
handler.setFormatter(formatter)


# Initialize Flask app

app = Flask(__name__)

# app configs and database configuration

app.config["JWT_IDENTITY_CLAIM"] = "identity"
app.config['JWT_SECRET_KEY'] = 'strong_unique_secret_key' # JWT pw key
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = timedelta(minutes=99999)  # Access token validity - long time for dev purposes
app.config['JWT_REFRESH_TOKEN_EXPIRES'] = timedelta(days=7)     # Refresh token validity  
app.config["JWT_TOKEN_LOCATION"] = ["headers"]
app.config["JWT_COOKIE_SECURE"] = False  # or True in production
app.config["JWT_COOKIE_CSRF_PROTECT"] = False  # set to True only if you're using cookies
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///dblibrary.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

CORS(app)
jwt = JWTManager(app)
db = SQLAlchemy(app)

#logger
app.logger.addHandler(handler)  # Add the handler to Flask's logger
app.logger.setLevel(logging.INFO)  # Ensure the logger level is set to INFO

# Define Models

class User(db.Model):
    __tablename__ = 'users'

    user_id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    username = db.Column(db.String(80), nullable=False, unique=True)
    password = db.Column(db.String(255), nullable=False)
    role = db.Column(db.String(20), nullable=False)
    status = db.Column(db.Boolean, nullable=False, default=True)
    name = db.Column(db.String(100), nullable=False, default="Unknown")
    city = db.Column(db.String(100), nullable=False, default="Unknown")
    age = db.Column(db.Integer, nullable=False, default=0)

    # The 'user_loans' property is dynamically created by the Loan backref
    def __repr__(self):
        return f"User ID {self.user_id}: Username {self.username}, role {self.role}, status {'active' if self.status else 'inactive'}, name {self.name}, age {self.age}, city {self.city} "


class Book(db.Model):
    __tablename__ = 'books'

    book_id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    book_name = db.Column(db.String(200), nullable=False)
    author = db.Column(db.String(100), nullable=False)
    year_published = db.Column(db.Integer, nullable=False)
    type = db.Column(db.Integer, nullable=False)  # 1, 2, or 3 for book type
    quantity = db.Column(db.Integer, nullable=False)
    status = db.Column(db.Boolean, default=True, nullable=False)  # True for available, False for unavailable

    def __repr__(self):
        return f"|Book ID {self.book_id}, name {self.book_name}, quantity {self.quantity} - {'Available' if self.status else 'Unavailable'}|"


class Loan(db.Model):
    __tablename__ = 'loans'

    loan_id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    book_id = db.Column(db.Integer, db.ForeignKey('books.book_id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('users.user_id'), nullable=False)
    loan_date = db.Column(db.Date, nullable=False)
    return_date = db.Column(db.Date, nullable=False)
    status = db.Column(db.Boolean, nullable=False)
    is_late = db.Column(db.Boolean, default=False, nullable=False)

    # Update the backref name to avoid conflict
    user = db.relationship('User', backref='user_loans')  # Changed backref to 'user_loans'

    # Relationship to the Book model
    book = db.relationship('Book', backref='book_loans')

    def __repr__(self):
        return f"Loan ID {self.loan_id} By User ID {self.user_id}, Book {self.book_id}"


# Initialize the database (run this once)
    # db.create_all()


#system functions 


def unit_test():
    # Use this code as the entry point for testing:
    # if __name__ == '__main__':
    #     with app.app_context():
    #         db.drop_all()
    #         db.create_all()
    #         unit_test()
    #     app.run(debug=True)

    b1 = Book(book_name='The Great Gatsby', author='F. Scott Fitzgerald',
              year_published=1925, type=1, quantity=3, status=True)
    b2 = Book(book_name='1984', author='George Orwell', year_published=1949,
              type=2, quantity=5, status=False)
    b3 = Book(book_name='To Kill a Mockingbird', author='Harper Lee',
              year_published=1960, type=3, quantity=4, status=True)
    b4 = Book(book_name='Brave New World', author='Aldous Huxley',
              year_published=1932, type=1, quantity=2, status=False)
    b5 = Book(book_name='Moby Dick', author='Herman Melville',
              year_published=1851, type=2, quantity=6, status=True)
    b6 = Book(book_name='Pride and Prejudice', author='Jane Austen',
              year_published=1813, type=3, quantity=1, status=True)

    db.session.add_all([b1, b2, b3, b4, b5, b6])
    
    # password for all users is 123
    u1 = User(username='admin', password='$2b$12$/syD2KEePYTeAUCWCsuvF.oX9Sm//3LHKvoz1d/gaKRb.wSrLR93O', role='admin',
              status=True, name='John Doe', city='New York', age=30)
    u2 = User(username='librarian', password='$2b$12$vZuR5Z8hEwIMGH4agRZ5UeDChIPynxgWR.8VVzBjQPfjgcN/XkqNC', role='librarian',
              status=True, name='Jane Doe', city='Los Angeles', age=28)
    u3 = User(username='customer1', password='$2b$12$ESMXDTpCI4cs9.XZDKCAB.ajoXFQ.Ik7CPwnzW1cPwhfFEezbUMfq', role='customer',
              status=True, name='Alice Smith', city='Chicago', age=25)
    

    db.session.add_all([u1, u2, u3, u4])

    # Commit so books and users get IDs assigned
    db.session.commit()

    l1 = Loan(book_id=b1.book_id, user_id=u3.user_id,
              loan_date=date(2025, 1, 1), return_date=date(2025, 1, 10),
              status=True, is_late=False)
    l2 = Loan(book_id=b3.book_id, user_id=u4.user_id,
              loan_date=date(2025, 1, 5), return_date=date(2025, 1, 15),
              status=False, is_late=True)
    l3 = Loan(book_id=b5.book_id, user_id=u2.user_id,
              loan_date=date(2025, 1, 10), return_date=date(2025, 1, 20),
              status=True, is_late=False)
    l4 = Loan(book_id=b6.book_id, user_id=u3.user_id,
              loan_date=date(2025, 1, 3), return_date=date(2025, 1, 12),
              status=False, is_late=True)
    l5 = Loan(book_id=b2.book_id, user_id=u1.user_id,
              loan_date=date(2025, 1, 7), return_date=date(2025, 1, 17),
              status=True, is_late=False)
    l6 = Loan(book_id=b4.book_id, user_id=u3.user_id,
              loan_date=date(2025, 1, 9), return_date=date(2025, 1, 18),
              status=False, is_late=True)

    db.session.add_all([l1, l2, l3, l4, l5, l6])

    db.session.commit()




def hash_password(password):
    salt = bcrypt.gensalt()
    hashed = bcrypt.hashpw(password.encode('utf-8'), salt)
    return hashed.decode('utf-8')

from flask_jwt_extended import get_jwt

def is_admin():
    claims = get_jwt()
    if claims.get("role") == "admin":
        return True
    else:
        return False

def is_librarian():
    claims = get_jwt()
    if claims.get("role") == 'librarian':
        return True
    else:
        return False


def is_customer():
    claims = get_jwt()
    if claims.get("role") == 'customer':
        return True
    else:
        return False

BLOCKLIST = set()

@app.route("/logout", methods=["POST"])
@jwt_required()
def logout():
    # Get the token's unique identifier from the JWT
    jti = get_jwt()["jti"]
    
    # Add that jti to our blocklist set
    BLOCKLIST.add(jti)

    return redirect("/index.html")

@jwt.token_in_blocklist_loader
def check_if_token_is_revoked(jwt_header, jwt_payload):
    jti = jwt_payload["jti"]
    return jti in BLOCKLIST

@app.route("/register", methods = ["POST"])
def register():
    visitor_ip = request.remote_addr  
    app.logger.info(f"Visitor intitated registeration from IP: {visitor_ip}")
    data = request.json
    username = data.get('username')
    password = data.get('password')
    name = data.get('name')
    city = data.get('city')
    age = data.get('age')
    if not username or not password: #validate
        app.logger.warning(f"Failed registration attempt from {visitor_ip}: Missing username or password")
        return {"error": "Username and password are required"}, 400
    user = User.query.filter_by(username = username).first()
    if user:
        return {"error":"Username already exists"}
    if age < 5:
        return {"error": "Minimum user age is 5 "}
    if not name or not city or not age:
        return {"error":"name, city and age are required"}
    hashedpass = hash_password(password)
    new_user = User(username = username, 
                    password= hashedpass, 
                    role = "customer", 
                    status = True, 
                    name = name,
                    city = city,
                    age = age)
    db.session.add(new_user)
    db.session.commit()
    app.logger.info(f"{visitor_ip} registered {new_user} sucessfuly ")
    return {"sucess":f"user {new_user} created sucesfuly"}

@app.route("/login", methods=['POST'])  # login is homepage
def login():
    # Get the client's IP address
    visitor_ip = request.remote_addr  
    app.logger.info(f"Visitor connected from IP: {visitor_ip}")

    # Extract data from the request body
    data = request.get_json()  # or request.json
    username = data.get('username')
    password = data.get('password')

    # Validate input
    if not username or not password:
        app.logger.warning(
            f"Failed login attempt from {visitor_ip}: Missing username or password"
        )
        return jsonify({"error": "Username and password are required"}), 400

    # Query the user from the database
    user = User.query.filter_by(username=username).first()
    if not user:
        app.logger.warning(
            f"Failed login attempt from {visitor_ip}: User '{username}' not found"
        )
        return jsonify({"error": "Invalid username or password"}), 401

    # Check password
    if not bcrypt.checkpw(password.encode('utf-8'), user.password.encode('utf-8')):
        app.logger.warning(
            f"Failed login attempt from {visitor_ip}: Incorrect password for '{username}'"
        )
        return jsonify({"error": "Invalid username or password"}), 401

    # Verify user status before login
    if not user.status:  # e.g. user.status == False
        app.logger.warning(
            f"Failed login attempt from {visitor_ip}: Inactive user '{username}'"
        )
        return jsonify({"error": "User account is inactive. Please contact support."}), 403

    # Log successful login
    app.logger.info(
        f"Successful login: User '{username}' with role '{user.role}' from IP {visitor_ip}"
    )

    # Create JWT tokens
    access_token = create_access_token(
        identity=str(user.user_id),  # must be a string
        additional_claims={
            "username": user.username,
            "role": user.role
        }
    )

    refresh_token = create_refresh_token(
        identity=str(user.user_id),
        additional_claims={
            "username": user.username,
            "role": user.role
        }
    )

    # Return tokens as JSON
    return jsonify({
        "access_token": access_token,
        "refresh_token": refresh_token
    }), 200

@app.route('/refresh', methods=['POST'])
@jwt_required(refresh=True)
def refresh():
    current_user = get_jwt_identity()
    new_access_token = create_access_token(identity=current_user)
    return jsonify(access_token=new_access_token)
    
# Admin CRUD

@app.route("/create_librarian", methods=['POST'])
@jwt_required()
def create_librarian():
    if not is_admin():
        return  jsonify({'error': 'Unauthorized access'}), 403
    # Extract and validate input data
    data = request.json
    username = data.get("username")
    password = data.get("password")
    name = data.get("name")
    city = data.get("city")
    age = data.get("age")
    if not username or not password:
        return {"error": "Username and password are required"}, 400

     # Check if username exists
    if User.query.filter_by(username=username).first():
        return {"error": "Username already exists"}, 400
    if not name or not city or not age or age < 18: #check correct data
        return {"Error":" Must enter name, city, age (can't be younger than 18) "}
    # Hash password and create the new librarian
    hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
    new_user = User(username=username, password=hashed_password, role="librarian", name=name, city =city, age=age, status= True)
    db.session.add(new_user)
    db.session.commit()
    app.logger.info(f"{request.remote_addr} created {new_user} as librarian sucessfuly")

    return {"message": f"Librarian '{username}' created successfully"}, 201

@app.route("/create_admin", methods = ["POST"])
@jwt_required()
def create_admin():
    if not is_admin():
        return jsonify({'error': 'Unauthorized access - admins only'}), 403
  
    # Extract and validate input data
    data = request.json
    username = data.get("username")
    password = data.get("password")
    name = data.get("name")
    city = data.get("city")
    age = data.get("age")
    if not username or not password: #check data
        return {"error": "Username and password are required"}, 400
    if User.query.filter_by(username=username).first():
        return {"error": "Username already exists"}, 400 # check username is unique
    if not name or not city or not age or age < 18: #check correct data
        return {"Error":" Must enter name, city, age (can't be younger than 18) "}
    hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
    new_user = User(username=username, password=hashed_password, role="admin", name=name, city =city, age=age, status= True)
    db.session.add(new_user)
    db.session.commit()
    app.logger.info(f"{request.remote_addr} created {new_user} sucessfuly")
    return {"message": f"Admin '{username}' created as admin successfully"}, 201

@app.route("/admin_read", methods = ["GET"])
@jwt_required()
def admin_read():
    if not is_admin():
        return jsonify({'error': 'Unauthorized access - admins only'}), 403
    role_filter = request.args.get('role', 'all')
    if role_filter == 'all':
        users = User.query.all()
    else:
        users = User.query.filter_by(role=role_filter).all()
    
    users_data = [
        {
            "id": user.user_id,
            "username": user.username,
            "role": user.role,
            "status": user.status,
        }
        for user in users
    ]

    return jsonify(users_data)

@app.route("/admin_user_update", methods=["PUT"])
@jwt_required()
def admin_update():
    if not is_admin():
        return jsonify({'error': 'Unauthorized access - admins only'}), 403

    data = request.json
    user_id = data.get('user_id')  # Required field
    new_data = data.get('new_data')  # Contains fields to update

    # Validate input
    if not user_id:
        return jsonify({'error': 'User ID is required'}), 400
    if not isinstance(new_data, dict) or not new_data:
        return jsonify({'error': 'New data must be provided as a dictionary'}), 400

    allowed_fields = ['username', 'role', 'name', 'city', 'age']
    disallowed_fields = [field for field in new_data.keys() if field not in allowed_fields]
    if disallowed_fields:
        return jsonify({'error': f'Unauthorized fields in update: {disallowed_fields}'}), 400

    # Find the user by ID
    user = User.query.get(user_id)
    if not user:
        return jsonify({'error': 'User not found'}), 404

    # If new_data contains 'username', check if it already exists in the db
    new_username = new_data.get('username')
    if new_username:  
        # Check if some other user already has this username
        existing_user = User.query.filter_by(username=new_username).first()
        if existing_user and existing_user.user_id != user_id:
            return jsonify({"error": "Username already exists"}), 400
        if not new_username.strip():
            return jsonify({'error': 'Username cannot be null or empty'}), 400

    # Update fields
    for field, value in new_data.items():
        if field == 'role':
            # Validate role
            if value not in ['admin', 'customer', 'librarian']:
                return jsonify({
                    'error': f"Invalid role '{value}'. Role must be 'admin', 'customer', or 'librarian'"
                }), 400

        if field == 'age':
            # Validate age based on role
            role = new_data.get('role', user.role)  # Use updated role if provided
            if role == 'customer' and value < 5:
                return jsonify({'error': 'Age must be greater than 5 for customers'}), 400
            if role in ['admin', 'librarian'] and value < 18:
                return jsonify({'error': 'Age must be greater than 18 for admins or librarians'}), 400

        setattr(user, field, value)

    db.session.commit()
    app.logger.info(f"{request.remote_addr} updated {user} successfully")
    return jsonify({'message': 'User updated successfully'}), 200



@app.route("/admin_delete_user", methods=["DELETE"])
@jwt_required()
def admin_delete():
    if not is_admin():
        return jsonify({'error': 'Unauthorized access - admins only'}), 403 #block non admins
    data = request.get_json()
    if not data or 'user_id' not in data:
        return jsonify({'error': 'User ID is required'}), 400 #validate user id data
    user_id = data['user_id']
    user = User.query.get(user_id)
    if not user: # validate user id in db
        return jsonify({'error': 'User not found'}), 404 
    
    if user.status == True:
        user.status = False #deactivate user
        db.session.commit()
        app.logger.info(f"{request.remote_addr} deactivated {user} sucessfuly")
        return jsonify({'message': f'User ID{user_id}, {user.username}  status has been deactivated.'}), 200
    elif user.status == False:
        user.status = True #reactivate user
        db.session.commit()
        app.logger.info(f"{request.remote_addr} reactivated {user} sucessfuly")
        return jsonify({'message': f'User ID{user_id}, {user.username} status has been reactivated.'}), 200


#Librarian section

#Users CRUD - done
@app.route("/librarian_create_user", methods=["POST"])
@jwt_required()
def create_user():
    if not is_librarian():
        return {"Error":"Librarians only"}
    # Extract and validate input data
    data = request.json
    username = data.get("username")
    password = data.get("password")
    name = data.get("name")
    city = data.get("city")
    age = data.get("age")
    if not username or not password:
        return {"error": "Username and password are required"}, 400

     # Check if username exists
    if User.query.filter_by(username=username).first():
        return {"error": "Username already exists"}, 400
    if not name or not city or not age or age < 5: #check correct data
        return {"Error":" Must enter name, city, age (can't be younger than 5) "}

    # Hash password and create the new customer
    hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
    new_user = User(username=username, password=hashed_password, role="customer", name=name, city =city, age=age, status= True)
    db.session.add(new_user)
    db.session.commit()
    app.logger.info(f"{request.remote_addr} created {new_user} as user sucessfuly")
    return {"message": f"User '{username}' created successfully"}, 201

@app.route("/librarian_read_user", methods=["GET"])
@jwt_required()
def librarian_read():
    if not is_librarian(): #limit to librarians only
        return {"Error":"Librarians only " }
    
    users = User.query.filter_by(role="customer").all() #view only customers 
    result = []
    for user in users:
        result.append({
            'id': user.user_id,
            'username': user.username,
            'role': user.role,
            'status': user.status,
            "name": user.name,
            "city": user.city,
            "age": user.age
        })

    return jsonify(result), 200


@app.route('/customers/search', methods=['GET'])
@jwt_required()
def search_customer_by_name():
    if not is_librarian():
        return {"Error":"Librarians only " }
    customer_name = request.args.get('name', '').strip()

    if not customer_name:
        return jsonify({"error": "Customer name is required"}), 400

    # Perform a case-insensitive search in the database
    customers = User.query.filter(User.name.ilike(f"%{customer_name}%")).all()

    # Prepare the result
    results = []
    for customer in customers:
        results.append({
            "user_id": customer.user_id,
            "username": customer.username,
            "name": customer.name,
            "city": customer.city,
            "age": customer.age,
            "status": customer.status,
        })

    return jsonify(results), 200

    
@app.route("/librarian_update_user", methods=["PUT"])
@jwt_required()
def librarian_update():
    if not is_librarian():
        return {"Error": "Librarians only"}, 403

    # Parse JSON payload
    data = request.json
    user_id = data.get('user_id')  # Required field
    new_data = data.get('new_data')  # Contains fields to update

    # Validate input
    if not user_id:
        return jsonify({'error': 'User ID is required'}), 400
    if not isinstance(new_data, dict) or not new_data:
        return jsonify({'error': 'New data must be provided as a dictionary'}), 400

    # Check for disallowed fields
    allowed_fields = ['username', 'name', 'city', 'age']
    disallowed_fields = [field for field in new_data.keys() if field not in allowed_fields]
    if disallowed_fields:
        return jsonify({'error': f'Unauthorized fields in update: {disallowed_fields}'}), 400

    # Find the user by ID
    user = User.query.get(user_id)
    if not user:
        return jsonify({'error': 'User not found'}), 404
    if user.role != "customer":
        return {"Error": "Can only update customers"}, 403

    # Validate fields in new_data
    for field, value in new_data.items():
        if not value or (isinstance(value, str) and value.strip() == ''):
            return jsonify({'error': f'Field "{field}" cannot be null, empty, or blank'}), 400

        if field == 'age':
            # Validate that age is an integer
            if not isinstance(value, int):
                return jsonify({'error': f'Field age must be an integer. Received: {type(value).__name__}'}), 400
            if value < 5:
                return jsonify({'error': 'Age must be greater than 5 for customers'}), 400

        if field == 'city' or field == 'name':
            # Validate that city is a string
            if not isinstance(value, str):
                return jsonify({'error': f'Field {field} must be a string. Received: {type(value).__name__}'}), 400

        # Update the user field
        setattr(user, field, value)

    db.session.commit()
    app.logger.info(f"{request.remote_addr} updated {user} successfully")
    return jsonify({'message': f'User {new_data} updated successfully'}), 200

@app.route("/librarian_delete_user", methods = ["DELETE"])
@jwt_required()
def librarian_delete():
    if not is_librarian():
        return {"Error": "Librarians only"}, 403
    data = request.get_json()
    if not data or 'user_id' not in data:
        return jsonify({'error': 'User ID is required'}), 400 #validate user id data
    user_id = data['user_id']
    user = User.query.get(user_id)
    if not user: # validate user id in db
        return jsonify({'error': 'User not found'}), 404 
    if user.role != "customer":
        return {"Error": "Can only update customers"}, 403

    if user.status == True:
        user.status = False #deactivate user
        db.session.commit()
        app.logger.info(f"{request.remote_addr} deactivated {user} sucessfuly")
        return jsonify({'message': f'User ID{user_id}, username {user.username}  status has been deactivated.'}), 200
    elif user.status == False:
        user.status = True #reactivate user
        db.session.commit()
        app.logger.info(f"{request.remote_addr} reactivated {user} sucessfuly")
        return jsonify({'message': f'User ID{user_id}, username {user.username} has been reactivated.'}), 200


# Books CRUD - done

# Create book
@app.route("/create_book", methods =["POST"])
@jwt_required()
def create_book():
    if not is_librarian():
        return {"Error": "Librarians only"}, 403
    #extract and validate data
    data = request.json
    name = data.get("book_name")
    author = data.get("author")
    year = data.get("year_published")
    type = data.get("type")
    quantity = data.get("quantity")
    if not name or not author or not quantity: #check all data
        return {"error": "Data required: Book name, author, year published, type, and quantity"}, 400
    if quantity < 0: #check positive quantity
        return {"error":"Must have positive or 0 quantity"}
    if type < 1 or type > 3:
        return {"error":"type must be 1, 2, or 3"}
    current_year = datetime.now().year #get current year
    if int(year) > int(current_year) or int(year) < 1000: #check year is correct
        return {"error": "invalid publishing year"}, 400

    existing_book = Book.query.filter_by(book_name=name, author=author).first() #check if this book already exists
    if existing_book:
        return {"error": "A book with the same name, and author already exists"}, 400

    # Create and commit
    new_book = Book(book_name = name, author = author, year_published = year, type = type, quantity = quantity, status = True)
    db.session.add(new_book)
    db.session.commit()
    app.logger.info(f"{request.remote_addr} created {new_book} sucessfuly")
    return {"message": f"Book '{new_book}' created successfully"}, 201

# Read books

@app.route("/librarian_read_books", methods=["GET"])
@jwt_required()
def librarian_read_books():
    if not is_librarian():
        return {"error": "Librarians only"}, 403
    
    # Use query parameters for filtering
    filter_param = request.args.get("filter", type=int, default=3)  # Defaults to all (3) if not provided

    # Validate the filter parameter
    if filter_param not in [1, 2, 3]:
        return {"error": "Invalid filter. Use 1 (inactive), 2 (active), or 3 (all)"}, 400

    # Query based on the filter parameter
    if filter_param == 1:
        books = Book.query.filter_by(status=0).all()  # Inactive books
    elif filter_param == 2:
        books = Book.query.filter_by(status=1).all()  # Active books
    else:
        books = Book.query.all()  # All books

    # Serialize the books into a list of dictionaries
    serialized_books = [
        {
            "book_id": book.book_id,
            "book_name": book.book_name,
            "author": book.author,
            "year_published": book.year_published,
            "type": book.type,
            "quantity": book.quantity,
            "status": book.status
        }
        for book in books
    ]

    return jsonify(serialized_books), 200

# Update books

@app.route("/update_book", methods = ["PUT"])
@jwt_required()
def update_book():
    if not is_librarian():
        return {"error": "Librarians only"}, 403
    data = request.json
    book_id = data.get('book_id') #required
    new_data = data.get('new_data') #new data is in a dictionary insdie the json {"book_id":123, "new_data":{new data section}}
    book = Book.query.get(book_id)
    #validation
    if not book_id:
        return jsonify({'error': 'Book ID is required'}), 400
    if not isinstance(new_data, dict) or not new_data:
            return jsonify({'error': 'New data must be provided as a dictionary'}), 400
    
    allowed_fields = ['book_name', 'author', 'year_published', 'quantity', "type"] #check allowed fields
    disallowed_fields = [field for field in new_data.keys() if field not in allowed_fields]
    if disallowed_fields:
        return jsonify({'error': f'Unauthorized fields in update: {disallowed_fields}'}), 400

    for field, value in new_data.items():
        if not value or (isinstance(value, str) and value.strip() == ''):
            return jsonify({'error': f'Field "{field}" cannot be null, empty, or blank'}), 400

        if field == "type":
            if value > 3 or value <1:
                return {"error":"Type must be 1, 2, or 3"}

        if field == 'year_published':
            # Validate that year is an integer in determined range (1000+)
            if not isinstance(value, int):
                return jsonify({'error': f'Field year published must be an integer. Received: {type(value).__name__}'}), 400
            if value < 1000:
                return jsonify({'error': 'Year must be 1000+'}), 400
        # Update the book field
        setattr(book, field, value)

    db.session.commit() #commit
    app.logger.info(f"{request.remote_addr} updated {book} successfully")
    return jsonify({'message': f'Book {new_data} updated successfully'}), 200 

# Delete books    

@app.route("/delete_book", methods = ["DELETE"])
@jwt_required()
def delete_book():
    if not is_librarian():
        return {"error": "Librarians only"}, 403
    data = request.get_json()
    if not data or 'book_id' not in data:
        return {'error': 'User ID is required'}, 400 #validate book id and data
    book_id = data['book_id']
    book = Book.query.get(book_id)
    if not book:
        return {'error': 'Book not found'}, 404
    if book.status == True:
        book.status = False # deactivate book
        db.session.commit() 
        app.logger.info(f"{request.remote_addr} deactivated {book} sucessfuly")
        return {"message":f'Book {book} deactivated sucessfully'}
    elif book.status == False:
        book.status = True #reactivate book
        db.session.commit()
        app.logger.info(f"{request.remote_addr} reactivated {book} sucessfuly")
        return {"message":f'Book {book} reactivated sucessfully'}
        
# Loans CRUD
 
 # Create new load - done
@app.route("/create_loan", methods = ["PUT"])        
@jwt_required()
def new_loan():
    if not is_librarian():
        return {"error": "Librarians only"}, 403
    data = request.json
    book_id = data.get("book_id")
    user_id = data.get("user_id")
    if not book_id or not user_id: #verify data
        return {"error":"missing book id or user id"}, 400
    book = Book.query.get(book_id)
    if not book: #verify book id
        return {"error": "Book not found"}, 404
    user = User.query.get(user_id)
    if not user: #verify user
        return {"error": "User not found"}, 404

    loan_date = datetime.today() #time stamp for loan creation
    #generate return date based on type
    if book.type == 1:
        return_date = loan_date + timedelta(days=10)
    elif book.type == 2:
        return_date = loan_date + timedelta(days=5)
    elif book.type == 3:
        return_date = loan_date + timedelta(days=2)
    else:
        return {"error": "Invalid book type"}, 400   

    #commit new book
    new_loan = Loan(book_id = book_id, user_id = user_id, loan_date =loan_date, return_date = return_date, status = True)
    db.session.add(new_loan)
    db.session.commit()
    app.logger.info(f"{request.remote_addr} created {new_loan} sucessfuly")
    return {"message": f"Loan '{new_loan}' created successfully"}, 201

# read all loans (and update if late loan) - done

@app.route("/librarian_read_loans", methods=["GET"])
@jwt_required()
def read_loans():
    if not is_librarian():
        return {"error": "Librarians only"}, 403
    result = []
    loans = Loan.query.all()
    if not loans:
        return {"error":"No loans found"}, 404 
    for loan in loans:
          # Check if the loan status is True and the return_date has passed
        if loan.status and loan.return_date < datetime.now().date():
            # Update is_late in the database
            loan.is_late = True
            db.session.commit()
        result.append({
            'loan_id': loan.loan_id,
            'book_id': loan.book_id,
            'user_id': loan.user_id,
            'loan_date': loan.loan_date,
            'return_date': loan.return_date,
            'status': loan.status,
            'is_late': loan.is_late
        })
    return result

# only late loans
@app.route('/loans/late', methods=['GET'])
@jwt_required()
def get_late_loans_route():
    if not is_librarian():
        return {"error": "Librarians only"}, 403
    read_loans() #this marks late loans automatically
    late_loans = Loan.query.filter(Loan.is_late == 1).all()
    
    results = []
    for loan in late_loans:
        results.append({
            "loan_id": loan.loan_id,
            "book_id": loan.book_id,
            "user_id": loan.user_id,
            "loan_date": loan.loan_date.isoformat() if loan.loan_date else None,
            "return_date": loan.return_date.isoformat() if loan.return_date else None,
            "status": loan.status,
            "is_late": loan.is_late,
        })

    return jsonify(results), 200

#find book by name
@app.route('/books/search', methods=['GET'])
def search_book_by_name():
    book_name = request.args.get('name', '').strip()

    if not book_name:
        return jsonify({"error": "Book name is required"}), 400

    # Perform a case-insensitive search in the database
    books = Book.query.filter(Book.book_name.ilike(f"%{book_name}%")).all()
    print(books)
    # Prepare the result
    results = []
    for book in books:
        results.append({
            "book_id": book.book_id,
            "book_name": book.book_name,
            "author": book.author,
            "year_published": book.year_published,
            "type": book.type,
            "quantity": book.quantity,
            "status": book.status,
        })
    print(results)
    return jsonify(results), 200

# Upate a loan - done

@app.route("/update_loan", methods=["PUT"])
@jwt_required()
def update_loan():
    if not is_librarian():
        return {"error": "Librarians only"}, 403

    data = request.get_json()
    if not data:
        return {"error": "No data provided"}, 400

    loan_id = data.get('loan_id')
    new_data = data.get('new_data')

    # Validate required fields
    if not loan_id:
        return {"error": "Loan ID is required"}, 400
    if not new_data:
        return {"error": "New data is required"}, 400

    # Fetch the loan record
    loan = Loan.query.get(loan_id)
    if not loan:
        return {"error": "Loan ID not found"}, 404

    # If book_id is in the request, validate it
    book_id = new_data.get('book_id')
    if book_id:
        book = Book.query.get(book_id)
        if not book:
            return {"error": "Book not found"}, 404
    
    user_id = new_data.get('user_id')
    if user_id:
        user = User.query.get(user_id)
        if not user:
            return {"error":"user not found"}

    # Define allowed fields for dynamic update
    allowed_fields = ['book_id', 'loan_date', 'return_date', 'user_id']
    disallowed_fields = [field for field in new_data.keys() if field not in allowed_fields]
    if disallowed_fields:
        return jsonify({'error': f'Unauthorized fields in update: {disallowed_fields}'}), 400

    # Update fields dynamically
    for field, value in new_data.items():
        if field in allowed_fields:
            if field in ['loan_date', 'return_date'] and isinstance(value, str):
                # Convert string to Python date object
                try:
                    value = datetime.strptime(value, "%Y-%m-%d").date()
                except ValueError:
                    return {"error": f"Invalid date format for {field}. Use YYYY-MM-DD."}, 400
            setattr(loan, field, value)

    # Commit the changes to the database
    db.session.commit()

    # Log the update action
    app.logger.info(f"{request.remote_addr} updated loan {loan_id} successfully")

    return jsonify({'message': 'Loan updated successfully'}), 200


# close loan 

@app.route("/close_loan", methods = ["DELETE"])
@jwt_required()
def close_loan():
    if not is_librarian():
        return {"error": "Librarians only"}, 403
    data = request.get_json()
    if not data or 'loan_id' not in data: #validate data
        return{"error":"Loan ID is required"}, 400
    loan_id = data['loan_id']
    loan = Loan.query.get(loan_id)
    print(loan.status)
    if not loan: #validate loan id
        return {"error":"loan not found"}
    if loan.status == True:
        loan.status = False #deactivate
        db.session.commit()
        app.logger.info(f"{request.remote_addr} deactivated {loan} sucessfuly")
        return jsonify({'message': f'loan ID{loan_id} status has been deactivated.'}), 200
    if loan.status == False:
        loan.status = True #reactivate 
        db.session.commit()
        app.logger.info(f"{request.remote_addr} reactivated {loan} sucessfuly")
        return jsonify({'message': f'User ID{loan_id} status has been reactivated.'}), 200

# Users section - read books and loans

@app.route("/user_read_books", methods =["GET"])
@jwt_required()
def user_read():
    if not is_customer():
        return {"error": "Customers only"}, 403
    books = Book.query.filter_by(status=1).all()  # filter only active books
    serialized_books = [
        {
            "book_id": book.book_id,
            "book_name": book.book_name,
            "author": book.author,
            "year_published": book.year_published,
            "type": book.type,
            "quantity": book.quantity
        }
        for book in books
    ]

    return jsonify(serialized_books), 200

#read loans 

@app.route("/user_read_loans", methods=["GET"])
@jwt_required()
def read_self_loans():
    if not is_customer():
        return {"error": "Customers only"}, 403
    
    # Directly get the user_id
    user_id = get_jwt_identity()
    
    loans = Loan.query.filter_by(user_id=user_id).all()  # filter only current user's loans
    
    if not loans:
        return {"error": "No loans found"}, 404
    
    for loan in loans:
        # Check if the loan status is True and the return_date has passed
        if loan.status and loan.return_date < datetime.now().date():
            # Update is_late in the database
            loan.is_late = True
            db.session.commit()
    
    serialized_loans = [
        {
            "loan_id": loan.loan_id,
            "book_ID": loan.book_id,
            "loan_date": loan.loan_date,
            "return_date": loan.return_date,
            "status": loan.status,
            "is_late": loan.is_late
        }
        for loan in loans
    ]
    return jsonify(serialized_loans), 200

    



# entry point 
if __name__ == '__main__':
    # with app.app_context():
    #     db.drop_all()
    #     db.create_all()
    #     unit_test()
    app.run(debug=True)    
