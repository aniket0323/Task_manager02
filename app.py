from flask import Flask, render_template, redirect, url_for, session
from flask_sqlalchemy import SQLAlchemy
from flask_jwt_extended import JWTManager
from flask import Flask, render_template, request, redirect, url_for
from flask import Flask, jsonify, request
from flask_jwt_extended import JWTManager, jwt_required, create_access_token, get_jwt_identity
from extensions import db,jwt
from auth import auth_bp
from users import user_bp
from models import User, TokenBlockList
from flask_sqlalchemy import SQLAlchemy
from auth import auth_bp
from users import user_bp
from models import User



app = Flask(__name__, template_folder='templates')
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite://///users.db"
# app.config["SECRET_KEY"] = "your_secret_key_here"  # Add your secret key here
app.config["JWT_SECRET_KEY"] = "1caccd4f5eb59e4a9706ad2c"  # Add your JWT secret key here


db = SQLAlchemy()
db.init_app(app)

jwt = JWTManager()
jwt.init_app(app)

# Register blueprints

app.register_blueprint(auth_bp)
app.register_blueprint(user_bp, url_prefix='/users')

# Redirect to login page before accessing any route
@app.before_request
def require_login():
    allowed_routes = ['login']  # Define allowed routes which don't require login
    if request.endpoint not in allowed_routes and 'username' not in session:
        return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()
        print("1")
        if user and user.check_password(password):
            print("2")
            session['username'] = username
            return redirect(url_for('index'))
        return render_template('login.html', error='Invalid username or password')
    print("3")
    return render_template('login.html')

@app.route('/')
def index():
    if 'username' in session:
        return render_template('index.html', username=session['username'])
    return redirect(url_for('login'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        email = request.form['email']
        if User.query.filter_by(username=username).first():
            return render_template('register.html', error='Username already exists')
        new_user = User(username=username, email=email)
        new_user.set_password(password)
        db.session.add(new_user)
        db.session.commit()
        session['username'] = username
        return redirect(url_for('index'))
    return render_template('register.html')

@app.route('/logout')
def logout():
    session.pop('username', None)
    return redirect(url_for('login'))

if __name__ == '__main__':
    app.run(debug=True)

# db = SQLAlchemy()
# db.init_app(app)

# jwt = JWTManager()
# jwt.init_app(app)

# app.register_blueprint(auth_bp, url_prefix='/')
# app.register_blueprint(user_bp, url_prefix='/users')

# # Redirect to login page before accessing any route
# @app.before_request
# def require_login():
#     allowed_routes = ['login', 'register']  # Define allowed routes which don't require login
#     if request.endpoint not in allowed_routes and 'user_id' not in session:
#         return redirect(url_for('auth.login_user'))

# # Define your routes here
# @app.route('/')
# def index():
#     return render_template('index.html')

# @app.route('/login')
# def login():
#     return render_template('login.html')

# @app.route('/register')
# def register():
#     return render_template('register.html')

# # Add other routes as needed

# if __name__ == '__main__':
#     app.run(debug=True)






# # def create_app():

# db = SQLAlchemy() # db intitialized here

# app = Flask(__name__, template_folder='templates')
# app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite://///test.db"
# db.init_app(app)
# jwt.init_app(app)


# app.register_blueprint(auth_bp,url_prefix='/auth')
# app.register_blueprint(user_bp, url_prefix='/users')

# @jwt.user_lookup_loader
# def user_lookup_callback(__jwt_headers, jwt_data):
#     identity = jwt_data['sub']
    
#     return User.query.filter_by(username = identity).one_or_none()

# @jwt.additional_claims_loader
# def make_additional_claims(identity):
#     if identity =="aniket123":
#         return {"is_staff":True}
#     return {"is_staff": False}

# @jwt.expired_token_loader
# def expired_token_callback(jwt_header, jwt_data):
#     return jsonify({"message":"Token has expired", "error":"token_expired"}),401
# @jwt.invalid_token_loader
# def invalid_token_callback(error):
#     return jsonify({"message":"Signature verification failed", "error":"invalid_token"}),401

# @jwt.unauthorized_loader
# def missing_token_callback(error):
#     return jsonify({"message":"Request doesn't contain valid token", "error":"authorisation_header"}),401


# @jwt.token_in_blocklist_loader
# def token_in_block_list_callback(jwt_header, jwt_data):
#     jti = jwt_data['jti']
    
#     token = db.session.query(TokenBlockList).filter(TokenBlockList.jti == jti).scalar()
#     return token is not None
    




# todos= []

# @app.route('/')
# def index():
#     return render_template('index.html', todos=todos)

# @app.route('/add', methods=['POST'])
# def add():
#     todo = request.form['todo']
#     todos.append({'task': todo, 'done': False})
#     return redirect(url_for('index'))

# @app.route('/edit/<int:index>', methods=['GET', 'POST'])
# def edit(index):
#     todo = todos[index]
#     if request.method == 'POST':
#         todo['task'] = request.form['todo']
#         return redirect(url_for('index'))
#     else:
#         return render_template('edit.html', todo=todo, index=index)

# @app.route('/check/<int:index>')
# def check(index):
#     todos[index]['done'] = not todos[index]['done']
#     return redirect(url_for('index'))

# @app.route('/delete/<int:index>')
# def delete(index):
#     del todos[index]
#     return redirect(url_for('index'))

# if __name__ == '__main__':
#     app.run(debug=True)




# # # Setup the Flask-JWT-Extended extension
# # app.config['JWT_SECRET_KEY'] = secrets.token_urlsafe(32)
# # jwt = JWTManager(app)

# # # Dummy user database for demonstration
# # users = {
# #     'john': 'password123',
# #     'jane': 'password456'
# # }

# # todos = []
# # # Login route
# # @app.route('/login', methods=['POST'])
# # def login():
# #     username = request.json.get('username', None)
# #     password = request.json.get('password', None)

# #     if not username or not password:
# #         return jsonify({"msg": "Missing username or password"}), 400

# #     if username not in users or users[username] != password:
# #         return jsonify({"msg": "Invalid username or password"}), 401

# #     # Identity can be any data that is json serializable
# #     access_token = create_access_token(identity=username)
# #     return jsonify(access_token=access_token), 200

# # # Protected route example
# # @app.route('/protected', methods=['GET'])
# # @jwt_required()
# # def protected():
# #     # Access the identity of the current user with get_jwt_identity
# #     current_user = get_jwt_identity()
# #     return jsonify(logged_in_as=current_user), 200
