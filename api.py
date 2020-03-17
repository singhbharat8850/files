from flask import Flask, request, jsonify, make_response
from flask_sqlalchemy import SQLAlchemy
import uuid
from werkzeug.security import generate_password_hash, check_password_hash
import jwt
import datetime
from functools import wraps
import whois
from flask_login import logout_user


app = Flask(__name__)

app.config['SECRET_KEY'] = 'thisissecret'

db = SQLAlchemy(app)

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True)
    email = db.Column(db.String(50), nullable=False, unique=True)
    password = db.Column(db.String(80))

def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None

        if 'x-access-token' in request.headers:
            token = request.headers['x-access-token']

        if not token:
            return jsonify({'message' : 'Token is missing!'}), 401

        try: 
            data = jwt.decode(token, app.config['SECRET_KEY'])
            current_user = User.query.filter_by(username=data['username']).first()
        except:
            return jsonify({'message' : 'Token is invalid!'}), 401

        return f(current_user, *args, **kwargs)

    return decorated


@app.route('/user/<username>', methods=['GET'])
@token_required
def get_one_user(current_user, username):

    user = User.query.filter_by(username=username).first()

    if not user:
        return jsonify({'message' : 'No user found!'})

    user_data = {}
    user_data['username'] = user.username
    user_data['email'] = user.email
    user_data['password'] = user.password

    return jsonify({'user' : user_data})

@app.route('/user', methods=['POST'])
@token_required
def register(current_user):
    
    data = request.get_json()

    hashed_password = generate_password_hash(data['password'], method='sha256')

    new_user = User(username=str(uuid.uuid4()), email=data['email'], password=hashed_password)
    db.session.add(new_user)
    db.session.commit()

    return jsonify({'message' : 'You are registered successfully'})

@app.route('/user/<username>', methods=['DELETE'])
@token_required
def delete_user(current_user, username):

    user = User.query.filter_by(username=username).first()

    if not user:
        return jsonify({'message' : 'No user found!'})

    db.session.delete(user)
    db.session.commit()

    return jsonify({'message' : 'The user has been deleted!'})

@app.route('/login')
def login():
    auth = request.authorization

    if not auth or not auth.username or not auth.password:
        return make_response('Could not verify', 401, {'WWW-Authenticate' : 'Basic realm="Login required!"'})

    user = User.query.filter_by(name=auth.username).first()

    if not user:
        return make_response('Could not verify', 401, {'WWW-Authenticate' : 'Basic realm="Login required!"'})

    if check_password_hash(user.password, auth.password):
        token = jwt.encode({'username' : user.username, 'exp' : datetime.datetime.utcnow() + datetime.timedelta(minutes=30)}, app.config['SECRET_KEY'])

        return jsonify({'token' : token.decode('UTF-8')})

    return make_response('Could not verify', 401, {'WWW-Authenticate' : 'Basic realm="Login required!"'})

@app.route('/whois')
def whois():
    count=0
    if count>1
        token.expire()
    token = jwt.encode({'username' : user.username, 'exp' : datetime.datetime.utcnow() + datetime.timedelta(minutes=30)}, app.config['SECRET_KEY'])
    return jsonify({'token' : token.decode('UTF-8')})
    count++

@app.route('/logout')
def logout():
    token = jwt.encode({'username' : user.username, 'exp' : datetime.datetime.utcnow() + datetime.timedelta(minutes=30)}, app.config['SECRET_KEY'])
    logout_user()
    return jsonify({'token' : token.decode('UTF-8')})
    token.expire()

if __name__ == '__main__':
    app.run(debug=True)
