from flask import Flask, request, jsonify, make_response, render_template, session
import jwt
from datetime import datetime, timedelta
from functools import wraps

app = Flask(__name__)
app.config['SECRET_KEY'] = 'ff8f8adb8dc3428cb7299a952d711009'


def token_required(func):
    @wraps(func)
    def decorated(*args, **kwargs):
        token = request.cookies.get('session')  # Retrieve the token from the cookie

        if not token:
            return jsonify({'message': 'Token is missing!'}), 403
        print(token)

        try:
            data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=["HS256"])
        except jwt.ExpiredSignatureError:
            return jsonify({'message': 'Token has expired!'}), 403
        except jwt.InvalidTokenError:
            return jsonify({'message': 'Token is invalid!'}), 403

        return func(*args, **kwargs)

    return decorated




@app.route('/public')
def public():
    return 'Public Content'

@app.route('/auth')
@token_required
def auth():
    return 'JWT Authorized'

@app.route('/')
def home():
    token = request.cookies.get('session')  # Retrieve the token from the cookie

    if not token:
        return render_template('login.html')  # If no token, show the login page

    try:
        # Decode the token to verify if it's valid
        data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=["HS256"])
    except jwt.ExpiredSignatureError:
        return render_template('login.html', message="Session expired. Please log in again.")  # Token expired
    except jwt.InvalidTokenError:
        return render_template('login.html', message="Invalid session. Please log in again.")  # Invalid token

    # If token is valid, render a logged-in message or redirect to a dashboard
    return f"Logged in as {data['user']}"


@app.route('/login', methods=['POST'])
def login():
    if request.form['username'] and request.form['password'] == '123456':
        # Generate the JWT token
        token = jwt.encode({
            'user': request.form['username'],
            'exp': datetime.utcnow() + timedelta(minutes=30)  # Token expires in 30 mins
        }, app.config['SECRET_KEY'], algorithm="HS256")

        # Set the JWT token as a cookie
        response = make_response(jsonify({'message': 'Logged in successfully'}), 200)
        response.set_cookie('session', token, httponly=True)  # Store the token in a cookie

        return response
    else:
        return make_response('Could not verify!', 403, {'WWW-Authenticate': 'Basic realm="Authentication Failed!"'})


if __name__ == '__main__':
    app.run(debug=True)