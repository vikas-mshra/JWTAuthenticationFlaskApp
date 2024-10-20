# JWT Authentication Flask Application

This Flask application implements a **JWT-based authentication system**. It utilizes **JSON Web Tokens (JWT)** for session management, replacing Flask's built-in session mechanism. This guide explains the key components of the app, how authentication is handled, and how JWT tokens are used to manage user sessions.

## Table of Contents

1. [Introduction to JWT](#introduction-to-jwt)
2. [Understanding the Application](#understanding-the-application)
   - [JWT Token Generation](#jwt-token-generation)
   - [Token Storage in Cookies](#token-storage-in-cookies)
   - [Token Verification](#token-verification)
3. [Detailed Code Explanation](#detailed-code-explanation)
   - [`token_required` Decorator](#token_required-decorator)
   - [Routes](#routes)
     - `/login`
     - `/auth`
     - `/public`
     - `/home`
4. [How the Application Works](#how-the-application-works)
5. [How to Run the Application](#how-to-run-the-application)
6. [Security Considerations](#security-considerations)

---

## Introduction to JWT

**JWT (JSON Web Tokens)** is a secure, compact, URL-safe way of representing claims to be transferred between two parties. It is commonly used for **stateless authentication** in web applications, where the server does not store session data. Instead, it encodes session data into a signed token that is sent to the client.

A JWT token consists of three parts:
1. **Header**: Contains metadata about the token, including the algorithm used to sign the token (e.g., HS256).
2. **Payload**: Contains the claims, typically user data or session information.
3. **Signature**: A hash of the header and payload, generated using the server’s secret key, ensuring the token's integrity.

---

## Understanding the Application

This application uses JWT tokens to manage user authentication. Here's how it works:

1. **User logs in**: The user submits their username and password via a login form.
2. **Token generation**: Upon successful login, the server generates a JWT token that contains the user's username and an expiration timestamp.
3. **Token storage**: The token is sent back to the client and stored in a **cookie**. The cookie is marked as **HttpOnly** to prevent client-side JavaScript from accessing it.
4. **Token verification**: On subsequent requests, the client sends the token via cookies, and the server verifies the token to authenticate the user.

### JWT Token Generation

When a user successfully logs in, a JWT token is generated using the `jwt.encode()` function:

```python
token = jwt.encode({
    'user': request.form['username'],
    'exp': datetime.utcnow() + timedelta(minutes=30)  # Token expires in 30 mins
}, app.config['SECRET_KEY'], algorithm="HS256")
```

- The token includes the user's username and an expiration time (30 minutes from the current time).
- The token is signed using the **HS256** algorithm and a secret key defined in the application configuration.

### Token Storage in Cookies

After generating the token, it is stored in a cookie that is sent back to the client:

```python
response.set_cookie('session', token, httponly=True)
```

- The cookie is named `session` and stores the JWT token.
- The `HttpOnly` flag ensures that the cookie cannot be accessed via JavaScript, preventing XSS (Cross-Site Scripting) attacks.

### Token Verification

For routes that require authentication, the server retrieves the token from the cookie, decodes it, and verifies its validity:

```python
token = request.cookies.get('session')  # Retrieve the token from the cookie
data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=["HS256"])
```

- The token is decoded using the same secret key and algorithm.
- If the token is valid, the server grants access to the protected resources.

---

## Detailed Code Explanation

### `token_required` Decorator

The `token_required` decorator is used to protect routes that require authentication. It ensures that a valid JWT token is present and decodes it to authenticate the user:

```python
def token_required(func):
    @wraps(func)
    def decorated(*args, **kwargs):
        token = request.cookies.get('session')  # Retrieve the token from the cookie

        if not token:
            return jsonify({'message': 'Token is missing!'}), 403

        try:
            data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=["HS256"])
        except jwt.ExpiredSignatureError:
            return jsonify({'message': 'Token has expired!'}), 403
        except jwt.InvalidTokenError:
            return jsonify({'message': 'Token is invalid!'}), 403

        return func(*args, **kwargs)

    return decorated
```

- The token is extracted from the `session` cookie.
- The token is decoded and validated using `jwt.decode()`.
- If the token is missing, expired, or invalid, an appropriate error message is returned.

---

### Routes

#### `/login` Route

This route handles user login. It validates the username and password, generates a JWT token upon successful login, and stores it in the user's browser via a cookie:

```python
@app.route('/login', methods=['POST'])
def login():
    if request.form['username'] and request.form['password'] == '123456':
        token = jwt.encode({
            'user': request.form['username'],
            'exp': datetime.utcnow() + timedelta(minutes=30)
        }, app.config['SECRET_KEY'], algorithm="HS256")

        response = make_response(jsonify({'message': 'Logged in successfully'}), 200)
        response.set_cookie('session', token, httponly=True)  # Store the token in a cookie
        return response
    else:
        return make_response('Could not verify!', 403, {'WWW-Authenticate': 'Basic realm="Authentication Failed!"'})
```

- It checks the user credentials (`username` and `password`).
- Upon successful login, a JWT token is generated and stored in the `session` cookie.

#### `/auth` Route

This is a protected route that requires authentication via the `token_required` decorator:

```python
@app.route('/auth')
@token_required
def auth():
    return 'JWT Authorized'
```

- If the token is valid, the user is authorized to access this route.
- Otherwise, an error message will be returned.

#### `/public` Route

This is a public route that doesn't require authentication:

```python
@app.route('/public')
def public():
    return 'Public Content'
```

- Any user, regardless of authentication, can access this route.

#### `/home` Route

This route checks if the user has a valid token and is logged in. If the token is invalid or missing, the user is redirected to the login page:

```python
@app.route('/')
def home():
    token = request.cookies.get('session')  # Retrieve the token from the cookie

    if not token:
        return render_template('login.html')

    try:
        data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=["HS256"])
    except jwt.ExpiredSignatureError:
        return render_template('login.html', message="Session expired. Please log in again.")
    except jwt.InvalidTokenError:
        return render_template('login.html', message="Invalid session. Please log in again.")

    return f"Logged in as {data['user']}"
```

- If a valid token is present, the user is authenticated, and a welcome message is shown.
- If the token is invalid or expired, the user is redirected to the login page.

---

## How the Application Works

1. **Login**:
   - The user sends a POST request to `/login` with their credentials.
   - If the credentials are correct, a JWT token is generated and stored in the user's cookies.

2. **Accessing Protected Routes**:
   - On subsequent requests, the token is sent back to the server in the cookie.
   - The `token_required` decorator ensures that protected routes like `/auth` can only be accessed by users with a valid JWT token.

3. **Session Management**:
   - Instead of using Flask's session management, the JWT token is used to manage the user's session.
   - The token contains user information and an expiration time. It is stored securely in a cookie.

---

## How to Run the Application

### Prerequisites

- Install Python 3.x
- Install the required dependencies:

```bash
pip install Flask PyJWT
```

### Running the Application

1. Save the script to a file, for example, `app.py`.
2. Run the Flask application:

```bash
python app.py
```

3. The application will be available at `http://127.0.0.1:5000/`.

---

## Security Considerations

1. **JWT Expiration**: 
   - The JWT token has an expiration time of 30 minutes (`timedelta(minutes=30)`). Adjust the expiration time based on your security requirements.

2. **HttpOnly Cookies**: 
   - The token is stored in an `HttpOnly` cookie, which enhances security by preventing JavaScript from accessing it.

3. **Secret Key**: 
   - Ensure the `SECRET_KEY` used to sign the tokens is kept secure and not hard-coded in production. You can load it from environment variables.

4. **HTTPS**: 
   - In production, always use **HTTPS** to encrypt the communication between the client and the server, ensuring the JWT token is transmitted securely.

