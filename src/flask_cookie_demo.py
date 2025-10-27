#!/usr/bin/env python3
"""
====================================================
FILE: flask_cookie_demo.py
PURPOSE:
    This Flask app runs locally and is used for testing 
    cookie-related security checks. It sets multiple cookies:
      - some secure (good examples)
      - some insecure (bad examples)

WHY:
    This helps the team test whether our cookie scanner
    (cookie_scanner.py) can correctly find cookies that:
      ❌ contain sensitive data
      ❌ lack Secure/HttpOnly/SameSite attributes
      ❌ have very long expiry times

USAGE:
    1. Activate venv:
         source venv/bin/activate

    2. Start the demo server:
         python3 src/flask_cookie_demo.py

    3. Visit this URL:
         http://127.0.0.1:5002/set_cookies_demo

    4. Run the cookie scanner to analyse it:
         python3 src/cookie_scanner.py --target http://127.0.0.1:5002/set_cookies_demo
====================================================
"""
from flask import Flask, make_response, jsonify

# Create a Flask app
app = Flask(__name__)

@app.route("/set_cookies_demo")
def set_cookies_demo():
    """
    This endpoint sets several cookies in the response.
    Some are 'good' and some are 'bad'.
    The cookie scanner script will test whether it can identify the bad ones.
    """
    # Create a response body
    resp = make_response(jsonify({"message": "Cookies set for demo"}))

    # ✅ GOOD COOKIE EXAMPLE
    # - HttpOnly: not accessible to JavaScript
    # - Secure: only sent via HTTPS
    # - SameSite=Lax: helps prevent CSRF
    # - Short expiration (1 hour)
    resp.set_cookie(
        "secure_session", 
        value="sess_abc123", 
        httponly=True, 
        secure=True, 
        samesite="Lax", 
        max_age=3600
    )

    # ❌ BAD COOKIE EXAMPLE #1
    # - Looks like a JWT token (sensitive info)
    # - Not Secure and not HttpOnly
    resp.set_cookie(
        "auth_token", 
        value="eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.bad_payload.signature",
        httponly=False, 
        secure=False, 
        samesite=None, 
        max_age=3600
    )

    # ❌ BAD COOKIE EXAMPLE #2
    # - Contains personal information (email)
    # - Accessible to JavaScript
    # - No Secure/HttpOnly protection
    resp.set_cookie(
        "user_email", 
        value="alice@example.com", 
        httponly=False, 
        secure=False, 
        samesite=None
    )

    # ❌ BAD COOKIE EXAMPLE #3
    # - Valid for 5 years (unrealistically long)
    # - Not Secure
    resp.set_cookie(
        "long_lived", 
        value="persistent_value", 
        httponly=True, 
        secure=False, 
        samesite="Lax", 
        max_age=60*60*24*365*5
    )

    # Send response back to browser
    return resp


# Standard Flask entry point
if __name__ == "__main__":
    # Run locally on port 5002
    app.run(port=5002, debug=True)
