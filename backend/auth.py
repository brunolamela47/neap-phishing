from fastapi import APIRouter, HTTPException, Header
from typing import Optional
from datetime import datetime, timedelta
import hashlib
import secrets
import sys
import os
import json

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from backend.models import RegisterModel, LoginModel, ResponseModel
from database.database import get_connection

SESSION_FILE = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), ".session")

router = APIRouter()

@router.post("/save-session")
async def save_session(data: dict):
    print(f"DEBUG save_session called with: {data}")
    try:
        with open(SESSION_FILE, 'w') as f:
            json.dump({"token": data["token"], "username": data["username"]}, f)
        print(f"DEBUG session saved to: {SESSION_FILE}")
        return {"success": True}
    except Exception as e:
        print(f"DEBUG save error: {e}")
        return {"success": False, "error": str(e)}


@router.get("/load-session")
async def load_session():
    try:
        print(f"DEBUG SESSION_FILE path: {SESSION_FILE}")
        print(f"DEBUG file exists: {os.path.exists(SESSION_FILE)}")

        if not os.path.exists(SESSION_FILE):
            return {"success": False}

        with open(SESSION_FILE, 'r') as f:
            data = json.load(f)

        print(f"DEBUG loaded data: {data}")

        conn = get_connection()
        cursor = conn.cursor()
        cursor.execute("""
            SELECT SESSIONS.token, USERS.username, SESSIONS.expires_at
            FROM SESSIONS
            JOIN USERS ON SESSIONS.id_user = USERS.id_user
            WHERE SESSIONS.token = ?
        """, (data["token"],))

        session = cursor.fetchone()
        print(f"DEBUG session from DB: {session}")
        conn.close()

        if not session:
            print("DEBUG: session not found in DB!")
            os.remove(SESSION_FILE)
            return {"success": False}

        from datetime import datetime
        expires_at = datetime.fromisoformat(session[2])
        now = datetime.now()
        print(f"DEBUG expires_at: {expires_at}, now: {now}")

        if now > expires_at:
            print("DEBUG: session expired!")
            os.remove(SESSION_FILE)
            return {"success": False}

        return {"success": True, "date": {"token": data["token"], "username": data["username"]}}

    except Exception as e:
        print(f"DEBUG load error: {e}")
        return {"success": False, "error": str(e)}


@router.post("/clear-session")
async def clear_session():
    """Clear saved session."""
    try:
        if os.path.exists(SESSION_FILE):
            os.remove(SESSION_FILE)
        return {"success": True}
    except:
        return {"success": True}

def hash_password(password):
	return hashlib.sha256(password.encode()).hexdigest()


def generate_token():
	return secrets.token_hex(32)

@router.post("/register", response_model = ResponseModel)
async def register(data: RegisterModel):
	conn = get_connection()
	cursor = conn.cursor()
	

	cursor.execute("SELECT id_user FROM USERS WHERE username = ?", (data.username,))
	if cursor.fetchone():
		conn.close()
		raise HTTPException(status_code=400, detail="Username already exists")

	cursor.execute("SELECT id_user FROM USERS WHERE email = ?", (data.email,))
	if cursor.fetchone():
		conn.close()
		raise HTTPException(status_code=400, detail="Email already exists")

	hashed = hash_password(data.password)
	cursor.execute("""
		INSERT INTO USERS (username, email, password)
		VALUES (?, ?, ?)
	""", (data.username, data.email, hashed))
	
	conn.commit()
	conn.close()

	
	return ResponseModel(
		success = True,
		message = "Account created successfuly"
	)


@router.post("/login", response_model=ResponseModel) 
async def login(data: LoginModel):
	conn = get_connection()
	cursor = conn.cursor()

	
	hashed = hash_password(data.password)
	cursor.execute("""
		SELECT id_user, username FROM USERS
		WHERE username = ? AND password = ?
	""", (data.username, hashed))

	user = cursor.fetchone()
	if not user:
	    conn.close()
	    raise HTTPException(status_code=401, detail="Invalid credentials")
		
	token = generate_token()
	expires_at = datetime.now() + timedelta(days=7)
	
	
	cursor.execute("""
	       INSERT INTO SESSIONS (id_user, token, expires_at)
	       VALUES (?, ?, ?)
	""", (user[0], token, expires_at))
	
	
	conn.commit()
	conn.close()
	
	return ResponseModel(
	    success = True,
	    message = "Login successful",
	    date = {"token": token, "username": user[1]}
	)

@router.get("/session", response_model=ResponseModel)
async def verify_session(token):
	
	conn = get_connection()
	cursor = conn.cursor()
	
	
	cursor.execute("""
		SELECT SESSIONS.token, USERS.username, SESSION.expires_at
		FROM SESSIONS
		JOIN USERS ON SESSIONS.id_user = USERS.id_user
		WHERE SESSIONS.token = ?
	""", (token,))

	session = cursor.fetchone()
	conn.close()

	if not session:
	    raise HTTPException(status_code=401, detail="Invalid session")
	

	expires_at = datetime.fromisoformat(session[2])
	if datetime.now() > expires_at:
		raise HTTPException(status_code=401, detail="Session expired")
	
	
	return ResponseModel(
		success = True,
		message = "Session valid",
		date = {"username", session[1]}
	)


# Add this endpoint to backend/auth.py

@router.get("/check", response_model=ResponseModel)
async def check_session(authorization: Optional[str] = Header(None)):
    """Check if token is still valid."""
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Invalid token")

    token = authorization.split(" ")[1]
    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute("""
        SELECT SESSIONS.token, USERS.username, SESSIONS.expires_at
        FROM SESSIONS
        JOIN USERS ON SESSIONS.id_user = USERS.id_user
        WHERE SESSIONS.token = ?
    """, (token,))

    session = cursor.fetchone()
    conn.close()

    if not session:
        raise HTTPException(status_code=401, detail="Invalid session")

    from datetime import datetime
    expires_at = datetime.fromisoformat(session[2])
    if datetime.now() > expires_at:
        raise HTTPException(status_code=401, detail="Session expired")

    return ResponseModel(
        success=True,
        message="Session valid",
        date={"username": session[1]}
    )

@router.post("/logout", response_model=ResponseModel)
async def logout(token):
	conn = get_connection()
	cursor = conn.cursor()
	
	
	cursor.execute("DELETE FROM SESSIONS WHERE token = ?", (token,))
	conn.commit()
	conn.close()

	
	return ResponseModel(
		success = True,
		message = "Logout successful"
	)


