from fastapi import FastAPI, Depends, HTTPException, status, Request
from starlette.middleware.sessions import SessionMiddleware
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from sqlalchemy.orm import Session
from fastapi.middleware.cors import CORSMiddleware
from datetime import datetime, timedelta
from jose import jwt
import models
from models import User
from database import SessionLocal, engine, Base
import auth_crud
# from forget_password import to_confirm_email
from auth import pwd_context
from auth_crud import SECRET_KEY, ALGORITHM
from auth_dependencies import get_current_user
from schemas import (
    RegistrationUser, TokenResponse, DeleteAccountRequest
)
from starlette.responses import RedirectResponse
from oauth import oauth
from dotenv import load_dotenv
import uuid
load_dotenv()

# ---------------------------------------------------
# DATABASE & APP SETUP
# ---------------------------------------------------

models.Base.metadata.create_all(bind=engine)

app = FastAPI()

app.add_middleware(SessionMiddleware, secret_key="auth")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)



def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


@app.get("/")
def read_root():
    return {"message": "This is Manager side of our app Auth!!"}

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

login_sessions = {}   

#if the fe is web application then there is no needd for this local_sessions dict and the start_google_login function and google_login_status function remove them both entirely...


# ---------------------------------------------------
# AUTH ROUTES (LOGIN / PASSWORD / OTP)
# ---------------------------------------------------


@app.get("/login/google")
async def google_login(request: Request):
    redirect_uri = request.url_for("google_callback")
    return await oauth.google.authorize_redirect(request, redirect_uri)

@app.get("/login/google/start")
def start_google_login(request:Request):     
    session_id = str(uuid.uuid4())
    login_sessions[session_id] = { "status": "pending", "jwt": None }
    login_url = request.url_for("google_login") + f"?session_id={session_id}"
    return {
        "session_id":session_id,
        "login_url":login_url
    }


@app.get("/login/google/status")
def google_login_status(session_id: str):
    session = login_sessions.get(session_id)

    if session is None:
        return {"status": "invalid_session"}

    if session["status"] == "pending":
        return {"status": "pending"}

    if session["status"] == "success":
        return {
            "status": "success",
            "access_token": session["jwt"],
            "token_type": "bearer"
        }


@app.get("/login/google/callback")
async def google_callback(request: Request, db: Session = Depends(get_db)):
    session_id = request.query_params.get("session_id")
    

    # S1: Exchange code for tokens
    token = await oauth.google.authorize_access_token(request)

    # S2: Extract user info from Google
    user_info = token.get("userinfo")
    if user_info is None:
        user_info = await oauth.google.parse_id_token(request, token)

    # Debug print
    print("Google user info:", user_info)
    
#extract email, sub
    user_email = user_info["email"]
    user_sub = user_info["sub"]
    
    user = db.query(User).filter(User.email == user_email).first()
    # in case of login
    if not user:
        base_username = user_email.split("@")[0]
        username = base_username
        count = 1


        while db.query(User).filter(User.username == username).first():
            username = f"{base_username}_{count}"
            count += 1

        new_user = User(
            username=username,
            hashed_password="", 
            email=user_email, 
            user_verified=True, 
            start_acc_time= datetime.utcnow(), 
            provider="google",
            provider_id=user_sub
            )

        db.add(new_user)
        db.commit()
        db.refresh(new_user)
        data = {  "sub": str(new_user.id)  }
        

    # in case of creating account
    data = {   "sub": user.id  }

    jwt_token = auth_crud.create_access_token(data, expires_delta=timedelta(minutes=30))

 # if the fe is web application then remove the whole sessionID logic & html_response and replace it with this code give below in comments
    # # 4. Redirect to frontend with JWT
    # redirect_url = f"http://localhost:3000/auth/success?token={jwt_token}"

    # return RedirectResponse(redirect_url)

    if session_id and session_id in login_sessions:
        login_sessions[session_id]["status"] = "success"
        login_sessions[session_id]["jwt"] = jwt_token

    return HTMLResponse("<h2>Login / Account created successfully. You may close this window.</h2>")


@app.post("/login", response_model=TokenResponse)
def login(
    form_data: OAuth2PasswordRequestForm = Depends(),
    db: Session = Depends(get_db)
):
    username = form_data.username
    password = form_data.password

    if '@' in username:
        user = auth_crud.authenticate_user(db, '', username, password)
    else:
        user = auth_crud.authenticate_user(db, username, '', password)

    if not user:
        raise HTTPException(status_code=401, detail="Invalid username or password")

    data = {"sub": user.username}
    token = auth_crud.create_access_token(data, expires_delta=timedelta(minutes=20))
    return {"access_token": token, "token_type": "bearer", "username":user.username, "email":user.email}


# @app.patch("/reset_password")
# def password_reset_endpoint(
#     new_password: str,
#     new_password_confirm: str,
#     old_password: str,
#     username: str,
#     db: Session = Depends(get_db)
# ):
#     reset = auth_crud.password_reset(db, new_password, new_password_confirm, old_password, username)
#     if not reset:
#         raise HTTPException(status_code=400, detail="Password reset failed")
#     return {"message": "Password reset successful!"}


# @app.post("/send_forgot_password_otp")
# def send_forgot_password_otp(email: str, db: Session = Depends(get_db)):
#     result = to_confirm_email(db, email)
#     if not result:
#         raise HTTPException(status_code=404, detail="Email not found")
#     return {"message": "OTP sent to your email"}


# @app.patch("/forgot_password")
# def forgot_password_endpoint(
#     entered_verify_code: str,
#     new_password: str,
#     new_password_confirm: str,
#     username: str,
#     db: Session = Depends(get_db)
# ):
#     forget = auth_crud.forget_password(db, entered_verify_code,username, new_password, new_password_confirm)
#     if not forget:
#         raise HTTPException(status_code=400, detail="Forget password reset failed")
#     return {"message": "Forget password reset done!"}


@app.delete("/delete_account")
def delete_account(data: DeleteAccountRequest,db: Session = Depends(get_db),current_user = Depends(get_current_user)):
    result = auth_crud.del_user(db, current_user.id, data.password)
    if not result:
        raise HTTPException(status_code=404, detail="user not found")
    return {"message": "user account deleted successfully"}


# ---------------------------------------------------
# REGISTRATION & EMAIL VERIFICATION
# ---------------------------------------------------

@app.post("/register")
def register_user(user: RegistrationUser, db: Session = Depends(get_db)):
    from sqlalchemy import or_
    # Check if username or email already exists
    existing = db.query(User).filter(or_(User.username == user.username, User.email == user.email)).first()
    if existing:
        if existing.username == user.username:
            raise HTTPException(status_code=400, detail="Username already exists")
        if existing.email == user.email:
            raise HTTPException(status_code=400, detail="Email already exists")

    auth_crud.create_user(db, user.username, user.password, user.email)
    return {"message": "User registered successfully!"}


@app.post("/verify_email")
def verify_email_endpoint(email: str, verification_token: str, db: Session = Depends(get_db)):
    result = auth_crud.verify_email(db, email, verification_token)
    if not result:
        raise HTTPException(status_code=400, detail="Email verification failed")
    return {"message": "Email verified successfully"}

