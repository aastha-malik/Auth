from fastapi import FastAPI, Depends, HTTPException, status
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

# ---------------------------------------------------
# DATABASE & APP SETUP
# ---------------------------------------------------

models.Base.metadata.create_all(bind=engine)

app = FastAPI()

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

# ---------------------------------------------------
# AUTH ROUTES (LOGIN / PASSWORD / OTP)
# ---------------------------------------------------

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

@app.get("/login/google")
async def login_with_google(request: Request):
    redirect_uri = request.url_for("google_callback")
    return await oauth.google.authorize_redirect(request, redirect_uri)

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

