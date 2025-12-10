from pydantic import BaseModel, EmailStr
from typing import Optional, Union
from datetime import datetime

# --------------------------------------
# USER SCHEMAS
# --------------------------------------

class UserBase(BaseModel):
    username: str
    email: Optional[EmailStr] = None


class UserCreate(UserBase):
    password: str


class UserResponse(UserBase):
    id: int

    class Config:
        from_attributes = True

# --------------------------------------
# AUTH / REGISTER / PASSWORD SCHEMAS
# --------------------------------------

class RegistrationUser(BaseModel):
    username: str
    password: str
    email: EmailStr


class TokenResponse(BaseModel):
    access_token: str
    token_type: str
    username: str
    email:str


class PasswordResetRequest(BaseModel):
    username: str
    old_password: str
    new_password: str
    new_password_confirm: str


class ForgotPasswordRequest(BaseModel):
    entered_verify_code: str
    new_password: str
    new_password_confirm: str
    email: EmailStr


class EmailVerificationRequest(BaseModel):
    email: EmailStr
    verification_token: str


class DeleteAccountRequest(BaseModel):
    password: str