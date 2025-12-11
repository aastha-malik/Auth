from sqlalchemy import Column, Integer, String, Boolean, DateTime, Float, ForeignKey
from sqlalchemy.orm import relationship
from database import Base
from datetime import datetime

class User(Base):
    __tablename__ = "user"
    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True, index=True)
    hashed_password = Column(String)
    email = Column(String, unique=True, index=True)
    
    provider = Column(String, nullable=True)
    provider_id = Column(String, nullable=True)

    start_acc_time = Column(DateTime, default=datetime.utcnow())

    user_verified = Column(Boolean, default=False) #whether email of user is verified or not
    user_verification_token = Column(String, default=False)  #verification token for user
    user_verification_token_expires_at = Column(DateTime, default=datetime.utcnow()) #when verification token expires