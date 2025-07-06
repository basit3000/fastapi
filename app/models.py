from pydantic import BaseModel, EmailStr, constr
from datetime import datetime 

class User(BaseModel):
    email: EmailStr
    password: constr(min_length=8, max_length=128)

class ChangePasswordRequest(BaseModel):
    old_password: constr(min_length=8)
    new_password: constr(min_length=8)