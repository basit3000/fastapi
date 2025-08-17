from fastapi import APIRouter, HTTPException, Depends, status
from fastapi.security import OAuth2PasswordRequestForm, OAuth2PasswordBearer
from pydantic import BaseModel, EmailStr, constr
from app.models import User, ChangePasswordRequest
from app.database import db
from app.auth import verify_password, create_access_token, hash_password, ALGORITHM, SECRET_KEY
import logging
from app.services.auth_service import change_user_password, get_current_user

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="login")

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

router = APIRouter()

class RegisterRequest(BaseModel):
    email: EmailStr
    password: constr(min_length=8)

class ChangePasswordRequest(BaseModel):
    old_password: constr(min_length=8)
    new_password: constr(min_length=8)

class MessageResponse(BaseModel):
    message: str

class TokenResponse(BaseModel):
    access_token: str
    token_type: str

class UserResponse(BaseModel):
    email: EmailStr

def get_current_user_dep(token: str = Depends(oauth2_scheme)):
    return get_current_user(token)

@router.post("/register", status_code=status.HTTP_201_CREATED, tags=["auth"], response_model=MessageResponse)
async def register(user: RegisterRequest):
    existing = await db.users.find_one({"email": user.email})
    if existing:
        raise HTTPException(status_code=400, detail="Email already registered.")
    
    user_dict = {"email": user.email, "password": hash_password(user.password)}
    await db.users.insert_one(user_dict)

    logger.info(f"User registered: {user.email}")

    return {"message": "User registered successfully."}

@router.post("/login", tags=["auth"], response_model=TokenResponse)
async def login(form_data: OAuth2PasswordRequestForm = Depends()):
    user = await db.users.find_one({"email": form_data.username})
    if not user or not verify_password(form_data.password, user["password"]):
        logger.warning(f"Failed login attempt for: {form_data.username}")
        raise HTTPException(status_code=401, detail="Invalid credentials")
    
    token = create_access_token(data={"sub": user["email"]})
    logger.info(f"User logged in: {form_data.username}")
    return {"access_token": token, "token_type": "bearer"}

@router.get("/me", tags=["auth"], response_model=UserResponse)
async def read_users_me(current_user: str = Depends(get_current_user_dep)):
    return {"email": current_user}

@router.post("/change-password", tags=["auth"], response_model=MessageResponse)
async def change_password(
    request: ChangePasswordRequest,
    current_user: str = Depends(get_current_user_dep),
):
    result = await change_user_password(
        email=current_user,
        old_password=request.old_password,
        new_password=request.new_password
    )
    if "error" in result:
        logger.warning(f"Password change failed for: {current_user} - {result['error']}")
        raise HTTPException(status_code=400, detail=result["error"])
    logger.info(f"Password changed successfully for: {current_user}")
    return {"message": "Password changed successfully."}