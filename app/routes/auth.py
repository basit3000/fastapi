from fastapi import APIRouter, HTTPException, Depends, status
from fastapi.security import OAuth2PasswordRequestForm, OAuth2PasswordBearer
from app.models import User, ChangePasswordRequest
from app.database import db
from app.auth import verify_password, create_access_token, hash_password, ALGORITHM, SECRET_KEY
from jose import JWTError, jwt
import logging
from app.services.auth_service import change_user_password

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="login")

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

router = APIRouter()

def get_current_user(token: str = Depends(oauth2_scheme)):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        email = payload.get("sub")
        if not email:
            raise HTTPException(status_code=401, detail="Invalid token")
        return email
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid token")

@router.post("/register", status_code=status.HTTP_201_CREATED, tags=["auth"])
async def register(user: User):
    existing = await db.users.find_one({"email": user.email})
    if existing:
        raise HTTPException(status_code=400, detail="Email already registered.")
    
    user_dict = {"email": user.email, "password": hash_password(user.password)}
    await db.users.insert_one(user_dict)

    logger.info(f"User registered: {user.email}")

    return {"message": "User registered successfully."}

@router.post("/login", tags=["auth"])
async def login(form_data: OAuth2PasswordRequestForm = Depends()):
    user = await db.users.find_one({"email": form_data.username})
    if not user or not verify_password(form_data.password, user["password"]):
        logger.warning(f"Failed login attempt for: {form_data.username}")
        raise HTTPException(status_code=401, detail="Invalid credentials")
    
    token = create_access_token(data={"sub": user["email"]})
    logger.info(f"User logged in: {form_data.username}")
    return {"access_token": token, "token_type": "bearer"}

@router.get("/me", tags=["auth"])
async def read_users_me(current_user: str = Depends(get_current_user)):
    return {"email": current_user}

@router.post("/change-password", tags=["auth"])
async def change_password(
    request: ChangePasswordRequest,
    current_user: str = Depends(get_current_user),
):
    result = await change_user_password(
        email=current_user,
        old_password=request.old_password,
        new_password=request.new_password
    )
    if "error" in result:
        raise HTTPException(status_code=400, detail=result["error"])
    return result