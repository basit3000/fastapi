from app.database import db
from app.auth import verify_password, hash_password
from fastapi import APIRouter, HTTPException, Depends
from jose import JWTError, jwt
from app.auth import ALGORITHM, SECRET_KEY

async def change_user_password(email: str, old_password: str, new_password: str):
    user = await db.users.find_one({"email": email})
    if not user:
        return {"error": "User not found"}

    if not verify_password(old_password, user["password"]):
        return {"error": "Old password is incorrect."}

    new_hashed = hash_password(new_password)
    await db.users.update_one({"email": email}, {"$set": {"password": new_hashed}})
    return {"message": "Password changed successfully"}

def get_current_user(token: str):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        email = payload.get("sub")
        if not email:
            raise HTTPException(status_code=401, detail="Invalid token")
        return email
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid token")