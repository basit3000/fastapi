from app.database import db
from app.auth import verify_password, hash_password

async def change_user_password(email: str, old_password: str, new_password: str):
    user = await db.users.find_one({"email": email})
    if not user:
        return {"error": "User not found"}

    if not verify_password(old_password, user["password"]):
        return {"error": "Old password is incorrect."}

    new_hashed = hash_password(new_password)
    await db.users.update_one({"email": email}, {"$set": {"password": new_hashed}})
    return {"message": "Password changed successfully"}
