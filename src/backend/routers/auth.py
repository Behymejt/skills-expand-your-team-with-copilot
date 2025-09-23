"""
Authentication endpoints for the High School Management System API
"""

from fastapi import APIRouter, HTTPException
from typing import Dict, Any
from argon2 import PasswordHasher

from ..database import teachers_collection

router = APIRouter(
    prefix="/auth",
    tags=["auth"]
)

ph = PasswordHasher()

def hash_password(password):
    """Hash password using Argon2"""
    return ph.hash(password)

def verify_password(stored_hash, input_password):
    """
    Verify if the input_password matches the stored Argon2 hash.
    Returns True if correct, False otherwise.
    """
    try:
        return ph.verify(stored_hash, input_password)
    except Exception:
        return False

@router.post("/login")
def login(username: str, password: str) -> Dict[str, Any]:
    """Login a teacher account"""
    # Hash the provided password
    hashed_password = hash_password(password)
    
    # Find the teacher in the database
    teacher = teachers_collection.find_one({"_id": username})
    
    if not teacher or not verify_password(teacher["password"], password):
        raise HTTPException(status_code=401, detail="Invalid username or password")
    
    # Return teacher information (excluding password)
    return {
        "username": teacher["username"],
        "display_name": teacher["display_name"],
        "role": teacher["role"]
    }

@router.get("/check-session")
def check_session(username: str) -> Dict[str, Any]:
    """Check if a session is valid by username"""
    teacher = teachers_collection.find_one({"_id": username})
    
    if not teacher:
        raise HTTPException(status_code=404, detail="Teacher not found")
    
    return {
        "username": teacher["username"],
        "display_name": teacher["display_name"],
        "role": teacher["role"]
    }