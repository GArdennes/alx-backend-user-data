#!/usr/bin/env python3
"""
encrypt_password
"""
import bcrypt


def hash_password(password: str) -> bytes:
    """
    Return hashed password as a byte string
    """
    password_bytes = password.encode("utf-8")
    salt = bcrypt.gensalt()
    hashed_password = bcrypt.hashpw(password_bytes, salt)
    return hashed_password


def is_valid(hashed_password: bytes, password: str) -> bool:
    """
    Verify if the provided password matches the hashed password.
    """
    password_bytes = password.encode("utf-8")
    password_matches = bcrypt.checkpw(
            password_bytes,
            hashed_password
            )
    return password_matches
