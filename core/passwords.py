import hashlib
import base64
import random


def hash_password_with_salt(password: str) -> str:
    salt = generate_salt()
    return hash_password(password + ":" + salt) + ":" + salt


def verify_password(password: str, compared_hash: str) -> bool:
    raw_hash, salt = compared_hash.split(":", 2)
    return hash_password(password + ":" + salt) == raw_hash


def hash_password(password: str) -> str:
    data = hashlib.md5(password.encode("utf-8"))
    return base64.b64encode(data.digest()).decode("utf-8")


def generate_salt() -> str:
    salt_number = random.randint(0, 2 ** 255)
    return base64.b64encode(salt_number.to_bytes(32, "little")).decode("utf-8")
