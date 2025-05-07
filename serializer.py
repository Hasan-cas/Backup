import os
from dotenv import load_dotenv
import logging
from itsdangerous import URLSafeTimedSerializer

load_dotenv()
SECRET_KEY = os.getenv('SECRET_KEY')
serializer = URLSafeTimedSerializer(SECRET_KEY, salt="4tZ9xwplLfD2#yNtx89w3F!aS@e")

logger = logging.getLogger(__name__)

def encrypt_csrf_token(data):
    """Encrypt and serialize the data."""
    try:
        return serializer.dumps(data)
    except Exception as e:
        logger.error(f"Encryption failed: {e}")
        return None

def decrypt_csrf_token(token, max_age=None):  # Set max_age=None for never expire
    """Decrypt and deserialize the CSRF token."""
    try:
        return serializer.loads(token, max_age=max_age)
    except Exception as e:
        logger.error(f"Decryption failed: {e}")
        return None
