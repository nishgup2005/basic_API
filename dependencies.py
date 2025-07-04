from typing import Annotated
from sqlalchemy.orm import session
from .database import get_db
from fastapi import Depends, Header, Request
from fastapi.security import OAuth2PasswordRequestForm
from fastapi_mail import FastMail, ConnectionConfig
from .model import Users
from passlib.context import CryptContext
from NewFast.setting.config import Config
from pathlib import Path
from itsdangerous.url_safe import URLSafeSerializer
from fastapi.templating import Jinja2Templates


# bcrypt context is used for encryption
bcrypt_context = CryptContext(schemes=['bcrypt'], deprecated='auto')

# db dependency for db connection injection
db_dependency = Annotated[session, Depends(get_db)]


# User Dependenccy requirements
def get_user_token(x_token: Annotated[str, Header()] = None):
    return x_token


def get_curr_user(token: Annotated[str, Depends(get_user_token)], db: db_dependency, request: Request):
    if not token:
        return "invalid_token"

    if not request.app.state.redis.exists(token):
        return "invalid_token"

    user_id = request.app.state.redis.get(token).decode('UTF-8')
    # request.app.state.redis.setex(token, 1000, user_id)
    user = db.get(Users, user_id)
    return user


# User dependency for gettting the current user. if invalid token the dependency returns "invalid_token" string
user_dependency = Annotated[Users, Depends(get_curr_user)]


BASE_DIR = Path(__file__).resolve().parent

conn = ConnectionConfig(MAIL_USERNAME=Config.MAIL_USERNAME,
                        MAIL_PASSWORD=Config.MAIL_PASSWORD,
                        MAIL_FROM=Config.MAIL_FROM,
                        MAIL_PORT=Config.MAIL_PORT,
                        MAIL_SERVER=Config.MAIL_SERVER,
                        MAIL_FROM_NAME=Config.MAIL_FROM_NAME,
                        MAIL_STARTTLS=Config.MAIL_STARTTLS,
                        MAIL_SSL_TLS=Config.MAIL_SSL_TLS,
                        USE_CREDENTIALS=Config.USE_CREDENTIALS,
                        VALIDATE_CERTS=Config.VALIDATE_CERTS,
                        TEMPLATE_FOLDER=Path(BASE_DIR, "templates"))

mail = FastMail(config=conn)

encoder = URLSafeSerializer(secret_key=Config.EMAIL_SECRET_KEY)


# oauth2 is security framework.
# OAuth2PasswordBearer is a security measure provided by the
# fastAPI framework to enbale secure authentication procedures ('flows')
# oauth2passwordrequestform can be used to capture the data in xform encoded url format
form_dependency = Annotated[OAuth2PasswordRequestForm, Depends()]

# Jinja2Template is used for creating HTML templates for ease of use
template = Jinja2Templates(directory=Config.TEMPLATE_FOLDER)
