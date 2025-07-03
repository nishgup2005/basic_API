from fastapi import FastAPI
from .model import Base
from .database import engine
# from sqlalchemy.orm import session
# from typing import Annotated
# from .router.user import create_user_token
# from datetime import timedelta, datetime
from .router import auth, salary, user
from redis import Redis, ConnectionPool
from contextlib import asynccontextmanager
# from fastapi_mail import FastMail, MessageSchema, ConnectionConfig, MessageType
# from pydantic import EmailStr
from NewFast.setting.config import Config
# from pathlib import Path
# from .base import EmailBase
# from fastapi.responses import JSONResponse
# from itsdangerous.url_safe import URLSafeSerializer
# from secrets import token_hex
# from jose import jwt

secret_key = Config.SECRET_KEY

# asynccontextmanager is a event handler that can be used to
# define functionality before the application is started 
# and after the application has ended
# code before yield statement is executed before the app starts
# code after the yield statement is executed after the app ends

@asynccontextmanager
async def lifespan(app:FastAPI):
    app.state.redis = Redis(connection_pool=ConnectionPool(host='localhost', port=6379))
    yield
    app.state.redis.close()

# the lifespan function defined above is passed in the lifetime 
# parameter of the app 

app = FastAPI(lifespan=lifespan)
app.include_router(salary.router)
app.include_router(user.router)
app.include_router(auth.router)
Base.metadata.create_all(bind=engine)

# email_secret_key = Config.EMAIL_SECRET_KEY

# encoder=URLSafeSerializer(secret_key=email_secret_key)

# BASE_DIR = Path(__file__).resolve().parent

# conn = ConnectionConfig(MAIL_USERNAME = Config.MAIL_USERNAME,
#                         MAIL_PASSWORD = Config.MAIL_PASSWORD,
#                         MAIL_FROM = Config.MAIL_FROM,
#                         MAIL_PORT = Config.MAIL_PORT,
#                         MAIL_SERVER = Config.MAIL_SERVER,
#                         MAIL_FROM_NAME=Config.MAIL_FROM_NAME,
#                         MAIL_STARTTLS = Config.MAIL_STARTTLS,
#                         MAIL_SSL_TLS = Config.MAIL_SSL_TLS,
#                         USE_CREDENTIALS = Config.USE_CREDENTIALS,
#                         VALIDATE_CERTS = Config.VALIDATE_CERTS,
#                         TEMPLATE_FOLDER = Path(BASE_DIR, "templates"))

# mail = FastMail(config=conn)

# def create_message(recipients: list[EmailStr], subject: str, body: str, ) -> MessageSchema:
#     message = MessageSchema(recipients=recipients, subject=subject, body=body, subtype=MessageType.html)
#     return message

# @app.post('/test')
# async def send_mail(email: EmailBase | None = None):
#     print(email_secret_key, "This is the secret key in test api", sep = "\n")
#     if email is None :
#         emails=["nishgup2004@gmail.com"]
#     else:
#         emails = email.addresses
#     user_id=5
#     name = "name_here"
#     encoded_url = encoder.dumps(user_id)
#     html = f"""<h1> Hello {name}</h1>
#               <a href="http://127.0.0.1:8000/verify?path={encoded_url}"> Verify Email here</a>"""

#     message = create_message(recipients=emails, subject = "Welcome User", body=html)
#     await mail.send_message(message=message)

#     return JSONResponse(content={"status_code":200,
#                                  "msg":"Email sent successfully"},
#                         status_code=200)


# db_dependency = Annotated[session, Depends(get_db)]
# @app.get('/verify')
# async def user_verify(path:str, db:db_dependency):
#     print(email_secret_key, "This is the secret key in verify api", sep = "\n")
#     if encoder.loads(path):
#         decoded_id=encoder.loads(path)
#         user = db.get(Users, decoded_id)
#         if user is None:
#             return JSONResponse(content = {"status_code":401,
#                                             "msg":"Invalid Verification URL"},
#                                 status_code=401)
#         token = create_user_token(user.email, user.id, timedelta(minutes=5))
#         if app.state.redis.setex(token, 300, user.id):
#             print("token inserted")
#         return JSONResponse(content={"status_code":200,
#                                     "msg":"Login Successful",
#                                     "return to home page":""},
#                             headers={"x-token":token},
#                             status_code=200)