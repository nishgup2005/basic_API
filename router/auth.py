from fastapi import APIRouter, Request, Form
from NewFast.base import RegisterBase, TokenBase, EmailBase, ResetPassBase
from NewFast.dependencies import db_dependency, form_dependency, bcrypt_context, template
from fastapi.responses import JSONResponse
from NewFast.model import Users
from datetime import timedelta, datetime
from pydantic import EmailStr
from jose import jwt
from NewFast.setting.config import Config
from NewFast.dependencies import encoder
from NewFast.utils import verify_mail, reset_pass_mail
from itsdangerous.exc import BadSignature
from typing import Annotated


time_to_live = Config.TIME_TO_LIVE
secret_key = Config.SECRET_KEY
email_secret_key = Config.EMAIL_SECRET_KEY
algorithm = Config.HASH


# authenticate the user with the a valid password

def authenticateUser(email: EmailStr,
                     password: str,
                     db: db_dependency) -> Users:

    user = (db.query(Users)
            .filter(Users.email == email)
            .first())
    if not user:
        return False

    if not bcrypt_context.verify(password, user.password):
        return False

    return user


# Generates a JWT token that contains
# the email, user_id for a user and
# contains the time to live for the
# token

def create_user_token(email: str, user_id: int, ttl: timedelta) -> str:
    encode = {"sub": email, "id": user_id}
    expires = datetime.now()+ttl
    encode.update({"exp": expires})
    return jwt.encode(encode, secret_key, algorithm=algorithm)


router = APIRouter(tags=["auth"])


# Register is used to register new users
# takes a user input corresponding to the Register
# Base model , newly registered users need to be verified

@router.post('/register', status_code=201)
async def user_register(user: RegisterBase, db: db_dependency, request: Request):
    try:
        db_user = Users(name=user.name,
                        email=user.email,
                        password=bcrypt_context.hash(user.password),
                        phone_no=user.phone_no,
                        role="user",
                        is_active=False)

        db.add(db_user)
        db.commit()
        db.refresh(db_user)
        print(email_secret_key, "This is the secret key in test api", sep="\n")
        if user.email is None:
            emails = ["nishgup2004@gmail.com"]
        else:
            emails = [user.email]
        user_id = db_user.id
        name = user.name
        verify_mail(email=emails, user_id=user_id, name=name, request=request)

        return JSONResponse(content={"status_code": 200,
                                     "msg": "Please Check your Email for Account Verification"},
                            status_code=200)

    except AttributeError as e:
        print(e)
        return JSONResponse(content={"status_code": 400,
                                     "msg": "Something Went Wrong"},
                            status_code=400)

    except Exception as e:
        msg = str(e.orig).split(':')[-1].replace('\n', '').strip()
        return JSONResponse(content={"status_code": 422,
                                     "msg": "Unprocessable Entity",
                                     "detail": msg},
                            status_code=422)


# /login is used to log in to the user database
# it generates a log in token which is a JWT token
# attaches it to the header of  the response
# this token is authenticated at the user portal

@router.post('/login', response_model=TokenBase)
async def token_login(form_data: form_dependency, db: db_dependency, request: Request):

    user = authenticateUser(form_data.username, form_data.password, db)
    if not user:
        return JSONResponse(content={"status_code": 401,
                                     "msg": "Unauthorized",
                                     "detail": "invalid username/password"},
                            status_code=401)

    if not user.is_active:
        return JSONResponse(content={"status_code": "401",
                                     "msg": "Unauthorized",
                                     "detail": "Inactive Account, Verify with valid email"},
                            status_code=401)

    token = create_user_token(
        user.email, user.id, timedelta(minutes=time_to_live))
    if request.app.state.redis.setex(token, 10000, user.id):
        print("token inserted")
    return JSONResponse(content={"status_code": 200,
                                 "msg": "Login Successful"},
                        headers={"x-token": token},
                        status_code=200)


# GET/ verify is used to accept incoming verification
# from the email that has been sent.
# Once recieved it changes the is_Active variable to True
# for the user whose email it has been sent to.

@router.get('/verify/{encoded_url}')
async def user_verify(db: db_dependency, request: Request, encoded_url: str):

    if not request.app.state.redis.exists(encoded_url):
        return JSONResponse(content={"status_code": 401,
                                     "msg": "Unauthorized",
                                     "detail": "Invalid Verification URL"},
                            status_code=401)
    valid_id = int(request.app.state.redis.get(encoded_url).decode("utf-8"))

    try:
        decoded_id = encoder.loads(encoded_url)
    except BadSignature as e:
        return JSONResponse(content={"status_code": 401,
                                     "msg": "Unauthorized",
                                     "detail": "Invalid Verification URL"},
                            status_code=401)

    if valid_id != decoded_id:
        return JSONResponse(content={"status_code": 401,
                                     "msg": "Unauthorized",
                                     "detail": "Invalid Verification URL"},
                            status_code=401)

    user = db.get(Users, decoded_id)
    token = create_user_token(user.email, user.id, timedelta(minutes=5))

    if not request.app.state.redis.setex(token, 300, user.id):
        return JSONResponse(content={"status_code": 500,
                                     "msg": "Server Error",
                                     "detail": "Please try again later"},
                            status_code=500)
    user.is_active = True
    db.commit()
    return JSONResponse(content={"status_code": 200,
                                 "msg": "Login Successful",
                                 "return to home page": ""},
                        headers={"x-token": token},
                        status_code=200)


# POST /verify is used to verify users who
# were not verified at the time of creation
# Simply entering the email in the body of
# the request will trigger the verification process

@router.post('/verify')
async def user_verify_email(db: db_dependency, request: Request, email: EmailBase):
    user = db.query(Users).filter(Users.email == email.address).first()
    if not user:
        return JSONResponse(content={"status_code": 401,
                                     "msg": "Invalid Verification email"},
                            status_code=401)
    emails = [email.address]
    name = user.name
    user_id = user.id
    name = user.name
    await verify_mail(email=emails, name=name, user_id=user_id, request=request)
    return JSONResponse(content={"status_code": 200,
                                 "msg": "Email Sent Successfully",
                                 "detail":"Please Check Your Email to Verify Your Account"},
                        status_code=200)


# PATCH /password is used to reset a user Password
# it takes the email and sends a reset password link
# to that email

@router.patch("/password")
async def reset_password(email: EmailBase, db: db_dependency, request: Request):
    user = db.query(Users).filter(Users.email == email.address).first()
    if not user:
        return JSONResponse(content={"status_code": 401,
                                     "msg": "Invalid Verification email"},
                            status_code=401)

    emails = [email.address]
    name = user.name
    user_id = user.id
    await reset_pass_mail(email=emails, user_id=user_id, name=name, request=request)

    return JSONResponse(content={"status_code": 200,
                                 "msg": "Email Sent Successfully",
                                 "detail":"Please Check Your Email to Reset Your Password"},
                        status_code=200)


# GET /password is use to display the reset password
# form for the user who have reached here from their emails

@router.get("/password/{encoded_url}")
async def new_password(encoded_url: str, request: Request):
    if not request.app.state.redis.exists(encoded_url):
        return JSONResponse(content={"status_code": 401,
                                     "msg": "Unauthorized",
                                     "detail": "Session Expired"},
                            status_code=401)

    return template.TemplateResponse(request=request, name="reset_password.html",context={"encoded_url":encoded_url})


# POST /password can be reached through the form in GET /password request
# This API is where the password is changed
# Once verified the password is hashed and changed

@router.post("/password/{encoded_url}", response_model=None)
async def set_password(encoded_url: str, db: db_dependency, reset_pass: Annotated[ResetPassBase, Form()], request: Request):

    if not request.app.state.redis.exists(encoded_url):
        return JSONResponse(content={"status_code": 401,
                                     "msg": "Unauthorized",
                                     "detail": "Session Expired"},
                            status_code=401)

    valid_id = int(request.app.state.redis.get(encoded_url).decode("utf-8"))

    try:
        decoded_id = encoder.loads(encoded_url)
    except BadSignature as e:
        return JSONResponse(content={"status_code": 401,
                                     "msg": "Unauthorized",
                                     "detail": "Invalid Verification URL"},
                            status_code=401)

    if valid_id != decoded_id:
        return JSONResponse(content={"status_code": 401,
                                     "msg": "Unauthorized",
                                     "detail": "Invalid Verification URL"},
                            status_code=401)

    user = db.get(Users, decoded_id)
    new_pass = reset_pass.new_pass
    confirm_new_pass = reset_pass.confirm_new_pass
    if new_pass != confirm_new_pass:
        return JSONResponse(content={"status_code": 422,
                                     "msg": "Unprocessable Entity",
                                     "detail": "New password and Confirm password do not match"},
                            status_code=422)

    user.password = bcrypt_context.hash(new_pass)
    db.commit()
    return JSONResponse(content={"status_code": 200,
                                 "msg": "Password Reset Successful",
                                 "detail": "Your Password was Reset Successfully. Please Login again with new Password"},
                        status_code=200)
