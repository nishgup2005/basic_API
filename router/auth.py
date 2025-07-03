from fastapi import APIRouter, Request
from NewFast.base import RegisterBase, TokenBase, EmailBase
from NewFast.dependencies import db_dependency, form_dependency, bcrypt_context
from fastapi.responses import JSONResponse
from NewFast.model import Users
from datetime import timedelta, datetime
from pydantic import EmailStr, ValidationError
from jose import jwt
from NewFast.setting.config import Config
from NewFast.dependencies import mail, encoder, create_message
from itsdangerous.exc import BadSignature


time_to_live = Config.TIME_TO_LIVE
secret_key = Config.SECRET_KEY
email_secret_key = Config.EMAIL_SECRET_KEY
algorithm = Config.HASH

# authenticate the user with the a valid password

def authenticateUser(email: EmailStr, password:str, db:db_dependency) -> Users:
    user = (db.query(Users)
            .filter(Users.email==email)
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

def create_user_token(email:str, user_id:int, ttl:timedelta) -> str:
    encode={"sub":email, "id":user_id}
    expires = datetime.now()+ttl
    encode.update({"exp":expires})
    return jwt.encode(encode, secret_key, algorithm=algorithm)


router = APIRouter()


# Register is used to register new users
# takes a user input corresponding to the Register
# Base model , newly registered users need to be verified 
@router.post('/register',status_code=201)
async def user_register(user:RegisterBase, db:db_dependency, request: Request):
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
        print(email_secret_key, "This is the secret key in test api", sep = "\n")
        if user.email is None :
            emails=["nishgup2004@gmail.com"]
            print(emails)
        else:
            emails = [user.email]
            print(emails)
        user_id = db_user.id
        name = user.name
        encoded_url = encoder.dumps(user_id)
        html = f"""<h1> Hello {name}</h1>
                <a href="http://127.0.0.1:8000/verify?path={encoded_url}"> Verify Email here</a>"""

        message = create_message(recipients=emails, subject = "Welcome User", body=html)
        await mail.send_message(message=message)

        request.app.state.redis.setex(encoded_url,300,user_id)

        return JSONResponse(content={"status_code":200,
                                    "msg":"Email sent successfully"},
                            status_code=200)
    
    except AttributeError as e :
        print(e)
        return JSONResponse(content={"status_code":400,
                                     "msg":"Something Went Wrong"},
                            status_code=400)
    

    except Exception as e:
        msg=str(e.orig).split(':')[-1].replace('\n', '').strip()
        return JSONResponse(content={"status_code": 422,
                                     "msg": "Unprocessable Entity",
                                     "detail":msg},
                            status_code=422)



# /login is used to log in to the user database
# it generates a log in token which is a JWT token 
# attaches it to the header of  the response 
# this token is authenticated at the user portal

@router.post('/login',response_model=TokenBase)
async def token_login(form_data: form_dependency, db:db_dependency, request:Request):

    user = authenticateUser(form_data.username, form_data.password, db)
    if not user:
        return JSONResponse(content={"status_code":401,
                                     "msg":"Unauthorized",
                                     "detail":"invalid username/password"},
                            status_code=401)
    
    if not user.is_active:
        return JSONResponse(content={"status_code":"401",
                                     "msg":"Unauthorized",
                                     "detail":"Inactive Account, Verify with valid email"},
                                     status_code=401)
    
    token = create_user_token(user.email, user.id, timedelta(minutes=time_to_live))
    if request.app.state.redis.setex(token, 10000, user.id):
        print("token inserted")
    return JSONResponse(content={"status_code":200,
                                 "msg":"Login Successful"},
                        headers={"x-token":token},
                        status_code=200)


@router.get('/verify')
async def user_verify_path(db: db_dependency, request: Request, path: str):
    try:
        if not request.app.state.redis.exists(path):
            print("galti exists mei hai")
            return JSONResponse(content = {"status_code":401,
                                           "msg":"Invalid Verification URL galti exists mei hai"},
                                status_code=401)
        valid_id=int(request.app.state.redis.get(path).decode("utf-8"))
        decoded_id=encoder.loads(path)
        if valid_id != decoded_id:
            print(valid_id,decoded_id,sep="\n")
            return JSONResponse(content = {"status_code":401,
                                           "msg":"Invalid Verification URL galti matching mei hai"},
                                status_code=401)
        user = db.get(Users, decoded_id)
        token = create_user_token(user.email, user.id, timedelta(minutes=5))
        if request.app.state.redis.setex(token, 300, user.id):
            print("token inserted")
        user.is_active = True
        db.commit()
        return JSONResponse(content={"status_code":200,
                                     "msg":"Login Successful",
                                     "return to home page":""},
                            headers={"x-token":token},
                            status_code=200)
    except BadSignature as e:
            return JSONResponse(content = {"status_code":401,
                                           "msg":"Invalid Verification URL galti signature mei hai"},
                                status_code=401)


@router.post('/verify')
async def user_verify_email(db: db_dependency, request: Request, email: EmailBase):
    user  = db.query(Users).filter(Users.email == email.address).first()
    if not user:
            return JSONResponse(content = {"status_code":401,
                                           "msg":"Invalid Verification email"},
                                status_code=401)
    emails = [email.address]
    name = user.name
    user_id = user.id
    name = user.name
    encoded_url = encoder.dumps(user_id)
    html = f"""<h1> Hello {name}</h1>
            <a href="http://127.0.0.1:8000/verify?path={encoded_url}"> Verify Email here</a>"""

    message = create_message(recipients=emails, subject = "Welcome User", body=html)
    await mail.send_message(message=message)

    request.app.state.redis.setex(encoded_url,300,user_id)

    return JSONResponse(content={"status_code":200,
                                 "msg":"Email sent successfully"},
                        status_code=200)