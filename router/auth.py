from fastapi import APIRouter, Request
from NewFast.base import RegisterBase, TokenBase
from NewFast.dependencies import db_dependency, form_dependency, bcrypt_context
from fastapi.responses import JSONResponse
from NewFast.model import Users
from datetime import timedelta, datetime
from pydantic import EmailStr
from jose import jwt
from NewFast.setting.config import Config
from NewFast.dependencies import mail, encoder, create_message


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

# if valid password then user token is generated 
def create_user_token(email:str, user_id:int, ttl:timedelta) -> str:
    encode={"sub":email, "id":user_id}
    expires = datetime.now()+ttl
    encode.update({"exp":expires})
    return jwt.encode(encode, secret_key, algorithm=algorithm)


router = APIRouter()
@router.post('/register',status_code=201)
async def user_register(user:RegisterBase, db:db_dependency):
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
        user_id=db_user.id
        name = "name_here"
        encoded_url = encoder.dumps(user_id)
        html = f"""<h1> Hello {name}</h1>
                <a href="http://127.0.0.1:8000/verify?path={encoded_url}"> Verify Email here</a>"""

        message = create_message(recipients=emails, subject = "Welcome User", body=html)
        await mail.send_message(message=message)

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

    # return JSONResponse(content={"status_code":201,
    #                              "user_id": db_user.id,
    #                              "msg": f"user {db_user.name} "
    #                              "has been added successfully."},
    #                     status_code=201)


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
    
    token = create_user_token(user.email, user.id, timedelta(minutes=time_to_live))
    if request.app.state.redis.setex(token, 10000, user.id):
        print("token inserted")
    return JSONResponse(content={"status_code":200,
                                 "msg":"Login Successful"},
                        headers={"x-token":token},
                        status_code=200)


@router.get('/verify')
async def user_verify(path:str, db:db_dependency, request:Request):
    print(email_secret_key, "This is the secret key in verify api", sep = "\n")
    if encoder.loads(path):
        decoded_id=encoder.loads(path)
        user = db.get(Users, decoded_id)
        if user is None:
            return JSONResponse(content = {"status_code":401,
                                            "msg":"Invalid Verification URL"},
                                status_code=401)
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