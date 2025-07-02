from typing import Annotated
from fastapi import FastAPI, Depends, Request, Response, Header
from fastapi.responses import JSONResponse
from pydantic import BaseModel, EmailStr, field_validator, Field
import model
from database import engine, get_db
from sqlalchemy.orm import session
from datetime import datetime, timedelta
from passlib.context import CryptContext
from secrets import token_hex
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from jose import jwt
from redis import Redis
from contextlib import asynccontextmanager

# asynccontextmanager is a event handler that can be used to
# define functionality before the application is started 
# and after the application has ended
# code before yield statement is executed before the app starts
# code after the yield statement is executed after the app ends

@asynccontextmanager
async def lifespan(app:FastAPI):
    app.state.redis = Redis(host='localhost', port=6379)
    yield
    app.state.redis.close()

# the lifespan function defined above is passed in the lifetime 
# parameter of the app 

app = FastAPI(lifespan=lifespan)
model.Base.metadata.create_all(bind=engine)

# secret key is used hash the data
# the token hex function from secrets module takes an input n 
# and returns random 32 byte string which can be used as a secret key

secret_key = token_hex(32)
hash = 'HS256'

# time_to_live is the time defined after which a token will expire
time_to_live = 30

# bcrypt context is used for encryption
bcrypt_context = CryptContext(schemes=['bcrypt'], deprecated='auto')

# oauth2 is security framework.
# OAuth2PasswordBearer is a security measure provided by the 
# fastAPI framework to enbale secure authentication procedures ('flows') 
oauth2_bearer = OAuth2PasswordBearer(tokenUrl='token')

#custom class to validate user information
class UserBase(BaseModel):

    name: str
    email: EmailStr
    password: str
    phone_no: str


#custom class to validate salary information 
class SalaryBase(BaseModel):

    salary: int
    credited_out: datetime = datetime.now()
    credited_by: str = "admin"
    is_partial: bool = False
    user_id: int

# custom class to validate input for user updation
class UserUpdateBase(BaseModel):

    field: str
    value: str | int | bool | datetime

# custom class to validate input for salary updation
class SalaryUpdateBase(BaseModel):

    user_id:int
    field: str
    value: str | int | bool | datetime

class DeleteBase(BaseModel):
    user_id:int

# custom class to validate input for login
class LoginBase(BaseModel):
    email: EmailStr
    password: str = Field(min_length=10)

    @field_validator('password', mode='after')
    @classmethod
    def validate_password(cls, value:str):
        uprcnt=0
        lwrcnt=0
        spclcnt=0
        for i in value:
            if i.isupper():
                uprcnt+=1
            if i.islower():
                lwrcnt+=1
            if not i.isalnum():
                spclcnt+=1
        if not(uprcnt >= 1):
            raise ValueError("password must have atleast 1 uppercase letter")
        if not(lwrcnt >= 1):
            raise ValueError("password must have atleast 1 lowercase letter")
        if not(spclcnt >= 1):
            raise ValueError("password must have atleast 1 special character")
        
        return value


# custom class to validate input for registration 
class RegisterBase(BaseModel):
    name: str
    email: EmailStr
    password: str = Field(min_length=10)
    phone_no: str = ""

    @field_validator('password', mode='after')
    @classmethod
    def validate_password(cls, value:str):
        uprcnt=0
        lwrcnt=0
        spclcnt=0
        for i in value:
            if i.isupper():
                uprcnt+=1
            if i.islower():
                lwrcnt+=1
            if not i.isalnum():
                spclcnt+=1
        if not(uprcnt >= 1):
            raise ValueError("password must have atleast 1 uppercase letter")
        if not(lwrcnt >= 1):
            raise ValueError("password must have atleast 1 lowercase letter")
        if not(spclcnt >= 1):
            raise ValueError("password must have atleast 1 special character")
        
        return value

# custom class to access a token
class Token(BaseModel):
    access_token: str
    token_type: str

db_dependency = Annotated[session, Depends(get_db)]

async def get_user_token(x_token: Annotated[str, Header()] = None):
    return x_token

async def get_curr_user(token:Annotated[str,Depends(get_user_token)], db:db_dependency):
    if not token:
        return JSONResponse(content={"status_code":401,
                                     "msg":"Unauthorized",
                                     "detail":"Invalid Token"},
                            status_code=401)

    if not app.state.redis.exists(token):
        return JSONResponse(content={"status_code":401,
                                     "msg":"Unauthorized",
                                     "detail":"Invalid Token"},
                            status_code=401)
    user_id = app.state.redis.get(token).decode('UTF-8')
    # app.state.redis.setex(token, 1000, user_id)
    user = db.get(model.Users,user_id)
    return user

@app.get("/test")


# Landing Page
@app.get("/")
async def read_root():
    return {"msg":"Welcome to User Manipulation Backend"}


# /users returns all the users in the database
@app.get("/users")
async def get_users(db: db_dependency):
    all_users = (
        db.query(model.Users).all()
    )

    if not all_users:
        return JSONResponse(content={"status_code": 404,
                                     "msg": "No Users Found"},

                            status_code=404)
    
    users=[{"user_id": i.id,
            "name": i.name,
            "salary": (i.salary[0].salary 
                       if i.salary 
                       else None)}
           for i in all_users ]

    return JSONResponse(content={"status_code": 200,
                                 "users": users,
                                 "msg": f"found {len(users)} user(s)"},
                        status_code=200)


# GET:/user returns the User whos session is currently logged
# session management is performed using tokens 
@app.get("/user", status_code=200)
async def get_user(curr_user: Annotated[model.Users, Depends(get_curr_user)]):

    if not curr_user:
        return JSONResponse(content={"status_code": 404,
                                     "msg": "User Not Found"},
                            status_code=404)

    if curr_user.salary:
        salary = curr_user.salary[0].salary
        return JSONResponse(content={"status_code": 200,
                                     "user": {"user_id": curr_user.id,
                                              "name": curr_user.name,
                                              "salary": salary},
                                     "msg":f"user {curr_user.id} found"},
                            status_code=200)

    else:
        return JSONResponse(content={"status_code": 200,
                                     "user": {"user_id": curr_user.id,
                                              "name": curr_user.name,
                                              "salary": None},
                                     "msg":f"user {curr_user.id} found"},
                            status_code=200)


# /register is used to register new users 
@app.post('/register',status_code=201)
async def user_register(user:RegisterBase, db:db_dependency):
    try:
        db_user = model.Users(name=user.name,
                            email=user.email,
                            password=bcrypt_context.hash(user.password),
                            phone_no=user.phone_no,
                            role="user")

        db.add(db_user)
        db.commit()
        db.refresh(db_user)


    except Exception as e:
        msg=str(e.orig).split(':')[-1].replace('\n', '').strip()
        return JSONResponse(content={"status_code": 422,
                                     "msg": "Unprocessable Entity",
                                     "detail":msg},
                            status_code=422)

    return JSONResponse(content={"status_code":201,
                                 "user_id": db_user.id,
                                 "msg": f"user {db_user.name} "
                                 "has been added successfully."},
                        status_code=201)


# /login is used to log in to the user database
# it generates a log in token which is a JWT token 
# attaches it to the header of  the response 
# this token is authenticated at the user portal
@app.post('/login',response_model=Token)
async def token_login(form_data: Annotated[OAuth2PasswordRequestForm,Depends()], db:db_dependency):

    user = authenticateUser(form_data.username, form_data.password, db)
    if not user:
        return JSONResponse(content={"status_code":401,
                                     "msg":"Unauthorized",
                                     "detail":"invalid username/password"},
                            status_code=401)
    
    token = create_user_token(user.email, user.id, timedelta(minutes=time_to_live))
    if app.state.redis.setex(token, 10000, user.id):
        print("token inserted")
    return JSONResponse(content={"status_code":200,
                                 "msg":"Login Successful"},
                        headers={"x-token":token},
                        status_code=200)


# authenticate the user with the a valid password 
def authenticateUser(email: EmailStr, password:str, db:db_dependency) -> model.Users:
    user = (db.query(model.Users)
            .filter(model.Users.email==email)
            .first())
    if not user:
        return False

    if not bcrypt_context.verify(password, user.password):
        return False
    
    return user

# if valid password then user token is generated 
def create_user_token(email:str, user_id:int, ttl:timedelta):
    encode={"sub":email, "id":user_id}
    expires = datetime.now()+ttl
    encode.update({"exp":expires})
    return jwt.encode(encode, secret_key, algorithm=hash)


# POST:/user is used to insert user data into the database
@app.post('/user', status_code=201)
async def create_User(user: RegisterBase, db: db_dependency, curr_user: Annotated[model.Users, Depends(get_curr_user)]):

    # checks if the current user has admin access
    if curr_user.role=="admin":
        try:
            db_user = model.Users(name=user.name,
                                  email=user.email,
                                  password=bcrypt_context.hash(user.password),
                                  phone_no=user.phone_no,
                                  role="user")

            db.add(db_user)
            db.commit()
            db.refresh(db_user)


        except Exception as e:
            msg=str(e.orig).split(':')[-1].replace('\n', '').strip()
            return JSONResponse(content={"status_code": 422,
                                        "msg": "Unprocessable Entity",
                                        "detail":msg},
                                
                                status_code=422)
        

        return JSONResponse(content={"status_code":201,
                                    "user_id": db_user.id,
                                    "msg": f"user {db_user.name} "
                                    "has been added successfully."},
                            status_code=201)
    else:
        return JSONResponse(content={"status_code":401,
                                     "msg":"Unauthorized",
                                     "detail":"User is not authorized to create user"},
                            status_code=401)


# POST:/salary adds the input data in the salary table for
# a correseponding user_id
# Salary id is generated automatically in the database
@app.post("/salary", status_code=400)
async def addSalary(userSalary: SalaryBase, db: db_dependency, curr_user: Annotated[model.Users, Depends(get_curr_user)]):

    # checks if the current user has admin access
    if curr_user.role=="admin":

        user=db.get(model.Users,userSalary.user_id)

        if not user:
            return JSONResponse(content={"status_code": 404,
                                        "msg": "User Not Found"},
                                status_code=404)
        
        if user.salary:
                return JSONResponse(content={"status_code": 422,
                                            "msg": "Unprocessable Entity",
                                            "detail":"Salary for this user exists"},
                                    status_code=422)
        
        try:
            db_salary = model.Salary(salary=userSalary.salary,
                                    credited_out=userSalary.credited_out,
                                    credited_by=userSalary.credited_by,
                                    is_partial=userSalary.is_partial,
                                    user_id=userSalary.user_id)
            db.add(db_salary)
            db.commit()
            db.refresh(db_salary)

        except Exception as e:
            msg=str(e.orig).split(':')[-1].replace('\n', '').strip()
            return JSONResponse(content={"status_code": 422,
                                        "msg": "Unprocessable Entity",
                                        "detail":msg},
                                
                                status_code=422)

        return JSONResponse(content={"status_code": 201,
                                        "salary": {"salary_ID": db_salary.id,
                                                "salary": db_salary.salary,
                                                "user_id": db_salary.user_id},
                                        "msg": f"Salary for user {db_salary.user_id} has been added successfully."},
                            status_code=201)
    
    else:
        return JSONResponse(content={"status_code":401,
                                     "msg":"Unauthorized",
                                     "detail":"User is not authorized to create salary"},
                            status_code=401)

    

# /deleteUser is used to delete a user and their salary
# with the given user_id
@app.delete("/user", status_code=200)
def delete_user(input: DeleteBase, db: db_dependency, curr_user: Annotated[model.Users, Depends(get_curr_user)]):

    # checks if the current user has admin access
    if curr_user.role=="admin":
        user = db.get(model.Users, input.user_id)

        if not user:
            return JSONResponse(content={"status_code": 404,
                                     "msg": "User Not Found"},
                                status_code=404)
        if user.role == "admin":
            return JSONResponse(content={"status_code": 403,
                                     "msg": "Forbidden",
                                     "detail": "Deleteing the admin ID is Forbidden"},
                            status_code=403)
        db.delete(user)
        db.commit()
        return JSONResponse(content={"status_code":200,
                                     "user_id": input.user_id,
                                     "msg":f"user {input.user_id} has been deleted successfully"},
                            status_code=200)

    else:
        return JSONResponse(content={"status_code":401,
                                     "msg":"Unauthorized",
                                     "detail":"User is not authorized to create salary"},
                            status_code=401)


# /updateUser is used to update the value of input field inside the User Table
@app.put("/user")
def update_user(input: UserUpdateBase, curr_user: Annotated[model.Users, Depends(get_curr_user)], db: db_dependency):

    if not curr_user:
        return JSONResponse(content={"status_code": 404,
                                     "msg": "User Not Found"},
                            status_code=404)

    field = input.field.lower()
    value = input.value
    
    if field == "id":
        return JSONResponse(content={"status_code": 403,
                                     "msg": "Forbidden",
                                     "detail": "Changing the ID for user is Forbidden"},
                            status_code=403)
    
    if field == "role":
        return JSONResponse(content={"status_code": 403,
                                     "msg": "Forbidden",
                                     "detail": "Changing the Role for user is Forbidden"},
                            status_code=403)
    
    if field == "salary":
        return JSONResponse(content={"status_code": 422,
                                     "msg": "Unprocessable Entity",
                                     "detail": "Salary cannot be changed through user table"},
                            status_code=422)

    if not isinstance(value,str):
        return JSONResponse(content={"status_code": 422,
                                     "msg": "Unprocessable Entity",
                                     "detail": "Invalid Input Format for chosen field"},
                            status_code=422)
    
    if field == "password":
        value = bcrypt_context.hash(value)


    
    if hasattr(curr_user, field):
        before = getattr(curr_user, field)
        setattr(curr_user, field, value)
        db.commit()
        return {

            "status_code":200,
            "before": before,
            "after": getattr(curr_user, field),
            "user_id":curr_user.id,
            "msg": f"Attribute {field} was updated with value {value} for user_id {curr_user.id} successfully"
        }
    else:
        return JSONResponse(content={"status_code": 422,
                                     "msg": "Unprocessable Entity",
                                     "detail": "Field for User does not exist"},
                            status_code=422)

# /updateSalary is used to update the value of input field
# inside the Salary table


@app.patch("/salary")
def update_salary(input:SalaryUpdateBase, db: db_dependency, curr_user: Annotated[model.Users, Depends(get_curr_user)]):
    
    # checks if the current user has admin access
    if curr_user.role=="admin":
        user_id = input.user_id
        field = input.field.lower()
        value = input.value
        invalid_input=False

        if field == "id":
            return JSONResponse(content={"status_code": 403,
                                        "msg": "Forbidden",
                                        "detail": "Changing the ID for salary is Forbidden"},
                                status_code=403)

        if field in ["salary","user_id"] and not isinstance(value,int):
            invalid_input=True
        elif field == "credited_by" and not isinstance(value,str):
            invalid_input=True
        elif field == "credited_out":
            try:
                value = datetime.isoformat(value)
            except Exception as e:
                invalid_input=True
        elif field == "is_partial" and not isinstance(value,bool):
            invalid_input=True

        if invalid_input:
            return JSONResponse(content={"status_code": 422,
                                        "msg": "Unprocessable Entity.",
                                        "detail": "Invalid Input Format for chosen Field"},
                                status_code=422)

        user = db.get(model.Users, user_id)
        if not user:
            return JSONResponse(content={"status_code": 404,
                                        "msg": "User Not Found"},
                                status_code=404)
        if not user.salary:
            return JSONResponse(content={"status_code": 422,
                                        "msg": "Unprocessable Entity.",
                                        "detail": "Salary for User does not exist"},
                                status_code=422)
        
        salary = user.salary[0]

        if hasattr(salary, field):
            before = getattr(salary, field)
            setattr(salary, field, value)
            db.commit()
            return JSONResponse(content={"status_code":200,
                                         "before": before,
                                         "after": getattr(salary, field),
                                         "user_id":user.id,
                                         "msg": f"Attribute {field} was updated with value {value} for salary with user_id {user_id} successfully"},
                                status_code=200)
        else:
            return JSONResponse(content={"status_code": 422,
                                        "msg": "Unprocessable Entity.",
                                        "detail": "Field for Salary does not exist"},
                                status_code=422)

    else:
        return JSONResponse(content={"status_code":401,
                                     "msg":"Unauthorized",
                                     "detail":"User is not authorized to create salary"},
                            status_code=401)
