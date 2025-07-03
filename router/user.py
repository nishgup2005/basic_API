from typing import Annotated
from fastapi import APIRouter, Depends, Header, Request
from ..database import get_db
from sqlalchemy.orm import session
from fastapi.responses import JSONResponse
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from ..model import Users
from ..base import RegisterBase, UserUpdateBase, DeleteBase, TokenBase
from jose import jwt
from datetime import datetime, timedelta
from pydantic import EmailStr
from passlib.context import CryptContext
from NewFast.setting.config import Config
from ..dependencies import user_dependency, form_dependency, db_dependency, bcrypt_context

router = APIRouter()

# secret key is used hash the data
# the token hex function from secrets module takes an input n 
# and returns random 32 byte string which can be used as a secret key

secret_key = Config.SECRET_KEY
hash = 'HS256'

# time_to_live is the time defined after which a token will expire
time_to_live = 30


# Base router leads to landing page
@router.get("/")
async def read_root():
    return {"msg":"Welcome to User Manipulation Backend"}

# /users returns all the users in the database
@router.get("/users")
async def get_users(db: db_dependency):
    all_users = (
        db.query(Users).all()
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


# GET:/user returns the User whos session
# is currently logged session management 
# is performed using tokens. Works for both
# admin and user roles 

@router.get("/user", status_code=200)
async def get_user(curr_user: user_dependency):
    if not curr_user:
        return JSONResponse(content={"status_code": 404,
                                     "msg": "User Not Found"},
                            status_code=404)
    
    if curr_user=="invalid_token":
        return JSONResponse(content={"status_code":401,
                                     "msg":"Unauthorized",
                                     "detail":"Invalid Token"},
                            status_code=401)        

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



# POST:/user is used to insert user data
# into the database only works if the 
# current user has admin access 

@router.post('/user', status_code=201)
async def create_User(user: RegisterBase, db: db_dependency, curr_user: user_dependency):
    if not curr_user:
        return JSONResponse(content={"status_code": 404,
                                     "msg": "User Not Found"},
                            status_code=404)
    
    if curr_user=="invalid_token":
        return JSONResponse(content={"status_code":401,
                                     "msg":"Unauthorized",
                                     "detail":"Invalid Token"},
                            status_code=401)         
    # checks if the current user has admin access
    if curr_user.role=="admin":
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


        except Exception as e:
            msg=str(e.orig).split(':')[-1].replace('\n', '').strip()
            return JSONResponse(content={"status_code": 422,
                                        "msg": "Unprocessable Entity",
                                        "detail":msg},
                                status_code=422)
        

        return JSONResponse(content={"status_code":201,
                                    "user_id": db_user.id,
                                    "msg": f"user {db_user.name} "
                                    "has been added successfully. Verify Email to activate User"},
                            status_code=201)
    else:
        return JSONResponse(content={"status_code":401,
                                     "msg":"Unauthorized",
                                     "detail":"User is not authorized to create user"},
                            status_code=401)


# DELETE /user used to delete a certain user
# only works if the current user has admin role 
# takes user id in the requet body 

@router.delete("/user", status_code=200)
def delete_user(input: DeleteBase, db: db_dependency, curr_user: user_dependency):
    if not curr_user:
        return JSONResponse(content={"status_code": 404,
                                     "msg": "User Not Found"},
                            status_code=404)
    
    if curr_user=="invalid_token":
        return JSONResponse(content={"status_code":401,
                                     "msg":"Unauthorized",
                                     "detail":"Invalid Token"},
                            status_code=401)     
    # checks if the current user has admin access
    if curr_user.role=="admin":
        user = db.get(Users, input.user_id)

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


# PUT /user is used to update the value of input
# field inside the User Table only works if the 
# current user has admin role 

@router.put("/user")
def update_user(input: UserUpdateBase, curr_user: user_dependency, db: db_dependency):
    if not curr_user:
        return JSONResponse(content={"status_code": 404,
                                     "msg": "User Not Found"},
                            status_code=404)
    
    if curr_user=="invalid_token":
        return JSONResponse(content={"status_code":401,
                                     "msg":"Unauthorized",
                                     "detail":"Invalid Token"},
                            status_code=401)

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
