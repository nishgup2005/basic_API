from typing import Annotated
from fastapi import FastAPI, HTTPException, Depends, Request, Response
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse, PlainTextResponse
from pydantic import BaseModel, EmailStr, ValidationError, field_validator, Field
import model
from database import engine, get_db
from sqlalchemy.orm import session
from datetime import datetime, timedelta
from passlib.context import CryptContext
from secrets import token_hex
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from jose import jwt, JWTError

app = FastAPI()
model.Base.metadata.create_all(bind=engine)
secret_key = token_hex(32)
hash = 'HS256'
time_to_live = 30
bcrypt_context = CryptContext(schemes=['bcrypt'], deprecated='auto')
oauth2_bearer = OAuth2PasswordBearer(tokenUrl='token')

#custom class to validate user information
class UserBase(BaseModel):

    name: str
    email: EmailStr
    password: str
    phone_no: str
    role : str = "user"


#custom class to validate salary information 
class SalaryBase(BaseModel):

    salary: int
    credited_out: datetime = datetime.now()
    credited_by: str = "admin"
    is_partial: bool = False
    user_id: int


class InputBase(BaseModel):
    user_id: int
    field: str
    value: str | int | bool | datetime


class LoginBase(BaseModel):
    email: EmailStr
    password: str


class RegisterBase(BaseModel):
    name: str
    email: EmailStr
    password: str = Field(min_length=10)
    phone_no: str = ""
    role : str = "user"

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
    
class Token(BaseModel):
    access_token: str
    token_type: str

db_dependency = Annotated[session, Depends(get_db)]


# @app.exception_handler(RequestValidationError)
# def validation_exception_handler(request, exc):
#     print(exc)
#     return {"status_code":422,
#     "msg":exc},


# Landing Page
@app.get("/")
async def read_root():
    return {"msg":"Welcome to User Manipulation Backend"}


# /users returns all the users in the database
@app.get("/users")
async def get_user(db: db_dependency):
    results = (
        db.query(model.Users).all()
    )

    if not results:
        return JSONResponse(content={"status_code": 404,
                                     "msg": "No Users Found"},

                            status_code=404)
    
    users=[{"user_id": i.id,
            "name": i.name,
            "salary": (i.salary[0].salary 
                       if i.salary 
                       else None)}
           for i in results ]

    return JSONResponse(content={"status_code": 200,
                                 "users": users,
                                 "msg": f"found {len(results)} user(s)"},
                        status_code=200)

# GET:/user returns the User whos id matches with the input user_id
# It takes the user_id as a path parameter

@app.get("/user/{user_id}", status_code=200)
async def get_user_id(user_id: int, db: db_dependency):
        
    result = (db
            .query(model.Users)
            .filter(model.Users.id==user_id).one_or_none()
            )
    
    if not result:
        return JSONResponse(content={"status_code": 404,
                                     "msg": "User Not Found"},

                            status_code=404)
    
    id = result.id
    name = result.name

    if result.salary:
        salary = result.salary[0].salary

        return JSONResponse(content={"status_code": 200,
                                     "user": {"user_id": id,
                                              "name": name,
                                              "salary": salary},
                                     "msg":f"user {id} found"},
                            
                            status_code=200)

    else:

        return JSONResponse(content={"status_code": 200,
                                     "user": {"user_id": id,
                                              "name": name,
                                              "salary": None},
                                     "msg":f"user {id} found"},
                            
                            status_code=200)

# POST:/user is used to insert user data into the database
# After inserting user data it is important to call POST:/salary
# as well for the inserted user-id

# @app.post('/login',status_code=200)
# async def user_login(user: LoginBase, db: db_dependency):

#     email = user.email
#     password = user.password
#     cUser = (db.query(model.Users)
#             .filter(model.Users.email==email)
#             .first())

#     if (password == cUser[0].password):
#         return JSONResponse(content={"status_code":200,
#                                      "msg":"Login Successful"
#                                      },
#                             headers={"x-user-token":cUser[0].id},
#                             status_code=200)

#     else:
#         return JSONResponse(content={"status_code":401,
#                                      "msg":"Incorrect Username/Password"},
#                             status_code=401)


@app.post('/register',status_code=201)
async def user_register(user:RegisterBase, db:db_dependency):
    try:
        db_user = model.Users(name=user.name,
                            email=user.email,
                            password=bcrypt_context.hash(user.password),
                            phone_no=user.phone_no,
                            role=user.role)

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


@app.post('/login',response_model=Token)
async def token_login(form_data:Annotated[OAuth2PasswordRequestForm,Depends()],db:db_dependency):
    print(form_data.username, form_data.password,sep=" | ")
    user = authenticateUser(form_data.username, form_data.password, db)

    if not user:
        return JSONResponse(content={"status_code":401,
                                     "msg":"Unauthorized",
                                     "detail":"invalid username/password"},
                            status_code=401)
    
    token = create_user_token(user.email, user.id, timedelta(minutes=time_to_live))
    return JSONResponse(content={"status_code":200,
                                 "msg":"Login Successful"},
                        headers={"token":token},
                        status_code=200)


def authenticateUser(email: EmailStr, password:str, db:db_dependency) -> model.Users:
    user = (db.query(model.Users)
            .filter(model.Users.email==email)
            .first())
    if not user:
        return False
    
    if not bcrypt_context.verify(password, user.password):
        return False
    
    return user

def create_user_token(email:str, user_id:int, ttl:timedelta):
    encode={"sub":email, "id":user_id}
    expires = datetime.now()+ttl
    encode.update({"exp":expires})
    print(jwt.encode(encode, secret_key, algorithm=hash))
    return jwt.encode(encode, secret_key, algorithm=hash)


@app.post('/user', status_code=201)
async def create_User(user: UserBase, db: db_dependency):
    try:
        db_user = model.Users(name=user.name,
                              email=user.email,
                              password=user.password,
                              phone_no=user.phone_no,
                              role=user.role)

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


# POST:/salary adds the input data in the salary table for
# a correseponding user_id
# Salary id is generated automatically in the database


@app.post("/salary", status_code=400)
async def addSalary(userSalary: SalaryBase, db: db_dependency):
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

    db_salary = model.Salary(salary=userSalary.salary,
                            credited_out=userSalary.credited_out,
                            credited_by=userSalary.credited_by,
                            is_partial=userSalary.is_partial,
                            user_id=userSalary.user_id)
    db.add(db_salary)
    db.commit()
    db.refresh(db_salary)

    return JSONResponse(content={"status_code": 201,
                                    "salary": {"salary_ID": db_salary.id,
                                            "salary": db_salary.salary,
                                            "user_id": db_salary.user_id},
                                    "msg": f"Salary for user {db_salary.user_id} has been added successfully."
    })

    

# /deleteUser is used to delete a user and their salary
# with the given user_id


@app.delete("/user", status_code=200)
def delete_user(user_id: int, db: db_dependency):
        
        user = db.get(model.Users, user_id)

        if user:
            db.delete(user)
        else :
            return JSONResponse(content={"status_code": 404,
                                     "msg": "User Not Found"},
                                     status_code=404)

        db.commit()

        return JSONResponse(content={"status_code":200,
                                     "user_id": user_id,
                                     "msg":f"user {user_id} has been deleted successfully"},
                                     status_code=200)


# /updateUser is used to update the value of input field inside the User Table


@app.put("/user")
def update_user(input: InputBase, db: db_dependency):

    user_id = input.user_id
    field = input.field
    value = input.value
    
    if field == "id":
        return JSONResponse(content={"status_code": 403,
                                     "msg": "Forbidden",
                                     "detail": "Changing the ID for user is Forbidden"},
                                     status_code=403)

    if not isinstance(value,str):
        return JSONResponse(content={"status_code": 422,
                                     "msg": "Unprocessable Entity",
                                     "detail": "Invalid Input Format for chosen field"},
                                     status_code=422)

    user = db.get(model.Users, user_id)
    if not user:
        return JSONResponse(content={"status_code": 404,
                                     "msg": "User Not Found"},
                                     status_code=404)
    
    if hasattr(user, field):
        before = getattr(user, field)
        setattr(user, field, value)
        db.commit()
        return {

            "status_code":200,
            "before": before,
            "after": getattr(user, field),
            "user_id":user.id,
            "msg": f"Attribute {field} was updated with value {value} for user_id {user_id} successfully"
        }
    else:
        return JSONResponse(content={"status_code": 422,
                                     "msg": "Unprocessable Entity",
                                     "detail": "Field for User does not exist"},
                                     status_code=422)

# /updateSalary is used to update the value of input field
# inside the Salary table


@app.patch("/salary")
def update_salary(input:InputBase, db: db_dependency):

    user_id = input.user_id
    field = input.field
    value = input.value
    invalid_input=False

    
    if field not in ["salary","user_id"] and not isinstance(value,int):
        invalid_input=True
    elif field == "credited_by" and not isinstance(value,str):
        invalid_input=True
    elif field == "credited_out"and not isinstance(value,datetime.isoformat(value)):
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
        return {
            "status_code":200,
            "before": before,
            "after": getattr(salary, field),
            "user_id":user.id,
            "msg": f"Attribute {field} was updated with value {value} for salary with user_id {user_id} successfully"
        }
    else:
        return JSONResponse(content={"status_code": 422,
                                     "msg": "Unprocessable Entity.",
                                     "detail": "Field for Salary does not exist"},
                                     status_code=422)
