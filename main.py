from typing import Annotated
from fastapi import FastAPI, HTTPException, Depends
from fastapi.responses import JSONResponse
from pydantic import BaseModel
import model
from database import engine, get_db
from sqlalchemy.orm import session
from datetime import datetime

app = FastAPI()
model.Base.metadata.create_all(bind=engine)


#custom class to validate user information
class UserBase(BaseModel):

    name: str
    email: str
    password: str
    phone_no: str
    salary: int = 0
    credited_out: datetime = datetime.now()
    credited_by: str = "admin"
    is_partial: bool = False


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


db_dependency = Annotated[session, Depends(get_db)]


# Landing Page
@app.get("/")
def read_root():
    return {"msg":"Welcome to User Manipulation Backend"}


# /users returns all the users in the database
@app.get("/users")
async def get_user(db: db_dependency):
    results = (
        db.query(model.Users).all()
    )
    print(results)

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


@app.post('/user', status_code=201)
async def create_User(user: UserBase, db: db_dependency):
    try:

        db_user = model.Users(name=user.name,
                            email=user.email,
                            password=user.password,
                            phone_no=user.phone_no)

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
    try:
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

    except Exception as e:
        return JSONResponse(content={"status_code": 404,
                                     "msg": "User Not Found"},
                                     status_code=404)

    

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
