from fastapi import APIRouter
from fastapi.responses import JSONResponse
from datetime import datetime
from NewFast.NewFast.dependencies import user_dependency, db_dependency
from NewFast.NewFast.base import SalaryBase, SalaryUpdateBase
from NewFast.NewFast.model import Salary, Users

router = APIRouter(tags=["salary"])

# POST:/salary adds the input data
# in the salary table for a 
# correseponding user_id Salary id
#  is generated automatically in the
# database. Only works if the current
# user has admin role 

@router.post("/salary", status_code=400)
async def addSalary(userSalary: SalaryBase, db: db_dependency, curr_user: user_dependency):
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

        user=db.get(Users,userSalary.user_id)

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
            db_salary = Salary(salary=userSalary.salary,
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


# PATCH:/salary is used to 
# update the value of input 
# field inside the Salary table

@router.patch("/salary")
def update_salary(input:SalaryUpdateBase, db: db_dependency, curr_user: user_dependency):
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

        user = db.get(Users, user_id)
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
