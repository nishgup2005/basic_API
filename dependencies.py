from typing import Annotated
from sqlalchemy.orm import session
from .database import get_db
from fastapi import Depends, Header
from fastapi.responses import JSONResponse
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from .model import Users, Salary
from .main import app

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
    user = db.get(Users,user_id)
    return user



user_dependency = Annotated[Users, Depends(get_curr_user)]

form_dependency = Annotated[OAuth2PasswordRequestForm,Depends()]