from fastapi import FastAPI
from .model import Base
from .database import engine
from .router import auth, salary, user
from redis import Redis, ConnectionPool
from contextlib import asynccontextmanager

# asynccontextmanager is a event handler that can be used to
# define functionality before the application is started 
# and after the application has ended
# code before yield statement is executed before the app starts
# code after the yield statement is executed after the app ends

# the lifespan function defined above is passed in the lifetime 
# parameter of the app 

@asynccontextmanager
async def lifespan(app:FastAPI):
    app.state.redis = Redis(connection_pool=ConnectionPool(host='localhost', port=6379))
    yield
    app.state.redis.close()


app = FastAPI(lifespan=lifespan)
app.include_router(salary.router)
app.include_router(user.router)
app.include_router(auth.router)
Base.metadata.create_all(bind=engine)