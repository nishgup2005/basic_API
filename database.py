from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

SQLALCHEMY_DATABASE_URL = 'postgresql://postgres:1234@localhost:5432'
db = 'company'
engine = create_engine(SQLALCHEMY_DATABASE_URL)
session = sessionmaker(autocommit=False, autoflush=False, bind=engine)

# get db function used to safely get a database connection
def get_db():
    db = session()
    try:
        yield db
    finally:
        db.close()
