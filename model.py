from sqlalchemy.orm import declarative_base
from sqlalchemy import Column, Integer, String, DateTime, Boolean, ForeignKey
from sqlalchemy.orm import relationship

Base = declarative_base()


class Users(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True, nullable=False, index=True)
    name = Column(String, nullable=False)
    email = Column(String, nullable=False)
    password = Column(String, nullable=False)
    phone_no = Column(String,  nullable=False)
    salary = relationship("Salary", back_populates="user", cascade="all, delete-orphan")


class Salary(Base):
    __tablename__ = "salary"
    id = Column(Integer, primary_key=True, nullable=False, index=True)
    salary = Column(Integer, nullable=False)
    credited_out = Column(DateTime, nullable=False)
    credited_by = Column(String, nullable=False)
    is_partial = Column(Boolean, nullable=False, default=False)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False, unique=True, onupdate="CASCADE")
    user = relationship("Users", back_populates="salary")
