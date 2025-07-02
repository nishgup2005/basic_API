from pydantic import BaseModel, EmailStr, field_validator, Field
from datetime import datetime

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
