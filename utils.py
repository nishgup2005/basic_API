from fastapi import Request
from pydantic import EmailStr
from NewFast.dependencies import encoder, mail, template
from fastapi_mail import MessageSchema, MessageType
from typing import Dict, Any


# Email Dependency Requirements

async def verify_mail(email: EmailStr, user_id: int, name: str, request: Request):

    # sending email with user id encoded
    encoded_url = encoder.dumps(user_id)
    verify_link = request.url_for('user_verify',encoded_url=encoded_url)
    body = {"name":name,
            "verify_link":verify_link}
    message = MessageSchema(
        recipients=email, subject="Welcome User", template_body=body, subtype=MessageType.html)
    await mail.send_message(message=message, template_name='verify_mail.html')

    # adding url to redis for url management
    request.app.state.redis.setex(encoded_url, 300, user_id)


async def reset_pass_mail(email: EmailStr, user_id: int, name: str, request: Request):
    encoded_url = encoder.dumps(user_id)
    reset_link = request.url_for('new_password', encoded_url=encoded_url)
    body = {
        "name":name,
        "reset_link":reset_link
    }
    # html = f"""<h1> Hello {name}</h1>
    #         <a href="http://127.0.0.1:8000/password/{encoded_url}"> Verify Email here</a>"""
    message = MessageSchema(
        recipients=email, subject="Password Reset Mail", template_body=body, subtype=MessageType.html)
    await mail.send_message(message=message, template_name='reset_mail.html')

    # adding url to redis for url management
    request.app.state.redis.setex(encoded_url, 300, user_id)
