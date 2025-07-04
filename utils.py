from fastapi import Request
from pydantic import EmailStr
from NewFast.dependencies import encoder, mail
from fastapi_mail import MessageSchema, MessageType

# Email Dependency Requirements


def create_message(recipients: list[EmailStr], subject: str, body: str) -> MessageSchema:
    message = MessageSchema(
        recipients=recipients, subject=subject, body=body, subtype=MessageType.html)
    return message


async def verify_mail(email: EmailStr, user_id: int, name: str, request: Request):

    # sending email with user id encoded
    encoded_url = encoder.dumps(user_id)
    html = f"""<h1> Hello {name}</h1>
            <a href="http://127.0.0.1:8000/verify?path={encoded_url}"> Verify Email here</a>"""

    message = create_message(
        recipients=email, subject="Welcome User", body=html)
    await mail.send_message(message=message)

    # adding url to redis for url management
    request.app.state.redis.setex(encoded_url, 300, user_id)


async def reset_pass_mail(email: EmailStr, user_id: int, name: str, request: Request):
    encoded_url = encoder.dumps(user_id)
    html = f"""<h1> Hello {name}</h1>
            <a href="http://127.0.0.1:8000/password/{encoded_url}"> Verify Email here</a>"""

    message = create_message(
        recipients=email, subject="Welcome User", body=html)
    await mail.send_message(message=message)

    # adding url to redis for url management
    request.app.state.redis.setex(encoded_url, 300, user_id)
