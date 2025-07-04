from pydantic_settings import BaseSettings, SettingsConfigDict

class Settings (BaseSettings):
    SQLALCHEMY_DATABASE_URL :str 
    SECRET_KEY: str
    HASH : str
    TIME_TO_LIVE : int = 30
    EMAIL_SECRET_KEY : str
    MAIL_USERNAME : str
    MAIL_PASSWORD : str
    MAIL_FROM : str
    MAIL_PORT: int
    MAIL_SERVER : str
    MAIL_FROM_NAME: str
    MAIL_STARTTLS :bool = True
    MAIL_SSL_TLS : bool= False
    USE_CREDENTIALS : bool = True
    VALIDATE_CERTS : bool = True

    model_config=SettingsConfigDict(env_file=".env", extra="ignore")

Config = Settings()