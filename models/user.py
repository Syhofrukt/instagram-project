from pydantic import BaseModel, Field, validator


class RegistrationModel(BaseModel):
    login: str = Field(min_length=5)
    password: str = Field(min_length=8)

    @validator("login")
    def validate_login(cls, login: str) -> None:
        assert " " not in login, "It's not allowed to put space in login"
        return login


class BaseUserModel(BaseModel):
    id: str
    login: str


class UserModel(BaseUserModel):
    followers: int
    follows: int
