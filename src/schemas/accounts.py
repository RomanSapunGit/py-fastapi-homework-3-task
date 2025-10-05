from pydantic import BaseModel, EmailStr, field_validator
import re


# Write your code here
class UserBase(BaseModel):
    email: EmailStr


class UserRegistrationRequestSchema(UserBase):
    password: str

    @field_validator("password")
    @classmethod
    def validate_password(cls, value: str) -> str:
        if len(value) < 8:
            raise ValueError("Password must contain at least 8 characters.")
        if not re.search(r"[a-z]", value):
            raise ValueError("Password must contain at least one lower letter.")
        if not re.search(r"[A-Z]", value):
            raise ValueError("Password must contain at least one uppercase letter.")
        if not re.search(r"[0-9]", value):
            raise ValueError("Password must contain at least one digit.")
        if not re.search(r"[^a-zA-Z0-9]", value):
            raise ValueError("Password must contain at least one special character: @, $, !, %, *, ?, #, &.")
        return value


class UserRegistrationResponseSchema(UserBase):
    id: int

    class Config:
        from_attributes = True


class Token(BaseModel):
    access_token: str
    token_type: str


class UserLoginRequestSchema(UserBase):
    password: str


class UserToken(UserBase):
    token: str


class PasswordResetRequestSchema(UserBase):
    pass


class TokenRefreshRequestSchema(BaseModel):
    refresh_token: str


class TokenRefreshResponseSchema(BaseModel):
    access_token: str


class UserLoginResponseSchema(
    TokenRefreshRequestSchema,
    TokenRefreshResponseSchema
):
    token_type: str


class PasswordResetCompleteRequestSchema(UserToken, UserLoginRequestSchema):
    pass


class MessageResponseSchema(BaseModel):
    message: str


class UserActivationRequestSchema(UserToken):
    pass
