from datetime import datetime, timezone, timedelta

from distlib import logger
from fastapi import APIRouter, Depends, HTTPException
from fastapi.security import OAuth2PasswordBearer
from sqlalchemy import select
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.ext.asyncio import AsyncSession
from starlette import status

from config import get_jwt_auth_manager
from database import (
    get_db,
    UserModel,
    UserGroupModel,
    UserGroupEnum,
    ActivationTokenModel,
    PasswordResetTokenModel,
    RefreshTokenModel
)
from exceptions import InvalidTokenError, TokenExpiredError
from schemas.accounts import (
    UserRegistrationRequestSchema,
    UserBase,
    TokenRefreshRequestSchema,
    TokenRefreshResponseSchema,
    UserLoginRequestSchema,
    PasswordResetCompleteRequestSchema,
    MessageResponseSchema,
    UserActivationRequestSchema,
    UserRegistrationResponseSchema
)
from security.passwords import hash_password, verify_password
from security.token_manager import JWTAuthManager
from security.utils import generate_secure_token

router = APIRouter()
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="login")


# Write your code here
@router.post(
    path="/register/",
    response_model=UserRegistrationResponseSchema,
    status_code=status.HTTP_201_CREATED
)
async def register(user: UserRegistrationRequestSchema, db: AsyncSession = Depends(get_db)):
    existing_user = await get_user_by_email(db, str(user.email))
    if existing_user:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"A user with this email {user.email} already exists."
        )

    hashed = hash_password(user.password)

    try:
        db_group = await db.execute(select(UserGroupModel).where(UserGroupModel.name == UserGroupEnum.USER))

        db_user = UserModel(email=str(user.email), _hashed_password=hashed, group=db_group.scalar())
        db.add(db_user)
        await db.flush()
        token = generate_secure_token(16)
        activation_token = ActivationTokenModel(
            user=db_user,
            token=token,
            expires_at=(datetime.now(timezone.utc) + timedelta(hours=2))
            .replace(tzinfo=timezone.utc),
            user_id=db_user.id
        )
        db.add(activation_token)
        await db.commit()
        await db.refresh(db_user)
    except SQLAlchemyError as e:
        await db.rollback()
        logger.error(f"DB error during user creation: {e}")
        raise HTTPException(500, detail="An error occurred during user creation.")
    return db_user


@router.post(path="/activate/")
async def activate_user(user_token: UserActivationRequestSchema, db: AsyncSession = Depends(get_db)):
    existing_user = await get_user_by_email(db, str(user_token.email))
    if not existing_user:
        raise HTTPException(
            status_code=409,
            detail=f"A user with this email {user_token.email} not exist."
        )
    if existing_user.is_active:
        raise HTTPException(
            status_code=400,
            detail="User account is already active."
        )
    db_token = await db.execute(
        select(ActivationTokenModel)
        .where(ActivationTokenModel.user == existing_user)
    )
    db_token = db_token.scalar_one_or_none()
    if not db_token or db_token.expires_at < datetime.now(timezone.utc):
        raise HTTPException(
            status_code=400,
            detail="Invalid or expired activation token."
        )
    existing_user.is_active = True
    await db.delete(db_token)
    await db.commit()
    return {"message": "User account activated successfully."}


@router.post(path="/password-reset/request/")
async def reset_password(user: UserBase, db: AsyncSession = Depends(get_db)):
    existing_user = await get_user_by_email(db, str(user.email))
    if existing_user and existing_user.is_active:
        db_tokens = await db.execute(
            select(PasswordResetTokenModel)
            .where(PasswordResetTokenModel.user == existing_user)
        )
        for token in db_tokens.scalars().all():
            await db.delete(token)
        token = generate_secure_token(16)
        db_token = PasswordResetTokenModel(
            user=existing_user,
            token=token,
            expires_at=(datetime.now(timezone.utc) + timedelta(hours=2))
            .replace(tzinfo=timezone.utc),
            user_id=existing_user.id
        )
        db.add(db_token)
        await db.commit()
    return {"message": "If you are registered, you will receive an email with instructions."}


@router.post(path="/reset-password/complete/", response_model=MessageResponseSchema)
async def complete_reset_password(
        token: PasswordResetCompleteRequestSchema,
        db: AsyncSession = Depends(get_db)
):
    existing_user = await get_user_by_email(db, str(token.email))
    if not existing_user:
        raise HTTPException(
            status_code=400,
            detail="Invalid email or token."
        )

    db_token = await db.execute(select(PasswordResetTokenModel).where(PasswordResetTokenModel.user == existing_user))
    db_token = db_token.scalar_one_or_none()
    if not db_token:
        raise HTTPException(
            status_code=400,
            detail="Invalid email or token."
        )

    if db_token.token != token.token or db_token.expires_at < datetime.now(timezone.utc):
        await db.delete(db_token)
        await db.commit()
        raise HTTPException(
            status_code=400,
            detail="Invalid email or token."
        )
    existing_user.password = token.password
    await db.delete(db_token)

    try:
        await db.commit()
    except SQLAlchemyError:
        await db.rollback()
        raise HTTPException(
            status_code=500,
            detail="An error occurred while resetting the password."
        )
    return {"message": "Password reset successfully."}


@router.post(
    path="/login/",
    status_code=status.HTTP_201_CREATED
)
async def login(
        user: UserLoginRequestSchema,
        db: AsyncSession = Depends(get_db),
        jwt_manager: JWTAuthManager = Depends(get_jwt_auth_manager)
):
    existing_user = await get_user_by_email(db, str(user.email))

    if not existing_user or not verify_password(
            user.password,
            existing_user._hashed_password
    ):
        raise HTTPException(
            status_code=401,
            detail="Invalid email or password."
        )
    if not existing_user.is_active:
        raise HTTPException(
            status_code=403,
            detail="User account is not activated."
        )
    refresh_token_result = jwt_manager.create_refresh_token(data={
        "user_id": existing_user.id},
        expires_delta=timedelta(hours=3)
    )

    db_refresh_token = RefreshTokenModel.create(
        user_id=existing_user.id,
        token=refresh_token_result,
        days_valid=7
    )

    access_token = jwt_manager.create_access_token(data={
        "user_id": existing_user.id},
        expires_delta=timedelta(hours=3)
    )
    try:
        db.add(db_refresh_token)
        await db.commit()
    except SQLAlchemyError:
        raise HTTPException(
            status_code=500,
            detail="An error occurred while processing the request."
        )
    return {
        "access_token": access_token,
        "refresh_token": refresh_token_result,
        "token_type": "bearer"
    }


@router.post(
    path="/refresh/",
    response_model=TokenRefreshResponseSchema,
)
async def refresh_token(
        token: TokenRefreshRequestSchema,
        db: AsyncSession = Depends(get_db),
        jwt_manager: JWTAuthManager = Depends(get_jwt_auth_manager)
):
    try:
        decoded_token = jwt_manager.decode_refresh_token(token.refresh_token)
    except InvalidTokenError:
        raise HTTPException(
            status_code=400,
            detail="Refresh token is incorrect."
        )
    except TokenExpiredError:
        raise HTTPException(
            status_code=400,
            detail="Token has expired."
        )

    db_token = await db.execute(select(RefreshTokenModel).where(RefreshTokenModel.token == token.refresh_token))
    db_token = db_token.scalar_one_or_none()
    if not db_token:
        raise HTTPException(
            status_code=401,
            detail="Refresh token not found."
        )
    existing_user = await db.execute(
        select(UserModel).where(UserModel.id == decoded_token["user_id"])
    )
    existing_user = existing_user.scalar_one_or_none()
    if not existing_user:
        raise HTTPException(
            status_code=404,
            detail="User not found."
        )
    access_token = jwt_manager.create_access_token(data={
        "user_id": existing_user.id},
        expires_delta=timedelta(hours=3)
    )

    return {"access_token": access_token}


async def get_user_by_email(db: AsyncSession, email: str) -> UserModel:
    result = await db.execute(select(UserModel).where(UserModel.email == email))
    return result.scalar_one_or_none()
