"""Authentication service."""

from typing import Optional
from datetime import datetime, timedelta
from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from sqlalchemy.orm import Session
from passlib.context import CryptContext
import jwt

from ..core.config import settings
from ..db.database import get_db
from ..models.user import User


security = HTTPBearer()
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


class AuthService:
    """Authentication service."""
    
    @staticmethod
    def verify_password(plain_password: str, hashed_password: str) -> bool:
        """Verify a password against its hash."""
        return pwd_context.verify(plain_password, hashed_password)
    
    @staticmethod
    def get_password_hash(password: str) -> str:
        """Generate password hash."""
        # 1. 确保是字符串
        if not isinstance(password, str):
            password = str(password)
            
        # 2. 【关键修复】尝试编码为 UTF-8 再解码，去除可能的奇怪控制符或编码问题
        # 这一步可以清洗掉很多导致 bcrypt 崩溃的隐形字符
        try:
            # 先转 bytes 再转回 str，确保是干净的 utf-8 字符串
            clean_password = password.encode('utf-8').decode('utf-8')
        except Exception:
            clean_password = password

        # 3. 【关键修复】bcrypt 限制 72 字节。注意是字节长度，不是字符长度！
        # 中文占 3 个字节，所以不能简单用 len() 截断字符串，要截断 bytes
        pwd_bytes = clean_password.encode('utf-8')
        if len(pwd_bytes) > 72:
            # 截断字节流
            pwd_bytes = pwd_bytes[:72]
            # 再转回字符串（忽略末尾可能截断半个中文的情况，errors='ignore'）
            clean_password = pwd_bytes.decode('utf-8', errors='ignore')
            
        # 4. 打印调试（上线后可删除），确认传进去的到底是什么
        import logging
        logging.warning(f"🔒 Hashing password: '{clean_password}' (Bytes Len: {len(clean_password.encode('utf-8'))})")

        # 5. 执行哈希
        return pwd_context.hash(clean_password)
    
    @staticmethod
    def create_access_token(data: dict, expires_delta: Optional[timedelta] = None) -> str:
        """Create JWT access token."""
        to_encode = data.copy()
        if expires_delta:
            expire = datetime.utcnow() + expires_delta
        else:
            expire = datetime.utcnow() + timedelta(minutes=settings.security.access_token_expire_minutes)
        
        to_encode.update({"exp": expire})
        encoded_jwt = jwt.encode(
            to_encode, 
            settings.security.secret_key, 
            algorithm=settings.security.algorithm
        )
        return encoded_jwt
    
    @staticmethod
    def verify_token(token: str) -> Optional[dict]:
        """Verify JWT token."""
        try:
            payload = jwt.decode(
                token, 
                settings.security.secret_key, 
                algorithms=[settings.security.algorithm]
            )
            return payload
        except jwt.PyJWTError as e:
            import logging
            logging.error(f"Token verification failed: {e}")
            logging.error(f"Token: {token[:50]}...")
            logging.error(f"Secret key: {settings.security.secret_key[:20]}...")
            logging.error(f"Algorithm: {settings.security.algorithm}")
            return None
    
    @staticmethod
    def authenticate_user(db: Session, username: str, password: str) -> Optional[User]:
        """Authenticate user with username and password."""
        user = db.query(User).filter(User.username == username).first()
        if not user:
            return None
        if not AuthService.verify_password(password, user.hashed_password):
            return None
        return user
    
    @staticmethod
    def authenticate_user_by_email(db: Session, email: str, password: str) -> Optional[User]:
        """Authenticate user with email and password."""
        user = db.query(User).filter(User.email == email).first()
        if not user:
            return None
        if not AuthService.verify_password(password, user.hashed_password):
            return None
        return user
    
    @staticmethod
    def get_current_user(
        credentials: HTTPAuthorizationCredentials = Depends(security),
        db: Session = Depends(get_db)
    ) -> User:
        """Get current authenticated user."""
        import logging
        from ..core.context import UserContext
        
        credentials_exception = HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Could not validate credentials",
            headers={"WWW-Authenticate": "Bearer"},
        )
        
        token = credentials.credentials
        logging.info(f"Received token: {token[:50]}...")
        payload = AuthService.verify_token(token)
        if payload is None:
            logging.error("Token verification failed")
            raise credentials_exception
        
        logging.info(f"Token payload: {payload}")
        username: str = payload.get("sub")
        if username is None:
            logging.error("No username in token payload")
            raise credentials_exception
        
        logging.info(f"Looking for user with username: {username}")
        user = db.query(User).filter(User.username == username).first()
        if user is None:
            logging.error(f"User not found with username: {username}")
            raise credentials_exception
        
        # Set user in context for global access
        UserContext.set_current_user(user)
        logging.info(f"User {user.username} (ID: {user.id}) set in UserContext")
        
        return user
    
    @staticmethod
    def get_current_active_user(current_user: User = Depends(get_current_user)) -> User:
        """Get current active user."""
        if not current_user.is_active:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST, 
                detail="Inactive user"
            )
        return current_user