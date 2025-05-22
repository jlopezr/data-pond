from fastapi import FastAPI, HTTPException, Depends, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from pydantic import BaseModel
from typing import Optional, List
from jose import JWTError, jwt
from passlib.context import CryptContext
from sqlalchemy import create_engine, Column, Integer, String, Boolean
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, Session
import os
from datetime import datetime, timedelta

# Configuración
SECRET_KEY = "supersecretkey"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60
DATABASE_URL = "sqlite:///./data_pond.db"

# Límite de tamaño de archivo (en bytes)
MAX_FILE_SIZE = 10 * 1024 * 1024  # 10 MB

# DB setup
engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

# Password hashing
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# JWT
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

# Modelos DB
class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True, index=True)
    hashed_password = Column(String)
    is_admin = Column(Boolean, default=False)

Base.metadata.create_all(bind=engine)

# Pydantic Schemas
class UserCreate(BaseModel):
    username: str
    password: str
    is_admin: Optional[bool] = False

class UserOut(BaseModel):
    id: int
    username: str
    is_admin: bool

    class Config:
        from_attributes = True

class Token(BaseModel):
    access_token: str
    token_type: str

# Utilidades
def get_password_hash(password):
    return pwd_context.hash(password)

def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    expire = datetime.utcnow() + (expires_delta or timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

def get_user(db: Session, username: str):
    return db.query(User).filter(User.username == username).first()

def authenticate_user(db: Session, username: str, password: str):
    user = get_user(db, username)
    if not user or not verify_password(password, user.hashed_password):
        return None
    return user

def get_current_user(token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise credentials_exception
    except JWTError:
        raise credentials_exception
    user = get_user(db, username)
    if user is None:
        raise credentials_exception
    return user

def get_current_admin(current_user: User = Depends(get_current_user)):
    if not current_user.is_admin:
        raise HTTPException(status_code=403, detail="Admin privileges required")
    return current_user

# Crear usuario admin por defecto si no existe
def create_default_admin():
    db = SessionLocal()
    if not get_user(db, "admin"):
        admin = User(
            username="admin",
            hashed_password=get_password_hash("admin"),
            is_admin=True
        )
        db.add(admin)
        db.commit()
    db.close()

create_default_admin()

# FastAPI app
app = FastAPI(title="Data Pond API")

# Auth endpoint
@app.post("/token", response_model=Token)
def login(form_data: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
    user = authenticate_user(db, form_data.username, form_data.password)
    if not user:
        raise HTTPException(status_code=400, detail="Incorrect username or password")
    access_token = create_access_token(data={"sub": user.username})
    return {"access_token": access_token, "token_type": "bearer"}

# CRUD Usuarios (solo admin)
@app.post("/users/", response_model=UserOut, dependencies=[Depends(get_current_admin)])
def create_user(user: UserCreate, db: Session = Depends(get_db)):
    if get_user(db, user.username):
        raise HTTPException(status_code=400, detail="Username already registered")
    db_user = User(
        username=user.username,
        hashed_password=get_password_hash(user.password),
        is_admin=user.is_admin
    )
    db.add(db_user)
    db.commit()
    db.refresh(db_user)
    return db_user

@app.get("/users/", response_model=List[UserOut], dependencies=[Depends(get_current_admin)])
def list_users(db: Session = Depends(get_db)):
    return db.query(User).all()

@app.get("/users/{user_id}", response_model=UserOut, dependencies=[Depends(get_current_admin)])
def get_user_by_id(user_id: int, db: Session = Depends(get_db)):
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    return user

@app.put("/users/{user_id}", response_model=UserOut, dependencies=[Depends(get_current_admin)])
def update_user(user_id: int, user: UserCreate, db: Session = Depends(get_db)):
    db_user = db.query(User).filter(User.id == user_id).first()
    if not db_user:
        raise HTTPException(status_code=404, detail="User not found")
    db_user.username = user.username
    db_user.hashed_password = get_password_hash(user.password)
    db_user.is_admin = user.is_admin
    db.commit()
    db.refresh(db_user)
    return db_user

@app.delete("/users/{user_id}", dependencies=[Depends(get_current_admin)])
def delete_user(user_id: int, db: Session = Depends(get_db)):
    db_user = db.query(User).filter(User.id == user_id).first()
    if not db_user:
        raise HTTPException(status_code=404, detail="User not found")
    db.delete(db_user)
    db.commit()
    return {"ok": True}

# Aquí irá la gestión de archivos en el siguiente paso
from fastapi import UploadFile, File, Response
import shutil

DATA_DIR = "data"

def get_user_dir(username: str):
    user_dir = os.path.join(DATA_DIR, username)
    os.makedirs(user_dir, exist_ok=True)
    return user_dir

@app.post("/files/upload")
def upload_file(
    file: UploadFile = File(...),
    current_user: User = Depends(get_current_user)
):
    contents = file.file.read()
    if len(contents) > MAX_FILE_SIZE:
        raise HTTPException(status_code=413, detail="File too large")
    user_dir = get_user_dir(current_user.username)
    file_path = os.path.join(user_dir, file.filename)
    with open(file_path, "wb") as f:
        f.write(contents)
    return {"filename": file.filename, "size": len(contents)}

@app.get("/files/", response_model=List[dict])
def list_files(
    username: Optional[str] = None,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    # Solo admin puede listar archivos de otros usuarios
    if username and (not current_user.is_admin or not get_user(db, username)):
        raise HTTPException(status_code=403, detail="Not allowed")
    target_user = username if (username and current_user.is_admin) else current_user.username
    user_dir = get_user_dir(target_user)
    files = []
    if os.path.exists(user_dir):
        for fname in os.listdir(user_dir):
            fpath = os.path.join(user_dir, fname)
            if os.path.isfile(fpath):
                stat = os.stat(fpath)
                files.append({
                    "username": target_user,
                    "filename": fname,
                    "size": stat.st_size,
                    "modified": datetime.fromtimestamp(stat.st_mtime).isoformat()
                })
    return files

@app.get("/files/download/{filename}")
def download_file(
    filename: str,
    current_user: User = Depends(get_current_user)
):
    user_dir = get_user_dir(current_user.username)
    file_path = os.path.join(user_dir, filename)
    if not os.path.exists(file_path):
        raise HTTPException(status_code=404, detail="File not found")
    return Response(
        content=open(file_path, "rb").read(),
        media_type="application/octet-stream",
        headers={"Content-Disposition": f"attachment; filename={filename}"}
    )

@app.delete("/files/{filename}")
def delete_file(
    filename: str,
    current_user: User = Depends(get_current_user)
):
    user_dir = get_user_dir(current_user.username)
    file_path = os.path.join(user_dir, filename)
    if not os.path.exists(file_path):
        raise HTTPException(status_code=404, detail="File not found")
    os.remove(file_path)
    return {"ok": True}