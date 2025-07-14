from datetime import timedelta,datetime,timezone
from fastapi import APIRouter,Depends,status,HTTPException
from models import Users
from pydantic import BaseModel
from passlib.context import CryptContext
from typing import Annotated
from database import SessionLocal
from sqlalchemy.orm import Session
from fastapi.security import OAuth2PasswordRequestForm,OAuth2PasswordBearer
from jose import jwt,JWTError

router = APIRouter(
    prefix='/auth',
    tags=['auth']
)

SECRET_KEY = '0bc9b91956fb89e02eadcdd7f2eb75da3ca2a16746871877653311af987365d2'
ALGORITHM = 'HS256'

bcrypt_context = CryptContext(schemes=['bcrypt'],deprecated='auto')
oauth2_bearer = OAuth2PasswordBearer(tokenUrl='auth/token')

class UserRequest(BaseModel):
    username: str
    email: str 
    first_name: str
    last_name: str
    password: str 
    role: str

class Token(BaseModel):
    acess_token: str
    token_type: str


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

db_dependancy = Annotated[Session,Depends(get_db)]

def authenicated_user(username:str,password:str,db):
    user = db.query(Users).filter(Users.username==username).first()
    if not user:
        return False
    if not bcrypt_context.verify(password,user.hashed_password):
        return False
    return user

def create_acess_token(username: str,user_id: int,expire_delta: timedelta):
    encode = {'sub':username,'id':user_id}
    expires = datetime.now(timezone.utc)+expire_delta
    encode.update({'exp':expires})
    return jwt.encode(encode,SECRET_KEY,algorithm=ALGORITHM)

def get_current_user(token: Annotated[str, Depends(oauth2_bearer)]):
    try:
        payload = jwt.decode(token,SECRET_KEY,algorithms=[ALGORITHM])
        username: str = payload.get('sub')
        user_id: str = payload.get('id')
        if username is None or user_id is None:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND,detail='Could not valid user')
        return {'username':username,'id':user_id}
    except JWTError:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND,detail='Could not valid user')


@router.post('/',status_code=status.HTTP_201_CREATED)
def create_user(db:db_dependancy,create_user_request: UserRequest):

    create_user_model = Users(
            email = create_user_request.email,
            username= create_user_request.username,
            first_name= create_user_request.first_name,
            last_name= create_user_request.last_name,
            role=create_user_request.role,
            hashed_password=bcrypt_context.hash(create_user_request.password),
            is_active= True
    )

    db.add(create_user_model)
    db.commit()

    return create_user_model

@router.post('/token',response_model=Token)
def login_for_acess_toeken(form_data:Annotated[OAuth2PasswordRequestForm,Depends()],db:db_dependancy):
    user = authenicated_user(form_data.username,form_data.password,db)
    if not user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND,detail='Could not valid user')
    
    token = create_acess_token(user.username,user.id,timedelta(minutes=20))

    return {'acess_token':token,'token_type':'bearer'}