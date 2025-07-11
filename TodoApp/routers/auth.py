from fastapi import APIRouter

router = APIRouter()


@router.get('/auth/')
def get_usre():
    return {'user':'authenticated'}