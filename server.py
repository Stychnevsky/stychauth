import base64   
import hmac
import hashlib
import json

from typing import Optional

from fastapi import FastAPI, Form, Cookie, Body
from fastapi.responses import Response # объект Response инкапсулирует в себе http-ответ

app = FastAPI() # создаем экземпляр приложения

# ключи ниже (они рандомные) сгенерированы командой openssl rand -hex 32
SECRET_KEY = "60fe42c124b3bc4f74af385b9b0edbe3952e175075edabe35d9ad7b90d8bfee3"
PASSWORD_SALT = '9a5e6ec855e1497dc41283a54f6e96e2665694f8eff6abb03348f65d25a9372b'

def encode(text: str) -> str:
    return base64.b64encode(text.encode()).decode()

def decode(text: str) -> str:
    return base64.b64decode(text.encode()).decode()

def sign_data(data: str) -> str:
    """Возвращает подписанные данные data"""
    return hmac.new(
        SECRET_KEY.encode(),
        msg=data.encode(),
        digestmod=hashlib.sha256
    ).hexdigest().upper()

def get_username_from_signed_string(username_signed: str) -> Optional[str]:
    username_base64, sign = username_signed.split(".")
    username = decode(username_base64)
    valid_sign = sign_data(username)
    if hmac.compare_digest(valid_sign, sign):
        return username


def verify_password(username: str, password: str) -> bool:
    password_hash = hashlib.sha256((password+PASSWORD_SALT).encode()).hexdigest().lower() 
    stored_password_hash = users[username]['password'].lower()
    return password_hash == stored_password_hash

# В "базе данных" ниже хэш паролей вычислен через hashlib.sha256((password+SALT).encode()).hexdigest()

users = {
    "alex": {
        "name": "Алексей Шатун",
        "password": "a2be528f8cddf6fd44c34f4909a287147920a6c20539a82447afda691c73a938", #pass
        "balance": 100_000
    },
    "petr" : {
        "name": "Петр Гришин",
        "password": "ce0e505a3269889d9fe9ef00d16c596552024c4e95b4632b2ce306e1b1326010", #1234
        "balance": 333
    }

}



@app.get("/") # показывает FastAPI что при get-запросе на / страничку возвращать эту функцию
def index_page(username: Optional[str] = Cookie(default=None)):
    with open('templates/login.html', 'r') as f:
        login_page = f.read()
    if not username:
        return Response(login_page, media_type="text/html")

    valid_username = get_username_from_signed_string(username)
    if not valid_username:
        response = Response(login_page, media_type="text/html")
        response.delete_cookie(key="username")
        return response

    try:
        user = users[valid_username]
    except KeyError:
        response = Response(login_page, media_type="text/html")
        response.delete_cookie(key="username")
        return response

    return Response(
        f"Привет, {users[valid_username]['name']}.<br />"\
        f"Баланс: {users[valid_username]['balance']}"
    , media_type="text/html")



@app.post("/login")
def process_login_page(data: dict = Body(...)):
    username = data["username"]
    password = data["password"]
    user = users.get(username)
    if not user or not verify_password(username, password):
        return Response(
            json.dumps({
                "success": False,
                "message": "Я вас не знаю"
            }),
            media_type="application/json")
    response = Response(
        json.dumps({
                "success": True,
                "message": f"Привет, {user['name']}.<br />Баланс: {user['balance']}"
            }),
        media_type="application/json")
    cookie_value = f'{encode(username)}.{sign_data(username)}'
    response.set_cookie(key="username", value=cookie_value)
    return response