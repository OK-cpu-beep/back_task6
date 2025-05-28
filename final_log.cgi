#!E:\PythonP\Python3.13\python.exe

import os
import sys
import time
import io
import hmac
import hashlib
import json
import base64
import mysql.connector as sq_con
from http import cookies
from hashlib import sha256
from urllib.parse import parse_qs
from datetime import datetime, timedelta
from jinja2 import Environment, FileSystemLoader

# Функция для проверки пароля
def check_password(hashed_password, user_password):
    return hashed_password == sha256(user_password.encode('utf-8')).hexdigest()
def hash_password(password):
    return sha256(password.encode('utf-8')).hexdigest()
JWT_SECRET = 'dsmfapsadlkfjsd1232132lkfjsalkdfjlksdajflksdfjsadf'
def generate_jwt(payload):
    header = {
        "alg": "HS256",
        "typ": "JWT"
    }
    encoded_header = base64.urlsafe_b64encode(json.dumps(header).encode()).decode().rstrip('=')
    encoded_payload = base64.urlsafe_b64encode(json.dumps(payload).encode()).decode().rstrip('=')
    signature = hmac.new(
        JWT_SECRET.encode(),
        f"{encoded_header}.{encoded_payload}".encode(),
        hashlib.sha256
    ).digest()
    encoded_signature = base64.urlsafe_b64encode(signature).decode().rstrip('=')
    return f"{encoded_header}.{encoded_payload}.{encoded_signature}"

def validate_jwt(token):
    try:
        encoded_header, encoded_payload, encoded_signature = token.split('.')
        # Добавляем обратно отрезанные '='
        padding = len(encoded_header) % 4
        if padding:
            encoded_header += '=' * (4 - padding)
        padding = len(encoded_payload) % 4
        if padding:
            encoded_payload += '=' * (4 - padding)
        padding = len(encoded_signature) % 4
        if padding:
            encoded_signature += '=' * (4 - padding)
        
        # Проверяем подпись
        expected_signature = hmac.new(
            JWT_SECRET.encode(),
            f"{encoded_header}.{encoded_payload}".encode(),
            hashlib.sha256
        ).digest()
        expected_encoded = base64.urlsafe_b64encode(expected_signature).decode().rstrip('=')
        
        if not hmac.compare_digest(encoded_signature, expected_encoded):
            return None
            
        # Декодируем payload
        payload = json.loads(base64.urlsafe_b64decode(encoded_payload).decode())
        
        # Проверяем срок действия
        if 'exp' in payload and payload['exp'] < time.time():
            return None
            
        return payload
    except:
        return None
def validatе_jwt():
    return True
class SQL_con():
        config = {
            'host': 'localhost',       # Адрес сервера БД
            'user': 'root',          # Имя пользователя
            'password': '1234',     # Пароль
            'database': 'web_back',      # Название БД
        }
        @staticmethod
        def post_user(data):

            conn = sq_con.connect(**SQL_con.config)
            curr = conn.cursor()
            curr.execute(f'''
                INSERT INTO users1 (fio, phone, email, birth_date, gender, bio, login, password_hash)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s)''',
                (data["fio"], data["phone"], data["email"], data["birth_date"], 
                data["gender"],data["bio"], data["login"], data["password_hash"]))
            conn.commit()
            conn.close()
        
        @staticmethod    
        def get_user_id(data):
            conn = sq_con.connect(**SQL_con.config)
            curr = conn.cursor()
            curr.execute(f'''
                SELECT * FROM users1 WHERE (fio='{data["fio"]}' AND phone = '{data["phone"]}'
                AND email = '{data["email"]}' AND birth_date = '{data["birth_date"]}'
                AND gender = {data["gender"]} AND bio = '{data["bio"]}');
                ''')
            user = curr.fetchall()
            conn.close()
            if(len(user)!=0):
                return user[0][0]
            return -1

        @staticmethod    
        def get_pass_from_log(login):
            conn = sq_con.connect(**SQL_con.config)
            curr = conn.cursor()
            curr.execute(f'''
                SELECT * FROM users1 WHERE (login = %s);
                ''', (login,))
            user = curr.fetchall()
            conn.close()
            if(len(user)!=0):
                return user[0][-1]
            return -1
        
        @staticmethod    
        def get_FULL(login):
            conn = sq_con.connect(**SQL_con.config)
            curr = conn.cursor()
            curr.execute(f'''
                SELECT * FROM users1 WHERE (login = %s);
                ''', (login,))
            user = curr.fetchall()
            conn.close()
            if(len(user)!=0):
                return user[0]
            return [-1]

        @staticmethod
        def post_language(user_id, data):
            conn = sq_con.connect(**SQL_con.config)
            curr = conn.cursor()
            for i in data:
                curr.execute(f'''
                    INSERT INTO users_languages1 VALUES ({user_id}, {i});
                    ''')
            conn.commit()
            conn.close()

def main():
    if method=="POST":
        content_length = int(os.environ.get('CONTENT_LENGTH', 0))
        post_data = sys.stdin.read(content_length)
        new_data = parse_qs(post_data)
        # {'field-log': ['fdssdf'], 'field-pass': ['werwerwer']}
        login = new_data['field-log'][0]
        password = new_data['field-pass'][0]
        needed_pass = SQL_con.get_pass_from_log(login)
        hashed_password = hash_password(password)
        is_validate_jwt = validatе_jwt()
        if(hashed_password == needed_pass and is_validate_jwt):
            #(6, 'wqeqwsadasdasdas', '89797895673', 'mnfdffssd@gmail.com', datetime.date(2025, 5, 13), 1, 'zcxzxczxczczxcz ', 'wqeqwsadasdasdas_25',)
            d = SQL_con.get_FULL(login)
            prep_cook = {
                "id" : d[0],
                "fio" : d[1],
                "phone" : d[2],
                "email" : d[3],
                "birth_date" : d[4],
                "checked"+str(d[5]) : "checked",
                "bio" : d[6]
            }
            cookie = cookies.SimpleCookie()
            expires = datetime.now() + timedelta(days=365)
            for field, value in prep_cook.items():
                if field != 'contract_agreed':
                    if field != "languages":
                        cookie[field] = value
                    else:
                        cookie[field] = ''.join(value)
                    cookie[field]['expires'] = expires.strftime("%a, %d-%b-%Y %H:%M:%S GMT")
            print("Status: 303 See Other")
            print(f"Location: final.cgi")
            print(cookie.output())
            print()  # Пустая строка между заголовками и телом
            sys.exit(0)
        else:
            env = Environment(
            loader=FileSystemLoader('.'),  # Ищем шаблоны в текущей директории
            )
            template = env.get_template('login.html')
            output = template.render(mess = "Неверно введён логин или пароль")
            #Выводим страницу
            print("Status: 200 OK")
            print("Content-Type: text/html; charset=utf-8")
            print()  # Пустая строка между заголовками и телом
            print(output)
    else:
        env = Environment(
            loader=FileSystemLoader('.'),  # Ищем шаблоны в текущей директории
        )
        template = env.get_template('login.html')
        output = template.render()
        #Выводим страницу
        print("Status: 200 OK")
        print("Content-Type: text/html; charset=utf-8")
        print()  # Пустая строка между заголовками и телом
        print(output)
method = os.environ.get('REQUEST_METHOD', '')
sys.stdout.reconfigure(encoding='utf-8')
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8')
try:
    main()
except Exception as e:
    error_msg = f"Critical error: {e}"
    file = open("logs.txt", "w")
    file.write(error_msg)
    file.close()
    print("Status: 200 OK")
    print("Content-Type: text/html; charset=utf-8")
    print()
    print(e)


