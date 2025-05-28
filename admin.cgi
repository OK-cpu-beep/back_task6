#!E:\PythonP\Python3.13\python.exe

import base64
from datetime import datetime, timedelta
import re
import sys
import io
from http import cookies
import os
from hashlib import sha256
from urllib.parse import parse_qs
import mysql.connector as sq_con
from jinja2 import Environment, FileSystemLoader
def hash_password(password):
    return sha256(password.encode('utf-8')).hexdigest()
def main():
# Конфигурация
    class SQL_con():
        config = {
            'host': 'localhost',       # Адрес сервера БД
            'user': 'root',          # Имя пользователя
            'password': '1234',     # Пароль
            'database': 'web_back',      # Название БД
        }

        @staticmethod
        def get_pass_from_log(login):
            conn = sq_con.connect(**SQL_con.config)
            curr = conn.cursor()
            curr.execute(f'''
                SELECT * FROM admin WHERE (login = %s);
                ''', (login,))
            user = curr.fetchall()
            conn.close()
            if(len(user)!=0):
                return user[0][1]
            return -1
        
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
        def get_user_id(user_id):
            conn = sq_con.connect(**SQL_con.config)
            curr = conn.cursor()
            curr.execute(f'''
                SELECT * FROM users1 WHERE (users_id = %s);
                ''', (user_id,))
            user = curr.fetchall()
            conn.close()
            if(len(user)!=0):
                return user[0]
            return -1
        
        @staticmethod
        def post_language(user_id, data):
            conn = sq_con.connect(**SQL_con.config)
            curr = conn.cursor()
            curr.execute('''DELETE FROM users_languages1 WHERE (user_id = %s);''', (user_id,))
            for i in data:
                curr.execute(f'''
                    INSERT INTO users_languages1 VALUES (%s, %s);
                    ''', (user_id, i))
            conn.commit()
            conn.close()
        
        @staticmethod
        def update_info(id, data):
            conn = sq_con.connect(**SQL_con.config)
            curr = conn.cursor()
            curr.execute(f'''
                UPDATE users1
                SET fio = %s, phone = %s, email = %s, birth_date = %s, gender = %s, bio = %s
                WHERE users_id = %s;
                ''', (data["fio"], data["phone"], data["email"], data["birth_date"], 
                data["gender"],data["bio"], id))
            conn.commit()
            conn.close()

        @staticmethod
        def get_names():
            conn = sq_con.connect(**SQL_con.config)
            curr = conn.cursor()
            curr.execute(f'''
                SELECT login FROM users1;
                ''')
            users = curr.fetchall()
            conn.close()
            return users
        @staticmethod
        def get_languages(user_id):
            conn = sq_con.connect(**SQL_con.config)
            curr = conn.cursor()
            curr.execute(f'''
                SELECT * FROM users_languages1 WHERE (user_id = %s);
                ''', (user_id,))
            langs = curr.fetchall()
            conn.close()
            if(len(langs)!=0):
                return langs[0]
            return []
        @staticmethod
        def get_all():
            conn = sq_con.connect(**SQL_con.config)
            curr = conn.cursor()
            curr.execute(f'''
                SELECT * FROM users1;
                ''')
            langs = curr.fetchall()
            conn.close()
            if(len(langs)!=0):
                return langs
            return -1
        @staticmethod
        def delete_user(user_id):
            conn = sq_con.connect(**SQL_con.config)
            curr = conn.cursor()
            curr.execute(f'''
                DELETE FROM users1 WHERE (users_id = %s);
                ''', (user_id,))
            conn.commit()
            conn.close()
    def check_auth(in_password, real_pass):
        if (real_pass == -1) or in_password != real_pass: 
            return False
        return True

    def require_auth():
        """Отправляет заголовок 401 для запроса авторизации"""
        print("Status: 401 Unauthorized")
        print('WWW-Authenticate: Basic realm="Secure Area"')
        print("Content-Type: text/html\n")
        print("<html><body><h1>Требуется авторизация</h1></body></html>")
        exit()

    # Проверка авторизации
    auth_header = os.environ.get('HTTP_AUTHORIZATION')
    if not auth_header or not auth_header.startswith('Basic '):
        require_auth()
    
    # Декодируем credentials
    try:
        encoded_creds = auth_header[6:]
        decoded_creds = base64.b64decode(encoded_creds).decode('utf-8')
        username, password = decoded_creds.split(':', 1)
    except:
        require_auth()
    right_pass = SQL_con.get_pass_from_log(username)
    password = hash_password(password)
    error_msg = f"Critical errorzcxzczxczcx: {right_pass} {password}"
    file = open("logs.txt", "w")
    file.write(error_msg)
    file.close()
    if not check_auth(password, right_pass):
        require_auth()
    all_users = SQL_con.get_all()
    langs_dict = {
        "1"	: "Pascal",
        "2" :	"C",
        "3" :	"C++",
        "4" :	"JavaScript",
        "5" :	"PHP",
        "6" :	"Python",
        "7" :	"Java",
        "8"	: "Haskel",
        "9" :	"Clojure",
        "10" :	"Prolog",
        "11"	:"Scala",
        "12" :	"Go"
    }
    message = ""
    output = ""
    if method == "POST":
        content_length = int(os.environ.get('CONTENT_LENGTH', 0))
        post_data = sys.stdin.read(content_length)
        new_data = parse_qs(post_data)
        
        #Валидация
        errors = {}

        #Поля для вставки
        fields = {}

        #Имя
        try:
            fio = new_data['field-fio'][0]
            fields["fio"] = fio
            if fio == '':
                errors['er_fio'] = "ФИО обязательно для заполнения"
            elif not re.match(r'^[A-Za-zА-Яа-яёЁ\s-]{1,150}$', fio):
                errors['er_fio'] = 'ФИО должно содержать только буквы, пробелы и дефисы (макс. 150 символов)'
        except:
            errors['er_fio'] = "Поле Фио не может быть пустым"
            fields["fio"] = ""

        #email
        try:
            email = new_data['field-email'][0]
            fields["email"] = email
            if not re.match(r'^[^@\s]+@[^@\s]+\.[^@\s]+$', email):
                errors['er_email'] = 'Введите корректный email'
        except:
            errors['er_email'] = "Поле email не может быть пустым"
            fields["email"] = ""

        #ЯП
        try:
            languages = new_data["languages"]
            fields["languages"] = languages 
        except:
            errors['er_languages'] = 'Выберете хотя бы 1 язык программирования'
            fields["languages"] = "" 

        #Дата рождения
        try:
            birth_date = datetime.strptime(new_data['field-birthday'][0], '%Y-%m-%d').date()
            fields["birth_date"] = birth_date
            if birth_date > datetime.now().date():
                errors['birth_date'] = 'Дата рождения не может быть в будущем'
        except ValueError:
            errors['er_birth_date'] = 'Некорректный формат даты. Используйте ГГГГ-ММ-ДД'
            fields["birth_date"] = new_data['field-birthday'][0]
        except KeyError:
            errors['er_birth_date'] = 'Поле даты не может быть пустым'
            fields["birth_date"] = " "

        #Телефон
        try:
            phone = new_data['field-tel'][0]
            fields["phone"] = phone
            cleaned_phone = re.sub(r'[^\d]', '', phone)
            # Проверяем основные форматы для России
            if not re.fullmatch(r'^(\+7|8)\d{10}$', cleaned_phone):
                errors['er_phone'] = "Введите корректный номер телефона(Россия)"
            if len(phone)>12:
                errors['er_phone'] = "Введите корректный номер телефона(Россия)"
        except:
            errors["er_phone"] = "Поле email не может быть пустым"
            fields["phone"] = ""

        #Cогласие
        try:
            if not new_data["check-1"]:
                errors['er_contract_agreed'] = "Ознакомьтесь с контрактом для отправки"
        except:
            errors['er_contract_agreed'] = "Ознакомьтесь с контрактом для отправки" 

        #Пол
        gender = new_data["radio-group-1"][0]
        fields["checked"+gender] = "checked"
        #Биография
        try:
            bio = new_data["bio"][0]
        except:
            bio = ""
        fields["bio"] = bio

        #Подключаем печеньки
        cookie = cookies.SimpleCookie()
        if 'HTTP_COOKIE' in os.environ:
            cookie.load(os.environ['HTTP_COOKIE'])
        
        #Проверка на ошибки
        if errors:
            for field, error in fields.items():
                try:
                    del cookie["er_"+field]
                except Exception as e:
                    ...
            expires = datetime.now() + timedelta(days=365)
            for field, error in errors.items():
                cookie[field] = error
            for field, value in fields.items():
                if field != 'contract_agreed':
                    if field != "languages":
                        cookie[field] = value
                    else:
                        cookie[field] = ''.join(value)
                    cookie[field]['expires'] = expires.strftime("%a, %d-%b-%Y %H:%M:%S GMT")
            env = Environment(
                loader=FileSystemLoader('.'),  # Ищем шаблоны в текущей директории
            )
            q = os.environ.get("QUERY_STRING")
            q = q.split("&")
            q[0] = q[0].split("=")
            q[1] = q[1].split("=")
            id = int(q[1][1]) 
            template = env.get_template('errorss.html')
            output = template.render(**cookie, id = id)
            for field, error in errors.items():
                del cookie[field]
        else:
            expires = datetime.now() + timedelta(days=365)
            for field, error in fields.items():
                try:
                    del cookie["er_"+field]
                except Exception as e:
                    ...
            for field, value in fields.items():
                if field != 'contract_agreed':
                    if field != "languages":
                        cookie[field] = value
                    else:
                        cookie[field] = ''.join(value)
                    cookie[field]['expires'] = expires.strftime("%a, %d-%b-%Y %H:%M:%S GMT")
            #Переделываем данные
            new_data = {
                    "fio": fio,
                    "phone": phone,
                    "email": email,
                    "birth_date": birth_date,
                    "gender": gender,
                    "bio": bio,
                }
            q = os.environ.get("QUERY_STRING")
            q = q.split("&")
            q[0] = q[0].split("=")
            q[1] = q[1].split("=")
            id = int(q[1][1]) 
            SQL_con.update_info(id, new_data)
            SQL_con.post_language(id, languages)
            message = "Пользователь обновлён"
    # Если авторизация успешна - показываем контент
    print("Content-Type: text/html; charset=utf-8")
    beg_table = f"""
    <!DOCTYPE html>

<head>
    <meta charset="UTF-8">
    <link href="static/styles.css" rel="stylesheet" type="text/css" />
    <title> Администрация Баззиков </title>
</head>

<body>
    <header>
        <div class="title_block">
            <a href="#">
                <img class="img-header" src="static/hyperbuzz_pin.png" />
            </a>
            <h1> АДМИНИСТРАЦИЯ БАЗЗИЛ </h1>
        </div>
    </header>
    <div class="main_block">
    <label> {message} </label>
        <table>
        <thead>
            <tr>
                <th>ID</th>
                <th>ФИО</th>
                <th>Телефон</th>
                <th>Email</th>
                <th>Дата рождения</th>
                <th>Пол</th>
                <th>Языки</th>
                <th>Биография</th>
                <th>Действия</th>
            </tr>
        </thead>
        """
    for x in all_users:
        user_id = x[0]
        langs = SQL_con.get_languages(user_id)
        beg_table += "<tr>"
        for i in range(len(x)-1):
            if i==6:
                beg_table+=f"<td>"
                ans_lang = ""
                for y in langs:
                    ans_lang+=f"{langs_dict[str(y)]}, "
                ans_lang = ans_lang[:-2]
                beg_table+=ans_lang
                beg_table+=f"</td>"
                continue
            beg_table += f"<td>{x[i]}</td>"

        beg_table += f"<td><a href = admin.cgi?action=edit&id={user_id}>Редактировать</a>"
        beg_table += f"<a href = admin.cgi?action=delete&id={user_id}>Удалить</a></td>"
        beg_table += "</tr>"
    beg_table += "</table>"
    print(beg_table)
    q = os.environ.get("QUERY_STRING")
    try:
        errors
        er_check = False
    except:
        er_check = True
    if q and er_check:
        q = q.split("&")
        q[0] = q[0].split("=")
        q[1] = q[1].split("=")
        if(q[0][0] == "action" and q[0][1] == "edit"):
            if (q[1][0] == "id"):
                str_id = q[1][1]
                try:
                    id = int(str_id)
                except:
                    id = -1
                if id>0:
                    us = SQL_con.get_user_id(id)
                    new_data = {
                    "fio": us[1],
                    "phone": us[2],
                    "email": us[3],
                    "birth_date": us[4],
                    "gender": us[5],
                    "bio": us[6],
                    }
                    new_data["checked"+str(us[5])] = "checked"
                    env = Environment(
                        loader=FileSystemLoader('.'),  # Ищем шаблоны в текущей директории
                    )
                    template = env.get_template('update.html')
                    output = template.render(**new_data, id = id)
                    print(output)
        if(q[0][0] == "action" and q[0][1] == "delete"):
            str_id = q[1][1]
            try:
                id = int(str_id)
            except:
                id = -1
            if(id>0):
                SQL_con.delete_user(id)


    elif er_check == False:
        print(output)
    print("""
    </div>
    <footer>
        <p> Ковязин Кирилл (c)</p>
    </footer>
          </body>""")
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