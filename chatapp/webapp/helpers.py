import os
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
from base64 import b64encode, b64decode
import onetimepass as otp
from wtforms import StringField
from wtforms.validators import DataRequired
import base64
import re
from PIL import Image, ImageDraw, ImageFont
import random
import string
import logging
import html

def generate_captcha_image():
    image = Image.new('RGB', (120, 30), color=(73, 109, 137))

    font_path = "./arial.ttf"
    fnt = ImageFont.truetype(font_path, 15)
    d = ImageDraw.Draw(image)

    captcha_text = ''.join(random.choices(string.ascii_uppercase + string.digits, k=5))
    d.text((10, 10), captcha_text, font=fnt, fill=(255, 255, 0))

    for _ in range(random.randint(3, 5)):
        start = (random.randint(0, image.width), random.randint(0, image.height))
        end = (random.randint(0, image.width), random.randint(0, image.height))
        d.line([start, end], fill=(random.randint(50, 200), random.randint(50, 200), random.randint(50, 200)))

    for _ in range(100):
        xy = (random.randrange(0, image.width), random.randrange(0, image.height))
        d.point(xy, fill=(random.randint(50, 200), random.randint(50, 200), random.randint(50, 200)))

    return image, captcha_text



# https://pycryptodome.readthedocs.io/en/latest/src/cipher/classic.html#cbc-mode
def AESencrypt(key, iv, plaintext):
    cipher = AES.new(key, AES.MODE_CBC, iv)
    ct_bytes = cipher.encrypt(pad(plaintext, AES.block_size))
    ct = b64encode(ct_bytes).decode('utf-8')
    return ct


def AESdecrypt(key, iv, ct):
    ct = b64decode(ct)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    pt = unpad(cipher.decrypt(ct), AES.block_size)
    return pt


def get_totp_uri(username, totp_secret):
    return f'otpauth://totp/TOTPDemo:{username}?secret={totp_secret}&issuer=TOTPDemo'


def verify_totp(totp_secret):
    return otp.valid_totp(StringField('Token', validators=[DataRequired()]), totp_secret)


def check_password_strength(password):
    # Standard 1: Length > 8
    if len(password) < 8:
        return "Password must be at least 8 characters long."

    # Standard 2: Combining digit, lower case, and upper case
    has_digit = any(char.isdigit() for char in password)
    has_lower = any(char.islower() for char in password)
    has_upper = any(char.isupper() for char in password)

    if not (has_digit and has_lower and has_upper):
        return "Password must contain at least one digit, one lowercase letter, and one uppercase letter."

    # Standard 3: Avoid repeating patterns (e.g., "aaaaaa" or "123123")
    if re.match(r"^(.)\1+$", password):
        return "Avoid repeating patterns in your password."

    # Standard 4: Check against a list of common passwords
    with open("./common_passwords.txt") as common_file: # assume that the current directory is webapp
        common_password_list = [line.strip().lower() for line in common_file]

    if password.lower() in common_password_list:
        return "Avoid using common passwords."

    return None

def validate_form(form):

    validated_data = {}
    for field, value in form.items():
        
        escaped_value = html.escape(value) # Escape all fields for XSS protection

        if field == "username" or field == "captcha_input":
            escaped_value = escaped_value.strip()
            if not re.match(r"^[a-zA-Z0-9]+$", escaped_value):
                logging.warning(f"Invalid username format for '{value}'. Username should only contain alphanumeric characters.")
                escaped_value = 'None'

            validated_data[field] = escaped_value

        elif field == "password" or field == "retyped_password" or field == "memorizedSecret":
            escaped_value = escaped_value.strip()
            # Allow alphanumeric, common symbols, and underscores
            if not re.match(r"^[a-zA-Z0-9!@#$%^&*()-_=+{}|:'\",./?]+$", escaped_value):
                logging.warning(f"Invalid password format for '{value}'. Passwords can contain alphanumeric characters, common symbols, and underscores.")
                escaped_value = 'None'
            validated_data[field] = escaped_value

        elif field == "securityAnswer":
    
            if not re.match(r"^[a-zA-Z0-9]+$", escaped_value):
                logging.warning(f"Invalid security answer format for '{value}'. Security answer should only contain alphanumeric characters.")
                escaped_value = 'None'

            validated_data[field] = escaped_value

        else:
            validated_data[field] = escaped_value
    return validated_data