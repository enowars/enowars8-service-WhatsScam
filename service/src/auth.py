from flask import Blueprint, render_template, request, flash, redirect, url_for
from .models import User
from werkzeug.security import generate_password_hash, check_password_hash
from . import db   ##means from __init__.py import db
from flask_login import login_user, login_required, logout_user, current_user
from . import rsa_encryption
import datetime


#backup func imports
from authlib.jose import jwt
from Crypto.PublicKey import RSA
import datetime
from cryptography.hazmat.backends import default_backend
import hmac


auth = Blueprint('auth', __name__)


def key_loader_public(key):
    try:
        # key = serialization.load_pem_private_key(key.encode('utf-8'),password=None,backend=default_backend())
        # return key
        PUBKEY = RSA.import_key(key)
        PUBKEY = PUBKEY.public_key().export_key(format='PEM')
        return PUBKEY
    except:
        return None
    

def key_loader_priv(key):
    try:
        # key = serialization.load_pem_public_key(key.encode('utf-8'),backend=default_backend())
        # return key
        PRIVKEY = RSA.import_key(key)
        PRIVKEY = PRIVKEY.export_key(format='PEM')
        return PRIVKEY
    except:
        return None


@auth.route('/login', methods=['GET', 'POST'])
async def login():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        user = User.query.filter_by(email=email).first()
        if user:
            if(hmac.compare_digest(user.password.encode('utf-8'), password.encode('utf-8'))):
                flash('Logged in successfully!', category='success')
                login_user(user, remember=True)
                return redirect(url_for('views.home'))
            else:
                flash('Incorrect password, try again.', category='error')
        else:
            flash('Email does not exist.', category='error')
    return render_template("login.html", user=current_user)


@auth.route('/logout')
@login_required
async def logout():
    logout_user()
    return redirect(url_for('auth.login'))


@auth.route('/sign-up', methods=['GET', 'POST'])
async def sign_up():
    if request.method == 'POST':
        email = request.form.get('email')
        name = request.form.get('name')
        password1 = request.form.get('password1')
        password2 = request.form.get('password2')
        #to be changed
        public_key = request.form.get('public_key')
        

        user = User.query.filter_by(email=email).first()
        if user:
            flash('Email already exists.', category='error')
        elif len(email) < 4:
            flash('Email must be greater than 3 characters.', category='error')
        elif len(name) < 2:
            flash('First name must be greater than 1 character.', category='error')
        elif password1 != password2:
            flash('Passwords don\'t match.', category='error')
        elif len(password1) < 7:
            flash('Password must be at least 7 characters.', category='error')
        else:
            if public_key == "on":
                #check if public key is already in use
                while True:
                    private_key, public_key = rsa_encryption.get_keys()
                    all_public_keys = [user_public.public_key for user_public in User.query.all()]
                    if public_key not in all_public_keys:
                        break
                    
                #saving the public key in a format that can be used as later
                text = public_key.split('\n')
                text = text[1:-2]
                final_text = ""
                for j in text:
                    final_text += j

                private_key_text = private_key.split('\n')
                text = private_key_text[1:-2]
                final_private_key_text = ""
                for j in text:
                    final_private_key_text += j
                
                new_user = User(email=email, name=name, private_key=private_key, public_key=public_key, public_key_name = final_text, private_key_name = final_private_key_text ,password= password1, time = datetime.datetime.now())
                db.session.add(new_user)
                db.session.commit()
                login_user(new_user, remember=True) # missing await?
                flash('Account created!', category='success')
                return redirect(url_for('views.home'))
            else:
                private_key = None
                public_key = None
                new_user = User(email=email, name=name, private_key=private_key, public_key=public_key, password= password1, time = datetime.datetime.now())
                db.session.add(new_user)
                db.session.commit() #await?
                login_user(new_user, remember=True) # missing await?
                flash('Account created!', category='success')
                return redirect(url_for('views.home'))

    return render_template("sign_up.html", user=current_user)


@auth.route('/backup', methods=['GET', 'POST'])
async def backup():
    if request.method == 'POST':
        email = request.form.get('email_backup')
        token = request.form.get('token_backup')
        if type(token) != bytes:
            token = token.encode('utf-8')
        get_user = User.query.filter_by(email=email).first() #email is unique
        status = get_user.status
        email = get_user.email
        token_user = get_user.token
        name = get_user.name
        user_data = {
            "email": email,
            "name": name,
            "token": token_user,
            "status": status
        }
        if get_user == None:
            flash('No user found!', category='error')
            return render_template("backup.html", user=None)
        if get_user.token == None:
            flash('You dont have backup active!', category='error')
            return render_template("backup.html", user=None)
        public_key = get_user.public_key.replace("\\n", "\n")
        try:
            public_key = key_loader_public(public_key)
        except:
            flash('Invalid public key!', category='error')
            return render_template("backup.html", user=None)
        PUBKEY = public_key
        try:
            claims = jwt.decode(token, PUBKEY)
        except:
            flash('Invalid token!', category='error')
            return render_template("backup.html", user=None)
        if claims["email"] == email:
            flash('Backup Login successful!', category='message')
            return render_template("backup.html", user=user_data)
        else:
            flash('Backup Login failed!', category='error')
            return render_template("backup.html", user=None)
    else:
        return render_template("backup.html", user=None)



