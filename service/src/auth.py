from flask import Blueprint, render_template, request, flash, redirect, url_for
from .models import User
from werkzeug.security import generate_password_hash, check_password_hash
from . import db, logger   ##means from __init__.py import db
from flask_login import login_user, login_required, logout_user, current_user
from . import rsa_encryption
import datetime


auth = Blueprint('auth', __name__)


@auth.route('/login', methods=['GET', 'POST'])
async def login():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')

        user = User.query.filter_by(email=email).first()
        if user:
            if check_password_hash(user.password, password):
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
        logger.info("attempting to sign up")
        start_time = datetime.datetime.now()
        email = request.form.get('email')
        first_name = request.form.get('firstName')
        password1 = request.form.get('password1')
        password2 = request.form.get('password2')
        #to be changed
        public_key = request.form.get('public_key')
        

        user = User.query.filter_by(email=email).first()
        if user:
            flash('Email already exists.', category='error')
        elif len(email) < 4:
            flash('Email must be greater than 3 characters.', category='error')
        elif len(first_name) < 2:
            flash('First name must be greater than 1 character.', category='error')
        elif password1 != password2:
            flash('Passwords don\'t match.', category='error')
        elif len(password1) < 7:
            flash('Password must be at least 7 characters.', category='error')
        else:
            first_time_check = datetime.datetime.now()
            logger.info("first time check: " + str(first_time_check - start_time))
            second_time_check = datetime.datetime.now()
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
                
                new_user = User(email=email, first_name=first_name, private_key=private_key, public_key=public_key, public_key_name = final_text, password=generate_password_hash(
                    password1, method='scrypt'))
                db.session.add(new_user)
                db.session.commit()
                login_user(new_user, remember=True) # missing await?
                flash('Account created!', category='success')
                logger.info("time taken publickey_on: " + str(datetime.datetime.now() - start_time))
                return redirect(url_for('views.home'))
            else:
                private_key = None
                public_key = None
                new_user = User(email=email, first_name=first_name, private_key=private_key, public_key=public_key, password=generate_password_hash(
                    password1, method='scrypt'))
                logger.info("second time check_user: " + str(datetime.datetime.now() - first_time_check))
                db.session.add(new_user)
                db.session.commit() #await?
                logger.info("second time check_db_commit: " + str(datetime.datetime.now() - first_time_check))
                login_user(new_user, remember=True) # missing await?
                flash('Account created!', category='success')
                logger.info("second time check_login_user: " + str(datetime.datetime.now() - first_time_check))
                logger.info("time taken publickey_off: " + str(datetime.datetime.now() - start_time))
                return redirect(url_for('views.home'))

    return render_template("sign_up.html", user=current_user)
