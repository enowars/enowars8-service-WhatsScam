from flask import Blueprint, render_template, request, flash, jsonify, redirect, url_for
from flask_login import login_required, current_user
from .models import Message
from .models import MessageGroup
from .models import User
from .models import user_group_association
from .models import MessageOfGroup
from .models import user_friends_association
from . import db
import json
import datetime as dt

from sqlalchemy.orm import aliased
from sqlalchemy.sql import exists

from . import aes_encryption
from . import rsa_encryption
from . import auth
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from authlib.jose import jwt
import hmac


views = Blueprint('views', __name__)

@views.route('/', methods=['GET', 'POST'])
@login_required
async def home():
    if request.method == 'POST': 
        message = request.form.get('message')#Gets the message from the HTML
        public_key = request.form.get('public_key')

        if len(message) < 1:
            flash('message is too short!', category='error')
        else:
            users = User.query.all()
            public_keys = [user.public_key_name for user in users]
            
            if public_key is None:
                new_message = Message(data=message, owner_id=current_user.id, destination_id=None, target_email = None, time = dt.datetime.now())  #providing the schema for the message
            elif public_key not in public_keys:
                new_message = Message(data=message, owner_id=current_user.id, destination_id=None, target_email = None, time = dt.datetime.now())  #providing the schema for the message
                flash('Public key not found, message not encrypted', category='error')
            else:
                target_user = User.query.filter_by(public_key_name=public_key).first()
                target_user_id = target_user.id
                target_email = target_user.email
                encrypted_message = await rsa_encryption.encryption_of_message(message, target_user.public_key)
                new_message = Message(data=message, encrypted_data = encrypted_message, owner_id=current_user.id, destination_id=target_user_id, target_email = target_email, time = dt.datetime.now())  #providing the schema for the message
                flash('Message encrypted and sent', category='success')

            db.session.add(new_message) #adding the message to the database 
            db.session.commit()
    n = Message.query
    return render_template("home.html", user=current_user, messages=n)

@views.route('/creategroup', methods=['GET', 'POST'])
@login_required
async def group_headfunction():
    if request.method == 'POST':
        if 'join_group' in request.form:
            group_id = request.form.get('join_group')
            key = request.form.get('group_key_join_' + str(group_id))
            return join_group(group_id, key)
        elif 'add_group' in request.form:
            group_name = request.form.get('group_name')
            group_key = request.form.get('group_key')
            return creategroup(group_name, group_key)

    message_groups = db.session.query(MessageGroup).all()
    groups = [{column.name: getattr(message_group, column.name) for column in MessageGroup.__table__.columns} for message_group in message_groups]
    return render_template("groups.html", user=current_user, groups=groups)

def creategroup(group_name, group_key):
    if request.method == 'POST':
        group_name = request.form.get('group_name')
        if len(group_name) < 1 or len(group_key) < 1:
            flash('Group Name or Key is too short!', category='error')
        
        elif db.session.query(MessageGroup).filter_by(name=group_name).first():
            flash('Group name already exists.', category='error')

        else:
            # Create a new MessageGroup instance
            new_group = MessageGroup(name=group_name, group_key=group_key, time= dt.datetime.now())

            # Add the current user to the group
            new_group.users.append(current_user)

            # Add the group to the session and commit
            db.session.add(new_group)
            db.session.commit()
            flash('Group added!', category='success')
            return redirect(url_for('views.group_page', group_id=new_group.id))

    #Show all the groups on the page
    # Retrieve all rows from the MessageGroup table
    message_groups = db.session.query(MessageGroup).all()
    # Prepare a list of dictionaries where each dictionary represents a row with column names as keys and values as values
    groups = [{column.name: getattr(message_group, column.name) for column in MessageGroup.__table__.columns} for message_group in message_groups]
    return render_template("groups.html", user=current_user, groups=groups)

def join_group(group_id, key):
    group = db.session.query(MessageGroup).filter_by(id=group_id).first()
    if group:
        if hmac.compare_digest(key.encode('utf-8'),group.group_key.encode('utf-8')):
            id = group.id
            UserId = current_user.id
            if db.session.query(user_group_association).filter_by(user_id=UserId, group_id=id).first():
                return redirect(url_for('views.group_page', group_id=group.id))
            else:
                # Add the current user to the group
                join = user_group_association.insert().values(user_id=UserId, group_id=id)
                db.session.execute(join)
                db.session.commit()
                flash('You have joined the group!', category='success')
                group = db.session.query(MessageGroup).filter_by(id=group_id).first()
                return redirect(url_for('views.group_page', group_id=group.id))
        else:
            flash('Incorrect key. Please try again.', category='error')
    else:
        flash('Group not found.', category='error')
    return redirect(url_for('views.home'))

@views.route('/creategroup/<int:group_id>', methods=['GET', 'POST'])
@login_required
async def group_page(group_id):
    #id unique so only one object will be returned
    group_allusers = db.session.query(MessageGroup).filter_by(id=group_id).first()
    if group_allusers:
        if any(one_user == current_user for one_user in group_allusers.users):
                if request.method == 'POST':
                    message_of_group_data = request.form.get('message_of_group')#Gets the message from the HTML 
                    if len(message_of_group_data) < 1:
                        flash('message is too short!', category='error') 
                    else:
                        encrypted_data, key, nonce = aes_encryption.aes_encrypt(message_of_group_data)
                        new_message_of_group = MessageOfGroup(data=message_of_group_data, group_id=group_allusers.id, encrypted_data=encrypted_data, time= dt.datetime.now(), key=str(key), nonce=str(nonce), owner_id=current_user.id)
                        db.session.add(new_message_of_group) #adding the message to the database 
                        db.session.commit()
                        flash('message added!', category='success')
                n = MessageOfGroup.query.filter_by(group_id=group_id)
                return render_template("group_page.html", user=current_user, messages=n, group=group_allusers)
        else:
            n = MessageOfGroup.query.filter_by(group_id=group_id)
            return render_template("group_page_unauthorized.html", user=current_user, messages=n, group=group_allusers)
    else:
        flash('Group not found.', category='error')
    return redirect(url_for('views.home'))

@views.route('/userlist', methods=['GET', 'POST'])
@login_required
async def userlist():
    users = User.query.all()
    user_list_with_public_keys = []
    for user in users:
        if user.public_key_name is not None:
            user_list_with_public_keys.append(user)
    return render_template("userlist.html", user=current_user, users=user_list_with_public_keys)
            
#view js script for information and base.html
@views.route('/delete-message', methods=['POST'])
async def delete_message():  
    message = json.loads(request.data) # this function expects a JSON from the INDEX.js file 
    messageId = message['messageId']
    message = Message.query.get(messageId)
    if message:
        if message.owner_id == current_user.id:
            db.session.delete(message)
            db.session.commit()

    return jsonify({})

#view js script for information and base.html
@views.route('/delete-message-group', methods=['POST'])
async def delete_message_group():
    message = json.loads(request.data)
    messageId = message['MessageGroupId']
    message = MessageOfGroup.query.get(messageId)

    if message:
        group = MessageGroup.query.filter_by(id=message.group_id).first()
        if any(one_user == current_user for one_user in group.users):
            db.session.delete(message)
            db.session.commit()
    
    return jsonify({})

######

@views.route('/profil', methods=['GET', 'POST'])
@login_required
async def profil():
    alias_a = aliased(user_group_association)
    group_users = db.session.query(alias_a.c.group_id).filter(
        alias_a.c.user_id == current_user.id,
    ).all()
    group_ids = [group_id for group_id, in group_users]
    final_group_ids = []
    for i in group_ids:
        a = db.session.query(user_group_association).filter_by(group_id=i).first()
        if a[0] == current_user.id:
            final_group_ids.append(i)
    message_groups = MessageGroup.query.filter(MessageGroup.id.in_(final_group_ids)).all()
        
    if request.method == 'POST':
        status = request.form.get('status')
        public_key = request.form.get('public_key')
        token = request.form.get('token') #token for the backup
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

                private_key_name = private_key.split('\n')
                private_key_name = private_key_name[1:-2]
                final_private_key_name = ""
                for j in private_key_name:
                    final_private_key_name += j
                

                current_user.public_key = public_key
                current_user.public_key_name = final_text
                current_user.private_key = private_key
                current_user.private_key_name = final_private_key_name
                current_user.status = status
                db.session.commit()
                return redirect(url_for('views.profil'))
        elif token == "on":
            if current_user.private_key is None or current_user.public_key is None:
                private_key_ = rsa.generate_private_key(
                    public_exponent=65537,
                    key_size=512
                )
                public_key = private_key_.public_key()
                PUBKEY = public_key.public_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PublicFormat.SubjectPublicKeyInfo
                )
                PRIVKEY = private_key_.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.PKCS8,
                    encryption_algorithm=serialization.NoEncryption()
                )
                current_user.public_key = PUBKEY.decode('utf-8')
                current_user.private_key = PRIVKEY.decode('utf-8')
                text = current_user.public_key.split('\n')
                text = text[1:-2]
                final_text = ""
                for j in text:
                    final_text += j
                current_user.public_key_name = final_text
                db.session.commit()
            
            PRIVKEY = current_user.private_key
            PUBKEY = current_user.public_key
            PRIVKEY = PRIVKEY.replace('\n', '\\n')
            PUBKEY = PUBKEY.replace('\n', '\\n')
            private_key = PRIVKEY.replace("\\n", "\n")
            try:
                private_key = auth.key_loader_priv(private_key)
            except:
                flash('Invalid private key!', category='error')
                return render_template("profil.html", user=current_user, groups=message_groups)
            token = jwt.encode({"alg": "RS256"}, {"email":current_user.email}, private_key)
            current_user.token = token.decode('utf-8')
            db.session.commit()
            flash('Token created!', category='success')
            return render_template("profil.html", user=current_user, groups=message_groups)
        else:
            if len(status) < 1:
                flash('Status is too short!', category='error')
            else:
                current_user.status = status
                db.session.commit()
                flash('Profile updated!', category='success')
    return render_template("profil.html", user=current_user, groups=message_groups)

@views.route('/flag', methods=['GET', 'POST'])
@login_required
async def flag():
    return render_template("flag.html", user=current_user)


@views.route('/add_friend', methods=['GET', 'POST'])
@login_required
async def add_friend_headfunction():
    if request.method == 'POST':
        if 'accept_friend' in request.form:
            user_email = request.form.get('accept_friend')
            accept_friend(user_email)

        elif 'reject_friend' in request.form:
            user_email = request.form.get('reject_friend')
            reject_friend(user_email)
            
        elif 'add_friend' in request.form:
            friend_email = request.form.get('friend_email')
            add_friend(friend_email)

        current_user_id = current_user.id
        userlist_of_friends = []
        for i in db.session.query(user_friends_association).filter_by(user_id=current_user_id).all():
            if db.session.query(user_friends_association).filter_by(user_id=i.friend_id, friend_id=current_user_id).first():
                userlist_of_friends.append(db.session.query(User).filter_by(id=i.friend_id).first())
        userlist_requests = []
        for i in db.session.query(user_friends_association).filter_by(friend_id=current_user_id).all():
            if not db.session.query(user_friends_association).filter_by(user_id=current_user_id, friend_id=i.user_id).first():
                userlist_requests.append(db.session.query(User).filter_by(id=i.user_id).first())
        return render_template("add_friend.html", friends = userlist_of_friends, requests = userlist_requests, user=current_user)
    
    else:
        current_user_id = current_user.id
        userlist_of_friends = []
        for i in db.session.query(user_friends_association).filter_by(user_id=current_user_id).all():
            if db.session.query(user_friends_association).filter_by(user_id=i.friend_id, friend_id=current_user_id).first():
                userlist_of_friends.append(db.session.query(User).filter_by(id=i.friend_id).first())
        userlist_requests = []
        for i in db.session.query(user_friends_association).filter_by(friend_id=current_user_id).all():
            if not db.session.query(user_friends_association).filter_by(user_id=current_user_id, friend_id=i.user_id).first():
                userlist_requests.append(db.session.query(User).filter_by(id=i.user_id).first())
        return render_template("add_friend.html", friends = userlist_of_friends, requests = userlist_requests, user=current_user)

def accept_friend(user_email):
    user_id = db.session.query(User).filter_by(email=user_email).first().id
    current_user_id = current_user.id
    new_friend = user_friends_association.insert().values(user_id=current_user_id, friend_id=user_id)
    db.session.execute(new_friend)
    db.session.commit()
    flash('Friend added!', category='success')
    
def reject_friend(user_email):
    user_id = db.session.query(User).filter_by(email=user_email).first().id
    current_user_id = current_user.id
    if db.session.query(user_friends_association).filter_by(user_id=user_id, friend_id=current_user_id).first():
        db.session.query(user_friends_association).filter_by(user_id=user_id, friend_id=current_user_id).delete()
        db.session.commit()
        flash('Friend rejected!', category='success')

def add_friend(friend_email):
    if len(friend_email) < 1:
        flash('Friend email is too short!', category='error')
    elif friend_email == current_user.email:
        flash('You cannot add yourself!', category='error')
    elif not db.session.query(User).filter_by(email=friend_email).first():
        flash('Email not found!', category='error')
    elif db.session.query(User).filter_by(email=friend_email).first():
        friend = db.session.query(User).filter_by(email=friend_email).first()
        friend_id = friend.id
        current_user_id = current_user.id
        if db.session.query(user_friends_association).filter_by(user_id=current_user_id, friend_id=friend_id).first():
            flash('Friend already added!', category='error')
        else:
            new_friend = user_friends_association.insert().values(user_id=current_user_id, friend_id=friend_id)
            db.session.execute(new_friend)
            db.session.commit()
            flash('Friend added!', category='success')

    
    
