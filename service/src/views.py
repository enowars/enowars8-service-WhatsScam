from flask import Blueprint, render_template, request, flash, jsonify, redirect, url_for
from flask_login import login_required, current_user
from .models import Note
from .models import NoteGroup
from .models import User
from .models import user_group_association
from .models import NoteOfGroup
from . import db
import json
import datetime as dt

from . import aes_encryption
from . import rsa_encryption


views = Blueprint('views', __name__)

@views.route('/', methods=['GET', 'POST'])
@login_required
async def home():
    if request.method == 'POST': 
        note = request.form.get('note')#Gets the note from the HTML
        public_key = request.form.get('public_key')

        if len(note) < 1:
            flash('Note is too short!', category='error')
        else:
            users = User.query.all()
            public_keys = [user.public_key_name for user in users]
            
            if public_key is None:
                new_note = Note(data=note, owner_id=current_user.id, destination_id=None, time = dt.datetime.now())  #providing the schema for the note
            elif public_key not in public_keys:
                new_note = Note(data=note, owner_id=current_user.id, destination_id=None, time = dt.datetime.now())  #providing the schema for the note
                flash('Public key not found, message not encrypted', category='error')
            else:
                target_user = User.query.filter_by(public_key_name=public_key).first()
                target_user_id = target_user.id
                encrypted_note = rsa_encryption.encryption_of_message(note, target_user.public_key)
                #print("encrypted note: ", encrypted_note)
                new_note = Note(data=note, encrypted_data = encrypted_note, owner_id=current_user.id, destination_id=target_user_id, time = dt.datetime.now())  #providing the schema for the note
                flash('Message encrypted and sent', category='success')

            db.session.add(new_note) #adding the note to the database 
            db.session.commit()
    n = Note.query
    return render_template("home.html", user=current_user, notes=n)

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

    note_groups = db.session.query(NoteGroup).all()
    groups = [{column.name: getattr(note_group, column.name) for column in NoteGroup.__table__.columns} for note_group in note_groups]
    return render_template("groups.html", user=current_user, groups=groups)

def creategroup(group_name, group_key):
    if request.method == 'POST':
        group_name = request.form.get('group_name')
        if len(group_name) < 1 or len(group_key) < 1:
            flash('Group Name or Key is too short!', category='error')
        
        elif db.session.query(NoteGroup).filter_by(name=group_name).first():
            flash('Group name already exists.', category='error')

        else:
            # Create a new NoteGroup instance
            new_group = NoteGroup(name=group_name, group_key=group_key, time= dt.datetime.now())

            # Add the current user to the group
            new_group.users.append(current_user)

            # Add the group to the session and commit
            db.session.add(new_group)
            db.session.commit()
            flash('Group added!', category='success')
            return redirect(url_for('views.group_page', group_id=new_group.id))

    #Show all the groups on the page
    # Retrieve all rows from the NoteGroup table
    note_groups = db.session.query(NoteGroup).all()
    # Prepare a list of dictionaries where each dictionary represents a row with column names as keys and values as values
    groups = [{column.name: getattr(note_group, column.name) for column in NoteGroup.__table__.columns} for note_group in note_groups]
    return render_template("groups.html", user=current_user, groups=groups)

def join_group(group_id, key):
    group = db.session.query(NoteGroup).filter_by(id=group_id).first()
    if group:
        if key == group.group_key:
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
                group = db.session.query(NoteGroup).filter_by(id=group_id).first()
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
    group_allusers = db.session.query(NoteGroup).filter_by(id=group_id).first()
    if group_allusers:
        if any(one_user == current_user for one_user in group_allusers.users):
                if request.method == 'POST':
                    note_of_group_data = request.form.get('note_of_group')#Gets the note from the HTML 
                    if len(note_of_group_data) < 1:
                        flash('Note is too short!', category='error') 
                    else:
                        encrypted_data, key, nonce = aes_encryption.aes_encrypt(note_of_group_data)
                        new_note_of_group = NoteOfGroup(data=note_of_group_data, group_id=group_allusers.id, encrypted_data=encrypted_data, time= dt.datetime.now(), key=str(key), nonce=str(nonce))
                        db.session.add(new_note_of_group) #adding the note to the database 
                        db.session.commit()
                        flash('Note added!', category='success')
                n = NoteOfGroup.query.filter_by(group_id=group_id)
                return render_template("group_page.html", user=current_user, notes=n, group=group_allusers)
        else:
            n = NoteOfGroup.query.filter_by(group_id=group_id)
            return render_template("group_page_unauthorized.html", user=current_user, notes=n, group=group_allusers)
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
@views.route('/delete-note', methods=['POST'])
async def delete_note():  
    note = json.loads(request.data) # this function expects a JSON from the INDEX.js file 
    noteId = note['noteId']
    note = Note.query.get(noteId)
    if note:
        if note.owner_id == current_user.id:
            db.session.delete(note)
            db.session.commit()

    return jsonify({})

#view js script for information and base.html
@views.route('/delete-note-group', methods=['POST'])
async def delete_note_group():
    note = json.loads(request.data)
    noteId = note['noteGroupId']
    note = NoteOfGroup.query.get(noteId)

    if note:
        group = NoteGroup.query.filter_by(id=note.group_id).first()
        if any(one_user == current_user for one_user in group.users):
            db.session.delete(note)
            db.session.commit()
    
    return jsonify({})

######

@views.route('/profil', methods=['GET', 'POST'])
@login_required
async def profil():
    if request.method == 'POST':
        status = request.form.get('status')
        public_key = request.form.get('public_key')
        if len(status) < 1:
            flash('Status to short!', category='error')
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
                

                current_user.public_key = public_key
                current_user.public_key_name = final_text
                current_user.private_key = private_key
                current_user.status = status
                db.session.commit()
                return redirect(url_for('views.profil'))
        else:
            current_user.status = status
            db.session.commit()
            flash('Profile updated!', category='success')
    return render_template("profil.html", user=current_user)