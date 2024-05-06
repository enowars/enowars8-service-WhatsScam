from flask import Blueprint, render_template, request, flash, jsonify, redirect, url_for
from flask_login import login_required, current_user
from .models import Note
from .models import NoteGroup
from .models import User
from .models import user_group_association
from .models import NoteOfGroup
from . import db
import json

from . import aes_encryption


views = Blueprint('views', __name__)

#works
@views.route('/', methods=['GET', 'POST'])
@login_required
def home():
    if request.method == 'POST': 
        note = request.form.get('note')#Gets the note from the HTML 

        if len(note) < 1:
            flash('Note is too short!', category='error') 
        else:
            new_note = Note(data=note, owner_id=current_user.id)  #providing the schema for the note 
            db.session.add(new_note) #adding the note to the database 
            db.session.commit()
            flash('Note added!', category='success')
    n = Note.query
    return render_template("home.html", user=current_user, notes=n)

#works
@views.route('/creategroup', methods=['GET', 'POST'])
@login_required
def group_headfunction():
    if request.method == 'POST':
        print(request.form)
        if 'join_group' in request.form:
            group_id = request.form.get('join_group')
            key = request.form.get('group_key_join_' + str(group_id))
            return join_group(group_id, key)
        elif 'add_group' in request.form:
            group_name = request.form.get('group_name')
            group_key = request.form.get('group_key')
            return creategroup(group_name, group_key)

    # Retrieve all rows from the NoteGroup table
    note_groups = db.session.query(NoteGroup).all()
    groups = [{column.name: getattr(note_group, column.name) for column in NoteGroup.__table__.columns} for note_group in note_groups]
    return render_template("groups.html", user=current_user, groups=groups)

#works
def creategroup(group_name, group_key):
    if request.method == 'POST':
        group_name = request.form.get('group_name')
        if len(group_name) < 1 or len(group_key) < 1:
            flash('Group Name or Key is too short!', category='error')
        
        elif db.session.query(NoteGroup).filter_by(name=group_name).first():
            flash('Group name already exists.', category='error')

        else:
            # Create a new NoteGroup instance
            new_group = NoteGroup(name=group_name, group_key=group_key)

            # Add the current user to the group
            new_group.users.append(current_user)

            # Add the group to the session and commit
            db.session.add(new_group)
            db.session.commit()
            flash('Group added!', category='success')

    #Show all the groups on the page

    # Retrieve all rows from the NoteGroup table
    note_groups = db.session.query(NoteGroup).all()
    # Prepare a list of dictionaries where each dictionary represents a row with column names as keys and values as values
    groups = [{column.name: getattr(note_group, column.name) for column in NoteGroup.__table__.columns} for note_group in note_groups]
    return render_template("groups.html", user=current_user, groups=groups)

#works
def join_group(group_id, key):
    group = db.session.query(NoteGroup).filter_by(id=group_id).first()
    if group:
        if key == group.group_key:
            id = group.id
            UserId = current_user.id
            if db.session.query(user_group_association).filter_by(user_id=UserId, group_id=id).first():
                #flash('You are already a member of this group.', category='error')
                print(redirect(url_for('views.group_page', group_id=group.id)).data)
                return redirect(url_for('views.group_page', group_id=group.id))
            else:
                # Add the current user to the group
                join = user_group_association.insert().values(user_id=UserId, group_id=id)
                db.session.execute(join)
                db.session.commit()
                flash('You have joined the group!', category='success')
                group = db.session.query(NoteGroup).filter_by(id=group_id).first()
                print(redirect(url_for('views.group_page', group_id=group.id)))
                return redirect(url_for('views.group_page', group_id=group.id))
        else:
            flash('Incorrect key. Please try again.', category='error')
    else:
        flash('Group not found.', category='error')
    return redirect(url_for('views.home'))

#works
@views.route('/creategroup/<int:group_id>', methods=['GET', 'POST'])
@login_required
def group_page(group_id):
    #id unique so only one object will be returned
    group_allusers = db.session.query(NoteGroup).filter_by(id=group_id).first()
    if group_allusers:
        if any(one_user == current_user for one_user in group_allusers.users):
                if request.method == 'POST':
                    print("da")
                    note_of_group_data = request.form.get('note_of_group')#Gets the note from the HTML 
                    if len(note_of_group_data) < 1:
                        flash('Note is too short!', category='error') 
                    else:
                        encrypted_data = aes_encryption.insecure_aes_encrypt(note_of_group_data)
                        new_note_of_group = NoteOfGroup(data=note_of_group_data, group_id=group_allusers.id, encrypted_data=encrypted_data)
                        db.session.add(new_note_of_group) #adding the note to the database 
                        db.session.commit()
                        flash('Note added!', category='success')
                print("hier")
                n = NoteOfGroup.query.filter_by(group_id=group_id)
                return render_template("group_page.html", user=current_user, notes=n, group=group_allusers)
        else:
            n = NoteOfGroup.query.filter_by(group_id=group_id)
            return render_template("group_page_unauthorized.html", user=current_user, notes=n, group=group_allusers)
            #flash('You are not authorized to access this group.', category='error')
    else:
        flash('Group not found.', category='error')
    return redirect(url_for('views.home'))

#@views.route('/creategroup/<int:group_id>/addnote', methods=['POST'])

#works
#view js script for information and base.html
@views.route('/delete-note', methods=['POST'])
def delete_note():  
    print(request.data)
    note = json.loads(request.data) # this function expects a JSON from the INDEX.js file 
    noteId = note['noteId']
    note = Note.query.get(noteId)
    if note:
        if note.owner_id == current_user.id:
            db.session.delete(note)
            db.session.commit()

    return jsonify({})

#works
#view js script for information and base.html
@views.route('/delete-note-group', methods=['POST'])
def delete_note_group():
    print("drinnnnnnn")
    note = json.loads(request.data)
    print(note)
    noteId = note['noteGroupId']
    print(noteId)
    note = NoteOfGroup.query.get(noteId)
    print(note)

    if note:
        group = NoteGroup.query.filter_by(id=note.group_id).first()
        if any(one_user == current_user for one_user in group.users):
            db.session.delete(note)
            db.session.commit()
    
    return jsonify({})
