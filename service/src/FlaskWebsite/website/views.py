from flask import Blueprint, render_template, request, flash, jsonify, redirect, url_for
from flask_login import login_required, current_user
from .models import Note
from .models import NoteGroup
from .models import User
from .models import user_group_association
from . import db
import json



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
            join_group(group_id, key)
        elif 'add_group' in request.form:
            group_name = request.form.get('group_name')
            group_key = request.form.get('group_key')
            creategroup(group_name, group_key)

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
            print("drin")
            id = group.id
            name = group.name   
            UserId = current_user.id
            group_key = group.group_key
            print(id, name, UserId, group_key)

            # Add the current user to the group
            join = user_group_association.insert().values(user_id=UserId, group_id=id)
            db.session.execute(join)
            db.session.commit()
            flash('You have joined the group!', category='success')
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
            # Retrieve all notes associated with the group
            #notes = db.session.query(Note).filter_by(NoteGroup.id = Note).all()
            return render_template("group_page.html", user=current_user, group=group_allusers)
        else:
            flash('You are not authorized to access this group.', category='error')
    else:
        flash('Group not found.', category='error')
    return redirect(url_for('views.home'))

# @views.route('/creategroup', methods=['POST'])
# @login_required
# def join_group(group_id):
#     key = request.form.get('key')
#     group = NoteGroup.query.get(group_id)
#     if group:
#         if key == group.group_key:
#             # Add the current user to the group
#             group.users.append(current_user)
#             db.session.commit()
#             flash('You have joined the group!', category='success')
#         else:
#             flash('Incorrect key. Please try again.', category='error')
#     else:
#         flash('Group not found.', category='error')
#     return redirect(url_for('views.home'))
    
#@views.route('/creategroup/<int:group_id>/addnote', methods=['POST'])

#works
@views.route('/delete-note', methods=['POST'])
def delete_note():  
    note = json.loads(request.data) # this function expects a JSON from the INDEX.js file 
    noteId = note['noteId']
    note = Note.query.get(noteId)
    if note:
        if note.owner_id == current_user.id:
            db.session.delete(note)
            db.session.commit()

    return jsonify({})
