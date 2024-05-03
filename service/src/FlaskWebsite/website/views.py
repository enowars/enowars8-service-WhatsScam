from flask import Blueprint, render_template, request, flash, jsonify, redirect, url_for
from flask_login import login_required, current_user
from .models import Note
from .models import NoteGroup
from . import db
import json



views = Blueprint('views', __name__)


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

    try:
        # Retrieve all rows from the NoteGroup table
        note_groups = db.session.query(NoteGroup).all()
    except:
        flash('No groups found.', category='error')
        return render_template("groups.html", user=current_user, groups=[])
    # Prepare a list of dictionaries where each dictionary represents a row with column names as keys and values as values
    groups = [{column.name: getattr(note_group, column.name) for column in NoteGroup.columns} for note_group in note_groups]
    return render_template("groups.html", user=current_user, groups=groups)

def creategroup(group_name, group_key):
    if request.method == 'POST':
        group_name = request.form.get('group_name')
        if len(group_name) < 1:
            flash('Group Name is too short!', category='error') 
        else:
            # Create a new NoteGroup instance and add it to the session
            new_group = NoteGroup.insert().values(name=group_name, group_key=group_key, UserId=current_user.id)
            db.session.execute(new_group)
            db.session.commit()
            flash('Group added!', category='success')
    # Retrieve all rows from the NoteGroup table
    note_groups = db.session.query(NoteGroup).all()
    # Prepare a list of dictionaries where each dictionary represents a row with column names as keys and values as values
    groups = [{column.name: getattr(note_group, column.name) for column in NoteGroup.columns} for note_group in note_groups]
    return render_template("groups.html", user=current_user, groups=groups)

def join_group(group_id, key):
    print("Joining group")
    group = db.session.query(NoteGroup).filter_by(id=group_id).all()
    if group:
        if key == group[0].group_key:
            #NoteGroup.insert().values(id=group[0].id, name=group[0]['name'], NoteId = group[0].NoteId,UserId=current_user.id, endDate=group[0].endDate, group_key=group[0]['group_key'])
            id = group[0][0]
            name = group[0][1]
            NoteId = group[0][2]
            UserId = current_user.id
            endDate = group[0][4]
            group_key = group[0][5]
            print(id, name, NoteId, UserId, endDate, group_key)

            # Add the current user to the group
            join = NoteGroup.insert().values(name=name, group_key=group_key, UserId=current_user.id)
            db.session.execute(join)
            db.session.commit()
            flash('You have joined the group!', category='success')
        else:
            flash('Incorrect key. Please try again.', category='error')
    else:
        flash('Group not found.', category='error')
    return redirect(url_for('views.home'))

@views.route('/creategroup/<int:group_id>', methods=['GET', 'POST'])
@login_required
def group_page(group_id):
    group_allusers = db.session.query(NoteGroup).filter_by(id=group_id).all()
    if group_allusers:
        if any(one_user.UserId == current_user.id for one_user in group_allusers):
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
