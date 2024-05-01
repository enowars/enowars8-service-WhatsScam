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
def creategroup():
    if request.method == 'POST':
        group_name = request.form.get('group_name')
        if len(group_name) < 1:
            flash('Group Name is too short!', category='error') 
        else:
            # Create a new NoteGroup instance and add it to the session
            new_group = NoteGroup.insert().values(name=group_name, UserId=current_user.id)
            db.session.execute(new_group)
            db.session.commit()
            flash('Group added!', category='success')
        
    print("here")
    # Retrieve all rows from the NoteGroup table
    note_groups = db.session.query(NoteGroup).all()
    # Prepare a list of dictionaries where each dictionary represents a row with column names as keys and values as values
    groups = [{column.name: getattr(note_group, column.name) for column in NoteGroup.columns} for note_group in note_groups]
    return render_template("groups.html", user=current_user, groups=groups)

@views.route('/creategroup/<int:group_id>', methods=['GET', 'POST'])
@login_required
def group_page(group_id):
    group_allusers = db.session.query(NoteGroup).filter_by(id=group_id).all()
    if group_allusers:
        if any(one_user.UserId == current_user.id for one_user in group_allusers):
            # Retrieve all notes associated with the group
            notes = db.session.query(Note).filter_by(owner_id=current_user.id).all()
            return render_template("group_page.html", user=current_user, group=group_allusers, notes=notes)
        else:
            flash('You are not authorized to access this group.', category='error')
    else:
        flash('Group not found.', category='error')
    return redirect(url_for('views.home'))

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
