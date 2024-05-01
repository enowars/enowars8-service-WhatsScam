from . import db
from flask_login import UserMixin
from sqlalchemy.sql import func

# NoteGroup = db.Table('NoteGroup',
#     db.Column('id', db.Integer, primary_key=True),
#     db.Column('name', db.String(150)),
#     db.Column('note_id', db.Integer, db.ForeignKey('Note.id')),
#     db.Column('user_id', db.Integer, db.ForeignKey('User.id'))
# )

# class Note(db.Model):
#     __tablename__ = 'Note'
#     id = db.Column(db.Integer, primary_key=True)
#     data = db.Column(db.String(10000))
#     date = db.Column(db.DateTime(timezone=True), default=func.now())
#     user_id = db.Column(db.Integer, db.ForeignKey('User.id'))  # Foreign key relationship to User

# class User(db.Model, UserMixin):
#     __tablename__ = 'User'
#     id = db.Column(db.Integer, primary_key=True)
#     email = db.Column(db.String(150), unique=True)
#     password = db.Column(db.String(150))
#     first_name = db.Column(db.String(150))
#     notes = db.relationship('Note', secondary=NoteGroup, backref='users')

NoteGroup = db.Table('NoteGroup',
    db.Column('id', db.Integer, primary_key=True),
    db.Column('name', db.String(150)),
    db.Column('NoteId', db.Integer, db.ForeignKey('Note.id')),
    db.Column('UserId', db.Integer, db.ForeignKey('User.id')),
    db.Column('endDate', db.Date))

class Note(db.Model):
    __tablename__ = 'Note'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(255))
    data = db.Column(db.String(10000))
    date = db.Column(db.DateTime(timezone=True), default=func.now())
    description = db.Column(db.Text)
    owner_id = db.Column(db.Integer, db.ForeignKey('User.id'))
    users = db.relationship('User', secondary=NoteGroup, backref='Note')

class User(db.Model, UserMixin):
    __tablename__ = 'User'
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(150), unique=True)
    password = db.Column(db.String(150))
    first_name = db.Column(db.String(150))
    name = db.Column(db.String)
    value = db.Column(db.String)
    notes_id = db.relationship('Note')
    notes = db.relationship('Note', secondary=NoteGroup, backref='User')



    

