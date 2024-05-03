from . import db
from flask_login import UserMixin
from sqlalchemy.sql import func

NoteGroup = db.Table('NoteGroup',
    db.Column('id', db.Integer, primary_key=True),
    db.Column('name', db.String(150)),
    db.Column('UserId', db.Integer, db.ForeignKey('User.id')),
    db.Column('NoteId', db.Integer, db.ForeignKey('Note.id')),
    db.Column('endDate', db.Date),
    db.Column('group_key', db.String(255)))

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