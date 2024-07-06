from . import db
from flask_login import UserMixin
from sqlalchemy.sql import func

# Association table for the many-to-many relationship between users and groups
user_group_association = db.Table('user_group_association',
    db.Column('user_id', db.Integer, db.ForeignKey('User.id')),
    db.Column('group_id', db.Integer, db.ForeignKey('MessageGroup.id'))
)

user_friends_association = db.Table('user_friends_association',
    db.Column('user_id', db.Integer, db.ForeignKey('User.id')),
    db.Column('friend_id', db.Integer, db.ForeignKey('User.id'))
)

class MessageGroup(db.Model):
    __tablename__ = 'MessageGroup'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(150))
    group_key = db.Column(db.String(255))
    time = db.Column(db.DateTime(timezone=True), default=func.now())
    # Define the relationship with User using the association table
    users = db.relationship('User', secondary=user_group_association, backref=db.backref('groups', lazy='dynamic'))
    message = db.relationship('MessageOfGroup', backref='group', lazy=True)

class MessageOfGroup(db.Model):
    __tablename__ = 'MessageOfGroup'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(255))
    data = db.Column(db.String(10000))
    encrypted_data = db.Column(db.String(10000))
    time = db.Column(db.DateTime(timezone=True), default=func.now())
    description = db.Column(db.Text)
    group_id = db.Column(db.Integer, db.ForeignKey('MessageGroup.id'))
    key = db.Column(db.String(255))
    nonce = db.Column(db.String(255))
    owner_id = db.Column(db.Integer, db.ForeignKey('User.id'))

class Message(db.Model):
    __tablename__ = 'Message'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(255))
    data = db.Column(db.String(10000))
    encrypted_data = db.Column(db.String(10000))
    description = db.Column(db.Text)
    owner_id = db.Column(db.Integer, db.ForeignKey('User.id'))
    destination_id = db.Column(db.Integer)
    target_email = db.Column(db.String(150))
    time = db.Column(db.DateTime(timezone=True), default=func.now())

class User(db.Model, UserMixin):
    __tablename__ = 'User'
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(150), unique=True)
    password = db.Column(db.String(150))
    name = db.Column(db.String(150))
    message = db.relationship('Message', backref='owner', lazy=True)
    private_key = db.Column(db.String(255), unique=True)
    public_key = db.Column(db.String(255), unique=True)
    public_key_name = db.Column(db.String(255), unique=True)
    private_key_name = db.Column(db.String(255), unique=True)
    token = db.Column(db.String(255), unique=True)
    status = db.Column(db.String(255))
    time = db.Column(db.DateTime(timezone=True), default=func.now())



