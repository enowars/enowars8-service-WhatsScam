import os
import sqlite3
import datetime
import time

Interval_for_cleanup = datetime.timedelta(minutes=11)

db_path = os.path.dirname(__file__)
db_path = os.path.dirname(db_path)
db_path = os.path.join(db_path, 'instance')
db_path = os.path.join(db_path, 'database.db')

def cleanup_header():
    time.sleep(120)
    time_to_sleep = 60
    while True:
        cleanup_Message()
        cleanup_User()
        cleanup_MessageGroup()
        cleanup_MessageOfGroup()
        time.sleep(time_to_sleep)


def cleanup_Message():
    db = sqlite3.connect(db_path)
    cursor = db.cursor()
    cursor.execute('DELETE FROM Message WHERE time < ?', (datetime.datetime.now() - Interval_for_cleanup,))
    db.commit()
    db.close()

def cleanup_User():
    db = sqlite3.connect(db_path)
    cursor = db.cursor()
    cursor.execute('SELECT id FROM User WHERE time < ?', (datetime.datetime.now() - Interval_for_cleanup,))
    users_to_delete = cursor.fetchall()
    users_to_delete = [user[0] for user in users_to_delete]
    cursor.execute('DELETE FROM user_group_association WHERE user_id IN ({})'.format(','.join('?' * len(users_to_delete))), users_to_delete)
    cursor.execute('DELETE FROM user_friends_association WHERE user_id IN ({})'.format(','.join('?' * len(users_to_delete))), users_to_delete)
    cursor.execute('DELETE FROM User WHERE time < ?', (datetime.datetime.now() - Interval_for_cleanup,))
    db.commit()
    db.close()

def cleanup_MessageGroup():
    db = sqlite3.connect(db_path)
    cursor = db.cursor()
    cursor.execute('DELETE FROM MessageGroup WHERE time < ?', (datetime.datetime.now() - Interval_for_cleanup,))
    db.commit()
    db.close()

def cleanup_MessageOfGroup():
    db = sqlite3.connect(db_path)
    cursor = db.cursor()
    cursor.execute('DELETE FROM MessageOfGroup WHERE time < ?', (datetime.datetime.now() - Interval_for_cleanup,))
    db.commit()
    db.close()


if __name__ == '__main__':
    cleanup_header()