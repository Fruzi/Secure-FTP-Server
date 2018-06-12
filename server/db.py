import sqlite3
import os
import json

ROOT = os.getcwd() + os.sep
users_db = ROOT + 'users.db'
file_meta_db = ROOT + 'file_metadata.db'
user_meta_db = ROOT + 'user_metadata.db'
filenums_db = ROOT + 'filenums.db'


def main():
    # create_user_metadata()
    # create_tag_file()
    # add_user("Rawn", "a3nme", "123456")
    # add_user("Uzi", "1245", "anjkf")
    # print(fetch_tag("uzi's file"))
    # print(fetch_tag("few"))
    # print(fetch_user("banana"))
    # print(has_user("Uzi"))
    # print(has_user("banana"))
    # add_user_metadata("v", '', '', {'p': '5'}, '', '')
    print(fetch_user_metadata("VVVV")[1])
    # print(has_user("Amit"))


# Check if userfile exists, if not then create it.
def create_user_file():
    db_existed = os.path.isfile(users_db)
    with sqlite3.connect(users_db) as dbcon:
        cursor = dbcon.cursor()
        if not db_existed:
            cursor.execute("""CREATE TABLE Users (
                            username TEXT PRIMARY KEY NOT NULL,
                            salt TEXT NOT NULL,
                            hashed_pass BLOB NOT NULL)""")


# check if tagfile exits, if not then create it.
def create_file_metadata():
    file_meta_existed = os.path.isfile(file_meta_db)
    with sqlite3.connect(file_meta_db) as dbcon:
        cursor = dbcon.cursor()
        if not file_meta_existed:
            cursor.execute("""CREATE TABLE FileMetadata (
                            tag TEXT NOT NULL,
                            size INTEGER NOT NULL,
                            numpath TEXT NOT NULL,
                            FOREIGN KEY (numpath) REFERENCES Filenums(numpath))""")


def create_user_metadata():
    metadata_existed = os.path.isfile(user_meta_db)
    with sqlite3.connect(user_meta_db) as dbcon:
        cursor = dbcon.cursor()
        if not metadata_existed:
            cursor.execute("""CREATE TABLE Metadata (
                            username TEXT PRIMARY KEY NOT NULL,
                            homedir TEXT NOT NULL,
                            perm TEXT NOT NULL,
                            operms NOT NULL,
                            msg_login TEXT NOT NULL,
                            msg_quit TEXT NOT NULL)""")


def create_filenum_file():
    tags_existed = os.path.isfile(filenums_db)
    with sqlite3.connect(filenums_db) as dbcon:
        cursor = dbcon.cursor()
        if not tags_existed:
            cursor.execute("""CREATE TABLE Filenums (
                            numpath TEXT PRIMARY KEY NOT NULL,
                            filename TEXT NOT NULL)""")
            cursor.execute("""INSERT INTO Filenums VALUES (0, 0)""")


def add_user_metadata(username, homedir, perm, operms, msg_login, msg_quit):
    with sqlite3.connect(user_meta_db) as dbcon:
        cursor = dbcon.cursor()
        cursor.execute("""INSERT INTO Metadata VALUES (?, ?, ?, ?, ?, ?)""",
                       (username, homedir, perm, json.dumps(operms), msg_login, msg_quit))
        return cursor.lastrowid


def remove_user_metadata(username):
    with sqlite3.connect(user_meta_db) as dbcon:
        cursor = dbcon.cursor()
        cursor.execute("""DELETE FROM Metadata WHERE username = (?)""", (username,))
        return cursor.lastrowid


def fetch_user_metadata(username):
    with sqlite3.connect(user_meta_db) as dbcon:
        cursor = dbcon.cursor()
        cursor.execute("""SELECT homedir, perm, msg_login, msg_quit FROM Metadata WHERE username = (?)""", (username,))
        return cursor.fetchone()


def fetch_operms(username):
    with sqlite3.connect(user_meta_db) as dbcon:
        cursor = dbcon.cursor()
        cursor.execute("""SELECT operms FROM Metadata WHERE username = (?)""", (username,))
        return json.loads(cursor.fetchone()[0])


# Adds a user to the userfile. Expects to receive a salted password post hashing.
def add_user(_name, _salt, _pass):
    with sqlite3.connect(users_db) as dbcon:
        cursor = dbcon.cursor()
        cursor.execute("""INSERT INTO Users VALUES (?,?,?)""", (_name, _salt, _pass))
        return cursor.lastrowid


def remove_user(_name):
    with sqlite3.connect(users_db) as dbcon:
        cursor = dbcon.cursor()
        cursor.execute("""DELETE FROM Users WHERE username = (?)""", (_name,))


# Returns a tuple contains the salt and hashed password of a given username
def fetch_user(_name):
    with sqlite3.connect(users_db) as dbcon:
        cursor = dbcon.cursor()
        cursor.execute("""SELECT salt, hashed_pass FROM Users WHERE username = (?)""", (_name,))
        return cursor.fetchone()


def has_user(_name):
    if fetch_user(_name):
        return 1
    return 0


def add_file_meta(_numpath, _tag, _size):
    with sqlite3.connect(file_meta_db) as dbcon:
        cursor = dbcon.cursor()
        cursor.execute("""INSERT INTO FileMetadata VALUES (?,?,?)""", (_tag, _size, _numpath))
        return cursor.lastrowid


# Updates an existing file's tag in the tagfile.
def update_file_meta(_numpath, _tag, _size):
    with sqlite3.connect(file_meta_db) as dbcon:
        cursor = dbcon.cursor()
        cursor.execute("""UPDATE FileMetadata SET tag = (?), size = (?) WHERE numpath = (?)""", (_tag, _size, _numpath))


# Returns a tuple with the tag for the given (encrypted) filename.
def fetch_tag(_numpath):
    with sqlite3.connect(file_meta_db) as dbcon:
        cursor = dbcon.cursor()
        cursor.execute("""SELECT tag FROM FileMetadata WHERE numpath = (?)""", (_numpath,))
        return cursor.fetchone()


def fetch_size(_numpath):
    with sqlite3.connect(file_meta_db) as dbcon:
        cursor = dbcon.cursor()
        cursor.execute("""SELECT size FROM FileMetadata WHERE numpath = (?)""", (_numpath,))
        return cursor.fetchone()


def fetch_all_file_metadata():
    with sqlite3.connect(file_meta_db) as dbcon:
        cursor = dbcon.cursor()
        cursor.execute("""SELECT numpath, size FROM FileMetadata""")
        return cursor.fetchall()


# Adds a file path to filenums.db. Returns the number.
def add_numpath(_numpath, _filepath):
    with sqlite3.connect(filenums_db) as dbcon:
        cursor = dbcon.cursor()
        cursor.execute("""INSERT INTO Filenums VALUES (?,?)""", (_numpath, _filepath))
        return cursor.lastrowid


def fetch_numpath(_filepath):
    with sqlite3.connect(filenums_db) as dbcon:
        cursor = dbcon.cursor()
        cursor.execute("""SELECT numpath FROM Filenums WHERE filename = (?)""", (_filepath,))
        return cursor.fetchone()


def fetch_filepath(_numpath):
    with sqlite3.connect(filenums_db) as dbcon:
        cursor = dbcon.cursor()
        cursor.execute("""SELECT filename FROM Filenums WHERE numpath = (?)""", (_numpath,))
        return cursor.fetchone()


def get_next_filenum():
    with sqlite3.connect(filenums_db) as dbcon:
        cursor = dbcon.cursor()
        cursor.execute("""SELECT numpath FROM Filenums WHERE filename = 0""")
        max_num = int(cursor.fetchone()[0])
        cursor.execute("""UPDATE Filenums SET numpath = (?) WHERE filename = 0""", (max_num + 1,))
        return max_num


def remove_file_by_num(_filenum):
    with sqlite3.connect(file_meta_db) as dbcon:
        cursor = dbcon.cursor()
        cursor.execute("""DELETE * FROM FileMetadata WHERE numpath = (?)""", (_filenum,))
    with sqlite3.connect(filenums_db) as dbcon:
        cursor = dbcon.cursor()
        cursor.execute("""DELETE * FROM Filenums WHERE numpath = (?)""", (_filenum,))
        return cursor.fetchone()


if __name__ == '__main__':
    main()

