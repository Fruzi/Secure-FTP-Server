import sqlite3
import os
import json

ROOT = os.getcwd() + os.sep
users_db = ROOT + 'users.db'
tags_db = ROOT + 'tags.db'
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
def create_tag_file():
    tags_existed = os.path.isfile(tags_db)
    with sqlite3.connect(tags_db) as dbcon:
        cursor = dbcon.cursor()
        if not tags_existed:
            cursor.execute("""CREATE TABLE Tags (
                            filename TEXT PRIMARY KEY NOT NULL,
                            tag TEXT NOT NULL)""")


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
                            filename TEXT PRIMARY KEY NOT NULL,
                            serial_num INTEGER NOT NULL)""")


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


# Adds a filename (encrypted) and it's tag to the tagfile.
def add_tag(_filename, _tag):
    with sqlite3.connect(tags_db) as dbcon:
        cursor = dbcon.cursor()
        cursor.execute("""INSERT INTO Tags VALUES (?,?)""", (_filename, _tag))
        return cursor.lastrowid


# Updates an existing file's tag in the tagfile.
def update_tag(_filename, _tag):
    with sqlite3.connect(tags_db) as dbcon:
        cursor = dbcon.cursor()
        cursor.execute("""UPDATE Tags SET tag = (?) WHERE filename = (?)""", (_tag, _filename))


def remove_tag(_filename):
    with sqlite3.connect(tags_db) as dbcon:
        cursor = dbcon.cursor()
        cursor.execute("""DELETE FROM Tags Where filename = (?)""", (_filename,))


# Returns a tuple with the tag for the given (encrypted) filename.
def fetch_tag(_filename):
    with sqlite3.connect(tags_db) as dbcon:
        cursor = dbcon.cursor()
        cursor.execute("""SELECT tag FROM Tags WHERE filename = (?)""", (_filename,))
        return cursor.fetchone()


# Adds a file path to filenums.db. Returns the number.
def add_filenum(_filepath):
    with sqlite3.connect(filenums_db) as dbcon:
        cursor = dbcon.cursor()
        num = get_next_filenum()
        cursor.execute("""INSERT INTO Filenums VALUES (?,?)""", (_filepath, num))
        return num


def fetch_filenum(_filepath):
    with sqlite3.connect(filenums_db) as dbcon:
        cursor = dbcon.cursor()
        cursor.execute("""SELECT serial_num FROM Filenums WHERE filename = (?)""", (_filepath,))
        return cursor.fetchone()


def fetch_filepath(_filenum):
    with sqlite3.connect(filenums_db) as dbcon:
        cursor = dbcon.cursor()
        cursor.execute("""SELECT filename FROM Filenums WHERE serial_num = (?)""", (_filenum,))
        return cursor.fetchone()


def get_next_filenum():
    with sqlite3.connect(filenums_db) as dbcon:
        cursor = dbcon.cursor()
        cursor.execute("""SELECT MAX(serial_num) FROM Filenums""")
        max_num = cursor.fetchone()[0]
        return (max_num + 1) if max_num is not None else 0


if __name__ == '__main__':
    main()

