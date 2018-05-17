import sqlite3
import os


def main():
    # create_user_file()
    # create_tag_file()
    # add_user("Rawn", "a3nme", "123456")
    # add_user("Uzi", "1245", "anjkf")
    # print(fetch_tag("uzi's file"))
    # print(fetch_tag("few"))
    print(fetch_user("banana"))
    print(has_user("Uzi"))
    print(has_user("banana"))


# Check if userfile exists, if not then create it.
def create_user_file():
    db_existed = os.path.isfile('users.db')
    with sqlite3.connect('users.db') as dbcon:
        cursor = dbcon.cursor()
        if not db_existed:
            cursor.execute("""CREATE TABLE Users (
                            username TEXT PRIMARY KEY NOT NULL,
                            salt TEXT NOT NULL,
                            hashed_pass TEXT NOT NULL)""")


# check if tagfile exits, if not then create it.
def create_tag_file():
    tags_existed = os.path.isfile('tags.db')
    with sqlite3.connect('tags.db') as dbcon:
        cursor = dbcon.cursor()
        if not tags_existed:
            cursor.execute("""CREATE TABLE Tags (
                            filename TEXT PRIMARY KEY NOT NULL,
                            tag TEXT NOT NULL)""")


# Adds a user to the userfile. Expects to receive a salted password post hashing.
def add_user(_name, _salt, _pass):
    with sqlite3.connect('users.db') as dbcon:
        cursor = dbcon.cursor()
        cursor.execute("""INSERT INTO Users VALUES (?,?,?)""", (_name, _salt, _pass))
        return cursor.lastrowid


# Returns a tuple contains the salt and hashed password of a given username
def fetch_user(_name):
    with sqlite3.connect('users.db') as dbcon:
        cursor = dbcon.cursor()
        cursor.execute("""SELECT salt, hashed_pass FROM Users WHERE username = (?)""", (_name,))
        return cursor.fetchone()


def has_user(_name):
    if fetch_user(_name):
        return 1
    return 0


# Adds a filename (encrypted) and it's tag to the tagfile.
def add_tag(_filename, _tag):
    with sqlite3.connect('tags.db') as dbcon:
        cursor = dbcon.cursor()
        cursor.execute("""INSERT INTO Tags VALUES (?,?)""", (_filename, _tag))
        return cursor.lastrowid


# Returns a tuple with the tag for the given (encrypted) filename.
def fetch_tag(_filename):
    with sqlite3.connect('tags.db') as dbcon:
        cursor = dbcon.cursor()
        cursor.execute("""SELECT tag FROM Tags WHERE filename = (?)""", (_filename,))
        return cursor.fetchone()


if __name__ == '__main__':
    main()

