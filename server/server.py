import os
import logging
import db
import pyftpdlib.filesystems
from pyftpdlib.authorizers import DummyAuthorizer
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.backends import default_backend
from pyftpdlib.handlers import FTPHandler, proto_cmds
from pyftpdlib.servers import FTPServer


class MySmartyAuthorizer(DummyAuthorizer):

    def __init__(self):
        db.create_user_file()
        db.create_tag_file()
        db.create_user_metadata()

    def add_user(self, username, password, homedir, perm='elr',
                 msg_login="Login successful.", msg_quit="Goodbye."):
        if self.has_user(username):
            raise ValueError('user %r already exists' % username)
        if not isinstance(homedir, pyftpdlib.filesystems.unicode):
            homedir = homedir.decode('utf8')
        if not os.path.isdir(homedir):
            raise ValueError('no such directory: %r' % homedir)
        homedir = os.path.realpath(homedir)
        self._check_permissions(username, perm)
        salt = os.urandom(16)
        kdf = Scrypt(
            salt=salt,
            length=32,
            n=2**14,
            r=8,
            p=1,
            backend=default_backend()
        )
        key = kdf.derive(bytes.fromhex(password))
        db.add_user(username, salt, key)
        db.add_user_metadata(username, homedir, perm, '', msg_login, msg_quit)

    def remove_user(self, username):
        super.remove_user(username)
        db.remove_user(username)
        db.remove_user_metadata(username)

    def validate_authentication(self, username, password, handler):
        msg = "Authentication failed."
        if not self.has_user(username):
            raise Exception(msg)
        udata = db.fetch_user(username)
        kdf = Scrypt(
            salt=udata[0],
            length=32,
            n=2**14,
            r=8,
            p=1,
            backend=default_backend()
        )
        kdf.verify(bytes.fromhex(password), udata[1])

    def get_home_dir(self, username):
        return db.fetch_user_metadata(username)[0]

    def has_user(self, username):
        return db.has_user(username)

    def has_perm(self, username, perm, path=None):
        """Whether the user has permission over path (an absolute
        pathname of a file or a directory).

        Expected perm argument is one of the following letters:
        "elradfmwMT".
        """
        if path is None:
            return perm in self.get_perms(username)

        path = os.path.normcase(path)
        operms = self.get_operms(username)
        if not operms:
            return perm in self.get_perms(username)
        for dir in operms.keys():
            operm, recursive = operms[dir]
            if self._issubpath(path, dir):
                if recursive:
                    return perm in operm
                if (path == dir or os.path.dirname(path) == dir and not
                        os.path.isdir(path)):
                    return perm in operm
        return perm in self.get_perms(username)

    def get_perms(self, username):
        """Return current user permissions."""
        return db.fetch_user_metadata(username)[1]

    def get_operms(self, username):
        return db.fetch_operms(username)

    def get_msg_login(self, username):
        return db.fetch_user_metadata(username)[2]

    def get_msg_quit(self, username):
        try:
            return db.fetch_user_metadata(username)[3]
        except KeyError:
            return "Goodbye."




class MyFTPHandler(FTPHandler):

    def __init__(self, conn, server, ioloop=None):
        # adding the RGTR (register) command to the protocol
        proto_cmds['RGTR'] = dict(
            perm=None, auth=False, arg=True,
            help='Syntax: RGTR <SP> user-name (set username).')
        self.registering = False
        super().__init__(conn, server, ioloop)

    def ftp_RGTR(self, line):
        """Register a new user."""
        if self.authorizer.has_user(line):
            self.respond("503 Username already exists. Choose a different name.")
            return

        self.respond('331 Username ok, send password.')
        self.username = line
        self.registering = True

    def ftp_PASS(self, line):
        if not self.registering:
            super().ftp_PASS(line)
            return

        username = self.username
        self.flush_account()
        self.username = username

        self.registering = False
        self.handle_auth_success(username, line, "New USER '%s' registered." % self.username)
        self.fs.mkdir(username)
        self.authorizer.add_user(username, line, username, perm='elradfmwMT')
        print("!!!!!!!")


def main():
    # TODO: Make secure authorizer
    authorizer = MySmartyAuthorizer()
    # authorizer.add_anonymous(os.getcwd(), perm='')

    handler = MyFTPHandler
    handler.authorizer = authorizer

    # Instantiate FTP server class and listen on localhost:21
    address = ('localhost', 21)
    server = FTPServer(address, handler)

    # set a limit for connections
    server.max_cons = 256
    server.max_cons_per_ip = 5

    logging.basicConfig(level=logging.DEBUG)

    # start ftp server
    server.serve_forever()


if __name__ == '__main__':
    main()
