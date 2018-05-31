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
        super().remove_user(username)
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
        super().__init__(conn, server, ioloop)

        # adding the RGTR (register) and TAG commands to the protocol
        proto_cmds.update({
            'RGTR': dict(
                perm=None, auth=False, arg=True,
                help='Syntax: RGTR <SP> user-name (set username).'),
            'TAG': dict(
                perm='w', auth=True, arg=True,
                help='Syntax: MAC <SP> tag (store a file tag).')
        })

        self._registering = False
        self._received_file = None
        self._sending_temp_file = False

    def ftp_RGTR(self, line):
        """Register a new user."""
        if self.authorizer.has_user(line):
            self.respond("503 Username already exists. Choose a different name.")
            return

        self.respond('331 Username ok, send password.')
        self.username = line
        self._registering = True

    def ftp_PASS(self, line):
        if not self._registering:
            super().ftp_PASS(line)
            return

        username = self.username
        self.flush_account()
        self.username = username

        self._registering = False
        self.handle_auth_success(username, line, "New USER '%s' registered." % self.username)
        self.fs.mkdir(username)
        self.authorizer.add_user(username, line, username, perm='elradfmwMT')
        self.flush_account()

    def ftp_TAG(self, line):
        """Receive an authorization tag for a file that was now uploaded."""
        if not self._received_file:
            self.respond("503 Bad sequence of commands: use STOR first.")
            return
        if not db.fetch_tag(self._received_file):
            db.add_tag(self._received_file, line)
        else:
            db.update_tag(self._received_file, line)
        self._received_file = None
        self.respond("250 File transfer completed.")

    def ftp_RETR(self, file):
        """
        Creates a temporary file with the requested file data and tag from the db appended to it
        and calls the super-method with it
        """
        temp_filename = file + '__temp__'
        with open(temp_filename, 'wb') as temp_file, self.fs.open(file, 'rb') as fd:
            temp_file.write(fd.read())
            temp_file.write(bytes.fromhex(db.fetch_tag(file)[0]))
        self._sending_temp_file = True
        return super().ftp_RETR(temp_filename)

    def on_file_received(self, file):
        self._received_file = file
        self.respond("350 Ready for authentication tag.")

    def on_file_sent(self, file):
        """Remove temporary file"""
        if self._sending_temp_file:
            os.remove(file)
            self._sending_temp_file = False

    def pre_process_command(self, line, cmd, arg):
        if cmd == 'TAG':
            self.logline("<- %s" % line)
            self.process_command(cmd, arg)
            return
        super().pre_process_command(line, cmd, arg)


def main():
    authorizer = MySmartyAuthorizer()

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
