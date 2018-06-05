import os
import logging
import db
from mycrypto import MyCipher
import pyftpdlib.filesystems
from pyftpdlib.authorizers import DummyAuthorizer
from pyftpdlib.handlers import FTPHandler, proto_cmds
from pyftpdlib.servers import FTPServer
from pyftpdlib.filesystems import AbstractedFS


class MySmartyAuthorizer(DummyAuthorizer):

    def __init__(self):
        db.create_user_file()
        db.create_tag_file()
        db.create_user_metadata()
        db.create_filenum_file()

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
        salt, key = MyCipher.derive_password_for_storage(password)
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
        MyCipher.verify_stored_password(password, udata[0], udata[1])

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


class MyDBFS(AbstractedFS):

    def ftp2fs(self, ftppath):
        """
        Call _ftppath2numpath on the result of ftpnorm.
        """
        assert isinstance(ftppath, pyftpdlib.filesystems.unicode), ftppath
        if os.path.normpath(self.root) == os.sep:
            return os.path.normpath(self._ftppath2numpath(self.ftpnorm(ftppath)))
        else:
            p = self._ftppath2numpath(self.ftpnorm(ftppath)[1:])
            return os.path.normpath(os.path.join(self.root, p))

    def fs2ftp(self, fspath):
        return super().fs2ftp(self._numpath2ftppath(fspath))

    def mkhomedir(self, home):
        homedir_num = str(self.get_filenum(home))
        self.mkdir(homedir_num)
        return homedir_num

    def listdir(self, path):
        """
        Gets ftp-filenames (not full paths) for each file.
        NLST works. LIST doesn't work!
        """
        return [self._numpath2ftppath(file).split('/')[-1] for file in super().listdir(path)]

    def _ftppath2numpath(self, path):
        """

        :param path: path of encrypted files
        :return: the above path but with the filenames represented as numbers
        """
        if not path:
            return ''
        parts = path.split('/')
        num_parts = [str(self.get_filenum('/'.join(parts[:i+1]))) for i in range(len(parts))]
        return '/'.join(num_parts)

    def _numpath2ftppath(self, path):
        """

        :param path: path of files represented by numbers
        :return: the full actual path of the file (last in path)
        """
        if path == self.root:
            return '/'
        last_file = path.split(os.sep)[-1]
        return db.fetch_filepath(int(last_file))[0]

    """
    Fetches a file's serial number from the DB, or creates one if doesn't exist
    """
    @staticmethod
    def get_filenum(path):
        filenum = db.fetch_filenum(path)
        if not filenum:
            return db.add_filenum(path)
        return filenum[0]


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

        self.handle_auth_success(username, line, "New USER '%s' registered." % username)
        homedir_num = self.fs.mkhomedir(username)
        self.authorizer.add_user(username, line, homedir_num, perm='elradfmwMT')
        self._registering = False

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
        with self.fs.open(temp_filename, 'wb') as temp_file, self.fs.open(file, 'rb') as fd:
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

    def on_incomplete_file_sent(self, file):
        self.on_file_sent(file)

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
    handler.abstracted_fs = MyDBFS

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
