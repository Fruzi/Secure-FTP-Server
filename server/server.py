import os
from pyftpdlib.authorizers import DummyAuthorizer
from pyftpdlib.handlers import FTPHandler, proto_cmds
from pyftpdlib.servers import FTPServer


class MyFTPHandler(FTPHandler):

    def __init__(self, conn, server, ioloop=None):
        # adding the RGTR (register) command to the protocol
        proto_cmds['RGTR'] = dict(
            perm=None, auth=False, arg=True,
            help='Syntax: RGTR <SP> user-name (set username).')
        self.registering = False
        super().__init__(conn, server, ioloop)

    def ftp_RGTR(self, line):
        """Register a new user. The logged in user must be the anonymous user."""
        if self.username != 'anonymous':
            self.respond("503 Can't register while logged in.")
            return
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

        self.fs.mkdir(username)
        self.authorizer.add_user(username, line, username, perm='elradfmwMT')
        self.log("New USER '%s' registered." % self.username)
        self.registering = False
        super().ftp_PASS(line)


def main():
    # TODO: Make secure authorizer
    authorizer = DummyAuthorizer()
    authorizer.add_anonymous(os.getcwd(), perm='')

    handler = MyFTPHandler
    handler.authorizer = authorizer

    # Instantiate FTP server class and listen on localhost:21
    address = ('localhost', 21)
    server = FTPServer(address, handler)

    # set a limit for connections
    server.max_cons = 256
    server.max_cons_per_ip = 5

    # start ftp server
    server.serve_forever()


if __name__ == '__main__':
    main()
