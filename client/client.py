# import os
from ftplib import FTP, error_reply
# from hashlib import sha256
# from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
# from cryptography.hazmat.backends import default_backend


class MyFTPClient(FTP):
    """
    def __init__(self, host='', user='', passwd='', acct='', timeout=object(), source_address=None):
        self._server_key = sha256(passwd + '1')
        self._mac_key = sha256(passwd + '2')
        self._encrypt_key = sha256(passwd + '3')
        super().__init__(host, user, self._server_key, acct, timeout, source_address)

    def login(self, user='', passwd='', acct=''):
        return super().login(user, passwd, acct)

    def storbinary(self, cmd, fp, blocksize=8192, callback=None, rest=None):
        return super().storbinary(cmd, fp, blocksize, callback, rest)
    """

    def register(self, user, passwd):
        acct = ''
        resp = self.sendcmd('RGTR ' + user)
        if resp[0] == '3':
            resp = self.sendcmd('PASS ' + passwd)
        if resp[0] == '3':
            resp = self.sendcmd('ACCT ' + acct)
        if resp[0] != '2':
            raise error_reply(resp)
        return resp


def main():
    with MyFTPClient('localhost') as ftp:
        ftp.login()
        ftp.register('Rawn', '1234')
        print(ftp.pwd())
        print(ftp.retrlines('LIST'))


if __name__ == '__main__':
    main()
