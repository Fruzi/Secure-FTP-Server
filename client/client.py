import os
from ftplib import FTP
from mycrypto import MyCipher


class MyFTPClient(FTP):
    from ftplib import _GLOBAL_DEFAULT_TIMEOUT

    def __init__(self, host='', user='', passwd='', acct='', timeout=_GLOBAL_DEFAULT_TIMEOUT, source_address=None):
        self._cipher = None
        super().__init__(host, user, passwd, acct, timeout, source_address)

    def login(self, user='', passwd='', acct=''):
        if not user and not passwd:
            super().login(user, passwd, acct)
            return
        server_key = MyCipher.derive_server_key(passwd)
        super().login(user, server_key, acct)

        self._cipher = MyCipher(passwd)

    def retrbinary(self, cmd, callback, blocksize=8192, rest=None):
        """
        Receive all data from the super-method and decrypt it as one piece
        callback takes the entire decrypted data as parameter (instead of a block) (bad??)
        """
        buf = bytearray()
        ret = super().retrbinary(cmd, lambda b: buf.extend(b), blocksize, rest)
        callback(self._cipher.decrypt(bytes(buf)))
        return ret

    def storbinary(self, cmd, fp, blocksize=8192, callback=None, rest=None):
        """Encrypt entire file into temporary file and call the super-method with it"""
        enc_filename = '_enc_' + cmd[5:]
        with open(enc_filename, 'wb') as temp_file:
            temp_file.write(self._cipher.encrypt(fp.read()))

        ret = super().storbinary(cmd, open(enc_filename, 'rb'), blocksize, callback, rest)
        os.remove(enc_filename)
        return ret

    def register(self, user, passwd, acct=''):
        server_key = MyCipher.derive_server_key(passwd)
        resp = self.sendcmd('RGTR ' + user)
        if resp[0] == '3':
            resp = self.sendcmd('PASS ' + server_key)
        if resp[0] == '3':
            resp = self.sendcmd('ACCT ' + acct)
        if resp[0] != '2':
            from ftplib import error_reply
            raise error_reply(resp)
        return resp


def main():
    with MyFTPClient('localhost') as ftp:
        ftp.login()
        ftp.register('Rawn', '1234')
        print(ftp.pwd())
        print(ftp.retrlines('LIST'))
        ftp.login('Rawn', '1234')
        ftp.storbinary('STOR timetable.png', open('timetable.png', 'rb'))
        with open('timetable_from_server.png', 'wb') as outfile:
            ftp.retrbinary('RETR timetable.png', lambda b: outfile.write(b))


if __name__ == '__main__':
    main()
