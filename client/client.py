import os
from ftplib import FTP, _GLOBAL_DEFAULT_TIMEOUT, error_reply, _SSLSocket
from hashlib import sha256
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend


class MyFTPClient(FTP):
    def __init__(self, host='', user='', passwd='', acct='', timeout=_GLOBAL_DEFAULT_TIMEOUT, source_address=None):
        self._server_key = None
        self._mac_key = None
        self._cipher = None
        super().__init__(host, user, passwd, acct, timeout, source_address)

    def login(self, user='', passwd='', acct=''):
        if not user and not passwd:
            super().login(user, passwd, acct)
            return
        # self._server_key = sha256((passwd + '1').encode()).hexdigest()
        self._server_key = passwd
        self._mac_key = sha256((passwd + '2').encode()).digest()
        crypt_key = sha256((passwd + '3').encode()).digest()
        iv = os.urandom(16)
        self._cipher = Cipher(algorithms.AES(crypt_key), modes.CFB(iv), backend=default_backend())
        super().login(user, self._server_key, acct)

    def retrbinary(self, cmd, callback, blocksize=8192, rest=None):
        decryptor = self._cipher.decryptor()
        self.voidcmd('TYPE I')
        with self.transfercmd(cmd, rest) as conn:
            while 1:
                data = conn.recv(blocksize)
                if not data:
                    break
                decrypted_data = decryptor.update(data) + decryptor.finalize()
                callback(decrypted_data)
            # shutdown ssl layer
            if _SSLSocket is not None and isinstance(conn, _SSLSocket):
                conn.unwrap()
        return self.voidresp()

    def storbinary(self, cmd, fp, blocksize=8192, callback=None, rest=None):
        encryptor = self._cipher.encryptor()
        self.voidcmd('TYPE I')
        with self.transfercmd(cmd, rest) as conn:
            while 1:
                buf = fp.read(blocksize)
                if not buf:
                    break
                encrypted_buf = encryptor.update(buf) + encryptor.finalize()
                conn.sendall(encrypted_buf)
                if callback:
                    callback(buf)
            # shutdown ssl layer
            if _SSLSocket is not None and isinstance(conn, _SSLSocket):
                conn.unwrap()
        return self.voidresp()

    def register(self, user, passwd, acct=''):
        resp = self.sendcmd('RGTR ' + user)
        if resp[0] == '3':
            resp = self.sendcmd('PASS ' + passwd)
        if resp[0] == '3':
            resp = self.sendcmd('ACCT ' + acct)
        if resp[0] != '2':
            raise error_reply(resp)
        return resp


def main():
    # with MyFTPClient('localhost') as ftp:
    with MyFTPClient('ftp.dlptest.com') as ftp:
        # ftp.login()
        # ftp.register('Rawn', '1234')
        # print(ftp.pwd())
        # print(ftp.retrlines('LIST'))
        # ftp.login('Rawn', '1234')
        ftp.login('dlpuser@dlptest.com', 'eiTqR7EMZD5zy7M')
        ftp.storbinary('STOR hello.txt', open('hello.txt', 'rb'))
        print(ftp.retrlines('RETR hello.txt'))
        with open('hello_back.txt', 'wb') as outfile:
            ftp.retrbinary('RETR hello.txt', lambda b: outfile.write(b))


if __name__ == '__main__':
    main()
