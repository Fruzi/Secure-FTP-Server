import io
import sys
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
        """Receive all data from the super-method and decrypt it as one piece"""
        # TODO: filename encryption/decryption???
        with io.BytesIO() as buf:
            ret = super().retrbinary(cmd, lambda b: buf.write(b), blocksize, rest)
            buf.flush()
            dec_bytes = self._cipher.decrypt(buf.getvalue())
        with io.BytesIO(dec_bytes) as buf:
            while True:
                b = buf.read(blocksize)
                if not b:
                    break
                callback(b)
        return ret

    def storbinary(self, cmd, fp, blocksize=8192, callback=None, rest=None):
        """Encrypt filename, encrypt file contents into memory buffer, then call the super-method with them"""
        storcmd, filename = cmd.split()
        enc_filename = self._cipher.encrypt(filename.encode()).hex()
        with io.BytesIO() as buf:
            while True:
                b = fp.read(blocksize)
                if not b:
                    break
                buf.write(b)
            buf.flush()
            enc_bytes = self._cipher.encrypt(buf.getvalue())
        return super().storbinary(' '.join((storcmd, enc_filename)), io.BytesIO(enc_bytes), blocksize, callback, rest)

    def retrlines(self, cmd, callback=None):
        """Decrypt filenames received from LIST command and print them"""
        if cmd != 'LIST':
            return super().retrlines(cmd, callback)

        def decrypt_line(line):
            rest, filename = line.rsplit(maxsplit=1)
            dec_filename = self._cipher.decrypt(bytes.fromhex(filename)).decode()
            return ' '.join((rest, dec_filename))

        return super().retrlines(cmd, lambda line: print(decrypt_line(line)))

    def register(self, user, passwd, acct=''):
        """This also makes the user logged in"""
        server_key = MyCipher.derive_server_key(passwd)
        self.login()    # must log in as anonymous user first
        resp = self.sendcmd('RGTR ' + user)
        if resp[0] == '3':
            resp = self.sendcmd('PASS ' + server_key)
        if resp[0] == '3':
            resp = self.sendcmd('ACCT ' + acct)
        if resp[0] != '2':
            from ftplib import error_reply
            raise error_reply(resp)
        self._cipher = MyCipher(passwd)
        return resp


def main():
    filename = 'potato.txt' if len(sys.argv) < 2 else sys.argv[1]
    name, _, ext = filename.partition('.')

    with MyFTPClient('localhost') as ftp:
        ftp.set_debuglevel(1)
        ftp.register('Rawn', '1234')
        ftp.storbinary('STOR ' + filename, open(filename, 'rb'))

    with MyFTPClient('localhost') as ftp:
        ftp.set_debuglevel(1)
        ftp.login('Rawn', '1234')
        print(ftp.retrlines('LIST'))
        # with open('%s_from_server.%s' % (name, ext), 'wb') as outfile:
        #     ftp.retrbinary('RETR ' + filename, lambda b: outfile.write(b))


if __name__ == '__main__':
    main()
