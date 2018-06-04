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
        self._cipher = MyCipher(passwd)
        server_key = self._cipher.derive_server_key()
        return super().login(user, server_key, acct)

    def register(self, user, passwd, acct=''):
        self._cipher = MyCipher(passwd)
        resp = self.sendcmd('RGTR ' + user)
        if resp[0] == '3':
            server_key = self._cipher.derive_server_key()
            resp = self.sendcmd('PASS ' + server_key)
        if resp[0] == '3':
            resp = self.sendcmd('ACCT ' + acct)
        if resp[0] != '2':
            from ftplib import error_reply
            raise error_reply(resp)
        return resp

    def retrbinary(self, cmd, callback, blocksize=8192, rest=None):
        """Encrypt filename, then receive all data from the super-method and decrypt it as one piece"""
        retrcmd, path = cmd.split()
        enc_path = self._encrypt_path(path)
        with io.BytesIO() as buf:
            ret = super().retrbinary(' '.join((retrcmd, enc_path)), buf.write, blocksize, rest)
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
        storcmd, path = cmd.split()
        enc_path = self._encrypt_path(path)
        enc_bytes, tag = self._cipher.encrypt(fp.read())
        super().storbinary(' '.join((storcmd, enc_path)), io.BytesIO(enc_bytes), blocksize, callback, rest)

        # send tag
        resp = super().getresp()
        if resp[0] == '3':
            resp = self.voidcmd('TAG ' + tag.hex())
        return resp

    def retrlines(self, cmd, callback=None):
        """Decrypt filenames received from LIST or NLST commands and print them"""
        if cmd not in ('LIST', 'NLST'):
            return super().retrlines(cmd, callback)

        def decrypt_line(line):
            line_parts = line.rsplit(' ', maxsplit=1)
            dec_filename = self._decrypt_filename(line_parts[-1])
            return ' '.join(line_parts[:-1] + [dec_filename])
        return super().retrlines(cmd, lambda line: print(decrypt_line(line)))

    def rename(self, fromname, toname):
        return super().rename(self._encrypt_path(fromname), self._encrypt_path(toname))

    def delete(self, filename):
        return super().delete(self._encrypt_path(filename))

    def cwd(self, dirname):
        return super().cwd(self._encrypt_path(dirname))

    def size(self, filename):
        return super().size(self._encrypt_path(filename))

    def mkd(self, dirname):
        return super().mkd(self._encrypt_path(dirname))

    def rmd(self, dirname):
        return super().rmd(self._encrypt_path(dirname))

    def pwd(self):
        return self._decrypt_path(super().pwd())

    def _encrypt_filename(self, filename):
        return self._cipher.encrypt(filename.encode(), is_filename=True).hex()

    def _decrypt_filename(self, filename):
        try:
            return self._cipher.decrypt(bytes.fromhex(filename)).decode()
        except ValueError:
            return filename

    def _encrypt_path(self, path):
        return '/'.join([self._encrypt_filename(dirname) if MyFTPClient.is_normal_filename(dirname) else dirname
                         for dirname in path.split('/')])

    def _decrypt_path(self, path):
        return '/'.join([self._decrypt_filename(dirname) if MyFTPClient.is_normal_filename(dirname) else dirname
                         for dirname in path.split('/')])

    @staticmethod
    def is_normal_filename(filename):
        return not (not filename or filename in ('.', '..'))


def test_files():
    filename = 'potato.txt' if len(sys.argv) < 2 else sys.argv[1]
    name, ext = filename.split('.')

    with MyFTPClient('localhost') as ftp:
        ftp.set_debuglevel(1)
        ftp.login('Rawn', '1234')
        ftp.storbinary('STOR ' + filename, open(filename, 'rb'))
        ftp.storbinary('STOR potato.txt', open('potato.txt', 'rb'))

    with MyFTPClient('localhost') as ftp:
        ftp.set_debuglevel(1)
        ftp.login('Rawn', '1234')
        # ftp.dir()
        with open('.'.join((name + '_from_server', ext)), 'wb') as outfile:
            ftp.retrbinary('RETR ' + filename, outfile.write)


def test_directories():
    with MyFTPClient('localhost') as ftp:
        ftp.set_debuglevel(1)
        ftp.login('Rawn', '1234')
        print(','.join(ftp.nlst()))
        # ftp.dir()
        ftp.mkd('stuff')
        # ftp.dir()
        ftp.cwd('stuff')
        ftp.mkd('things')
        ftp.cwd('things')
        ftp.mkd('abc')
        ftp.cwd('abc')
        print(ftp.pwd())
        ftp.cwd('..')
        ftp.cwd('..')
        ftp.cwd('..')
        print(','.join(ftp.nlst()))
        print(ftp.pwd())
        # ftp.dir()
        # ftp.cwd('..')


def register_users():
    with MyFTPClient('localhost') as ftp:
        ftp.set_debuglevel(1)
        ftp.register('Rawn', '1234')
        ftp.register('Uzi', '5678')
        ftp.register('Amit', 'blabla')


def main():
    register_users()
    test_files()
    test_directories()


if __name__ == '__main__':
    main()
