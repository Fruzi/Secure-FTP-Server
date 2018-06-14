import io
import sys
from ftplib import FTP, error_perm
from mycrypto import MyCipher


class MyFTPClient(FTP):
    from ftplib import _GLOBAL_DEFAULT_TIMEOUT

    def __init__(self, host='', user='', passwd='', acct='', timeout=_GLOBAL_DEFAULT_TIMEOUT, source_address=None):
        self._cipher = None
        super().__init__(host, user, passwd, acct, timeout, source_address)

    def _encrypt_filename(self, filename):
        return self._cipher.encrypt(filename.encode(), is_filename=True).hex()

    def _decrypt_filename(self, filename):
        try:
            ret = self._cipher.decrypt(bytes.fromhex(filename)).decode()
            if ret is None:
                print('The filename has been altered!', file=sys.stderr)
            return ret
        except ValueError:
            return filename

    @staticmethod
    def _is_normal_filename(filename):
        return not (not filename or filename in ('.', '..'))

    def _encrypt_path(self, path):
        return '/'.join([self._encrypt_filename(dirname) if self._is_normal_filename(dirname) else dirname
                         for dirname in path.split('/')])

    def _decrypt_path(self, path):
        return '/'.join([self._decrypt_filename(dirname) if self._is_normal_filename(dirname) else dirname
                         for dirname in path.split('/')])

    def login(self, user='', passwd='', acct=''):
        self._cipher = MyCipher(passwd)
        user = self._encrypt_filename(user)
        server_key = self._cipher.derive_server_key()
        return super().login(user, server_key, acct)

    def register(self, user, passwd, acct=''):
        self._cipher = MyCipher(passwd)
        user = self._encrypt_filename(user)
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
            try:
                ret = super().retrbinary(' '.join((retrcmd, enc_path)), buf.write, blocksize, rest)
            except error_perm as e:
                if str(e).startswith('555'):
                    print(e, file=sys.stderr)
                    return None
                else:
                    raise e
            buf.flush()
            dec_bytes = self._cipher.decrypt(buf.getvalue())
            if dec_bytes is None:
                print('The file %s has been altered!' % path, file=sys.stderr)
                return None
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
        if callback is None:
            callback = print

        def decrypt_line(line):
            line_parts = line.rsplit(' ', maxsplit=1)
            dec_filename = self._decrypt_filename(line_parts[-1])
            return ' '.join(line_parts[:-1] + [dec_filename])
        return super().retrlines(cmd, lambda line: callback(decrypt_line(line)))

    def rename(self, fromname, toname):
        return super().rename(self._encrypt_path(fromname), self._encrypt_path(toname))

    def delete(self, filename):
        return super().delete(self._encrypt_path(filename))

    def cwd(self, dirname):
        return super().cwd(self._encrypt_path(dirname))

    def size(self, filename):
        self.voidcmd('TYPE I')
        return super().size(self._encrypt_path(filename))

    def mkd(self, dirname):
        return super().mkd(self._encrypt_path(dirname))

    def rmd(self, dirname):
        return super().rmd(self._encrypt_path(dirname))

    def pwd(self):
        return self._decrypt_path(super().pwd())

    def client_logout(self):
        self.__exit__()
        return None

    def client_upload_file(self):
        filename = input('Please enter a filename\n').strip()
        self.storbinary('STOR ' + filename, open(filename, 'rb'))
        return self

    def client_download_file(self):
        filename = input('Please enter a filename\n').strip()
        with open(filename, 'wb') as outfile:
            self.retrbinary('RETR ' + filename, outfile.write)
        return self

    def client_list_files(self):
        print(', '.join(self.nlst()))
        return self

    def client_size(self):
        filename = input('Please enter a filename\n').strip()
        print(self.size(filename))
        return self

    def client_rename(self):
        fromname = input('Please enter a filename\n').strip()
        toname = input('Please enter a new name\n').strip()
        print(self.rename(fromname, toname))
        return self

    def client_delete_file(self):
        filename = input('Please enter a filename\n').strip()
        print(self.delete(filename))
        return self

    def client_create_folder(self):
        dirname = input('Please enter a directory name\n').strip()
        print(self.mkd(dirname))
        return self

    def client_delete_folder(self):
        dirname = input('Please enter a directory name\n').strip()
        print(self.rmd(dirname))
        return self

    def client_cwd(self):
        dirname = input('Please enter a directory name\n').strip()
        print(self.cwd(dirname))
        return self

    def client_pwd(self):
        print(self.pwd())
        return self

    @staticmethod
    def client_login(*args):
        username = input('Please enter a username\n').strip()
        password = input('Please enter a password\n').strip()
        ftp = MyFTPClient('localhost', user=username, passwd=password).__enter__()
        return ftp

    @staticmethod
    def client_register(*args):
        username = input('Please enter a username\n').strip()
        password = input('Please enter a password\n').strip()
        with MyFTPClient('localhost') as ftp:
            ftp.register(username, password)
        return None


def test_files():
    filename = 'potato.txt' if len(sys.argv) < 2 else sys.argv[1]
    name, ext = filename.split('.')

    with MyFTPClient('localhost') as ftp:
        ftp.set_debuglevel(1)
        ftp.login('Rawn', '1234')
        ftp.storbinary('STOR ' + filename, open(filename, 'rb'))
    #     ftp.storbinary('STOR potato.txt', open('potato.txt', 'rb'))

    with MyFTPClient('localhost') as ftp:
        ftp.set_debuglevel(1)
        ftp.login('Rawn', '1234')
        with open('.'.join((name + '_from_server', ext)), 'wb') as outfile:
            ftp.retrbinary('RETR ' + filename, outfile.write)


def test_directories():
    with MyFTPClient('localhost') as ftp:
        ftp.set_debuglevel(1)
        ftp.login('Rawn', '1234')
        print(', '.join(ftp.nlst()))
        ftp.mkd('stuff')
        ftp.cwd('stuff')
        ftp.mkd('things')
        ftp.cwd('things')
        ftp.mkd('abc')
        ftp.cwd('abc')
        print(ftp.pwd())
        ftp.cwd('..')
        ftp.cwd('..')
        print(ftp.pwd())
        ftp.cwd('..')
        print(', '.join(ftp.nlst()))
        print(ftp.pwd())


def register_users():
    with MyFTPClient('localhost') as ftp:
        ftp.set_debuglevel(1)
        ftp.register('Rawn', '1234')
        ftp.register('Uzi', '5678')
        ftp.register('Amit', 'blabla')


logged_out_menu = [
    {
        'name': 'Register',
        'fun': getattr(MyFTPClient, 'client_register')
    },
    {
        'name': 'Log in',
        'fun': getattr(MyFTPClient, 'client_login')
    }
]


logged_in_menu = [
    {
        'name': 'List files',
        'fun': getattr(MyFTPClient, 'client_list_files')
    },
    {
        'name': 'Upload file',
        'fun': getattr(MyFTPClient, 'client_upload_file')
    },
    {
        'name': 'Download file',
        'fun': getattr(MyFTPClient, 'client_download_file')
    },
    {
        'name': 'Rename file or folder',
        'fun': getattr(MyFTPClient, 'client_rename')
    },
    {
        'name': 'Get file size',
        'fun': getattr(MyFTPClient, 'client_size')
    },
    {
        'name': 'Delete file',
        'fun': getattr(MyFTPClient, 'client_delete_file')
    },
    {
        'name': 'Create folder',
        'fun': getattr(MyFTPClient, 'client_create_folder')
    },
    {
        'name': 'Delete folder',
        'fun': getattr(MyFTPClient, 'client_delete_folder')
    },
    {
        'name': 'Change working directory',
        'fun': getattr(MyFTPClient, 'client_cwd')
    },
    {
        'name': 'Show current working directory',
        'fun': getattr(MyFTPClient, 'client_pwd')
    },
    {
        'name': 'Log out',
        'fun': getattr(MyFTPClient, 'client_logout')
    }
]


def display_menu(menu):
    print('Choose an operation:')
    for idx, menu_item in enumerate(menu):
        print('%d. %s' % (idx + 1, menu_item['name']))


def main():
    # register_users()
    # test_files()
    # test_directories()
    ftp = None
    while True:
        menu = logged_in_menu if ftp else logged_out_menu
        display_menu(menu)
        choice = int(input().strip())
        ftp = menu[choice - 1]['fun'](ftp)


if __name__ == '__main__':
    main()
