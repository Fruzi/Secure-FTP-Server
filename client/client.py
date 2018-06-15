import io
import sys
import os
from ftplib import FTP, error_perm
from mycrypto import MyCipher
from cryptography.exceptions import InvalidSignature


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
        super().login(user, server_key, acct)
        try:
            self.getresp()
        except error_perm as e:
            print(' '.join([self._decrypt_path(word) if len(word) == 160 or (len(word) == 161 and word[0] == '/')
                            else word for word in str(e).split(' ')[4:]]), file=sys.stderr)

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
                buf.flush()
                dec_bytes = self._cipher.decrypt(buf.getvalue())
            except (error_perm, InvalidSignature):
                print('The file %s has been altered! Download aborted' % path, file=sys.stderr)
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
        self.sendcmd('TYPE I')
        return super().size(self._encrypt_path(filename))

    def mkd(self, dirname):
        return self._decrypt_path(super().mkd(self._encrypt_path(dirname)))

    def rmd(self, dirname):
        return super().rmd(self._encrypt_path(dirname))

    def pwd(self):
        return self._decrypt_path(super().pwd())

    def nlst(self, *args):
        return ', '.join(super().nlst(*args))

    def upload_file(self, filename):
        return self.storbinary('STOR ' + filename, open(filename, 'rb'))

    def download_file(self, filename):
        with open(filename, 'wb') as outfile:
            ret = self.retrbinary('RETR ' + filename, outfile.write)
        if not ret:
            os.remove(filename)

    def client_op(self, *args):
        method = getattr(MyFTPClient, args[0])
        args = [input('Please enter a %s\n' % arg) for arg in args[1:]]
        ret = method(self, *args)
        if ret:
            print(ret)
        return self

    def client_logout(self):
        self.__exit__()
        return None

    @staticmethod
    def client_register(ftp):
        username = input('Please enter a username\n')
        password = input('Please enter a password\n')
        with MyFTPClient('localhost') as ftp:
            print(ftp.register(username, password))
        return None

    @staticmethod
    def client_login(ftp):
        username = input('Please enter a username\n')
        password = input('Please enter a password\n')
        ftp = MyFTPClient('localhost', user=username, passwd=password).__enter__()
        return ftp

    @staticmethod
    def client_quit(ftp):
        sys.exit()


logged_out_menu = [
    {
        'name': 'Register',
        'fun': MyFTPClient.client_register,
        'args': []
    },
    {
        'name': 'Log in',
        'fun': MyFTPClient.client_login,
        'args': []
    },
    {
        'name': 'Quit',
        'fun': MyFTPClient.client_quit,
        'args': []
    }
]


logged_in_menu = [
    {
        'name': 'List files',
        'fun': MyFTPClient.client_op,
        'args': ['nlst']
    },
    {
        'name': 'Upload file',
        'fun': MyFTPClient.client_op,
        'args': ['upload_file', 'filename']
    },
    {
        'name': 'Download file',
        'fun': MyFTPClient.client_op,
        'args': ['download_file', 'filename']
    },
    {
        'name': 'Rename file or folder',
        'fun': MyFTPClient.client_op,
        'args': ['rename', 'filename', 'new name']
    },
    {
        'name': 'Get file size',
        'fun': MyFTPClient.client_op,
        'args': ['size', 'filename']
    },
    {
        'name': 'Delete file',
        'fun': MyFTPClient.client_op,
        'args': ['delete', 'filename']
    },
    {
        'name': 'Create folder',
        'fun': MyFTPClient.client_op,
        'args': ['mkd', 'dirname']
    },
    {
        'name': 'Delete folder',
        'fun': MyFTPClient.client_op,
        'args': ['rmd', 'dirname']
    },
    {
        'name': 'Change working directory',
        'fun': MyFTPClient.client_op,
        'args': ['cwd', 'dirname']
    },
    {
        'name': 'Show current working directory',
        'fun': MyFTPClient.client_op,
        'args': ['pwd']
    },
    {
        'name': 'Log out',
        'fun': MyFTPClient.client_logout,
        'args': []
    }
]


def display_menu(menu):
    print('Choose an operation:')
    for idx, menu_item in enumerate(menu):
        print('%d. %s' % (idx + 1, menu_item['name']))


def main():
    ftp = None
    while True:
        menu = logged_in_menu if ftp else logged_out_menu
        display_menu(menu)
        choice = int(input().strip())
        menu_item = menu[choice - 1]
        try:
            ftp = menu_item['fun'](ftp, *menu_item['args'])
        except error_perm as e:
            print(e, file=sys.stderr)
        except (EOFError, OSError):
            print('Server error', file=sys.stderr)
            ftp = None
        print()


if __name__ == '__main__':
    main()
