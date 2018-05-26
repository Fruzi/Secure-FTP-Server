# Topics in Computer Security Mini-Project #

## TODO ##
### Client ###
* Add encryption/decryption and authentication to filename on upload and download, rename, delete, 'ls' procedures
* Notify user if a file was deleted/renamed/size changed (upon connection)
* Notify user if a file was modified (but file size unchanged) (upon file download)

### Server ###
* Authorizer: add new users with randomly-generated salt and hashed salted passwords into users.db on register requests (use [Scrypt](https://cryptography.io/en/latest/hazmat/primitives/key-derivation-functions/#cryptography.hazmat.primitives.kdf.scrypt.Scrypt))
* Authorizer: authenticate users with users.db on login requests (salt and hash the given password and match the data) (use [Scrypt](https://cryptography.io/en/latest/hazmat/primitives/key-derivation-functions/#cryptography.hazmat.primitives.kdf.scrypt.Scrypt))
* Handler: add encrypted filenames and their MAC tags to tags.db on file upload
