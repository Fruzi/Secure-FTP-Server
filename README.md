# Topics in Computer Security Mini-Project #

## TODO ##
### Client ###
* Add encryption/decryption and authentication to filename on rename, delete procedures
* Notify user if a file was deleted/renamed/size changed (upon connection)
* Notify user if a file was modified (but file size unchanged) (upon file download)

### Server ###
* Handler: add encrypted filenames and their MAC tags to tags.db on file upload
* Authorizer: remove import of hazmat, use MyCrypto instead
