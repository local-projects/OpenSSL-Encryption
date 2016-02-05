# OpenSSL-Encryption
A small python script for encrypting data with OpenSSL keys

`./openssl_encrypt [OpenSSL public key file] [input file] [output file]` or `echo '[OpenSSL public key]' | %s [input file] [output file]` to encrypt

`./generated_file` or `/generated_file` to decrypt

## Example

`./openssl_encrypt.py ~/.ssh/id_rsa.pub secret/secret-file.yml encrypted-file`

`./encrypted-file`
