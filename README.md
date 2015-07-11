# shell-tips
Tips for living comfortably in Unix shell

Partially borrowed from [The art of command line](https://github.com/jlevy/the-art-of-command-line)
- [Processing files and data](#files)
- [OpenSSL](#openssl)
- [Git](#git)



## Files
TODO

## OpenSSL

- `openssl x509 -noout -text -in cert.pem` – view cert info
- `openssl x509 -purpose -in cert.pem –noout` – view effective cert purposes
- `openssl smime -sign -in text.txt -signer signingcertkey.pem -inkey signingcertkey.pem -out signed.pkcs7.smime` – SMIME sign 
- `openssl smime -verify -in signed.pkcs7.smime -CAfile signingcertca.pem` – verify SMIME-signed message against the issuer CA
- `openssl smime -verify -in message -noverify -signer cert.pem` – extract cert from SMIME-signed message to cert.pem
- `openssl rsa -in privateKey.pem -out newPrivateKey.pem` – remove passphrase from RSA private key
- `openssl pkcs12 –nodes -in file.pfx -out file.pem` – extract all from PKCS#12 package
- `echo –n "some text" | openssl base64 –e` - base64 encode
- `echo "ABCDEF==" | openssl base64 –d` – base64-decode


## Git

### Manage git subtrees

Add repository as git subtree
```
git remote add pretty-python-remote https://github.com/kindkaktus/PrettyPython
git fetch pretty-python-remote
git read-tree --prefix=Software/Import/PrettyPython -u pretty-python-remote/master
git commit -a -m"Added PrettyPython library as a subtree from https://github.com/kindkaktus/PrettyPython"
git push
```
... and later on, incorporate new changes made to the 3rd party library into our repo
```
git fetch pretty-python-remote
git pull -s subtree --no-edit pretty-python-remote master
git push
```
List subtrees merged to your project:

`git log | grep git-subtree-dir | tr -d ' ' | cut -d ":" -f2 | sort | uniq`


### Misc

Diff commited file to the previous commit:

`git diff HEAD@{1} filename`

