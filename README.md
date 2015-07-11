# shell-tips
Tips for living comfortably in Unix shell

Partially borrowed from [The art of command line](https://github.com/jlevy/the-art-of-command-line)
- [Processing files and data](#processing-files-and-data)
  - [Redirection](#redirection) 
- [Crypto](#crypto)
- [Git](#git)



## Processing files and data

- `cd ~-` -  change to $(OLDPWD).
- `rm -rf ./* ./.*[!.]* ./...*` - recursively remove all files in the current dir including hidden
- `ln [–s] target [linkname]` – make [symbolic] links between files/dirs
- `ls –lia` – list files with symlinks and hardlinks (hardlinks are files having the same index)
- `diff /etc/hosts <(ssh somehost cat /etc/hosts)` –compare local /etc/hosts with a remote one

### The power of `find`:
- `find /usr/lib –iname ‘libstdc*’` - ignore case
- `find ./dir1 ./dir2 –name "*.cpp"–or –name "*.h" | xargs cat | wc –l` - calculate LOC
- `find ./ -name "*.h" | xargs egrep -H "^class[ ]*Thread"` - search for declarations of Thread class
- `find ./ -type d -path "*.svn" -prune | xargs rm -rf` - clean up .svn dirs:
- `find ./ -name configure | xargs svn propset svn:executable yes` - set svn:executable flag on all configure scripts
- `find ./ -name configure | xargs svn propdel svn:executable`- remove svn:executable flag from all configure scripts
- `find /usr/local/lib/ -iname libicu*.so* -exec du -ks {} \; | cut -f1 | awk '{total=total+$1}END{print total/1024 " KB"}'` – find an aggregate size of all filed by mask
- `find . -name "*.py" -exec grep -qI '\r\n' {} ';' -exec perl -pi -e 's/\r\n/\n/g' {} '+'` -  fix CRLF to LF lineendings in all .py files in the current directory
- ``perl -i -pe's/\r$//;' `find . | grep Makefile | xargs` `` - replace CRLF with LF in all makefiles in the current dir recursively (use `od –c <filename>` to test for CRLF)

#### The power of grep:
- `grep –RI KEEP_ALIVES_TIMEOUT /projects` recursively search for files with KEEP_ALIVES_TIME in ‘/projects’  skipping binary files
Useful grep options: 
- `-C <num>` – show number of surrounding lines of match
- `-A <num>` or `–B <num>` – show a number of lines after or before the match

- `locate something` -  find a file anywhere by name, but bear in mind updatedb may not have indexed recently created files

- For general searching through source or data files (more advanced than grep -r), use `ag`.
- To convert HTML to text: `lynx -dump -stdin`
- For Markdown, HTML, and all kinds of document conversion, try `pandoc`.
- If you must handle XML, `xmlstarlet` is old but good.
- For JSON, use `jq`.
- For Excel or CSV files, `csvkit` provides `in2csv`, `csvcut`, `csvjoin`, `csvgrep`, etc.
- For Amazon S3, `s3cmd` is convenient and `s4cmd` is faster. Amazon's aws is essential for other AWS-related tasks.
- f you ever need to write a tab literal in a command line in Bash (e.g. for the -t argument to sort), press `ctrl-v [Tab]` or write `$'\t'` (the latter is better as you can copy/paste it).
- For binary files, use `hd` for simple hex dumps and `bvi` for binary editing.
- To split files into pieces, see `split` (to split by size) and `csplit` (to split by a pattern).
- Use `zless`, `zmore`, `zcat`, and `zgrep` to operate on compressed files.
- To rename many files at once according to a pattern, use `rename`. For complex renames, `reprenmay` help.
  - `rename 's/\.bak$//' *.bak` - Recover backup files foo.bak -> foo
  - `repren --full --preserve-case --from foo --to bar` - full rename of filenames, directories, and contents foo -> bar

- `cut` select portions of each line of a file (IMHO simpler and user-friendlier alternative to `awk`)
  - `cut -d : -f 1,7 /etc/passwd` - extract login names and shells from the passwd(5)
- `which`, `whereis`, `type` – locate the binary, source and manual page for a command
- `file` – determine file type

- `tar –xvf somearchive.tar [-C out_dir]` – extract from somearchive.tar with verbose output [to out_dir, which should already exist]
- `tar –xjf simearchive.tar.bz2` – for bz2-compressed tars
- `tar –xzf simearchive.tar.gz` – for gzip-compressed tars
- `tar cvzf log.tgz /var/log` – create a compressed archive log.tgz from the directory /var/log
- `wc` – calculate the number of bytes, newlines, words in a file
- `od –t x1 file` – print hex chars of file
- `stat` – view file statistics

### Redirection
- `gcc main.c >file` – stdout to file
- `gcc main.c 2>file` – stderr to file
- `gcc main.c 1>&2` - stdout to stderr
- `gcc main.c 2>&1` -  stderr to stdout
- `gcc main.c >& file`  - stdout and stderr to file (bash)
- `gcc main.c >file 2>&1` - stdout and stderr to file (ksh and bash)
- `gcc main.c 2>&1 >file` – stderr to file, stdout to file (note the difference with the above)




## Crypto

- `openssl x509 -noout -text -in cert.pem` – view cert info
- `openssl x509 -purpose -in cert.pem –noout` – view effective cert purposes
- `openssl smime -sign -in text.txt -signer signingcertkey.pem -inkey signingcertkey.pem -out signed.pkcs7.smime` – SMIME sign 
- `openssl smime -verify -in signed.pkcs7.smime -CAfile signingcertca.pem` – verify SMIME-signed message against the issuer CA
- `openssl smime -verify -in message -noverify -signer cert.pem` – extract cert from SMIME-signed message to cert.pem
- `openssl rsa -in privateKey.pem -out newPrivateKey.pem` – remove passphrase from RSA private key
- `openssl pkcs12 –nodes -in file.pfx -out file.pem` – extract all from PKCS#12 package
- `echo –n "some text" | openssl base64 –e` - base64 encode
- `echo "ABCDEF==" | openssl base64 –d` – base64-decode
- `echo -n "text" | md5sum` - calculate MD5 digest of the file 
- `echo –n "text" | uuencode –m /dev/stdout`  - base64-encode
- `htpasswd [–c] passwd_file username` - generate Apache password for username and store it to passwd_file. `–c` option is used to create a new passwd-file instead of adding lines to an existing one.


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

