# shell-tips
Tips for living comfortably in Unix shell

Partially borrowed from [The art of command line](https://github.com/jlevy/the-art-of-command-line)
- [Processing files and data](#processing-files-and-data)
- [System administration](#system-administration)
- [Working with disk](#working-with-disk)
- [Manage processes](#manage-processes)
- [Network](#network)
- [Bash](#bash)
- [Crypto](#crypto)
- [Git](#git)
- [Proxy](#proxy)
- [Miscellaneous](#miscellaneous)



## Processing files and data

- `cd -` -  cd to `$(OLDPWD)`
- `rm -rf ./* ./.*[!.]* ./...*` - recursively remove all files in the current dir including hidden
- `ln [–s] target [linkname]` – make [symbolic] links between files/dirs
- `ls –lia` – list files with symlinks and hardlinks (hardlinks are files having the same index)
- `diff /etc/hosts <(ssh somehost cat /etc/hosts)` –compare local /etc/hosts with a remote one

- `find /usr/lib –iname ‘libstdc*’` - ignore case
- `find ./dir1 ./dir2 –name "*.cpp"–or –name "*.h" | xargs cat | wc –l` - calculate LOC
- `find ./ -name "*.h" | xargs egrep -H "^class[ ]*Thread"` - search for declarations of Thread class
- `find ./ -type d -path "*.svn" -prune | xargs rm -rf` - clean up .svn dirs:
- `find ./ -name configure | xargs svn propset svn:executable yes` - set svn:executable flag on all configure scripts
- `find ./ -name configure | xargs svn propdel svn:executable`- remove svn:executable flag from all configure scripts
- `find /usr/local/lib/ -iname libicu*.so* -exec du -ks {} \; | cut -f1 | awk '{total=total+$1}END{print total/1024 " KB"}'` – find an aggregate size of all filed by mask
- `find . -name "*.py" -exec grep -qI '\r\n' {} ';' -exec perl -pi -e 's/\r\n/\n/g' {} '+'` -  fix CRLF to LF lineendings in all .py files in the current directory

- `od –t x1 file` – print hex chars of file
- `file myfile` or `cat -e myfile` – test newline type used (CRLF/LF)
- `perl -i -pe's/\r$//;' myfile` – replace CRLF -> LF for myfile
- ``perl -i -pe's/\r$//;' `find . | grep Makefile | xargs` `` - replace CRLF -> LF for makefiles in the current dir recursively (use `od –c <filename>` to test for CRLF)

- `grep –RI KEEP_ALIVES_TIMEOUT /projects` recursively search for files with KEEP_ALIVES_TIME in ‘/projects’  skipping binary files
Useful grep options: 
- `-C <num>` – show number of surrounding lines of match
- `-A <num>` or `–B <num>` – show a number of lines after or before the match

- `echo '12.34.5' | egrep -o [0-9]+` - print each match on a separate line:

  ```
  12
  34
  5
  ```

- Parsing space-delimited text

  ```
  cat file | grep '[j]boss' | awk '{print $4}'
  cat file | awk '/[j]boss/ {print $4}'
  cat file | grep '[j]boss' | sed 's/\s\s*/ /g' | cut -d' ' -f4
  ```
  
- Changing file in-place

  `sed -i -r 's/^[;]?display_errors\s*=.*$/display_errors = On/' /etc/php5/apache2/php.ini`

- `locate something` -  find a file anywhere by name, but bear in mind updatedb may not have indexed recently created files
- `which`, `whereis`, `type` – locate the binary, source and manual page for a command
- `file` – determine file type
- `unison` – file synchronization tool (uses e.g. rsync)

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

- `tar –xvf somearchive.tar [-C out_dir]` – extract from somearchive.tar with verbose output [to `out_dir`, which should already exist]
- `tar –xjf simearchive.tar.bz2` – for bz2-compressed tars
- `tar –xzf simearchive.tar.gz` – for gzip-compressed tars
- `tar cvzf log.tgz /var/log` – create a compressed archive log.tgz from the directory /var/log
- `wc` – calculate the number of bytes, newlines, words in a file
- `stat` – view file statistics

### Redirection
- `gcc main.c >file` – stdout to file
- `gcc main.c 2>file` – stderr to file
- `gcc main.c 1>&2` - stdout to stderr
- `gcc main.c 2>&1` -  stderr to stdout
- `gcc main.c >& file`  - stdout and stderr to file (bash)
- `gcc main.c >file 2>&1` - stdout and stderr to file (ksh and bash)
- `gcc main.c 2>&1 >file` – stderr to file, stdout to file (note the difference with the above)

## System administration
- `ipcs -m`  - information about shared memory
- `ipcs -s`  - information about existing semaphore sets.
- `sysctl –a`   - kernel configuration info
- `env` – environment variables,
- `uname –a` – print system info (kernel, hostname, OS etc)
- `$ cat /etc/*-release` – information about Linux distribution
- `cat /proc/version or dmesg | head -1`  – pretty much the same but with Linux distribution
- `cat /proc/cpuinfo`  - CPU info
- `cat /proc/meminfo` – memory info
- `cat /proc/loadavg` – system load
- `vmstat` – virtual memory, CPU etc
- `free` - memory usage information. 
- `hostname` Print the name of the local machine (host). 
- `stat` – info about file system (files, dirs)
- `lsmod` – list of loaded modules
- `ldd <binary>` – print shared library dependencies
- `ldconfig, ld.so` – configure the location of dynamic libs
- `nm`, `objdump`, `ldd`, `readelf` - inspecting binaries (export/import symbols, dependant libraries etc)
- `export LD_DEBUG=symbols; ./myapp` – run myapp displaying shared libs symbols resolution progress
- `id`  - show current user access rights
- `whoami` - your login name
- `who` - list the users logged into the machine. 
- `w` – show who is logged and what they are doing
- `last` – show listing of last logged users (is taken from /var/log/wtmp)
- `rwho -a` - list all users logged into the network. 
- `uptime`  - the amount of time since the last reboot
- `write user [tty]` – send text message to a logged user on the same machine
- `passwd` – change password
- `adduser <username>` - add new user (preferred to useradd)
- `adduser <username> sudo` – add existing user to sudo group. The change will take effect the next time the user logs in
- `for s in /etc/rc$(runlevel  | awk '{ print $2}').d/*; do  basename $s | grep '^S' | sed 's/S[0-9].//g' ;done | sort` – list services started on boot on Debian. As an alternative install `sysv-rc-conf` package. On CentOS use `chkconfig`
- For a more in-depth system overview, use `glances`. It presents you with several system level statistics in one terminal window. Very helpful for quickly checking on various subsystems.
- ``dpkg -S `which program-name` `` - check which package `program-name` comes from


## Systemd and System V (init.d) equivalents

system V |  systemd equivalent | description
--------|---------------------|-------------
`service foobar start	`| `systemctl start foobar.service`	| start a service
`service foobar stop`	| `systemctl stop foobar.service`	| stop a service
`service foobar restart`	| `systemctl restart foobar.service`	| stop and then start a service
`service foobar reload`	| `systemctl reload foobar.service`	| when supported, reloads the config file without interrupting pending operations
`service foobar status`	| `systemctl status foobar.service`	| tells whether a service is currently running
`ls /etc/rc.d/init.d/`	| `ls /lib/systemd/system/*.service /etc/systemd/system/*.service`	| list the services
`service --status-all`	| `systemctl list-units`	| list the services
`update-rc foobar defaults` | systemctl enable foobar.service | enables the service to start on boot
`update-rc foobar remove` | `systemctl disable foobar.service` | disables the service to start on boot
? | 	`systemctl is-enabled foobar.service` | check if a service is currently configured to start on boot
? | `systemctl is-active <service-name>` | check if a service is currently active (running).
? | `systemctl show <service-name>` | show all the information about the service.

## Working with disk

- `dstat` = `vmstat` + `iostat` + `ifstat`
  - `iostat` – brief system disk statistics
- `du –hs /www` - output the total size of /www folder in a human-readable format
- `df -h` - file system space usage
For looking at why a disk is full, `ncdu` saves time over the usual commands like `du -sh *`
- `disklabel` (BSD) – manipulate disk label
- `fdisk sd0` or `disklabel sd0` – retrieve disk info including disk geometry. Typical location of USB Flash on OpenBSD is `/dev/sd0i`
- `hdparm -ftT /dev/hda` – retrieve disk speed information
- `mke2fs -j /dev/<drive-device>` - format with ext3
- `mkswap /dev/<drive-device>` - format as swap
- `newfs` (BSD) – format partitions
- `mount –a`  - process `/etc/fstab`, however skipping lines with `‘noauto’` keyword
In order to add new currently mounted points to `/etc/fstab`, use /etc/mtab which contains list of currently mounted devices in `fstab` format

### Extending LVM partition
1. Add physical disk space
2. Add disk partition (fdisk)
```
fdisk /dev/sda
```
3. Povided a new disk has been adde, extend volume group with the added partition
```
vgextend ubuntu16-vg /dev/sda3
```
4. Extend logical volume with the added partition
```
lvextend /dev/ubuntu16-vg/root /dev/sda3
resize2fs /dev/ubuntu16-vg/root
```

## Manage processes
- `dstat` = `vmstat` + `iostat` + `ifstat`
- `htop` - similar to `top`, but is better (i.e. shows correct CPU timings for multithreaded programs which uses NPL threads; also more user-friendly etc)
- `ps aux` – obtain process list
  - `ps auxw` – with wide output (matters when the line does not fit the window width)
  - `ps auxf` – with tree
- `ps –eLf` – info about threads
  - `ps -eLo pid,ppid,lwp,%cpu,%mem,vsize,rssize` – info per thread with CPU/memory usage
- `ps –o pid,cmd –ppid <ppid>`  - get processes having parent <ppid>
- `pstree –p` – display process tree
- `cat /proc/self` – info about self
- `command &`  run command in the background
- `Ctrl-z + bg` - interactively move the current foreground process to the background
- `kill <pid>` - try to kill the process with SIGTERM.
- `kill -9 <pid>` - kill the process with SIGKILL, unlike SIGTREM the SIGKILL cannot be caught by a process.
- `killall <name>` - kill all processes with the specified name.
- `kill –s 0 <pid>` - check the existence of a process with <pid>. Cannot be sent to system processes (such as 1 [init]). In this case simpy use `ps –p <pid> -o pid=`
- `sudo kill –HUP 1`  - tell `‘init’` that it should re-read `/etc/inittab`
- `pkill –f mask` – kill all processes mathing pattern
- `pidof` – get pid of the running program
- `fuser` – identify processes using files and sockets
- `nice <program> <level>`  - run program with niceness level. Specifying a high nice level will make the program run with a lower priority.
- `/proc/mounts` == `/etc/mtab` – mounts
- `nohup <command>` - runs the given command with hangup signals ignored, so that the command can continue running in the background after you log out.
- E.g. you remotely login to the server, then give
```%ssh <some_server> -l <username>
%nohup <some_long_executing_program> &
%logout```
- `watch`  - execute a program periodically, showing output fuulscreen (i.e. like top). For example: `watch tail –n 25 /tmp/myprog.log` will periodically print last 25 lines of `/tmp/myprog.log`
- `gdb <program> <pid>` – attach to process pid associating with program executable
- `gdb <program> <core>` – debug core file core associating with program executable
- `time <command>` – executes command and displays its resource usage after it finishes
- `strace` – trace system calls and signals E.g. strace ./myprog will execute program and intercept all its system calls abd signals.
- `ltrace` – library call tracer (like strace for system calls)
- `gcov` – code coverage tool
- `gprof` – profiling tool

## Network
- For web debugging, `curl` especiallt `curl -I`, `wget`, and the more modern `httpie`
- `dstat` = `vmstat` + `iostat` + `ifstat`
- `netstat -tlnp` - show all TCP listening sockets
- `netstat –a –p tcp | grep LISTEN` – show all listening TCP sockets (works in OpenBSD)
- `netstat –tanp` - show all TCP listening sockets and TCP sockets with established connections
- `netstat –anp` - show all (TCP and UDP) listening sockets and sockets with established connections
- `nmap` – network exploration tool and security scanner (e.g. ports scanner)
- `xprobe (xprobe2)` – OS fingerprint scanner (guesses OS version)
- `finger` – look up users of (remote) OS
- `rpcinfo` – reports rpc information of the (remote) host
- `netcat $ip $port < /dev/zero` – send stream of zeroes to the server (might be useful for testing)
- `echo "hello from server" | netcat -l -p 443` - simple server, can be checked with telnet
- `python -m SimpleHTTPServer 80` - simple webserver for testing
- `lsof -i TCP:1234 open` – who is listeinng port 1234.
- `fuser` – identify processes using files and sockets
- `host [pcname]` – DNS lookup (of pcname).
- `nslookup` – query Internet domain name servers (DNS). Most implementations of nslookup do not look at `/etc/hosts`, they only query domain name servers.
- `tcpdump` – console sniffer
  - `tcpdump tcp port 80`
  - `tcpdump -X -i lo0 tcp port 1235` – sniff on lo0:1235 and print packets payload
- `whois` – submit whois query
- `tcpkill` -  kill connections to or from a particular host, network, port, or combination of all.
- Use `mtr` as a better traceroute, to identify network issues
  - To find which socket or process is using bandwidth, try `iftop` or `nethogs`.
  - The `ab` tool (comes with Apache) is helpful for quick-and-dirty checking of web server performance. For more complex load testing, try `siege`.
  - For more serious network debugging, `wireshark`, `tshark`, or `ngrep`.
- `minicom` – serial port console client


## Bash 
- `!< num>` - execite the command number num from the history list
- `Ctrl + r` – search history in reverse order, press `Ctrl + r` to search further
- `Ctrl + a` – go to the start of the command line
- `Ctrl + e` – go to the end of the command line
- `Ctrl + k` – delete from cursor to the end of the command line
- `Ctrl + u` – delete from cursor to the start of the command line
- `Ctrl + w` – delete the word before the cursor
- `Ctrl + y` – paste word or text that was cut using one of the deletion shortcuts (such as the one above) after the cursor
- `Alt + b` – move backward one word (or go to start of word the cursor is currently on)
- `Alt + f` – move forward one word (or go to end of word the cursor is currently on)
- `shopt –s dotglob` – enable visibility of hidden files in bash shell
- To go to a new line in shell hit `Enter` after typing `\`

### Checking files:
- `-r file` - Check if file is readable.
- `-w file` - Check if file is writable.
- `-x file` - Check if we have execute access to file.
- `-f file` - Check if file is an ordinary file (as opposed to a directory, a device special file, etc.)
- `-s file` - Check if file has size greater than 0.
- `-d file` - Check if file is a directory.
- `-e file` - Check if file exists. Is true even if file is a directory
```bash
  if [ -f "$file" ] ; then
    echo $file exists 
  fi
```

### Checking strings:
- `[ "$s1" = "$s2" ]` - Check if s1 equals s2.
- `[ "$s1" != "$s2" ]` - Check if s1 is not equal to s2.
- `[ -z "$s1" ]` - Check if s1 has size 0.
- `[ -n "$s1" ]` - Check if s1 has nonzero size.
- `[ "$s1" ]` - Check if s1 is not the empty string.
- `[[ "$s1" < "$s2" ]] or [ "$s1" \< "$s2" ]` - Check if s1 is less than s2 in alphabetical order
- Checking using regex:
```
re='some REGEX'
if [[ $foo =~ $re ]]
...
``` 

### Checking numbers:
- `[ "$n1" -eq "$n2" ]` -  Check to see if n1 equals n2
- `[ "$n1" -ne "$n2" ]` -  Check to see if n1 is not equal to n2.
- `[ "$n1" -lt "$n2" ]` or `((n1 < n2))` - Check to see if n1 < n2.
- `[ "$n1" -le "$n2" ]` or `((n1 <= n2))` - Check to see if n1 <= n2.
- `[ "$n1" -gt "$n2" ]` or `((n1 > n2))` - Check to see if n1 > n2.
- `[ "$n1" -ge "$n2" ]` or `((n1 >= n2))` -  Check to see if n1 >= n2.

### Loops in bash
```
for ((i=1; i<=n; i++)); do
...
done
```

### Colorizing bash
https://gist.github.com/kindkaktus/11d7005ddbf955772dbb

### Quoting in BASH:
- `echo '$1$2hello'` - Writes literally $1$2hello on screen.
- `echo "$1$2hello"` - Writes value of parameters 1 and 2 and string hello
```bash
v=' one    two  
three '
echo $v # will replace all whitespaces with a single space and output one two three
echo "$v" # will print the value of $v as is

v="*.sh"
echo $v  # will print test1.sh test2.sh
echo "$v" # will print *.sh
```

### Grouping in BASH:
#### Uing more conservative single-bracket syntax
- `if [ $foo -ge 3 -a $foo -lt 10 ]; then` 
- `if [ $my_error_flag -eq 1 ] ||  [ $my_error_flag_o -eq 2 ]; then`
- `if [ $my_error_flag -eq 1 ] ||  [ $my_error_flag_o -eq 2 ] || ([ $my_error_flag -eq 1 ] && [ $my_error_flag_o -eq 2 ]); then`
- `if [ -f /var/run/reboot-required -o -f /var/run/reboot-required.pkgs ]; then`

#### Using more modern double-bracket syntax
- `if [[ $num -eq 3 && "$stringvar" == "foo" ]]; then`
- `if [[ $num -eq 3 -a "$stringvar" == "foo" ]]; then`
- `if [[ -f /var/run/reboot-required || -f /var/run/reboot-required.pkgs ]]; then`

### Arithmetic expansion
`i=$(( (i + 1) % 5 ))`

### Caveat with colon
`[ -f ./file ] || { echo "The file does not exist"; touch ./file; }` - notice colon ; at the end of the expression inside {..}

### Caveat with set -e

```
set -e

bad_func() { return 1; }

func()
{
    bad_func
    echo "Bad function is called"
}

if ! func ; then
    echo "SURPRISE We don't get here!"
fi

func || echo "SURPRISE! We don't get here!"

func
echo "CORRECT! We don't get here!"
```

### Caveat with local variables

```
set -e

bad_func() { return 1; }

func1()
{
  local var=$(bad_func)             
  echo "SURPRISE We get here!"
}

func2()
{
  local var
  var=$(bad_func)             
  echo "CORRECT! We never get here!"
}

VAR=$(bad_func)     
echo "CORRECT! We never get here!"
```

### Tips for defining function
- `foo() {...}` - ok and portable
- `function doo() {...}` - ok in bash but not widely portable 

### Parse command line arguments in BASH
Correct:
```
for x in "$@"; do
  echo "parameter: '$x'"
done
```

Also correct:
```
for x; do
  echo "parameter: '$x'"
done
```

Not correct:
```
for x in $*; do
  echo "parameter: '$x'"
done
```

### Parameter substitution in BASH:
- `${parameter-default}` If parameter not declared, use default
- `${parameter:-default}` If parameter not declared or is null, use default
```bash
  variable= #declare variable and set it to null.
  echo "${variable-0}"   # no output
  echo "${variable:-1}"  # 1
  unset variable         # variable is not declared
  echo "${variable-2}"   # 2
  echo "${variable:-3}"  # 3
```
- Checking a variable exists: `${name:?error message}`
  - For example to fetch an argument in Bash script that requires a single argument only `arg=${1:?usage: $0 input_file}`
 
- `${var#Pattern}`  - Remove from `var`  the shortest part of `Pattern` that matches the front of `var`.
- `${var##Pattern}` - Remove from `var` the longest part of `Pattern` that matches the front of `var`.
- `${var%Pattern}` -  Remove from `var`  the shortest part of `Pattern` that matches the back of `var`.
- `${var%%Pattern}` - Remove from `var` the longest part of `Pattern` that matches the back of `var`.
- `${var/Pattern/Replacement}` -  First match of `Pattern`, within var replaced with `Replacement`.  If `Replacement` is omitted, then the first match of `Pattern` is replaced by nothing, that is, deleted.
- `${var//Pattern/Replacement}` - All matches of `Pattern`, within var replaced with `Replacement`.  If `Replacement` is omitted, then all occurrences of `Pattern` are replaced by nothing, that is, deleted.
- `${var/#Pattern/Replacement}` If prefix of `var` matches `Pattern`, then substitute `Replacement` for `Pattern`.
- `${var/%Pattern/Replacement}` If suffix of `var` matches `Pattern`, then substitute `Replacement` for `Pattern`.
- `${0%/*.*}` – retrieves script directory name (same as `$(dirname $0)`, but much faster)
- `${0##/*/}` – retrieves script base name (same as `$(basename $0)`, but much faster)

### Bash: copy files by mask
```bash
  for file in "file1 file2 /var/log/*.log"
  do
      [ -f "$file" ] || continue 
      cp $file /tmp
  done
```
Notice: [ -f "$file" ] check is necessary because if there are no files matching `/var/log/*.log`, the pattrern itself will be substituted for `cp` which will produce error: `cp: /var/log/*.log: No such file or directory`
Another correct way to copy files by mask is:
`find . -type f -exec some command {} \;`

WRONG way to copy files by mask (though used very often):
```
for i in $(ls *.mp3); do    # WRONG because of word splittling (file names with spaces), globbing and because `ls` may corrupt file names
    some command "$i"         
done
```
## Bash other
- `source <file>`- include another file
- `. <file>` – include another file; the dot-syntax is more portable
- `ctrl-r` - search through command history
- `ctrl-w` - to delete the last word
- `ctrl-u` - to delete the whole line.
- `alt-b` and `alt-f` to move by word
- `ctrl-k` to kill to the end of the line
- `(cd somedir || exit; some-command)` - do something in `somedir` dir, continue in the current dir after the subshell finishes
- `set -x` - enable debugging of bash script

## Crypto

- `openssl x509 -noout -text -in cert.pem` – view cert info (show only the first cert)
- `openssl x509 -noout -text -fingerprint -sha1 -in cert.pem` – view cert info including its sha1 fingerptint
- `openssl x509 -purpose -in cert.pem –noout` – view effective cert purposes (show only the first cert)
- `openssl crl2pkcs7 -nocrl -certfile certs.pem | openssl pkcs7 -print_certs -text -noout` - view cert info (show all certs found in certs.pem)
- `openssl smime -sign -in text.txt -signer signingcertkey.pem -inkey signingcertkey.pem -out signed.pkcs7.smime` – SMIME sign 
- `openssl smime -verify -in signed.pkcs7.smime -CAfile signingcertca.pem` – verify SMIME-signed message against the issuer CA
- `openssl smime -verify -in message -noverify -signer cert.pem` – extract cert from SMIME-signed message to cert.pem
- `openssl rsa -in privateKey.pem -out newPrivateKey.pem` – remove passphrase from RSA private key
- `openssl rsa -in private.key -inform PEM  -out private-rsa.key -outform PEM` - convert PKCS#8 private key (i.e. the one with `BEGIN PRIVATE KEY` header) to PKCS#1 RSA private key (i.e. the one with `BEGIN RSA PRIVATE KEY` header)
- `openssl pkcs12 –nodes -in file.pfx -out file.pem` – extract all from PKCS#12 package
- `echo –n "some text" | openssl base64 –e` - base64 encode
- `echo "ABCDEF==" | openssl base64 –d` – base64-decode
- `echo -n "text" | md5sum` - calculate MD5 digest of the file 
- `echo –n "text" | uuencode –m /dev/stdout`  - base64-encode
- `htpasswd [–c] passwd_file username` - generate Apache password for username and store it to passwd_file. `–c` option is used to create a new passwd-file instead of adding lines to an existing one.
- `echo -n | openssl s_client -showcerts -connect github.com:443  2>/dev/null  | sed -ne '/-BEGIN CERTIFICATE-/,/-END CERTIFICATE-/p' > /usr/local/share/ca-certificates/DigiCert-CA.crt && update-ca-certificates` - quick install github CA certificates to the trusted store

### Signing others' certificate requests with our CA and key
```bash
cat signingca.pem signingkey.pem rootca.pem > signingcacertkey.pem
openssl x509 -req -in certreq.p10 -sha256 -extfile openssl.cnf -extensions usr_cert -CA signingcacertkey.pem -CAkey signingcacertkey.pem -CAcreateserial -out cert.pem -days 365
# produce also PKCS#7 cert
openssl crl2pkcs7 -nocrl -certfile cert.pem -out cert.p7b -certfile signingcacertkey.pem
```
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
Sample merge session
```
git checkout -B master origin/master
git merge --no-ff --no-commit origin/feature
git diff master
git commit -a
git push
```
List subtrees merged to your project:

`git log | grep git-subtree-dir | tr -d ' ' | cut -d ":" -f2 | sort | uniq`

### Housekeeping
- `git branch -D unneeded-branch` - delete local branch
- `git push origin --delete unneeded-branch` - delete remote branch
- `git fetch -p`  - prune remote-tracking branches no longer on remote

### Pretty print logs
```
git config --global alias.lg "log --color=auto --graph --abbrev-commit --decorate --date=relative --format=format:'%C(bold blue)%h%C(reset) - %C(green)(%ar)%C(reset) %C(white)%s%C(reset) %C(bold black)- %an%C(reset)%C(bold yellow)%d%C(reset)'"
git config --global alias.lg2 "log --color=auto --graph --abbrev-commit --decorate --format=format:'%C(bold blue)%h%C(reset) - %C(cyan)%aD%C(reset) %C(green)(%ar)%C(reset)%C(bold yellow)%d%C(reset)%n''          %C(white)%s%C(reset) %C(bold black)- %an%C(reset)' --all"
```

### Pretty print status
```
git config --global status.color "auto"
git config --global color.status.added "green"
git config --global color.status.changed "bold blue"
git config --global color.status.untracked "magenta"
git config --global color.status.deleted "red"
```

### Convenience aliases
```
git config --global alias.ci "commit"
git config --global alias.st "status"
git config --global alias.di "diff"
```

### Rewrite merge commit (making merge branch disappear)
  1. Reset master branch to the commit in the master branch before the merge
  2. `git cherry-pick -m 1 <sha-of-the-merge-commit>`
  3. Now just add remaining commits e.g. by cherry picking them, reshuffling them as you wish

### Misc git gotchas

Diff commited file to the previous commit:

`git diff HEAD@{1} filename`

Diff between the current and the previous commit, ignoring whitespace:

`git diff -w HEAD^`

Diff between the current and the previous commit, file names only:

`git diff HEAD^ --name-status`
 
Revert local modifications to a file

`git checkout filename`

Revert all local modifications

`git checkout -f`

Checkout remote branch overwriting a local branch

`git checkout -B my-branch origin/my-branch`

Combine two last commits into one

`git reset --soft "HEAD^ && git commit --amend --no-edit`

Oh shit, I accidentally committed something to master that should have been on a brand new branch!
```
# create a new branch from the current state of master
git branch new-branch-name
# remove the commit from the master branch
git reset HEAD~ --hard
git checkout new-branch-name
```

Oh shit, I accidentally committed to the wrong branch!
```
git reset HEAD~ --soft
git stash
# move to the correct branch
git checkout name-of-the-correct-branch
git stash pop
git add . # or add individual files
git commit -m "your message here"
```
another way is to use cherry-pick
```
git checkout name-of-the-correct-branch
git cherry-pick master
git checkout master
git reset HEAD~ --hard
```

Duplicate repo including all branches and tags

```
git clone --bare <original-repo-url> <clone-dir>
cd <clone-dir>
git push --mirror <new-repo-url>
```


#### Good git commit messages
 Check this out [The seven rules of a great git commit message](http://chris.beams.io/posts/git-commit/)

## Docker

Cleanup all stopped containers and untagged images
```
docker rm $(docker ps -a -q)
docker rmi $(docker images | grep "^<none>" | awk '{print $3}')
```

## Proxy
### How to set up a SOCKS proxy server and proxy traffic from browser on Windows and from git client on *nix

#### 1. Setup proxy server
Just make sure you have ssh daemon up and running. That's the nice thing of SOCKS proxy, once you have sshd running, there is no need for more configuration serve-side.
#### 2. Setup browser on Windows client machine
Create ssh session in Putty with hostname and ssh port of your proxy server.
Under menu Connection -> SSH -> Tunnels add source port (say, 1337), and destination "dynamic".
Open this session, enter login credentials and leave the session open
In your browser (Firefox/Chrome) just specify SOCK5 server localhost and port 1337
#### 3. Setup git over ssh on *nix client machine
Setup ssh tunnel to your proxy my-proxy.org:2222
`ssh -D 1337 -f -C -q -N -p 2222 your-username@my-proxy.org`
enter username and password when prompted
##### When accessing git repo via `ssh` protocol e.g. ssh://git@my-repo.com/my-product.git on Linux
Add to ~/.ssh/config:
(make sure to install the program specified via ProxyCommand)
```
Host my-repo.com
User                    git
ProxyComman connect-proxy -S localhost:1337 %h 
```
alternatively to `connect-proxy` you may use `socat` or `tsocks`.
##### When accessing git repo via `ssh` protocol e.g. ssh://git@my-repo.com/my-product.git on OpenBSD
Add to ~/.ssh/config:
```
Host my-repo.com
User                    git
ProxyCommand            nc -x localhost:1337 %h %p
```
##### When accessing git repo via `http(s)` protocol e.g. `https://my-repo.com/my-product.git`
`git config --global http.proxy socks5://localhost:1337`
##### When accessing git repo via `git` protocol e.g. `git://my-repo.com/my-product.git`
```
git config --global core.gitproxy "git-proxy"
git config --global socks.proxy "localhost:1337"
```

for more info:
- http://cms-sw.github.io/tutorial-proxy.html
- https://www.digitalocean.com/community/tutorials/how-to-route-web-traffic-securely-without-a-vpn-using-a-socks-tunnel#step-4-(mac-os-xlinux)-—-creating-shortcuts-for-repeated-use

## Miscellaneous
- `date MMDDhhmmYYYY`  - set date
- `ntpd –s` – set time immidiately (OpenBSD)
- `ntpd -gq` – set time and exit (Linux)
- `uuidgen` – generated uuid
- `screen `- screen window manager that multiplexes a physical terminal between several processes. Useful e.g. when having multiple screens per one ssh connection
- `grabserial` - reads a serial port and writes the data to standard output. Useful e.g. to measure system boot time (`-t` option)
- `echo $?` – exit code of the last executed program

### Granting permissions to /var/www
Taken from [here](http://superuser.com/questions/19318/how-can-i-give-write-access-of-a-folder-to-all-users-in-linux)
 
To best share with multiple users who should be able to write in `/var/www`, it should be assigned a common group. For example the default group for web content on Ubuntu and Debian is `www-data`. 

- Make sure all the users who need write access to `/var/www` are in this group.

  `sudo usermod -a -G www-data phpadmin`

- Give `www-data` group ownership of `/var/www`:

  `sudo chgrp -R www-data /var/www`

- Give `www-data` group write permissions on `/var/www`:

  `sudo chmod -R g+w /var/www`

- It is also recommended that you set setgid on `/var/www` to have all files created under `/var/www` owned by the `www-data` group.

  `sudo find /var/www -type d -exec chmod g+s {} \; `
  
Notice that it it not possible set setuid on `/var/www` so that all new files created under `/var/www` owned by the `phpadmin` user (only possible on FreeBSD). The best you can do is to give all *existing* files in `/var/www` read and write permission for owner and group:

  `sudo find /var/www -type f -exec chmod ug+rw {} \;`

You might have to log out and log back in to be able to make changes if you're editing permission for your own account.

 

### Restrict access for ftpuser to `/var/www` only using `vsftpd`

`usermod --home /var/www/ ftpuser`

then set required permission for ftpuser on `/var/www/` if needed (see the above section about apache)
 
Edit `/etc/vsftpd/vsftpd.conf`:

`chroot_local_user=YES`

 and restart `vsftpd`
 
### Analyse Apache access log for the most frequent source IP addresses
`tail -10000 /var/log/apache2/access.log | awk '{print $1}' | sort | uniq -c | sort -n | tail`
 
### Analyse Apache access log for the most frequent source user agent
`tail -10000 /var/log/apache2/access.log | awk '{print $12}' | sort | uniq -c | sort -n | tail`


### See package changelog
- `apt-get changelog <package>` - for Debian/Ubuntu
- `rpm -q --changelog <package> | head` - for CentOS
 

