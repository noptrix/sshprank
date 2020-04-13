# Description
A fast SSH mass-scanner, login cracker and banner grabber tool using the
python-masscan module.

# Usage

```
[ hacker@blackarch ~ ]$ sshprank -H
--==[ sshprank by nullsecurity.net ]==--

usage

  sshprank <mode> [opts] | <misc>

modes

  -h <host:[ports]>     - single host to crack. multiple ports can be seperated
                          by comma, e.g.: 22,2022,22222 (default port: 22)

  -l <file>             - list of hosts to crack. format: <host>[:ports]. multiple
                          ports can be seperated by comma (default port: 22)

  -m <opts> [-r <num>]  - pass arbitrary masscan opts, portscan given hosts and
                          crack for logins. found sshd services will be saved to
                          'sshds.txt' in supported format for '-l' option and
                          even for '-b'. use '-r' for generating random ipv4
                          addresses rather than scanning given hosts. these
                          options are always on: '-sS -oX - --open'.
                          NOTE: if you intent to use the '--banner' option then
                          you need to specify '--source-ip <some_ipaddr>' which
                          is needed by masscan.

  -b <file>             - list of hosts to grab sshd banner from
                          format: <host>[:ports]. multiple ports can be
                          seperated by comma (default port: 22)

options

  -r <num>              - generate <num> random ipv4 addresses, check for open
                          sshd port and crack for login (only with -m option!)
  -c <cmd>              - execute this <cmd> on host if login was cracked
  -u <user>             - single username (default: root)
  -U <file>             - list of usernames
  -p                    - single password (default: root)
  -P <file>             - list of passwords
  -C <file>             - list of user:pass combination
  -x <num>              - num threads for parallel host crack (default: 20)
  -s <num>              - num threads for parallel service crack (default: 10)
  -X <num>              - num threads for parallel login crack (default: 20)
  -B <num>              - num threads for parallel banner grabbing (default: 50)
  -T <sec>              - num sec for connect timeout (default: 2s)
  -R <sec>              - num sec for (banner) read timeout (default: 2s)
  -o <file>             - write found logins to file. format:
                          <host>:<port>:<user>:<pass> (default: owned.txt)
  -e                    - exit after first login was found. continue with other
                          hosts instead (default: off)
  -v                    - verbose mode. show found logins, sshds, etc.
                          (default: off)

misc

  -H                    - print help
  -V                    - print version information

examples

  # crack targets from a given list with user admin, pw-list and 20 host-threads
  $ ./sshprank -l sshds.txt -u admin -P /tmp/passlist.txt -x 20

  # first scan then crack from founds ssh services
  $ sudo ./sshprank -m '-p22,2022 --rate=5000 --source-ip 192.168.13.37 \
    --range 192.168.13.1/24'

  # generate 1k random ipv4 addresses, then port-scan (tcp/22 here) with 1k p/s
  # and crack login 'root:root' on found sshds
  $ sudo ./sshprank -m '-p22 --rate=1000' -r 1000 -v

  # grab banners and output to file with format supported for '-l' option
  $ ./sshprank -b hosts.txt > sshds2.txt

```

# Notes

- sshprank is already packaged and available for [BlackArch Linux](https://www.blackarch.org/)
- My master-branches are always dev-branches; use releases for stable versions.
- All of my public stuff you find are officially announced and published via [nullsecurity.net](https://www.nullsecurity.net).

# Author
noptrix

# Disclaimer
We hereby emphasize, that the hacking related stuff found on
[nullsecurity.net](http://nullsecurity.net/) are only for education purposes.
We are not responsible for any damages. You are responsible for your own
actions.
