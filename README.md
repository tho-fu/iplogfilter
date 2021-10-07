# iplogfilter
Search for ip-ranges within your logfiles

1. Edit the Config Variables for your own IP-Ranges to search for.
2. Start the script

That's it. :-)

The initial release works only for fail2ban.log and auth.log.

---

usage: iplogfilter.py [-h] [-v] -t  logfile

Search for most wanted IP-Ranges in your logfiles

positional arguments:
  logfile           logfile name and path

optional arguments:
  -h, --help        show this help message and exit
  -v, --version     show program's version number and exit
  -t , --filetype   input filetype - 1 = Fail2Ban - 2 = AuthLog

Example of usage: iplogfilter/iplogfilter.py -t 1 logfile
