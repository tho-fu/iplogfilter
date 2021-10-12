# iplogfilter
Search for ip-ranges within your logfiles

1. Edit the Config Variables for your own IP-Ranges to search for.
2. Configure your mailsettings, if you want to use this function
3. Start the script

That's it. :-)

Works for fail2ban.log, auth.log, OPNSense and IPTables logfiles.

---
<pre>
usage: iplogfilter.py [-h] [-v] -t  [-m] logfile

Search for interesting IP-Ranges within your logfiles

positional arguments:
  logfile           logfile name and path

optional arguments:
  -h, --help        show this help message and exit
  -v, --version     show program's version number and exit
  -t , --filetype   input filetype - 1 = Fail2Ban - 2 = AuthLog - 3 = OPNSense - 4 = IPTables
  -m , --mail       mail the result (only if) to this address

Example of usage: iplogfilter/iplogfilter.py -t 1 logfile
