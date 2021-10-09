# iplogfilter
Search for ip-ranges within your logfiles

1. Edit the Config Variables for your own IP-Ranges to search for.
2. Start the script

That's it. :-)

Works for fail2ban.log, auth.log and OPNSense logfiles.

---
<pre>
usage: iplogfilter.py [-h] [-v] -t  logfile

Search for most wanted IP-Ranges in your logfiles

positional arguments:
  logfile           logfile name and path

optional arguments:<br /> 
  -h, --help        show this help message and exit<br /> 
  -v, --version     show program's version number and exit<br /> 
  -t , --filetype   input filetype - 1 = Fail2Ban - 2 = AuthLog - 3 = OPNSense

Example of usage: iplogfilter/iplogfilter.py -t 1 logfile<pre>
