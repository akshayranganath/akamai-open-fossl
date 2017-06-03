# FOSSL Helper

This module will provide helper functions to easily pull the origin's PEM file and update the Akamai configuration rules. Using the Property Manager API [PAPI](https://developer.akamai.com/api/luna/papi/overview.html), the configuration can then be activated to the Akamai network.

## Usage
The main python file is fossl_setup.py. CLI usage is as follows:
```bash
$ python fossl_setup.py --help
usage: fossl_setup.py [-h] --file FILE [--origin ORIGIN] [--pem_file PEM_FILE]
                      [--use_sni]

Script to create the FOSSL setting for your origin and update your
configuration rules

optional arguments:
  -h, --help           show this help message and exit
  --file FILE          PAPI Rules file to update with the FOSSL details
  --origin ORIGIN      Origin server name. Using openssl, the TLS cert will be
                       downloaded and stored in 'pem_file'
  --pem_file PEM_FILE  Origin's PEM file to use for creating FOSSL section. If
                       unspecified, a temporary file called cert.txt will be
                       created.
  --use_sni            Use SNI header when pulling the origin certificate
 ```