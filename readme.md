# FOSSL Helper

This module will provide helper functions to easily pull the origin's PEM file and update the Akamai configuration rules. Using the Property Manager API [PAPI](https://developer.akamai.com/api/luna/papi/overview.html), the configuration can then be activated to the Akamai network.

## Usage
The main python file is fossl_setup.py. CLI usage is as follows:
```bash
$ python fossl_setup.py --help
usage: fossl_setup.py [-h] --file FILE [--origin ORIGIN] [--pem_file PEM_FILE]
                      [--use_sni]

Script to create the FOSSL setting for your origin and update your configuration rules

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

 
## Background

While building a __secure configuration__ on the Akamai platform, you will need to provide the origin server's certificate information. Normally, if you have a standard Certificate Authority (CA), no special setting may be required. However, if you are using a self-signed certificate or a CA that is considered as part of standard Akamai supported set, you will need to __pin__ the TLS certificate.

If you need to pin the origin certificate using the Property Manager interface, the UI runs the following command to extract the details:

	openssl s_client -connect origin-server.customer.com:443

However, when using the Property Manager API (PAPI) or while using the [Akamai Configkit](https://github.com/akamai-open/akamaiconfigkit-public), you would need to follow these steps:

- Pull in the origin certificate and add the details by running the openssl command. If origin is not accessible due to ACL, get the certification information from the Ops teams.
- Run a PAPI / ConfigKit command to extract the rules for the configuration.
- Insert the certificate details and push out a new version of the configuration.

The FOSSL helper function tries to automate this part of the job. If you already have the configuration rules, helper function will run the openssl commands and then insert the certificate details into the correct section. Using PAPI/Config Kit.