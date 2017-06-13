# FOSSL Helper

This module will provide helper functions to easily pull the origin's PEM file and update the Akamai configuration rules. Using the Property Manager API [PAPI](https://developer.akamai.com/api/luna/papi/overview.html), the configuration can then be activated to the Akamai network.

## Setup
After downloading the code, execute the following to install the libraries.
```bash
pip -r requirements.txt
```

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

## Cert Update Pipeline

Here's the steps to update your rules to use the new cert.

### Step 1: Get the current configuration rules.
Suppose the configuration file at Akamai is named __papitest2.demo.com__. Here's the method to get back the rules.
```bash  
./akamaiProperty retrieve papitest2.demo.com --file rules.json
```

### Step 2: Run fossl_setup.py

Assuming that the origin is not ACLed for just Akamai, you can run this script to pull the origin certificate and insert it into rules.
```bash  
python fossl_setup.py --file rules.json --origin akshayranganath.github.io
```

### Step 3: Update rules
After the rules have been updated with the certificate information, run the _akamaiProperty_ command to push out the update to the configuration on Akamai.
```bash  
./akamaiProperty update papitest2.demo.com --file rules.json
```

### Step 4: Activate configuration
Once the update completes, you should be able to push the configuration out to Akamai staging network and test the new setup.
```bash  
./akamaiProperty activate papitest2.demo.com
```

This will the latest configuration version to staging. Please see the documentation at [Akamai ConfigKit](https://github.com/akamai-open/akamaiconfigkit-public) page for more details.