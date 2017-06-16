#! /usr/bin/env python
import subprocess
import argparse
import json
from tlscertificate import TLSCertificate
import os, errno

def getCertDetails(filename):	
	"""	
	Arguments: 
		filename: File contaning PEM encoded certificates.
	
	Returns: 
		list of tls certificates (TLSCertificate objects)

	Description:
		Takes the openssl output data and extracts the PEM encoded certificate information. 
		It can handle muliple certificate details when a chain is presented.
	"""
	tlscerts = []
	with open(filename, "rb") as f:
		cert_data = f.read()
		tlscert = TLSCertificate()
		certs = tlscert.splitPemStrings(cert_data)
		for cert in certs:
			tlscerts.append( tlscert.loadCertificate(cert) )				
		return tlscerts

def saveOriginCert(origin, pem_file, use_sni):		
	"""
	Arguments: 
		origin: DNS name of the origin. It can also be an IP address.
		pem_file: File name to store the PEM-encoded TLS certificate retrieved from origin. Default storage path is the current director.
		use_sni: If enabled, --servername option is used with openssl command. Value is same as origin.
		TO_DO: Allow overriding the servername parameter.
	
	Returns: 
		None

	Description:
		Executes openssl command and saves the certificate information to a file name passed in the argument 'pem_file'		
	"""
	command = ['openssl', 's_client', '-showcerts', '-connect', origin+':443']
	if use_sni==True:
		command.append('-servername')
		command.append(origin)
	
	openssl_data = subprocess.check_output(command ,stdin=subprocess.PIPE,stderr=subprocess.PIPE)		
	tlscert = TLSCertificate()
	tlscert.writePemFile(pem_file, openssl_data)
		
		
def createPapiRule(papiFile, tlscerts):
	"""
	Arguments:
		papiFile: Name of the file containing the PAPI rules.
		tlscerts: List of objets of type TLSCertificate. 

	Returns:
		None

	Desciption:
		Update the PAPI rules by replacing the default origin TLS certificate details with the certificates passed to this function. 	
	"""
	rules = None
	with open(papiFile, 'r') as papiRules:	
		rules = json.loads(papiRules.read())
		for behavior in rules['rules']['behaviors']:			
			if behavior['name']=="origin":
				origin_behavior_options = behavior['options']
				#reset the origin cert behavior field
				origin_behavior_options['customCertificates'] = []
				origin_behavior_options['verificationMode'] = 'CUSTOM'
				origin_behavior_options['originCertsToHonor'] = 'CUSTOM_CERTIFICATES'
				origin_behavior_options['customValidCnValues'] = [\
															            "{{Origin Hostname}}",\
															            "{{Forward Host Header}}"\
     															  ]
				for tlscert in tlscerts:
					origin_certificate = origin_behavior_options['customCertificates'].append(tlscert)
					
				

	with open(papiFile,'w') as papiRules:
		papiRules.write( json.dumps(rules, indent=2, sort_keys=True) )
	print "Papi file updated"
				
	

def cleanup(pem_file="cert.txt"):	
	"""
	Arguments:
		pem_file: Remove the temporary file created to hold the PEM-encoded TLS certificate.

	Returns:
		None

	"""
	os.remove(pem_file)	



if __name__=="__main__":
	parser = argparse.ArgumentParser(description='Script to create the FOSSL setting for your origin and update your configuration rules')
	parser.add_argument('--file', help="PAPI Rules file to update with the FOSSL details",required=True )	
	parser.add_argument('--origin', help="Origin server name. Using openssl, the TLS cert will be downloaded and stored in 'pem_file'")
	parser.add_argument('--pem_file',  help="Origin's PEM file to use for creating FOSSL section. If unspecified, a temporary file called cert.txt will be created.")
	parser.add_argument('--use_sni', help="(Boolena) If present, then use SNI header when pulling the origin certificate", action="store_true")
	args = parser.parse_args()	

	pem_file = "cert.txt" if args.pem_file is None else args.pem_file	

	if args.origin is None and args.pem_file is None:
		parser.error("Either the pem file (--pem_file) or the origin name (--origin) has to be specified")

	if args.origin is not None:		
		saveOriginCert(args.origin, pem_file, args.use_sni)
		
	tlscert = getCertDetails(pem_file)	
	createPapiRule(args.file, tlscert)
	#cleanup is not needed as per the bug https://github.com/akshayranganath/akamai-open-fossl/issues/1
	#cleanup(pem_file)
