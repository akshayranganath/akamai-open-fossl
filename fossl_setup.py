import subprocess
import argparse
import json
from tlscertificate import TLSCertificate
import os, errno

def getCertDetails(filename):
	with open(filename, "rb") as f:
		cert = f.read()		
		tlscert = TLSCertificate(cert)
		return tlscert

def saveOriginCert(origin, pem_file, use_sni=False):	
	certificate = subprocess.check_output(['openssl', 's_client', '-showcerts', '-connect', origin+':443'],stdin=subprocess.PIPE,stderr=None)		
	with open(pem_file,'wb') as pem_file:	
		pem_file.write('-----BEGIN CERTIFICATE-----'+ certificate.split('-----BEGIN CERTIFICATE-----')[1].split('-----END CERTIFICATE-----')[0] + '-----END CERTIFICATE-----')
		
def createPapiRule(papiFile, tlscert):
	rules = None
	with open(papiFile, 'r') as papiRules:	
		rules = json.loads(papiRules.read())
		for behavior in rules['rules']['behaviors']:			
			if behavior['name']=="origin":
				origin_behavior_options = behavior['options']
				#reset the origin cert behavior field
				origin_behavior_options['customCertificates'] = [{}]
				origin_behavior_options['verificationMode'] = 'CUSTOM'
				origin_behavior_options['originCertsToHonor'] = 'CUSTOM_CERTIFICATES'
				origin_behavior_options['customValidCnValues'] = [\
															            "{{Origin Hostname}}",\
															            "{{Forward Host Header}}"\
     															  ]
				origin_certificate = origin_behavior_options['customCertificates'][0]
				origin_certificate['sha1Fingerprint'] = tlscert.get_sha1Fingerprint()
				origin_certificate['pemEncodedCert'] = tlscert.get_pemEncodedCert()

				#print behavior

	with open(papiFile,'w') as papiRules:
		papiRules.write( json.dumps(rules, indent=2, sort_keys=True) )
	print "Papi file updated"
				#print json.dumps(behavior)

	#now find the correct place in the rule hierarchy

def cleanup(pem_file="cert.txt"):	
	os.remove(pem_file)	



if __name__=="__main__":
	parser = argparse.ArgumentParser(description='Script to create the FOSSL setting for your origin \and update your configuration rules')
	parser.add_argument('--file', help="PAPI Rules file to update with the FOSSL details",required=True )	
	parser.add_argument('--origin', help="Origin server name. Using openssl, the TLS cert will be downloaded and stored in 'pem_file'")
	parser.add_argument('--pem_file',  help="Origin's PEM file to use for creating FOSSL section. If unspecified, a temporary file called cert.txt will be created.")
	parser.add_argument('--use_sni', help="Use SNI header when pulling the origin certificate", action="store_true")
	args = parser.parse_args()	

	pem_file = "cert.txt" if args.pem_file is None else args.pem_file	

	if args.origin is None and args.pem_file is None:
		parser.error("Either the pem file (--pem_file) or the origin name (--origin) has to be specified")

	if args.origin is not None:		
		saveOriginCert(args.origin, pem_file)
		
	tlscert = getCertDetails(pem_file)	
	createPapiRule(args.file, tlscert)
	#now cleanup
	cleanup(pem_file)
