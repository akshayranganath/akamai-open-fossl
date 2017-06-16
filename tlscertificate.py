import OpenSSL.crypto 

class TLSCertificate:	
	"""
		Description: 
			Object to store the TLS certificate information.

			For now, we only extract and store only 3 things:
				pemEncodedCert: PEM encoded certificate
				sha1Fingerprint: SHA1 fingerprint in lower case with all the ':' removed.
				cert: The full certificate information, if it is required for future.

	"""
	def __init__(self):
		self.cert = None
		self.sha1Fingerprint = None
		self.pemEncodedCert = None

	def loadCertificate(self, cert):	
		"""
			Arguments:
				cert: PEM encoded certificate, typically extracted from an openssl s_client call.

			Returns:
				Returns a dictionary with 2 parameters: { sha1Fingerprint, pemEncodedCert }

		"""	
		self.cert = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, cert)
		self.sha1Fingerprint = self.cert.digest("sha1").lower().replace(':','')
		self.pemEncodedCert = cert.replace('\n','')+'\\n'
		return { \
				'sha1Fingerprint' : self.sha1Fingerprint, \
				'pemEncodedCert' : 	self.pemEncodedCert \
			}

	def getSha1Fingerprint(self):		
		return self.sha1Fingerprint

	def getPemEncodedCert(self):
		return self.pemEncodedCert
	
	def splitPemStrings(self, certData):
		"""
		Arguments: 
			certData: Raw PEM string returned from an openssl call. 

		Returns:
			List of certificate strings extraccted from the raw string.

		Description:
			An origin cert can have multiple certificates (the root, the intermediate and so on) each seperated by the "----BEGIN CERTIFICATE----" and "-----END CERTIFICATE-----".
			Each such string is split and saved into a list.			
		"""
		tlsCerts = []
		
		parsingCert = True
		currentCert = ""
		for line in certData.split('\n'):
			if line.strip()!="-----END CERTIFICATE-----":
				currentCert += line+'\n'
			else:
				currentCert += line+'\n'
				tlsCerts.append(currentCert)
				currentCert = ""
		
		return tlsCerts

	def writePemFile(self, pem_file_name, openssl_data):
		"""
		Arguments:
			pem_file_name: Name of the file where the certificate information will be saved.
			openssl_data: Raw data from an openssl call

		Description:
			When the raw response from an openssl s_client call is passed into this function, it will generate a file containing all the 
			PEM encoded TLS certificates.
		"""
		with open(pem_file_name,'wb') as pem_file:	
			writing_cert = False
			for line in openssl_data.split('\n'):
				line = line.strip()
				if line == "-----BEGIN CERTIFICATE-----":
					writing_cert=True
				
				if writing_cert:
					pem_file.write(line+'\n')

				if line == "-----END CERTIFICATE-----":
					writing_cert=False			


	def __str__(self):
		return "Fingerprint: "+self.sha1Fingerprint+"\n"+self.pemEncodedCert