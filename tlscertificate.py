import OpenSSL.crypto 

class TLSCertificate:	
	
	def __init__(self):
		self.cert = None
		self.sha1Fingerprint = None
		self.pemEncodedCert = None

	def loadCertificate(self, cert):		
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