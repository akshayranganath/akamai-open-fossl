import OpenSSL.crypto 

class TLSCertificate:	
	def __init__(self, cert):		
		self.cert = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, cert)
		self.sha1Fingerprint = self.cert.digest("sha1").lower().replace(':','')
		self.pemEncodedCert = cert.replace('\n','')+'\\n'

	def get_sha1Fingerprint(self):
		return self.sha1Fingerprint

	def get_pemEncodedCert(self):
		return self.pemEncodedCert
	
	def __str__(self):
		return "Fingerprint: "+self.sha1Fingerprint+"\n"+self.pemEncodedCert