#pragma once
#include "Rawsocket.h"
#include "openssl/evp.h"
#include "openssl/rsa.h"
#include "openssl/x509.h"
#include <openssl/bio.h>
#include <openssl/pem.h>
#include <openssl/pkcs12.h>
#include <openssl/x509v3.h>

constexpr auto MAXBUFLEN = 200;

class CertHandler
{
public:
	CertHandler(CWizReadWriteSocket* socket);
	int openPKCS12(const char* fileName);
	int writeToPKCS12(EVP_PKEY* privateKey, X509* certificate, const char* fileName = "CAFiles.pfx");
	int createCert(EVP_PKEY* pkey, X509* cert);
	int createKey(EVP_PKEY* pkey);
	int handleConnection();
private:
	CWizReadWriteSocket* h_socket = nullptr;
	std::string clientIPAdds = "";
	EVP_PKEY* CAKey;
	EVP_PKEY* PrivateKey;
	X509* CACert;
	X509* ServerCert;
	const char* cafilesName = "CAFiles.pfx";
};

