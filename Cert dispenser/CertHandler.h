#pragma once
#include "Rawsocket.h"
#include "openssl/evp.h"
#include "openssl/rsa.h"
constexpr auto MAXBUFLEN = 200;

class CertHandler
{
public:
	CertHandler(CWizReadWriteSocket* socket);
	int createCert();
	int createKey(EVP_PKEY* pkey);
	int handleConnection();
private:
	CWizReadWriteSocket* h_socket = nullptr;
	std::string clientIPAdds = "";
	EVP_PKEY* CAKey;
};

