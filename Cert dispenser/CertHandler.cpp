#include "CertHandler.h"
#include <iostream>

CertHandler::CertHandler(CWizReadWriteSocket* socket)
{
	h_socket = socket;
}

int CertHandler::createCert()
{
	return 0;
}

int CertHandler::createKey(EVP_PKEY* pkey) {
	pkey = EVP_PKEY_new();
	RSA* rsa = NULL;
	rsa = RSA_generate_key(
		2048,   /* number of bits for the key - 2048 is a sensible value */
		RSA_F4, /* exponent - RSA_F4 is defined as 0x10001L */
		NULL,   /* callback - can be NULL if we aren't displaying progress */
		NULL    /* callback argument - not needed in this case */
	);

	if(rsa!= NULL)
		EVP_PKEY_assign_RSA(pkey, rsa);

}

int CertHandler::handleConnection()
{
	char* inBuf[MAXBUFLEN]{};
	int iRead = 0;
	//First we want to read the connection for the IP that we are to make the cert for
	while(iRead == 0)
		iRead = h_socket->Read(inBuf, MAXBUFLEN);
	//The format should be: IP Address:127.0.0.1, IP Address xx.x.x.xx, IP ...
	clientIPAdds = *inBuf;
	if (strncmp(clientIPAdds.c_str(), "IP Address", 11) != 0) {
		std::cout << "Invalid data received" << std::endl;
	}
	else
		createCert();
	return 0;
}


