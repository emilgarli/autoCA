#include "CertHandler.h"
#include <iostream>

#include "cstring"
CertHandler::CertHandler(CWizReadWriteSocket* socket)
{
	//If we don't find the CA files, we create them
	/*if (openPKCS12(cafilesName) != 0) {
		std::cout << "No CA files found. Generating new..." << std::endl;
		createKey(CAKey);
		createCert(CAKey, CACert);
		writeToPKCS12(CAKey, CACert);
	}*/
	h_socket = socket;
}

int CertHandler::openPKCS12(const char* fileName) {
	PKCS12* p12 = NULL;
	STACK_OF(X509)* stack;

	FILE* pfxFile = fopen(fileName, "rb");
	if (!pfxFile)
		return 1;
	p12 = d2i_PKCS12_fp(pfxFile, &p12);
	if (!p12)
		return 2;
	//The stack should be NULL
	if (!PKCS12_parse(p12, "password", &CAKey, &CACert, &stack)) {
		printf("Failed to parse PKCS#12 structure\n");
		PKCS12_free(p12); // Clean up
		return 3;
	}
	PKCS12_free(p12);
	return 0;
}

int CertHandler::writeToPKCS12(EVP_PKEY* privateKey, X509* certificate, const char* fileName) {
	BIO* mem = BIO_new(BIO_s_mem());
	PEM_write_bio_X509(mem, ServerCert);
	PEM_write_bio_X509(mem, CACert);

	STACK_OF(X509)* ca = sk_X509_new_null();
	if (!ca) {
		printf("Failed to create X509 stack\n");
		BIO_free(mem);
		return -1;
	}

	sk_X509_push(ca, ServerCert);
	sk_X509_push(ca, CACert);

	PKCS12* p12 = PKCS12_create(
		"password",         // Password to protect the PFX file
		"MyCert",         // Friendly name for the certificate
		PrivateKey,        // The server's private key
		ServerCert,       // The server certificate
		ca,               // The CA chain (stack of intermediate/root certificates)
		0, 0, 0, 0, 0);   // Various PKCS#12 flags (defaults for encryption, iteration counts, etc.)

	if (!p12) {
		printf("Failed to create PKCS#12 structure\n");
		sk_X509_free(ca);
		BIO_free(mem);
		return -1;
	}
	FILE* pfxFile = fopen(fileName, "wb");
	if (!pfxFile) {
		printf("Failed to open file for writing\n");
		PKCS12_free(p12);
		sk_X509_free(ca);
		BIO_free(mem);
		return -1;
	}

	if (i2d_PKCS12_fp(pfxFile, p12) <= 0) {
		printf("Failed to write PKCS#12 to file\n");
		fclose(pfxFile);
		PKCS12_free(p12);
		sk_X509_free(ca);
		BIO_free(mem);
		return -1;
	}

	fclose(pfxFile);
	PKCS12_free(p12); 
	sk_X509_free(ca);  
	BIO_free(mem);    

	printf("PKCS#12 (PFX) file successfully created\n");
	return 0;
}

int CertHandler::createCert(EVP_PKEY* pkey, X509* cert)
{
	X509* x509;
	x509 = X509_new();
	ASN1_INTEGER_set(X509_get_serialNumber(x509), 1);
	X509_gmtime_adj(X509_get_notBefore(x509), 0);
	X509_gmtime_adj(X509_get_notAfter(x509), 31536000L); //This is one year validity period of the cert
	X509_set_pubkey(x509, pkey);
	X509_NAME* name = X509_get_subject_name(x509);
	X509_NAME_add_entry_by_txt(name, "C", MBSTRING_ASC, (const unsigned char*)"NO", -1, -1, 0);
	X509_NAME_add_entry_by_txt(name, "O", MBSTRING_ASC, (const unsigned char*)"CryptOrg", -1, -1, 0);
	X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC, (const unsigned char*)"emil.garli@gmail.com", -1, -1, 0);
	X509_EXTENSION* ext;
	X509V3_CTX ctx; // Create an X509V3 context for extensions

	X509_set_issuer_name(x509, X509_get_subject_name(CACert));

	X509V3_set_ctx_nodb(&ctx);
	X509V3_set_ctx(&ctx, CACert, x509, NULL, NULL, 0);

	// Example SAN string: "DNS:example.com,IP:192.168.0.1"
	std::string sanField = "subjectAltName=" + clientIPAdds;

	// Create and add SAN extension
	ext = X509V3_EXT_conf_nid(NULL, &ctx, NID_subject_alt_name, sanField.c_str());
	if (!ext) {
		X509_free(x509);
		return -1; // Failed to create SAN extension
	}
	X509_add_ext(x509, ext, -1);
	X509_EXTENSION_free(ext); // Free the extension object once added to cert

	if (!X509_sign(x509, CAKey, EVP_sha256())) {
		X509_free(x509);
		return -1; // Failed to sign certificate
	}
	cert = x509;
	X509_free(x509);
	return 0;
}

//Takes a reference to a EVP_PKEY and fills it with a new rsa key
int CertHandler::createKey(EVP_PKEY* pkey) {

	EVP_PKEY_CTX* ctx = NULL;
	pkey = NULL;

	// Create context for key generation
	ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);
	if (!ctx) {
		printf("Failed to create EVP_PKEY_CTX\n");
		return NULL;
	}

	// Initialize the context for key generation
	if (EVP_PKEY_keygen_init(ctx) <= 0) {
		printf("Failed to initialize keygen context\n");
		EVP_PKEY_CTX_free(ctx); // Clean up context
		return NULL;
	}

	// Set the key length (2048-bit RSA)
	if (EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, 2048) <= 0) {
		printf("Failed to set RSA key length\n");
		EVP_PKEY_CTX_free(ctx);
		return NULL;
	}

	// Generate the key
	if (EVP_PKEY_keygen(ctx, &pkey) <= 0) {
		printf("Failed to generate RSA key\n");
		EVP_PKEY_CTX_free(ctx);
		return NULL;
	}

	// Clean up context
	EVP_PKEY_CTX_free(ctx);
	return 0;
}

int CertHandler::handleConnection()
{
	int iRead = 0;
	char addressBuffer[64];
	UINT peerPort = 0;
	h_socket->GetPeerName(addressBuffer, sizeof(addressBuffer) / sizeof(TCHAR), peerPort);
	//The format should be: IP Address xx.x.x.xx, IP Address:127.0.0.1
	//Maybe add support for more IPs?
	clientIPAdds = "IP Address:" + std::string(addressBuffer) + ", IP Address:127.0.0.1";
	//First we fill the slot PrivateKey in the class with a new RSA key
	createKey(PrivateKey);
	createCert(PrivateKey, ServerCert);
	writeToPKCS12(PrivateKey, ServerCert, "collection.pfx");
	FILE* pfxFile = fopen("collection.pfx", "rb");
	//Figure out file size
	fseek(pfxFile, 0, SEEK_END);
	long fileSize = ftell(pfxFile);
	fseek(pfxFile, 0, SEEK_SET);

	BYTE* fileBuffer = new BYTE[fileSize];
	size_t bytesRead = fread(fileBuffer, 1, fileSize, pfxFile);

	if (bytesRead != fileSize) {
		delete[] fileBuffer;
		fclose(pfxFile);
		return 0;
	}

	fclose(pfxFile);

	return h_socket->Write(fileBuffer, bytesRead);
	
}