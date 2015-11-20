#include "SocketClient.h"

//MARCB TODO make this TLS so the callback can grab the pinned certificate that is set
//per thread SocketClient pair.
const char *AUTH_CERTIFICATE =
"-----BEGIN CERTIFICATE-----\n"
"MIIDVzCCAj+gAwIBAgIJANFTqY2e1UnJMA0GCSqGSIb3DQEBBQUAMEIxCzAJBgNV\n"
"BAYTAlhYMRUwEwYDVQQHDAxEZWZhdWx0IENpdHkxHDAaBgNVBAoME0RlZmF1bHQg\n"
"Q29tcGFueSBMdGQwHhcNMTUwOTEwMjIyMjQ5WhcNMTgwOTA5MjIyMjQ5WjBCMQsw\n"
"CQYDVQQGEwJYWDEVMBMGA1UEBwwMRGVmYXVsdCBDaXR5MRwwGgYDVQQKDBNEZWZh\n"
"dWx0IENvbXBhbnkgTHRkMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA\n"
"6ebkhLmOzs8vukS1fqKjF47RD53ZwzOSMYVo14EECMW/3+AS3CG0wjvOJflBm0Kd\n"
"DfRxs+US+Y4bMIZ3ZUD7GxxOlcgnl/Xrcu7rnJU7b6ZIBpfPN4nEaRXXAdbL6A+x\n"
"p+9Kfl5azKdMTKj7ZPT8G8TLbcvJYfSIDGQed7D0aT0vBrP8tJoI3nAwurLJgzdC\n"
"AEaruE3rwoYC0yjFEbgRvtgfJksY1+oRuDUJfcB1AQCxEMoiARofmLhagWWMwPc2\n"
"uoeoB7jjtgTPMZBZqxtFtqoF4LT1U3+DWB6iIz8lPZYE/bw/Ok43lE3lEkLPJveS\n"
"rk2wgkVURkaYwVzPtz0A9QIDAQABo1AwTjAdBgNVHQ4EFgQUR7qcS1PxgJBEeJ3s\n"
"5aHeIiMU+TgwHwYDVR0jBBgwFoAUR7qcS1PxgJBEeJ3s5aHeIiMU+TgwDAYDVR0T\n"
"BAUwAwEB/zANBgkqhkiG9w0BAQUFAAOCAQEAEhkLTlTx0E1wxQFiB22PQxTLi9V1\n"
"7TMz+RiJTjCjjpS+q/aXfbo3m7sLcCOkz9vA2be8LrtcAqbW6PTB8eXwrjgfFwjW\n"
"qczF0tsJYwVHBp52DpynW0Sn3XOW6Br9fg9cVi0COLrnSQFwxV26OMkVM2VZNuuQ\n"
"sR39vAcagqutWKcAb+7yx5uTQMaivb4F7+MY1rqo+k2nNWOhwBa+hKaPSt9D5lCP\n"
"u4VKKK4hmHizEFT4CcWjXgIKMNRhnJAzRSCsArhjaeL8Udx2CYjSttQWPf0i7Jnj\n"
"zxJK95IM1zGDjbKcPds405xlNm/0Se2wY9I90+gAmM3Xzscrie4ppsaZbQ==\n"
"-----END CERTIFICATE-----\n";


SocketClient::SocketClient():
  _socketFd(-1),
  _sslHandle(NULL),
  _sslContext(NULL)
{
  loadOpenSSL();
}

SocketClient::~SocketClient()
{
  closeSocket();
  if(_sslHandle)
  {
    deleteSSLStruct(_sslHandle);
  }
  ::SSL_CTX_free(_sslContext);
  unloadOpenSSL();
}

void SocketClient::closeSocket()
{
  close(_socketFd);
}

bool SocketClient::setUpClient(const std::string& serverIP, int portNumber)
{
  _socketFd = socket(AF_INET, SOCK_STREAM, 0);
  if(_socketFd < 0)
  {
    std::cerr << "unable to create client socket..." << std::endl;
    return false;
  }

  struct hostent* server;
  server = gethostbyname(serverIP.c_str());
  if(server == NULL)
  {
    std::cerr << "unable to parse server ip..." << std::endl;
    return false;
  }

  if((portNumber < 1) || (portNumber > 65535))
  {
    std::cerr << "Incorrect port number..." << std::endl;
    return false;
  }

  _server_address.sin_family = AF_INET;
  _server_address.sin_port = htons(portNumber);
  memcpy(&(_server_address.sin_addr.s_addr), server->h_addr, server->h_length);
  memset(_server_address.sin_zero, 0, 8);
  return true;
}

bool SocketClient::connectSSL()
{
  int ret = connect(_socketFd, (struct sockaddr*)&_server_address, sizeof(_server_address));
  if(ret < 0)
  {
    std::cerr << "can't create client connection..." << std::endl;
    return false;
  }
  return upgradeSocketToSSL();
}

bool SocketClient::writeSSL(const std::string& data)
{
  if(data.size() <= 0)
  {
    std::cerr << "Request to write 0 bytes, ignoring" << std::endl;
    return false;
  }
  int ret = SSL_write(_sslHandle, data.c_str(), data.size());
  return (ret > 0);
}

int SocketClient::checkSSLSocket()
{
  int count = 0;
  int ret = ioctl(_socketFd, FIONREAD, &count);
  if(ret < 0)
  {
    std::cout << "ERROR!" << std::endl;
    return ret;
  }
  return count;
}


std::string SocketClient::readSSL()
{
  return readSocket(_sslHandle);
}

bool SocketClient::upgradeSocketToSSL()
{
  //new SSL context for client
  _sslContext = SSL_CTX_new(SSLv3_client_method());
  if(_sslContext == NULL)
  {
    std::cerr << "Can't create SSL context for client..." << std::endl;
    return false;
  }

  //disable SSLv2
  ::SSL_CTX_set_options(_sslContext, SSL_OP_ALL | SSL_OP_NO_SSLv2);
  //disable weak ciphers
  ::SSL_CTX_set_cipher_list(_sslContext, "ALL:!ADH:!LOW:!EXP:!MD5:@STRENGTH");
  //check server certificate
  ::SSL_CTX_set_verify(_sslContext, SSL_VERIFY_PEER | SSL_VERIFY_CLIENT_ONCE, pinCertCallback);

  //new handle for context
  _sslHandle = ::SSL_new(_sslContext);
  if(_sslHandle == NULL)
  {
    std::cerr << "Can't create SSL handle for context..." << std::endl;
    return false;
  }

  if(!::SSL_set_fd(_sslHandle, _socketFd))
  {
    std::cerr << "Can't upgrade socket to SSL..." << std::endl;
    return false;
  }

  if(::SSL_connect(_sslHandle) != 1)
  {
    std::cerr << "Can't initiate handshake with SSL server..." << std::endl;
    return false;
  }
  std::cout << "upgraded socket to SSL" << std::endl;
  return true;
}

int SocketClient::pinCertCallback(int pok, X509_STORE_CTX *ctx)
{
  std::cout << "Checking pinned certificate" << std::endl;

  X509 *cert = NULL;
  BIO *b64 = NULL;
  BUF_MEM *bptr = NULL;
  char *szCert = NULL;

  cert = ctx->current_cert;
  assert(cert != NULL);

  b64 = BIO_new(BIO_s_mem());
  assert(b64 != NULL);
  assert(1 == PEM_write_bio_X509(b64, cert));

  BIO_get_mem_ptr(b64, &bptr);

  assert(NULL != (szCert = (char*)malloc(bptr->length + 1)));
  assert(0 < BIO_read(b64, szCert, bptr->length));

  int ret = strncmp(szCert, AUTH_CERTIFICATE, strlen(AUTH_CERTIFICATE));

  free(szCert);
  if (b64)
  {
    BIO_free(b64);
  }

  if(ret == 0)
  {
    std::cout << "pinned certificate verification passed..." << std::endl;
    return 1;
  }
  else
  {
    std::cout << "pinned certificate verification failed..." << std::endl;
    return 0;
  }
}
