#pragma once
#include "helpers.h"

class SocketClient;
typedef std::shared_ptr<SocketClient> SocketClientPtr;


//Class that creates SSL socket to remote server and writes to it
class SocketClient
{
  public:
    SocketClient();

    ~SocketClient();

    void closeSocket();

    bool setUpClient(const std::string& serverIP, int portNumber);

    bool connectSSL();

    bool writeSSL(const std::string& data);

    int checkSSLSocket();

    std::string readSSL();

  private:
    static int pinCertCallback(int pok, X509_STORE_CTX *ctx);

    bool upgradeSocketToSSL();

    int                 _socketFd;            //file descriptor for client socket
    struct sockaddr_in  _server_address;      //sockaddr struct for remote server information

    //openssl SSL wrappers
    ::SSL*                _sslHandle;
    ::SSL_CTX*            _sslContext;
};
