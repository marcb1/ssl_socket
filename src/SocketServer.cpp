#include "SocketServer.h"
#include "helpers.h"

void SocketServer::runCallBack(SSL* sslSock, int sockFd, SocketServer::CallBack f)
{
    f(sslSock, sockFd);
    close(sockFd);
    deleteSSLStruct(sslSock);
}

SocketServer::SocketServer(unsigned int portNumber):
    _port(portNumber),
    _socketfd(-1)
{
    loadOpenSSL();
}

SocketServer::~SocketServer()
{
    unloadOpenSSL();
}

int SocketServer::startServer(SocketServer::CallBack f)
{
    _socketfd = socket(AF_INET, SOCK_STREAM, 0);
    if(_socketfd < 0)
    {
        std::cerr << "Encountered error while creating socket..." << std::endl;
        return 1;
    }

    struct sockaddr_in server_address;
    server_address.sin_family = AF_INET;
    server_address.sin_port = htons(_port); //host to network for short, flips bytes if machine is little endian
    server_address.sin_addr.s_addr = htonl(INADDR_ANY);//contains primary address of machine
    memset(server_address.sin_zero, 0, 8);

    int res = bind(_socketfd, (struct sockaddr*)&server_address, sizeof(server_address));
    if(res < 0)
    {
        std::cerr << "Cannot bind to socket" << std::endl;
        return 1;
    }

    //listen and accept max 5 connections
    res = listen(_socketfd, 5);
    if(res < 0)
    {
        std::cerr << "cannot listen to socket" << std::endl;
        return 1;
    }

    std::cout << "Listening on local port:" <<  _port << std::endl;

    while(1)
    {
        struct sockaddr_in client_address;
        socklen_t client_length = sizeof(client_address);

        std::cout << std::endl << "Waiting for connection..." << std::endl;
        // acccept will fill in the data
        int client_fd = accept(_socketfd, (struct sockaddr*)&client_address, &client_length);         
        if (client_fd < 0)
        {
            std::cerr << "cannot accept new socket" << std::endl;
            continue;
        }
        std::cout << "Accepted new client connection; upgrading connection to SSL..." << std::endl;

        SSL_CTX *sslctx = NULL;
        sslctx = SSL_CTX_new(SSLv3_server_method());
        if (sslctx == NULL)
        {
            std::cerr << "Error: can't create ssl context..." << std::endl;
            close(client_fd);
            return 1;
        }

        SSL_CTX_set_options(sslctx, SSL_OP_SINGLE_DH_USE);
        // load certificate
        int cert = SSL_CTX_use_certificate_file(sslctx, "./certs/cacert.pem" , SSL_FILETYPE_PEM);
        if (cert != 1)
        {
            std::cerr << "Can't load certificate, exiting..." << std::endl;
            close(client_fd);
            continue;
        }

        //load private key associated with certificate
        int prv = SSL_CTX_use_PrivateKey_file(sslctx, "./certs/private.pem", SSL_FILETYPE_PEM);
        if (prv != 1)
        {
            std::cerr << "Can't load private key, exiting..." << std::endl;
            close(client_fd);
            continue;
        }

        SSL* cSSL = SSL_new(sslctx);
        SSL_set_fd(cSSL, client_fd);

        //future reads and write to socket will use SSL
        int ret = SSL_accept(cSSL);
        if (ret <= 0)
        {
            std::cerr << "can't accept SSL upgraded socket..." << std::endl;
            // cleanUpOpenSSL(cSSL);
            close(client_fd);
            continue;
        }
        std::cout << "succesfully upgraded socket to SSL..." << std::endl;
        ThreadPtr pThread(new std::thread(&SocketServer::runCallBack, this, cSSL, client_fd, f));
        _threadPool.push_back(pThread);
    }
}
