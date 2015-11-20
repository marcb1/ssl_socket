#pragma once

#include "helpers.h"

class SocketServer;
typedef std::shared_ptr<SocketServer> SocketServerPtr;

typedef std::function<void(SSL*, int)> CallBack;

class SocketServer
{
  private:
    typedef std::shared_ptr<std::thread> ThreadPtr;
    typedef std::function<void(SSL*, int)> CallBack;

    unsigned int              _port;
    int                       _socketfd;
    std::vector<ThreadPtr>    _threadPool;
    
    void runCallBack(SSL* sslSock, int sockFd, CallBack f);

  public:
    SocketServer(unsigned int portNumber);

    ~SocketServer();

    int startServer(CallBack f);
};
