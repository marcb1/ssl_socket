#pragma once

//openssl headers
#include <openssl/bio.h>
#include <openssl/ssl.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/aes.h>
#include <openssl/md5.h>
#include <openssl/err.h>
#include <openssl/sha.h>

//unix headers
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <sys/ioctl.h>
#include <signal.h>
#include <assert.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <time.h>

//c++ headers
#include <string>
#include <iostream>
#include <fstream>
#include <sstream>
#include <algorithm>
#include <iterator>
#include <vector>
#include <thread>
#include <mutex>

//constants
const int MAX_READ = 100;

bool writeSSL(const std::string& data, SSL* sslHandle)
{
  if(data.size() <= 0)
  {
    std::cerr << "Request to write 0 bytes, ignoring" << std::endl;
    return false;
  }
  unsigned int ret = SSL_write(sslHandle, data.c_str(), data.length());
  assert(ret == data.length());
  return (ret > 0);
}

inline std::string string_to_hex(const std::string& input)
{
    static const char* const lut = "0123456789ABCDEF";
    size_t len = input.length();

    std::string output;
    output.reserve(2 * len);
    for (size_t i = 0; i < len; ++i)
    {
        const unsigned char c = input[i];
        output.push_back(lut[c >> 4]);
        output.push_back(lut[c & 15]);
    }
    return output;
}

std::string readSocket(SSL* sslHandle)
{
  // this is needed because the read is blocking, so we need to read everything in one chunk
  unsigned int maxRead = 1001;
  char readBuffer[maxRead];

  int readb = SSL_read(sslHandle, readBuffer, maxRead-1);
  if(readb <= 0)
  {
    std::cout << "Cannot read from socket; closing connection..." << std::endl;
    return std::string();
  }
  readBuffer[readb] = '\0';
  return std::string(readBuffer, readb);
}

//Open SSL wrapper functions
inline void loadOpenSSL()
{
  SSL_load_error_strings();
  SSL_library_init();
  OpenSSL_add_all_algorithms();
}

inline void unloadOpenSSL()
{
  ERR_free_strings();
  EVP_cleanup();
}

inline void deleteSSLStruct(SSL* ssl)
{
  SSL_shutdown(ssl);
  SSL_free(ssl);
}

inline void printErrno()
{
  printf("Errno()! %s\n", strerror(errno));
}
