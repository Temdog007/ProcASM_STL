#if _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>

#include <afunix.h>
#undef min
#undef max
#else
#include <unistd.h>

#include <arpa/inet.h>
#include <netdb.h>
#include <netinet/in.h>
#include <poll.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/un.h>
#endif

#include <stdlib.h>

#include "stl.h"

#if _WIN32
#define MSG_NOSIGNAL 0
#else
#define SOCKET int
#define INVALID_SOCKET (-1)
#endif

constexpr bool validSocket(SOCKET sockfd) noexcept
{
#if _WIN32
    return sockfd != INVALID_SOCKET;
#else
    return sockfd > 0;
#endif
}

#include <memory>

struct AddrInfoDeleter
{
    void operator()(struct addrinfo *ptr)
    {
        freeaddrinfo(ptr);
    }
};
using AddrInfo = std::unique_ptr<struct addrinfo, AddrInfoDeleter>;

inline void *get_in_addr(struct sockaddr *sa)
{
    if (sa->sa_family == AF_INET)
    {
        return &(((struct sockaddr_in *)sa)->sin_addr);
    }
    return &(((struct sockaddr_in6 *)sa)->sin6_addr);
}

inline void closeSocket(SOCKET sockfd)
{
    if (validSocket(sockfd))
    {
#if _WIN32
        closesocket(sockfd);
#else
        close(sockfd);
#endif
        printf("Closed socket: %d\n", sockfd);
    }
}

static inline void *openSocket(const char *ip, size_t length, uint16_t port, bool isClient)
{
    char ipAddress[256];
    snprintf(ipAddress, sizeof(ipAddress), "%.*s", static_cast<int32_t>(length), ip);

    char buffer[16];
    snprintf(buffer, sizeof(buffer), "%u", port);

    struct addrinfo hints;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_PASSIVE;

    struct addrinfo *servinfoPtr = nullptr;
    const int status = getaddrinfo(ipAddress, buffer, &hints, &servinfoPtr);
    if (status != 0)
    {
        fprintf(stderr, "getaddrinfo error: %s\n", gai_strerror(status));
        return nullptr;
    }

    AddrInfo servinfo(servinfoPtr);

    for (auto p = servinfo.get(); p != nullptr; p = p->ai_next)
    {
        SOCKET sockfd = socket(p->ai_family, p->ai_socktype, p->ai_protocol);
        if (!validSocket(sockfd))
        {
            perror("socket");
            goto cleanup;
        }
        if (isClient)
        {
            if (connect(sockfd, p->ai_addr, p->ai_addrlen) == -1)
            {
                perror("connect");
                goto cleanup;
            }
        }
        else
        {
            int yes = 1;
            if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(int)) == -1)
            {
                perror("setsockopt");
                goto cleanup;
            }
            if (bind(sockfd, p->ai_addr, p->ai_addrlen) == -1)
            {
                perror("bind");
                goto cleanup;
            }
            if (listen(sockfd, 10) == -1)
            {
                perror("listen");
                goto cleanup;
            }
        }
        return reinterpret_cast<void *>(static_cast<size_t>(sockfd));
    cleanup:
        closeSocket(sockfd);
    }

    fprintf(stderr, "Failed to find address info for %s:%u\n", ip, port);
    return nullptr;
}

void *openServer(const char *ip, size_t length, uint16_t port)
{
    return openSocket(ip, length, port, false);
}

void *openClient(const char *ip, size_t length, uint16_t port)
{
    return openSocket(ip, length, port, true);
}

inline bool socketReady(SOCKET sockfd, bool readFrom)
{
    const int flag = readFrom ? POLLIN : POLLOUT;
    struct pollfd pfd;
    pfd.fd = sockfd;
    pfd.events = flag;

#if _WIN32
    int events = WSAPoll(&pfd, 1, 0);
#else
    int events = poll(&pfd, 1, 0);
#endif
    return events > 0 && (pfd.revents & flag) != 0;
}

inline bool socketReadyToRead(SOCKET sockfd)
{
    return socketReady(sockfd, true);
}

void *acceptClient(void *ptr)
{
    size_t addr = reinterpret_cast<size_t>(ptr);
    SOCKET sockfd = static_cast<SOCKET>(addr);
    if (!socketReadyToRead(sockfd))
    {
        return nullptr;
    }
    struct sockaddr_storage theirAddr;
    socklen_t addr_size = sizeof(theirAddr);
    auto clientSocket = accept(sockfd, (struct sockaddr *)&theirAddr, &addr_size);
    if (!validSocket(clientSocket))
    {
        perror("accept");
        return nullptr;
    }
    return reinterpret_cast<void *>(static_cast<size_t>(clientSocket));
}

int32_t readFromSocket(void *ptr, char *buffer, size_t length)
{
    if (ptr == nullptr)
    {
        return -1;
    }
    size_t addr = reinterpret_cast<size_t>(ptr);
    SOCKET sockfd = static_cast<SOCKET>(addr);
    if (!socketReadyToRead(sockfd))
    {
        return 0;
    }
    auto bytesRead = recv(sockfd, buffer, length, 0);
    if (bytesRead < 0)
    {
        perror("recv");
    }
    return bytesRead;
}

inline bool socketReadyToWrite(SOCKET sockfd)
{
    return socketReady(sockfd, false);
}

int32_t sendThroughSocket(void *ptr, const char *buffer, size_t length)
{
    if (ptr == nullptr)
    {
        return -1;
    }
    size_t addr = reinterpret_cast<size_t>(ptr);
    SOCKET sockfd = static_cast<SOCKET>(addr);
    if (!socketReadyToWrite(sockfd))
    {
        return 0;
    }
    auto bytesSent = send(sockfd, buffer, length, MSG_NOSIGNAL);
    if (bytesSent < 0)
    {
        perror("send");
    }
    return bytesSent;
}

void closeSocket(void *ptr)
{
    if (ptr == nullptr)
    {
        return;
    }
    size_t addr = reinterpret_cast<size_t>(ptr);
    SOCKET sockfd = static_cast<SOCKET>(addr);
    closeSocket(sockfd);
}

int32_t readEnvironmentVariable(const char *key, char *buffer, size_t length)
{
    const char *value = getenv(key);
    return snprintf(buffer, length, "%s", value);
}