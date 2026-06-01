#if _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>

#include <Windows.h>

#include <afunix.h>
#undef min
#undef max
#else
#define _GNU_SOURCE
#include <unistd.h>

#include <arpa/inet.h>
#include <errno.h>
#include <netdb.h>
#include <netinet/in.h>
#include <poll.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/un.h>
#endif

#include <stdbool.h>
#include <stdlib.h>
#include <time.h>

#include <openssl/evp.h>
#include <openssl/sha.h>

#include "stl.h"

// Start File
static inline FILE *openFile(const char *string, size_t length, const char *flags)
{
    if (length > 1024)
    {
        return NULL;
    }
    char filename[1024];
    snprintf(filename, sizeof(filename), "%.*s", (int32_t)(length), string);
    FILE *file = fopen(filename, flags);
    if (file == NULL)
    {
        perror("fopen");
        return NULL;
    }
    return file;
}

bool checkIfFileExists(const char *filename, size_t filenameLength)
{
    FILE *file = openFile(filename, filenameLength, "r");
    if (file == NULL)
    {
        return false;
    }
    else
    {
        fclose(file);
        return true;
    }
}

size_t readTextFile(const char *filename, size_t filenameLength, char *buffer, size_t length)
{
    FILE *file = openFile(filename, filenameLength, "r");
    if (file == NULL)
    {
        return 0;
    }
    const size_t bytesRead = fread(buffer, sizeof(char), length, file);
    fclose(file);
    return bytesRead;
}

size_t readBinaryFile(const char *filename, size_t filenameLength, uint8_t *buffer, size_t length)
{
    FILE *file = openFile(filename, filenameLength, "rb");
    if (file == NULL)
    {
        return 0;
    }
    const size_t bytesRead = fread(buffer, sizeof(char), length, file);
    fclose(file);
    return bytesRead;
}

size_t writeTextFile(const char *filename, size_t filenameLength, const char *buffer, size_t length)
{
    FILE *file = openFile(filename, filenameLength, "w");
    if (file == NULL)
    {
        return 0;
    }
    const size_t bytesWritten = fwrite(buffer, sizeof(char), length, file);
    fclose(file);
    return bytesWritten;
}

size_t writeBinaryFile(const char *filename, size_t filenameLength, const uint8_t *buffer, size_t length)
{
    FILE *file = openFile(filename, filenameLength, "wb");
    if (file == NULL)
    {
        return 0;
    }
    const size_t bytesWritten = fwrite(buffer, sizeof(char), length, file);
    fclose(file);
    return bytesWritten;
}

size_t appendTextToFile(const char *filename, size_t filenameLength, const char *buffer, size_t length)
{
    FILE *file = openFile(filename, filenameLength, "a");
    if (file == NULL)
    {
        return 0;
    }
    const size_t bytesWritten = fwrite(buffer, sizeof(char), length, file);
    fclose(file);
    return bytesWritten;
}

size_t appendBinaryToFile(const char *filename, size_t filenameLength, const uint8_t *buffer, size_t length)
{
    FILE *file = openFile(filename, filenameLength, "ab");
    if (file == NULL)
    {
        return 0;
    }
    const size_t bytesWritten = fwrite(buffer, sizeof(char), length, file);
    fclose(file);
    return bytesWritten;
}
// End File

// Start Networking
#if _WIN32
#define MSG_NOSIGNAL 0
#else
#define SOCKET int
#define INVALID_SOCKET (-1)
#endif

static inline bool validSocket(SOCKET sockfd)
{
#if _WIN32
    return sockfd != INVALID_SOCKET;
#else
    return sockfd >= 0;
#endif
}

static inline void *get_in_addr(struct sockaddr *sa)
{
    if (sa->sa_family == AF_INET)
    {
        return &(((struct sockaddr_in *)sa)->sin_addr);
    }
    return &(((struct sockaddr_in6 *)sa)->sin6_addr);
}

size_t getIpString(const struct sockaddr *sa, char *s, size_t length)
{
    switch (sa->sa_family)
    {
    case AF_INET:
        inet_ntop(AF_INET, &(((struct sockaddr_in *)sa)->sin_addr), s, length);
        break;
    case AF_INET6:
        inet_ntop(AF_INET6, &(((struct sockaddr_in6 *)sa)->sin6_addr), s, length);
        break;
    default:
        return snprintf(s, length, "Unknown AF");
    }
    return strlen(s);
}

size_t getSocket(SOCKET sockfd, char *buffer, size_t length)
{
    struct sockaddr_storage addr;
    memset(&addr, 0, sizeof(addr));
    socklen_t len = sizeof(addr);
    if (getpeername(sockfd, (struct sockaddr *)&addr, &len) == -1)
    {
        perror("getpeername");
        return snprintf(buffer, length, "Unknown Socket");
    }

    return getIpString((struct sockaddr *)&addr, buffer, length);
}

static inline size_t printSocket(SOCKET sockfd, const char *message)
{
    char buffer[256];
    size_t read = 0;
    if (message != NULL)
    {
        read += snprintf(buffer, sizeof(buffer), "%s ", message);
    }
    read += snprintf(buffer + read, sizeof(buffer) - read, "socket (%d) ", sockfd);
    getSocket(sockfd, buffer + read, sizeof(buffer) - read);
    return printf("%s \n", buffer);
}

size_t getSocketInformation(void *ptr, char *buffer, size_t length)
{
    size_t addr = (size_t)(ptr);
    SOCKET sockfd = (SOCKET)(addr);
    return getSocket(sockfd, buffer, length);
}

static inline void closeActualSocket(SOCKET sockfd)
{
    if (validSocket(sockfd))
    {
#if NDEBUG
#else
        printSocket(sockfd, "Closing");
#endif
#if _WIN32
        closesocket(sockfd);
#else
        close(sockfd);
#endif
    }
}

static inline void *openIpSocket(const char *ip, size_t length, uint16_t port, bool isClient)
{
    char ipAddress[256];
    snprintf(ipAddress, sizeof(ipAddress), "%.*s", (int32_t)(length), ip);

    char buffer[16];
    snprintf(buffer, sizeof(buffer), "%u", port);

    struct addrinfo hints;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_PASSIVE;

    struct addrinfo *addressInfo = NULL;
    const int status = getaddrinfo(ipAddress, buffer, &hints, &addressInfo);
    if (status != 0)
    {
        fprintf(stderr, "getaddrinfo error: %s\n", gai_strerror(status));
        return NULL;
    }

    void *newSocket = NULL;

    for (struct addrinfo *p = addressInfo; p != NULL; p = p->ai_next)
    {
        SOCKET sockfd = socket(p->ai_family, p->ai_socktype, p->ai_protocol);
        if (!validSocket(sockfd))
        {
            perror("socket");
            continue;
        }
        if (isClient)
        {
            if (connect(sockfd, p->ai_addr, p->ai_addrlen) == -1)
            {
                perror("connect");
                goto cleanup;
            }
            printSocket(sockfd, "Opening");
        }
        else
        {
#if _WIN32
            char yes = 1;
#else
            int yes = 1;
#endif
            if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes)) == -1)
            {
                perror("setsockopt");
                goto cleanup;
            }
            if (bind(sockfd, p->ai_addr, p->ai_addrlen) == -1)
            {
                perror("bind");
                goto cleanup;
            }
            if (listen(sockfd, 128) == -1)
            {
                perror("listen");
                goto cleanup;
            }
            printf("Opening server (%d)\n", sockfd);
        }
        newSocket = (void *)((size_t)(sockfd));
        goto end;
    cleanup:
        closeActualSocket(sockfd);
    }

    fprintf(stderr, "Failed to find address info for %s:%u\n", ipAddress, port);
end:
    freeaddrinfo(addressInfo);
    return newSocket;
}

void *openIpServer(const char *ip, size_t length, uint16_t port)
{
    return openIpSocket(ip, length, port, false);
}

void *openIpClient(const char *ip, size_t length, uint16_t port)
{
    return openIpSocket(ip, length, port, true);
}

static inline void *openDomainSocket(const char *ip, size_t length, bool isClient)
{
    struct sockaddr_un addr;
    memset(&addr, 0, sizeof(addr));

    if (length > sizeof(addr.sun_path) - 1)
    {
        fprintf(stderr, "Domain address is too long (%zu)\n", length);
        return NULL;
    }

    addr.sun_family = AF_UNIX;
    snprintf(addr.sun_path, sizeof(addr.sun_path), "%.*s", (int32_t)(length), ip);

    SOCKET sockfd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (!validSocket(sockfd))
    {
        perror("socket");
        return NULL;
    }

    if (isClient)
    {
        if (connect(sockfd, (struct sockaddr *)&addr, sizeof(addr)) == -1)
        {
            perror("client: connect");
            goto error;
        }
    }
    else
    {
        if (remove(addr.sun_path) == -1 && errno != ENOENT)
        {
            fprintf(stderr, "Failed to remove old domain file: %s\n", addr.sun_path);
            goto error;
        }

        if (bind(sockfd, (struct sockaddr *)&addr, sizeof(addr)) == -1)
        {
            perror("bind");
            goto error;
        }

        if (listen(sockfd, 10) == -1)
        {
            perror("listen");
            goto error;
        }
    }

    return (void *)((size_t)(sockfd));

error:
    closeActualSocket(sockfd);
    return NULL;
}

void *openDomainServer(const char *ip, size_t length)
{
    return openDomainSocket(ip, length, false);
}

void *openDomainClient(const char *ip, size_t length)
{
    return openDomainSocket(ip, length, true);
}

enum SocketState
{
    SocketState_NotReady,
    SocketState_Ready,
    SocketState_Error,
};

static inline enum SocketState socketReady(SOCKET sockfd, size_t timeout, int flag)
{
#if _WIN32
    const int errors = 0;
#else
    const int errors = POLLERR | POLLNVAL | POLLPRI | POLLHUP | POLLRDHUP;
#endif

    struct pollfd pfd;
    memset(&pfd, 0, sizeof(pfd));
    pfd.fd = sockfd;
    pfd.events = flag | errors;

#if _WIN32
    const int events = WSAPoll(&pfd, 1, timeout);
#else
    const int events = poll(&pfd, 1, timeout);
#endif

    if (events < 0)
    {
#if _WIN32
        char buffer[1024];
        FormatMessageA(FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS, NULL, GetLastError(),
                       MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), buffer, sizeof(buffer), NULL);
        fprintf(stderr, "Poll Error: %s\n", buffer);
#else
        fprintf(stderr, "Poll Error: %s\n", strerror(errno));
#endif
        return SocketState_Error;
    }
    if (events == 0)
    {
        return SocketState_NotReady;
    }

    if ((pfd.revents & errors) != 0)
    {
        return SocketState_Error;
    }
    if ((pfd.revents & flag) != 0)
    {
        return SocketState_Ready;
    }
    return SocketState_NotReady;
}

static inline enum SocketState socketReadyToRead(SOCKET sockfd, size_t timeout)
{
    return socketReady(sockfd, timeout, POLLIN);
}

bool socketIsOpen(void *ptr)
{
    size_t addr = (size_t)(ptr);
    SOCKET sockfd = (SOCKET)(addr);
    return socketReady(sockfd, 0, 0) != SocketState_Error;
}

void *acceptClient(void *ptr, size_t timeout)
{
    size_t addr = (size_t)(ptr);
    SOCKET sockfd = (SOCKET)(addr);
    switch (socketReadyToRead(sockfd, timeout))
    {
    case SocketState_Ready:
        break;
    default:
        return NULL;
    }
    struct sockaddr_storage theirAddr;
    socklen_t addr_size = sizeof(theirAddr);

    SOCKET clientSocket = accept(sockfd, (struct sockaddr *)&theirAddr, &addr_size);
    if (!validSocket(clientSocket))
    {
        perror("accept");
        return NULL;
    }
    char buffer[INET6_ADDRSTRLEN];
    inet_ntop(theirAddr.ss_family, get_in_addr((struct sockaddr *)&theirAddr), buffer, sizeof(buffer));
#if NDEBUG
#else
    printf("Accepted client: %s (%d)\n", buffer, clientSocket);
#endif
    return (void *)((size_t)(clientSocket));
}

int32_t readFromSocket(void *ptr, void *buffer, size_t length)
{
    if (ptr == NULL)
    {
        return -1;
    }
    if (length == 0)
    {
        return 0;
    }
    size_t addr = (size_t)(ptr);
    SOCKET sockfd = (SOCKET)(addr);
    switch (socketReadyToRead(sockfd, 0))
    {
    case SocketState_Ready:
        break;
    case SocketState_NotReady:
        return 0;
    default:
        return -1;
    }
    const int32_t bytesRead = recv(sockfd, buffer, length, 0);
    if (bytesRead < 0)
    {
        perror("recv");
    }
    return bytesRead;
}

static inline enum SocketState socketReadyToWrite(SOCKET sockfd)
{
    return socketReady(sockfd, 0, POLLOUT);
}

int32_t sendThroughSocket(void *ptr, const void *buffer, size_t length)
{
    if (ptr == NULL)
    {
        fputs("Passed NULL to sendThroughSocket\n", stderr);
        return -1;
    }
    size_t addr = (size_t)(ptr);
    SOCKET sockfd = (SOCKET)(addr);
    switch (socketReadyToWrite(sockfd))
    {
    case SocketState_Ready:
        break;
    case SocketState_NotReady:
        return 0;
    default:
        return -1;
    }
    const int32_t bytesSent = send(sockfd, buffer, length, MSG_NOSIGNAL);
    if (bytesSent < 0)
    {
        perror("send");
    }
    return bytesSent;
}

int32_t convertWebSocketKeyToAcceptKey(unsigned char *inputOutput, size_t length)
{
    unsigned char buffer[EVP_MAX_MD_SIZE];
    if (length >= sizeof(buffer))
    {
        return -1;
    }

    EVP_MD_CTX *ctx = EVP_MD_CTX_create();
    const EVP_MD *md = EVP_sha1();
    EVP_DigestInit_ex(ctx, md, NULL);
    EVP_DigestUpdate(ctx, inputOutput, length);

    unsigned int len;
    EVP_DigestFinal_ex(ctx, buffer, &len);
    EVP_MD_CTX_destroy(ctx);

    return EVP_EncodeBlock(inputOutput, buffer, len);
}

void closeSocket(void *ptr)
{
    if (ptr == NULL)
    {
        return;
    }
    size_t addr = (size_t)(ptr);
    SOCKET sockfd = (SOCKET)(addr);
    closeActualSocket(sockfd);
}
// End Network

static volatile sig_atomic_t shouldExit = 0;

#if _WIN32
BOOL WINAPI signal_callback_handler(_In_ DWORD ctrlType)
{
    switch (ctrlType)
    {
    case CTRL_C_EVENT:
        shouldExit = 1;
        return TRUE;
    default:
        break;
    }
    return FALSE;
}
#else
void signal_callback_handler(int signalNumber)
{
    switch (signalNumber)
    {
    case SIGINT:
    case SIGHUP:
        shouldExit = 1;
        break;
    default:
        break;
    }
}
#endif

bool applicationShouldExit()
{
    static bool signalHandlerSet = false;
    if (!signalHandlerSet)
    {
#if _WIN32
        SetConsoleCtrlHandler(signal_callback_handler, TRUE);
#else
        struct sigaction action;
        memset(&action, 0, sizeof(struct sigaction));
        action.sa_handler = signal_callback_handler;
        sigemptyset(&action.sa_mask);
        action.sa_flags = 0;
        sigaction(SIGINT, &action, NULL);
        sigaction(SIGHUP, &action, NULL);
#endif
        signalHandlerSet = true;
    }

    return shouldExit != 0;
}

void seedRandomNumberGenerator()
{
    srand(time(NULL));
}

int32_t getRandomNumber()
{
    return rand();
}