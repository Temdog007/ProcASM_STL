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

#include <stdbool.h>
#include <stdlib.h>
#include <time.h>

#include "stl.h"

// Start Printing
int32_t printAscii(const char *string, int32_t length)
{
    return printf("%.*s\n", length, string);
}

static inline size_t ProcASM_utf32_to_utf8(uint8_t *const buffer, const unsigned int code)
{
    if (code <= 0x7F)
    {
        buffer[0] = code;
        return 1;
    }
    if (code <= 0x7FF)
    {
        buffer[0] = 0xC0 | (code >> 6);   /* 110xxxxx */
        buffer[1] = 0x80 | (code & 0x3F); /* 10xxxxxx */
        return 2;
    }
    if (code <= 0xFFFF)
    {
        buffer[0] = 0xE0 | (code >> 12);         /* 1110xxxx */
        buffer[1] = 0x80 | ((code >> 6) & 0x3F); /* 10xxxxxx */
        buffer[2] = 0x80 | (code & 0x3F);        /* 10xxxxxx */
        return 3;
    }
    if (code <= 0x10FFFF)
    {
        buffer[0] = 0xF0 | (code >> 18);          /* 11110xxx */
        buffer[1] = 0x80 | ((code >> 12) & 0x3F); /* 10xxxxxx */
        buffer[2] = 0x80 | ((code >> 6) & 0x3F);  /* 10xxxxxx */
        buffer[3] = 0x80 | (code & 0x3F);         /* 10xxxxxx */
        return 4;
    }
    return 0;
}

int32_t printUTF32(const char32_t *string, size_t length)
{
    int total = 0;
    for (size_t i = 0; i < length; ++i)
    {
        char buffer[5];
        const size_t size = ProcASM_utf32_to_utf8((uint8_t *)buffer, string[i]);
        buffer[size] = '\0';
        total += printf("%s", buffer);
    }
    return total;
}
// End Printing

// Start File
static inline FILE *openFile(const char *string, size_t length, const char *flags)
{
    char filename[256];
    snprintf(filename, sizeof(filename), "%.*s", (int32_t)(length), string);
    FILE *file = fopen(filename, flags);
    if (file == NULL)
    {
        perror("fopen");
        return NULL;
    }
    return file;
}

int32_t checkIfFileExists(const char *filename, size_t filenameLength)
{
    FILE *file = openFile(filename, filenameLength, "r");
    const int32_t fileExists = file != NULL;
    fclose(file);
    return fileExists;
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
    FILE *file = openFile(filename, filenameLength, "w+");
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
    FILE *file = openFile(filename, filenameLength, "wb+");
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

inline bool validSocket(SOCKET sockfd)
{
#if _WIN32
    return sockfd != INVALID_SOCKET;
#else
    return sockfd > 0;
#endif
}

inline void *get_in_addr(struct sockaddr *sa)
{
    if (sa->sa_family == AF_INET)
    {
        return &(((struct sockaddr_in *)sa)->sin_addr);
    }
    return &(((struct sockaddr_in6 *)sa)->sin6_addr);
}

inline void closeActualSocket(SOCKET sockfd)
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
            if (listen(sockfd, 10) == -1)
            {
                perror("listen");
                goto cleanup;
            }
        }
        newSocket = (void *)((size_t)(sockfd));
        break;
    cleanup:
        closeActualSocket(sockfd);
    }

    freeaddrinfo(addressInfo);
    fprintf(stderr, "Failed to find address info for %s:%u\n", ip, port);
    return newSocket;
}

void *openServer(const char *ip, size_t length, uint16_t port)
{
    return openSocket(ip, length, port, false);
}

void *openClient(const char *ip, size_t length, uint16_t port)
{
    return openSocket(ip, length, port, true);
}

inline bool socketReady(SOCKET sockfd, int flag)
{
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
    return socketReady(sockfd, POLLIN);
}

void *acceptClient(void *ptr)
{
    size_t addr = (size_t)(ptr);
    SOCKET sockfd = (SOCKET)(addr);
    if (!socketReadyToRead(sockfd))
    {
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
    return (void *)((size_t)(clientSocket));
}

int32_t readFromSocket(void *ptr, char *buffer, size_t length)
{
    if (ptr == NULL)
    {
        return -1;
    }
    size_t addr = (size_t)(ptr);
    SOCKET sockfd = (SOCKET)(addr);
    if (!socketReadyToRead(sockfd))
    {
        return 0;
    }
    int32_t bytesRead = recv(sockfd, buffer, length, 0);
    if (bytesRead < 0)
    {
        perror("recv");
    }
    return bytesRead;
}

inline bool socketReadyToWrite(SOCKET sockfd)
{
    return socketReady(sockfd, POLLOUT);
}

int32_t sendThroughSocket(void *ptr, const char *buffer, size_t length)
{
    if (ptr == NULL)
    {
        return -1;
    }
    size_t addr = (size_t)(ptr);
    SOCKET sockfd = (SOCKET)(addr);
    if (!socketReadyToWrite(sockfd))
    {
        return 0;
    }
    int32_t bytesSent = send(sockfd, buffer, length, MSG_NOSIGNAL);
    if (bytesSent < 0)
    {
        perror("send");
    }
    return bytesSent;
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

// Start Other
int32_t readEnvironmentVariable(const char *key, char *buffer, size_t length)
{
    const char *value = getenv(key);
    return snprintf(buffer, length, "%s", value);
}
int32_t getTimeSinceEpooch(size_t *seconds, size_t *nanoseconds)
{
    struct timespec now;
    const int32_t result = timespec_get(&now, TIME_UTC);
    *seconds = now.tv_sec;
    *nanoseconds = now.tv_nsec;
    return result;
}
int32_t sleepInSecondsAndNanoseconds(size_t seconds, size_t nanoseconds)
{
    struct timespec ts;
    ts.tv_sec = seconds;
    ts.tv_nsec = nanoseconds;
    return nanosleep(&ts, NULL);
}
int32_t sleepInSeconds(size_t seconds)
{
    return sleepInSecondsAndNanoseconds(seconds, 0);
}
int32_t sleepInMilliseconds(size_t milliseconds)
{
    const size_t millisecondsInSeconds = 1000;
    return sleepInSecondsAndNanoseconds(milliseconds / millisecondsInSeconds,
                                        (milliseconds % millisecondsInSeconds) * 100000);
}
int32_t sleepInMicroseconds(size_t microseconds)
{
    const size_t microSecondsInSeconds = 100000;
    return sleepInSecondsAndNanoseconds(microseconds / microSecondsInSeconds,
                                        (microseconds % microSecondsInSeconds) * 1000);
}
// End Other