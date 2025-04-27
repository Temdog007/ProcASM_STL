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

// Start Printing
int32_t printAscii(const char *string, int32_t length)
{
    return printf("%.*s\n", length, string);
}

size_t utf8Length(const uint8_t c)
{
    if (c < 0x80)
    {
        return 1; /* 0xxxxxxx */
    }
    else if ((c & 0xe0) == 0xc0)
    {
        return 2; /* 110xxxxx */
    }
    else if ((c & 0xf0) == 0xe0)
    {
        return 3; /* 1110xxxx */
    }
    else if ((c & 0xf8) == 0xf0 && (c <= 0xf4))
    {
        return 4; /* 11110xxx */
    }
    return 0; /* invalid UTF8 */
}

size_t convertUTF32toUTF8(uint8_t *const buffer, const unsigned int code)
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

size_t convertUTF32toUTF8List(void *ptr, size_t dstLength, const char32_t *src, size_t srcLength)
{
    char *dst = (char *)ptr;
    size_t j = 0;
    for (size_t i = 0; i < srcLength && j < dstLength; ++i)
    {
        char buffer[5];
        size_t len = convertUTF32toUTF8((uint8_t *)buffer, src[i]);
        if (len == 0)
        {
            return 0;
        }
        buffer[len] = '\0';
        len = snprintf(dst + j, dstLength - j, "%s", buffer);
        j += len;
    }
    return j;
}

size_t validUTF8(const uint8_t *c)
{
    const size_t len = utf8Length(c[0]);
    switch (len)
    {
    case 4:
        if ((c[3] & 0xc0) != 0x80)
        {
            break;
        }
        [[fallthrough]];
    case 3:
        if ((c[2] & 0xc0) != 0x80)
        {
            break;
        }
        [[fallthrough]];
    case 2:
        if ((c[1] & 0xc0) != 0x80)
        {
            break;
        }
        [[fallthrough]];
    case 1:
        return len; /* no trailing bytes to validate */
    default:
        break;
    }
    return 0; /* invalid utf8 */
}

char32_t convertUTF8toUTF32(const uint8_t *c, size_t *len)
{
    *len = validUTF8(c);
    switch (*len)
    {
    case 1:
        return *c;
    case 2:
        return ((c[0] & 0x1f) << 6) | (c[1] & 0x3f);
    case 3:
        return ((c[0] & 0x0f) << 12) | ((c[1] & 0x3f) << 6) | (c[2] & 0x3f);
    case 4:
        return ((c[0] & 0x07) << 18) | ((c[1] & 0x3f) << 12) | ((c[2] & 0x3f) << 6) | (c[3] & 0x3f);
    default:
        break;
    }
    return 0;
}

size_t convertUTF8toUTF32List(char32_t *dst, size_t dstLength, const void *ptr, size_t srcLength)
{
    const char *src = (const char *)ptr;
    size_t i = 0;
    for (size_t j = 0; i < dstLength && j < srcLength; ++i)
    {
        size_t len;
        const char32_t c = convertUTF8toUTF32((const uint8_t *)&src[j], &len);
        if (len == 0)
        {
            return 0;
        }
        dst[i] = c;
        j += len;
    }
    return i;
}

int32_t printUTF32(const char32_t *string, size_t length)
{
    int total = 0;
    for (size_t i = 0; i < length; ++i)
    {
        char buffer[5];
        const size_t size = convertUTF32toUTF8((uint8_t *)buffer, string[i]);
        buffer[size] = '\0';
        total += printf("%s", buffer);
    }
    total += puts("");
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

bool checkIfFileExists(const char *filename, size_t filenameLength)
{
    FILE *file = openFile(filename, filenameLength, "r");
    const bool fileExists = file != NULL;
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

static inline bool validSocket(SOCKET sockfd)
{
#if _WIN32
    return sockfd != INVALID_SOCKET;
#else
    return sockfd > 0;
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

    if (remove(addr.sun_path) == -1 && errno != ENOENT)
    {
        fprintf(stderr, "Failed to remove old domain file: %s\n", addr.sun_path);
        return NULL;
    }

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
            return NULL;
        }
    }
    else
    {
        if (bind(sockfd, (struct sockaddr *)&addr, sizeof(addr)) == -1)
        {
            perror("bind");
            return NULL;
        }

        if (listen(sockfd, 10) == -1)
        {
            perror("listen");
            return NULL;
        }
    }

    return (void *)((size_t)(sockfd));
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

bool sendAllThroughSocket(void *ptr, const void *output, size_t length)
{
    const char *buffer = (const char *)output;
    size_t sent = 0;
    while (sent < length)
    {
        const int result = sendThroughSocket(ptr, buffer + sent, length - sent);
        if (result < 0)
        {
            return false;
        }
        sent += result;
    }
    return true;
}

int32_t convertWebSocketKeyToAcceptKey(unsigned char *inputOutput, size_t length)
{
    unsigned char buffer[EVP_MAX_MD_SIZE];
    if (length >= sizeof(buffer))
    {
        return -1;
    }
    memcpy(buffer, inputOutput, length);

    EVP_MD_CTX *ctx = EVP_MD_CTX_create();
    const EVP_MD *md = EVP_sha1();
    EVP_DigestInit_ex(ctx, md, NULL);
    EVP_DigestUpdate(ctx, inputOutput, length);

    unsigned int len;
    EVP_DigestFinal_ex(ctx, buffer, &len);
    EVP_MD_CTX_destroy(ctx);
    EVP_cleanup();

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

// Start Other
int32_t readEnvironmentVariable(const char *key, size_t keyLength, char *buffer, size_t bufferLength)
{
    char actualKey[256];
    snprintf(actualKey, sizeof(actualKey), "%.*s", (int32_t)keyLength, key);

    const char *value = getenv(actualKey);
    if (value == NULL)
    {
        return 0;
    }
    return snprintf(buffer, bufferLength, "%s", value);
}

bool getTimeSinceEpooch(size_t *seconds, size_t *nanoseconds)
{
    struct timespec now;
    const int32_t result = timespec_get(&now, TIME_UTC);
    if (seconds != NULL)
    {
        *seconds = now.tv_sec;
    }
    if (nanoseconds != NULL)
    {
        *nanoseconds = now.tv_nsec;
    }
    return result != 0;
}

bool sleepInSecondsAndNanoseconds(size_t seconds, size_t nanoseconds)
{
    struct timespec ts;
    ts.tv_sec = seconds;
    ts.tv_nsec = nanoseconds;
    return nanosleep(&ts, NULL) == 0;
}

bool sleepInSeconds(size_t seconds)
{
    return sleepInSecondsAndNanoseconds(seconds, 0);
}

bool sleepInMilliseconds(size_t milliseconds)
{
    const size_t millisecondsInSeconds = 1000;
    const size_t nanoSecondsInMilliseconds = 1000000;
    return sleepInSecondsAndNanoseconds(milliseconds / millisecondsInSeconds,
                                        (milliseconds % millisecondsInSeconds) * nanoSecondsInMilliseconds);
}

bool sleepInMicroseconds(size_t microseconds)
{
    const size_t microSecondsInSeconds = 1000000;
    const size_t nanoSecondsInMicroSeconds = 1000;
    return sleepInSecondsAndNanoseconds(microseconds / microSecondsInSeconds,
                                        (microseconds % microSecondsInSeconds) * nanoSecondsInMicroSeconds);
}

static bool shouldExit = false;

#if _WIN32
BOOL WINAPI signal_callback_handler(_In_ DWORD ctrlType)
{
    switch (ctrlType)
    {
    case CTRL_C_EVENT:
        shouldExit = true;
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
        shouldExit = true;
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
        action.sa_handler = signal_callback_handler;
        sigemptyset(&action.sa_mask);
        action.sa_flags = 0;
        sigaction(SIGINT, &action, NULL);
        sigaction(SIGHUP, &action, NULL);
#endif
        signalHandlerSet = true;
    }

    return shouldExit;
}
// End Other

void seedRandomNumberGenerator()
{
    srand(time(NULL));
}

int32_t getRandomNumber()
{
    return rand();
}