#include <stddef.h>
#include <stdint.h>
#include <uchar.h>

#if _WIN32
#define API __declspec(dllexport)
#else
#define API
#endif

#ifdef __cplusplus
extern "C"
{
#endif

    // Start Printing
    API int32_t printAscii(const char *, int32_t);
    API int32_t printUTF32(const char32_t *, size_t);
    // End Printing

    // Start Convert
    API size_t convertUTF32toUTF8(uint8_t *const buffer, const unsigned int code);
    API char32_t convertUTF8toUTF32(const uint8_t *, size_t *);
    API size_t validUTF8(const uint8_t *);
    API size_t utf8Length(uint8_t);
    API size_t convertUTF32toUTF8List(char *, size_t, const char32_t *, size_t);
    API size_t convertUTF8toUTF32List(char32_t *, size_t, const char *, size_t);
    // End Convert

    // Start File
    API int32_t checkIfFileExists(const char *filename, size_t filenameLength);
    API size_t readTextFile(const char *filename, size_t filenameLength, char *buffer, size_t);
    API size_t readBinaryFile(const char *filename, size_t filenameLength, uint8_t *buffer, size_t);
    API size_t writeTextFile(const char *filename, size_t filenameLength, const char *, size_t);
    API size_t writeBinaryFile(const char *filename, size_t filenameLength, const uint8_t *, size_t);
    API size_t appendTextToFile(const char *filename, size_t filenameLength, const char *, size_t);
    API size_t appendBinaryToFile(const char *filename, size_t filenameLength, const uint8_t *, size_t);
    // End File

    // Start Network
    API //#closeSocket
        void *
        openIpServer(const char *ip, size_t length, uint16_t port);

    API //#closeSocket
        void *
        openIpClient(const char *ip, size_t length, uint16_t port);

    API //#closeSocket
        void *
        openDomainServer(const char *ip, size_t length);

    API //#closeSocket
        void *
        openDomainClient(const char *ip, size_t length);

    API //#closeSocket
        void *
        acceptClient(void *);

    API void closeSocket(void *);

    API size_t getSocketInformation(void *, char *, size_t);

    /*
       return < 0: Error/Socket Closed
       return == 0: No Data
       return > 0: Number of bytes read
   */
    API int32_t readFromSocket(void *, void *, size_t);

    /*
          return < 0: Error/Socket Closed
          return >= 0: Number of bytes sent
      */
    API int32_t sendThroughSocket(void *, const void *, size_t);
    // End Network

    // Start Other
    API int32_t readEnvironmentVariable(const char *, size_t, char *, size_t);
    API int32_t getTimeSinceEpooch(size_t *seconds, size_t *nanoseconds);
    API int32_t sleepInSecondsAndNanoseconds(size_t, size_t);
    API int32_t sleepInSeconds(size_t);
    API int32_t sleepInMilliseconds(size_t);
    API int32_t sleepInMicroseconds(size_t);
    // End Other

#ifdef __cplusplus
}
#endif