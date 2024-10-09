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
        openServer(const char *ip, size_t length, uint16_t port);
    API //#closeSocket
        void *
        openClient(const char *ip, size_t length, uint16_t port);
    API //#closeSocket
        void *
        acceptClient(void *);
    API void closeSocket(void *);

    /*
       return < 0: Error/Socket Closed
       return == 0: No Data
       return > 0: Number of bytes read
   */
    API int32_t readFromSocket(void *, char *, size_t);

    /*
          return < 0: Error/Socket Closed
          return >= 0: Number of bytes sent
      */
    API int32_t sendThroughSocket(void *, const char *, size_t);
    // End Network

    // Start Other
    API int32_t readEnvironmentVariable(const char *, char *, size_t);
    // End Other

#ifdef __cplusplus
}
#endif