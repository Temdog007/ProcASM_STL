#include <stddef.h>
#include <stdint.h>

#if _WIN32
#define API __declspec(dllexport)
#else
#define API
#endif

#ifdef __cplusplus
extern "C"
{
#endif
    API //#closeSocket
        void *
        openServer(const char *ip, size_t length, uint16_t port);

    API //#closeSocket
        void *
        openClient(const char *ip, size_t length, uint16_t port);

    API //#closeSocket
        void *
        acceptClient(void *);

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

    API void closeSocket(void *);

    API int32_t readEnvironmentVariable(const char *, char *, size_t);

#ifdef __cplusplus
}
#endif