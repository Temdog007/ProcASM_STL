#include <stdbool.h>
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

    // -> Start Printing

    // buffer: list of ASCII characters
    // length: number of ASCII characters in list
    // return: number of ASCII characters printed
    API int32_t printAscii(const char *buffer, int32_t length);

    // buffer: list of ASCII characters
    // length: number of ASCII characters in list
    // return: number of UTF32 characters printed
    API int32_t printUTF32(const char32_t *buffer, size_t length);
    // <- End Printing

    // -> Start Convert

    // buffer: the resulting UTF8 character converted from the UTF32 character
    // code: the UTF32 character
    // return: size of the converted UTF8 character
    API size_t convertUTF32toUTF8(uint8_t *const buffer, const unsigned int code);

    // buffer: the UTF8 character
    // length: output parameter; the size of the UTF8 character
    // return: the UTF32 character converted from the UTF8 character
    API char32_t convertUTF8toUTF32(const uint8_t *buffer, size_t *length);

    // buffer: the UTF8 character
    // return: the size of the UTF8 character
    API size_t validUTF8(const uint8_t *buffer);

    // buffer: the UTF8 character
    // return: the size of the UTF8 character
    API size_t utf8Length(uint8_t character);

    // output: the UTF8 buffer to contain the conversion from UTF32
    // outputLength: the number of bytes in output
    // input: list of UTF32 characters to convert
    // inputLength: number of UTF32 characters to convert
    // return: the number of bytes written in output
    API size_t convertUTF32toUTF8List(void *output, size_t outputLength, const char32_t *input, size_t inputLength);

    // output: the UTF32 buffer to contain the conversion from UTF8
    // outputLength: the number of UTF32 characters in output
    // input: list of UTF8 characters to convert
    // inputLength: number of bytes in input
    // return: the number of UTF32 characters written in output
    API size_t convertUTF8toUTF32List(char32_t *output, size_t outputLength, const void *input, size_t inputLength);
    // <- End Convert

    // -> Start File

    // filename: list of characters representing the filename
    // filenameLength: the number of bytes in the filename
    // return: True if the file exists
    API bool checkIfFileExists(const char *filename, size_t filenameLength);

    // filename: list of characters representing the filename
    // filenameLength: the number of bytes in the filename
    // buffer: the buffer to contain the contents the of the file
    // length: number of characters in buffer
    // return: the number of characters written to buffer
    API size_t readTextFile(const char *filename, size_t filenameLength, char *buffer, size_t length);

    // filename: list of characters representing the filename
    // filenameLength: the number of bytes in the filename
    // buffer: the buffer to contain the contents the of the file
    // length: number of bytes in buffer
    // return: the number of bytes written to buffer
    API size_t readBinaryFile(const char *filename, size_t filenameLength, uint8_t *buffer, size_t length);

    // filename: list of characters representing the filename
    // filenameLength: the number of bytes in the filename
    // buffer: the buffer that contains the contents to write to the file
    // length: number of bytes in buffer
    // return: the number of bytes written to the file
    API size_t writeTextFile(const char *filename, size_t filenameLength, const char *buffer, size_t length);

    // filename: list of characters representing the filename
    // filenameLength: the number of bytes in the filename
    // buffer: the buffer that contains the contents to write to the file
    // length: number of bytes in buffer
    // return: the number of bytes written to the file
    API size_t writeBinaryFile(const char *filename, size_t filenameLength, const uint8_t *buffer, size_t length);

    // filename: list of characters representing the filename
    // filenameLength: the number of bytes in the filename
    // buffer: the buffer that contains the contents to write to the file
    // length: number of bytes in buffer
    // return: the number of bytes appended to the file
    API size_t appendTextToFile(const char *filename, size_t filenameLength, const char *buffer, size_t length);

    // filename: list of characters representing the filename
    // filenameLength: the number of bytes in the filename
    // buffer: the buffer that contains the contents to write to the file
    // length: number of bytes in buffer
    // return: the number of bytes appended to the file
    API size_t appendBinaryToFile(const char *filename, size_t filenameLength, const uint8_t *, size_t);
    // <- End File

    // -> Start Network

    // ip: the IP Address
    // length: the number of characters in ip
    // port: the port
    // return: the newly created socket
    API //#closeSocket
        void *
        openIpServer(const char *ip, size_t length, uint16_t port);

    // ip: the IP Address
    // length: the number of characters in ip
    // port: the port
    // return: the newly created socket
    API //#closeSocket
        void *
        openIpClient(const char *ip, size_t length, uint16_t port);

    // ip: the IP Address
    // length: the number of characters in ip
    // return: the newly created socket
    API //#closeSocket
        void *
        openDomainServer(const char *ip, size_t length);

    // ip: the IP Address
    // length: the number of characters in ip
    // return: the newly created socket
    API //#closeSocket
        void *
        openDomainClient(const char *ip, size_t length);

    // socket: the socket
    // return: true if the socket is NOT closed
    API bool socketIsOpen(void *socket);

    // socket: the server socket
    // timeoutInMilliseconds: the length to wait for a new client in milliseconds
    // return: the newly created socket for the connected client
    API //#closeSocket
        void *
        acceptClient(void *server, size_t timeoutInMilliseconds);

    // socket: the socket to close
    API void closeSocket(void *socket);

    // socket: the socket to get information from
    // buffer: the buffer that contains the socket's information
    // length: the number of characters in buffer
    // return: the number of characters written to buffer
    API size_t getSocketInformation(void *socket, char *buffer, size_t length);

    // socket: the socket to read data from
    // buffer: the buffer that contains to data read from the socket
    // length: the number of bytes in buffer
    /*
       return < 0: Error/Socket Closed
       return == 0: No Data
       return > 0: Number of bytes read
   */
    API int32_t readFromSocket(void *socket, void *buffer, size_t length);

    // socket: the socket to send data to
    // buffer: the buffer that contains the data to write to the socket
    // length: the number of bytes in buffer
    /*
          return < 0: Error/Socket Closed
          return >= 0: Number of bytes sent
    */
    API int32_t sendThroughSocket(void *socket, const void *buffer, size_t length);

    // socket: the socket to send data to
    // buffer: the buffer that contains the data to write to the socket
    // length: the number of bytes in buffer
    // return: True if all data was sent without an error
    API bool sendAllThroughSocket(void *socket, const void *buffer, size_t length);

    /*
        buffer: the buffer that contains the client's Sec-WebSocket-Key concatenated
                with the magic string '258EAFA5-E914-47DA-95CA-C5AB0DC85B11'
    */
    // length: the number of characters in buffer
    // return: The number of characters written to buffer
    API int32_t convertWebSocketKeyToAcceptKey(unsigned char *buffer, size_t length);
    // <- End Network

    // -> Start Random
    API void seedRandomNumberGenerator();

    // return: a random integer between 0 and INT_MAX
    API int32_t getRandomNumber();
    // <-> End Random

    // -> Start Other

    // key: the environment variable's key
    // keyLength: the number of characters in key
    // buffer: the buffer to contain the environment variable's value
    // bufferLength: the number of characters in buffer
    // return: the number of characters written to buffer
    API int32_t readEnvironmentVariable(const char *key, size_t keyLength, char *buffer, size_t bufferLength);

    // seconds: output parameter; the seconds porition of the timstamp
    // nanoseconds: output parameter; the nanoseconds porition of the timstamp
    // return: True if the timestamp was acquired
    API bool getTimeSinceEpooch(size_t *seconds, size_t *nanoseconds);

    // seconds: the number of seconds to wait
    // nanoseconds: the number of nanoseconds to wait
    // return: True if waited the specified duration
    API bool sleepInSecondsAndNanoseconds(size_t seconds, size_t nanoseconds);

    // seconds: the number of seconds to wait
    // return: True if waited the specified duration
    API bool sleepInSeconds(size_t seconds);

    // milliseconds: the number of seconds to wait
    // return: True if waited the specified duration
    API bool sleepInMilliseconds(size_t milliseconds);

    // microseconds: the number of seconds to wait
    // return: True if waited the specified duration
    API bool sleepInMicroseconds(size_t microseconds);

    // return: True if a signal to close the application was received
    API bool applicationShouldExit();
    // <- End Other

#ifdef __cplusplus
}
#endif