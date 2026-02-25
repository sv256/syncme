#include <Syncme/Sockets/BIOHelpers.h>
#include <Syncme/Sockets/BIOSocket.h>

#if defined(USE_BORINGSSL) && !defined(BIO_CB_FREE)
// BoringSSL does not define BIO_CB_* constants used by OpenSSL.
// We only need them for human-readable diagnostics.
#define BIO_CB_FREE 0x01
#define BIO_CB_READ 0x02
#define BIO_CB_WRITE 0x03
#define BIO_CB_PUTS 0x04
#define BIO_CB_GETS 0x05
#define BIO_CB_CTRL 0x06
#define BIO_CB_RECVMMSG 0x07
#define BIO_CB_SENDMMSG 0x08
#endif

const char* Syncme::BIOperationName(int op)
{
  switch (op & 0xF)
  {
  case BIO_CB_FREE: return "FREE";
  case BIO_CB_READ: return "READ";
  case BIO_CB_WRITE: return "WRITE";
  case BIO_CB_PUTS: return "PUTS";
  case BIO_CB_GETS: return "GETS";
  case BIO_CB_CTRL: return "CTRL";
  case BIO_CB_RECVMMSG: return "RECVMMSG";
  case BIO_CB_SENDMMSG: return "SENDMMSG";
  default:
    break;
  }
  return "???";
}
