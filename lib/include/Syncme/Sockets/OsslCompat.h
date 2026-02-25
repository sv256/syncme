#pragma once

// Windows headers define macros that conflict with OpenSSL/BoringSSL type and method names.
// Undef them before including <openssl/*.h>.
#if defined(_WIN32)
  #ifdef X509_NAME
    #undef X509_NAME
  #endif
  #ifdef X509_EXTENSIONS
    #undef X509_EXTENSIONS
  #endif
  #ifdef X509_CERT_PAIR
    #undef X509_CERT_PAIR
  #endif
  #ifdef X509_CERT
    #undef X509_CERT
  #endif
  #ifdef PKCS7
    #undef PKCS7
  #endif
  #ifdef PKCS7_SIGNER_INFO
    #undef PKCS7_SIGNER_INFO
  #endif
  #ifdef PKCS7_RECIP_INFO
    #undef PKCS7_RECIP_INFO
  #endif
  #ifdef PKCS7_ISSUER_AND_SERIAL
    #undef PKCS7_ISSUER_AND_SERIAL
  #endif
  #ifdef min
    #undef min
  #endif
  #ifdef max
    #undef max
  #endif
#endif
