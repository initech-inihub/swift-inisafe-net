#ifndef HEADER_PKCS11_H
#define HEADER_PKCS11_H

#ifdef NO_PKI
#error PKI is disabled.
#endif

#include <inicrypto/foundation.h>
#include "asn1.h"

/************************************************************************/
/*
	#include "PKCS11/cryptoki.h"
	darpangs
*/
/************************************************************************/
/* cryptoki.h include file for PKCS #11. */
/* $Revision: 1.4 $ */

#ifndef ___CRYPTOKI_H_INC___
#define ___CRYPTOKI_H_INC___

#ifdef WIN32
#pragma pack(push, cryptoki, 1)
#endif

/* Specifies that the function is a DLL entry point. */
#ifdef WIN32
#define CK_IMPORT_SPEC __declspec(dllimport)
#else
#define CK_IMPORT_SPEC
#endif

/* Define CRYPTOKI_EXPORTS during the build of cryptoki libraries. Do
* not define it in applications.
*/
#ifdef CRYPTOKI_EXPORTS
/* Specified that the function is an exported DLL entry point. */
#define CK_EXPORT_SPEC __declspec(dllexport)
#else
#define CK_EXPORT_SPEC CK_IMPORT_SPEC
#endif

/* Ensures the calling convention for Win32 builds */
#ifdef WIN32
#define CK_CALL_SPEC __cdecl
#else
#define CK_CALL_SPEC
#endif

#define CK_PTR *

#define CK_DEFINE_FUNCTION(returnType, name) \
	returnType CK_EXPORT_SPEC CK_CALL_SPEC name

#define CK_DECLARE_FUNCTION(returnType, name) \
	returnType CK_EXPORT_SPEC CK_CALL_SPEC name

#define CK_DECLARE_FUNCTION_POINTER(returnType, name) \
	returnType CK_IMPORT_SPEC (CK_CALL_SPEC CK_PTR name)

#define CK_CALLBACK_FUNCTION(returnType, name) \
	returnType (CK_CALL_SPEC CK_PTR name)

#ifndef NULL_PTR
#define NULL_PTR 0
#endif
/************************************************************************/
/*
	#include "pkcs11.h"
	darpangs
*/
/************************************************************************/
/* pkcs11.h include file for PKCS #11. */
/* $Revision: 1.4 $ */

#ifndef _PKCS11_H_
#define _PKCS11_H_ 1

#ifdef __cplusplus
extern "C" {
#endif

	/* All the various Cryptoki types and #define'd values are in the
	* file pkcs11t.h. */
/************************************************************************/
/*
	#include "pkcs11t.h"
	darpangs
*/
/************************************************************************/
/* pkcs11t.h include file for PKCS #11. */
/* $Revision: 1.10 $ */

/* See top of pkcs11.h for information about the macros that
* must be defined and the structure-packing conventions that
* must be set before including this file. */

#ifndef _PKCS11T_H_
#define _PKCS11T_H_ 1

#define CRYPTOKI_VERSION_MAJOR 2
#define CRYPTOKI_VERSION_MINOR 20
#define CRYPTOKI_VERSION_AMENDMENT 3

#define CK_TRUE 1
#define CK_FALSE 0

#ifndef CK_DISABLE_TRUE_FALSE
#ifndef FALSE
#define FALSE CK_FALSE
#endif

#ifndef TRUE
#define TRUE CK_TRUE
#endif
#endif

/* an unsigned 8-bit value */
typedef unsigned char     CK_BYTE;

/* an unsigned 8-bit character */
typedef CK_BYTE           CK_CHAR;

/* an 8-bit UTF-8 character */
typedef CK_BYTE           CK_UTF8CHAR;

/* a BYTE-sized Boolean flag */
typedef CK_BYTE           CK_BBOOL;

/* an unsigned value, at least 32 bits long */
typedef unsigned long int CK_ULONG;

/* a signed value, the same size as a CK_ULONG */
/* CK_LONG is new for v2.0 */
typedef long int          CK_LONG;

/* at least 32 bits; each bit is a Boolean flag */
typedef CK_ULONG          CK_FLAGS;


/* some special values for certain CK_ULONG variables */
#define CK_UNAVAILABLE_INFORMATION (~0UL)
#define CK_EFFECTIVELY_INFINITE    0


typedef CK_BYTE     CK_PTR   CK_BYTE_PTR;
typedef CK_CHAR     CK_PTR   CK_CHAR_PTR;
typedef CK_UTF8CHAR CK_PTR   CK_UTF8CHAR_PTR;
typedef CK_ULONG    CK_PTR   CK_ULONG_PTR;
typedef void        CK_PTR   CK_VOID_PTR;

/* Pointer to a CK_VOID_PTR-- i.e., pointer to pointer to void */
typedef CK_VOID_PTR CK_PTR CK_VOID_PTR_PTR;


/* The following value is always invalid if used as a session */
/* handle or object handle */
#define CK_INVALID_HANDLE 0


typedef struct CK_VERSION {
	CK_BYTE       major;  /* integer portion of version number */
	CK_BYTE       minor;  /* 1/100ths portion of version number */
} CK_VERSION;

typedef CK_VERSION CK_PTR CK_VERSION_PTR;


typedef struct CK_INFO {
	/* manufacturerID and libraryDecription have been changed from
	* CK_CHAR to CK_UTF8CHAR for v2.10 */
	CK_VERSION    cryptokiVersion;     /* Cryptoki interface ver */
	CK_UTF8CHAR   manufacturerID[32];  /* blank padded */
	CK_FLAGS      flags;               /* must be zero */

	/* libraryDescription and libraryVersion are new for v2.0 */
	CK_UTF8CHAR   libraryDescription[32];  /* blank padded */
	CK_VERSION    libraryVersion;          /* version of library */
} CK_INFO;

typedef CK_INFO CK_PTR    CK_INFO_PTR;


/* CK_NOTIFICATION enumerates the types of notifications that
* Cryptoki provides to an application */
/* CK_NOTIFICATION has been changed from an enum to a CK_ULONG
* for v2.0 */
typedef CK_ULONG CK_NOTIFICATION;
#define CKN_SURRENDER       0

/* The following notification is new for PKCS #11 v2.20 amendment 3 */
#define CKN_OTP_CHANGED     1


typedef CK_ULONG          CK_SLOT_ID;

typedef CK_SLOT_ID CK_PTR CK_SLOT_ID_PTR;


/* CK_SLOT_INFO provides information about a slot */
typedef struct CK_SLOT_INFO {
	/* slotDescription and manufacturerID have been changed from
	* CK_CHAR to CK_UTF8CHAR for v2.10 */
	CK_UTF8CHAR   slotDescription[64];  /* blank padded */
	CK_UTF8CHAR   manufacturerID[32];   /* blank padded */
	CK_FLAGS      flags;

	/* hardwareVersion and firmwareVersion are new for v2.0 */
	CK_VERSION    hardwareVersion;  /* version of hardware */
	CK_VERSION    firmwareVersion;  /* version of firmware */
} CK_SLOT_INFO;

/* flags: bit flags that provide capabilities of the slot
*      Bit Flag              Mask        Meaning
*/
#define CKF_TOKEN_PRESENT     0x00000001  /* a token is there */
#define CKF_REMOVABLE_DEVICE  0x00000002  /* removable devices*/
#define CKF_HW_SLOT           0x00000004  /* hardware slot */

typedef CK_SLOT_INFO CK_PTR CK_SLOT_INFO_PTR;


/* CK_TOKEN_INFO provides information about a token */
typedef struct CK_TOKEN_INFO {
	/* label, manufacturerID, and model have been changed from
	* CK_CHAR to CK_UTF8CHAR for v2.10 */
	CK_UTF8CHAR   label[32];           /* blank padded */
	CK_UTF8CHAR   manufacturerID[32];  /* blank padded */
	CK_UTF8CHAR   model[16];           /* blank padded */
	CK_CHAR       serialNumber[16];    /* blank padded */
	CK_FLAGS      flags;               /* see below */

	/* ulMaxSessionCount, ulSessionCount, ulMaxRwSessionCount,
	* ulRwSessionCount, ulMaxPinLen, and ulMinPinLen have all been
	* changed from CK_USHORT to CK_ULONG for v2.0 */
	CK_ULONG      ulMaxSessionCount;     /* max open sessions */
	CK_ULONG      ulSessionCount;        /* sess. now open */
	CK_ULONG      ulMaxRwSessionCount;   /* max R/W sessions */
	CK_ULONG      ulRwSessionCount;      /* R/W sess. now open */
	CK_ULONG      ulMaxPinLen;           /* in bytes */
	CK_ULONG      ulMinPinLen;           /* in bytes */
	CK_ULONG      ulTotalPublicMemory;   /* in bytes */
	CK_ULONG      ulFreePublicMemory;    /* in bytes */
	CK_ULONG      ulTotalPrivateMemory;  /* in bytes */
	CK_ULONG      ulFreePrivateMemory;   /* in bytes */

	/* hardwareVersion, firmwareVersion, and time are new for
	* v2.0 */
	CK_VERSION    hardwareVersion;       /* version of hardware */
	CK_VERSION    firmwareVersion;       /* version of firmware */
	CK_CHAR       utcTime[16];           /* time */
} CK_TOKEN_INFO;

/* The flags parameter is defined as follows:
*      Bit Flag                    Mask        Meaning
*/
#define CKF_RNG                     0x00000001  /* has random #
* generator */
#define CKF_WRITE_PROTECTED         0x00000002  /* token is
* write-
* protected */
#define CKF_LOGIN_REQUIRED          0x00000004  /* user must
* login */
#define CKF_USER_PIN_INITIALIZED    0x00000008  /* normal user's
* PIN is set */

/* CKF_RESTORE_KEY_NOT_NEEDED is new for v2.0.  If it is set,
* that means that *every* time the state of cryptographic
* operations of a session is successfully saved, all keys
* needed to continue those operations are stored in the state */
#define CKF_RESTORE_KEY_NOT_NEEDED  0x00000020

/* CKF_CLOCK_ON_TOKEN is new for v2.0.  If it is set, that means
* that the token has some sort of clock.  The time on that
* clock is returned in the token info structure */
#define CKF_CLOCK_ON_TOKEN          0x00000040

/* CKF_PROTECTED_AUTHENTICATION_PATH is new for v2.0.  If it is
* set, that means that there is some way for the user to login
* without sending a PIN through the Cryptoki library itself */
#define CKF_PROTECTED_AUTHENTICATION_PATH 0x00000100

/* CKF_DUAL_CRYPTO_OPERATIONS is new for v2.0.  If it is true,
* that means that a single session with the token can perform
* dual simultaneous cryptographic operations (digest and
* encrypt; decrypt and digest; sign and encrypt; and decrypt
* and sign) */
#define CKF_DUAL_CRYPTO_OPERATIONS  0x00000200

/* CKF_TOKEN_INITIALIZED if new for v2.10. If it is true, the
* token has been initialized using C_InitializeToken or an
* equivalent mechanism outside the scope of PKCS #11.
* Calling C_InitializeToken when this flag is set will cause
* the token to be reinitialized. */
#define CKF_TOKEN_INITIALIZED       0x00000400

/* CKF_SECONDARY_AUTHENTICATION if new for v2.10. If it is
* true, the token supports secondary authentication for
* private key objects. This flag is deprecated in v2.11 and
onwards. */
#define CKF_SECONDARY_AUTHENTICATION  0x00000800

/* CKF_USER_PIN_COUNT_LOW if new for v2.10. If it is true, an
* incorrect user login PIN has been entered at least once
* since the last successful authentication. */
#define CKF_USER_PIN_COUNT_LOW       0x00010000

/* CKF_USER_PIN_FINAL_TRY if new for v2.10. If it is true,
* supplying an incorrect user PIN will it to become locked. */
#define CKF_USER_PIN_FINAL_TRY       0x00020000

/* CKF_USER_PIN_LOCKED if new for v2.10. If it is true, the
* user PIN has been locked. User login to the token is not
* possible. */
#define CKF_USER_PIN_LOCKED          0x00040000

/* CKF_USER_PIN_TO_BE_CHANGED if new for v2.10. If it is true,
* the user PIN value is the default value set by token
* initialization or manufacturing, or the PIN has been
* expired by the card. */
#define CKF_USER_PIN_TO_BE_CHANGED   0x00080000

/* CKF_SO_PIN_COUNT_LOW if new for v2.10. If it is true, an
* incorrect SO login PIN has been entered at least once since
* the last successful authentication. */
#define CKF_SO_PIN_COUNT_LOW         0x00100000

/* CKF_SO_PIN_FINAL_TRY if new for v2.10. If it is true,
* supplying an incorrect SO PIN will it to become locked. */
#define CKF_SO_PIN_FINAL_TRY         0x00200000

/* CKF_SO_PIN_LOCKED if new for v2.10. If it is true, the SO
* PIN has been locked. SO login to the token is not possible.
*/
#define CKF_SO_PIN_LOCKED            0x00400000

/* CKF_SO_PIN_TO_BE_CHANGED if new for v2.10. If it is true,
* the SO PIN value is the default value set by token
* initialization or manufacturing, or the PIN has been
* expired by the card. */
#define CKF_SO_PIN_TO_BE_CHANGED     0x00800000

typedef CK_TOKEN_INFO CK_PTR CK_TOKEN_INFO_PTR;


/* CK_SESSION_HANDLE is a Cryptoki-assigned value that
* identifies a session */
typedef CK_ULONG          CK_SESSION_HANDLE;

typedef CK_SESSION_HANDLE CK_PTR CK_SESSION_HANDLE_PTR;


/* CK_USER_TYPE enumerates the types of Cryptoki users */
/* CK_USER_TYPE has been changed from an enum to a CK_ULONG for
* v2.0 */
typedef CK_ULONG          CK_USER_TYPE;
/* Security Officer */
#define CKU_SO    0
/* Normal user */
#define CKU_USER  1
/* Context specific (added in v2.20) */
#define CKU_CONTEXT_SPECIFIC   2

/* CK_STATE enumerates the session states */
/* CK_STATE has been changed from an enum to a CK_ULONG for
* v2.0 */
typedef CK_ULONG          CK_STATE;
#define CKS_RO_PUBLIC_SESSION  0
#define CKS_RO_USER_FUNCTIONS  1
#define CKS_RW_PUBLIC_SESSION  2
#define CKS_RW_USER_FUNCTIONS  3
#define CKS_RW_SO_FUNCTIONS    4


/* CK_SESSION_INFO provides information about a session */
typedef struct CK_SESSION_INFO {
	CK_SLOT_ID    slotID;
	CK_STATE      state;
	CK_FLAGS      flags;          /* see below */

	/* ulDeviceError was changed from CK_USHORT to CK_ULONG for
	* v2.0 */
	CK_ULONG      ulDeviceError;  /* device-dependent error code */
} CK_SESSION_INFO;

/* The flags are defined in the following table:
*      Bit Flag                Mask        Meaning
*/
#define CKF_RW_SESSION          0x00000002  /* session is r/w */
#define CKF_SERIAL_SESSION      0x00000004  /* no parallel */

typedef CK_SESSION_INFO CK_PTR CK_SESSION_INFO_PTR;


/* CK_OBJECT_HANDLE is a token-specific identifier for an
* object  */
typedef CK_ULONG          CK_OBJECT_HANDLE;

typedef CK_OBJECT_HANDLE CK_PTR CK_OBJECT_HANDLE_PTR;


/* CK_OBJECT_CLASS is a value that identifies the classes (or
* types) of objects that Cryptoki recognizes.  It is defined
* as follows: */
/* CK_OBJECT_CLASS was changed from CK_USHORT to CK_ULONG for
* v2.0 */
typedef CK_ULONG          CK_OBJECT_CLASS;

/* The following classes of objects are defined: */
/* CKO_HW_FEATURE is new for v2.10 */
/* CKO_DOMAIN_PARAMETERS is new for v2.11 */
/* CKO_MECHANISM is new for v2.20 */
#define CKO_DATA              0x00000000
#define CKO_CERTIFICATE       0x00000001
#define CKO_PUBLIC_KEY        0x00000002
#define CKO_PRIVATE_KEY       0x00000003
#define CKO_SECRET_KEY        0x00000004
#define CKO_HW_FEATURE        0x00000005
#define CKO_DOMAIN_PARAMETERS 0x00000006
#define CKO_MECHANISM         0x00000007

/* CKO_OTP_KEY is new for PKCS #11 v2.20 amendment 1 */
#define CKO_OTP_KEY           0x00000008

#define CKO_VENDOR_DEFINED    0x80000000

typedef CK_OBJECT_CLASS CK_PTR CK_OBJECT_CLASS_PTR;

/* CK_HW_FEATURE_TYPE is new for v2.10. CK_HW_FEATURE_TYPE is a
* value that identifies the hardware feature type of an object
* with CK_OBJECT_CLASS equal to CKO_HW_FEATURE. */
typedef CK_ULONG          CK_HW_FEATURE_TYPE;

/* The following hardware feature types are defined */
/* CKH_USER_INTERFACE is new for v2.20 */
#define CKH_MONOTONIC_COUNTER  0x00000001
#define CKH_CLOCK           0x00000002
#define CKH_USER_INTERFACE  0x00000003
#define CKH_VENDOR_DEFINED  0x80000000

/* CK_KEY_TYPE is a value that identifies a key type */
/* CK_KEY_TYPE was changed from CK_USHORT to CK_ULONG for v2.0 */
typedef CK_ULONG          CK_KEY_TYPE;

/* the following key types are defined: */
#define CKK_RSA             0x00000000
#define CKK_DSA             0x00000001
#define CKK_DH              0x00000002

/* CKK_ECDSA and CKK_KEA are new for v2.0 */
/* CKK_ECDSA is deprecated in v2.11, CKK_EC is preferred. */
#define CKK_ECDSA           0x00000003
#define CKK_EC              0x00000003
#define CKK_X9_42_DH        0x00000004
#define CKK_KEA             0x00000005

#define CKK_GENERIC_SECRET  0x00000010
#define CKK_RC2             0x00000011
#define CKK_RC4             0x00000012
#define CKK_DES             0x00000013
#define CKK_DES2            0x00000014
#define CKK_DES3            0x00000015

/* all these key types are new for v2.0 */
#define CKK_CAST            0x00000016
#define CKK_CAST3           0x00000017
/* CKK_CAST5 is deprecated in v2.11, CKK_CAST128 is preferred. */
#define CKK_CAST5           0x00000018
#define CKK_CAST128         0x00000018
#define CKK_RC5             0x00000019
#define CKK_IDEA            0x0000001A
#define CKK_SKIPJACK        0x0000001B
#define CKK_BATON           0x0000001C
#define CKK_JUNIPER         0x0000001D
#define CKK_CDMF            0x0000001E
#define CKK_AES             0x0000001F

/* BlowFish and TwoFish are new for v2.20 */
#define CKK_BLOWFISH        0x00000020
#define CKK_TWOFISH         0x00000021

/* SecurID, HOTP, and ACTI are new for PKCS #11 v2.20 amendment 1 */
#define CKK_SECURID         0x00000022
#define CKK_HOTP            0x00000023
#define CKK_ACTI            0x00000024

/* Camellia is new for PKCS #11 v2.20 amendment 3 */
#define CKK_CAMELLIA                   0x00000025
/* ARIA is new for PKCS #11 v2.20 amendment 3 */
#define CKK_ARIA                       0x00000026


#define CKK_VENDOR_DEFINED  0x80000000


/* CK_CERTIFICATE_TYPE is a value that identifies a certificate
* type */
/* CK_CERTIFICATE_TYPE was changed from CK_USHORT to CK_ULONG
* for v2.0 */
typedef CK_ULONG          CK_CERTIFICATE_TYPE;

/* The following certificate types are defined: */
/* CKC_X_509_ATTR_CERT is new for v2.10 */
/* CKC_WTLS is new for v2.20 */
#define CKC_X_509           0x00000000
#define CKC_X_509_ATTR_CERT 0x00000001
#define CKC_WTLS            0x00000002
#define CKC_VENDOR_DEFINED  0x80000000


/* CK_ATTRIBUTE_TYPE is a value that identifies an attribute
* type */
/* CK_ATTRIBUTE_TYPE was changed from CK_USHORT to CK_ULONG for
* v2.0 */
typedef CK_ULONG          CK_ATTRIBUTE_TYPE;

/* The CKF_ARRAY_ATTRIBUTE flag identifies an attribute which
consists of an array of values. */
#define CKF_ARRAY_ATTRIBUTE    0x40000000

/* The following OTP-related defines are new for PKCS #11 v2.20 amendment 1
and relates to the CKA_OTP_FORMAT attribute */
#define CK_OTP_FORMAT_DECIMAL      0
#define CK_OTP_FORMAT_HEXADECIMAL  1
#define CK_OTP_FORMAT_ALPHANUMERIC 2
#define CK_OTP_FORMAT_BINARY       3

/* The following OTP-related defines are new for PKCS #11 v2.20 amendment 1
and relates to the CKA_OTP_..._REQUIREMENT attributes */
#define CK_OTP_PARAM_IGNORED       0
#define CK_OTP_PARAM_OPTIONAL      1
#define CK_OTP_PARAM_MANDATORY     2

/* The following attribute types are defined: */
#define CKA_CLASS              0x00000000
#define CKA_TOKEN              0x00000001
#define CKA_PRIVATE            0x00000002
#define CKA_LABEL              0x00000003
#define CKA_APPLICATION        0x00000010
#define CKA_VALUE              0x00000011

/* CKA_OBJECT_ID is new for v2.10 */
#define CKA_OBJECT_ID          0x00000012

#define CKA_CERTIFICATE_TYPE   0x00000080
#define CKA_ISSUER             0x00000081
#define CKA_SERIAL_NUMBER      0x00000082

/* CKA_AC_ISSUER, CKA_OWNER, and CKA_ATTR_TYPES are new
* for v2.10 */
#define CKA_AC_ISSUER          0x00000083
#define CKA_OWNER              0x00000084
#define CKA_ATTR_TYPES         0x00000085

/* CKA_TRUSTED is new for v2.11 */
#define CKA_TRUSTED            0x00000086

/* CKA_CERTIFICATE_CATEGORY ...
* CKA_CHECK_VALUE are new for v2.20 */
#define CKA_CERTIFICATE_CATEGORY        0x00000087
#define CKA_JAVA_MIDP_SECURITY_DOMAIN   0x00000088
#define CKA_URL                         0x00000089
#define CKA_HASH_OF_SUBJECT_PUBLIC_KEY  0x0000008A
#define CKA_HASH_OF_ISSUER_PUBLIC_KEY   0x0000008B
#define CKA_CHECK_VALUE                 0x00000090

#define CKA_KEY_TYPE           0x00000100
#define CKA_SUBJECT            0x00000101
#define CKA_ID                 0x00000102
#define CKA_SENSITIVE          0x00000103
#define CKA_ENCRYPT            0x00000104
#define CKA_DECRYPT            0x00000105
#define CKA_WRAP               0x00000106
#define CKA_UNWRAP             0x00000107
#define CKA_SIGN               0x00000108
#define CKA_SIGN_RECOVER       0x00000109
#define CKA_VERIFY             0x0000010A
#define CKA_VERIFY_RECOVER     0x0000010B
#define CKA_DERIVE             0x0000010C
#define CKA_START_DATE         0x00000110
#define CKA_END_DATE           0x00000111
#define CKA_MODULUS            0x00000120
#define CKA_MODULUS_BITS       0x00000121
#define CKA_PUBLIC_EXPONENT    0x00000122
#define CKA_PRIVATE_EXPONENT   0x00000123
#define CKA_PRIME_1            0x00000124
#define CKA_PRIME_2            0x00000125
#define CKA_EXPONENT_1         0x00000126
#define CKA_EXPONENT_2         0x00000127
#define CKA_COEFFICIENT        0x00000128
#define CKA_PRIME              0x00000130
#define CKA_SUBPRIME           0x00000131
#define CKA_BASE               0x00000132

/* CKA_PRIME_BITS and CKA_SUB_PRIME_BITS are new for v2.11 */
#define CKA_PRIME_BITS         0x00000133
#define CKA_SUBPRIME_BITS      0x00000134
#define CKA_SUB_PRIME_BITS     CKA_SUBPRIME_BITS
/* (To retain backwards-compatibility) */

#define CKA_VALUE_BITS         0x00000160
#define CKA_VALUE_LEN          0x00000161

/* CKA_EXTRACTABLE, CKA_LOCAL, CKA_NEVER_EXTRACTABLE,
* CKA_ALWAYS_SENSITIVE, CKA_MODIFIABLE, CKA_ECDSA_PARAMS,
* and CKA_EC_POINT are new for v2.0 */
#define CKA_EXTRACTABLE        0x00000162
#define CKA_LOCAL              0x00000163
#define CKA_NEVER_EXTRACTABLE  0x00000164
#define CKA_ALWAYS_SENSITIVE   0x00000165

/* CKA_KEY_GEN_MECHANISM is new for v2.11 */
#define CKA_KEY_GEN_MECHANISM  0x00000166

#define CKA_MODIFIABLE         0x00000170

/* CKA_ECDSA_PARAMS is deprecated in v2.11,
* CKA_EC_PARAMS is preferred. */
#define CKA_ECDSA_PARAMS       0x00000180
#define CKA_EC_PARAMS          0x00000180

#define CKA_EC_POINT           0x00000181

/* CKA_SECONDARY_AUTH, CKA_AUTH_PIN_FLAGS,
* are new for v2.10. Deprecated in v2.11 and onwards. */
#define CKA_SECONDARY_AUTH     0x00000200
#define CKA_AUTH_PIN_FLAGS     0x00000201

/* CKA_ALWAYS_AUTHENTICATE ...
* CKA_UNWRAP_TEMPLATE are new for v2.20 */
#define CKA_ALWAYS_AUTHENTICATE  0x00000202

#define CKA_WRAP_WITH_TRUSTED    0x00000210
#define CKA_WRAP_TEMPLATE        (CKF_ARRAY_ATTRIBUTE|0x00000211)
#define CKA_UNWRAP_TEMPLATE      (CKF_ARRAY_ATTRIBUTE|0x00000212)

/* CKA_OTP... atttributes are new for PKCS #11 v2.20 amendment 3. */
#define CKA_OTP_FORMAT                0x00000220
#define CKA_OTP_LENGTH                0x00000221
#define CKA_OTP_TIME_INTERVAL         0x00000222
#define CKA_OTP_USER_FRIENDLY_MODE    0x00000223
#define CKA_OTP_CHALLENGE_REQUIREMENT 0x00000224
#define CKA_OTP_TIME_REQUIREMENT      0x00000225
#define CKA_OTP_COUNTER_REQUIREMENT   0x00000226
#define CKA_OTP_PIN_REQUIREMENT       0x00000227
#define CKA_OTP_COUNTER               0x0000022E
#define CKA_OTP_TIME                  0x0000022F
#define CKA_OTP_USER_IDENTIFIER       0x0000022A
#define CKA_OTP_SERVICE_IDENTIFIER    0x0000022B
#define CKA_OTP_SERVICE_LOGO          0x0000022C
#define CKA_OTP_SERVICE_LOGO_TYPE     0x0000022D


/* CKA_HW_FEATURE_TYPE, CKA_RESET_ON_INIT, and CKA_HAS_RESET
* are new for v2.10 */
#define CKA_HW_FEATURE_TYPE    0x00000300
#define CKA_RESET_ON_INIT      0x00000301
#define CKA_HAS_RESET          0x00000302

/* The following attributes are new for v2.20 */
#define CKA_PIXEL_X                     0x00000400
#define CKA_PIXEL_Y                     0x00000401
#define CKA_RESOLUTION                  0x00000402
#define CKA_CHAR_ROWS                   0x00000403
#define CKA_CHAR_COLUMNS                0x00000404
#define CKA_COLOR                       0x00000405
#define CKA_BITS_PER_PIXEL              0x00000406
#define CKA_CHAR_SETS                   0x00000480
#define CKA_ENCODING_METHODS            0x00000481
#define CKA_MIME_TYPES                  0x00000482
#define CKA_MECHANISM_TYPE              0x00000500
#define CKA_REQUIRED_CMS_ATTRIBUTES     0x00000501
#define CKA_DEFAULT_CMS_ATTRIBUTES      0x00000502
#define CKA_SUPPORTED_CMS_ATTRIBUTES    0x00000503
#define CKA_ALLOWED_MECHANISMS          (CKF_ARRAY_ATTRIBUTE|0x00000600)

#define CKA_VENDOR_DEFINED     0x80000000

/* CK_ATTRIBUTE is a structure that includes the type, length
* and value of an attribute */
typedef struct CK_ATTRIBUTE {
	CK_ATTRIBUTE_TYPE type;
	CK_VOID_PTR       pValue;

	/* ulValueLen went from CK_USHORT to CK_ULONG for v2.0 */
	CK_ULONG          ulValueLen;  /* in bytes */
} CK_ATTRIBUTE;

typedef CK_ATTRIBUTE CK_PTR CK_ATTRIBUTE_PTR;


/* CK_DATE is a structure that defines a date */
typedef struct CK_DATE{
	CK_CHAR       year[4];   /* the year ("1900" - "9999") */
	CK_CHAR       month[2];  /* the month ("01" - "12") */
	CK_CHAR       day[2];    /* the day   ("01" - "31") */
} CK_DATE;


/* CK_MECHANISM_TYPE is a value that identifies a mechanism
* type */
/* CK_MECHANISM_TYPE was changed from CK_USHORT to CK_ULONG for
* v2.0 */
typedef CK_ULONG          CK_MECHANISM_TYPE;

/* the following mechanism types are defined: */
#define CKM_RSA_PKCS_KEY_PAIR_GEN      0x00000000
#define CKM_RSA_PKCS                   0x00000001
#define CKM_RSA_9796                   0x00000002
#define CKM_RSA_X_509                  0x00000003

/* CKM_MD2_RSA_PKCS, CKM_MD5_RSA_PKCS, and CKM_SHA1_RSA_PKCS
* are new for v2.0.  They are mechanisms which hash and sign */
#define CKM_MD2_RSA_PKCS               0x00000004
#define CKM_MD5_RSA_PKCS               0x00000005
#define CKM_SHA1_RSA_PKCS              0x00000006

/* CKM_RIPEMD128_RSA_PKCS, CKM_RIPEMD160_RSA_PKCS, and
* CKM_RSA_PKCS_OAEP are new for v2.10 */
#define CKM_RIPEMD128_RSA_PKCS         0x00000007
#define CKM_RIPEMD160_RSA_PKCS         0x00000008
#define CKM_RSA_PKCS_OAEP              0x00000009

/* CKM_RSA_X9_31_KEY_PAIR_GEN, CKM_RSA_X9_31, CKM_SHA1_RSA_X9_31,
* CKM_RSA_PKCS_PSS, and CKM_SHA1_RSA_PKCS_PSS are new for v2.11 */
#define CKM_RSA_X9_31_KEY_PAIR_GEN     0x0000000A
#define CKM_RSA_X9_31                  0x0000000B
#define CKM_SHA1_RSA_X9_31             0x0000000C
#define CKM_RSA_PKCS_PSS               0x0000000D
#define CKM_SHA1_RSA_PKCS_PSS          0x0000000E

#define CKM_DSA_KEY_PAIR_GEN           0x00000010
#define CKM_DSA                        0x00000011
#define CKM_DSA_SHA1                   0x00000012
#define CKM_DH_PKCS_KEY_PAIR_GEN       0x00000020
#define CKM_DH_PKCS_DERIVE             0x00000021

/* CKM_X9_42_DH_KEY_PAIR_GEN, CKM_X9_42_DH_DERIVE,
* CKM_X9_42_DH_HYBRID_DERIVE, and CKM_X9_42_MQV_DERIVE are new for
* v2.11 */
#define CKM_X9_42_DH_KEY_PAIR_GEN      0x00000030
#define CKM_X9_42_DH_DERIVE            0x00000031
#define CKM_X9_42_DH_HYBRID_DERIVE     0x00000032
#define CKM_X9_42_MQV_DERIVE           0x00000033

/* CKM_SHA256/384/512 are new for v2.20 */
#define CKM_SHA256_RSA_PKCS            0x00000040
#define CKM_SHA384_RSA_PKCS            0x00000041
#define CKM_SHA512_RSA_PKCS            0x00000042
#define CKM_SHA256_RSA_PKCS_PSS        0x00000043
#define CKM_SHA384_RSA_PKCS_PSS        0x00000044
#define CKM_SHA512_RSA_PKCS_PSS        0x00000045

/* SHA-224 ISC_RSA mechanisms are new for PKCS #11 v2.20 amendment 3 */
#define CKM_SHA224_RSA_PKCS            0x00000046
#define CKM_SHA224_RSA_PKCS_PSS        0x00000047

#define CKM_RC2_KEY_GEN                0x00000100
#define CKM_RC2_ECB                    0x00000101
#define CKM_RC2_CBC                    0x00000102
#define CKM_RC2_MAC                    0x00000103

/* CKM_RC2_MAC_GENERAL and CKM_RC2_CBC_PAD are new for v2.0 */
#define CKM_RC2_MAC_GENERAL            0x00000104
#define CKM_RC2_CBC_PAD                0x00000105

#define CKM_RC4_KEY_GEN                0x00000110
#define CKM_RC4                        0x00000111
#define CKM_DES_KEY_GEN                0x00000120
#define CKM_DES_ECB                    0x00000121
#define CKM_DES_CBC                    0x00000122
#define CKM_DES_MAC                    0x00000123

/* CKM_DES_MAC_GENERAL and CKM_DES_CBC_PAD are new for v2.0 */
#define CKM_DES_MAC_GENERAL            0x00000124
#define CKM_DES_CBC_PAD                0x00000125

#define CKM_DES2_KEY_GEN               0x00000130
#define CKM_DES3_KEY_GEN               0x00000131
#define CKM_DES3_ECB                   0x00000132
#define CKM_DES3_CBC                   0x00000133
#define CKM_DES3_MAC                   0x00000134

/* CKM_DES3_MAC_GENERAL, CKM_DES3_CBC_PAD, CKM_CDMF_KEY_GEN,
* CKM_CDMF_ECB, CKM_CDMF_CBC, CKM_CDMF_MAC,
* CKM_CDMF_MAC_GENERAL, and CKM_CDMF_CBC_PAD are new for v2.0 */
#define CKM_DES3_MAC_GENERAL           0x00000135
#define CKM_DES3_CBC_PAD               0x00000136
#define CKM_CDMF_KEY_GEN               0x00000140
#define CKM_CDMF_ECB                   0x00000141
#define CKM_CDMF_CBC                   0x00000142
#define CKM_CDMF_MAC                   0x00000143
#define CKM_CDMF_MAC_GENERAL           0x00000144
#define CKM_CDMF_CBC_PAD               0x00000145

/* the following four ISC_DES mechanisms are new for v2.20 */
#define CKM_DES_OFB64                  0x00000150
#define CKM_DES_OFB8                   0x00000151
#define CKM_DES_CFB64                  0x00000152
#define CKM_DES_CFB8                   0x00000153

#define CKM_MD2                        0x00000200

/* CKM_MD2_HMAC and CKM_MD2_HMAC_GENERAL are new for v2.0 */
#define CKM_MD2_HMAC                   0x00000201
#define CKM_MD2_HMAC_GENERAL           0x00000202

#define CKM_MD5                        0x00000210

/* CKM_MD5_HMAC and CKM_MD5_HMAC_GENERAL are new for v2.0 */
#define CKM_MD5_HMAC                   0x00000211
#define CKM_MD5_HMAC_GENERAL           0x00000212

#define CKM_SHA_1                      0x00000220

/* CKM_SHA_1_HMAC and CKM_SHA_1_HMAC_GENERAL are new for v2.0 */
#define CKM_SHA_1_HMAC                 0x00000221
#define CKM_SHA_1_HMAC_GENERAL         0x00000222

/* CKM_RIPEMD128, CKM_RIPEMD128_HMAC,
* CKM_RIPEMD128_HMAC_GENERAL, CKM_RIPEMD160, CKM_RIPEMD160_HMAC,
* and CKM_RIPEMD160_HMAC_GENERAL are new for v2.10 */
#define CKM_RIPEMD128                  0x00000230
#define CKM_RIPEMD128_HMAC             0x00000231
#define CKM_RIPEMD128_HMAC_GENERAL     0x00000232
#define CKM_RIPEMD160                  0x00000240
#define CKM_RIPEMD160_HMAC             0x00000241
#define CKM_RIPEMD160_HMAC_GENERAL     0x00000242

/* CKM_SHA256/384/512 are new for v2.20 */
#define CKM_SHA256                     0x00000250
#define CKM_SHA256_HMAC                0x00000251
#define CKM_SHA256_HMAC_GENERAL        0x00000252

/* SHA-224 is new for PKCS #11 v2.20 amendment 3 */
#define CKM_SHA224                     0x00000255
#define CKM_SHA224_HMAC                0x00000256
#define CKM_SHA224_HMAC_GENERAL        0x00000257

#define CKM_SHA384                     0x00000260
#define CKM_SHA384_HMAC                0x00000261
#define CKM_SHA384_HMAC_GENERAL        0x00000262
#define CKM_SHA512                     0x00000270
#define CKM_SHA512_HMAC                0x00000271
#define CKM_SHA512_HMAC_GENERAL        0x00000272

/* SecurID is new for PKCS #11 v2.20 amendment 1 */
#define CKM_SECURID_KEY_GEN            0x00000280
#define CKM_SECURID                    0x00000282

/* HOTP is new for PKCS #11 v2.20 amendment 1 */
#define CKM_HOTP_KEY_GEN    0x00000290
#define CKM_HOTP            0x00000291

/* ACTI is new for PKCS #11 v2.20 amendment 1 */
#define CKM_ACTI            0x000002A0
#define CKM_ACTI_KEY_GEN    0x000002A1

/* All of the following mechanisms are new for v2.0 */
/* Note that CAST128 and CAST5 are the same algorithm */
#define CKM_CAST_KEY_GEN               0x00000300
#define CKM_CAST_ECB                   0x00000301
#define CKM_CAST_CBC                   0x00000302
#define CKM_CAST_MAC                   0x00000303
#define CKM_CAST_MAC_GENERAL           0x00000304
#define CKM_CAST_CBC_PAD               0x00000305
#define CKM_CAST3_KEY_GEN              0x00000310
#define CKM_CAST3_ECB                  0x00000311
#define CKM_CAST3_CBC                  0x00000312
#define CKM_CAST3_MAC                  0x00000313
#define CKM_CAST3_MAC_GENERAL          0x00000314
#define CKM_CAST3_CBC_PAD              0x00000315
#define CKM_CAST5_KEY_GEN              0x00000320
#define CKM_CAST128_KEY_GEN            0x00000320
#define CKM_CAST5_ECB                  0x00000321
#define CKM_CAST128_ECB                0x00000321
#define CKM_CAST5_CBC                  0x00000322
#define CKM_CAST128_CBC                0x00000322
#define CKM_CAST5_MAC                  0x00000323
#define CKM_CAST128_MAC                0x00000323
#define CKM_CAST5_MAC_GENERAL          0x00000324
#define CKM_CAST128_MAC_GENERAL        0x00000324
#define CKM_CAST5_CBC_PAD              0x00000325
#define CKM_CAST128_CBC_PAD            0x00000325
#define CKM_RC5_KEY_GEN                0x00000330
#define CKM_RC5_ECB                    0x00000331
#define CKM_RC5_CBC                    0x00000332
#define CKM_RC5_MAC                    0x00000333
#define CKM_RC5_MAC_GENERAL            0x00000334
#define CKM_RC5_CBC_PAD                0x00000335
#define CKM_IDEA_KEY_GEN               0x00000340
#define CKM_IDEA_ECB                   0x00000341
#define CKM_IDEA_CBC                   0x00000342
#define CKM_IDEA_MAC                   0x00000343
#define CKM_IDEA_MAC_GENERAL           0x00000344
#define CKM_IDEA_CBC_PAD               0x00000345
#define CKM_GENERIC_SECRET_KEY_GEN     0x00000350
#define CKM_CONCATENATE_BASE_AND_KEY   0x00000360
#define CKM_CONCATENATE_BASE_AND_DATA  0x00000362
#define CKM_CONCATENATE_DATA_AND_BASE  0x00000363
#define CKM_XOR_BASE_AND_DATA          0x00000364
#define CKM_EXTRACT_KEY_FROM_KEY       0x00000365
#define CKM_SSL3_PRE_MASTER_KEY_GEN    0x00000370
#define CKM_SSL3_MASTER_KEY_DERIVE     0x00000371
#define CKM_SSL3_KEY_AND_MAC_DERIVE    0x00000372

/* CKM_SSL3_MASTER_KEY_DERIVE_DH, CKM_TLS_PRE_MASTER_KEY_GEN,
* CKM_TLS_MASTER_KEY_DERIVE, CKM_TLS_KEY_AND_MAC_DERIVE, and
* CKM_TLS_MASTER_KEY_DERIVE_DH are new for v2.11 */
#define CKM_SSL3_MASTER_KEY_DERIVE_DH  0x00000373
#define CKM_TLS_PRE_MASTER_KEY_GEN     0x00000374
#define CKM_TLS_MASTER_KEY_DERIVE      0x00000375
#define CKM_TLS_KEY_AND_MAC_DERIVE     0x00000376
#define CKM_TLS_MASTER_KEY_DERIVE_DH   0x00000377

/* CKM_TLS_PRF is new for v2.20 */
#define CKM_TLS_PRF                    0x00000378

#define CKM_SSL3_MD5_MAC               0x00000380
#define CKM_SSL3_SHA1_MAC              0x00000381
#define CKM_MD5_KEY_DERIVATION         0x00000390
#define CKM_MD2_KEY_DERIVATION         0x00000391
#define CKM_SHA1_KEY_DERIVATION        0x00000392

/* CKM_SHA256/384/512 are new for v2.20 */
#define CKM_SHA256_KEY_DERIVATION      0x00000393
#define CKM_SHA384_KEY_DERIVATION      0x00000394
#define CKM_SHA512_KEY_DERIVATION      0x00000395

/* SHA-224 key derivation is new for PKCS #11 v2.20 amendment 3 */
#define CKM_SHA224_KEY_DERIVATION      0x00000396

#define CKM_PBE_MD2_DES_CBC            0x000003A0
#define CKM_PBE_MD5_DES_CBC            0x000003A1
#define CKM_PBE_MD5_CAST_CBC           0x000003A2
#define CKM_PBE_MD5_CAST3_CBC          0x000003A3
#define CKM_PBE_MD5_CAST5_CBC          0x000003A4
#define CKM_PBE_MD5_CAST128_CBC        0x000003A4
#define CKM_PBE_SHA1_CAST5_CBC         0x000003A5
#define CKM_PBE_SHA1_CAST128_CBC       0x000003A5
#define CKM_PBE_SHA1_RC4_128           0x000003A6
#define CKM_PBE_SHA1_RC4_40            0x000003A7
#define CKM_PBE_SHA1_DES3_EDE_CBC      0x000003A8
#define CKM_PBE_SHA1_DES2_EDE_CBC      0x000003A9
#define CKM_PBE_SHA1_RC2_128_CBC       0x000003AA
#define CKM_PBE_SHA1_RC2_40_CBC        0x000003AB

/* CKM_PKCS5_PBKD2 is new for v2.10 */
#define CKM_PKCS5_PBKD2                0x000003B0

#define CKM_PBA_SHA1_WITH_SHA1_HMAC    0x000003C0

/* WTLS mechanisms are new for v2.20 */
#define CKM_WTLS_PRE_MASTER_KEY_GEN         0x000003D0
#define CKM_WTLS_MASTER_KEY_DERIVE          0x000003D1
#define CKM_WTLS_MASTER_KEY_DERIVE_DH_ECC   0x000003D2
#define CKM_WTLS_PRF                        0x000003D3
#define CKM_WTLS_SERVER_KEY_AND_MAC_DERIVE  0x000003D4
#define CKM_WTLS_CLIENT_KEY_AND_MAC_DERIVE  0x000003D5

#define CKM_KEY_WRAP_LYNKS             0x00000400
#define CKM_KEY_WRAP_SET_OAEP          0x00000401

/* CKM_CMS_SIG is new for v2.20 */
#define CKM_CMS_SIG                    0x00000500

/* CKM_KIP mechanisms are new for PKCS #11 v2.20 amendment 2 */
#define CKM_KIP_DERIVE	               0x00000510
#define CKM_KIP_WRAP	               0x00000511
#define CKM_KIP_MAC	               0x00000512

/* Camellia is new for PKCS #11 v2.20 amendment 3 */
#define CKM_CAMELLIA_KEY_GEN           0x00000550
#define CKM_CAMELLIA_ECB               0x00000551
#define CKM_CAMELLIA_CBC               0x00000552
#define CKM_CAMELLIA_MAC               0x00000553
#define CKM_CAMELLIA_MAC_GENERAL       0x00000554
#define CKM_CAMELLIA_CBC_PAD           0x00000555
#define CKM_CAMELLIA_ECB_ENCRYPT_DATA  0x00000556
#define CKM_CAMELLIA_CBC_ENCRYPT_DATA  0x00000557
#define CKM_CAMELLIA_CTR               0x00000558

/* ARIA is new for PKCS #11 v2.20 amendment 3 */
#define CKM_ARIA_KEY_GEN               0x00000560
#define CKM_ARIA_ECB                   0x00000561
#define CKM_ARIA_CBC                   0x00000562
#define CKM_ARIA_MAC                   0x00000563
#define CKM_ARIA_MAC_GENERAL           0x00000564
#define CKM_ARIA_CBC_PAD               0x00000565
#define CKM_ARIA_ECB_ENCRYPT_DATA      0x00000566
#define CKM_ARIA_CBC_ENCRYPT_DATA      0x00000567

/* Fortezza mechanisms */
#define CKM_SKIPJACK_KEY_GEN           0x00001000
#define CKM_SKIPJACK_ECB64             0x00001001
#define CKM_SKIPJACK_CBC64             0x00001002
#define CKM_SKIPJACK_OFB64             0x00001003
#define CKM_SKIPJACK_CFB64             0x00001004
#define CKM_SKIPJACK_CFB32             0x00001005
#define CKM_SKIPJACK_CFB16             0x00001006
#define CKM_SKIPJACK_CFB8              0x00001007
#define CKM_SKIPJACK_WRAP              0x00001008
#define CKM_SKIPJACK_PRIVATE_WRAP      0x00001009
#define CKM_SKIPJACK_RELAYX            0x0000100a
#define CKM_KEA_KEY_PAIR_GEN           0x00001010
#define CKM_KEA_KEY_DERIVE             0x00001011
#define CKM_FORTEZZA_TIMESTAMP         0x00001020
#define CKM_BATON_KEY_GEN              0x00001030
#define CKM_BATON_ECB128               0x00001031
#define CKM_BATON_ECB96                0x00001032
#define CKM_BATON_CBC128               0x00001033
#define CKM_BATON_COUNTER              0x00001034
#define CKM_BATON_SHUFFLE              0x00001035
#define CKM_BATON_WRAP                 0x00001036

/* CKM_ECDSA_KEY_PAIR_GEN is deprecated in v2.11,
* CKM_EC_KEY_PAIR_GEN is preferred */
#define CKM_ECDSA_KEY_PAIR_GEN         0x00001040
#define CKM_EC_KEY_PAIR_GEN            0x00001040

#define CKM_ECDSA                      0x00001041
#define CKM_ECDSA_SHA1                 0x00001042

/* CKM_ECDH1_DERIVE, CKM_ECDH1_COFACTOR_DERIVE, and CKM_ECMQV_DERIVE
* are new for v2.11 */
#define CKM_ECDH1_DERIVE               0x00001050
#define CKM_ECDH1_COFACTOR_DERIVE      0x00001051
#define CKM_ECMQV_DERIVE               0x00001052

#define CKM_JUNIPER_KEY_GEN            0x00001060
#define CKM_JUNIPER_ECB128             0x00001061
#define CKM_JUNIPER_CBC128             0x00001062
#define CKM_JUNIPER_COUNTER            0x00001063
#define CKM_JUNIPER_SHUFFLE            0x00001064
#define CKM_JUNIPER_WRAP               0x00001065
#define CKM_FASTHASH                   0x00001070

/* CKM_AES_KEY_GEN, CKM_AES_ECB, CKM_AES_CBC, CKM_AES_MAC,
* CKM_AES_MAC_GENERAL, CKM_AES_CBC_PAD, CKM_DSA_PARAMETER_GEN,
* CKM_DH_PKCS_PARAMETER_GEN, and CKM_X9_42_DH_PARAMETER_GEN are
* new for v2.11 */
#define CKM_AES_KEY_GEN                0x00001080
#define CKM_AES_ECB                    0x00001081
#define CKM_AES_CBC                    0x00001082
#define CKM_AES_MAC                    0x00001083
#define CKM_AES_MAC_GENERAL            0x00001084
#define CKM_AES_CBC_PAD                0x00001085

/* AES counter mode is new for PKCS #11 v2.20 amendment 3 */
#define CKM_AES_CTR                    0x00001086

/* BlowFish and TwoFish are new for v2.20 */
#define CKM_BLOWFISH_KEY_GEN           0x00001090
#define CKM_BLOWFISH_CBC               0x00001091
#define CKM_TWOFISH_KEY_GEN            0x00001092
#define CKM_TWOFISH_CBC                0x00001093


/* CKM_xxx_ENCRYPT_DATA mechanisms are new for v2.20 */
#define CKM_DES_ECB_ENCRYPT_DATA       0x00001100
#define CKM_DES_CBC_ENCRYPT_DATA       0x00001101
#define CKM_DES3_ECB_ENCRYPT_DATA      0x00001102
#define CKM_DES3_CBC_ENCRYPT_DATA      0x00001103
#define CKM_AES_ECB_ENCRYPT_DATA       0x00001104
#define CKM_AES_CBC_ENCRYPT_DATA       0x00001105

#define CKM_DSA_PARAMETER_GEN          0x00002000
#define CKM_DH_PKCS_PARAMETER_GEN      0x00002001
#define CKM_X9_42_DH_PARAMETER_GEN     0x00002002

#define CKM_VENDOR_DEFINED             0x80000000

typedef CK_MECHANISM_TYPE CK_PTR CK_MECHANISM_TYPE_PTR;


/* CK_MECHANISM is a structure that specifies a particular
* mechanism  */
typedef struct CK_MECHANISM {
	CK_MECHANISM_TYPE mechanism;
	CK_VOID_PTR       pParameter;

	/* ulParameterLen was changed from CK_USHORT to CK_ULONG for
	* v2.0 */
	CK_ULONG          ulParameterLen;  /* in bytes */
} CK_MECHANISM;

typedef CK_MECHANISM CK_PTR CK_MECHANISM_PTR;


/* CK_MECHANISM_INFO provides information about a particular
* mechanism */
typedef struct CK_MECHANISM_INFO {
	CK_ULONG    ulMinKeySize;
	CK_ULONG    ulMaxKeySize;
	CK_FLAGS    flags;
} CK_MECHANISM_INFO;

/* The flags are defined as follows:
*      Bit Flag               Mask        Meaning */
#define CKF_HW                 0x00000001  /* performed by HW */

/* The flags CKF_ENCRYPT, CKF_DECRYPT, CKF_DIGEST, CKF_SIGN,
* CKG_SIGN_RECOVER, CKF_VERIFY, CKF_VERIFY_RECOVER,
* CKF_GENERATE, CKF_GENERATE_KEY_PAIR, CKF_WRAP, CKF_UNWRAP,
* and CKF_DERIVE are new for v2.0.  They specify whether or not
* a mechanism can be used for a particular task */
#define CKF_ENCRYPT            0x00000100
#define CKF_DECRYPT            0x00000200
#define CKF_DIGEST             0x00000400
#define CKF_SIGN               0x00000800
#define CKF_SIGN_RECOVER       0x00001000
#define CKF_VERIFY             0x00002000
#define CKF_VERIFY_RECOVER     0x00004000
#define CKF_GENERATE           0x00008000
#define CKF_GENERATE_KEY_PAIR  0x00010000
#define CKF_WRAP               0x00020000
#define CKF_UNWRAP             0x00040000
#define CKF_DERIVE             0x00080000

/* CKF_EC_F_P, CKF_EC_F_2M, CKF_EC_ECPARAMETERS, CKF_EC_NAMEDCURVE,
* CKF_EC_UNCOMPRESS, and CKF_EC_COMPRESS are new for v2.11. They
* describe a token's EC capabilities not available in mechanism
* information. */
#define CKF_EC_F_P             0x00100000
#define CKF_EC_F_2M            0x00200000
#define CKF_EC_ECPARAMETERS    0x00400000
#define CKF_EC_NAMEDCURVE      0x00800000
#define CKF_EC_UNCOMPRESS      0x01000000
#define CKF_EC_COMPRESS        0x02000000

#define CKF_EXTENSION          0x80000000 /* FALSE for this version */

typedef CK_MECHANISM_INFO CK_PTR CK_MECHANISM_INFO_PTR;


/* CK_RV is a value that identifies the return value of a
* Cryptoki function */
/* CK_RV was changed from CK_USHORT to CK_ULONG for v2.0 */
typedef CK_ULONG          CK_RV;

#define CKR_OK                                0x00000000
#define CKR_CANCEL                            0x00000001
#define CKR_HOST_MEMORY                       0x00000002
#define CKR_SLOT_ID_INVALID                   0x00000003

/* CKR_FLAGS_INVALID was removed for v2.0 */

/* CKR_GENERAL_ERROR and CKR_FUNCTION_FAILED are new for v2.0 */
#define CKR_GENERAL_ERROR                     0x00000005
#define CKR_FUNCTION_FAILED                   0x00000006

/* CKR_ARGUMENTS_BAD, CKR_NO_EVENT, CKR_NEED_TO_CREATE_THREADS,
* and CKR_CANT_LOCK are new for v2.01 */
#define CKR_ARGUMENTS_BAD                     0x00000007
#define CKR_NO_EVENT                          0x00000008
#define CKR_NEED_TO_CREATE_THREADS            0x00000009
#define CKR_CANT_LOCK                         0x0000000A

#define CKR_ATTRIBUTE_READ_ONLY               0x00000010
#define CKR_ATTRIBUTE_SENSITIVE               0x00000011
#define CKR_ATTRIBUTE_TYPE_INVALID            0x00000012
#define CKR_ATTRIBUTE_VALUE_INVALID           0x00000013
#define CKR_DATA_INVALID                      0x00000020
#define CKR_DATA_LEN_RANGE                    0x00000021
#define CKR_DEVICE_ERROR                      0x00000030
#define CKR_DEVICE_MEMORY                     0x00000031
#define CKR_DEVICE_REMOVED                    0x00000032
#define CKR_ENCRYPTED_DATA_INVALID            0x00000040
#define CKR_ENCRYPTED_DATA_LEN_RANGE          0x00000041
#define CKR_FUNCTION_CANCELED                 0x00000050
#define CKR_FUNCTION_NOT_PARALLEL             0x00000051

/* CKR_FUNCTION_NOT_SUPPORTED is new for v2.0 */
#define CKR_FUNCTION_NOT_SUPPORTED            0x00000054

#define CKR_KEY_HANDLE_INVALID                0x00000060

/* CKR_KEY_SENSITIVE was removed for v2.0 */

#define CKR_KEY_SIZE_RANGE                    0x00000062
#define CKR_KEY_TYPE_INCONSISTENT             0x00000063

/* CKR_KEY_NOT_NEEDED, CKR_KEY_CHANGED, CKR_KEY_NEEDED,
* CKR_KEY_INDIGESTIBLE, CKR_KEY_FUNCTION_NOT_PERMITTED,
* CKR_KEY_NOT_WRAPPABLE, and CKR_KEY_UNEXTRACTABLE are new for
* v2.0 */
#define CKR_KEY_NOT_NEEDED                    0x00000064
#define CKR_KEY_CHANGED                       0x00000065
#define CKR_KEY_NEEDED                        0x00000066
#define CKR_KEY_INDIGESTIBLE                  0x00000067
#define CKR_KEY_FUNCTION_NOT_PERMITTED        0x00000068
#define CKR_KEY_NOT_WRAPPABLE                 0x00000069
#define CKR_KEY_UNEXTRACTABLE                 0x0000006A

#define CKR_MECHANISM_INVALID                 0x00000070
#define CKR_MECHANISM_PARAM_INVALID           0x00000071

/* CKR_OBJECT_CLASS_INCONSISTENT and CKR_OBJECT_CLASS_INVALID
* were removed for v2.0 */
#define CKR_OBJECT_HANDLE_INVALID             0x00000082
#define CKR_OPERATION_ACTIVE                  0x00000090
#define CKR_OPERATION_NOT_INITIALIZED         0x00000091
#define CKR_PIN_INCORRECT                     0x000000A0
#define CKR_PIN_INVALID                       0x000000A1
#define CKR_PIN_LEN_RANGE                     0x000000A2

/* CKR_PIN_EXPIRED and CKR_PIN_LOCKED are new for v2.0 */
#define CKR_PIN_EXPIRED                       0x000000A3
#define CKR_PIN_LOCKED                        0x000000A4

#define CKR_SESSION_CLOSED                    0x000000B0
#define CKR_SESSION_COUNT                     0x000000B1
#define CKR_SESSION_HANDLE_INVALID            0x000000B3
#define CKR_SESSION_PARALLEL_NOT_SUPPORTED    0x000000B4
#define CKR_SESSION_READ_ONLY                 0x000000B5
#define CKR_SESSION_EXISTS                    0x000000B6

/* CKR_SESSION_READ_ONLY_EXISTS and
* CKR_SESSION_READ_WRITE_SO_EXISTS are new for v2.0 */
#define CKR_SESSION_READ_ONLY_EXISTS          0x000000B7
#define CKR_SESSION_READ_WRITE_SO_EXISTS      0x000000B8

#define CKR_SIGNATURE_INVALID                 0x000000C0
#define CKR_SIGNATURE_LEN_RANGE               0x000000C1
#define CKR_TEMPLATE_INCOMPLETE               0x000000D0
#define CKR_TEMPLATE_INCONSISTENT             0x000000D1
#define CKR_TOKEN_NOT_PRESENT                 0x000000E0
#define CKR_TOKEN_NOT_RECOGNIZED              0x000000E1
#define CKR_TOKEN_WRITE_PROTECTED             0x000000E2
#define CKR_UNWRAPPING_KEY_HANDLE_INVALID     0x000000F0
#define CKR_UNWRAPPING_KEY_SIZE_RANGE         0x000000F1
#define CKR_UNWRAPPING_KEY_TYPE_INCONSISTENT  0x000000F2
#define CKR_USER_ALREADY_LOGGED_IN            0x00000100
#define CKR_USER_NOT_LOGGED_IN                0x00000101
#define CKR_USER_PIN_NOT_INITIALIZED          0x00000102
#define CKR_USER_TYPE_INVALID                 0x00000103

/* CKR_USER_ANOTHER_ALREADY_LOGGED_IN and CKR_USER_TOO_MANY_TYPES
* are new to v2.01 */
#define CKR_USER_ANOTHER_ALREADY_LOGGED_IN    0x00000104
#define CKR_USER_TOO_MANY_TYPES               0x00000105

#define CKR_WRAPPED_KEY_INVALID               0x00000110
#define CKR_WRAPPED_KEY_LEN_RANGE             0x00000112
#define CKR_WRAPPING_KEY_HANDLE_INVALID       0x00000113
#define CKR_WRAPPING_KEY_SIZE_RANGE           0x00000114
#define CKR_WRAPPING_KEY_TYPE_INCONSISTENT    0x00000115
#define CKR_RANDOM_SEED_NOT_SUPPORTED         0x00000120

/* These are new to v2.0 */
#define CKR_RANDOM_NO_RNG                     0x00000121

/* These are new to v2.11 */
#define CKR_DOMAIN_PARAMS_INVALID             0x00000130

/* These are new to v2.0 */
#define CKR_BUFFER_TOO_SMALL                  0x00000150
#define CKR_SAVED_STATE_INVALID               0x00000160
#define CKR_INFORMATION_SENSITIVE             0x00000170
#define CKR_STATE_UNSAVEABLE                  0x00000180

/* These are new to v2.01 */
#define CKR_CRYPTOKI_NOT_INITIALIZED          0x00000190
#define CKR_CRYPTOKI_ALREADY_INITIALIZED      0x00000191
#define CKR_MUTEX_BAD                         0x000001A0
#define CKR_MUTEX_NOT_LOCKED                  0x000001A1

/* The following return values are new for PKCS #11 v2.20 amendment 3 */
#define CKR_NEW_PIN_MODE                      0x000001B0
#define CKR_NEXT_OTP                          0x000001B1

/* This is new to v2.20 */
#define CKR_FUNCTION_REJECTED                 0x00000200

#define CKR_VENDOR_DEFINED                    0x80000000

int p11_get_depActionFlag(void);

/* CK_NOTIFY is an application callback that processes events */
typedef CK_CALLBACK_FUNCTION(CK_RV, CK_NOTIFY)(
	CK_SESSION_HANDLE hSession,     /* the session's handle */
	CK_NOTIFICATION   event,
	CK_VOID_PTR       pApplication  /* passed to C_OpenSession */
);


/* CK_FUNCTION_LIST is a structure holding a Cryptoki spec
* version and pointers of appropriate types to all the
* Cryptoki functions */
/* CK_FUNCTION_LIST is new for v2.0 */
typedef struct CK_FUNCTION_LIST CK_FUNCTION_LIST;

typedef CK_FUNCTION_LIST CK_PTR CK_FUNCTION_LIST_PTR;

typedef CK_FUNCTION_LIST_PTR CK_PTR CK_FUNCTION_LIST_PTR_PTR;


/* CK_CREATEMUTEX is an application callback for creating a
* mutex object */
typedef CK_CALLBACK_FUNCTION(CK_RV, CK_CREATEMUTEX)(
	CK_VOID_PTR_PTR ppMutex  /* location to receive ptr to mutex */
	);


/* CK_DESTROYMUTEX is an application callback for destroying a
* mutex object */
typedef CK_CALLBACK_FUNCTION(CK_RV, CK_DESTROYMUTEX)(
	CK_VOID_PTR pMutex  /* pointer to mutex */
	);


/* CK_LOCKMUTEX is an application callback for locking a mutex */
typedef CK_CALLBACK_FUNCTION(CK_RV, CK_LOCKMUTEX)(
	CK_VOID_PTR pMutex  /* pointer to mutex */
	);


/* CK_UNLOCKMUTEX is an application callback for unlocking a
* mutex */
typedef CK_CALLBACK_FUNCTION(CK_RV, CK_UNLOCKMUTEX)(
	CK_VOID_PTR pMutex  /* pointer to mutex */
	);


/* CK_C_INITIALIZE_ARGS provides the optional arguments to
* C_Initialize */
typedef struct CK_C_INITIALIZE_ARGS {
	CK_CREATEMUTEX CreateMutex;
	CK_DESTROYMUTEX DestroyMutex;
	CK_LOCKMUTEX LockMutex;
	CK_UNLOCKMUTEX UnlockMutex;
	CK_FLAGS flags;
	CK_VOID_PTR pReserved;
} CK_C_INITIALIZE_ARGS;

/* flags: bit flags that provide capabilities of the slot
*      Bit Flag                           Mask       Meaning
*/
#define CKF_LIBRARY_CANT_CREATE_OS_THREADS 0x00000001
#define CKF_OS_LOCKING_OK                  0x00000002

typedef CK_C_INITIALIZE_ARGS CK_PTR CK_C_INITIALIZE_ARGS_PTR;


/* additional flags for parameters to functions */

/* CKF_DONT_BLOCK is for the function C_WaitForSlotEvent */
#define CKF_DONT_BLOCK     1

/* CK_RSA_PKCS_OAEP_MGF_TYPE is new for v2.10.
* CK_RSA_PKCS_OAEP_MGF_TYPE  is used to indicate the Message
* Generation Function (MGF) applied to a message block when
* formatting a message block for the PKCS #1 OAEP encryption
* scheme. */
typedef CK_ULONG CK_RSA_PKCS_MGF_TYPE;

typedef CK_RSA_PKCS_MGF_TYPE CK_PTR CK_RSA_PKCS_MGF_TYPE_PTR;

/* The following MGFs are defined */
/* CKG_MGF1_SHA256, CKG_MGF1_SHA384, and CKG_MGF1_SHA512
* are new for v2.20 */
#define CKG_MGF1_SHA1         0x00000001
#define CKG_MGF1_SHA256       0x00000002
#define CKG_MGF1_SHA384       0x00000003
#define CKG_MGF1_SHA512       0x00000004
/* SHA-224 is new for PKCS #11 v2.20 amendment 3 */
#define CKG_MGF1_SHA224       0x00000005

/* CK_RSA_PKCS_OAEP_SOURCE_TYPE is new for v2.10.
* CK_RSA_PKCS_OAEP_SOURCE_TYPE  is used to indicate the source
* of the encoding parameter when formatting a message block
* for the PKCS #1 OAEP encryption scheme. */
typedef CK_ULONG CK_RSA_PKCS_OAEP_SOURCE_TYPE;

typedef CK_RSA_PKCS_OAEP_SOURCE_TYPE CK_PTR CK_RSA_PKCS_OAEP_SOURCE_TYPE_PTR;

/* The following encoding parameter sources are defined */
#define CKZ_DATA_SPECIFIED    0x00000001

/* CK_RSA_PKCS_OAEP_PARAMS is new for v2.10.
* CK_RSA_PKCS_OAEP_PARAMS provides the parameters to the
* CKM_RSA_PKCS_OAEP mechanism. */
typedef struct CK_RSA_PKCS_OAEP_PARAMS {
	CK_MECHANISM_TYPE hashAlg;
	CK_RSA_PKCS_MGF_TYPE mgf;
	CK_RSA_PKCS_OAEP_SOURCE_TYPE source;
	CK_VOID_PTR pSourceData;
	CK_ULONG ulSourceDataLen;
} CK_RSA_PKCS_OAEP_PARAMS;

typedef CK_RSA_PKCS_OAEP_PARAMS CK_PTR CK_RSA_PKCS_OAEP_PARAMS_PTR;

/* CK_RSA_PKCS_PSS_PARAMS is new for v2.11.
* CK_RSA_PKCS_PSS_PARAMS provides the parameters to the
* CKM_RSA_PKCS_PSS mechanism(s). */
typedef struct CK_RSA_PKCS_PSS_PARAMS {
	CK_MECHANISM_TYPE    hashAlg;
	CK_RSA_PKCS_MGF_TYPE mgf;
	CK_ULONG             sLen;
} CK_RSA_PKCS_PSS_PARAMS;

typedef CK_RSA_PKCS_PSS_PARAMS CK_PTR CK_RSA_PKCS_PSS_PARAMS_PTR;

/* CK_EC_KDF_TYPE is new for v2.11. */
typedef CK_ULONG CK_EC_KDF_TYPE;

/* The following EC Key Derivation Functions are defined */
#define CKD_NULL                 0x00000001
#define CKD_SHA1_KDF             0x00000002

/* CK_ECDH1_DERIVE_PARAMS is new for v2.11.
* CK_ECDH1_DERIVE_PARAMS provides the parameters to the
* CKM_ECDH1_DERIVE and CKM_ECDH1_COFACTOR_DERIVE mechanisms,
* where each party contributes one key pair.
*/
typedef struct CK_ECDH1_DERIVE_PARAMS {
	CK_EC_KDF_TYPE kdf;
	CK_ULONG ulSharedDataLen;
	CK_BYTE_PTR pSharedData;
	CK_ULONG ulPublicDataLen;
	CK_BYTE_PTR pPublicData;
} CK_ECDH1_DERIVE_PARAMS;

typedef CK_ECDH1_DERIVE_PARAMS CK_PTR CK_ECDH1_DERIVE_PARAMS_PTR;


/* CK_ECDH2_DERIVE_PARAMS is new for v2.11.
* CK_ECDH2_DERIVE_PARAMS provides the parameters to the
* CKM_ECMQV_DERIVE mechanism, where each party contributes two key pairs. */
typedef struct CK_ECDH2_DERIVE_PARAMS {
	CK_EC_KDF_TYPE kdf;
	CK_ULONG ulSharedDataLen;
	CK_BYTE_PTR pSharedData;
	CK_ULONG ulPublicDataLen;
	CK_BYTE_PTR pPublicData;
	CK_ULONG ulPrivateDataLen;
	CK_OBJECT_HANDLE hPrivateData;
	CK_ULONG ulPublicDataLen2;
	CK_BYTE_PTR pPublicData2;
} CK_ECDH2_DERIVE_PARAMS;

typedef CK_ECDH2_DERIVE_PARAMS CK_PTR CK_ECDH2_DERIVE_PARAMS_PTR;

typedef struct CK_ECMQV_DERIVE_PARAMS {
	CK_EC_KDF_TYPE kdf;
	CK_ULONG ulSharedDataLen;
	CK_BYTE_PTR pSharedData;
	CK_ULONG ulPublicDataLen;
	CK_BYTE_PTR pPublicData;
	CK_ULONG ulPrivateDataLen;
	CK_OBJECT_HANDLE hPrivateData;
	CK_ULONG ulPublicDataLen2;
	CK_BYTE_PTR pPublicData2;
	CK_OBJECT_HANDLE publicKey;
} CK_ECMQV_DERIVE_PARAMS;

typedef CK_ECMQV_DERIVE_PARAMS CK_PTR CK_ECMQV_DERIVE_PARAMS_PTR;

/* Typedefs and defines for the CKM_X9_42_DH_KEY_PAIR_GEN and the
* CKM_X9_42_DH_PARAMETER_GEN mechanisms (new for PKCS #11 v2.11) */
typedef CK_ULONG CK_X9_42_DH_KDF_TYPE;
typedef CK_X9_42_DH_KDF_TYPE CK_PTR CK_X9_42_DH_KDF_TYPE_PTR;

/* The following X9.42 DH key derivation functions are defined
(besides CKD_NULL already defined : */
#define CKD_SHA1_KDF_ASN1        0x00000003
#define CKD_SHA1_KDF_CONCATENATE 0x00000004

/* CK_X9_42_DH1_DERIVE_PARAMS is new for v2.11.
* CK_X9_42_DH1_DERIVE_PARAMS provides the parameters to the
* CKM_X9_42_DH_DERIVE key derivation mechanism, where each party
* contributes one key pair */
typedef struct CK_X9_42_DH1_DERIVE_PARAMS {
	CK_X9_42_DH_KDF_TYPE kdf;
	CK_ULONG ulOtherInfoLen;
	CK_BYTE_PTR pOtherInfo;
	CK_ULONG ulPublicDataLen;
	CK_BYTE_PTR pPublicData;
} CK_X9_42_DH1_DERIVE_PARAMS;

typedef struct CK_X9_42_DH1_DERIVE_PARAMS CK_PTR CK_X9_42_DH1_DERIVE_PARAMS_PTR;

/* CK_X9_42_DH2_DERIVE_PARAMS is new for v2.11.
* CK_X9_42_DH2_DERIVE_PARAMS provides the parameters to the
* CKM_X9_42_DH_HYBRID_DERIVE and CKM_X9_42_MQV_DERIVE key derivation
* mechanisms, where each party contributes two key pairs */
typedef struct CK_X9_42_DH2_DERIVE_PARAMS {
	CK_X9_42_DH_KDF_TYPE kdf;
	CK_ULONG ulOtherInfoLen;
	CK_BYTE_PTR pOtherInfo;
	CK_ULONG ulPublicDataLen;
	CK_BYTE_PTR pPublicData;
	CK_ULONG ulPrivateDataLen;
	CK_OBJECT_HANDLE hPrivateData;
	CK_ULONG ulPublicDataLen2;
	CK_BYTE_PTR pPublicData2;
} CK_X9_42_DH2_DERIVE_PARAMS;

typedef CK_X9_42_DH2_DERIVE_PARAMS CK_PTR CK_X9_42_DH2_DERIVE_PARAMS_PTR;

typedef struct CK_X9_42_MQV_DERIVE_PARAMS {
	CK_X9_42_DH_KDF_TYPE kdf;
	CK_ULONG ulOtherInfoLen;
	CK_BYTE_PTR pOtherInfo;
	CK_ULONG ulPublicDataLen;
	CK_BYTE_PTR pPublicData;
	CK_ULONG ulPrivateDataLen;
	CK_OBJECT_HANDLE hPrivateData;
	CK_ULONG ulPublicDataLen2;
	CK_BYTE_PTR pPublicData2;
	CK_OBJECT_HANDLE publicKey;
} CK_X9_42_MQV_DERIVE_PARAMS;

typedef CK_X9_42_MQV_DERIVE_PARAMS CK_PTR CK_X9_42_MQV_DERIVE_PARAMS_PTR;

/* CK_KEA_DERIVE_PARAMS provides the parameters to the
* CKM_KEA_DERIVE mechanism */
/* CK_KEA_DERIVE_PARAMS is new for v2.0 */
typedef struct CK_KEA_DERIVE_PARAMS {
	CK_BBOOL      isSender;
	CK_ULONG      ulRandomLen;
	CK_BYTE_PTR   pRandomA;
	CK_BYTE_PTR   pRandomB;
	CK_ULONG      ulPublicDataLen;
	CK_BYTE_PTR   pPublicData;
} CK_KEA_DERIVE_PARAMS;

typedef CK_KEA_DERIVE_PARAMS CK_PTR CK_KEA_DERIVE_PARAMS_PTR;


/* CK_RC2_PARAMS provides the parameters to the CKM_RC2_ECB and
* CKM_RC2_MAC mechanisms.  An instance of CK_RC2_PARAMS just
* holds the effective keysize */
typedef CK_ULONG          CK_RC2_PARAMS;

typedef CK_RC2_PARAMS CK_PTR CK_RC2_PARAMS_PTR;


/* CK_RC2_CBC_PARAMS provides the parameters to the CKM_RC2_CBC
* mechanism */
typedef struct CK_RC2_CBC_PARAMS {
	/* ulEffectiveBits was changed from CK_USHORT to CK_ULONG for
	* v2.0 */
	CK_ULONG      ulEffectiveBits;  /* effective bits (1-1024) */

	CK_BYTE       iv[8];            /* IV for CBC mode */
} CK_RC2_CBC_PARAMS;

typedef CK_RC2_CBC_PARAMS CK_PTR CK_RC2_CBC_PARAMS_PTR;


/* CK_RC2_MAC_GENERAL_PARAMS provides the parameters for the
* CKM_RC2_MAC_GENERAL mechanism */
/* CK_RC2_MAC_GENERAL_PARAMS is new for v2.0 */
typedef struct CK_RC2_MAC_GENERAL_PARAMS {
	CK_ULONG      ulEffectiveBits;  /* effective bits (1-1024) */
	CK_ULONG      ulMacLength;      /* Length of MAC in bytes */
} CK_RC2_MAC_GENERAL_PARAMS;

typedef CK_RC2_MAC_GENERAL_PARAMS CK_PTR \
CK_RC2_MAC_GENERAL_PARAMS_PTR;


/* CK_RC5_PARAMS provides the parameters to the CKM_RC5_ECB and
* CKM_RC5_MAC mechanisms */
/* CK_RC5_PARAMS is new for v2.0 */
typedef struct CK_RC5_PARAMS {
	CK_ULONG      ulWordsize;  /* wordsize in bits */
	CK_ULONG      ulRounds;    /* number of rounds */
} CK_RC5_PARAMS;

typedef CK_RC5_PARAMS CK_PTR CK_RC5_PARAMS_PTR;


/* CK_RC5_CBC_PARAMS provides the parameters to the CKM_RC5_CBC
* mechanism */
/* CK_RC5_CBC_PARAMS is new for v2.0 */
typedef struct CK_RC5_CBC_PARAMS {
	CK_ULONG      ulWordsize;  /* wordsize in bits */
	CK_ULONG      ulRounds;    /* number of rounds */
	CK_BYTE_PTR   pIv;         /* pointer to IV */
	CK_ULONG      ulIvLen;     /* length of IV in bytes */
} CK_RC5_CBC_PARAMS;

typedef CK_RC5_CBC_PARAMS CK_PTR CK_RC5_CBC_PARAMS_PTR;


/* CK_RC5_MAC_GENERAL_PARAMS provides the parameters for the
* CKM_RC5_MAC_GENERAL mechanism */
/* CK_RC5_MAC_GENERAL_PARAMS is new for v2.0 */
typedef struct CK_RC5_MAC_GENERAL_PARAMS {
	CK_ULONG      ulWordsize;   /* wordsize in bits */
	CK_ULONG      ulRounds;     /* number of rounds */
	CK_ULONG      ulMacLength;  /* Length of MAC in bytes */
} CK_RC5_MAC_GENERAL_PARAMS;

typedef CK_RC5_MAC_GENERAL_PARAMS CK_PTR \
CK_RC5_MAC_GENERAL_PARAMS_PTR;


/* CK_MAC_GENERAL_PARAMS provides the parameters to most block
* ciphers' MAC_GENERAL mechanisms.  Its value is the length of
* the MAC */
/* CK_MAC_GENERAL_PARAMS is new for v2.0 */
typedef CK_ULONG          CK_MAC_GENERAL_PARAMS;

typedef CK_MAC_GENERAL_PARAMS CK_PTR CK_MAC_GENERAL_PARAMS_PTR;

/* CK_DES/AES_ECB/CBC_ENCRYPT_DATA_PARAMS are new for v2.20 */
typedef struct CK_DES_CBC_ENCRYPT_DATA_PARAMS {
	CK_BYTE      iv[8];
	CK_BYTE_PTR  pData;
	CK_ULONG     length;
} CK_DES_CBC_ENCRYPT_DATA_PARAMS;

typedef CK_DES_CBC_ENCRYPT_DATA_PARAMS CK_PTR CK_DES_CBC_ENCRYPT_DATA_PARAMS_PTR;

typedef struct CK_AES_CBC_ENCRYPT_DATA_PARAMS {
	CK_BYTE      iv[16];
	CK_BYTE_PTR  pData;
	CK_ULONG     length;
} CK_AES_CBC_ENCRYPT_DATA_PARAMS;

typedef CK_AES_CBC_ENCRYPT_DATA_PARAMS CK_PTR CK_AES_CBC_ENCRYPT_DATA_PARAMS_PTR;

/* CK_SKIPJACK_PRIVATE_WRAP_PARAMS provides the parameters to the
* CKM_SKIPJACK_PRIVATE_WRAP mechanism */
/* CK_SKIPJACK_PRIVATE_WRAP_PARAMS is new for v2.0 */
typedef struct CK_SKIPJACK_PRIVATE_WRAP_PARAMS {
	CK_ULONG      ulPasswordLen;
	CK_BYTE_PTR   pPassword;
	CK_ULONG      ulPublicDataLen;
	CK_BYTE_PTR   pPublicData;
	CK_ULONG      ulPAndGLen;
	CK_ULONG      ulQLen;
	CK_ULONG      ulRandomLen;
	CK_BYTE_PTR   pRandomA;
	CK_BYTE_PTR   pPrimeP;
	CK_BYTE_PTR   pBaseG;
	CK_BYTE_PTR   pSubprimeQ;
} CK_SKIPJACK_PRIVATE_WRAP_PARAMS;

typedef CK_SKIPJACK_PRIVATE_WRAP_PARAMS CK_PTR \
CK_SKIPJACK_PRIVATE_WRAP_PTR;


/* CK_SKIPJACK_RELAYX_PARAMS provides the parameters to the
* CKM_SKIPJACK_RELAYX mechanism */
/* CK_SKIPJACK_RELAYX_PARAMS is new for v2.0 */
typedef struct CK_SKIPJACK_RELAYX_PARAMS {
	CK_ULONG      ulOldWrappedXLen;
	CK_BYTE_PTR   pOldWrappedX;
	CK_ULONG      ulOldPasswordLen;
	CK_BYTE_PTR   pOldPassword;
	CK_ULONG      ulOldPublicDataLen;
	CK_BYTE_PTR   pOldPublicData;
	CK_ULONG      ulOldRandomLen;
	CK_BYTE_PTR   pOldRandomA;
	CK_ULONG      ulNewPasswordLen;
	CK_BYTE_PTR   pNewPassword;
	CK_ULONG      ulNewPublicDataLen;
	CK_BYTE_PTR   pNewPublicData;
	CK_ULONG      ulNewRandomLen;
	CK_BYTE_PTR   pNewRandomA;
} CK_SKIPJACK_RELAYX_PARAMS;

typedef CK_SKIPJACK_RELAYX_PARAMS CK_PTR \
CK_SKIPJACK_RELAYX_PARAMS_PTR;


typedef struct CK_PBE_PARAMS {
	CK_BYTE_PTR      pInitVector;
	CK_UTF8CHAR_PTR  pPassword;
	CK_ULONG         ulPasswordLen;
	CK_BYTE_PTR      pSalt;
	CK_ULONG         ulSaltLen;
	CK_ULONG         ulIteration;
} CK_PBE_PARAMS;

typedef CK_PBE_PARAMS CK_PTR CK_PBE_PARAMS_PTR;


/* CK_KEY_WRAP_SET_OAEP_PARAMS provides the parameters to the
* CKM_KEY_WRAP_SET_OAEP mechanism */
/* CK_KEY_WRAP_SET_OAEP_PARAMS is new for v2.0 */
typedef struct CK_KEY_WRAP_SET_OAEP_PARAMS {
	CK_BYTE       bBC;     /* block contents byte */
	CK_BYTE_PTR   pX;      /* extra data */
	CK_ULONG      ulXLen;  /* length of extra data in bytes */
} CK_KEY_WRAP_SET_OAEP_PARAMS;

typedef CK_KEY_WRAP_SET_OAEP_PARAMS CK_PTR \
CK_KEY_WRAP_SET_OAEP_PARAMS_PTR;


typedef struct CK_SSL3_RANDOM_DATA {
	CK_BYTE_PTR  pClientRandom;
	CK_ULONG     ulClientRandomLen;
	CK_BYTE_PTR  pServerRandom;
	CK_ULONG     ulServerRandomLen;
} CK_SSL3_RANDOM_DATA;


typedef struct CK_SSL3_MASTER_KEY_DERIVE_PARAMS {
	CK_SSL3_RANDOM_DATA RandomInfo;
	CK_VERSION_PTR pVersion;
} CK_SSL3_MASTER_KEY_DERIVE_PARAMS;

typedef struct CK_SSL3_MASTER_KEY_DERIVE_PARAMS CK_PTR \
CK_SSL3_MASTER_KEY_DERIVE_PARAMS_PTR;


typedef struct CK_SSL3_KEY_MAT_OUT {
	CK_OBJECT_HANDLE hClientMacSecret;
	CK_OBJECT_HANDLE hServerMacSecret;
	CK_OBJECT_HANDLE hClientKey;
	CK_OBJECT_HANDLE hServerKey;
	CK_BYTE_PTR      pIVClient;
	CK_BYTE_PTR      pIVServer;
} CK_SSL3_KEY_MAT_OUT;

typedef CK_SSL3_KEY_MAT_OUT CK_PTR CK_SSL3_KEY_MAT_OUT_PTR;


typedef struct CK_SSL3_KEY_MAT_PARAMS {
	CK_ULONG                ulMacSizeInBits;
	CK_ULONG                ulKeySizeInBits;
	CK_ULONG                ulIVSizeInBits;
	CK_BBOOL                bIsExport;
	CK_SSL3_RANDOM_DATA     RandomInfo;
	CK_SSL3_KEY_MAT_OUT_PTR pReturnedKeyMaterial;
} CK_SSL3_KEY_MAT_PARAMS;

typedef CK_SSL3_KEY_MAT_PARAMS CK_PTR CK_SSL3_KEY_MAT_PARAMS_PTR;

/* CK_TLS_PRF_PARAMS is new for version 2.20 */
typedef struct CK_TLS_PRF_PARAMS {
	CK_BYTE_PTR  pSeed;
	CK_ULONG     ulSeedLen;
	CK_BYTE_PTR  pLabel;
	CK_ULONG     ulLabelLen;
	CK_BYTE_PTR  pOutput;
	CK_ULONG_PTR pulOutputLen;
} CK_TLS_PRF_PARAMS;

typedef CK_TLS_PRF_PARAMS CK_PTR CK_TLS_PRF_PARAMS_PTR;

/* WTLS is new for version 2.20 */
typedef struct CK_WTLS_RANDOM_DATA {
	CK_BYTE_PTR pClientRandom;
	CK_ULONG    ulClientRandomLen;
	CK_BYTE_PTR pServerRandom;
	CK_ULONG    ulServerRandomLen;
} CK_WTLS_RANDOM_DATA;

typedef CK_WTLS_RANDOM_DATA CK_PTR CK_WTLS_RANDOM_DATA_PTR;

typedef struct CK_WTLS_MASTER_KEY_DERIVE_PARAMS {
	CK_MECHANISM_TYPE   DigestMechanism;
	CK_WTLS_RANDOM_DATA RandomInfo;
	CK_BYTE_PTR         pVersion;
} CK_WTLS_MASTER_KEY_DERIVE_PARAMS;

typedef CK_WTLS_MASTER_KEY_DERIVE_PARAMS CK_PTR \
CK_WTLS_MASTER_KEY_DERIVE_PARAMS_PTR;

typedef struct CK_WTLS_PRF_PARAMS {
	CK_MECHANISM_TYPE DigestMechanism;
	CK_BYTE_PTR       pSeed;
	CK_ULONG          ulSeedLen;
	CK_BYTE_PTR       pLabel;
	CK_ULONG          ulLabelLen;
	CK_BYTE_PTR       pOutput;
	CK_ULONG_PTR      pulOutputLen;
} CK_WTLS_PRF_PARAMS;

typedef CK_WTLS_PRF_PARAMS CK_PTR CK_WTLS_PRF_PARAMS_PTR;

typedef struct CK_WTLS_KEY_MAT_OUT {
	CK_OBJECT_HANDLE hMacSecret;
	CK_OBJECT_HANDLE hKey;
	CK_BYTE_PTR      pIV;
} CK_WTLS_KEY_MAT_OUT;

typedef CK_WTLS_KEY_MAT_OUT CK_PTR CK_WTLS_KEY_MAT_OUT_PTR;

typedef struct CK_WTLS_KEY_MAT_PARAMS {
	CK_MECHANISM_TYPE       DigestMechanism;
	CK_ULONG                ulMacSizeInBits;
	CK_ULONG                ulKeySizeInBits;
	CK_ULONG                ulIVSizeInBits;
	CK_ULONG                ulSequenceNumber;
	CK_BBOOL                bIsExport;
	CK_WTLS_RANDOM_DATA     RandomInfo;
	CK_WTLS_KEY_MAT_OUT_PTR pReturnedKeyMaterial;
} CK_WTLS_KEY_MAT_PARAMS;

typedef CK_WTLS_KEY_MAT_PARAMS CK_PTR CK_WTLS_KEY_MAT_PARAMS_PTR;

/* CMS is new for version 2.20 */
typedef struct CK_CMS_SIG_PARAMS {
	CK_OBJECT_HANDLE      certificateHandle;
	CK_MECHANISM_PTR      pSigningMechanism;
	CK_MECHANISM_PTR      pDigestMechanism;
	CK_UTF8CHAR_PTR       pContentType;
	CK_BYTE_PTR           pRequestedAttributes;
	CK_ULONG              ulRequestedAttributesLen;
	CK_BYTE_PTR           pRequiredAttributes;
	CK_ULONG              ulRequiredAttributesLen;
} CK_CMS_SIG_PARAMS;

typedef CK_CMS_SIG_PARAMS CK_PTR CK_CMS_SIG_PARAMS_PTR;

typedef struct CK_KEY_DERIVATION_STRING_DATA {
	CK_BYTE_PTR pData;
	CK_ULONG    ulLen;
} CK_KEY_DERIVATION_STRING_DATA;

typedef CK_KEY_DERIVATION_STRING_DATA CK_PTR \
CK_KEY_DERIVATION_STRING_DATA_PTR;


/* The CK_EXTRACT_PARAMS is used for the
* CKM_EXTRACT_KEY_FROM_KEY mechanism.  It specifies which bit
* of the base key should be used as the first bit of the
* derived key */
/* CK_EXTRACT_PARAMS is new for v2.0 */
typedef CK_ULONG CK_EXTRACT_PARAMS;

typedef CK_EXTRACT_PARAMS CK_PTR CK_EXTRACT_PARAMS_PTR;

/* CK_PKCS5_PBKD2_PSEUDO_RANDOM_FUNCTION_TYPE is new for v2.10.
* CK_PKCS5_PBKD2_PSEUDO_RANDOM_FUNCTION_TYPE is used to
* indicate the Pseudo-Random Function (PRF) used to generate
* key bits using PKCS #5 PBKDF2. */
typedef CK_ULONG CK_PKCS5_PBKD2_PSEUDO_RANDOM_FUNCTION_TYPE;

typedef CK_PKCS5_PBKD2_PSEUDO_RANDOM_FUNCTION_TYPE CK_PTR CK_PKCS5_PBKD2_PSEUDO_RANDOM_FUNCTION_TYPE_PTR;

/* The following PRFs are defined in PKCS #5 v2.0. */
#define CKP_PKCS5_PBKD2_HMAC_SHA1 0x00000001


/* CK_PKCS5_PBKDF2_SALT_SOURCE_TYPE is new for v2.10.
* CK_PKCS5_PBKDF2_SALT_SOURCE_TYPE is used to indicate the
* source of the salt value when deriving a key using PKCS #5
* PBKDF2. */
typedef CK_ULONG CK_PKCS5_PBKDF2_SALT_SOURCE_TYPE;

typedef CK_PKCS5_PBKDF2_SALT_SOURCE_TYPE CK_PTR CK_PKCS5_PBKDF2_SALT_SOURCE_TYPE_PTR;

/* The following salt value sources are defined in PKCS #5 v2.0. */
#define CKZ_SALT_SPECIFIED        0x00000001

/* CK_PKCS5_PBKD2_PARAMS is new for v2.10.
* CK_PKCS5_PBKD2_PARAMS is a structure that provides the
* parameters to the CKM_PKCS5_PBKD2 mechanism. */
typedef struct CK_PKCS5_PBKD2_PARAMS {
	CK_PKCS5_PBKDF2_SALT_SOURCE_TYPE           saltSource;
	CK_VOID_PTR                                pSaltSourceData;
	CK_ULONG                                   ulSaltSourceDataLen;
	CK_ULONG                                   iterations;
	CK_PKCS5_PBKD2_PSEUDO_RANDOM_FUNCTION_TYPE prf;
	CK_VOID_PTR                                pPrfData;
	CK_ULONG                                   ulPrfDataLen;
	CK_UTF8CHAR_PTR                            pPassword;
	CK_ULONG_PTR                               ulPasswordLen;
} CK_PKCS5_PBKD2_PARAMS;

typedef CK_PKCS5_PBKD2_PARAMS CK_PTR CK_PKCS5_PBKD2_PARAMS_PTR;

/* All CK_OTP structs are new for PKCS #11 v2.20 amendment 3 */

typedef CK_ULONG CK_OTP_PARAM_TYPE;
typedef CK_OTP_PARAM_TYPE CK_PARAM_TYPE; /* B/w compatibility */

typedef struct CK_OTP_PARAM {
	CK_OTP_PARAM_TYPE type;
	CK_VOID_PTR pValue;
	CK_ULONG ulValueLen;
} CK_OTP_PARAM;

typedef CK_OTP_PARAM CK_PTR CK_OTP_PARAM_PTR;

typedef struct CK_OTP_PARAMS {
	CK_OTP_PARAM_PTR pParams;
	CK_ULONG ulCount;
} CK_OTP_PARAMS;

typedef CK_OTP_PARAMS CK_PTR CK_OTP_PARAMS_PTR;

typedef struct CK_OTP_SIGNATURE_INFO {
	CK_OTP_PARAM_PTR pParams;
	CK_ULONG ulCount;
} CK_OTP_SIGNATURE_INFO;

typedef CK_OTP_SIGNATURE_INFO CK_PTR CK_OTP_SIGNATURE_INFO_PTR;

/* The following OTP-related defines are new for PKCS #11 v2.20 amendment 1 */
#define CK_OTP_VALUE          0
#define CK_OTP_PIN            1
#define CK_OTP_CHALLENGE      2
#define CK_OTP_TIME           3
#define CK_OTP_COUNTER        4
#define CK_OTP_FLAGS          5
#define CK_OTP_OUTPUT_LENGTH  6
#define CK_OTP_OUTPUT_FORMAT  7

/* The following OTP-related defines are new for PKCS #11 v2.20 amendment 1 */
#define CKF_NEXT_OTP          0x00000001
#define CKF_EXCLUDE_TIME      0x00000002
#define CKF_EXCLUDE_COUNTER   0x00000004
#define CKF_EXCLUDE_CHALLENGE 0x00000008
#define CKF_EXCLUDE_PIN       0x00000010
#define CKF_USER_FRIENDLY_OTP 0x00000020

/* CK_KIP_PARAMS is new for PKCS #11 v2.20 amendment 2 */
typedef struct CK_KIP_PARAMS {
	CK_MECHANISM_PTR  pMechanism;
	CK_OBJECT_HANDLE  hKey;
	CK_BYTE_PTR       pSeed;
	CK_ULONG          ulSeedLen;
} CK_KIP_PARAMS;

typedef CK_KIP_PARAMS CK_PTR CK_KIP_PARAMS_PTR;

/* CK_AES_CTR_PARAMS is new for PKCS #11 v2.20 amendment 3 */
typedef struct CK_AES_CTR_PARAMS {
	CK_ULONG ulCounterBits;
	CK_BYTE cb[16];
} CK_AES_CTR_PARAMS;

typedef CK_AES_CTR_PARAMS CK_PTR CK_AES_CTR_PARAMS_PTR;

/* CK_CAMELLIA_CTR_PARAMS is new for PKCS #11 v2.20 amendment 3 */
typedef struct CK_CAMELLIA_CTR_PARAMS {
	CK_ULONG ulCounterBits;
	CK_BYTE cb[16];
} CK_CAMELLIA_CTR_PARAMS;

typedef CK_CAMELLIA_CTR_PARAMS CK_PTR CK_CAMELLIA_CTR_PARAMS_PTR;

/* CK_CAMELLIA_CBC_ENCRYPT_DATA_PARAMS is new for PKCS #11 v2.20 amendment 3 */
typedef struct CK_CAMELLIA_CBC_ENCRYPT_DATA_PARAMS {
	CK_BYTE      iv[16];
	CK_BYTE_PTR  pData;
	CK_ULONG     length;
} CK_CAMELLIA_CBC_ENCRYPT_DATA_PARAMS;

typedef CK_CAMELLIA_CBC_ENCRYPT_DATA_PARAMS CK_PTR CK_CAMELLIA_CBC_ENCRYPT_DATA_PARAMS_PTR;

/* CK_ARIA_CBC_ENCRYPT_DATA_PARAMS is new for PKCS #11 v2.20 amendment 3 */
typedef struct CK_ARIA_CBC_ENCRYPT_DATA_PARAMS {
	CK_BYTE      iv[16];
	CK_BYTE_PTR  pData;
	CK_ULONG     length;
} CK_ARIA_CBC_ENCRYPT_DATA_PARAMS;

typedef CK_ARIA_CBC_ENCRYPT_DATA_PARAMS CK_PTR CK_ARIA_CBC_ENCRYPT_DATA_PARAMS_PTR;

#endif

/************************************************************************/
/*
	end of
	#include "pkcs11t.h"
	darpangs
*/
/************************************************************************/

#define __PASTE(x,y)      x##y


	/* ==============================================================
	* Define the "extern" form of all the entry points.
	* ==============================================================
	*/

#define CK_NEED_ARG_LIST  1
#define CK_PKCS11_FUNCTION_INFO(name) \
	extern CK_DECLARE_FUNCTION(CK_RV, name)

	/* pkcs11f.h has all the information about the Cryptoki
	* function prototypes. */
/************************************************************************/
/*
	#include "pkcs11f.h"
	darpangs
*/
/************************************************************************/
/* pkcs11f.h include file for PKCS #11. */
/* $Revision: 1.4 $ */
/* General-purpose */

/* C_Initialize initializes the Cryptoki library. */
CK_PKCS11_FUNCTION_INFO(C_Initialize)
#ifdef CK_NEED_ARG_LIST
(
 CK_VOID_PTR   pInitArgs  /* if this is not NULL_PTR, it gets
						  * cast to CK_C_INITIALIZE_ARGS_PTR
						  * and dereferenced */
						  );
#endif


/* C_Finalize indicates that an application is done with the
* Cryptoki library. */
CK_PKCS11_FUNCTION_INFO(C_Finalize)
#ifdef CK_NEED_ARG_LIST
(
 CK_VOID_PTR   pReserved  /* reserved.  Should be NULL_PTR */
 );
#endif


/* C_GetInfo returns general information about Cryptoki. */
CK_PKCS11_FUNCTION_INFO(C_GetInfo)
#ifdef CK_NEED_ARG_LIST
(
 CK_INFO_PTR   pInfo  /* location that receives information */
 );
#endif


/* C_GetFunctionList returns the function list. */
CK_PKCS11_FUNCTION_INFO(C_GetFunctionList)
#ifdef CK_NEED_ARG_LIST
(
 CK_FUNCTION_LIST_PTR_PTR ppFunctionList  /* receives pointer to
										  * function list */
										  );
#endif



/* Slot and token management */

/* C_GetSlotList obtains a list of slots in the system. */
CK_PKCS11_FUNCTION_INFO(C_GetSlotList)
#ifdef CK_NEED_ARG_LIST
(
 CK_BBOOL       tokenPresent,  /* only slots with tokens? */
 CK_SLOT_ID_PTR pSlotList,     /* receives array of slot IDs */
 CK_ULONG_PTR   pulCount       /* receives number of slots */
 );
#endif


/* C_GetSlotInfo obtains information about a particular slot in
* the system. */
CK_PKCS11_FUNCTION_INFO(C_GetSlotInfo)
#ifdef CK_NEED_ARG_LIST
(
 CK_SLOT_ID       slotID,  /* the ID of the slot */
 CK_SLOT_INFO_PTR pInfo    /* receives the slot information */
 );
#endif


/* C_GetTokenInfo obtains information about a particular token
* in the system. */
CK_PKCS11_FUNCTION_INFO(C_GetTokenInfo)
#ifdef CK_NEED_ARG_LIST
(
 CK_SLOT_ID        slotID,  /* ID of the token's slot */
 CK_TOKEN_INFO_PTR pInfo    /* receives the token information */
 );
#endif


/* C_GetMechanismList obtains a list of mechanism types
* supported by a token. */
CK_PKCS11_FUNCTION_INFO(C_GetMechanismList)
#ifdef CK_NEED_ARG_LIST
(
 CK_SLOT_ID            slotID,          /* ID of token's slot */
 CK_MECHANISM_TYPE_PTR pMechanismList,  /* gets mech. array */
 CK_ULONG_PTR          pulCount         /* gets # of mechs. */
 );
#endif


/* C_GetMechanismInfo obtains information about a particular
* mechanism possibly supported by a token. */
CK_PKCS11_FUNCTION_INFO(C_GetMechanismInfo)
#ifdef CK_NEED_ARG_LIST
(
 CK_SLOT_ID            slotID,  /* ID of the token's slot */
 CK_MECHANISM_TYPE     type,    /* type of mechanism */
 CK_MECHANISM_INFO_PTR pInfo    /* receives mechanism info */
 );
#endif


/* C_InitToken initializes a token. */
CK_PKCS11_FUNCTION_INFO(C_InitToken)
#ifdef CK_NEED_ARG_LIST
/* pLabel changed from CK_CHAR_PTR to CK_UTF8CHAR_PTR for v2.10 */
(
 CK_SLOT_ID      slotID,    /* ID of the token's slot */
 CK_UTF8CHAR_PTR pPin,      /* the SO's initial PIN */
 CK_ULONG        ulPinLen,  /* length in bytes of the PIN */
 CK_UTF8CHAR_PTR pLabel     /* 32-byte token label (blank padded) */
 );
#endif


/* C_InitPIN initializes the normal user's PIN. */
CK_PKCS11_FUNCTION_INFO(C_InitPIN)
#ifdef CK_NEED_ARG_LIST
(
 CK_SESSION_HANDLE hSession,  /* the session's handle */
 CK_UTF8CHAR_PTR   pPin,      /* the normal user's PIN */
 CK_ULONG          ulPinLen   /* length in bytes of the PIN */
 );
#endif


/* C_SetPIN modifies the PIN of the user who is logged in. */
CK_PKCS11_FUNCTION_INFO(C_SetPIN)
#ifdef CK_NEED_ARG_LIST
(
 CK_SESSION_HANDLE hSession,  /* the session's handle */
 CK_UTF8CHAR_PTR   pOldPin,   /* the old PIN */
 CK_ULONG          ulOldLen,  /* length of the old PIN */
 CK_UTF8CHAR_PTR   pNewPin,   /* the new PIN */
 CK_ULONG          ulNewLen   /* length of the new PIN */
 );
#endif



/* Session management */

/* C_OpenSession opens a session between an application and a
* token. */
CK_PKCS11_FUNCTION_INFO(C_OpenSession)
#ifdef CK_NEED_ARG_LIST
(
 CK_SLOT_ID            slotID,        /* the slot's ID */
 CK_FLAGS              flags,         /* from CK_SESSION_INFO */
 CK_VOID_PTR           pApplication,  /* passed to callback */
 CK_NOTIFY             Notify,        /* callback function */
 CK_SESSION_HANDLE_PTR phSession      /* gets session handle */
 );
#endif


/* C_CloseSession closes a session between an application and a
* token. */
CK_PKCS11_FUNCTION_INFO(C_CloseSession)
#ifdef CK_NEED_ARG_LIST
(
 CK_SESSION_HANDLE hSession  /* the session's handle */
 );
#endif


/* C_CloseAllSessions closes all sessions with a token. */
CK_PKCS11_FUNCTION_INFO(C_CloseAllSessions)
#ifdef CK_NEED_ARG_LIST
(
 CK_SLOT_ID     slotID  /* the token's slot */
 );
#endif


/* C_GetSessionInfo obtains information about the session. */
CK_PKCS11_FUNCTION_INFO(C_GetSessionInfo)
#ifdef CK_NEED_ARG_LIST
(
 CK_SESSION_HANDLE   hSession,  /* the session's handle */
 CK_SESSION_INFO_PTR pInfo      /* receives session info */
 );
#endif


/* C_GetOperationState obtains the state of the cryptographic operation
* in a session. */
CK_PKCS11_FUNCTION_INFO(C_GetOperationState)
#ifdef CK_NEED_ARG_LIST
(
 CK_SESSION_HANDLE hSession,             /* session's handle */
 CK_BYTE_PTR       pOperationState,      /* gets state */
 CK_ULONG_PTR      pulOperationStateLen  /* gets state length */
 );
#endif


/* C_SetOperationState restores the state of the cryptographic
* operation in a session. */
CK_PKCS11_FUNCTION_INFO(C_SetOperationState)
#ifdef CK_NEED_ARG_LIST
(
 CK_SESSION_HANDLE hSession,            /* session's handle */
 CK_BYTE_PTR      pOperationState,      /* holds state */
 CK_ULONG         ulOperationStateLen,  /* holds state length */
 CK_OBJECT_HANDLE hEncryptionKey,       /* en/decryption key */
 CK_OBJECT_HANDLE hAuthenticationKey    /* sign/verify key */
 );
#endif


/* C_Login logs a user into a token. */
CK_PKCS11_FUNCTION_INFO(C_Login)
#ifdef CK_NEED_ARG_LIST
(
 CK_SESSION_HANDLE hSession,  /* the session's handle */
 CK_USER_TYPE      userType,  /* the user type */
 CK_UTF8CHAR_PTR   pPin,      /* the user's PIN */
 CK_ULONG          ulPinLen   /* the length of the PIN */
 );
#endif


/* C_Logout logs a user out from a token. */
CK_PKCS11_FUNCTION_INFO(C_Logout)
#ifdef CK_NEED_ARG_LIST
(
 CK_SESSION_HANDLE hSession  /* the session's handle */
 );
#endif

CK_PKCS11_FUNCTION_INFO(C_LoginBegin)
#ifdef CK_NEED_ARG_LIST
(
  CK_SESSION_HANDLE hSession,  /* the session's handle */
  CK_USER_TYPE      userType,  /* the user type */
  CK_ULONG_PTR      pulK,      /* cards required to load logical token. */
  CK_ULONG_PTR      pulN       /* Number of cards in set */
);
#endif

/* C_LoginNext logs a user into a token. */
CK_PKCS11_FUNCTION_INFO(C_LoginNext)
#ifdef CK_NEED_ARG_LIST
(
  CK_SESSION_HANDLE hSession,  /* the session's handle */
  CK_USER_TYPE      userType,  /* the user type */
  CK_CHAR_PTR       pPin,      /* the user's PIN */
  CK_ULONG          ulPinLen,   /* the length of the PIN */
  CK_ULONG_PTR      pulSharesLeft /* Number of remaining shares */
);
#endif

/* C_LoginEnd logs a user into a token. */
CK_PKCS11_FUNCTION_INFO(C_LoginEnd)
#ifdef CK_NEED_ARG_LIST
(
  CK_SESSION_HANDLE hSession,  /* the session's handle */
  CK_USER_TYPE      userType  /* the user type */
);
#endif


/* Object management */

/* C_CreateObject creates a new object. */
CK_PKCS11_FUNCTION_INFO(C_CreateObject)
#ifdef CK_NEED_ARG_LIST
(
 CK_SESSION_HANDLE hSession,    /* the session's handle */
 CK_ATTRIBUTE_PTR  pTemplate,   /* the object's template */
 CK_ULONG          ulCount,     /* attributes in template */
 CK_OBJECT_HANDLE_PTR phObject  /* gets new object's handle. */
 );
#endif


/* C_CopyObject copies an object, creating a new object for the
* copy. */
CK_PKCS11_FUNCTION_INFO(C_CopyObject)
#ifdef CK_NEED_ARG_LIST
(
 CK_SESSION_HANDLE    hSession,    /* the session's handle */
 CK_OBJECT_HANDLE     hObject,     /* the object's handle */
 CK_ATTRIBUTE_PTR     pTemplate,   /* template for new object */
 CK_ULONG             ulCount,     /* attributes in template */
 CK_OBJECT_HANDLE_PTR phNewObject  /* receives handle of copy */
 );
#endif


/* C_DestroyObject destroys an object. */
CK_PKCS11_FUNCTION_INFO(C_DestroyObject)
#ifdef CK_NEED_ARG_LIST
(
 CK_SESSION_HANDLE hSession,  /* the session's handle */
 CK_OBJECT_HANDLE  hObject    /* the object's handle */
 );
#endif


/* C_GetObjectSize gets the size of an object in bytes. */
CK_PKCS11_FUNCTION_INFO(C_GetObjectSize)
#ifdef CK_NEED_ARG_LIST
(
 CK_SESSION_HANDLE hSession,  /* the session's handle */
 CK_OBJECT_HANDLE  hObject,   /* the object's handle */
 CK_ULONG_PTR      pulSize    /* receives size of object */
 );
#endif


/* C_GetAttributeValue obtains the value of one or more object
* attributes. */
CK_PKCS11_FUNCTION_INFO(C_GetAttributeValue)
#ifdef CK_NEED_ARG_LIST
(
 CK_SESSION_HANDLE hSession,   /* the session's handle */
 CK_OBJECT_HANDLE  hObject,    /* the object's handle */
 CK_ATTRIBUTE_PTR  pTemplate,  /* specifies attrs; gets vals */
 CK_ULONG          ulCount     /* attributes in template */
 );
#endif


/* C_SetAttributeValue modifies the value of one or more object
* attributes */
CK_PKCS11_FUNCTION_INFO(C_SetAttributeValue)
#ifdef CK_NEED_ARG_LIST
(
 CK_SESSION_HANDLE hSession,   /* the session's handle */
 CK_OBJECT_HANDLE  hObject,    /* the object's handle */
 CK_ATTRIBUTE_PTR  pTemplate,  /* specifies attrs and values */
 CK_ULONG          ulCount     /* attributes in template */
 );
#endif


/* C_FindObjectsInit initializes a search for token and session
* objects that match a template. */
CK_PKCS11_FUNCTION_INFO(C_FindObjectsInit)
#ifdef CK_NEED_ARG_LIST
(
 CK_SESSION_HANDLE hSession,   /* the session's handle */
 CK_ATTRIBUTE_PTR  pTemplate,  /* attribute values to match */
 CK_ULONG          ulCount     /* attrs in search template */
 );
#endif


/* C_FindObjects continues a search for token and session
* objects that match a template, obtaining additional object
* handles. */
CK_PKCS11_FUNCTION_INFO(C_FindObjects)
#ifdef CK_NEED_ARG_LIST
(
 CK_SESSION_HANDLE    hSession,          /* session's handle */
 CK_OBJECT_HANDLE_PTR phObject,          /* gets obj. handles */
 CK_ULONG             ulMaxObjectCount,  /* max handles to get */
 CK_ULONG_PTR         pulObjectCount     /* actual # returned */
 );
#endif


/* C_FindObjectsFinal finishes a search for token and session
* objects. */
CK_PKCS11_FUNCTION_INFO(C_FindObjectsFinal)
#ifdef CK_NEED_ARG_LIST
(
 CK_SESSION_HANDLE hSession  /* the session's handle */
 );
#endif



/* Encryption and decryption */

/* C_EncryptInit initializes an encryption operation. */
CK_PKCS11_FUNCTION_INFO(C_EncryptInit)
#ifdef CK_NEED_ARG_LIST
(
 CK_SESSION_HANDLE hSession,    /* the session's handle */
 CK_MECHANISM_PTR  pMechanism,  /* the encryption mechanism */
 CK_OBJECT_HANDLE  hKey         /* handle of encryption key */
 );
#endif


/* C_Encrypt encrypts single-part data. */
CK_PKCS11_FUNCTION_INFO(C_Encrypt)
#ifdef CK_NEED_ARG_LIST
(
 CK_SESSION_HANDLE hSession,            /* session's handle */
 CK_BYTE_PTR       pData,               /* the plaintext data */
 CK_ULONG          ulDataLen,           /* bytes of plaintext */
 CK_BYTE_PTR       pEncryptedData,      /* gets ciphertext */
 CK_ULONG_PTR      pulEncryptedDataLen  /* gets c-text size */
 );
#endif


/* C_EncryptUpdate continues a multiple-part encryption
* operation. */
CK_PKCS11_FUNCTION_INFO(C_EncryptUpdate)
#ifdef CK_NEED_ARG_LIST
(
 CK_SESSION_HANDLE hSession,           /* session's handle */
 CK_BYTE_PTR       pPart,              /* the plaintext data */
 CK_ULONG          ulPartLen,          /* plaintext data len */
 CK_BYTE_PTR       pEncryptedPart,     /* gets ciphertext */
 CK_ULONG_PTR      pulEncryptedPartLen /* gets c-text size */
 );
#endif


/* C_EncryptFinal finishes a multiple-part encryption
* operation. */
CK_PKCS11_FUNCTION_INFO(C_EncryptFinal)
#ifdef CK_NEED_ARG_LIST
(
 CK_SESSION_HANDLE hSession,                /* session handle */
 CK_BYTE_PTR       pLastEncryptedPart,      /* last c-text */
 CK_ULONG_PTR      pulLastEncryptedPartLen  /* gets last size */
 );
#endif


/* C_DecryptInit initializes a decryption operation. */
CK_PKCS11_FUNCTION_INFO(C_DecryptInit)
#ifdef CK_NEED_ARG_LIST
(
 CK_SESSION_HANDLE hSession,    /* the session's handle */
 CK_MECHANISM_PTR  pMechanism,  /* the decryption mechanism */
 CK_OBJECT_HANDLE  hKey         /* handle of decryption key */
 );
#endif


/* C_Decrypt decrypts encrypted data in a single part. */
CK_PKCS11_FUNCTION_INFO(C_Decrypt)
#ifdef CK_NEED_ARG_LIST
(
 CK_SESSION_HANDLE hSession,           /* session's handle */
 CK_BYTE_PTR       pEncryptedData,     /* ciphertext */
 CK_ULONG          ulEncryptedDataLen, /* ciphertext length */
 CK_BYTE_PTR       pData,              /* gets plaintext */
 CK_ULONG_PTR      pulDataLen          /* gets p-text size */
 );
#endif


/* C_DecryptUpdate continues a multiple-part decryption
* operation. */
CK_PKCS11_FUNCTION_INFO(C_DecryptUpdate)
#ifdef CK_NEED_ARG_LIST
(
 CK_SESSION_HANDLE hSession,            /* session's handle */
 CK_BYTE_PTR       pEncryptedPart,      /* encrypted data */
 CK_ULONG          ulEncryptedPartLen,  /* input length */
 CK_BYTE_PTR       pPart,               /* gets plaintext */
 CK_ULONG_PTR      pulPartLen           /* p-text size */
 );
#endif


/* C_DecryptFinal finishes a multiple-part decryption
* operation. */
CK_PKCS11_FUNCTION_INFO(C_DecryptFinal)
#ifdef CK_NEED_ARG_LIST
(
 CK_SESSION_HANDLE hSession,       /* the session's handle */
 CK_BYTE_PTR       pLastPart,      /* gets plaintext */
 CK_ULONG_PTR      pulLastPartLen  /* p-text size */
 );
#endif



/* Message digesting */

/* C_DigestInit initializes a message-digesting operation. */
CK_PKCS11_FUNCTION_INFO(C_DigestInit)
#ifdef CK_NEED_ARG_LIST
(
 CK_SESSION_HANDLE hSession,   /* the session's handle */
 CK_MECHANISM_PTR  pMechanism  /* the digesting mechanism */
 );
#endif


/* C_Digest digests data in a single part. */
CK_PKCS11_FUNCTION_INFO(C_Digest)
#ifdef CK_NEED_ARG_LIST
(
 CK_SESSION_HANDLE hSession,     /* the session's handle */
 CK_BYTE_PTR       pData,        /* data to be digested */
 CK_ULONG          ulDataLen,    /* bytes of data to digest */
 CK_BYTE_PTR       pDigest,      /* gets the message digest */
 CK_ULONG_PTR      pulDigestLen  /* gets digest length */
 );
#endif


/* C_DigestUpdate continues a multiple-part message-digesting
* operation. */
CK_PKCS11_FUNCTION_INFO(C_DigestUpdate)
#ifdef CK_NEED_ARG_LIST
(
 CK_SESSION_HANDLE hSession,  /* the session's handle */
 CK_BYTE_PTR       pPart,     /* data to be digested */
 CK_ULONG          ulPartLen  /* bytes of data to be digested */
 );
#endif


/* C_DigestKey continues a multi-part message-digesting
* operation, by digesting the value of a secret key as part of
* the data already digested. */
CK_PKCS11_FUNCTION_INFO(C_DigestKey)
#ifdef CK_NEED_ARG_LIST
(
 CK_SESSION_HANDLE hSession,  /* the session's handle */
 CK_OBJECT_HANDLE  hKey       /* secret key to digest */
 );
#endif


/* C_DigestFinal finishes a multiple-part message-digesting
* operation. */
CK_PKCS11_FUNCTION_INFO(C_DigestFinal)
#ifdef CK_NEED_ARG_LIST
(
 CK_SESSION_HANDLE hSession,     /* the session's handle */
 CK_BYTE_PTR       pDigest,      /* gets the message digest */
 CK_ULONG_PTR      pulDigestLen  /* gets byte count of digest */
 );
#endif



/* Signing and MACing */

/* C_SignInit initializes a signature (private key encryption)
* operation, where the signature is (will be) an appendix to
* the data, and plaintext cannot be recovered from the
*signature. */
CK_PKCS11_FUNCTION_INFO(C_SignInit)
#ifdef CK_NEED_ARG_LIST
(
 CK_SESSION_HANDLE hSession,    /* the session's handle */
 CK_MECHANISM_PTR  pMechanism,  /* the signature mechanism */
 CK_OBJECT_HANDLE  hKey         /* handle of signature key */
 );
#endif


/* C_Sign signs (encrypts with private key) data in a single
* part, where the signature is (will be) an appendix to the
* data, and plaintext cannot be recovered from the signature. */
CK_PKCS11_FUNCTION_INFO(C_Sign)
#ifdef CK_NEED_ARG_LIST
(
 CK_SESSION_HANDLE hSession,        /* the session's handle */
 CK_BYTE_PTR       pData,           /* the data to sign */
 CK_ULONG          ulDataLen,       /* count of bytes to sign */
 CK_BYTE_PTR       pSignature,      /* gets the signature */
 CK_ULONG_PTR      pulSignatureLen  /* gets signature length */
 );
#endif


/* C_SignUpdate continues a multiple-part signature operation,
* where the signature is (will be) an appendix to the data,
* and plaintext cannot be recovered from the signature. */
CK_PKCS11_FUNCTION_INFO(C_SignUpdate)
#ifdef CK_NEED_ARG_LIST
(
 CK_SESSION_HANDLE hSession,  /* the session's handle */
 CK_BYTE_PTR       pPart,     /* the data to sign */
 CK_ULONG          ulPartLen  /* count of bytes to sign */
 );
#endif


/* C_SignFinal finishes a multiple-part signature operation,
* returning the signature. */
CK_PKCS11_FUNCTION_INFO(C_SignFinal)
#ifdef CK_NEED_ARG_LIST
(
 CK_SESSION_HANDLE hSession,        /* the session's handle */
 CK_BYTE_PTR       pSignature,      /* gets the signature */
 CK_ULONG_PTR      pulSignatureLen  /* gets signature length */
 );
#endif


/* C_SignRecoverInit initializes a signature operation, where
* the data can be recovered from the signature. */
CK_PKCS11_FUNCTION_INFO(C_SignRecoverInit)
#ifdef CK_NEED_ARG_LIST
(
 CK_SESSION_HANDLE hSession,   /* the session's handle */
 CK_MECHANISM_PTR  pMechanism, /* the signature mechanism */
 CK_OBJECT_HANDLE  hKey        /* handle of the signature key */
 );
#endif


/* C_SignRecover signs data in a single operation, where the
* data can be recovered from the signature. */
CK_PKCS11_FUNCTION_INFO(C_SignRecover)
#ifdef CK_NEED_ARG_LIST
(
 CK_SESSION_HANDLE hSession,        /* the session's handle */
 CK_BYTE_PTR       pData,           /* the data to sign */
 CK_ULONG          ulDataLen,       /* count of bytes to sign */
 CK_BYTE_PTR       pSignature,      /* gets the signature */
 CK_ULONG_PTR      pulSignatureLen  /* gets signature length */
 );
#endif



/* Verifying signatures and MACs */

/* C_VerifyInit initializes a verification operation, where the
* signature is an appendix to the data, and plaintext cannot
*  cannot be recovered from the signature (e.g. ISC_DSA). */
CK_PKCS11_FUNCTION_INFO(C_VerifyInit)
#ifdef CK_NEED_ARG_LIST
(
 CK_SESSION_HANDLE hSession,    /* the session's handle */
 CK_MECHANISM_PTR  pMechanism,  /* the verification mechanism */
 CK_OBJECT_HANDLE  hKey         /* verification key */
 );
#endif


/* C_Verify verifies a signature in a single-part operation,
* where the signature is an appendix to the data, and plaintext
* cannot be recovered from the signature. */
CK_PKCS11_FUNCTION_INFO(C_Verify)
#ifdef CK_NEED_ARG_LIST
(
 CK_SESSION_HANDLE hSession,       /* the session's handle */
 CK_BYTE_PTR       pData,          /* signed data */
 CK_ULONG          ulDataLen,      /* length of signed data */
 CK_BYTE_PTR       pSignature,     /* signature */
 CK_ULONG          ulSignatureLen  /* signature length*/
 );
#endif


/* C_VerifyUpdate continues a multiple-part verification
* operation, where the signature is an appendix to the data,
* and plaintext cannot be recovered from the signature. */
CK_PKCS11_FUNCTION_INFO(C_VerifyUpdate)
#ifdef CK_NEED_ARG_LIST
(
 CK_SESSION_HANDLE hSession,  /* the session's handle */
 CK_BYTE_PTR       pPart,     /* signed data */
 CK_ULONG          ulPartLen  /* length of signed data */
 );
#endif


/* C_VerifyFinal finishes a multiple-part verification
* operation, checking the signature. */
CK_PKCS11_FUNCTION_INFO(C_VerifyFinal)
#ifdef CK_NEED_ARG_LIST
(
 CK_SESSION_HANDLE hSession,       /* the session's handle */
 CK_BYTE_PTR       pSignature,     /* signature to verify */
 CK_ULONG          ulSignatureLen  /* signature length */
 );
#endif


/* C_VerifyRecoverInit initializes a signature verification
* operation, where the data is recovered from the signature. */
CK_PKCS11_FUNCTION_INFO(C_VerifyRecoverInit)
#ifdef CK_NEED_ARG_LIST
(
 CK_SESSION_HANDLE hSession,    /* the session's handle */
 CK_MECHANISM_PTR  pMechanism,  /* the verification mechanism */
 CK_OBJECT_HANDLE  hKey         /* verification key */
 );
#endif


/* C_VerifyRecover verifies a signature in a single-part
* operation, where the data is recovered from the signature. */
CK_PKCS11_FUNCTION_INFO(C_VerifyRecover)
#ifdef CK_NEED_ARG_LIST
(
 CK_SESSION_HANDLE hSession,        /* the session's handle */
 CK_BYTE_PTR       pSignature,      /* signature to verify */
 CK_ULONG          ulSignatureLen,  /* signature length */
 CK_BYTE_PTR       pData,           /* gets signed data */
 CK_ULONG_PTR      pulDataLen       /* gets signed data len */
 );
#endif



/* Dual-function cryptographic operations */

/* C_DigestEncryptUpdate continues a multiple-part digesting
* and encryption operation. */
CK_PKCS11_FUNCTION_INFO(C_DigestEncryptUpdate)
#ifdef CK_NEED_ARG_LIST
(
 CK_SESSION_HANDLE hSession,            /* session's handle */
 CK_BYTE_PTR       pPart,               /* the plaintext data */
 CK_ULONG          ulPartLen,           /* plaintext length */
 CK_BYTE_PTR       pEncryptedPart,      /* gets ciphertext */
 CK_ULONG_PTR      pulEncryptedPartLen  /* gets c-text length */
 );
#endif


/* C_DecryptDigestUpdate continues a multiple-part decryption and
* digesting operation. */
CK_PKCS11_FUNCTION_INFO(C_DecryptDigestUpdate)
#ifdef CK_NEED_ARG_LIST
(
 CK_SESSION_HANDLE hSession,            /* session's handle */
 CK_BYTE_PTR       pEncryptedPart,      /* ciphertext */
 CK_ULONG          ulEncryptedPartLen,  /* ciphertext length */
 CK_BYTE_PTR       pPart,               /* gets plaintext */
 CK_ULONG_PTR      pulPartLen           /* gets plaintext len */
 );
#endif


/* C_SignEncryptUpdate continues a multiple-part signing and
* encryption operation. */
CK_PKCS11_FUNCTION_INFO(C_SignEncryptUpdate)
#ifdef CK_NEED_ARG_LIST
(
 CK_SESSION_HANDLE hSession,            /* session's handle */
 CK_BYTE_PTR       pPart,               /* the plaintext data */
 CK_ULONG          ulPartLen,           /* plaintext length */
 CK_BYTE_PTR       pEncryptedPart,      /* gets ciphertext */
 CK_ULONG_PTR      pulEncryptedPartLen  /* gets c-text length */
 );
#endif


/* C_DecryptVerifyUpdate continues a multiple-part decryption and
* verify operation. */
CK_PKCS11_FUNCTION_INFO(C_DecryptVerifyUpdate)
#ifdef CK_NEED_ARG_LIST
(
 CK_SESSION_HANDLE hSession,            /* session's handle */
 CK_BYTE_PTR       pEncryptedPart,      /* ciphertext */
 CK_ULONG          ulEncryptedPartLen,  /* ciphertext length */
 CK_BYTE_PTR       pPart,               /* gets plaintext */
 CK_ULONG_PTR      pulPartLen           /* gets p-text length */
 );
#endif



/* Key management */

/* C_GenerateKey generates a secret key, creating a new key
* object. */
CK_PKCS11_FUNCTION_INFO(C_GenerateKey)
#ifdef CK_NEED_ARG_LIST
(
 CK_SESSION_HANDLE    hSession,    /* the session's handle */
 CK_MECHANISM_PTR     pMechanism,  /* key generation mech. */
 CK_ATTRIBUTE_PTR     pTemplate,   /* template for new key */
 CK_ULONG             ulCount,     /* # of attrs in template */
 CK_OBJECT_HANDLE_PTR phKey        /* gets handle of new key */
 );
#endif


/* C_GenerateKeyPair generates a public-key/private-key pair,
* creating new key objects. */
CK_PKCS11_FUNCTION_INFO(C_GenerateKeyPair)
#ifdef CK_NEED_ARG_LIST
(
 CK_SESSION_HANDLE    hSession,                    /* session
												   * handle */
												   CK_MECHANISM_PTR     pMechanism,                  /* key-gen
																									 * mech. */
																									 CK_ATTRIBUTE_PTR     pPublicKeyTemplate,          /* template
																																					   * for pub.
																																					   * key */
																																					   CK_ULONG             ulPublicKeyAttributeCount,   /* # pub.
																																																		 * attrs. */
																																																		 CK_ATTRIBUTE_PTR     pPrivateKeyTemplate,         /* template
																																																														   * for priv.
																																																														   * key */
																																																														   CK_ULONG             ulPrivateKeyAttributeCount,  /* # priv.
																																																																											 * attrs. */
																																																																											 CK_OBJECT_HANDLE_PTR phPublicKey,                 /* gets pub.
																																																																																							   * key
																																																																																							   * handle */
																																																																																							   CK_OBJECT_HANDLE_PTR phPrivateKey                 /* gets
																																																																																																				 * priv. key
																																																																																																				 * handle */
																																																																																																				 );
#endif


/* C_WrapKey wraps (i.e., encrypts) a key. */
CK_PKCS11_FUNCTION_INFO(C_WrapKey)
#ifdef CK_NEED_ARG_LIST
(
 CK_SESSION_HANDLE hSession,        /* the session's handle */
 CK_MECHANISM_PTR  pMechanism,      /* the wrapping mechanism */
 CK_OBJECT_HANDLE  hWrappingKey,    /* wrapping key */
 CK_OBJECT_HANDLE  hKey,            /* key to be wrapped */
 CK_BYTE_PTR       pWrappedKey,     /* gets wrapped key */
 CK_ULONG_PTR      pulWrappedKeyLen /* gets wrapped key size */
 );
#endif


/* C_UnwrapKey unwraps (decrypts) a wrapped key, creating a new
* key object. */
CK_PKCS11_FUNCTION_INFO(C_UnwrapKey)
#ifdef CK_NEED_ARG_LIST
(
 CK_SESSION_HANDLE    hSession,          /* session's handle */
 CK_MECHANISM_PTR     pMechanism,        /* unwrapping mech. */
 CK_OBJECT_HANDLE     hUnwrappingKey,    /* unwrapping key */
 CK_BYTE_PTR          pWrappedKey,       /* the wrapped key */
 CK_ULONG             ulWrappedKeyLen,   /* wrapped key len */
 CK_ATTRIBUTE_PTR     pTemplate,         /* new key template */
 CK_ULONG             ulAttributeCount,  /* template length */
 CK_OBJECT_HANDLE_PTR phKey              /* gets new handle */
 );
#endif


/* C_DeriveKey derives a key from a base key, creating a new key
* object. */
CK_PKCS11_FUNCTION_INFO(C_DeriveKey)
#ifdef CK_NEED_ARG_LIST
(
 CK_SESSION_HANDLE    hSession,          /* session's handle */
 CK_MECHANISM_PTR     pMechanism,        /* key deriv. mech. */
 CK_OBJECT_HANDLE     hBaseKey,          /* base key */
 CK_ATTRIBUTE_PTR     pTemplate,         /* new key template */
 CK_ULONG             ulAttributeCount,  /* template length */
 CK_OBJECT_HANDLE_PTR phKey              /* gets new handle */
 );
#endif



/* Random number generation */

/* C_SeedRandom mixes additional seed material into the token's
* random number generator. */
CK_PKCS11_FUNCTION_INFO(C_SeedRandom)
#ifdef CK_NEED_ARG_LIST
(
 CK_SESSION_HANDLE hSession,  /* the session's handle */
 CK_BYTE_PTR       pSeed,     /* the seed material */
 CK_ULONG          ulSeedLen  /* length of seed material */
 );
#endif


/* C_GenerateRandom generates random data. */
CK_PKCS11_FUNCTION_INFO(C_GenerateRandom)
#ifdef CK_NEED_ARG_LIST
(
 CK_SESSION_HANDLE hSession,    /* the session's handle */
 CK_BYTE_PTR       RandomData,  /* receives the random data */
 CK_ULONG          ulRandomLen  /* # of bytes to generate */
 );
#endif



/* Parallel function management */

/* C_GetFunctionStatus is a legacy function; it obtains an
* updated status of a function running in parallel with an
* application. */
CK_PKCS11_FUNCTION_INFO(C_GetFunctionStatus)
#ifdef CK_NEED_ARG_LIST
(
 CK_SESSION_HANDLE hSession  /* the session's handle */
 );
#endif


/* C_CancelFunction is a legacy function; it cancels a function
* running in parallel. */
CK_PKCS11_FUNCTION_INFO(C_CancelFunction)
#ifdef CK_NEED_ARG_LIST
(
 CK_SESSION_HANDLE hSession  /* the session's handle */
 );
#endif



/* Functions added in for Cryptoki Version 2.01 or later */

/* C_WaitForSlotEvent waits for a slot event (token insertion,
* removal, etc.) to occur. */
CK_PKCS11_FUNCTION_INFO(C_WaitForSlotEvent)
#ifdef CK_NEED_ARG_LIST
(
 CK_FLAGS flags,        /* blocking/nonblocking flag */
 CK_SLOT_ID_PTR pSlot,  /* location that receives the slot ID */
 CK_VOID_PTR pRserved   /* reserved.  Should be NULL_PTR */
 );
#endif


/************************************************************************/
/*
	end of
	#include "pkcs11f.h"
	darpangs
*/
/************************************************************************/

#undef CK_NEED_ARG_LIST
#undef CK_PKCS11_FUNCTION_INFO


	/* ==============================================================
	* Define the typedef form of all the entry points.  That is, for
	* each Cryptoki function C_XXX, define a type CK_C_XXX which is
	* a pointer to that kind of function.
	* ==============================================================
	*/

#define CK_NEED_ARG_LIST  1
#define CK_PKCS11_FUNCTION_INFO(name) \
	typedef CK_DECLARE_FUNCTION_POINTER(CK_RV, __PASTE(CK_,name))

	/* pkcs11f.h has all the information about the Cryptoki
	* function prototypes. */
/************************************************************************/
/*
	#include "pkcs11f.h"
	darpangs
*/
/************************************************************************/
/* pkcs11f.h include file for PKCS #11. */
/* $Revision: 1.4 $ */


/* General-purpose */

/* C_Initialize initializes the Cryptoki library. */
CK_PKCS11_FUNCTION_INFO(C_Initialize)
#ifdef CK_NEED_ARG_LIST
(
 CK_VOID_PTR   pInitArgs  /* if this is not NULL_PTR, it gets
						  * cast to CK_C_INITIALIZE_ARGS_PTR
						  * and dereferenced */
						  );
#endif


/* C_Finalize indicates that an application is done with the
* Cryptoki library. */
CK_PKCS11_FUNCTION_INFO(C_Finalize)
#ifdef CK_NEED_ARG_LIST
(
 CK_VOID_PTR   pReserved  /* reserved.  Should be NULL_PTR */
 );
#endif


/* C_GetInfo returns general information about Cryptoki. */
CK_PKCS11_FUNCTION_INFO(C_GetInfo)
#ifdef CK_NEED_ARG_LIST
(
 CK_INFO_PTR   pInfo  /* location that receives information */
 );
#endif


/* C_GetFunctionList returns the function list. */
CK_PKCS11_FUNCTION_INFO(C_GetFunctionList)
#ifdef CK_NEED_ARG_LIST
(
 CK_FUNCTION_LIST_PTR_PTR ppFunctionList  /* receives pointer to
										  * function list */
										  );
#endif



/* Slot and token management */

/* C_GetSlotList obtains a list of slots in the system. */
CK_PKCS11_FUNCTION_INFO(C_GetSlotList)
#ifdef CK_NEED_ARG_LIST
(
 CK_BBOOL       tokenPresent,  /* only slots with tokens? */
 CK_SLOT_ID_PTR pSlotList,     /* receives array of slot IDs */
 CK_ULONG_PTR   pulCount       /* receives number of slots */
 );
#endif


/* C_GetSlotInfo obtains information about a particular slot in
* the system. */
CK_PKCS11_FUNCTION_INFO(C_GetSlotInfo)
#ifdef CK_NEED_ARG_LIST
(
 CK_SLOT_ID       slotID,  /* the ID of the slot */
 CK_SLOT_INFO_PTR pInfo    /* receives the slot information */
 );
#endif


/* C_GetTokenInfo obtains information about a particular token
* in the system. */
CK_PKCS11_FUNCTION_INFO(C_GetTokenInfo)
#ifdef CK_NEED_ARG_LIST
(
 CK_SLOT_ID        slotID,  /* ID of the token's slot */
 CK_TOKEN_INFO_PTR pInfo    /* receives the token information */
 );
#endif


/* C_GetMechanismList obtains a list of mechanism types
* supported by a token. */
CK_PKCS11_FUNCTION_INFO(C_GetMechanismList)
#ifdef CK_NEED_ARG_LIST
(
 CK_SLOT_ID            slotID,          /* ID of token's slot */
 CK_MECHANISM_TYPE_PTR pMechanismList,  /* gets mech. array */
 CK_ULONG_PTR          pulCount         /* gets # of mechs. */
 );
#endif


/* C_GetMechanismInfo obtains information about a particular
* mechanism possibly supported by a token. */
CK_PKCS11_FUNCTION_INFO(C_GetMechanismInfo)
#ifdef CK_NEED_ARG_LIST
(
 CK_SLOT_ID            slotID,  /* ID of the token's slot */
 CK_MECHANISM_TYPE     type,    /* type of mechanism */
 CK_MECHANISM_INFO_PTR pInfo    /* receives mechanism info */
 );
#endif


/* C_InitToken initializes a token. */
CK_PKCS11_FUNCTION_INFO(C_InitToken)
#ifdef CK_NEED_ARG_LIST
/* pLabel changed from CK_CHAR_PTR to CK_UTF8CHAR_PTR for v2.10 */
(
 CK_SLOT_ID      slotID,    /* ID of the token's slot */
 CK_UTF8CHAR_PTR pPin,      /* the SO's initial PIN */
 CK_ULONG        ulPinLen,  /* length in bytes of the PIN */
 CK_UTF8CHAR_PTR pLabel     /* 32-byte token label (blank padded) */
 );
#endif


/* C_InitPIN initializes the normal user's PIN. */
CK_PKCS11_FUNCTION_INFO(C_InitPIN)
#ifdef CK_NEED_ARG_LIST
(
 CK_SESSION_HANDLE hSession,  /* the session's handle */
 CK_UTF8CHAR_PTR   pPin,      /* the normal user's PIN */
 CK_ULONG          ulPinLen   /* length in bytes of the PIN */
 );
#endif


/* C_SetPIN modifies the PIN of the user who is logged in. */
CK_PKCS11_FUNCTION_INFO(C_SetPIN)
#ifdef CK_NEED_ARG_LIST
(
 CK_SESSION_HANDLE hSession,  /* the session's handle */
 CK_UTF8CHAR_PTR   pOldPin,   /* the old PIN */
 CK_ULONG          ulOldLen,  /* length of the old PIN */
 CK_UTF8CHAR_PTR   pNewPin,   /* the new PIN */
 CK_ULONG          ulNewLen   /* length of the new PIN */
 );
#endif



/* Session management */

/* C_OpenSession opens a session between an application and a
* token. */
CK_PKCS11_FUNCTION_INFO(C_OpenSession)
#ifdef CK_NEED_ARG_LIST
(
 CK_SLOT_ID            slotID,        /* the slot's ID */
 CK_FLAGS              flags,         /* from CK_SESSION_INFO */
 CK_VOID_PTR           pApplication,  /* passed to callback */
 CK_NOTIFY             Notify,        /* callback function */
 CK_SESSION_HANDLE_PTR phSession      /* gets session handle */
 );
#endif


/* C_CloseSession closes a session between an application and a
* token. */
CK_PKCS11_FUNCTION_INFO(C_CloseSession)
#ifdef CK_NEED_ARG_LIST
(
 CK_SESSION_HANDLE hSession  /* the session's handle */
 );
#endif


/* C_CloseAllSessions closes all sessions with a token. */
CK_PKCS11_FUNCTION_INFO(C_CloseAllSessions)
#ifdef CK_NEED_ARG_LIST
(
 CK_SLOT_ID     slotID  /* the token's slot */
 );
#endif


/* C_GetSessionInfo obtains information about the session. */
CK_PKCS11_FUNCTION_INFO(C_GetSessionInfo)
#ifdef CK_NEED_ARG_LIST
(
 CK_SESSION_HANDLE   hSession,  /* the session's handle */
 CK_SESSION_INFO_PTR pInfo      /* receives session info */
 );
#endif


/* C_GetOperationState obtains the state of the cryptographic operation
* in a session. */
CK_PKCS11_FUNCTION_INFO(C_GetOperationState)
#ifdef CK_NEED_ARG_LIST
(
 CK_SESSION_HANDLE hSession,             /* session's handle */
 CK_BYTE_PTR       pOperationState,      /* gets state */
 CK_ULONG_PTR      pulOperationStateLen  /* gets state length */
 );
#endif


/* C_SetOperationState restores the state of the cryptographic
* operation in a session. */
CK_PKCS11_FUNCTION_INFO(C_SetOperationState)
#ifdef CK_NEED_ARG_LIST
(
 CK_SESSION_HANDLE hSession,            /* session's handle */
 CK_BYTE_PTR      pOperationState,      /* holds state */
 CK_ULONG         ulOperationStateLen,  /* holds state length */
 CK_OBJECT_HANDLE hEncryptionKey,       /* en/decryption key */
 CK_OBJECT_HANDLE hAuthenticationKey    /* sign/verify key */
 );
#endif


/* C_Login logs a user into a token. */
CK_PKCS11_FUNCTION_INFO(C_Login)
#ifdef CK_NEED_ARG_LIST
(
 CK_SESSION_HANDLE hSession,  /* the session's handle */
 CK_USER_TYPE      userType,  /* the user type */
 CK_UTF8CHAR_PTR   pPin,      /* the user's PIN */
 CK_ULONG          ulPinLen   /* the length of the PIN */
 );
#endif

CK_PKCS11_FUNCTION_INFO(C_LoginBegin)
#ifdef CK_NEED_ARG_LIST
(
  CK_SESSION_HANDLE hSession,  /* the session's handle */
  CK_USER_TYPE      userType,  /* the user type */
  CK_ULONG_PTR      pulK,      /* cards required to load logical token. */
  CK_ULONG_PTR      pulN       /* Number of cards in set */
);
#endif

/* C_LoginNext logs a user into a token. */
CK_PKCS11_FUNCTION_INFO(C_LoginNext)
#ifdef CK_NEED_ARG_LIST
(
  CK_SESSION_HANDLE hSession,  /* the session's handle */
  CK_USER_TYPE      userType,  /* the user type */
  CK_CHAR_PTR       pPin,      /* the user's PIN */
  CK_ULONG          ulPinLen,   /* the length of the PIN */
  CK_ULONG_PTR      pulSharesLeft /* Number of remaining shares */
);
#endif

/* C_LoginEnd logs a user into a token. */
CK_PKCS11_FUNCTION_INFO(C_LoginEnd)
#ifdef CK_NEED_ARG_LIST
(
  CK_SESSION_HANDLE hSession,  /* the session's handle */
  CK_USER_TYPE      userType  /* the user type */
);
#endif


/* C_Logout logs a user out from a token. */
CK_PKCS11_FUNCTION_INFO(C_Logout)
#ifdef CK_NEED_ARG_LIST
(
 CK_SESSION_HANDLE hSession  /* the session's handle */
 );
#endif



/* Object management */

/* C_CreateObject creates a new object. */
CK_PKCS11_FUNCTION_INFO(C_CreateObject)
#ifdef CK_NEED_ARG_LIST
(
 CK_SESSION_HANDLE hSession,    /* the session's handle */
 CK_ATTRIBUTE_PTR  pTemplate,   /* the object's template */
 CK_ULONG          ulCount,     /* attributes in template */
 CK_OBJECT_HANDLE_PTR phObject  /* gets new object's handle. */
 );
#endif


/* C_CopyObject copies an object, creating a new object for the
* copy. */
CK_PKCS11_FUNCTION_INFO(C_CopyObject)
#ifdef CK_NEED_ARG_LIST
(
 CK_SESSION_HANDLE    hSession,    /* the session's handle */
 CK_OBJECT_HANDLE     hObject,     /* the object's handle */
 CK_ATTRIBUTE_PTR     pTemplate,   /* template for new object */
 CK_ULONG             ulCount,     /* attributes in template */
 CK_OBJECT_HANDLE_PTR phNewObject  /* receives handle of copy */
 );
#endif


/* C_DestroyObject destroys an object. */
CK_PKCS11_FUNCTION_INFO(C_DestroyObject)
#ifdef CK_NEED_ARG_LIST
(
 CK_SESSION_HANDLE hSession,  /* the session's handle */
 CK_OBJECT_HANDLE  hObject    /* the object's handle */
 );
#endif


/* C_GetObjectSize gets the size of an object in bytes. */
CK_PKCS11_FUNCTION_INFO(C_GetObjectSize)
#ifdef CK_NEED_ARG_LIST
(
 CK_SESSION_HANDLE hSession,  /* the session's handle */
 CK_OBJECT_HANDLE  hObject,   /* the object's handle */
 CK_ULONG_PTR      pulSize    /* receives size of object */
 );
#endif


/* C_GetAttributeValue obtains the value of one or more object
* attributes. */
CK_PKCS11_FUNCTION_INFO(C_GetAttributeValue)
#ifdef CK_NEED_ARG_LIST
(
 CK_SESSION_HANDLE hSession,   /* the session's handle */
 CK_OBJECT_HANDLE  hObject,    /* the object's handle */
 CK_ATTRIBUTE_PTR  pTemplate,  /* specifies attrs; gets vals */
 CK_ULONG          ulCount     /* attributes in template */
 );
#endif


/* C_SetAttributeValue modifies the value of one or more object
* attributes */
CK_PKCS11_FUNCTION_INFO(C_SetAttributeValue)
#ifdef CK_NEED_ARG_LIST
(
 CK_SESSION_HANDLE hSession,   /* the session's handle */
 CK_OBJECT_HANDLE  hObject,    /* the object's handle */
 CK_ATTRIBUTE_PTR  pTemplate,  /* specifies attrs and values */
 CK_ULONG          ulCount     /* attributes in template */
 );
#endif


/* C_FindObjectsInit initializes a search for token and session
* objects that match a template. */
CK_PKCS11_FUNCTION_INFO(C_FindObjectsInit)
#ifdef CK_NEED_ARG_LIST
(
 CK_SESSION_HANDLE hSession,   /* the session's handle */
 CK_ATTRIBUTE_PTR  pTemplate,  /* attribute values to match */
 CK_ULONG          ulCount     /* attrs in search template */
 );
#endif


/* C_FindObjects continues a search for token and session
* objects that match a template, obtaining additional object
* handles. */
CK_PKCS11_FUNCTION_INFO(C_FindObjects)
#ifdef CK_NEED_ARG_LIST
(
 CK_SESSION_HANDLE    hSession,          /* session's handle */
 CK_OBJECT_HANDLE_PTR phObject,          /* gets obj. handles */
 CK_ULONG             ulMaxObjectCount,  /* max handles to get */
 CK_ULONG_PTR         pulObjectCount     /* actual # returned */
 );
#endif


/* C_FindObjectsFinal finishes a search for token and session
* objects. */
CK_PKCS11_FUNCTION_INFO(C_FindObjectsFinal)
#ifdef CK_NEED_ARG_LIST
(
 CK_SESSION_HANDLE hSession  /* the session's handle */
 );
#endif



/* Encryption and decryption */

/* C_EncryptInit initializes an encryption operation. */
CK_PKCS11_FUNCTION_INFO(C_EncryptInit)
#ifdef CK_NEED_ARG_LIST
(
 CK_SESSION_HANDLE hSession,    /* the session's handle */
 CK_MECHANISM_PTR  pMechanism,  /* the encryption mechanism */
 CK_OBJECT_HANDLE  hKey         /* handle of encryption key */
 );
#endif


/* C_Encrypt encrypts single-part data. */
CK_PKCS11_FUNCTION_INFO(C_Encrypt)
#ifdef CK_NEED_ARG_LIST
(
 CK_SESSION_HANDLE hSession,            /* session's handle */
 CK_BYTE_PTR       pData,               /* the plaintext data */
 CK_ULONG          ulDataLen,           /* bytes of plaintext */
 CK_BYTE_PTR       pEncryptedData,      /* gets ciphertext */
 CK_ULONG_PTR      pulEncryptedDataLen  /* gets c-text size */
 );
#endif


/* C_EncryptUpdate continues a multiple-part encryption
* operation. */
CK_PKCS11_FUNCTION_INFO(C_EncryptUpdate)
#ifdef CK_NEED_ARG_LIST
(
 CK_SESSION_HANDLE hSession,           /* session's handle */
 CK_BYTE_PTR       pPart,              /* the plaintext data */
 CK_ULONG          ulPartLen,          /* plaintext data len */
 CK_BYTE_PTR       pEncryptedPart,     /* gets ciphertext */
 CK_ULONG_PTR      pulEncryptedPartLen /* gets c-text size */
 );
#endif


/* C_EncryptFinal finishes a multiple-part encryption
* operation. */
CK_PKCS11_FUNCTION_INFO(C_EncryptFinal)
#ifdef CK_NEED_ARG_LIST
(
 CK_SESSION_HANDLE hSession,                /* session handle */
 CK_BYTE_PTR       pLastEncryptedPart,      /* last c-text */
 CK_ULONG_PTR      pulLastEncryptedPartLen  /* gets last size */
 );
#endif


/* C_DecryptInit initializes a decryption operation. */
CK_PKCS11_FUNCTION_INFO(C_DecryptInit)
#ifdef CK_NEED_ARG_LIST
(
 CK_SESSION_HANDLE hSession,    /* the session's handle */
 CK_MECHANISM_PTR  pMechanism,  /* the decryption mechanism */
 CK_OBJECT_HANDLE  hKey         /* handle of decryption key */
 );
#endif


/* C_Decrypt decrypts encrypted data in a single part. */
CK_PKCS11_FUNCTION_INFO(C_Decrypt)
#ifdef CK_NEED_ARG_LIST
(
 CK_SESSION_HANDLE hSession,           /* session's handle */
 CK_BYTE_PTR       pEncryptedData,     /* ciphertext */
 CK_ULONG          ulEncryptedDataLen, /* ciphertext length */
 CK_BYTE_PTR       pData,              /* gets plaintext */
 CK_ULONG_PTR      pulDataLen          /* gets p-text size */
 );
#endif


/* C_DecryptUpdate continues a multiple-part decryption
* operation. */
CK_PKCS11_FUNCTION_INFO(C_DecryptUpdate)
#ifdef CK_NEED_ARG_LIST
(
 CK_SESSION_HANDLE hSession,            /* session's handle */
 CK_BYTE_PTR       pEncryptedPart,      /* encrypted data */
 CK_ULONG          ulEncryptedPartLen,  /* input length */
 CK_BYTE_PTR       pPart,               /* gets plaintext */
 CK_ULONG_PTR      pulPartLen           /* p-text size */
 );
#endif


/* C_DecryptFinal finishes a multiple-part decryption
* operation. */
CK_PKCS11_FUNCTION_INFO(C_DecryptFinal)
#ifdef CK_NEED_ARG_LIST
(
 CK_SESSION_HANDLE hSession,       /* the session's handle */
 CK_BYTE_PTR       pLastPart,      /* gets plaintext */
 CK_ULONG_PTR      pulLastPartLen  /* p-text size */
 );
#endif



/* Message digesting */

/* C_DigestInit initializes a message-digesting operation. */
CK_PKCS11_FUNCTION_INFO(C_DigestInit)
#ifdef CK_NEED_ARG_LIST
(
 CK_SESSION_HANDLE hSession,   /* the session's handle */
 CK_MECHANISM_PTR  pMechanism  /* the digesting mechanism */
 );
#endif


/* C_Digest digests data in a single part. */
CK_PKCS11_FUNCTION_INFO(C_Digest)
#ifdef CK_NEED_ARG_LIST
(
 CK_SESSION_HANDLE hSession,     /* the session's handle */
 CK_BYTE_PTR       pData,        /* data to be digested */
 CK_ULONG          ulDataLen,    /* bytes of data to digest */
 CK_BYTE_PTR       pDigest,      /* gets the message digest */
 CK_ULONG_PTR      pulDigestLen  /* gets digest length */
 );
#endif


/* C_DigestUpdate continues a multiple-part message-digesting
* operation. */
CK_PKCS11_FUNCTION_INFO(C_DigestUpdate)
#ifdef CK_NEED_ARG_LIST
(
 CK_SESSION_HANDLE hSession,  /* the session's handle */
 CK_BYTE_PTR       pPart,     /* data to be digested */
 CK_ULONG          ulPartLen  /* bytes of data to be digested */
 );
#endif


/* C_DigestKey continues a multi-part message-digesting
* operation, by digesting the value of a secret key as part of
* the data already digested. */
CK_PKCS11_FUNCTION_INFO(C_DigestKey)
#ifdef CK_NEED_ARG_LIST
(
 CK_SESSION_HANDLE hSession,  /* the session's handle */
 CK_OBJECT_HANDLE  hKey       /* secret key to digest */
 );
#endif


/* C_DigestFinal finishes a multiple-part message-digesting
* operation. */
CK_PKCS11_FUNCTION_INFO(C_DigestFinal)
#ifdef CK_NEED_ARG_LIST
(
 CK_SESSION_HANDLE hSession,     /* the session's handle */
 CK_BYTE_PTR       pDigest,      /* gets the message digest */
 CK_ULONG_PTR      pulDigestLen  /* gets byte count of digest */
 );
#endif



/* Signing and MACing */

/* C_SignInit initializes a signature (private key encryption)
* operation, where the signature is (will be) an appendix to
* the data, and plaintext cannot be recovered from the
*signature. */
CK_PKCS11_FUNCTION_INFO(C_SignInit)
#ifdef CK_NEED_ARG_LIST
(
 CK_SESSION_HANDLE hSession,    /* the session's handle */
 CK_MECHANISM_PTR  pMechanism,  /* the signature mechanism */
 CK_OBJECT_HANDLE  hKey         /* handle of signature key */
 );
#endif


/* C_Sign signs (encrypts with private key) data in a single
* part, where the signature is (will be) an appendix to the
* data, and plaintext cannot be recovered from the signature. */
CK_PKCS11_FUNCTION_INFO(C_Sign)
#ifdef CK_NEED_ARG_LIST
(
 CK_SESSION_HANDLE hSession,        /* the session's handle */
 CK_BYTE_PTR       pData,           /* the data to sign */
 CK_ULONG          ulDataLen,       /* count of bytes to sign */
 CK_BYTE_PTR       pSignature,      /* gets the signature */
 CK_ULONG_PTR      pulSignatureLen  /* gets signature length */
 );
#endif


/* C_SignUpdate continues a multiple-part signature operation,
* where the signature is (will be) an appendix to the data,
* and plaintext cannot be recovered from the signature. */
CK_PKCS11_FUNCTION_INFO(C_SignUpdate)
#ifdef CK_NEED_ARG_LIST
(
 CK_SESSION_HANDLE hSession,  /* the session's handle */
 CK_BYTE_PTR       pPart,     /* the data to sign */
 CK_ULONG          ulPartLen  /* count of bytes to sign */
 );
#endif


/* C_SignFinal finishes a multiple-part signature operation,
* returning the signature. */
CK_PKCS11_FUNCTION_INFO(C_SignFinal)
#ifdef CK_NEED_ARG_LIST
(
 CK_SESSION_HANDLE hSession,        /* the session's handle */
 CK_BYTE_PTR       pSignature,      /* gets the signature */
 CK_ULONG_PTR      pulSignatureLen  /* gets signature length */
 );
#endif


/* C_SignRecoverInit initializes a signature operation, where
* the data can be recovered from the signature. */
CK_PKCS11_FUNCTION_INFO(C_SignRecoverInit)
#ifdef CK_NEED_ARG_LIST
(
 CK_SESSION_HANDLE hSession,   /* the session's handle */
 CK_MECHANISM_PTR  pMechanism, /* the signature mechanism */
 CK_OBJECT_HANDLE  hKey        /* handle of the signature key */
 );
#endif


/* C_SignRecover signs data in a single operation, where the
* data can be recovered from the signature. */
CK_PKCS11_FUNCTION_INFO(C_SignRecover)
#ifdef CK_NEED_ARG_LIST
(
 CK_SESSION_HANDLE hSession,        /* the session's handle */
 CK_BYTE_PTR       pData,           /* the data to sign */
 CK_ULONG          ulDataLen,       /* count of bytes to sign */
 CK_BYTE_PTR       pSignature,      /* gets the signature */
 CK_ULONG_PTR      pulSignatureLen  /* gets signature length */
 );
#endif



/* Verifying signatures and MACs */

/* C_VerifyInit initializes a verification operation, where the
* signature is an appendix to the data, and plaintext cannot
*  cannot be recovered from the signature (e.g. ISC_DSA). */
CK_PKCS11_FUNCTION_INFO(C_VerifyInit)
#ifdef CK_NEED_ARG_LIST
(
 CK_SESSION_HANDLE hSession,    /* the session's handle */
 CK_MECHANISM_PTR  pMechanism,  /* the verification mechanism */
 CK_OBJECT_HANDLE  hKey         /* verification key */
 );
#endif


/* C_Verify verifies a signature in a single-part operation,
* where the signature is an appendix to the data, and plaintext
* cannot be recovered from the signature. */
CK_PKCS11_FUNCTION_INFO(C_Verify)
#ifdef CK_NEED_ARG_LIST
(
 CK_SESSION_HANDLE hSession,       /* the session's handle */
 CK_BYTE_PTR       pData,          /* signed data */
 CK_ULONG          ulDataLen,      /* length of signed data */
 CK_BYTE_PTR       pSignature,     /* signature */
 CK_ULONG          ulSignatureLen  /* signature length*/
 );
#endif


/* C_VerifyUpdate continues a multiple-part verification
* operation, where the signature is an appendix to the data,
* and plaintext cannot be recovered from the signature. */
CK_PKCS11_FUNCTION_INFO(C_VerifyUpdate)
#ifdef CK_NEED_ARG_LIST
(
 CK_SESSION_HANDLE hSession,  /* the session's handle */
 CK_BYTE_PTR       pPart,     /* signed data */
 CK_ULONG          ulPartLen  /* length of signed data */
 );
#endif


/* C_VerifyFinal finishes a multiple-part verification
* operation, checking the signature. */
CK_PKCS11_FUNCTION_INFO(C_VerifyFinal)
#ifdef CK_NEED_ARG_LIST
(
 CK_SESSION_HANDLE hSession,       /* the session's handle */
 CK_BYTE_PTR       pSignature,     /* signature to verify */
 CK_ULONG          ulSignatureLen  /* signature length */
 );
#endif


/* C_VerifyRecoverInit initializes a signature verification
* operation, where the data is recovered from the signature. */
CK_PKCS11_FUNCTION_INFO(C_VerifyRecoverInit)
#ifdef CK_NEED_ARG_LIST
(
 CK_SESSION_HANDLE hSession,    /* the session's handle */
 CK_MECHANISM_PTR  pMechanism,  /* the verification mechanism */
 CK_OBJECT_HANDLE  hKey         /* verification key */
 );
#endif


/* C_VerifyRecover verifies a signature in a single-part
* operation, where the data is recovered from the signature. */
CK_PKCS11_FUNCTION_INFO(C_VerifyRecover)
#ifdef CK_NEED_ARG_LIST
(
 CK_SESSION_HANDLE hSession,        /* the session's handle */
 CK_BYTE_PTR       pSignature,      /* signature to verify */
 CK_ULONG          ulSignatureLen,  /* signature length */
 CK_BYTE_PTR       pData,           /* gets signed data */
 CK_ULONG_PTR      pulDataLen       /* gets signed data len */
 );
#endif



/* Dual-function cryptographic operations */

/* C_DigestEncryptUpdate continues a multiple-part digesting
* and encryption operation. */
CK_PKCS11_FUNCTION_INFO(C_DigestEncryptUpdate)
#ifdef CK_NEED_ARG_LIST
(
 CK_SESSION_HANDLE hSession,            /* session's handle */
 CK_BYTE_PTR       pPart,               /* the plaintext data */
 CK_ULONG          ulPartLen,           /* plaintext length */
 CK_BYTE_PTR       pEncryptedPart,      /* gets ciphertext */
 CK_ULONG_PTR      pulEncryptedPartLen  /* gets c-text length */
 );
#endif


/* C_DecryptDigestUpdate continues a multiple-part decryption and
* digesting operation. */
CK_PKCS11_FUNCTION_INFO(C_DecryptDigestUpdate)
#ifdef CK_NEED_ARG_LIST
(
 CK_SESSION_HANDLE hSession,            /* session's handle */
 CK_BYTE_PTR       pEncryptedPart,      /* ciphertext */
 CK_ULONG          ulEncryptedPartLen,  /* ciphertext length */
 CK_BYTE_PTR       pPart,               /* gets plaintext */
 CK_ULONG_PTR      pulPartLen           /* gets plaintext len */
 );
#endif


/* C_SignEncryptUpdate continues a multiple-part signing and
* encryption operation. */
CK_PKCS11_FUNCTION_INFO(C_SignEncryptUpdate)
#ifdef CK_NEED_ARG_LIST
(
 CK_SESSION_HANDLE hSession,            /* session's handle */
 CK_BYTE_PTR       pPart,               /* the plaintext data */
 CK_ULONG          ulPartLen,           /* plaintext length */
 CK_BYTE_PTR       pEncryptedPart,      /* gets ciphertext */
 CK_ULONG_PTR      pulEncryptedPartLen  /* gets c-text length */
 );
#endif


/* C_DecryptVerifyUpdate continues a multiple-part decryption and
* verify operation. */
CK_PKCS11_FUNCTION_INFO(C_DecryptVerifyUpdate)
#ifdef CK_NEED_ARG_LIST
(
 CK_SESSION_HANDLE hSession,            /* session's handle */
 CK_BYTE_PTR       pEncryptedPart,      /* ciphertext */
 CK_ULONG          ulEncryptedPartLen,  /* ciphertext length */
 CK_BYTE_PTR       pPart,               /* gets plaintext */
 CK_ULONG_PTR      pulPartLen           /* gets p-text length */
 );
#endif



/* Key management */

/* C_GenerateKey generates a secret key, creating a new key
* object. */
CK_PKCS11_FUNCTION_INFO(C_GenerateKey)
#ifdef CK_NEED_ARG_LIST
(
 CK_SESSION_HANDLE    hSession,    /* the session's handle */
 CK_MECHANISM_PTR     pMechanism,  /* key generation mech. */
 CK_ATTRIBUTE_PTR     pTemplate,   /* template for new key */
 CK_ULONG             ulCount,     /* # of attrs in template */
 CK_OBJECT_HANDLE_PTR phKey        /* gets handle of new key */
 );
#endif


/* C_GenerateKeyPair generates a public-key/private-key pair,
* creating new key objects. */
CK_PKCS11_FUNCTION_INFO(C_GenerateKeyPair)
#ifdef CK_NEED_ARG_LIST
(
 CK_SESSION_HANDLE    hSession,                    /* session
												   * handle */
												   CK_MECHANISM_PTR     pMechanism,                  /* key-gen
																									 * mech. */
																									 CK_ATTRIBUTE_PTR     pPublicKeyTemplate,          /* template
																																					   * for pub.
																																					   * key */
																																					   CK_ULONG             ulPublicKeyAttributeCount,   /* # pub.
																																																		 * attrs. */
																																																		 CK_ATTRIBUTE_PTR     pPrivateKeyTemplate,         /* template
																																																														   * for priv.
																																																														   * key */
																																																														   CK_ULONG             ulPrivateKeyAttributeCount,  /* # priv.
																																																																											 * attrs. */
																																																																											 CK_OBJECT_HANDLE_PTR phPublicKey,                 /* gets pub.
																																																																																							   * key
																																																																																							   * handle */
																																																																																							   CK_OBJECT_HANDLE_PTR phPrivateKey                 /* gets
																																																																																																				 * priv. key
																																																																																																				 * handle */
																																																																																																				 );
#endif


/* C_WrapKey wraps (i.e., encrypts) a key. */
CK_PKCS11_FUNCTION_INFO(C_WrapKey)
#ifdef CK_NEED_ARG_LIST
(
 CK_SESSION_HANDLE hSession,        /* the session's handle */
 CK_MECHANISM_PTR  pMechanism,      /* the wrapping mechanism */
 CK_OBJECT_HANDLE  hWrappingKey,    /* wrapping key */
 CK_OBJECT_HANDLE  hKey,            /* key to be wrapped */
 CK_BYTE_PTR       pWrappedKey,     /* gets wrapped key */
 CK_ULONG_PTR      pulWrappedKeyLen /* gets wrapped key size */
 );
#endif


/* C_UnwrapKey unwraps (decrypts) a wrapped key, creating a new
* key object. */
CK_PKCS11_FUNCTION_INFO(C_UnwrapKey)
#ifdef CK_NEED_ARG_LIST
(
 CK_SESSION_HANDLE    hSession,          /* session's handle */
 CK_MECHANISM_PTR     pMechanism,        /* unwrapping mech. */
 CK_OBJECT_HANDLE     hUnwrappingKey,    /* unwrapping key */
 CK_BYTE_PTR          pWrappedKey,       /* the wrapped key */
 CK_ULONG             ulWrappedKeyLen,   /* wrapped key len */
 CK_ATTRIBUTE_PTR     pTemplate,         /* new key template */
 CK_ULONG             ulAttributeCount,  /* template length */
 CK_OBJECT_HANDLE_PTR phKey              /* gets new handle */
 );
#endif


/* C_DeriveKey derives a key from a base key, creating a new key
* object. */
CK_PKCS11_FUNCTION_INFO(C_DeriveKey)
#ifdef CK_NEED_ARG_LIST
(
 CK_SESSION_HANDLE    hSession,          /* session's handle */
 CK_MECHANISM_PTR     pMechanism,        /* key deriv. mech. */
 CK_OBJECT_HANDLE     hBaseKey,          /* base key */
 CK_ATTRIBUTE_PTR     pTemplate,         /* new key template */
 CK_ULONG             ulAttributeCount,  /* template length */
 CK_OBJECT_HANDLE_PTR phKey              /* gets new handle */
 );
#endif



/* Random number generation */

/* C_SeedRandom mixes additional seed material into the token's
* random number generator. */
CK_PKCS11_FUNCTION_INFO(C_SeedRandom)
#ifdef CK_NEED_ARG_LIST
(
 CK_SESSION_HANDLE hSession,  /* the session's handle */
 CK_BYTE_PTR       pSeed,     /* the seed material */
 CK_ULONG          ulSeedLen  /* length of seed material */
 );
#endif


/* C_GenerateRandom generates random data. */
CK_PKCS11_FUNCTION_INFO(C_GenerateRandom)
#ifdef CK_NEED_ARG_LIST
(
 CK_SESSION_HANDLE hSession,    /* the session's handle */
 CK_BYTE_PTR       RandomData,  /* receives the random data */
 CK_ULONG          ulRandomLen  /* # of bytes to generate */
 );
#endif



/* Parallel function management */

/* C_GetFunctionStatus is a legacy function; it obtains an
* updated status of a function running in parallel with an
* application. */
CK_PKCS11_FUNCTION_INFO(C_GetFunctionStatus)
#ifdef CK_NEED_ARG_LIST
(
 CK_SESSION_HANDLE hSession  /* the session's handle */
 );
#endif


/* C_CancelFunction is a legacy function; it cancels a function
* running in parallel. */
CK_PKCS11_FUNCTION_INFO(C_CancelFunction)
#ifdef CK_NEED_ARG_LIST
(
 CK_SESSION_HANDLE hSession  /* the session's handle */
 );
#endif



/* Functions added in for Cryptoki Version 2.01 or later */

/* C_WaitForSlotEvent waits for a slot event (token insertion,
* removal, etc.) to occur. */
CK_PKCS11_FUNCTION_INFO(C_WaitForSlotEvent)
#ifdef CK_NEED_ARG_LIST
(
 CK_FLAGS flags,        /* blocking/nonblocking flag */
 CK_SLOT_ID_PTR pSlot,  /* location that receives the slot ID */
 CK_VOID_PTR pRserved   /* reserved.  Should be NULL_PTR */
 );
#endif

/************************************************************************/
/*
	end of
	#include "pkcs11f.h"
	darpangs
*/
/************************************************************************/


#undef CK_NEED_ARG_LIST
#undef CK_PKCS11_FUNCTION_INFO


	/* ==============================================================
	* Define structed vector of entry points.  A CK_FUNCTION_LIST
	* contains a CK_VERSION indicating a library's Cryptoki version
	* and then a whole slew of function pointers to the routines in
	* the library.  This type was declared, but not defined, in
	* pkcs11t.h.
	* ==============================================================
	*/

#define CK_PKCS11_FUNCTION_INFO(name) \
	__PASTE(CK_,name) name;

	struct CK_FUNCTION_LIST {

		CK_VERSION    version;  /* Cryptoki version */

		/* Pile all the function pointers into the CK_FUNCTION_LIST. */
		/* pkcs11f.h has all the information about the Cryptoki
		* function prototypes. */
/************************************************************************/
/*
	#include "pkcs11f.h"
	darpangs
*/
/************************************************************************/
		/* pkcs11f.h include file for PKCS #11. */
		/* $Revision: 1.4 $ */

		/* General-purpose */

		/* C_Initialize initializes the Cryptoki library. */
		CK_PKCS11_FUNCTION_INFO(C_Initialize)
#ifdef CK_NEED_ARG_LIST
			(
			CK_VOID_PTR   pInitArgs  /* if this is not NULL_PTR, it gets
									 * cast to CK_C_INITIALIZE_ARGS_PTR
									 * and dereferenced */
									 );
#endif


		/* C_Finalize indicates that an application is done with the
		* Cryptoki library. */
		CK_PKCS11_FUNCTION_INFO(C_Finalize)
#ifdef CK_NEED_ARG_LIST
			(
			CK_VOID_PTR   pReserved  /* reserved.  Should be NULL_PTR */
			);
#endif


		/* C_GetInfo returns general information about Cryptoki. */
		CK_PKCS11_FUNCTION_INFO(C_GetInfo)
#ifdef CK_NEED_ARG_LIST
			(
			CK_INFO_PTR   pInfo  /* location that receives information */
			);
#endif


		/* C_GetFunctionList returns the function list. */
		CK_PKCS11_FUNCTION_INFO(C_GetFunctionList)
#ifdef CK_NEED_ARG_LIST
			(
			CK_FUNCTION_LIST_PTR_PTR ppFunctionList  /* receives pointer to
													 * function list */
													 );
#endif



		/* Slot and token management */

		/* C_GetSlotList obtains a list of slots in the system. */
		CK_PKCS11_FUNCTION_INFO(C_GetSlotList)
#ifdef CK_NEED_ARG_LIST
			(
			CK_BBOOL       tokenPresent,  /* only slots with tokens? */
			CK_SLOT_ID_PTR pSlotList,     /* receives array of slot IDs */
			CK_ULONG_PTR   pulCount       /* receives number of slots */
			);
#endif


		/* C_GetSlotInfo obtains information about a particular slot in
		* the system. */
		CK_PKCS11_FUNCTION_INFO(C_GetSlotInfo)
#ifdef CK_NEED_ARG_LIST
			(
			CK_SLOT_ID       slotID,  /* the ID of the slot */
			CK_SLOT_INFO_PTR pInfo    /* receives the slot information */
			);
#endif


		/* C_GetTokenInfo obtains information about a particular token
		* in the system. */
		CK_PKCS11_FUNCTION_INFO(C_GetTokenInfo)
#ifdef CK_NEED_ARG_LIST
			(
			CK_SLOT_ID        slotID,  /* ID of the token's slot */
			CK_TOKEN_INFO_PTR pInfo    /* receives the token information */
			);
#endif


		/* C_GetMechanismList obtains a list of mechanism types
		* supported by a token. */
		CK_PKCS11_FUNCTION_INFO(C_GetMechanismList)
#ifdef CK_NEED_ARG_LIST
			(
			CK_SLOT_ID            slotID,          /* ID of token's slot */
			CK_MECHANISM_TYPE_PTR pMechanismList,  /* gets mech. array */
			CK_ULONG_PTR          pulCount         /* gets # of mechs. */
			);
#endif


		/* C_GetMechanismInfo obtains information about a particular
		* mechanism possibly supported by a token. */
		CK_PKCS11_FUNCTION_INFO(C_GetMechanismInfo)
#ifdef CK_NEED_ARG_LIST
			(
			CK_SLOT_ID            slotID,  /* ID of the token's slot */
			CK_MECHANISM_TYPE     type,    /* type of mechanism */
			CK_MECHANISM_INFO_PTR pInfo    /* receives mechanism info */
			);
#endif


		/* C_InitToken initializes a token. */
		CK_PKCS11_FUNCTION_INFO(C_InitToken)
#ifdef CK_NEED_ARG_LIST
			/* pLabel changed from CK_CHAR_PTR to CK_UTF8CHAR_PTR for v2.10 */
			(
			CK_SLOT_ID      slotID,    /* ID of the token's slot */
			CK_UTF8CHAR_PTR pPin,      /* the SO's initial PIN */
			CK_ULONG        ulPinLen,  /* length in bytes of the PIN */
			CK_UTF8CHAR_PTR pLabel     /* 32-byte token label (blank padded) */
			);
#endif


		/* C_InitPIN initializes the normal user's PIN. */
		CK_PKCS11_FUNCTION_INFO(C_InitPIN)
#ifdef CK_NEED_ARG_LIST
			(
			CK_SESSION_HANDLE hSession,  /* the session's handle */
			CK_UTF8CHAR_PTR   pPin,      /* the normal user's PIN */
			CK_ULONG          ulPinLen   /* length in bytes of the PIN */
			);
#endif


		/* C_SetPIN modifies the PIN of the user who is logged in. */
		CK_PKCS11_FUNCTION_INFO(C_SetPIN)
#ifdef CK_NEED_ARG_LIST
			(
			CK_SESSION_HANDLE hSession,  /* the session's handle */
			CK_UTF8CHAR_PTR   pOldPin,   /* the old PIN */
			CK_ULONG          ulOldLen,  /* length of the old PIN */
			CK_UTF8CHAR_PTR   pNewPin,   /* the new PIN */
			CK_ULONG          ulNewLen   /* length of the new PIN */
			);
#endif



		/* Session management */

		/* C_OpenSession opens a session between an application and a
		* token. */
		CK_PKCS11_FUNCTION_INFO(C_OpenSession)
#ifdef CK_NEED_ARG_LIST
			(
			CK_SLOT_ID            slotID,        /* the slot's ID */
			CK_FLAGS              flags,         /* from CK_SESSION_INFO */
			CK_VOID_PTR           pApplication,  /* passed to callback */
			CK_NOTIFY             Notify,        /* callback function */
			CK_SESSION_HANDLE_PTR phSession      /* gets session handle */
			);
#endif


		/* C_CloseSession closes a session between an application and a
		* token. */
		CK_PKCS11_FUNCTION_INFO(C_CloseSession)
#ifdef CK_NEED_ARG_LIST
			(
			CK_SESSION_HANDLE hSession  /* the session's handle */
			);
#endif


		/* C_CloseAllSessions closes all sessions with a token. */
		CK_PKCS11_FUNCTION_INFO(C_CloseAllSessions)
#ifdef CK_NEED_ARG_LIST
			(
			CK_SLOT_ID     slotID  /* the token's slot */
			);
#endif


		/* C_GetSessionInfo obtains information about the session. */
		CK_PKCS11_FUNCTION_INFO(C_GetSessionInfo)
#ifdef CK_NEED_ARG_LIST
			(
			CK_SESSION_HANDLE   hSession,  /* the session's handle */
			CK_SESSION_INFO_PTR pInfo      /* receives session info */
			);
#endif


		/* C_GetOperationState obtains the state of the cryptographic operation
		* in a session. */
		CK_PKCS11_FUNCTION_INFO(C_GetOperationState)
#ifdef CK_NEED_ARG_LIST
			(
			CK_SESSION_HANDLE hSession,             /* session's handle */
			CK_BYTE_PTR       pOperationState,      /* gets state */
			CK_ULONG_PTR      pulOperationStateLen  /* gets state length */
			);
#endif


		/* C_SetOperationState restores the state of the cryptographic
		* operation in a session. */
		CK_PKCS11_FUNCTION_INFO(C_SetOperationState)
#ifdef CK_NEED_ARG_LIST
			(
			CK_SESSION_HANDLE hSession,            /* session's handle */
			CK_BYTE_PTR      pOperationState,      /* holds state */
			CK_ULONG         ulOperationStateLen,  /* holds state length */
			CK_OBJECT_HANDLE hEncryptionKey,       /* en/decryption key */
			CK_OBJECT_HANDLE hAuthenticationKey    /* sign/verify key */
			);
#endif


		/* C_Login logs a user into a token. */
		CK_PKCS11_FUNCTION_INFO(C_Login)
#ifdef CK_NEED_ARG_LIST
			(
			CK_SESSION_HANDLE hSession,  /* the session's handle */
			CK_USER_TYPE      userType,  /* the user type */
			CK_UTF8CHAR_PTR   pPin,      /* the user's PIN */
			CK_ULONG          ulPinLen   /* the length of the PIN */
			);
#endif


		/* C_Logout logs a user out from a token. */
		CK_PKCS11_FUNCTION_INFO(C_Logout)
#ifdef CK_NEED_ARG_LIST
			(
			CK_SESSION_HANDLE hSession  /* the session's handle */
			);
#endif

	CK_PKCS11_FUNCTION_INFO(C_LoginBegin)
#ifdef CK_NEED_ARG_LIST
		(
			CK_SESSION_HANDLE hSession,  /* the session's handle */
			CK_USER_TYPE      userType,  /* the user type */
			CK_ULONG_PTR      pulK,      /* cards required to load logical token. */
			CK_ULONG_PTR      pulN       /* Number of cards in set */
		);
#endif

/* C_LoginNext logs a user into a token. */
CK_PKCS11_FUNCTION_INFO(C_LoginNext)
#ifdef CK_NEED_ARG_LIST
		(
			CK_SESSION_HANDLE hSession,  /* the session's handle */
			CK_USER_TYPE      userType,  /* the user type */
			CK_CHAR_PTR       pPin,      /* the user's PIN */
			CK_ULONG          ulPinLen,   /* the length of the PIN */
			CK_ULONG_PTR      pulSharesLeft /* Number of remaining shares */
		);
#endif

/* C_LoginEnd logs a user into a token. */
CK_PKCS11_FUNCTION_INFO(C_LoginEnd)
#ifdef CK_NEED_ARG_LIST
		(
			CK_SESSION_HANDLE hSession,  /* the session's handle */
			CK_USER_TYPE      userType  /* the user type */
		);
#endif


		/* Object management */

		/* C_CreateObject creates a new object. */
		CK_PKCS11_FUNCTION_INFO(C_CreateObject)
#ifdef CK_NEED_ARG_LIST
			(
			CK_SESSION_HANDLE hSession,    /* the session's handle */
			CK_ATTRIBUTE_PTR  pTemplate,   /* the object's template */
			CK_ULONG          ulCount,     /* attributes in template */
			CK_OBJECT_HANDLE_PTR phObject  /* gets new object's handle. */
			);
#endif


		/* C_CopyObject copies an object, creating a new object for the
		* copy. */
		CK_PKCS11_FUNCTION_INFO(C_CopyObject)
#ifdef CK_NEED_ARG_LIST
			(
			CK_SESSION_HANDLE    hSession,    /* the session's handle */
			CK_OBJECT_HANDLE     hObject,     /* the object's handle */
			CK_ATTRIBUTE_PTR     pTemplate,   /* template for new object */
			CK_ULONG             ulCount,     /* attributes in template */
			CK_OBJECT_HANDLE_PTR phNewObject  /* receives handle of copy */
			);
#endif


		/* C_DestroyObject destroys an object. */
		CK_PKCS11_FUNCTION_INFO(C_DestroyObject)
#ifdef CK_NEED_ARG_LIST
			(
			CK_SESSION_HANDLE hSession,  /* the session's handle */
			CK_OBJECT_HANDLE  hObject    /* the object's handle */
			);
#endif


		/* C_GetObjectSize gets the size of an object in bytes. */
		CK_PKCS11_FUNCTION_INFO(C_GetObjectSize)
#ifdef CK_NEED_ARG_LIST
			(
			CK_SESSION_HANDLE hSession,  /* the session's handle */
			CK_OBJECT_HANDLE  hObject,   /* the object's handle */
			CK_ULONG_PTR      pulSize    /* receives size of object */
			);
#endif


		/* C_GetAttributeValue obtains the value of one or more object
		* attributes. */
		CK_PKCS11_FUNCTION_INFO(C_GetAttributeValue)
#ifdef CK_NEED_ARG_LIST
			(
			CK_SESSION_HANDLE hSession,   /* the session's handle */
			CK_OBJECT_HANDLE  hObject,    /* the object's handle */
			CK_ATTRIBUTE_PTR  pTemplate,  /* specifies attrs; gets vals */
			CK_ULONG          ulCount     /* attributes in template */
			);
#endif


		/* C_SetAttributeValue modifies the value of one or more object
		* attributes */
		CK_PKCS11_FUNCTION_INFO(C_SetAttributeValue)
#ifdef CK_NEED_ARG_LIST
			(
			CK_SESSION_HANDLE hSession,   /* the session's handle */
			CK_OBJECT_HANDLE  hObject,    /* the object's handle */
			CK_ATTRIBUTE_PTR  pTemplate,  /* specifies attrs and values */
			CK_ULONG          ulCount     /* attributes in template */
			);
#endif


		/* C_FindObjectsInit initializes a search for token and session
		* objects that match a template. */
		CK_PKCS11_FUNCTION_INFO(C_FindObjectsInit)
#ifdef CK_NEED_ARG_LIST
			(
			CK_SESSION_HANDLE hSession,   /* the session's handle */
			CK_ATTRIBUTE_PTR  pTemplate,  /* attribute values to match */
			CK_ULONG          ulCount     /* attrs in search template */
			);
#endif


		/* C_FindObjects continues a search for token and session
		* objects that match a template, obtaining additional object
		* handles. */
		CK_PKCS11_FUNCTION_INFO(C_FindObjects)
#ifdef CK_NEED_ARG_LIST
			(
			CK_SESSION_HANDLE    hSession,          /* session's handle */
			CK_OBJECT_HANDLE_PTR phObject,          /* gets obj. handles */
			CK_ULONG             ulMaxObjectCount,  /* max handles to get */
			CK_ULONG_PTR         pulObjectCount     /* actual # returned */
			);
#endif


		/* C_FindObjectsFinal finishes a search for token and session
		* objects. */
		CK_PKCS11_FUNCTION_INFO(C_FindObjectsFinal)
#ifdef CK_NEED_ARG_LIST
			(
			CK_SESSION_HANDLE hSession  /* the session's handle */
			);
#endif



		/* Encryption and decryption */

		/* C_EncryptInit initializes an encryption operation. */
		CK_PKCS11_FUNCTION_INFO(C_EncryptInit)
#ifdef CK_NEED_ARG_LIST
			(
			CK_SESSION_HANDLE hSession,    /* the session's handle */
			CK_MECHANISM_PTR  pMechanism,  /* the encryption mechanism */
			CK_OBJECT_HANDLE  hKey         /* handle of encryption key */
			);
#endif


		/* C_Encrypt encrypts single-part data. */
		CK_PKCS11_FUNCTION_INFO(C_Encrypt)
#ifdef CK_NEED_ARG_LIST
			(
			CK_SESSION_HANDLE hSession,            /* session's handle */
			CK_BYTE_PTR       pData,               /* the plaintext data */
			CK_ULONG          ulDataLen,           /* bytes of plaintext */
			CK_BYTE_PTR       pEncryptedData,      /* gets ciphertext */
			CK_ULONG_PTR      pulEncryptedDataLen  /* gets c-text size */
			);
#endif


		/* C_EncryptUpdate continues a multiple-part encryption
		* operation. */
		CK_PKCS11_FUNCTION_INFO(C_EncryptUpdate)
#ifdef CK_NEED_ARG_LIST
			(
			CK_SESSION_HANDLE hSession,           /* session's handle */
			CK_BYTE_PTR       pPart,              /* the plaintext data */
			CK_ULONG          ulPartLen,          /* plaintext data len */
			CK_BYTE_PTR       pEncryptedPart,     /* gets ciphertext */
			CK_ULONG_PTR      pulEncryptedPartLen /* gets c-text size */
			);
#endif


		/* C_EncryptFinal finishes a multiple-part encryption
		* operation. */
		CK_PKCS11_FUNCTION_INFO(C_EncryptFinal)
#ifdef CK_NEED_ARG_LIST
			(
			CK_SESSION_HANDLE hSession,                /* session handle */
			CK_BYTE_PTR       pLastEncryptedPart,      /* last c-text */
			CK_ULONG_PTR      pulLastEncryptedPartLen  /* gets last size */
			);
#endif


		/* C_DecryptInit initializes a decryption operation. */
		CK_PKCS11_FUNCTION_INFO(C_DecryptInit)
#ifdef CK_NEED_ARG_LIST
			(
			CK_SESSION_HANDLE hSession,    /* the session's handle */
			CK_MECHANISM_PTR  pMechanism,  /* the decryption mechanism */
			CK_OBJECT_HANDLE  hKey         /* handle of decryption key */
			);
#endif


		/* C_Decrypt decrypts encrypted data in a single part. */
		CK_PKCS11_FUNCTION_INFO(C_Decrypt)
#ifdef CK_NEED_ARG_LIST
			(
			CK_SESSION_HANDLE hSession,           /* session's handle */
			CK_BYTE_PTR       pEncryptedData,     /* ciphertext */
			CK_ULONG          ulEncryptedDataLen, /* ciphertext length */
			CK_BYTE_PTR       pData,              /* gets plaintext */
			CK_ULONG_PTR      pulDataLen          /* gets p-text size */
			);
#endif


		/* C_DecryptUpdate continues a multiple-part decryption
		* operation. */
		CK_PKCS11_FUNCTION_INFO(C_DecryptUpdate)
#ifdef CK_NEED_ARG_LIST
			(
			CK_SESSION_HANDLE hSession,            /* session's handle */
			CK_BYTE_PTR       pEncryptedPart,      /* encrypted data */
			CK_ULONG          ulEncryptedPartLen,  /* input length */
			CK_BYTE_PTR       pPart,               /* gets plaintext */
			CK_ULONG_PTR      pulPartLen           /* p-text size */
			);
#endif


		/* C_DecryptFinal finishes a multiple-part decryption
		* operation. */
		CK_PKCS11_FUNCTION_INFO(C_DecryptFinal)
#ifdef CK_NEED_ARG_LIST
			(
			CK_SESSION_HANDLE hSession,       /* the session's handle */
			CK_BYTE_PTR       pLastPart,      /* gets plaintext */
			CK_ULONG_PTR      pulLastPartLen  /* p-text size */
			);
#endif



		/* Message digesting */

		/* C_DigestInit initializes a message-digesting operation. */
		CK_PKCS11_FUNCTION_INFO(C_DigestInit)
#ifdef CK_NEED_ARG_LIST
			(
			CK_SESSION_HANDLE hSession,   /* the session's handle */
			CK_MECHANISM_PTR  pMechanism  /* the digesting mechanism */
			);
#endif


		/* C_Digest digests data in a single part. */
		CK_PKCS11_FUNCTION_INFO(C_Digest)
#ifdef CK_NEED_ARG_LIST
			(
			CK_SESSION_HANDLE hSession,     /* the session's handle */
			CK_BYTE_PTR       pData,        /* data to be digested */
			CK_ULONG          ulDataLen,    /* bytes of data to digest */
			CK_BYTE_PTR       pDigest,      /* gets the message digest */
			CK_ULONG_PTR      pulDigestLen  /* gets digest length */
			);
#endif


		/* C_DigestUpdate continues a multiple-part message-digesting
		* operation. */
		CK_PKCS11_FUNCTION_INFO(C_DigestUpdate)
#ifdef CK_NEED_ARG_LIST
			(
			CK_SESSION_HANDLE hSession,  /* the session's handle */
			CK_BYTE_PTR       pPart,     /* data to be digested */
			CK_ULONG          ulPartLen  /* bytes of data to be digested */
			);
#endif


		/* C_DigestKey continues a multi-part message-digesting
		* operation, by digesting the value of a secret key as part of
		* the data already digested. */
		CK_PKCS11_FUNCTION_INFO(C_DigestKey)
#ifdef CK_NEED_ARG_LIST
			(
			CK_SESSION_HANDLE hSession,  /* the session's handle */
			CK_OBJECT_HANDLE  hKey       /* secret key to digest */
			);
#endif


		/* C_DigestFinal finishes a multiple-part message-digesting
		* operation. */
		CK_PKCS11_FUNCTION_INFO(C_DigestFinal)
#ifdef CK_NEED_ARG_LIST
			(
			CK_SESSION_HANDLE hSession,     /* the session's handle */
			CK_BYTE_PTR       pDigest,      /* gets the message digest */
			CK_ULONG_PTR      pulDigestLen  /* gets byte count of digest */
			);
#endif



		/* Signing and MACing */

		/* C_SignInit initializes a signature (private key encryption)
		* operation, where the signature is (will be) an appendix to
		* the data, and plaintext cannot be recovered from the
		*signature. */
		CK_PKCS11_FUNCTION_INFO(C_SignInit)
#ifdef CK_NEED_ARG_LIST
			(
			CK_SESSION_HANDLE hSession,    /* the session's handle */
			CK_MECHANISM_PTR  pMechanism,  /* the signature mechanism */
			CK_OBJECT_HANDLE  hKey         /* handle of signature key */
			);
#endif


		/* C_Sign signs (encrypts with private key) data in a single
		* part, where the signature is (will be) an appendix to the
		* data, and plaintext cannot be recovered from the signature. */
		CK_PKCS11_FUNCTION_INFO(C_Sign)
#ifdef CK_NEED_ARG_LIST
			(
			CK_SESSION_HANDLE hSession,        /* the session's handle */
			CK_BYTE_PTR       pData,           /* the data to sign */
			CK_ULONG          ulDataLen,       /* count of bytes to sign */
			CK_BYTE_PTR       pSignature,      /* gets the signature */
			CK_ULONG_PTR      pulSignatureLen  /* gets signature length */
			);
#endif


		/* C_SignUpdate continues a multiple-part signature operation,
		* where the signature is (will be) an appendix to the data,
		* and plaintext cannot be recovered from the signature. */
		CK_PKCS11_FUNCTION_INFO(C_SignUpdate)
#ifdef CK_NEED_ARG_LIST
			(
			CK_SESSION_HANDLE hSession,  /* the session's handle */
			CK_BYTE_PTR       pPart,     /* the data to sign */
			CK_ULONG          ulPartLen  /* count of bytes to sign */
			);
#endif


		/* C_SignFinal finishes a multiple-part signature operation,
		* returning the signature. */
		CK_PKCS11_FUNCTION_INFO(C_SignFinal)
#ifdef CK_NEED_ARG_LIST
			(
			CK_SESSION_HANDLE hSession,        /* the session's handle */
			CK_BYTE_PTR       pSignature,      /* gets the signature */
			CK_ULONG_PTR      pulSignatureLen  /* gets signature length */
			);
#endif


		/* C_SignRecoverInit initializes a signature operation, where
		* the data can be recovered from the signature. */
		CK_PKCS11_FUNCTION_INFO(C_SignRecoverInit)
#ifdef CK_NEED_ARG_LIST
			(
			CK_SESSION_HANDLE hSession,   /* the session's handle */
			CK_MECHANISM_PTR  pMechanism, /* the signature mechanism */
			CK_OBJECT_HANDLE  hKey        /* handle of the signature key */
			);
#endif


		/* C_SignRecover signs data in a single operation, where the
		* data can be recovered from the signature. */
		CK_PKCS11_FUNCTION_INFO(C_SignRecover)
#ifdef CK_NEED_ARG_LIST
			(
			CK_SESSION_HANDLE hSession,        /* the session's handle */
			CK_BYTE_PTR       pData,           /* the data to sign */
			CK_ULONG          ulDataLen,       /* count of bytes to sign */
			CK_BYTE_PTR       pSignature,      /* gets the signature */
			CK_ULONG_PTR      pulSignatureLen  /* gets signature length */
			);
#endif



		/* Verifying signatures and MACs */

		/* C_VerifyInit initializes a verification operation, where the
		* signature is an appendix to the data, and plaintext cannot
		*  cannot be recovered from the signature (e.g. ISC_DSA). */
		CK_PKCS11_FUNCTION_INFO(C_VerifyInit)
#ifdef CK_NEED_ARG_LIST
			(
			CK_SESSION_HANDLE hSession,    /* the session's handle */
			CK_MECHANISM_PTR  pMechanism,  /* the verification mechanism */
			CK_OBJECT_HANDLE  hKey         /* verification key */
			);
#endif


		/* C_Verify verifies a signature in a single-part operation,
		* where the signature is an appendix to the data, and plaintext
		* cannot be recovered from the signature. */
		CK_PKCS11_FUNCTION_INFO(C_Verify)
#ifdef CK_NEED_ARG_LIST
			(
			CK_SESSION_HANDLE hSession,       /* the session's handle */
			CK_BYTE_PTR       pData,          /* signed data */
			CK_ULONG          ulDataLen,      /* length of signed data */
			CK_BYTE_PTR       pSignature,     /* signature */
			CK_ULONG          ulSignatureLen  /* signature length*/
			);
#endif


		/* C_VerifyUpdate continues a multiple-part verification
		* operation, where the signature is an appendix to the data,
		* and plaintext cannot be recovered from the signature. */
		CK_PKCS11_FUNCTION_INFO(C_VerifyUpdate)
#ifdef CK_NEED_ARG_LIST
			(
			CK_SESSION_HANDLE hSession,  /* the session's handle */
			CK_BYTE_PTR       pPart,     /* signed data */
			CK_ULONG          ulPartLen  /* length of signed data */
			);
#endif


		/* C_VerifyFinal finishes a multiple-part verification
		* operation, checking the signature. */
		CK_PKCS11_FUNCTION_INFO(C_VerifyFinal)
#ifdef CK_NEED_ARG_LIST
			(
			CK_SESSION_HANDLE hSession,       /* the session's handle */
			CK_BYTE_PTR       pSignature,     /* signature to verify */
			CK_ULONG          ulSignatureLen  /* signature length */
			);
#endif


		/* C_VerifyRecoverInit initializes a signature verification
		* operation, where the data is recovered from the signature. */
		CK_PKCS11_FUNCTION_INFO(C_VerifyRecoverInit)
#ifdef CK_NEED_ARG_LIST
			(
			CK_SESSION_HANDLE hSession,    /* the session's handle */
			CK_MECHANISM_PTR  pMechanism,  /* the verification mechanism */
			CK_OBJECT_HANDLE  hKey         /* verification key */
			);
#endif


		/* C_VerifyRecover verifies a signature in a single-part
		* operation, where the data is recovered from the signature. */
		CK_PKCS11_FUNCTION_INFO(C_VerifyRecover)
#ifdef CK_NEED_ARG_LIST
			(
			CK_SESSION_HANDLE hSession,        /* the session's handle */
			CK_BYTE_PTR       pSignature,      /* signature to verify */
			CK_ULONG          ulSignatureLen,  /* signature length */
			CK_BYTE_PTR       pData,           /* gets signed data */
			CK_ULONG_PTR      pulDataLen       /* gets signed data len */
			);
#endif



		/* Dual-function cryptographic operations */

		/* C_DigestEncryptUpdate continues a multiple-part digesting
		* and encryption operation. */
		CK_PKCS11_FUNCTION_INFO(C_DigestEncryptUpdate)
#ifdef CK_NEED_ARG_LIST
			(
			CK_SESSION_HANDLE hSession,            /* session's handle */
			CK_BYTE_PTR       pPart,               /* the plaintext data */
			CK_ULONG          ulPartLen,           /* plaintext length */
			CK_BYTE_PTR       pEncryptedPart,      /* gets ciphertext */
			CK_ULONG_PTR      pulEncryptedPartLen  /* gets c-text length */
			);
#endif


		/* C_DecryptDigestUpdate continues a multiple-part decryption and
		* digesting operation. */
		CK_PKCS11_FUNCTION_INFO(C_DecryptDigestUpdate)
#ifdef CK_NEED_ARG_LIST
			(
			CK_SESSION_HANDLE hSession,            /* session's handle */
			CK_BYTE_PTR       pEncryptedPart,      /* ciphertext */
			CK_ULONG          ulEncryptedPartLen,  /* ciphertext length */
			CK_BYTE_PTR       pPart,               /* gets plaintext */
			CK_ULONG_PTR      pulPartLen           /* gets plaintext len */
			);
#endif


		/* C_SignEncryptUpdate continues a multiple-part signing and
		* encryption operation. */
		CK_PKCS11_FUNCTION_INFO(C_SignEncryptUpdate)
#ifdef CK_NEED_ARG_LIST
			(
			CK_SESSION_HANDLE hSession,            /* session's handle */
			CK_BYTE_PTR       pPart,               /* the plaintext data */
			CK_ULONG          ulPartLen,           /* plaintext length */
			CK_BYTE_PTR       pEncryptedPart,      /* gets ciphertext */
			CK_ULONG_PTR      pulEncryptedPartLen  /* gets c-text length */
			);
#endif


		/* C_DecryptVerifyUpdate continues a multiple-part decryption and
		* verify operation. */
		CK_PKCS11_FUNCTION_INFO(C_DecryptVerifyUpdate)
#ifdef CK_NEED_ARG_LIST
			(
			CK_SESSION_HANDLE hSession,            /* session's handle */
			CK_BYTE_PTR       pEncryptedPart,      /* ciphertext */
			CK_ULONG          ulEncryptedPartLen,  /* ciphertext length */
			CK_BYTE_PTR       pPart,               /* gets plaintext */
			CK_ULONG_PTR      pulPartLen           /* gets p-text length */
			);
#endif



		/* Key management */

		/* C_GenerateKey generates a secret key, creating a new key
		* object. */
		CK_PKCS11_FUNCTION_INFO(C_GenerateKey)
#ifdef CK_NEED_ARG_LIST
			(
			CK_SESSION_HANDLE    hSession,    /* the session's handle */
			CK_MECHANISM_PTR     pMechanism,  /* key generation mech. */
			CK_ATTRIBUTE_PTR     pTemplate,   /* template for new key */
			CK_ULONG             ulCount,     /* # of attrs in template */
			CK_OBJECT_HANDLE_PTR phKey        /* gets handle of new key */
			);
#endif


		/* C_GenerateKeyPair generates a public-key/private-key pair,
		* creating new key objects. */
		CK_PKCS11_FUNCTION_INFO(C_GenerateKeyPair)
#ifdef CK_NEED_ARG_LIST
			(
			CK_SESSION_HANDLE    hSession,                    /* session
															  * handle */
															  CK_MECHANISM_PTR     pMechanism,                  /* key-gen
																												* mech. */
																												CK_ATTRIBUTE_PTR     pPublicKeyTemplate,          /* template
																																								  * for pub.
																																								  * key */
																																								  CK_ULONG             ulPublicKeyAttributeCount,   /* # pub.
																																																					* attrs. */
																																																					CK_ATTRIBUTE_PTR     pPrivateKeyTemplate,         /* template
																																																																	  * for priv.
																																																																	  * key */
																																																																	  CK_ULONG             ulPrivateKeyAttributeCount,  /* # priv.
																																																																														* attrs. */
																																																																														CK_OBJECT_HANDLE_PTR phPublicKey,                 /* gets pub.
																																																																																										  * key
																																																																																										  * handle */
																																																																																										  CK_OBJECT_HANDLE_PTR phPrivateKey                 /* gets
																																																																																																							* priv. key
																																																																																																							* handle */
																																																																																																							);
#endif


		/* C_WrapKey wraps (i.e., encrypts) a key. */
		CK_PKCS11_FUNCTION_INFO(C_WrapKey)
#ifdef CK_NEED_ARG_LIST
			(
			CK_SESSION_HANDLE hSession,        /* the session's handle */
			CK_MECHANISM_PTR  pMechanism,      /* the wrapping mechanism */
			CK_OBJECT_HANDLE  hWrappingKey,    /* wrapping key */
			CK_OBJECT_HANDLE  hKey,            /* key to be wrapped */
			CK_BYTE_PTR       pWrappedKey,     /* gets wrapped key */
			CK_ULONG_PTR      pulWrappedKeyLen /* gets wrapped key size */
			);
#endif


		/* C_UnwrapKey unwraps (decrypts) a wrapped key, creating a new
		* key object. */
		CK_PKCS11_FUNCTION_INFO(C_UnwrapKey)
#ifdef CK_NEED_ARG_LIST
			(
			CK_SESSION_HANDLE    hSession,          /* session's handle */
			CK_MECHANISM_PTR     pMechanism,        /* unwrapping mech. */
			CK_OBJECT_HANDLE     hUnwrappingKey,    /* unwrapping key */
			CK_BYTE_PTR          pWrappedKey,       /* the wrapped key */
			CK_ULONG             ulWrappedKeyLen,   /* wrapped key len */
			CK_ATTRIBUTE_PTR     pTemplate,         /* new key template */
			CK_ULONG             ulAttributeCount,  /* template length */
			CK_OBJECT_HANDLE_PTR phKey              /* gets new handle */
			);
#endif


		/* C_DeriveKey derives a key from a base key, creating a new key
		* object. */
		CK_PKCS11_FUNCTION_INFO(C_DeriveKey)
#ifdef CK_NEED_ARG_LIST
			(
			CK_SESSION_HANDLE    hSession,          /* session's handle */
			CK_MECHANISM_PTR     pMechanism,        /* key deriv. mech. */
			CK_OBJECT_HANDLE     hBaseKey,          /* base key */
			CK_ATTRIBUTE_PTR     pTemplate,         /* new key template */
			CK_ULONG             ulAttributeCount,  /* template length */
			CK_OBJECT_HANDLE_PTR phKey              /* gets new handle */
			);
#endif



		/* Random number generation */

		/* C_SeedRandom mixes additional seed material into the token's
		* random number generator. */
		CK_PKCS11_FUNCTION_INFO(C_SeedRandom)
#ifdef CK_NEED_ARG_LIST
			(
			CK_SESSION_HANDLE hSession,  /* the session's handle */
			CK_BYTE_PTR       pSeed,     /* the seed material */
			CK_ULONG          ulSeedLen  /* length of seed material */
			);
#endif


		/* C_GenerateRandom generates random data. */
		CK_PKCS11_FUNCTION_INFO(C_GenerateRandom)
#ifdef CK_NEED_ARG_LIST
			(
			CK_SESSION_HANDLE hSession,    /* the session's handle */
			CK_BYTE_PTR       RandomData,  /* receives the random data */
			CK_ULONG          ulRandomLen  /* # of bytes to generate */
			);
#endif



		/* Parallel function management */

		/* C_GetFunctionStatus is a legacy function; it obtains an
		* updated status of a function running in parallel with an
		* application. */
		CK_PKCS11_FUNCTION_INFO(C_GetFunctionStatus)
#ifdef CK_NEED_ARG_LIST
			(
			CK_SESSION_HANDLE hSession  /* the session's handle */
			);
#endif


		/* C_CancelFunction is a legacy function; it cancels a function
		* running in parallel. */
		CK_PKCS11_FUNCTION_INFO(C_CancelFunction)
#ifdef CK_NEED_ARG_LIST
			(
			CK_SESSION_HANDLE hSession  /* the session's handle */
			);
#endif



		/* Functions added in for Cryptoki Version 2.01 or later */

		/* C_WaitForSlotEvent waits for a slot event (token insertion,
		* removal, etc.) to occur. */
		CK_PKCS11_FUNCTION_INFO(C_WaitForSlotEvent)
#ifdef CK_NEED_ARG_LIST
			(
			CK_FLAGS flags,        /* blocking/nonblocking flag */
			CK_SLOT_ID_PTR pSlot,  /* location that receives the slot ID */
			CK_VOID_PTR pRserved   /* reserved.  Should be NULL_PTR */
			);
#endif

/************************************************************************/
/*
	end of
	#include "pkcs11f.h"
	darpangs
*/
/************************************************************************/

	};

#undef CK_PKCS11_FUNCTION_INFO


#undef __PASTE

#ifdef __cplusplus
}
#endif

#endif


/************************************************************************/
/*
	end of
	#include "pkcs11.h"
	darpangs
*/
/************************************************************************/
#ifdef WIN32
#pragma pack(pop, cryptoki)
#endif

#endif /* ___CRYPTOKI_H_INC___ */


/************************************************************************/
/*
	end of
	#include "PKCS11/cryptoki.h"
	darpangs
*/
/************************************************************************/
#define CKA_VENDOR_DEFINED 0x80000000
#define CKM_VENDOR_DEFINED 0x80000000
#define CKK_VENDOR_DEFINED 0x80000000

#define NFCK_VENDOR_NCIPHER 0xde436972UL
#define CKA_NCIPHER (CKA_VENDOR_DEFINED | NFCK_VENDOR_NCIPHER)
#define CKM_NCIPHER (CKM_VENDOR_DEFINED | NFCK_VENDOR_NCIPHER)
#define CKK_NCIPHER (CKK_VENDOR_DEFINED | NFCK_VENDOR_NCIPHER)

#define CKK_SEED (CKK_NCIPHER + 0x33UL)

/* Adding ISC_SEED mech key genration and usage */
#define CKM_SEED_KEY_GEN (CKM_NCIPHER + 0x12UL)
#define CKM_SEED_ECB (CKM_NCIPHER + 0x13UL)
#define CKM_SEED_CBC (CKM_NCIPHER + 0x14UL)
#define CKM_SEED_CBC_PAD (CKM_NCIPHER + 0x15UL)
#define CKM_SEED_MAC (CKM_NCIPHER + 0x16UL)
#define CKM_SEED_MAC_GENERAL (CKM_NCIPHER + 0x17UL)

typedef CK_RV (*Initialize)( CK_VOID_PTR);
typedef CK_RV (*GetSlotList)(CK_BBOOL, CK_SLOT_ID_PTR, CK_ULONG_PTR);
typedef CK_RV (*GetSlotInfo)( CK_SLOT_ID ,CK_SLOT_INFO_PTR );
typedef CK_RV (*GetTokenInfo)(CK_SLOT_ID, CK_TOKEN_INFO_PTR);
typedef CK_RV (*GetMechanismList)(CK_SLOT_ID, CK_MECHANISM_TYPE_PTR, CK_ULONG_PTR);
typedef CK_RV (*GetMechanismInfo)(CK_SLOT_ID, CK_MECHANISM_TYPE, CK_MECHANISM_INFO_PTR);
typedef CK_RV (*OpenSession)(CK_SLOT_ID, CK_FLAGS, CK_VOID_PTR, CK_NOTIFY, CK_SESSION_HANDLE_PTR);
typedef CK_RV (*CloseSession)(CK_SESSION_HANDLE);
typedef CK_RV (*Login)(CK_SESSION_HANDLE, CK_USER_TYPE, CK_CHAR_PTR, CK_ULONG);
typedef CK_RV (*Logout)(CK_SESSION_HANDLE);
typedef CK_RV (*LoginBegin)(CK_SESSION_HANDLE, CK_USER_TYPE, CK_ULONG_PTR, CK_ULONG_PTR);
typedef CK_RV (*LoginNext)(CK_SESSION_HANDLE, CK_USER_TYPE, CK_CHAR_PTR, CK_ULONG, CK_ULONG_PTR );
typedef CK_RV (*LoginEnd)(CK_SESSION_HANDLE,  CK_USER_TYPE);
typedef CK_RV (*Finalize)( CK_VOID_PTR );
typedef CK_RV (*GetAttributeValue)(CK_SESSION_HANDLE, CK_OBJECT_HANDLE, CK_ATTRIBUTE_PTR, CK_ULONG);
typedef CK_RV (*FindObjectsInit)(CK_SESSION_HANDLE, CK_ATTRIBUTE_PTR, CK_ULONG);
typedef CK_RV (*FindObjects)(CK_SESSION_HANDLE, CK_OBJECT_HANDLE_PTR, CK_ULONG, CK_ULONG_PTR);
typedef CK_RV (*FindObjectsFinal)(CK_SESSION_HANDLE);
typedef CK_RV (*GetFunctionList)(CK_FUNCTION_LIST_PTR_PTR );
typedef CK_RV (*GetInfo)(CK_INFO_PTR );
typedef CK_RV (*GenerateKeyPair )(CK_SESSION_HANDLE ,CK_MECHANISM_PTR ,CK_ATTRIBUTE_PTR ,CK_ULONG ,CK_ATTRIBUTE_PTR ,CK_ULONG ,CK_OBJECT_HANDLE_PTR ,CK_OBJECT_HANDLE_PTR );
typedef CK_RV (*CreateObject)(CK_SESSION_HANDLE ,CK_ATTRIBUTE_PTR ,CK_ULONG ,CK_OBJECT_HANDLE_PTR );
typedef CK_RV (*EncryptInit)(CK_SESSION_HANDLE ,CK_MECHANISM_PTR ,CK_OBJECT_HANDLE );
typedef CK_RV (*Encrypt)(CK_SESSION_HANDLE ,CK_BYTE_PTR ,CK_ULONG ,CK_BYTE_PTR ,CK_ULONG_PTR );
typedef CK_RV (*EncryptUpdate)(CK_SESSION_HANDLE ,CK_BYTE_PTR ,CK_ULONG ,CK_BYTE_PTR ,CK_ULONG_PTR );
typedef CK_RV (*EncryptFinal)(CK_SESSION_HANDLE ,CK_BYTE_PTR ,CK_ULONG_PTR );
typedef CK_RV (*DecryptInit)(CK_SESSION_HANDLE ,CK_MECHANISM_PTR ,CK_OBJECT_HANDLE );
typedef CK_RV (*Decrypt)(CK_SESSION_HANDLE ,CK_BYTE_PTR ,CK_ULONG ,CK_BYTE_PTR ,CK_ULONG_PTR );
typedef CK_RV (*DecryptUpdate)(CK_SESSION_HANDLE ,CK_BYTE_PTR ,CK_ULONG ,CK_BYTE_PTR ,CK_ULONG_PTR );
typedef CK_RV (*DecryptFinal)(CK_SESSION_HANDLE ,CK_BYTE_PTR ,CK_ULONG_PTR );
typedef CK_RV (*DigestInit)(CK_SESSION_HANDLE ,CK_MECHANISM_PTR );
typedef CK_RV (*digest)(CK_SESSION_HANDLE ,CK_BYTE_PTR ,CK_ULONG ,CK_BYTE_PTR ,CK_ULONG_PTR ); 
typedef CK_RV (*DigestUpdate)(CK_SESSION_HANDLE ,CK_BYTE_PTR ,CK_ULONG );
typedef CK_RV (*DigestKey)(CK_SESSION_HANDLE ,CK_OBJECT_HANDLE );
typedef CK_RV (*DigestFinal)(CK_SESSION_HANDLE ,CK_BYTE_PTR ,CK_ULONG_PTR );
typedef CK_RV (*SignInit)(CK_SESSION_HANDLE ,CK_MECHANISM_PTR ,CK_OBJECT_HANDLE );
typedef CK_RV (*Sign)(CK_SESSION_HANDLE ,CK_BYTE_PTR ,CK_ULONG ,CK_BYTE_PTR ,CK_ULONG_PTR );
typedef CK_RV (*SignUpdate)(CK_SESSION_HANDLE ,CK_BYTE_PTR ,CK_ULONG );
typedef CK_RV (*SignFinal )(CK_SESSION_HANDLE ,CK_BYTE_PTR ,CK_ULONG_PTR );
typedef CK_RV (*VerifyInit )(CK_SESSION_HANDLE ,CK_MECHANISM_PTR ,CK_OBJECT_HANDLE );
typedef CK_RV (*Verify )(CK_SESSION_HANDLE ,CK_BYTE_PTR ,CK_ULONG ,CK_BYTE_PTR ,CK_ULONG );
typedef CK_RV (*DestroyObject)(CK_SESSION_HANDLE ,CK_OBJECT_HANDLE );
typedef CK_RV (*GetOperationState)(CK_SESSION_HANDLE ,CK_BYTE_PTR ,CK_ULONG_PTR );

#ifndef WIN_INI_LOADLIBRARY_PKI

ISC_API int _load_pkcs11_module(const char *module_path);
ISC_API void _unload_pkcs11_module();
ISC_API void _assign_function_list();

/************************************************************************/
/*
wrapping functions
*/
/************************************************************************/
ISC_API CK_RV p11_C_Initialize( CK_VOID_PTR pvoid );
ISC_API CK_RV p11_C_Finalize( CK_VOID_PTR pvoid );
ISC_API CK_RV p11_C_GetSlotList(CK_BBOOL arg1, CK_SLOT_ID_PTR arg2, CK_ULONG_PTR arg3);
ISC_API CK_RV p11_C_GetTokenInfo(CK_SLOT_ID arg1, CK_TOKEN_INFO_PTR arg2 );
ISC_API CK_RV p11_C_GetMechanismList(CK_SLOT_ID slotID, CK_MECHANISM_TYPE_PTR pMechanismList, CK_ULONG_PTR pulCount);
ISC_API CK_RV p11_C_GetMechanismInfo(CK_SLOT_ID slotID, CK_MECHANISM_TYPE type, CK_MECHANISM_INFO_PTR pInfo);
ISC_API CK_RV p11_C_OpenSession(CK_SLOT_ID arg1, CK_FLAGS arg2, CK_VOID_PTR arg3, CK_NOTIFY arg4, CK_SESSION_HANDLE_PTR arg5 );
ISC_API CK_RV p11_C_CloseSession(CK_SESSION_HANDLE arg1 );
ISC_API CK_RV p11_C_Login(CK_SESSION_HANDLE arg1, CK_USER_TYPE arg2, CK_CHAR_PTR arg3, CK_ULONG arg4 );
ISC_API CK_RV p11_C_Logout(CK_SESSION_HANDLE arg1 );
ISC_API CK_RV p11_C_LoginBegin(CK_SESSION_HANDLE arg1, CK_USER_TYPE arg2, CK_ULONG_PTR arg3, CK_ULONG_PTR arg4);
ISC_API CK_RV p11_C_LoginNext(CK_SESSION_HANDLE arg1, CK_USER_TYPE arg2, CK_CHAR_PTR arg3, CK_ULONG arg4, CK_ULONG_PTR arg5);
ISC_API CK_RV p11_C_LoginEnd(CK_SESSION_HANDLE arg1, CK_USER_TYPE arg2);
ISC_API CK_RV p11_C_GetAttributeValue(CK_SESSION_HANDLE arg1, CK_OBJECT_HANDLE arg2, CK_ATTRIBUTE_PTR arg3, CK_ULONG arg4 );
ISC_API CK_RV p11_C_FindObjectsInit(CK_SESSION_HANDLE arg1, CK_ATTRIBUTE_PTR arg2, CK_ULONG arg3 );
ISC_API CK_RV p11_C_FindObjects(CK_SESSION_HANDLE arg1, CK_OBJECT_HANDLE_PTR arg2, CK_ULONG arg3, CK_ULONG_PTR arg4);
ISC_API CK_RV p11_C_FindObjectsFinal(CK_SESSION_HANDLE arg1 );
ISC_API CK_RV p11_C_GetSlotInfo(CK_SLOT_ID arg1, CK_SLOT_INFO_PTR arg2 );
ISC_API CK_RV p11_C_GetFunctionList(CK_FUNCTION_LIST_PTR_PTR arg1);
ISC_API CK_RV p11_C_GetInfo(CK_INFO_PTR arg1 );
ISC_API CK_RV p11_C_GenerateKeyPair(CK_SESSION_HANDLE arg1,CK_MECHANISM_PTR arg2,CK_ATTRIBUTE_PTR arg3,CK_ULONG arg4,CK_ATTRIBUTE_PTR arg5,CK_ULONG arg6,CK_OBJECT_HANDLE_PTR arg7,CK_OBJECT_HANDLE_PTR arg8);
ISC_API CK_RV p11_C_CreateObject(CK_SESSION_HANDLE arg1,CK_ATTRIBUTE_PTR arg2,CK_ULONG arg3,CK_OBJECT_HANDLE_PTR arg4);
ISC_API CK_RV p11_C_EncryptInit(CK_SESSION_HANDLE arg1,CK_MECHANISM_PTR arg2,CK_OBJECT_HANDLE arg3);
ISC_API CK_RV p11_C_Encrypt(CK_SESSION_HANDLE arg1,CK_BYTE_PTR arg2,CK_ULONG arg3,CK_BYTE_PTR arg4,CK_ULONG_PTR arg5);
ISC_API CK_RV p11_C_EncryptUpdate(CK_SESSION_HANDLE arg1,CK_BYTE_PTR arg2,CK_ULONG arg3,CK_BYTE_PTR arg4,CK_ULONG_PTR arg5);
ISC_API CK_RV p11_C_EncryptFinal(CK_SESSION_HANDLE arg1,CK_BYTE_PTR arg2,CK_ULONG_PTR arg3);
ISC_API CK_RV p11_C_DecryptInit(CK_SESSION_HANDLE arg1 ,CK_MECHANISM_PTR arg2,CK_OBJECT_HANDLE arg3 );
ISC_API CK_RV p11_C_Decrypt(CK_SESSION_HANDLE arg1,CK_BYTE_PTR arg2,CK_ULONG arg3,CK_BYTE_PTR arg4,CK_ULONG_PTR arg5 );
ISC_API CK_RV p11_C_DecryptUpdate(CK_SESSION_HANDLE arg1,CK_BYTE_PTR arg2,CK_ULONG arg3,CK_BYTE_PTR arg4,CK_ULONG_PTR arg5 );
ISC_API CK_RV p11_C_DecryptFinal(CK_SESSION_HANDLE arg1,CK_BYTE_PTR arg2,CK_ULONG_PTR arg3 );
ISC_API CK_RV p11_C_DigestInit( CK_SESSION_HANDLE arg1, CK_MECHANISM_PTR arg2 );
ISC_API CK_RV p11_C_Digest( CK_SESSION_HANDLE arg1 ,CK_BYTE_PTR arg2 ,CK_ULONG arg3,CK_BYTE_PTR arg4,CK_ULONG_PTR arg5);
ISC_API CK_RV p11_C_DigestUpdate( CK_SESSION_HANDLE arg1,CK_BYTE_PTR arg2,CK_ULONG arg3 );
ISC_API CK_RV p11_C_DigestKey ( CK_SESSION_HANDLE arg1 ,CK_OBJECT_HANDLE  arg2 );
ISC_API CK_RV p11_C_DigestFinal( CK_SESSION_HANDLE arg1 ,CK_BYTE_PTR arg2,CK_ULONG_PTR  arg3 );
ISC_API CK_RV p11_C_SignInit(CK_SESSION_HANDLE arg1,CK_MECHANISM_PTR arg2,CK_OBJECT_HANDLE arg3 );
ISC_API CK_RV p11_C_Sign(CK_SESSION_HANDLE arg1,CK_BYTE_PTR arg2,CK_ULONG arg3,CK_BYTE_PTR arg4,CK_ULONG_PTR arg5);
ISC_API CK_RV p11_C_SignUpdate(CK_SESSION_HANDLE arg1 ,CK_BYTE_PTR arg2 ,CK_ULONG arg3 );
ISC_API CK_RV p11_C_SignFinal(CK_SESSION_HANDLE arg1,CK_BYTE_PTR arg2,CK_ULONG_PTR arg3);
ISC_API CK_RV p11_C_VerifyInit(CK_SESSION_HANDLE arg1 ,CK_MECHANISM_PTR arg2,CK_OBJECT_HANDLE arg3);
ISC_API CK_RV p11_C_Verify(CK_SESSION_HANDLE arg1 ,CK_BYTE_PTR arg2,CK_ULONG arg3,CK_BYTE_PTR arg4,CK_ULONG arg5);
ISC_API CK_RV p11_C_DestroyObject(CK_SESSION_HANDLE arg1,CK_OBJECT_HANDLE arg2);
ISC_API CK_RV p11_C_GetOperationState(CK_SESSION_HANDLE arg1 ,CK_BYTE_PTR arg2 ,CK_ULONG_PTR arg3 );

#else

#include "foundation_pki.h"

INI_RET_LOADLIB_PKI(int, _load_pkcs11_module, (const char *module_path), (module_path), ISC_FAIL);
INI_VOID_LOADLIB_PKI(void, _unload_pkcs11_module, (), () );
INI_VOID_LOADLIB_PKI(void, _assign_function_list, (), () );
INI_RET_LOADLIB_PKI(CK_RV, p11_C_Initialize, ( CK_VOID_PTR pvoid ), (CK_VOID_PTR pvoid), ISC_FAIL);
INI_RET_LOADLIB_PKI(CK_RV, p11_C_Finalize, ( CK_VOID_PTR pvoid ), (CK_VOID_PTR pvoid), ISC_FAIL);
INI_RET_LOADLIB_PKI(CK_RV, p11_C_GetSlotList, (CK_BBOOL arg1, CK_SLOT_ID_PTR arg2, CK_ULONG_PTR arg3), (arg1,arg2,arg3), ISC_FAIL);
INI_RET_LOADLIB_PKI(CK_RV, p11_C_GetTokenInfo, (CK_SLOT_ID arg1, CK_TOKEN_INFO_PTR arg2 ), (arg1,arg2), ISC_FAIL);
INI_RET_LOADLIB_PKI(CK_RV, p11_C_OpenSession, (CK_SLOT_ID arg1, CK_FLAGS arg2, CK_VOID_PTR arg3, CK_NOTIFY arg4, CK_SESSION_HANDLE_PTR arg5 ), (arg1,arg2,arg3,arg4,arg5), ISC_FAIL);
INI_RET_LOADLIB_PKI(CK_RV, p11_C_GetMechanismList, (CK_SLOT_ID slotID, CK_MECHANISM_TYPE_PTR pMechanismList, CK_ULONG_PTR pulCount), (slotID, pMechanismList, pulCount), ISC_FAIL);
INI_RET_LOADLIB_PKI(CK_RV, p11_C_GetMechanismInfo, (CK_SLOT_ID slotID, CK_MECHANISM_TYPE type, CK_MECHANISM_INFO_PTR pInfo), (slotID, type, pInfo), ISC_FAIL);
INI_RET_LOADLIB_PKI(CK_RV, p11_C_CloseSession, (CK_SESSION_HANDLE arg1 ), (arg1), ISC_FAIL);
INI_RET_LOADLIB_PKI(CK_RV, p11_C_Login, (CK_SESSION_HANDLE arg1, CK_USER_TYPE arg2, CK_CHAR_PTR arg3, CK_ULONG arg4 ), (arg1,arg2,arg3,arg4), ISC_FAIL);
INI_RET_LOADLIB_PKI(CK_RV, p11_C_Logout, (CK_SESSION_HANDLE arg1 ), (arg1), ISC_FAIL);
INI_RET_LOADLIB_PKI(CK_RV, p11_C_LoginBegin, (CK_SESSION_HANDLE arg1, CK_USER_TYPE arg2, CK_ULONG_PTR arg3, CK_ULONG_PTR arg4 ), (arg1,arg2,arg3,arg4), ISC_FAIL);
INI_RET_LOADLIB_PKI(CK_RV, p11_C_LoginNext, (CK_SESSION_HANDLE arg1, CK_USER_TYPE arg2, CK_CHAR_PTR arg3, CK_ULONG arg4, CK_ULONG_PTR arg5), (arg1,arg2,arg3,arg4,arg5), ISC_FAIL);
INI_RET_LOADLIB_PKI(CK_RV, p11_C_LoginEnd, (CK_SESSION_HANDLE arg1, CK_USER_TYPE arg2), (arg1,arg2), ISC_FAIL);
INI_RET_LOADLIB_PKI(CK_RV, p11_C_GetAttributeValue, (CK_SESSION_HANDLE arg1, CK_OBJECT_HANDLE arg2, CK_ATTRIBUTE_PTR arg3, CK_ULONG arg4 ), (arg1,arg2,arg3,arg4), ISC_FAIL);
INI_RET_LOADLIB_PKI(CK_RV, p11_C_FindObjectsInit, (CK_SESSION_HANDLE arg1, CK_ATTRIBUTE_PTR arg2, CK_ULONG arg3 ), (arg1,arg2,arg3), ISC_FAIL);
INI_RET_LOADLIB_PKI(CK_RV, p11_C_FindObjects, (CK_SESSION_HANDLE arg1, CK_OBJECT_HANDLE_PTR arg2, CK_ULONG arg3, CK_ULONG_PTR arg4), (arg1,arg2,arg3,arg4), ISC_FAIL);
INI_RET_LOADLIB_PKI(CK_RV, p11_C_FindOb jectsFinal, (CK_SESSION_HANDLE arg1 ), (arg1), ISC_FAIL);
INI_RET_LOADLIB_PKI(CK_RV, p11_C_GetSlotInfo, (CK_SLOT_ID arg1, CK_SLOT_INFO_PTR arg2 ), (arg1,arg2), ISC_FAIL);
INI_RET_LOADLIB_PKI(CK_RV, p11_C_GetFunctionList, (CK_FUNCTION_LIST_PTR_PTR arg1), (arg1), ISC_FAIL);
INI_RET_LOADLIB_PKI(CK_RV, p11_C_GetInfo, (CK_INFO_PTR arg1 ), (arg1), ISC_FAIL);
INI_RET_LOADLIB_PKI(CK_RV, p11_C_GenerateKeyPair, (CK_SESSION_HANDLE arg1,CK_MECHANISM_PTR arg2,CK_ATTRIBUTE_PTR arg3,CK_ULONG arg4,CK_ATTRIBUTE_PTR arg5,CK_ULONG arg6,CK_OBJECT_HANDLE_PTR arg7,CK_OBJECT_HANDLE_PTR arg8), (arg1,arg2,arg3,arg4,arg5,arg6,arg7,arg8), ISC_FAIL);
INI_RET_LOADLIB_PKI(CK_RV, p11_C_CreateObject, (CK_SESSION_HANDLE arg1,CK_ATTRIBUTE_PTR arg2,CK_ULONG arg3,CK_OBJECT_HANDLE_PTR arg4), (arg1,arg2,arg3,arg4), ISC_FAIL);
INI_RET_LOADLIB_PKI(CK_RV, p11_C_EncryptInit, (CK_SESSION_HANDLE arg1,CK_MECHANISM_PTR arg2,CK_OBJECT_HANDLE arg3), (arg1,arg2,arg3), ISC_FAIL);
INI_RET_LOADLIB_PKI(CK_RV, p11_C_Encrypt, (CK_SESSION_HANDLE arg1,CK_BYTE_PTR arg2,CK_ULONG arg3,CK_BYTE_PTR arg4,CK_ULONG_PTR arg5), (arg1,arg2,arg3,arg4,arg5), ISC_FAIL);
INI_RET_LOADLIB_PKI(CK_RV, p11_C_EncryptUpdate, (CK_SESSION_HANDLE arg1,CK_BYTE_PTR arg2,CK_ULONG arg3,CK_BYTE_PTR arg4,CK_ULONG_PTR arg5), (arg1,arg2,arg3,arg4,arg5), ISC_FAIL);
INI_RET_LOADLIB_PKI(CK_RV, p11_C_EncryptFinal, (CK_SESSION_HANDLE arg1,CK_BYTE_PTR arg2,CK_ULONG_PTR arg3), (arg1,arg2,arg3), ISC_FAIL);
INI_RET_LOADLIB_PKI(CK_RV, p11_C_DecryptInit, (CK_SESSION_HANDLE arg1 ,CK_MECHANISM_PTR arg2,CK_OBJECT_HANDLE arg3 ), (arg1,arg2,arg3), ISC_FAIL);
INI_RET_LOADLIB_PKI(CK_RV, p11_C_Decrypt, (CK_SESSION_HANDLE arg1,CK_BYTE_PTR arg2,CK_ULONG arg3,CK_BYTE_PTR arg4,CK_ULONG_PTR arg5 ), (arg1,arg2,arg3,arg4,arg5), ISC_FAIL);
INI_RET_LOADLIB_PKI(CK_RV, p11_C_DecryptUpdate, (CK_SESSION_HANDLE arg1,CK_BYTE_PTR arg2,CK_ULONG arg3,CK_BYTE_PTR arg4,CK_ULONG_PTR arg5 ), (arg1,arg2,arg3,arg4,arg5), ISC_FAIL);
INI_RET_LOADLIB_PKI(CK_RV, p11_C_DecryptFinal, (CK_SESSION_HANDLE arg1,CK_BYTE_PTR arg2,CK_ULONG_PTR arg3 ), (arg1,arg2,arg3), ISC_FAIL);
INI_RET_LOADLIB_PKI(CK_RV, p11_C_DigestInit, ( CK_SESSION_HANDLE arg1, CK_MECHANISM_PTR arg2 ), (arg1,arg2), ISC_FAIL);
INI_RET_LOADLIB_PKI(CK_RV, p11_C_Digest, ( CK_SESSION_HANDLE arg1 ,CK_BYTE_PTR arg2 ,CK_ULONG arg3,CK_BYTE_PTR arg4,CK_ULONG_PTR arg5), (arg1,arg2,arg3,arg4,arg5), ISC_FAIL);
INI_RET_LOADLIB_PKI(CK_RV, p11_C_DigestUpdate, ( CK_SESSION_HANDLE arg1,CK_BYTE_PTR arg2,CK_ULONG arg3 ), (arg1,arg2,arg3), ISC_FAIL);
INI_RET_LOADLIB_PKI(CK_RV, p11_C_DigestKey, ( CK_SESSION_HANDLE arg1 ,CK_OBJECT_HANDLE arg2 ), (arg1,arg2), ISC_FAIL);
INI_RET_LOADLIB_PKI(CK_RV, p11_C_DigestFinal, ( CK_SESSION_HANDLE arg1 ,CK_BYTE_PTR arg2,CK_ULONG_PTR arg3 ), (arg1,arg2,arg3), ISC_FAIL);
INI_RET_LOADLIB_PKI(CK_RV, p11_C_SignInit, (CK_SESSION_HANDLE arg1,CK_MECHANISM_PTR arg2,CK_OBJECT_HANDLE arg3 ), (arg1,arg2,arg3), ISC_FAIL);
INI_RET_LOADLIB_PKI(CK_RV, p11_C_Sign, (CK_SESSION_HANDLE arg1,CK_BYTE_PTR arg2,CK_ULONG arg3,CK_BYTE_PTR arg4,CK_ULONG_PTR arg5), (arg1,arg2,arg3,arg4,arg5), ISC_FAIL);
INI_RET_LOADLIB_PKI(CK_RV, p11_C_SignUpdate, (CK_SESSION_HANDLE arg1 ,CK_BYTE_PTR arg2 ,CK_ULONG arg3 ), (arg1,arg2,arg3), ISC_FAIL);
INI_RET_LOADLIB_PKI(CK_RV, p11_C_SignFinal, (CK_SESSION_HANDLE arg1,CK_BYTE_PTR arg2,CK_ULONG_PTR arg3), (arg1,arg2,arg3), ISC_FAIL);
INI_RET_LOADLIB_PKI(CK_RV, p11_C_VerifyInit, (CK_SESSION_HANDLE arg1 ,CK_MECHANISM_PTR arg2,CK_OBJECT_HANDLE arg3), (arg1,arg2,arg3), ISC_FAIL);
INI_RET_LOADLIB_PKI(CK_RV, p11_C_Verify, (CK_SESSION_HANDLE arg1 ,CK_BYTE_PTR arg2,CK_ULONG arg3,CK_BYTE_PTR arg4,CK_ULONG arg5), (arg1,arg2,arg3,arg4,arg5), ISC_FAIL);
INI_RET_LOADLIB_PKI(CK_RV, p11_C_DestroyObject, (CK_SESSION_HANDLE arg1,CK_OBJECT_HANDLE arg2), (arg1,arg2), ISC_FAIL);
INI_RET_LOADLIB_PKI(CK_RV, p11_C_GetOperationState, (CK_SESSION_HANDLE arg1 ,CK_BYTE_PTR arg2 ,CK_ULONG_PTR arg3 ), (arg1,arg2,arg3), ISC_FAIL);

#endif

#endif /* __SAMPLE_PKCS11_H__ */

extern Initialize pfnC_Initialize;
extern Finalize pfnC_Finalize;
extern GetSlotList pfnC_GetSlotList;
extern GetTokenInfo pfnC_GetTokenInfo;
extern GetMechanismList pfnC_GetMechanismList;
extern GetMechanismInfo pfnC_GetMechanismInfo;
extern OpenSession pfnC_OpenSession;
extern CloseSession pfnC_CloseSession;
extern Login pfnC_Login;
extern Logout pfnC_Logout;
extern LoginBegin pfnC_LoginBegin;
extern LoginNext pfnC_LoginNext;
extern LoginEnd pfnC_LognEnd;
extern GetAttributeValue pfnC_GetAttributeValue;
extern FindObjectsInit pfnC_FindObjectsInit;
extern FindObjects pfnC_FindObjects;
extern FindObjectsFinal pfnC_FindObjectsFinal;
extern GetSlotInfo pfnC_GetSlotInfo;
extern GetFunctionList pfnC_GetFunctionList;
extern GetInfo pfnC_GetInfo;
extern GetAttributeValue				pfnC_GetAttributeValue;
extern GenerateKeyPair 				pfnC_GenerateKeyPair;
extern CreateObject					pfnC_CreateObject;
extern EncryptInit						pfnC_EncryptInit;
extern Encrypt							pfnC_Encrypt;
extern EncryptUpdate					pfnC_EncryptUpdate;
extern EncryptFinal					pfnC_EncryptFinal;
extern DecryptInit						pfnC_DecryptInit;
extern Decrypt							pfnC_Decrypt;
extern DecryptUpdate					pfnC_DecryptUpdate;
extern DecryptFinal					pfnC_DecryptFinal;
extern SignInit	pfnC_SignInit;
extern Sign		pfnC_Sign;
extern SignUpdate	pfnC_SignUpdate;
extern SignFinal	pfnC_SignFinal;
extern VerifyInit	pfnC_VerifyInit;
extern Verify		pfnC_Verify;
extern GetOperationState				pfnC_GetOperationState;


