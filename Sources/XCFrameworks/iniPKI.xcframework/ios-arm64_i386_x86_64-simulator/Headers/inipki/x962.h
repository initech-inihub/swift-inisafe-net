//
//  x962.h
//  iniPKI
//
//  Created by myoungjoong.kim on 2019/10/16.
//  Copyright ? 2019 INITECH. CO. All rights reserved.
//
#ifndef HEADER_X962_H
#define HEADER_X962_H

#include <stdio.h>
#include <inicrypto/ecdsa.h>
#include "asn1.h"
#include "x509.h"

/*!
 * \brief
 * ECDSA ????? ??????? ?????
 */
typedef struct ec_private_key_st
{
    INTEGER *version;
    OCTET_STRING *privateKey;
    OBJECT_IDENTIFIER *parameters;
    BIT_STRING *publicKey;
} EC_PRIVATE_KEY;

/*!
 * \brief
 * ECDSA ????? ??????? ?????
 */
typedef struct ec_public_key_st
{
    X509_ALGO_IDENTIFIER *algorithm;
    BIT_STRING *subjectPublicKey;
} EC_PUBLIC_KEY;

#ifdef  __cplusplus
extern "C" {
#endif


#ifndef WIN_INI_LOADLIBRARY_PKI

/*!
* \brief
* BIT_STRING?? ISC_ECC_KEY_UNIT ??????? ??? ???
* \param bit_string
* Decoding BIT_STRING ?????
* \param ec_key
* ISC_ECC_KEY_UNIT ?????
* \returns
* -# ISC_SUCCESS : ????
* -# LOCATION^F_BITSTRING_TO_EC_KEY^ISC_ERR_NULL_INPUT : NULL ??¡Æ? ???
* -# LOCATION^F_BITSTRING_TO_EC_KEY^ISC_ERR_INVALID_INPUT : ????? ??¡Æ? ???
*/
ISC_API ISC_STATUS BITSTRING_to_EC_KEY(BIT_STRING *bit_string, ISC_ECC_KEY_UNIT **ec_key);

/*!
* \brief
* BIT_STRING?? ISC_ECDSA_UNIT ??????? ??? ???
* \param bit_string
* Decoding BIT_STRING ?????
* \param ecdsa
* ISC_ECDSA_UNIT ?????
* \returns
* -# ISC_SUCCESS : ????
* -# LOCATION^F_BITSTRING_TO_EC_KEY^ISC_ERR_NULL_INPUT : NULL ??¡Æ? ???
* -# LOCATION^F_BITSTRING_TO_EC_KEY^ISC_ERR_INVALID_INPUT : ????? ??¡Æ? ???
*/
ISC_API ISC_STATUS BITSTRING_to_ECDSA_KEY(BIT_STRING *bit_string, ISC_ECDSA_UNIT **ecdsa);

/*!
 * \brief
 * BIT_STRING?? ISC_ECC_KEY_UNIT ??????? ??? ??? (???? ???? ???????????? ?????)
 * \param bit_string
 * Decoding BIT_STRING ?????
 * \param ecc
 * ISC_ECC_KEY_UNIT ?????
 * \returns
 * -# ISC_SUCCESS : ????
 * -# LOCATION^F_BITSTRING_TO_EC_KEY^ISC_ERR_NULL_INPUT : NULL ??¡Æ? ???
 * -# LOCATION^F_BITSTRING_TO_EC_KEY^ISC_ERR_INVALID_INPUT : ????? ??¡Æ? ???
 */
ISC_API ISC_STATUS BITSTRING_to_ECC_KEY(BIT_STRING *bit_string, ISC_ECC_KEY_UNIT **ecc);
    
/*!
 * \brief
 * ISC_ECC_KEY_UNIT ??????? BitString ??????? ??? ??? (???? ???? ???????????? ?????)
 * \param ecc
 * ISC_ECC_KEY_UNIT ?????
 * \param bit_string
 * BIT_STRING ?????
 * \returns
 * -# ISC_SUCCESS : ????
 * -# LOCATION^F_EC_KEY_TO_BITSTRING^ISC_ERR_NULL_INPUT : NULL ??¡Æ? ???
 * -# LOCATION^F_EC_KEY_TO_BITSTRING^ISC_ERR_MEMORY_ALLOC : ??? ??? ????
 */
ISC_API ISC_STATUS EC_KEY_to_BITSTRING(ISC_ECC_KEY_UNIT *ec_key, BIT_STRING **bit_string);

/*!
* \brief
* ISC_ECDSA_UNIT ??????? BitString ??????? ??? ???
* \param ecc
* ISC_ECDSA_UNIT ?????
* \param bit_string
* BIT_STRING ?????
* \returns
* -# ISC_SUCCESS : ????
* -# LOCATION^F_EC_KEY_TO_BITSTRING^ISC_ERR_NULL_INPUT : NULL ??¡Æ? ???
* -# LOCATION^F_EC_KEY_TO_BITSTRING^ISC_ERR_MEMORY_ALLOC : ??? ??? ????
*/
ISC_API ISC_STATUS ECDSA_KEY_to_BITSTRING(ISC_ECDSA_UNIT *ecdsa, BIT_STRING **bit_string);

/*!
 * \brief
 * ISC_ECC_KEY_UNIT ??????? BitString ??????? ??? ???
 * \param ecc
 * ISC_ECC_KEY_UNIT ?????
 * \param bit_string
 * BIT_STRING ?????
 * \returns
 * -# ISC_SUCCESS : ????
 * -# LOCATION^F_EC_KEY_TO_BITSTRING^ISC_ERR_NULL_INPUT : NULL ??¡Æ? ???
 * -# LOCATION^F_EC_KEY_TO_BITSTRING^ISC_ERR_MEMORY_ALLOC : ??? ??? ????
 */
ISC_API ISC_STATUS ECC_KEY_to_BITSTRING(ISC_ECC_KEY_UNIT *ecc, BIT_STRING **bit_string);

/*!
 * \brief
 * EC_PUBLIC_KEY ??????? ???? ???
 * \returns
 * EC_PUBLIC_KEY ????? ??????
 */
ISC_API EC_PUBLIC_KEY *new_EC_PUBLIC_KEY(void);

/*!
 * \brief
 * EC_PUBLIC_KEY ??????? ??? ??? ????
 * \param ecdsa_pub
 * ?????? ?????
 * \remarks
 * ??????? ????(ISC_MEM_FREE)
 */
ISC_API void free_EC_PUBLIC_KEY(EC_PUBLIC_KEY *ecdsa_pub);

/*!
 * \brief
 * EC_PUBLIC_KEY ??????? ????
 * \param ecdsa_pub
 * ?????? ?????
 */
ISC_API void clean_EC_PUBLIC_KEY(EC_PUBLIC_KEY *ecdsa_pub);
    
/*!
 * \brief
 * ISC_ECC_KEY_UNIT ??????¥ê??? EC_PUBLIC_KEY?? ????? ???
 * \param ec_key
 * ISC_ECC_KEY_UNIT ?????
 * \param out
 * EC_PUBLIC_KEY ?????
 * \returns
 * -# ISC_SUCCESS : ????
 * -# LOCATION^F_SET_EC_KEY_UNIT_TO_EC_PUBLIC_KEY : ?? ???????
 */
ISC_API ISC_STATUS set_EC_KEY_UNIT_to_EC_PUBLIC_KEY(ISC_ECC_KEY_UNIT *ec_key, EC_PUBLIC_KEY **pubkey);

/*!
 * \brief
 * ISC_ECDSA_UNIT ??????¥ê??? EC_PUBLIC_KEY?? ????? ???
 * \param ecdsa
 * ISC_ECDSA_UNIT ?????
 * \param out
 * EC_PUBLIC_KEY ?????
 * \returns
 * -# ISC_SUCCESS : ????
 * -# LOCATION^F_SET_EC_KEY_UNIT_TO_EC_PUBLIC_KEY : ?? ???????
 */
ISC_API ISC_STATUS set_ECDSA_UNIT_to_EC_PUBLIC_KEY(ISC_ECDSA_UNIT *ecdsa, EC_PUBLIC_KEY **pubkey);

/*!
 * \brief
 * EC_PUBLIC_KEY ??????¥ê??? ISC_ECC_KEY_UNIT?? ????? ???
 * \param ec_key
 * ISC_ECC_KEY_UNIT ?????
 * \param ecdsa_pub
 * EC_PUBLIC_KEY ?????
 * \returns
 * -# ISC_SUCCESS : ????
 * -# LOCATION^F_GET_ECDA_UNIT_FROM_PUB_KEY : ?? ???????
 * -# LOCATION^F_GET_ECDA_UNIT_FROM_PUB_KEY^ISC_ERR_INVALID_INPUT : ecdsa ??? NULL?? ???
 */
ISC_API ISC_STATUS get_EC_KEY_UNIT_from_EC_PUBLIC_KEY(ISC_ECC_KEY_UNIT **ec_key, EC_PUBLIC_KEY *ecdsa_pub);

/*!
 * \brief
 * EC_PUBLIC_KEY ??????¥ê??? ISC_ECDAS_UNIT?? ????? ???
 * \param ecdsa
 * ISC_ECDAS_UNIT ?????
 * \param ecdsa_pub
 * EC_PUBLIC_KEY ?????
 * \returns
 * -# ISC_SUCCESS : ????
 * -# LOCATION^F_GET_ECDA_UNIT_FROM_PUB_KEY : ?? ???????
 * -# LOCATION^F_GET_ECDA_UNIT_FROM_PUB_KEY^ISC_ERR_INVALID_INPUT : ecdsa ??? NULL?? ???
 */
ISC_API ISC_STATUS get_ECDSA_UNIT_from_EC_PUBLIC_KEY(ISC_ECDSA_UNIT **ecdsa, EC_PUBLIC_KEY *ecdsa_pub);
    
/*!
 * \brief
 * EC_PUBLIC_KEY ??????? SEQENCE?? ????? ???
 * \param unit
 * SEQENCE?? ???? ISC_ECDAS_UNIT ?????
 * \param out
 * EC_PUBLIC_KEY ??????? SEQENCE ????? ??
 * \returns
 * -# ISC_SUCCESS : ????
 * -# LOCATION^F_EC_PUBLIC_KEY_TO_SEQ^ISC_ERR_NULL_INPUT : NULL ???
 */
ISC_API ISC_STATUS EC_PUBLIC_KEY_to_Seq(EC_PUBLIC_KEY *unit, SEQUENCE** out);
    
/*!
 * \brief
 * Sequence?? EC_PUBLIC_KEY ??????? Decode ???
 * \param in
 * Decoding Sequece ?????
 * \param out
 * EC_PUBLIC_KEY ?????
 * \returns
 * -# ISC_SUCCESS : ????
 * -# LOCATION^F_SEQ_TO_EC_PUBLIC_KEY^ISC_ERR_NULL_INPUT : Null Input
 */
ISC_API ISC_STATUS Seq_to_EC_PUBLIC_KEY(SEQUENCE* in, EC_PUBLIC_KEY **out);
    
/*!
 * \brief
 * EC_PRIVATE_KEY ??????? ???? ???
 * \returns
 * EC_PRIVATE_KEY ????? ??????
 */
ISC_API EC_PRIVATE_KEY *new_EC_PRIVATE_KEY(void);

/*!
 * \brief
 * EC_PRIVATE_KEY ??????? ??? ??? ????
 * \param ecdsa_priv
 * ?????? ?????
 * \remarks
 * ??????? ????(ISC_MEM_FREE)
 */
ISC_API void free_EC_PRIVATE_KEY(EC_PRIVATE_KEY *ecdsa_priv);

/*!
 * \brief
 * EC_PRIVATE_KEY ??????? ????
 * \param ecdsa_priv
 * ?????? ?????
 */
ISC_API void clean_EC_PRIVATE_KEY(EC_PRIVATE_KEY *ecdsa_priv);

/*!
 * \brief
 * ISC_ECC_KEY_UNIT ??????¥ê??? EC_PRIVATE_KEY?? ????? ???
 * \param ec_key
 * EC_PRIVATE_KEY ??????? ?????? ISC_ECC_KEY_UNIT ?????
 * \param ecdsa_priv
 * ??¡Æ? EC_PRIVATE_KEY ?????
 * \returns
 * -# ISC_SUCCESS : ????
 * -# LOCATION^F_SET_EC_KEY_UNIT_TO_EC_PRIVATE_KEY^ISC_ERR_NULL_INPUT : NULL ???
 */
ISC_API ISC_STATUS set_EC_KEY_UNIT_to_EC_PRIVATE_KEY(ISC_ECC_KEY_UNIT *ec_key, EC_PRIVATE_KEY **ecdsa_priv);

/*!
 * \brief
 * ISC_ECDSA_UNIT ??????¥ê??? EC_PRIVATE_KEY?? ????? ???
 * \param ecdsa
 * EC_PRIVATE_KEY ??????? ?????? ISC_ECDSA_UNIT ?????
 * \param ecdsa_priv
 * ??¡Æ? EC_PRIVATE_KEY ?????
 * \returns
 * -# ISC_SUCCESS : ????
 * -# LOCATION^F_SET_EC_KEY_UNIT_TO_EC_PRIVATE_KEY^ISC_ERR_NULL_INPUT : NULL ???
 */
ISC_API ISC_STATUS set_ECDSA_UNIT_to_EC_PRIVATE_KEY(ISC_ECDSA_UNIT *ecdsa, EC_PRIVATE_KEY **ecdsa_priv);

/*!
 * \brief
 * EC_PRIVATE_KEY ??????¥ê??? ISC_ECC_KEY_UNIT?? ????? ???
 * \param ec_key
 * ISC_ECC_KEY_UNIT ?????
 * \param ecdsa_priv
 * EC_PUBLIC_KEY ?????
 * \returns
 * -# ISC_SUCCESS : ????
 * -# LOCATION^F_GET_EC_KEY_UNIT_FROM_EC_PRIVATE_KEY^ISC_ERR_NULL_INPUT : NULL ???
 */
ISC_API ISC_STATUS get_EC_KEY_UNIT_from_EC_PRIVATE_KEY(ISC_ECC_KEY_UNIT **ec_key, EC_PRIVATE_KEY *ecdsa_priv);

/*!
 * \brief
 * EC_PRIVATE_KEY ??????¥ê??? ISC_ECDAS_UNIT?? ????? ???
 * \param ecdsa
 * ISC_ECDAS_UNIT ?????
 * \param ecdsa_priv
 * EC_PUBLIC_KEY ?????
 * \returns
 * -# ISC_SUCCESS : ????
 * -# LOCATION^F_GET_EC_KEY_UNIT_FROM_EC_PRIVATE_KEY^ISC_ERR_NULL_INPUT : NULL ???
 */
ISC_API ISC_STATUS get_ECDSA_UNIT_from_EC_PRIVATE_KEY(ISC_ECDSA_UNIT **ecdsa, EC_PRIVATE_KEY *ecdsa_priv);

/*!
 * \brief
 * EC_PRIVATE_KEY ??????? SEQENCE?? ????? ???
 * \param unit
 * SEQENCE?? ???? EC_PRIVATE_KEY ?????
 * \param out
 * EC_PRIVATE_KEY ??????? SEQENCE ????? ??
 * \returns
 * -# ISC_SUCCESS : ????
 * -# LOCATION^F_EC_PRIVATE_KEY_TO_SEQ^ISC_ERR_NULL_INPUT : NULL ???
 */
ISC_API ISC_STATUS EC_PRIVATE_KEY_to_Seq(EC_PRIVATE_KEY *unit, SEQUENCE** out);

/*!
 * \brief
 * Sequence?? EC_PRIVATE_KEY ??????? Decode ???
 * \param in
 * Decoding Sequece ?????
 * \param out
 * EC_PRIVATE_KEY ?????
 * \returns
 * -# ISC_SUCCESS : ????
 * -# LOCATION^F_SEQ_TO_EC_PRIVATE_KEY^ISC_ERR_NULL_INPUT : Null Input
 */
ISC_API ISC_STATUS Seq_to_EC_PRIVATE_KEY(SEQUENCE* in, EC_PRIVATE_KEY **out);

/*!
* \brief
* ISC_ECDSA ?????? ???????? ASN.1 DER ???????? ???
* \param buf
* ??????? ?????? ???????? ??????
* \param bufLen
* buf?? ???? ??????
* \param r
* ISC_ECDSA?? R ??
* \param rLen
* ISC_ECDSA?? R ????
* \param s
* ISC_ECDSA?? S ??
* \param sLen
* ISC_ECDSA?? S ????
* \returns
* -# LOCATION^F_ENCODE_ECDSA_SIGNATURE_VALUE^ISC_ERR_NULL_INPUT : NULL ??¡Æ? ???
* -# LOCATION^F_ENCODE_ECDSA_SIGNATURE_VALUE^ISC_ERR_MEMORY_ALLOC : ??? ??? ????
* -# LOCATION^F_ENCODE_ECDSA_SIGNATURE_VALUE^ERR_ASN1_DECODING : ASN1_DECODING ????
*/
ISC_API ISC_STATUS encode_ECDSASignatureValue(uint8 **buf, int *bufLen, uint8 *r, int rLen, uint8 *s, int sLen);

/*!
* \brief
* ISC_ECDSA ASN.1 DER ????? ???????? DER ???????? ???
* \param r
* ISC_ECDSA?? R ??
* \param rLen
* ISC_ECDSA?? R ????
* \param s
* ISC_ECDSA?? S ??
* \param sLen
* ISC_ECDSA?? S ????
* \param buf
* ????? ??????? ?????? ???????? ??????
* -# ISC_SUCCESS : ????
* -# LOCATION^F_DECODE_ECDSA_SIGNATURE_VALUE^ISC_ERR_NULL_INPUT : NULL ??¡Æ? ???
* -# LOCATION^F_DECODE_ECDSA_SIGNATURE_VALUE^ERR_ASN1_DECODING : ASN1_DECODING ????
*/
ISC_API ISC_STATUS decode_ECDSASignatureValue(uint8 *r, int *rLen, uint8 *s, int *sLen, uint8 *buf);

#else

#include "foundation_pki.h"

INI_RET_LOADLIB_PKI(ISC_STATUS, BITSTRING_to_EC_KEY, (BIT_STRING *bit_string, ISC_ECC_KEY_UNIT **ec_key), (bit_string,ec_key), ISC_FAIL);
INI_RET_LOADLIB_PKI(ISC_STATUS, BITSTRING_to_ECDSA_KEY, (BIT_STRING *bit_string, ISC_ECDSA_UNIT **ecdsa), (bit_string,ecdsa), ISC_FAIL);
INI_RET_LOADLIB_PKI(ISC_STATUS, BITSTRING_to_ECC_KEY, (BIT_STRING *bit_string, ISC_ECC_KEY_UNIT **ecc), (bit_string,ecc), ISC_FAIL);
INI_RET_LOADLIB_PKI(ISC_STATUS, EC_KEY_to_BITSTRING, (ISC_ECC_KEY_UNIT *ec_key, BIT_STRING **bit_string), (ec_key,bit_string), ISC_FAIL);
INI_RET_LOADLIB_PKI(ISC_STATUS, ECDSA_KEY_to_BITSTRING, (ISC_ECDSA_UNIT *ecdsa, BIT_STRING **bit_string), (ecdsa,bit_string), ISC_FAIL);
INI_RET_LOADLIB_PKI(ISC_STATUS, ECC_KEY_to_BITSTRING, (ISC_ECC_KEY_UNIT *ecc, BIT_STRING **bit_string), (ecc,bit_string), ISC_FAIL);
INI_RET_LOADLIB_PKI(EC_PUBLIC_KEY*, new_EC_PUBLIC_KEY, (), (), NULL);
INI_VOID_LOADLIB_PKI(void, free_EC_PUBLIC_KEY, (EC_PUBLIC_KEY *ecdsa_pub), (ecdsa_pub) );
INI_VOID_LOADLIB_PKI(void, clean_EC_PUBLIC_KEY, (EC_PUBLIC_KEY *ecdsa_pub), (ecdsa_pub) );
INI_RET_LOADLIB_PKI(ISC_STATUS, set_EC_KEY_UNIT_to_EC_PUBLIC_KEY(ISC_ECC_KEY_UNIT *ec_key, EC_PUBLIC_KEY **pubkey), (ec_key,pubkey), ISC_FAIL);
INI_RET_LOADLIB_PKI(ISC_STATUS, set_ECDSA_UNIT_to_EC_PUBLIC_KEY(ISC_ECDSA_UNIT *ecdsa, EC_PUBLIC_KEY **pubkey), (ecdsa,pubkey), ISC_FAIL);
INI_RET_LOADLIB_PKI(ISC_STATUS, get_EC_KEY_UNIT_from_EC_PUBLIC_KEY, (ISC_ECC_KEY_UNIT **ec_key, EC_PUBLIC_KEY *ecdsa_pub), (ec_key,ecdsa_pub), ISC_FAIL);
INI_RET_LOADLIB_PKI(ISC_STATUS, get_ECDSA_UNIT_from_EC_PUBLIC_KEY, (ISC_ECDSA_UNIT **ecdsa, EC_PUBLIC_KEY *ecdsa_pub), (ecdsa,ecdsa_pub), ISC_FAIL);
INI_RET_LOADLIB_PKI(ISC_STATUS, EC_PUBLIC_KEY_to_Seq, (EC_PUBLIC_KEY *unit, SEQUENCE** out), (unit, out), ISC_FAIL);
INI_RET_LOADLIB_PKI(ISC_STATUS, Seq_to_EC_PUBLIC_KEY (SEQUENCE* in, EC_PUBLIC_KEY **out), (in, out), ISC_FAIL);
INI_RET_LOADLIB_PKI(EC_PRIVATE_KEY*, new_EC_PRIVATE_KEY, (), (), NULL);
INI_VOID_LOADLIB_PKI(void, free_EC_PRIVATE_KEY, (EC_PRIVATE_KEY *ecdsa_priv), (ecdsa_priv) );
INI_VOID_LOADLIB_PKI(void, clean_EC_PRIVATE_KEY, (EC_PRIVATE_KEY *ecdsa_priv), (ecdsa_priv) );
INI_RET_LOADLIB_PKI(ISC_STATUS, set_EC_KEY_UNIT_to_EC_PRIVATE_KEY, (ISC_ECC_KEY_UNIT *ec_key, EC_PRIVATE_KEY **ecdsa_priv), (ec_key,ecdsa_priv), ISC_FAIL);
INI_RET_LOADLIB_PKI(ISC_STATUS, set_ECDSA_UNIT_to_EC_PRIVATE_KEY, (ISC_ECDSA_UNIT *ecdsa, EC_PRIVATE_KEY **ecdsa_priv), (ecdsa,ecdsa_priv), ISC_FAIL);
INI_RET_LOADLIB_PKI(ISC_STATUS, get_EC_KEY_UNIT_from_EC_PRIVATE_KEY, (ISC_ECC_KEY_UNIT *ec_key, EC_PRIVATE_KEY *ecdsa_priv), (ec_key,ecdsa_priv), ISC_FAIL);
INI_RET_LOADLIB_PKI(ISC_STATUS, get_ECDSA_UNIT_from_EC_PRIVATE_KEY, (ISC_ECDSA_UNIT **ecdsa, EC_PRIVATE_KEY *ecdsa_priv), (ecdsa,ecdsa_priv), ISC_FAIL);
INI_RET_LOADLIB_PKI(ISC_STATUS, EC_PRIVATE_KEY_to_Seq, (EC_PRIVATE_KEY *unit, SEQUENCE** out), (unit,out), ISC_FAIL);
INI_RET_LOADLIB_PKI(ISC_STATUS, Seq_to_EC_PRIVATE_KEY, (SEQUENCE* in, EC_PRIVATE_KEY **out), (in,out), ISC_FAIL);
INI_RET_LOADLIB_PKI(ISC_STATUS, encode_ECDSASignatureValue, (uint8 **buf, int *bufLen, uint8 *r, int rLen, uint8 *s, int sLen), (buf, bufLen, r, rLen, s, sLen), ISC_FAIL);
INI_RET_LOADLIB_PKI(ISC_STATUS, decode_ECDSASignatureValue, (uint8 *r, int *rLen, uint8 *s, int *sLen, uint8 *buf), (r, rLen, s, sLen, buf), ISC_FAIL);

#endif /* #ifndef WIN_INI_LOADLIBRARY_PKI */

#ifdef  __cplusplus
}
#endif

#endif /* HEADER_X962_H */
