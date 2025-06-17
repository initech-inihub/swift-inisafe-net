/*!
* \file pkcs10.h
* \brief PKCS10 
* Certification Request Syntax Specification 
* \remarks
* PKCS10 
* \author
* Copyright (c) 2008 by \<INITech\>
*/

#ifndef HEADER_PKCS10_H
#define HEADER_PKCS10_H

#ifdef NO_PKI
#error PKI is disabled.
#endif

#include <inicrypto/foundation.h>

#include "asn1.h"
#include "asn1_objects.h"
#include "x509.h"

#ifdef  __cplusplus
extern "C" {
#endif

/*
PKCSReq ::= SEQUENCE {
    endEntityInfo    EndEntityInfo,
    regInfo          OCTET STRING OPTIONAL,
    certReqId        INTEGER OPTIONAL }

endEntityInfo :: CHOICE {
pKCS10         CertificationRequest,
signedKey  [0] SignedPublicKeyAndChallenge }

SignedPublicKeyAndChallenge :: SEQUENCE {
publicKeyAndChallenge PublicKeyAndChallenge,
signatureAlgorithm AlgorithmIdentifier,
signature BIT STRING }

PublicKeyAndChallenge :: SEQUENCE {
spki SubjectPublicKeyInfo,
challenge IA5String }


CertificationRequest ::=         SEQUENCE {
  certificationRequestInfo         SEQUENCE {
    version                          INTEGER,
    subject                          Name,
    subjectPublicKeyInfo             SEQUENCE {
      algorithm                        AlgorithmIdentifier,
      subjectPublicKey                 BIT STRING }
    attributes                     [0] IMPLICIT SET OF Attribute
                                       }
  signatureAlgorithm               AlgorithmIdentifier,
  signature                        BIT STRING }


 CertificationRequestInfo ::= SEQUENCE {
         version Version,
         subject Name,
         subjectPublicKeyInfo SubjectPublicKeyInfo,
         attributes [0] IMPLICIT Attributes }

  Version ::= INTEGER
  Attributes ::= SET OF Attribute
*/

/*!
* \brief
* PKCS10 
*/
typedef struct pkcs10_X509_REQ_Info_st
{
	INTEGER			*version;
	X509_NAME		*subject;
	X509_PUBKEY		*subjectPublicKeyInfo;
	X509_ATTRIBUTES		*attributes;
} PKCS10_X509_REQ_INFO;

typedef struct pkcs10_X509_REQ_st
{
	PKCS10_X509_REQ_INFO	*certificationRequestInfo;
	X509_ALGO_IDENTIFIER	*signatureAlgorithm;
	BIT_STRING		*signature;
} PKCS10_X509_REQ;

#ifndef WIN_INI_LOADLIBRARY_PKI

ISC_API PKCS10_X509_REQ_INFO *new_PKCS10_X509_REQ_INFO(void);
/**
*  
*  @brief: new_PKCS10_X509_REQ_INFO 외부에서 별도로 할당하는 메모리를 자동으로 할당하는 경우
*          memory leak이 발생하여 해당부분을 주석처리함 
*          (ca에서 memory leak 을 방지하는 용도로 사용)
*  @author: hyungsun.cho 2021.02.01
*/
ISC_API PKCS10_X509_REQ_INFO *new_PKCS10_X509_REQ_INFO2(void);
ISC_API void free_PKCS10_X509_REQ_INFO(PKCS10_X509_REQ_INFO *unit);
ISC_API PKCS10_X509_REQ_INFO * dup_PKCS10_X509_REQ_INFO(PKCS10_X509_REQ_INFO *unit);
ISC_API ISC_STATUS PKCS10_X509_REQ_to_Seq(PKCS10_X509_REQ *certreq, SEQUENCE **CertificationRequest_seq);
ISC_API ISC_STATUS Seq_to_PKCS10_X509_REQ(SEQUENCE *top, PKCS10_X509_REQ **certreq);
ISC_API ISC_STATUS PKCS10_X509_REQ_INFO_to_Seq(PKCS10_X509_REQ_INFO *certreqinfo, SEQUENCE **CertificationRequestInfo_seq);
ISC_API ISC_STATUS Seq_to_PKCS10_X509_REQ_INFO(SEQUENCE *top, PKCS10_X509_REQ_INFO **certreqinfo);
ISC_API ISC_STATUS PKCS10_X509_REQ_INFO_Set_Version(PKCS10_X509_REQ_INFO *a, int version);
ISC_API ISC_STATUS PKCS10_X509_REQ_INFO_Set_Subject(PKCS10_X509_REQ_INFO *ri, X509_NAME *name);
ISC_API ISC_STATUS PKCS10_X509_REQ_INFO_Set_Pubkey(PKCS10_X509_REQ_INFO *ri, X509_PUBKEY *pubkey);
ISC_API ISC_STATUS PKCS10_X509_REQ_INFO_Add_Extension(PKCS10_X509_REQ_INFO *ri, X509_EXTENSIONS *xext);
ISC_API PKCS10_X509_REQ *new_PKCS10_X509_REQ(void);
/**
*  
*  @brief: new_PKCS10_X509_REQ 외부에서 별도로 할당하는 메모리를 자동으로 할당하는 경우
*          memory leak이 발생하여 해당부분을 주석처리함 
*          (ca에서 memory leak 을 방지하는 용도로 사용)
*  @author: hyungsun.cho 2021.02.01
*/
ISC_API PKCS10_X509_REQ *new_PKCS10_X509_REQ2(void);
ISC_API void free_PKCS10_X509_REQ(PKCS10_X509_REQ *unit);
ISC_API PKCS10_X509_REQ * dup_PKCS10_X509_REQ(PKCS10_X509_REQ *unit);
ISC_API ISC_STATUS encode_PKCS10_X509_REQ(SEQUENCE *CertificationRequest_seq, unsigned char **bin, int *binlen);
ISC_API ISC_STATUS decode_PKCS10_X509_REQ(unsigned char *bin, int binlen, SEQUENCE **CertificationRequest_seq);
ISC_API ISC_STATUS PKCS10_X509_REQ_Set_signatureAlgorithm(PKCS10_X509_REQ *req, X509_ALGO_IDENTIFIER *alg);
   
#else

#include "foundation_pki.h"


#endif

#ifdef  __cplusplus
}
#endif
#endif
