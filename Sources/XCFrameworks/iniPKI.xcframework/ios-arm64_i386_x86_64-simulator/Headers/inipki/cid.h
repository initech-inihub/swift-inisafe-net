/**
 * @file cid.h
 * @author kwangho.jung (kwangho.jung@initech.com)
 * @brief ecdh 방식 cid 교환 구조체 정의
 * @version 0.1
 * @date 2021-04-07
 * 
 * @copyright Copyright (c) 2021
 * 
 */
#ifndef __CI_H_
#define __CI_H_

#include "version.h"
#include "inicrypto/digest.h"
#include "asn1.h"
#include "asn1_stack.h"
#include "asn1_objects.h"
#include "asn1_objects.h"
#include "x962.h"

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

// https://tools.ietf.org/html/rfc5480
/*
    SubjectPublicKeyInfo  ::=  SEQUENCE  {
       algorithm         AlgorithmIdentifier,  // oid of public key
       subjectPublicKey  BIT STRING
     }
     EC_PUBLIC_KEY
*/
typedef struct AlgorithmIdentifier_tag {
	OBJECT_IDENTIFIER *algorithm;  /*!< 알고리즘의 OBJECT IDENTIFIER */
	int type;
#define      unitparameters_chosen 1
#define      strparameters_chosen 2
#define      unknown_chosen 3
	union {
        ASN1_UNIT   *unitparameters;
        ASN1_STRING *strparameters; /*!< 알고리즘에 따른 Parameter */
	} d;
} AlgorithmIdentifier;


typedef struct CIREQ_tag{
    INTEGER *version;
    EC_PUBLIC_KEY* reqPubKey;
    AlgorithmIdentifier* ciEncAlg;
}CIREQ;

typedef struct CIRES_tag{
    INTEGER *version;
    EC_PUBLIC_KEY* resPubKey;
    AlgorithmIdentifier* ciEncAlg;
    OCTET_STRING* encryptedCI;
}CIRES;

AlgorithmIdentifier* new_AlgorithmIdentifier();
void free_AlgorithmIdentifier(AlgorithmIdentifier* algorithm_identifier);
int AlgorithmIdentifier_to_Seq(AlgorithmIdentifier* algorithm_identifier, SEQUENCE** algorithm_identifier_seq);
int Seq_to_AlgorithmIdentifier(SEQUENCE* algorithm_identifier_seq, AlgorithmIdentifier** algorithm_identifier);
AlgorithmIdentifier* dup_AlgorithmIdentifier(AlgorithmIdentifier* algorithm_identifier);
int cmp_AlgorithmIdentifier(AlgorithmIdentifier* algid1, AlgorithmIdentifier* algid2);

ISC_API CIREQ* new_CIREQ();
ISC_API void free_CIREQ(CIREQ* ci_req);
ISC_API int CIREQ_to_Seq(CIREQ* ci_req, SEQUENCE** ci_req_seq);
ISC_API int Seq_to_CIREQ(SEQUENCE* ci_req_seq, CIREQ** ci_req);

ISC_API CIRES* new_CIRES();
ISC_API void free_CIRES(CIRES* ci_res);
ISC_API int CIRES_to_Seq(CIRES* ci_res, SEQUENCE** ci_res_seq);
ISC_API int Seq_to_CIRES(SEQUENCE* ci_res_seq, CIRES** ci_res);

ISC_API int createCIRequest(CIREQ** cireq, short version, int cipherID, ISC_ECC_KEY_UNIT* pubKey);
ISC_API int createCIResponse(CIRES** cires, short version, int cipherID, ISC_ECC_KEY_UNIT* pubKey, const unsigned char* encryptedCI, int encCILen);

#ifdef __cplusplus
}	/* extern "C" */
#endif /* __cplusplus */

#endif
