/**
 * @file cid_dh.h
 * @author kwangho.jung (kwangho.jung@initech.om)
 * @brief 디피헬만 키교환 방식 CID 송/수신을 위한 구조체 정의
 * @version 0.1
 * @date 2021-04-07
 *
 * @copyright Copyright (c) 2021
 *
 */
#ifndef __DHCI_H_
#define __DHCI_H_

#include "version.h"
#include "inicrypto/digest.h"
#include "inicrypto/dh.h"
#include "asn1.h"
#include "asn1_stack.h"
#include "asn1_objects.h"
#include "asn1_objects.h"
#include "cid.h"

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

// https://tools.ietf.org/html/rfc3279
/*
    DomainParameters ::= SEQUENCE {
        p INTEGER,
        g INTEGER,
        q INTEGER,
    }
    DHPublicKey ::= INTEGER
*/

typedef struct DomainParameters_tag{
    INTEGER *p;
    INTEGER *g;
    INTEGER *q;
}DOMAIN_PARAMS;

DOMAIN_PARAMS* new_DOMAIN_PARAMS();
void free_DOMAIN_PARAMS(DOMAIN_PARAMS* dparams);
ISC_API int DOMAIN_PARAMS_to_Seq(DOMAIN_PARAMS* domain_params, SEQUENCE** domain_params_seq);
ISC_API int Seq_to_DOMAIN_PARAMS(SEQUENCE* domain_params_seq, DOMAIN_PARAMS** domain_params);

typedef struct DHCIREQ_tag{
    INTEGER *version;
    DOMAIN_PARAMS* reqPubParams;
    INTEGER* reqPubKey;
    AlgorithmIdentifier* ciEncAlg;
}DHCIREQ;

typedef struct DHCIRES_tag{
    INTEGER *version;
    INTEGER *resPubKey;
    AlgorithmIdentifier* ciEncAlg;
    OCTET_STRING* encryptedCI;
}DHCIRES;

#ifndef WIN_INI_LOADLIBRARY_PKI
ISC_API DHCIREQ* new_DHCIREQ();
ISC_API void free_DHCIREQ(DHCIREQ* ci_req);
ISC_API int DHCIREQ_to_Seq(DHCIREQ* ci_req, SEQUENCE** ci_req_seq);
ISC_API int Seq_to_DHCIREQ(SEQUENCE* ci_req_seq, DHCIREQ** ci_req);

ISC_API DHCIRES* new_DHCIRES();
ISC_API void free_DHCIRES(DHCIRES* ci_res);
ISC_API int DHCIRES_to_Seq(DHCIRES* ci_res, SEQUENCE** ci_res_seq);
ISC_API int Seq_to_DHCIRES(SEQUENCE* ci_res_seq, DHCIRES** ci_res);

ISC_API int createDHCIRequest(DHCIREQ** cireq, short version, int cipherID, ISC_DH_UNIT* pubKey);
ISC_API int createDHCIResponse(DHCIRES** cires, short version, int cipherID, ISC_DH_UNIT* pubKey, const unsigned char* encryptedCI, int encCILen);
#else
#include "foundation_pki.h"
INI_RET_LOADLIB_PKI(DHCIREQ*, new_DHCIREQ, (void), (), NULL);
INI_VOID_LOADLIB_PKI(void, free_DHCIREQ, (DHCIREQ *ci_req), (ci_req) );
INI_RET_LOADLIB_PKI(int, DHCIREQ_to_Seq, (DHCIREQ* ci_req, SEQUENCE** ci_req_seq), (ci_req,ci_req_seq), ISC_FAIL);
INI_RET_LOADLIB_PKI(int, Seq_to_DHCIREQ, (SEQUENCE* ci_req_seq, DHCIREQ** ci_req), (ci_req_seq,ci_req), ISC_FAIL);

INI_RET_LOADLIB_PKI(DHCIRES*, new_DHCIRES, (void), (), NULL);
INI_VOID_LOADLIB_PKI(void, free_DHCIRES, (DHCIRES *ci_res), (ci_res) );
INI_RET_LOADLIB_PKI(int, DHCIRES_to_Seq, (DHCIRES* ci_res, SEQUENCE** ci_res_seq), (ci_res,ci_res_seq), ISC_FAIL);
INI_RET_LOADLIB_PKI(int, Seq_to_DHCIRES, (SEQUENCE* ci_res_seq, DHCIRES** ci_res), (ci_res_seq,ci_res), ISC_FAIL);

INI_RET_LOADLIB_PKI(int, createDHCIRequest, (DHCIREQ** cireq, short version, int cipherID, ISC_DH_UNIT* pubKey), (cireq, version, cipherID, pubKey), ISC_FAIL);
INI_RET_LOADLIB_PKI(int, createDHCIResponse, (DHCIRES** cires, short version, int cipherID, ISC_DH_UNIT* pubKey, const unsigned char* encryptedCI, int encCILen), (cires, version, cipherID, pubKey, encryptedCI, encCILen), ISC_FAIL);
#endif

#ifdef __cplusplus
}	/* extern "C" */
#endif /* __cplusplus */

#endif
