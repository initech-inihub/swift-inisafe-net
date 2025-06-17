//
//  ipin.h
//  iPin
//
//  Created by myoungjoong.kim on 25/09/2019.
//  Copyright © 2019 myoungjoong.kim. All rights reserved.
//

#ifndef HEADER_UCPID_H
#define HEADER_UCPID_H

#include <stdio.h>
#include "asn1.h"

#ifdef  __cplusplus
extern "C" {
#endif
    
#define CI_RESIDENT_NUMBER_LEN             13
#define CI_SECRET_INFORMATION_LEN          64
#define CI_SECRET_KEY_LEN                  64
    
/******************* CI *******************/
typedef struct ci_combination_st {
    PRINTABLE_STRING *registerNumber;   /* 가입자의 주민등록번호 */
    PRINTABLE_STRING *padding;          /* 해시 입력(512비트)을 위한 패딩(Padding) 값 */
} CI_COMBINATION;

typedef struct ci_exclusive_st {
    BIT_STRING *combinationResult;      /* RN과 패딩(Padding)의 연접 결과 */
    BIT_STRING *secretInformationA;     /* 연계 정보 생성을 위해 본인 확인 기관 간 공유된 비밀정보 */
} CI_EXCLUSIVE;

typedef struct ci_to_be_hmac_st {
    BIT_STRING *shareKey;               /* 연계 정보 생성을 위해 본인 확인 기관 간 공유된 비밀 키 */
    BIT_STRING *exclusiveResult;        /* XOR한 결과값 */
} CI_TO_BE_HMAC;

typedef struct conneting_info_st {
    OBJECT_IDENTIFIER *hmacAlgorithm;   /* HMAC 알고리즘 식별자 정보를 사용 */
    BIT_STRING *hmac;                   /* HMAC의 출력값 */
} CONNETING_INFO;

CI_COMBINATION* new_CI_COMBINATION(void);
void free_CI_COMBINATION(CI_COMBINATION *unit);
void clean_CI_COMBINATION(CI_COMBINATION *unit);
int set_CI_COMBINATION(CI_COMBINATION **unit, char *rn, char *padding);
int CI_COMBINATION_to_seq(CI_COMBINATION *unit, SEQUENCE **seq);

CI_EXCLUSIVE* new_CI_EXCLUSIVE(void);
void free_CI_EXCLUSIVE(CI_EXCLUSIVE *unit);
void clean_CI_EXCLUSIVE(CI_EXCLUSIVE *unit);

CI_TO_BE_HMAC* new_CI_TO_BE_HMAC(void);
void free_CI_TO_BE_HMAC(CI_TO_BE_HMAC *unit);
void clean_CI_TO_BE_HMAC(CI_TO_BE_HMAC *unit);

CONNETING_INFO* new_CONNETING_INFO(void);
void free_CONNETING_INFO(CONNETING_INFO *unit);
void clean_CONNETING_INFO(CONNETING_INFO *unit);
int set_CONNETING_INFO(CONNETING_INFO **unit, unsigned char *xor_result, int xor_result_len, unsigned char *sk, int sk_len, int hmac_id);

/******************* DI *******************/
typedef struct before_mac_st {
    PRINTABLE_STRING *registerNumber;   /* 가입자의 주민등록번호 */
    PRINTABLE_STRING *siteInfo;         /* 인터넷 사업자의 웹사이트 식별정보 */
} BEFORE_MAC;

typedef struct temp_hash_value_st {
    OBJECT_IDENTIFIER *macAlgorithm;    /* 해시 알고리즘 식별자 정보를 사용(SHA256) */
    BIT_STRING *mac;                    /* BeforeMac을 해시알고리즘에 입력하여 해시한 결과 값 */
} TEMP_HASH_VALUE;

typedef struct tobemac_st {
    BIT_STRING *shareKey;           /* 본인 확인 기관 간 공유된 비밀정보 */
    BIT_STRING *beforeMacResult;    /* BeforeMac을 해시알고리즘에 입력하여 해시한 TemphashValue 값 */
} TO_BE_MAC;

typedef struct duplicateion_join_verification_info_st {
    OBJECT_IDENTIFIER *hmacAlgorithm;   /* HMAC 알고리즘 식별자 정보를 사용 */
    BIT_STRING *hmac;                   /* ToBeMac을 HMAC한 출력값 */
} DUPLICATION_JOIN_VERIFICATION_INFO;

BEFORE_MAC* new_BEFORE_MAC(void);
void free_BEFORE_MAC(BEFORE_MAC *unit);
void clean_BEFORE_MAC(BEFORE_MAC *unit);
int set_BEFORE_MAC(BEFORE_MAC **unit, char *rn, char *si);
int BEFORE_MAC_to_seq(BEFORE_MAC *unit, SEQUENCE **seq);

TEMP_HASH_VALUE* new_TEMP_HASH_VALUE(void);
void free_TEMP_HASH_VALUE(TEMP_HASH_VALUE *unit);
void clean_TEMP_HASH_VALUE(TEMP_HASH_VALUE *unit);
int set_TEMP_HASH_VALUE(TEMP_HASH_VALUE **unit, BEFORE_MAC *bm, char *hash_alg);
int TEMP_HASH_VALUE_to_seq(TEMP_HASH_VALUE *unit, SEQUENCE **seq);

TO_BE_MAC* new_TO_BE_MAC(void);
void free_TO_BE_MAC(TO_BE_MAC *unit);
void clean_TO_BE_MAC(TO_BE_MAC *unit);
int set_TO_BE_MAC(TO_BE_MAC **unit, TEMP_HASH_VALUE *thv, unsigned char *sk, int sk_len);
int TO_BE_MAC_to_seq(TO_BE_MAC *unit, SEQUENCE **seq);

DUPLICATION_JOIN_VERIFICATION_INFO* new_DUPLICATION_JOIN_VERIFICATION_INFO(void);
void free_DUPLICATION_JOIN_VERIFICATION_INFO(DUPLICATION_JOIN_VERIFICATION_INFO *unit);
void clean_DUPLICATION_JOIN_VERIFICATION_INFO(DUPLICATION_JOIN_VERIFICATION_INFO *unit);
int set_DUPLICATION_JOIN_VERIFICATION_INFO(DUPLICATION_JOIN_VERIFICATION_INFO **unit, TO_BE_MAC *tbm, int hmac_id);
int DUPLICATION_JOIN_VERIFICATION_INFO_to_seq(DUPLICATION_JOIN_VERIFICATION_INFO *unit, SEQUENCE **seq);

    
#ifdef  __cplusplus
}
#endif

#endif /* #ifndef HEADER_UCPID_H */
