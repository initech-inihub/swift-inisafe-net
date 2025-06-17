/*!
* \file cpv.h
* \brief CPV
* Certificate Path Validate
* \remarks
* \author
* Copyright (c) 2008 by \<INITECH\>
*/
#ifndef __CPV_H__
#define __CPV_H__

#ifdef NO_PKI
#error PKI is disabled.
#endif

#include "ctl.h"
#include "pkcs7.h"

#ifdef  __cplusplus
extern "C" {
#endif

#define MAX_LENGTH_OF_PATH		3

/* type of certificate */
#define PKI_UNKNOWN				0x00
#define PKI_ROOTCA				0x01
#define PKI_CA					0x02
#define PKI_USER				0x04

#define TYPE_X509_CERT			0x10
#define TYPE_TRUST_ANCHOR		0x20
#define TYPE_POLICY				0x40

#define DATA_TYPE_MASK			0xF0
#define PKI_TYPE_MASK			0x0F

#define new_TRUST_ANCHOR_STK() new_STK(TRUST_ANCHOR)
#define free_TRUST_ANCHOR_STK(st) free_STK(TRUST_ANCHOR, (st))
#define get_TRUST_ANCHOR_STK_count(st) get_STK_count(TRUST_ANCHOR, (st))
#define get_TRUST_ANCHOR_STK_value(st, i) get_STK_value(TRUST_ANCHOR, (st), (i))
#define push_TRUST_ANCHOR_STK(st, val) push_STK_value(TRUST_ANCHOR, (st), (val))
#define find_TRUST_ANCHOR_STK(st, val) find_STK_value(TRUST_ANCHOR, (st), (val))
#define remove_TRUST_ANCHOR_STK(st, i) remove_STK_value(TRUST_ANCHOR, (st), (i))
#define insert_TRUST_ANCHOR_STK(st, val, i) insert_STK_value(TRUST_ANCHOR, (st), (val), (i))
#define dup_TRUST_ANCHOR_STK(st) dup_STK(TRUST_ANCHOR, st)
#define free_TRUST_ANCHOR_STK_values(st, free_func) free_STK_values(TRUST_ANCHOR, (st), (free_func))
#define pop_TRUST_ANCHOR_STK(st) pop_STK_value(TRUST_ANCHOR, (st))
#define sort_TRUST_ANCHOR_STK(st) sort_STK(TRUST_ANCHOR, (st))
#define is_TRUST_ANCHOR_STK_sorted(st) is_STK_sorted(TRUST_ANCHOR, (st))

#define new_VALID_POLICY_NODE_STK() new_STK(VALID_POLICY_NODE)
#define free_VALID_POLICY_NODE_STK(st) free_STK(VALID_POLICY_NODE, (st))
#define get_VALID_POLICY_NODE_STK_count(st) get_STK_count(VALID_POLICY_NODE, (st))
#define get_VALID_POLICY_NODE_STK_value(st, i) get_STK_value(VALID_POLICY_NODE, (st), (i))
#define push_VALID_POLICY_NODE_STK(st, val) push_STK_value(VALID_POLICY_NODE, (st), (val))
#define find_VALID_POLICY_NODE_STK(st, val) find_STK_value(VALID_POLICY_NODE, (st), (val))
#define remove_VALID_POLICY_NODE_STK(st, i) remove_STK_value(VALID_POLICY_NODE, (st), (i))
#define insert_VALID_POLICY_NODE_STK(st, val, i) insert_STK_value(VALID_POLICY_NODE, (st), (val), (i))
#define dup_VALID_POLICY_NODE_STK(st) dup_STK(VALID_POLICY_NODE, st)
#define free_VALID_POLICY_NODE_STK_values(st, free_func) free_STK_values(VALID_POLICY_NODE, (st), (free_func))
#define pop_VALID_POLICY_NODE_STK(st) pop_STK_value(VALID_POLICY_NODE, (st))
#define sort_VALID_POLICY_NODE_STK(st) sort_STK(VALID_POLICY_NODE, (st))
#define is_VALID_POLICY_NODE_STK_sorted(st) is_STK_sorted(VALID_POLICY_NODE, (st))

#define OID_ANY_POLICY_LENGTH		11
#define OID_ANY_POLICY				"2.5.29.32.0"

/*!
* \brief
* linked list 의 정보를 저장하는 구조체
*/
typedef struct node_LIST_st {
	int						idx;										/*!< index */
	int						type;										/*!< TYPE_X509_CERT(and type of certificate), TYPE_TRUST_ANCHOR */
	void					*data;										/*!< 인증서 정보 */
	struct node_LIST_st		*next;										/*!< 다음 인증서정보 구조체 포인트 */
} node_LIST;

/*!
* \brief
* trustAnchor
* trustAnchor  ::= SEQUENCE  {
*				rootCAName Name,
*				rootCAPublicKeyInfo PublicKeyInfo
*			}
*/
typedef struct TRUST_ANCHOR_st {
	int						idx;										/*!< */
	X509_NAME				*rootCAName;								/*!< */
	X509_PUBKEY 			*rootCAPublickKeyInfo;						/*!< */
} TRUST_ANCHOR;

/*!
* \brief
* TRUST_ANCHOR STACK
*/
typedef STK(TRUST_ANCHOR) TRUST_ANCHORS;

/*!
* \brief
* VALID_POLICY_DATA
*/
typedef struct VALID_POLICY_DATA_st
{
	unsigned int			criticality;								/*!< criticality */
	OBJECT_IDENTIFIER		*valid_policy;								/*!< POLICY OID */
	POLICY_QUALIFIERS		*qualifier_set;								/*!< stack of POLICY_QUALIFIER */
	OBJECT_IDENTIFIERS		*expected_policy_set;						/*!< stack of OBJECT_IDENTIFIER */
} VALID_POLICY_DATA;

/*!
* \brief
* VALID_POLICY_NODE
*/
typedef struct VALID_POLICY_NODE_st
{
	int									count;							/*!< child count */
	VALID_POLICY_DATA					*data;							/*!< policy data */
	struct VALID_POLICY_NODE_st			*parent;						/*!< parent policy node */
} VALID_POLICY_NODE;

/*!
* \brief
* VALID_POLICY_NODE의 스택 구조체
*/
typedef STK(VALID_POLICY_NODE) VALID_POLICY_NODES;

#ifndef WIN_INI_LOADLIBRARY_PKI

/*!
* \brief
* node_LIST 구조체의 초기화 함수
* \returns
* node_LIST 구조체 포인터
*/
ISC_API node_LIST *new_node_LIST(void);

/*!
* \brief
* node_LIST 구조체를 메모리 할당 해제하는 함수
* \param list
* 제거할 구조체
* \remarks
* 구조체를 제거(ISC_MEM_FREE)
*/
ISC_API void free_node_LIST(node_LIST *list);

/*!
* \brief
* node_LIST 구조체의 인증서 삭제하는 함수
* \returns
* 성공/실패
*/
ISC_API ISC_STATUS remove_node_LIST(node_LIST *list, int idx);

/*!
* \brief
* node_LIST 구조체를 링크를 역순으로 변경하는 함수
* \param list
* 변경할 구조체
* \returns
* node_LIST 구조체 포인터
*/
ISC_API node_LIST *reverse_node_LIST (node_LIST *list);

/*!
* \brief
* node_LIST 구조체에서 저장된 인증서의 수를 구하는 함수
* \returns
* 인증서 갯수
*/
ISC_API int get_count_from_node_LIST(node_LIST *list);

/*!
* \brief
* VALID_POLICY_DATA 구조체의 초기화 함수
* \returns
* VALID_POLICY_DATA 구조체 포인터
*/
ISC_API VALID_POLICY_DATA *new_VALID_POLICY_DATA(void);

/*!
* \brief
* VALID_POLICY_DATA 구조체를 메모리 할당 해제하는 함수
* \param data
* 제거할 구조체
* \remarks
* 구조체를 제거(ISC_MEM_FREE)
*/
ISC_API void free_VALID_POLICY_DATA(VALID_POLICY_DATA *data);

/*!
* \brief
* VALID_POLICY_NODE 구조체의 초기화 함수
* \returns
* VALID_POLICY_NODE 구조체 포인터
*/
ISC_API VALID_POLICY_NODE *new_VALID_POLICY_NODE(void);

/*!
* \brief
* VALID_POLICY_NODE 구조체를 메모리 할당 해제하는 함수
* \param vpn
* 제거할 구조체
* \remarks
* 구조체를 제거(ISC_MEM_FREE)
*/
ISC_API void free_VALID_POLICY_NODE(VALID_POLICY_NODE *vpn);

/*!
* \brief
* VALID_POLICY_NODES 구조체의 초기화 함수
* \returns
* VALID_POLICY_NODES 구조체 포인터
*/
ISC_API VALID_POLICY_NODES *new_VALID_POLICY_NODES(void);

/*!
* \brief
* VALID_POLICY_NODES 구조체를 메모리 할당 해제하는 함수
* \param nodes
* 제거할 구조체
* \remarks
* 구조체를 제거(ISC_MEM_FREE)
*/
ISC_API void free_VALID_POLICY_NODES(VALID_POLICY_NODES *nodes);

/*!
* \brief
* node_LIST 구조체의 VALID_POLICY_TREE_LIST 추가하는 함수
* \returns
* 성공/실패
*/
ISC_API ISC_STATUS add_VALID_POLICY_TREE_LIST(node_LIST *vptlist, VALID_POLICY_NODES *vpns);

/*!
* \brief
* 대상인증서가 self signed인가를 검사하는 함수
* \returns
* 성공/실패
*/

ISC_API ISC_STATUS is_selfSigned(X509_CERT *cert);

/*!
* \brief
* 대상인증서가 issuer_candidate 가 cert 를 발급한 인증서인지 검사하는 함수
* \returns
* 성공/실패
*/
ISC_API ISC_STATUS is_issuer(X509_CERT *issuer_candidate, X509_CERT *cert);
/*!
* \brief
* 대상인증서의 인증경로를 구축하는 함수
* \returns
* 성공/실패
*/
ISC_API ISC_STATUS build_certPath(X509_CERTS *certs, TRUST_ANCHORS *trusts, X509_CERT *cert, X509_CERTS **pathcert);

/*!
* \brief
* TRUST_ANCHOR 구조체의 초기화 함수
* \returns
* TRUST_ANCHOR 구조체 포인터
*/
ISC_API TRUST_ANCHOR *new_TRUST_ANCHOR(void);

/*!
* \brief
* TRUST_ANCHOR 구조체를 메모리 할당 해제
* \param TRUST_ANCHOR
* 제거할 구조체
* \remarks
* 구조체를 제거(ISC_MEM_FREE)
*/
ISC_API void free_TRUST_ANCHOR(TRUST_ANCHOR *unit);

/*!
* \brief
* TRUST_ANCHOR 구조체를 리셋
* \param unit
* 리셋할 구조체
*/
ISC_API void clean_TRUST_ANCHOR(TRUST_ANCHOR *unit);

/*!
* \brief
* TRUST_ANCHOR 구조체를 Sequence로 Encode 함수
* \param ta
* TRUST_ANCHOR 구조체
* \param seq
* Encoding Sequence 구조체
* \returns
* -# ISC_SUCCESS : 성공
* -# LOCATION^F_TRUST_ANCHOR_TO_SEQ^ISC_ERR_NULL_INPUT : Null_Input
* -# LOCATION^F_TRUST_ANCHOR_TO_SEQ^ERR_ASN1_ENCODING : ASN1 Err
* -# TRUST_ANCHOR_to_Seq()의 에러 코드\n
*/
ISC_API ISC_STATUS TRUST_ANCHOR_to_Seq (TRUST_ANCHOR *ta, SEQUENCE **seq);

/*!
* \brief
* Sequence를 TRUST_ANCHOR 구조체로 Decode 함수
* \param seq
* Decoding Sequece 구조체
* \param ta
* TRUST_ANCHOR 구조체
* \returns
* -# ISC_SUCCESS : 성공
* -# LOCATION^F_SEQ_TO_TRUST_ANCHOR^ISC_ERR_NULL_INPUT : Null_Input
* -# LOCATION^F_SEQ_TO_TRUST_ANCHOR^ERR_ASN1_ENCODING : ASN1 Err
* -# Seq_to_TRUST_ANCHOR()의 에러 코드\n
*/
ISC_API ISC_STATUS Seq_to_TRUST_ANCHOR (SEQUENCE *seq, TRUST_ANCHOR** ta);

/*!
* \brief
* TRUST_ANCHOR를 복사하는 기능
* \param 복사할 원본 TRUST_ANCHOR* pkey
* \return 복사된 TRUST_ANCHOR* 
*/
ISC_API TRUST_ANCHOR * dup_TRUST_ANCHOR(TRUST_ANCHOR *src);

/*!
* \brief
* TRUST_ANCHORS 스택의 초기화 함수
* \returns
* TRUST_ANCHORS 스택 포인터
*/
ISC_API TRUST_ANCHORS *new_TRUST_ANCHORS(void);

/*!
* \brief
* TRUST_ANCHORS 구조체를 메모리 할당 해제
* \param TRUST_ANCHORS
* 제거할 구조체
* \remarks
* 구조체를 제거(ISC_MEM_FREE)
*/
ISC_API void free_TRUST_ANCHORS(TRUST_ANCHORS *unit);

/*!
* \brief
* TRUST_ANCHORS 스택에 TRUST_ANCHOR를 추가
* \param trustanchors
* TRUST_ANCHORS 스택 포인터
* \param trustanchor
* 추가될 TRUST_ANCHOR 구조체 포인터
* \return
* -# ISC_SUCCESS : 성공
* -# ISC_FAIL : 실패
*/
ISC_API ISC_STATUS add_TRUST_ANCHORS(TRUST_ANCHORS *trustanchors, TRUST_ANCHOR *trustanchor);

/*!
* \brief
* TRUST_ANCHORS 스택에서 X509_CERT와 일치하는 인덱스를 검색
* \param tas
* TRUST_ANCHORS 스택 포인터
* \param ta
* TRUST_ANCHOR 구조체 포인터
* \return
* -# ta와 일치하는 인덱스
* -# ta와 일치하는 인덱스가 없을경우 -1
*/
ISC_API int get_TRUST_ANCHORS_index_by_TRUST_ANCHOR(TRUST_ANCHORS *tas, TRUST_ANCHOR *ta);

/*!
* \brief
* MAX_CERTIFICATEPATH_LENGTH를 설정하는 기능
* \param 설정할 MAX_CERTIFICATEPATH_LENGTH length
* \returns
* -# ISC_SUCCESS : 성공
* -# ISC_FAIL : 실패
*/
ISC_API ISC_STATUS set_max_certificatePath_length(int length);


/*!
* \brief
* MAX_CERTIFICATEPATH_LENGTH를 구하는 기능
* \returns
* -# int : MAX_CERTIFICATEPATH_LENGTH
*/
ISC_API int get_max_certificatePath_length(void);

/*!
* \brief
* initial_policy_mapping_inhibit를 설정하는 기능
* \param 설정할 initial_policy_mapping_inhibit 사용여부(TRUE/FALSE)
* \returns
* -# 없음
*/
ISC_API void set_initial_policy_mapping_inhibit(int flag);

/*!
* \brief
* initial_policy_mapping_inhibit를 구하는 기능
* 초기정책 매핑금지여부 
* 현재 국내 공인인증기관 CA인증서에는 정책매핑 확장필드 없음.
* \returns
* -# bool : 초기정책 매핑금지 여부 (항상 FALSE)
*/
ISC_API int get_initial_policy_mapping_inhibit(void);

/*!
* \brief
* initial_explicit_policy를 설정하는 기능
* \param 설정할 initial_explicit_policy 사용여부(TRUE/FALSE)
* \returns
* -# 없음
*/
ISC_API void set_initial_explicit_policy(int flag);

/*!
* \brief
* initial_explicit_policy를 구하는 기능
* 초기 명시 정책 여부
* 사용자 초기정책 집합과 유효정책트리를 비교할지 여부.
* \returns
* -# bool : 초기 명시 정책 여부(기본값 TURE)
*/
ISC_API int get_initial_explicit_policy(void);

/*!
* \brief
* initial_any_policy_inhibit를 설정하는 기능
* \param 설정할 initial_any_policy_inhibit 사용여부(TRUE/FALSE)
* \returns
* -# 없음
*/
ISC_API void set_initial_any_policy_inhibit(int flag);

/*!
* \brief
* initial_any_policy_inhibit를 구하는 기능
* 초기 모든정책금지 여부 
* anypolicy 정책을 허용할지 여부. TRUE이면 anypolicy 사용불가
* \returns
* -# bool : 초기 모든정책금지 여부 (기본값 FALSE)
*/
ISC_API int get_initial_any_policy_inhibit(void);

/*!
* \brief
* 해당 인증경로의 유효성을 검증하는 기능
* \param 대상 인증경로
* \returns
* -# ISC_SUCCESS : 성공
* -# ISC_FAIL : 실패
*/
ISC_API ISC_STATUS validate_certpath(X509_CERTS *certpathlist, OBJECT_IDENTIFIERS *user_policies, node_LIST **valid_policy_tree);

/*!
* \brief
* VALID_POLICY_TREE_LIST구조체에 인증서의 정보를 출력
* \param list
* VALID_POLICY_TREE_LIST 구조체
*/
ISC_API void print_VALID_POLICY_TREE_LIST(node_LIST *list);

/*!
* \brief
* 해당 인증서 신뢰목록의 유효성을 검증하는 기능
* \param 인증서 신뢰목록 (pkcs7 's SignedData)
* \returns
* -# ISC_SUCCESS : 성공
* -# ISC_FAIL : 실패
*/
ISC_API ISC_STATUS verify_ctlSignedData(P7_CONTENT_INFO *p7);

/*!
* \brief
* TRUST_ANCHORS 스택에 TRUST_ANCHOR를 추가
* \param ta
* TRUST_ANCHORS 스택 포인터
* \param p7
* 추가될 CTL 구조체 포인터(PKCS7's SignedData)
* \return
* -# ISC_SUCCESS : 성공
* -# ISC_FAIL : 실패
*/
ISC_API ISC_STATUS add_TRUST_ANCHORS_from_CTL(TRUST_ANCHORS *ta, P7_CONTENT_INFO *p7);

/*!
* \brief
* X509_CERTS 스택에 CTL의 인증서를 추가
* \param certs
* P7_CONTENT_INFO 포인터
* \param p7
* 추가될 CTL 구조체 포인터(PKCS7's SignedData)
* \return
* -# ISC_SUCCESS : 성공
* -# ISC_FAIL : 실패
*/
ISC_API ISC_STATUS add_CERTIFICATES_from_CTL(X509_CERTS *certs, P7_CONTENT_INFO *p7);

#else

#include "foundation_pki.h"

INI_RET_LOADLIB_PKI(node_LIST*, new_node_LIST, (void), (), NULL);
INI_VOID_LOADLIB_PKI(void, free_node_LIST, (node_LIST *list), (list) );
INI_RET_LOADLIB_PKI(ISC_STATUS, remove_node_LIST, (node_LIST *list, int idx), (list,idx), ISC_FAIL);
INI_RET_LOADLIB_PKI(node_LIST*, reverse_node_LIST, (node_LIST *list), (list), NULL);
INI_RET_LOADLIB_PKI(int, get_count_from_node_LIST, (node_LIST *list), (list), ISC_FAIL);
INI_RET_LOADLIB_PKI(VALID_POLICY_DATA*, new_VALID_POLICY_DATA, (void), (), NULL);
INI_VOID_LOADLIB_PKI(void, free_VALID_POLICY_DATA, (VALID_POLICY_DATA *data), (data) );
INI_RET_LOADLIB_PKI(VALID_POLICY_NODE*, new_VALID_POLICY_NODE, (void), (), NULL);
INI_VOID_LOADLIB_PKI(void, free_VALID_POLICY_NODE, (VALID_POLICY_NODE *vpn), (vpn) );
INI_RET_LOADLIB_PKI(VALID_POLICY_NODES*, new_VALID_POLICY_NODES, (void), (), NULL);
INI_VOID_LOADLIB_PKI(void, free_VALID_POLICY_NODES, (VALID_POLICY_NODES *nodes), (nodes) );
INI_RET_LOADLIB_PKI(ISC_STATUS, add_VALID_POLICY_TREE_LIST, (node_LIST *vptlist, VALID_POLICY_NODES *vpns), (vptlist,vpns), ISC_FAIL);
INI_RET_LOADLIB_PKI(ISC_STATUS, is_selfSigned, (X509_CERT *cert), (cert), ISC_FAIL);
INI_RET_LOADLIB_PKI(ISC_STATUS, build_certPath, (X509_CERTS *certs, TRUST_ANCHORS *trusts, X509_CERT *cert, X509_CERTS **pathcert), (certs,trusts,cert,pathcert), ISC_FAIL);
INI_RET_LOADLIB_PKI(TRUST_ANCHOR*, new_TRUST_ANCHOR, (void), (), NULL);
INI_VOID_LOADLIB_PKI(void, free_TRUST_ANCHOR, (TRUST_ANCHOR *unit), (unit) );
INI_VOID_LOADLIB_PKI(void, clean_TRUST_ANCHOR, (TRUST_ANCHOR *unit), (unit) );
INI_RET_LOADLIB_PKI(ISC_STATUS, TRUST_ANCHOR_to_Seq, (TRUST_ANCHOR *ta, SEQUENCE **seq), (ta,seq), ISC_FAIL);
INI_RET_LOADLIB_PKI(ISC_STATUS, Seq_to_TRUST_ANCHOR, (SEQUENCE *seq, TRUST_ANCHOR** ta), (seq,ta), ISC_FAIL);
INI_RET_LOADLIB_PKI(TRUST_ANCHOR*, dup_TRUST_ANCHOR, (TRUST_ANCHOR *src), (src), NULL);
INI_RET_LOADLIB_PKI(TRUST_ANCHORS*, new_TRUST_ANCHORS, (void), (), NULL);
INI_VOID_LOADLIB_PKI(void, free_TRUST_ANCHORS, (TRUST_ANCHORS *unit), (unit) );
INI_RET_LOADLIB_PKI(ISC_STATUS, add_TRUST_ANCHORS, (TRUST_ANCHORS *trustanchors, TRUST_ANCHOR *trustanchor), (trustanchors,trustanchor), ISC_FAIL);
INI_RET_LOADLIB_PKI(int, get_TRUST_ANCHORS_index_by_TRUST_ANCHOR, (TRUST_ANCHORS *tas, TRUST_ANCHOR *ta), (tas,ta), ISC_FAIL);
INI_RET_LOADLIB_PKI(ISC_STATUS, set_max_certificatePath_length, (int length), (length), ISC_FAIL);
INI_RET_LOADLIB_PKI(int, get_max_certificatePath_length, (void), (), ISC_FAIL);
INI_VOID_LOADLIB_PKI(void, set_initial_policy_mapping_inhibit, (int flag), (flag) );
INI_RET_LOADLIB_PKI(int, get_initial_policy_mapping_inhibit, (void), (), ISC_FAIL);
INI_VOID_LOADLIB_PKI(void, set_initial_explicit_policy, (int flag), (flag) );
INI_RET_LOADLIB_PKI(int, get_initial_explicit_policy, (void), (), ISC_FAIL);
INI_VOID_LOADLIB_PKI(void, set_initial_any_policy_inhibit, (int flag), (flag) );
INI_RET_LOADLIB_PKI(int, get_initial_any_policy_inhibit, (void), (), ISC_FAIL);
INI_RET_LOADLIB_PKI(ISC_STATUS, validate_certpath, (X509_CERTS *certpathlist, OBJECT_IDENTIFIERS *user_policies, node_LIST **valid_policy_tree), (certpathlist,user_policies,valid_policy_tree), ISC_FAIL);
INI_VOID_LOADLIB_PKI(void, print_VALID_POLICY_TREE_LIST, (node_LIST *list), (list) );
INI_RET_LOADLIB_PKI(ISC_STATUS, verify_ctlSignedData, (P7_CONTENT_INFO *p7), (p7), ISC_FAIL);
INI_RET_LOADLIB_PKI(ISC_STATUS, add_TRUST_ANCHORS_from_CTL, (TRUST_ANCHORS *ta, P7_CONTENT_INFO *p7), (ta,p7), ISC_FAIL);
INI_RET_LOADLIB_PKI(ISC_STATUS, add_CERTIFICATES_from_CTL, (X509_CERTS *certs, P7_CONTENT_INFO *p7), (certs,p7), ISC_FAIL);


#endif

#ifdef  __cplusplus
}
#endif
#endif /* __CPV_H__ */

