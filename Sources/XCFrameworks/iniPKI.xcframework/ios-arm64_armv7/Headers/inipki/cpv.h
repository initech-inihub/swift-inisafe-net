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
* linked list �� ������ �����ϴ� ����ü
*/
typedef struct node_LIST_st {
	int						idx;										/*!< index */
	int						type;										/*!< TYPE_X509_CERT(and type of certificate), TYPE_TRUST_ANCHOR */
	void					*data;										/*!< ������ ���� */
	struct node_LIST_st		*next;										/*!< ���� ���������� ����ü ����Ʈ */
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
* VALID_POLICY_NODE�� ���� ����ü
*/
typedef STK(VALID_POLICY_NODE) VALID_POLICY_NODES;

#ifndef WIN_INI_LOADLIBRARY_PKI

/*!
* \brief
* node_LIST ����ü�� �ʱ�ȭ �Լ�
* \returns
* node_LIST ����ü ������
*/
ISC_API node_LIST *new_node_LIST(void);

/*!
* \brief
* node_LIST ����ü�� �޸� �Ҵ� �����ϴ� �Լ�
* \param list
* ������ ����ü
* \remarks
* ����ü�� ����(ISC_MEM_FREE)
*/
ISC_API void free_node_LIST(node_LIST *list);

/*!
* \brief
* node_LIST ����ü�� ������ �����ϴ� �Լ�
* \returns
* ����/����
*/
ISC_API ISC_STATUS remove_node_LIST(node_LIST *list, int idx);

/*!
* \brief
* node_LIST ����ü�� ��ũ�� �������� �����ϴ� �Լ�
* \param list
* ������ ����ü
* \returns
* node_LIST ����ü ������
*/
ISC_API node_LIST *reverse_node_LIST (node_LIST *list);

/*!
* \brief
* node_LIST ����ü���� ����� �������� ���� ���ϴ� �Լ�
* \returns
* ������ ����
*/
ISC_API int get_count_from_node_LIST(node_LIST *list);

/*!
* \brief
* VALID_POLICY_DATA ����ü�� �ʱ�ȭ �Լ�
* \returns
* VALID_POLICY_DATA ����ü ������
*/
ISC_API VALID_POLICY_DATA *new_VALID_POLICY_DATA(void);

/*!
* \brief
* VALID_POLICY_DATA ����ü�� �޸� �Ҵ� �����ϴ� �Լ�
* \param data
* ������ ����ü
* \remarks
* ����ü�� ����(ISC_MEM_FREE)
*/
ISC_API void free_VALID_POLICY_DATA(VALID_POLICY_DATA *data);

/*!
* \brief
* VALID_POLICY_NODE ����ü�� �ʱ�ȭ �Լ�
* \returns
* VALID_POLICY_NODE ����ü ������
*/
ISC_API VALID_POLICY_NODE *new_VALID_POLICY_NODE(void);

/*!
* \brief
* VALID_POLICY_NODE ����ü�� �޸� �Ҵ� �����ϴ� �Լ�
* \param vpn
* ������ ����ü
* \remarks
* ����ü�� ����(ISC_MEM_FREE)
*/
ISC_API void free_VALID_POLICY_NODE(VALID_POLICY_NODE *vpn);

/*!
* \brief
* VALID_POLICY_NODES ����ü�� �ʱ�ȭ �Լ�
* \returns
* VALID_POLICY_NODES ����ü ������
*/
ISC_API VALID_POLICY_NODES *new_VALID_POLICY_NODES(void);

/*!
* \brief
* VALID_POLICY_NODES ����ü�� �޸� �Ҵ� �����ϴ� �Լ�
* \param nodes
* ������ ����ü
* \remarks
* ����ü�� ����(ISC_MEM_FREE)
*/
ISC_API void free_VALID_POLICY_NODES(VALID_POLICY_NODES *nodes);

/*!
* \brief
* node_LIST ����ü�� VALID_POLICY_TREE_LIST �߰��ϴ� �Լ�
* \returns
* ����/����
*/
ISC_API ISC_STATUS add_VALID_POLICY_TREE_LIST(node_LIST *vptlist, VALID_POLICY_NODES *vpns);

/*!
* \brief
* ����������� self signed�ΰ��� �˻��ϴ� �Լ�
* \returns
* ����/����
*/

ISC_API ISC_STATUS is_selfSigned(X509_CERT *cert);

/*!
* \brief
* ����������� issuer_candidate �� cert �� �߱��� ���������� �˻��ϴ� �Լ�
* \returns
* ����/����
*/
ISC_API ISC_STATUS is_issuer(X509_CERT *issuer_candidate, X509_CERT *cert);
/*!
* \brief
* ����������� ������θ� �����ϴ� �Լ�
* \returns
* ����/����
*/
ISC_API ISC_STATUS build_certPath(X509_CERTS *certs, TRUST_ANCHORS *trusts, X509_CERT *cert, X509_CERTS **pathcert);

/*!
* \brief
* TRUST_ANCHOR ����ü�� �ʱ�ȭ �Լ�
* \returns
* TRUST_ANCHOR ����ü ������
*/
ISC_API TRUST_ANCHOR *new_TRUST_ANCHOR(void);

/*!
* \brief
* TRUST_ANCHOR ����ü�� �޸� �Ҵ� ����
* \param TRUST_ANCHOR
* ������ ����ü
* \remarks
* ����ü�� ����(ISC_MEM_FREE)
*/
ISC_API void free_TRUST_ANCHOR(TRUST_ANCHOR *unit);

/*!
* \brief
* TRUST_ANCHOR ����ü�� ����
* \param unit
* ������ ����ü
*/
ISC_API void clean_TRUST_ANCHOR(TRUST_ANCHOR *unit);

/*!
* \brief
* TRUST_ANCHOR ����ü�� Sequence�� Encode �Լ�
* \param ta
* TRUST_ANCHOR ����ü
* \param seq
* Encoding Sequence ����ü
* \returns
* -# ISC_SUCCESS : ����
* -# LOCATION^F_TRUST_ANCHOR_TO_SEQ^ISC_ERR_NULL_INPUT : Null_Input
* -# LOCATION^F_TRUST_ANCHOR_TO_SEQ^ERR_ASN1_ENCODING : ASN1 Err
* -# TRUST_ANCHOR_to_Seq()�� ���� �ڵ�\n
*/
ISC_API ISC_STATUS TRUST_ANCHOR_to_Seq (TRUST_ANCHOR *ta, SEQUENCE **seq);

/*!
* \brief
* Sequence�� TRUST_ANCHOR ����ü�� Decode �Լ�
* \param seq
* Decoding Sequece ����ü
* \param ta
* TRUST_ANCHOR ����ü
* \returns
* -# ISC_SUCCESS : ����
* -# LOCATION^F_SEQ_TO_TRUST_ANCHOR^ISC_ERR_NULL_INPUT : Null_Input
* -# LOCATION^F_SEQ_TO_TRUST_ANCHOR^ERR_ASN1_ENCODING : ASN1 Err
* -# Seq_to_TRUST_ANCHOR()�� ���� �ڵ�\n
*/
ISC_API ISC_STATUS Seq_to_TRUST_ANCHOR (SEQUENCE *seq, TRUST_ANCHOR** ta);

/*!
* \brief
* TRUST_ANCHOR�� �����ϴ� ���
* \param ������ ���� TRUST_ANCHOR* pkey
* \return ����� TRUST_ANCHOR* 
*/
ISC_API TRUST_ANCHOR * dup_TRUST_ANCHOR(TRUST_ANCHOR *src);

/*!
* \brief
* TRUST_ANCHORS ������ �ʱ�ȭ �Լ�
* \returns
* TRUST_ANCHORS ���� ������
*/
ISC_API TRUST_ANCHORS *new_TRUST_ANCHORS(void);

/*!
* \brief
* TRUST_ANCHORS ����ü�� �޸� �Ҵ� ����
* \param TRUST_ANCHORS
* ������ ����ü
* \remarks
* ����ü�� ����(ISC_MEM_FREE)
*/
ISC_API void free_TRUST_ANCHORS(TRUST_ANCHORS *unit);

/*!
* \brief
* TRUST_ANCHORS ���ÿ� TRUST_ANCHOR�� �߰�
* \param trustanchors
* TRUST_ANCHORS ���� ������
* \param trustanchor
* �߰��� TRUST_ANCHOR ����ü ������
* \return
* -# ISC_SUCCESS : ����
* -# ISC_FAIL : ����
*/
ISC_API ISC_STATUS add_TRUST_ANCHORS(TRUST_ANCHORS *trustanchors, TRUST_ANCHOR *trustanchor);

/*!
* \brief
* TRUST_ANCHORS ���ÿ��� X509_CERT�� ��ġ�ϴ� �ε����� �˻�
* \param tas
* TRUST_ANCHORS ���� ������
* \param ta
* TRUST_ANCHOR ����ü ������
* \return
* -# ta�� ��ġ�ϴ� �ε���
* -# ta�� ��ġ�ϴ� �ε����� ������� -1
*/
ISC_API int get_TRUST_ANCHORS_index_by_TRUST_ANCHOR(TRUST_ANCHORS *tas, TRUST_ANCHOR *ta);

/*!
* \brief
* MAX_CERTIFICATEPATH_LENGTH�� �����ϴ� ���
* \param ������ MAX_CERTIFICATEPATH_LENGTH length
* \returns
* -# ISC_SUCCESS : ����
* -# ISC_FAIL : ����
*/
ISC_API ISC_STATUS set_max_certificatePath_length(int length);


/*!
* \brief
* MAX_CERTIFICATEPATH_LENGTH�� ���ϴ� ���
* \returns
* -# int : MAX_CERTIFICATEPATH_LENGTH
*/
ISC_API int get_max_certificatePath_length(void);

/*!
* \brief
* initial_policy_mapping_inhibit�� �����ϴ� ���
* \param ������ initial_policy_mapping_inhibit ��뿩��(TRUE/FALSE)
* \returns
* -# ����
*/
ISC_API void set_initial_policy_mapping_inhibit(int flag);

/*!
* \brief
* initial_policy_mapping_inhibit�� ���ϴ� ���
* �ʱ���å ���α������� 
* ���� ���� ����������� CA���������� ��å���� Ȯ���ʵ� ����.
* \returns
* -# bool : �ʱ���å ���α��� ���� (�׻� FALSE)
*/
ISC_API int get_initial_policy_mapping_inhibit(void);

/*!
* \brief
* initial_explicit_policy�� �����ϴ� ���
* \param ������ initial_explicit_policy ��뿩��(TRUE/FALSE)
* \returns
* -# ����
*/
ISC_API void set_initial_explicit_policy(int flag);

/*!
* \brief
* initial_explicit_policy�� ���ϴ� ���
* �ʱ� ��� ��å ����
* ����� �ʱ���å ���հ� ��ȿ��åƮ���� ������ ����.
* \returns
* -# bool : �ʱ� ��� ��å ����(�⺻�� TURE)
*/
ISC_API int get_initial_explicit_policy(void);

/*!
* \brief
* initial_any_policy_inhibit�� �����ϴ� ���
* \param ������ initial_any_policy_inhibit ��뿩��(TRUE/FALSE)
* \returns
* -# ����
*/
ISC_API void set_initial_any_policy_inhibit(int flag);

/*!
* \brief
* initial_any_policy_inhibit�� ���ϴ� ���
* �ʱ� �����å���� ���� 
* anypolicy ��å�� ������� ����. TRUE�̸� anypolicy ���Ұ�
* \returns
* -# bool : �ʱ� �����å���� ���� (�⺻�� FALSE)
*/
ISC_API int get_initial_any_policy_inhibit(void);

/*!
* \brief
* �ش� ��������� ��ȿ���� �����ϴ� ���
* \param ��� �������
* \returns
* -# ISC_SUCCESS : ����
* -# ISC_FAIL : ����
*/
ISC_API ISC_STATUS validate_certpath(X509_CERTS *certpathlist, OBJECT_IDENTIFIERS *user_policies, node_LIST **valid_policy_tree);

/*!
* \brief
* VALID_POLICY_TREE_LIST����ü�� �������� ������ ���
* \param list
* VALID_POLICY_TREE_LIST ����ü
*/
ISC_API void print_VALID_POLICY_TREE_LIST(node_LIST *list);

/*!
* \brief
* �ش� ������ �ŷڸ���� ��ȿ���� �����ϴ� ���
* \param ������ �ŷڸ�� (pkcs7 's SignedData)
* \returns
* -# ISC_SUCCESS : ����
* -# ISC_FAIL : ����
*/
ISC_API ISC_STATUS verify_ctlSignedData(P7_CONTENT_INFO *p7);

/*!
* \brief
* TRUST_ANCHORS ���ÿ� TRUST_ANCHOR�� �߰�
* \param ta
* TRUST_ANCHORS ���� ������
* \param p7
* �߰��� CTL ����ü ������(PKCS7's SignedData)
* \return
* -# ISC_SUCCESS : ����
* -# ISC_FAIL : ����
*/
ISC_API ISC_STATUS add_TRUST_ANCHORS_from_CTL(TRUST_ANCHORS *ta, P7_CONTENT_INFO *p7);

/*!
* \brief
* X509_CERTS ���ÿ� CTL�� �������� �߰�
* \param certs
* P7_CONTENT_INFO ������
* \param p7
* �߰��� CTL ����ü ������(PKCS7's SignedData)
* \return
* -# ISC_SUCCESS : ����
* -# ISC_FAIL : ����
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

