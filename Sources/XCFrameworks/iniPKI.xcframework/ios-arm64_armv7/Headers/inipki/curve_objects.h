/*!
* \file curve_objects.h
* \brief ECC�� CURVE�� �ٷ�� ���� ���
* \remarks
* CURVE IDENTIFIER�� ���� CURVE�� ���� ���Ѵ�.
* \author
* Copyright (c) 2013 by \<INITech\>
*/

#ifndef HEADER_CURVE_OBJECT_H
#define HEADER_CURVE_OBJECT_H

#ifdef NO_PKI
#error PKI is disabled.
#endif

#include <inicrypto/foundation.h>
#include <inicrypto/ecurve.h>

#ifdef  __cplusplus
extern "C" {
#endif

/* 2017-09-11, SAFEDB ADD 
  * Crypt Module���� named curve (P-224 / P-256 / K-233 / K-283)��
  * �����ϱ� ������ ������ �Ķ���� ������ �ʿ����� �ʴ�.
  * ���� Crypto ��⿡�� �����ϸ� ����ϰ�, ����� fiedl_id , oid , curve name
  * ������ ó���ϵ��� �����Ѵ�.
  */
#if 0
/*!
* \brief
* �̸� ����� CURVE LIST�� ��� �ִ� ����ü
*/
typedef struct curve_list_structure
{
	int field_id;				/*!< field_id */
	int index;					/*!< curve oid index */
	char name[ISC_ECC_CURVE_NAME_LEN];	/*!< curve name */
	uint8 a[64];				/*!< a*/
	int aLen;					/*!< a len*/	
	uint8 b[64];				/*!< b*/
	int bLen;					/*!< b len*/
	uint8 prime[64];			/*!< prime*/
	int primeLen;				/*!< prime len*/
	uint8 gx[64];				/*!< gx*/
	int gxLen;					/*!< gx len*/
	uint8 gy[64];				/*!< gy*/
	int gyLen;					/*!< gy len*/
	uint8 order[64];			/*!< order*/
	int orderLen;				/*!< order len*/
} CURVE_LIST;

#define CURVE_LIST_SIZE 1
#else
/*!
* \brief
* �̸� ����� CURVE LIST�� ��� �ִ� ����ü
*/
typedef struct curve_list_structure
{
	int field_id;				/*!< field_id */
	int index;					/*!< curve oid index */
	char name[ISC_ECC_CURVE_NAME_LEN];	/*!< curve name */
} CURVE_LIST;

#define CURVE_LIST_SIZE 5
#endif

#ifndef WIN_INI_LOADLIBRARY_PKI

/*
* \brief
* �Էµ� curve_oid_index�� ��ġ�Ǵ� curve�� CURVE_LIST�� ã�� out�� ����.
* \param out
* curve�� ����� ISC_ECURVE ����ü ������ (�޸� �ڵ� �Ҵ�)
* \param curve_oid_index
* ã�� curve�� oid index
* \returns
* -# ISC_SUCCESS : Success
* -# ISC_FAIL : Fail
*/
ISC_API ISC_STATUS set_ECURVE_from_list(ISC_ECURVE **out, int curve_oid_index);

/*
* \brief
* �Էµ� curve_oid�� ��ġ�Ǵ� curve�� CURVE_LIST�� ã�� out�� ����.
* \param out
* curve�� ����� ISC_ECURVE ����ü ������ (�޸� �ڵ� �Ҵ�)
* \param oid
* ã�� curve�� oid
* \returns
* -# ISC_SUCCESS : Success
* -# ISC_FAIL : Fail
*/
ISC_API ISC_STATUS set_ECURVE_from_list_ex(ISC_ECURVE **out, OBJECT_IDENTIFIER *oid);

/*
* \brief
* �Էµ� curve name�� ��ġ�Ǵ� curve�� OBJECT_IDENTIFIER�� CURVE_LIST���� ã�� out�� ����
* \param out
* curve�� OBJECT_IDENTIFIER ����� ����ü ������ (�޸� �ڵ� �Ҵ�)
* \param name
* curve�� �̸�
* \returns
* -# ISC_SUCCESS : Success
* -# ISC_FAIL : Fail
*/
ISC_API ISC_STATUS get_ECURVE_OID_from_name(OBJECT_IDENTIFIER **out, char *name);

/*
 * \brief
 * �Էµ� curve id�� ��Ī�Ǵ� curve name�� �����Ѵ�.
 * \param name
 * ��°� - curve�� �̸�
 * \param curve_id
 * �Է°� - curve�� ID (ISC_ECC_P_224 ��)
 * \returns
 * -# ISC_SUCCESS : Success
 * -# ISC_FAIL : Fail
 */
ISC_API ISC_STATUS get_ECURVE_Name_from_Curve_ID(char *name, int curve_id);
  
/*
* \brief
* �Էµ� curve name�� ��Ī�Ǵ� curve id�� �����Ѵ�.
* \param curve_id
* ��°� - curve�� ID (ISC_ECC_P_224 ��)
* \param name
* �Է°� - curve�� �̸� (secp224r1, secp256r1 ��)
* \returns
* -# ISC_SUCCESS : Success
* -# ISC_FAIL : Fail
*/
ISC_API ISC_STATUS get_ECURVE_ID_from_Curve_Name(int *curve_id, char *name);

#else

#include "foundation_pki.h"

INI_RET_LOADLIB_PKI(ISC_STATUS, set_ECURVE_from_list, (ISC_ECURVE **out, int curve_oid_index), (out, curve_oid_index), ERR_GET_ADRESS_LOADLIBRARY);
INI_RET_LOADLIB_PKI(ISC_STATUS, get_ECURVE_OID_from_name, (OBJECT_IDENTIFIER **out, char *name), (out, name), ERR_GET_ADRESS_LOADLIBRARY);
INI_RET_LOADLIB_PKI(ISC_STATUS, get_ECURVE_Name_from_Curve_ID, (char *name, int curve_id), (name, curve_id), ERR_GET_ADRESS_LOADLIBRARY);
INI_RET_LOADLIB_PKI(ISC_STATUS, get_ECURVE_ID_from_Curve_Name, (int *curve_id, char *name), (curve_id, name), ERR_GET_ADRESS_LOADLIBRARY);

#endif /* #ifndef WIN_INI_LOADLIBRARY_PKI  */

#ifdef  __cplusplus
}
#endif

#endif /* HEADER_CURVE_OBJECT_H */
