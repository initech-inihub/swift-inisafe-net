/*!
* \file curve_objects.h
* \brief ECC의 CURVE를 다루기 위한 헤더
* \remarks
* CURVE IDENTIFIER를 통해 CURVE의 값을 구한다.
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
  * Crypt Module에서 named curve (P-224 / P-256 / K-233 / K-283)만
  * 지원하기 함으로 도메인 파라미터 정보는 필요하지 않다.
  * 추후 Crypto 모듈에서 지원하면 사용하고, 현재는 fiedl_id , oid , curve name
  * 정보만 처리하도록 수정한다.
  */
#if 0
/*!
* \brief
* 미리 저장된 CURVE LIST를 담고 있는 구조체
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
* 미리 저장된 CURVE LIST를 담고 있는 구조체
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
* 입력된 curve_oid_index와 매치되는 curve를 CURVE_LIST에 찾아 out에 복사.
* \param out
* curve가 저장될 ISC_ECURVE 구조체 포인터 (메모리 자동 할당)
* \param curve_oid_index
* 찾을 curve의 oid index
* \returns
* -# ISC_SUCCESS : Success
* -# ISC_FAIL : Fail
*/
ISC_API ISC_STATUS set_ECURVE_from_list(ISC_ECURVE **out, int curve_oid_index);

/*
* \brief
* 입력된 curve_oid와 매치되는 curve를 CURVE_LIST에 찾아 out에 복사.
* \param out
* curve가 저장될 ISC_ECURVE 구조체 포인터 (메모리 자동 할당)
* \param oid
* 찾을 curve의 oid
* \returns
* -# ISC_SUCCESS : Success
* -# ISC_FAIL : Fail
*/
ISC_API ISC_STATUS set_ECURVE_from_list_ex(ISC_ECURVE **out, OBJECT_IDENTIFIER *oid);

/*
* \brief
* 입력된 curve name와 매치되는 curve의 OBJECT_IDENTIFIER를 CURVE_LIST에서 찾아 out에 복사
* \param out
* curve의 OBJECT_IDENTIFIER 저장될 구조체 포인터 (메모리 자동 할당)
* \param name
* curve의 이름
* \returns
* -# ISC_SUCCESS : Success
* -# ISC_FAIL : Fail
*/
ISC_API ISC_STATUS get_ECURVE_OID_from_name(OBJECT_IDENTIFIER **out, char *name);

/*
 * \brief
 * 입력된 curve id에 매칭되는 curve name를 리턴한다.
 * \param name
 * 출력값 - curve의 이름
 * \param curve_id
 * 입력값 - curve의 ID (ISC_ECC_P_224 등)
 * \returns
 * -# ISC_SUCCESS : Success
 * -# ISC_FAIL : Fail
 */
ISC_API ISC_STATUS get_ECURVE_Name_from_Curve_ID(char *name, int curve_id);
  
/*
* \brief
* 입력된 curve name에 매칭되는 curve id를 리턴한다.
* \param curve_id
* 출력값 - curve의 ID (ISC_ECC_P_224 등)
* \param name
* 입력값 - curve의 이름 (secp224r1, secp256r1 등)
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
