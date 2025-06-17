/*!
* \file ecdh.h
* \brief ecdh 헤더파일
* \author
* Copyright (c) 2013 by \<INITech\>
*/

#ifndef HEADER_ECDH_H
#define HEADER_ECDH_H

#include "biginteger.h"
#include "foundation.h"
#include "ecc.h"

#ifdef ISC_NO_HAS160
#define ISC_NO_ECDH
#endif

#ifdef ISC_NO_ECDH
#error ISC_ECDH is disabled.
#endif

#define ISC_ECDH_PROVEN_MODE  0    /*!<  0: 비검증 모드, 1: 검증모드 */

/*ISC_ECDH Alias				0x80000000 ------------------------------------------------ */
#define ISC_ECDH				0x80000000   /*!< ISC_ECDH 알고리즘 ID */

#ifdef  __cplusplus
extern "C" {
#endif

/*!
* \brief
* ISC_ECDH 알고리즘을 위한 구조체
*/
struct isc_ecdh_st {
	ISC_ECC_KEY_UNIT *key;			/*!< ECC 키쌍 및 커브 */
	ISC_BIGINT_POOL *pool;			/*!< 연산 효율을 위한 풀 */
	
	/* KCMVP TEST 용도 정식 릴리즈에서는 사용되지 않음*/
	ISC_ECPOINT *kab;				/*!< 공유키 */
};

#ifndef ISC_WIN_LOADLIBRARY_CRYPTO

/*!
* \brief
* ISC_ECDH_UNIT 구조체의 메모리 할당
* \returns
* ISC_ECDH_UNIT 구조체
*/
ISC_API ISC_ECDH_UNIT* ISC_New_ECDH(void);

/*!
* \brief
* ISC_ECDH_UNIT 메모리 해제 함수
* \param ecdh
* 메모리 해제할 ISC_ECDH_UNIT
*/
ISC_API void ISC_Free_ECDH(ISC_ECDH_UNIT* unit);

/*!
* \brief
* ISC_ECDH_UNIT 메모리 초기화 함수
* \param ecdh
* 초기화 할 ISC_ECDH_UNIT
*/
ISC_API void ISC_Clean_ECDH(ISC_ECDH_UNIT *unit);

/*!
* \brief
* ECDH Parameter를 입력된 파라메터로 초기화 한다.
* \param ecdh
* Parameter가 저장될 ISC_ECDH_UNIT
* \param field_id
* 입력값 curve id
* \param ra
* 자신의 개인키
* \param kta
* 자신의 공개키
* \returns
* -# ISC_SUCCESS : Success
* -# LOCATION^ISC_F_SET_ECDH_PARAMS_Ex^ISC_ERR_NULL_INPUT : NULL값 입력
* -# LOCATION^ISC_F_SET_ECDH_PARAMS_Ex^ISC_ERR_MEM_ALLOC : 메모리 할당 실패
* -# LOCATION^ISC_F_SET_ECDH_PARAMS_Ex^ISC_ERR_SET_ECC_KEY_PARAMS_EX : 커브값 설정 실패
* -# LOCATION^ISC_F_SET_ECDH_PARAMS_Ex^ISC_ERR_COPY_BIGINT_FAIL : COPY_BIGINT 실패
*/
ISC_API ISC_STATUS ISC_Set_ECDH_Params(ISC_ECDH_UNIT *unit, int field_id, ISC_BIGINT *ra, ISC_ECPOINT *kta);

/*!
* \brief
* ECDH Parameter를 입력된 파라메터로 초기화 한다.
* \param ecdh
* Parameter가 저장될 ISC_ECDH__UNIT
* \param curve
* 입력값 curve
* \param ra
* 자신의 개인키
* \param kta
* 자신의 공개키
* \returns
* -# ISC_SUCCESS : Success
* -# LOCATION^ISC_F_SET_ECDH_PARAMS^ISC_ERR_NULL_INPUT : NULL값 입력
* -# LOCATION^ISC_F_SET_ECDH_PARAMS^ISC_ERR_MEM_ALLOC : 메모리 할당 실패
* -# LOCATION^ISC_F_SET_ECDH_PARAMS^ISC_ERR_SUB_OPERATION_FAILURE : 커브값 설정 실패
* -# LOCATION^ISC_F_SET_ECDH_PARAMS^ISC_ERR_COPY_BIGINT_FAIL : COPY_BIGINT 실패
*/
ISC_API ISC_STATUS ISC_Set_ECDH_Params_Ex(ISC_ECDH_UNIT *unit, ISC_ECURVE *curve, ISC_BIGINT *ra, ISC_ECPOINT *kta);							

/*!
* \brief
* 공개키, 개인키 키쌍을 생성
* \param key
* ISC_ECC_KEY_UNIT 구조체 포인터로 curve값 세팅이 되었어야 한다. 성공 시 키쌍을 저장한다.
* -# ISC_SUCCESS : Success
* -# ISC_Crypto_Initialize()의 에러코드
* -# ISC_L_ECDH^ISC_F_GENERATE_ECDH_KEY_PAIR^ISC_ERR_NULL_INPUT : NULL값 입력          
* -# ISC_L_ECDH^ ISC_F_GENERATE_ECDH_KEY_PAIR^ISC_ERR_NOT_SUPPORTED_CURVE_TYPE : 지원하
* -# ISC_L_ECDH^ISC_F_GENERATE_ECDH_KEY_PAIR^ISC_ERR_GENERATE_KEY_PAIR : 키쌍 생성 실패
*/
ISC_API ISC_STATUS ISC_Generate_ECDH_Key_Pair(ISC_ECDH_UNIT *unit);

/*!
* \brief
* 입력받은 ISC_ECDH_UNIT의 자신의 비밀키 ra, 상대방의 공개키 ktb를 이용해 공유키 kab를 생성한다. kab = ktb^ra mod p
* \param key
* 리턴할 uint8형의 공유키값
* \param key_len
* 리턴할 uint8형의 공유키값 길이
* \param ecdh
* 공유키를 만들기 위한 파라메터 값
* \returns
* -# ISC_SUCCESS : Success
* -# ISC_Crypto_Initialize()의 에러코드
* -# ISC_L_ECDH^ISC_F_COMPUTE_ECDH_KEY^ISC_ERR_NULL_INPUT : NULL값 입력
* -# ISC_L_ECDH^ISC_F_COMPUTE_ECDH_KEY^ISC_ERR_MEM_ALLOC : 메모리 할당 실패
* -# ISC_L_ECDH^ISC_F_COMPUTE_ECDH_KEY^ISC_ERR_NOT_SUPPORTED_CURVE_TYPE : 지원하지 않는 커브값 입력
* -# ISC_L_ECDH^ISC_F_COMPUTE_ECDH_KEY^ISC_ERR_MTP_BIGINT_FAIL : MTP_BIGINT 실패
* -# ISC_L_ECDH^ISC_F_COMPUTE_ECDH_KEY^ISC_ERR_MTP_ECC_MONT_FAIL : _MTP_ECC_MONT 실패
*/
ISC_API ISC_STATUS ISC_Compute_ECDH_Key(ISC_ECDH_UNIT *unit, ISC_ECPOINT *pub_key, uint8 *out, int *out_len);


#else

ISC_RET_LOADLIB_CRYPTO(ISC_ECDH_UNIT*, ISC_New_ECDH, (void), (), NULL );
ISC_VOID_LOADLIB_CRYPTO(void, ISC_Free_ECDH, (ISC_ECDH_UNIT* unit), (unit) );
ISC_VOID_LOADLIB_CRYPTO(void, ISC_Clean_ECDH, (ISC_ECDH_UNIT* unit), (unit) );
ISC_RET_LOADLIB_CRYPTO(ISC_STATUS, ISC_Set_ECDH_Params, (ISC_ECDH_UNIT *unit, int field_id, ISC_BIGINT *ra, ISC_ECPOINT *kta), (unit,field_id,ra,kta), ISC_ERR_GET_ADRESS_LOADLIBRARY);
ISC_RET_LOADLIB_CRYPTO(ISC_STATUS, ISC_Set_ECDH_Params_Ex, (ISC_ECDH_UNIT *unit,ISC_ECURVE *curve,ISC_BIGINT *ra,ISC_ECPOINT *kta,ISC_ECPOINT *ktb,ISC_ECPOINT *kab), (unit,curve,ra,kta,ktb,kab), ISC_ERR_GET_ADRESS_LOADLIBRARY);
ISC_RET_LOADLIB_CRYPTO(ISC_STATUS, ISC_Generate_ECDH_Key_Pair, (ISC_ECDH_UNIT *unit), (unit), ISC_ERR_GET_ADRESS_LOADLIBRARY );
ISC_RET_LOADLIB_CRYPTO(ISC_STATUS, ISC_Compute_Key, (ISC_ECDH_UNIT *unit, ISC_ECPOINT *pub_key, uint8 *out, int *out_len), (unit, pub_key, out, out_len), ISC_ERR_GET_ADRESS_LOADLIBRARY );

#endif

#ifdef  __cplusplus
}
#endif

#endif


