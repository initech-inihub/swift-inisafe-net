/*!
* \file prng.h
* \brief PRNG; Pseudo Random Number Generator
* \remarks
* NIST FIPS PUB186-2 Appendix 3.1 & 3.2 문서를 기준으로 작성 되었음.
* \author
* Copyright (c) 2008 by \<INITech\>
*/

#ifndef HEADER_PRNG_H
#define HEADER_PRNG_H

#include "foundation.h"
#include "mem.h"

#ifdef ISC_NO_PRNG
#error PRNG is disabled.
#endif

#ifndef ISC_NO_BIGINT
#include "biginteger.h"
#endif

#ifdef  __cplusplus
extern "C" {
#endif

#define ISC_ENTROPY_NEEDED 64
#define ISC_DEVRANDOM "/dev/urandom","/dev/random","/dev/srandom"

#define ISC_PRNG_PROVEN_MODE  0    /*!<  0: 비검증 모드, 1: 검증모드 */
/*---------------------------------------------------------------------------------*/

/*!
* \brief
* PRNG에서 쓰이는 정보를 담고 있는 구조체
* \remarks
* G Function의 종류에 따라
* 해쉬함수 계열은 digestState에 State 정보를 저장하고
* 블록암호 계열은 cipherKey에 키 값을 저장한다.
*/
struct isc_prng_unit_st {
	ISC_BIGINT *XKEY;           /*!< ISC_BIGINT XKEY의 포인터*/
	ISC_BIGINT *XSEED;          /*!< ISC_BIGINT XSEED의 포인터*/
	int GFuncID;            /*!< G_Function 알고리즘 ID*/
	union {
		void *digestState;  /*!< 해쉬 계열 G_Function의 STATE 포인터*/
		void *cipherKey;    /*!< 블록 암호 계열 G_Function의 키 포인터*/
	} GFuncINFO;
	int GFuncINFOLen;		/*!< G_Function정보의 길이*/
	int unit_status;
	ISC_BIGINT_POOL *pool;		/*!< 연산 효출을 위한 ISC_BIGINT_POOL*/
	int isgenpool;			/*!< ISC_BIGINT_POOL 자체 생성 여부*/
};

#ifndef ISC_WIN_LOADLIBRARY_CRYPTO

/*!
* \brief
* ISC_New_PRNG_Unit(), ISC_Init_PRNG(), ISC_Get_Rand()를 한 번에 하는 함수
* \param rand
* 생성된 랜덤 값을 저장하기 위한 배열의 포인터
* \param length
* 생성하길 원하는 랜덤 값의 길이(Byte)
* \returns
* -# ISC_SUCCESS : Success
* -# ISC_Crypto_Initialize()의 에러코드
-. LOCATION^ISC_F_RAND_BYTES^ISC_ERR_MEM_ALLOC : 동적 메모리 할당 실패
-. LOCATION^ISC_F_RAND_BYTES^ISC_ERR_INIT_PRNG_FAIL : INT PRNG 실패
-. LOCATION^ISC_F_RAND_BYTES^ISC_ERR_GET_RAND_FAIL : : GET RAND 실패
*/
ISC_API ISC_STATUS ISC_Rand_Bytes_PRNG(uint8 *rand, int length);

/*!
* \brief
* ISC_PRNG_UNIT 생성 함수
* \returns
* 생성된 ISC_PRNG_UNIT의 포인터
*/
ISC_API ISC_PRNG_UNIT *ISC_New_PRNG_Unit(void);

/*!
* \brief
* ISC_PRNG_UNIT의 값 초기화 함수
* \param unit
* ISC_PRNG_UNIT 구조체의 포인터
*/
ISC_API void ISC_Clean_PRNG_Unit(ISC_PRNG_UNIT *unit);

/*!
* \brief
* ISC_PRNG_UNIT 삭제 함수
* \param unit
* ISC_PRNG_UNIT 구조체의 포인터
*/
ISC_API void ISC_Free_PRNG_Unit(ISC_PRNG_UNIT *unit);


/*!
* \brief
* PRNG 초기화 함수
* \param unit
* ISC_PRNG_UNIT 구조체의 포인터
* \param alg_id
* G Function에 쓰일 알고리즘 ID
* \param XKEYbin
* XKEY의 값을 담고 있는 배열의 포인터,
* XKEY는 ISC_SEED-Key 값으로 임의의 비밀 값이며 160~512bit의 길이를 갖는다.
* \param XKEY_SIZE
* XKEY의 길이
* \param XSEEDbin
* XSEED의 값을 담고 있는 배열의 포인터,
* XSEED는 사용자가 선택적으로 입력하는 임의의 값이다.
* \param XSEED_SIZE
* XSEED의 길이
* \param pool
* 연산 효율을 위한 ISC_BIGINT_POOL (NULL 입력시 내부 생성)
* \returns
* -# ISC_SUCCESS : Success
* -# ISC_Crypto_Initialize()의 에러코드
* -# ISC_L_PRNG^ISC_F_INIT_PRNG^ISC_ERR_NULL_INPUT : 입력값을 NULL로 입력
* -# ISC_L_PRNG^ISC_F_INIT_PRNG^ISC_ERR_NOT_PROVEN_ALGORITHM : 검증모드에서 지원하지 않는 알고리즘
* -# ISC_L_PRNG^ISC_F_INIT_PRNG^ISC_ERR_INIT_FAILURE : 초기화 실패
* -# ISC_L_PRNG^ISC_F_INIT_PRNG^ISC_ERR_MEM_ALLOC : 동적 메모리 할당 실패
* -# ISC_L_PRNG^ISC_F_INIT_PRNG^ISC_ERR_DIGEST_FAIL : DIGEST 함수 실패
*/
ISC_API ISC_STATUS ISC_Init_PRNG(ISC_PRNG_UNIT *unit, int alg_id, const uint8 *XKEYbin, int XKEY_SIZE, const uint8 *XSEEDbin, int XSEED_SIZE, ISC_BIGINT_POOL *pool);

/*!
* \brief
* 랜덤한 수를 uint8 배열 형식으로 얻기 위한 함수,
* NIST FIPS PUB186-2 Appendix 3.1 & 3.2 문서를 기준으로 작성 되었음.
* 문서는 ISC_DSA에서 쓰이는 랜덤 x(0<x<q)값을 구하기 위한 알고리즘으로
* 일반적인 랜덤 값을 얻을 때에는 mod q 연산이 불필요하기 때문에 mod q연산은 하지 않았음.
* \param unit
* ISC_PRNG_UNIT 구조체의 포인터
* \param output
* 랜덤 값을 저장하기 위한 uint8 배열의 포인터
* \param length
* 원하는 랜덤 값의 길이(Byte)
* \returns
* -# ISC_SUCCESS : Success
* -# ISC_Crypto_Initialize()의 에러코드
* -# ISC_L_PRNG^ISC_F_GET_RAND^ISC_ERR_NULL_INPUT : 입력값을 NULL로 입력
* -# ISC_L_PRNG^ISC_F_GET_RAND^ISC_ERR_MEM_ALLOC : 동적 메모리 할당 실패
* -# ISC_L_PRNG^ISC_F_GET_RAND^ISC_ERR_RANDOM_GEN_FAILURE : 난수 생성 실패
* -# ISC_L_PRNG^ISC_F_GET_RAND^ISC_ERR_ENTROPY_FAIL : 엔트로피 실패
*/
ISC_API ISC_STATUS ISC_Get_Rand(ISC_PRNG_UNIT *unit, uint8 *output, int length);

/*!
* \brief
* 랜덤한 수를 ISC_BIGINT 형식으로 얻기 위한 함수,
* NIST FIPS PUB186-2 Appendix 3.1 & 3.2 문서를 기준으로 작성 되었음.
* 문서는 ISC_DSA에서 쓰이는 랜덤 x(0<x<q)값을 구하기 위한 알고리즘으로
* 일반적인 랜덤 값을 얻을 때에는 mod q 연산이 불필요하기 때문에 mod q연산은 하지 않았음.
* \param unit
* ISC_PRNG_UNIT 구조체의 포인터
* \param output
* 랜덤 값을 저장하기 위한 ISC_BIGINT의 포인터
* \param bit_length
* 원하는 랜덤 값의 길이(bit)
* \returns
* -# ISC_Get_Rand()의 에러코드\n
* -# ISC_SUCCESS : Success\n
* -# ISC_Crypto_Initialize()의 에러코드
* -# ISC_L_PRNG^ISC_F_GET_RAND_BIGINT^ISC_ERR_NULL_INPUT : 입력값을 NULL로 입력
* -# ISC_L_PRNG^ISC_F_GET_RAND_BIGINT^ISC_ERR_GET_RAND_FAIL : 난수 생성 실패
* -# ISC_L_PRNG^ISC_F_GET_RAND_BIGINT^ISC_ERR_BINARY_TO_BIGINT_FAIL : BINARY TO BIGINT 실패
*/
ISC_API ISC_STATUS ISC_Get_Rand_BIGINT(ISC_PRNG_UNIT *unit, ISC_BIGINT *output, int bit_length);

/*!
* \brief
* ISC_DSA의 표준(NIST FIPS PUB 186-2 Appendix 3.1 & 3.2)에 맞는 랜덤 x(0<x<q)를 ISC_BIGINT 형식으로 얻기 위한 함수
* \param unit
* ISC_PRNG_UNIT 구조체의 포인터
* \param output
* 랜덤 값을 저장하기 위한 ISC_BIGINT의 포인터
* \param q
* 랜덤 값의 범위를 결정하는 prime(mod q 연산을 통해 랜덤 값의 범위 결정) q의 포인터
* \returns
* -# ISC_SUCCESS : Success
* -# ISC_Crypto_Initialize()의 에러코드
* -# ISC_L_PRNG^ISC_F_GET_INNER_RAND^ISC_ERR_NULL_INPUT : 입력값을 NULL로 입력
* -# ISC_L_PRNG^ISC_F_GET_INNER_RAND^ISC_ERR_START_BIGINT_POOL_FAIL : START_BIGINT_POOL 실패
* -# ISC_L_PRNG^ISC_F_GET_INNER_RAND^ISC_ERR_MEM_ALLOC : 동적 메모리 할당 실패
* -# ISC_L_PRNG^ISC_F_GET_INNER_RAND^ISC_ERR_BINARY_TO_BIGINT_FAIL : BINARY TO BIGINT 실패
* -# ISC_L_PRNG^ISC_F_GET_RAND^ISC_ERR_NULL_XKEY_VALUE : XKEY값이 NULL일 경우 실패
*/
ISC_API ISC_STATUS ISC_Get_Rand_DSA_BIGINT(ISC_PRNG_UNIT *unit, ISC_BIGINT *output, ISC_BIGINT *q);

/*!
* \brief
* ISC_SEED 엔트로피 생성
*      : 현재시간 + 현재 프로세스 + rand + 시스템정보(CPU, DISK, Network)  
*/
ISC_INTERNAL void isc_SEED_Poll();


/*!
* \brief
* ISC_SEED 엔트로피 생성 (비검증모드 - Fast)
*      : 현재 시간 + rand + 현재 프로세스 ID
*/
ISC_INTERNAL void isc_SEED_Poll_Fast();

/*!
* \brief
* ISC_SEED 에 엔트로피를 추가한다.
* \param buf
* 추가할 엔트로피 배열의 포인터
* \param num
* 추가할 엔트로피 배열의 포인터 길이
* \param add
* 추가할 엔트로피 길이 (총 추가된 량이 ISC_ENTROPY_NEEDED 보다 커야 한다)
*/
ISC_INTERNAL void SEED_add(const void *buf, int num, double add);

#else /* ISC_WIN_LOADLIBRARY_CRYPTO */

ISC_RET_LOADLIB_CRYPTO(ISC_STATUS, ISC_Rand_Bytes_PRNG, (uint8 *rand, int length), (rand, length), ISC_ERR_GET_ADRESS_LOADLIBRARY );

#endif /* ISC_WIN_LOADLIBRARY_CRYPTO */

#ifdef  __cplusplus
}
#endif
#endif /* HEADER_PRNG_H */

