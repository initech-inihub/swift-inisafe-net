/*!
* \file lsh.h
* \brief LSH 알고리즘(256, 512) 헤더파일
* \author
* Copyright (c) 2021 by \<INITech\>
*/

#ifndef HEADER_LSH_H
#define HEADER_LSH_H

#ifdef ISC_NO_LSH
#error LSH is disabled.
#endif

#include "foundation.h"
#include "mem.h"
#include "utils.h"
#include "isc_endian.h"

/* LSH Constants */
#define ISC_LSH_TYPE_256_256				0x0000020
#define ISC_LSH_TYPE_256_224				0x000001C

#define ISC_LSH_TYPE_512_512				0x0010040
#define ISC_LSH_TYPE_512_384				0x0010030
#define ISC_LSH_TYPE_512_256				0x0010020
#define ISC_LSH_TYPE_512_224				0x001001C


/* LSH Constants */
#define ISC_LSH256_BLOCK_SIZE			128
/* #define LSH256_HASH_VAL_MAX_BYTE_LEN	32 */

#define ISC_LSH512_BLOCK_SIZE			256
/* #define LSH512_HASH_VAL_MAX_BYTE_LEN	64 */


/*----------------------------------------------------------------------------------------------------*/
#define ISC_LSH256_224_NAME					"LSH256_224"
#define ISC_LSH256_224_BLOCK_SIZE			ISC_LSH256_BLOCK_SIZE
#define ISC_LSH256_224_DIGEST_LENGTH		ISC_LSH_TYPE_256_224
#define ISC_LSH256_224_INIT					isc_Init_LSH256_224
#define ISC_LSH256_224_UPDATE				isc_Update_LSH256_224
#define ISC_LSH256_224_FINAL				isc_Final_LSH256_224
#define ISC_LSH256_224_STATE_SIZE			sizeof(ISC_LSH256_STATE)
/*----------------------------------------------------------------------------------------------------*/
/*----------------------------------------------------------------------------------------------------*/
#define ISC_LSH256_256_NAME					"LSH256_256"
#define ISC_LSH256_256_BLOCK_SIZE			ISC_LSH256_BLOCK_SIZE
#define ISC_LSH256_256_DIGEST_LENGTH		ISC_LSH_TYPE_256_256
#define ISC_LSH256_256_INIT					isc_Init_LSH256_256
#define ISC_LSH256_256_UPDATE				isc_Update_LSH256_256
#define ISC_LSH256_256_FINAL				isc_Final_LSH256_256
#define ISC_LSH256_256_STATE_SIZE			sizeof(ISC_LSH256_STATE)
/*----------------------------------------------------------------------------------------------------*/

/*----------------------------------------------------------------------------------------------------*/
#define ISC_LSH512_224_NAME					"LSH512_224"
#define ISC_LSH512_224_BLOCK_SIZE			ISC_LSH512_BLOCK_SIZE
#define ISC_LSH512_224_DIGEST_LENGTH		(ISC_LSH_TYPE_512_224 & 0xffff)
#define ISC_LSH512_224_INIT					isc_Init_LSH512_224
#define ISC_LSH512_224_UPDATE				isc_Update_LSH512_224
#define ISC_LSH512_224_FINAL				isc_Final_LSH512_224
#define ISC_LSH512_224_STATE_SIZE			sizeof(ISC_LSH512_STATE)
/*----------------------------------------------------------------------------------------------------*/
/*----------------------------------------------------------------------------------------------------*/
#define ISC_LSH512_256_NAME					"LSH512_256"
#define ISC_LSH512_256_BLOCK_SIZE			ISC_LSH512_BLOCK_SIZE
#define ISC_LSH512_256_DIGEST_LENGTH		(ISC_LSH_TYPE_512_256 & 0xffff)
#define ISC_LSH512_256_INIT					isc_Init_LSH512_256
#define ISC_LSH512_256_UPDATE				isc_Update_LSH512_256
#define ISC_LSH512_256_FINAL				isc_Final_LSH512_256
#define ISC_LSH512_256_STATE_SIZE			sizeof(ISC_LSH512_STATE)
/*----------------------------------------------------------------------------------------------------*/
/*----------------------------------------------------------------------------------------------------*/
#define ISC_LSH512_384_NAME					"LSH512_384"
#define ISC_LSH512_384_BLOCK_SIZE			ISC_LSH512_BLOCK_SIZE
#define ISC_LSH512_384_DIGEST_LENGTH		(ISC_LSH_TYPE_512_384 & 0xffff)
#define ISC_LSH512_384_INIT					isc_Init_LSH512_384
#define ISC_LSH512_384_UPDATE				isc_Update_LSH512_384
#define ISC_LSH512_384_FINAL				isc_Final_LSH512_384
#define ISC_LSH512_384_STATE_SIZE			sizeof(ISC_LSH512_STATE)
/*----------------------------------------------------------------------------------------------------*/
/*----------------------------------------------------------------------------------------------------*/
#define ISC_LSH512_512_NAME					"LSH512_512"
#define ISC_LSH512_512_BLOCK_SIZE			ISC_LSH512_BLOCK_SIZE
#define ISC_LSH512_512_DIGEST_LENGTH		(ISC_LSH_TYPE_512_512 & 0xffff)
#define ISC_LSH512_512_INIT					isc_Init_LSH512_512
#define ISC_LSH512_512_UPDATE				isc_Update_LSH512_512
#define ISC_LSH512_512_FINAL				isc_Final_LSH512_512
#define ISC_LSH512_512_STATE_SIZE			sizeof(ISC_LSH512_STATE)
/*----------------------------------------------------------------------------------------------------*/

#ifdef __cplusplus
extern "C" {
#endif

	/*!
	* \brief
	* ISC_LSH256_224, ISC_LSH256_256에서 쓰이는 정보를 담고 있는 구조체
	*/
	typedef struct isc_lsh256_state_st {
		uint32_t algtype;
		uint32_t remain_databitlen;
		uint32_t cv_l[8];
		uint32_t cv_r[8];
		uint8_t last_block[ISC_LSH256_BLOCK_SIZE];
	} ISC_LSH256_STATE;


	/*!
	* \brief
	* ISC_LSH512_224, ISC_LSH512_256, ISC_LSH512_384, ISC_LSH512_512에서 쓰이는 정보를 담고 있는 구조체
	*/
	typedef struct isc_lsh512_state_st {
		uint32_t algtype;
		uint32_t remain_databitlen;
		uint64_t cv_l[8];
		uint64_t cv_r[8];
		uint8_t last_block[ISC_LSH512_BLOCK_SIZE];
	} ISC_LSH512_STATE;

	/*!
	* \brief
	* ISC_LSH256_224 초기화 함수
	* \param state
	* ISC_LSH256_STATE 구조체의 포인터
	* \returns
	* -# ISC_SUCCESS : Success
	* -# LOCATION^ISC_F_INIT_LSH256_224^ISC_ERR_NULL_INPUT : 초기 입력값이 NULL임
	* -# ISC_Crypto_Initialize()의 에러코드
	*/
    ISC_INTERNAL ISC_STATUS isc_Init_LSH256_224(void *state);

	/*!
	* \brief
	* ISC_LSH256_224 업데이트 함수
	* \param state
	* ISC_LSH256_STATE 구조체의 포인터
	* \param data
	* 해쉬를 할 메시지의 포인터
	* \param count
	* 해쉬를 할 메시지의 길이
	* \returns
	* -# ISC_SUCCESS : Success
	* -# LOCATION^ISC_F_UPDATE_LSH256_224^ISC_ERR_NULL_INPUT : 초기 입력값이 NULL임
	*/
    ISC_INTERNAL ISC_STATUS isc_Update_LSH256_224(void *state, const uint8 *data, uint32 count);

	/*!
	* \brief
	* ISC_LSH256_224 파이널 함수
	* \param state
	* ISC_LSH256_STATE 구조체의 포인터
	* \param md
	* 해쉬의 결과를 저장할 버퍼의 포인터
	* \returns
	* -# ISC_SUCCESS : Success
	* -#  LOCATION^ISC_F_FINAL_LSH256_224^ISC_ERR_NULL_INPUT : 초기 입력값이 NULL임
	*/
    ISC_INTERNAL ISC_STATUS isc_Final_LSH256_224(void *state, uint8 *md);


	/*!
	* \brief
	* ISC_LSH256_256 초기화 함수
	* \param state
	* ISC_LSH256_STATE 구조체의 포인터
	* \returns
	* -# ISC_SUCCESS : Success
	* -# LOCATION^ISC_F_INIT_LSH256_256^ISC_ERR_NULL_INPUT : 초기 입력값이 NULL임
	* -# ISC_Crypto_Initialize()의 에러코드
	*/
    ISC_INTERNAL ISC_STATUS isc_Init_LSH256_256(void *state);

	/*!
	* \brief
	* ISC_LSH256_256 업데이트 함수
	* \param state
	* ISC_LSH256_STATE 구조체의 포인터
	* \param data
	* 해쉬를 할 메시지의 포인터
	* \param count
	* 해쉬를 할 메시지의 길이
	* \returns
	* -# ISC_SUCCESS : Success
	* -# LOCATION^ISC_F_UPDATE_LSH256_256^ISC_ERR_NULL_INPUT : 초기 입력값이 NULL임
	*/
    ISC_INTERNAL ISC_STATUS isc_Update_LSH256_256(void *state, const uint8 *data, uint32 count);

	/*!
	* \brief
	* ISC_LSH256_256 파이널 함수
	* \param state
	* ISC_LSH256_STATE 구조체의 포인터
	* \param md
	* 해쉬의 결과를 저장할 버퍼의 포인터
	* \returns
	* -# ISC_SUCCESS : Success
	* -#  LOCATION^ISC_F_FINAL_LSH256_256^ISC_ERR_NULL_INPUT : 초기 입력값이 NULL임
	*/
    ISC_INTERNAL ISC_STATUS isc_Final_LSH256_256(void *state, uint8 *md);


	/*!
	* \brief
	* ISC_LSH512_224 초기화 함수
	* \param state
	* ISC_LSH512_STATE 구조체의 포인터
	* \returns
	* -# ISC_SUCCESS : Success
	* -# LOCATION^ISC_F_INIT_LSH512_224^ISC_ERR_NULL_INPUT : 초기 입력값이 NULL임
	* -# ISC_Crypto_Initialize()의 에러코드
	*/
    ISC_INTERNAL ISC_STATUS isc_Init_LSH512_224(void *state);

	/*!
	* \brief
	* ISC_LSH512_224 업데이트 함수
	* \param state
	* ISC_LSH512_STATE 구조체의 포인터
	* \param data
	* 해쉬를 할 메시지의 포인터
	* \param count
	* 해쉬를 할 메시지의 길이
	* \returns
	* -# ISC_SUCCESS : Success
	* -# LOCATION^ISC_F_UPDATE_LSH512_224^ISC_ERR_NULL_INPUT : 초기 입력값이 NULL임
	*/
    ISC_INTERNAL ISC_STATUS isc_Update_LSH512_224(void *state, const uint8 *data, uint32 count);

	/*!
	* \brief
	* ISC_LSH512_224 파이널 함수
	* \param state
	* ISC_LSH512_STATE 구조체의 포인터
	* \param md
	* 해쉬의 결과를 저장할 버퍼의 포인터
	* \returns
	* -# ISC_SUCCESS : Success
	* -#  LOCATION^ISC_F_FINAL_LSH512_224^ISC_ERR_NULL_INPUT : 초기 입력값이 NULL임
	*/
    ISC_INTERNAL ISC_STATUS isc_Final_LSH512_224(void *state, uint8 *md);


	/*!
	* \brief
	* ISC_LSH512_256 초기화 함수
	* \param state
	* ISC_LSH512_STATE 구조체의 포인터
	* \returns
	* -# ISC_SUCCESS : Success
	* -# LOCATION^ISC_F_INIT_LSH512_256^ISC_ERR_NULL_INPUT : 초기 입력값이 NULL임
	* -# ISC_Crypto_Initialize()의 에러코드
	*/
    ISC_INTERNAL ISC_STATUS isc_Init_LSH512_256(void *state);

	/*!
	* \brief
	* ISC_LSH512_256 업데이트 함수
	* \param state
	* ISC_LSH512_STATE 구조체의 포인터
	* \param data
	* 해쉬를 할 메시지의 포인터
	* \param count
	* 해쉬를 할 메시지의 길이
	* \returns
	* -# ISC_SUCCESS : Success
	* -# LOCATION^ISC_F_UPDATE_LSH512_256^ISC_ERR_NULL_INPUT : 초기 입력값이 NULL임
	*/
    ISC_INTERNAL ISC_STATUS isc_Update_LSH512_256(void *state, const uint8 *data, uint32 count);

	/*!
	* \brief
	* ISC_LSH512_256 파이널 함수
	* \param state
	* ISC_LSH512_STATE 구조체의 포인터
	* \param md
	* 해쉬의 결과를 저장할 버퍼의 포인터
	* \returns
	* -# ISC_SUCCESS : Success
	* -#  LOCATION^ISC_F_FINAL_LSH512_256^ISC_ERR_NULL_INPUT : 초기 입력값이 NULL임
	*/
    ISC_INTERNAL ISC_STATUS isc_Final_LSH512_256(void *state, uint8 *md);


	/*!
	* \brief
	* ISC_LSH512_384 초기화 함수
	* \param state
	* ISC_LSH512_STATE 구조체의 포인터
	* \returns
	* -# ISC_SUCCESS : Success
	* -# LOCATION^ISC_F_INIT_LSH512_384^ISC_ERR_NULL_INPUT : 초기 입력값이 NULL임
	* -# ISC_Crypto_Initialize()의 에러코드
	*/
    ISC_INTERNAL ISC_STATUS isc_Init_LSH512_384(void *state);

	/*!
	* \brief
	* ISC_LSH512_384 업데이트 함수
	* \param state
	* ISC_LSH512_STATE 구조체의 포인터
	* \param data
	* 해쉬를 할 메시지의 포인터
	* \param count
	* 해쉬를 할 메시지의 길이
	* \returns
	* -# ISC_SUCCESS : Success
	* -# LOCATION^ISC_F_UPDATE_LSH512_384^ISC_ERR_NULL_INPUT : 초기 입력값이 NULL임
	*/
    ISC_INTERNAL ISC_STATUS isc_Update_LSH512_384(void *state, const uint8 *data, uint32 count);

	/*!
	* \brief
	* ISC_LSH512_384 파이널 함수
	* \param state
	* ISC_LSH512_STATE 구조체의 포인터
	* \param md
	* 해쉬의 결과를 저장할 버퍼의 포인터
	* \returns
	* -# ISC_SUCCESS : Success
	* -#  LOCATION^ISC_F_FINAL_LSH512_384^ISC_ERR_NULL_INPUT : 초기 입력값이 NULL임
	*/
    ISC_INTERNAL ISC_STATUS isc_Final_LSH512_384(void *state, uint8 *md);


	/*!
	* \brief
	* ISC_LSH512_512 초기화 함수
	* \param state
	* ISC_LSH512_STATE 구조체의 포인터
	* \returns
	* -# ISC_SUCCESS : Success
	* -# LOCATION^ISC_F_INIT_LSH512_512^ISC_ERR_NULL_INPUT : 초기 입력값이 NULL임
	* -# ISC_Crypto_Initialize()의 에러코드
	*/
    ISC_INTERNAL ISC_STATUS isc_Init_LSH512_512(void *state);

	/*!
	* \brief
	* ISC_LSH512_512 업데이트 함수
	* \param state
	* ISC_LSH512_STATE 구조체의 포인터
	* \param data
	* 해쉬를 할 메시지의 포인터
	* \param count
	* 해쉬를 할 메시지의 길이
	* \returns
	* -# ISC_SUCCESS : Success
	* -# LOCATION^ISC_F_UPDATE_LSH512_512^ISC_ERR_NULL_INPUT : 초기 입력값이 NULL임
	*/
    ISC_INTERNAL ISC_STATUS isc_Update_LSH512_512(void *state, const uint8 *data, uint32 count);

	/*!
	* \brief
	* ISC_LSH512_512 파이널 함수
	* \param state
	* ISC_LSH512_STATE 구조체의 포인터
	* \param md
	* 해쉬의 결과를 저장할 버퍼의 포인터
	* \returns
	* -# ISC_SUCCESS : Success
	* -#  LOCATION^ISC_F_FINAL_LSH512_512^ISC_ERR_NULL_INPUT : 초기 입력값이 NULL임
	*/
    ISC_INTERNAL ISC_STATUS isc_Final_LSH512_512(void *state, uint8 *md);

		/*!
	* \brief
	* ISC_LSH256 초기화 함수
	* \param algType
	* ISC_LSH256 알고리즘 타입(224, 256)
	* \param state
	* ISC_LSH256_STATE 구조체의 포인터
	* \returns
	* -# ISC_SUCCESS : Success
	* -# LOCATION^ISC_F_INIT_LSH256_xxx^ISC_ERR_NULL_INPUT : 초기 입력값이 NULL임
	* -# ISC_Crypto_Initialize()의 에러코드
	*/
    ISC_INTERNAL ISC_STATUS lsh256_init(const uint32_t algType, ISC_LSH256_STATE *state);

	/*!
	* \brief
	* ISC_LSH256 업데이트 함수
	* \param algType
	* ISC_LSH256 알고리즘 타입(224, 256)
	* \param state
	* ISC_LSH256_STATE 구조체의 포인터
	* \param data
	* 해쉬를 할 메시지의 포인터
	* \param count
	* 해쉬를 할 메시지의 길이
	* \returns
	* -# ISC_SUCCESS : Success
	* -# LOCATION^ISC_F_UPDATE_LSH256_xxx^ISC_ERR_NULL_INPUT : 초기 입력값이 NULL임
	*/
    ISC_INTERNAL ISC_STATUS lsh256_update(const uint32_t algType, ISC_LSH256_STATE *state, const uint8 *data, uint32 count);

	/*!
	* \brief
	* ISC_LSH256 파이널 함수
	* \param algType
	* ISC_LSH256 알고리즘 타입(224, 256)
	* \param state
	* ISC_LSH256_STATE 구조체의 포인터
	* \param md
	* 해쉬의 결과를 저장할 버퍼의 포인터
	* \returns
	* -# ISC_SUCCESS : Success
	* -#  LOCATION^ISC_F_FINAL_LSH256_xxx^ISC_ERR_NULL_INPUT : 초기 입력값이 NULL임
	*/
    ISC_INTERNAL ISC_STATUS lsh256_final(const uint32_t algType, ISC_LSH256_STATE *state, uint8 *md);


	/*!
	* \brief
	* ISC_LSH512 초기화 함수
	* \param algType
	* ISC_LSH512 알고리즘 타입(224, 256, 384, 512)
	* \param state
	* ISC_LSH512_STATE 구조체의 포인터
	* \returns
	* -# ISC_SUCCESS : Success
	* -# LOCATION^ISC_F_INIT_LSH512_224^ISC_ERR_NULL_INPUT : 초기 입력값이 NULL임
	* -# ISC_Crypto_Initialize()의 에러코드
	*/
    ISC_INTERNAL ISC_STATUS lsh512_init(const uint32_t algType, ISC_LSH512_STATE *state);

	/*!
	* \brief
	* ISC_LSH512 업데이트 함수
	* \param algType
	* ISC_LSH512 알고리즘 타입(224, 256, 384, 512)
	* \param state
	* ISC_LSH512_STATE 구조체의 포인터
	* \param data
	* 해쉬를 할 메시지의 포인터
	* \param count
	* 해쉬를 할 메시지의 길이
	* \returns
	* -# ISC_SUCCESS : Success
	* -# LOCATION^ISC_F_UPDATE_LSH512_xxx^ISC_ERR_NULL_INPUT : 초기 입력값이 NULL임
	*/
    ISC_INTERNAL ISC_STATUS lsh512_update(const uint32_t algType, ISC_LSH512_STATE *state, const uint8 *data, uint32 count);

	/*!
	* \brief
	* ISC_LSH512 파이널 함수
	* \param algType
	* ISC_LSH512 알고리즘 타입(224, 256, 384, 512)
	* \param state
	* ISC_LSH512_STATE 구조체의 포인터
	* \param md
	* 해쉬의 결과를 저장할 버퍼의 포인터
	* \returns
	* -# ISC_SUCCESS : Success
	* -#  LOCATION^ISC_F_FINAL_LSH512_224^ISC_ERR_NULL_INPUT : 초기 입력값이 NULL임
	*/
    ISC_INTERNAL ISC_STATUS lsh512_final(const uint32_t algType, ISC_LSH512_STATE *state, uint8 *md);

#ifdef __cplusplus
}
#endif

#endif/* HEADER_LSH_H */

