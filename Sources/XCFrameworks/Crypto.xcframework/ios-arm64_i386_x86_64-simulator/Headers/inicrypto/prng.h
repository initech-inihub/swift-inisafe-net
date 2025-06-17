/*!
* \file prng.h
* \brief PRNG; Pseudo Random Number Generator
* \remarks
* NIST FIPS PUB186-2 Appendix 3.1 & 3.2 ������ �������� �ۼ� �Ǿ���.
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

#define ISC_PRNG_PROVEN_MODE  0    /*!<  0: ����� ���, 1: ������� */
/*---------------------------------------------------------------------------------*/

/*!
* \brief
* PRNG���� ���̴� ������ ��� �ִ� ����ü
* \remarks
* G Function�� ������ ����
* �ؽ��Լ� �迭�� digestState�� State ������ �����ϰ�
* ��Ͼ�ȣ �迭�� cipherKey�� Ű ���� �����Ѵ�.
*/
struct isc_prng_unit_st {
	ISC_BIGINT *XKEY;           /*!< ISC_BIGINT XKEY�� ������*/
	ISC_BIGINT *XSEED;          /*!< ISC_BIGINT XSEED�� ������*/
	int GFuncID;            /*!< G_Function �˰��� ID*/
	union {
		void *digestState;  /*!< �ؽ� �迭 G_Function�� STATE ������*/
		void *cipherKey;    /*!< ��� ��ȣ �迭 G_Function�� Ű ������*/
	} GFuncINFO;
	int GFuncINFOLen;		/*!< G_Function������ ����*/
	int unit_status;
	ISC_BIGINT_POOL *pool;		/*!< ���� ȿ���� ���� ISC_BIGINT_POOL*/
	int isgenpool;			/*!< ISC_BIGINT_POOL ��ü ���� ����*/
};

#ifndef ISC_WIN_LOADLIBRARY_CRYPTO

/*!
* \brief
* ISC_New_PRNG_Unit(), ISC_Init_PRNG(), ISC_Get_Rand()�� �� ���� �ϴ� �Լ�
* \param rand
* ������ ���� ���� �����ϱ� ���� �迭�� ������
* \param length
* �����ϱ� ���ϴ� ���� ���� ����(Byte)
* \returns
* -# ISC_SUCCESS : Success
* -# ISC_Crypto_Initialize()�� �����ڵ�
-. LOCATION^ISC_F_RAND_BYTES^ISC_ERR_MEM_ALLOC : ���� �޸� �Ҵ� ����
-. LOCATION^ISC_F_RAND_BYTES^ISC_ERR_INIT_PRNG_FAIL : INT PRNG ����
-. LOCATION^ISC_F_RAND_BYTES^ISC_ERR_GET_RAND_FAIL : : GET RAND ����
*/
ISC_API ISC_STATUS ISC_Rand_Bytes_PRNG(uint8 *rand, int length);

/*!
* \brief
* ISC_PRNG_UNIT ���� �Լ�
* \returns
* ������ ISC_PRNG_UNIT�� ������
*/
ISC_API ISC_PRNG_UNIT *ISC_New_PRNG_Unit(void);

/*!
* \brief
* ISC_PRNG_UNIT�� �� �ʱ�ȭ �Լ�
* \param unit
* ISC_PRNG_UNIT ����ü�� ������
*/
ISC_API void ISC_Clean_PRNG_Unit(ISC_PRNG_UNIT *unit);

/*!
* \brief
* ISC_PRNG_UNIT ���� �Լ�
* \param unit
* ISC_PRNG_UNIT ����ü�� ������
*/
ISC_API void ISC_Free_PRNG_Unit(ISC_PRNG_UNIT *unit);


/*!
* \brief
* PRNG �ʱ�ȭ �Լ�
* \param unit
* ISC_PRNG_UNIT ����ü�� ������
* \param alg_id
* G Function�� ���� �˰��� ID
* \param XKEYbin
* XKEY�� ���� ��� �ִ� �迭�� ������,
* XKEY�� ISC_SEED-Key ������ ������ ��� ���̸� 160~512bit�� ���̸� ���´�.
* \param XKEY_SIZE
* XKEY�� ����
* \param XSEEDbin
* XSEED�� ���� ��� �ִ� �迭�� ������,
* XSEED�� ����ڰ� ���������� �Է��ϴ� ������ ���̴�.
* \param XSEED_SIZE
* XSEED�� ����
* \param pool
* ���� ȿ���� ���� ISC_BIGINT_POOL (NULL �Է½� ���� ����)
* \returns
* -# ISC_SUCCESS : Success
* -# ISC_Crypto_Initialize()�� �����ڵ�
* -# ISC_L_PRNG^ISC_F_INIT_PRNG^ISC_ERR_NULL_INPUT : �Է°��� NULL�� �Է�
* -# ISC_L_PRNG^ISC_F_INIT_PRNG^ISC_ERR_NOT_PROVEN_ALGORITHM : ������忡�� �������� �ʴ� �˰���
* -# ISC_L_PRNG^ISC_F_INIT_PRNG^ISC_ERR_INIT_FAILURE : �ʱ�ȭ ����
* -# ISC_L_PRNG^ISC_F_INIT_PRNG^ISC_ERR_MEM_ALLOC : ���� �޸� �Ҵ� ����
* -# ISC_L_PRNG^ISC_F_INIT_PRNG^ISC_ERR_DIGEST_FAIL : DIGEST �Լ� ����
*/
ISC_API ISC_STATUS ISC_Init_PRNG(ISC_PRNG_UNIT *unit, int alg_id, const uint8 *XKEYbin, int XKEY_SIZE, const uint8 *XSEEDbin, int XSEED_SIZE, ISC_BIGINT_POOL *pool);

/*!
* \brief
* ������ ���� uint8 �迭 �������� ��� ���� �Լ�,
* NIST FIPS PUB186-2 Appendix 3.1 & 3.2 ������ �������� �ۼ� �Ǿ���.
* ������ ISC_DSA���� ���̴� ���� x(0<x<q)���� ���ϱ� ���� �˰�������
* �Ϲ����� ���� ���� ���� ������ mod q ������ ���ʿ��ϱ� ������ mod q������ ���� �ʾ���.
* \param unit
* ISC_PRNG_UNIT ����ü�� ������
* \param output
* ���� ���� �����ϱ� ���� uint8 �迭�� ������
* \param length
* ���ϴ� ���� ���� ����(Byte)
* \returns
* -# ISC_SUCCESS : Success
* -# ISC_Crypto_Initialize()�� �����ڵ�
* -# ISC_L_PRNG^ISC_F_GET_RAND^ISC_ERR_NULL_INPUT : �Է°��� NULL�� �Է�
* -# ISC_L_PRNG^ISC_F_GET_RAND^ISC_ERR_MEM_ALLOC : ���� �޸� �Ҵ� ����
* -# ISC_L_PRNG^ISC_F_GET_RAND^ISC_ERR_RANDOM_GEN_FAILURE : ���� ���� ����
* -# ISC_L_PRNG^ISC_F_GET_RAND^ISC_ERR_ENTROPY_FAIL : ��Ʈ���� ����
*/
ISC_API ISC_STATUS ISC_Get_Rand(ISC_PRNG_UNIT *unit, uint8 *output, int length);

/*!
* \brief
* ������ ���� ISC_BIGINT �������� ��� ���� �Լ�,
* NIST FIPS PUB186-2 Appendix 3.1 & 3.2 ������ �������� �ۼ� �Ǿ���.
* ������ ISC_DSA���� ���̴� ���� x(0<x<q)���� ���ϱ� ���� �˰�������
* �Ϲ����� ���� ���� ���� ������ mod q ������ ���ʿ��ϱ� ������ mod q������ ���� �ʾ���.
* \param unit
* ISC_PRNG_UNIT ����ü�� ������
* \param output
* ���� ���� �����ϱ� ���� ISC_BIGINT�� ������
* \param bit_length
* ���ϴ� ���� ���� ����(bit)
* \returns
* -# ISC_Get_Rand()�� �����ڵ�\n
* -# ISC_SUCCESS : Success\n
* -# ISC_Crypto_Initialize()�� �����ڵ�
* -# ISC_L_PRNG^ISC_F_GET_RAND_BIGINT^ISC_ERR_NULL_INPUT : �Է°��� NULL�� �Է�
* -# ISC_L_PRNG^ISC_F_GET_RAND_BIGINT^ISC_ERR_GET_RAND_FAIL : ���� ���� ����
* -# ISC_L_PRNG^ISC_F_GET_RAND_BIGINT^ISC_ERR_BINARY_TO_BIGINT_FAIL : BINARY TO BIGINT ����
*/
ISC_API ISC_STATUS ISC_Get_Rand_BIGINT(ISC_PRNG_UNIT *unit, ISC_BIGINT *output, int bit_length);

/*!
* \brief
* ISC_DSA�� ǥ��(NIST FIPS PUB 186-2 Appendix 3.1 & 3.2)�� �´� ���� x(0<x<q)�� ISC_BIGINT �������� ��� ���� �Լ�
* \param unit
* ISC_PRNG_UNIT ����ü�� ������
* \param output
* ���� ���� �����ϱ� ���� ISC_BIGINT�� ������
* \param q
* ���� ���� ������ �����ϴ� prime(mod q ������ ���� ���� ���� ���� ����) q�� ������
* \returns
* -# ISC_SUCCESS : Success
* -# ISC_Crypto_Initialize()�� �����ڵ�
* -# ISC_L_PRNG^ISC_F_GET_INNER_RAND^ISC_ERR_NULL_INPUT : �Է°��� NULL�� �Է�
* -# ISC_L_PRNG^ISC_F_GET_INNER_RAND^ISC_ERR_START_BIGINT_POOL_FAIL : START_BIGINT_POOL ����
* -# ISC_L_PRNG^ISC_F_GET_INNER_RAND^ISC_ERR_MEM_ALLOC : ���� �޸� �Ҵ� ����
* -# ISC_L_PRNG^ISC_F_GET_INNER_RAND^ISC_ERR_BINARY_TO_BIGINT_FAIL : BINARY TO BIGINT ����
* -# ISC_L_PRNG^ISC_F_GET_RAND^ISC_ERR_NULL_XKEY_VALUE : XKEY���� NULL�� ��� ����
*/
ISC_API ISC_STATUS ISC_Get_Rand_DSA_BIGINT(ISC_PRNG_UNIT *unit, ISC_BIGINT *output, ISC_BIGINT *q);

/*!
* \brief
* ISC_SEED ��Ʈ���� ����
*      : ����ð� + ���� ���μ��� + rand + �ý�������(CPU, DISK, Network)  
*/
ISC_INTERNAL void isc_SEED_Poll();


/*!
* \brief
* ISC_SEED ��Ʈ���� ���� (�������� - Fast)
*      : ���� �ð� + rand + ���� ���μ��� ID
*/
ISC_INTERNAL void isc_SEED_Poll_Fast();

/*!
* \brief
* ISC_SEED �� ��Ʈ���Ǹ� �߰��Ѵ�.
* \param buf
* �߰��� ��Ʈ���� �迭�� ������
* \param num
* �߰��� ��Ʈ���� �迭�� ������ ����
* \param add
* �߰��� ��Ʈ���� ���� (�� �߰��� ���� ISC_ENTROPY_NEEDED ���� Ŀ�� �Ѵ�)
*/
ISC_INTERNAL void SEED_add(const void *buf, int num, double add);

#else /* ISC_WIN_LOADLIBRARY_CRYPTO */

ISC_RET_LOADLIB_CRYPTO(ISC_STATUS, ISC_Rand_Bytes_PRNG, (uint8 *rand, int length), (rand, length), ISC_ERR_GET_ADRESS_LOADLIBRARY );

#endif /* ISC_WIN_LOADLIBRARY_CRYPTO */

#ifdef  __cplusplus
}
#endif
#endif /* HEADER_PRNG_H */

