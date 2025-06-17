/*!
* \file pkcs1.h
* \brief PKCS1 
* Private-Key Information Syntax Standard
* \remarks
* P1_ENCRYPTED_KEY, P1_PRIV_KEY_INFO 관련 헤더
* \author
* Copyright (c) 2008 by \<INITech\>
*/

#ifndef HEADER_PKCS1_H
#define HEADER_PKCS1_H

#ifdef NO_PKI
#error PKI is disabled.
#endif

#include <inicrypto/foundation.h>

#include "asn1.h"
#include "asn1_objects.h"
#include "x509.h"

#define PKCS1_TYPE_ENCRYPT		0x00
#define PKCS1_TYPE_PLAIN		0x01

#ifdef  __cplusplus
extern "C" {
#endif

/*!
* \brief
* PKCS1 ISC_RSA 개인키 정보를 다루는 구조체
* 암호화된 PKCS1파일을 다루는 경우 암호화 알고리즘은 ISC_DES-EDE3-CBC만을 사용한다.
*/
typedef struct pkcs1_rsa_private_key_st
{
	INTEGER	* version;						/*!< Version : 항상 0 */
	INTEGER * modulus;						/*!< n */
	INTEGER * publicExponent;				/*!< e */
	INTEGER * privateExponent;				/*!< d */
	INTEGER * prime1;						/*!< p */
	INTEGER * prime2;						/*!< q */
	INTEGER * exponent1;					/*!< d mod (p-1) */
	INTEGER * exponent2;					/*!< d mod (q-1) */
	INTEGER * coefficient;					/*!< (inverse of q) mod p */
	SEQUENCE * otherPrimeInfos;				/*!< Not Used yet */
} PKCS1_RSA_PRIVATE_KEY;

typedef struct pkcs1_rsa_public_key_st
{
	INTEGER * modulus;
	INTEGER * publicExponent;
} PKCS1_RSA_PUBLIC_KEY;
    
/*!
* \brief
* RSAES OAEP Parameter를 저장하는 구조체
*/
typedef struct RSAES_OAEP_PARAM_st {
	X509_ALGO_IDENTIFIER *hashAlgorithm;	/*!< identifies the hash function */
	X509_ALGO_IDENTIFIER *maskGenAlgorithm;	/*!< identifies the mask generation function */
	X509_ALGO_IDENTIFIER *pSourceAlgorithm;	/*!< identifies the source (and possibly the value) of the label L. */
} RSAES_OAEP_PARAM;

/*!
* \brief
* RSASSA PSS Parameter를 저장하는 구조체
*/
typedef struct RSASSA_PSS_PARAM_st {
	X509_ALGO_IDENTIFIER *hashAlgorithm;	/*!< identifies the hash function */
	X509_ALGO_IDENTIFIER *maskGenAlgorithm;	/*!< identifies the mask generation function */
	INTEGER *trailerField;		/*!< the trailer field number */
} RSASSA_PSS_PARAM;
    
#ifndef WIN_INI_LOADLIBRARY_PKI

/*!
* \brief
* PKCS1_RSA_PRIVATE_KEY 구조체의 초기화 함수
* \returns
* PKCS1_RSA_PRIVATE_KEY 구조체 포인터
*/
ISC_API PKCS1_RSA_PRIVATE_KEY *new_PKCS1_RSA_PRIVATE_KEY(void);

/*!
* \brief
* PKCS1_RSA_PUBLIC_KEY 구조체의 초기화 함수
* \returns
* PKCS1_RSA_PUBLIC_KEY 구조체 포인터
*/
ISC_API PKCS1_RSA_PUBLIC_KEY *new_PKCS1_RSA_PUBLIC_KEY(void);

/*!
* \brief
* PKCS1_RSA_PRIVATE_KEY 구조체를 메모리 할당 해제
* \param unit
* 제거할 구조체
* \remarks
* 구조체를 제거(ISC_MEM_FREE)
*/
ISC_API void free_PKCS1_RSA_PRIVATE_KEY(PKCS1_RSA_PRIVATE_KEY *unit);

/*!
* \brief
* PKCS1_RSA_PUBLIC_KEY 구조체를 메모리 할당 해제
* \param unit
* 제거할 구조체
* \remarks
* 구조체를 제거(ISC_MEM_FREE)
*/
ISC_API void free_PKCS1_RSA_PUBLIC_KEY(PKCS1_RSA_PUBLIC_KEY *unit);

/*!
* \brief
* PKCS1_RSA_PRIVATE_KEY 구조체를 리셋
* \param unit
* 리셋할 PKCS1_RSA_PRIVATE_KEY 구조체
*/
ISC_API void clean_PKCS1_RSA_PRIVATE_KEY(PKCS1_RSA_PRIVATE_KEY *unit);

/*!
* \brief
* PKCS1_RSA_PUBLIC_KEY 구조체를 리셋
* \param unit
* 리셋할 PKCS1_RSA_PUBLIC_KEY 구조체
*/
ISC_API void clean_PKCS1_RSA_PUBLIC_KEY(PKCS1_RSA_PUBLIC_KEY *unit);

/*!
* \brief
* PKCS1_RSA_PRIVATE_KEY 구조체를 Sequence로 Encode 함수
* \param unit
* PKCS1_RSA_PRIVATE_KEY 구조체
* \param out
* Encoding Sequence 구조체
* \returns
* -# ISC_SUCCESS : 성공
* -# L_PKCS1^F_P1_PRIV_KEY_INFO_TO_SEQ : 기본 에러코드
*/
ISC_API ISC_STATUS PKCS1_RSA_PRIVATE_KEY_to_Seq (PKCS1_RSA_PRIVATE_KEY *unit, SEQUENCE** out);

/*!
* \brief
* PKCS1_RSA_PUBLIC_KEY 구조체를 Sequence로 Encode 함수
* \param unit
* PKCS1_RSA_PUBLIC_KEY 구조체
* \param out
* Encoding Sequence 구조체
* \returns
* -# ISC_SUCCESS : 성공
* -# L_PKCS1^F_P1_PUB_KEY_INFO_TO_SEQ : 기본 에러코드
*/
ISC_API ISC_STATUS PKCS1_RSA_PUBLIC_KEY_to_Seq (PKCS1_RSA_PUBLIC_KEY *unit, SEQUENCE** out);

/*!
* \brief
* Sequence를 PKCS1_RSA_PRIVATE_KEY 구조체로 Decode 함수
* \param in
* Decoding Sequece 구조체
* \param out
* PKCS1_RSA_PRIVATE_KEY 구조체
* \returns
* -# ISC_SUCCESS : 성공
* -#  L_PKCS1^F_SEQ_TO_P1_PRIV_KEY_INFO : 기본 에러코드
*/
ISC_API ISC_STATUS Seq_to_PKCS1_RSA_PRIVATE_KEY (SEQUENCE* in, PKCS1_RSA_PRIVATE_KEY **out);

/*!
* \brief
* Sequence를 PKCS1_RSA_PUBLIC_KEY 구조체로 Decode 함수
* \param in
* Decoding Sequece 구조체
* \param out
* PKCS1_RSA_PUBLIC_KEY 구조체
* \returns
* -# ISC_SUCCESS : 성공
* -# L_PKCS1^F_SEQ_TO_P1_PUB_KEY_INFO : 기본 에러코드
*/
ISC_API ISC_STATUS Seq_to_PKCS1_RSA_PUBLIC_KEY (SEQUENCE* in, PKCS1_RSA_PUBLIC_KEY **out);

/*!
* \brief
* PKCS1_RSA_PRIVATE_KEY 구조체로부터 ISC_RSA_UNIT을 구하는 함수
* \param rsa
* ISC_RSA_UNIT 구조체
* \param out
* PKCS1_RSA_PRIVATE_KEY 구조체
* \returns
* -# ISC_SUCCESS : 성공
* -# L_PKCS1^F_GET_RSA_UNIT_FROM_PRIV_KEY : 기본 에러코드
* -# L_RSA^F_SET_RSA_PRAMS^ISC_ERR_INVALID_INPUT : 입력 파라미터 오류
*/
ISC_API ISC_STATUS get_RSA_UNIT_from_PKCS1_RSA_PRIVATE_KEY(ISC_RSA_UNIT **rsa, PKCS1_RSA_PRIVATE_KEY *pkcs1);

/*!
* \brief
* PKCS1_RSA_PUBLIC_KEY 구조체로부터 ISC_RSA_UNIT을 구하는 함수
* \param rsa
* ISC_RSA_UNIT 구조체
* \param out
* PKCS1_RSA_PUBLIC_KEY 구조체
* \returns
* -# ISC_SUCCESS : 성공
* -# L_PKCS1^F_GET_RSA_UNIT_FROM_PUB_KEY : 기본 에러코드
* -# L_RSA^F_SET_RSA_PRAMS^ISC_ERR_INVALID_INPUT : e와 n이 NULL일 경우
*/
ISC_API ISC_STATUS get_RSA_UNIT_from_PKCS1_RSA_PUBLIC_KEY(ISC_RSA_UNIT **rsa, PKCS1_RSA_PUBLIC_KEY *pkcs1);

/*!
* \brief
* ISC_RSA_UNIT 구조체로부터 PKCS1_RSA_PRIVATE_KEY을 구하는 함수
* \param rsa
* ISC_RSA_UNIT 구조체
* \param out
* PKCS1_RSA_PRIVATE_KEY 구조체
* \returns
* -# ISC_SUCCESS : 성공
* -# L_PKCS1^F_SET_RSA_UNIT_TO_P1_PRIV_KEY : 기본 에러코드
*/
ISC_API ISC_STATUS set_RSA_UNIT_to_PKCS1_RSA_PRIVATE_KEY(ISC_RSA_UNIT *rsa, PKCS1_RSA_PRIVATE_KEY **pkcs1);

/*!
* \brief
* ISC_RSA_UNIT 구조체로부터 PKCS1_RSA_PUBLIC_KEY을 구하는 함수
* \param rsa
* ISC_RSA_UNIT 구조체
* \param out
* PKCS1_RSA_PUBLIC_KEY 구조체
* \returns
* -# ISC_SUCCESS : 성공
* -# L_PKCS1^F_SET_RSA_UNIT_TO_P1_PUB_KEY : 기본 에러코드
*/
ISC_API ISC_STATUS set_RSA_UNIT_to_PKCS1_RSA_PUBLIC_KEY(ISC_RSA_UNIT *rsa, PKCS1_RSA_PUBLIC_KEY **pkcs1);
   
/*!
* \brief
* PBKDF
* \param password
* 패스워드
* \param passwordLen
* 패스워드 길이
* \param salt
* SALT 값
* \param dk_buf
* PBKDF을 통해 생성된 키
* \param dkLen
* 생성된 키의 길이
* \returns
* -# ISC_SUCCESS : 성공
* -# LOCATION^F_PBKDF^ISC_ERR_INVALID_OUTPUT : 입력 파라미터 오류
*/
ISC_API int PBKDF(uint8* password, int passwordLen, uint8* salt, uint8* dk_buf, int dkLen);

/*!
* \brief
* 파일로부터 PEM으로 인코딩된 PKCS1 데이터(공개키/개인키)를 읽어서 ISC_RSA_UNIT 제공하는 리턴해주는 함수
* 개인키의 경우 암호화된 PKCS1 또는 평문 PKCS1 PEM 데이터를 읽는다.
* 공개키의 경우 평문 PKCS1 데이터만 처리한다.
* 개인키의 경우 암호화 되어있는 경우 password 파라미터를 사용하여 복호화 한다.
* \param rsa
* PKCS1 ISC_RSA키 구조체
* \param password 
* 개인키의 경우 PEM 파일이 암호화 되어 있는 경우 복호화시 시용할 개인키 password
* 개인키 PEM 데이터가 평문이거나 공개키 PEM인 경우 사용되지 않는다.
* \param passwordLen 
* password의 길이
* \param fileName
* File 이름 문자열의 포인터, Ex)"D:\\test.pem"
* \returns
* -# ISC_SUCCESS : 성공
* -# L_PKCS1^ISC_ERR_READ_FROM_FILE : 기본 에러코드
* -# L_PKCS1^ISC_ERR_INVALID_INPUT : 입력 파라미터 오류
* -# readPEM_from_Binary 함수로부터 발생된 오류 코드
*/
ISC_API ISC_STATUS readPKCS1_from_File(ISC_RSA_UNIT **rsa, uint8* password, int passwordLen, const char* fileName);
/*!
* \brief
* 바이너리 데이터로부터 PEM으로 인코딩된 PKCS1 데이터(공개키/개인키)를 읽어서 ISC_RSA_UNIT 제공하는 리턴해주는 함수
* 개인키의 경우 암호화된 PKCS1 또는 평문 PKCS1 PEM 데이터를 읽는다.
* 공개키의 경우 평문 PKCS1 데이터만 처리한다.
* 개인키의 경우 암호화 되어있는 경우 password 파라미터를 사용하여 복호화 한다.
* \param rsa
* PKCS1 ISC_RSA키 구조체
* \param password 
* 개인키의 경우 PEM 파일이 암호화 되어 있는 경우 복호화시 시용할 개인키 password
* 개인키 PEM 데이터가 평문이거나 공개키 PEM인 경우 사용되지 않는다.
* \param passwordLen 
* password의 길이
* \param pemBytes
* PEM으로 인코딩된 바이너리를 가리키는 포인터
* \param pemLength
* PEM으로 인코딩된 바이너리의 길이
* \returns
* -# ISC_SUCCESS : 성공
* -# L_PKCS1^ISC_ERR_READ_FROM_BINARY : 기본 에러코드
* -# L_PKCS1^ISC_ERR_INVALID_INPUT : 입력 파라미터 오류
* -# L_PKCS1^ISC_ERR_MALLOC : 할당 에러
*/
ISC_API ISC_STATUS readPKCS1_from_Binary(ISC_RSA_UNIT **rsa, uint8* password, int passwordLen, uint8* pemBytes, int pemLength);

/*!
 * \brief
 * 바이너리 데이터로부터 PEM으로 인코딩된 PKCS1 데이터(공개키/개인키)를 읽어서 ISC_RSA_UNIT || ISC_ECDSA_UNIT 제공하는 리턴해주는 함수
 * 개인키의 경우 암호화된 PKCS1 또는 평문 PKCS1 PEM 데이터를 읽는다.
 * 공개키의 경우 평문 PKCS1 데이터만 처리한다.
 * 개인키의 경우 암호화 되어있는 경우 password 파라미터를 사용하여 복호화 한다.
 * \param unit
 * PKCS1 ISC_RSA || ISC_ECDSA 키 구조체
 * \param alg
 * RSA/ECDSA 알고리즘 구분. ASYMMETRIC_RSA_KEY || ASYMMETRIC_ECDSA_KEY
 * \param password
 * 개인키의 경우 PEM 파일이 암호화 되어 있는 경우 복호화시 시용할 개인키 password
 * 개인키 PEM 데이터가 평문이거나 공개키 PEM인 경우 사용되지 않는다.
 * \param passwordLen
 * password의 길이
 * \param pemBytes
 * PEM으로 인코딩된 바이너리를 가리키는 포인터
 * \param pemLength
 * PEM으로 인코딩된 바이너리의 길이
 * \returns
 * -# ISC_SUCCESS : 성공
 * -# L_PKCS1^ISC_ERR_READ_FROM_BINARY : 기본 에러코드
 * -# L_PKCS1^ISC_ERR_INVALID_INPUT : 입력 파라미터 오류
 * -# L_PKCS1^ISC_ERR_MALLOC : 할당 에러
 */
ISC_API ISC_STATUS readPKCS1_from_Binary_ex(void **unit, int alg, uint8* password, int passwordLen, uint8* inPEMData, int inPEMDataLen);
    
/*!
* \brief
* ISC_RSA_UNIT 개인키 구조체를 PKCS1 PEM으로 인코딩한 뒤 파일로 쓰는 함수
* password가 NULL이 아니면 암호화된 PKCS1 PEM을 생성하고, NULL인 경우 평문 PKCS1 PEM을 생성한다.
* \param rsa
* 저장할 ISC_RSA_UNIT 구조체
* \param password 
* 암호화된 PKCS1 PEM을 생성하려는 경우 사용할 개인키 패스워드, NULL이면 평문 PKCS1 PEM을 생성한다.
* \param passwordLen 
* password의 길이, password가 NULL인 경우 0을 지정
* \param fileName
* File 이름 문자열의 포인터, Ex)"D:\\test.pem"
* \returns
* -# 버퍼에 쓰여진 길이 : 성공
* -# -1 : 실패
*/
ISC_API int writePKCS1PrivateKey_to_File(ISC_RSA_UNIT *rsa, uint8* password, int passwordLen, const char* fileName);

/*!
* \brief
* ISC_RSA_UNIT 개인키 구조체를 PKCS1 PEM으로 인코딩한 뒤 바이너리로 쓰는 함수
* password가 NULL이 아니면 암호화된 PKCS1 PEM을 생성하고, NULL인 경우 평문 PKCS1 PEM을 생성한다.
* \param rsa
* 저장할 ISC_RSA_UNIT 구조체
* \param password 
* 암호화된 PKCS1 PEM을 생성하려는 경우 사용할 개인키 패스워드, NULL이면 평문 PKCS1 PEM을 생성한다.
* \param passwordLen 
* password의 길이, password가 NULL인 경우 0을 지정
* \param pemBytes
* 바이너리로 저장할 버퍼의 이중 포인터
* \returns
* -# 버퍼에 쓰여진 길이 : 성공
* -# -1 : 실패
*/
ISC_API int writePKCS1PrivateKey_to_Binary(ISC_RSA_UNIT *rsa, uint8* password, int passwordLen, uint8** pemBytes);

/*!
* \brief
* ISC_RSA_UNIT 공개키 구조체를 PKCS1 PEM으로 인코딩한 뒤 파일로 쓰는 함수
* oid가 지정되면 oid를 포함하고 있는 포멧의 PEM을 생성하고, NULL인 경우 일반PKCS1포멧의 PEM을 생성한다.
* \param rsa
* 저장할 ISC_RSA_UNIT 구조체
* \param oid 
* 공개키의 OID, NULL이면 oid가 포함되지 않은 일반PKCS1포멧의 PEM을 생성한다.
* \param fileName
* File 이름 문자열의 포인터, Ex)"D:\\test.pem"
* \returns
* -# 버퍼에 쓰여진 길이 : 성공
* -# -1 : 실패
*/
ISC_API int writePKCS1PublicKey_to_File(ISC_RSA_UNIT *rsa, OBJECT_IDENTIFIER *oid, const char* fileName);

/*!
* \brief
* ISC_RSA_UNIT 공개키 구조체를 PKCS1 PEM으로 인코딩한 뒤 바이너리로 쓰는 함수
* oid가 지정되면 oid를 포함하고 있는 포멧의 PEM을 생성하고, NULL인 경우 일반PKCS1포멧의 PEM을 생성한다.
* \param rsa
* 저장할 ISC_RSA_UNIT 구조체
* \param oid 
* 공개키의 OID, NULL이면 oid가 포함되지 않은 일반PKCS1포멧의 PEM을 생성한다.
* \param pemBytes
* 바이너리로 저장할 버퍼의 이중 포인터
* \returns
* -# 버퍼에 쓰여진 길이 : 성공
* -# -1 : 실패
*/
ISC_API int writePKCS1PublicKey_to_Binary(ISC_RSA_UNIT *rsa, OBJECT_IDENTIFIER *oid, uint8** pemBytes);
    
/*!
* \brief
* RSAES_OAEP_PARAM 구조체를 생성하는 함수
* \returns
* 생성된 RSAES_OAEP_PARAM 구조체의 포인터
*/
ISC_API RSAES_OAEP_PARAM *new_RSAES_OAEP_PARAM(void);

/*!
* \brief
* RSAES_OAEP_PARAM 구조체의 메모리 해지 함수
* \param rsaesoaepParam
* 메모리를 해지할 ASN1_UNIT 구조체의 포인터
*/
ISC_API void free_RSAES_OAEP_PARAM(RSAES_OAEP_PARAM *param);

/*!
* \brief
* RSAES_OAEP_PARAM 구조체의 값을 초기화하는 함수
* \param rsaesoaepParam
* 값을 초기화 할 RSAES_OAEP_PARAM 구조체의 포인터
*/
ISC_API void clean_RSAES_OAEP_PARAM(RSAES_OAEP_PARAM *param);

/*!
* \brief
* RSAES_OAEP_PARAM 구조체를 복사하는 함수
* \param param
* 복사할 원본 RSAES_OAEP_PARAM 구조체의 포인터
* \returns
* 복사된 RSAES_OAEP_PARAM 구조체의 포인터
*/
ISC_API RSAES_OAEP_PARAM *dup_RSAES_OAEP_PARAM(RSAES_OAEP_PARAM *param);

/*!
* \brief
* RSAES_OAEP_PARAM 구조체에 hashAlgorithm을 입력
* \param param
* RSAES_OAEP_PARAM 구조체 포인터
* \param index
* OAEP-PSSDigestAlgorithms의 OID index
* \return
* -# ISC_SUCCESS : 성공
* -# ISC_FAIL : 실패
*/
ISC_API ISC_STATUS set_RSAES_OAEP_PARAM_hashAlgorithm(RSAES_OAEP_PARAM* param, int index);

/*!
* \brief
* RSAES_OAEP_PARAM 구조체에 hashAlgorithm을 입력
* \param param
* RSAES_OAEP_PARAM 구조체 포인터
* \param oid
* OAEP-PSSDigestAlgorithms의 OID
* \return
* -# ISC_SUCCESS : 성공
* -# ISC_FAIL : 실패
*/
ISC_API ISC_STATUS set_RSAES_OAEP_PARAM_hashAlgorithm_OID(RSAES_OAEP_PARAM* param, OBJECT_IDENTIFIER *oid);

/*!
* \brief
* RSAES_OAEP_PARAM 구조체에 maskGenAlgorithm을 입력
* \param param
* RSAES_OAEP_PARAM 구조체 포인터
* \param index
* PKCS1MGFAlgorithms의 OID index
* \return
* -# ISC_SUCCESS : 성공
* -# ISC_FAIL : 실패
*/
ISC_API ISC_STATUS set_RSAES_OAEP_PARAM_maskGenAlgorithm(RSAES_OAEP_PARAM* param, int index);

/*!
* \brief
* RSAES_OAEP_PARAM 구조체에 maskGenAlgorithm을 입력
* \param param
* RSAES_OAEP_PARAM 구조체 포인터
* \param oid
* PKCS1MGFAlgorithms의 OID
* \return
* -# ISC_SUCCESS : 성공
* -# ISC_FAIL : 실패
*/
ISC_API ISC_STATUS set_RSAES_OAEP_PARAM_maskGenAlgorithm_OID(RSAES_OAEP_PARAM* param, OBJECT_IDENTIFIER *oid);

/*!
* \brief
* RSAES_OAEP_PARAM 구조체에 pSourceAlgorithm을 입력
* \param param
* RSAES_OAEP_PARAM 구조체 포인터
* \param index
* PKCS1pSourceAlgorithms의 OID index
* \return
* -# ISC_SUCCESS : 성공
* -# ISC_FAIL : 실패
*/
ISC_API ISC_STATUS set_RSAES_OAEP_PARAM_pSourceAlgorithm(RSAES_OAEP_PARAM* param, int index, uint8* salt, int saltLen);

/*!
* \brief
* RSAES_OAEP_PARAM 구조체에 pSourceAlgorithm을 입력
* \param param
* RSAES_OAEP_PARAM 구조체 포인터
* \param oid
* PKCS1pSourceAlgorithms의 OID
* \return
* -# ISC_SUCCESS : 성공
* -# ISC_FAIL : 실패
*/
ISC_API ISC_STATUS set_RSAES_OAEP_PARAM_pSourceAlgorithm_OID(RSAES_OAEP_PARAM* param, OBJECT_IDENTIFIER *oid, uint8* salt, int saltLen);

/*!
* \brief
* RSAES_OAEP_PARAM 구조체를 Sequence로 Encode 함수
* \param st
* RSAES_OAEP_PARAM 구조체
* \param seq
* Encoding Sequence 구조체
* \returns
* -# ISC_SUCCESS : 성공
* -# RSAES_OAEP_PARAM_to_Seq()의 에러 코드\n
*/
ISC_API ISC_STATUS RSAES_OAEP_PARAM_to_Seq (RSAES_OAEP_PARAM *st, SEQUENCE **seq);

/*!
* \brief
* Sequence를 RSAES_OAEP_PARAM 구조체로 Decode 함수
* \param seq
* Decoding Sequece 구조체
* \param st
* RSAES_OAEP_PARAM 구조체
* \returns
* -# ISC_SUCCESS : 성공
* -# Seq_to_RSAES_OAEP_PARAM()의 에러 코드\n
*/
ISC_API ISC_STATUS Seq_to_RSAES_OAEP_PARAM (SEQUENCE *seq, RSAES_OAEP_PARAM **st);


/*!
* \brief
* RSASSA_PSS_PARAM 구조체를 생성하는 함수
* \returns
* 생성된 RSASSA_PSS_PARAM 구조체의 포인터
*/
ISC_API RSASSA_PSS_PARAM *new_RSASSA_PSS_PARAM(void);

/*!
* \brief
* RSASSA_PSS_PARAM 구조체의 메모리 해지 함수
* \param param
* 메모리를 해지할 RSASSA_PSS_PARAM 구조체의 포인터
*/
ISC_API void free_RSASSA_PSS_PARAM(RSASSA_PSS_PARAM *param);

/*!
* \brief
* RSASSA_PSS_PARAM 구조체의 값을 초기화하는 함수
* \param param
* 값을 초기화 할 RSASSA_PSS_PARAM 구조체의 포인터
*/
ISC_API void clean_RSASSA_PSS_PARAM(RSASSA_PSS_PARAM *param);

/*!
* \brief
* RSASSA_PSS_PARAM 구조체를 복사하는 함수
* \param param
* 복사할 원본 RSASSA_PSS_PARAM 구조체의 포인터
* \returns
* 복사된 RSASSA_PSS_PARAM 구조체의 포인터
*/
ISC_API RSASSA_PSS_PARAM *dup_RSASSA_PSS_PARAM(RSASSA_PSS_PARAM *param);

/*!
* \brief
* RSASSA_PSS_PARAM 구조체에 hashAlgorithm을 입력
* \param param
* RSASSA_PSS_PARAM 구조체 포인터
* \param index
* OAEP-PSSDigestAlgorithms의 OID idex
* \return
* -# ISC_SUCCESS : 성공
* -# ISC_FAIL : 실패
*/
ISC_API ISC_STATUS set_RSASSA_PSS_PARAM_hashAlgorithm(RSASSA_PSS_PARAM* param, int index);

/*!
* \brief
* RSASSA_PSS_PARAM 구조체에 hashAlgorithm을 입력
* \param param
* RSASSA_PSS_PARAM 구조체 포인터
* \param oid
* OAEP-PSSDigestAlgorithms의 OID
* \return
* -# ISC_SUCCESS : 성공
* -# ISC_FAIL : 실패
*/
ISC_API ISC_STATUS set_RSASSA_PSS_PARAM_hashAlgorithm_OID(RSASSA_PSS_PARAM* param, OBJECT_IDENTIFIER *oid);

/*!
* \brief
* RSASSA_PSS_PARAM 구조체에 maskGenAlgorithm을 입력
* \param param
* RSASSA_PSS_PARAM 구조체 포인터
* \param index
* PKCS1MGFAlgorithms의 OID index
* \return
* -# ISC_SUCCESS : 성공
* -# ISC_FAIL : 실패
*/
ISC_API ISC_STATUS set_RSASSA_PSS_PARAM_maskGenAlgorithm(RSASSA_PSS_PARAM* param, int index);

/*!
* \brief
* RSASSA_PSS_PARAM 구조체에 maskGenAlgorithm을 입력
* \param param
* RSASSA_PSS_PARAM 구조체 포인터
* \param oid
* PKCS1MGFAlgorithms의 OID
* \return
* -# ISC_SUCCESS : 성공
* -# ISC_FAIL : 실패
*/
ISC_API ISC_STATUS set_RSASSA_PSS_PARAM_maskGenAlgorithm_OID(RSASSA_PSS_PARAM* param, OBJECT_IDENTIFIER *oid);

/*!
* \brief
* RSASSA_PSS_PARAM 구조체에 pSourceAlgorithm을 입력
* \param param
* RSASSA_PSS_PARAM 구조체 포인터
* \param filedNum
* the trailer field number
* \return
* -# ISC_SUCCESS : 성공
* -# ISC_FAIL : 실패
*/
ISC_API ISC_STATUS set_RSASSA_PSS_PARAM_trailerField(RSASSA_PSS_PARAM* param, uint8 filedNum);


/*!
* \brief
* RSASSA_PSS_PARAM 구조체를 Sequence로 Encode 함수
* \param st
* RSASSA_PSS_PARAM 구조체
* \param seq
* Encoding Sequence 구조체
* \returns
* -# ISC_SUCCESS : 성공
* -# RSASSA_PSS_PARAM_to_Seq()의 에러 코드\n
*/
ISC_API ISC_STATUS RSASSA_PSS_PARAM_to_Seq (RSASSA_PSS_PARAM *src, SEQUENCE **dst);

/*!
* \brief
* Sequence를 RSAES_OAEP_PARAM 구조체로 Decode 함수
* \param seq
* Decoding Sequece 구조체
* \param st
* RSASSA_PSS_PARAM 구조체
* \returns
* -# ISC_SUCCESS : 성공
* -# Seq_to_RSASSA_PSS_PARAM()의 에러 코드\n
*/
ISC_API ISC_STATUS Seq_to_RSASSA_PSS_PARAM (SEQUENCE *src, RSASSA_PSS_PARAM **dst);


/*!
* \brief
* X509_ALGO_IDENTIFIER 구조체에 RSAES_OAEP_PARAM을 입력
* \param x509Algo
* X509_ALGO_IDENTIFIER 구조체 포인터
* \param param
* RSAES_OAEP_PARAM 구조체 포인터
* \return
* -# ISC_SUCCESS : 성공
* -# ISC_FAIL : 실패
*/
ISC_API ISC_STATUS  set_X509_ALGO_IDENTIFIER_with_RSAES_OAEP_PARAM(X509_ALGO_IDENTIFIER *x509Algo, RSAES_OAEP_PARAM *param);

/*!
* \brief
* X509_ALGO_IDENTIFIER 구조체에 RSASSA_PSS_PARAM을 입력
* \param x509Algo
* X509_ALGO_IDENTIFIER 구조체 포인터
* \param param
* RSASSA_PSS_PARAM 구조체 포인터
* \return
* -# ISC_SUCCESS : 성공
* -# ISC_FAIL : 실패
*/
ISC_API ISC_STATUS set_X509_ALGO_IDENTIFIER_with_RSASSA_PSS_PARAM(X509_ALGO_IDENTIFIER *x509Algo, RSASSA_PSS_PARAM *param);

    
/*!
 * \brief
 * ISC_ECDSA_UNIT 공개키 구조체를 PEM으로 인코딩한 뒤 파일로 쓰는 함수 - RFC5480 참조
 * oid가 지정되면 oid를 포함하고 있는 포멧의 PEM을 생성하고, NULL인 경우 일반 포멧의 PEM을 생성한다.
 * \param ecdsa
 * 저장할 ISC_ECDSA_UNIT 구조체
 * \param fileName
 * File 이름 문자열의 포인터, Ex)"D:\\test.pem"
 * \returns
 * -# 버퍼에 쓰여진 길이 : 성공
 * -# -1 : 실패
 */
ISC_API int writeECDSAPublicKey_to_File(ISC_ECDSA_UNIT *ecdsa, const char* fileName);

/*!
 * \brief
 * ISC_ECDSA_UNIT 공개키 구조체를 PEM으로 인코딩한 뒤 바이너리로 쓰는 함수 - RFC5480 참조
 * oid가 지정되면 oid를 포함하고 있는 포멧의 PEM을 생성하고, NULL인 경우 PEM을 생성한다.
 * \param ecdsa
 * 저장할 ISC_ECDSA_UNIT 구조체
 * \param pemBytes
 * 바이너리로 저장할 버퍼의 이중 포인터
 * \returns
 * -# 버퍼에 쓰여진 길이 : 성공
 * -# -1 : 실패
 */
ISC_API int writeECDSAPublicKey_to_Binary(ISC_ECDSA_UNIT *ecdsa, uint8** pemBytes);

/*!
 * \brief
 * ISC_ECDSA_UNIT 개인키 구조체를 PKCS1 PEM으로 인코딩한 뒤 파일로 쓰는 함수
 * password가 NULL이 아니면 암호화된 PKCS1 PEM을 생성하고, NULL인 경우 평문 PKCS1 PEM을 생성한다.
 * \param rsa
 * 저장할 ISC_ECDSA_UNIT 구조체
 * \param password
 * 암호화된 PKCS1 PEM을 생성하려는 경우 사용할 개인키 패스워드, NULL이면 평문 PKCS1 PEM을 생성한다.
 * \param passwordLen
 * password의 길이, password가 NULL인 경우 0을 지정
 * \param fileName
 * File 이름 문자열의 포인터, Ex)"D:\\test.pem"
 * \returns
 * -# 버퍼에 쓰여진 길이 : 성공
 * -# -1 : 실패
 */
ISC_API int writeECDSAPrivateKey_to_File(ISC_ECDSA_UNIT *ecdsa, uint8* password, int passwordLen, const char* fileName);

/*!
 * \brief
 * ISC_ECDSA_UNIT 개인키 구조체를 PKCS1 PEM으로 인코딩한 뒤 바이너리로 쓰는 함수
 * password가 NULL이 아니면 암호화된 PKCS1 PEM을 생성하고, NULL인 경우 평문 PKCS1 PEM을 생성한다.
 * \param rsa
 * 저장할 ISC_ECDSA_UNIT 구조체
 * \param password
 * 암호화된 PKCS1 PEM을 생성하려는 경우 사용할 개인키 패스워드, NULL이면 평문 PKCS1 PEM을 생성한다.
 * \param passwordLen
 * password의 길이, password가 NULL인 경우 0을 지정
 * \param pemBytes
 * 바이너리로 저장할 버퍼의 이중 포인터
 * \returns
 * -# 버퍼에 쓰여진 길이 : 성공
 * -# -1 : 실패
 */
ISC_API int writeECDSAPrivateKey_to_Binary(ISC_ECDSA_UNIT *ecdsa, uint8* password, int passwordLen, uint8** pemBytes);

/*!
 * \brief
 * get Asymmetric key Type
 * \param asymmkey
 * Sequence of key
 * \param typeAsymmKey
 * type of Asymmetric-key
 * \returns
 * -# 0 : success
 * -# -1 : fail
 */
ISC_API int getAsymmkeyType_from_sequence(SEQUENCE* asymmkey, int* typeAsymmKey);

/*!
 * \brief
 * get Asymmetric key Type
 * \param asymmkey
 * buffer of key-array
 * \param length_asymmkey
 * length of key-array
 * \param typeAsymmKey
 * type of Asymmetric-key
 * \returns
 * -# 0 : success
 * -# -1 : fail
 */
ISC_API int getAsymmkeyType(uint8* asymmkey, int length_asymmkey, int* typeAsymmKey);
    
#else

#include "foundation_pki.h"

INI_RET_LOADLIB_PKI(PKCS1_RSA_PRIVATE_KEY*, new_PKCS1_RSA_PRIVATE_KEY, (void), (), NULL);
INI_RET_LOADLIB_PKI(PKCS1_RSA_PUBLIC_KEY*, new_PKCS1_RSA_PUBLIC_KEY, (void), (), NULL);
INI_VOID_LOADLIB_PKI(void, free_PKCS1_RSA_PRIVATE_KEY, (PKCS1_RSA_PRIVATE_KEY *unit), (unit) );
INI_VOID_LOADLIB_PKI(void, free_PKCS1_RSA_PUBLIC_KEY, (PKCS1_RSA_PUBLIC_KEY *unit), (unit) );
INI_VOID_LOADLIB_PKI(void, clean_PKCS1_RSA_PRIVATE_KEY, (PKCS1_RSA_PRIVATE_KEY *unit), (unit) );
INI_VOID_LOADLIB_PKI(void, clean_PKCS1_RSA_PUBLIC_KEY, (PKCS1_RSA_PUBLIC_KEY *unit), (unit) );
INI_RET_LOADLIB_PKI(ISC_STATUS, PKCS1_RSA_PRIVATE_KEY_to_Seq, (PKCS1_RSA_PRIVATE_KEY *unit, SEQUENCE** out), (unit,out), ISC_FAIL);
INI_RET_LOADLIB_PKI(ISC_STATUS, PKCS1_RSA_PUBLIC_KEY_to_Seq, (PKCS1_RSA_PUBLIC_KEY *unit, SEQUENCE** out), (unit,out), ISC_FAIL);
INI_RET_LOADLIB_PKI(ISC_STATUS, Seq_to_PKCS1_RSA_PRIVATE_KEY, (SEQUENCE* in, PKCS1_RSA_PRIVATE_KEY **out), (in,out), ISC_FAIL);
INI_RET_LOADLIB_PKI(ISC_STATUS, Seq_to_PKCS1_RSA_PUBLIC_KEY, (SEQUENCE* in, PKCS1_RSA_PUBLIC_KEY **out), (in,out), ISC_FAIL);
INI_RET_LOADLIB_PKI(ISC_STATUS, get_RSA_UNIT_from_PKCS1_RSA_PRIVATE_KEY, (ISC_RSA_UNIT **rsa, PKCS1_RSA_PRIVATE_KEY *pkcs1), (rsa,pkcs1), ISC_FAIL);
INI_RET_LOADLIB_PKI(ISC_STATUS, get_RSA_UNIT_from_PKCS1_RSA_PUBLIC_KEY, (ISC_RSA_UNIT **rsa, PKCS1_RSA_PUBLIC_KEY *pkcs1), (rsa,pkcs1), ISC_FAIL);
INI_RET_LOADLIB_PKI(ISC_STATUS, set_RSA_UNIT_to_PKCS1_RSA_PRIVATE_KEY, (ISC_RSA_UNIT *rsa, PKCS1_RSA_PRIVATE_KEY **pkcs1), (rsa,pkcs1), ISC_FAIL);
INI_RET_LOADLIB_PKI(ISC_STATUS, set_RSA_UNIT_to_PKCS1_RSA_PUBLIC_KEY, (ISC_RSA_UNIT *rsa, PKCS1_RSA_PUBLIC_KEY **pkcs1), (rsa,pkcs1), ISC_FAIL);
INI_RET_LOADLIB_PKI(int, PBKDF, (uint8* password, int passwordLen, uint8* salt, uint8* dk_buf, int dkLen), (password,passwordLen,salt,dk_buf,dkLen), ISC_FAIL);
INI_RET_LOADLIB_PKI(ISC_STATUS, readPKCS1_from_File, (ISC_RSA_UNIT **rsa, uint8* password, int passwordLen, const char* fileName), (rsa,password,passwordLen,fileName), ISC_FAIL);
INI_RET_LOADLIB_PKI(ISC_STATUS, readPKCS1_from_Binary, (ISC_RSA_UNIT **rsa, uint8* password, int passwordLen, uint8* pemBytes, int pemLength), (rsa,password,passwordLen,pemBytes,pemLength), ISC_FAIL);
INI_RET_LOADLIB_PKI(int, writePKCS1PrivateKey_to_File, (ISC_RSA_UNIT *rsa, uint8* password, int passwordLen, const char* fileName), (rsa,password,passwordLen,fileName), ISC_FAIL);
INI_RET_LOADLIB_PKI(int, writePKCS1PrivateKey_to_Binary, (ISC_RSA_UNIT *rsa, uint8* password, int passwordLen, uint8** pemBytes), (rsa,password,passwordLen,pemBytes), ISC_FAIL);
INI_RET_LOADLIB_PKI(int, writePKCS1PublicKey_to_File, (ISC_RSA_UNIT *rsa, OBJECT_IDENTIFIER *oid, const char* fileName), (rsa,oid,fileName), ISC_FAIL);
INI_RET_LOADLIB_PKI(int, writePKCS1PublicKey_to_Binary, (ISC_RSA_UNIT *rsa, OBJECT_IDENTIFIER *oid, uint8** pemBytes), (rsa,oid,pemBytes), ISC_FAIL);
INI_RET_LOADLIB_PKI(RSAES_OAEP_PARAM*, new_RSAES_OAEP_PARAM, (void), (), NULL);
INI_VOID_LOADLIB_PKI(void, free_RSAES_OAEP_PARAM, (RSAES_OAEP_PARAM *param), (param) );
INI_VOID_LOADLIB_PKI(void, clean_RSAES_OAEP_PARAM, (RSAES_OAEP_PARAM *param), (param) );
INI_RET_LOADLIB_PKI(RSAES_OAEP_PARAM*, dup_RSAES_OAEP_PARAM, (RSAES_OAEP_PARAM *param), (param), NULL);
INI_RET_LOADLIB_PKI(ISC_STATUS, set_RSAES_OAEP_PARAM_hashAlgorithm, (RSAES_OAEP_PARAM* param, int index), (param,index), ISC_FAIL);
INI_RET_LOADLIB_PKI(ISC_STATUS, set_RSAES_OAEP_PARAM_hashAlgorithm_OID, (RSAES_OAEP_PARAM* param, OBJECT_IDENTIFIER *oid), (param,oid), ISC_FAIL);
INI_RET_LOADLIB_PKI(ISC_STATUS, set_RSAES_OAEP_PARAM_maskGenAlgorithm, (RSAES_OAEP_PARAM* param, int index), (param,index), ISC_FAIL);
INI_RET_LOADLIB_PKI(ISC_STATUS, set_RSAES_OAEP_PARAM_maskGenAlgorithm_OID, (RSAES_OAEP_PARAM* param, OBJECT_IDENTIFIER *oid), (param,oid), ISC_FAIL);
INI_RET_LOADLIB_PKI(ISC_STATUS, set_RSAES_OAEP_PARAM_pSourceAlgorithm, (RSAES_OAEP_PARAM* param, int index, uint8* salt, int saltLen), (param,index,salt,saltLen), ISC_FAIL);
INI_RET_LOADLIB_PKI(ISC_STATUS, set_RSAES_OAEP_PARAM_pSourceAlgorithm_OID, (RSAES_OAEP_PARAM* param, OBJECT_IDENTIFIER *oid, uint8* salt, int saltLen), (param,oid,salt,saltLen), ISC_FAIL);
INI_RET_LOADLIB_PKI(ISC_STATUS, RSAES_OAEP_PARAM_to_Seq, (RSAES_OAEP_PARAM *st, SEQUENCE **seq), (st,seq), ISC_FAIL);
INI_RET_LOADLIB_PKI(ISC_STATUS, Seq_to_RSAES_OAEP_PARAM, (SEQUENCE *seq, RSAES_OAEP_PARAM **st), (seq,st), ISC_FAIL);
INI_RET_LOADLIB_PKI(RSASSA_PSS_PARAM*, new_RSASSA_PSS_PARAM, (void), (), NULL);
INI_VOID_LOADLIB_PKI(void, free_RSASSA_PSS_PARAM, (RSASSA_PSS_PARAM *param), (param) );
INI_VOID_LOADLIB_PKI(void, clean_RSASSA_PSS_PARAM, (RSASSA_PSS_PARAM *param), (param) );
INI_RET_LOADLIB_PKI(RSASSA_PSS_PARAM*, dup_RSASSA_PSS_PARAM, (RSASSA_PSS_PARAM *param), (param), NULL);
INI_RET_LOADLIB_PKI(ISC_STATUS, set_RSASSA_PSS_PARAM_hashAlgorithm, (RSASSA_PSS_PARAM* param, int index), (param,index), ISC_FAIL);
INI_RET_LOADLIB_PKI(ISC_STATUS, set_RSASSA_PSS_PARAM_hashAlgorithm_OID, (RSASSA_PSS_PARAM* param, OBJECT_IDENTIFIER *oid), (param,oid), ISC_FAIL);
INI_RET_LOADLIB_PKI(ISC_STATUS, set_RSASSA_PSS_PARAM_maskGenAlgorithm, (RSASSA_PSS_PARAM* param, int index), (param,index), ISC_FAIL);
INI_RET_LOADLIB_PKI(ISC_STATUS, set_RSASSA_PSS_PARAM_maskGenAlgorithm_OID, (RSASSA_PSS_PARAM* param, OBJECT_IDENTIFIER *oid), (param,oid), ISC_FAIL);
INI_RET_LOADLIB_PKI(ISC_STATUS, set_RSASSA_PSS_PARAM_trailerField, (RSASSA_PSS_PARAM* param, uint8 filedNum), (param,filedNum), ISC_FAIL);
INI_RET_LOADLIB_PKI(ISC_STATUS, RSASSA_PSS_PARAM_to_Seq, (RSASSA_PSS_PARAM *src, SEQUENCE **dst), (src,dst), ISC_FAIL);
INI_RET_LOADLIB_PKI(ISC_STATUS, Seq_to_RSASSA_PSS_PARAM, (SEQUENCE *src, RSASSA_PSS_PARAM **dst), (src,dst), ISC_FAIL);
INI_RET_LOADLIB_PKI(ISC_STATUS, set_X509_ALGO_IDENTIFIER_with_RSAES_OAEP_PARAM, (X509_ALGO_IDENTIFIER *x509Algo, RSAES_OAEP_PARAM *param), (x509Algo,param), ISC_FAIL);
INI_RET_LOADLIB_PKI(ISC_STATUS, set_X509_ALGO_IDENTIFIER_with_RSASSA_PSS_PARAM, (X509_ALGO_IDENTIFIER *x509Algo, RSASSA_PSS_PARAM *param), (x509Algo,param), ISC_FAIL);
INI_RET_LOADLIB_PKI(ISC_STATUS, writeECDSAPublicKey_to_File, (ISC_ECDSA_UNIT *ecdsa, const char* fileName), (ecdsa, fileName), ISC_FAIL);
INI_RET_LOADLIB_PKI(ISC_STATUS, writeECDSAPublicKey_to_Binary, (ISC_ECDSA_UNIT *ecdsa, uint8** pemBytes), (ecdsa, pemBytes), ISC_FAIL);
INI_RET_LOADLIB_PKI(ISC_STATUS, writeECDSAPrivateKey_to_File, (ISC_ECDSA_UNIT *ecdsa, uint8* password, int passwordLen, const char* fileName), (ecdsa,password,passwordLen,fileName), (x509Algo,param), ISC_FAIL);
INI_RET_LOADLIB_PKI(ISC_STATUS, writeECDSAPrivateKey_to_Binary, (ISC_ECDSA_UNIT *ecdsa, uint8* password, int passwordLen, uint8** pemBytes), (ecdsa,password,passwordLen,pemBytes), ISC_FAIL);
INI_RET_LOADLIB_PKI(ISC_STATUS, getAsymmkeyType_from_sequence, (SEQUENCE* asymmkey, int* typeAsymmKey), (asymmkey, typeAsymmKey), ISC_FAIL);
INI_RET_LOADLIB_PKI(ISC_STATUS, getAsymmkeyType, (uint8* asymmkey, int length_asymmkey, int* typeAsymmKey), (asymmkey, length_asymmkey, typeAsymmKey), ISC_FAIL); 
#endif

#ifdef  __cplusplus
}
#endif
#endif
