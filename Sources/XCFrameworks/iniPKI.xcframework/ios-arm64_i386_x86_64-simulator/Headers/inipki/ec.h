/*!
* \file ec.h
* \brief ECC ( Elliptic Curve Cryptography )
* 
* \remarks
* ECC Public / Private Key 관련 헤더
* \author
* Copyright (c) 2017 by \<INITech\>
*/

#ifndef HEADER_EC_H
#define HEADER_EC_H

#ifdef NO_PKI
#error PKI is disabled.
#endif

#include <inicrypto/foundation.h>

#include "asn1.h"
#include "asn1_objects.h"
#include "x509.h"


#ifdef  __cplusplus
extern "C" {
#endif

#define UNUSED_TYPE				-1

#define CHARACTERISTIC_GNB		0
#define CHARACTERISTIC_TPB		1
#define CHARACTERISTIC_PPB		2

#define FIELDID_PRIME			0
#define FIELDID_CHARACTERISTIC	1

#define ALGOR_NAMED_CURVE		0
#define ALGOR_ECPARAMETERS		1

#define TYPE_X509_PUBKEY        0
#define TYPE_X509_PUBKEY_EX	    1

#define ECC_TYPE_ECDSA          0
#define ECC_TYPE_ECDH           1
#define ECC_TYPE_ECMQV          2


/*!
* \brief
*/
typedef struct ECC_curve_st
{
	OCTET_STRING        *a;            /*!< Elliptic curve coefficient a */
	OCTET_STRING        *b;            /*!< Elliptic curve coefficient b */
	BIT_STRING          *seed;         /*!< optional */
} ECC_CURVE;

/*!
* \brief
* Pentanomial basis representation of F2^m
* reduction polynomial integers k1, k2, k3
* f(x) - x**m + x**k3 + x**k2 + x**k1 + 1
*/
typedef struct ECC_pentanomial_st
{
	INTEGER             *k1;
	INTEGER             *k2;
	INTEGER             *k3;
} ECC_PENTANOMIAL;

/*!
* \brief
* X9.62 표준문서에서는 3가지의 basis type을 지원한다.
* gnBasis	, GNB			( 1.2.840.10045.1.2.3.1 )
* tpBasis, TPB				( 1.2.840.10045.1.2.3.2 ) -> Used parameters.trinomail 
* ppBasis	, PPB			( 1.2.840.10045.1.2.3.3 ) -> Used parameters.pentanomial
*/
typedef struct ECC_characteristic_two_st
{
	int                 type;              /*!< 0: GNB, 1 : TPB, 2: PPB */
	INTEGER             *m;            	   /*!< degredd of the field, Field size 2^m */
	OBJECT_IDENTIFIER   *basis;            /*!< the type of representation used (GNB, TPB, PPB) */
	union{                                 /*!< the values associated with each characteristic two basis type */
		NULL_VALUE                          *gnb;         /*!< */
		INTEGER                             *trinomial;   /*!< f(x) = xm + xk +1 */
		struct ECC_pentanomial_st   *pentanomial; /*!< f(x) - x**m + x**k3 + x**k2 + x**k1 + 1 */
	} parameters;
} ECC_CHARACTERISTIC_TWO;

/*!
* \brief
* Finite field
* X9.62 표준문서에서는 2가지 (prime-field, characteristic-two-field)의 field-type이 정의 됨
* prime-filed 				( 1.2.840.10045.1.1 ) -> Used parameters.prime_p
* characteristic-two-field	( 1.2.840.10045.1.2 ) -> Used parameters.characteristic_two
*/
typedef struct ECC_fieldid_st
{
	int                 type;                                               /*!< 0: prime, 1 :characteristic */
	OBJECT_IDENTIFIER   *fieldtype;
	union{
		INTEGER                                     *prime_p;				/*!< Field size p */		
		struct ECC_characteristic_two_st    *characteristic_two;	/*!< Field size 2^m */
	} parameters;
} ECC_FIELD_ID;

/*!
* \brief
*/
typedef struct ECC_ecparameters_st
{
	INTEGER                 *version;      /*!< specifies the version number of the elliptic curve domain parameters , ecpVer(1) */
	ECC_FIELD_ID            *field_id;     /*!< identifies the finite field over which the elliptic curve is defined. */
	ECC_CURVE               *curve;        /*!< specifies the coefficients a and b of the elliptic curve E. Each coefficient shall be represented as 
	                                                                             a value of the FieldElement. The Value seed is an optional parameter used to derive the 
	                                                                             coefficients of a randomly generated elliptic curve. */
	OCTET_STRING            *base;         /*!< specifies the base point G on the elliptic curve */
	INTEGER                 *order;        /*!< specifies the order n of the base point */
	INTEGER                 *cofactor;     /*!< cofactor is the integer h =#E(Fq)/n */
} ECC_ECPARAMETERS;


/*!
* \brief
* 참고) X509_ALGO_IDENTIFIER 으로 대처하는 방법도 고민해 봐야 한다. 
*/
typedef struct ECC_algorithm_st
{
	int                     type;                             /*!< 0: named curve, 1 : ec parameters */
	OBJECT_IDENTIFIER       *algorithm;                       /*!< */
	union{
		OBJECT_IDENTIFIER                  *named_curve;      /*!<  */
		struct ECC_ecparameters_st *ec_parameter;   /*!<  */		
	} parameters;
} ECC_ALGORITHM;

/*!
* \brief
* elliptic curve public key (Q)
*/
typedef struct pubkey_extension_st
{
	ECC_ALGORITHM        *algorithm;           /*!< */
	BIT_STRING           *public_key;          /*!< */
	ASYMMETRIC_KEY       *akey;                /*!< */
} PUBKEY_EX;

/*!
* \brief
* elliptic curve private key(d)
*/
typedef struct ECC_privatekey_st
{
	int                     type;                             /*!< 0: named curve, 1 : ec parameters */
	INTEGER                 *version;                         /*!<  ecPriKeyVer(1) */
	OCTET_STRING            *private_key;                     /*!<  */
	union{
		OBJECT_IDENTIFIER                  *named_curve;      /*!<  */
		struct ECC_ecparameters_st *ec_parameter;   /*!<  */
	} parameters;                                             /*!< OPTIONAL  [0] */
	BIT_STRING              *public_key;                      /*!< OPTIONAL  [1] */
} ECC_PRIKEY;



#ifndef WIN_INI_LOADLIBRARY_PKI

/*!
* \brief
* ECC_CURVE 구조체의 메모리 할당
* \returns
* ECC_CURVE 구조체 포인터
*/
ISC_API ECC_CURVE *new_ECC_Curve(void);

/*!
* \brief
* ECC_CURVE 구조체를 메모리 할당 해제
* \param st  [ IN ]
* 제거할 구조체
* \remarks
* 구조체를 제거(ISC_MEM_FREE)
*/
ISC_API void free_ECC_Curve(ECC_CURVE *curve);

/*!
* \brief
* ECC_CURVE 구조체의 초기화 함수
* \returns
* ECC_CURVE 구조체 포인터
*/
ISC_API ISC_STATUS check_ECC_Curve(ECC_CURVE *curve);

/*!
* \brief
* ECC_PENTANOMIAL 구조체의 메모리 할당
* \returns
* ECC_PENTANOMIAL 구조체 포인터
*/
ISC_API ECC_PENTANOMIAL *new_ECC_Pentanomial(void);

/*!
* \brief
* ECC_PENTANOMIAL 구조체를 메모리 할당 해제
* \param st  [ IN ]
* 제거할 구조체
* \remarks
* 구조체를 제거(ISC_MEM_FREE)
*/
ISC_API void free_ECC_Pentanomial(ECC_PENTANOMIAL *pentanomial);

/*!
* \brief
* ECC_PENTANOMIAL 구조체의 초기화 함수
* \returns
* ECC_PENTANOMIAL 구조체 포인터
*/
ISC_API ISC_STATUS check_ECC_Pentanomial(ECC_PENTANOMIAL *pentanomial);

/*!
* \brief
* ECC_CHARACTERISTIC_TWO 구조체의 메모리 할당
* \returns
* ECC_CHARACTERISTIC_TWO 구조체 포인터
*/
ISC_API ECC_CHARACTERISTIC_TWO *new_ECC_Characteristic_two(void);

/*!
* \brief
* ECC_CHARACTERISTIC_TWO 구조체를 메모리 할당 해제
* \param st  [ IN ]
* 제거할 구조체
* \remarks
* 구조체를 제거(ISC_MEM_FREE)
*/
ISC_API void free_ECC_Characteristic_two(ECC_CHARACTERISTIC_TWO *characteristic_two);

/*!
* \brief
* ECC_CHARACTERISTIC_TWO 구조체의 초기화 함수
* \returns
* ECC_CHARACTERISTIC_TWO 구조체 포인터
*/
ISC_API ISC_STATUS check_ECC_Characteristic_two(ECC_CHARACTERISTIC_TWO *characteristic_two);

/*!
* \brief
* ECC_FIELD_ID 구조체의 메모리 할당
* \returns
* ECC_PUBKEY 구조체 포인터
*/
ISC_API ECC_FIELD_ID *new_ECC_Fieldid(void);

/*!
* \brief
* ECC_FIELD_ID 구조체를 메모리 할당 해제
* \param st  [ IN ]
* 제거할 구조체
* \remarks
* 구조체를 제거(ISC_MEM_FREE)
*/
ISC_API void free_ECC_Fieldid(ECC_FIELD_ID *fieldid);

/*!
* \brief
* ECC_FIELD_ID 구조체의 초기화 함수
* \returns
* ECC_FIELD_ID 구조체 포인터
*/
ISC_API ISC_STATUS check_ECC_Fieldid(ECC_FIELD_ID *fieldid);

/*!
* \brief
* ECC_ECPARAMETERS 구조체의 메모리 할당
* \returns
* ECC_ECPARAMETERS 구조체 포인터
*/
ISC_API ECC_ECPARAMETERS *new_ECC_Parameter(void);

/*!
* \brief
* ECC_ECPARAMETERS 구조체를 메모리 할당 해제
* \param st  [ IN ]
* 제거할 구조체
* \remarks
* 구조체를 제거(ISC_MEM_FREE)
*/
ISC_API void free_ECC_Parameter(ECC_ECPARAMETERS *parameter);

/*!
* \brief
* ECC_ECPARAMETERS 구조체의 초기화 함수
* \returns
* ECC_ECPARAMETERS 구조체 포인터
*/
ISC_API ISC_STATUS check_ECC_Parameter(ECC_ECPARAMETERS *parameter);

/*!
* \brief
* ECC_ALGORITHM 구조체의 메모리 할당
* \returns
* ECC_ALGORITHM 구조체 포인터
*/
ISC_API ECC_ALGORITHM *new_ECC_Algorithm(void);

/*!
* \brief
* ECC_ALGORITHM 구조체를 메모리 할당 해제
* \param st  [ IN ]
* 제거할 구조체
* \remarks
* 구조체를 제거(ISC_MEM_FREE)
*/
ISC_API void free_ECC_Algorithm(ECC_ALGORITHM *algo);

/*!
* \brief
* ECC_ALGORITHM 구조체의 초기화 함수
* \returns
* ECC_ALGORITHM 구조체 포인터
*/
ISC_API ISC_STATUS check_ECC_Algorithm(ECC_ALGORITHM *algo);

/*!
* \brief
* PUBKEY_EX 구조체의 초기화 함수
* \returns
* PUBKEY_EX 구조체 포인터
*/
ISC_API PUBKEY_EX *new_PUBKEY_EX(void);

/*!
* \brief
* PUBKEY_EX 구조체를 메모리 할당 해제
* \param st  [ IN ]
* 제거할 구조체
* \remarks
* 구조체를 제거(ISC_MEM_FREE)
*/
ISC_API void free_PUBKEY_EX(PUBKEY_EX *ecc_pubkey);

/*!
* \brief
* ECC_PRIKEY 구조체의 초기화 함수
* \returns
* ECC_PUBKEY 구조체 포인터
*/
ISC_API ECC_PRIKEY *new_ECC_PRIKEY(void);

/*!
* \brief
* ECC_PRIKEY 구조체를 메모리 할당 해제
* \param st  [ IN ]
* 제거할 구조체
* \remarks
* 구조체를 제거(ISC_MEM_FREE)
*/
ISC_API void free_ECC_PRIKEY(ECC_PRIKEY *ecc_prikey);

/*!
* \brief
* ECC_CURVE 구조체를 Sequence로 Encode 함수
* \param st [ IN ]
* ECC_CURVE 구조체
* \param seq [ OUT ]
* Encoding Sequence 구조체
* \returns
* -# ISC_SUCCESS : 성공
*/
ISC_API ISC_STATUS ECC_CURVE_to_Seq(ECC_CURVE *curve, SEQUENCE **seq);

/*!
* \brief
* Sequence를 ECC_CURVE 구조체로 Decode 함수
* \param seq [ IN ]
* Decoding Sequece 구조체
* \param st [ OUT ]
* ECC_CURVE 구조체
* \returns
* -# ISC_SUCCESS : 성공
*/
ISC_API ISC_STATUS Seq_to_ECC_CURVE(SEQUENCE *seq, ECC_CURVE **curve);

/*!
* \brief
* ECC_PENTANOMIAL 구조체를 Sequence로 Encode 함수
* \param st [ IN ]
* ECC_PENTANOMIAL 구조체
* \param seq [ OUT ]
* Encoding Sequence 구조체
* \returns
* -# ISC_SUCCESS : 성공
*/
ISC_API ISC_STATUS ECC_PENTANOMIAL_to_Seq(ECC_PENTANOMIAL *pentanomial, SEQUENCE **seq);

/*!
* \brief
* Sequence를 ECC_PENTANOMIAL 구조체로 Decode 함수
* \param seq [ IN ]
* Decoding Sequece 구조체
* \param st [ OUT ]
* ECC_PENTANOMIAL 구조체
* \returns
* -# ISC_SUCCESS : 성공
*/
ISC_API ISC_STATUS Seq_to_ECC_PENTANOMIAL(SEQUENCE *seq, ECC_PENTANOMIAL **pentanomial);

/*!
* \brief
* ECC_CHARACTERISTIC_TWO 구조체를 Sequence로 Encode 함수
* \param st [ IN ]
* ECC_CHARACTERISTIC_TWO 구조체
* \param seq [ OUT ]
* Encoding Sequence 구조체
* \returns
* -# ISC_SUCCESS : 성공
*/
ISC_API ISC_STATUS ECC_CHARACTERISTIC_TWO_to_Seq(ECC_CHARACTERISTIC_TWO *charactristic, SEQUENCE **seq);

/*!
* \brief
* Sequence를 ECC_CHARACTERISTIC_TWO 구조체로 Decode 함수
* \param seq [ IN ]
* Decoding Sequece 구조체
* \param st [ OUT ]
* ECC_CHARACTERISTIC_TWO 구조체
* \returns
* -# ISC_SUCCESS : 성공
*/
ISC_API ISC_STATUS Seq_to_ECC_CHARACTERISTIC_TWO(SEQUENCE *seq, ECC_CHARACTERISTIC_TWO **charactristic);

/*!
* \brief
* ECC_FIELD_ID 구조체를 Sequence로 Encode 함수
* \param st [ IN ]
* ECC_FIELD_ID 구조체
* \param seq [ OUT ]
* Encoding Sequence 구조체
* \returns
* -# ISC_SUCCESS : 성공
*/
ISC_API ISC_STATUS ECC_FIELD_ID_to_Seq(ECC_FIELD_ID *fieldid, SEQUENCE **seq);

/*!
* \brief
* Sequence를 ECC_FIELD_ID 구조체로 Decode 함수
* \param seq [ IN ]
* Decoding Sequece 구조체
* \param st [ OUT ]
* ECC_FIELD_ID 구조체
* \returns
* -# ISC_SUCCESS : 성공
*/
ISC_API ISC_STATUS Seq_to_ECC_FIELD_ID(SEQUENCE *seq, ECC_FIELD_ID **fieldid);

/*!
* \brief
* ECC_ECPARAMETERS 구조체를 Sequence로 Encode 함수
* \param st [ IN ]
* ECC_ECPARAMETERS 구조체
* \param seq [ OUT ]
* Encoding Sequence 구조체
* \returns
* -# ISC_SUCCESS : 성공
*/
ISC_API ISC_STATUS ECC_PARAMETER_to_Seq(ECC_ECPARAMETERS *ec_param, SEQUENCE **seq);

/*!
* \brief
* Sequence를 ECC_ECPARAMETERS 구조체로 Decode 함수
* \param seq [ IN ]
* Decoding Sequece 구조체
* \param st [ OUT ]
* ECC_ECPARAMETERS 구조체
* \returns
* -# ISC_SUCCESS : 성공
*/
ISC_API ISC_STATUS Seq_to_ECC_PARAMETER(SEQUENCE *seq, ECC_ECPARAMETERS **ecparam);

/*!
* \brief
* ECC_ALGORITHM 구조체를 Sequence로 Encode 함수
* \param st [ IN ]
* ECC_ALGORITHM 구조체
* \param seq [ OUT ]
* Encoding Sequence 구조체
* \returns
* -# ISC_SUCCESS : 성공
*/
ISC_API ISC_STATUS ECC_ALGORITHM_to_Seq(ECC_ALGORITHM *algo, SEQUENCE **seq);

/*!
* \brief
* Sequence를 ECC_ALGORITHM 구조체로 Decode 함수
* \param seq [ IN ] 
* Decoding Sequece 구조체
* \param st [ OUT ]
* ECC_ALGORITHM 구조체
* \returns
* -# ISC_SUCCESS : 성공
*/
ISC_API ISC_STATUS Seq_to_ECC_ALGORITHM(SEQUENCE *seq, ECC_ALGORITHM **algo);

/*!
* \brief
* PUBKEY_EX 구조체를 Sequence로 Encode 함수
* \param st [ IN ]
* PUBKEY_EX 구조체
* \param seq [ OUT ]
* Encoding Sequence 구조체
* \returns
* -# ISC_SUCCESS : 성공
*/
ISC_API ISC_STATUS PUBKEY_EX_to_Seq(PUBKEY_EX *st, SEQUENCE **seq);

/*!
* \brief
* Sequence를 PUBKEY_EX 구조체로 Decode 함수
* \param seq [ IN ]
* Decoding Sequece 구조체
* \param st [ OUT ]
* PUBKEY_EX 구조체
* \returns
* -# ISC_SUCCESS : 성공
*/
ISC_API ISC_STATUS Seq_to_PUBKEY_EX(SEQUENCE *seq, PUBKEY_EX **st);

/*!
* \brief
* ECC_PRIKEY 구조체를 Sequence로 Encode 함수
* \param st [ IN ]
* ECC_PRIKEY 구조체
* \param seq [ OUT ]
* Encoding Sequence 구조체
* \returns
* -# ISC_SUCCESS : 성공
*/
ISC_API ISC_STATUS ECC_PRIKEY_to_Seq(ECC_PRIKEY *st, SEQUENCE **seq);

/*!
* \brief
* Sequence를 ECC_PRIKEY 구조체로 Decode 함수
* \param seq [ IN ]
* Decoding Sequece 구조체
* \param st [ OUT ]
* ECC_PRIKEY 구조체
* \returns
* -# ISC_SUCCESS : 성공
*/
ISC_API ISC_STATUS Seq_to_ECC_PRIKEY(SEQUENCE *seq, ECC_PRIKEY **st);

/*!
* \brief
* ECC_PRIKEY 구조체로부터 ISC_ECC_KEY_UNIT을 구하는 함수
* \param st [ IN ]
* ECC_PRIKEY 구조체
* \param st [ OUT ]
* ISC_ECC_KEY_UNIT 구조체
* \returns
* -# ISC_SUCCESS : 성공
*/
ISC_API ISC_STATUS get_ECC_UNIT_from_PRIVATE_KEY(ECC_PRIKEY *ecc_prikey, ISC_ECC_KEY_UNIT **ecc_unit);

/*!
* \brief
* ECC_PUBKEY 구조체로부터 ISC_ECC_KEY_UNIT을 구하는 함수
* \param st [ IN ]
* ECC_PUBKEY 구조체
* \param st [ OUT ]
* ISC_ECC_KEY_UNIT 구조체
* \returns
* -# ISC_SUCCESS : 성공
*/
ISC_API ISC_STATUS get_ECC_UNIT_from_PUBLIC_KEY(PUBKEY_EX *ecc_pubkey, ISC_ECC_KEY_UNIT **ecc_unit);

/*!
* \brief
* ISC_ECC_KEY_UNIT 구조체로부터 ECC_PRIKEY을 구하는 함수
* \param st [ IN ]
* ISC_ECC_KEY_UNIT 구조체
* \param out
* ECC_PRIKEY 구조체
* \returns
* -# ISC_SUCCESS : 성공
*/
ISC_API ISC_STATUS set_ECC_UNIT_to_PRIVATE_KEY(ISC_ECC_KEY_UNIT *ecc_unit, ECC_PRIKEY **ecc_prikey);

/*!
* \brief
* ISC_ECC_KEY_UNIT 구조체로부터 ECC_PUBKEY을 구하는 함수
* \param st [ IN ]
* ISC_ECC_KEY_UNIT 구조체
* \param int [ IN ]
* KEY Type (0:ECDSA, 1:ECDH, 2:ECMQV)
* \param out
* ECC_PUBKEY 구조체
* \returns
* -# ISC_SUCCESS : 성공
*/
ISC_API ISC_STATUS set_ECC_UNIT_to_PUBLIC_KEY(ISC_ECC_KEY_UNIT *ecc_unit, int key_type, PUBKEY_EX **ecc_pubkey);


#else
INI_RET_LOADLIB_PKI(ECC_CURVE*, new_ECC_Curve, (void), (), NULL);
INI_VOID_LOADLIB_PKI(void, free_ECC_Curve, (ECC_CURVE *curve), (curve) );
INI_RET_LOADLIB_PKI(ISC_STATUS, check_ECC_Curve, (ECC_CURVE *curve), (curve), ISC_FAIL);

INI_RET_LOADLIB_PKI(ECC_PENTANOMIAL*, new_ECC_Pentanomial, (void), (), NULL);
INI_VOID_LOADLIB_PKI(void, free_ECC_Pentanomial, (ECC_PENTANOMIAL *pentanomial), (pentanomial) );
INI_RET_LOADLIB_PKI(ISC_STATUS, check_ECC_Pentanomial, (ECC_PENTANOMIAL *pentanomial), (pentanomial), ISC_FAIL);

INI_RET_LOADLIB_PKI(ECC_CHARACTERISTIC_TWO*, new_ECC_Characteristic_two, (void), (), NULL);
INI_VOID_LOADLIB_PKI(void, free_ECC_Characteristic_two, (ECC_CHARACTERISTIC_TWO *characteristic_two), (characteristic_two) );
INI_RET_LOADLIB_PKI(ISC_STATUS, check_ECC_Characteristic_two, (ECC_CHARACTERISTIC_TWO *characteristic_two), (characteristic_two), ISC_FAIL);

INI_RET_LOADLIB_PKI(ECC_FIELD_ID*, new_ECC_Fieldid, (void), (), NULL);
INI_VOID_LOADLIB_PKI(void, free_ECC_Fieldid, (ECC_FIELD_ID *fieldid), (fieldid) );
INI_RET_LOADLIB_PKI(ISC_STATUS, check_ECC_Fieldid, (ECC_FIELD_ID *fieldid), (fieldid), ISC_FAIL);

INI_RET_LOADLIB_PKI(ECC_ECPARAMETERS*, new_ECC_Parameter, (void), (), NULL);
INI_VOID_LOADLIB_PKI(void, free_ECC_Parameter, (ECC_ECPARAMETERS *parameter), (parameter) );
INI_RET_LOADLIB_PKI(ISC_STATUS, check_ECC_Parameter, (ECC_ECPARAMETERS *parameter), (parameter), ISC_FAIL);

INI_RET_LOADLIB_PKI(ECC_ALGORITHM*, new_ECC_Algorithm, (void), (), NULL);
INI_VOID_LOADLIB_PKI(void, free_ECC_Algorithm, (ECC_ALGORITHM *algo), (algo) );
INI_RET_LOADLIB_PKI(ISC_STATUS, check_ECC_Algorithm, (ECC_ALGORITHM *algo), (algo), ISC_FAIL);

INI_RET_LOADLIB_PKI(PUBKEY_EX*, new_PUBKEY_EX, (void), (), NULL);
INI_VOID_LOADLIB_PKI(void, free_PUBKEY_EX, (PUBKEY_EX *ecc_pubkey), (ecc_pubkey) );


INI_RET_LOADLIB_PKI(ECC_PRIKEY*, new_ECC_PRIKEY, (void), (), NULL);
INI_VOID_LOADLIB_PKI(void, free_ECC_PRIKEY, (ECC_PRIKEY *ecc_prikey), (ecc_prikey) );


INI_RET_LOADLIB_PKI(ISC_STATUS, ECC_CURVE_to_Seq, (ECC_CURVE *curve, SEQUENCE **seq), (curve,seq), ISC_FAIL);
INI_RET_LOADLIB_PKI(ISC_STATUS, Seq_to_ECC_CURVE, (SEQUENCE *seq, ECC_CURVE **curve), (seq,curve), ISC_FAIL);

INI_RET_LOADLIB_PKI(ISC_STATUS, ECC_PENTANOMIAL_to_Seq, (ECC_PENTANOMIAL *pentanomial, SEQUENCE **seq), (pentanomial,seq), ISC_FAIL);
INI_RET_LOADLIB_PKI(ISC_STATUS, Seq_to_ECC_PENTANOMIAL, (SEQUENCE *seq, ECC_PENTANOMIAL **pentanomial), (seq,pentanomial), ISC_FAIL);

INI_RET_LOADLIB_PKI(ISC_STATUS, ECC_CHARACTERISTIC_TWO_to_Seq, (ECC_CHARACTERISTIC_TWO *charactristic, SEQUENCE **seq), (charactristic,seq), ISC_FAIL);
INI_RET_LOADLIB_PKI(ISC_STATUS, Seq_to_ECC_CHARACTERISTIC_TWO, (SEQUENCE *seq, ECC_CHARACTERISTIC_TWO **charactristic), (seq,charactristic), ISC_FAIL);

INI_RET_LOADLIB_PKI(ISC_STATUS, ECC_FIELD_ID_to_Seq, (ECC_FIELD_ID *fieldid, SEQUENCE **seq), (fieldid,seq), ISC_FAIL);
INI_RET_LOADLIB_PKI(ISC_STATUS, Seq_to_ECC_FIELD_ID, (SEQUENCE *seq, ECC_FIELD_ID **fieldid), (seq,fieldid), ISC_FAIL);

INI_RET_LOADLIB_PKI(ISC_STATUS, ECC_PARAMETER_to_Seq, (ECC_ECPARAMETERS *ec_param, SEQUENCE **seq), (ec_param,seq), ISC_FAIL);
INI_RET_LOADLIB_PKI(ISC_STATUS, Seq_to_ECC_PARAMETER, (SEQUENCE *seq, ECC_ECPARAMETERS **ecparam), (seq,ecparam), ISC_FAIL);

INI_RET_LOADLIB_PKI(ISC_STATUS, ECC_ALGORITHM_to_Seq, (ECC_ALGORITHM *algo, SEQUENCE **seq), (algo,seq), ISC_FAIL);
INI_RET_LOADLIB_PKI(ISC_STATUS, Seq_to_ECC_ALGORITHM, (SEQUENCE *seq, ECC_ALGORITHM **algo), (seq,algo), ISC_FAIL);

INI_RET_LOADLIB_PKI(ISC_STATUS, PUBKEY_EX_to_Seq, (PUBKEY_EX *st, SEQUENCE **seq), (st,seq), ISC_FAIL);
INI_RET_LOADLIB_PKI(ISC_STATUS, Seq_to_PUBKEY_EX, (SEQUENCE *seq, PUBKEY_EX **st), (seq,st), ISC_FAIL);

INI_RET_LOADLIB_PKI(ISC_STATUS, ECC_PRIKEY_to_Seq, (ECC_PRIKEY *st, SEQUENCE **seq), (st,seq), ISC_FAIL);
INI_RET_LOADLIB_PKI(ISC_STATUS, Seq_to_ECC_PRIKEY, (SEQUENCE *seq, ECC_PRIKEY **st), (seq,st), ISC_FAIL);


INI_RET_LOADLIB_PKI(ISC_STATUS, get_ECC_UNIT_from_PRIVATE_KEY, (ECC_PRIKEY *ecc_prikey, ISC_ECC_KEY_UNIT **ecc_unit), (ecc_prikey,ecc_unit), ISC_FAIL);
INI_RET_LOADLIB_PKI(ISC_STATUS, get_ECC_UNIT_from_PUBLIC_KEY, (PUBKEY_EX *ecc_pubkey, ISC_ECC_KEY_UNIT **ecc_unit), (ecc_pubkey,ecc_unit), ISC_FAIL);

INI_RET_LOADLIB_PKI(ISC_STATUS, set_ECC_UNIT_to_PRIVATE_KEY, (ISC_ECC_KEY_UNIT *ecc_unit, int is_named_curve, ECC_PRIKEY **ecc_prikey), (ecc_unit,is_named_curve,ecc_prikey), ISC_FAIL);
INI_RET_LOADLIB_PKI(ISC_STATUS, set_ECC_UNIT_to_PUBLIC_KEY, (ISC_ECC_KEY_UNIT *ecc_unit, int key_type, int is_named_curve, PUBKEY_EX **ecc_pubkey), (ecc_unit,key_type,is_named_curve,ecc_pubkey), ISC_FAIL);


#endif   /* #ifndef WIN_INI_LOADLIBRARY_PKI */

#ifdef  __cplusplus
}
#endif
#endif   /* #ifndef HEADER_EC_H */

