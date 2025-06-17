/*!
* \file ec.h
* \brief ECC ( Elliptic Curve Cryptography )
* 
* \remarks
* ECC Public / Private Key ���� ���
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
* X9.62 ǥ�ع��������� 3������ basis type�� �����Ѵ�.
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
* X9.62 ǥ�ع��������� 2���� (prime-field, characteristic-two-field)�� field-type�� ���� ��
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
* ����) X509_ALGO_IDENTIFIER ���� ��ó�ϴ� ����� ����� ���� �Ѵ�. 
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
* ECC_CURVE ����ü�� �޸� �Ҵ�
* \returns
* ECC_CURVE ����ü ������
*/
ISC_API ECC_CURVE *new_ECC_Curve(void);

/*!
* \brief
* ECC_CURVE ����ü�� �޸� �Ҵ� ����
* \param st  [ IN ]
* ������ ����ü
* \remarks
* ����ü�� ����(ISC_MEM_FREE)
*/
ISC_API void free_ECC_Curve(ECC_CURVE *curve);

/*!
* \brief
* ECC_CURVE ����ü�� �ʱ�ȭ �Լ�
* \returns
* ECC_CURVE ����ü ������
*/
ISC_API ISC_STATUS check_ECC_Curve(ECC_CURVE *curve);

/*!
* \brief
* ECC_PENTANOMIAL ����ü�� �޸� �Ҵ�
* \returns
* ECC_PENTANOMIAL ����ü ������
*/
ISC_API ECC_PENTANOMIAL *new_ECC_Pentanomial(void);

/*!
* \brief
* ECC_PENTANOMIAL ����ü�� �޸� �Ҵ� ����
* \param st  [ IN ]
* ������ ����ü
* \remarks
* ����ü�� ����(ISC_MEM_FREE)
*/
ISC_API void free_ECC_Pentanomial(ECC_PENTANOMIAL *pentanomial);

/*!
* \brief
* ECC_PENTANOMIAL ����ü�� �ʱ�ȭ �Լ�
* \returns
* ECC_PENTANOMIAL ����ü ������
*/
ISC_API ISC_STATUS check_ECC_Pentanomial(ECC_PENTANOMIAL *pentanomial);

/*!
* \brief
* ECC_CHARACTERISTIC_TWO ����ü�� �޸� �Ҵ�
* \returns
* ECC_CHARACTERISTIC_TWO ����ü ������
*/
ISC_API ECC_CHARACTERISTIC_TWO *new_ECC_Characteristic_two(void);

/*!
* \brief
* ECC_CHARACTERISTIC_TWO ����ü�� �޸� �Ҵ� ����
* \param st  [ IN ]
* ������ ����ü
* \remarks
* ����ü�� ����(ISC_MEM_FREE)
*/
ISC_API void free_ECC_Characteristic_two(ECC_CHARACTERISTIC_TWO *characteristic_two);

/*!
* \brief
* ECC_CHARACTERISTIC_TWO ����ü�� �ʱ�ȭ �Լ�
* \returns
* ECC_CHARACTERISTIC_TWO ����ü ������
*/
ISC_API ISC_STATUS check_ECC_Characteristic_two(ECC_CHARACTERISTIC_TWO *characteristic_two);

/*!
* \brief
* ECC_FIELD_ID ����ü�� �޸� �Ҵ�
* \returns
* ECC_PUBKEY ����ü ������
*/
ISC_API ECC_FIELD_ID *new_ECC_Fieldid(void);

/*!
* \brief
* ECC_FIELD_ID ����ü�� �޸� �Ҵ� ����
* \param st  [ IN ]
* ������ ����ü
* \remarks
* ����ü�� ����(ISC_MEM_FREE)
*/
ISC_API void free_ECC_Fieldid(ECC_FIELD_ID *fieldid);

/*!
* \brief
* ECC_FIELD_ID ����ü�� �ʱ�ȭ �Լ�
* \returns
* ECC_FIELD_ID ����ü ������
*/
ISC_API ISC_STATUS check_ECC_Fieldid(ECC_FIELD_ID *fieldid);

/*!
* \brief
* ECC_ECPARAMETERS ����ü�� �޸� �Ҵ�
* \returns
* ECC_ECPARAMETERS ����ü ������
*/
ISC_API ECC_ECPARAMETERS *new_ECC_Parameter(void);

/*!
* \brief
* ECC_ECPARAMETERS ����ü�� �޸� �Ҵ� ����
* \param st  [ IN ]
* ������ ����ü
* \remarks
* ����ü�� ����(ISC_MEM_FREE)
*/
ISC_API void free_ECC_Parameter(ECC_ECPARAMETERS *parameter);

/*!
* \brief
* ECC_ECPARAMETERS ����ü�� �ʱ�ȭ �Լ�
* \returns
* ECC_ECPARAMETERS ����ü ������
*/
ISC_API ISC_STATUS check_ECC_Parameter(ECC_ECPARAMETERS *parameter);

/*!
* \brief
* ECC_ALGORITHM ����ü�� �޸� �Ҵ�
* \returns
* ECC_ALGORITHM ����ü ������
*/
ISC_API ECC_ALGORITHM *new_ECC_Algorithm(void);

/*!
* \brief
* ECC_ALGORITHM ����ü�� �޸� �Ҵ� ����
* \param st  [ IN ]
* ������ ����ü
* \remarks
* ����ü�� ����(ISC_MEM_FREE)
*/
ISC_API void free_ECC_Algorithm(ECC_ALGORITHM *algo);

/*!
* \brief
* ECC_ALGORITHM ����ü�� �ʱ�ȭ �Լ�
* \returns
* ECC_ALGORITHM ����ü ������
*/
ISC_API ISC_STATUS check_ECC_Algorithm(ECC_ALGORITHM *algo);

/*!
* \brief
* PUBKEY_EX ����ü�� �ʱ�ȭ �Լ�
* \returns
* PUBKEY_EX ����ü ������
*/
ISC_API PUBKEY_EX *new_PUBKEY_EX(void);

/*!
* \brief
* PUBKEY_EX ����ü�� �޸� �Ҵ� ����
* \param st  [ IN ]
* ������ ����ü
* \remarks
* ����ü�� ����(ISC_MEM_FREE)
*/
ISC_API void free_PUBKEY_EX(PUBKEY_EX *ecc_pubkey);

/*!
* \brief
* ECC_PRIKEY ����ü�� �ʱ�ȭ �Լ�
* \returns
* ECC_PUBKEY ����ü ������
*/
ISC_API ECC_PRIKEY *new_ECC_PRIKEY(void);

/*!
* \brief
* ECC_PRIKEY ����ü�� �޸� �Ҵ� ����
* \param st  [ IN ]
* ������ ����ü
* \remarks
* ����ü�� ����(ISC_MEM_FREE)
*/
ISC_API void free_ECC_PRIKEY(ECC_PRIKEY *ecc_prikey);

/*!
* \brief
* ECC_CURVE ����ü�� Sequence�� Encode �Լ�
* \param st [ IN ]
* ECC_CURVE ����ü
* \param seq [ OUT ]
* Encoding Sequence ����ü
* \returns
* -# ISC_SUCCESS : ����
*/
ISC_API ISC_STATUS ECC_CURVE_to_Seq(ECC_CURVE *curve, SEQUENCE **seq);

/*!
* \brief
* Sequence�� ECC_CURVE ����ü�� Decode �Լ�
* \param seq [ IN ]
* Decoding Sequece ����ü
* \param st [ OUT ]
* ECC_CURVE ����ü
* \returns
* -# ISC_SUCCESS : ����
*/
ISC_API ISC_STATUS Seq_to_ECC_CURVE(SEQUENCE *seq, ECC_CURVE **curve);

/*!
* \brief
* ECC_PENTANOMIAL ����ü�� Sequence�� Encode �Լ�
* \param st [ IN ]
* ECC_PENTANOMIAL ����ü
* \param seq [ OUT ]
* Encoding Sequence ����ü
* \returns
* -# ISC_SUCCESS : ����
*/
ISC_API ISC_STATUS ECC_PENTANOMIAL_to_Seq(ECC_PENTANOMIAL *pentanomial, SEQUENCE **seq);

/*!
* \brief
* Sequence�� ECC_PENTANOMIAL ����ü�� Decode �Լ�
* \param seq [ IN ]
* Decoding Sequece ����ü
* \param st [ OUT ]
* ECC_PENTANOMIAL ����ü
* \returns
* -# ISC_SUCCESS : ����
*/
ISC_API ISC_STATUS Seq_to_ECC_PENTANOMIAL(SEQUENCE *seq, ECC_PENTANOMIAL **pentanomial);

/*!
* \brief
* ECC_CHARACTERISTIC_TWO ����ü�� Sequence�� Encode �Լ�
* \param st [ IN ]
* ECC_CHARACTERISTIC_TWO ����ü
* \param seq [ OUT ]
* Encoding Sequence ����ü
* \returns
* -# ISC_SUCCESS : ����
*/
ISC_API ISC_STATUS ECC_CHARACTERISTIC_TWO_to_Seq(ECC_CHARACTERISTIC_TWO *charactristic, SEQUENCE **seq);

/*!
* \brief
* Sequence�� ECC_CHARACTERISTIC_TWO ����ü�� Decode �Լ�
* \param seq [ IN ]
* Decoding Sequece ����ü
* \param st [ OUT ]
* ECC_CHARACTERISTIC_TWO ����ü
* \returns
* -# ISC_SUCCESS : ����
*/
ISC_API ISC_STATUS Seq_to_ECC_CHARACTERISTIC_TWO(SEQUENCE *seq, ECC_CHARACTERISTIC_TWO **charactristic);

/*!
* \brief
* ECC_FIELD_ID ����ü�� Sequence�� Encode �Լ�
* \param st [ IN ]
* ECC_FIELD_ID ����ü
* \param seq [ OUT ]
* Encoding Sequence ����ü
* \returns
* -# ISC_SUCCESS : ����
*/
ISC_API ISC_STATUS ECC_FIELD_ID_to_Seq(ECC_FIELD_ID *fieldid, SEQUENCE **seq);

/*!
* \brief
* Sequence�� ECC_FIELD_ID ����ü�� Decode �Լ�
* \param seq [ IN ]
* Decoding Sequece ����ü
* \param st [ OUT ]
* ECC_FIELD_ID ����ü
* \returns
* -# ISC_SUCCESS : ����
*/
ISC_API ISC_STATUS Seq_to_ECC_FIELD_ID(SEQUENCE *seq, ECC_FIELD_ID **fieldid);

/*!
* \brief
* ECC_ECPARAMETERS ����ü�� Sequence�� Encode �Լ�
* \param st [ IN ]
* ECC_ECPARAMETERS ����ü
* \param seq [ OUT ]
* Encoding Sequence ����ü
* \returns
* -# ISC_SUCCESS : ����
*/
ISC_API ISC_STATUS ECC_PARAMETER_to_Seq(ECC_ECPARAMETERS *ec_param, SEQUENCE **seq);

/*!
* \brief
* Sequence�� ECC_ECPARAMETERS ����ü�� Decode �Լ�
* \param seq [ IN ]
* Decoding Sequece ����ü
* \param st [ OUT ]
* ECC_ECPARAMETERS ����ü
* \returns
* -# ISC_SUCCESS : ����
*/
ISC_API ISC_STATUS Seq_to_ECC_PARAMETER(SEQUENCE *seq, ECC_ECPARAMETERS **ecparam);

/*!
* \brief
* ECC_ALGORITHM ����ü�� Sequence�� Encode �Լ�
* \param st [ IN ]
* ECC_ALGORITHM ����ü
* \param seq [ OUT ]
* Encoding Sequence ����ü
* \returns
* -# ISC_SUCCESS : ����
*/
ISC_API ISC_STATUS ECC_ALGORITHM_to_Seq(ECC_ALGORITHM *algo, SEQUENCE **seq);

/*!
* \brief
* Sequence�� ECC_ALGORITHM ����ü�� Decode �Լ�
* \param seq [ IN ] 
* Decoding Sequece ����ü
* \param st [ OUT ]
* ECC_ALGORITHM ����ü
* \returns
* -# ISC_SUCCESS : ����
*/
ISC_API ISC_STATUS Seq_to_ECC_ALGORITHM(SEQUENCE *seq, ECC_ALGORITHM **algo);

/*!
* \brief
* PUBKEY_EX ����ü�� Sequence�� Encode �Լ�
* \param st [ IN ]
* PUBKEY_EX ����ü
* \param seq [ OUT ]
* Encoding Sequence ����ü
* \returns
* -# ISC_SUCCESS : ����
*/
ISC_API ISC_STATUS PUBKEY_EX_to_Seq(PUBKEY_EX *st, SEQUENCE **seq);

/*!
* \brief
* Sequence�� PUBKEY_EX ����ü�� Decode �Լ�
* \param seq [ IN ]
* Decoding Sequece ����ü
* \param st [ OUT ]
* PUBKEY_EX ����ü
* \returns
* -# ISC_SUCCESS : ����
*/
ISC_API ISC_STATUS Seq_to_PUBKEY_EX(SEQUENCE *seq, PUBKEY_EX **st);

/*!
* \brief
* ECC_PRIKEY ����ü�� Sequence�� Encode �Լ�
* \param st [ IN ]
* ECC_PRIKEY ����ü
* \param seq [ OUT ]
* Encoding Sequence ����ü
* \returns
* -# ISC_SUCCESS : ����
*/
ISC_API ISC_STATUS ECC_PRIKEY_to_Seq(ECC_PRIKEY *st, SEQUENCE **seq);

/*!
* \brief
* Sequence�� ECC_PRIKEY ����ü�� Decode �Լ�
* \param seq [ IN ]
* Decoding Sequece ����ü
* \param st [ OUT ]
* ECC_PRIKEY ����ü
* \returns
* -# ISC_SUCCESS : ����
*/
ISC_API ISC_STATUS Seq_to_ECC_PRIKEY(SEQUENCE *seq, ECC_PRIKEY **st);

/*!
* \brief
* ECC_PRIKEY ����ü�κ��� ISC_ECC_KEY_UNIT�� ���ϴ� �Լ�
* \param st [ IN ]
* ECC_PRIKEY ����ü
* \param st [ OUT ]
* ISC_ECC_KEY_UNIT ����ü
* \returns
* -# ISC_SUCCESS : ����
*/
ISC_API ISC_STATUS get_ECC_UNIT_from_PRIVATE_KEY(ECC_PRIKEY *ecc_prikey, ISC_ECC_KEY_UNIT **ecc_unit);

/*!
* \brief
* ECC_PUBKEY ����ü�κ��� ISC_ECC_KEY_UNIT�� ���ϴ� �Լ�
* \param st [ IN ]
* ECC_PUBKEY ����ü
* \param st [ OUT ]
* ISC_ECC_KEY_UNIT ����ü
* \returns
* -# ISC_SUCCESS : ����
*/
ISC_API ISC_STATUS get_ECC_UNIT_from_PUBLIC_KEY(PUBKEY_EX *ecc_pubkey, ISC_ECC_KEY_UNIT **ecc_unit);

/*!
* \brief
* ISC_ECC_KEY_UNIT ����ü�κ��� ECC_PRIKEY�� ���ϴ� �Լ�
* \param st [ IN ]
* ISC_ECC_KEY_UNIT ����ü
* \param out
* ECC_PRIKEY ����ü
* \returns
* -# ISC_SUCCESS : ����
*/
ISC_API ISC_STATUS set_ECC_UNIT_to_PRIVATE_KEY(ISC_ECC_KEY_UNIT *ecc_unit, ECC_PRIKEY **ecc_prikey);

/*!
* \brief
* ISC_ECC_KEY_UNIT ����ü�κ��� ECC_PUBKEY�� ���ϴ� �Լ�
* \param st [ IN ]
* ISC_ECC_KEY_UNIT ����ü
* \param int [ IN ]
* KEY Type (0:ECDSA, 1:ECDH, 2:ECMQV)
* \param out
* ECC_PUBKEY ����ü
* \returns
* -# ISC_SUCCESS : ����
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

