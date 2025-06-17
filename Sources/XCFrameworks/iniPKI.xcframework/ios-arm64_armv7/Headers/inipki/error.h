/*!
* \file error.h
* \brief 에러 처리에 관련된 내용을 담고 있는 헤더\n
* INICrypto의 에러 코드는 4바이트로 이루어져 있으며,\n
* 1 번째 바이트는 에러가 발생한 위치 / 2번째 바이트는 함수 /\n
* 3~4번째 바이트는 에러의 이유를 나타냄\n
* \author sungwook.jang@initech.com
* Copyright (c) 2008 by \<INITech\>
*/

#ifndef __PKI_ERROR_H__
#define __PKI_ERROR_H__

#include <inicrypto/types.h>

/*--------------------------------------------------------------*/
/*
 * 애러코드 범위
 *
 * inicrypto :	0x01000000 ~ 0x3FFFFFFF
 * inipki	 :	0x41000000 ~ 0x6FFFFFFF
 */
/*--------------------------------------------------------------*/

#define LF_MASK								0xFFFF0000	/*!< */

/*--------------------------------------------------------------*/
#ifdef L_ASN1
#undef L_ASN1
#endif
#define L_ASN1								0x41000000	/*!< */
#define F_SET_ASN1_STRING_VALUE				0x00010000  /*!< */
#define F_ASN1_STRING_TO_SEQ				0x00020000  /*!< */
#define F_CHECK_ASN1_TIME					0x00030000  /*!< */

/*--------------------------------------------------------------*/
#ifdef L_BER
#undef L_BER
#endif
#define L_BER								0x42000000	/*!< */
#define F_ENCODE_TO_BER_BOOLEAN				0x00010000	/*!< */
#define F_ENCODE_TO_BER_INTEGER				0x00020000	/*!< */
#define	F_ENCODE_TO_BER_BIT_STRING			0x00030000  /*!< */
#define F_ENCODE_TO_BER_NULL				0x00040000  /*!< */
#define	F_ENCODE_TO_BER_OBJECT_IDENTIFIER	0x00050000  /*!< */
#define F_ENCODE_TO_BER_UTC_TIME			0x00060000  /*!< */
#define F_ENCODE_TO_BER_TIME                0x00070000 
#define F_ENCODE_TO_BER_ASN1_STRING			0x00080000  /*!< */
#define F_ENCODE_TO_BER						0x00090000  /*!< */
#define F_ENCODE_TO_BER_CS					0x000A0000  /*!< */
#define F_ADD_TO_BER_SEQUENCE				0x000B0000  /*!< */
#define F_ADD_TO_BER_SEQUENCE_OF			0x000C0000  /*!< */
#define F_ADD_TO_BER_SET					0x000D0000  /*!< */
#define F_ADD_TO_BER_SET_OF					0x000E0000  /*!< */
#define	F_ADD_TO_BER_SEQUENCE_CS			0x000F0000  /*!< */
#define F_SET_BER_LENGTH_FORM				0x00100000  /*!< */
#define F_ADD_TO_BER_STRING_SEQUENCE		0x00110000  /*!< */
#define F_ADD_PAD_TO_BER_BIT_STRING			0x00120000  /*!< */

/*--------------------------------------------------------------*/
#ifdef L_DER
#undef L_DER
#endif
#define	L_DER								0x43000000	/*!< */
#define F_CHECK_DER							0x00010000	/*!< */
#define F_ENCODE_TO_DER						0x00020000	/*!< */
#define	F_ENCODE_TO_DER_CS					0x00030000  /*!< */
#define F_ADD_TO_DER_SEQUENCE				0x00040000  /*!< */
#define F_ADD_TO_DER_SEQUENCE_OF			0x00050000  /*!< */
#define F_ADD_TO_DER_SET					0x00060000  /*!< */
#define F_ADD_TO_DER_SET_OF					0x00070000  /*!< */
#define F_ADD_TO_DER_SEQUENCE_CS			0x00080000  /*!< */

/*--------------------------------------------------------------*/
#ifdef L_UTC_TIME
#undef L_UTC_TIME
#endif
#define L_UTC_TIME							0x44000000  /*!< */

/*--------------------------------------------------------------*/
#ifdef L_TIME
#undef L_TIME
#endif
#define L_TIME                              0x45000000  /*!< */
#define F_ADD_UTC_TIME						0x00010000  /*!< */
#define F_ADD_TIME							0x00020000  /*!< */

/*--------------------------------------------------------------*/
#ifdef L_X509
#undef L_X509
#endif
#define L_X509								0x46000000	/*!< */
#define F_SET_X509_VERSION					0x00010000	/*!< */
#define F_SET_X509_SERIAL					0x00020000	/*!< */
#define F_SET_X509_SIGNATURE				0x00030000	/*!< */
#define F_SET_X509_ISSUER					0x00040000	/*!< */
#define F_SET_X509_SUBJECT					0x00050000	/*!< */
#define F_SET_X509_NOTAFTER					0x00060000	/*!< */
#define F_SET_X509_NOTBEFORE				0x00070000	/*!< */
#define F_SET_X509_PUB_KEY					0x00080000	/*!< */
#define F_BITSTRING_to_RSA_KEY				0x00090000	/*!< */
#define F_RSA_KEY_to_BITSTRING				0x000A0000	/*!< */
#define F_BITSTRING_to_KCDSA_KEY			0x000B0000	/*!< */
#define F_KCDSA_KEY_to_BITSTRING			0x000C0000	/*!< */
#define F_KCDSA_KEY_to_Seq					0x000D0000	/*!< */
#define F_Seq_to_KCDSA_KEY					0x000E0000	/*!< */
#define F_SEQ_TO_X509_CERT					0x000F0000	/*!< */
#define F_X509_CERT_TO_SEQ					0x00100000	/*!< */
#define F_SEQ_TO_X509_TBS_CERT				0x00110000	/*!< */
#define F_X509_TBS_CERT_TO_SEQ				0x00120000	/*!< */
#define F_SEQ_TO_X509_PUBKEY				0x00130000	/*!< */
#define F_X509_PUBKEY_TO_SEQ				0x00140000	/*!< */
#define F_GEN_RSASIGN_TBS_CERT				0x00150000	/*!< */
#define F_GEN_KCDSASIGN_TBS_CERT			0x00160000	/*!< */
#define F_VERIFY_RSASIGN_TBS_CERT			0x00170000	/*!< */
#define F_VERIFY_KCDSASIGN_TBS_CERT			0x00180000	/*!< */
#define F_X509_EXT_TO_SEQ					0x00190000	/*!< */
#define F_SEQ_TO_X509_EXT					0x001A0000	/*!< */
#define F_X509_NAME_TO_SEQ					0x001B0000	/*!< */
#define F_SEQ_TO_X509_NAME					0x001C0000	/*!< */
#define F_X509_CERT_PAIR_TO_SEQ				0x001D0000	/*!< */
#define F_SEQ_TO_X509_CERT_PAIR				0x001E0000	/*!< */
#define F_X509_CERTIFICATES_TO_SEQ			0x001F0000	/*!< */
#define F_SEQ_TO_X509_CERTIFICATES			0x00200000	/*!< */
#define F_X509_ATTRIBUTE_TO_SEQ				0x00210000	/*!< */
#define F_SEQ_TO_X509_ATTRIBUTE				0x00220000	/*!< */
#define F_X509_ATTRIBUTES_TO_SEQ			0x00230000	/*!< */
#define F_SEQ_TO_X509_ATTRIBUTES			0x00240000	/*!< */
#define F_X509_ALGO_IDENTIFIER_TO_SEQ		0x00250000	/*!< */
#define F_SEQ_TO_X509_ALGO_IDENTIFIER		0x00260000	/*!< */
#define F_X509_ALGO_IDENTIFIERS_TO_SEQ		0x00270000	/*!< */
#define F_SEQ_TO_X509_ALGO_IDENTIFIERS		0x00280000	/*!< */
#define F_RSA_KEY_to_Seq					0x00290000	/*!< */
#define F_Seq_to_RSA_KEY					0x002A0000	/*!< */
#define F_VERIFY_X509_VALIDITY				0x002B0000	/*!< */
#define F_GEN_ECDSASIGN_TBS_CERT            0x00300000  /*!< */
#define F_VERIFY_ECDSASIGN_TBS_CERT         0x00310000  /*!< */
#define F_GEN_ECDSASIGN				0x00320000  /*!< */


/*--------------------------------------------------------------*/
#ifdef L_X509V3
#undef L_X509V3
#endif
#define L_X509V3							0x47000000	/*!< */
#define F_SEQ_TO_VID						0x00010000	/*!< */
#define F_VID_TO_SEQ						0x00020000	/*!< */
#define F_SEQ_TO_KISA_IDENTIFY_DATA			0x00030000	/*!< */
#define F_KISA_IDENTIFY_DATA_TO_SEQ			0x00040000	/*!< */
#define F_SEQ_TO_GENERAL_NAME				0x00050000	/*!< */
#define F_GENERAL_NAME_TO_SEQ				0x00060000	/*!< */
#define F_SEQ_TO_GENERAL_NAMES				0x00070000	/*!< */
#define F_GENERAL_NAMES_TO_SEQ				0x00080000	/*!< */
#define F_SEQ_TO_AUTHORITY_KEYID			0x00090000	/*!< */
#define F_AUTHORITY_KEYID_TO_SEQ			0x00100000	/*!< */
#define F_SEQ_TO_OTHERNAME					0x00110000	/*!< */
#define F_OTHERNAME_TO_SEQ					0x00120000	/*!< */
#define F_SEQ_TO_EDIPARTYNAME				0x00130000	/*!< */
#define F_EDIPARTYNAME_TO_SEQ				0x00140000	/*!< */
#define F_SEQ_TO_DIST_POINT					0x00150000	/*!< */
#define F_DIST_POINT_TO_SEQ					0x00160000	/*!< */
#define F_SEQ_TO_ISSUING_DIST_POINT			0x00170000	/*!< */
#define F_ISSUING_DIST_POINT_TO_SEQ			0x00180000	/*!< */
#define F_SEQ_TO_POLICY_MAPPING				0x00190000	/*!< */
#define F_POLICY_MAPPING_TO_SEQ				0x00200000	/*!< */
#define F_SEQ_TO_POLICY_MAPPINGS			0x00210000	/*!< */
#define F_POLICY_MAPPINGS_TO_SEQ			0x00220000	/*!< */
#define F_SEQ_TO_BASIC_CONSTRAINTS			0x00230000	/*!< */
#define F_BASIC_CONSTRAINTS_TO_SEQ			0x00240000	/*!< */
#define F_SEQ_TO_AUTHORITY_INFO_ACCESS		0x00250000	/*!< */
#define F_AUTHORITY_INFO_ACCESS_TO_SEQ		0x00260000	/*!< */
#define F_SEQ_TO_ISSUING_DIST_POINTS		0x00270000	/*!< */
#define F_ISSUING_DIST_POINTS_TO_SEQ		0x00280000	/*!< */
#define F_SEQ_TO_CERTIFICATE_POLICIES		0x00270000	/*!< */
#define F_CERTIFICATE_POLICIES_TO_SEQ		0x00280000	/*!< */
#define F_SEQ_TO_POLICY_INFO				0x00290000	/*!< */
#define F_POLICY_INFO_TO_SEQ				0x00300000	/*!< */
#define F_SEQ_TO_POLICY_QUALIFIERS			0x00310000	/*!< */
#define F_POLICY_QUALIFIERS_TO_SEQ			0x00320000	/*!< */
#define F_SEQ_TO_POLICY_QUALIFIER_INFO		0x00330000	/*!< */
#define F_POLICY_QUALIFIER_INFO_TO_SEQ		0x00340000	/*!< */
#define F_SEQ_TO_USER_NOTICE				0x00350000	/*!< */
#define F_USER_NOTICE_TO_SEQ				0x00360000	/*!< */
#define F_SEQ_TO_NOTICE_REFERENCE			0x00370000	/*!< */
#define F_NOTICE_REFERENCE_TO_SEQ			0x00380000	/*!< */
#define F_SEQ_TO_NOTICE_NUMBERS				0x00390000	/*!< */
#define F_NOTICE_NUMBERS_TO_SEQ				0x00400000	/*!< */
#define F_SEQ_TO_CRL_DIST_POINTS			0x00410000	/*!< */
#define F_CRL_DIST_POINTS_TO_SEQ			0x00420000	/*!< */
#define F_SEQ_TO_ACCESS_DESCRIPTION			0x00430000	/*!< */
#define F_ACCESS_DESCRIPTION_TO_SEQ			0x00440000	/*!< */
#define F_SEQ_TO_POLICY_CONSTRAINTS			0x00450000	/*!< */
#define F_POLICY_CONSTRAINTS_TO_SEQ			0x00460000	/*!< */
#define F_SEQ_TO_GENERAL_SUBTREE			0x00470000	/*!< */
#define F_GENERAL_SUBTREE_TO_SEQ			0x00480000	/*!< */
#define F_SEQ_TO_GENERAL_SUBTREES			0x00490000	/*!< */
#define F_GENERAL_SUBTREES_TO_SEQ			0x00500000	/*!< */
#define F_SEQ_TO_NAME_CONSTRAINTS			0x00510000	/*!< */
#define F_NAME_CONSTRAINTS_TO_SEQ			0x00520000	/*!< */
#define F_SEQ_TO_X509_SIGN				0x00530000	/*!< */
#define F_X509_SIGN_TO_SEQ				0x00540000	/*!< */
#define F_CHECK_VID					0x00550000	/*!< */
#define F_SEQ_TO_SUBJECT_INFO_ACCESS			0x00560000	/*!< */
#define F_SUBJECT_INFO_ACCESS_TO_SEQ			0x00570000	/*!< */
#define F_SEQ_TO_ALT_NAME				0x00580000	/*!< */
#define F_ALT_NAME_TO_SEQ				0x00590000	/*!< */
/*--------------------------------------------------------------*/
#ifdef L_X509_CRL
#undef L_X509_CRL
#endif
#define L_X509_CRL							0x48000000	/*!< */
#define F_X509_CRL_TO_SEQ					0x00010000	/*!< */
#define F_SEQ_TO_X509_CRL					0x00020000	/*!< */
#define F_X509_CRLINFO_TO_SEQ				0x00030000	/*!< */
#define F_SEQ_TO_X509_CRLINFO				0x00040000	/*!< */
#define F_GEN_RSASIGN						0x00050000	/*!< */
#define F_VERIFY_RSASIGN					0x00060000	/*!< */
#define F_GEN_KCDSASIGN						0x00070000	/*!< */
#define F_VERIFY_KCDSASIGN					0x00080000	/*!< */
#define F_SEQ_TO_X509_REVOKED               0x00090000  /*!< */
#define F_X509_REVOKED_TO_SEQ				0x00100000	/*!< */
#define F_X509_CRLS_TO_SEQ					0x00110000	/*!< */
#define F_SEQ_TO_X509_CRLS					0x00120000	/*!< */
#define F_VERIFY_ECDSASIGN                  0x00130000  /*!< */

/*--------------------------------------------------------------*/
#ifdef L_PKCS1
#undef L_PKCS1
#endif
#define L_PKCS1									0x49000000	/*!< */
#define F_P1_ENCRYPTED_KEY_TO_SEQ				0x00010000	/*!< */
#define F_SEQ_TO_P1_ENCRYPTED_KEY				0x00020000	/*!< */
#define F_SEQ_TO_P1_PRIV_KEY_INFO          		0x00030000  /*!< */
#define F_P1_PRIV_KEY_INFO_TO_SEQ				0x00040000	/*!< */
#define F_SEQ_TO_P5_PBE_PARAM					0x00050000  /*!< */
#define F_P5_PBE_PARAM_TO_SEQ					0x00060000	/*!< */
#define F_P1_PUB_KEY_INFO_TO_SEQ				0x00070000	/*!< */
#define F_SEQ_TO_P1_PUB_KEY_INFO				0x00080000	/*!< */
#define F_SET_RSA_UNIT_TO_P1_PRIV_KEY			0x00090000	/*!< */
#define F_SET_RSA_UNIT_TO_P1_PUB_KEY			0x000A0000	/*!< */
#define F_GET_RSA_UNIT_FROM_PRIV_KEY			0x000B0000	/*!< */
#define F_GET_RSA_UNIT_FROM_PUB_KEY				0x000C0000	/*!< */
#define F_SET_RSAES_OAEP_PARAM_HASHALGORITHM	0x000D0000	/*!< */
#define F_SET_RSAES_OAEP_PARAM_MASKGENALGORITHM	0x000E0000	/*!< */
#define F_SET_RSAES_OAEP_PARAM_PSOURCEALGORITHM	0x000F0000	/*!< */
#define F_RSAES_OAEP_PARAM_TO_SEQ				0x00100000	/*!< */
#define F_SEQ_TO_RSAES_OAEP_PARAM				0x00110000	/*!< */
#define F_SET_RSASSA_PSS_PARAM_HASHALGORITHM	0x00120000	/*!< */
#define F_SET_RSASSA_PSS_PARAM_MASKGENALGORITHM	0x00130000	/*!< */
#define F_SET_RSASSA_PSS_PARAM_TRAILERFIELD		0x00140000	/*!< */
#define F_RSASSA_PSS_PARAM_TO_SEQ				0x00150000	/*!< */
#define F_SEQ_TO_RSASSA_PSS_PARAM				0x00160000	/*!< */

/*--------------------------------------------------------------*/
#ifdef L_PKCS5
#undef L_PKCS5
#endif
#define L_PKCS5								0x4A000000	/*!< */
#define F_ENCRYPT_PBES1						0x00010000	/*!< */
#define F_DECRYPT_PBES1						0x00020000	/*!< */
#define F_PBKDF								0x00030000	/*!< */
#define F_PBKDF1							0x00040000	/*!< */
#define F_PBKDF2							0x00050000	/*!< */
#define F_ENC_PKCS5							0x00060000	/*!< */
#define F_DEC_PKCS5							0x00070000	/*!< */
#define F_ENC_PBES1_KISA					0x00080000	/*!< */
#define F_DEC_PBES1_KISA					0x00090000	/*!< */
#define F_ENCRYPT_PBES2						0x00100000	/*!< */
#define F_DECRYPT_PBES2						0x00110000	/*!< */
#define F_ENC_PBES1_GPKI					0x00120000	/*!< */
#define F_DEC_PBES1_GPKI					0x00130000	/*!< */

/*--------------------------------------------------------------*/
#ifdef L_PKCS7
#undef L_PKCS7
#endif
#define L_PKCS7								0x4B000000	/*!< */
#define F_P7_IS_AND_SN_TO_SEQ				0x00010000  /*!< */
#define F_SEQ_TO_P7_IS_AND_SN				0x00020000  /*!< */
#define F_P7_SIGNER_INFO_TO_SEQ				0x00030000  /*!< */
#define F_SEQ_TO_P7_SIGNER_INFO				0x00040000  /*!< */
#define F_P7_DIGEST_INFO_TO_SEQ				0x00050000  /*!< */
#define F_SEQ_TO_P7_DIGEST_INFO				0x00060000  /*!< */
#define F_P7_SIGNER_INFOS_TO_SEQ			0x00070000  /*!< */
#define F_SEQ_TO_P7_SIGNER_INFOS			0x00080000  /*!< */
#define F_P7_SIGNED_DATA_TO_SEQ				0x00090000  /*!< */
#define F_SEQ_TO_P7_SIGNED_DATA				0x000A0000  /*!< */
#define F_P7_RECIPIENT_INFO_TO_SEQ			0x000B0000  /*!< */
#define F_SEQ_TO_P7_RECIPIENT_INFO			0x000C0000  /*!< */
#define F_P7_RECIPIENT_INFOS_TO_SEQ			0x000D0000  /*!< */
#define F_SEQ_TO_P7_RECIPIENT_INFOS			0x000E0000	/*!< */
#define F_P7_ENCRYPTED_CONTENT_INFO_TO_SEQ  0x000F0000  /*!< */
#define F_SEQ_TO_P7_ENCRYPTED_CONTENT_INFO	0x00100000  /*!< */
#define F_P7_ENVELOPED_DATA_TO_SEQ			0x00110000  /*!< */
#define F_SEQ_TO_P7_ENVELOPED_DATA			0x00120000	/*!< */
#define F_P7_SIG_AND_ENV_DATA_TO_SEQ		0x00130000  /*!< */
#define F_SEQ_TO_P7_SIG_AND_ENV_DATA		0x00140000  /*!< */
#define F_P7_DIGESTED_DATA_TO_SEQ			0x00150000	/*!< */
#define F_SEQ_TO_P7_DIGESTED_DATA			0x00160000  /*!< */
#define F_P7_ENCRYPTED_DATA_TO_SEQ			0x00170000	/*!< */
#define F_SEQ_TO_P7_ENCRYPTED_DATA			0x00180000	/*!< */
#define F_P7_CONTENT_INFO_TO_SEQ			0x00190000	/*!< */
#define F_SEQ_TO_P7_CONTENT_INFO			0x001A0000	/*!< */
#define F_P7_VERIFY							0x001B0000	/*!< */
#define F_P7_SIGN							0x001C0000	/*!< */
#define F_GET_PKCS7_DATA					0x001D0000  /*!< */
#define F_SET_PKCS7_P7_SIGNER_INFO			0x001E0000  /*!< */
#define F_SET_PKCS7_P7_RECIPIENT_INFO		0x001F0000  /*!< */
#define F_P7_ENCRYPT						0x00200000  /*!< */

/*--------------------------------------------------------------*/
#ifdef L_PKCS8
#undef L_PKCS8
#endif
#define L_PKCS8								0x4C000000	/*!< */
#define F_P8_ENCRYPTED_KEY_TO_SEQ			0x00010000	/*!< */
#define F_SEQ_TO_P8_ENCRYPTED_KEY			0x00020000	/*!< */
#define F_SEQ_TO_P8_PRIV_KEY_INFO			0x00030000  /*!< */
#define F_P8_PRIV_KEY_INFO_TO_SEQ			0x00040000	/*!< */

/*--------------------------------------------------------------*/
#ifdef L_PKCS12
#undef L_PKCS12
#endif
#define L_PKCS12							0x4D000000	/*!< */
#define F_X509_CERT_TO_CERTBAG				0x00010000	/*!< */
#define F_CERTBAG_TO_X509_CERT				0x00020000	/*!< */
#define F_P12_SAFEBAGS_TO_SEQ				0x00030000	/*!< */
#define F_SEQ_TO_P12_SAFEBAGS				0x00040000	/*!< */
#define F_P12_SAFEBAG_TO_SEQ				0x00050000	/*!< */
#define F_SEQ_TO_P12_SAFEBAG				0x00060000	/*!< */
#define F_P12_BAGS_TO_SEQ					0x00070000	/*!< */
#define F_SEQ_TO_P12_BAGS					0x00080000	/*!< */
#define F_P12_MAC_DATA_TO_SEQ				0x00090000	/*!< */
#define F_SEQ_TO_P12_MAC_DATA				0x000A0000	/*!< */
#define F_P12_PFX_TO_SEQ					0x000B0000	/*!< */
#define F_SEQ_TO_P12_PFX					0x000C0000	/*!< */
#define F_SEQ_TO_P12_AUTH_SAFE				0x000D0000	/*!< */
#define F_P12_AUTH_SAFE_TO_SEQ				0x000E0000	/*!< */
#define F_IMPORT_PKCS12						0x000F0000	/*!< */
#define F_PKCS12_ADD_SAFE					0x00100000	/*!< */
#define F_SET_PKCS12_MAC					0x00110000	/*!< */
#define F_ADD_PKCS12_BAG					0x00120000	/*!< */

/*--------------------------------------------------------------*/
#ifdef L_PEM
#undef L_PEM
#endif
#define L_PEM								0x4E000000	/*!< */
/*--------------------------------------------------------------*/
#ifdef L_GPKI
#undef L_GPKI
#endif
#define L_GPKI								0x4F000000	/*!< */
/*--------------------------------------------------------------*/
#ifdef L_GENERALIZED_TIME
#undef L_GENERALIZED_TIME
#endif
#define L_GENERALIZED_TIME					0x50000000	/*!< */

/*--------------------------------------------------------------*/
#ifdef L_ISSUER_AND_SERIAL_NUMBER
#undef L_ISSUER_AND_SERIAL_NUMBER
#endif
#define L_ISSUER_AND_SERIAL_NUMBER			0x51000000  /*!< */
#define F_ISSUER_AND_SERIAL_NUMBER_TO_SEQ	0x00010000  /*!< */
#define F_SEQ_TO_ISSUER_AND_SERIAL_NUMBER	0x00020000  /*!< */


/*--------------------------------------------------------------*/
#ifdef L_CMS
#undef L_CMS
#endif
#define L_CMS								0x52000000  /*!< */
#define F_SET_CMS_TYPE						0x00010000  /*!< */
#define F_SET_CMS_SIGNER_INFO				0x00020000  /*!< */
#define F_SET_CMS_VERSION					0x00030000  /*!< */
#define F_SET_ENCAPSULATED_CONTENT_INFO		0x00040000  /*!< */
#define F_SET_CMS_CIPHER					0x00050000  /*!< */
#define F_SET_CMS_ENCRYPTED_CONTENT_INFO	0x00060000  /*!< */
#define F_SET_CMS_RECIPIENT_INFO			0x00070000  /*!< */
#define F_SET_CMS_CONTENT					0x00080000  /*!< */
#define F_SET_CMS_MACALGORITHM				0x00090000  /*!< */
#define F_SET_CMS_DIGESTALGORITHM			0x000A0000  /*!< */
#define F_SET_CMS_MAC						0x000B0000  /*!< */
#define F_ADD_CMS_SIGNER					0x00110000  /*!< */
#define F_ADD_CMS_SIGNATURE					0x00120000  /*!< */
#define F_ADD_CMS_CERTIFICATE				0x00130000  /*!< */
#define F_ADD_CMS_CRL						0x00140000  /*!< */
#define F_ADD_CMS_RECIPIENT_INFO			0x00150000  /*!< */
#define F_ADD_ATTRIBUTE						0x00160000  /*!< */
#define F_INIT_CMS_SIGN						0x00170000  /*!< */
#define F_UPDATE_CMS_SIGN					0x00180000  /*!< */
#define F_FINAL_CMS_SIGN					0x00190000  /*!< */
#define F_ADD_CMS_ORIGINATOR_CERTIFICATE	0x001A0000  /*!< */
#define F_ADD_CMS_ORIGINATOR_CRL			0x001B0000  /*!< */
#define F_ADD_CMS_UNPROTECTED_ATTRIBUTE		0x001C0000  /*!< */
#define F_ADD_CMS_AUTHENTICATED_ATTRIBUTE	0x001D0000  /*!< */
#define F_ADD_CMS_UNAUTHENTICATED_ATTRIBUTE	0x001E0000  /*!< */
#define F_VERIFY_CMS						0x00210000  /*!< */
#define F_DIGEST_CMS						0x00220000  /*!< */
#define F_ENCRYPT_CMS						0x00230000  /*!< */
#define F_DECRYPT_CMS						0x00240000  /*!< */
#define F_INIT_CMS_ENCRYPT					0x00250000  /*!< */
#define F_UPDATE_CMS_ENCRYPT				0x00260000  /*!< */
#define F_FINAL_CMS_ENCRYPT					0x00270000  /*!< */
#define F_DECRYPT_CONTENT_ENCRYPTION_KEY	0x00280000  /*!< */
#define F_CMS_SIGNER_INFO_TO_SEQ			0x00310000  /*!< */
#define F_SEQ_TO_CMS_SIGNER_INFO			0x00320000  /*!< */
#define F_CMS_SIGNER_INFOS_TO_SEQ			0x00330000  /*!< */
#define F_SEQ_TO_CMS_SIGNER_INFOS			0x00340000  /*!< */
#define F_CMS_SIGNED_DATA_TO_SEQ			0x00350000  /*!< */
#define F_SEQ_TO_CMS_SIGNED_DATA			0x00360000  /*!< */
#define F_CMS_ENVELOPED_DATA_TO_SEQ			0x00370000  /*!< */
#define F_SEQ_TO_CMS_ENVELOPED_DATA			0x00380000  /*!< */
#define F_CMS_RECIPIENT_INFO_TO_SEQ			0x00390000  /*!< */
#define F_SEQ_TO_CMS_RECIPIENT_INFO			0x00400000  /*!< */
#define F_CMS_RECIPIENT_INFOS_TO_SEQ		0x00410000  /*!< */
#define F_SEQ_TO_CMS_RECIPIENT_INFOS		0x00420000  /*!< */
#define F_CMS_ENCRYPTED_DATA_TO_SEQ			0x00430000  /*!< */
#define F_SEQ_TO_CMS_ENCRYPTED_DATA			0x00440000  /*!< */
#define F_ENCAPSULATED_CONTENT_INFO_TO_SEQ	0x00450000  /*!< */
#define F_SEQ_TO_ENCAPSULATED_CONTENT_INFO	0x00460000  /*!< */
#define F_CMS_CONTENT_INFO_TO_SEQ			0x00470000  /*!< */
#define F_SEQ_TO_CMS_CONTENT_INFO			0x00480000  /*!< */
#define F_CMS_ENCRYPTED_CONTENT_INFO_TO_SEQ	0x00490000  /*!< */
#define F_SEQ_TO_CMS_ENCRYPTED_CONTENT_INFO	0x004A0000  /*!< */
#define F_CMS_DIGESTED_DATA_TO_SEQ			0x00510000  /*!< */
#define F_SEQ_TO_CMS_DIGESTED_DATA			0x00520000  /*!< */
#define F_CMS_AUTHENTICATED_DATA_TO_SEQ		0x00530000  /*!< */
#define F_SEQ_TO_CMS_AUTHENTICATED_DATA		0x00540000  /*!< */
#define F_CMS_ORIGINATOR_INFO_TO_SEQ		0x00550000  /*!< */
#define F_SEQ_TO_CMS_ORIGINATOR_INFO		0x00560000  /*!< */
#define F_SET_CMS_ISSUERANDSERIALNUMBER		0x00570000  /*!< */
#define F_SET_CMS_SUBJECTKEYIDENTIFIER		0x00580000  /*!< */
#define F_SET_CMS_ORIGINATORPUBLICKKEY		0x00590000  /*!< */
#define F_ENCRYPT_CMS_RECIPIENTINFO			0x005A0000  /*!< */
#define F_INIT_CMS_ENCRYPT_RECIPIENTINFO	0x005B0000  /*!< */


/*--------------------------------------------------------------*/
#ifdef L_CPV
#undef L_CPV
#endif
#define L_CPV								0x53000000  /*!< */
#define F_ADD_CERTLIST						0x00010000  /*!< */
#define F_ADD_TRUSTLIST						0x00020000  /*!< */
#define F_TRUST_ANCHOR_TO_SEQ				0x00030000  /*!< */
#define F_SEQ_TO_TRUST_ANCHOR				0x00040000  /*!< */
#define F_BUILD_CERTPATH					0x00050000  /*!< */
#define F_ADD_CERTPATHLIST					0x00060000  /*!< */
#define F_VALIDATE_CERTPATH					0x00070000  /*!< */
#define F_VERIFY_POLICYMAPPINGS				0x00080000  /*!< */
#define F_VERIFY_BASICCONSTRAINTS			0x00090000  /*!< */
#define F_VERIFY_KEYUSAGE					0x000A0000  /*!< */
#define F_ADD_USERPOLICYLIST				0x000B0000  /*!< */
#define F_ADD_VALID_POLICY_TREE_LIST		0x000C0000  /*!< */
#define F_VERIFY_INHIBITANYPOLICY			0x000D0000	/*!< */
#define F_VERIFY_POLICYCONSTRANITS			0x000E0000	/*!< */
#define F_VERIFY_PATHLENGTHCONSTRAINT		0x000F0000	/*!< */
#define F_PROCESS_BASIC_CERTIFICATE			0x00100000	/*!< */
#define F_PROCESS_PREPARE_FOR_NEXT			0x00110000	/*!< */


/*--------------------------------------------------------------*/
#ifdef L_CTL
#undef L_CTL
#endif
#define L_CTL								0x54000000  /*!< */

#define F_CERT_TRUST_LIST_TO_SEQ			0x00010000  /*!< */
#define F_SEQ_TO_CERT_TRUST_LIST			0x00020000  /*!< */
#define F_TRUSTED_SUBJECTS_TO_SEQ			0x00030000  /*!< */
#define F_SEQ_TO_TRUSTED_SUBJECTS			0x00040000  /*!< */
#define F_TRUSTED_CERTIFICATE_TO_SEQ		0x00050000  /*!< */
#define F_SEQ_TO_TRUSTED_CERTIFICATE		0x00060000  /*!< */

#ifdef L_PKCS10
#undef L_PKCS10
#endif
#define L_PKCS10                            0x55000000  /*!< */
#define F_P10_REQ_TO_SEQ                    0x00010000  /*!< */
#define F_SEQ_TO_P10_REQ                    0x00020000  /*!< */
#define F_P10_REQ_INFO_TO_SEQ               0x00030000  /*!< */
#define F_SEQ_TO_P10_REQ_INFO               0x00040000  /*!< */
#define F_P10_REQ_INFO_SET_VERSION          0x00050000  /*!< */
#define F_P10_REQ_INFO_SET_SUBJECT          0x00060000  /*!< */
#define F_P10_REQ_INFO_SET_PUBKEY           0x00070000  /*!< */
#define F_P10_REQ_INFO_ADD_EXTENSION        0x00080000  /*!< */
#define F_ENCODE_P10_REQ                    0x00090000  /*!< */
#define F_DECODE_P10_REQ                    0x000A0000  /*!< */

#ifdef L_ECC
#undef L_ECC
#endif
#define L_ECC                               0x56000000  /*!< */
#define F_PUBKEY_EX_TO_SEQ                  0x00010000  /*!< */
#define F_SEQ_TO_PUBKEY_EX                  0x00020000  /*!< */
#define F_ECC_PRIKEY_TO_SEQ                 0x00030000  /*!< */
#define F_SEQ_TO_ECC_PRIKEY                 0x00040000  /*!< */
#define F_ECC_PARAMETER_TO_SEQ              0x00050000  /*!< */
#define F_SEQ_TO_ECC_PARAMETER              0x00060000  /*!< */

#define F_ECC_CURVE_TO_SEQ                  0x00070000  /*!< */
#define F_SEQ_TO_ECC_CURVE                  0x00080000  /*!< */
#define F_ECC_PENTANOMIAL_TO_SEQ            0x00090000  /*!< */
#define F_SEQ_TO_ECC_PENTANOMIAL            0x000A0000  /*!< */
#define F_ECC_CHARACTERISTIC_TWO_TO_SEQ     0x000B0000  /*!< */
#define F_SEQ_TO_ECC_CHARACTERISTIC_TWO     0x000C0000  /*!< */
#define F_ECC_FIELD_ID_TO_SEQ               0x000D0000  /*!< */
#define F_SEQ_TO_ECC_FIELD_ID               0x000E0000  /*!< */
#define F_ECC_ALGORITHM_TO_SEQ             0x000F0000  /*!< */
#define F_SEQ_TO_ECC_ALGORITHM             0x00100000  /*!< */

#define F_GET_ECC_UNIT_FROM_PRIKEY          0x00110000  /*!< */
#define F_GET_ECC_UNIT_FROM_PUBKEY          0x00120000  /*!< */
#define F_SET_ECC_UNIT_TO_PRIKEY            0x00130000  /*!< */
#define F_SET_ECC_UNIT_TO_PUBKEY            0x00140000  /*!< */

#ifdef L_X962
#undef L_X962
#endif
#define L_X962                                  0x57000000  /*!< */
#define F_SET_EC_KEY_UNIT_TO_EC_PUBLIC_KEY      0x00010000  /*!< */
#define F_GET_EC_KEY_UNIT_FROM_EC_PUBLIC_KEY    0x00020000  /*!< */
#define F_SET_EC_KEY_UNIT_TO_EC_PRIVATE_KEY     0x00030000  /*!< */
#define F_GET_EC_KEY_UNIT_FROM_EC_PRIVATE_KEY   0x00040000  /*!< */
#define F_SET_EC_KEY_UNIT_TO_PUB_KEY            0x00010000  /*!< */
#define F_GET_EC_KEY_UNIT_FROM_PUB_KEY          0x00020000  /*!< */
#define F_SET_EC_KEY_UNIT_TO_PRIV_KEY           0x00030000  /*!< */
#define F_GET_EC_KEY_UNIT_FROM_PRIV_KEY         0x00040000  /*!< */
#define F_EC_PUBLIC_KEY_TO_SEQ                  0x00050000  /*!< */
#define F_SEQ_TO_EC_PUBLIC_KEY                  0x00060000  /*!< */
#define F_EC_PRIVATE_KEY_TO_SEQ                 0x00070000  /*!< */
#define F_SEQ_TO_EC_PRIVATE_KEY                 0x00080000  /*!< */
#define F_BITSTRING_TO_EC_KEY                   0x00090000  /*!< */
#define F_EC_KEY_TO_BITSTRING                   0x000A0000  /*!< */
#define F_ENCODE_ECDSA_SIGNATURE_VALUE          0x00100000  /*!< */
#define F_DECODE_ECDSA_SIGNATURE_VALUE          0x00110000  /*!< */

/*--------------------------------------------------------------*/
#define ERR_INVALID_ENCODE_INPUT			0x00000101	/*!< */
#define	ERR_INVALID_DECODE_INPUT			0x00000102	/*!< */
#define ERR_ASN1_ENCODING					0x00000103	/*!< */
#define ERR_ASN1_DECODING					0x00000104	/*!< */
#define ERR_TBS_CERT_ISSUER					0x00000105	/*!< */
#define ERR_TBS_CERT_SUBJECT				0x00000106	/*!< */
#define ERR_TBS_CERT_VALIDITY				0x00000107	/*!< */
#define ERR_TBS_CERT_SIGNATURE				0x00000108	/*!< */
#define ERR_TBS_CERT_SPKI					0x00000109	/*!< */
#define ERR_TBS_CERT_SERIAL					0x0000010A	/*!< */
#define ERR_TBS_CERT_VERSION				0x0000010B	/*!< */
#define ERR_STK_ERROR						0x0000010C	/*!< */
#define ERR_P12_MAC_INIT					0x0000010D	/*!< */
#define ERR_P12_MAC_GEN						0x0000010E	/*!< */
#define ERR_CERT_NOT_BEFORE					0x0000010F	/*!< */
#define ERR_CERT_NOT_AFTER					0x00000110	/*!< */
#define ERR_INVALID_VID_LENGTH				0x00000111	/*!< */
#define ERR_INVALID_VID_DATA				0x00000112	/*!< */
#define ERR_INVALID_CERT_NOT_BEFORE			0x00000113	/*!< */
#define ERR_INVALID_CERT_NOT_AFTER			0x00000114	/*!< */
#define ERR_INVALID_X509_TIME_TYPE			0x00000115	/*!< */
#define ERR_INVALID_TRUST_ANCHOR			0x00000116	/*!< */
#define ERR_INVALID_POLICY_MAPPING			0x00000117	/*!< */
#define ERR_INVALID_KEY_USAGE				0x00000118	/*!< */
#define ERR_INVALID_VALID_POLICY_TREE		0x00000119	/*!< */
#define ERR_INVALID_MAX_PATH_LENGTH			0x0000011A	/*!< */
#define ERR_INVALID_BASIC_CONSTRAINTS		0x0000011B	/*!< */
#define ERR_INVALID_CERTIFICATE_POLICIES	0x0000011C	/*!< */
#define ERR_FAIL_ASN1_TO_BINARY             0x0000011D	/*!< */
#define ERR_FAIL_INDEX_TO_OID               0x0000011E	/*!< */
#define ERR_FAIL_PKI_MALLOC            	   0x0000011F	/*!< */
#define ERR_INVALID_ASYMMETRICKEY_TYPE      0x00000120	/*!< */

/*--------------------------------------------------------------*/

#ifdef L_KISA
#undef L_KISA
#endif
#define L_KISA								0x58000000  /*!< */

#define F_SEQ_TO_KISA_HASH_CONTENT			0x00010000  /*!< */
#define F_KISA_HASH_CONTENT_TO_SEQ			0x00020000  /*!< */

#define ERR_INVALID_INPUT					0x00000101  /*!< */
#define ERR_NEW_HASH_CONTENT				0x00000102  /*!< */
#define ERR_EMPTY_SEQ_CHILD					0x00000103  /*!< */
#define ERR_GET_CHILD_IDN					0x00000104  /*!< */
#define ERR_GET_CHILD_RANDOM				0x00000105  /*!< */
#define ERR_ADD_CHILD_IDN					0x00000106  /*!< */
#define ERR_ADD_CHILD_RANDOM				0x00000107  /*!< */


/*--------------------------------------------------------------*/
#ifdef L_CID
#undef L_CID
#endif
#define L_CID                               0x59000000

#define F_NEW_ALGID                         0x00010000
#define F_FREE_ALGID                        0x00020000
#define F_ALGID_TO_SEQ                      0x00030000
#define F_SEQ_TO_ALGID                      0x00040000
#define F_DUP_ALGID                         0x00050000
#define F_CMP_ALGID                         0x00060000

#define F_NEW_CIREQ                         0x00070000
#define F_FREE_CIREQ                        0x00080000
#define F_CIREQ_TO_SEQ                      0x00090000
#define F_SEQ_TO_CIREQ                      0x00100000

#define F_NEW_CIRES                         0x00110000
#define F_FREE_CIRES                        0x00120000
#define F_CIRES_TO_SEQ                      0x00130000
#define F_SEQ_TO_CIRES                      0x00140000

#define F_CREATE_CIREQ                      0x00150000
#define F_CREATE_CIRES                      0x00160000

#define ERR_NEW_SEQ                         0x00000101
#define ERR_ADD_TO_DERSEQ                   0x00000102
#define ERR_NEW_ALG                         0x00000103
#define ERR_GET_DERCHILD                    0x00000104
#define ERR_NEW_ASN1_STRING                 0x00000105
#define ERR_SET_ASN1_STRING                 0x00000106
#define ERR_INVALID_VERSION                 0x00000107
#define ERR_INVALID_ENCALG                  0x00000108
#define ERR_INVALID_PUBKEY                  0x00000109
#define ERR_ALG_TO_SEQ                      0x00000110
#define ERR_ECPUBK_TO_SEQ                   0x00000111
#define ERR_GET_SEQ_CHILD_NUM               0x00000112
#define ERR_SEQ_TO_ALG                      0x00000113
#define ERR_SEQ_TO_ECPUBK                   0x00000114
#define ERR_INVALID_ENCCI                   0x00000115
#define ERR_NEW_CIREQ                       0x00000116
#define ERR_NEW_CIRES                       0x00000117
#define ERR_NEW_BIGINT                      0x00000118
#define ERR_GET_OID2                         0x00000119
#define ERR_ECKEY_TO_ECPUBK                 0x00000120
#define ERR_NEW_OCTET_STRING                0x00000121

#ifdef L_DHCID
#undef L_DHCID
#endif
#define L_DHCID                               0x60000000

#define F_DOMAIN_PARAMS_TO_SEQ                0x00030000
#define F_SEQ_TO_DOMAIN_PARAMS                0x00040000

#define F_NEW_DHCIREQ                         0x00070000
#define F_FREE_DHCIREQ                        0x00080000
#define F_DHCIREQ_TO_SEQ                      0x00090000
#define F_SEQ_TO_DHCIREQ                      0x00100000

#define F_NEW_DHCIRES                         0x00110000
#define F_FREE_DHCIRES                        0x00120000
#define F_DHCIRES_TO_SEQ                      0x00130000
#define F_SEQ_TO_DHCIRES                      0x00140000

#define F_CREATE_DHCIREQ                      0x00150000
#define F_CREATE_DHCIRES                      0x00160000

#define ERR_NEW_DOMAIN_PARAMS                 0x00000101
#define ERR_INVALID_P                         0x00000102
#define ERR_INVALID_G                         0x00000103
#define ERR_INVALID_Q                         0x00000104
#define ERR_DOMAIN_PARAMS_TO_SEQ              0x00000105
#define ERR_SEQ_TO_DOMAIN_PARAMS              0x00000106
#define ERR_NEW_DHCIREQ                         0x00000116
#define ERR_NEW_DHCIRES                         0x00000117

/* for crypto 509 */
#ifndef ERR_NOT_FOUNDED
#define ERR_NOT_FOUNDED						0x0000012F	/*!< */
#endif

/*!
* \brief
* 에러메시지를 출력해주는 함수
*/
/*INI_API void print_PKIErrorString(int err);*/

#endif /* __PKI_ERROR_H__ */
