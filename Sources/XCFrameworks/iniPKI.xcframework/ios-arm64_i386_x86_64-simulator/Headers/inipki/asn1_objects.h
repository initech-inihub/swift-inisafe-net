/*!
* \file asn1_objects.h
* \brief ASN1의 OBJECT_IDENTIFIER를 다루기 위한 헤더
* \remarks
* OBJECT_IDENTIFIER와 oid_index 매크로, 관련 함수를 정의
* \author
* Copyright (c) 2008 by \<INITech\>
*/

#ifndef HEADER_ASN1_OBJECT_H
#define HEADER_ASN1_OBJECT_H


#ifdef NO_PKI
#error PKI is disabled.
#endif

#include <inicrypto/foundation.h>
#include "asn1.h"
#ifdef  __cplusplus
extern "C" {
#endif

/*!
* \brief
* 미리 저장된 OID LIST를 담고 있는 구조체 (OID_LIST()함수 참조)
*/
typedef struct oid_st
{
	const char *sn;	/*!< Short Name*/
	const char *ln;	/*!< Long Name*/
	const char *data;	/*!< "1.2.XX와 같은 oid 스트링"*/
}OID_ST;

#define OID_LIST_SIZE 881

#define OID_undefined   0
#define OID_RSA_Data_Security_Inc   1
#define OID_RSA_Data_Security_Inc_PKCS   2
#define OID_md2   3
#define OID_md5   4
#define OID_rc4   5
#define OID_rsaEncryption   6
#define OID_md2WithRSAEncryption   7
#define OID_md5WithRSAEncryption   8
#define OID_pbeWithMD2AndDES_CBC   9
#define OID_pbeWithMD5AndDES_CBC   10
#define OID_directory_services_X_500   11
#define OID_X509   12
#define OID_commonName   13
#define OID_countryName   14
#define OID_localityName   15
#define OID_stateOrProvinceName   16
#define OID_organizationName   17
#define OID_organizationalUnitName   18
#define OID_rsa   19
#define OID_pkcs7   20
#define OID_pkcs7_data   21
#define OID_pkcs7_signedData   22
#define OID_pkcs7_envelopedData   23
#define OID_pkcs7_signedAndEnvelopedData   24
#define OID_pkcs7_digestData   25
#define OID_pkcs7_encryptedData   26
#define OID_pkcs3   27
#define OID_dhKeyAgreement   28
#define OID_des_ecb   29
#define OID_des_cfb   30
#define OID_des_cbc   31
#define OID_des_ede   32
#define OID_des_ede3   33
#define OID_idea_cbc   34
#define OID_idea_cfb   35
#define OID_idea_ecb   36
#define OID_rc2_cbc   37
#define OID_rc2_ecb   38
#define OID_rc2_cfb   39
#define OID_rc2_ofb   40
#define OID_sha   41
#define OID_shaWithRSAEncryption   42
#define OID_des_ede_cbc   43
#define OID_des_ede3_cbc   44
#define OID_des_ofb   45
#define OID_idea_ofb   46
#define OID_pkcs9   47
#define OID_emailAddress   48
#define OID_unstructuredName   49
#define OID_contentType   50
#define OID_messageDigest   51
#define OID_signingTime   52
#define OID_countersignature   53
#define OID_challengePassword   54
#define OID_unstructuredAddress   55
#define OID_extendedCertificateAttributes   56
#define OID_Netscape_Communications_Corp   57
#define OID_Netscape_Certificate_Extension   58
#define OID_Netscape_Data_Type   59
#define OID_des_ede_cfb   60
#define OID_des_ede3_cfb   61
#define OID_des_ede_ofb   62
#define OID_des_ede3_ofb   63
#define OID_sha1   64
#define OID_sha1WithRSAEncryption   65
#define OID_dsaWithSHA   66
#define OID_dsaEncryption_old   67
#define OID_pbeWithSHA1AndRC2_CBC   68 
#define OID_PBKDF2   69
#define OID_dsaWithSHA1_old   70
#define OID_Netscape_Cert_Type   71
#define OID_Netscape_Base_Url   72
#define OID_Netscape_Revocation_Url   73
#define OID_Netscape_CA_Revocation_Url   74
#define OID_Netscape_Renewal_Url   75
#define OID_Netscape_CA_Policy_Url   76
#define OID_Netscape_SSL_Server_Name   77
#define OID_Netscape_Comment   78
#define OID_Netscape_Certificate_Sequence   79
#define OID_desx_cbc   80
#define OID_id_ce   81
#define OID_X509v3_Subject_Key_Identifier   82
#define OID_X509v3_Key_Usage   83
#define OID_X509v3_Private_Key_Usage_Period   84
#define OID_X509v3_Subject_Alternative_Name   85
#define OID_X509v3_Issuer_Alternative_Name   86
#define OID_X509v3_Basic_Constraints   87
#define OID_X509v3_CRL_Number   88
#define OID_X509v3_Certificate_Policies   89
#define OID_X509v3_Authority_Key_Identifier   90
#define OID_bf_cbc   91
#define OID_bf_ecb   92
#define OID_bf_cfb   93
#define OID_bf_ofb   94
#define OID_mdc2   95
#define OID_mdc2WithRSA   96
#define OID_rc4_40   97
#define OID_rc2_40_cbc   98
#define OID_givenName   99
#define OID_surname   100
#define OID_initials   101
#define OID_(null)   102
#define OID_X509v3_CRL_Distribution_Points   103
#define OID_md5WithRSA   104
#define OID_serialNumber   105
#define OID_title   106
#define OID_description   107
#define OID_cast5_cbc   108
#define OID_cast5_ecb   109
#define OID_cast5_cfb   110
#define OID_cast5_ofb   111
#define OID_pbeWithMD5AndCast5CBC   112
#define OID_dsaWithSHA1   113
#define OID_md5_sha1   114
#define OID_sha1WithRSA   115
#define OID_dsaEncryption   116
#define OID_ripemd160   117
#define OID_ripemd160WithRSA   119
#define OID_rc5_cbc   120
#define OID_rc5_ecb   121
#define OID_rc5_cfb   122
#define OID_rc5_ofb   123
#define OID_run_length_compression   124
#define OID_zlib_compression   125
#define OID_X509v3_Extended_Key_Usage   126
#define OID_PKIX   127
#define OID_id_kp   128
#define OID_TLS_Web_Server_Authentication   129
#define OID_TLS_Web_Client_Authentication   130
#define OID_Code_Signing   131
#define OID_E_mail_Protection   132
#define OID_Time_Stamping   133
#define OID_Microsoft_Individual_Code_Signing   134
#define OID_Microsoft_Commercial_Code_Signing   135
#define OID_Microsoft_Trust_List_Signing   136
#define OID_Microsoft_Server_Gated_Crypto   137
#define OID_Microsoft_Encrypted_File_System   138
#define OID_Netscape_Server_Gated_Crypto   139
#define OID_X509v3_Delta_CRL_Indicator   140
#define OID_X509v3_CRL_Reason_Code   141
#define OID_Invalidity_Date   142
#define OID_Strong_Extranet_ID   143
#define OID_pbeWithSHA1And128BitRC4   144
#define OID_pbeWithSHA1And40BitRC4   145
#define OID_pbeWithSHA1And3_KeyTripleDES_CBC   146
#define OID_pbeWithSHA1And2_KeyTripleDES_CBC   147
#define OID_pbeWithSHA1And128BitRC2_CBC   148
#define OID_pbeWithSHA1And40BitRC2_CBC   149
#define OID_keyBag   150
#define OID_pkcs8ShroudedKeyBag   151
#define OID_certBag   152
#define OID_crlBag   153
#define OID_secretBag   154
#define OID_safeContentsBag   155
#define OID_friendlyName   156
#define OID_localKeyID   157
#define OID_x509Certificate   158
#define OID_sdsiCertificate   159
#define OID_x509Crl   160
#define OID_PBES2   161
#define OID_PBMAC1   162
#define OID_hmacWithSHA1   163
#define OID_Policy_Qualifier_CPS   164
#define OID_Policy_Qualifier_User_Notice   165
#define OID_rc2_64_cbc   166
#define OID_SMIME_Capabilities   167
#define OID_pbeWithMD2AndRC2_CBC   168
#define OID_pbeWithMD5AndRC2_CBC   169
#define OID_pbeWithSHA1AndDES_CBC   170
#define OID_Microsoft_Extension_Request   171
#define OID_Extension_Request   172
#define OID_name   173
#define OID_dnQualifier   174
#define OID_id_pe   175
#define OID_id_ad   176
#define OID_Authority_Information_Access   177
#define OID_OCSP   178
#define OID_CA_Issuers   179
#define OID_OCSP_Signing   180
#define OID_iso   181
#define OID_ISO_Member_Body   182
#define OID_ISO_US_Member_Body   183
#define OID_X9_57   184
#define OID_X9_57_CM   185
#define OID_pkcs1   186
#define OID_pkcs5   187
#define OID_S_MIME   188
#define OID_id_smime_mod   189
#define OID_id_smime_ct   190
#define OID_id_smime_aa   191
#define OID_id_smime_alg   192
#define OID_id_smime_cd   193
#define OID_id_smime_spq   194
#define OID_id_smime_cti   195
#define OID_id_smime_mod_cms   196
#define OID_id_smime_mod_ess   197
#define OID_id_smime_mod_oid   198
#define OID_id_smime_mod_msg_v3   199
#define OID_id_smime_mod_ets_eSignature_88   200
#define OID_id_smime_mod_ets_eSignature_97   201
#define OID_id_smime_mod_ets_eSigPolicy_88   202
#define OID_id_smime_mod_ets_eSigPolicy_97   203
#define OID_id_smime_ct_receipt   204
#define OID_id_smime_ct_authData   205
#define OID_id_smime_ct_publishCert   206
#define OID_id_smime_ct_TSTInfo   207
#define OID_id_smime_ct_TDTInfo   208
#define OID_id_smime_ct_contentInfo   209
#define OID_id_smime_ct_DVCSRequestData   210
#define OID_id_smime_ct_DVCSResponseData   211
#define OID_id_smime_aa_receiptRequest   212
#define OID_id_smime_aa_securityLabel   213
#define OID_id_smime_aa_mlExpandHistory   214
#define OID_id_smime_aa_contentHint   215
#define OID_id_smime_aa_msgSigDigest   216
#define OID_id_smime_aa_encapContentType   217
#define OID_id_smime_aa_contentIdentifier   218
#define OID_id_smime_aa_macValue   219
#define OID_id_smime_aa_equivalentLabels   220
#define OID_id_smime_aa_contentReference   221
#define OID_id_smime_aa_encrypKeyPref   222
#define OID_id_smime_aa_signingCertificate   223
#define OID_id_smime_aa_smimeEncryptCerts   224
#define OID_id_smime_aa_timeStampToken   225
#define OID_id_smime_aa_ets_sigPolicyId   226
#define OID_id_smime_aa_ets_commitmentType   227
#define OID_id_smime_aa_ets_signerLocation   228
#define OID_id_smime_aa_ets_signerAttr   229
#define OID_id_smime_aa_ets_otherSigCert   230
#define OID_id_smime_aa_ets_contentTimestamp   231
#define OID_id_smime_aa_ets_CertificateRefs   232
#define OID_id_smime_aa_ets_RevocationRefs   233
#define OID_id_smime_aa_ets_certValues   234
#define OID_id_smime_aa_ets_revocationValues   235
#define OID_id_smime_aa_ets_escTimeStamp   236
#define OID_id_smime_aa_ets_certCRLTimestamp   237
#define OID_id_smime_aa_ets_archiveTimeStamp   238
#define OID_id_smime_aa_signatureType   239
#define OID_id_smime_aa_dvcs_dvc   240
#define OID_id_smime_alg_ESDHwith3DES   241
#define OID_id_smime_alg_ESDHwithRC2   242
#define OID_id_smime_alg_3DESwrap   243
#define OID_id_smime_alg_RC2wrap   244
#define OID_id_smime_alg_ESDH   245
#define OID_id_smime_alg_CMS3DESwrap   246
#define OID_id_smime_alg_CMSRC2wrap   247
#define OID_id_smime_cd_ldap   248
#define OID_id_smime_spq_ets_sqt_uri   249
#define OID_id_smime_spq_ets_sqt_unotice   250
#define OID_id_smime_cti_ets_proofOfOrigin   251
#define OID_id_smime_cti_ets_proofOfReceipt   252
#define OID_id_smime_cti_ets_proofOfDelivery   253
#define OID_id_smime_cti_ets_proofOfSender   254
#define OID_id_smime_cti_ets_proofOfApproval   255
#define OID_id_smime_cti_ets_proofOfCreation   256
#define OID_md4   257
#define OID_id_pkix_mod   258
#define OID_id_qt   259
#define OID_id_it   260
#define OID_id_pkip   261
#define OID_id_alg   262
#define OID_id_cmc   263
#define OID_id_on   264
#define OID_id_pda   265
#define OID_id_aca   266
#define OID_id_qcs   267
#define OID_id_cct   268
#define OID_id_pkix1_explicit_88   269
#define OID_id_pkix1_implicit_88   270
#define OID_id_pkix1_explicit_93   271
#define OID_id_pkix1_implicit_93   272
#define OID_id_mod_crmf   273
#define OID_id_mod_cmc   274
#define OID_id_mod_kea_profile_88   275
#define OID_id_mod_kea_profile_93   276
#define OID_id_mod_cmp   277
#define OID_id_mod_qualified_cert_88   278
#define OID_id_mod_qualified_cert_93   279
#define OID_id_mod_attribute_cert   280
#define OID_id_mod_timestamp_protocol   281
#define OID_id_mod_ocsp   282
#define OID_id_mod_dvcs   283
#define OID_id_mod_cmp2000   284
#define OID_Biometric_Info   285
#define OID_qcStatements   286
#define OID_ac_auditEntity   287
#define OID_ac_targeting   288
#define OID_aaControls   289
#define OID_sbgp_ipAddrBlock   290
#define OID_sbgp_autonomousSysNum   291
#define OID_sbgp_routerIdentifier   292
#define OID_textNotice   293
#define OID_IPSec_End_System   294
#define OID_IPSec_Tunnel   295
#define OID_IPSec_User   296
#define OID_dvcs   297
#define OID_id_it_caProtEncCert   298
#define OID_id_it_signKeyPairTypes   299
#define OID_id_it_encKeyPairTypes   300
#define OID_id_it_preferredSymmAlg   301
#define OID_id_it_caKeyUpdateInfo   302
#define OID_id_it_currentCRL   303
#define OID_id_it_unsupportedOIDs   304
#define OID_id_it_subscriptionRequest   305
#define OID_id_it_subscriptionResponse   306
#define OID_id_it_keyPairParamReq   307
#define OID_id_it_keyPairParamRep   308
#define OID_id_it_revPassphrase   309
#define OID_id_it_implicitConfirm   310
#define OID_id_it_confirmWaitTime   311
#define OID_id_it_origPKIMessage   312
#define OID_id_regCtrl   313
#define OID_id_regInfo   314
#define OID_id_regCtrl_regToken   315
#define OID_id_regCtrl_authenticator   316
#define OID_id_regCtrl_pkiPublicationInfo   317
#define OID_id_regCtrl_pkiArchiveOptions   318
#define OID_id_regCtrl_oldCertID   319
#define OID_id_regCtrl_protocolEncrKey   320
#define OID_id_regInfo_utf8Pairs   321
#define OID_id_regInfo_certReq   322
#define OID_id_alg_des40   323
#define OID_id_alg_noSignature   324
#define OID_id_alg_dh_sig_hmac_sha1   325
#define OID_id_alg_dh_pop   326
#define OID_id_cmc_statusInfo   327
#define OID_id_cmc_identification   328
#define OID_id_cmc_identityProof   329
#define OID_id_cmc_dataReturn   330
#define OID_id_cmc_transactionId   331
#define OID_id_cmc_senderNonce   332
#define OID_id_cmc_recipientNonce   333
#define OID_id_cmc_addExtensions   334
#define OID_id_cmc_encryptedPOP   335
#define OID_id_cmc_decryptedPOP   336
#define OID_id_cmc_lraPOPWitness   337
#define OID_id_cmc_getCert   338
#define OID_id_cmc_getCRL   339
#define OID_id_cmc_revokeRequest   340
#define OID_id_cmc_regInfo   341
#define OID_id_cmc_responseInfo   342
#define OID_id_cmc_queryPending   343
#define OID_id_cmc_popLinkRandom   344
#define OID_id_cmc_popLinkWitness   345
#define OID_id_cmc_confirmCertAcceptance   346
#define OID_id_on_personalData   347
#define OID_id_pda_dateOfBirth   348
#define OID_id_pda_placeOfBirth   349
#define OID_id_pda_gender   351
#define OID_id_pda_countryOfCitizenship   352
#define OID_id_pda_countryOfResidence   353
#define OID_id_aca_authenticationInfo   354
#define OID_id_aca_accessIdentity   355
#define OID_id_aca_chargingIdentity   356
#define OID_id_aca_group   357
#define OID_id_aca_role   358
#define OID_id_qcs_pkixQCSyntax_v1   359
#define OID_id_cct_crs   360
#define OID_id_cct_PKIData   361
#define OID_id_cct_PKIResponse   362
#define OID_AD_Time_Stamping   363
#define OID_ad_dvcs   364
#define OID_Basic_OCSP_Response   365
#define OID_OCSP_Nonce   366
#define OID_OCSP_CRL_ID   367
#define OID_Acceptable_OCSP_Responses   368
#define OID_OCSP_No_Check   369
#define OID_OCSP_Archive_Cutoff   370
#define OID_OCSP_Service_Locator   371
#define OID_Extended_OCSP_Status   372
#define OID_valid   373
#define OID_path   374
#define OID_Trust_Root   375
#define OID_algorithm   376
#define OID_rsaSignature   377
#define OID_directory_services   algorithms   378
#define OID_org   379
#define OID_dod   380
#define OID_iana   381
#define OID_Directory   382
#define OID_Management   383
#define OID_Experimental   384
#define OID_Private   385
#define OID_Security   386
#define OID_SNMPv2   387
#define OID_Mail   388
#define OID_Enterprises   389
#define OID_dcObject   390
#define OID_domainComponent   391
#define OID_Domain   392
#define OID_NULL   393
#define OID_Selected_Attribute_Types   394
#define OID_clearance   395
#define OID_md4WithRSAEncryption   396
#define OID_ac_proxying   397
#define OID_Subject_Information_Access   398
#define OID_id_aca_encAttrs   399
#define OID_role   400
#define OID_X509v3_Policy_Constraints   401
#define OID_X509v3_AC_Targeting   402
#define OID_X509v3_No_Revocation_Available   403
#define OID_ANSI_X9_62   405
#define OID_prime_field   406
#define OID_characteristic_two_field   407
#define OID_id_ecPublicKey   408
#define OID_prime192v1   409
#define OID_prime192v2   410
#define OID_prime192v3   411
#define OID_prime239v1   412
#define OID_prime239v2   413
#define OID_prime239v3   414
#define OID_prime256v1   415
#define OID_ecdsa_with_SHA1   416
#define OID_Microsoft_CSP_Name   417
#define OID_aes_128_ecb   418
#define OID_aes_128_cbc   419
#define OID_aes_128_ofb   420
#define OID_aes_128_cfb   421
#define OID_aes_192_ecb   422
#define OID_aes_192_cbc   423
#define OID_aes_192_ofb   424
#define OID_aes_192_cfb   425
#define OID_aes_256_ecb   426
#define OID_aes_256_cbc   427
#define OID_aes_256_ofb   428
#define OID_aes_256_cfb   429
#define OID_Hold_Instruction_Code   430
#define OID_Hold_Instruction_None   431
#define OID_Hold_Instruction_Call_Issuer   432
#define OID_Hold_Instruction_Reject   433
#define OID_data   434
#define OID_pss   435
#define OID_ucl   436
#define OID_pilot   437
#define OID_pilotAttributeType   438
#define OID_pilotAttributeSyntax   439
#define OID_pilotObjectClass   440
#define OID_pilotGroups   441
#define OID_iA5StringSyntax   442
#define OID_caseIgnoreIA5StringSyntax   443
#define OID_pilotObject   444
#define OID_pilotPerson   445
#define OID_account   446
#define OID_document   447
#define OID_room   448
#define OID_documentSeries   449
#define OID_rFC822localPart   450
#define OID_dNSDomain   451
#define OID_domainRelatedObject   452
#define OID_friendlyCountry   453
#define OID_simpleSecurityObject   454
#define OID_pilotOrganization   455
#define OID_pilotDSA   456
#define OID_qualityLabelledData   457
#define OID_userId   458
#define OID_textEncodedORAddress   459
#define OID_rfc822Mailbox   460
#define OID_info   461
#define OID_favouriteDrink   462
#define OID_roomNumber   463
#define OID_photo   464
#define OID_userClass   465
#define OID_host   466
#define OID_manager   467
#define OID_documentIdentifier   468
#define OID_documentTitle   469
#define OID_documentVersion   470
#define OID_documentAuthor   471
#define OID_documentLocation   472
#define OID_homeTelephoneNumber   473
#define OID_secretary   474
#define OID_otherMailbox   475
#define OID_lastModifiedTime   476
#define OID_lastModifiedBy   477
#define OID_aRecord   478
#define OID_pilotAttributeType27   479
#define OID_mXRecord   480
#define OID_nSRecord   481
#define OID_sOARecord   482
#define OID_cNAMERecord   483
#define OID_associatedDomain   484
#define OID_associatedName   485
#define OID_homePostalAddress   486
#define OID_personalTitle   487
#define OID_mobileTelephoneNumber   488
#define OID_pagerTelephoneNumber   489
#define OID_friendlyCountryName   490
#define OID_organizationalStatus   491
#define OID_janetMailbox   492
#define OID_mailPreferenceOption   493
#define OID_buildingName   494
#define OID_dSAQuality   495
#define OID_singleLevelQuality   496
#define OID_subtreeMinimumQuality   497
#define OID_subtreeMaximumQuality   498
#define OID_personalSignature   499
#define OID_dITRedirect   500
#define OID_audio   501
#define OID_documentPublisher   502
#define OID_x500UniqueIdentifier   503
#define OID_MIME_MHS   504
#define OID_mime_mhs_headings   505
#define OID_mime_mhs_bodies   506
#define OID_id_hex_partial_message   507
#define OID_id_hex_multipart_message   508
#define OID_generationQualifier   509
#define OID_pseudonym   510
#define OID_Secure_Electronic_Transactions   512
#define OID_content_types   513
#define OID_message_extensions   514
#define OID_set_attr   515
#define OID_set_policy   516
#define OID_certificate_extensions   517
#define OID_set_brand   518
#define OID_setct_PANData   519
#define OID_setct_PANToken   520
#define OID_setct_PANOnly   521
#define OID_setct_OIData   522
#define OID_setct_PI   523
#define OID_setct_PIData   524
#define OID_setct_PIDataUnsigned   525
#define OID_setct_HODInput   526
#define OID_setct_AuthResBaggage   527
#define OID_setct_AuthRevReqBaggage   528
#define OID_setct_AuthRevResBaggage   529
#define OID_setct_CapTokenSeq   530
#define OID_setct_PInitResData   531
#define OID_setct_PI_TBS   532
#define OID_setct_PResData   533
#define OID_setct_AuthReqTBS   534
#define OID_setct_AuthResTBS   535
#define OID_setct_AuthResTBSX   536
#define OID_setct_AuthTokenTBS   537
#define OID_setct_CapTokenData   538
#define OID_setct_CapTokenTBS   539
#define OID_setct_AcqCardCodeMsg   540
#define OID_setct_AuthRevReqTBS   541
#define OID_setct_AuthRevResData   542
#define OID_setct_AuthRevResTBS   543
#define OID_setct_CapReqTBS   544
#define OID_setct_CapReqTBSX   545
#define OID_setct_CapResData   546
#define OID_setct_CapRevReqTBS   547
#define OID_setct_CapRevReqTBSX   548
#define OID_setct_CapRevResData   549
#define OID_setct_CredReqTBS   550
#define OID_setct_CredReqTBSX   551
#define OID_setct_CredResData   552
#define OID_setct_CredRevReqTBS   553
#define OID_setct_CredRevReqTBSX   554
#define OID_setct_CredRevResData   555
#define OID_setct_PCertReqData   556
#define OID_setct_PCertResTBS   557
#define OID_setct_BatchAdminReqData   558
#define OID_setct_BatchAdminResData   559
#define OID_setct_CardCInitResTBS   560
#define OID_setct_MeAqCInitResTBS   561
#define OID_setct_RegFormResTBS   562
#define OID_setct_CertReqData   563
#define OID_setct_CertReqTBS   564
#define OID_setct_CertResData   565
#define OID_setct_CertInqReqTBS   566
#define OID_setct_ErrorTBS   567
#define OID_setct_PIDualSignedTBE   568
#define OID_setct_PIUnsignedTBE   569
#define OID_setct_AuthReqTBE   570
#define OID_setct_AuthResTBE   571
#define OID_setct_AuthResTBEX   572
#define OID_setct_AuthTokenTBE   573
#define OID_setct_CapTokenTBE   574
#define OID_setct_CapTokenTBEX   575
#define OID_setct_AcqCardCodeMsgTBE   576
#define OID_setct_AuthRevReqTBE   577
#define OID_setct_AuthRevResTBE   578
#define OID_setct_AuthRevResTBEB   579
#define OID_setct_CapReqTBE   580
#define OID_setct_CapReqTBEX   581
#define OID_setct_CapResTBE   582
#define OID_setct_CapRevReqTBE   583
#define OID_setct_CapRevReqTBEX   584
#define OID_setct_CapRevResTBE   585
#define OID_setct_CredReqTBE   586
#define OID_setct_CredReqTBEX   587
#define OID_setct_CredResTBE   588
#define OID_setct_CredRevReqTBE   589
#define OID_setct_CredRevReqTBEX   590
#define OID_setct_CredRevResTBE   591
#define OID_setct_BatchAdminReqTBE   592
#define OID_setct_BatchAdminResTBE   593
#define OID_setct_RegFormReqTBE   594
#define OID_setct_CertReqTBE   595
#define OID_setct_CertReqTBEX   596
#define OID_setct_CertResTBE   597
#define OID_setct_CRLNotificationTBS   598
#define OID_setct_CRLNotificationResTBS   599
#define OID_setct_BCIDistributionTBS   600
#define OID_generic_cryptogram   601
#define OID_merchant_initiated_auth   602
#define OID_setext_pinSecure   603
#define OID_setext_pinAny   604
#define OID_setext_track2   605
#define OID_additional_verification   606
#define OID_set_policy_root   607
#define OID_setCext_hashedRoot   608
#define OID_setCext_certType   609
#define OID_setCext_merchData   610
#define OID_setCext_cCertRequired   611
#define OID_setCext_tunneling   612
#define OID_setCext_setExt   613
#define OID_setCext_setQualf   614
#define OID_setCext_PGWYcapabilities   615
#define OID_setCext_TokenIdentifier   616
#define OID_setCext_Track2Data   617
#define OID_setCext_TokenType   618
#define OID_setCext_IssuerCapabilities   619
#define OID_setAttr_Cert   620
#define OID_payment_gateway_capabilities   621
#define OID_setAttr_TokenType   622
#define OID_issuer_capabilities   623
#define OID_set_rootKeyThumb   624
#define OID_set_addPolicy   625
#define OID_setAttr_Token_EMV   626
#define OID_setAttr_Token_B0Prime   627
#define OID_setAttr_IssCap_CVM   628
#define OID_setAttr_IssCap_T2   629
#define OID_setAttr_IssCap_Sig   630
#define OID_generate_cryptogram   631
#define OID_encrypted_track_2   632
#define OID_cleartext_track_2   633
#define OID_ICC_or_token_signature   634
#define OID_secure_device_signature   635
#define OID_set_brand_IATA_ATA   636
#define OID_set_brand_Diners   637
#define OID_set_brand_AmericanExpress   638
#define OID_set_brand_JCB   639
#define OID_set_brand_Visa   640
#define OID_set_brand_MasterCard   641
#define OID_set_brand_Novus   642
#define OID_des_cdmf   643
#define OID_rsaOAEPEncryptionSET   644
#define OID_itu_t   645
#define OID_joint_iso_itu_t   646
#define OID_International_Organizations   647
#define OID_Microsoft_Smartcardlogin   648
#define OID_Microsoft_Universal_Principal_Name   649
#define OID_aes_128_cfb1   650
#define OID_aes_192_cfb1   651
#define OID_aes_256_cfb1   652
#define OID_aes_128_cfb8   653
#define OID_aes_192_cfb8   654
#define OID_aes_256_cfb8   655
#define OID_des_cfb1   656
#define OID_des_cfb8   657
#define OID_des_ede3_cfb1   658
#define OID_des_ede3_cfb8   659
#define OID_streetAddress   660
#define OID_postalCode   661
#define OID_id_ppl   662
#define OID_Proxy_Certificate_Information   663
#define OID_Any_language   664
#define OID_Inherit_all   665
#define OID_X509v3_Name_Constraints   666
#define OID_Independent   667
#define OID_sha256WithRSAEncryption   668
#define OID_sha384WithRSAEncryption   669
#define OID_sha512WithRSAEncryption   670
#define OID_sha224WithRSAEncryption   671
#define OID_sha256   672
#define OID_sha384   673
#define OID_sha512   674
#define OID_sha224   675
#define OID_identified_organization   676
#define OID_certicom_arc   677
#define OID_wap   678
#define OID_wap_wsg   679
#define OID_id_characteristic_two_basis   680
#define OID_onBasis   681
#define OID_tpBasis   682
#define OID_ppBasis   683
#define OID_c2pnb163v1   684
#define OID_c2pnb163v2   685
#define OID_c2pnb163v3   686
#define OID_c2pnb176v1   687
#define OID_c2tnb191v1   688
#define OID_c2tnb191v2   689
#define OID_c2tnb191v3   690
#define OID_c2onb191v4   691
#define OID_c2onb191v5   692
#define OID_c2pnb208w1   693
#define OID_c2tnb239v1   694
#define OID_c2tnb239v2   695
#define OID_c2tnb239v3   696
#define OID_c2onb239v4   697
#define OID_c2onb239v5   698
#define OID_c2pnb272w1   699
#define OID_c2pnb304w1   700
#define OID_c2tnb359v1   701
#define OID_c2pnb368w1   702
#define OID_c2tnb431r1   703
#define OID_secp112r1   704
#define OID_secp112r2   705
#define OID_secp128r1   706
#define OID_secp128r2   707
#define OID_secp160k1   708
#define OID_secp160r1   709
#define OID_secp160r2   710
#define OID_secp192k1   711
#define OID_secp224k1   712
#define OID_secp224r1   713
#define OID_secp256k1   714
#define OID_secp384r1   715
#define OID_secp521r1   716
#define OID_sect113r1   717
#define OID_sect113r2   718
#define OID_sect131r1   719
#define OID_sect131r2   720
#define OID_sect163k1   721
#define OID_sect163r1   722
#define OID_sect163r2   723
#define OID_sect193r1   724
#define OID_sect193r2   725
#define OID_sect233k1   726
#define OID_sect233r1   727
#define OID_sect239k1   728
#define OID_sect283k1   729
#define OID_sect283r1   730
#define OID_sect409k1   731
#define OID_sect409r1   732
#define OID_sect571k1   733
#define OID_sect571r1   734
#define OID_wap_wsg_idm_ecid_wtls1   735
#define OID_wap_wsg_idm_ecid_wtls3   736
#define OID_wap_wsg_idm_ecid_wtls4   737
#define OID_wap_wsg_idm_ecid_wtls5   738
#define OID_wap_wsg_idm_ecid_wtls6   739
#define OID_wap_wsg_idm_ecid_wtls7   740
#define OID_wap_wsg_idm_ecid_wtls8   741
#define OID_wap_wsg_idm_ecid_wtls9   742
#define OID_wap_wsg_idm_ecid_wtls10   743
#define OID_wap_wsg_idm_ecid_wtls11   744
#define OID_wap_wsg_idm_ecid_wtls12   745
#define OID_X509v3_Any_Policy   746
#define OID_X509v3_Policy_Mappings   747
#define OID_X509v3_Inhibit_Any_Policy   748
#define OID_ipsec3   749
#define OID_ipsec4   750
#define OID_camellia_128_cbc   751
#define OID_camellia_192_cbc   752
#define OID_camellia_256_cbc   753
#define OID_camellia_128_ecb   754
#define OID_camellia_192_ecb   755
#define OID_camellia_256_ecb   756
#define OID_camellia_128_cfb   757
#define OID_camellia_192_cfb   758
#define OID_camellia_256_cfb   759
#define OID_camellia_128_cfb1   760
#define OID_camellia_192_cfb1   761
#define OID_camellia_256_cfb1   762
#define OID_camellia_128_cfb8   763
#define OID_camellia_192_cfb8   764
#define OID_camellia_256_cfb8   765
#define OID_camellia_128_ofb   766
#define OID_camellia_192_ofb   767
#define OID_camellia_256_ofb   768
#define OID_X509v3_Subject_Directory_Attributes   769
#define OID_X509v3_Issuing_Distrubution_Point   770
#define OID_X509v3_Certificate_Issuer   771
#define OID_korea   772
#define OID_kisa   773
#define OID_kftc   774
#define OID_npki_alg   775
#define OID_seed_ecb   776
#define OID_seed_cbc   777
#define OID_seed_ofb128   778
#define OID_seed_cfb128   779
#define OID_pbeWithSHA1AndSEED_CBC   780
#define OID_has160   781
#define OID_kcdsa1   782
#define OID_kcdsa1WithHAS160   783
#define OID_kcdsa1WithSHA1   784
#define OID_kisa_identifyData   785
#define OID_kisa_identifyData2   786
#define OID_VID   787
#define OID_EncryptedVID   788
#define OID_randomNum   789
#define OID_yessignCA   790
#define OID_yessignCA_attribute   791
#define OID_yessign_enCert4ssn   792
#define OID_GPKIpbeWithSHA1AndSEED_CBC   793
#define OID_cmsRsaEncryption   794
#define OID_id_kisa_HSM   795
#define OID_password_based_MAC   796
#define OID_Diffie_Hellman_based_MAC   797
#define OID_id_it_suppLangTags   798
#define OID_hmacSHA   799
#define OID_desMAC	800
#define OID_kcdsaWithHAS160	801
#define OID_kcdsaWithSHA1	802

#define OID_gcma		803
#define OID_gpki_alg	804
#define OID_neat		805
#define OID_neat_ecb	806
#define OID_neat_cbc	807
#define OID_neat_ofb	808
#define OID_neat_cfb	809
#define OID_neat_mac	810
#define OID_pbeWithSHA1AndNEAT_CBC		811
#define OID_pbeWithHAS160AndNEAT_CBC	812

#define OID_nes			813
#define OID_nes_ecb		814
#define OID_nes_cbc		815
#define OID_nes_ofb		816
#define OID_nes_cfb		817
#define OID_nes_mac		818
#define OID_pbeWithSHA1AndNES_CBC		819
#define OID_pbeWithSHA256AndNES_CBC		820
#define OID_pbeWithHAS160AndNES_CBC		821

#define OID_aria		822
#define OID_aria_ecb	823
#define OID_aria_cbc	824
#define OID_aria_ofb	825
#define OID_aria_cfb	826
#define OID_aria_mac	827
#define OID_pbeWithSHA1AndARIA_CBC		828
#define OID_pbeWithSHA256AndARIA_CBC	829
#define OID_pbeWithHAS160AndARIA_CBC	830

#define OID_id_pkix_ocsp_nonce	831

/* added pkcs1algorithms 2010.04.30 */
#define OID_id_RSAES_OAEP		832
#define OID_id_mgf1				833
#define OID_id_pSpecified		834
#define OID_id_RSASSA_PSS		835

/* added oid 2011.04.04 */
#define OID_id_INITECH_Encrypted_RANDOM		836

/* added for ctl */
#define OID_CTL						837
#define OID_CTL_SubjectUsage		838

/* added oid 2013.02.19 */
#define OID_id_INITECH_Encrypted_Device_Info		839

/* added for ISC_ECDSA */
#define OID_ecdsa_with_SHA256		840

/* added for KCDSA1WithSHA256 */
#define OID_kcdsa1WithSHA256   841
    
/* privatekey extend */
    
    /*
     biometric/nfc oid definition
     NOBE:NfcObjectBaseEncryption
     BOBE:BluetoothObjectBaseEncryption
     FOBE:FingerObjectBaseEncryption
     IOBE:IrisObjectBaseEncryption
     SOBE:SignObjectBaseEncryption
     VOBE:VoiceObjectBaseEncryption
     */
#define OID_NOBEWithSHA1AndSeedcbc  842
#define OID_BOBEWithSHA1AndSeedcbc  843
#define OID_FOBEWithSHA1AndSeedcbc  844
#define OID_IOBEWithSHA1AndSeedcbc  845
#define OID_SOBEWithSHA1AndSeedcbc  846
#define OID_VOBEWithSHA1AndSeedcbc  847
    
/*
 keyFatoryIDS
 */
#define	OID_Tag_TYPE                848
#define	OID_Technologies_Available	849
#define	OID_Serial_Number			850
#define	OID_ATOA                    852
#define	OID_SAK                     852
#define	OID_ATS                     853

/* 2017-09-11 ADD, ec-DH */
#define OID_id_ecDH                 854
#define OID_id_ecMQV                855
#define OID_secp256r1               856
    
#define OID_REPLAY_ATTACK           857
#define OID_hmacWithSHA256          858
#define OID_hmacWithSHA512          859
#define OID_initech                 860
    
    
#define OID_initech_ci_request                 861
#define OID_initech_ci_response                 862
#define OID_initech_dh_ci_request                 863
#define OID_initech_dh_ci_response                 864
#define OID_id_pkix_ocsp_extended_revoke           865


#define OID_DVCS_Signing            866

#define OID_ecdsa_with_SHA224		867
#define OID_ecdsa_with_SHA384		868
#define OID_ecdsa_with_SHA512		869

#define OID_EncryptedPrivateKeyInfos            870
#define OID_nfcObjectBasedEncryption            871
#define OID_fingerprintBasedEncryption          872
#define OID_faceprintBasedEncryption            873
#define OID_voiceprintBasedEncryption           874
#define OID_eyeprintBasedEncryption             875
#define OID_irisprintBasedEncryption            876
#define OID_handprintBasedEncryption            877
#define OID_actofsigningBasedEncryption         878
#define OID_pinBasedEncryption                  879
#define OID_patternBasedEncryption              880

#define	OID_ALG_TYPE_UNDEF			0x00
#define	OID_ALG_TYPE_DIGEST			0x01
#define	OID_ALG_TYPE_MAC			0x01
#define	OID_ALG_TYPE_BLOCKCIPHER	0x02
#define	OID_ALG_TYPE_PUBLIC_KEY		0x03
#define	OID_ALG_TYPE_PBE			0x04
    
#ifndef WIN_INI_LOADLIBRARY_PKI
/*!
* \brief
* OID의 텍스트 스트링 ("1.x.x.x....")나 oid_index를 입력하여 OBJECT_IDENTIFIER를 생성. (ex: get_OBJECT_IDENTIFIER(NULL,OID_rsaEncryption))
* 
* \param s
* OBJECT_IDENTIFIER 구조체 포인터
* 
* \param index
* oid 인덱스
*
* \returns
* -# 해당하는 OBJECT_IDENTIFIER
* -# NULL : 해당하는 OBJECT_IDENTIFIER가 없을 경우
*/
ISC_API OBJECT_IDENTIFIER *get_OBJECT_IDENTIFIER(const char *s, int index);

/*!
* \brief
* OBJECT_IDENTIFIER 로 부터 OID 리스트의 인덱스를 검색
* 
* \param oid
* OBJECT_IDENTIFIER 구조체 포인터
* 
* \returns
* OID 인덱스
*/
ISC_API int index_from_OBJECT_IDENTIFIER(OBJECT_IDENTIFIER* oid);

/*!
* \brief
* OID의 텍스트 스트링 ("1.x.x.x....")을 입력하여 oid_index를 검색
* 
* \param oid_string
*  OID의 텍스트 스트링 ("1.x.x.x....")
* 
* \param len
*  OID의 텍스트 스트링의 길이
* 
* \returns
* oid 인덱스
*/
ISC_API int index_from_oid_string(const char *oid_string, int len);

/*!
* \brief
* OID의 long name을 oid list에서 검색
* 
* \param ln
*  oid long name 캐릭터 스트링
* 
* \param len
*  ln의 길이
* 
* \returns
* oid 인덱스
*/
ISC_API int index_from_ln(const char *ln, int len);

/*!
* \brief
* OID의 long name을 oid list에서 검색
* 
* \param sn
*  oid short name 캐릭터 스트링
* 
* \param len
*  sn의 길이
* 
* \returns
* oid 인덱스
*/
ISC_API int index_from_sn(const char *sn, int len);

/*!
* \brief
* oid 인덱스을 oid list에서 검색하여 oid short name 반환
* 
* \param index
*  oid 인덱스
*  
* \returns
* oid short name 캐릭터 스트링
*/
ISC_API const char *sn_from_index(int index);

/*!
* \brief
* oid 인덱스을 oid list에서 검색하여 oid long name 반환
* 
* \param index
*  oid 인덱스
* 
* \returns
* oid long name 캐릭터 스트링
*/
ISC_API const char *ln_from_index(int index);

/*!
* \brief
* oid index에 해당하는 OBJECT_IDENTIFIER를 생성
* 
* \param index
*  oid 인덱스
* 
* \returns
* 생성된 OBJECT_IDENTIFIER
*/
ISC_API OBJECT_IDENTIFIER *index_to_OBJECT_IDENTIFIER(int index);


/*!
* \brief
* 두개의 OBJECT_IDENTIFIER를 비교
* 
* \param a
*  OBJECT_IDENTIFIER 구조체 포인터 a
*
* \param b
*  OBJECT_IDENTIFIER 구조체 포인터 b
* 
* \returns
* -# 0 : 같을경우
* -# 0 이외의 integer : 다를 경우
*/
ISC_API int cmp_OBJECT_IDENTIFIER(const OBJECT_IDENTIFIER *a, const OBJECT_IDENTIFIER *b);

/*!
* \brief
* OBJECT_IDENTIFIER를 복사
* 
* \param src
* 복사하려는 OBJECT_IDENTIFIER
*
* \returns
* 복제된 OBJECT_IDENTIFIER
*/
ISC_API OBJECT_IDENTIFIER * dup_OBJECT_IDENTIFIER(const OBJECT_IDENTIFIER *src);

/*!
* \brief
* OBJECT_IDENTIFIER가 담고있는 다이제스트 알고리즘의 id를 검색(digest.h 참조) 
* 
* \param oid
* OBJECT_IDENTIFIER 구조체 포인터
*
* \returns
* 다이제스트 알고리즘 id
*/
ISC_API int get_DigestID_from_OID(OBJECT_IDENTIFIER* oid);

/*!
* \brief
* OBJECT_IDENTIFIER가 담고있는 블럭 암호 / 공개키 암호 알고리즘의 id를 검색(blockcipher.h, rsa.h, dsa.h, kcdsa.h 참조) 
* 
* \param oid
* OBJECT_IDENTIFIER 구조체 포인터
*
* \returns
* 블럭 암호 / 공개키 암호 알고리즘 id
*/
ISC_API int get_CipherID_from_OID(OBJECT_IDENTIFIER* oid);

/*!
* \brief
* OBJECT_IDENTIFIER가 담고있는 알고리즘의 타입 검색
* 
* \param oid
* OBJECT_IDENTIFIER 구조체 포인터
*
* \returns
* -# OID_ALG_TYPE_UNDEF
* -# OID_ALG_TYPE_DIGEST
* -# OID_ALG_TYPE_MAC
* -# OID_ALG_TYPE_BLOCKCIPHER
* -# OID_ALG_TYPE_PUBLIC_KEY
* -# OID_ALG_TYPE_PB
*/
ISC_API int get_AlgorType_from_OID(OBJECT_IDENTIFIER* oid);
  
/*!
* \brief
* digest 알고리즘 id로부터 oid index 검색
* 
* \param digestID
* digest 알고리즘 id
*
* \returns
* oid index
*/
ISC_API int get_OID_from_DigestID(int digestID);

/*!
* \brief
* cipher 알고리즘 id로부터 oid index 검색
* 
* \param cipherID
* cipher 알고리즘 id
*
* \returns
* oid index
*/
ISC_API int get_OID_from_CipherID(int cipherID);

/*!
* \brief
* oid index에 해당하는 OID_ST의 포인터 주소를 반환
* 
* \param index
* oid index
*
* \returns
* OID_ST의 포인터
*/
ISC_API OID_ST* OID_LIST(int index);

/*!
 * \brief
 * digest 알고리즘 id로부터 ECDSA OID index 검색
 *
 * \param digestID
 * digest 알고리즘 id
 *
 * \returns
 * ecdsa oid index
 */
ISC_API int get_ECDSA_OID_from_DigestID(int digestID);
    
#else

#include "foundation_pki.h"

INI_RET_LOADLIB_PKI(OBJECT_IDENTIFIER*, get_OBJECT_IDENTIFIER, (const char *s, int index), (s,index), NULL);
INI_RET_LOADLIB_PKI(int, index_from_OBJECT_IDENTIFIER, (OBJECT_IDENTIFIER* oid), (oid), ISC_FAIL);
INI_RET_LOADLIB_PKI(int, index_from_oid_string, (const char *oid_string, int len), (oid_string,len), ISC_FAIL);
INI_RET_LOADLIB_PKI(int, index_from_ln, (const char *ln, int len), (ln,len), ISC_FAIL);
INI_RET_LOADLIB_PKI(int, index_from_sn, (const char *sn, int len), (sn,len), ISC_FAIL);
INI_RET_LOADLIB_PKI(const char*, sn_from_index, (int index), (index), NULL);
INI_RET_LOADLIB_PKI(const char*, ln_from_index, (int index), (index), NULL);
INI_RET_LOADLIB_PKI(OBJECT_IDENTIFIER*, index_to_OBJECT_IDENTIFIER, (int index), (index), NULL);
INI_RET_LOADLIB_PKI(int, cmp_OBJECT_IDENTIFIER, (const OBJECT_IDENTIFIER *a, const OBJECT_IDENTIFIER *b), (a,b), ISC_FAIL);
INI_RET_LOADLIB_PKI(OBJECT_IDENTIFIER*, dup_OBJECT_IDENTIFIER, (const OBJECT_IDENTIFIER *src), (src), NULL);
INI_RET_LOADLIB_PKI(int, get_DigestID_from_OID, (OBJECT_IDENTIFIER* oid), (oid), ISC_FAIL);
INI_RET_LOADLIB_PKI(int, get_CipherID_from_OID, (OBJECT_IDENTIFIER* oid), (oid), ISC_FAIL);
INI_RET_LOADLIB_PKI(int, get_AlgorType_from_OID, (OBJECT_IDENTIFIER* oid), (oid), ISC_FAIL);
INI_RET_LOADLIB_PKI(int, get_OID_from_DigestID, (int digestID), (digestID), ISC_FAIL);
INI_RET_LOADLIB_PKI(int, get_OID_from_CipherID, (int cipherID), (cipherID), ISC_FAIL);
INI_RET_LOADLIB_PKI(OID_ST*, OID_LIST, (int index), (index), NULL);
INI_RET_LOADLIB_PKI(int, get_ECDSA_OID_from_DigestID, (int digestID), (digestID), ISC_FAIL);

#endif

#ifdef  __cplusplus
}
#endif

#endif /* HEADER_ASN1_OBJECT_H */






