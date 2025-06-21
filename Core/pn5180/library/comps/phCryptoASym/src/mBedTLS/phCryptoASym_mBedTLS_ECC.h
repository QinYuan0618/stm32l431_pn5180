/*----------------------------------------------------------------------------*/
/* Copyright 2021 - 2025 NXP                                                  */
/*                                                                            */
/* NXP Confidential. This software is owned or controlled by NXP and may only */
/* be used strictly in accordance with the applicable license terms.          */
/* By expressly accepting such terms or by downloading, installing,           */
/* activating and/or otherwise using the software, you are agreeing that you  */
/* have read, and that you agree to comply with and are bound by, such        */
/* license terms. If you do not agree to be bound by the applicable license   */
/* terms, then you may not retain, install, activate or otherwise use the     */
/* software.                                                                  */
/*----------------------------------------------------------------------------*/

/** \file
* mBedTLS specific ECC ASymmetric Cryptography Component of Reader Library Framework.
* $Author: NXP $
* $Revision: $ (v07.13.00)
* $Date: $
*
*/

#ifndef PHCRYPTOASYM_MBEDTLS_ECC_H
#define PHCRYPTOASYM_MBEDTLS_ECC_H

#include <ph_Status.h>

#ifdef NXPBUILD__PH_CRYPTOASYM_ECC

#include <ph_RefDefs.h>
#include <phCryptoASym.h>

#ifdef MBEDTLS_BIGNUM_C
#include "mbedtls/bignum.h"
#endif /* MBEDTLS_BIGNUM_C */

#if !defined(MBEDTLS_NO_PLATFORM_ENTROPY) || !defined(NXPBUILD__PHHAL_HW_PN7642)
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#endif /* !defined(MBEDTLS_NO_PLATFORM_ENTROPY) || !defined(NXPBUILD__PHHAL_HW_PN7642) */

#ifdef MBEDTLS_ECDSA_C
#include "mbedtls/ecdsa.h"
#include "mbedtls/ecdh.h"
#endif /* MBEDTLS_ECDSA_C */

#define PH_CRYPTOASYM_MBEDTLS_ECC_GET_GROUP         &((phCryptoASym_mBedTLS_ECC_KeyPair *) pDataParams->pCtx)->stGroup
#define PH_CRYPTOASYM_MBEDTLS_ECC_GET_POINT         &((phCryptoASym_mBedTLS_ECC_KeyPair *) pDataParams->pCtx)->stPoint
#define PH_CRYPTOASYM_MBEDTLS_ECC_GET_MPI           &((phCryptoASym_mBedTLS_ECC_KeyPair *) pDataParams->pCtx)->stMpi
#define PH_CRYPTOASYM_MBEDTLS_ECC_GET_CURVE_ID      (uint8_t) ((phCryptoASym_mBedTLS_ECC_KeyPair *) pDataParams->pCtx)->stGroup.id

phStatus_t phCryptoASym_mBedTLS_ECC_GenerateKeyPair(phCryptoASym_mBedTLS_DataParams_t * pDataParams, uint8_t bCurveID);

phStatus_t phCryptoASym_mBedTLS_ECC_ExportKey(phCryptoASym_mBedTLS_DataParams_t * pDataParams, uint16_t wOption, uint16_t wKeyBuffSize,
    uint8_t * pCurveID, uint8_t * pKey, uint16_t * pKeyLen);

phStatus_t phCryptoASym_mBedTLS_ECC_LoadKey(phCryptoASym_mBedTLS_DataParams_t * pDataParams, uint16_t wOption, uint16_t wKeyNo, uint16_t wPos);

phStatus_t phCryptoASym_mBedTLS_ECC_LoadKeyDirect(phCryptoASym_mBedTLS_DataParams_t * pDataParams, uint16_t wOption, uint8_t * pKey,
    uint16_t wKeyLen);

phStatus_t phCryptoASym_mBedTLS_ECC_Sign(phCryptoASym_mBedTLS_DataParams_t * pDataParams, uint16_t wOption, uint8_t bHashAlgo, uint8_t * pMessage,
    uint16_t wMsgLen, uint8_t * pSign, uint16_t * pSignLen);

phStatus_t phCryptoASym_mBedTLS_ECC_Verify(phCryptoASym_mBedTLS_DataParams_t * pDataParams, uint16_t wOption, uint8_t bHashAlgo, uint8_t * pMessage,
    uint16_t wMsgLen, uint8_t * pSign, uint16_t wSignLen);

phStatus_t phCryptoASym_mBedTLS_ECC_SharedSecret(phCryptoASym_mBedTLS_DataParams_t * pDataParams, uint16_t wOption, uint8_t * pPublicKey,
    uint16_t wPublicKeyLen, uint8_t * pSharedSecret, uint16_t * pSharedSecretLen);

uint16_t phCryptoASym_mBedTLS_ECC_GetKeySize(uint16_t wKeyPair, uint8_t bCurveID);

void phCryptoASym_mBedTLS_ECC_InitContext(phCryptoASym_mBedTLS_DataParams_t * pDataParams);

phStatus_t phCryptoASym_mBedTLS_ECC_ValidateCurveID(mbedtls_ecp_group * pCtx_Group, uint8_t bCurveID);

phStatus_t phCryptoASym_mBedTLS_ECC_SetCurveInfo(phCryptoASym_mBedTLS_DataParams_t * pDataParams, mbedtls_ecp_group * pCtx_Group, uint8_t bCurveID);

phStatus_t phCryptoASym_mBedTLS_ECC_Export_PrivateKey(phCryptoASym_mBedTLS_DataParams_t * pDataParams, uint16_t wKeyBuffSize, uint8_t * pCurveID,
    uint8_t * pKey, uint16_t * pKeyLen);

phStatus_t phCryptoASym_mBedTLS_ECC_Export_PublicKey(phCryptoASym_mBedTLS_DataParams_t * pDataParams, uint16_t wKeyBuffSize, uint8_t * pCurveID,
    uint8_t * pKey, uint16_t * pKeyLen);

phStatus_t phCryptoASym_mBedTLS_ECC_Load_PrivateKey(phCryptoASym_mBedTLS_DataParams_t * pDataParams, mbedtls_ecp_group * pCtx_Group,
    mbedtls_mpi * pCtx_Mpi, uint8_t bCurveID, uint8_t * pKey, uint16_t wKeyLen);

phStatus_t phCryptoASym_mBedTLS_ECC_Load_PublicKey(phCryptoASym_mBedTLS_DataParams_t * pDataParams, mbedtls_ecp_group * pCtx_Group,
    mbedtls_ecp_point * pCtx_Point, uint8_t bCurveID, uint8_t * pKey, uint16_t wKeyLen);

#endif /* NXPBUILD__PH_CRYPTOASYM_ECC */

#endif /* PHCRYPTOASYM_MBEDTLS_ECC_H */
