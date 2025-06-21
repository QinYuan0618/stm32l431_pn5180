/*----------------------------------------------------------------------------*/
/* Copyright 2025 NXP                                                         */
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
* mBedTLS specific Hashing Component of Reader Library Framework.
* $Author: NXP $
* $Revision: $ (v07.13.00)
* $Date: $
*
*/

#ifndef PHCRYPTOASYM_MBEDTLS_HASH_H
#define PHCRYPTOASYM_MBEDTLS_HASH_H

#include <ph_Status.h>

#ifdef NXPBUILD__PH_CRYPTOASYM_HASH

#include <ph_RefDefs.h>
#include <phCryptoASym.h>

#ifdef PH_CRYPTOASYM_SHA256
#include "mbedtls/sha256.h"
#endif /* PH_CRYPTOASYM_SHA256 */

#ifdef PH_CRYPTOASYM_SHA512
#include "mbedtls/sha512.h"
#endif /* PH_CRYPTOASYM_SHA512 */

#ifdef PH_CRYPTOASYM_SHA256
extern mbedtls_sha256_context stMD_SHA256_Ctx;
#endif /* PH_CRYPTOASYM_SHA256 */

#ifdef PH_CRYPTOASYM_SHA512
extern mbedtls_sha512_context stMD_SHA512_Ctx;
#endif /* PH_CRYPTOASYM_SHA512 */

phStatus_t phCryptoASym_mBedTLS_ComputeHash(phCryptoASym_mBedTLS_DataParams_t * pDataParams, uint16_t wOption,
    uint8_t bHashAlgo, uint8_t * pMessage, uint16_t wMsgLen, uint8_t * pHash, uint16_t * pHashLen);

phStatus_t phCryptoASym_mBedTLS_Hash_Start(phCryptoASym_mBedTLS_DataParams_t * pDataParams);

phStatus_t phCryptoASym_mBedTLS_Hash_Update(phCryptoASym_mBedTLS_DataParams_t * pDataParams, uint8_t * pMessage,
    uint16_t wMsgLen);

phStatus_t phCryptoASym_mBedTLS_Hash_Finish(phCryptoASym_mBedTLS_DataParams_t * pDataParams, uint8_t * pHash,
    uint16_t * pHashLen);

phStatus_t phCryptoASym_mBedTLS_Hash_Free(phCryptoASym_mBedTLS_DataParams_t * pDataParams);

#endif /* NXPBUILD__PH_CRYPTOASYM_HASH */

#endif /* PHCRYPTOASYM_MBEDTLS_HASH_H */
