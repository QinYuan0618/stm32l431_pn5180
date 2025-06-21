/*----------------------------------------------------------------------------*/
/* Copyright 2022, 2024 - 2025 NXP                                            */
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
* mBedTLS specific Symmetric Cryptography Component of Reader Library Framework.
* $Author: NXP $
* $Revision: $ (v07.13.00)
* $Date: $
*
*/

#ifndef PHCRYPTOSYM_MBEDTLS_H
#define PHCRYPTOSYM_MBEDTLS_H

#include <ph_Status.h>
#include <ph_RefDefs.h>

#ifdef NXPBUILD__PH_CRYPTOSYM_MBEDTLS

#include <phCryptoSym.h>

#define PH_CRYPTOSYM_VALIDATE_MAC_MODE(MacMode)                                                 \
    switch((uint8_t) (MacMode))                                                                 \
    {                                                                                           \
            case PH_CRYPTOSYM_MAC_MODE_CBCMAC:                                                  \
            case PH_CRYPTOSYM_MAC_MODE_CMAC:                                                    \
                break;                                                                          \
                                                                                                \
            default:                                                                            \
                /* Add additional Modes of operation in here! */                                \
                return PH_ADD_COMPCODE_FIXED(PH_ERR_UNSUPPORTED_PARAMETER, PH_COMP_CRYPTOSYM);  \
    }

phStatus_t phCryptoSym_mBedTLS_InvalidateKey(phCryptoSym_mBedTLS_DataParams_t * pDataParams);

phStatus_t phCryptoSym_mBedTLS_Encrypt(phCryptoSym_mBedTLS_DataParams_t * pDataParams, uint16_t wOption, const uint8_t * pPlainBuff,
    uint16_t wPlainBuffLen, uint8_t * pEncBuff);

phStatus_t phCryptoSym_mBedTLS_Decrypt(phCryptoSym_mBedTLS_DataParams_t * pDataParams, uint16_t wOption, uint8_t * pEncBuff,
    uint16_t  wEncBuffLen, uint8_t * pPlainBuff);

phStatus_t phCryptoSym_mBedTLS_CalculateMac(phCryptoSym_mBedTLS_DataParams_t * pDataParams, uint16_t wOption, const uint8_t * pData,
    uint16_t  wDataLen, uint8_t * pMac, uint8_t * pMacLen);

phStatus_t phCryptoSym_mBedTLS_LoadNonce(phCryptoSym_mBedTLS_DataParams_t * pDataParams, uint8_t bCipher, const uint8_t * pNonce,
    uint8_t bNonceLen);

phStatus_t phCryptoSym_mBedTLS_LoadIv(phCryptoSym_mBedTLS_DataParams_t * pDataParams, const uint8_t * pIV, uint8_t bIVLen);

phStatus_t phCryptoSym_mBedTLS_LoadAdditionalData(phCryptoSym_mBedTLS_DataParams_t * pDataParams, const uint8_t * pAddData,
    uint16_t wAddData_Len);

phStatus_t phCryptoSym_mBedTLS_LoadKey(phCryptoSym_mBedTLS_DataParams_t * pDataParams, uint16_t wKeyNo, uint16_t wKeyVer, uint16_t wKeyType);

phStatus_t phCryptoSym_mBedTLS_LoadKeyDirect(phCryptoSym_mBedTLS_DataParams_t * pDataParams, const uint8_t * pKey, uint16_t wKeyType);

phStatus_t phCryptoSym_mBedTLS_DiversifyKey(phCryptoSym_mBedTLS_DataParams_t * pDataParams, uint16_t wOption, uint16_t wKeyNo, uint16_t wKeyVer,
    uint8_t * pDivInput, uint8_t  bDivInputLen, uint8_t * pDiversifiedKey, uint8_t * pDivKeyLen);

phStatus_t phCryptoSym_mBedTLS_DiversifyDirectKey(phCryptoSym_mBedTLS_DataParams_t * pDataParams, uint16_t wOption, uint8_t * pKey, uint16_t wKeyType,
    uint8_t * pDivInput, uint8_t bDivInputLen, uint8_t * pDiversifiedKey, uint8_t * pDivKeyLen);

phStatus_t phCryptoSym_mBedTLS_SetConfig(phCryptoSym_mBedTLS_DataParams_t * pDataParams, uint16_t wConfig, uint16_t wValue);

phStatus_t phCryptoSym_mBedTLS_GetConfig(phCryptoSym_mBedTLS_DataParams_t * pDataParams, uint16_t wConfig, uint16_t * pValue);

phStatus_t phCryptoSym_mBedTLS_SetAuthenticationTag(phCryptoSym_mBedTLS_DataParams_t * pDataParams, const uint8_t * pTag, uint8_t bTag_Len);

phStatus_t phCryptoSym_mBedTLS_GetAuthenticationTag(phCryptoSym_mBedTLS_DataParams_t * pDataParams, uint8_t * pTag, uint8_t * pTag_Len);

phStatus_t phCryptoSym_mBedTLS_GetLastStatus(phCryptoSym_mBedTLS_DataParams_t * pDataParams, uint16_t wStatusMsgLen, int8_t * pStatusMsg,
    int32_t * pStatusCode);

#endif /* NXPBUILD__PH_CRYPTOSYM_MBEDTLS */

#endif /* PHCRYPTOSYM_MBEDTLS_H */
