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

#ifndef PHCRYPTOSYM_MBEDTLS_INT_H
#define PHCRYPTOSYM_MBEDTLS_INT_H

#include <ph_Status.h>
#include <ph_RefDefs.h>
#include <phCryptoSym.h>

#ifdef NXPBUILD__PH_CRYPTOSYM_MBEDTLS
#include <setjmp.h>

#include <mbedtls_config_sw.h>

#ifdef MBEDTLS_ERROR_C
#include "mbedtls/error.h"
#endif /* MBEDTLS_ERROR_C */

#ifdef PH_CRYPTOSYM_AES
#include <mbedtls/aes.h>
#endif /* PH_CRYPTOSYM_AES */

#ifdef MBEDTLS_CCM_C
#include <mbedtls/ccm.h>
#include <mbedtls/cipher.h>
#endif /* MBEDTLS_CCM_C */

#ifdef PH_CRYPTOSYM_DES
#include <mbedtls/des.h>
#endif /* PH_CRYPTOSYM_DES */

#ifdef NXPBUILD__PH_KEYSTORE
#include <phKeyStore.h>

#endif /* NXPBUILD__PH_KEYSTORE */

#define TRY                                                                                 \
    do                                                                                      \
    {                                                                                       \
        jmp_buf ex_buf__;                                                                   \
        switch( setjmp(ex_buf__) )                                                          \
        {                                                                                   \
            case 0:                                                                         \
                while (1)                                                                   \
                {

#define CATCH(x)                                                                            \
                break;                                                                      \
            case x:

#define FINALLY                                                                             \
                break;                                                                      \
                }                                                                           \
            default:

#define END                                                                                 \
        }                                                                                   \
    } while(0);

#define END_EXT                                                                             \
                break;                                                                      \
                }                                                                           \
            default:                                                                        \
                break;                                                                      \
        }                                                                                   \
    } while(0);

#define THROW(x) longjmp(ex_buf__, x)

#define EXCEPTION           (1)
#define RDLIB_EXCEPTION     (2)
#define MBEDTLS_EXCEPTION   (3)

#define PH_CHECK_SUCCESS_FCT_EXT(Status, Fct)                                               \
    {                                                                                       \
        (Status) = (Fct);                                                                   \
        if (Status != 0)                                                                    \
        {                                                                                   \
            THROW(RDLIB_EXCEPTION);                                                         \
        }                                                                                   \
    }

#define PH_CRYPTOSYM_CHECK_STATUS(DataParams, Status)                                       \
    {                                                                                       \
        if (Status != 0)                                                                    \
        {                                                                                   \
            DataParams->dwErrorCode = Status;                                               \
            THROW(MBEDTLS_EXCEPTION);                                                       \
        }                                                                                   \
    }

#define PH_CRYPTOSYM_ENCRYPTION                         1U
#define PH_CRYPTOSYM_DECRYPTION                         0U

#define PH_CRYPTOSYM_MBEDTLS_KDIV_MFP_AES128_CONST       0x01U
#define PH_CRYPTOSYM_MBEDTLS_KDIV_MFP_AES192_CONST_1     0x11U
#define PH_CRYPTOSYM_MBEDTLS_KDIV_MFP_AES192_CONST_2     0x12U
#define PH_CRYPTOSYM_MBEDTLS_KDIV_MFP_AES256_CONST_1     0x41U
#define PH_CRYPTOSYM_MBEDTLS_KDIV_MFP_AES256_CONST_2     0x42U
#define PH_CRYPTOSYM_MBEDTLS_KDIV_MFP_3DES_CONST_1       0x21U
#define PH_CRYPTOSYM_MBEDTLS_KDIV_MFP_3DES_CONST_2       0x22U
#define PH_CRYPTOSYM_MBEDTLS_KDIV_MFP_3KEY3DES_CONST_1   0x31U
#define PH_CRYPTOSYM_MBEDTLS_KDIV_MFP_3KEY3DES_CONST_2   0x32U
#define PH_CRYPTOSYM_MBEDTLS_KDIV_MFP_3KEY3DES_CONST_3   0x33U
#define PH_CRYPTOSYM_MBEDTLS_KDIV_MFUL_AES128_CONST      0x02U
#define PH_CRYPTOSYM_MBEDTLS_KDIV_MFP_DIVLENGTH_AES_MAX  31U
#define PH_CRYPTOSYM_MBEDTLS_KDIV_MFP_DIVLENGTH_DES_MAX  15U

phStatus_t phCryptoSym_mBedTLS_Int_InitContext(phCryptoSym_mBedTLS_DataParams_t * pDataParams, uint8_t bCipher);

void phCryptoSym_mBedTLS_Int_FreeContext(phCryptoSym_mBedTLS_DataParams_t * pDataParams, uint8_t bCipher);

phStatus_t phCryptoSym_mBedTLS_Int_LoadKey(phCryptoSym_mBedTLS_DataParams_t * pDataParams, uint8_t bMode, uint8_t bCipher);

phStatus_t phCryptoSym_mBedTLS_Int_Crypt_ECB(phCryptoSym_mBedTLS_DataParams_t * pDataParams, uint8_t bMode, uint16_t wKeyType,
    const uint8_t * pInBuff, uint8_t * pOutBuff);

phStatus_t phCryptoSym_mBedTLS_Int_Crypt_CBC(phCryptoSym_mBedTLS_DataParams_t * pDataParams, uint8_t bMode, uint16_t wKeyType,
    uint8_t * pIv, const uint8_t * pInBuff, uint16_t wInBuffLen, uint8_t * pOutBuff);

phStatus_t phCryptoSym_mBedTLS_Int_Crypt_CCM_EncyptTag(phCryptoSym_mBedTLS_DataParams_t * pDataParams, uint16_t wOption,
    uint8_t bCipher, uint8_t * pIv, uint8_t bIvLen, uint8_t * pAddData, uint16_t wAddDataLen, const uint8_t * pInBuff,
    uint16_t wInBuffLen, uint8_t * pOutBuff);

phStatus_t phCryptoSym_mBedTLS_Int_Crypt_CCM_AuthDecrypt(phCryptoSym_mBedTLS_DataParams_t * pDataParams, uint16_t wOption,
    uint8_t bCipher, uint8_t * pIv, uint8_t bIvLen, uint8_t * pAddData, uint16_t wAddDataLen, uint8_t * pInBuff,
    uint16_t wInBuffLen, uint8_t * pOutBuff);

phStatus_t phCryptoSym_mBedTLS_Int_CMAC_Diversify(phCryptoSym_mBedTLS_DataParams_t * pDataParams, const uint8_t * pData,
    uint16_t  wDataLen, uint8_t * pMac, uint8_t * pMacLen);

phStatus_t phCryptoSym_mBedTLS_Int_CMAC_GenerateK1K2(phCryptoSym_mBedTLS_DataParams_t * pDataParams, uint16_t wBlockSize,
    uint8_t * pSubKey1, uint8_t * pSubKey2);

void phCryptoSym_mBedTLS_Int_CMAC_LeftShift(const uint8_t * pInBuff, uint8_t bInLen, uint8_t * pOutBuff);

phStatus_t phCryptoSym_mBedTLS_Int_Des_DecodeVersion(uint8_t * pKey, uint16_t * pKeyVer);

phStatus_t phCryptoSym_mBedTLS_Int_Des_EncodeVersion(uint8_t * pKey, uint16_t wKeyVer, uint16_t wKeyType, uint8_t * pEncodedKey);

#endif /* NXPBUILD__PH_CRYPTOSYM_MBEDTLS */

#endif /* PHCRYPTOSYM_MBEDTLS_INT_H */
