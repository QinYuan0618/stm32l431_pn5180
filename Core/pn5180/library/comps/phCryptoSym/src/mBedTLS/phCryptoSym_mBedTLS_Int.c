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

#include <stdlib.h>
#include <ph_Status.h>
#include <ph_RefDefs.h>

#ifdef NXPBUILD__PH_CRYPTOSYM_MBEDTLS

#include "phCryptoSym_mBedTLS.h"
#include "phCryptoSym_mBedTLS_Int.h"

phStatus_t phCryptoSym_mBedTLS_Int_InitContext(phCryptoSym_mBedTLS_DataParams_t * pDataParams, uint8_t bCipher)
{
    phStatus_t                         PH_MEMLOC_REM wStatus = 0;
    static phCryptoSym_mBedTLS_Context PH_MEMLOC_REM stCtx;

    switch(pDataParams->wKeyType)
    {
#ifdef PH_CRYPTOSYM_DES
#ifndef MBEDTLS_DES_ALT
        case PH_CRYPTOSYM_KEY_TYPE_DES:
            if(pDataParams->pCtx_Crypto == NULL)
            {
                pDataParams->pCtx_Crypto = &stCtx.stDES;
            }

            /* Initialize the context. */
            mbedtls_des_init((mbedtls_des_context *)pDataParams->pCtx_Crypto);
            break;
#endif /* MBEDTLS_DES_ALT */

        case PH_CRYPTOSYM_KEY_TYPE_2K3DES:
        case PH_CRYPTOSYM_KEY_TYPE_3K3DES:
            if(pDataParams->pCtx_Crypto == NULL)
            {
                pDataParams->pCtx_Crypto = &stCtx.st3DES;
            }

            /* Initialize the context. */
            mbedtls_des3_init((mbedtls_des3_context *)pDataParams->pCtx_Crypto);
            break;
#endif /* PH_CRYPTOSYM_DES */

#ifdef PH_CRYPTOSYM_AES
        case PH_CRYPTOSYM_KEY_TYPE_AES128:
#ifndef MBEDTLS_AES_ALT
        case PH_CRYPTOSYM_KEY_TYPE_AES192:
#endif /* MBEDTLS_AES_ALT */
        case PH_CRYPTOSYM_KEY_TYPE_AES256:
            switch(bCipher)
            {

                case PH_CRYPTOSYM_CIPHER_MODE_CCM:
                case PH_CRYPTOSYM_CIPHER_MODE_CCM_STAR:
                    if(pDataParams->pCtx_Crypto == NULL)
                    {
                        pDataParams->pCtx_Crypto = &stCtx.stAES_CCM;
                    }

                    /* Initialize the context. */
                    mbedtls_ccm_init((mbedtls_ccm_context *)pDataParams->pCtx_Crypto);
                    break;

                default:
                    if(pDataParams->pCtx_Crypto == NULL)
                    {
                        pDataParams->pCtx_Crypto = &stCtx.stAES;
                    }

                    /* Initialize the context. */
                    mbedtls_aes_init((mbedtls_aes_context *)pDataParams->pCtx_Crypto);
                    break;
            }
            break;
#endif /* PH_CRYPTOSYM_AES */

        default:
            /* Nothing to do here. */
            break;
    }

    return wStatus;
}

void phCryptoSym_mBedTLS_Int_FreeContext(phCryptoSym_mBedTLS_DataParams_t * pDataParams, uint8_t bCipher)
{
    if(pDataParams->pCtx_Crypto != NULL)
    {
        switch(pDataParams->wKeyType)
        {
#ifdef PH_CRYPTOSYM_DES
#ifndef MBEDTLS_DES_ALT
            case PH_CRYPTOSYM_KEY_TYPE_DES:
                mbedtls_des_free((mbedtls_des_context *)pDataParams->pCtx_Crypto);
                break;
#endif /* MBEDTLS_DES_ALT */

            case PH_CRYPTOSYM_KEY_TYPE_2K3DES:
            case PH_CRYPTOSYM_KEY_TYPE_3K3DES:
                mbedtls_des3_free((mbedtls_des3_context *)pDataParams->pCtx_Crypto);
                break;
#endif /* PH_CRYPTOSYM_DES */

#ifdef PH_CRYPTOSYM_AES
            case PH_CRYPTOSYM_KEY_TYPE_AES128:
#ifndef MBEDTLS_AES_ALT
            case PH_CRYPTOSYM_KEY_TYPE_AES192:
#endif /* MBEDTLS_AES_ALT */
            case PH_CRYPTOSYM_KEY_TYPE_AES256:
                switch(bCipher)
                {

                    case PH_CRYPTOSYM_CIPHER_MODE_CCM:
                    case PH_CRYPTOSYM_CIPHER_MODE_CCM_STAR:
                        mbedtls_ccm_free((mbedtls_ccm_context *)pDataParams->pCtx_Crypto);
                        break;

                    default:
                        mbedtls_aes_free((mbedtls_aes_context *)pDataParams->pCtx_Crypto);
                        break;
                }
                break;
#endif /* PH_CRYPTOSYM_AES */

            default:
                /* Nothing to do here. */
                break;
        }
    }
    else
    {
        /* Nothing to do here. */
    }
}

phStatus_t phCryptoSym_mBedTLS_Int_LoadKey(phCryptoSym_mBedTLS_DataParams_t * pDataParams, uint8_t bMode, uint8_t bCipher)
{
    phStatus_t  PH_MEMLOC_REM wStatus = 0;
    uint16_t    PH_MEMLOC_REM wBits = 0;
    uint8_t     PH_MEMLOC_REM * pKey = NULL;

    /* Load the Key to use. */
    pKey = pDataParams->aKey;

    TRY
    {
        switch(pDataParams->wKeyType)
        {
#ifdef PH_CRYPTOSYM_DES
#ifndef MBEDTLS_DES_ALT
            case PH_CRYPTOSYM_KEY_TYPE_DES:
                /* Load the Key. */
                if(bMode == PH_CRYPTOSYM_ENCRYPTION)
                {
                    PH_CRYPTOSYM_CHECK_STATUS(pDataParams, mbedtls_des_setkey_enc((mbedtls_des_context *)pDataParams->pCtx_Crypto, pKey));
                }
                else
                {
                    PH_CRYPTOSYM_CHECK_STATUS(pDataParams, mbedtls_des_setkey_dec((mbedtls_des_context *)pDataParams->pCtx_Crypto, pKey));
                }
                break;
#endif /* MBEDTLS_DES_ALT */

            case PH_CRYPTOSYM_KEY_TYPE_2K3DES:
                /* Load the Key. */

                if(bMode == PH_CRYPTOSYM_ENCRYPTION)
                {
                    PH_CRYPTOSYM_CHECK_STATUS(pDataParams, mbedtls_des3_set2key_enc((mbedtls_des3_context *)pDataParams->pCtx_Crypto, pKey));
                }
                else
                {
                    PH_CRYPTOSYM_CHECK_STATUS(pDataParams, mbedtls_des3_set2key_dec((mbedtls_des3_context *)pDataParams->pCtx_Crypto, pKey));
                }
                break;

            case PH_CRYPTOSYM_KEY_TYPE_3K3DES:
                /* Load the Key. */

                if(bMode == PH_CRYPTOSYM_ENCRYPTION)
                {
                    PH_CRYPTOSYM_CHECK_STATUS(pDataParams, mbedtls_des3_set3key_enc((mbedtls_des3_context *)pDataParams->pCtx_Crypto, pKey));
                }
                else
                {
                    PH_CRYPTOSYM_CHECK_STATUS(pDataParams, mbedtls_des3_set3key_dec((mbedtls_des3_context *)pDataParams->pCtx_Crypto, pKey));
                }
                break;
#endif /* PH_CRYPTOSYM_DES */

#ifdef PH_CRYPTOSYM_AES
            case PH_CRYPTOSYM_KEY_TYPE_AES128:
#ifndef MBEDTLS_AES_ALT
            case PH_CRYPTOSYM_KEY_TYPE_AES192:
#endif /* MBEDTLS_AES_ALT */
            case PH_CRYPTOSYM_KEY_TYPE_AES256:
                /* Evaluate the bits for keytype. */
                wBits = (uint16_t) (
                    (pDataParams->wKeyType == PH_CRYPTOSYM_KEY_TYPE_AES128) ? 128 :
#ifndef MBEDTLS_AES_ALT
                    (pDataParams->wKeyType == PH_CRYPTOSYM_KEY_TYPE_AES192) ? 192 :
#endif /* MBEDTLS_AES_ALT */
                    256);

                /* Load the Key. */
                switch(bCipher)
                {

                    case PH_CRYPTOSYM_CIPHER_MODE_CCM:
                    case PH_CRYPTOSYM_CIPHER_MODE_CCM_STAR:
                        PH_CRYPTOSYM_CHECK_STATUS(pDataParams, mbedtls_ccm_setkey((mbedtls_ccm_context *)pDataParams->pCtx_Crypto, MBEDTLS_CIPHER_ID_AES,
                            pKey, wBits));
                        break;

                    default:
                        if(bMode == PH_CRYPTOSYM_ENCRYPTION)
                        {
                            PH_CRYPTOSYM_CHECK_STATUS(pDataParams, mbedtls_aes_setkey_enc((mbedtls_aes_context *)pDataParams->pCtx_Crypto, pKey, wBits));
                        }
                        else
                        {
                            PH_CRYPTOSYM_CHECK_STATUS(pDataParams, mbedtls_aes_setkey_dec((mbedtls_aes_context *)pDataParams->pCtx_Crypto, pKey, wBits));
                        }
                        break;
                }
                break;
#endif /* PH_CRYPTOSYM_AES */

            default:
                PH_UNUSED_VARIABLE(pDataParams);
                PH_UNUSED_VARIABLE(wBits);
                PH_UNUSED_VARIABLE(bCipher);
                wStatus = PH_ADD_COMPCODE_FIXED(PH_ERR_UNSUPPORTED_PARAMETER, PH_COMP_CRYPTOSYM);
                break;
        }
    }
    CATCH(MBEDTLS_EXCEPTION)
    {
        wStatus = PH_ADD_COMPCODE_FIXED(PH_ERR_INTERNAL_ERROR, PH_COMP_CRYPTOSYM);
    }
    END_EXT

    return wStatus;
}

phStatus_t phCryptoSym_mBedTLS_Int_Crypt_ECB(phCryptoSym_mBedTLS_DataParams_t * pDataParams, uint8_t bMode, uint16_t wKeyType,
    const uint8_t * pInBuff, uint8_t * pOutBuff)
{
    phStatus_t  PH_MEMLOC_REM wStatus = 0;

    TRY
    {
        switch(wKeyType)
        {
#ifdef PH_CRYPTOSYM_DES
#ifndef MBEDTLS_DES_ALT
            case PH_CRYPTOSYM_KEY_TYPE_DES:
                PH_CRYPTOSYM_CHECK_STATUS(pDataParams, mbedtls_des_crypt_ecb((mbedtls_des_context *)pDataParams->pCtx_Crypto, pInBuff, pOutBuff));
                break;
#endif /* PH_CRYPTOSYM_MBEDTLS_DES */

            case PH_CRYPTOSYM_KEY_TYPE_2K3DES:
            case PH_CRYPTOSYM_KEY_TYPE_3K3DES:
                PH_CRYPTOSYM_CHECK_STATUS(pDataParams, mbedtls_des3_crypt_ecb((mbedtls_des3_context *)pDataParams->pCtx_Crypto, pInBuff, pOutBuff));
                break;
#endif /* PH_CRYPTOSYM_DES */

#ifdef PH_CRYPTOSYM_AES
            case PH_CRYPTOSYM_KEY_TYPE_AES128:
#ifndef MBEDTLS_AES_ALT
            case PH_CRYPTOSYM_KEY_TYPE_AES192:
#endif /* MBEDTLS_AES_ALT */
            case PH_CRYPTOSYM_KEY_TYPE_AES256:
                PH_CRYPTOSYM_CHECK_STATUS(pDataParams, mbedtls_aes_crypt_ecb((mbedtls_aes_context *)pDataParams->pCtx_Crypto, bMode, pInBuff, pOutBuff));
                break;
#endif /* PH_CRYPTOSYM_AES */

            default:
                wStatus = PH_ADD_COMPCODE_FIXED(PH_ERR_INVALID_PARAMETER, PH_COMP_CRYPTOSYM);
                break;
        }
    }
    CATCH(MBEDTLS_EXCEPTION)
    {
        wStatus = PH_ADD_COMPCODE_FIXED(PH_ERR_INTERNAL_ERROR, PH_COMP_CRYPTOSYM);
    }
    END_EXT

    return wStatus;
}

phStatus_t phCryptoSym_mBedTLS_Int_Crypt_CBC(phCryptoSym_mBedTLS_DataParams_t * pDataParams, uint8_t bMode, uint16_t wKeyType,
    uint8_t * pIv, const uint8_t * pInBuff, uint16_t wInBuffLen, uint8_t * pOutBuff)
{
    phStatus_t  PH_MEMLOC_REM wStatus = 0;

    TRY
    {
        switch(wKeyType)
        {
#ifdef PH_CRYPTOSYM_DES
#ifndef MBEDTLS_DES_ALT
            case PH_CRYPTOSYM_KEY_TYPE_DES:
                PH_CRYPTOSYM_CHECK_STATUS(pDataParams, mbedtls_des_crypt_cbc((mbedtls_des_context *)pDataParams->pCtx_Crypto, bMode, wInBuffLen, pIv,
                    pInBuff, pOutBuff));
                break;
#endif /* PH_CRYPTOSYM_MBEDTLS_DES */

            case PH_CRYPTOSYM_KEY_TYPE_2K3DES:
            case PH_CRYPTOSYM_KEY_TYPE_3K3DES:
                PH_CRYPTOSYM_CHECK_STATUS(pDataParams, mbedtls_des3_crypt_cbc((mbedtls_des3_context *)pDataParams->pCtx_Crypto, bMode, wInBuffLen, pIv,
                    pInBuff, pOutBuff));
                break;
#endif /* PH_CRYPTOSYM_DES */

#ifdef PH_CRYPTOSYM_AES
            case PH_CRYPTOSYM_KEY_TYPE_AES128:
#ifndef MBEDTLS_AES_ALT
            case PH_CRYPTOSYM_KEY_TYPE_AES192:
#endif /* MBEDTLS_AES_ALT */
            case PH_CRYPTOSYM_KEY_TYPE_AES256:
                PH_CRYPTOSYM_CHECK_STATUS(pDataParams, mbedtls_aes_crypt_cbc((mbedtls_aes_context *)pDataParams->pCtx_Crypto, bMode, wInBuffLen, pIv,
                    pInBuff, pOutBuff));
                break;
#endif /* PH_CRYPTOSYM_AES */

            default:
                wStatus = PH_ADD_COMPCODE_FIXED(PH_ERR_INVALID_PARAMETER, PH_COMP_CRYPTOSYM);
                break;
        }
    }
    CATCH(MBEDTLS_EXCEPTION)
    {
        wStatus = PH_ADD_COMPCODE_FIXED(PH_ERR_INTERNAL_ERROR, PH_COMP_CRYPTOSYM);
    }
    END_EXT

    return wStatus;
}

phStatus_t phCryptoSym_mBedTLS_Int_Crypt_CCM_EncyptTag(phCryptoSym_mBedTLS_DataParams_t * pDataParams, uint16_t wOption,
    uint8_t bCipher, uint8_t * pIv, uint8_t bIvLen, uint8_t * pAddData, uint16_t wAddDataLen, const uint8_t * pInBuff,
    uint16_t wInBuffLen, uint8_t * pOutBuff)
{
    phStatus_t  PH_MEMLOC_REM wStatus = 0;
    uint16_t    PH_MEMLOC_REM wOffset = 0;

    TRY
    {
        if(bCipher == PH_CRYPTOSYM_CIPHER_MODE_CCM)
        {
            PH_CRYPTOSYM_CHECK_STATUS(pDataParams, mbedtls_ccm_encrypt_and_tag((mbedtls_ccm_context *)pDataParams->pCtx_Crypto, wInBuffLen, pIv,
                bIvLen, pAddData, wAddDataLen, pInBuff, pOutBuff, pDataParams->aTag, pDataParams->bTagLen));
        }
        else
        {
            PH_CRYPTOSYM_CHECK_STATUS(pDataParams, mbedtls_ccm_star_encrypt_and_tag((mbedtls_ccm_context *)pDataParams->pCtx_Crypto, wInBuffLen,
                pIv, bIvLen, pAddData, wAddDataLen, pInBuff, pOutBuff, pDataParams->aTag, pDataParams->bTagLen));
        }

        /* Copy Tag to Output buffer. */
        if(wOption & PH_CRYPTOSYM_AUTH_TAG_ON)
        {
            (void) memcpy(&pOutBuff[wInBuffLen], pDataParams->aTag, pDataParams->bTagLen);

            /* Clear the Tag information as its copied to output buffer. */
            (void) memset(pDataParams->aTag, 0x00, sizeof(pDataParams->aTag));
        }

        /* Save the IV for next operation. */
        wOffset = (uint16_t) ((wInBuffLen > bIvLen) ? (wInBuffLen - bIvLen) : (bIvLen - wInBuffLen));
        (void) memcpy(pIv, &pOutBuff[wOffset], bIvLen);
    }
    CATCH(MBEDTLS_EXCEPTION)
    {
        wStatus = PH_ADD_COMPCODE(PH_ERR_INTERNAL_ERROR, PH_COMP_CRYPTOSYM);
    }
    END_EXT

    return wStatus;
}

phStatus_t phCryptoSym_mBedTLS_Int_Crypt_CCM_AuthDecrypt(phCryptoSym_mBedTLS_DataParams_t * pDataParams, uint16_t wOption,
    uint8_t bCipher, uint8_t * pIv, uint8_t bIvLen, uint8_t * pAddData, uint16_t wAddDataLen, uint8_t * pInBuff,
    uint16_t wInBuffLen, uint8_t * pOutBuff)
{
    phStatus_t  PH_MEMLOC_REM wStatus = 0;

    uint8_t     PH_MEMLOC_REM * pTag = NULL;
    uint8_t     PH_MEMLOC_REM bTagLen = 0;

    /* Extract Tag information */
    bTagLen = pDataParams->bTagLen;
    if(wOption & PH_CRYPTOSYM_AUTH_TAG_ON)
    {
        pTag = &pInBuff[wInBuffLen - bTagLen];
        wInBuffLen = (uint16_t) (wInBuffLen - bTagLen);
    }
    else
    {
        pTag = pDataParams->aTag;
    }

    TRY
    {
        if(bCipher == PH_CRYPTOSYM_CIPHER_MODE_CCM)
        {
            PH_CRYPTOSYM_CHECK_STATUS(pDataParams, mbedtls_ccm_auth_decrypt((mbedtls_ccm_context *)pDataParams->pCtx_Crypto, wInBuffLen, pIv,
                bIvLen, pAddData, wAddDataLen, pInBuff, pOutBuff, pTag, bTagLen));
        }
        else
        {
            PH_CRYPTOSYM_CHECK_STATUS(pDataParams, mbedtls_ccm_star_auth_decrypt((mbedtls_ccm_context *)pDataParams->pCtx_Crypto, wInBuffLen,
                pIv, bIvLen, pAddData, wAddDataLen, pInBuff, pOutBuff, pTag, bTagLen));
        }
    }
        CATCH(MBEDTLS_EXCEPTION)
    {
        wStatus = PH_ADD_COMPCODE(PH_ERR_INTERNAL_ERROR, PH_COMP_CRYPTOSYM);
    }
    END_EXT

    return wStatus;
}

phStatus_t phCryptoSym_mBedTLS_Int_CMAC_Diversify(phCryptoSym_mBedTLS_DataParams_t * pDataParams, const uint8_t * pData,
    uint16_t  wDataLen, uint8_t * pMac, uint8_t * pMacLen)
{
    phStatus_t  PH_MEMLOC_REM wStatus = 0;
    uint16_t    PH_MEMLOC_REM wBlockSize = 0;
    uint16_t    PH_MEMLOC_REM wIndex = 0;
    uint8_t     PH_MEMLOC_REM aData_Tmp[PH_CRYPTOSYM_AES_BLOCK_SIZE * 2U];

    uint8_t     PH_MEMLOC_REM aSubKey1[PH_CRYPTOSYM_MAX_BLOCK_SIZE];
    uint8_t     PH_MEMLOC_REM aSubKey2[PH_CRYPTOSYM_MAX_BLOCK_SIZE];

    (void) memset(aSubKey1, 0x00, (size_t)sizeof(aSubKey1));
    (void) memset(aSubKey2, 0x00, (size_t)sizeof(aSubKey2));

    /* Clear MAC length */
    *pMacLen = 0;

    /* Get the block size of the currently loaded key */
    PH_CHECK_SUCCESS_FCT(wStatus, phCryptoSym_mBedTLS_GetConfig(pDataParams, PH_CRYPTOSYM_CONFIG_BLOCK_SIZE, &wBlockSize));

    /* Check input length */
    if(wDataLen > (wBlockSize << 1U))
    {
        return PH_ADD_COMPCODE_FIXED(PH_ERR_LENGTH_ERROR, PH_COMP_CRYPTOSYM);
    }

    /* Clear IV */
    (void) memset(pDataParams->aIV, 0x00, wBlockSize);

    /* Now we may start with  MAC calculation */

    /* Always perform with sub key generation */
    PH_CHECK_SUCCESS_FCT(wStatus, phCryptoSym_mBedTLS_Int_CMAC_GenerateK1K2(pDataParams, wBlockSize, aSubKey1, aSubKey2));

    /* Copy data to temporary buffer */
    (void) memcpy(aData_Tmp, pData, wDataLen);

    /* Two full blocks -> NO PADDING, K1 */
    if(wDataLen == (wBlockSize << 1U))
    {
        /* XOR with K1 */
        for(wIndex = 0; wIndex < wBlockSize; ++wIndex)
        {
            aData_Tmp[wBlockSize + wIndex] ^= aSubKey1[wIndex];
        }
    }
    /* Otherwise APPLY PADDING, K2 */
    else
    {
        /* Apply padding */
        PH_CHECK_SUCCESS_FCT(wStatus, phCryptoSym_ApplyPadding(
            PH_CRYPTOSYM_PADDING_MODE_2,
            aData_Tmp,
            wDataLen,
            (uint8_t) (wBlockSize << 1U),
            (uint16_t) (sizeof(aData_Tmp)),
            aData_Tmp,
            &wDataLen));

        /* XOR with K2 */
        for(wIndex = 0; wIndex < wBlockSize; ++wIndex)
        {
            aData_Tmp[wBlockSize + wIndex] ^= aSubKey2[wIndex];
        }
    }

    /* Perform encryption */
    PH_CHECK_SUCCESS_FCT(wStatus, phCryptoSym_mBedTLS_Encrypt(
        pDataParams,
        PH_CRYPTOSYM_CIPHER_MODE_CBC,
        aData_Tmp,
        (PH_CRYPTOSYM_AES_BLOCK_SIZE * 2U),
        aData_Tmp));

    /* Return MAC */
    (void) memcpy(pMac, &aData_Tmp[wBlockSize], wBlockSize);
    *pMacLen = (uint8_t) wBlockSize;

    /* Clear the IV for security reasons */
    (void) memset(pDataParams->aIV, 0, wBlockSize);

    /* Clear key arrays */
    (void) memset(aSubKey1, 0x00, (size_t)sizeof(aSubKey1));
    (void) memset(aSubKey2, 0x00, (size_t)sizeof(aSubKey2));

    return PH_ERR_SUCCESS;
}

phStatus_t phCryptoSym_mBedTLS_Int_CMAC_GenerateK1K2(phCryptoSym_mBedTLS_DataParams_t * pDataParams, uint16_t wBlockSize,
    uint8_t * pSubKey1, uint8_t * pSubKey2)
{
    phStatus_t  PH_MEMLOC_REM wStatus = 0;
    uint8_t     PH_MEMLOC_REM aBuffer[PH_CRYPTOSYM_MAX_BLOCK_SIZE];
    uint8_t     PH_MEMLOC_REM bR_b = 0;

    /* Clear the local buffer. */
    (void) memset(aBuffer, 0x00, (size_t)sizeof(aBuffer));

    /* Calculate xor value according to Seq. 5.3 of SP_800-38B */
    /* R128 = 0exp(120) || 10000111, and R64 = 0exp(59) || 11011. */
    bR_b = (uint8_t) ((wBlockSize == PH_CRYPTOSYM_AES_BLOCK_SIZE) ? 0x87U : 0x1BU);

    /* Encrypt zero block*/
    /* 1. Let L = CIPHK(0 exp b). */
    PH_CHECK_SUCCESS_FCT(wStatus, phCryptoSym_mBedTLS_Encrypt(pDataParams, PH_CRYPTOSYM_CIPHER_MODE_ECB, aBuffer,
        wBlockSize, aBuffer));

    /* Shift the pSubKey array according to NIST SP_800-38B */
    /* 2. If MSB1(L) = 0, then K1 = L << 1U; */
    /* Else K1 = (L << 1U) xor Rb; see Sec. 5.3 for the definition of Rb. */
    phCryptoSym_mBedTLS_Int_CMAC_LeftShift(aBuffer, (uint8_t) wBlockSize, pSubKey1);
    if(0U != (aBuffer[0] & 0x80U))
    {
        /* We need to perform the XOR operation with the R_b array */
        pSubKey1[wBlockSize - 1U] ^= bR_b;
    }
    else
    {
        /* We are done with key1 generation */
    }

    /* Now let's continue with Key 2 */
    /* Shift the pSubKey array according to NIST SP_800-38B*/
    /* 3. If MSB1(K1) = 0, then K2 = K1 << 1U; */
    /* Else K2 = (K1 << 1U) xor Rb. */
    phCryptoSym_mBedTLS_Int_CMAC_LeftShift(pSubKey1, (uint8_t) wBlockSize, pSubKey2);
    if(0U != (pSubKey1[0] & 0x80U))
    {
        /* We need to perform the XOR operation with the R_b array */
        pSubKey2[wBlockSize - 1U] ^= bR_b;
    }
    else
    {
        /* We are done with key2 generation */
    }

    /* Clear buffer for security reasons */
    (void) memset(aBuffer, 0x00, (size_t)sizeof(aBuffer));

    return PH_ERR_SUCCESS;
}

void phCryptoSym_mBedTLS_Int_CMAC_LeftShift(const uint8_t * pInBuff, uint8_t bInLen, uint8_t * pOutBuff)
{
    uint8_t PH_MEMLOC_REM bOverflow = 0;

    do
    {
        bInLen--;
        pOutBuff[bInLen] = pInBuff[bInLen] << 1U;
        pOutBuff[bInLen] |= bOverflow;
        bOverflow = (uint8_t) (((pInBuff[bInLen] & 0x80U) != 0U) ? 0x01U : 0x00U);
    } while(0U != bInLen);
}

phStatus_t phCryptoSym_mBedTLS_Int_Des_DecodeVersion(uint8_t * pKey, uint16_t * pKeyVer)
{
    uint8_t PH_MEMLOC_REM bIndex = 0;

    /* Init. KeyVersion */
    *pKeyVer = 0x00;

    /* Parse KeyVersion */
    for(bIndex = 0; bIndex < PH_CRYPTOSYM_DES_KEY_SIZE; ++bIndex)
    {
        *pKeyVer |= (pKey[bIndex] & 0x01U) << (7U - bIndex);
    }

    return PH_ERR_SUCCESS;
}

phStatus_t phCryptoSym_mBedTLS_Int_Des_EncodeVersion(uint8_t * pKey, uint16_t wKeyVer, uint16_t wKeyType, uint8_t * pEncodedKey)
{
    uint8_t PH_MEMLOC_REM bIndex = 0;
    uint8_t PH_MEMLOC_REM bKeySize = 0;

    /* Parameter check */
    if((wKeyType != PH_CRYPTOSYM_KEY_TYPE_DES) &&
        (wKeyType != PH_CRYPTOSYM_KEY_TYPE_2K3DES) &&
        (wKeyType != PH_CRYPTOSYM_KEY_TYPE_3K3DES))
    {
        return PH_ADD_COMPCODE_FIXED(PH_ERR_INVALID_PARAMETER, PH_COMP_CRYPTOSYM);
    }

    /* Retrieve KeySize */
    bKeySize = (uint8_t) phCryptoSym_GetKeySize(wKeyType);

    /* Insert KeyVersion */
    for(bIndex = 0; bIndex < bKeySize; ++bIndex)
    {
        pEncodedKey[bIndex] = (uint8_t) ((pKey[bIndex] & 0xFEU) | ((wKeyVer >> (7 - (bIndex % 8))) & 0x01));
    }

    return PH_ERR_SUCCESS;
}

#endif /* NXPBUILD__PH_CRYPTOSYM_MBEDTLS */
