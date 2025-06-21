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

#include <mbedtls_config_sw.h>

#include "phCryptoSym_mBedTLS.h"
#include "phCryptoSym_mBedTLS_Int.h"

phStatus_t phCryptoSym_mBedTLS_Init(phCryptoSym_mBedTLS_DataParams_t * pDataParams, uint16_t wSizeOfDataParams, void * pKeyStoreDataParams,
    uint8_t *pAddData_Buffer, uint16_t wAddData_Size)
{
    phStatus_t wStatus = 0;
    if(sizeof(phCryptoSym_mBedTLS_DataParams_t) != wSizeOfDataParams)
    {
        return PH_ADD_COMPCODE_FIXED(PH_ERR_INVALID_DATA_PARAMS, PH_COMP_CRYPTOSYM);
    }

    PH_ASSERT_NULL(pDataParams);

    if(wAddData_Size > 0)
    {
        PH_ASSERT_NULL_PARAM(pAddData_Buffer, PH_COMP_CRYPTOSYM);
    }

    if(wAddData_Size > 65280U)
    {
        return PH_ADD_COMPCODE_FIXED(PH_ERR_INVALID_PARAMETER, PH_COMP_CRYPTOSYM);
    }

    /* Init. private data */
    pDataParams->wId = PH_COMP_CRYPTOSYM | PH_CRYPTOSYM_MBEDTLS_ID;
    pDataParams->pKeyStoreDataParams = pKeyStoreDataParams;

    /* Buffer for CCM operation */
    pDataParams->pAddData = pAddData_Buffer;
    pDataParams->wAddData_Size = wAddData_Size;
    pDataParams->wAddData_Len = 0;

    pDataParams->bIV_Len = 0;

    /* Invalidate keys */
    PH_CHECK_SUCCESS_FCT(wStatus, phCryptoSym_mBedTLS_InvalidateKey(pDataParams));

    /* Initialize mBedTLS alternate initialization. */

    return PH_ERR_SUCCESS;
}

phStatus_t phCryptoSym_mBedTLS_DeInit(phCryptoSym_mBedTLS_DataParams_t * pDataParams)
{

    /* Reset members of Data Params */
    (void) memset(pDataParams->pAddData, 0x00, pDataParams->wAddData_Size);
    pDataParams->wAddData_Size = 0;
    pDataParams->wAddData_Len = 0;

    (void) memset(pDataParams->aIV, 0x00, sizeof(pDataParams->aIV));
    pDataParams->bIV_Len = 0;

    /* Invalidate keys */
    phCryptoSym_mBedTLS_InvalidateKey(pDataParams);

    return PH_ERR_SUCCESS;
}

phStatus_t phCryptoSym_mBedTLS_InvalidateKey(phCryptoSym_mBedTLS_DataParams_t * pDataParams)
{
    /* Reset all the key storage */
    (void) memset(pDataParams->aKey, 0x00, sizeof(pDataParams->aKey));

    (void) memset(pDataParams->aIV, 0x00, sizeof(pDataParams->aIV));
    pDataParams->bIV_Len = 0;

    pDataParams->wKeyNo = 0xFFU;
    pDataParams->wKeyType = PH_CRYPTOSYM_KEY_TYPE_INVALID;
    pDataParams->wKeepIV = PH_CRYPTOSYM_VALUE_KEEP_IV_OFF;
    pDataParams->wAddInfo = 0U;
    pDataParams->bIsDirectKey = PH_ON;
    pDataParams->wKey_Bit = 0x00U;

    /* Clear the context. */
    phCryptoSym_mBedTLS_Int_FreeContext(pDataParams, PH_CRYPTOSYM_CIPHER_MODE_CBC);

    phCryptoSym_mBedTLS_Int_FreeContext(pDataParams, PH_CRYPTOSYM_CIPHER_MODE_CCM);

    return PH_ERR_SUCCESS;
}

phStatus_t phCryptoSym_mBedTLS_Encrypt(phCryptoSym_mBedTLS_DataParams_t * pDataParams, uint16_t wOption, const uint8_t * pPlainBuff,
    uint16_t wPlainBuffLen, uint8_t * pEncBuff)
{
    phStatus_t  PH_MEMLOC_REM wStatus = 0;
    uint16_t    PH_MEMLOC_REM wBlockSize = 0;
    uint16_t    PH_MEMLOC_REM wBufOption = 0;
    uint16_t    PH_MEMLOC_REM wIndex = 0;
    uint8_t     PH_MEMLOC_REM bIndex_BlockSize = 0;
    uint8_t     PH_MEMLOC_REM bCipherMode = 0;

    uint8_t     PH_MEMLOC_REM * pIv = NULL;

    /* Clear the Error Code. */
    pDataParams->dwErrorCode = 0;

    /* Extract the Cipher mode. */
    bCipherMode = (uint8_t) (wOption & 0x000FU);

    /* Get the Buffering option. */
    wBufOption = (uint16_t) (wOption & PH_EXCHANGE_BUFFER_MASK);

    /* Check that the input buffer length is a multiple of the block size; */
    if((bCipherMode != PH_CRYPTOSYM_CIPHER_MODE_CCM) && (bCipherMode != PH_CRYPTOSYM_CIPHER_MODE_CCM_STAR))

    {
        /* Get the block size of the currently loaded key */
        PH_CHECK_SUCCESS_FCT(wStatus, phCryptoSym_mBedTLS_GetConfig(pDataParams, PH_CRYPTOSYM_CONFIG_BLOCK_SIZE,
            &wBlockSize));

        if(wPlainBuffLen % wBlockSize)
        {
            return PH_ADD_COMPCODE_FIXED(PH_ERR_INVALID_PARAMETER, PH_COMP_CRYPTOSYM);
        }
    }

    /* Set the IV to the iv specified in the private data params */
    pIv = pDataParams->aIV;

    /* Initialize the context. */
    phCryptoSym_mBedTLS_Int_InitContext(pDataParams, bCipherMode);

    /* Perform Encryption based on the cipher Mode. */
    switch(bCipherMode)
    {
        case PH_CRYPTOSYM_CIPHER_MODE_ECB:
            /* Load the Key to use. */
            PH_CHECK_SUCCESS_FCT(wStatus, phCryptoSym_mBedTLS_Int_LoadKey(pDataParams, PH_CRYPTOSYM_ENCRYPTION,
                PH_CRYPTOSYM_CIPHER_MODE_ECB));

            /* Iterate over all blocks and perform the encryption*/
            wIndex = 0;

            while(wIndex < wPlainBuffLen)
            {
                wStatus = phCryptoSym_mBedTLS_Int_Crypt_ECB(pDataParams, PH_CRYPTOSYM_ENCRYPTION, pDataParams->wKeyType,
                    &pPlainBuff[wIndex], &pEncBuff[wIndex]);

                /* Break the loop in case of error. */
                if((wStatus & PH_ERR_MASK) != PH_ERR_SUCCESS)
                    break;

                /* Update the loop counter */
                wIndex = wBlockSize + wIndex;
            }
            break;

        case PH_CRYPTOSYM_CIPHER_MODE_CBC_DF4:
            /* Load the Key to use. */
            PH_CHECK_SUCCESS_FCT(wStatus, phCryptoSym_mBedTLS_Int_LoadKey(pDataParams, PH_CRYPTOSYM_DECRYPTION,
                PH_CRYPTOSYM_CIPHER_MODE_CBC_DF4));

            /* Iterate over all blocks and perform the encryption*/
            wIndex = 0;

            while(wIndex < wPlainBuffLen)
            {
                /* Is the output array the same as the input array? Else we need to recopy the plain text upfront */
                if(pPlainBuff != pEncBuff)
                {
                    (void) memcpy(&pEncBuff[wIndex], &pPlainBuff[wIndex], wBlockSize);
                }

                /* Perform XOR before decryption. */
                for(bIndex_BlockSize = 0; bIndex_BlockSize < wBlockSize; bIndex_BlockSize++)
                {
                    pEncBuff[bIndex_BlockSize + wIndex] ^= pIv[bIndex_BlockSize];
                }

                /* Perform Decryption based on block. */
                wStatus = phCryptoSym_mBedTLS_Int_Crypt_ECB(pDataParams, PH_CRYPTOSYM_DECRYPTION, pDataParams->wKeyType,
                    &pEncBuff[wIndex], &pEncBuff[wIndex]);

                /* Break the loop in case of error. */
                if((wStatus & PH_ERR_MASK) != PH_ERR_SUCCESS)
                    break;

                /* we should set the IV now to the old cipher text... */
                pIv = &pEncBuff[wIndex];

                /* update the loop counter */
                wIndex = wBlockSize + wIndex;
            }
            break;

        case PH_CRYPTOSYM_CIPHER_MODE_CBC:
            /* Load the Key to use. */
            PH_CHECK_SUCCESS_FCT(wStatus, phCryptoSym_mBedTLS_Int_LoadKey(pDataParams, PH_CRYPTOSYM_ENCRYPTION,
                PH_CRYPTOSYM_CIPHER_MODE_CBC));

            wStatus = phCryptoSym_mBedTLS_Int_Crypt_CBC(pDataParams, PH_CRYPTOSYM_ENCRYPTION, pDataParams->wKeyType, pIv,
                pPlainBuff, wPlainBuffLen, pEncBuff);
            break;

        case PH_CRYPTOSYM_CIPHER_MODE_CCM:
        case PH_CRYPTOSYM_CIPHER_MODE_CCM_STAR:
            /* Check if Tag length is not specified. */
            if((bCipherMode == PH_CRYPTOSYM_CIPHER_MODE_CCM) && (pDataParams->bTagLen == 0))
            {
                return PH_ADD_COMPCODE(PH_ERR_INVALID_PARAMETER, PH_COMP_CRYPTOSYM);
            }

            /* Load the Key to use. */
            PH_CHECK_SUCCESS_FCT(wStatus, phCryptoSym_mBedTLS_Int_LoadKey(pDataParams, PH_CRYPTOSYM_ENCRYPTION,
                PH_CRYPTOSYM_CIPHER_MODE_CCM));

            wStatus = phCryptoSym_mBedTLS_Int_Crypt_CCM_EncyptTag(pDataParams, wOption, bCipherMode,
                pIv, pDataParams->bIV_Len, pDataParams->pAddData, pDataParams->wAddData_Len, pPlainBuff,
                wPlainBuffLen, pEncBuff);
            break;

        default:
            wStatus = PH_ADD_COMPCODE_FIXED(PH_ERR_UNSUPPORTED_PARAMETER, PH_COMP_CRYPTOSYM);
            break;
    }

    /* Do the final update of the IV according to the keep IV setting. */
    if((wStatus & PH_ERR_MASK) == PH_ERR_SUCCESS)
    {
        if((pDataParams->wKeepIV == PH_CRYPTOSYM_VALUE_KEEP_IV_ON) || (wBufOption & PH_EXCHANGE_BUFFERED_BIT))
        {
            (void) memcpy(pDataParams->aIV, pIv, wBlockSize);
        }
    }

    /* Free the context for next operations. */
    phCryptoSym_mBedTLS_Int_FreeContext(pDataParams, bCipherMode);

    return wStatus;
}

phStatus_t phCryptoSym_mBedTLS_Decrypt(phCryptoSym_mBedTLS_DataParams_t * pDataParams, uint16_t wOption, uint8_t * pEncBuff,
    uint16_t  wEncBuffLen, uint8_t * pPlainBuff)
{
    phStatus_t  PH_MEMLOC_REM wStatus = 0;
    uint16_t    PH_MEMLOC_REM wBlockSize = 0;
    uint16_t    PH_MEMLOC_REM wIndex = 0;
    uint8_t     PH_MEMLOC_REM bCipherMode = 0;

    uint8_t     PH_MEMLOC_REM * pIv = NULL;

    /* Clear the Error Code. */
    pDataParams->dwErrorCode = 0;

    /* Extract the Cipher mode. */
    bCipherMode = (uint8_t) (wOption & 0x000FU);

    /* Check that the input buffer length is a multiple of the block size; */
    if((bCipherMode != PH_CRYPTOSYM_CIPHER_MODE_CCM) && (bCipherMode != PH_CRYPTOSYM_CIPHER_MODE_CCM_STAR))

    {
        /* Get the block size of the currently loaded key. */
        PH_CHECK_SUCCESS_FCT(wStatus, phCryptoSym_mBedTLS_GetConfig(pDataParams, PH_CRYPTOSYM_CONFIG_BLOCK_SIZE,
            &wBlockSize));

        if(wEncBuffLen % wBlockSize)
        {
            return PH_ADD_COMPCODE_FIXED(PH_ERR_INVALID_PARAMETER, PH_COMP_CRYPTOSYM);
        }
    }

    /* Set the IV to the iv specified in the private data params */
    pIv = pDataParams->aIV;

    /* Initialize the context. */
    phCryptoSym_mBedTLS_Int_InitContext(pDataParams, bCipherMode);

    /* Load the Key to use. */
    PH_CHECK_SUCCESS_FCT(wStatus, phCryptoSym_mBedTLS_Int_LoadKey(pDataParams, PH_CRYPTOSYM_DECRYPTION, bCipherMode));

    /* Perform Decryption based on the cipher Mode. */
    switch(bCipherMode)
    {
        case PH_CRYPTOSYM_CIPHER_MODE_ECB:
            /*Iterate over all blocks and perform the decryption. */
            wIndex = 0;

            while(wIndex < wEncBuffLen)
            {
                wStatus = phCryptoSym_mBedTLS_Int_Crypt_ECB(pDataParams, PH_CRYPTOSYM_DECRYPTION, pDataParams->wKeyType,
                    &pEncBuff[wIndex], &pPlainBuff[wIndex]);

                /* Break the loop in case of error. */
                if((wStatus & PH_ERR_MASK) != PH_ERR_SUCCESS)
                    break;

                /* Update the loop counter */
                wIndex = wBlockSize + wIndex;
            }
            break;

        case PH_CRYPTOSYM_CIPHER_MODE_CBC:
        case PH_CRYPTOSYM_CIPHER_MODE_CBC_DF4:
            wStatus = phCryptoSym_mBedTLS_Int_Crypt_CBC(pDataParams, PH_CRYPTOSYM_DECRYPTION, pDataParams->wKeyType, pIv,
                pEncBuff, wEncBuffLen, pPlainBuff);
            break;

        case PH_CRYPTOSYM_CIPHER_MODE_CCM:
        case PH_CRYPTOSYM_CIPHER_MODE_CCM_STAR:
            wStatus = phCryptoSym_mBedTLS_Int_Crypt_CCM_AuthDecrypt(pDataParams, wOption, bCipherMode, pIv, pDataParams->bIV_Len,
                pDataParams->pAddData, pDataParams->wAddData_Len, pEncBuff, wEncBuffLen, pPlainBuff);
            break;

        default:
            wStatus = PH_ADD_COMPCODE_FIXED(PH_ERR_UNSUPPORTED_PARAMETER, PH_COMP_CRYPTOSYM);
            break;
    }

    /* Do the final update of the IV according to the keep IV setting. */
    if((wStatus & PH_ERR_MASK) == PH_ERR_SUCCESS)
    {
        if((pDataParams->wKeepIV == PH_CRYPTOSYM_VALUE_KEEP_IV_ON) || (wOption & PH_EXCHANGE_BUFFERED_BIT))
        {
            (void) memcpy(pDataParams->aIV, pIv, wBlockSize);
        }
    }

    /* Free the context for next operations. */
    phCryptoSym_mBedTLS_Int_FreeContext(pDataParams, bCipherMode);

    return wStatus;
}

phStatus_t phCryptoSym_mBedTLS_CalculateMac(phCryptoSym_mBedTLS_DataParams_t * pDataParams, uint16_t wOption, const uint8_t * pData,
    uint16_t  wDataLen, uint8_t * pMac, uint8_t * pMacLen)
{
    phStatus_t  PH_MEMLOC_REM wStatus = 0;
    uint16_t    PH_MEMLOC_REM wBlockSize = 0;
    uint8_t     PH_MEMLOC_REM bPaddingLen = 0;
    uint16_t    PH_MEMLOC_REM wIndex_Buff = 0;
    uint8_t     PH_MEMLOC_REM bIndex_BlockSize = 0;
    uint8_t     PH_MEMLOC_REM bLastBlock[16];
    uint8_t     PH_MEMLOC_REM aSubKey1[PH_CRYPTOSYM_MAX_BLOCK_SIZE];
    uint8_t     PH_MEMLOC_REM aSubKey2[PH_CRYPTOSYM_MAX_BLOCK_SIZE];
    uint8_t *   PH_MEMLOC_REM pIv = NULL;

    /* Validate supported MAC modes. */
    PH_CRYPTOSYM_VALIDATE_MAC_MODE(wOption);

    /* Clear the last block array */
    (void) memset(bLastBlock, 0, sizeof(bLastBlock));
    (void) memset(aSubKey1, 0x00, sizeof(aSubKey1));
    (void) memset(aSubKey2, 0x00, sizeof(aSubKey2));

    /* Clear MAC buffer Length. */
    *pMacLen = 0;

    /* Get the block size of the currently loaded key */
    PH_CHECK_SUCCESS_FCT(wStatus, phCryptoSym_mBedTLS_GetConfig(pDataParams, PH_CRYPTOSYM_CONFIG_BLOCK_SIZE, &wBlockSize));

    /* In case of a first block and in case of KEEP_IV is not set, the IV has to be cleared. */
    if((0U != (wOption & PH_EXCHANGE_LEAVE_BUFFER_BIT)) ||
            (pDataParams->wKeepIV == PH_CRYPTOSYM_VALUE_KEEP_IV_ON))
    {
        /* better leave the IV */
    }
    else
    {
        (void) memset(pDataParams->aIV, 0x00, wBlockSize);
    }

    /* Now we may start with  MAC calculation */
    /*Let's find out whether we should complete the MAC or if this is just an intermediate MAC calculation */
    if(0U != (wOption & PH_EXCHANGE_BUFFERED_BIT))
    {
        /* This is just an intermediate MAC */

        /* In this case we do not allow incomplete blocks. */
        if(0U != (wDataLen % wBlockSize))
        {
            return PH_ADD_COMPCODE_FIXED(PH_ERR_INVALID_PARAMETER, PH_COMP_CRYPTOSYM);
        }
    }
    else
    {
        if(((uint8_t) (wOption)) == PH_CRYPTOSYM_MAC_MODE_CMAC)
        {
            /* Always perform with sub key generation */
            PH_CHECK_SUCCESS_FCT(wStatus, phCryptoSym_mBedTLS_Int_CMAC_GenerateK1K2(pDataParams, wBlockSize, aSubKey1, aSubKey2));
        }

        /* Get number of bytes in last block */
        bPaddingLen = (uint8_t) (wDataLen % wBlockSize);

        /* do we have incomplete blocks? */
        if((0U != bPaddingLen) || (wDataLen == 0x0000U))
        {
            /* Update wDataLen, last block is in other array */
            wDataLen = (uint16_t) (wDataLen - bPaddingLen);

            (void) memcpy(bLastBlock, &pData[wDataLen], bPaddingLen);

            /* Apply padding byte*/
            bLastBlock[bPaddingLen] = 0x80;
            /* pad with zeros not necessary, memset done upfront*/

            if((uint8_t) wOption == PH_CRYPTOSYM_MAC_MODE_CMAC)
            {
                /* XOR with K2, as we have an icomplete block */
                for(bIndex_BlockSize = 0; bIndex_BlockSize < wBlockSize; bIndex_BlockSize++)
                {
                    bLastBlock[bIndex_BlockSize] ^= aSubKey2[bIndex_BlockSize];
                }
            }
        }
        else
        {
            /* Update wDataLen, last block is in other array */
            wDataLen = wDataLen - wBlockSize;

            /* Copy whole block into bLastBlock */
            (void) memcpy(bLastBlock, &pData[wDataLen], wBlockSize);

            if((uint8_t) wOption == PH_CRYPTOSYM_MAC_MODE_CMAC)
            {
                /* XOR with K1, as we have a complete block */
                for(bIndex_BlockSize = 0; bIndex_BlockSize < wBlockSize; bIndex_BlockSize++)
                {
                    bLastBlock[bIndex_BlockSize] ^= aSubKey1[bIndex_BlockSize];
                }
            }
        }
    }

    /* Set the IV to the iv specified in the private data params */
    pIv = pDataParams->aIV;

    /*Iterate over all blocks and perform the CBC encryption*/
    wIndex_Buff = 0;
    while(wIndex_Buff < wDataLen)
    {
        /* perform the XOR with the previous cipher block */
        for(bIndex_BlockSize = 0; bIndex_BlockSize < wBlockSize; bIndex_BlockSize++)
        {
            pMac[bIndex_BlockSize] = pIv[bIndex_BlockSize] ^ pData[wIndex_Buff + bIndex_BlockSize];
        }

        PH_CHECK_SUCCESS_FCT(wStatus, phCryptoSym_mBedTLS_Encrypt(pDataParams, PH_CRYPTOSYM_CIPHER_MODE_ECB, pMac,
                wBlockSize, pMac));

        /* set pIv to last cipher block*/
        pIv = pMac;

        /* update the loop counter */
        wIndex_Buff = wBlockSize + wIndex_Buff;
    }

    /* If we have a complete MAC, lets encrypt the last block */
    if(0U == (wOption & PH_EXCHANGE_BUFFERED_BIT))
    {
        /* Encrypt last block. */
        /* perform the XOR with the previous cipher block */
        for(bIndex_BlockSize = 0; bIndex_BlockSize < wBlockSize; bIndex_BlockSize++)
        {
            pMac[bIndex_BlockSize] = pIv[bIndex_BlockSize] ^ bLastBlock[bIndex_BlockSize];
        }

        PH_CHECK_SUCCESS_FCT(wStatus, phCryptoSym_mBedTLS_Encrypt(pDataParams, PH_CRYPTOSYM_CIPHER_MODE_ECB, pMac,
                wBlockSize, pMac));
    }

    /* do the final update of the IV according to the settings */
    if((pDataParams->wKeepIV == PH_CRYPTOSYM_VALUE_KEEP_IV_ON) || (0U != (wOption & PH_EXCHANGE_BUFFERED_BIT)))
    {
        (void) memcpy(pDataParams->aIV, pMac, wBlockSize);
    }
    else
    {
        /* Clear the IV for security reasons */
        (void) memset(pDataParams->aIV, 0, wBlockSize);
    }

    /* Clear key arrays */
    (void) memset(aSubKey1, 0x00, sizeof(aSubKey1));
    (void) memset(aSubKey2, 0x00, sizeof(aSubKey2));

    *pMacLen = (uint8_t) wBlockSize;
    return PH_ERR_SUCCESS;
}

phStatus_t phCryptoSym_mBedTLS_LoadIv(phCryptoSym_mBedTLS_DataParams_t * pDataParams, const uint8_t * pIV, uint8_t bIVLen)
{
    phStatus_t  PH_MEMLOC_REM wStatus = 0;
    uint16_t    PH_MEMLOC_REM wBlockSize = 0;

    /* Get the block size of the currently loaded key */
    PH_CHECK_SUCCESS_FCT(wStatus, phCryptoSym_mBedTLS_GetConfig(pDataParams, PH_CRYPTOSYM_CONFIG_BLOCK_SIZE, &wBlockSize));

    /* Check block-size */
    if(bIVLen != wBlockSize)
    {
        return PH_ADD_COMPCODE_FIXED(PH_ERR_INVALID_PARAMETER, PH_COMP_CRYPTOSYM);
    }

    /* Update IV */
    (void) memcpy(pDataParams->aIV, pIV, wBlockSize);
    pDataParams->bIV_Len = bIVLen;

    return PH_ERR_SUCCESS;
}

phStatus_t phCryptoSym_mBedTLS_LoadNonce(phCryptoSym_mBedTLS_DataParams_t * pDataParams, uint8_t bCipher, const uint8_t * pNonce,
    uint8_t bNonceLen)
{
    switch(bCipher)
    {
        case PH_CRYPTOSYM_CIPHER_MODE_CCM:
            if((bNonceLen < 7U) || (bNonceLen > 13U))
            {
                return PH_ADD_COMPCODE(PH_ERR_INVALID_PARAMETER, PH_COMP_CRYPTOSYM);
            }
            break;

        case PH_CRYPTOSYM_CIPHER_MODE_CCM_STAR:
            if((bNonceLen != 0) && ((bNonceLen < 7U) || (bNonceLen > 13U)))
            {
                return PH_ADD_COMPCODE(PH_ERR_INVALID_PARAMETER, PH_COMP_CRYPTOSYM);
            }
            break;

        default:
            return PH_ADD_COMPCODE(PH_ERR_INVALID_PARAMETER, PH_COMP_CRYPTOSYM);
    }

    /* Update IV */
    (void) memcpy(pDataParams->aIV, pNonce, bNonceLen);
    pDataParams->bIV_Len = bNonceLen;

    return PH_ERR_SUCCESS;
}

phStatus_t phCryptoSym_mBedTLS_LoadAdditionalData(phCryptoSym_mBedTLS_DataParams_t * pDataParams, const uint8_t * pAddData,
    uint16_t wAddData_Len)
{
    /* Update Additional Data. */
    (void) memcpy(pDataParams->pAddData, pAddData, wAddData_Len);
    pDataParams->wAddData_Len = wAddData_Len;

    return PH_ERR_SUCCESS;
}

phStatus_t phCryptoSym_mBedTLS_LoadKey(phCryptoSym_mBedTLS_DataParams_t * pDataParams, uint16_t wKeyNo, uint16_t wKeyVer, uint16_t wKeyType)
{
#ifdef NXPBUILD__PH_KEYSTORE
    phStatus_t  PH_MEMLOC_REM wStatus = 0;
    uint8_t     PH_MEMLOC_BUF aKey[PH_CRYPTOSYM_AES256_KEY_SIZE];
    uint16_t    PH_MEMLOC_REM wKeyTypeStorage = 0;

    /* Update DataParams members */
    pDataParams->wKeyType = PH_CRYPTOSYM_KEY_TYPE_INVALID;
    pDataParams->wKeyNo = 0xFFU;
    pDataParams->bIsDirectKey = PH_ON;

    /* Not possible without KeyStore */
    if(pDataParams->pKeyStoreDataParams == NULL)
    {
        return PH_ADD_COMPCODE_FIXED(PH_ERR_UNSUPPORTED_COMMAND, PH_COMP_CRYPTOSYM);
    }

    /* Retrieve key settings */
    PH_CHECK_SUCCESS_FCT(wStatus, phKeyStore_GetKey(
        pDataParams->pKeyStoreDataParams,
        wKeyNo,
        wKeyVer,
        sizeof(aKey),
        aKey,
        &wKeyTypeStorage));

    /* KeyType should match */
    if(wKeyType != wKeyTypeStorage)
    {
        return PH_ADD_COMPCODE_FIXED(PH_ERR_INVALID_PARAMETER, PH_COMP_CRYPTOSYM);
    }

    /* Finally load the key */
    PH_CHECK_SUCCESS_FCT(wStatus, phCryptoSym_mBedTLS_LoadKeyDirect(pDataParams, aKey, wKeyTypeStorage));

    /* For security reasons */
    (void) memset(aKey, 0x00, sizeof(aKey));

    return PH_ERR_SUCCESS;
#else
    /* satisfy compiler */
    if(pDataParams || wKeyNo || wKeyVer || wKeyType);
    return PH_ADD_COMPCODE_FIXED(PH_ERR_UNSUPPORTED_COMMAND, PH_COMP_CRYPTOSYM);
#endif /* NXPBUILD__PH_KEYSTORE */
}

phStatus_t phCryptoSym_mBedTLS_LoadKeyDirect(phCryptoSym_mBedTLS_DataParams_t * pDataParams, const uint8_t * pKey, uint16_t wKeyType)
{
    phStatus_t  PH_MEMLOC_REM wStatus = 0;
    uint8_t     PH_MEMLOC_REM bIsDirectKey = PH_ON;

    if(bIsDirectKey == PH_ON)
    {
        pDataParams->wKeyNo = 0xFFU;

        switch(wKeyType)
        {
    #ifdef PH_CRYPTOSYM_DES
    #ifndef MBEDTLS_DES_ALT
            case PH_CRYPTOSYM_KEY_TYPE_DES:
                /* Copy the key to DataParams. */
                (void) memcpy(pDataParams->aKey, pKey, PH_CRYPTOSYM_DES_KEY_SIZE);
                break;
    #endif /* MBEDTLS_DES_ALT */

            case PH_CRYPTOSYM_KEY_TYPE_2K3DES:
                /* Copy the key to DataParams. */
                (void) memcpy(pDataParams->aKey, pKey, PH_CRYPTOSYM_2K3DES_KEY_SIZE);
                break;

            case PH_CRYPTOSYM_KEY_TYPE_3K3DES:
                /* Copy the key to DataParams. */
                (void) memcpy(pDataParams->aKey, pKey, PH_CRYPTOSYM_3K3DES_KEY_SIZE);
                break;
    #endif /* PH_CRYPTOSYM_DES */

    #ifdef PH_CRYPTOSYM_AES
            case PH_CRYPTOSYM_KEY_TYPE_AES128:
                /* Copy the key to DataParams. */
                (void) memcpy(pDataParams->aKey, pKey, PH_CRYPTOSYM_AES128_KEY_SIZE);
                break;

    #ifndef MBEDTLS_AES_ALT
            case PH_CRYPTOSYM_KEY_TYPE_AES192:
                /* Copy the key to DataParams. */
                (void) memcpy(pDataParams->aKey, pKey, PH_CRYPTOSYM_AES192_KEY_SIZE);
                break;
    #endif /* MBEDTLS_AES_ALT */

            case PH_CRYPTOSYM_KEY_TYPE_AES256:
                /* Copy the key to DataParams. */
                (void) memcpy(pDataParams->aKey, pKey, PH_CRYPTOSYM_AES256_KEY_SIZE);
                break;
    #endif /* PH_CRYPTOSYM_AES */

            default:
                PH_UNUSED_VARIABLE(pDataParams);
                PH_UNUSED_VARIABLE(wKeyType);
                PH_UNUSED_VARIABLE(pKey);
                bIsDirectKey = PH_OFF;
                wStatus = PH_ADD_COMPCODE_FIXED(PH_ERR_UNSUPPORTED_PARAMETER, PH_COMP_CRYPTOSYM);
                break;
        }
    }

    /* Update DataParams members */
    pDataParams->wKeyType = wKeyType;
    pDataParams->bIsDirectKey = bIsDirectKey;

    return wStatus;
}

phStatus_t phCryptoSym_mBedTLS_DiversifyKey(phCryptoSym_mBedTLS_DataParams_t * pDataParams, uint16_t wOption, uint16_t wKeyNo, uint16_t wKeyVer,
    uint8_t * pDivInput, uint8_t  bDivInputLen, uint8_t * pDiversifiedKey, uint8_t * pDivKeyLen)
{
#ifdef NXPBUILD__PH_KEYSTORE
    phStatus_t  PH_MEMLOC_REM wStatus = 0;
    uint8_t     PH_MEMLOC_REM aKey[PH_CRYPTOSYM_AES256_KEY_SIZE];
    uint16_t    PH_MEMLOC_REM wKeyType = 0;

    /* Not possible without KeyStore */
    if(pDataParams->pKeyStoreDataParams == NULL)
    {
        return PH_ADD_COMPCODE_FIXED(PH_ERR_UNSUPPORTED_COMMAND, PH_COMP_CRYPTOSYM);
    }

    /* Parameter check */
    if(((wOption & PH_CRYPTOSYM_DIV_MODE_MASK) != PH_CRYPTOSYM_DIV_MODE_DESFIRE) &&
        ((wOption & PH_CRYPTOSYM_DIV_MODE_MASK) != PH_CRYPTOSYM_DIV_MODE_MIFARE_PLUS) &&
        ((wOption & PH_CRYPTOSYM_DIV_MODE_MASK) != PH_CRYPTOSYM_DIV_MODE_MIFARE_ULTRALIGHT))
    {
        return PH_ADD_COMPCODE_FIXED(PH_ERR_UNSUPPORTED_PARAMETER, PH_COMP_CRYPTOSYM);
    }

    /* Retrieve key from KeyStore */
    PH_CHECK_SUCCESS_FCT(wStatus, phKeyStore_GetKey(
        pDataParams->pKeyStoreDataParams,
        wKeyNo,
        wKeyVer,
        sizeof(aKey),
        aKey,
        &wKeyType));

    /* Perform diversification */
    PH_CHECK_SUCCESS_FCT(wStatus, phCryptoSym_mBedTLS_DiversifyDirectKey(
        pDataParams,
        wOption,
        aKey,
        wKeyType,
        pDivInput,
        bDivInputLen,
        pDiversifiedKey,
        pDivKeyLen));

    /* For security reasons */
    (void) memset(aKey, 0x00, sizeof(aKey));

    return PH_ERR_SUCCESS;

#else
    /* satisfy compiler */
    if(pDataParams || wKeyNo || wKeyVer || pDiversifiedKey || bDivInputLen || pDivInput || wOption);
    return PH_ADD_COMPCODE_FIXED(PH_ERR_UNSUPPORTED_COMMAND, PH_COMP_CRYPTOSYM);
#endif  /* NXPBUILD__PH_KEYSTORE */
}

phStatus_t phCryptoSym_mBedTLS_DiversifyDirectKey(phCryptoSym_mBedTLS_DataParams_t * pDataParams, uint16_t wOption, uint8_t * pKey, uint16_t wKeyType,
    uint8_t * pDivInput, uint8_t bDivInputLen, uint8_t * pDiversifiedKey, uint8_t * pDivKeyLen)
{
    phStatus_t  PH_MEMLOC_REM wStatus = 0;
    uint16_t    PH_MEMLOC_REM wKeyVer = 0;
    uint8_t     PH_MEMLOC_REM bTmpLen = 0;
    uint8_t     PH_MEMLOC_BUF aDivData[PH_CRYPTOSYM_MBEDTLS_KDIV_MFP_DIVLENGTH_AES_MAX + 1];

#ifndef MBEDTLS_AES_ALT
    uint8_t     PH_MEMLOC_BUF aMac[16];
#endif /* MBEDTLS_AES_ALT */

    /* To resolve warning */
    PH_UNUSED_VARIABLE(wKeyVer);

    /* Load the Key to diversify */
    PH_CHECK_SUCCESS_FCT(wStatus, phCryptoSym_mBedTLS_LoadKeyDirect(pDataParams, pKey, wKeyType));

    /* Check diversification method */
    switch(wOption & PH_CRYPTOSYM_DIV_MODE_MASK)
    {
        case PH_CRYPTOSYM_DIV_MODE_DESFIRE:
            switch(wKeyType)
            {
#ifdef PH_CRYPTOSYM_AES
                case PH_CRYPTOSYM_KEY_TYPE_AES128:
#ifndef MBEDTLS_AES_ALT
                case PH_CRYPTOSYM_KEY_TYPE_AES192:
#endif /* MBEDTLS_AES_ALT */
                    /* Parameter check */
                    if(bDivInputLen != PH_CRYPTOSYM_AES128_KEY_SIZE)
                    {
                        return PH_ADD_COMPCODE_FIXED(PH_ERR_INVALID_PARAMETER, PH_COMP_CRYPTOSYM);
                    }

                    /* Use the DivData as IV */
                    PH_CHECK_SUCCESS_FCT(wStatus, phCryptoSym_mBedTLS_LoadIv(pDataParams, pDivInput, bDivInputLen));

                    /* Retrieve KeySize */
                    bDivInputLen = (uint8_t) phCryptoSym_GetKeySize(wKeyType);

                    /* Copy Key to temporary diversification data */
                    (void) memcpy(aDivData, pKey, bDivInputLen);

                    /* Apply padding if necessary */
                    if((bDivInputLen % PH_CRYPTOSYM_AES_BLOCK_SIZE) != 0)
                    {
                        (void) memset(&aDivData[PH_CRYPTOSYM_AES192_KEY_SIZE], 0x00, 8);
                        bTmpLen = PH_CRYPTOSYM_AES192_KEY_SIZE + 8;
                    }
                    else
                    {
                        bTmpLen = bDivInputLen;
                    }

                    /* Initialize the context. */
                    phCryptoSym_mBedTLS_Int_InitContext(pDataParams, PH_CRYPTOSYM_CIPHER_MODE_CBC);

                    /* Perform Encryption */
                    wStatus = phCryptoSym_mBedTLS_Encrypt(
                        pDataParams,
                        (uint16_t) (PH_CRYPTOSYM_CIPHER_MODE_CBC | PH_EXCHANGE_BUFFER_CONT),
                        aDivData,
                        (uint16_t) bTmpLen,
                        aDivData);

                    /* Free the context for next operations. */
                    phCryptoSym_mBedTLS_Int_FreeContext(pDataParams, PH_CRYPTOSYM_CIPHER_MODE_CBC);

                    /* Perform Status Verification */
                    PH_CHECK_SUCCESS(wStatus);

                    /* Copy diversified Key to output buffer */
                    (void) memcpy(pDiversifiedKey, aDivData, bDivInputLen);
                    *pDivKeyLen = bDivInputLen;

                    pDataParams->wAddInfo = bDivInputLen;
                    break;
#endif /* PH_CRYPTOSYM_AES */

#ifdef PH_CRYPTOSYM_DES
#ifndef MBEDTLS_DES_ALT
                case PH_CRYPTOSYM_KEY_TYPE_DES:
#endif /* MBEDTLS_DES_ALT */
                case PH_CRYPTOSYM_KEY_TYPE_2K3DES:
                    /* Parameter check */
                    if(bDivInputLen != PH_CRYPTOSYM_DES_KEY_SIZE)
                    {
                        return PH_ADD_COMPCODE_FIXED(PH_ERR_INVALID_PARAMETER, PH_COMP_CRYPTOSYM);
                    }

                    /* Use the DivData as IV */
                    PH_CHECK_SUCCESS_FCT(wStatus, phCryptoSym_mBedTLS_LoadIv(pDataParams, pDivInput, bDivInputLen));

                    /* Retrieve KeyVersion */
                    PH_CHECK_SUCCESS_FCT(wStatus, phCryptoSym_mBedTLS_Int_Des_DecodeVersion(pKey, &wKeyVer));

                    /* Initialize the context. */
                    phCryptoSym_mBedTLS_Int_InitContext(pDataParams, PH_CRYPTOSYM_CIPHER_MODE_CBC);

                    /* Half-Key Diversification (DES 56 Bit Key Type ) */
                    if(wOption & PH_CRYPTOSYM_DIV_OPTION_2K3DES_HALF)
                    {
                        /* Perform Encryption */
                        wStatus = phCryptoSym_mBedTLS_Encrypt(
                            pDataParams,
                            (uint16_t) (PH_CRYPTOSYM_CIPHER_MODE_CBC | PH_EXCHANGE_BUFFER_CONT),
                            pKey,
                            PH_CRYPTOSYM_DES_KEY_SIZE,
                            pDiversifiedKey);

                        /* Free the context for next operations. */
                        phCryptoSym_mBedTLS_Int_FreeContext(pDataParams, PH_CRYPTOSYM_CIPHER_MODE_CBC);

                        /* Perform Status Verification */
                        PH_CHECK_SUCCESS(wStatus);

                        /* half key diversification -> copy first part to second part */
                        (void) memcpy(&pDiversifiedKey[PH_CRYPTOSYM_DES_KEY_SIZE], &pDiversifiedKey[0], PH_CRYPTOSYM_DES_KEY_SIZE);
                        *pDivKeyLen = (uint8_t) PH_CRYPTOSYM_DES_KEY_SIZE;

                        pDataParams->wAddInfo = PH_CRYPTOSYM_DES_KEY_SIZE;
                    }

                    /* Full-Key Diversification (DES2K3 - 112 Bit Key Type) */
                    else
                    {
                        /* Perform Encryption */
                        wStatus = phCryptoSym_mBedTLS_Encrypt(
                            pDataParams,
                            (uint16_t) (PH_CRYPTOSYM_CIPHER_MODE_CBC | PH_EXCHANGE_BUFFER_CONT),
                            pKey,
                            PH_CRYPTOSYM_2K3DES_KEY_SIZE,
                            pDiversifiedKey);

                        /* Free the context for next operations. */
                        phCryptoSym_mBedTLS_Int_FreeContext(pDataParams, PH_CRYPTOSYM_CIPHER_MODE_CBC);

                        /* Perform Status Verification */
                        PH_CHECK_SUCCESS(wStatus);

                        *pDivKeyLen = (uint8_t) PH_CRYPTOSYM_2K3DES_KEY_SIZE;

                        pDataParams->wAddInfo = PH_CRYPTOSYM_2K3DES_KEY_SIZE;
                    }

                    /* Re-Encode KeyVersion */
                    PH_CHECK_SUCCESS_FCT(wStatus, phCryptoSym_mBedTLS_Int_Des_EncodeVersion(pDiversifiedKey, wKeyVer, wKeyType, pDiversifiedKey));
                    break;

                case PH_CRYPTOSYM_KEY_TYPE_3K3DES:
                    /* Parameter check */
                    if(bDivInputLen != PH_CRYPTOSYM_DES_KEY_SIZE)
                    {
                        return PH_ADD_COMPCODE_FIXED(PH_ERR_INVALID_PARAMETER, PH_COMP_CRYPTOSYM);
                    }

                    /* Use the DivData as IV */
                    PH_CHECK_SUCCESS_FCT(wStatus, phCryptoSym_mBedTLS_LoadIv(pDataParams, pDivInput, bDivInputLen));

                    /* Retrieve KeyVersion */
                    PH_CHECK_SUCCESS_FCT(wStatus, phCryptoSym_mBedTLS_Int_Des_DecodeVersion(pKey, &wKeyVer));

                    /* Initialize the context. */
                    phCryptoSym_mBedTLS_Int_InitContext(pDataParams, PH_CRYPTOSYM_CIPHER_MODE_CBC);

                    /* Perform Encryption */
                    wStatus = phCryptoSym_mBedTLS_Encrypt(
                        pDataParams,
                        (uint16_t) (PH_CRYPTOSYM_CIPHER_MODE_CBC | PH_EXCHANGE_BUFFER_CONT),
                        pKey,
                        PH_CRYPTOSYM_3K3DES_KEY_SIZE,
                        pDiversifiedKey);

                    /* Free the context for next operations. */
                    phCryptoSym_mBedTLS_Int_FreeContext(pDataParams, PH_CRYPTOSYM_CIPHER_MODE_CBC);

                    /* Perform Status Verification */
                    PH_CHECK_SUCCESS(wStatus);

                    /* Re-Encode KeyVersion */
                    PH_CHECK_SUCCESS_FCT(wStatus, phCryptoSym_mBedTLS_Int_Des_EncodeVersion(pDiversifiedKey, wKeyVer, wKeyType, pDiversifiedKey));
                    *pDivKeyLen = (uint8_t) PH_CRYPTOSYM_3K3DES_KEY_SIZE;

                    pDataParams->wAddInfo = PH_CRYPTOSYM_3K3DES_KEY_SIZE;
                    break;
#endif /* PH_CRYPTOSYM_DES */

                default:
                    wStatus = PH_ADD_COMPCODE_FIXED(PH_ERR_INVALID_PARAMETER, PH_COMP_CRYPTOSYM);
                    break;
            }
            break;

        case PH_CRYPTOSYM_DIV_MODE_MIFARE_PLUS:
            /* Parameter check */
            if(bDivInputLen > PH_CRYPTOSYM_MBEDTLS_KDIV_MFP_DIVLENGTH_AES_MAX)
            {
                return PH_ADD_COMPCODE_FIXED(PH_ERR_INVALID_PARAMETER, PH_COMP_CRYPTOSYM);
            }

            /* Copy div. input */
            (void) memcpy(&aDivData[1], pDivInput, bDivInputLen);

            /* Increment div. input length */
            ++bDivInputLen;

            switch(wKeyType)
            {
#ifdef PH_CRYPTOSYM_AES
                case PH_CRYPTOSYM_KEY_TYPE_AES128:
                    /* Set div. header */
                    aDivData[0] = PH_CRYPTOSYM_MBEDTLS_KDIV_MFP_AES128_CONST;

                    /* Perform CMAC calculation. */
                    PH_CHECK_SUCCESS_FCT(wStatus, phCryptoSym_mBedTLS_Int_CMAC_Diversify(
                        pDataParams,
                        aDivData,
                        (uint16_t) bDivInputLen,
                        pDiversifiedKey,
                        &bTmpLen));
                    *pDivKeyLen = bTmpLen;

                    pDataParams->wAddInfo = bTmpLen;
                    break;

#ifndef MBEDTLS_AES_ALT
                case PH_CRYPTOSYM_KEY_TYPE_AES192:
                    /* Set div. header for DiversifiedKeyA */
                    aDivData[0] = PH_CRYPTOSYM_MBEDTLS_KDIV_MFP_AES192_CONST_1;

                    /* Perform CMAC calculation (KeyA) */
                    PH_CHECK_SUCCESS_FCT(wStatus, phCryptoSym_mBedTLS_Int_CMAC_Diversify(
                        pDataParams,
                        aDivData,
                        (uint16_t) bDivInputLen,
                        pDiversifiedKey,
                        &bTmpLen));

                    /* Set div. header for DiversifiedKeyB */
                    aDivData[0] = PH_CRYPTOSYM_MBEDTLS_KDIV_MFP_AES192_CONST_2;

                    /* Perform CMAC calculation (KeyB) */
                    PH_CHECK_SUCCESS_FCT(wStatus, phCryptoSym_mBedTLS_Int_CMAC_Diversify(
                        pDataParams,
                        aDivData,
                        (uint16_t) bDivInputLen,
                        aMac,
                        &bTmpLen));

                    /* perform DiversifiedKeyA[8-15] ^ DiversifiedKeyB[0-7] */
                    for(bTmpLen = 0; bTmpLen < 8; ++bTmpLen)
                    {
                        pDiversifiedKey[8 + bTmpLen] ^= aMac[bTmpLen];
                    }

                    /* copy DiversifiedKeyB[8-15] to DiversifiedKey[16-23] */
                    (void)memcpy(&pDiversifiedKey[16], &aMac[8], 8);
                    *pDivKeyLen = 24;

                    pDataParams->wAddInfo = 24;
                    break;

                case PH_CRYPTOSYM_KEY_TYPE_AES256:
                    /* Set div. header for DiversifiedKeyA */
                    aDivData[0] = PH_CRYPTOSYM_MBEDTLS_KDIV_MFP_AES256_CONST_1;

                    /* Perform MAC calculation (KeyA) */
                    PH_CHECK_SUCCESS_FCT(wStatus, phCryptoSym_mBedTLS_Int_CMAC_Diversify(
                        pDataParams,
                        aDivData,
                        (uint16_t) bDivInputLen,
                        &pDiversifiedKey[0],
                        &bTmpLen));

                    /* Set div. header for DiversifiedKeyB */
                    aDivData[0] = PH_CRYPTOSYM_MBEDTLS_KDIV_MFP_AES256_CONST_2;

                    /* Perform MAC calculation (KeyB) */
                    PH_CHECK_SUCCESS_FCT(wStatus, phCryptoSym_mBedTLS_Int_CMAC_Diversify(
                        pDataParams,
                        aDivData,
                        (uint16_t) bDivInputLen,
                        &pDiversifiedKey[16],
                        &bTmpLen));

                    pDataParams->wAddInfo = 32;
                    break;
#endif /* MBEDTLS_AES_ALT */
#endif /* PH_CRYPTOSYM_AES */

#ifdef PH_CRYPTOSYM_DES
#ifndef MBEDTLS_DES_ALT
                case PH_CRYPTOSYM_KEY_TYPE_DES:
#endif /* MBEDTLS_DES_ALT */
                case PH_CRYPTOSYM_KEY_TYPE_2K3DES:
                    /* Set div. header for DiversifiedKeyA */
                    aDivData[0] = PH_CRYPTOSYM_MBEDTLS_KDIV_MFP_3DES_CONST_1;

                    /* Perform CMAC calculation (KeyA) */
                    PH_CHECK_SUCCESS_FCT(wStatus, phCryptoSym_mBedTLS_Int_CMAC_Diversify(
                        pDataParams,
                        aDivData,
                        (uint16_t) bDivInputLen,
                        &pDiversifiedKey[0],
                        &bTmpLen));

                    /* Set div. header for DiversifiedKeyB */
                    aDivData[0] = PH_CRYPTOSYM_MBEDTLS_KDIV_MFP_3DES_CONST_2;

                    /* Perform CMAC calculation (KeyB) */
                    PH_CHECK_SUCCESS_FCT(wStatus, phCryptoSym_mBedTLS_Int_CMAC_Diversify(
                        pDataParams,
                        aDivData,
                        (uint16_t) bDivInputLen,
                        &pDiversifiedKey[8],
                        &bTmpLen));

                    *pDivKeyLen = 16;
                    pDataParams->wAddInfo = 16;
                    break;

                case PH_CRYPTOSYM_KEY_TYPE_3K3DES:
                    /* Set div. header for DiversifiedKeyA */
                    aDivData[0] = PH_CRYPTOSYM_MBEDTLS_KDIV_MFP_3KEY3DES_CONST_1;

                    /* Perform CMAC calculation (KeyA) */
                    PH_CHECK_SUCCESS_FCT(wStatus, phCryptoSym_mBedTLS_Int_CMAC_Diversify(
                        pDataParams,
                        aDivData,
                        (uint16_t) bDivInputLen,
                        &pDiversifiedKey[0],
                        &bTmpLen));

                    /* Set div. header for DiversifiedKeyB */
                    aDivData[0] = PH_CRYPTOSYM_MBEDTLS_KDIV_MFP_3KEY3DES_CONST_2;

                    /* Perform CMAC calculation (KeyB) */
                    PH_CHECK_SUCCESS_FCT(wStatus, phCryptoSym_mBedTLS_Int_CMAC_Diversify(
                        pDataParams,
                        aDivData,
                        (uint16_t) bDivInputLen,
                        &pDiversifiedKey[8],
                        &bTmpLen));

                    /* Set div. header for DiversifiedKeyC */
                    aDivData[0] = PH_CRYPTOSYM_MBEDTLS_KDIV_MFP_3KEY3DES_CONST_3;

                    /* Perform CMAC calculation (KeyC) */
                    PH_CHECK_SUCCESS_FCT(wStatus, phCryptoSym_mBedTLS_Int_CMAC_Diversify(
                        pDataParams,
                        aDivData,
                        (uint16_t) bDivInputLen,
                        &pDiversifiedKey[16],
                        &bTmpLen));

                    *pDivKeyLen = 24;
                    pDataParams->wAddInfo = 24;
                    break;
#endif /* PH_CRYPTOSYM_DES */

                default:
                    wStatus = PH_ADD_COMPCODE_FIXED(PH_ERR_INVALID_PARAMETER, PH_COMP_CRYPTOSYM);
                    break;
            }
            break;

        case PH_CRYPTOSYM_DIV_MODE_MIFARE_ULTRALIGHT:
            /* Parameter check */
            if(bDivInputLen > PH_CRYPTOSYM_MBEDTLS_KDIV_MFP_DIVLENGTH_AES_MAX)
            {
                return PH_ADD_COMPCODE_FIXED(PH_ERR_INVALID_PARAMETER, PH_COMP_CRYPTOSYM);
            }

            /* Copy div. input */
            (void)memcpy(&aDivData[1], pDivInput, bDivInputLen);

            /* Increment div. input length */
            ++bDivInputLen;

            switch(wKeyType)
            {
#ifdef PH_CRYPTOSYM_AES
                case PH_CRYPTOSYM_KEY_TYPE_AES128:
                    /* Set div. header */
                    aDivData[0] = PH_CRYPTOSYM_MBEDTLS_KDIV_MFUL_AES128_CONST;

                    /* Perform CMAC calculation */
                    PH_CHECK_SUCCESS_FCT(wStatus, phCryptoSym_mBedTLS_Int_CMAC_Diversify(
                        pDataParams,
                        aDivData,
                        (uint16_t) bDivInputLen,
                        pDiversifiedKey,
                        &bTmpLen));

                    *pDivKeyLen = bTmpLen;
                    pDataParams->wAddInfo = bTmpLen;
                    break;
#endif /* PH_CRYPTOSYM_AES */

                default:
                    return PH_ADD_COMPCODE_FIXED(PH_ERR_INVALID_PARAMETER, PH_COMP_CRYPTOSYM);
            }
            break;

        default:
            wStatus = PH_ADD_COMPCODE_FIXED(PH_ERR_UNSUPPORTED_PARAMETER, PH_COMP_CRYPTOSYM);
    }

    return wStatus;
}

phStatus_t phCryptoSym_mBedTLS_SetConfig(phCryptoSym_mBedTLS_DataParams_t * pDataParams, uint16_t wConfig, uint16_t wValue)
{
    phStatus_t  PH_MEMLOC_REM wStatus = 0;

    /* Place success status. */
    wStatus = PH_ERR_SUCCESS;

    switch(wConfig)
    {
        case PH_CRYPTOSYM_CONFIG_KEEP_IV:
            /* parameter check */
            if((wValue != PH_CRYPTOSYM_VALUE_KEEP_IV_OFF) &&
                (wValue != PH_CRYPTOSYM_VALUE_KEEP_IV_ON))
            {
                wStatus = PH_ADD_COMPCODE_FIXED(PH_ERR_INVALID_PARAMETER, PH_COMP_CRYPTOSYM);
            }
            pDataParams->wKeepIV = wValue;
            break;

        case PH_CRYPTOSYM_CONFIG_CCM_TAG_LENGTH:
            pDataParams->bTagLen = (uint8_t) wValue;
            break;

        default:
            wStatus = PH_ADD_COMPCODE_FIXED(PH_ERR_UNSUPPORTED_PARAMETER, PH_COMP_CRYPTOSYM);
            break;
    }

    return wStatus;
}

phStatus_t phCryptoSym_mBedTLS_GetConfig(phCryptoSym_mBedTLS_DataParams_t * pDataParams, uint16_t wConfig, uint16_t * pValue)
{
    phStatus_t  PH_MEMLOC_REM wStatus = 0;

    /* Place success status. */
    wStatus = PH_ERR_SUCCESS;

    switch(wConfig)
    {
        case PH_CRYPTOSYM_CONFIG_KEY_SIZE:
            switch(pDataParams->wKeyType)
            {
#ifdef PH_CRYPTOSYM_AES
                case PH_CRYPTOSYM_KEY_TYPE_AES128:
                    *pValue = PH_CRYPTOSYM_AES128_KEY_SIZE;
                    break;

#ifndef MBEDTLS_AES_ALT
                case PH_CRYPTOSYM_KEY_TYPE_AES192:
                    *pValue = PH_CRYPTOSYM_AES192_KEY_SIZE;
                    break;
#endif /* MBEDTLS_AES_ALT */

                case PH_CRYPTOSYM_KEY_TYPE_AES256:
                    *pValue = PH_CRYPTOSYM_AES256_KEY_SIZE;
                    break;
#endif /* PH_CRYPTOSYM_AES */

#ifdef PH_CRYPTOSYM_DES
#ifndef MBEDTLS_DES_ALT
                case PH_CRYPTOSYM_KEY_TYPE_DES:
                    *pValue = PH_CRYPTOSYM_DES_KEY_SIZE;
                    break;
#endif /* MBEDTLS_DES_ALT */

                case PH_CRYPTOSYM_KEY_TYPE_2K3DES:
                    *pValue = PH_CRYPTOSYM_2K3DES_KEY_SIZE;
                    break;

                case PH_CRYPTOSYM_KEY_TYPE_3K3DES:
                    *pValue = PH_CRYPTOSYM_3K3DES_KEY_SIZE;
                    break;
#endif /* PH_CRYPTOSYM_DES */

                default:
                    wStatus = PH_ADD_COMPCODE_FIXED(PH_ERR_INVALID_PARAMETER, PH_COMP_CRYPTOSYM);
            }
            break;

        case PH_CRYPTOSYM_CONFIG_BLOCK_SIZE:
            switch(pDataParams->wKeyType)
            {
#ifdef PH_CRYPTOSYM_AES
                case PH_CRYPTOSYM_KEY_TYPE_AES128:
#ifndef MBEDTLS_AES_ALT
                case PH_CRYPTOSYM_KEY_TYPE_AES192:
#endif /* MBEDTLS_AES_ALT */
                case PH_CRYPTOSYM_KEY_TYPE_AES256:
                    *pValue = PH_CRYPTOSYM_AES_BLOCK_SIZE;
                    break;
#endif /* PH_CRYPTOSYM_AES */

#ifdef PH_CRYPTOSYM_DES
#ifndef MBEDTLS_DES_ALT
                case PH_CRYPTOSYM_KEY_TYPE_DES:
#endif /* MBEDTLS_DES_ALT */
                case PH_CRYPTOSYM_KEY_TYPE_2K3DES:
                case PH_CRYPTOSYM_KEY_TYPE_3K3DES:
                    *pValue = PH_CRYPTOSYM_DES_BLOCK_SIZE;
                    break;
#endif /* PH_CRYPTOSYM_DES */

                default:
                    wStatus = PH_ADD_COMPCODE_FIXED(PH_ERR_INVALID_PARAMETER, PH_COMP_CRYPTOSYM);
            }
            break;

        case PH_CRYPTOSYM_CONFIG_KEY_TYPE:
            *pValue = pDataParams->wKeyType;
            break;

        case PH_CRYPTOSYM_CONFIG_KEEP_IV:
            *pValue = pDataParams->wKeepIV;
            break;

        case PH_CRYPTOSYM_CONFIG_ADDITIONAL_INFO:
            *pValue = pDataParams->wAddInfo;
            break;

        case PH_CRYPTOSYM_CONFIG_CCM_TAG_LENGTH:
            *pValue = pDataParams->bTagLen;
            break;

        default:
            wStatus = PH_ADD_COMPCODE_FIXED(PH_ERR_UNSUPPORTED_PARAMETER, PH_COMP_CRYPTOSYM);
    }

    return wStatus;
}

phStatus_t phCryptoSym_mBedTLS_SetAuthenticationTag(phCryptoSym_mBedTLS_DataParams_t * pDataParams, const uint8_t * pTag, uint8_t bTag_Len)
{
    /* Validate Tag Length */
    if(bTag_Len > PH_CRYPTOSYM_AES128_KEY_SIZE)
    {
        return PH_ADD_COMPCODE(PH_ERR_INVALID_PARAMETER, PH_COMP_CRYPTOSYM);
    }

    /* Update Additional Data. */
    (void) memcpy(pDataParams->aTag, pTag, bTag_Len);
    pDataParams->bTagLen = bTag_Len;

    return PH_ADD_COMPCODE(PH_ERR_SUCCESS, PH_COMP_CRYPTOSYM);
}

phStatus_t phCryptoSym_mBedTLS_GetAuthenticationTag(phCryptoSym_mBedTLS_DataParams_t * pDataParams, uint8_t * pTag, uint8_t * pTag_Len)
{
    /* Update Additional Data. */
    (void) memcpy(pTag, pDataParams->aTag, pDataParams->bTagLen);
    *pTag_Len = pDataParams->bTagLen;

    return PH_ADD_COMPCODE(PH_ERR_SUCCESS, PH_COMP_CRYPTOSYM);
}

phStatus_t phCryptoSym_mBedTLS_GetLastStatus(phCryptoSym_mBedTLS_DataParams_t * pDataParams, uint16_t wStatusMsgLen, int8_t * pStatusMsg,
    int32_t * pStatusCode)
{
    *pStatusCode = pDataParams->dwErrorCode;

#ifdef MBEDTLS_ERROR_C

    mbedtls_strerror(pDataParams->dwErrorCode, (char *) pStatusMsg, wStatusMsgLen);

#endif /* MBEDTLS_ERROR_C */

    return PH_ERR_SUCCESS;
}

#endif /* NXPBUILD__PH_CRYPTOSYM_MBEDTLS */
