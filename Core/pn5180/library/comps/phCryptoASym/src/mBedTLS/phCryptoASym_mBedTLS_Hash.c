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

#include <ph_Status.h>

#ifdef NXPBUILD__PH_CRYPTOASYM_HASH

#include <ph_RefDefs.h>

#include "phCryptoASym_mBedTLS.h"
#include "phCryptoASym_mBedTLS_Hash.h"

#ifdef PH_CRYPTOASYM_SHA256
mbedtls_sha256_context stMD_SHA256_Ctx;
#endif /* PH_CRYPTOASYM_SHA256 */

#ifdef PH_CRYPTOASYM_SHA512
mbedtls_sha512_context stMD_SHA512_Ctx;
#endif /* PH_CRYPTOASYM_SHA512 */

phStatus_t phCryptoASym_mBedTLS_ComputeHash(phCryptoASym_mBedTLS_DataParams_t * pDataParams, uint16_t wOption, uint8_t bHashAlgo,
    uint8_t * pMessage, uint16_t wMsgLen, uint8_t * pHash, uint16_t * pHashLen)
{
    phStatus_t          PH_MEMLOC_REM wStatus = 0;
    uint16_t            PH_MEMLOC_REM wBufOption = 0;

    /* Get the Buffering option. */
    wBufOption = (uint16_t) ( wOption & PH_EXCHANGE_BUFFER_MASK );

    /* Start the Hashing process. */
    if((wBufOption == PH_EXCHANGE_DEFAULT) || (wBufOption == PH_EXCHANGE_BUFFER_FIRST))
    {
        /* Save Hash Algorithm Identifier. */
        pDataParams->bHashAlgo = bHashAlgo;

        PH_CHECK_SUCCESS_FCT(wStatus, phCryptoASym_mBedTLS_Hash_Start(pDataParams));
    }

    /* Update Message for Hash computation. */
    if(wMsgLen)
    {
        PH_CHECK_SUCCESS_FCT(wStatus, phCryptoASym_mBedTLS_Hash_Update(pDataParams, pMessage, wMsgLen));
    }

    /* Finish Hashing. */
    if((wBufOption == PH_EXCHANGE_DEFAULT) || (wBufOption == PH_EXCHANGE_BUFFER_LAST))
    {
        PH_CHECK_SUCCESS_FCT(wStatus, phCryptoASym_mBedTLS_Hash_Finish(pDataParams, pHash, pHashLen));
    }

    return wStatus;
}

phStatus_t phCryptoASym_mBedTLS_Hash_Start(phCryptoASym_mBedTLS_DataParams_t * pDataParams)
{
    phStatus_t PH_MEMLOC_REM wStatus = 0;

    TRY
    {
        switch(pDataParams->bHashAlgo)
        {
#ifdef PH_CRYPTOASYM_SHA256
            case PH_CRYPTOASYM_HASH_ALGO_SHA224:
            case PH_CRYPTOASYM_HASH_ALGO_SHA256:
                /* Initialize the Context. */
                mbedtls_sha256_init(&stMD_SHA256_Ctx);

                /* Initiate Message Digest routine. */
                PH_CRYPTOASYM_CHECK_STATUS(pDataParams, mbedtls_sha256_starts_ret(&stMD_SHA256_Ctx,
                    ((pDataParams->bHashAlgo == PH_CRYPTOASYM_HASH_ALGO_SHA224) ? PH_ON : PH_OFF)));
                break;
#endif /* PH_CRYPTOASYM_SHA256 */

#ifdef PH_CRYPTOASYM_SHA512
            case PH_CRYPTOASYM_HASH_ALGO_SHA384:
            case PH_CRYPTOASYM_HASH_ALGO_SHA512:
                /* Initialize the Context. */
                mbedtls_sha512_init(&stMD_SHA512_Ctx);

                /* Initiate Message Digest routine. */
                PH_CRYPTOASYM_CHECK_STATUS(pDataParams, mbedtls_sha512_starts_ret(&stMD_SHA512_Ctx,
                    ((pDataParams->bHashAlgo == PH_CRYPTOASYM_HASH_ALGO_SHA384) ? PH_ON : PH_OFF)));
                break;
#endif /* PH_CRYPTOASYM_SHA512 */

            default:
                return PH_ADD_COMPCODE_FIXED(PH_ERR_UNSUPPORTED_HASH_ALGO, PH_COMP_CRYPTOASYM);
        }
    }
    CATCH(MBEDTLS_EXCEPTION)
    {
        phCryptoASym_mBedTLS_Hash_Free(pDataParams);

        wStatus = PH_ADD_COMPCODE_FIXED(PH_ERR_INTERNAL_ERROR, PH_COMP_CRYPTOASYM);
    }
    END_EXT

    return wStatus;
}

phStatus_t phCryptoASym_mBedTLS_Hash_Update(phCryptoASym_mBedTLS_DataParams_t * pDataParams, uint8_t * pMessage,
    uint16_t wMsgLen)
{
    phStatus_t PH_MEMLOC_REM wStatus = 0;

    TRY
    {
        switch(pDataParams->bHashAlgo)
        {
#ifdef PH_CRYPTOASYM_SHA256
            case PH_CRYPTOASYM_HASH_ALGO_SHA224:
            case PH_CRYPTOASYM_HASH_ALGO_SHA256:
                PH_CRYPTOASYM_CHECK_STATUS(pDataParams, mbedtls_sha256_update_ret(&stMD_SHA256_Ctx, pMessage, wMsgLen));
                break;
#endif /* PH_CRYPTOASYM_SHA256 */

#ifdef PH_CRYPTOASYM_SHA512
            case PH_CRYPTOASYM_HASH_ALGO_SHA384:
            case PH_CRYPTOASYM_HASH_ALGO_SHA512:
                PH_CRYPTOASYM_CHECK_STATUS(pDataParams, mbedtls_sha512_update_ret(&stMD_SHA512_Ctx, pMessage, wMsgLen));
                break;
#endif /* PH_CRYPTOASYM_SHA512 */

            default:
                return PH_ADD_COMPCODE_FIXED(PH_ERR_UNSUPPORTED_HASH_ALGO, PH_COMP_CRYPTOASYM);
        }
    }
    CATCH(MBEDTLS_EXCEPTION)
    {
        phCryptoASym_mBedTLS_Hash_Free(pDataParams);

        wStatus = PH_ADD_COMPCODE_FIXED(PH_ERR_INTERNAL_ERROR, PH_COMP_CRYPTOASYM);
    }
    END_EXT

    return wStatus;
}

phStatus_t phCryptoASym_mBedTLS_Hash_Finish(phCryptoASym_mBedTLS_DataParams_t * pDataParams, uint8_t * pHash,
    uint16_t * pHashLen)
{
    phStatus_t  PH_MEMLOC_REM wStatus = 0;
    int         PH_MEMLOC_REM dwStatus = 0;

    /* Clear temporary buffer. */
    (void) memset(PH_CRYPTOASYM_INT_BUFFER, 0x00, PH_CRYPTOASYM_INT_BUFFER_SIZE);

    /* Clear the Hash length. */
    *pHashLen = 0;

    TRY
    {
        switch(pDataParams->bHashAlgo)
        {
#ifdef PH_CRYPTOASYM_SHA256
            case PH_CRYPTOASYM_HASH_ALGO_SHA224:
            case PH_CRYPTOASYM_HASH_ALGO_SHA256:
                dwStatus = mbedtls_sha256_finish_ret(&stMD_SHA256_Ctx, PH_CRYPTOASYM_INT_BUFFER);
                if(dwStatus == 0U)
                {
                    *pHashLen = (uint16_t) ((pDataParams->bHashAlgo == PH_CRYPTOASYM_HASH_ALGO_SHA224) ? 28U : 32U);
                    (void) memcpy(pHash, PH_CRYPTOASYM_INT_BUFFER, *pHashLen);
                }
                break;
#endif /* PH_CRYPTOASYM_SHA256 */

#ifdef PH_CRYPTOASYM_SHA512
            case PH_CRYPTOASYM_HASH_ALGO_SHA384:
            case PH_CRYPTOASYM_HASH_ALGO_SHA512:
                dwStatus = mbedtls_sha512_finish_ret(&stMD_SHA512_Ctx, PH_CRYPTOASYM_INT_BUFFER);
                if(dwStatus == 0U)
                {
                    *pHashLen = (uint16_t) ((pDataParams->bHashAlgo == PH_CRYPTOASYM_HASH_ALGO_SHA384) ? 48U : 64U);
                    (void) memcpy(pHash, PH_CRYPTOASYM_INT_BUFFER, *pHashLen);
                }
                break;
#endif /* PH_CRYPTOASYM_SHA512 */

            default:
                wStatus = PH_ADD_COMPCODE_FIXED(PH_ERR_UNSUPPORTED_HASH_ALGO, PH_COMP_CRYPTOASYM);
                break;
        }

        /* Check the status. */
        PH_CRYPTOASYM_CHECK_STATUS(pDataParams, dwStatus);
    }
    CATCH(MBEDTLS_EXCEPTION)
    {
        wStatus = PH_ADD_COMPCODE_FIXED(PH_ERR_INTERNAL_ERROR, PH_COMP_CRYPTOASYM);
    }
    END_EXT

    phCryptoASym_mBedTLS_Hash_Free(pDataParams);

    return wStatus;
}

phStatus_t phCryptoASym_mBedTLS_Hash_Free(phCryptoASym_mBedTLS_DataParams_t * pDataParams)
{
    switch(pDataParams->bHashAlgo)
    {
#ifdef PH_CRYPTOASYM_SHA256
        case PH_CRYPTOASYM_HASH_ALGO_SHA224:
        case PH_CRYPTOASYM_HASH_ALGO_SHA256:
            mbedtls_sha256_free(&stMD_SHA256_Ctx);
            break;
#endif /* PH_CRYPTOASYM_SHA256 */

#ifdef PH_CRYPTOASYM_SHA512
        case PH_CRYPTOASYM_HASH_ALGO_SHA384:
        case PH_CRYPTOASYM_HASH_ALGO_SHA512:
            mbedtls_sha512_free(&stMD_SHA512_Ctx);
            break;
#endif /* PH_CRYPTOASYM_SHA512 */

        default:
            /* Nothing to do here. */
            break;
    }

    /* Clear Hash Algorithm in Data Context */
    pDataParams->bHashAlgo = 0xFFU;

    return PH_ADD_COMPCODE_FIXED(PH_ERR_SUCCESS, PH_COMP_CRYPTOASYM);
}

#endif /* NXPBUILD__PH_CRYPTOASYM_HASH */
