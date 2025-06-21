/*----------------------------------------------------------------------------*/
/* Copyright 2022, 2024 NXP                                                   */
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
* mBedTLS specific Random Number Component of the Reader Library Framework.
* $Author: NXP $
* $Revision: $ (v07.13.00)
* $Date: $
*
*/

#include <ph_Status.h>
#include <phCryptoRng.h>
#include <ph_RefDefs.h>

#ifdef NXPBUILD__PH_CRYPTORNG_MBEDTLS

#include "phCryptoRng_mBedTLS.h"

#ifdef MBEDTLS_CTR_DRBG_C
/**< Member to save the DRBG information of the Random number. */
static mbedtls_ctr_drbg_context     stDrbg;
#define PH_CRYPTORNG_DRBG_CTX       &stDrbg

/**< Member to save the Entropy information of the Random number. */
static mbedtls_entropy_context      stEntropy;
#define PH_CRYPTORNG_ENTROPY_CTX    &stEntropy
#endif /* MBEDTLS_CTR_DRBG_C */

phStatus_t phCryptoRng_mBedTLS_Init(phCryptoRng_mBedTLS_DataParams_t * pDataParams, uint16_t wSizeOfDataParams)
{
    if(sizeof(phCryptoRng_mBedTLS_DataParams_t) != wSizeOfDataParams)
    {
        return PH_ADD_COMPCODE(PH_ERR_INVALID_DATA_PARAMS, PH_COMP_CRYPTORNG);
    }
    PH_ASSERT_NULL(pDataParams);

    /* Init. private data */
    pDataParams->wId = PH_COMP_CRYPTORNG | PH_CRYPTORNG_MBEDTLS_ID;
    pDataParams->dwErrorCode = 0;

#ifdef MBEDTLS_CTR_DRBG_C
    /* Initialize the context. */
    mbedtls_ctr_drbg_init(PH_CRYPTORNG_DRBG_CTX);
    mbedtls_entropy_init(PH_CRYPTORNG_ENTROPY_CTX);
#else
#endif /* MBEDTLS_CTR_DRBG_C */

    return PH_ERR_SUCCESS;
}

phStatus_t phCryptoRng_mBedTLS_DeInit(phCryptoRng_mBedTLS_DataParams_t * pDataParams)
{
    PH_UNUSED_VARIABLE(pDataParams);

#ifdef MBEDTLS_CTR_DRBG_C
    mbedtls_ctr_drbg_free(PH_CRYPTORNG_DRBG_CTX);
    mbedtls_entropy_free(PH_CRYPTORNG_ENTROPY_CTX);
#endif /* MBEDTLS_CTR_DRBG_C */

    return PH_ERR_SUCCESS;
}

phStatus_t phCryptoRng_mBedTLS_Seed(phCryptoRng_mBedTLS_DataParams_t * pDataParams, uint8_t * pSeed, uint8_t bSeedLen)
{
    phStatus_t  PH_MEMLOC_REM wStatus = PH_ERR_SUCCESS;

#ifdef MBEDTLS_CTR_DRBG_C
    TRY
    {
        PH_CRYPTOSYM_CHECK_STATUS(pDataParams, mbedtls_ctr_drbg_seed(PH_CRYPTORNG_DRBG_CTX, mbedtls_entropy_func, PH_CRYPTORNG_ENTROPY_CTX,
            pSeed, bSeedLen));
    }
    CATCH(MBEDTLS_EXCEPTION)
    {
        wStatus = PH_ADD_COMPCODE(PH_ERR_INTERNAL_ERROR, PH_COMP_CRYPTOASYM);
    }
    END_EXT
#else
    PH_UNUSED_VARIABLE(pDataParams);
    PH_UNUSED_VARIABLE(pSeed);
    PH_UNUSED_VARIABLE(bSeedLen);
#endif /* MBEDTLS_CTR_DRBG_C */

    return wStatus;
}

phStatus_t phCryptoRng_mBedTLS_Rnd(phCryptoRng_mBedTLS_DataParams_t * pDataParams, uint16_t  wNoOfRndBytes, uint8_t * pRnd)
{
    phStatus_t  PH_MEMLOC_REM wStatus = PH_ERR_SUCCESS;

#ifdef MBEDTLS_CTR_DRBG_C
    TRY
    {
        PH_CRYPTOSYM_CHECK_STATUS(pDataParams, mbedtls_ctr_drbg_random(PH_CRYPTORNG_DRBG_CTX, pRnd, wNoOfRndBytes));
    }
    CATCH(MBEDTLS_EXCEPTION)
    {
        wStatus = PH_ADD_COMPCODE(PH_ERR_INTERNAL_ERROR, PH_COMP_CRYPTOASYM);
    }
    END_EXT
#else
    PH_UNUSED_VARIABLE(pDataParams);
#endif /* MBEDTLS_CTR_DRBG_C */

    return wStatus;
}

phStatus_t phCryptoRng_mBedTLS_GetLastStatus(phCryptoRng_mBedTLS_DataParams_t * pDataParams, uint16_t wStatusMsgLen, int8_t * pStatusMsg,
    int32_t * pStatusCode)
{
    *pStatusCode = pDataParams->dwErrorCode;

#ifdef MBEDTLS_ERROR_C

    mbedtls_strerror(pDataParams->dwErrorCode, (char *) pStatusMsg, wStatusMsgLen);

#endif /* MBEDTLS_ERROR_C */

    return PH_ERR_SUCCESS;
}

#endif /* NXPBUILD__PH_CRYPTORNG_MBEDTLS */
