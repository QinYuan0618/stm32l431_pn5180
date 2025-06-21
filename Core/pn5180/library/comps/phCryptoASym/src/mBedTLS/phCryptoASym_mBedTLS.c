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
* mBedTLS specific ASymmetric Cryptography Component of Reader Library Framework.
* $Author: NXP $
* $Revision: $ (v07.13.00)
* $Date: $
*
*/

#include <ph_Status.h>
#include <ph_RefDefs.h>
#include <phCryptoASym.h>

#ifdef NXPBUILD__PH_CRYPTOASYM_MBEDTLS
#include "phCryptoASym_mBedTLS.h"

#ifdef MBEDTLS_ERROR_C
#include "mbedtls/error.h"
#endif /* MBEDTLS_ERROR_C */

#ifdef NXPBUILD__PH_CRYPTOASYM_ECC
#include "phCryptoASym_mBedTLS_ECC.h"
#endif /* NXPBUILD__PH_CRYPTOASYM_ECC*/

#ifdef NXPBUILD__PH_CRYPTOASYM_HASH
#include "phCryptoASym_mBedTLS_Hash.h"
#endif /* NXPBUILD__PH_CRYPTOASYM_HASH*/
phStatus_t phCryptoASym_mBedTLS_Init(phCryptoASym_mBedTLS_DataParams_t * pDataParams, uint16_t wSizeOfDataParams, void * pKeyStoreDataParams,
    uint8_t * pBuffer, uint16_t wBufferSize)
{
    phStatus_t PH_MEMLOC_REM wStatus = 0;

    if(sizeof(phCryptoASym_mBedTLS_DataParams_t) != wSizeOfDataParams)
    {
        return PH_ADD_COMPCODE_FIXED(PH_ERR_INVALID_DATA_PARAMS, PH_COMP_CRYPTOASYM);
    }
    PH_ASSERT_NULL_DATA_PARAM(pDataParams, PH_COMP_CRYPTOASYM);

#ifdef NXPBUILD__PH_KEYSTORE
    PH_ASSERT_NULL_DATA_PARAM(pKeyStoreDataParams, PH_COMP_CRYPTOASYM);
#endif /* NXPBUILD__PH_KEYSTORE */

    PH_ASSERT_NULL_PARAM(pBuffer, PH_COMP_CRYPTOASYM);

    /* Validate the buffer size. */
    if(wBufferSize < PH_CRYPTOASYM_INTERNAL_BUFFER_SIZE)
        return PH_ADD_COMPCODE_FIXED(PH_ERR_PARAMETER_SIZE, PH_COMP_CRYPTOASYM);

    /* Init. private data */
    pDataParams->wId = PH_COMP_CRYPTOASYM | PH_CRYPTOASYM_MBEDTLS_ID;

    pDataParams->pKeyStoreDataParams = pKeyStoreDataParams;

    pDataParams->pBuffer = pBuffer;
    pDataParams->wBufferSize = wBufferSize;

    /* Invalidate keys */
    PH_CHECK_SUCCESS_FCT(wStatus, phCryptoASym_mBedTLS_InvalidateKey(pDataParams));

    /* Initialize mBedTLS alternate initialization. */

    return PH_ERR_SUCCESS;
}

phStatus_t phCryptoASym_mBedTLS_DeInit(phCryptoASym_mBedTLS_DataParams_t * pDataParams)
{
    phCryptoASym_mBedTLS_InvalidateKey(pDataParams);
    pDataParams->pCtx = NULL;
    PH_CRYPTOASYM_INT_BUFFER_SIZE = 0;

    /* UnInitialize mBedTLS alternate initialization. */

    return PH_ERR_SUCCESS;
}

/* CryptoASym Utility functions -------------------------------------------------------------------------------------------------------- */
phStatus_t phCryptoASym_mBedTLS_InvalidateKey(phCryptoASym_mBedTLS_DataParams_t * pDataParams)
{
    /* Reset DataParams. */
    pDataParams->wKeyType = PH_CRYPTOASYM_KEY_TYPE_INVALID;
    pDataParams->bCurveID = PH_CRYPTOASYM_CURVE_ID_NONE;

    (void) memset(PH_CRYPTOASYM_INT_BUFFER, 0x00, PH_CRYPTOASYM_INT_BUFFER_SIZE);

    if(pDataParams->pCtx != NULL)
    {
#ifdef NXPBUILD__PH_CRYPTOASYM_ECC
#ifdef MBEDTLS_ECP_C
        mbedtls_ecp_group_free(PH_CRYPTOASYM_MBEDTLS_ECC_GET_GROUP);
        mbedtls_ecp_point_free(PH_CRYPTOASYM_MBEDTLS_ECC_GET_POINT);
        mbedtls_mpi_free(PH_CRYPTOASYM_MBEDTLS_ECC_GET_MPI);
#endif /* MBEDTLS_ECP_C */
#endif /* NXPBUILD__PH_CRYPTOASYM_ECC */
    }

    phCryptoASym_mBedTLS_Hash_Free(pDataParams);

    return PH_ERR_SUCCESS;
}

phStatus_t phCryptoASym_mBedTLS_GetLastStatus(phCryptoASym_mBedTLS_DataParams_t * pDataParams, uint16_t wStatusMsgLen, int8_t * pStatusMsg,
    int32_t * pStatusCode)
{
    *pStatusCode = pDataParams->dwErrorCode;

#ifdef MBEDTLS_ERROR_C

    mbedtls_strerror(pDataParams->dwErrorCode, (char *) pStatusMsg, wStatusMsgLen);

#endif /* MBEDTLS_ERROR_C */

    return PH_ERR_SUCCESS;
}

#endif /* NXPBUILD__PH_CRYPTOASYM_MBEDTLS */
