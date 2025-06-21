/*----------------------------------------------------------------------------*/
/* Copyright 2021 - 2022, 2024 - 2025 NXP                                     */
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
* Generic ASymmetric Cryptography Component of the Reader Library Framework.
* $Author: NXP $
* $Revision: $ (v07.13.00)
* $Date: $
*
*/

#include <ph_Status.h>
#include <ph_RefDefs.h>
#include <phCryptoASym.h>

#ifdef NXPBUILD__PH_CRYPTOASYM_MBEDTLS
#include "mBedTLS/phCryptoASym_mBedTLS.h"

#ifdef NXPBUILD__PH_CRYPTOASYM_HASH
#include "mBedTLS/phCryptoASym_mBedTLS_Hash.h"
#endif /* NXPBUILD__PH_CRYPTOASYM_HASH */
#endif /* NXPBUILD__PH_CRYPTOASYM_MBEDTLS */

#ifdef NXPBUILD__PH_CRYPTOASYM_ECC
#include "mBedTLS/phCryptoASym_mBedTLS_ECC.h"
#endif /* NXPBUILD__PH_CRYPTOASYM_ECC */

#ifdef NXPBUILD__PH_CRYPTOASYM
/* CryptoASym RSA related commands ----------------------------------------------------------------------------------------------------- */

/* CryptoASym Hash related commands ---------------------------------------------------------------------------------------------------- */
phStatus_t phCryptoASym_ComputeHash(void * pDataParams, uint16_t wOption, uint8_t bHashAlgo, uint8_t * pMessage, uint16_t wMsgLen,
    uint8_t * pHash, uint16_t * pHashLen)
{
    phStatus_t PH_MEMLOC_REM wStatus = 0;

    PH_LOG_HELPER_ALLOCATE_TEXT(bFunctionName, "phCryptoASym_ComputeHash");
    PH_LOG_HELPER_ALLOCATE_PARAMNAME(wOption);
    PH_LOG_HELPER_ALLOCATE_PARAMNAME(bHashAlgo);
    PH_LOG_HELPER_ALLOCATE_PARAMNAME(pMessage);
    PH_LOG_HELPER_ALLOCATE_PARAMNAME(wMsgLen);
    PH_LOG_HELPER_ALLOCATE_PARAMNAME(pHash);
    PH_LOG_HELPER_ALLOCATE_PARAMNAME(pHashLen);
    PH_LOG_HELPER_ALLOCATE_PARAMNAME(wStatus);

    /* Validate the parameters. */
    PH_ASSERT_NULL_DATA_PARAM(pDataParams, PH_COMP_CRYPTOASYM);
    PH_ASSERT_NULL_PARAM(pMessage, PH_COMP_CRYPTOASYM);

    if((wOption == PH_EXCHANGE_DEFAULT) || (wOption == PH_EXCHANGE_BUFFER_LAST))
        PH_ASSERT_NULL_PARAM(pHashLen, PH_COMP_CRYPTOASYM);

    /* Log the information. */
    PH_LOG_HELPER_ADDSTRING(PH_LOG_LOGTYPE_INFO, bFunctionName);
    PH_LOG_HELPER_ADDPARAM_UINT16(PH_LOG_LOGTYPE_DEBUG, PH_LOG_VAR(wOption), &wOption);
    PH_LOG_HELPER_ADDPARAM_UINT8(PH_LOG_LOGTYPE_DEBUG, PH_LOG_VAR(bHashAlgo), &bHashAlgo);
    PH_LOG_HELPER_ADDPARAM_BUFFER(PH_LOG_LOGTYPE_DEBUG, PH_LOG_VAR(pMessage), pMessage, wMsgLen);
    PH_LOG_HELPER_ADDPARAM_UINT16(PH_LOG_LOGTYPE_DEBUG, PH_LOG_VAR(wMsgLen), &wMsgLen);
    PH_LOG_HELPER_EXECUTE(PH_LOG_OPTION_CATEGORY_ENTER);

    /* Component Code Validation */
    if(PH_GET_COMPCODE(pDataParams) != PH_COMP_CRYPTOASYM)
    {
        wStatus = PH_ADD_COMPCODE_FIXED(PH_ERR_INVALID_DATA_PARAMS, PH_COMP_CRYPTOASYM);

        PH_LOG_HELPER_ADDSTRING(PH_LOG_LOGTYPE_INFO, bFunctionName);
        PH_LOG_HELPER_ADDPARAM_UINT16(PH_LOG_LOGTYPE_INFO, PH_LOG_VAR(wStatus), &wStatus);
        PH_LOG_HELPER_EXECUTE(PH_LOG_OPTION_CATEGORY_LEAVE);

        return wStatus;
    }

    /* Perform operation on active layer. */
    switch(PH_GET_COMPID(pDataParams))
    {
#ifdef NXPBUILD__PH_CRYPTOASYM_MBEDTLS
        case PH_CRYPTOASYM_MBEDTLS_ID:
            wStatus = phCryptoASym_mBedTLS_ComputeHash((phCryptoASym_mBedTLS_DataParams_t *) pDataParams, wOption,
                bHashAlgo, pMessage, wMsgLen, pHash, pHashLen);
            break;
#endif /* NXPBUILD__PH_CRYPTOASYM_MBEDTLS */

        default:
            wStatus = PH_ADD_COMPCODE_FIXED(PH_ERR_INVALID_DATA_PARAMS, PH_COMP_CRYPTOASYM);
            break;
    }

    PH_LOG_HELPER_ADDSTRING(PH_LOG_LOGTYPE_INFO, bFunctionName);
#ifdef NXPBUILD__PH_LOG
    if((wStatus & PH_ERR_MASK) == PH_ERR_SUCCESS)
    {
        if((wOption == PH_EXCHANGE_DEFAULT) || (wOption == PH_EXCHANGE_BUFFER_LAST))
        {
            PH_LOG_HELPER_ADDPARAM_BUFFER(PH_LOG_LOGTYPE_DEBUG, PH_LOG_VAR(pHash), pHash, *pHashLen);
            PH_LOG_HELPER_ADDPARAM_UINT16(PH_LOG_LOGTYPE_DEBUG, PH_LOG_VAR(pHashLen), pHashLen);
        }
    }
#endif /* NXPBUILD__PH_LOG */
    PH_LOG_HELPER_ADDPARAM_UINT16(PH_LOG_LOGTYPE_INFO, PH_LOG_VAR(wStatus), &wStatus);
    PH_LOG_HELPER_EXECUTE(PH_LOG_OPTION_CATEGORY_LEAVE);

    return wStatus;
}

/* CryptoASym ECC related commands ----------------------------------------------------------------------------------------------------- */
phStatus_t phCryptoASym_ECC_GenerateKeyPair(void * pDataParams, uint8_t bCurveID)
{
    phStatus_t PH_MEMLOC_REM wStatus = 0;

    PH_LOG_HELPER_ALLOCATE_TEXT(bFunctionName, "phCryptoASym_ECC_GenerateKeyPair");
    PH_LOG_HELPER_ALLOCATE_PARAMNAME(wStatus);
    PH_LOG_HELPER_ALLOCATE_PARAMNAME(bCurveID);

    /* Validate the parameters. */
    PH_ASSERT_NULL_DATA_PARAM(pDataParams, PH_COMP_CRYPTOASYM);

    /* Log the information. */
    PH_LOG_HELPER_ADDSTRING(PH_LOG_LOGTYPE_INFO, bFunctionName);
    PH_LOG_HELPER_ADDPARAM_UINT8(PH_LOG_LOGTYPE_DEBUG, PH_LOG_VAR(bCurveID), &bCurveID);
    PH_LOG_HELPER_EXECUTE(PH_LOG_OPTION_CATEGORY_ENTER);

    /* Component Code Validation */
    if(PH_GET_COMPCODE(pDataParams) != PH_COMP_CRYPTOASYM)
    {
        wStatus = PH_ADD_COMPCODE_FIXED(PH_ERR_INVALID_DATA_PARAMS, PH_COMP_CRYPTOASYM);

        PH_LOG_HELPER_ADDSTRING(PH_LOG_LOGTYPE_INFO, bFunctionName);
        PH_LOG_HELPER_ADDPARAM_UINT16(PH_LOG_LOGTYPE_INFO, PH_LOG_VAR(wStatus), &wStatus);
        PH_LOG_HELPER_EXECUTE(PH_LOG_OPTION_CATEGORY_LEAVE);

        return wStatus;
    }

    /* Perform operation on active layer. */
    switch(PH_GET_COMPID(pDataParams))
    {
#ifdef NXPBUILD__PH_CRYPTOASYM_MBEDTLS
        case PH_CRYPTOASYM_MBEDTLS_ID:
            wStatus = phCryptoASym_mBedTLS_ECC_GenerateKeyPair((phCryptoASym_mBedTLS_DataParams_t *) pDataParams, bCurveID);
            break;
#endif /* NXPBUILD__PH_CRYPTOASYM_MBEDTLS */

        default:
            wStatus = PH_ADD_COMPCODE_FIXED(PH_ERR_INVALID_DATA_PARAMS, PH_COMP_CRYPTOASYM);
            break;
    }

    PH_LOG_HELPER_ADDSTRING(PH_LOG_LOGTYPE_INFO, bFunctionName);
    PH_LOG_HELPER_ADDPARAM_UINT16(PH_LOG_LOGTYPE_INFO, PH_LOG_VAR(wStatus), &wStatus);
    PH_LOG_HELPER_EXECUTE(PH_LOG_OPTION_CATEGORY_LEAVE);

    return wStatus;
}

phStatus_t phCryptoASym_ECC_ExportKey(void * pDataParams, uint16_t wOption, uint16_t wKeyBuffSize, uint8_t * pCurveID, uint8_t * pKey,
    uint16_t * pKeyLen)
{
    phStatus_t PH_MEMLOC_REM wStatus = 0;

    PH_LOG_HELPER_ALLOCATE_TEXT(bFunctionName, "phCryptoASym_ECC_ExportKey");
    PH_LOG_HELPER_ALLOCATE_PARAMNAME(wStatus);
    PH_LOG_HELPER_ALLOCATE_PARAMNAME(wOption);
    PH_LOG_HELPER_ALLOCATE_PARAMNAME(wKeyBuffSize);
    PH_LOG_HELPER_ALLOCATE_PARAMNAME(pCurveID);
    PH_LOG_HELPER_ALLOCATE_PARAMNAME(pKey);
    PH_LOG_HELPER_ALLOCATE_PARAMNAME(pKeyLen);

    /* Validate the parameters. */
    PH_ASSERT_NULL_DATA_PARAM(pDataParams, PH_COMP_CRYPTOASYM);
    PH_ASSERT_NULL_PARAM(pKeyLen, PH_COMP_CRYPTOASYM);

    /* Log the information. */
    PH_LOG_HELPER_ADDSTRING(PH_LOG_LOGTYPE_INFO, bFunctionName);
    PH_LOG_HELPER_ADDPARAM_UINT16(PH_LOG_LOGTYPE_DEBUG, PH_LOG_VAR(wOption), &wOption);
    PH_LOG_HELPER_ADDPARAM_UINT16(PH_LOG_LOGTYPE_DEBUG, PH_LOG_VAR(wKeyBuffSize), &wKeyBuffSize);
    PH_LOG_HELPER_EXECUTE(PH_LOG_OPTION_CATEGORY_ENTER);

    /* Component Code Validation */
    if(PH_GET_COMPCODE(pDataParams) != PH_COMP_CRYPTOASYM)
    {
        wStatus = PH_ADD_COMPCODE_FIXED(PH_ERR_INVALID_DATA_PARAMS, PH_COMP_CRYPTOASYM);

        PH_LOG_HELPER_ADDSTRING(PH_LOG_LOGTYPE_INFO, bFunctionName);
        PH_LOG_HELPER_ADDPARAM_UINT16(PH_LOG_LOGTYPE_INFO, PH_LOG_VAR(wStatus), &wStatus);
        PH_LOG_HELPER_EXECUTE(PH_LOG_OPTION_CATEGORY_LEAVE);

        return wStatus;
    }

    /* Perform operation on active layer. */
    switch(PH_GET_COMPID(pDataParams))
    {
#ifdef NXPBUILD__PH_CRYPTOASYM_MBEDTLS
        case PH_CRYPTOASYM_MBEDTLS_ID:
            wStatus = phCryptoASym_mBedTLS_ECC_ExportKey((phCryptoASym_mBedTLS_DataParams_t *) pDataParams, wOption, wKeyBuffSize,
                pCurveID, pKey, pKeyLen);
            break;
#endif /* NXPBUILD__PH_CRYPTOASYM_MBEDTLS */

        default:
            wStatus = PH_ADD_COMPCODE_FIXED(PH_ERR_INVALID_DATA_PARAMS, PH_COMP_CRYPTOASYM);
            break;
    }

    PH_LOG_HELPER_ADDSTRING(PH_LOG_LOGTYPE_INFO, bFunctionName);
    PH_LOG_HELPER_ADDPARAM_UINT8(PH_LOG_LOGTYPE_DEBUG, PH_LOG_VAR(pCurveID), pCurveID);
    PH_LOG_HELPER_ADDPARAM_BUFFER(PH_LOG_LOGTYPE_DEBUG, PH_LOG_VAR(pKey), pKey, *pKeyLen);
    PH_LOG_HELPER_ADDPARAM_UINT16(PH_LOG_LOGTYPE_DEBUG, PH_LOG_VAR(pKeyLen), pKeyLen);
    PH_LOG_HELPER_ADDPARAM_UINT16(PH_LOG_LOGTYPE_INFO, PH_LOG_VAR(wStatus), &wStatus);
    PH_LOG_HELPER_EXECUTE(PH_LOG_OPTION_CATEGORY_LEAVE);

    return wStatus;
}

phStatus_t phCryptoASym_ECC_LoadKey(void * pDataParams, uint16_t wOption, uint16_t wKeyNo, uint16_t wPos)
{
    phStatus_t PH_MEMLOC_REM wStatus = 0;

    PH_LOG_HELPER_ALLOCATE_TEXT(bFunctionName, "phCryptoASym_ECC_LoadKey");
    PH_LOG_HELPER_ALLOCATE_PARAMNAME(wOption);
    PH_LOG_HELPER_ALLOCATE_PARAMNAME(wKeyNo);
    PH_LOG_HELPER_ALLOCATE_PARAMNAME(wPos);
    PH_LOG_HELPER_ALLOCATE_PARAMNAME(wStatus);

    /* Validate the parameters. */
    PH_ASSERT_NULL_DATA_PARAM(pDataParams, PH_COMP_CRYPTOASYM);

    /* Log the information. */
    PH_LOG_HELPER_ADDSTRING(PH_LOG_LOGTYPE_INFO, bFunctionName);
    PH_LOG_HELPER_ADDPARAM_UINT16(PH_LOG_LOGTYPE_DEBUG, PH_LOG_VAR(wOption), &wOption);
    PH_LOG_HELPER_ADDPARAM_UINT16(PH_LOG_LOGTYPE_DEBUG, PH_LOG_VAR(wKeyNo), &wKeyNo);
    PH_LOG_HELPER_ADDPARAM_UINT16(PH_LOG_LOGTYPE_DEBUG, PH_LOG_VAR(wPos), &wPos);
    PH_LOG_HELPER_EXECUTE(PH_LOG_OPTION_CATEGORY_ENTER);

    /* Component Code Validation */
    if(PH_GET_COMPCODE(pDataParams) != PH_COMP_CRYPTOASYM)
    {
        wStatus = PH_ADD_COMPCODE_FIXED(PH_ERR_INVALID_DATA_PARAMS, PH_COMP_CRYPTOASYM);

        PH_LOG_HELPER_ADDSTRING(PH_LOG_LOGTYPE_INFO, bFunctionName);
        PH_LOG_HELPER_ADDPARAM_UINT16(PH_LOG_LOGTYPE_INFO, PH_LOG_VAR(wStatus), &wStatus);
        PH_LOG_HELPER_EXECUTE(PH_LOG_OPTION_CATEGORY_LEAVE);

        return wStatus;
    }

    /* Perform operation on active layer. */
    switch(PH_GET_COMPID(pDataParams))
    {
#ifdef NXPBUILD__PH_CRYPTOASYM_MBEDTLS
        case PH_CRYPTOASYM_MBEDTLS_ID:
            wStatus = phCryptoASym_mBedTLS_ECC_LoadKey((phCryptoASym_mBedTLS_DataParams_t *) pDataParams, wOption, wKeyNo, wPos);
            break;
#endif /* NXPBUILD__PH_CRYPTOASYM_MBEDTLS */

        default:
            wStatus = PH_ADD_COMPCODE_FIXED(PH_ERR_INVALID_DATA_PARAMS, PH_COMP_CRYPTOASYM);
            break;
    }

    PH_LOG_HELPER_ADDSTRING(PH_LOG_LOGTYPE_INFO, bFunctionName);
    PH_LOG_HELPER_ADDPARAM_UINT16(PH_LOG_LOGTYPE_INFO, PH_LOG_VAR(wStatus), &wStatus);
    PH_LOG_HELPER_EXECUTE(PH_LOG_OPTION_CATEGORY_LEAVE);

    return wStatus;
}

phStatus_t phCryptoASym_ECC_LoadKeyDirect(void * pDataParams, uint16_t wOption, uint8_t * pKey, uint16_t wKeyLen)
{
    phStatus_t PH_MEMLOC_REM wStatus = 0;

    PH_LOG_HELPER_ALLOCATE_TEXT(bFunctionName, "phCryptoASym_ECC_LoadKeyDirect");
    PH_LOG_HELPER_ALLOCATE_PARAMNAME(wOption);
    PH_LOG_HELPER_ALLOCATE_PARAMNAME(pKey);
    PH_LOG_HELPER_ALLOCATE_PARAMNAME(wKeyLen);
    PH_LOG_HELPER_ALLOCATE_PARAMNAME(wStatus);

    /* Validate the parameters. */
    PH_ASSERT_NULL_DATA_PARAM(pDataParams, PH_COMP_CRYPTOASYM);
    PH_ASSERT_NULL_PARAM(pKey, PH_COMP_CRYPTOASYM);

    /* Log the information. */
    PH_LOG_HELPER_ADDSTRING(PH_LOG_LOGTYPE_INFO, bFunctionName);
    PH_LOG_HELPER_ADDPARAM_UINT16(PH_LOG_LOGTYPE_DEBUG, PH_LOG_VAR(wOption), &wOption);
    PH_LOG_HELPER_ADDPARAM_BUFFER(PH_LOG_LOGTYPE_DEBUG, PH_LOG_VAR(pKey), pKey, wKeyLen);
    PH_LOG_HELPER_ADDPARAM_UINT16(PH_LOG_LOGTYPE_DEBUG, PH_LOG_VAR(wKeyLen), &wKeyLen);
    PH_LOG_HELPER_EXECUTE(PH_LOG_OPTION_CATEGORY_ENTER);

    /* Component Code Validation */
    if(PH_GET_COMPCODE(pDataParams) != PH_COMP_CRYPTOASYM)
    {
        wStatus = PH_ADD_COMPCODE_FIXED(PH_ERR_INVALID_DATA_PARAMS, PH_COMP_CRYPTOASYM);

        PH_LOG_HELPER_ADDSTRING(PH_LOG_LOGTYPE_INFO, bFunctionName);
        PH_LOG_HELPER_ADDPARAM_UINT16(PH_LOG_LOGTYPE_INFO, PH_LOG_VAR(wStatus), &wStatus);
        PH_LOG_HELPER_EXECUTE(PH_LOG_OPTION_CATEGORY_LEAVE);

        return wStatus;
    }

    /* Perform operation on active layer. */
    switch(PH_GET_COMPID(pDataParams))
    {
#ifdef NXPBUILD__PH_CRYPTOASYM_MBEDTLS
        case PH_CRYPTOASYM_MBEDTLS_ID:
            wStatus = phCryptoASym_mBedTLS_ECC_LoadKeyDirect((phCryptoASym_mBedTLS_DataParams_t *) pDataParams, wOption, pKey, wKeyLen);
            break;
#endif /* NXPBUILD__PH_CRYPTOASYM_MBEDTLS */

        default:
            wStatus = PH_ADD_COMPCODE_FIXED(PH_ERR_INVALID_DATA_PARAMS, PH_COMP_CRYPTOASYM);
            break;
    }

    PH_LOG_HELPER_ADDSTRING(PH_LOG_LOGTYPE_INFO, bFunctionName);
    PH_LOG_HELPER_ADDPARAM_UINT16(PH_LOG_LOGTYPE_INFO, PH_LOG_VAR(wStatus), &wStatus);
    PH_LOG_HELPER_EXECUTE(PH_LOG_OPTION_CATEGORY_LEAVE);

    return wStatus;
}

phStatus_t phCryptoASym_ECC_Sign(void * pDataParams, uint16_t wOption, uint8_t bHashAlgo, uint8_t * pMessage, uint16_t wMsgLen, uint8_t * pSign,
    uint16_t * pSignLen)
{
    phStatus_t PH_MEMLOC_REM wStatus = 0;

    PH_LOG_HELPER_ALLOCATE_TEXT(bFunctionName, "phCryptoASym_ECC_Sign");
    PH_LOG_HELPER_ALLOCATE_PARAMNAME(wOption);
    PH_LOG_HELPER_ALLOCATE_PARAMNAME(bHashAlgo);
    PH_LOG_HELPER_ALLOCATE_PARAMNAME(pMessage);
    PH_LOG_HELPER_ALLOCATE_PARAMNAME(wMsgLen);
    PH_LOG_HELPER_ALLOCATE_PARAMNAME(pSign);
    PH_LOG_HELPER_ALLOCATE_PARAMNAME(pSignLen);
    PH_LOG_HELPER_ALLOCATE_PARAMNAME(wStatus);

    /* Validate the parameters. */
    PH_ASSERT_NULL_DATA_PARAM(pDataParams, PH_COMP_CRYPTOASYM);

    if(wMsgLen)
        PH_ASSERT_NULL_PARAM(pMessage, PH_COMP_CRYPTOASYM);

    if((wOption == PH_EXCHANGE_DEFAULT) || (wOption == PH_EXCHANGE_BUFFER_LAST))
        PH_ASSERT_NULL_PARAM(pSignLen, PH_COMP_CRYPTOASYM);

    /* Log the information. */
    PH_LOG_HELPER_ADDSTRING(PH_LOG_LOGTYPE_INFO, bFunctionName);
    PH_LOG_HELPER_ADDPARAM_UINT16(PH_LOG_LOGTYPE_DEBUG, PH_LOG_VAR(wOption), &wOption);
    PH_LOG_HELPER_ADDPARAM_UINT8(PH_LOG_LOGTYPE_DEBUG, PH_LOG_VAR(bHashAlgo), &bHashAlgo);
    PH_LOG_HELPER_ADDPARAM_BUFFER(PH_LOG_LOGTYPE_DEBUG, PH_LOG_VAR(pMessage), pMessage, wMsgLen);
    PH_LOG_HELPER_ADDPARAM_UINT16(PH_LOG_LOGTYPE_DEBUG, PH_LOG_VAR(wMsgLen), &wMsgLen);
    PH_LOG_HELPER_EXECUTE(PH_LOG_OPTION_CATEGORY_ENTER);

    /* Component Code Validation */
    if(PH_GET_COMPCODE(pDataParams) != PH_COMP_CRYPTOASYM)
    {
        wStatus = PH_ADD_COMPCODE_FIXED(PH_ERR_INVALID_DATA_PARAMS, PH_COMP_CRYPTOASYM);

        PH_LOG_HELPER_ADDSTRING(PH_LOG_LOGTYPE_INFO, bFunctionName);
        PH_LOG_HELPER_ADDPARAM_UINT16(PH_LOG_LOGTYPE_INFO, PH_LOG_VAR(wStatus), &wStatus);
        PH_LOG_HELPER_EXECUTE(PH_LOG_OPTION_CATEGORY_LEAVE);

        return wStatus;
    }

    /* Perform operation on active layer. */
    switch(PH_GET_COMPID(pDataParams))
    {
#ifdef NXPBUILD__PH_CRYPTOASYM_MBEDTLS
        case PH_CRYPTOASYM_MBEDTLS_ID:
            wStatus = phCryptoASym_mBedTLS_ECC_Sign((phCryptoASym_mBedTLS_DataParams_t *) pDataParams, wOption, bHashAlgo, pMessage, wMsgLen,
                pSign, pSignLen);
            break;
#endif /* NXPBUILD__PH_CRYPTOASYM_MBEDTLS */

        default:
            wStatus = PH_ADD_COMPCODE_FIXED(PH_ERR_INVALID_DATA_PARAMS, PH_COMP_CRYPTOASYM);
            break;
    }

    PH_LOG_HELPER_ADDSTRING(PH_LOG_LOGTYPE_INFO, bFunctionName);
    PH_LOG_HELPER_ADDPARAM_BUFFER(PH_LOG_LOGTYPE_DEBUG, PH_LOG_VAR(pSign), pSign, ((pSignLen == NULL) ? 0 : *pSignLen));
    PH_LOG_HELPER_ADDPARAM_UINT16(PH_LOG_LOGTYPE_DEBUG, PH_LOG_VAR(pSignLen), ((pSignLen == NULL) ? 0 : pSignLen));
    PH_LOG_HELPER_ADDPARAM_UINT16(PH_LOG_LOGTYPE_INFO, PH_LOG_VAR(wStatus), &wStatus);
    PH_LOG_HELPER_EXECUTE(PH_LOG_OPTION_CATEGORY_LEAVE);

    return wStatus;
}

phStatus_t phCryptoASym_ECC_Verify(void * pDataParams, uint16_t wOption, uint8_t bHashAlgo, uint8_t * pMessage, uint16_t wMsgLen, uint8_t * pSign,
    uint16_t wSignLen)
{
    phStatus_t PH_MEMLOC_REM wStatus = 0;

    PH_LOG_HELPER_ALLOCATE_TEXT(bFunctionName, "phCryptoASym_ECC_Verify");
    PH_LOG_HELPER_ALLOCATE_PARAMNAME(wOption);
    PH_LOG_HELPER_ALLOCATE_PARAMNAME(bHashAlgo);
    PH_LOG_HELPER_ALLOCATE_PARAMNAME(pMessage);
    PH_LOG_HELPER_ALLOCATE_PARAMNAME(wMsgLen);
    PH_LOG_HELPER_ALLOCATE_PARAMNAME(pSign);
    PH_LOG_HELPER_ALLOCATE_PARAMNAME(wSignLen);
    PH_LOG_HELPER_ALLOCATE_PARAMNAME(wStatus);

    /* Validate the parameters. */
    PH_ASSERT_NULL_DATA_PARAM(pDataParams, PH_COMP_CRYPTOASYM);

    if(wMsgLen)
        PH_ASSERT_NULL_PARAM(pMessage, PH_COMP_CRYPTOASYM);

    if((wOption == PH_EXCHANGE_DEFAULT) || (wOption == PH_EXCHANGE_BUFFER_LAST))
        PH_ASSERT_NULL_PARAM(pSign, PH_COMP_CRYPTOASYM);

    /* Log the information. */
    PH_LOG_HELPER_ADDSTRING(PH_LOG_LOGTYPE_INFO, bFunctionName);
    PH_LOG_HELPER_ADDPARAM_UINT16(PH_LOG_LOGTYPE_DEBUG, PH_LOG_VAR(wOption), &wOption);
    PH_LOG_HELPER_ADDPARAM_UINT8(PH_LOG_LOGTYPE_DEBUG, PH_LOG_VAR(bHashAlgo), &bHashAlgo);
    PH_LOG_HELPER_ADDPARAM_BUFFER(PH_LOG_LOGTYPE_DEBUG, PH_LOG_VAR(pMessage), pMessage, wMsgLen);
    PH_LOG_HELPER_ADDPARAM_UINT16(PH_LOG_LOGTYPE_DEBUG, PH_LOG_VAR(wMsgLen), &wMsgLen);
    PH_LOG_HELPER_ADDPARAM_BUFFER(PH_LOG_LOGTYPE_DEBUG, PH_LOG_VAR(pSign), pSign, wSignLen);
    PH_LOG_HELPER_ADDPARAM_UINT16(PH_LOG_LOGTYPE_DEBUG, PH_LOG_VAR(wSignLen), &wSignLen);
    PH_LOG_HELPER_EXECUTE(PH_LOG_OPTION_CATEGORY_ENTER);

    /* Component Code Validation */
    if(PH_GET_COMPCODE(pDataParams) != PH_COMP_CRYPTOASYM)
    {
        wStatus = PH_ADD_COMPCODE_FIXED(PH_ERR_INVALID_DATA_PARAMS, PH_COMP_CRYPTOASYM);

        PH_LOG_HELPER_ADDSTRING(PH_LOG_LOGTYPE_INFO, bFunctionName);
        PH_LOG_HELPER_ADDPARAM_UINT16(PH_LOG_LOGTYPE_INFO, PH_LOG_VAR(wStatus), &wStatus);
        PH_LOG_HELPER_EXECUTE(PH_LOG_OPTION_CATEGORY_LEAVE);

        return wStatus;
    }

    /* Perform operation on active layer. */
    switch(PH_GET_COMPID(pDataParams))
    {
#ifdef NXPBUILD__PH_CRYPTOASYM_MBEDTLS
        case PH_CRYPTOASYM_MBEDTLS_ID:
            wStatus = phCryptoASym_mBedTLS_ECC_Verify((phCryptoASym_mBedTLS_DataParams_t *) pDataParams, wOption, bHashAlgo, pMessage, wMsgLen,
                pSign, wSignLen);
            break;
#endif /* NXPBUILD__PH_CRYPTOASYM_MBEDTLS */

        default:
            wStatus = PH_ADD_COMPCODE_FIXED(PH_ERR_INVALID_DATA_PARAMS, PH_COMP_CRYPTOASYM);
            break;
    }

    PH_LOG_HELPER_ADDSTRING(PH_LOG_LOGTYPE_INFO, bFunctionName);
    PH_LOG_HELPER_ADDPARAM_UINT16(PH_LOG_LOGTYPE_INFO, PH_LOG_VAR(wStatus), &wStatus);
    PH_LOG_HELPER_EXECUTE(PH_LOG_OPTION_CATEGORY_LEAVE);

    return wStatus;
}

phStatus_t phCryptoASym_ECC_SharedSecret(void * pDataParams, uint16_t wOption, uint8_t * pPublicKey, uint16_t wPublicKeyLen, uint8_t * pSharedSecret,
    uint16_t * pSharedSecretLen)
{
    phStatus_t PH_MEMLOC_REM wStatus = 0;

    PH_LOG_HELPER_ALLOCATE_TEXT(bFunctionName, "phCryptoASym_ECC_SharedSecret");
    PH_LOG_HELPER_ALLOCATE_PARAMNAME(wOption);
    PH_LOG_HELPER_ALLOCATE_PARAMNAME(pPublicKey);
    PH_LOG_HELPER_ALLOCATE_PARAMNAME(wPublicKeyLen);
    PH_LOG_HELPER_ALLOCATE_PARAMNAME(pSharedSecret);
    PH_LOG_HELPER_ALLOCATE_PARAMNAME(pSharedSecretLen);
    PH_LOG_HELPER_ALLOCATE_PARAMNAME(wStatus);

    /* Validate the parameters. */
    PH_ASSERT_NULL_DATA_PARAM(pDataParams, PH_COMP_CRYPTOASYM);
    PH_ASSERT_NULL_PARAM(pPublicKey, PH_COMP_CRYPTOASYM);
    PH_ASSERT_NULL_PARAM(pSharedSecretLen, PH_COMP_CRYPTOASYM);

    /* Log the information. */
    PH_LOG_HELPER_ADDSTRING(PH_LOG_LOGTYPE_INFO, bFunctionName);
    PH_LOG_HELPER_ADDPARAM_UINT16(PH_LOG_LOGTYPE_DEBUG, PH_LOG_VAR(wOption), &wOption);
    PH_LOG_HELPER_ADDPARAM_BUFFER(PH_LOG_LOGTYPE_DEBUG, PH_LOG_VAR(pPublicKey), pPublicKey, wPublicKeyLen);
    PH_LOG_HELPER_ADDPARAM_UINT16(PH_LOG_LOGTYPE_DEBUG, PH_LOG_VAR(wPublicKeyLen), &wPublicKeyLen);
    PH_LOG_HELPER_EXECUTE(PH_LOG_OPTION_CATEGORY_ENTER);

    /* Component Code Validation */
    if(PH_GET_COMPCODE(pDataParams) != PH_COMP_CRYPTOASYM)
    {
        wStatus = PH_ADD_COMPCODE_FIXED(PH_ERR_INVALID_DATA_PARAMS, PH_COMP_CRYPTOASYM);

        PH_LOG_HELPER_ADDSTRING(PH_LOG_LOGTYPE_INFO, bFunctionName);
        PH_LOG_HELPER_ADDPARAM_UINT16(PH_LOG_LOGTYPE_INFO, PH_LOG_VAR(wStatus), &wStatus);
        PH_LOG_HELPER_EXECUTE(PH_LOG_OPTION_CATEGORY_LEAVE);

        return wStatus;
    }

    /* Perform operation on active layer. */
    switch(PH_GET_COMPID(pDataParams))
    {
#ifdef NXPBUILD__PH_CRYPTOASYM_MBEDTLS
        case PH_CRYPTOASYM_MBEDTLS_ID:
            wStatus = phCryptoASym_mBedTLS_ECC_SharedSecret((phCryptoASym_mBedTLS_DataParams_t *) pDataParams, wOption, pPublicKey, wPublicKeyLen,
                pSharedSecret, pSharedSecretLen);
            break;
#endif /* NXPBUILD__PH_CRYPTOASYM_MBEDTLS */

        default:
            wStatus = PH_ADD_COMPCODE_FIXED(PH_ERR_INVALID_DATA_PARAMS, PH_COMP_CRYPTOASYM);
            break;
    }

    PH_LOG_HELPER_ADDSTRING(PH_LOG_LOGTYPE_INFO, bFunctionName);
    PH_LOG_HELPER_ADDPARAM_BUFFER(PH_LOG_LOGTYPE_DEBUG, PH_LOG_VAR(pSharedSecret), pSharedSecret, *pSharedSecretLen);
    PH_LOG_HELPER_ADDPARAM_UINT16(PH_LOG_LOGTYPE_DEBUG, PH_LOG_VAR(pSharedSecretLen), pSharedSecretLen);
    PH_LOG_HELPER_ADDPARAM_UINT16(PH_LOG_LOGTYPE_INFO, PH_LOG_VAR(wStatus), &wStatus);
    PH_LOG_HELPER_EXECUTE(PH_LOG_OPTION_CATEGORY_LEAVE);

    return wStatus;
}

/* CryptoASym Utility functions -------------------------------------------------------------------------------------------------------- */
phStatus_t phCryptoASym_InvalidateKey(void * pDataParams)
{
    phStatus_t PH_MEMLOC_REM wStatus = 0;

    PH_LOG_HELPER_ALLOCATE_TEXT(bFunctionName, "phCryptoASym_InvalidateKey");
    PH_LOG_HELPER_ALLOCATE_PARAMNAME(wStatus);

    /* Validate the parameters. */
    PH_ASSERT_NULL_DATA_PARAM(pDataParams, PH_COMP_CRYPTOASYM);

    /* Log the information. */
    PH_LOG_HELPER_ADDSTRING(PH_LOG_LOGTYPE_INFO, bFunctionName);
    PH_LOG_HELPER_EXECUTE(PH_LOG_OPTION_CATEGORY_ENTER);

    /* Component Code Validation */
    if(PH_GET_COMPCODE(pDataParams) != PH_COMP_CRYPTOASYM)
    {
        wStatus = PH_ADD_COMPCODE_FIXED(PH_ERR_INVALID_DATA_PARAMS, PH_COMP_CRYPTOASYM);

        PH_LOG_HELPER_ADDSTRING(PH_LOG_LOGTYPE_INFO, bFunctionName);
        PH_LOG_HELPER_ADDPARAM_UINT16(PH_LOG_LOGTYPE_INFO, PH_LOG_VAR(wStatus), &wStatus);
        PH_LOG_HELPER_EXECUTE(PH_LOG_OPTION_CATEGORY_LEAVE);

        return wStatus;
    }

    /* Perform operation on active layer. */
    switch(PH_GET_COMPID(pDataParams))
    {
#ifdef NXPBUILD__PH_CRYPTOASYM_MBEDTLS
        case PH_CRYPTOASYM_MBEDTLS_ID:
            wStatus = phCryptoASym_mBedTLS_InvalidateKey((phCryptoASym_mBedTLS_DataParams_t *) pDataParams);
            break;
#endif /* NXPBUILD__PH_CRYPTOASYM_MBEDTLS */

        default:
            wStatus = PH_ADD_COMPCODE_FIXED(PH_ERR_INVALID_DATA_PARAMS, PH_COMP_CRYPTOASYM);
            break;
    }

    PH_LOG_HELPER_ADDSTRING(PH_LOG_LOGTYPE_INFO, bFunctionName);
    PH_LOG_HELPER_ADDPARAM_UINT16(PH_LOG_LOGTYPE_INFO, PH_LOG_VAR(wStatus), &wStatus);
    PH_LOG_HELPER_EXECUTE(PH_LOG_OPTION_CATEGORY_LEAVE);

    return wStatus;
}

phStatus_t phCryptoASym_GetLastStatus(void * pDataParams, uint16_t wStatusMsgLen, int8_t * pStatusMsg, int32_t * pStatusCode)
{
    phStatus_t PH_MEMLOC_REM wStatus = 0;

    PH_LOG_HELPER_ALLOCATE_TEXT(bFunctionName, "phCryptoASym_GetLastStatus");
    PH_LOG_HELPER_ALLOCATE_PARAMNAME(wStatusMsgLen);
    PH_LOG_HELPER_ALLOCATE_PARAMNAME(pStatusMsg);
    PH_LOG_HELPER_ALLOCATE_PARAMNAME(pStatusCode);
    PH_LOG_HELPER_ALLOCATE_PARAMNAME(wStatus);

    /* Validate the parameters. */
    PH_ASSERT_NULL_DATA_PARAM(pDataParams, PH_COMP_CRYPTOASYM);
    PH_ASSERT_NULL_PARAM(pStatusMsg, PH_COMP_CRYPTOASYM);
    PH_ASSERT_NULL_PARAM(pStatusCode, PH_COMP_CRYPTOASYM);

    /* Log the information. */
    PH_LOG_HELPER_ADDSTRING(PH_LOG_LOGTYPE_INFO, bFunctionName);
    PH_LOG_HELPER_ADDPARAM_UINT16(PH_LOG_LOGTYPE_DEBUG, PH_LOG_VAR(wStatusMsgLen), &wStatusMsgLen);
    PH_LOG_HELPER_EXECUTE(PH_LOG_OPTION_CATEGORY_ENTER);

    /* Component Code Validation */
    if(PH_GET_COMPCODE(pDataParams) != PH_COMP_CRYPTOASYM)
    {
        wStatus = PH_ADD_COMPCODE_FIXED(PH_ERR_INVALID_DATA_PARAMS, PH_COMP_CRYPTOASYM);

        PH_LOG_HELPER_ADDSTRING(PH_LOG_LOGTYPE_INFO, bFunctionName);
        PH_LOG_HELPER_ADDPARAM_UINT16(PH_LOG_LOGTYPE_INFO, PH_LOG_VAR(wStatus), &wStatus);
        PH_LOG_HELPER_EXECUTE(PH_LOG_OPTION_CATEGORY_LEAVE);

        return wStatus;
    }

    /* Perform operation on active layer. */
    switch(PH_GET_COMPID(pDataParams))
    {
#ifdef NXPBUILD__PH_CRYPTOASYM_MBEDTLS
        case PH_CRYPTOASYM_MBEDTLS_ID:
            wStatus = phCryptoASym_mBedTLS_GetLastStatus((phCryptoASym_mBedTLS_DataParams_t *) pDataParams, wStatusMsgLen, pStatusMsg, pStatusCode);
            break;
#endif /* NXPBUILD__PH_CRYPTOASYM_MBEDTLS */

        default:
            wStatus = PH_ADD_COMPCODE_FIXED(PH_ERR_INVALID_DATA_PARAMS, PH_COMP_CRYPTOASYM);
            break;
    }

    PH_LOG_HELPER_ADDSTRING(PH_LOG_LOGTYPE_INFO, bFunctionName);
#ifdef NXPBUILD__PH_LOG
    if(( wStatus & PH_ERR_MASK ) == PH_ERR_SUCCESS)
    {
        PH_LOG_HELPER_ADDPARAM_BUFFER(PH_LOG_LOGTYPE_DEBUG, PH_LOG_VAR(pStatusMsg), pStatusMsg, wStatusMsgLen);
        PH_LOG_HELPER_ADDPARAM_INT32(PH_LOG_LOGTYPE_DEBUG, PH_LOG_VAR(pStatusCode), pStatusCode);
    }
#endif /* NXPBUILD__PH_LOG */
    PH_LOG_HELPER_ADDPARAM_UINT16(PH_LOG_LOGTYPE_INFO, PH_LOG_VAR(wStatus), &wStatus);
    PH_LOG_HELPER_EXECUTE(PH_LOG_OPTION_CATEGORY_LEAVE);

    return wStatus;
}

uint16_t phCryptoASym_GetKeySize(uint16_t wKeyType, uint16_t wKeyPair, uint8_t bCurveID)
{
    uint16_t wKeySize = 0;

    switch(wKeyType)
    {
#ifdef NXPBUILD__PH_CRYPTOASYM_ECC
        case PH_CRYPTOASYM_KEY_TYPE_ECC:
            wKeySize = phCryptoASym_mBedTLS_ECC_GetKeySize(wKeyPair, bCurveID);
            break;
#endif /* NXPBUILD__PH_CRYPTOASYM_ECC */

        default:
            wKeySize = 0;
            break;
    }

    return wKeySize;
}

#endif /* NXPBUILD__PH_CRYPTOASYM */
