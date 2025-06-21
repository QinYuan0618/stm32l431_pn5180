/*----------------------------------------------------------------------------*/
/* Copyright 2021 - 2024 NXP                                                  */
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
* Generic MIFARE DUOX Application Component of Reader Library Framework.
* $Author: NXP $
* $Revision: $ (v07.13.00)
* $Date: $
*
*/

#include <ph_Status.h>

#ifdef NXPBUILD__PHAL_MFDUOX

#include <ph_TypeDefs.h>
#include <phalMfDuoX.h>

#ifdef NXPBUILD__PHAL_MFDUOX_SW
#include "Sw/phalMfDuoX_Sw.h"
#endif /* NXPBUILD__PHAL_MFDUOX_SW */

phStatus_t phalMfDuoX_ISOInternalAuthenticate(void * pDataParams, uint8_t bPrivKeyNo, uint8_t bCurveID, uint8_t * pPubBKey,
    uint16_t wPubBKeyLen, uint8_t * pOptsA, uint8_t bOptsALen, uint8_t * pExpRspLen, uint8_t bExpRspLen)
{
    phStatus_t PH_MEMLOC_REM wStatus;

    PH_LOG_HELPER_ALLOCATE_TEXT(bFunctionName, "phalMfDuoX_ISOInternalAuthenticate");
    PH_LOG_HELPER_ALLOCATE_PARAMNAME(bPrivKeyNo);
    PH_LOG_HELPER_ALLOCATE_PARAMNAME(bCurveID);
    PH_LOG_HELPER_ALLOCATE_PARAMNAME(pPubBKey);
    PH_LOG_HELPER_ALLOCATE_PARAMNAME(wPubBKeyLen);
    PH_LOG_HELPER_ALLOCATE_PARAMNAME(pOptsA);
    PH_LOG_HELPER_ALLOCATE_PARAMNAME(bOptsALen);
    PH_LOG_HELPER_ALLOCATE_PARAMNAME(pExpRspLen);
    PH_LOG_HELPER_ALLOCATE_PARAMNAME(bExpRspLen);
    PH_LOG_HELPER_ALLOCATE_PARAMNAME(wStatus);

    /* Validate the parameters */
    PH_ASSERT_NULL_DATA_PARAM(pDataParams, PH_COMP_AL_MFDUOX);
    if(bOptsALen) PH_ASSERT_NULL_PARAM(pOptsA, PH_COMP_AL_MFDUOX);
    if(bExpRspLen) PH_ASSERT_NULL_PARAM(pExpRspLen, PH_COMP_AL_MFDUOX);

    /* Log the information. */
    PH_LOG_HELPER_ADDSTRING(PH_LOG_LOGTYPE_INFO, bFunctionName);
    PH_LOG_HELPER_ADDPARAM_UINT8(PH_LOG_LOGTYPE_DEBUG, PH_LOG_VAR(bPrivKeyNo), &bPrivKeyNo);
    PH_LOG_HELPER_ADDPARAM_UINT8(PH_LOG_LOGTYPE_DEBUG, PH_LOG_VAR(bCurveID), &bCurveID);
    PH_LOG_HELPER_ADDPARAM_BUFFER(PH_LOG_LOGTYPE_DEBUG, PH_LOG_VAR(pPubBKey), pPubBKey, wPubBKeyLen);
    PH_LOG_HELPER_ADDPARAM_UINT16(PH_LOG_LOGTYPE_DEBUG, PH_LOG_VAR(wPubBKeyLen), &wPubBKeyLen);
    PH_LOG_HELPER_ADDPARAM_BUFFER(PH_LOG_LOGTYPE_DEBUG, PH_LOG_VAR(pOptsA), pOptsA, bOptsALen);
    PH_LOG_HELPER_ADDPARAM_UINT8(PH_LOG_LOGTYPE_DEBUG, PH_LOG_VAR(bOptsALen), &bOptsALen);
    PH_LOG_HELPER_ADDPARAM_BUFFER(PH_LOG_LOGTYPE_DEBUG, PH_LOG_VAR(pExpRspLen), pExpRspLen, bExpRspLen);
    PH_LOG_HELPER_ADDPARAM_UINT8(PH_LOG_LOGTYPE_DEBUG, PH_LOG_VAR(bExpRspLen), &bExpRspLen);
    PH_LOG_HELPER_EXECUTE(PH_LOG_OPTION_CATEGORY_ENTER);

    /* Component Code Validation */
    if(PH_GET_COMPCODE(pDataParams) != PH_COMP_AL_MFDUOX)
    {
        PH_LOG_HELPER_ADDSTRING(PH_LOG_LOGTYPE_INFO, bFunctionName);
        PH_LOG_HELPER_ADDPARAM_UINT16(PH_LOG_LOGTYPE_INFO, PH_LOG_VAR(wStatus), &wStatus);
        PH_LOG_HELPER_EXECUTE(PH_LOG_OPTION_CATEGORY_LEAVE);

        return PH_ADD_COMPCODE(PH_ERR_INVALID_DATA_PARAMS, PH_COMP_AL_MFDUOX);
    }

    /* Perform operation on active layer */
    switch(PH_GET_COMPID(pDataParams))
    {
#ifdef NXPBUILD__PHAL_MFDUOX_SW
        case PHAL_MFDUOX_SW_ID:
            wStatus = phalMfDuoX_Sw_ISOInternalAuthenticate((phalMfDuoX_Sw_DataParams_t *) pDataParams, bPrivKeyNo,
                bCurveID, pPubBKey, wPubBKeyLen, pOptsA, bOptsALen, pExpRspLen, bExpRspLen);
            break;
#endif /* NXPBUILD__PHAL_MFDUOX_SW */

        default:
            wStatus = PH_ADD_COMPCODE(PH_ERR_INVALID_DATA_PARAMS, PH_COMP_AL_MFDUOX);
            break;
    }

    PH_LOG_HELPER_ADDSTRING(PH_LOG_LOGTYPE_INFO, bFunctionName);
    PH_LOG_HELPER_ADDPARAM_UINT16(PH_LOG_LOGTYPE_INFO, PH_LOG_VAR(wStatus), &wStatus);
    PH_LOG_HELPER_EXECUTE(PH_LOG_OPTION_CATEGORY_LEAVE);

    return wStatus;
}

/* MIFARE DUOX Memory and Configuration management commands ----------------------------------------------------------------------------- */
phStatus_t phalMfDuoX_FreeMem(void * pDataParams, uint8_t ** ppMemInfo, uint16_t * pMemInfoLen)
{
    phStatus_t PH_MEMLOC_REM wStatus;

    PH_LOG_HELPER_ALLOCATE_TEXT(bFunctionName, "phalMfDuoX_FreeMem");
    PH_LOG_HELPER_ALLOCATE_PARAMNAME(ppMemInfo);
    PH_LOG_HELPER_ALLOCATE_PARAMNAME(pMemInfoLen);
    PH_LOG_HELPER_ALLOCATE_PARAMNAME(wStatus);

    /* Validate the parameters */
    PH_ASSERT_NULL_DATA_PARAM(pDataParams, PH_COMP_AL_MFDUOX);
    PH_ASSERT_NULL_PARAM(pMemInfoLen, PH_COMP_AL_MFDUOX);

    /* Log the information. */
    PH_LOG_HELPER_ADDSTRING(PH_LOG_LOGTYPE_INFO, bFunctionName);
    PH_LOG_HELPER_EXECUTE(PH_LOG_OPTION_CATEGORY_ENTER);

    /* Component Code Validation */
    if(PH_GET_COMPCODE(pDataParams) != PH_COMP_AL_MFDUOX)
    {
        PH_LOG_HELPER_ADDSTRING(PH_LOG_LOGTYPE_INFO, bFunctionName);
        PH_LOG_HELPER_ADDPARAM_UINT16(PH_LOG_LOGTYPE_INFO, PH_LOG_VAR(wStatus), &wStatus);
        PH_LOG_HELPER_EXECUTE(PH_LOG_OPTION_CATEGORY_LEAVE);

        return PH_ADD_COMPCODE(PH_ERR_INVALID_DATA_PARAMS, PH_COMP_AL_MFDUOX);
    }

    /* Perform operation on active layer */
    switch(PH_GET_COMPID(pDataParams))
    {
#ifdef NXPBUILD__PHAL_MFDUOX_SW
        case PHAL_MFDUOX_SW_ID:
            wStatus = phalMfDuoX_Sw_FreeMem((phalMfDuoX_Sw_DataParams_t *) pDataParams, ppMemInfo, pMemInfoLen);
            break;
#endif /* NXPBUILD__PHAL_MFDUOX_SW */

        default:
            wStatus = PH_ADD_COMPCODE(PH_ERR_INVALID_DATA_PARAMS, PH_COMP_AL_MFDUOX);
            break;
    }

    PH_LOG_HELPER_ADDSTRING(PH_LOG_LOGTYPE_INFO, bFunctionName);
#ifdef NXPBUILD__PH_LOG
    if((wStatus & PH_ERR_MASK) == PH_ERR_SUCCESS)
    {
        PH_LOG_HELPER_ADDPARAM_BUFFER(PH_LOG_LOGTYPE_DEBUG, PH_LOG_VAR(ppMemInfo), ppMemInfo, *pMemInfoLen);
        PH_LOG_HELPER_ADDPARAM_UINT16(PH_LOG_LOGTYPE_INFO, PH_LOG_VAR(pMemInfoLen), pMemInfoLen);
    }
#endif /* NXPBUILD__PH_LOG */
    PH_LOG_HELPER_ADDPARAM_UINT16(PH_LOG_LOGTYPE_INFO, PH_LOG_VAR(wStatus), &wStatus);
    PH_LOG_HELPER_EXECUTE(PH_LOG_OPTION_CATEGORY_LEAVE);

    return wStatus;
}

phStatus_t phalMfDuoX_GetVersion(void * pDataParams, uint8_t bOption, uint8_t ** ppVersion, uint16_t * pVerLen)
{
    phStatus_t PH_MEMLOC_REM wStatus;

    PH_LOG_HELPER_ALLOCATE_TEXT(bFunctionName, "phalMfDuoX_GetVersion");
    PH_LOG_HELPER_ALLOCATE_PARAMNAME(bOption);
    PH_LOG_HELPER_ALLOCATE_PARAMNAME(ppVersion);
    PH_LOG_HELPER_ALLOCATE_PARAMNAME(pVerLen);
    PH_LOG_HELPER_ALLOCATE_PARAMNAME(wStatus);

    /* Validate the parameters */
    PH_ASSERT_NULL_DATA_PARAM(pDataParams, PH_COMP_AL_MFDUOX);
    PH_ASSERT_NULL_PARAM(pVerLen, PH_COMP_AL_MFDUOX);

    /* Log the information. */
    PH_LOG_HELPER_ADDSTRING(PH_LOG_LOGTYPE_INFO, bFunctionName);
    PH_LOG_HELPER_ADDPARAM_UINT8(PH_LOG_LOGTYPE_DEBUG, PH_LOG_VAR(bOption), &bOption);
    PH_LOG_HELPER_EXECUTE(PH_LOG_OPTION_CATEGORY_ENTER);

    /* Component Code Validation */
    if(PH_GET_COMPCODE(pDataParams) != PH_COMP_AL_MFDUOX)
    {
        PH_LOG_HELPER_ADDSTRING(PH_LOG_LOGTYPE_INFO, bFunctionName);
        PH_LOG_HELPER_ADDPARAM_UINT16(PH_LOG_LOGTYPE_INFO, PH_LOG_VAR(wStatus), &wStatus);
        PH_LOG_HELPER_EXECUTE(PH_LOG_OPTION_CATEGORY_LEAVE);

        return PH_ADD_COMPCODE(PH_ERR_INVALID_DATA_PARAMS, PH_COMP_AL_MFDUOX);
    }

    /* Perform operation on active layer */
    switch(PH_GET_COMPID(pDataParams))
    {
#ifdef NXPBUILD__PHAL_MFDUOX_SW
        case PHAL_MFDUOX_SW_ID:
            wStatus = phalMfDuoX_Sw_GetVersion((phalMfDuoX_Sw_DataParams_t *) pDataParams, bOption, ppVersion, pVerLen);
            break;
#endif /* NXPBUILD__PHAL_MFDUOX_SW */

        default:
            wStatus = PH_ADD_COMPCODE(PH_ERR_INVALID_DATA_PARAMS, PH_COMP_AL_MFDUOX);
            break;
    }

    PH_LOG_HELPER_ADDSTRING(PH_LOG_LOGTYPE_INFO, bFunctionName);
#ifdef NXPBUILD__PH_LOG
    if((wStatus & PH_ERR_MASK) == PH_ERR_SUCCESS)
    {
        PH_LOG_HELPER_ADDPARAM_BUFFER(PH_LOG_LOGTYPE_DEBUG, PH_LOG_VAR(ppVersion), *ppVersion, *pVerLen);
        PH_LOG_HELPER_ADDPARAM_UINT16(PH_LOG_LOGTYPE_INFO, PH_LOG_VAR(pVerLen), pVerLen);
    }
#endif /* NXPBUILD__PH_LOG */
    PH_LOG_HELPER_ADDPARAM_UINT16(PH_LOG_LOGTYPE_INFO, PH_LOG_VAR(wStatus), &wStatus);
    PH_LOG_HELPER_EXECUTE(PH_LOG_OPTION_CATEGORY_LEAVE);

    return wStatus;
}

/* MIFARE DUOX Symmetric Key management commands ---------------------------------------------------------------------------------------- */

phStatus_t phalMfDuoX_GetKeySettings(void * pDataParams, uint8_t bOption, uint8_t ** ppResponse,
    uint16_t * pRspLen)
{
    phStatus_t PH_MEMLOC_REM wStatus;

    PH_LOG_HELPER_ALLOCATE_TEXT(bFunctionName, "phalMfDuoX_GetKeySettings");
    PH_LOG_HELPER_ALLOCATE_PARAMNAME(bOption);
    PH_LOG_HELPER_ALLOCATE_PARAMNAME(ppResponse);
    PH_LOG_HELPER_ALLOCATE_PARAMNAME(pRspLen);
    PH_LOG_HELPER_ALLOCATE_PARAMNAME(wStatus);

    /* Validate the parameters */
    PH_ASSERT_NULL_DATA_PARAM(pDataParams, PH_COMP_AL_MFDUOX);
    PH_ASSERT_NULL_PARAM(pRspLen, PH_COMP_AL_MFDUOX);

    /* Log the information. */
    PH_LOG_HELPER_ADDSTRING(PH_LOG_LOGTYPE_INFO, bFunctionName);
    if(bOption)
        PH_LOG_HELPER_ADDPARAM_UINT8(PH_LOG_LOGTYPE_DEBUG, PH_LOG_VAR(bOption), &bOption);
    PH_LOG_HELPER_EXECUTE(PH_LOG_OPTION_CATEGORY_ENTER);

    /* Component Code Validation */
    if(PH_GET_COMPCODE(pDataParams) != PH_COMP_AL_MFDUOX)
    {
        PH_LOG_HELPER_ADDSTRING(PH_LOG_LOGTYPE_INFO, bFunctionName);
        PH_LOG_HELPER_ADDPARAM_UINT16(PH_LOG_LOGTYPE_INFO, PH_LOG_VAR(wStatus), &wStatus);
        PH_LOG_HELPER_EXECUTE(PH_LOG_OPTION_CATEGORY_LEAVE);

        return PH_ADD_COMPCODE(PH_ERR_INVALID_DATA_PARAMS, PH_COMP_AL_MFDUOX);
    }

    /* Perform operation on active layer */
    switch(PH_GET_COMPID(pDataParams))
    {
#ifdef NXPBUILD__PHAL_MFDUOX_SW
        case PHAL_MFDUOX_SW_ID:
            wStatus = phalMfDuoX_Sw_GetKeySettings((phalMfDuoX_Sw_DataParams_t *) pDataParams, bOption, ppResponse, pRspLen);
            break;
#endif /* NXPBUILD__PHAL_MFDUOX_SW */

        default:
            wStatus = PH_ADD_COMPCODE(PH_ERR_INVALID_DATA_PARAMS, PH_COMP_AL_MFDUOX);
            break;
    }

    PH_LOG_HELPER_ADDSTRING(PH_LOG_LOGTYPE_INFO, bFunctionName);
#ifdef NXPBUILD__PH_LOG
    if((wStatus & PH_ERR_MASK) == PH_ERR_SUCCESS)
    {
        PH_LOG_HELPER_ADDPARAM_BUFFER(PH_LOG_LOGTYPE_DEBUG, PH_LOG_VAR(ppResponse), *ppResponse, *pRspLen);
        PH_LOG_HELPER_ADDPARAM_UINT16(PH_LOG_LOGTYPE_DEBUG, PH_LOG_VAR(pRspLen), pRspLen);
    }
#endif /* NXPBUILD__PH_LOG */
    PH_LOG_HELPER_ADDPARAM_UINT16(PH_LOG_LOGTYPE_INFO, PH_LOG_VAR(wStatus), &wStatus);
    PH_LOG_HELPER_EXECUTE(PH_LOG_OPTION_CATEGORY_LEAVE);

    return wStatus;
}

/* MIFARE DUOX ASymmetric Key management commands --------------------------------------------------------------------------------------- */
phStatus_t phalMfDuoX_ManageKeyPair(void * pDataParams, uint8_t bComOption, uint8_t bKeyNo, uint8_t bOption,
    uint8_t bCurveID, uint8_t * pKeyPolicy, uint8_t bWriteAccess, uint32_t dwKUCLimit, uint16_t wPrivKey_No,
    uint16_t wPrivKey_Pos, uint8_t ** ppResponse, uint16_t * pRspLen)
{
    phStatus_t PH_MEMLOC_REM wStatus;

    PH_LOG_HELPER_ALLOCATE_TEXT(bFunctionName, "phalMfDuoX_ManageKeyPair");
    PH_LOG_HELPER_ALLOCATE_PARAMNAME(bComOption);
    PH_LOG_HELPER_ALLOCATE_PARAMNAME(bKeyNo);
    PH_LOG_HELPER_ALLOCATE_PARAMNAME(bOption);
    PH_LOG_HELPER_ALLOCATE_PARAMNAME(bCurveID);
    PH_LOG_HELPER_ALLOCATE_PARAMNAME(pKeyPolicy);
    PH_LOG_HELPER_ALLOCATE_PARAMNAME(bWriteAccess);
    PH_LOG_HELPER_ALLOCATE_PARAMNAME(dwKUCLimit);
    PH_LOG_HELPER_ALLOCATE_PARAMNAME(wPrivKey_No);
    PH_LOG_HELPER_ALLOCATE_PARAMNAME(wPrivKey_Pos);
    PH_LOG_HELPER_ALLOCATE_PARAMNAME(ppResponse);
    PH_LOG_HELPER_ALLOCATE_PARAMNAME(pRspLen);
    PH_LOG_HELPER_ALLOCATE_PARAMNAME(wStatus);

    /* Validate the parameters */
    PH_ASSERT_NULL_DATA_PARAM(pDataParams, PH_COMP_AL_MFDUOX);
    PH_ASSERT_NULL_PARAM(pKeyPolicy, PH_COMP_AL_MFDUOX);
    PH_ASSERT_NULL_PARAM(pRspLen, PH_COMP_AL_MFDUOX);

    /* Log the information. */
    PH_LOG_HELPER_ADDSTRING(PH_LOG_LOGTYPE_INFO, bFunctionName);
    PH_LOG_HELPER_ADDPARAM_UINT8(PH_LOG_LOGTYPE_DEBUG, PH_LOG_VAR(bComOption), &bComOption);
    PH_LOG_HELPER_ADDPARAM_UINT8(PH_LOG_LOGTYPE_DEBUG, PH_LOG_VAR(bKeyNo), &bKeyNo);
    PH_LOG_HELPER_ADDPARAM_UINT8(PH_LOG_LOGTYPE_DEBUG, PH_LOG_VAR(bOption), &bOption);
    PH_LOG_HELPER_ADDPARAM_UINT8(PH_LOG_LOGTYPE_DEBUG, PH_LOG_VAR(bCurveID), &bCurveID);
    PH_LOG_HELPER_ADDPARAM_BUFFER(PH_LOG_LOGTYPE_DEBUG, PH_LOG_VAR(pKeyPolicy), pKeyPolicy, 2);
    PH_LOG_HELPER_ADDPARAM_UINT8(PH_LOG_LOGTYPE_DEBUG, PH_LOG_VAR(bWriteAccess), &bWriteAccess);
    PH_LOG_HELPER_ADDPARAM_UINT32(PH_LOG_LOGTYPE_DEBUG, PH_LOG_VAR(dwKUCLimit), &dwKUCLimit);
    PH_LOG_HELPER_ADDPARAM_UINT16(PH_LOG_LOGTYPE_DEBUG, PH_LOG_VAR(wPrivKey_No), &wPrivKey_No);
    PH_LOG_HELPER_ADDPARAM_UINT16(PH_LOG_LOGTYPE_DEBUG, PH_LOG_VAR(wPrivKey_Pos), &wPrivKey_Pos);
    PH_LOG_HELPER_EXECUTE(PH_LOG_OPTION_CATEGORY_ENTER);

    /* Component Code Validation */
    if(PH_GET_COMPCODE(pDataParams) != PH_COMP_AL_MFDUOX)
    {
        PH_LOG_HELPER_ADDSTRING(PH_LOG_LOGTYPE_INFO, bFunctionName);
        PH_LOG_HELPER_ADDPARAM_UINT16(PH_LOG_LOGTYPE_INFO, PH_LOG_VAR(wStatus), &wStatus);
        PH_LOG_HELPER_EXECUTE(PH_LOG_OPTION_CATEGORY_LEAVE);

        return PH_ADD_COMPCODE(PH_ERR_INVALID_DATA_PARAMS, PH_COMP_AL_MFDUOX);
    }

    /* Perform operation on active layer */
    switch(PH_GET_COMPID(pDataParams))
    {
#ifdef NXPBUILD__PHAL_MFDUOX_SW
        case PHAL_MFDUOX_SW_ID:
            wStatus = phalMfDuoX_Sw_ManageKeyPair((phalMfDuoX_Sw_DataParams_t *) pDataParams, bComOption, bKeyNo, bOption,
                bCurveID, pKeyPolicy, bWriteAccess, dwKUCLimit, wPrivKey_No, wPrivKey_Pos, ppResponse, pRspLen);
            break;
#endif /* NXPBUILD__PHAL_MFDUOX_SW */

        default:
            wStatus = PH_ADD_COMPCODE(PH_ERR_INVALID_DATA_PARAMS, PH_COMP_AL_MFDUOX);
            break;
    }

    PH_LOG_HELPER_ADDSTRING(PH_LOG_LOGTYPE_INFO, bFunctionName);
#ifdef NXPBUILD__PH_LOG
    if((wStatus & PH_ERR_MASK) == PH_ERR_SUCCESS)
    {
        PH_LOG_HELPER_ADDPARAM_BUFFER(PH_LOG_LOGTYPE_DEBUG, PH_LOG_VAR(ppResponse), *ppResponse, *pRspLen);
        PH_LOG_HELPER_ADDPARAM_UINT16(PH_LOG_LOGTYPE_DEBUG, PH_LOG_VAR(pRspLen), pRspLen);
    }
#endif /* NXPBUILD__PH_LOG */
    PH_LOG_HELPER_ADDPARAM_UINT16(PH_LOG_LOGTYPE_INFO, PH_LOG_VAR(wStatus), &wStatus);
    PH_LOG_HELPER_EXECUTE(PH_LOG_OPTION_CATEGORY_LEAVE);

    return wStatus;
}

phStatus_t phalMfDuoX_ManageCARootKey(void * pDataParams, uint8_t bComOption, uint8_t bKeyNo, uint8_t bCurveID,
    uint8_t * pAccessRights, uint8_t bWriteAccess, uint8_t bReadAccess, uint8_t bCRLFile, uint8_t * pCRLFileAID,
    uint16_t wPubKey_No, uint16_t wPubKey_Pos, uint8_t * pIssuer, uint8_t bIssuerLen)
{
    phStatus_t PH_MEMLOC_REM wStatus;

    PH_LOG_HELPER_ALLOCATE_TEXT(bFunctionName, "phalMfDuoX_ManageCARootKey");
    PH_LOG_HELPER_ALLOCATE_PARAMNAME(bComOption);
    PH_LOG_HELPER_ALLOCATE_PARAMNAME(bKeyNo);
    PH_LOG_HELPER_ALLOCATE_PARAMNAME(bCurveID);
    PH_LOG_HELPER_ALLOCATE_PARAMNAME(pAccessRights);
    PH_LOG_HELPER_ALLOCATE_PARAMNAME(bWriteAccess);
    PH_LOG_HELPER_ALLOCATE_PARAMNAME(bReadAccess);
    PH_LOG_HELPER_ALLOCATE_PARAMNAME(bCRLFile);
    PH_LOG_HELPER_ALLOCATE_PARAMNAME(pCRLFileAID);
    PH_LOG_HELPER_ALLOCATE_PARAMNAME(wPubKey_No);
    PH_LOG_HELPER_ALLOCATE_PARAMNAME(wPubKey_Pos);
    PH_LOG_HELPER_ALLOCATE_PARAMNAME(pIssuer);
    PH_LOG_HELPER_ALLOCATE_PARAMNAME(bIssuerLen);
    PH_LOG_HELPER_ALLOCATE_PARAMNAME(wStatus);

    /* Validate the parameters */
    PH_ASSERT_NULL_DATA_PARAM(pDataParams, PH_COMP_AL_MFDUOX);
    PH_ASSERT_NULL_PARAM(pAccessRights, PH_COMP_AL_MFDUOX);
    PH_ASSERT_NULL_PARAM(pCRLFileAID, PH_COMP_AL_MFDUOX);

    /* Log the information. */
    PH_LOG_HELPER_ADDSTRING(PH_LOG_LOGTYPE_INFO, bFunctionName);
    PH_LOG_HELPER_ADDPARAM_UINT8(PH_LOG_LOGTYPE_DEBUG, PH_LOG_VAR(bComOption), &bComOption);
    PH_LOG_HELPER_ADDPARAM_UINT8(PH_LOG_LOGTYPE_DEBUG, PH_LOG_VAR(bKeyNo), &bKeyNo);
    PH_LOG_HELPER_ADDPARAM_UINT8(PH_LOG_LOGTYPE_DEBUG, PH_LOG_VAR(bCurveID), &bCurveID);
    PH_LOG_HELPER_ADDPARAM_BUFFER(PH_LOG_LOGTYPE_DEBUG, PH_LOG_VAR(pAccessRights), pAccessRights, 2);
    PH_LOG_HELPER_ADDPARAM_UINT8(PH_LOG_LOGTYPE_DEBUG, PH_LOG_VAR(bWriteAccess), &bWriteAccess);
    PH_LOG_HELPER_ADDPARAM_UINT8(PH_LOG_LOGTYPE_DEBUG, PH_LOG_VAR(bReadAccess), &bReadAccess);
    PH_LOG_HELPER_ADDPARAM_UINT8(PH_LOG_LOGTYPE_DEBUG, PH_LOG_VAR(bCRLFile), &bCRLFile);
    PH_LOG_HELPER_ADDPARAM_BUFFER(PH_LOG_LOGTYPE_DEBUG, PH_LOG_VAR(pCRLFileAID), pCRLFileAID, PHAL_MFDUOX_APP_ID_LEN);
    PH_LOG_HELPER_ADDPARAM_UINT16(PH_LOG_LOGTYPE_DEBUG, PH_LOG_VAR(wPubKey_No), &wPubKey_No);
    PH_LOG_HELPER_ADDPARAM_UINT16(PH_LOG_LOGTYPE_DEBUG, PH_LOG_VAR(wPubKey_Pos), &wPubKey_Pos);
    PH_LOG_HELPER_ADDPARAM_UINT8(PH_LOG_LOGTYPE_DEBUG, PH_LOG_VAR(bIssuerLen), &bIssuerLen);
    PH_LOG_HELPER_ADDPARAM_BUFFER(PH_LOG_LOGTYPE_DEBUG, PH_LOG_VAR(pIssuer), pIssuer, bIssuerLen);
    PH_LOG_HELPER_EXECUTE(PH_LOG_OPTION_CATEGORY_ENTER);

    /* Component Code Validation */
    if(PH_GET_COMPCODE(pDataParams) != PH_COMP_AL_MFDUOX)
    {
        PH_LOG_HELPER_ADDSTRING(PH_LOG_LOGTYPE_INFO, bFunctionName);
        PH_LOG_HELPER_ADDPARAM_UINT16(PH_LOG_LOGTYPE_INFO, PH_LOG_VAR(wStatus), &wStatus);
        PH_LOG_HELPER_EXECUTE(PH_LOG_OPTION_CATEGORY_LEAVE);

        return PH_ADD_COMPCODE(PH_ERR_INVALID_DATA_PARAMS, PH_COMP_AL_MFDUOX);
    }

    /* Perform operation on active layer */
    switch(PH_GET_COMPID(pDataParams))
    {
#ifdef NXPBUILD__PHAL_MFDUOX_SW
        case PHAL_MFDUOX_SW_ID:
            wStatus = phalMfDuoX_Sw_ManageCARootKey((phalMfDuoX_Sw_DataParams_t *) pDataParams, bComOption, bKeyNo, bCurveID,
                pAccessRights, bWriteAccess, bReadAccess, bCRLFile, pCRLFileAID, wPubKey_No, wPubKey_Pos, pIssuer, bIssuerLen);
            break;
#endif /* NXPBUILD__PHAL_MFDUOX_SW */

        default:
            wStatus = PH_ADD_COMPCODE(PH_ERR_INVALID_DATA_PARAMS, PH_COMP_AL_MFDUOX);
            break;
    }

    PH_LOG_HELPER_ADDSTRING(PH_LOG_LOGTYPE_INFO, bFunctionName);
    PH_LOG_HELPER_ADDPARAM_UINT16(PH_LOG_LOGTYPE_INFO, PH_LOG_VAR(wStatus), &wStatus);
    PH_LOG_HELPER_EXECUTE(PH_LOG_OPTION_CATEGORY_LEAVE);

    return wStatus;
}

phStatus_t phalMfDuoX_ExportKey(void * pDataParams, uint8_t bComOption, uint8_t bOption, uint8_t bKeyNo,
    uint8_t ** ppResponse, uint16_t * pRspLen)
{
    phStatus_t PH_MEMLOC_REM wStatus;

    PH_LOG_HELPER_ALLOCATE_TEXT(bFunctionName, "phalMfDuoX_ExportKey");
    PH_LOG_HELPER_ALLOCATE_PARAMNAME(bComOption);
    PH_LOG_HELPER_ALLOCATE_PARAMNAME(bOption);
    PH_LOG_HELPER_ALLOCATE_PARAMNAME(bKeyNo);
    PH_LOG_HELPER_ALLOCATE_PARAMNAME(ppResponse);
    PH_LOG_HELPER_ALLOCATE_PARAMNAME(pRspLen);
    PH_LOG_HELPER_ALLOCATE_PARAMNAME(wStatus);

    /* Validate the parameters */
    PH_ASSERT_NULL_DATA_PARAM(pDataParams, PH_COMP_AL_MFDUOX);
    PH_ASSERT_NULL_PARAM(pRspLen, PH_COMP_AL_MFDUOX);

    /* Log the information. */
    PH_LOG_HELPER_ADDSTRING(PH_LOG_LOGTYPE_INFO, bFunctionName);
    PH_LOG_HELPER_ADDPARAM_UINT8(PH_LOG_LOGTYPE_DEBUG, PH_LOG_VAR(bComOption), &bComOption);
    PH_LOG_HELPER_ADDPARAM_UINT8(PH_LOG_LOGTYPE_DEBUG, PH_LOG_VAR(bKeyNo), &bKeyNo);
    PH_LOG_HELPER_ADDPARAM_UINT8(PH_LOG_LOGTYPE_DEBUG, PH_LOG_VAR(bOption), &bOption);
    PH_LOG_HELPER_EXECUTE(PH_LOG_OPTION_CATEGORY_ENTER);

    /* Component Code Validation */
    if(PH_GET_COMPCODE(pDataParams) != PH_COMP_AL_MFDUOX)
    {
        PH_LOG_HELPER_ADDSTRING(PH_LOG_LOGTYPE_INFO, bFunctionName);
        PH_LOG_HELPER_ADDPARAM_UINT16(PH_LOG_LOGTYPE_INFO, PH_LOG_VAR(wStatus), &wStatus);
        PH_LOG_HELPER_EXECUTE(PH_LOG_OPTION_CATEGORY_LEAVE);

        return PH_ADD_COMPCODE(PH_ERR_INVALID_DATA_PARAMS, PH_COMP_AL_MFDUOX);
    }

    /* Perform operation on active layer */
    switch(PH_GET_COMPID(pDataParams))
    {
#ifdef NXPBUILD__PHAL_MFDUOX_SW
        case PHAL_MFDUOX_SW_ID:
            wStatus = phalMfDuoX_Sw_ExportKey((phalMfDuoX_Sw_DataParams_t *) pDataParams, bComOption, bOption, bKeyNo, ppResponse,
                pRspLen);
            break;
#endif /* NXPBUILD__PHAL_MFDUOX_SW */

        default:
            wStatus = PH_ADD_COMPCODE(PH_ERR_INVALID_DATA_PARAMS, PH_COMP_AL_MFDUOX);
            break;
    }

    PH_LOG_HELPER_ADDSTRING(PH_LOG_LOGTYPE_INFO, bFunctionName);
#ifdef NXPBUILD__PH_LOG
    if((wStatus & PH_ERR_MASK) == PH_ERR_SUCCESS)
    {
        PH_LOG_HELPER_ADDPARAM_BUFFER(PH_LOG_LOGTYPE_DEBUG, PH_LOG_VAR(ppResponse), *ppResponse, *pRspLen);
        PH_LOG_HELPER_ADDPARAM_UINT16(PH_LOG_LOGTYPE_DEBUG, PH_LOG_VAR(pRspLen), pRspLen);
    }
#endif /* NXPBUILD__PH_LOG */
    PH_LOG_HELPER_ADDPARAM_UINT16(PH_LOG_LOGTYPE_INFO, PH_LOG_VAR(wStatus), &wStatus);
    PH_LOG_HELPER_EXECUTE(PH_LOG_OPTION_CATEGORY_LEAVE);

    return wStatus;
}

/* MIFARE DUOX Application management commands ------------------------------------------------------------------------------------------ */
phStatus_t phalMfDuoX_CreateApplication(void * pDataParams, uint8_t bOption, uint8_t * pAid, uint8_t bKeySettings1,
    uint8_t bKeySettings2, uint8_t bKeySettings3, uint8_t * pKeySetValues, uint8_t bKeySetValuesLen, uint8_t * pISOFileId,
    uint8_t * pISODFName, uint8_t bISODFNameLen)
{
    phStatus_t PH_MEMLOC_REM wStatus;

    PH_LOG_HELPER_ALLOCATE_TEXT(bFunctionName, "phalMfDuoX_CreateApplication");
    PH_LOG_HELPER_ALLOCATE_PARAMNAME(bOption);
    PH_LOG_HELPER_ALLOCATE_PARAMNAME(pAid);
    PH_LOG_HELPER_ALLOCATE_PARAMNAME(bKeySettings1);
    PH_LOG_HELPER_ALLOCATE_PARAMNAME(bKeySettings2);
    PH_LOG_HELPER_ALLOCATE_PARAMNAME(bKeySettings3);
    PH_LOG_HELPER_ALLOCATE_PARAMNAME(pKeySetValues);
    PH_LOG_HELPER_ALLOCATE_PARAMNAME(bKeySetValuesLen);
    PH_LOG_HELPER_ALLOCATE_PARAMNAME(pISOFileId);
    PH_LOG_HELPER_ALLOCATE_PARAMNAME(pISODFName);
    PH_LOG_HELPER_ALLOCATE_PARAMNAME(bISODFNameLen);
    PH_LOG_HELPER_ALLOCATE_PARAMNAME(wStatus);

    /* Validate the parameters */
    PH_ASSERT_NULL_DATA_PARAM(pDataParams, PH_COMP_AL_MFDUOX);
    PH_ASSERT_NULL_PARAM(pAid, PH_COMP_AL_MFDUOX);
    if(bKeySetValuesLen) PH_ASSERT_NULL_PARAM(pKeySetValues, PH_COMP_AL_MFDUOX);
    if(bOption & PHAL_MFDUOX_ISO_FILE_ID_AVAILABLE)
        PH_ASSERT_NULL_PARAM(pISOFileId, PH_COMP_AL_MFDUOX);
    if(bISODFNameLen) PH_ASSERT_NULL_PARAM(pISODFName, PH_COMP_AL_MFDUOX);

    /* Log the information. */
    PH_LOG_HELPER_ADDSTRING(PH_LOG_LOGTYPE_INFO, bFunctionName);
    PH_LOG_HELPER_ADDPARAM_UINT8(PH_LOG_LOGTYPE_DEBUG, PH_LOG_VAR(bOption), &bOption);
    PH_LOG_HELPER_ADDPARAM_BUFFER(PH_LOG_LOGTYPE_DEBUG, PH_LOG_VAR(pAid), pAid, PHAL_MFDUOX_APP_ID_LEN);
    PH_LOG_HELPER_ADDPARAM_UINT8(PH_LOG_LOGTYPE_DEBUG, PH_LOG_VAR(bKeySettings1), &bKeySettings1);
    PH_LOG_HELPER_ADDPARAM_UINT8(PH_LOG_LOGTYPE_DEBUG, PH_LOG_VAR(bKeySettings2), &bKeySettings2);
    PH_LOG_HELPER_ADDPARAM_UINT8(PH_LOG_LOGTYPE_DEBUG, PH_LOG_VAR(bKeySettings3), &bKeySettings3);
    PH_LOG_HELPER_ADDPARAM_BUFFER(PH_LOG_LOGTYPE_DEBUG, PH_LOG_VAR(pKeySetValues), pKeySetValues, bKeySetValuesLen);
    PH_LOG_HELPER_ADDPARAM_UINT8(PH_LOG_LOGTYPE_DEBUG, PH_LOG_VAR(bKeySetValuesLen), &bKeySetValuesLen);
    PH_LOG_HELPER_ADDPARAM_BUFFER(PH_LOG_LOGTYPE_DEBUG, PH_LOG_VAR(pISOFileId), pISOFileId, 2);
    PH_LOG_HELPER_ADDPARAM_BUFFER(PH_LOG_LOGTYPE_DEBUG, PH_LOG_VAR(pISODFName), pISODFName, bISODFNameLen);
    PH_LOG_HELPER_ADDPARAM_UINT8(PH_LOG_LOGTYPE_DEBUG, PH_LOG_VAR(bISODFNameLen), &bISODFNameLen);
    PH_LOG_HELPER_EXECUTE(PH_LOG_OPTION_CATEGORY_ENTER);

    /* Component Code Validation */
    if(PH_GET_COMPCODE(pDataParams) != PH_COMP_AL_MFDUOX)
    {
        PH_LOG_HELPER_ADDSTRING(PH_LOG_LOGTYPE_INFO, bFunctionName);
        PH_LOG_HELPER_ADDPARAM_UINT16(PH_LOG_LOGTYPE_INFO, PH_LOG_VAR(wStatus), &wStatus);
        PH_LOG_HELPER_EXECUTE(PH_LOG_OPTION_CATEGORY_LEAVE);

        return PH_ADD_COMPCODE(PH_ERR_INVALID_DATA_PARAMS, PH_COMP_AL_MFDUOX);
    }

    /* Perform operation on active layer */
    switch(PH_GET_COMPID(pDataParams))
    {
#ifdef NXPBUILD__PHAL_MFDUOX_SW
        case PHAL_MFDUOX_SW_ID:
            wStatus = phalMfDuoX_Sw_CreateApplication((phalMfDuoX_Sw_DataParams_t *) pDataParams, bOption, pAid, bKeySettings1,
                bKeySettings2, bKeySettings3, pKeySetValues, bKeySetValuesLen, pISOFileId, pISODFName, bISODFNameLen);
            break;
#endif /* NXPBUILD__PHAL_MFDUOX_SW */

        default:
            wStatus = PH_ADD_COMPCODE(PH_ERR_INVALID_DATA_PARAMS, PH_COMP_AL_MFDUOX);
            break;
    }

    PH_LOG_HELPER_ADDSTRING(PH_LOG_LOGTYPE_INFO, bFunctionName);
    PH_LOG_HELPER_ADDPARAM_UINT16(PH_LOG_LOGTYPE_INFO, PH_LOG_VAR(wStatus), &wStatus);
    PH_LOG_HELPER_EXECUTE(PH_LOG_OPTION_CATEGORY_LEAVE);

    return wStatus;
}

phStatus_t phalMfDuoX_DeleteApplication(void * pDataParams, uint8_t * pAid, uint8_t * pDAMMAC, uint8_t bDAMMAC_Len)
{
    phStatus_t PH_MEMLOC_REM wStatus;

    PH_LOG_HELPER_ALLOCATE_TEXT(bFunctionName, "phalMfDuoX_DeleteApplication");
    PH_LOG_HELPER_ALLOCATE_PARAMNAME(pAid);
    PH_LOG_HELPER_ALLOCATE_PARAMNAME(pDAMMAC);
    PH_LOG_HELPER_ALLOCATE_PARAMNAME(bDAMMAC_Len);
    PH_LOG_HELPER_ALLOCATE_PARAMNAME(wStatus);

    /* Validate the parameters */
    PH_ASSERT_NULL_DATA_PARAM(pDataParams, PH_COMP_AL_MFDUOX);
    PH_ASSERT_NULL_PARAM(pAid, PH_COMP_AL_MFDUOX);
    if(bDAMMAC_Len) PH_ASSERT_NULL_PARAM(pDAMMAC, PH_COMP_AL_MFDUOX);

    /* Log the information. */
    PH_LOG_HELPER_ADDSTRING(PH_LOG_LOGTYPE_INFO, bFunctionName);
    PH_LOG_HELPER_ADDPARAM_BUFFER(PH_LOG_LOGTYPE_DEBUG, PH_LOG_VAR(pAid), pAid, PHAL_MFDUOX_APP_ID_LEN);
    PH_LOG_HELPER_ADDPARAM_BUFFER(PH_LOG_LOGTYPE_DEBUG, PH_LOG_VAR(pDAMMAC), pDAMMAC, bDAMMAC_Len);
    PH_LOG_HELPER_ADDPARAM_UINT8(PH_LOG_LOGTYPE_DEBUG, PH_LOG_VAR(bDAMMAC_Len), &bDAMMAC_Len);
    PH_LOG_HELPER_EXECUTE(PH_LOG_OPTION_CATEGORY_ENTER);

    /* Component Code Validation */
    if(PH_GET_COMPCODE(pDataParams) != PH_COMP_AL_MFDUOX)
    {
        PH_LOG_HELPER_ADDSTRING(PH_LOG_LOGTYPE_INFO, bFunctionName);
        PH_LOG_HELPER_ADDPARAM_UINT16(PH_LOG_LOGTYPE_INFO, PH_LOG_VAR(wStatus), &wStatus);
        PH_LOG_HELPER_EXECUTE(PH_LOG_OPTION_CATEGORY_LEAVE);

        return PH_ADD_COMPCODE(PH_ERR_INVALID_DATA_PARAMS, PH_COMP_AL_MFDUOX);
    }

    /* Perform operation on active layer */
    switch(PH_GET_COMPID(pDataParams))
    {
#ifdef NXPBUILD__PHAL_MFDUOX_SW
        case PHAL_MFDUOX_SW_ID:
            wStatus = phalMfDuoX_Sw_DeleteApplication((phalMfDuoX_Sw_DataParams_t *) pDataParams, pAid, pDAMMAC, bDAMMAC_Len);
            break;
#endif /* NXPBUILD__PHAL_MFDUOX_SW */

        default:
            wStatus = PH_ADD_COMPCODE(PH_ERR_INVALID_DATA_PARAMS, PH_COMP_AL_MFDUOX);
            break;
    }

    PH_LOG_HELPER_ADDSTRING(PH_LOG_LOGTYPE_INFO, bFunctionName);
    PH_LOG_HELPER_ADDPARAM_UINT16(PH_LOG_LOGTYPE_INFO, PH_LOG_VAR(wStatus), &wStatus);
    PH_LOG_HELPER_EXECUTE(PH_LOG_OPTION_CATEGORY_LEAVE);

    return wStatus;
}

phStatus_t phalMfDuoX_SelectApplication(void * pDataParams, uint8_t bOption, uint8_t * pAid1, uint8_t * pAid2)
{
    phStatus_t PH_MEMLOC_REM wStatus;

    PH_LOG_HELPER_ALLOCATE_TEXT(bFunctionName, "phalMfDuoX_SelectApplication");
    PH_LOG_HELPER_ALLOCATE_PARAMNAME(bOption);
    PH_LOG_HELPER_ALLOCATE_PARAMNAME(pAid1);
    PH_LOG_HELPER_ALLOCATE_PARAMNAME(pAid2);
    PH_LOG_HELPER_ALLOCATE_PARAMNAME(wStatus);

    /* Validate the parameters */
    PH_ASSERT_NULL_DATA_PARAM(pDataParams, PH_COMP_AL_MFDUOX);
    PH_ASSERT_NULL_PARAM(pAid1, PH_COMP_AL_MFDUOX);
    if(bOption) PH_ASSERT_NULL_PARAM(pAid2, PH_COMP_AL_MFDUOX);

    /* Log the information. */
    PH_LOG_HELPER_ADDSTRING(PH_LOG_LOGTYPE_INFO, bFunctionName);
    PH_LOG_HELPER_ADDPARAM_UINT8(PH_LOG_LOGTYPE_DEBUG, PH_LOG_VAR(bOption), &bOption);
    PH_LOG_HELPER_ADDPARAM_BUFFER(PH_LOG_LOGTYPE_DEBUG, PH_LOG_VAR(pAid1), pAid1, PHAL_MFDUOX_APP_ID_LEN);
    if(bOption)
        PH_LOG_HELPER_ADDPARAM_BUFFER(PH_LOG_LOGTYPE_DEBUG, PH_LOG_VAR(pAid2), pAid2, PHAL_MFDUOX_APP_ID_LEN);
    PH_LOG_HELPER_EXECUTE(PH_LOG_OPTION_CATEGORY_ENTER);

    /* Component Code Validation */
    if(PH_GET_COMPCODE(pDataParams) != PH_COMP_AL_MFDUOX)
    {
        PH_LOG_HELPER_ADDSTRING(PH_LOG_LOGTYPE_INFO, bFunctionName);
        PH_LOG_HELPER_ADDPARAM_UINT16(PH_LOG_LOGTYPE_INFO, PH_LOG_VAR(wStatus), &wStatus);
        PH_LOG_HELPER_EXECUTE(PH_LOG_OPTION_CATEGORY_LEAVE);

        return PH_ADD_COMPCODE(PH_ERR_INVALID_DATA_PARAMS, PH_COMP_AL_MFDUOX);
    }

    /* Perform operation on active layer */
    switch(PH_GET_COMPID(pDataParams))
    {
#ifdef NXPBUILD__PHAL_MFDUOX_SW
        case PHAL_MFDUOX_SW_ID:
            wStatus = phalMfDuoX_Sw_SelectApplication((phalMfDuoX_Sw_DataParams_t *) pDataParams, bOption, pAid1, pAid2);
            break;
#endif /* NXPBUILD__PHAL_MFDUOX_SW */

        default:
            wStatus = PH_ADD_COMPCODE(PH_ERR_INVALID_DATA_PARAMS, PH_COMP_AL_MFDUOX);
            break;
    }

    PH_LOG_HELPER_ADDSTRING(PH_LOG_LOGTYPE_INFO, bFunctionName);
    PH_LOG_HELPER_ADDPARAM_UINT16(PH_LOG_LOGTYPE_INFO, PH_LOG_VAR(wStatus), &wStatus);
    PH_LOG_HELPER_EXECUTE(PH_LOG_OPTION_CATEGORY_LEAVE);

    return wStatus;
}

phStatus_t phalMfDuoX_GetApplicationIDs(void * pDataParams, uint8_t bOption, uint8_t ** ppAidBuff, uint16_t * pAidLen)
{
    phStatus_t PH_MEMLOC_REM wStatus;

    PH_LOG_HELPER_ALLOCATE_TEXT(bFunctionName, "phalMfDuoX_GetApplicationIDs");
    PH_LOG_HELPER_ALLOCATE_PARAMNAME(wStatus);
    PH_LOG_HELPER_ALLOCATE_PARAMNAME(bOption);
    PH_LOG_HELPER_ALLOCATE_PARAMNAME(ppAidBuff);
    PH_LOG_HELPER_ALLOCATE_PARAMNAME(pAidLen);

    /* Validate the parameters */
    PH_ASSERT_NULL_DATA_PARAM(pDataParams, PH_COMP_AL_MFDUOX);
    PH_ASSERT_NULL_PARAM(pAidLen, PH_COMP_AL_MFDUOX);

    /* Log the information. */
    PH_LOG_HELPER_ADDSTRING(PH_LOG_LOGTYPE_INFO, bFunctionName);
    PH_LOG_HELPER_ADDPARAM_UINT8(PH_LOG_LOGTYPE_DEBUG, PH_LOG_VAR(bOption), &bOption);
    PH_LOG_HELPER_EXECUTE(PH_LOG_OPTION_CATEGORY_ENTER);

    /* Component Code Validation */
    if(PH_GET_COMPCODE(pDataParams) != PH_COMP_AL_MFDUOX)
    {
        PH_LOG_HELPER_ADDSTRING(PH_LOG_LOGTYPE_INFO, bFunctionName);
        PH_LOG_HELPER_ADDPARAM_UINT16(PH_LOG_LOGTYPE_INFO, PH_LOG_VAR(wStatus), &wStatus);
        PH_LOG_HELPER_EXECUTE(PH_LOG_OPTION_CATEGORY_LEAVE);

        return PH_ADD_COMPCODE(PH_ERR_INVALID_DATA_PARAMS, PH_COMP_AL_MFDUOX);
    }

    /* Perform operation on active layer */
    switch(PH_GET_COMPID(pDataParams))
    {
#ifdef NXPBUILD__PHAL_MFDUOX_SW
        case PHAL_MFDUOX_SW_ID:
            wStatus = phalMfDuoX_Sw_GetApplicationIDs((phalMfDuoX_Sw_DataParams_t *) pDataParams, bOption, ppAidBuff, pAidLen);
            break;
#endif /* NXPBUILD__PHAL_MFDUOX_SW */

        default:
            wStatus = PH_ADD_COMPCODE(PH_ERR_INVALID_DATA_PARAMS, PH_COMP_AL_MFDUOX);
            break;
    }

    PH_LOG_HELPER_ADDSTRING(PH_LOG_LOGTYPE_INFO, bFunctionName);
#ifdef NXPBUILD__PH_LOG
    if(((wStatus & PH_ERR_MASK) == PH_ERR_SUCCESS) || ((wStatus & PH_ERR_MASK) == PH_ERR_SUCCESS_CHAINING))
    {
        PH_LOG_HELPER_ADDPARAM_BUFFER(PH_LOG_LOGTYPE_DEBUG, PH_LOG_VAR(ppAidBuff), *ppAidBuff, *pAidLen);
        PH_LOG_HELPER_ADDPARAM_UINT16(PH_LOG_LOGTYPE_DEBUG, PH_LOG_VAR(pAidLen), pAidLen);
    }
#endif /* NXPBUILD__PH_LOG */
    PH_LOG_HELPER_ADDPARAM_UINT16(PH_LOG_LOGTYPE_INFO, PH_LOG_VAR(wStatus), &wStatus);
    PH_LOG_HELPER_EXECUTE(PH_LOG_OPTION_CATEGORY_LEAVE);

    return wStatus;
}

phStatus_t phalMfDuoX_GetDFNames(void * pDataParams, uint8_t bOption, uint8_t ** ppDFBuffer, uint16_t * pDFInfoLen)
{
    phStatus_t PH_MEMLOC_REM wStatus;

    PH_LOG_HELPER_ALLOCATE_TEXT(bFunctionName, "phalMfDuoX_GetDFNames");
    PH_LOG_HELPER_ALLOCATE_PARAMNAME(wStatus);
    PH_LOG_HELPER_ALLOCATE_PARAMNAME(bOption);
    PH_LOG_HELPER_ALLOCATE_PARAMNAME(ppDFBuffer);
    PH_LOG_HELPER_ALLOCATE_PARAMNAME(pDFInfoLen);

    /* Validate the parameters */
    PH_ASSERT_NULL_DATA_PARAM(pDataParams, PH_COMP_AL_MFDUOX);
    PH_ASSERT_NULL_PARAM(pDFInfoLen, PH_COMP_AL_MFDUOX);

    /* Log the information. */
    PH_LOG_HELPER_ADDSTRING(PH_LOG_LOGTYPE_INFO, bFunctionName);
    PH_LOG_HELPER_ADDPARAM_UINT8(PH_LOG_LOGTYPE_DEBUG, PH_LOG_VAR(bOption), &bOption);
    PH_LOG_HELPER_EXECUTE(PH_LOG_OPTION_CATEGORY_ENTER);

    /* Component Code Validation */
    if(PH_GET_COMPCODE(pDataParams) != PH_COMP_AL_MFDUOX)
    {
        PH_LOG_HELPER_ADDSTRING(PH_LOG_LOGTYPE_INFO, bFunctionName);
        PH_LOG_HELPER_ADDPARAM_UINT16(PH_LOG_LOGTYPE_INFO, PH_LOG_VAR(wStatus), &wStatus);
        PH_LOG_HELPER_EXECUTE(PH_LOG_OPTION_CATEGORY_LEAVE);

        return PH_ADD_COMPCODE(PH_ERR_INVALID_DATA_PARAMS, PH_COMP_AL_MFDUOX);
    }

    /* Perform operation on active layer */
    switch(PH_GET_COMPID(pDataParams))
    {
#ifdef NXPBUILD__PHAL_MFDUOX_SW
        case PHAL_MFDUOX_SW_ID:
            wStatus = phalMfDuoX_Sw_GetDFNames((phalMfDuoX_Sw_DataParams_t *) pDataParams, bOption, ppDFBuffer, pDFInfoLen);
            break;
#endif /* NXPBUILD__PHAL_MFDUOX_SW */

        default:
            wStatus = PH_ADD_COMPCODE(PH_ERR_INVALID_DATA_PARAMS, PH_COMP_AL_MFDUOX);
            break;
    }

    PH_LOG_HELPER_ADDSTRING(PH_LOG_LOGTYPE_INFO, bFunctionName);
#ifdef NXPBUILD__PH_LOG
    if(((wStatus & PH_ERR_MASK) == PH_ERR_SUCCESS) || ((wStatus & PH_ERR_MASK) == PH_ERR_SUCCESS_CHAINING))
    {
        PH_LOG_HELPER_ADDPARAM_BUFFER(PH_LOG_LOGTYPE_DEBUG, PH_LOG_VAR(ppDFBuffer), *ppDFBuffer, *pDFInfoLen);
        PH_LOG_HELPER_ADDPARAM_UINT16(PH_LOG_LOGTYPE_DEBUG, PH_LOG_VAR(pDFInfoLen), pDFInfoLen);
    }
#endif /* NXPBUILD__PH_LOG */
    PH_LOG_HELPER_ADDPARAM_UINT16(PH_LOG_LOGTYPE_INFO, PH_LOG_VAR(wStatus), &wStatus);
    PH_LOG_HELPER_EXECUTE(PH_LOG_OPTION_CATEGORY_LEAVE);

    return wStatus;
}

/* MIFARE DUOX File management commands ------------------------------------------------------------------------------------------------ */
phStatus_t phalMfDuoX_CreateStdDataFile(void * pDataParams, uint8_t bOption, uint8_t bFileNo, uint8_t * pISOFileId,
    uint8_t bFileOption, uint8_t * pAccessRights, uint8_t * pFileSize)
{
    phStatus_t PH_MEMLOC_REM wStatus;

    PH_LOG_HELPER_ALLOCATE_TEXT(bFunctionName, "phalMfDuoX_CreateStdDataFile");
    PH_LOG_HELPER_ALLOCATE_PARAMNAME(wStatus);
    PH_LOG_HELPER_ALLOCATE_PARAMNAME(bOption);
    PH_LOG_HELPER_ALLOCATE_PARAMNAME(bFileNo);
    PH_LOG_HELPER_ALLOCATE_PARAMNAME(pISOFileId);
    PH_LOG_HELPER_ALLOCATE_PARAMNAME(bFileOption);
    PH_LOG_HELPER_ALLOCATE_PARAMNAME(pAccessRights);
    PH_LOG_HELPER_ALLOCATE_PARAMNAME(pFileSize);

    /* Validate the parameters */
    PH_ASSERT_NULL_DATA_PARAM(pDataParams, PH_COMP_AL_MFDUOX);
    if(bOption & PHAL_MFDUOX_ISO_FILE_ID_AVAILABLE) PH_ASSERT_NULL_PARAM(pISOFileId, PH_COMP_AL_MFDUOX);
    PH_ASSERT_NULL_PARAM(pAccessRights, PH_COMP_AL_MFDUOX);
    PH_ASSERT_NULL_PARAM(pFileSize, PH_COMP_AL_MFDUOX);

    /* Log the information. */
    PH_LOG_HELPER_ADDSTRING(PH_LOG_LOGTYPE_INFO, bFunctionName);
    PH_LOG_HELPER_ADDPARAM_UINT8(PH_LOG_LOGTYPE_DEBUG, PH_LOG_VAR(bOption), &bOption);
    PH_LOG_HELPER_ADDPARAM_UINT8(PH_LOG_LOGTYPE_DEBUG, PH_LOG_VAR(bFileNo), &bFileNo);
    PH_LOG_HELPER_ADDPARAM_BUFFER(PH_LOG_LOGTYPE_DEBUG, PH_LOG_VAR(pISOFileId), pISOFileId, 2);
    PH_LOG_HELPER_ADDPARAM_UINT8(PH_LOG_LOGTYPE_DEBUG, PH_LOG_VAR(bFileOption), &bFileOption);
    PH_LOG_HELPER_ADDPARAM_BUFFER(PH_LOG_LOGTYPE_DEBUG, PH_LOG_VAR(pAccessRights), pAccessRights, 2);
    PH_LOG_HELPER_ADDPARAM_BUFFER(PH_LOG_LOGTYPE_DEBUG, PH_LOG_VAR(pFileSize), pFileSize, 2);
    PH_LOG_HELPER_EXECUTE(PH_LOG_OPTION_CATEGORY_ENTER);

    /* Component Code Validation */
    if(PH_GET_COMPCODE(pDataParams) != PH_COMP_AL_MFDUOX)
    {
        PH_LOG_HELPER_ADDSTRING(PH_LOG_LOGTYPE_INFO, bFunctionName);
        PH_LOG_HELPER_ADDPARAM_UINT16(PH_LOG_LOGTYPE_INFO, PH_LOG_VAR(wStatus), &wStatus);
        PH_LOG_HELPER_EXECUTE(PH_LOG_OPTION_CATEGORY_LEAVE);

        return PH_ADD_COMPCODE(PH_ERR_INVALID_DATA_PARAMS, PH_COMP_AL_MFDUOX);
    }

    /* Perform operation on active layer */
    switch(PH_GET_COMPID(pDataParams))
    {
#ifdef NXPBUILD__PHAL_MFDUOX_SW
        case PHAL_MFDUOX_SW_ID:
            wStatus = phalMfDuoX_Sw_CreateStdDataFile((phalMfDuoX_Sw_DataParams_t *) pDataParams, bOption, bFileNo, pISOFileId,
                bFileOption, pAccessRights, pFileSize);
            break;
#endif /* NXPBUILD__PHAL_MFDUOX_SW */

        default:
            wStatus = PH_ADD_COMPCODE(PH_ERR_INVALID_DATA_PARAMS, PH_COMP_AL_MFDUOX);
            break;
    }

    PH_LOG_HELPER_ADDSTRING(PH_LOG_LOGTYPE_INFO, bFunctionName);
    PH_LOG_HELPER_ADDPARAM_UINT16(PH_LOG_LOGTYPE_INFO, PH_LOG_VAR(wStatus), &wStatus);
    PH_LOG_HELPER_EXECUTE(PH_LOG_OPTION_CATEGORY_LEAVE);

    return wStatus;
}

phStatus_t phalMfDuoX_CreateBackupDataFile(void * pDataParams, uint8_t bOption, uint8_t bFileNo, uint8_t * pISOFileId,
    uint8_t bFileOption, uint8_t * pAccessRights, uint8_t * pFileSize)
{
    phStatus_t PH_MEMLOC_REM wStatus;

    PH_LOG_HELPER_ALLOCATE_TEXT(bFunctionName, "phalMfDuoX_CreateBackupDataFile");
    PH_LOG_HELPER_ALLOCATE_PARAMNAME(wStatus);
    PH_LOG_HELPER_ALLOCATE_PARAMNAME(bOption);
    PH_LOG_HELPER_ALLOCATE_PARAMNAME(bFileNo);
    PH_LOG_HELPER_ALLOCATE_PARAMNAME(pISOFileId);
    PH_LOG_HELPER_ALLOCATE_PARAMNAME(bFileOption);
    PH_LOG_HELPER_ALLOCATE_PARAMNAME(pAccessRights);
    PH_LOG_HELPER_ALLOCATE_PARAMNAME(pFileSize);

    /* Validate the parameters */
    PH_ASSERT_NULL_DATA_PARAM(pDataParams, PH_COMP_AL_MFDUOX);
    if(bOption & PHAL_MFDUOX_ISO_FILE_ID_AVAILABLE) PH_ASSERT_NULL_PARAM(pISOFileId, PH_COMP_AL_MFDUOX);
    PH_ASSERT_NULL_PARAM(pAccessRights, PH_COMP_AL_MFDUOX);
    PH_ASSERT_NULL_PARAM(pFileSize, PH_COMP_AL_MFDUOX);

    /* Log the information. */
    PH_LOG_HELPER_ADDSTRING(PH_LOG_LOGTYPE_INFO, bFunctionName);
    PH_LOG_HELPER_ADDPARAM_UINT8(PH_LOG_LOGTYPE_DEBUG, PH_LOG_VAR(bOption), &bOption);
    PH_LOG_HELPER_ADDPARAM_UINT8(PH_LOG_LOGTYPE_DEBUG, PH_LOG_VAR(bFileNo), &bFileNo);
    PH_LOG_HELPER_ADDPARAM_BUFFER(PH_LOG_LOGTYPE_DEBUG, PH_LOG_VAR(pISOFileId), pISOFileId, 2);
    PH_LOG_HELPER_ADDPARAM_UINT8(PH_LOG_LOGTYPE_DEBUG, PH_LOG_VAR(bFileOption), &bFileOption);
    PH_LOG_HELPER_ADDPARAM_BUFFER(PH_LOG_LOGTYPE_DEBUG, PH_LOG_VAR(pAccessRights), pAccessRights, 2);
    PH_LOG_HELPER_ADDPARAM_BUFFER(PH_LOG_LOGTYPE_DEBUG, PH_LOG_VAR(pFileSize), pFileSize, 2);
    PH_LOG_HELPER_EXECUTE(PH_LOG_OPTION_CATEGORY_ENTER);

    /* Component Code Validation */
    if(PH_GET_COMPCODE(pDataParams) != PH_COMP_AL_MFDUOX)
    {
        PH_LOG_HELPER_ADDSTRING(PH_LOG_LOGTYPE_INFO, bFunctionName);
        PH_LOG_HELPER_ADDPARAM_UINT16(PH_LOG_LOGTYPE_INFO, PH_LOG_VAR(wStatus), &wStatus);
        PH_LOG_HELPER_EXECUTE(PH_LOG_OPTION_CATEGORY_LEAVE);

        return PH_ADD_COMPCODE(PH_ERR_INVALID_DATA_PARAMS, PH_COMP_AL_MFDUOX);
    }

    /* Perform operation on active layer */
    switch(PH_GET_COMPID(pDataParams))
    {
#ifdef NXPBUILD__PHAL_MFDUOX_SW
        case PHAL_MFDUOX_SW_ID:
            wStatus = phalMfDuoX_Sw_CreateBackupDataFile((phalMfDuoX_Sw_DataParams_t *) pDataParams, bOption, bFileNo, pISOFileId,
                bFileOption, pAccessRights, pFileSize);
            break;
#endif /* NXPBUILD__PHAL_MFDUOX_SW */

        default:
            wStatus = PH_ADD_COMPCODE(PH_ERR_INVALID_DATA_PARAMS, PH_COMP_AL_MFDUOX);
            break;
    }

    PH_LOG_HELPER_ADDSTRING(PH_LOG_LOGTYPE_INFO, bFunctionName);
    PH_LOG_HELPER_ADDPARAM_UINT16(PH_LOG_LOGTYPE_INFO, PH_LOG_VAR(wStatus), &wStatus);
    PH_LOG_HELPER_EXECUTE(PH_LOG_OPTION_CATEGORY_LEAVE);

    return wStatus;
}

phStatus_t phalMfDuoX_CreateValueFile(void * pDataParams, uint8_t bFileNo, uint8_t bFileOption, uint8_t * pAccessRights,
    uint8_t * pLowerLmit, uint8_t * pUpperLmit, uint8_t * pValue, uint8_t bLimitedCredit)
{
    phStatus_t PH_MEMLOC_REM wStatus;

    PH_LOG_HELPER_ALLOCATE_TEXT(bFunctionName, "phalMfDuoX_CreateValueFile");
    PH_LOG_HELPER_ALLOCATE_PARAMNAME(wStatus);
    PH_LOG_HELPER_ALLOCATE_PARAMNAME(bFileNo);
    PH_LOG_HELPER_ALLOCATE_PARAMNAME(bFileOption);
    PH_LOG_HELPER_ALLOCATE_PARAMNAME(pAccessRights);
    PH_LOG_HELPER_ALLOCATE_PARAMNAME(pLowerLmit);
    PH_LOG_HELPER_ALLOCATE_PARAMNAME(pUpperLmit);
    PH_LOG_HELPER_ALLOCATE_PARAMNAME(pValue);
    PH_LOG_HELPER_ALLOCATE_PARAMNAME(bLimitedCredit);

    /* Validate the parameters */
    PH_ASSERT_NULL_DATA_PARAM(pDataParams, PH_COMP_AL_MFDUOX);
    PH_ASSERT_NULL_PARAM(pAccessRights, PH_COMP_AL_MFDUOX);
    PH_ASSERT_NULL_PARAM(pLowerLmit, PH_COMP_AL_MFDUOX);
    PH_ASSERT_NULL_PARAM(pUpperLmit, PH_COMP_AL_MFDUOX);
    PH_ASSERT_NULL_PARAM(pValue, PH_COMP_AL_MFDUOX);

    /* Log the information. */
    PH_LOG_HELPER_ADDSTRING(PH_LOG_LOGTYPE_INFO, bFunctionName);
    PH_LOG_HELPER_ADDPARAM_UINT8(PH_LOG_LOGTYPE_DEBUG, PH_LOG_VAR(bFileNo), &bFileNo);
    PH_LOG_HELPER_ADDPARAM_UINT8(PH_LOG_LOGTYPE_DEBUG, PH_LOG_VAR(bFileOption), &bFileOption);
    PH_LOG_HELPER_ADDPARAM_BUFFER(PH_LOG_LOGTYPE_DEBUG, PH_LOG_VAR(pAccessRights), pAccessRights, 2);
    PH_LOG_HELPER_ADDPARAM_BUFFER(PH_LOG_LOGTYPE_DEBUG, PH_LOG_VAR(pLowerLmit), pLowerLmit, 4);
    PH_LOG_HELPER_ADDPARAM_BUFFER(PH_LOG_LOGTYPE_DEBUG, PH_LOG_VAR(pUpperLmit), pUpperLmit, 4);
    PH_LOG_HELPER_ADDPARAM_BUFFER(PH_LOG_LOGTYPE_DEBUG, PH_LOG_VAR(pValue), pValue, 4);
    PH_LOG_HELPER_ADDPARAM_UINT8(PH_LOG_LOGTYPE_DEBUG, PH_LOG_VAR(bLimitedCredit), &bLimitedCredit);
    PH_LOG_HELPER_EXECUTE(PH_LOG_OPTION_CATEGORY_ENTER);

    /* Component Code Validation */
    if(PH_GET_COMPCODE(pDataParams) != PH_COMP_AL_MFDUOX)
    {
        PH_LOG_HELPER_ADDSTRING(PH_LOG_LOGTYPE_INFO, bFunctionName);
        PH_LOG_HELPER_ADDPARAM_UINT16(PH_LOG_LOGTYPE_INFO, PH_LOG_VAR(wStatus), &wStatus);
        PH_LOG_HELPER_EXECUTE(PH_LOG_OPTION_CATEGORY_LEAVE);

        return PH_ADD_COMPCODE(PH_ERR_INVALID_DATA_PARAMS, PH_COMP_AL_MFDUOX);
    }

    /* Perform operation on active layer */
    switch(PH_GET_COMPID(pDataParams))
    {
#ifdef NXPBUILD__PHAL_MFDUOX_SW
        case PHAL_MFDUOX_SW_ID:
            wStatus = phalMfDuoX_Sw_CreateValueFile((phalMfDuoX_Sw_DataParams_t *) pDataParams, bFileNo, bFileOption, pAccessRights,
                pLowerLmit, pUpperLmit, pValue, bLimitedCredit);
            break;
#endif /* NXPBUILD__PHAL_MFDUOX_SW */

        default:
            wStatus = PH_ADD_COMPCODE(PH_ERR_INVALID_DATA_PARAMS, PH_COMP_AL_MFDUOX);
            break;
    }

    PH_LOG_HELPER_ADDSTRING(PH_LOG_LOGTYPE_INFO, bFunctionName);
    PH_LOG_HELPER_ADDPARAM_UINT16(PH_LOG_LOGTYPE_INFO, PH_LOG_VAR(wStatus), &wStatus);
    PH_LOG_HELPER_EXECUTE(PH_LOG_OPTION_CATEGORY_LEAVE);

    return wStatus;
}

phStatus_t phalMfDuoX_CreateLinearRecordFile(void * pDataParams, uint8_t bOption, uint8_t bFileNo, uint8_t * pISOFileId,
    uint8_t bFileOption, uint8_t * pAccessRights, uint8_t * pRecordSize, uint8_t * pMaxNoOfRec)
{
    phStatus_t PH_MEMLOC_REM wStatus;

    PH_LOG_HELPER_ALLOCATE_TEXT(bFunctionName, "phalMfDuoX_CreateLinearRecordFile");
    PH_LOG_HELPER_ALLOCATE_PARAMNAME(wStatus);
    PH_LOG_HELPER_ALLOCATE_PARAMNAME(bOption);
    PH_LOG_HELPER_ALLOCATE_PARAMNAME(bFileNo);
    PH_LOG_HELPER_ALLOCATE_PARAMNAME(pISOFileId);
    PH_LOG_HELPER_ALLOCATE_PARAMNAME(bFileOption);
    PH_LOG_HELPER_ALLOCATE_PARAMNAME(pAccessRights);
    PH_LOG_HELPER_ALLOCATE_PARAMNAME(pRecordSize);
    PH_LOG_HELPER_ALLOCATE_PARAMNAME(pMaxNoOfRec);

    /* Validate the parameters */
    PH_ASSERT_NULL_DATA_PARAM(pDataParams, PH_COMP_AL_MFDUOX);
    if(bOption & PHAL_MFDUOX_ISO_FILE_ID_AVAILABLE) PH_ASSERT_NULL_PARAM(pISOFileId, PH_COMP_AL_MFDUOX);
    PH_ASSERT_NULL_PARAM(pAccessRights, PH_COMP_AL_MFDUOX);
    PH_ASSERT_NULL_PARAM(pRecordSize, PH_COMP_AL_MFDUOX);
    PH_ASSERT_NULL_PARAM(pMaxNoOfRec, PH_COMP_AL_MFDUOX);

    /* Log the information. */
    PH_LOG_HELPER_ADDSTRING(PH_LOG_LOGTYPE_INFO, bFunctionName);
    PH_LOG_HELPER_ADDPARAM_UINT8(PH_LOG_LOGTYPE_DEBUG, PH_LOG_VAR(bOption), &bOption);
    PH_LOG_HELPER_ADDPARAM_UINT8(PH_LOG_LOGTYPE_DEBUG, PH_LOG_VAR(bFileNo), &bFileNo);
    PH_LOG_HELPER_ADDPARAM_BUFFER(PH_LOG_LOGTYPE_DEBUG, PH_LOG_VAR(pISOFileId), pISOFileId, 2);
    PH_LOG_HELPER_ADDPARAM_UINT8(PH_LOG_LOGTYPE_DEBUG, PH_LOG_VAR(bFileOption), &bFileOption);
    PH_LOG_HELPER_ADDPARAM_BUFFER(PH_LOG_LOGTYPE_DEBUG, PH_LOG_VAR(pAccessRights), pAccessRights, 2);
    PH_LOG_HELPER_ADDPARAM_BUFFER(PH_LOG_LOGTYPE_DEBUG, PH_LOG_VAR(pRecordSize), pRecordSize, 3);
    PH_LOG_HELPER_ADDPARAM_BUFFER(PH_LOG_LOGTYPE_DEBUG, PH_LOG_VAR(pMaxNoOfRec), pMaxNoOfRec, 3);
    PH_LOG_HELPER_EXECUTE(PH_LOG_OPTION_CATEGORY_ENTER);

    /* Component Code Validation */
    if(PH_GET_COMPCODE(pDataParams) != PH_COMP_AL_MFDUOX)
    {
        PH_LOG_HELPER_ADDSTRING(PH_LOG_LOGTYPE_INFO, bFunctionName);
        PH_LOG_HELPER_ADDPARAM_UINT16(PH_LOG_LOGTYPE_INFO, PH_LOG_VAR(wStatus), &wStatus);
        PH_LOG_HELPER_EXECUTE(PH_LOG_OPTION_CATEGORY_LEAVE);

        return PH_ADD_COMPCODE(PH_ERR_INVALID_DATA_PARAMS, PH_COMP_AL_MFDUOX);
    }

    /* Perform operation on active layer */
    switch(PH_GET_COMPID(pDataParams))
    {
#ifdef NXPBUILD__PHAL_MFDUOX_SW
        case PHAL_MFDUOX_SW_ID:
            wStatus = phalMfDuoX_Sw_CreateLinearRecordFile((phalMfDuoX_Sw_DataParams_t *) pDataParams, bOption, bFileNo, pISOFileId,
                bFileOption, pAccessRights, pRecordSize, pMaxNoOfRec);
            break;
#endif /* NXPBUILD__PHAL_MFDUOX_SW */

        default:
            wStatus = PH_ADD_COMPCODE(PH_ERR_INVALID_DATA_PARAMS, PH_COMP_AL_MFDUOX);
            break;
    }

    PH_LOG_HELPER_ADDSTRING(PH_LOG_LOGTYPE_INFO, bFunctionName);
    PH_LOG_HELPER_ADDPARAM_UINT16(PH_LOG_LOGTYPE_INFO, PH_LOG_VAR(wStatus), &wStatus);
    PH_LOG_HELPER_EXECUTE(PH_LOG_OPTION_CATEGORY_LEAVE);

    return wStatus;
}

phStatus_t phalMfDuoX_CreateCyclicRecordFile(void * pDataParams, uint8_t bOption, uint8_t bFileNo, uint8_t * pISOFileId,
    uint8_t bFileOption, uint8_t * pAccessRights, uint8_t * pRecordSize, uint8_t * pMaxNoOfRec)
{
    phStatus_t PH_MEMLOC_REM wStatus;

    PH_LOG_HELPER_ALLOCATE_TEXT(bFunctionName, "phalMfDuoX_CreateCyclicRecordFile");
    PH_LOG_HELPER_ALLOCATE_PARAMNAME(wStatus);
    PH_LOG_HELPER_ALLOCATE_PARAMNAME(bOption);
    PH_LOG_HELPER_ALLOCATE_PARAMNAME(bFileNo);
    PH_LOG_HELPER_ALLOCATE_PARAMNAME(pISOFileId);
    PH_LOG_HELPER_ALLOCATE_PARAMNAME(bFileOption);
    PH_LOG_HELPER_ALLOCATE_PARAMNAME(pAccessRights);
    PH_LOG_HELPER_ALLOCATE_PARAMNAME(pRecordSize);
    PH_LOG_HELPER_ALLOCATE_PARAMNAME(pMaxNoOfRec);

    /* Validate the parameters */
    PH_ASSERT_NULL_DATA_PARAM(pDataParams, PH_COMP_AL_MFDUOX);
    if(bOption & PHAL_MFDUOX_ISO_FILE_ID_AVAILABLE) PH_ASSERT_NULL_PARAM(pISOFileId, PH_COMP_AL_MFDUOX);
    PH_ASSERT_NULL_PARAM(pAccessRights, PH_COMP_AL_MFDUOX);
    PH_ASSERT_NULL_PARAM(pRecordSize, PH_COMP_AL_MFDUOX);
    PH_ASSERT_NULL_PARAM(pMaxNoOfRec, PH_COMP_AL_MFDUOX);

    /* Log the information. */
    PH_LOG_HELPER_ADDSTRING(PH_LOG_LOGTYPE_INFO, bFunctionName);
    PH_LOG_HELPER_ADDPARAM_UINT8(PH_LOG_LOGTYPE_DEBUG, PH_LOG_VAR(bOption), &bOption);
    PH_LOG_HELPER_ADDPARAM_UINT8(PH_LOG_LOGTYPE_DEBUG, PH_LOG_VAR(bFileNo), &bFileNo);
    PH_LOG_HELPER_ADDPARAM_BUFFER(PH_LOG_LOGTYPE_DEBUG, PH_LOG_VAR(pISOFileId), pISOFileId, 2);
    PH_LOG_HELPER_ADDPARAM_UINT8(PH_LOG_LOGTYPE_DEBUG, PH_LOG_VAR(bFileOption), &bFileOption);
    PH_LOG_HELPER_ADDPARAM_BUFFER(PH_LOG_LOGTYPE_DEBUG, PH_LOG_VAR(pAccessRights), pAccessRights, 2);
    PH_LOG_HELPER_ADDPARAM_BUFFER(PH_LOG_LOGTYPE_DEBUG, PH_LOG_VAR(pRecordSize), pRecordSize, 3);
    PH_LOG_HELPER_ADDPARAM_BUFFER(PH_LOG_LOGTYPE_DEBUG, PH_LOG_VAR(pMaxNoOfRec), pMaxNoOfRec, 3);
    PH_LOG_HELPER_EXECUTE(PH_LOG_OPTION_CATEGORY_ENTER);

    /* Component Code Validation */
    if(PH_GET_COMPCODE(pDataParams) != PH_COMP_AL_MFDUOX)
    {
        PH_LOG_HELPER_ADDSTRING(PH_LOG_LOGTYPE_INFO, bFunctionName);
        PH_LOG_HELPER_ADDPARAM_UINT16(PH_LOG_LOGTYPE_INFO, PH_LOG_VAR(wStatus), &wStatus);
        PH_LOG_HELPER_EXECUTE(PH_LOG_OPTION_CATEGORY_LEAVE);

        return PH_ADD_COMPCODE(PH_ERR_INVALID_DATA_PARAMS, PH_COMP_AL_MFDUOX);
    }

    /* Perform operation on active layer */
    switch(PH_GET_COMPID(pDataParams))
    {
#ifdef NXPBUILD__PHAL_MFDUOX_SW
        case PHAL_MFDUOX_SW_ID:
            wStatus = phalMfDuoX_Sw_CreateCyclicRecordFile((phalMfDuoX_Sw_DataParams_t *) pDataParams, bOption, bFileNo, pISOFileId,
                bFileOption, pAccessRights, pRecordSize, pMaxNoOfRec);
            break;
#endif /* NXPBUILD__PHAL_MFDUOX_SW */

        default:
            wStatus = PH_ADD_COMPCODE(PH_ERR_INVALID_DATA_PARAMS, PH_COMP_AL_MFDUOX);
            break;
    }

    PH_LOG_HELPER_ADDSTRING(PH_LOG_LOGTYPE_INFO, bFunctionName);
    PH_LOG_HELPER_ADDPARAM_UINT16(PH_LOG_LOGTYPE_INFO, PH_LOG_VAR(wStatus), &wStatus);
    PH_LOG_HELPER_EXECUTE(PH_LOG_OPTION_CATEGORY_LEAVE);

    return wStatus;
}

phStatus_t phalMfDuoX_DeleteFile(void * pDataParams, uint8_t bFileNo)
{
    phStatus_t PH_MEMLOC_REM wStatus;

    PH_LOG_HELPER_ALLOCATE_TEXT(bFunctionName, "phalMfDuoX_DeleteFile");
    PH_LOG_HELPER_ALLOCATE_PARAMNAME(wStatus);
    PH_LOG_HELPER_ALLOCATE_PARAMNAME(bFileNo);

    /* Validate the parameters */
    PH_ASSERT_NULL_DATA_PARAM(pDataParams, PH_COMP_AL_MFDUOX);

    /* Log the information. */
    PH_LOG_HELPER_ADDSTRING(PH_LOG_LOGTYPE_INFO, bFunctionName);
    PH_LOG_HELPER_ADDPARAM_UINT8(PH_LOG_LOGTYPE_DEBUG, PH_LOG_VAR(bFileNo), &bFileNo);
    PH_LOG_HELPER_EXECUTE(PH_LOG_OPTION_CATEGORY_ENTER);

    /* Component Code Validation */
    if(PH_GET_COMPCODE(pDataParams) != PH_COMP_AL_MFDUOX)
    {
        PH_LOG_HELPER_ADDSTRING(PH_LOG_LOGTYPE_INFO, bFunctionName);
        PH_LOG_HELPER_ADDPARAM_UINT16(PH_LOG_LOGTYPE_INFO, PH_LOG_VAR(wStatus), &wStatus);
        PH_LOG_HELPER_EXECUTE(PH_LOG_OPTION_CATEGORY_LEAVE);

        return PH_ADD_COMPCODE(PH_ERR_INVALID_DATA_PARAMS, PH_COMP_AL_MFDUOX);
    }

    /* Perform operation on active layer */
    switch(PH_GET_COMPID(pDataParams))
    {
#ifdef NXPBUILD__PHAL_MFDUOX_SW
        case PHAL_MFDUOX_SW_ID:
            wStatus = phalMfDuoX_Sw_DeleteFile((phalMfDuoX_Sw_DataParams_t *) pDataParams, bFileNo);
            break;
#endif /* NXPBUILD__PHAL_MFDUOX_SW */

        default:
            wStatus = PH_ADD_COMPCODE(PH_ERR_INVALID_DATA_PARAMS, PH_COMP_AL_MFDUOX);
            break;
    }

    PH_LOG_HELPER_ADDSTRING(PH_LOG_LOGTYPE_INFO, bFunctionName);
    PH_LOG_HELPER_ADDPARAM_UINT16(PH_LOG_LOGTYPE_INFO, PH_LOG_VAR(wStatus), &wStatus);
    PH_LOG_HELPER_EXECUTE(PH_LOG_OPTION_CATEGORY_LEAVE);

    return wStatus;
}

phStatus_t phalMfDuoX_GetFileIDs(void * pDataParams, uint8_t ** ppFileId, uint16_t * pFileIdLen)
{
    phStatus_t PH_MEMLOC_REM wStatus;

    PH_LOG_HELPER_ALLOCATE_TEXT(bFunctionName, "phalMfDuoX_GetFileIDs");
    PH_LOG_HELPER_ALLOCATE_PARAMNAME(wStatus);
    PH_LOG_HELPER_ALLOCATE_PARAMNAME(ppFileId);
    PH_LOG_HELPER_ALLOCATE_PARAMNAME(pFileIdLen);

    /* Validate the parameters */
    PH_ASSERT_NULL_DATA_PARAM(pDataParams, PH_COMP_AL_MFDUOX);
    PH_ASSERT_NULL_PARAM(pFileIdLen, PH_COMP_AL_MFDUOX);

    /* Log the information. */
    PH_LOG_HELPER_ADDSTRING(PH_LOG_LOGTYPE_INFO, bFunctionName);
    PH_LOG_HELPER_EXECUTE(PH_LOG_OPTION_CATEGORY_ENTER);

    /* Component Code Validation */
    if(PH_GET_COMPCODE(pDataParams) != PH_COMP_AL_MFDUOX)
    {
        PH_LOG_HELPER_ADDSTRING(PH_LOG_LOGTYPE_INFO, bFunctionName);
        PH_LOG_HELPER_ADDPARAM_UINT16(PH_LOG_LOGTYPE_INFO, PH_LOG_VAR(wStatus), &wStatus);
        PH_LOG_HELPER_EXECUTE(PH_LOG_OPTION_CATEGORY_LEAVE);

        return PH_ADD_COMPCODE(PH_ERR_INVALID_DATA_PARAMS, PH_COMP_AL_MFDUOX);
    }

    /* Perform operation on active layer */
    switch(PH_GET_COMPID(pDataParams))
    {
#ifdef NXPBUILD__PHAL_MFDUOX_SW
        case PHAL_MFDUOX_SW_ID:
            wStatus = phalMfDuoX_Sw_GetFileIDs((phalMfDuoX_Sw_DataParams_t *) pDataParams, ppFileId, pFileIdLen);
            break;
#endif /* NXPBUILD__PHAL_MFDUOX_SW */

        default:
            wStatus = PH_ADD_COMPCODE(PH_ERR_INVALID_DATA_PARAMS, PH_COMP_AL_MFDUOX);
            break;
    }

    PH_LOG_HELPER_ADDSTRING(PH_LOG_LOGTYPE_INFO, bFunctionName);
#ifdef NXPBUILD__PH_LOG
    if((wStatus & PH_ERR_MASK) == PH_ERR_SUCCESS)
    {
        PH_LOG_HELPER_ADDPARAM_BUFFER(PH_LOG_LOGTYPE_DEBUG, PH_LOG_VAR(ppFileId), *ppFileId, *pFileIdLen);
        PH_LOG_HELPER_ADDPARAM_UINT16(PH_LOG_LOGTYPE_DEBUG, PH_LOG_VAR(pFileIdLen), pFileIdLen);
    }
#endif /* NXPBUILD__PH_LOG */
    PH_LOG_HELPER_ADDPARAM_UINT16(PH_LOG_LOGTYPE_INFO, PH_LOG_VAR(wStatus), &wStatus);
    PH_LOG_HELPER_EXECUTE(PH_LOG_OPTION_CATEGORY_LEAVE);

    return wStatus;
}

phStatus_t phalMfDuoX_GetISOFileIDs(void * pDataParams, uint8_t ** ppISOFileId, uint16_t * pISOFileIdLen)
{
    phStatus_t PH_MEMLOC_REM wStatus;

    PH_LOG_HELPER_ALLOCATE_TEXT(bFunctionName, "phalMfDuoX_GetISOFileIDs");
    PH_LOG_HELPER_ALLOCATE_PARAMNAME(wStatus);
    PH_LOG_HELPER_ALLOCATE_PARAMNAME(ppISOFileId);
    PH_LOG_HELPER_ALLOCATE_PARAMNAME(pISOFileIdLen);

    /* Validate the parameters */
    PH_ASSERT_NULL_DATA_PARAM(pDataParams, PH_COMP_AL_MFDUOX);
    PH_ASSERT_NULL_PARAM(pISOFileIdLen, PH_COMP_AL_MFDUOX);

    /* Log the information. */
    PH_LOG_HELPER_ADDSTRING(PH_LOG_LOGTYPE_INFO, bFunctionName);
    PH_LOG_HELPER_EXECUTE(PH_LOG_OPTION_CATEGORY_ENTER);

    /* Component Code Validation */
    if(PH_GET_COMPCODE(pDataParams) != PH_COMP_AL_MFDUOX)
    {
        PH_LOG_HELPER_ADDSTRING(PH_LOG_LOGTYPE_INFO, bFunctionName);
        PH_LOG_HELPER_ADDPARAM_UINT16(PH_LOG_LOGTYPE_INFO, PH_LOG_VAR(wStatus), &wStatus);
        PH_LOG_HELPER_EXECUTE(PH_LOG_OPTION_CATEGORY_LEAVE);

        return PH_ADD_COMPCODE(PH_ERR_INVALID_DATA_PARAMS, PH_COMP_AL_MFDUOX);
    }

    /* Perform operation on active layer */
    switch(PH_GET_COMPID(pDataParams))
    {
#ifdef NXPBUILD__PHAL_MFDUOX_SW
        case PHAL_MFDUOX_SW_ID:
            wStatus = phalMfDuoX_Sw_GetISOFileIDs((phalMfDuoX_Sw_DataParams_t *) pDataParams, ppISOFileId, pISOFileIdLen);
            break;
#endif /* NXPBUILD__PHAL_MFDUOX_SW */

        default:
            wStatus = PH_ADD_COMPCODE(PH_ERR_INVALID_DATA_PARAMS, PH_COMP_AL_MFDUOX);
            break;
    }

    PH_LOG_HELPER_ADDSTRING(PH_LOG_LOGTYPE_INFO, bFunctionName);
#ifdef NXPBUILD__PH_LOG
    if((wStatus & PH_ERR_MASK) == PH_ERR_SUCCESS)
    {
        PH_LOG_HELPER_ADDPARAM_BUFFER(PH_LOG_LOGTYPE_DEBUG, PH_LOG_VAR(ppISOFileId), *ppISOFileId, *pISOFileIdLen);
        PH_LOG_HELPER_ADDPARAM_UINT16(PH_LOG_LOGTYPE_DEBUG, PH_LOG_VAR(pISOFileIdLen), pISOFileIdLen);
    }
#endif /* NXPBUILD__PH_LOG */
    PH_LOG_HELPER_ADDPARAM_UINT16(PH_LOG_LOGTYPE_INFO, PH_LOG_VAR(wStatus), &wStatus);
    PH_LOG_HELPER_EXECUTE(PH_LOG_OPTION_CATEGORY_LEAVE);

    return wStatus;
}

phStatus_t phalMfDuoX_GetFileSettings(void * pDataParams, uint8_t bFileNo, uint8_t ** ppFSBuffer, uint16_t * pFSBufLen)
{
    phStatus_t PH_MEMLOC_REM wStatus;

    PH_LOG_HELPER_ALLOCATE_TEXT(bFunctionName, "phalMfDuoX_GetFileSettings");
    PH_LOG_HELPER_ALLOCATE_PARAMNAME(wStatus);
    PH_LOG_HELPER_ALLOCATE_PARAMNAME(bFileNo);
    PH_LOG_HELPER_ALLOCATE_PARAMNAME(ppFSBuffer);
    PH_LOG_HELPER_ALLOCATE_PARAMNAME(pFSBufLen);

    /* Validate the parameters */
    PH_ASSERT_NULL_DATA_PARAM(pDataParams, PH_COMP_AL_MFDUOX);
    PH_ASSERT_NULL_PARAM(pFSBufLen, PH_COMP_AL_MFDUOX);

    /* Log the information. */
    PH_LOG_HELPER_ADDSTRING(PH_LOG_LOGTYPE_INFO, bFunctionName);
    PH_LOG_HELPER_ADDPARAM_UINT8(PH_LOG_LOGTYPE_DEBUG, PH_LOG_VAR(bFileNo), &bFileNo);
    PH_LOG_HELPER_EXECUTE(PH_LOG_OPTION_CATEGORY_ENTER);

    /* Component Code Validation */
    if(PH_GET_COMPCODE(pDataParams) != PH_COMP_AL_MFDUOX)
    {
        PH_LOG_HELPER_ADDSTRING(PH_LOG_LOGTYPE_INFO, bFunctionName);
        PH_LOG_HELPER_ADDPARAM_UINT16(PH_LOG_LOGTYPE_INFO, PH_LOG_VAR(wStatus), &wStatus);
        PH_LOG_HELPER_EXECUTE(PH_LOG_OPTION_CATEGORY_LEAVE);

        return PH_ADD_COMPCODE(PH_ERR_INVALID_DATA_PARAMS, PH_COMP_AL_MFDUOX);
    }

    /* Perform operation on active layer */
    switch(PH_GET_COMPID(pDataParams))
    {
#ifdef NXPBUILD__PHAL_MFDUOX_SW
        case PHAL_MFDUOX_SW_ID:
            wStatus = phalMfDuoX_Sw_GetFileSettings((phalMfDuoX_Sw_DataParams_t *) pDataParams, bFileNo,ppFSBuffer, pFSBufLen);
            break;
#endif /* NXPBUILD__PHAL_MFDUOX_SW */

        default:
            wStatus = PH_ADD_COMPCODE(PH_ERR_INVALID_DATA_PARAMS, PH_COMP_AL_MFDUOX);
            break;
    }

    PH_LOG_HELPER_ADDSTRING(PH_LOG_LOGTYPE_INFO, bFunctionName);
#ifdef NXPBUILD__PH_LOG
    if((wStatus & PH_ERR_MASK) == PH_ERR_SUCCESS)
    {
        PH_LOG_HELPER_ADDPARAM_BUFFER(PH_LOG_LOGTYPE_DEBUG, PH_LOG_VAR(ppFSBuffer), *ppFSBuffer, *pFSBufLen);
        PH_LOG_HELPER_ADDPARAM_UINT16(PH_LOG_LOGTYPE_DEBUG, PH_LOG_VAR(pFSBufLen), pFSBufLen);
    }
#endif /* NXPBUILD__PH_LOG */
    PH_LOG_HELPER_ADDPARAM_UINT16(PH_LOG_LOGTYPE_INFO, PH_LOG_VAR(wStatus), &wStatus);
    PH_LOG_HELPER_EXECUTE(PH_LOG_OPTION_CATEGORY_LEAVE);

    return wStatus;
}

phStatus_t phalMfDuoX_GetFileCounters(void * pDataParams, uint8_t bOption, uint8_t bFileNo, uint8_t ** ppFileCounters,
    uint16_t * pFileCounterLen)
{
    phStatus_t PH_MEMLOC_REM wStatus;

    PH_LOG_HELPER_ALLOCATE_TEXT(bFunctionName, "phalMfDuoX_GetFileCounters");
    PH_LOG_HELPER_ALLOCATE_PARAMNAME(wStatus);
    PH_LOG_HELPER_ALLOCATE_PARAMNAME(bOption);
    PH_LOG_HELPER_ALLOCATE_PARAMNAME(bFileNo);
    PH_LOG_HELPER_ALLOCATE_PARAMNAME(ppFileCounters);
    PH_LOG_HELPER_ALLOCATE_PARAMNAME(pFileCounterLen);

    /* Validate the parameters */
    PH_ASSERT_NULL_DATA_PARAM(pDataParams, PH_COMP_AL_MFDUOX);
    PH_ASSERT_NULL_PARAM(pFileCounterLen, PH_COMP_AL_MFDUOX);

    /* Log the information. */
    PH_LOG_HELPER_ADDSTRING(PH_LOG_LOGTYPE_INFO, bFunctionName);
    PH_LOG_HELPER_ADDPARAM_UINT8(PH_LOG_LOGTYPE_DEBUG, PH_LOG_VAR(bOption), &bOption);
    PH_LOG_HELPER_ADDPARAM_UINT8(PH_LOG_LOGTYPE_DEBUG, PH_LOG_VAR(bFileNo), &bFileNo);
    PH_LOG_HELPER_EXECUTE(PH_LOG_OPTION_CATEGORY_ENTER);

    /* Component Code Validation */
    if(PH_GET_COMPCODE(pDataParams) != PH_COMP_AL_MFDUOX)
    {
        PH_LOG_HELPER_ADDSTRING(PH_LOG_LOGTYPE_INFO, bFunctionName);
        PH_LOG_HELPER_ADDPARAM_UINT16(PH_LOG_LOGTYPE_INFO, PH_LOG_VAR(wStatus), &wStatus);
        PH_LOG_HELPER_EXECUTE(PH_LOG_OPTION_CATEGORY_LEAVE);

        return PH_ADD_COMPCODE(PH_ERR_INVALID_DATA_PARAMS, PH_COMP_AL_MFDUOX);
    }

    /* Perform operation on active layer */
    switch(PH_GET_COMPID(pDataParams))
    {
#ifdef NXPBUILD__PHAL_MFDUOX_SW
        case PHAL_MFDUOX_SW_ID:
            wStatus = phalMfDuoX_Sw_GetFileCounters((phalMfDuoX_Sw_DataParams_t *) pDataParams, bOption, bFileNo, ppFileCounters, pFileCounterLen);
            break;
#endif /* NXPBUILD__PHAL_MFDUOX_SW */

        default:
            wStatus = PH_ADD_COMPCODE(PH_ERR_INVALID_DATA_PARAMS, PH_COMP_AL_MFDUOX);
            break;
    }

    PH_LOG_HELPER_ADDSTRING(PH_LOG_LOGTYPE_INFO, bFunctionName);
#ifdef NXPBUILD__PH_LOG
    if((wStatus & PH_ERR_MASK) == PH_ERR_SUCCESS)
    {
        PH_LOG_HELPER_ADDPARAM_BUFFER(PH_LOG_LOGTYPE_DEBUG, PH_LOG_VAR(ppFileCounters), *ppFileCounters, *pFileCounterLen);
        PH_LOG_HELPER_ADDPARAM_UINT16(PH_LOG_LOGTYPE_DEBUG, PH_LOG_VAR(pFileCounterLen), pFileCounterLen);
    }
#endif /* NXPBUILD__PH_LOG */
    PH_LOG_HELPER_ADDPARAM_UINT16(PH_LOG_LOGTYPE_INFO, PH_LOG_VAR(wStatus), &wStatus);
    PH_LOG_HELPER_EXECUTE(PH_LOG_OPTION_CATEGORY_LEAVE);

    return wStatus;
}

phStatus_t phalMfDuoX_ChangeFileSettings(void * pDataParams, uint8_t bOption, uint8_t bFileNo, uint8_t bFileOption,
    uint8_t * pAccessRights, uint8_t * pAddInfo, uint8_t bAddInfoLen)
{
    phStatus_t PH_MEMLOC_REM wStatus;

    PH_LOG_HELPER_ALLOCATE_TEXT(bFunctionName, "phalMfDuoX_ChangeFileSettings");
    PH_LOG_HELPER_ALLOCATE_PARAMNAME(wStatus);
    PH_LOG_HELPER_ALLOCATE_PARAMNAME(bOption);
    PH_LOG_HELPER_ALLOCATE_PARAMNAME(bFileNo);
    PH_LOG_HELPER_ALLOCATE_PARAMNAME(bFileOption);
    PH_LOG_HELPER_ALLOCATE_PARAMNAME(pAccessRights);
    PH_LOG_HELPER_ALLOCATE_PARAMNAME(pAddInfo);
    PH_LOG_HELPER_ALLOCATE_PARAMNAME(bAddInfoLen);

    /* Validate the parameters */
    PH_ASSERT_NULL_DATA_PARAM(pDataParams, PH_COMP_AL_MFDUOX);
    PH_ASSERT_NULL_PARAM(pAccessRights, PH_COMP_AL_MFDUOX);

    /* Log the information. */
    PH_LOG_HELPER_ADDSTRING(PH_LOG_LOGTYPE_INFO, bFunctionName);
    PH_LOG_HELPER_ADDPARAM_UINT8(PH_LOG_LOGTYPE_DEBUG, PH_LOG_VAR(bOption), &bOption);
    PH_LOG_HELPER_ADDPARAM_UINT8(PH_LOG_LOGTYPE_DEBUG, PH_LOG_VAR(bFileNo), &bFileNo);
    PH_LOG_HELPER_ADDPARAM_UINT8(PH_LOG_LOGTYPE_DEBUG, PH_LOG_VAR(bFileOption), &bFileOption);
    PH_LOG_HELPER_ADDPARAM_BUFFER(PH_LOG_LOGTYPE_DEBUG, PH_LOG_VAR(pAccessRights), pAccessRights, 2);
    PH_LOG_HELPER_ADDPARAM_BUFFER(PH_LOG_LOGTYPE_DEBUG, PH_LOG_VAR(pAddInfo), pAddInfo, bAddInfoLen);
    PH_LOG_HELPER_ADDPARAM_UINT8(PH_LOG_LOGTYPE_DEBUG, PH_LOG_VAR(bAddInfoLen), &bAddInfoLen);
    PH_LOG_HELPER_EXECUTE(PH_LOG_OPTION_CATEGORY_ENTER);

    /* Component Code Validation */
    if(PH_GET_COMPCODE(pDataParams) != PH_COMP_AL_MFDUOX)
    {
        PH_LOG_HELPER_ADDSTRING(PH_LOG_LOGTYPE_INFO, bFunctionName);
        PH_LOG_HELPER_ADDPARAM_UINT16(PH_LOG_LOGTYPE_INFO, PH_LOG_VAR(wStatus), &wStatus);
        PH_LOG_HELPER_EXECUTE(PH_LOG_OPTION_CATEGORY_LEAVE);

        return PH_ADD_COMPCODE(PH_ERR_INVALID_DATA_PARAMS, PH_COMP_AL_MFDUOX);
    }

    /* Perform operation on active layer */
    switch(PH_GET_COMPID(pDataParams))
    {
#ifdef NXPBUILD__PHAL_MFDUOX_SW
        case PHAL_MFDUOX_SW_ID:
            wStatus = phalMfDuoX_Sw_ChangeFileSettings((phalMfDuoX_Sw_DataParams_t *) pDataParams, bOption, bFileNo, bFileOption,
                pAccessRights, pAddInfo, bAddInfoLen);
            break;
#endif /* NXPBUILD__PHAL_MFDUOX_SW */

        default:
            wStatus = PH_ADD_COMPCODE(PH_ERR_INVALID_DATA_PARAMS, PH_COMP_AL_MFDUOX);
            break;
    }

    PH_LOG_HELPER_ADDSTRING(PH_LOG_LOGTYPE_INFO, bFunctionName);
    PH_LOG_HELPER_ADDPARAM_UINT16(PH_LOG_LOGTYPE_INFO, PH_LOG_VAR(wStatus), &wStatus);
    PH_LOG_HELPER_EXECUTE(PH_LOG_OPTION_CATEGORY_LEAVE);

    return wStatus;
}

/* MIFARE DUOX Data management commands ------------------------------------------------------------------------------------------------- */
phStatus_t phalMfDuoX_ReadData(void * pDataParams, uint8_t bOption, uint8_t bIns, uint8_t bFileNo, uint8_t * pOffset,
    uint8_t * pLength, uint8_t ** ppResponse, uint16_t * pRspLen)
{
    phStatus_t PH_MEMLOC_REM wStatus;

    PH_LOG_HELPER_ALLOCATE_TEXT(bFunctionName, "phalMfDuoX_ReadData");
    PH_LOG_HELPER_ALLOCATE_PARAMNAME(wStatus);
    PH_LOG_HELPER_ALLOCATE_PARAMNAME(bOption);
    PH_LOG_HELPER_ALLOCATE_PARAMNAME(bIns);
    PH_LOG_HELPER_ALLOCATE_PARAMNAME(bFileNo);
    PH_LOG_HELPER_ALLOCATE_PARAMNAME(pOffset);
    PH_LOG_HELPER_ALLOCATE_PARAMNAME(pLength);
    PH_LOG_HELPER_ALLOCATE_PARAMNAME(ppResponse);
    PH_LOG_HELPER_ALLOCATE_PARAMNAME(pRspLen);

    /* Validate the parameters */
    PH_ASSERT_NULL_DATA_PARAM(pDataParams, PH_COMP_AL_MFDUOX);
    PH_ASSERT_NULL_PARAM(pOffset, PH_COMP_AL_MFDUOX);
    PH_ASSERT_NULL_PARAM(pLength, PH_COMP_AL_MFDUOX);
    PH_ASSERT_NULL_PARAM(pRspLen, PH_COMP_AL_MFDUOX);

    /* Log the information. */
    PH_LOG_HELPER_ADDSTRING(PH_LOG_LOGTYPE_INFO, bFunctionName);
    PH_LOG_HELPER_ADDPARAM_UINT8(PH_LOG_LOGTYPE_DEBUG, PH_LOG_VAR(bOption), &bOption);
    PH_LOG_HELPER_ADDPARAM_UINT8(PH_LOG_LOGTYPE_DEBUG, PH_LOG_VAR(bIns), &bIns);
    PH_LOG_HELPER_ADDPARAM_UINT8(PH_LOG_LOGTYPE_DEBUG, PH_LOG_VAR(bFileNo), &bFileNo);
    PH_LOG_HELPER_ADDPARAM_BUFFER(PH_LOG_LOGTYPE_DEBUG, PH_LOG_VAR(pOffset), pOffset, 3);
    PH_LOG_HELPER_ADDPARAM_BUFFER(PH_LOG_LOGTYPE_DEBUG, PH_LOG_VAR(pLength), pLength, 3);
    PH_LOG_HELPER_EXECUTE(PH_LOG_OPTION_CATEGORY_ENTER);

    /* Component Code Validation */
    if(PH_GET_COMPCODE(pDataParams) != PH_COMP_AL_MFDUOX)
    {
        PH_LOG_HELPER_ADDSTRING(PH_LOG_LOGTYPE_INFO, bFunctionName);
        PH_LOG_HELPER_ADDPARAM_UINT16(PH_LOG_LOGTYPE_INFO, PH_LOG_VAR(wStatus), &wStatus);
        PH_LOG_HELPER_EXECUTE(PH_LOG_OPTION_CATEGORY_LEAVE);

        return PH_ADD_COMPCODE(PH_ERR_INVALID_DATA_PARAMS, PH_COMP_AL_MFDUOX);
    }

    /* Perform operation on active layer */
    switch(PH_GET_COMPID(pDataParams))
    {
#ifdef NXPBUILD__PHAL_MFDUOX_SW
        case PHAL_MFDUOX_SW_ID:
            wStatus = phalMfDuoX_Sw_ReadData((phalMfDuoX_Sw_DataParams_t *) pDataParams, bOption, bIns, bFileNo, pOffset, pLength,
                ppResponse, pRspLen);
            break;
#endif /* NXPBUILD__PHAL_MFDUOX_SW */

        default:
            wStatus = PH_ADD_COMPCODE(PH_ERR_INVALID_DATA_PARAMS, PH_COMP_AL_MFDUOX);
            break;
    }

    PH_LOG_HELPER_ADDSTRING(PH_LOG_LOGTYPE_INFO, bFunctionName);
#ifdef NXPBUILD__PH_LOG
    if(((wStatus & PH_ERR_MASK) == PH_ERR_SUCCESS) || ((wStatus & PH_ERR_MASK) == PH_ERR_SUCCESS_CHAINING))
    {
        PH_LOG_HELPER_ADDPARAM_BUFFER(PH_LOG_LOGTYPE_DEBUG, PH_LOG_VAR(ppResponse), *ppResponse, *pRspLen);
        PH_LOG_HELPER_ADDPARAM_UINT16(PH_LOG_LOGTYPE_DEBUG, PH_LOG_VAR(pRspLen), pRspLen);
    }
#endif /* NXPBUILD__PH_LOG */
    PH_LOG_HELPER_ADDPARAM_UINT16(PH_LOG_LOGTYPE_INFO, PH_LOG_VAR(wStatus), &wStatus);
    PH_LOG_HELPER_EXECUTE(PH_LOG_OPTION_CATEGORY_LEAVE);

    return wStatus;
}

phStatus_t phalMfDuoX_WriteData(void * pDataParams, uint8_t bOption, uint8_t bIns, uint8_t bFileNo, uint16_t wCRLVer,
    uint8_t * pOffset, uint8_t * pData, uint8_t * pLength)
{
    phStatus_t  PH_MEMLOC_REM wStatus;
    uint16_t    PH_MEMLOC_REM wDataLen;

    PH_LOG_HELPER_ALLOCATE_TEXT(bFunctionName, "phalMfDuoX_WriteData");
    PH_LOG_HELPER_ALLOCATE_PARAMNAME(wStatus);
    PH_LOG_HELPER_ALLOCATE_PARAMNAME(bOption);
    PH_LOG_HELPER_ALLOCATE_PARAMNAME(bIns);
    PH_LOG_HELPER_ALLOCATE_PARAMNAME(bFileNo);
    PH_LOG_HELPER_ALLOCATE_PARAMNAME(wCRLVer);
    PH_LOG_HELPER_ALLOCATE_PARAMNAME(pOffset);
    PH_LOG_HELPER_ALLOCATE_PARAMNAME(pData);
    PH_LOG_HELPER_ALLOCATE_PARAMNAME(pLength);

    /* Validate the parameters */
    PH_ASSERT_NULL_DATA_PARAM(pDataParams, PH_COMP_AL_MFDUOX);
    PH_ASSERT_NULL_PARAM(pOffset, PH_COMP_AL_MFDUOX);
    PH_ASSERT_NULL_PARAM(pData, PH_COMP_AL_MFDUOX);
    PH_ASSERT_NULL_PARAM(pLength, PH_COMP_AL_MFDUOX);

    /* Get length from pointer to unsigned integer. */
    wDataLen = (uint16_t) ((pLength[1] << 8) | (pLength[0]));

    /* Log the information. */
    PH_LOG_HELPER_ADDSTRING(PH_LOG_LOGTYPE_INFO, bFunctionName);
    PH_LOG_HELPER_ADDPARAM_UINT8(PH_LOG_LOGTYPE_DEBUG, PH_LOG_VAR(bOption), &bOption);
    PH_LOG_HELPER_ADDPARAM_UINT8(PH_LOG_LOGTYPE_DEBUG, PH_LOG_VAR(bIns), &bIns);
    PH_LOG_HELPER_ADDPARAM_UINT8(PH_LOG_LOGTYPE_DEBUG, PH_LOG_VAR(bFileNo), &bFileNo);
    PH_LOG_HELPER_ADDPARAM_UINT16(PH_LOG_LOGTYPE_DEBUG, PH_LOG_VAR(wCRLVer), &wCRLVer);
    PH_LOG_HELPER_ADDPARAM_BUFFER(PH_LOG_LOGTYPE_DEBUG, PH_LOG_VAR(pOffset), pOffset, 3);
    PH_LOG_HELPER_ADDPARAM_BUFFER(PH_LOG_LOGTYPE_DEBUG, PH_LOG_VAR(pData), pData, wDataLen);
    PH_LOG_HELPER_ADDPARAM_BUFFER(PH_LOG_LOGTYPE_DEBUG, PH_LOG_VAR(pLength), pLength, 3);
    PH_LOG_HELPER_EXECUTE(PH_LOG_OPTION_CATEGORY_ENTER);

    /* Component Code Validation */
    if(PH_GET_COMPCODE(pDataParams) != PH_COMP_AL_MFDUOX)
    {
        PH_LOG_HELPER_ADDSTRING(PH_LOG_LOGTYPE_INFO, bFunctionName);
        PH_LOG_HELPER_ADDPARAM_UINT16(PH_LOG_LOGTYPE_INFO, PH_LOG_VAR(wStatus), &wStatus);
        PH_LOG_HELPER_EXECUTE(PH_LOG_OPTION_CATEGORY_LEAVE);

        return PH_ADD_COMPCODE(PH_ERR_INVALID_DATA_PARAMS, PH_COMP_AL_MFDUOX);
    }

    /* Perform operation on active layer */
    switch(PH_GET_COMPID(pDataParams))
    {
#ifdef NXPBUILD__PHAL_MFDUOX_SW
        case PHAL_MFDUOX_SW_ID:
            wStatus = phalMfDuoX_Sw_WriteData((phalMfDuoX_Sw_DataParams_t *) pDataParams, bOption, bIns, bFileNo,
                wCRLVer, pOffset, pData, pLength);
            break;
#endif /* NXPBUILD__PHAL_MFDUOX_SW */

        default:
            wStatus = PH_ADD_COMPCODE(PH_ERR_INVALID_DATA_PARAMS, PH_COMP_AL_MFDUOX);
            break;
    }

    PH_LOG_HELPER_ADDSTRING(PH_LOG_LOGTYPE_INFO, bFunctionName);
    PH_LOG_HELPER_ADDPARAM_UINT16(PH_LOG_LOGTYPE_INFO, PH_LOG_VAR(wStatus), &wStatus);
    PH_LOG_HELPER_EXECUTE(PH_LOG_OPTION_CATEGORY_LEAVE);
    /* To resolve warning */
    PH_UNUSED_VARIABLE(wDataLen);

    return wStatus;
}

phStatus_t phalMfDuoX_GetValue(void * pDataParams, uint8_t bOption, uint8_t bFileNo, uint8_t ** ppValue,
    uint16_t * pValueLen)
{
    phStatus_t PH_MEMLOC_REM wStatus;

    PH_LOG_HELPER_ALLOCATE_TEXT(bFunctionName, "phalMfDuoX_GetValue");
    PH_LOG_HELPER_ALLOCATE_PARAMNAME(wStatus);
    PH_LOG_HELPER_ALLOCATE_PARAMNAME(bOption);
    PH_LOG_HELPER_ALLOCATE_PARAMNAME(bFileNo);
    PH_LOG_HELPER_ALLOCATE_PARAMNAME(ppValue);
    PH_LOG_HELPER_ALLOCATE_PARAMNAME(pValueLen);

    /* Validate the parameters */
    PH_ASSERT_NULL_DATA_PARAM(pDataParams, PH_COMP_AL_MFDUOX);
    PH_ASSERT_NULL_PARAM(pValueLen, PH_COMP_AL_MFDUOX);

    /* Log the information. */
    PH_LOG_HELPER_ADDSTRING(PH_LOG_LOGTYPE_INFO, bFunctionName);
    PH_LOG_HELPER_ADDPARAM_UINT8(PH_LOG_LOGTYPE_DEBUG, PH_LOG_VAR(bOption), &bOption);
    PH_LOG_HELPER_ADDPARAM_UINT8(PH_LOG_LOGTYPE_DEBUG, PH_LOG_VAR(bFileNo), &bFileNo);
    PH_LOG_HELPER_EXECUTE(PH_LOG_OPTION_CATEGORY_ENTER);

    /* Component Code Validation */
    if(PH_GET_COMPCODE(pDataParams) != PH_COMP_AL_MFDUOX)
    {
        PH_LOG_HELPER_ADDSTRING(PH_LOG_LOGTYPE_INFO, bFunctionName);
        PH_LOG_HELPER_ADDPARAM_UINT16(PH_LOG_LOGTYPE_INFO, PH_LOG_VAR(wStatus), &wStatus);
        PH_LOG_HELPER_EXECUTE(PH_LOG_OPTION_CATEGORY_LEAVE);

        return PH_ADD_COMPCODE(PH_ERR_INVALID_DATA_PARAMS, PH_COMP_AL_MFDUOX);
    }

    /* Perform operation on active layer */
    switch(PH_GET_COMPID(pDataParams))
    {
#ifdef NXPBUILD__PHAL_MFDUOX_SW
        case PHAL_MFDUOX_SW_ID:
            wStatus = phalMfDuoX_Sw_GetValue((phalMfDuoX_Sw_DataParams_t *) pDataParams, bOption, bFileNo, ppValue, pValueLen);
            break;
#endif /* NXPBUILD__PHAL_MFDUOX_SW */

        default:
            wStatus = PH_ADD_COMPCODE(PH_ERR_INVALID_DATA_PARAMS, PH_COMP_AL_MFDUOX);
            break;
    }

    PH_LOG_HELPER_ADDSTRING(PH_LOG_LOGTYPE_INFO, bFunctionName);
#ifdef NXPBUILD__PH_LOG
    if(((wStatus & PH_ERR_MASK) == PH_ERR_SUCCESS) || ((wStatus & PH_ERR_MASK) == PH_ERR_SUCCESS_CHAINING))
    {
        PH_LOG_HELPER_ADDPARAM_BUFFER(PH_LOG_LOGTYPE_DEBUG, PH_LOG_VAR(ppValue), *ppValue, *pValueLen);
        PH_LOG_HELPER_ADDPARAM_UINT16(PH_LOG_LOGTYPE_DEBUG, PH_LOG_VAR(pValueLen), pValueLen);
    }
#endif /* NXPBUILD__PH_LOG */
    PH_LOG_HELPER_ADDPARAM_UINT16(PH_LOG_LOGTYPE_INFO, PH_LOG_VAR(wStatus), &wStatus);
    PH_LOG_HELPER_EXECUTE(PH_LOG_OPTION_CATEGORY_LEAVE);

    return wStatus;
}

phStatus_t phalMfDuoX_Credit(void * pDataParams, uint8_t bOption, uint8_t bFileNo, uint8_t * pData)
{
    phStatus_t  PH_MEMLOC_REM wStatus;

    PH_LOG_HELPER_ALLOCATE_TEXT(bFunctionName, "phalMfDuoX_Credit");
    PH_LOG_HELPER_ALLOCATE_PARAMNAME(wStatus);
    PH_LOG_HELPER_ALLOCATE_PARAMNAME(bOption);
    PH_LOG_HELPER_ALLOCATE_PARAMNAME(bFileNo);
    PH_LOG_HELPER_ALLOCATE_PARAMNAME(pData);

    /* Validate the parameters */
    PH_ASSERT_NULL_DATA_PARAM(pDataParams, PH_COMP_AL_MFDUOX);
    PH_ASSERT_NULL_PARAM(pData, PH_COMP_AL_MFDUOX);

    /* Log the information. */
    PH_LOG_HELPER_ADDSTRING(PH_LOG_LOGTYPE_INFO, bFunctionName);
    PH_LOG_HELPER_ADDPARAM_UINT8(PH_LOG_LOGTYPE_DEBUG, PH_LOG_VAR(bOption), &bOption);
    PH_LOG_HELPER_ADDPARAM_UINT8(PH_LOG_LOGTYPE_DEBUG, PH_LOG_VAR(bFileNo), &bFileNo);
    PH_LOG_HELPER_ADDPARAM_BUFFER(PH_LOG_LOGTYPE_DEBUG, PH_LOG_VAR(pData), pData, 4);
    PH_LOG_HELPER_EXECUTE(PH_LOG_OPTION_CATEGORY_ENTER);

    /* Component Code Validation */
    if(PH_GET_COMPCODE(pDataParams) != PH_COMP_AL_MFDUOX)
    {
        PH_LOG_HELPER_ADDSTRING(PH_LOG_LOGTYPE_INFO, bFunctionName);
        PH_LOG_HELPER_ADDPARAM_UINT16(PH_LOG_LOGTYPE_INFO, PH_LOG_VAR(wStatus), &wStatus);
        PH_LOG_HELPER_EXECUTE(PH_LOG_OPTION_CATEGORY_LEAVE);

        return PH_ADD_COMPCODE(PH_ERR_INVALID_DATA_PARAMS, PH_COMP_AL_MFDUOX);
    }

    /* Perform operation on active layer */
    switch(PH_GET_COMPID(pDataParams))
    {
#ifdef NXPBUILD__PHAL_MFDUOX_SW
        case PHAL_MFDUOX_SW_ID:
            wStatus = phalMfDuoX_Sw_Credit((phalMfDuoX_Sw_DataParams_t *) pDataParams, bOption, bFileNo, pData);
            break;
#endif /* NXPBUILD__PHAL_MFDUOX_SW */

        default:
            wStatus = PH_ADD_COMPCODE(PH_ERR_INVALID_DATA_PARAMS, PH_COMP_AL_MFDUOX);
            break;
    }

    PH_LOG_HELPER_ADDSTRING(PH_LOG_LOGTYPE_INFO, bFunctionName);
    PH_LOG_HELPER_ADDPARAM_UINT16(PH_LOG_LOGTYPE_INFO, PH_LOG_VAR(wStatus), &wStatus);
    PH_LOG_HELPER_EXECUTE(PH_LOG_OPTION_CATEGORY_LEAVE);

    return wStatus;
}

phStatus_t phalMfDuoX_Debit(void * pDataParams, uint8_t bOption, uint8_t bFileNo, uint8_t * pData)
{
    phStatus_t  PH_MEMLOC_REM wStatus;

    PH_LOG_HELPER_ALLOCATE_TEXT(bFunctionName, "phalMfDuoX_Debit");
    PH_LOG_HELPER_ALLOCATE_PARAMNAME(wStatus);
    PH_LOG_HELPER_ALLOCATE_PARAMNAME(bOption);
    PH_LOG_HELPER_ALLOCATE_PARAMNAME(bFileNo);
    PH_LOG_HELPER_ALLOCATE_PARAMNAME(pData);

    /* Validate the parameters */
    PH_ASSERT_NULL_DATA_PARAM(pDataParams, PH_COMP_AL_MFDUOX);
    PH_ASSERT_NULL_PARAM(pData, PH_COMP_AL_MFDUOX);

    /* Log the information. */
    PH_LOG_HELPER_ADDSTRING(PH_LOG_LOGTYPE_INFO, bFunctionName);
    PH_LOG_HELPER_ADDPARAM_UINT8(PH_LOG_LOGTYPE_DEBUG, PH_LOG_VAR(bOption), &bOption);
    PH_LOG_HELPER_ADDPARAM_UINT8(PH_LOG_LOGTYPE_DEBUG, PH_LOG_VAR(bFileNo), &bFileNo);
    PH_LOG_HELPER_ADDPARAM_BUFFER(PH_LOG_LOGTYPE_DEBUG, PH_LOG_VAR(pData), pData, 4);
    PH_LOG_HELPER_EXECUTE(PH_LOG_OPTION_CATEGORY_ENTER);

    /* Component Code Validation */
    if(PH_GET_COMPCODE(pDataParams) != PH_COMP_AL_MFDUOX)
    {
        PH_LOG_HELPER_ADDSTRING(PH_LOG_LOGTYPE_INFO, bFunctionName);
        PH_LOG_HELPER_ADDPARAM_UINT16(PH_LOG_LOGTYPE_INFO, PH_LOG_VAR(wStatus), &wStatus);
        PH_LOG_HELPER_EXECUTE(PH_LOG_OPTION_CATEGORY_LEAVE);

        return PH_ADD_COMPCODE(PH_ERR_INVALID_DATA_PARAMS, PH_COMP_AL_MFDUOX);
    }

    /* Perform operation on active layer */
    switch(PH_GET_COMPID(pDataParams))
    {
#ifdef NXPBUILD__PHAL_MFDUOX_SW
        case PHAL_MFDUOX_SW_ID:
            wStatus = phalMfDuoX_Sw_Debit((phalMfDuoX_Sw_DataParams_t *) pDataParams, bOption, bFileNo, pData);
            break;
#endif /* NXPBUILD__PHAL_MFDUOX_SW */

        default:
            wStatus = PH_ADD_COMPCODE(PH_ERR_INVALID_DATA_PARAMS, PH_COMP_AL_MFDUOX);
            break;
    }

    PH_LOG_HELPER_ADDSTRING(PH_LOG_LOGTYPE_INFO, bFunctionName);
    PH_LOG_HELPER_ADDPARAM_UINT16(PH_LOG_LOGTYPE_INFO, PH_LOG_VAR(wStatus), &wStatus);
    PH_LOG_HELPER_EXECUTE(PH_LOG_OPTION_CATEGORY_LEAVE);

    return wStatus;
}

phStatus_t phalMfDuoX_LimitedCredit(void * pDataParams, uint8_t bOption, uint8_t bFileNo, uint8_t * pData)
{
    phStatus_t  PH_MEMLOC_REM wStatus;

    PH_LOG_HELPER_ALLOCATE_TEXT(bFunctionName, "phalMfDuoX_LimitedCredit");
    PH_LOG_HELPER_ALLOCATE_PARAMNAME(wStatus);
    PH_LOG_HELPER_ALLOCATE_PARAMNAME(bOption);
    PH_LOG_HELPER_ALLOCATE_PARAMNAME(bFileNo);
    PH_LOG_HELPER_ALLOCATE_PARAMNAME(pData);

    /* Validate the parameters */
    PH_ASSERT_NULL_DATA_PARAM(pDataParams, PH_COMP_AL_MFDUOX);
    PH_ASSERT_NULL_PARAM(pData, PH_COMP_AL_MFDUOX);

    /* Log the information. */
    PH_LOG_HELPER_ADDSTRING(PH_LOG_LOGTYPE_INFO, bFunctionName);
    PH_LOG_HELPER_ADDPARAM_UINT8(PH_LOG_LOGTYPE_DEBUG, PH_LOG_VAR(bOption), &bOption);
    PH_LOG_HELPER_ADDPARAM_UINT8(PH_LOG_LOGTYPE_DEBUG, PH_LOG_VAR(bFileNo), &bFileNo);
    PH_LOG_HELPER_ADDPARAM_BUFFER(PH_LOG_LOGTYPE_DEBUG, PH_LOG_VAR(pData), pData, 4);
    PH_LOG_HELPER_EXECUTE(PH_LOG_OPTION_CATEGORY_ENTER);

    /* Component Code Validation */
    if(PH_GET_COMPCODE(pDataParams) != PH_COMP_AL_MFDUOX)
    {
        PH_LOG_HELPER_ADDSTRING(PH_LOG_LOGTYPE_INFO, bFunctionName);
        PH_LOG_HELPER_ADDPARAM_UINT16(PH_LOG_LOGTYPE_INFO, PH_LOG_VAR(wStatus), &wStatus);
        PH_LOG_HELPER_EXECUTE(PH_LOG_OPTION_CATEGORY_LEAVE);

        return PH_ADD_COMPCODE(PH_ERR_INVALID_DATA_PARAMS, PH_COMP_AL_MFDUOX);
    }

    /* Perform operation on active layer */
    switch(PH_GET_COMPID(pDataParams))
    {
#ifdef NXPBUILD__PHAL_MFDUOX_SW
        case PHAL_MFDUOX_SW_ID:
            wStatus = phalMfDuoX_Sw_LimitedCredit((phalMfDuoX_Sw_DataParams_t *) pDataParams, bOption, bFileNo, pData);
            break;
#endif /* NXPBUILD__PHAL_MFDUOX_SW */

        default:
            wStatus = PH_ADD_COMPCODE(PH_ERR_INVALID_DATA_PARAMS, PH_COMP_AL_MFDUOX);
            break;
    }

    PH_LOG_HELPER_ADDSTRING(PH_LOG_LOGTYPE_INFO, bFunctionName);
    PH_LOG_HELPER_ADDPARAM_UINT16(PH_LOG_LOGTYPE_INFO, PH_LOG_VAR(wStatus), &wStatus);
    PH_LOG_HELPER_EXECUTE(PH_LOG_OPTION_CATEGORY_LEAVE);

    return wStatus;
}

phStatus_t phalMfDuoX_ReadRecords(void * pDataParams, uint8_t bOption, uint8_t bIns, uint8_t bFileNo, uint8_t * pRecNo,
    uint8_t * pRecCount, uint8_t * pRecSize, uint8_t ** ppResponse, uint16_t * pRspLen)
{
    phStatus_t PH_MEMLOC_REM wStatus;

    PH_LOG_HELPER_ALLOCATE_TEXT(bFunctionName, "phalMfDuoX_ReadRecords");
    PH_LOG_HELPER_ALLOCATE_PARAMNAME(wStatus);
    PH_LOG_HELPER_ALLOCATE_PARAMNAME(bOption);
    PH_LOG_HELPER_ALLOCATE_PARAMNAME(bIns);
    PH_LOG_HELPER_ALLOCATE_PARAMNAME(bFileNo);
    PH_LOG_HELPER_ALLOCATE_PARAMNAME(pRecNo);
    PH_LOG_HELPER_ALLOCATE_PARAMNAME(pRecCount);
    PH_LOG_HELPER_ALLOCATE_PARAMNAME(pRecSize);
    PH_LOG_HELPER_ALLOCATE_PARAMNAME(ppResponse);
    PH_LOG_HELPER_ALLOCATE_PARAMNAME(pRspLen);

    /* Validate the parameters */
    PH_ASSERT_NULL_DATA_PARAM(pDataParams, PH_COMP_AL_MFDUOX);
    PH_ASSERT_NULL_PARAM(pRecNo, PH_COMP_AL_MFDUOX);
    PH_ASSERT_NULL_PARAM(pRecCount, PH_COMP_AL_MFDUOX);
    PH_ASSERT_NULL_PARAM(pRecSize, PH_COMP_AL_MFDUOX);
    PH_ASSERT_NULL_PARAM(pRspLen, PH_COMP_AL_MFDUOX);

    /* Log the information. */
    PH_LOG_HELPER_ADDSTRING(PH_LOG_LOGTYPE_INFO, bFunctionName);
    PH_LOG_HELPER_ADDPARAM_UINT8(PH_LOG_LOGTYPE_DEBUG, PH_LOG_VAR(bOption), &bOption);
    PH_LOG_HELPER_ADDPARAM_UINT8(PH_LOG_LOGTYPE_DEBUG, PH_LOG_VAR(bIns), &bIns);
    PH_LOG_HELPER_ADDPARAM_UINT8(PH_LOG_LOGTYPE_DEBUG, PH_LOG_VAR(bFileNo), &bFileNo);
    PH_LOG_HELPER_ADDPARAM_BUFFER(PH_LOG_LOGTYPE_DEBUG, PH_LOG_VAR(pRecNo), pRecNo, 3);
    PH_LOG_HELPER_ADDPARAM_BUFFER(PH_LOG_LOGTYPE_DEBUG, PH_LOG_VAR(pRecCount), pRecCount, 3);
    PH_LOG_HELPER_ADDPARAM_BUFFER(PH_LOG_LOGTYPE_DEBUG, PH_LOG_VAR(pRecSize), pRecSize, 3);
    PH_LOG_HELPER_EXECUTE(PH_LOG_OPTION_CATEGORY_ENTER);

    /* Component Code Validation */
    if(PH_GET_COMPCODE(pDataParams) != PH_COMP_AL_MFDUOX)
    {
        PH_LOG_HELPER_ADDSTRING(PH_LOG_LOGTYPE_INFO, bFunctionName);
        PH_LOG_HELPER_ADDPARAM_UINT16(PH_LOG_LOGTYPE_INFO, PH_LOG_VAR(wStatus), &wStatus);
        PH_LOG_HELPER_EXECUTE(PH_LOG_OPTION_CATEGORY_LEAVE);

        return PH_ADD_COMPCODE(PH_ERR_INVALID_DATA_PARAMS, PH_COMP_AL_MFDUOX);
    }

    /* Perform operation on active layer */
    switch(PH_GET_COMPID(pDataParams))
    {
#ifdef NXPBUILD__PHAL_MFDUOX_SW
        case PHAL_MFDUOX_SW_ID:
            wStatus = phalMfDuoX_Sw_ReadRecords((phalMfDuoX_Sw_DataParams_t *) pDataParams, bOption, bIns, bFileNo, pRecNo, pRecCount,
                pRecSize, ppResponse, pRspLen);
            break;
#endif /* NXPBUILD__PHAL_MFDUOX_SW */

        default:
            wStatus = PH_ADD_COMPCODE(PH_ERR_INVALID_DATA_PARAMS, PH_COMP_AL_MFDUOX);
            break;
    }

    PH_LOG_HELPER_ADDSTRING(PH_LOG_LOGTYPE_INFO, bFunctionName);
#ifdef NXPBUILD__PH_LOG
    if(((wStatus & PH_ERR_MASK) == PH_ERR_SUCCESS) || ((wStatus & PH_ERR_MASK) == PH_ERR_SUCCESS_CHAINING))
    {
        PH_LOG_HELPER_ADDPARAM_BUFFER(PH_LOG_LOGTYPE_DEBUG, PH_LOG_VAR(ppResponse), *ppResponse, *pRspLen);
        PH_LOG_HELPER_ADDPARAM_UINT16(PH_LOG_LOGTYPE_DEBUG, PH_LOG_VAR(pRspLen), pRspLen);
    }
#endif /* NXPBUILD__PH_LOG */
    PH_LOG_HELPER_ADDPARAM_UINT16(PH_LOG_LOGTYPE_INFO, PH_LOG_VAR(wStatus), &wStatus);
    PH_LOG_HELPER_EXECUTE(PH_LOG_OPTION_CATEGORY_LEAVE);

    return wStatus;
}

phStatus_t phalMfDuoX_WriteRecord(void * pDataParams, uint8_t bOption, uint8_t bIns, uint8_t bFileNo, uint8_t * pOffset,
    uint8_t * pData, uint8_t * pLength)
{
    phStatus_t  PH_MEMLOC_REM wStatus;
    uint16_t    PH_MEMLOC_REM wDataLen;

    PH_LOG_HELPER_ALLOCATE_TEXT(bFunctionName, "phalMfDuoX_WriteRecord");
    PH_LOG_HELPER_ALLOCATE_PARAMNAME(wStatus);
    PH_LOG_HELPER_ALLOCATE_PARAMNAME(bOption);
    PH_LOG_HELPER_ALLOCATE_PARAMNAME(bIns);
    PH_LOG_HELPER_ALLOCATE_PARAMNAME(bFileNo);
    PH_LOG_HELPER_ALLOCATE_PARAMNAME(pOffset);
    PH_LOG_HELPER_ALLOCATE_PARAMNAME(pData);
    PH_LOG_HELPER_ALLOCATE_PARAMNAME(pLength);

    /* Validate the parameters */
    PH_ASSERT_NULL_DATA_PARAM(pDataParams, PH_COMP_AL_MFDUOX);
    PH_ASSERT_NULL_PARAM(pOffset, PH_COMP_AL_MFDUOX);
    PH_ASSERT_NULL_PARAM(pData, PH_COMP_AL_MFDUOX);
    PH_ASSERT_NULL_PARAM(pLength, PH_COMP_AL_MFDUOX);

    /* Get length from pointer to unsigned integer. */
    wDataLen = (uint16_t) ((pLength[1] << 8) | (pLength[0]));

    /* Log the information. */
    PH_LOG_HELPER_ADDSTRING(PH_LOG_LOGTYPE_INFO, bFunctionName);
    PH_LOG_HELPER_ADDPARAM_UINT8(PH_LOG_LOGTYPE_DEBUG, PH_LOG_VAR(bOption), &bOption);
    PH_LOG_HELPER_ADDPARAM_UINT8(PH_LOG_LOGTYPE_DEBUG, PH_LOG_VAR(bIns), &bIns);
    PH_LOG_HELPER_ADDPARAM_UINT8(PH_LOG_LOGTYPE_DEBUG, PH_LOG_VAR(bFileNo), &bFileNo);
    PH_LOG_HELPER_ADDPARAM_BUFFER(PH_LOG_LOGTYPE_DEBUG, PH_LOG_VAR(pOffset), pOffset, 3);
    PH_LOG_HELPER_ADDPARAM_BUFFER(PH_LOG_LOGTYPE_DEBUG, PH_LOG_VAR(pData), pData, wDataLen);
    PH_LOG_HELPER_ADDPARAM_BUFFER(PH_LOG_LOGTYPE_DEBUG, PH_LOG_VAR(pLength), pLength, 3);
    PH_LOG_HELPER_EXECUTE(PH_LOG_OPTION_CATEGORY_ENTER);

    /* Component Code Validation */
    if(PH_GET_COMPCODE(pDataParams) != PH_COMP_AL_MFDUOX)
    {
        PH_LOG_HELPER_ADDSTRING(PH_LOG_LOGTYPE_INFO, bFunctionName);
        PH_LOG_HELPER_ADDPARAM_UINT16(PH_LOG_LOGTYPE_INFO, PH_LOG_VAR(wStatus), &wStatus);
        PH_LOG_HELPER_EXECUTE(PH_LOG_OPTION_CATEGORY_LEAVE);

        return PH_ADD_COMPCODE(PH_ERR_INVALID_DATA_PARAMS, PH_COMP_AL_MFDUOX);
    }

    /* Perform operation on active layer */
    switch(PH_GET_COMPID(pDataParams))
    {
#ifdef NXPBUILD__PHAL_MFDUOX_SW
        case PHAL_MFDUOX_SW_ID:
            wStatus = phalMfDuoX_Sw_WriteRecord((phalMfDuoX_Sw_DataParams_t *) pDataParams, bOption, bIns, bFileNo, pOffset, pData,
                pLength);
            break;
#endif /* NXPBUILD__PHAL_MFDUOX_SW */

        default:
            wStatus = PH_ADD_COMPCODE(PH_ERR_INVALID_DATA_PARAMS, PH_COMP_AL_MFDUOX);
            break;
    }

    PH_LOG_HELPER_ADDSTRING(PH_LOG_LOGTYPE_INFO, bFunctionName);
    PH_LOG_HELPER_ADDPARAM_UINT16(PH_LOG_LOGTYPE_INFO, PH_LOG_VAR(wStatus), &wStatus);
    PH_LOG_HELPER_EXECUTE(PH_LOG_OPTION_CATEGORY_LEAVE);
    /* To resolve warning */
    PH_UNUSED_VARIABLE(wDataLen);

    return wStatus;
}

phStatus_t phalMfDuoX_UpdateRecord(void * pDataParams, uint8_t bOption, uint8_t bIns, uint8_t bFileNo, uint8_t * pRecNo,
    uint8_t * pOffset, uint8_t * pData, uint8_t * pLength)
{
    phStatus_t  PH_MEMLOC_REM wStatus;
    uint16_t    PH_MEMLOC_REM wDataLen;

    PH_LOG_HELPER_ALLOCATE_TEXT(bFunctionName, "phalMfDuoX_UpdateRecord");
    PH_LOG_HELPER_ALLOCATE_PARAMNAME(wStatus);
    PH_LOG_HELPER_ALLOCATE_PARAMNAME(bOption);
    PH_LOG_HELPER_ALLOCATE_PARAMNAME(bIns);
    PH_LOG_HELPER_ALLOCATE_PARAMNAME(bFileNo);
    PH_LOG_HELPER_ALLOCATE_PARAMNAME(pRecNo);
    PH_LOG_HELPER_ALLOCATE_PARAMNAME(pOffset);
    PH_LOG_HELPER_ALLOCATE_PARAMNAME(pData);
    PH_LOG_HELPER_ALLOCATE_PARAMNAME(pLength);

    /* Validate the parameters */
    PH_ASSERT_NULL_DATA_PARAM(pDataParams, PH_COMP_AL_MFDUOX);
    PH_ASSERT_NULL_PARAM(pRecNo, PH_COMP_AL_MFDUOX);
    PH_ASSERT_NULL_PARAM(pOffset, PH_COMP_AL_MFDUOX);
    PH_ASSERT_NULL_PARAM(pData, PH_COMP_AL_MFDUOX);
    PH_ASSERT_NULL_PARAM(pLength, PH_COMP_AL_MFDUOX);

    /* Get length from pointer to unsigned integer. */
    wDataLen = (uint16_t) ((pLength[1] << 8) | (pLength[0]));

    /* Log the information. */
    PH_LOG_HELPER_ADDSTRING(PH_LOG_LOGTYPE_INFO, bFunctionName);
    PH_LOG_HELPER_ADDPARAM_UINT8(PH_LOG_LOGTYPE_DEBUG, PH_LOG_VAR(bOption), &bOption);
    PH_LOG_HELPER_ADDPARAM_UINT8(PH_LOG_LOGTYPE_DEBUG, PH_LOG_VAR(bIns), &bIns);
    PH_LOG_HELPER_ADDPARAM_UINT8(PH_LOG_LOGTYPE_DEBUG, PH_LOG_VAR(bFileNo), &bFileNo);
    PH_LOG_HELPER_ADDPARAM_BUFFER(PH_LOG_LOGTYPE_DEBUG, PH_LOG_VAR(pRecNo), pRecNo, 3);
    PH_LOG_HELPER_ADDPARAM_BUFFER(PH_LOG_LOGTYPE_DEBUG, PH_LOG_VAR(pOffset), pOffset, 3);
    PH_LOG_HELPER_ADDPARAM_BUFFER(PH_LOG_LOGTYPE_DEBUG, PH_LOG_VAR(pData), pData, wDataLen);
    PH_LOG_HELPER_ADDPARAM_BUFFER(PH_LOG_LOGTYPE_DEBUG, PH_LOG_VAR(pLength), pLength, 3);
    PH_LOG_HELPER_EXECUTE(PH_LOG_OPTION_CATEGORY_ENTER);

    /* Component Code Validation */
    if(PH_GET_COMPCODE(pDataParams) != PH_COMP_AL_MFDUOX)
    {
        PH_LOG_HELPER_ADDSTRING(PH_LOG_LOGTYPE_INFO, bFunctionName);
        PH_LOG_HELPER_ADDPARAM_UINT16(PH_LOG_LOGTYPE_INFO, PH_LOG_VAR(wStatus), &wStatus);
        PH_LOG_HELPER_EXECUTE(PH_LOG_OPTION_CATEGORY_LEAVE);

        return PH_ADD_COMPCODE(PH_ERR_INVALID_DATA_PARAMS, PH_COMP_AL_MFDUOX);
    }

    /* Perform operation on active layer */
    switch(PH_GET_COMPID(pDataParams))
    {
#ifdef NXPBUILD__PHAL_MFDUOX_SW
        case PHAL_MFDUOX_SW_ID:
            wStatus = phalMfDuoX_Sw_UpdateRecord((phalMfDuoX_Sw_DataParams_t *) pDataParams, bOption, bIns, bFileNo, pRecNo, pOffset,
                pData, pLength);
            break;
#endif /* NXPBUILD__PHAL_MFDUOX_SW */

        default:
            wStatus = PH_ADD_COMPCODE(PH_ERR_INVALID_DATA_PARAMS, PH_COMP_AL_MFDUOX);
            break;
    }

    PH_LOG_HELPER_ADDSTRING(PH_LOG_LOGTYPE_INFO, bFunctionName);
    PH_LOG_HELPER_ADDPARAM_UINT16(PH_LOG_LOGTYPE_INFO, PH_LOG_VAR(wStatus), &wStatus);
    PH_LOG_HELPER_EXECUTE(PH_LOG_OPTION_CATEGORY_LEAVE);
    /* To resolve warning */
    PH_UNUSED_VARIABLE(wDataLen);

    return wStatus;
}

phStatus_t phalMfDuoX_ClearRecordFile(void * pDataParams, uint8_t bFileNo)
{
    phStatus_t  PH_MEMLOC_REM wStatus;

    PH_LOG_HELPER_ALLOCATE_TEXT(bFunctionName, "phalMfDuoX_ClearRecordFile");
    PH_LOG_HELPER_ALLOCATE_PARAMNAME(wStatus);
    PH_LOG_HELPER_ALLOCATE_PARAMNAME(bFileNo);

    /* Validate the parameters */
    PH_ASSERT_NULL_DATA_PARAM(pDataParams, PH_COMP_AL_MFDUOX);

    /* Log the information. */
    PH_LOG_HELPER_ADDSTRING(PH_LOG_LOGTYPE_INFO, bFunctionName);
    PH_LOG_HELPER_ADDPARAM_UINT8(PH_LOG_LOGTYPE_DEBUG, PH_LOG_VAR(bFileNo), &bFileNo);
    PH_LOG_HELPER_EXECUTE(PH_LOG_OPTION_CATEGORY_ENTER);

    /* Component Code Validation */
    if(PH_GET_COMPCODE(pDataParams) != PH_COMP_AL_MFDUOX)
    {
        PH_LOG_HELPER_ADDSTRING(PH_LOG_LOGTYPE_INFO, bFunctionName);
        PH_LOG_HELPER_ADDPARAM_UINT16(PH_LOG_LOGTYPE_INFO, PH_LOG_VAR(wStatus), &wStatus);
        PH_LOG_HELPER_EXECUTE(PH_LOG_OPTION_CATEGORY_LEAVE);

        return PH_ADD_COMPCODE(PH_ERR_INVALID_DATA_PARAMS, PH_COMP_AL_MFDUOX);
    }

    /* Perform operation on active layer */
    switch(PH_GET_COMPID(pDataParams))
    {
#ifdef NXPBUILD__PHAL_MFDUOX_SW
        case PHAL_MFDUOX_SW_ID:
            wStatus = phalMfDuoX_Sw_ClearRecordFile((phalMfDuoX_Sw_DataParams_t *) pDataParams, bFileNo);
            break;
#endif /* NXPBUILD__PHAL_MFDUOX_SW */

        default:
            wStatus = PH_ADD_COMPCODE(PH_ERR_INVALID_DATA_PARAMS, PH_COMP_AL_MFDUOX);
            break;
    }

    PH_LOG_HELPER_ADDSTRING(PH_LOG_LOGTYPE_INFO, bFunctionName);
    PH_LOG_HELPER_ADDPARAM_UINT16(PH_LOG_LOGTYPE_INFO, PH_LOG_VAR(wStatus), &wStatus);
    PH_LOG_HELPER_EXECUTE(PH_LOG_OPTION_CATEGORY_LEAVE);

    return wStatus;
}

/* MIFARE DUOX Transaction Management commands ------------------------------------------------------------------------------------------ */
phStatus_t phalMfDuoX_CommitTransaction(void * pDataParams, uint8_t bOption, uint8_t ** ppTMC, uint16_t * pTMCLen,
    uint8_t ** ppResponse, uint16_t * pRspLen)
{
    phStatus_t PH_MEMLOC_REM wStatus;

    PH_LOG_HELPER_ALLOCATE_TEXT(bFunctionName, "phalMfDuoX_CommitTransaction");
    PH_LOG_HELPER_ALLOCATE_PARAMNAME(wStatus);
    PH_LOG_HELPER_ALLOCATE_PARAMNAME(bOption);
    PH_LOG_HELPER_ALLOCATE_PARAMNAME(ppTMC);
    PH_LOG_HELPER_ALLOCATE_PARAMNAME(pTMCLen);
    PH_LOG_HELPER_ALLOCATE_PARAMNAME(ppResponse);
    PH_LOG_HELPER_ALLOCATE_PARAMNAME(pRspLen);

    /* Validate the parameters */
    PH_ASSERT_NULL_DATA_PARAM(pDataParams, PH_COMP_AL_MFDUOX);
    PH_ASSERT_NULL_PARAM(pTMCLen, PH_COMP_AL_MFDUOX);
    PH_ASSERT_NULL_PARAM(pRspLen, PH_COMP_AL_MFDUOX);

    /* Log the information. */
    PH_LOG_HELPER_ADDSTRING(PH_LOG_LOGTYPE_INFO, bFunctionName);
    PH_LOG_HELPER_ADDPARAM_UINT8(PH_LOG_LOGTYPE_DEBUG, PH_LOG_VAR(bOption), &bOption);
    PH_LOG_HELPER_EXECUTE(PH_LOG_OPTION_CATEGORY_ENTER);

    /* Component Code Validation */
    if(PH_GET_COMPCODE(pDataParams) != PH_COMP_AL_MFDUOX)
    {
        PH_LOG_HELPER_ADDSTRING(PH_LOG_LOGTYPE_INFO, bFunctionName);
        PH_LOG_HELPER_ADDPARAM_UINT16(PH_LOG_LOGTYPE_INFO, PH_LOG_VAR(wStatus), &wStatus);
        PH_LOG_HELPER_EXECUTE(PH_LOG_OPTION_CATEGORY_LEAVE);

        return PH_ADD_COMPCODE(PH_ERR_INVALID_DATA_PARAMS, PH_COMP_AL_MFDUOX);
    }

    /* Perform operation on active layer */
    switch(PH_GET_COMPID(pDataParams))
    {
#ifdef NXPBUILD__PHAL_MFDUOX_SW
        case PHAL_MFDUOX_SW_ID:
            wStatus = phalMfDuoX_Sw_CommitTransaction((phalMfDuoX_Sw_DataParams_t *) pDataParams, bOption, ppTMC, pTMCLen,
                ppResponse, pRspLen);
            break;
#endif /* NXPBUILD__PHAL_MFDUOX_SW */

        default:
            wStatus = PH_ADD_COMPCODE(PH_ERR_INVALID_DATA_PARAMS, PH_COMP_AL_MFDUOX);
            break;
    }

    PH_LOG_HELPER_ADDSTRING(PH_LOG_LOGTYPE_INFO, bFunctionName);
#ifdef NXPBUILD__PH_LOG
    if((wStatus & PH_ERR_MASK) == PH_ERR_SUCCESS)
    {
        PH_LOG_HELPER_ADDPARAM_BUFFER(PH_LOG_LOGTYPE_DEBUG, PH_LOG_VAR(ppTMC), *ppTMC, *pTMCLen);
        PH_LOG_HELPER_ADDPARAM_UINT16(PH_LOG_LOGTYPE_DEBUG, PH_LOG_VAR(pTMCLen), pTMCLen);

        PH_LOG_HELPER_ADDPARAM_BUFFER(PH_LOG_LOGTYPE_DEBUG, PH_LOG_VAR(ppResponse), *ppResponse, *pRspLen);
        PH_LOG_HELPER_ADDPARAM_UINT16(PH_LOG_LOGTYPE_DEBUG, PH_LOG_VAR(pRspLen), pRspLen);
    }
#endif /* NXPBUILD__PH_LOG */
    PH_LOG_HELPER_ADDPARAM_UINT16(PH_LOG_LOGTYPE_INFO, PH_LOG_VAR(wStatus), &wStatus);
    PH_LOG_HELPER_EXECUTE(PH_LOG_OPTION_CATEGORY_LEAVE);

    return wStatus;
}

phStatus_t phalMfDuoX_AbortTransaction(void * pDataParams)
{
    phStatus_t PH_MEMLOC_REM wStatus;

    PH_LOG_HELPER_ALLOCATE_TEXT(bFunctionName, "phalMfDuoX_AbortTransaction");
    PH_LOG_HELPER_ALLOCATE_PARAMNAME(wStatus);

    /* Validate the parameters */
    PH_ASSERT_NULL_DATA_PARAM(pDataParams, PH_COMP_AL_MFDUOX);

    /* Log the information. */
    PH_LOG_HELPER_ADDSTRING(PH_LOG_LOGTYPE_INFO, bFunctionName);
    PH_LOG_HELPER_EXECUTE(PH_LOG_OPTION_CATEGORY_ENTER);

    /* Component Code Validation */
    if(PH_GET_COMPCODE(pDataParams) != PH_COMP_AL_MFDUOX)
    {
        PH_LOG_HELPER_ADDSTRING(PH_LOG_LOGTYPE_INFO, bFunctionName);
        PH_LOG_HELPER_ADDPARAM_UINT16(PH_LOG_LOGTYPE_INFO, PH_LOG_VAR(wStatus), &wStatus);
        PH_LOG_HELPER_EXECUTE(PH_LOG_OPTION_CATEGORY_LEAVE);

        return PH_ADD_COMPCODE(PH_ERR_INVALID_DATA_PARAMS, PH_COMP_AL_MFDUOX);
    }

    /* Perform operation on active layer */
    switch(PH_GET_COMPID(pDataParams))
    {
#ifdef NXPBUILD__PHAL_MFDUOX_SW
        case PHAL_MFDUOX_SW_ID:
            wStatus = phalMfDuoX_Sw_AbortTransaction((phalMfDuoX_Sw_DataParams_t *) pDataParams);
            break;
#endif /* NXPBUILD__PHAL_MFDUOX_SW */

        default:
            wStatus = PH_ADD_COMPCODE(PH_ERR_INVALID_DATA_PARAMS, PH_COMP_AL_MFDUOX);
            break;
    }

    PH_LOG_HELPER_ADDSTRING(PH_LOG_LOGTYPE_INFO, bFunctionName);
    PH_LOG_HELPER_ADDPARAM_UINT16(PH_LOG_LOGTYPE_INFO, PH_LOG_VAR(wStatus), &wStatus);
    PH_LOG_HELPER_EXECUTE(PH_LOG_OPTION_CATEGORY_LEAVE);

    return wStatus;
}

phStatus_t phalMfDuoX_CommitReaderID(void * pDataParams, uint8_t * pTMRI, uint8_t bTMRILen, uint8_t ** ppEncTMRI,
    uint16_t * pEncTMRILen)
{
    phStatus_t PH_MEMLOC_REM wStatus;

    PH_LOG_HELPER_ALLOCATE_TEXT(bFunctionName, "phalMfDuoX_CommitReaderID");
    PH_LOG_HELPER_ALLOCATE_PARAMNAME(wStatus);
    PH_LOG_HELPER_ALLOCATE_PARAMNAME(pTMRI);
    PH_LOG_HELPER_ALLOCATE_PARAMNAME(bTMRILen);
    PH_LOG_HELPER_ALLOCATE_PARAMNAME(ppEncTMRI);
    PH_LOG_HELPER_ALLOCATE_PARAMNAME(pEncTMRILen);

    /* Validate the parameters */
    PH_ASSERT_NULL_DATA_PARAM(pDataParams, PH_COMP_AL_MFDUOX);
    PH_ASSERT_NULL_PARAM(pTMRI, PH_COMP_AL_MFDUOX);
    PH_ASSERT_NULL_PARAM(pEncTMRILen, PH_COMP_AL_MFDUOX);

    /* Log the information. */
    PH_LOG_HELPER_ADDSTRING(PH_LOG_LOGTYPE_INFO, bFunctionName);
    PH_LOG_HELPER_ADDPARAM_BUFFER(PH_LOG_LOGTYPE_DEBUG, PH_LOG_VAR(pTMRI), pTMRI, bTMRILen);
    PH_LOG_HELPER_ADDPARAM_UINT8(PH_LOG_LOGTYPE_DEBUG, PH_LOG_VAR(bTMRILen), &bTMRILen);
    PH_LOG_HELPER_EXECUTE(PH_LOG_OPTION_CATEGORY_ENTER);

    /* Component Code Validation */
    if(PH_GET_COMPCODE(pDataParams) != PH_COMP_AL_MFDUOX)
    {
        PH_LOG_HELPER_ADDSTRING(PH_LOG_LOGTYPE_INFO, bFunctionName);
        PH_LOG_HELPER_ADDPARAM_UINT16(PH_LOG_LOGTYPE_INFO, PH_LOG_VAR(wStatus), &wStatus);
        PH_LOG_HELPER_EXECUTE(PH_LOG_OPTION_CATEGORY_LEAVE);

        return PH_ADD_COMPCODE(PH_ERR_INVALID_DATA_PARAMS, PH_COMP_AL_MFDUOX);
    }

    /* Perform operation on active layer */
    switch(PH_GET_COMPID(pDataParams))
    {
#ifdef NXPBUILD__PHAL_MFDUOX_SW
        case PHAL_MFDUOX_SW_ID:
            wStatus = phalMfDuoX_Sw_CommitReaderID((phalMfDuoX_Sw_DataParams_t *) pDataParams, pTMRI, bTMRILen,
                ppEncTMRI, pEncTMRILen);
            break;
#endif /* NXPBUILD__PHAL_MFDUOX_SW */

        default:
            wStatus = PH_ADD_COMPCODE(PH_ERR_INVALID_DATA_PARAMS, PH_COMP_AL_MFDUOX);
            break;
    }

    PH_LOG_HELPER_ADDSTRING(PH_LOG_LOGTYPE_INFO, bFunctionName);
#ifdef NXPBUILD__PH_LOG
    if((wStatus & PH_ERR_MASK) == PH_ERR_SUCCESS)
    {
        PH_LOG_HELPER_ADDPARAM_BUFFER(PH_LOG_LOGTYPE_DEBUG, PH_LOG_VAR(ppEncTMRI), *ppEncTMRI, *pEncTMRILen);
        PH_LOG_HELPER_ADDPARAM_UINT16(PH_LOG_LOGTYPE_DEBUG, PH_LOG_VAR(pEncTMRILen), pEncTMRILen);
    }
#endif /* NXPBUILD__PH_LOG */
    PH_LOG_HELPER_ADDPARAM_UINT16(PH_LOG_LOGTYPE_INFO, PH_LOG_VAR(wStatus), &wStatus);
    PH_LOG_HELPER_EXECUTE(PH_LOG_OPTION_CATEGORY_LEAVE);

    return wStatus;
}

/* MIFARE DUOX Cryptographic support commands ------------------------------------------------------------------------------------------- */
phStatus_t phalMfDuoX_CryptoRequest(void * pDataParams, uint8_t bComOption, uint8_t bAction, uint8_t * pInputData,
    uint16_t wInputLen, uint8_t ** ppResponse, uint16_t * pRspLen)
{
    phStatus_t PH_MEMLOC_REM wStatus;

    PH_LOG_HELPER_ALLOCATE_TEXT(bFunctionName, "phalMfDuoX_IsoSelectFile");
    PH_LOG_HELPER_ALLOCATE_PARAMNAME(wStatus);
    PH_LOG_HELPER_ALLOCATE_PARAMNAME(bComOption);
    PH_LOG_HELPER_ALLOCATE_PARAMNAME(bAction);
    PH_LOG_HELPER_ALLOCATE_PARAMNAME(pInputData);
    PH_LOG_HELPER_ALLOCATE_PARAMNAME(wInputLen);
    PH_LOG_HELPER_ALLOCATE_PARAMNAME(ppResponse);
    PH_LOG_HELPER_ALLOCATE_PARAMNAME(pRspLen);

    /* Validate the parameters */
    PH_ASSERT_NULL_DATA_PARAM(pDataParams, PH_COMP_AL_MFDUOX);
    PH_ASSERT_NULL_PARAM(pInputData, PH_COMP_AL_MFDUOX);
    PH_ASSERT_NULL_PARAM(pRspLen, PH_COMP_AL_MFDUOX);

    /* Log the information. */
    PH_LOG_HELPER_ADDSTRING(PH_LOG_LOGTYPE_INFO, bFunctionName);
    PH_LOG_HELPER_ADDPARAM_UINT8(PH_LOG_LOGTYPE_DEBUG, PH_LOG_VAR(bComOption), &bComOption);
    PH_LOG_HELPER_ADDPARAM_UINT8(PH_LOG_LOGTYPE_DEBUG, PH_LOG_VAR(bAction), &bAction);
    PH_LOG_HELPER_ADDPARAM_BUFFER(PH_LOG_LOGTYPE_DEBUG, PH_LOG_VAR(pInputData), pInputData, wInputLen);
    PH_LOG_HELPER_ADDPARAM_UINT16(PH_LOG_LOGTYPE_DEBUG, PH_LOG_VAR(wInputLen), &wInputLen);
    PH_LOG_HELPER_EXECUTE(PH_LOG_OPTION_CATEGORY_ENTER);

    /* Component Code Validation */
    if(PH_GET_COMPCODE(pDataParams) != PH_COMP_AL_MFDUOX)
    {
        PH_LOG_HELPER_ADDSTRING(PH_LOG_LOGTYPE_INFO, bFunctionName);
        PH_LOG_HELPER_ADDPARAM_UINT16(PH_LOG_LOGTYPE_INFO, PH_LOG_VAR(wStatus), &wStatus);
        PH_LOG_HELPER_EXECUTE(PH_LOG_OPTION_CATEGORY_LEAVE);

        return PH_ADD_COMPCODE(PH_ERR_INVALID_DATA_PARAMS, PH_COMP_AL_MFDUOX);
    }

    /* Perform operation on active layer */
    switch(PH_GET_COMPID(pDataParams))
    {
#ifdef NXPBUILD__PHAL_MFDUOX_SW
        case PHAL_MFDUOX_SW_ID:
            wStatus = phalMfDuoX_Sw_CryptoRequest((phalMfDuoX_Sw_DataParams_t *) pDataParams, bComOption, bAction, pInputData, wInputLen,
                ppResponse, pRspLen);
            break;
#endif /* NXPBUILD__PHAL_MFDUOX_SW */

        default:
            wStatus = PH_ADD_COMPCODE(PH_ERR_INVALID_DATA_PARAMS, PH_COMP_AL_MFDUOX);
            break;
    }

    PH_LOG_HELPER_ADDSTRING(PH_LOG_LOGTYPE_INFO, bFunctionName);
#ifdef NXPBUILD__PH_LOG
    if((wStatus & PH_ERR_MASK) == PH_ERR_SUCCESS)
    {
        PH_LOG_HELPER_ADDPARAM_BUFFER(PH_LOG_LOGTYPE_DEBUG, PH_LOG_VAR(ppResponse), *ppResponse, *pRspLen);
        PH_LOG_HELPER_ADDPARAM_UINT16(PH_LOG_LOGTYPE_DEBUG, PH_LOG_VAR(pRspLen), pRspLen);
    }
#endif /* NXPBUILD__PH_LOG */
    PH_LOG_HELPER_ADDPARAM_UINT16(PH_LOG_LOGTYPE_INFO, PH_LOG_VAR(wStatus), &wStatus);
    PH_LOG_HELPER_EXECUTE(PH_LOG_OPTION_CATEGORY_LEAVE);

    return wStatus;
}

phStatus_t phalMfDuoX_CryptoRequestECCSign(void * pDataParams, uint8_t bComOption, uint8_t bOperation, uint8_t bAlgo,
    uint8_t bKeyNo, uint8_t bInputSource, uint8_t * pInputData, uint8_t bInputLen, uint8_t ** ppSign,
    uint16_t * pSignLen)
{
    phStatus_t PH_MEMLOC_REM wStatus;

    PH_LOG_HELPER_ALLOCATE_TEXT(bFunctionName, "phalMfDuoX_CryptoRequestECCSign");
    PH_LOG_HELPER_ALLOCATE_PARAMNAME(wStatus);
    PH_LOG_HELPER_ALLOCATE_PARAMNAME(bComOption);
    PH_LOG_HELPER_ALLOCATE_PARAMNAME(bKeyNo);
    PH_LOG_HELPER_ALLOCATE_PARAMNAME(bAlgo);
    PH_LOG_HELPER_ALLOCATE_PARAMNAME(bInputSource);
    PH_LOG_HELPER_ALLOCATE_PARAMNAME(bOperation);
    PH_LOG_HELPER_ALLOCATE_PARAMNAME(pInputData);
    PH_LOG_HELPER_ALLOCATE_PARAMNAME(bInputLen);
    PH_LOG_HELPER_ALLOCATE_PARAMNAME(ppSign);
    PH_LOG_HELPER_ALLOCATE_PARAMNAME(pSignLen);

    /* Validate the parameters */
    PH_ASSERT_NULL_DATA_PARAM(pDataParams, PH_COMP_AL_MFDUOX);
    PH_ASSERT_NULL_PARAM(pInputData, PH_COMP_AL_MFDUOX);
    PH_ASSERT_NULL_PARAM(pSignLen, PH_COMP_AL_MFDUOX);

    /* Log the information. */
    PH_LOG_HELPER_ADDSTRING(PH_LOG_LOGTYPE_INFO, bFunctionName);
    PH_LOG_HELPER_ADDPARAM_UINT8(PH_LOG_LOGTYPE_DEBUG, PH_LOG_VAR(bComOption), &bComOption);
    PH_LOG_HELPER_ADDPARAM_UINT8(PH_LOG_LOGTYPE_DEBUG, PH_LOG_VAR(bKeyNo), &bKeyNo);
    PH_LOG_HELPER_ADDPARAM_UINT8(PH_LOG_LOGTYPE_DEBUG, PH_LOG_VAR(bAlgo), &bAlgo);
    PH_LOG_HELPER_ADDPARAM_UINT8(PH_LOG_LOGTYPE_DEBUG, PH_LOG_VAR(bInputSource), &bInputSource);
    PH_LOG_HELPER_ADDPARAM_UINT8(PH_LOG_LOGTYPE_DEBUG, PH_LOG_VAR(bOperation), &bOperation);
    PH_LOG_HELPER_ADDPARAM_BUFFER(PH_LOG_LOGTYPE_DEBUG, PH_LOG_VAR(pInputData), pInputData, bInputLen);
    PH_LOG_HELPER_ADDPARAM_UINT8(PH_LOG_LOGTYPE_DEBUG, PH_LOG_VAR(bInputLen), &bInputLen);
    PH_LOG_HELPER_EXECUTE(PH_LOG_OPTION_CATEGORY_ENTER);

    /* Component Code Validation */
    if(PH_GET_COMPCODE(pDataParams) != PH_COMP_AL_MFDUOX)
    {
        PH_LOG_HELPER_ADDSTRING(PH_LOG_LOGTYPE_INFO, bFunctionName);
        PH_LOG_HELPER_ADDPARAM_UINT16(PH_LOG_LOGTYPE_INFO, PH_LOG_VAR(wStatus), &wStatus);
        PH_LOG_HELPER_EXECUTE(PH_LOG_OPTION_CATEGORY_LEAVE);

        return PH_ADD_COMPCODE(PH_ERR_INVALID_DATA_PARAMS, PH_COMP_AL_MFDUOX);
    }

    /* Perform operation on active layer */
    switch(PH_GET_COMPID(pDataParams))
    {
#ifdef NXPBUILD__PHAL_MFDUOX_SW
        case PHAL_MFDUOX_SW_ID:
            wStatus = phalMfDuoX_Sw_CryptoRequestECCSign((phalMfDuoX_Sw_DataParams_t *) pDataParams, bComOption, bOperation, bAlgo,
                bKeyNo, bInputSource, pInputData, bInputLen, ppSign, pSignLen);
            break;
#endif /* NXPBUILD__PHAL_MFDUOX_SW */

        default:
            wStatus = PH_ADD_COMPCODE(PH_ERR_INVALID_DATA_PARAMS, PH_COMP_AL_MFDUOX);
            break;
    }

    PH_LOG_HELPER_ADDSTRING(PH_LOG_LOGTYPE_INFO, bFunctionName);
#ifdef NXPBUILD__PH_LOG
    if((wStatus & PH_ERR_MASK) == PH_ERR_SUCCESS)
    {
        PH_LOG_HELPER_ADDPARAM_BUFFER(PH_LOG_LOGTYPE_DEBUG, PH_LOG_VAR(ppSign), *ppSign, *pSignLen);
        PH_LOG_HELPER_ADDPARAM_UINT16(PH_LOG_LOGTYPE_DEBUG, PH_LOG_VAR(pSignLen), pSignLen);
    }
#endif /* NXPBUILD__PH_LOG */
    PH_LOG_HELPER_ADDPARAM_UINT16(PH_LOG_LOGTYPE_INFO, PH_LOG_VAR(wStatus), &wStatus);
    PH_LOG_HELPER_EXECUTE(PH_LOG_OPTION_CATEGORY_LEAVE);

    return wStatus;
}

phStatus_t phalMfDuoX_CryptoRequestEcho(void * pDataParams, uint8_t bComOption, uint8_t * pInputData, uint8_t bInputLen,
    uint8_t ** ppResponse, uint16_t * pRspLen)
{
    phStatus_t PH_MEMLOC_REM wStatus;

    PH_LOG_HELPER_ALLOCATE_TEXT(bFunctionName, "phalMfDuoX_CryptoRequestEcho");
    PH_LOG_HELPER_ALLOCATE_PARAMNAME(wStatus);
    PH_LOG_HELPER_ALLOCATE_PARAMNAME(bComOption);
    PH_LOG_HELPER_ALLOCATE_PARAMNAME(pInputData);
    PH_LOG_HELPER_ALLOCATE_PARAMNAME(bInputLen);
    PH_LOG_HELPER_ALLOCATE_PARAMNAME(ppResponse);
    PH_LOG_HELPER_ALLOCATE_PARAMNAME(pRspLen);

    /* Validate the parameters */
    PH_ASSERT_NULL_DATA_PARAM(pDataParams, PH_COMP_AL_MFDUOX);
    PH_ASSERT_NULL_PARAM(pInputData, PH_COMP_AL_MFDUOX);
    PH_ASSERT_NULL_PARAM(pRspLen, PH_COMP_AL_MFDUOX);

    /* Log the information. */
    PH_LOG_HELPER_ADDSTRING(PH_LOG_LOGTYPE_INFO, bFunctionName);
    PH_LOG_HELPER_ADDPARAM_UINT8(PH_LOG_LOGTYPE_DEBUG, PH_LOG_VAR(bComOption), &bComOption);
    PH_LOG_HELPER_ADDPARAM_BUFFER(PH_LOG_LOGTYPE_DEBUG, PH_LOG_VAR(pInputData), pInputData, bInputLen);
    PH_LOG_HELPER_ADDPARAM_UINT8(PH_LOG_LOGTYPE_DEBUG, PH_LOG_VAR(bInputLen), &bInputLen);
    PH_LOG_HELPER_EXECUTE(PH_LOG_OPTION_CATEGORY_ENTER);

    /* Component Code Validation */
    if(PH_GET_COMPCODE(pDataParams) != PH_COMP_AL_MFDUOX)
    {
        PH_LOG_HELPER_ADDSTRING(PH_LOG_LOGTYPE_INFO, bFunctionName);
        PH_LOG_HELPER_ADDPARAM_UINT16(PH_LOG_LOGTYPE_INFO, PH_LOG_VAR(wStatus), &wStatus);
        PH_LOG_HELPER_EXECUTE(PH_LOG_OPTION_CATEGORY_LEAVE);

        return PH_ADD_COMPCODE(PH_ERR_INVALID_DATA_PARAMS, PH_COMP_AL_MFDUOX);
    }

    /* Perform operation on active layer */
    switch(PH_GET_COMPID(pDataParams))
    {
#ifdef NXPBUILD__PHAL_MFDUOX_SW
        case PHAL_MFDUOX_SW_ID:
            wStatus = phalMfDuoX_Sw_CryptoRequestEcho((phalMfDuoX_Sw_DataParams_t *) pDataParams, bComOption, pInputData,
                bInputLen, ppResponse, pRspLen);
            break;
#endif /* NXPBUILD__PHAL_MFDUOX_SW */

        default:
            wStatus = PH_ADD_COMPCODE(PH_ERR_INVALID_DATA_PARAMS, PH_COMP_AL_MFDUOX);
            break;
    }

    PH_LOG_HELPER_ADDSTRING(PH_LOG_LOGTYPE_INFO, bFunctionName);
#ifdef NXPBUILD__PH_LOG
    if((wStatus & PH_ERR_MASK) == PH_ERR_SUCCESS)
    {
        PH_LOG_HELPER_ADDPARAM_BUFFER(PH_LOG_LOGTYPE_DEBUG, PH_LOG_VAR(ppResponse), *ppResponse, *pRspLen);
        PH_LOG_HELPER_ADDPARAM_UINT16(PH_LOG_LOGTYPE_DEBUG, PH_LOG_VAR(pRspLen), pRspLen);
    }
#endif /* NXPBUILD__PH_LOG */
    PH_LOG_HELPER_ADDPARAM_UINT16(PH_LOG_LOGTYPE_INFO, PH_LOG_VAR(wStatus), &wStatus);
    PH_LOG_HELPER_EXECUTE(PH_LOG_OPTION_CATEGORY_LEAVE);

    return wStatus;
}

/* MIFARE DUOX GPIO Management commands ------------------------------------------------------------------------------------------------- */
phStatus_t phalMfDuoX_ManageGPIO(void * pDataParams, uint16_t wOption, uint8_t bGPIONo, uint8_t bOperation,
    uint8_t * pNFCPauseRspData, uint16_t wNFCPauseRspDataLen, uint8_t ** ppResponse, uint16_t * pRspLen)
{
    phStatus_t PH_MEMLOC_REM wStatus;

    PH_LOG_HELPER_ALLOCATE_TEXT(bFunctionName, "phalMfDuoX_ManageGPIO");
    PH_LOG_HELPER_ALLOCATE_PARAMNAME(wStatus);
    PH_LOG_HELPER_ALLOCATE_PARAMNAME(wOption);
    PH_LOG_HELPER_ALLOCATE_PARAMNAME(bGPIONo);
    PH_LOG_HELPER_ALLOCATE_PARAMNAME(bOperation);
    PH_LOG_HELPER_ALLOCATE_PARAMNAME(pNFCPauseRspData);
    PH_LOG_HELPER_ALLOCATE_PARAMNAME(wNFCPauseRspDataLen);
    PH_LOG_HELPER_ALLOCATE_PARAMNAME(ppResponse);
    PH_LOG_HELPER_ALLOCATE_PARAMNAME(pRspLen);

    /* Validate the parameters */
    PH_ASSERT_NULL_DATA_PARAM(pDataParams, PH_COMP_AL_MFDUOX);
    if(wNFCPauseRspDataLen)
        PH_ASSERT_NULL_PARAM(pNFCPauseRspData, PH_COMP_AL_MFDUOX);
    PH_ASSERT_NULL_PARAM(pRspLen, PH_COMP_AL_MFDUOX);

    /* Log the information. */
    PH_LOG_HELPER_ADDSTRING(PH_LOG_LOGTYPE_INFO, bFunctionName);
    PH_LOG_HELPER_ADDPARAM_UINT16(PH_LOG_LOGTYPE_DEBUG, PH_LOG_VAR(wOption), &wOption);
    PH_LOG_HELPER_ADDPARAM_UINT8(PH_LOG_LOGTYPE_DEBUG, PH_LOG_VAR(bGPIONo), &bGPIONo);
    PH_LOG_HELPER_ADDPARAM_UINT8(PH_LOG_LOGTYPE_DEBUG, PH_LOG_VAR(bOperation), &bOperation);
    PH_LOG_HELPER_ADDPARAM_BUFFER(PH_LOG_LOGTYPE_DEBUG, PH_LOG_VAR(pNFCPauseRspData), pNFCPauseRspData, wNFCPauseRspDataLen);
    PH_LOG_HELPER_ADDPARAM_UINT16(PH_LOG_LOGTYPE_DEBUG, PH_LOG_VAR(wNFCPauseRspDataLen), &wNFCPauseRspDataLen);
    PH_LOG_HELPER_EXECUTE(PH_LOG_OPTION_CATEGORY_ENTER);

    /* Component Code Validation */
    if(PH_GET_COMPCODE(pDataParams) != PH_COMP_AL_MFDUOX)
    {
        PH_LOG_HELPER_ADDSTRING(PH_LOG_LOGTYPE_INFO, bFunctionName);
        PH_LOG_HELPER_ADDPARAM_UINT16(PH_LOG_LOGTYPE_INFO, PH_LOG_VAR(wStatus), &wStatus);
        PH_LOG_HELPER_EXECUTE(PH_LOG_OPTION_CATEGORY_LEAVE);

        return PH_ADD_COMPCODE(PH_ERR_INVALID_DATA_PARAMS, PH_COMP_AL_MFDUOX);
    }

    /* Perform operation on active layer */
    switch(PH_GET_COMPID(pDataParams))
    {
#ifdef NXPBUILD__PHAL_MFDUOX_SW
        case PHAL_MFDUOX_SW_ID:
            wStatus = phalMfDuoX_Sw_ManageGPIO((phalMfDuoX_Sw_DataParams_t *) pDataParams, wOption, bGPIONo, bOperation,
                pNFCPauseRspData, wNFCPauseRspDataLen, ppResponse, pRspLen);
            break;
#endif /* NXPBUILD__PHAL_MFDUOX_SW */

        default:
            wStatus = PH_ADD_COMPCODE(PH_ERR_INVALID_DATA_PARAMS, PH_COMP_AL_MFDUOX);
            break;
    }

    PH_LOG_HELPER_ADDSTRING(PH_LOG_LOGTYPE_INFO, bFunctionName);
#ifdef NXPBUILD__PH_LOG
    if((wStatus & PH_ERR_MASK) == PH_ERR_SUCCESS)
    {
        PH_LOG_HELPER_ADDPARAM_BUFFER(PH_LOG_LOGTYPE_DEBUG, PH_LOG_VAR(ppResponse), *ppResponse, *pRspLen);
        PH_LOG_HELPER_ADDPARAM_UINT16(PH_LOG_LOGTYPE_DEBUG, PH_LOG_VAR(pRspLen), pRspLen);
    }
#endif /* NXPBUILD__PH_LOG */
    PH_LOG_HELPER_ADDPARAM_UINT16(PH_LOG_LOGTYPE_INFO, PH_LOG_VAR(wStatus), &wStatus);
    PH_LOG_HELPER_EXECUTE(PH_LOG_OPTION_CATEGORY_LEAVE);

    return wStatus;
}

phStatus_t phalMfDuoX_ReadGPIO(void * pDataParams, uint16_t wOption, uint8_t ** ppResponse, uint16_t * pRspLen)
{
    phStatus_t PH_MEMLOC_REM wStatus;

    PH_LOG_HELPER_ALLOCATE_TEXT(bFunctionName, "phalMfDuoX_ReadGPIO");
    PH_LOG_HELPER_ALLOCATE_PARAMNAME(wStatus);
    PH_LOG_HELPER_ALLOCATE_PARAMNAME(wOption);
    PH_LOG_HELPER_ALLOCATE_PARAMNAME(ppResponse);
    PH_LOG_HELPER_ALLOCATE_PARAMNAME(pRspLen);

    /* Validate the parameters */
    PH_ASSERT_NULL_DATA_PARAM(pDataParams, PH_COMP_AL_MFDUOX);
    PH_ASSERT_NULL_PARAM(pRspLen, PH_COMP_AL_MFDUOX);

    /* Log the information. */
    PH_LOG_HELPER_ADDSTRING(PH_LOG_LOGTYPE_INFO, bFunctionName);
    PH_LOG_HELPER_ADDPARAM_UINT16(PH_LOG_LOGTYPE_DEBUG, PH_LOG_VAR(wOption), &wOption);
    PH_LOG_HELPER_EXECUTE(PH_LOG_OPTION_CATEGORY_ENTER);

    /* Component Code Validation */
    if(PH_GET_COMPCODE(pDataParams) != PH_COMP_AL_MFDUOX)
    {
        PH_LOG_HELPER_ADDSTRING(PH_LOG_LOGTYPE_INFO, bFunctionName);
        PH_LOG_HELPER_ADDPARAM_UINT16(PH_LOG_LOGTYPE_INFO, PH_LOG_VAR(wStatus), &wStatus);
        PH_LOG_HELPER_EXECUTE(PH_LOG_OPTION_CATEGORY_LEAVE);

        return PH_ADD_COMPCODE(PH_ERR_INVALID_DATA_PARAMS, PH_COMP_AL_MFDUOX);
    }

    /* Perform operation on active layer */
    switch(PH_GET_COMPID(pDataParams))
    {
#ifdef NXPBUILD__PHAL_MFDUOX_SW
        case PHAL_MFDUOX_SW_ID:
            wStatus = phalMfDuoX_Sw_ReadGPIO((phalMfDuoX_Sw_DataParams_t *) pDataParams, wOption, ppResponse, pRspLen);
            break;
#endif /* NXPBUILD__PHAL_MFDUOX_SW */

        default:
            wStatus = PH_ADD_COMPCODE(PH_ERR_INVALID_DATA_PARAMS, PH_COMP_AL_MFDUOX);
            break;
    }

    PH_LOG_HELPER_ADDSTRING(PH_LOG_LOGTYPE_INFO, bFunctionName);
#ifdef NXPBUILD__PH_LOG
    if((wStatus & PH_ERR_MASK) == PH_ERR_SUCCESS)
    {
        PH_LOG_HELPER_ADDPARAM_BUFFER(PH_LOG_LOGTYPE_DEBUG, PH_LOG_VAR(ppResponse), *ppResponse, *pRspLen);
        PH_LOG_HELPER_ADDPARAM_UINT16(PH_LOG_LOGTYPE_DEBUG, PH_LOG_VAR(pRspLen), pRspLen);
    }
#endif /* NXPBUILD__PH_LOG */
    PH_LOG_HELPER_ADDPARAM_UINT16(PH_LOG_LOGTYPE_INFO, PH_LOG_VAR(wStatus), &wStatus);
    PH_LOG_HELPER_EXECUTE(PH_LOG_OPTION_CATEGORY_LEAVE);

    return wStatus;
}

/* MIFARE DUOX ISO7816-4 commands ------------------------------------------------------------------------------------------------------- */
phStatus_t phalMfDuoX_IsoSelectFile(void * pDataParams, uint8_t bOption, uint8_t bSelector, uint8_t * pFid, uint8_t * pDFname,
    uint8_t bDFnameLen, uint8_t bExtendedLenApdu, uint8_t ** ppFCI, uint16_t * pFCILen)
{
    phStatus_t PH_MEMLOC_REM wStatus;

    PH_LOG_HELPER_ALLOCATE_TEXT(bFunctionName, "phalMfDuoX_IsoSelectFile");
    PH_LOG_HELPER_ALLOCATE_PARAMNAME(wStatus);
    PH_LOG_HELPER_ALLOCATE_PARAMNAME(bOption);
    PH_LOG_HELPER_ALLOCATE_PARAMNAME(bSelector);
    PH_LOG_HELPER_ALLOCATE_PARAMNAME(pFid);
    PH_LOG_HELPER_ALLOCATE_PARAMNAME(pDFname);
    PH_LOG_HELPER_ALLOCATE_PARAMNAME(bDFnameLen);
    PH_LOG_HELPER_ALLOCATE_PARAMNAME(bExtendedLenApdu);
    PH_LOG_HELPER_ALLOCATE_PARAMNAME(ppFCI);
    PH_LOG_HELPER_ALLOCATE_PARAMNAME(pFCILen);

    /* Validate the parameters */
    PH_ASSERT_NULL_DATA_PARAM(pDataParams, PH_COMP_AL_MFDUOX);
    if(bDFnameLen) PH_ASSERT_NULL_PARAM(pDFname, PH_COMP_AL_MFDUOX);
    PH_ASSERT_NULL_PARAM(pFCILen, PH_COMP_AL_MFDUOX);

    /* Log the information. */
    PH_LOG_HELPER_ADDSTRING(PH_LOG_LOGTYPE_INFO, bFunctionName);
    PH_LOG_HELPER_ADDPARAM_UINT8(PH_LOG_LOGTYPE_DEBUG, PH_LOG_VAR(bOption), &bOption);
    PH_LOG_HELPER_ADDPARAM_UINT8(PH_LOG_LOGTYPE_DEBUG, PH_LOG_VAR(bSelector), &bSelector);
    PH_LOG_HELPER_ADDPARAM_BUFFER(PH_LOG_LOGTYPE_DEBUG, PH_LOG_VAR(pFid), pFid, 2);
    PH_LOG_HELPER_ADDPARAM_BUFFER(PH_LOG_LOGTYPE_DEBUG, PH_LOG_VAR(pDFname), pDFname, (uint16_t) bDFnameLen);
    PH_LOG_HELPER_ADDPARAM_UINT8(PH_LOG_LOGTYPE_DEBUG, PH_LOG_VAR(bDFnameLen), &bDFnameLen);
    PH_LOG_HELPER_ADDPARAM_UINT8(PH_LOG_LOGTYPE_DEBUG, PH_LOG_VAR(bExtendedLenApdu), &bExtendedLenApdu);
    PH_LOG_HELPER_EXECUTE(PH_LOG_OPTION_CATEGORY_ENTER);

    /* Component Code Validation */
    if(PH_GET_COMPCODE(pDataParams) != PH_COMP_AL_MFDUOX)
    {
        PH_LOG_HELPER_ADDSTRING(PH_LOG_LOGTYPE_INFO, bFunctionName);
        PH_LOG_HELPER_ADDPARAM_UINT16(PH_LOG_LOGTYPE_INFO, PH_LOG_VAR(wStatus), &wStatus);
        PH_LOG_HELPER_EXECUTE(PH_LOG_OPTION_CATEGORY_LEAVE);

        return PH_ADD_COMPCODE(PH_ERR_INVALID_DATA_PARAMS, PH_COMP_AL_MFDUOX);
    }

    /* Perform operation on active layer */
    switch(PH_GET_COMPID(pDataParams))
    {
#ifdef NXPBUILD__PHAL_MFDUOX_SW
        case PHAL_MFDUOX_SW_ID:
            wStatus = phalMfDuoX_Sw_IsoSelectFile((phalMfDuoX_Sw_DataParams_t *) pDataParams, bOption, bSelector, pFid,
                pDFname, bDFnameLen, bExtendedLenApdu, ppFCI, pFCILen);
            break;
#endif /* NXPBUILD__PHAL_MFDUOX_SW */

        default:
            wStatus = PH_ADD_COMPCODE(PH_ERR_INVALID_DATA_PARAMS, PH_COMP_AL_MFDUOX);
            break;
    }

    PH_LOG_HELPER_ADDSTRING(PH_LOG_LOGTYPE_INFO, bFunctionName);
#ifdef NXPBUILD__PH_LOG
    if((wStatus & PH_ERR_MASK) == PH_ERR_SUCCESS)
    {
        PH_LOG_HELPER_ADDPARAM_BUFFER(PH_LOG_LOGTYPE_DEBUG, PH_LOG_VAR(ppFCI), *ppFCI, *pFCILen);
        PH_LOG_HELPER_ADDPARAM_UINT16(PH_LOG_LOGTYPE_DEBUG, PH_LOG_VAR(pFCILen), pFCILen);
    }
#endif /* NXPBUILD__PH_LOG */
    PH_LOG_HELPER_ADDPARAM_UINT16(PH_LOG_LOGTYPE_INFO, PH_LOG_VAR(wStatus), &wStatus);
    PH_LOG_HELPER_EXECUTE(PH_LOG_OPTION_CATEGORY_LEAVE);

    return wStatus;
}

phStatus_t phalMfDuoX_IsoReadBinary(void * pDataParams, uint16_t wOption, uint8_t bOffset, uint8_t bSfid, uint32_t dwBytesToRead,
    uint8_t bExtendedLenApdu, uint8_t ** ppResponse, uint16_t * pRspLen)
{
    phStatus_t PH_MEMLOC_REM wStatus;

    PH_LOG_HELPER_ALLOCATE_TEXT(bFunctionName, "phalMfDuoX_IsoReadBinary");
    PH_LOG_HELPER_ALLOCATE_PARAMNAME(wStatus);
    PH_LOG_HELPER_ALLOCATE_PARAMNAME(wOption);
    PH_LOG_HELPER_ALLOCATE_PARAMNAME(bOffset);
    PH_LOG_HELPER_ALLOCATE_PARAMNAME(bSfid);
    PH_LOG_HELPER_ALLOCATE_PARAMNAME(dwBytesToRead);
    PH_LOG_HELPER_ALLOCATE_PARAMNAME(bExtendedLenApdu);
    PH_LOG_HELPER_ALLOCATE_PARAMNAME(ppResponse);
    PH_LOG_HELPER_ALLOCATE_PARAMNAME(pRspLen);

    /* Validate the parameters */
    PH_ASSERT_NULL_DATA_PARAM(pDataParams, PH_COMP_AL_MFDUOX);
    PH_ASSERT_NULL_PARAM(pRspLen, PH_COMP_AL_MFDUOX);

    /* Log the information. */
    PH_LOG_HELPER_ADDSTRING(PH_LOG_LOGTYPE_INFO, bFunctionName);
    PH_LOG_HELPER_ADDPARAM_UINT16(PH_LOG_LOGTYPE_DEBUG, PH_LOG_VAR(wOption), &wOption);
    PH_LOG_HELPER_ADDPARAM_UINT8(PH_LOG_LOGTYPE_DEBUG, PH_LOG_VAR(bOffset), &bOffset);
    PH_LOG_HELPER_ADDPARAM_UINT8(PH_LOG_LOGTYPE_DEBUG, PH_LOG_VAR(bSfid), &bSfid);
    PH_LOG_HELPER_ADDPARAM_UINT32(PH_LOG_LOGTYPE_DEBUG, PH_LOG_VAR(dwBytesToRead), &dwBytesToRead);
    PH_LOG_HELPER_ADDPARAM_UINT8(PH_LOG_LOGTYPE_DEBUG, PH_LOG_VAR(bExtendedLenApdu), &bExtendedLenApdu);
    PH_LOG_HELPER_EXECUTE(PH_LOG_OPTION_CATEGORY_ENTER);

    /* Component Code Validation */
    if(PH_GET_COMPCODE(pDataParams) != PH_COMP_AL_MFDUOX)
    {
        PH_LOG_HELPER_ADDSTRING(PH_LOG_LOGTYPE_INFO, bFunctionName);
        PH_LOG_HELPER_ADDPARAM_UINT16(PH_LOG_LOGTYPE_INFO, PH_LOG_VAR(wStatus), &wStatus);
        PH_LOG_HELPER_EXECUTE(PH_LOG_OPTION_CATEGORY_LEAVE);

        return PH_ADD_COMPCODE(PH_ERR_INVALID_DATA_PARAMS, PH_COMP_AL_MFDUOX);
    }

    /* Perform operation on active layer */
    switch(PH_GET_COMPID(pDataParams))
    {
#ifdef NXPBUILD__PHAL_MFDUOX_SW
        case PHAL_MFDUOX_SW_ID:
            wStatus = phalMfDuoX_Sw_IsoReadBinary((phalMfDuoX_Sw_DataParams_t *) pDataParams, wOption, bOffset, bSfid,
                dwBytesToRead, bExtendedLenApdu, ppResponse, pRspLen);
            break;
#endif /* NXPBUILD__PHAL_MFDUOX_SW */

        default:
            wStatus = PH_ADD_COMPCODE(PH_ERR_INVALID_DATA_PARAMS, PH_COMP_AL_MFDUOX);
            break;
    }

    PH_LOG_HELPER_ADDSTRING(PH_LOG_LOGTYPE_INFO, bFunctionName);
#ifdef NXPBUILD__PH_LOG
    if((wStatus & PH_ERR_MASK) == PH_ERR_SUCCESS)
    {
        PH_LOG_HELPER_ADDPARAM_BUFFER(PH_LOG_LOGTYPE_DEBUG, PH_LOG_VAR(ppResponse), *ppResponse, *pRspLen);
        PH_LOG_HELPER_ADDPARAM_UINT16(PH_LOG_LOGTYPE_DEBUG, PH_LOG_VAR(pRspLen), pRspLen);
    }
#endif /* NXPBUILD__PH_LOG */
    PH_LOG_HELPER_ADDPARAM_UINT16(PH_LOG_LOGTYPE_INFO, PH_LOG_VAR(wStatus), &wStatus);
    PH_LOG_HELPER_EXECUTE(PH_LOG_OPTION_CATEGORY_LEAVE);

    return wStatus;
}

phStatus_t phalMfDuoX_IsoUpdateBinary(void * pDataParams, uint8_t bOffset, uint8_t bSfid, uint8_t bExtendedLenApdu, uint8_t * pData,
    uint16_t wDataLen)
{
    phStatus_t PH_MEMLOC_REM wStatus;

    PH_LOG_HELPER_ALLOCATE_TEXT(bFunctionName, "phalMfDuoX_IsoUpdateBinary");
    PH_LOG_HELPER_ALLOCATE_PARAMNAME(wStatus);
    PH_LOG_HELPER_ALLOCATE_PARAMNAME(bOffset);
    PH_LOG_HELPER_ALLOCATE_PARAMNAME(bSfid);
    PH_LOG_HELPER_ALLOCATE_PARAMNAME(bExtendedLenApdu);
    PH_LOG_HELPER_ALLOCATE_PARAMNAME(pData);
    PH_LOG_HELPER_ALLOCATE_PARAMNAME(wDataLen);

    /* Validate the parameters */
    PH_ASSERT_NULL_DATA_PARAM(pDataParams, PH_COMP_AL_MFDUOX);
    if(wDataLen) PH_ASSERT_NULL_PARAM(pData, PH_COMP_AL_MFDUOX);

    /* Log the information. */
    PH_LOG_HELPER_ADDSTRING(PH_LOG_LOGTYPE_INFO, bFunctionName);
    PH_LOG_HELPER_ADDPARAM_UINT8(PH_LOG_LOGTYPE_DEBUG, PH_LOG_VAR(bOffset), &bOffset);
    PH_LOG_HELPER_ADDPARAM_UINT8(PH_LOG_LOGTYPE_DEBUG, PH_LOG_VAR(bSfid), &bSfid);
    PH_LOG_HELPER_ADDPARAM_UINT8(PH_LOG_LOGTYPE_DEBUG, PH_LOG_VAR(bExtendedLenApdu), &bExtendedLenApdu);
    PH_LOG_HELPER_ADDPARAM_BUFFER(PH_LOG_LOGTYPE_DEBUG, PH_LOG_VAR(pData), pData, wDataLen);
    PH_LOG_HELPER_ADDPARAM_UINT16(PH_LOG_LOGTYPE_DEBUG, PH_LOG_VAR(wDataLen), &wDataLen);
    PH_LOG_HELPER_EXECUTE(PH_LOG_OPTION_CATEGORY_ENTER);

    /* Component Code Validation */
    if(PH_GET_COMPCODE(pDataParams) != PH_COMP_AL_MFDUOX)
    {
        PH_LOG_HELPER_ADDSTRING(PH_LOG_LOGTYPE_INFO, bFunctionName);
        PH_LOG_HELPER_ADDPARAM_UINT16(PH_LOG_LOGTYPE_INFO, PH_LOG_VAR(wStatus), &wStatus);
        PH_LOG_HELPER_EXECUTE(PH_LOG_OPTION_CATEGORY_LEAVE);

        return PH_ADD_COMPCODE(PH_ERR_INVALID_DATA_PARAMS, PH_COMP_AL_MFDUOX);
    }

    /* Perform operation on active layer */
    switch(PH_GET_COMPID(pDataParams))
    {
#ifdef NXPBUILD__PHAL_MFDUOX_SW
        case PHAL_MFDUOX_SW_ID:
            wStatus = phalMfDuoX_Sw_IsoUpdateBinary((phalMfDuoX_Sw_DataParams_t *) pDataParams, bOffset, bSfid, bExtendedLenApdu,
                pData, wDataLen);
            break;
#endif /* NXPBUILD__PHAL_MFDUOX_SW */

        default:
            wStatus = PH_ADD_COMPCODE(PH_ERR_INVALID_DATA_PARAMS, PH_COMP_AL_MFDUOX);
            break;
    }

    PH_LOG_HELPER_ADDSTRING(PH_LOG_LOGTYPE_INFO, bFunctionName);
    PH_LOG_HELPER_ADDPARAM_UINT16(PH_LOG_LOGTYPE_INFO, PH_LOG_VAR(wStatus), &wStatus);
    PH_LOG_HELPER_EXECUTE(PH_LOG_OPTION_CATEGORY_LEAVE);

    return wStatus;
}

phStatus_t phalMfDuoX_IsoReadRecords(void * pDataParams, uint16_t wOption, uint8_t bRecNo, uint8_t bReadAllRecords, uint8_t bSfid,
    uint32_t dwBytesToRead, uint8_t bExtendedLenApdu, uint8_t ** ppResponse, uint16_t * pRspLen)
{
    phStatus_t PH_MEMLOC_REM wStatus;

    PH_LOG_HELPER_ALLOCATE_TEXT(bFunctionName, "phalMfDuoX_IsoReadRecords");
    PH_LOG_HELPER_ALLOCATE_PARAMNAME(wStatus);
    PH_LOG_HELPER_ALLOCATE_PARAMNAME(wOption);
    PH_LOG_HELPER_ALLOCATE_PARAMNAME(bRecNo);
    PH_LOG_HELPER_ALLOCATE_PARAMNAME(bReadAllRecords);
    PH_LOG_HELPER_ALLOCATE_PARAMNAME(bSfid);
    PH_LOG_HELPER_ALLOCATE_PARAMNAME(dwBytesToRead);
    PH_LOG_HELPER_ALLOCATE_PARAMNAME(bExtendedLenApdu);
    PH_LOG_HELPER_ALLOCATE_PARAMNAME(ppResponse);
    PH_LOG_HELPER_ALLOCATE_PARAMNAME(pRspLen);

    /* Validate the parameters */
    PH_ASSERT_NULL_DATA_PARAM(pDataParams, PH_COMP_AL_MFDUOX);
    PH_ASSERT_NULL_PARAM(pRspLen, PH_COMP_AL_MFDUOX);

    /* Log the information. */
    PH_LOG_HELPER_ADDSTRING(PH_LOG_LOGTYPE_INFO, bFunctionName);
    PH_LOG_HELPER_ADDPARAM_UINT16(PH_LOG_LOGTYPE_DEBUG, PH_LOG_VAR(wOption), &wOption);
    PH_LOG_HELPER_ADDPARAM_UINT8(PH_LOG_LOGTYPE_DEBUG, PH_LOG_VAR(bRecNo), &bRecNo);
    PH_LOG_HELPER_ADDPARAM_UINT8(PH_LOG_LOGTYPE_DEBUG, PH_LOG_VAR(bReadAllRecords), &bReadAllRecords);
    PH_LOG_HELPER_ADDPARAM_UINT8(PH_LOG_LOGTYPE_DEBUG, PH_LOG_VAR(bSfid), &bSfid);
    PH_LOG_HELPER_ADDPARAM_UINT32(PH_LOG_LOGTYPE_DEBUG, PH_LOG_VAR(dwBytesToRead), &dwBytesToRead);
    PH_LOG_HELPER_ADDPARAM_UINT8(PH_LOG_LOGTYPE_DEBUG, PH_LOG_VAR(bExtendedLenApdu), &bExtendedLenApdu);
    PH_LOG_HELPER_EXECUTE(PH_LOG_OPTION_CATEGORY_ENTER);

    /* Component Code Validation */
    if(PH_GET_COMPCODE(pDataParams) != PH_COMP_AL_MFDUOX)
    {
        PH_LOG_HELPER_ADDSTRING(PH_LOG_LOGTYPE_INFO, bFunctionName);
        PH_LOG_HELPER_ADDPARAM_UINT16(PH_LOG_LOGTYPE_INFO, PH_LOG_VAR(wStatus), &wStatus);
        PH_LOG_HELPER_EXECUTE(PH_LOG_OPTION_CATEGORY_LEAVE);

        return PH_ADD_COMPCODE(PH_ERR_INVALID_DATA_PARAMS, PH_COMP_AL_MFDUOX);
    }

    /* Perform operation on active layer */
    switch(PH_GET_COMPID(pDataParams))
    {
#ifdef NXPBUILD__PHAL_MFDUOX_SW
        case PHAL_MFDUOX_SW_ID:
            wStatus = phalMfDuoX_Sw_IsoReadRecords((phalMfDuoX_Sw_DataParams_t *) pDataParams, wOption, bRecNo, bReadAllRecords,
                bSfid, dwBytesToRead, bExtendedLenApdu, ppResponse, pRspLen);
            break;
#endif /* NXPBUILD__PHAL_MFDUOX_SW */

        default:
            wStatus = PH_ADD_COMPCODE(PH_ERR_INVALID_DATA_PARAMS, PH_COMP_AL_MFDUOX);
            break;
    }

    PH_LOG_HELPER_ADDSTRING(PH_LOG_LOGTYPE_INFO, bFunctionName);
#ifdef NXPBUILD__PH_LOG
    if((wStatus & PH_ERR_MASK) == PH_ERR_SUCCESS)
    {
        PH_LOG_HELPER_ADDPARAM_BUFFER(PH_LOG_LOGTYPE_DEBUG, PH_LOG_VAR(ppResponse), *ppResponse, *pRspLen);
        PH_LOG_HELPER_ADDPARAM_UINT16(PH_LOG_LOGTYPE_DEBUG, PH_LOG_VAR(pRspLen), pRspLen);
    }
#endif /* NXPBUILD__PH_LOG */
    PH_LOG_HELPER_ADDPARAM_UINT16(PH_LOG_LOGTYPE_INFO, PH_LOG_VAR(wStatus), &wStatus);
    PH_LOG_HELPER_EXECUTE(PH_LOG_OPTION_CATEGORY_LEAVE);

    return wStatus;
}

phStatus_t phalMfDuoX_IsoAppendRecord(void * pDataParams, uint8_t bSfid, uint8_t bExtendedLenApdu, uint8_t * pData,
    uint16_t wDataLen)
{
    phStatus_t PH_MEMLOC_REM wStatus;

    PH_LOG_HELPER_ALLOCATE_TEXT(bFunctionName, "phalMfDuoX_IsoAppendRecord");
    PH_LOG_HELPER_ALLOCATE_PARAMNAME(wStatus);
    PH_LOG_HELPER_ALLOCATE_PARAMNAME(bSfid);
    PH_LOG_HELPER_ALLOCATE_PARAMNAME(bExtendedLenApdu);
    PH_LOG_HELPER_ALLOCATE_PARAMNAME(pData);
    PH_LOG_HELPER_ALLOCATE_PARAMNAME(wDataLen);

    /* Validate the parameters */
    PH_ASSERT_NULL_DATA_PARAM(pDataParams, PH_COMP_AL_MFDUOX);
    if(wDataLen) PH_ASSERT_NULL_PARAM(pData, PH_COMP_AL_MFDUOX);

    /* Log the information. */
    PH_LOG_HELPER_ADDSTRING(PH_LOG_LOGTYPE_INFO, bFunctionName);
    PH_LOG_HELPER_ADDPARAM_UINT8(PH_LOG_LOGTYPE_DEBUG, PH_LOG_VAR(bSfid), &bSfid);
    PH_LOG_HELPER_ADDPARAM_UINT8(PH_LOG_LOGTYPE_DEBUG, PH_LOG_VAR(bExtendedLenApdu), &bExtendedLenApdu);
    PH_LOG_HELPER_ADDPARAM_BUFFER(PH_LOG_LOGTYPE_DEBUG, PH_LOG_VAR(pData), pData, wDataLen);
    PH_LOG_HELPER_ADDPARAM_UINT16(PH_LOG_LOGTYPE_DEBUG, PH_LOG_VAR(wDataLen), &wDataLen);
    PH_LOG_HELPER_EXECUTE(PH_LOG_OPTION_CATEGORY_ENTER);

    /* Component Code Validation */
    if(PH_GET_COMPCODE(pDataParams) != PH_COMP_AL_MFDUOX)
    {
        PH_LOG_HELPER_ADDSTRING(PH_LOG_LOGTYPE_INFO, bFunctionName);
        PH_LOG_HELPER_ADDPARAM_UINT16(PH_LOG_LOGTYPE_INFO, PH_LOG_VAR(wStatus), &wStatus);
        PH_LOG_HELPER_EXECUTE(PH_LOG_OPTION_CATEGORY_LEAVE);

        return PH_ADD_COMPCODE(PH_ERR_INVALID_DATA_PARAMS, PH_COMP_AL_MFDUOX);
    }

    /* Perform operation on active layer */
    switch(PH_GET_COMPID(pDataParams))
    {
#ifdef NXPBUILD__PHAL_MFDUOX_SW
        case PHAL_MFDUOX_SW_ID:
            wStatus = phalMfDuoX_Sw_IsoAppendRecord((phalMfDuoX_Sw_DataParams_t *) pDataParams, bSfid, bExtendedLenApdu, pData,
                wDataLen);
            break;
#endif /* NXPBUILD__PHAL_MFDUOX_SW */

        default:
            wStatus = PH_ADD_COMPCODE(PH_ERR_INVALID_DATA_PARAMS, PH_COMP_AL_MFDUOX);
            break;
    }

    PH_LOG_HELPER_ADDSTRING(PH_LOG_LOGTYPE_INFO, bFunctionName);
    PH_LOG_HELPER_ADDPARAM_UINT16(PH_LOG_LOGTYPE_INFO, PH_LOG_VAR(wStatus), &wStatus);
    PH_LOG_HELPER_EXECUTE(PH_LOG_OPTION_CATEGORY_LEAVE);

    return wStatus;
}

phStatus_t phalMfDuoX_IsoGetChallenge(void * pDataParams, uint8_t bExpRsp, uint8_t bExtendedLenApdu, uint8_t ** ppResponse,
    uint16_t * pRspLen)
{
    phStatus_t PH_MEMLOC_REM wStatus;

    PH_LOG_HELPER_ALLOCATE_TEXT(bFunctionName, "phalMfDuoX_IsoGetChallenge");
    PH_LOG_HELPER_ALLOCATE_PARAMNAME(bExpRsp);
    PH_LOG_HELPER_ALLOCATE_PARAMNAME(bExtendedLenApdu);
    PH_LOG_HELPER_ALLOCATE_PARAMNAME(ppResponse);
    PH_LOG_HELPER_ALLOCATE_PARAMNAME(pRspLen);
    PH_LOG_HELPER_ALLOCATE_PARAMNAME(wStatus);

    /* Validate the parameters */
    PH_ASSERT_NULL_DATA_PARAM(pDataParams, PH_COMP_AL_MFDUOX);
    PH_ASSERT_NULL_PARAM(pRspLen, PH_COMP_AL_MFDUOX);

    /* Log the information. */
    PH_LOG_HELPER_ADDSTRING(PH_LOG_LOGTYPE_INFO, bFunctionName);
    PH_LOG_HELPER_ADDPARAM_UINT8(PH_LOG_LOGTYPE_DEBUG, PH_LOG_VAR(bExpRsp), &bExpRsp);
    PH_LOG_HELPER_ADDPARAM_UINT8(PH_LOG_LOGTYPE_DEBUG, PH_LOG_VAR(bExtendedLenApdu), &bExtendedLenApdu);
    PH_LOG_HELPER_EXECUTE(PH_LOG_OPTION_CATEGORY_ENTER);

    /* Component Code Validation */
    if(PH_GET_COMPCODE(pDataParams) != PH_COMP_AL_MFDUOX)
    {
        PH_LOG_HELPER_ADDSTRING(PH_LOG_LOGTYPE_INFO, bFunctionName);
        PH_LOG_HELPER_ADDPARAM_UINT16(PH_LOG_LOGTYPE_INFO, PH_LOG_VAR(wStatus), &wStatus);
        PH_LOG_HELPER_EXECUTE(PH_LOG_OPTION_CATEGORY_LEAVE);

        return PH_ADD_COMPCODE(PH_ERR_INVALID_DATA_PARAMS, PH_COMP_AL_MFDUOX);
    }

    /* Perform operation on active layer */
    switch(PH_GET_COMPID(pDataParams))
    {
#ifdef NXPBUILD__PHAL_MFDUOX_SW
        case PHAL_MFDUOX_SW_ID:
            wStatus = phalMfDuoX_Sw_IsoGetChallenge((phalMfDuoX_Sw_DataParams_t *) pDataParams, bExpRsp, bExtendedLenApdu, ppResponse, pRspLen);
            break;
#endif /* NXPBUILD__PHAL_MFDUOX_SW */

        default:
            wStatus = PH_ADD_COMPCODE(PH_ERR_INVALID_DATA_PARAMS, PH_COMP_AL_MFDUOX);
            break;
    }

    PH_LOG_HELPER_ADDSTRING(PH_LOG_LOGTYPE_INFO, bFunctionName);
#ifdef NXPBUILD__PH_LOG
    if((wStatus & PH_ERR_MASK) == PH_ERR_SUCCESS)
    {
        PH_LOG_HELPER_ADDPARAM_BUFFER(PH_LOG_LOGTYPE_DEBUG, PH_LOG_VAR(ppResponse), *ppResponse, *pRspLen);
        PH_LOG_HELPER_ADDPARAM_UINT16(PH_LOG_LOGTYPE_DEBUG, PH_LOG_VAR(pRspLen), pRspLen);
    }
#endif /* NXPBUILD__PH_LOG */
    PH_LOG_HELPER_ADDPARAM_UINT16(PH_LOG_LOGTYPE_INFO, PH_LOG_VAR(wStatus), &wStatus);
    PH_LOG_HELPER_EXECUTE(PH_LOG_OPTION_CATEGORY_LEAVE);

    return wStatus;
}

/* MIFARE DUOX EV Charging command ------------------------------------------------------------------------------------------------------ */
phStatus_t phalMfDuoX_VdeReadData(void * pDataParams, uint16_t wOption, uint8_t bFileNo, uint16_t wBytesToRead,
    uint8_t bExtendedLenApdu, uint8_t ** ppResponse, uint16_t * pRspLen)
{
    phStatus_t PH_MEMLOC_REM wStatus;

    PH_LOG_HELPER_ALLOCATE_TEXT(bFunctionName, "phalMfDuoX_VdeReadData");
    PH_LOG_HELPER_ALLOCATE_PARAMNAME(wStatus);
    PH_LOG_HELPER_ALLOCATE_PARAMNAME(wOption);
    PH_LOG_HELPER_ALLOCATE_PARAMNAME(bFileNo);
    PH_LOG_HELPER_ALLOCATE_PARAMNAME(wBytesToRead);
    PH_LOG_HELPER_ALLOCATE_PARAMNAME(bExtendedLenApdu);
    PH_LOG_HELPER_ALLOCATE_PARAMNAME(ppResponse);
    PH_LOG_HELPER_ALLOCATE_PARAMNAME(pRspLen);

    /* Validate the parameters */
    PH_ASSERT_NULL_DATA_PARAM(pDataParams, PH_COMP_AL_MFDUOX);
    PH_ASSERT_NULL_PARAM(pRspLen, PH_COMP_AL_MFDUOX);

    /* Log the information. */
    PH_LOG_HELPER_ADDSTRING(PH_LOG_LOGTYPE_INFO, bFunctionName);
    PH_LOG_HELPER_ADDPARAM_UINT16(PH_LOG_LOGTYPE_DEBUG, PH_LOG_VAR(wOption), &wOption);
    PH_LOG_HELPER_ADDPARAM_UINT8(PH_LOG_LOGTYPE_DEBUG, PH_LOG_VAR(bFileNo), &bFileNo);
    PH_LOG_HELPER_ADDPARAM_UINT16(PH_LOG_LOGTYPE_DEBUG, PH_LOG_VAR(wBytesToRead), &wBytesToRead);
    PH_LOG_HELPER_ADDPARAM_UINT8(PH_LOG_LOGTYPE_DEBUG, PH_LOG_VAR(bExtendedLenApdu), &bExtendedLenApdu);
    PH_LOG_HELPER_EXECUTE(PH_LOG_OPTION_CATEGORY_ENTER);

    /* Component Code Validation */
    if(PH_GET_COMPCODE(pDataParams) != PH_COMP_AL_MFDUOX)
    {
        PH_LOG_HELPER_ADDSTRING(PH_LOG_LOGTYPE_INFO, bFunctionName);
        PH_LOG_HELPER_ADDPARAM_UINT16(PH_LOG_LOGTYPE_INFO, PH_LOG_VAR(wStatus), &wStatus);
        PH_LOG_HELPER_EXECUTE(PH_LOG_OPTION_CATEGORY_LEAVE);

        return PH_ADD_COMPCODE(PH_ERR_INVALID_DATA_PARAMS, PH_COMP_AL_MFDUOX);
    }

    /* Perform operation on active layer */
    switch(PH_GET_COMPID(pDataParams))
    {
#ifdef NXPBUILD__PHAL_MFDUOX_SW
        case PHAL_MFDUOX_SW_ID:
            wStatus = phalMfDuoX_Sw_VdeReadData((phalMfDuoX_Sw_DataParams_t *) pDataParams, wOption, bFileNo, wBytesToRead,
                bExtendedLenApdu, ppResponse, pRspLen);
            break;
#endif /* NXPBUILD__PHAL_MFDUOX_SW */

        default:
            wStatus = PH_ADD_COMPCODE(PH_ERR_INVALID_DATA_PARAMS, PH_COMP_AL_MFDUOX);
            break;
    }

    PH_LOG_HELPER_ADDSTRING(PH_LOG_LOGTYPE_INFO, bFunctionName);
#ifdef NXPBUILD__PH_LOG
    if((wStatus & PH_ERR_MASK) == PH_ERR_SUCCESS)
    {
        PH_LOG_HELPER_ADDPARAM_BUFFER(PH_LOG_LOGTYPE_DEBUG, PH_LOG_VAR(ppResponse), *ppResponse, *pRspLen);
        PH_LOG_HELPER_ADDPARAM_UINT16(PH_LOG_LOGTYPE_DEBUG, PH_LOG_VAR(pRspLen), pRspLen);
    }
#endif /* NXPBUILD__PH_LOG */
    PH_LOG_HELPER_ADDPARAM_UINT16(PH_LOG_LOGTYPE_INFO, PH_LOG_VAR(wStatus), &wStatus);
    PH_LOG_HELPER_EXECUTE(PH_LOG_OPTION_CATEGORY_LEAVE);

    return wStatus;
}

phStatus_t phalMfDuoX_VdeWriteData(void * pDataParams, uint8_t bOperation, uint8_t bExtendedLenApdu, uint8_t * pData,
    uint16_t wDataLen)
{
    phStatus_t PH_MEMLOC_REM wStatus;

    PH_LOG_HELPER_ALLOCATE_TEXT(bFunctionName, "phalMfDuoX_VdeWriteData");
    PH_LOG_HELPER_ALLOCATE_PARAMNAME(wStatus);
    PH_LOG_HELPER_ALLOCATE_PARAMNAME(bOperation);
    PH_LOG_HELPER_ALLOCATE_PARAMNAME(bExtendedLenApdu);
    PH_LOG_HELPER_ALLOCATE_PARAMNAME(pData);
    PH_LOG_HELPER_ALLOCATE_PARAMNAME(wDataLen);

    /* Validate the parameters */
    PH_ASSERT_NULL_DATA_PARAM(pDataParams, PH_COMP_AL_MFDUOX);
    if(wDataLen) PH_ASSERT_NULL_PARAM(pData, PH_COMP_AL_MFDUOX);

    /* Log the information. */
    PH_LOG_HELPER_ADDSTRING(PH_LOG_LOGTYPE_INFO, bFunctionName);
    PH_LOG_HELPER_ADDPARAM_UINT8(PH_LOG_LOGTYPE_DEBUG, PH_LOG_VAR(bOperation), &bOperation);
    PH_LOG_HELPER_ADDPARAM_UINT8(PH_LOG_LOGTYPE_DEBUG, PH_LOG_VAR(bExtendedLenApdu), &bExtendedLenApdu);
    PH_LOG_HELPER_ADDPARAM_BUFFER(PH_LOG_LOGTYPE_DEBUG, PH_LOG_VAR(pData), pData, wDataLen);
    PH_LOG_HELPER_ADDPARAM_UINT16(PH_LOG_LOGTYPE_DEBUG, PH_LOG_VAR(wDataLen), &wDataLen);
    PH_LOG_HELPER_EXECUTE(PH_LOG_OPTION_CATEGORY_ENTER);

    /* Component Code Validation */
    if(PH_GET_COMPCODE(pDataParams) != PH_COMP_AL_MFDUOX)
    {
        PH_LOG_HELPER_ADDSTRING(PH_LOG_LOGTYPE_INFO, bFunctionName);
        PH_LOG_HELPER_ADDPARAM_UINT16(PH_LOG_LOGTYPE_INFO, PH_LOG_VAR(wStatus), &wStatus);
        PH_LOG_HELPER_EXECUTE(PH_LOG_OPTION_CATEGORY_LEAVE);

        return PH_ADD_COMPCODE(PH_ERR_INVALID_DATA_PARAMS, PH_COMP_AL_MFDUOX);
    }

    /* Perform operation on active layer */
    switch(PH_GET_COMPID(pDataParams))
    {
#ifdef NXPBUILD__PHAL_MFDUOX_SW
        case PHAL_MFDUOX_SW_ID:
            wStatus = phalMfDuoX_Sw_VdeWriteData((phalMfDuoX_Sw_DataParams_t *) pDataParams, bOperation, bExtendedLenApdu, pData, wDataLen);
            break;
#endif /* NXPBUILD__PHAL_MFDUOX_SW */

        default:
            wStatus = PH_ADD_COMPCODE(PH_ERR_INVALID_DATA_PARAMS, PH_COMP_AL_MFDUOX);
            break;
    }

    PH_LOG_HELPER_ADDSTRING(PH_LOG_LOGTYPE_INFO, bFunctionName);
    PH_LOG_HELPER_ADDPARAM_UINT16(PH_LOG_LOGTYPE_INFO, PH_LOG_VAR(wStatus), &wStatus);
    PH_LOG_HELPER_EXECUTE(PH_LOG_OPTION_CATEGORY_LEAVE);

    return wStatus;
}

phStatus_t phalMfDuoX_VdeECDSASign(void * pDataParams, uint16_t wBytesToRead, uint8_t bExtendedLenApdu, uint8_t * pData,
    uint16_t wDataLen, uint8_t ** ppResponse, uint16_t * pRspLen)
{
    phStatus_t PH_MEMLOC_REM wStatus;

    PH_LOG_HELPER_ALLOCATE_TEXT(bFunctionName, "phalMfDuoX_VdeECDSASign");
    PH_LOG_HELPER_ALLOCATE_PARAMNAME(wStatus);
    PH_LOG_HELPER_ALLOCATE_PARAMNAME(wBytesToRead);
    PH_LOG_HELPER_ALLOCATE_PARAMNAME(bExtendedLenApdu);
    PH_LOG_HELPER_ALLOCATE_PARAMNAME(pData);
    PH_LOG_HELPER_ALLOCATE_PARAMNAME(wDataLen);
    PH_LOG_HELPER_ALLOCATE_PARAMNAME(ppResponse);
    PH_LOG_HELPER_ALLOCATE_PARAMNAME(pRspLen);

    /* Validate the parameters */
    PH_ASSERT_NULL_DATA_PARAM(pDataParams, PH_COMP_AL_MFDUOX);
    if(wDataLen) PH_ASSERT_NULL_PARAM(pData, PH_COMP_AL_MFDUOX);
    PH_ASSERT_NULL_PARAM(pRspLen, PH_COMP_AL_MFDUOX);

    /* Log the information. */
    PH_LOG_HELPER_ADDSTRING(PH_LOG_LOGTYPE_INFO, bFunctionName);
    PH_LOG_HELPER_ADDPARAM_UINT16(PH_LOG_LOGTYPE_DEBUG, PH_LOG_VAR(wBytesToRead), &wBytesToRead);
    PH_LOG_HELPER_ADDPARAM_UINT8(PH_LOG_LOGTYPE_DEBUG, PH_LOG_VAR(bExtendedLenApdu), &bExtendedLenApdu);
    PH_LOG_HELPER_ADDPARAM_BUFFER(PH_LOG_LOGTYPE_DEBUG, PH_LOG_VAR(pData), pData, wDataLen);
    PH_LOG_HELPER_ADDPARAM_UINT16(PH_LOG_LOGTYPE_DEBUG, PH_LOG_VAR(wDataLen), &wDataLen);
    PH_LOG_HELPER_EXECUTE(PH_LOG_OPTION_CATEGORY_ENTER);

    /* Component Code Validation */
    if(PH_GET_COMPCODE(pDataParams) != PH_COMP_AL_MFDUOX)
    {
        PH_LOG_HELPER_ADDSTRING(PH_LOG_LOGTYPE_INFO, bFunctionName);
        PH_LOG_HELPER_ADDPARAM_UINT16(PH_LOG_LOGTYPE_INFO, PH_LOG_VAR(wStatus), &wStatus);
        PH_LOG_HELPER_EXECUTE(PH_LOG_OPTION_CATEGORY_LEAVE);

        return PH_ADD_COMPCODE(PH_ERR_INVALID_DATA_PARAMS, PH_COMP_AL_MFDUOX);
    }

    /* Perform operation on active layer */
    switch(PH_GET_COMPID(pDataParams))
    {
#ifdef NXPBUILD__PHAL_MFDUOX_SW
        case PHAL_MFDUOX_SW_ID:
            wStatus = phalMfDuoX_Sw_VdeECDSASign((phalMfDuoX_Sw_DataParams_t *) pDataParams, wBytesToRead, bExtendedLenApdu, pData,
                wDataLen, ppResponse, pRspLen);
            break;
#endif /* NXPBUILD__PHAL_MFDUOX_SW */

        default:
            wStatus = PH_ADD_COMPCODE(PH_ERR_INVALID_DATA_PARAMS, PH_COMP_AL_MFDUOX);
            break;
    }

    PH_LOG_HELPER_ADDSTRING(PH_LOG_LOGTYPE_INFO, bFunctionName);
#ifdef NXPBUILD__PH_LOG
    if((wStatus & PH_ERR_MASK) == PH_ERR_SUCCESS)
    {
        PH_LOG_HELPER_ADDPARAM_BUFFER(PH_LOG_LOGTYPE_DEBUG, PH_LOG_VAR(ppResponse), *ppResponse, *pRspLen);
        PH_LOG_HELPER_ADDPARAM_UINT16(PH_LOG_LOGTYPE_DEBUG, PH_LOG_VAR(pRspLen), pRspLen);
    }
#endif /* NXPBUILD__PH_LOG */
    PH_LOG_HELPER_ADDPARAM_UINT16(PH_LOG_LOGTYPE_INFO, PH_LOG_VAR(wStatus), &wStatus);
    PH_LOG_HELPER_EXECUTE(PH_LOG_OPTION_CATEGORY_LEAVE);

    return wStatus;
}

/* MIFARE DUOX Utility functions -------------------------------------------------------------------------------------------------------- */
phStatus_t phalMfDuoX_GetConfig(void * pDataParams, uint16_t wConfig, uint16_t * pValue)
{
    phStatus_t PH_MEMLOC_REM wStatus;

    PH_LOG_HELPER_ALLOCATE_TEXT(bFunctionName, "phalMfDuoX_GetConfig");
    PH_LOG_HELPER_ALLOCATE_PARAMNAME(wConfig);
    PH_LOG_HELPER_ALLOCATE_PARAMNAME(pValue);
    PH_LOG_HELPER_ALLOCATE_PARAMNAME(wStatus);
    PH_LOG_HELPER_ADDSTRING(PH_LOG_LOGTYPE_INFO, bFunctionName);
    PH_LOG_HELPER_ADDPARAM_UINT16(PH_LOG_LOGTYPE_DEBUG, PH_LOG_VAR(wConfig), &wConfig);
    PH_LOG_HELPER_EXECUTE(PH_LOG_OPTION_CATEGORY_ENTER);

    /* Validate the parameters */
    PH_ASSERT_NULL_DATA_PARAM(pDataParams, PH_COMP_AL_MFDUOX);
    PH_ASSERT_NULL_PARAM(pValue, PH_COMP_AL_MFDUOX);

    /* Check data parameters */
    if(PH_GET_COMPCODE(pDataParams) != PH_COMP_AL_MFDUOX)
    {
        PH_LOG_HELPER_ADDSTRING(PH_LOG_LOGTYPE_INFO, bFunctionName);
        PH_LOG_HELPER_ADDPARAM_UINT16(PH_LOG_LOGTYPE_INFO, PH_LOG_VAR(wStatus), &wStatus);
        PH_LOG_HELPER_EXECUTE(PH_LOG_OPTION_CATEGORY_LEAVE);

        return PH_ADD_COMPCODE(PH_ERR_INVALID_DATA_PARAMS, PH_COMP_AL_MFDUOX);
    }

    /* Perform operation on active layer */
    switch(PH_GET_COMPID(pDataParams))
    {
#ifdef NXPBUILD__PHAL_MFDUOX_SW
        case PHAL_MFDUOX_SW_ID:
            wStatus = phalMfDuoX_Sw_GetConfig((phalMfDuoX_Sw_DataParams_t *) pDataParams, wConfig, pValue);
            break;
#endif /* NXPBUILD__PHAL_MFDUOX_SW */

        default:
            wStatus = PH_ADD_COMPCODE(PH_ERR_INVALID_DATA_PARAMS, PH_COMP_AL_MFDUOX);
            break;
    }

    PH_LOG_HELPER_ADDSTRING(PH_LOG_LOGTYPE_INFO, bFunctionName);
#ifdef NXPBUILD__PH_LOG
    if((wStatus & PH_ERR_MASK) == PH_ERR_SUCCESS)
    {
        PH_LOG_HELPER_ADDPARAM_UINT16(PH_LOG_LOGTYPE_DEBUG, PH_LOG_VAR(pValue), pValue);
    }
#endif /* NXPBUILD__PH_LOG */
    PH_LOG_HELPER_ADDPARAM_UINT16(PH_LOG_LOGTYPE_INFO, PH_LOG_VAR(wStatus), &wStatus);
    PH_LOG_HELPER_EXECUTE(PH_LOG_OPTION_CATEGORY_LEAVE);

    return wStatus;
}

phStatus_t phalMfDuoX_SetConfig(void * pDataParams, uint16_t wConfig, uint16_t wValue)
{
    phStatus_t PH_MEMLOC_REM wStatus;

    PH_LOG_HELPER_ALLOCATE_TEXT(bFunctionName, "phalMfDuoX_SetConfig");
    PH_LOG_HELPER_ALLOCATE_PARAMNAME(wConfig);
    PH_LOG_HELPER_ALLOCATE_PARAMNAME(wValue);
    PH_LOG_HELPER_ALLOCATE_PARAMNAME(wStatus);
    PH_LOG_HELPER_ADDSTRING(PH_LOG_LOGTYPE_INFO, bFunctionName);
    PH_LOG_HELPER_ADDPARAM_UINT16(PH_LOG_LOGTYPE_DEBUG, PH_LOG_VAR(wConfig), &wConfig);
    PH_LOG_HELPER_ADDPARAM_UINT16(PH_LOG_LOGTYPE_DEBUG, PH_LOG_VAR(wValue), &wValue);
    PH_LOG_HELPER_EXECUTE(PH_LOG_OPTION_CATEGORY_ENTER);

    /* Validate the parameters */
    PH_ASSERT_NULL_DATA_PARAM(pDataParams, PH_COMP_AL_MFDUOX);

    /* Check data parameters */
    if(PH_GET_COMPCODE(pDataParams) != PH_COMP_AL_MFDUOX)
    {
        PH_LOG_HELPER_ADDSTRING(PH_LOG_LOGTYPE_INFO, bFunctionName);
        PH_LOG_HELPER_ADDPARAM_UINT16(PH_LOG_LOGTYPE_INFO, PH_LOG_VAR(wStatus), &wStatus);
        PH_LOG_HELPER_EXECUTE(PH_LOG_OPTION_CATEGORY_LEAVE);

        return PH_ADD_COMPCODE(PH_ERR_INVALID_DATA_PARAMS, PH_COMP_AL_MFDUOX);
    }

    /* Perform operation on active layer */
    switch(PH_GET_COMPID(pDataParams))
    {
#ifdef NXPBUILD__PHAL_MFDUOX_SW
        case PHAL_MFDUOX_SW_ID:
            wStatus = phalMfDuoX_Sw_SetConfig((phalMfDuoX_Sw_DataParams_t *) pDataParams, wConfig, wValue);
            break;
#endif /* NXPBUILD__PHAL_MFDUOX_SW */

        default:
            wStatus = PH_ADD_COMPCODE(PH_ERR_INVALID_DATA_PARAMS, PH_COMP_AL_MFDUOX);
            break;
    }

    PH_LOG_HELPER_ADDSTRING(PH_LOG_LOGTYPE_INFO, bFunctionName);

    PH_LOG_HELPER_ADDPARAM_UINT16(PH_LOG_LOGTYPE_INFO, PH_LOG_VAR(wStatus), &wStatus);
    PH_LOG_HELPER_EXECUTE(PH_LOG_OPTION_CATEGORY_LEAVE);

    return wStatus;
}

phStatus_t phalMfDuoX_ResetAuthentication(void * pDataParams)
{
    phStatus_t PH_MEMLOC_REM wStatus;

    PH_LOG_HELPER_ALLOCATE_TEXT(bFunctionName, "phalMfDuoX_ResetAuthentication");
    PH_LOG_HELPER_ALLOCATE_PARAMNAME(wStatus);
    PH_LOG_HELPER_ADDSTRING(PH_LOG_LOGTYPE_INFO, bFunctionName);
    PH_LOG_HELPER_EXECUTE(PH_LOG_OPTION_CATEGORY_ENTER);

    /* Validate the parameters */
    PH_ASSERT_NULL_DATA_PARAM(pDataParams, PH_COMP_AL_MFDUOX);

    /* Check data parameters */
    if(PH_GET_COMPCODE(pDataParams) != PH_COMP_AL_MFDUOX)
    {
        PH_LOG_HELPER_ADDSTRING(PH_LOG_LOGTYPE_INFO, bFunctionName);
        PH_LOG_HELPER_ADDPARAM_UINT16(PH_LOG_LOGTYPE_INFO, PH_LOG_VAR(wStatus), &wStatus);
        PH_LOG_HELPER_EXECUTE(PH_LOG_OPTION_CATEGORY_LEAVE);

        return PH_ADD_COMPCODE(PH_ERR_INVALID_DATA_PARAMS, PH_COMP_AL_MFDUOX);
    }

    /* Perform operation on active layer */
    switch(PH_GET_COMPID(pDataParams))
    {
#ifdef NXPBUILD__PHAL_MFDUOX_SW
        case PHAL_MFDUOX_SW_ID:
            wStatus = phalMfDuoX_Sw_ResetAuthentication((phalMfDuoX_Sw_DataParams_t *) pDataParams);
            break;
#endif /* NXPBUILD__PHAL_MFDUOX_SW */

        default:
            wStatus = PH_ADD_COMPCODE(PH_ERR_INVALID_DATA_PARAMS, PH_COMP_AL_MFDUOX);
            break;
    }
    PH_LOG_HELPER_ADDSTRING(PH_LOG_LOGTYPE_INFO, bFunctionName);

    PH_LOG_HELPER_ADDPARAM_UINT16(PH_LOG_LOGTYPE_INFO, PH_LOG_VAR(wStatus), &wStatus);
    PH_LOG_HELPER_EXECUTE(PH_LOG_OPTION_CATEGORY_LEAVE);

    return wStatus;
}

#endif /* NXPBUILD__PHAL_MFDUOX */
