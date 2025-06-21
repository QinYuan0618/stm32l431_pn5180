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
* Software implementation of MIFARE DUOX application layer.
* $Author: NXP $
* $Revision: $ (v07.13.00)
* $Date: $
*
*/

#include <ph_Status.h>

#ifdef NXPBUILD__PHAL_MFDUOX_SW
#include <string.h>
#include <stdlib.h>
#include <phTools.h>
#include <phKeyStore.h>
#include <phCryptoASym.h>
#include <phCryptoSym.h>
#include <phCryptoRng.h>

#ifdef NXPBUILD__PHAL_VCA
#include <phalVca.h>
#endif /* NXPBUILD__PHAL_VCA */
#include <phalMfDuoX.h>
#include "../phalMfDuoX_Int.h"
#include "phalMfDuoX_Sw.h"
#include "phalMfDuoX_Sw_Int.h"

phStatus_t phalMfDuoX_Sw_Init(phalMfDuoX_Sw_DataParams_t * pDataParams, uint16_t wSizeOfDataParams, void * pPalMifareDataParams,
    void * pKeyStoreDataParams, void * pCryptoDataParamsASym, void * pCryptoDataParamsEnc, void * pCryptoDataParamsMac,
    void * pCryptoRngDataParams, void * pTMIDataParams, void * pVCADataParams, uint8_t * pCmdBuf, uint16_t wCmdBufSize,
    uint8_t * pPrsBuf, uint16_t wPrsBufSize)
{
    /* DataParams Size Validation */
    if(sizeof(phalMfDuoX_Sw_DataParams_t) != wSizeOfDataParams)
    {
        return PH_ADD_COMPCODE(PH_ERR_INVALID_DATA_PARAMS, PH_COMP_AL_MFDUOX);
    }

    PH_ASSERT_NULL_DATA_PARAM(pDataParams, PH_COMP_AL_MFDUOX);
    PH_ASSERT_NULL_DATA_PARAM(pPalMifareDataParams, PH_COMP_AL_MFDUOX);
    PH_ASSERT_NULL_DATA_PARAM(pKeyStoreDataParams, PH_COMP_AL_MFDUOX);
    PH_ASSERT_NULL_DATA_PARAM(pCryptoDataParamsASym, PH_COMP_AL_MFDUOX);
    PH_ASSERT_NULL_DATA_PARAM(pCryptoDataParamsEnc, PH_COMP_AL_MFDUOX);
    PH_ASSERT_NULL_DATA_PARAM(pCryptoDataParamsMac, PH_COMP_AL_MFDUOX);
    PH_ASSERT_NULL_DATA_PARAM(pCryptoRngDataParams, PH_COMP_AL_MFDUOX);
#ifdef NXPBUILD__PH_TMIUTILS
    PH_ASSERT_NULL_DATA_PARAM(pTMIDataParams, PH_COMP_AL_MFDUOX);
#endif /* NXPBUILD__PH_TMIUTILS */
#ifdef NXPBUILD__PHAL_VCA
    PH_ASSERT_NULL_DATA_PARAM(pVCADataParams, PH_COMP_AL_MFDUOX);
#endif /* NXPBUILD__PHAL_VCA */

    PH_ASSERT_NULL_PARAM(pCmdBuf, PH_COMP_AL_MFDUOX);
    PH_ASSERT_NULL_PARAM(pPrsBuf, PH_COMP_AL_MFDUOX);

    if(wCmdBufSize < PHAL_MFDUOX_CMD_BUFFER_SIZE_MINIMUM)
        return PH_ADD_COMPCODE(PH_ERR_PARAMETER_SIZE, PH_COMP_AL_MFDUOX);

    if(wPrsBufSize < PHAL_MFDUOX_PRS_BUFFER_SIZE_MINIMUM)
        return PH_ADD_COMPCODE(PH_ERR_PARAMETER_SIZE, PH_COMP_AL_MFDUOX);

    if(wPrsBufSize < wCmdBufSize)
        return PH_ADD_COMPCODE(PH_ERR_PARAMETER_SIZE, PH_COMP_AL_MFDUOX);

    pDataParams->wId = PH_COMP_AL_MFDUOX | PHAL_MFDUOX_SW_ID;

    pDataParams->pPalMifareDataParams = pPalMifareDataParams;
    pDataParams->pKeyStoreDataParams = pKeyStoreDataParams;
    pDataParams->pCryptoDataParamsASym = pCryptoDataParamsASym;
    pDataParams->pCryptoDataParamsEnc = pCryptoDataParamsEnc;
    pDataParams->pCryptoDataParamsMac = pCryptoDataParamsMac;
    pDataParams->pCryptoRngDataParams = pCryptoRngDataParams;
    PH_UNUSED_VARIABLE(pCryptoDataParamsASym);
    PH_UNUSED_VARIABLE(pCryptoDataParamsEnc);
    PH_UNUSED_VARIABLE(pCryptoDataParamsMac);
    PH_UNUSED_VARIABLE(pCryptoRngDataParams);

#ifdef NXPBUILD__PH_TMIUTILS
    pDataParams->pTMIDataParams = pTMIDataParams;
#endif /* NXPBUILD__PH_TMIUTILS */
#ifdef NXPBUILD__PHAL_VCA
    pDataParams->pVCADataParams = pVCADataParams;
#endif /* NXPBUILD__PHAL_VCA */

    pDataParams->pCmdBuf = pCmdBuf;
    pDataParams->wCmdBufSize = wCmdBufSize;
    pDataParams->wCmdBufLen = 0;
    pDataParams->wCmdBufOffset = 0;

    pDataParams->pPrsBuf = pPrsBuf;
    pDataParams->wPrsBufSize = wPrsBufSize;
    pDataParams->wPrsBufLen = 0;
    pDataParams->wPrsBufOffset = 0;

    (void) memset(pCmdBuf, 0x00, PHAL_MFDUOX_CMD_BUFFER_SIZE_MINIMUM);
    (void) memset(pPrsBuf, 0x00, PHAL_MFDUOX_PRS_BUFFER_SIZE_MINIMUM);
    (void) memset(pDataParams->aAid, 0x00, 3);

    pDataParams->wCmdCtr = 0;
    pDataParams->wAdditionalInfo = 0x0000;
    pDataParams->bWrappedMode = PH_OFF;
    pDataParams->bShortLenApdu = PH_ON;                        /* By default, short length APDU format is used. */
    pDataParams->bCmdCode = PHAL_MFDUOX_CMD_INVALID;
    pDataParams->bAuthState = PHAL_MFDUOX_NOT_AUTHENTICATED;
    pDataParams->bKeyNo = 0xFF;
    pDataParams->bPICCDataComplete = PH_OFF;

    return PH_ADD_COMPCODE(PH_ERR_SUCCESS, PH_COMP_AL_MFDUOX);
}

phStatus_t phalMfDuoX_Sw_DeInit(phalMfDuoX_Sw_DataParams_t * pDataParams)
{
    phalMfDuoX_Sw_ResetAuthentication(pDataParams);

    pDataParams->wCmdBufSize = 0;
    pDataParams->wPrsBufSize = 0;

    return PH_ADD_COMPCODE(PH_ERR_SUCCESS, PH_COMP_AL_MFDUOX);
}

phStatus_t phalMfDuoX_Sw_ISOInternalAuthenticate(phalMfDuoX_Sw_DataParams_t * pDataParams, uint8_t bPrivKeyNo, uint8_t bCurveID,
    uint8_t * pPubBKey, uint16_t wPubBKeyLen, uint8_t * pOptsA, uint8_t bOptsALen, uint8_t * pExpRspLen, uint8_t bExpRspLen)
{
    phStatus_t  PH_MEMLOC_REM wStatus = 0;
    phStatus_t  PH_MEMLOC_REM wStatus1 = 0;
    uint16_t    PH_MEMLOC_REM wRspLen = 0;
    uint16_t    PH_MEMLOC_REM wAPDU_Mode = 0;
    uint16_t    PH_MEMLOC_REM wIsShortLen = 0;
    uint16_t    PH_MEMLOC_REM wLC = 0;
    uint8_t     PH_MEMLOC_REM bLE_Len = 0;
    uint8_t     PH_MEMLOC_REM bRndALen = 0;
    uint8_t     PH_MEMLOC_REM bRndBLen = 0;
    uint8_t     PH_MEMLOC_REM bSigLen = 0;
    uint8_t     PH_MEMLOC_REM bOffset = 0;

    uint8_t     PH_MEMLOC_REM aLE[2];
    uint8_t     PH_MEMLOC_REM aCont[2] = { 0xF0, 0xF0 };
    uint8_t     PH_MEMLOC_REM *pRndA = NULL;
    uint8_t     PH_MEMLOC_REM *pRndB = NULL;
    uint8_t     PH_MEMLOC_REM *pSignature = NULL;
    uint8_t     PH_MEMLOC_REM *pResponse = NULL;

    /* Validate Curve ID */
    PHAL_MFDUOX_VALIDATE_CURVE(bCurveID);

    /* Clear LE buffer. */
    (void) memset(aLE, 0x00, sizeof(aLE));

    /* Get the current APDU format. */
    PH_CHECK_SUCCESS_FCT(wStatus, phalMfDuoX_Sw_GetConfig(pDataParams, PHAL_MFDUOX_WRAPPED_MODE, &wAPDU_Mode));
    PH_CHECK_SUCCESS_FCT(wStatus, phalMfDuoX_Sw_GetConfig(pDataParams, PHAL_MFDUOX_SHORT_LENGTH_APDU, &wIsShortLen));

    /* Disable Wrapped format.
     * This is required for internal PICC exchange interface to stop from framing the ISO7816 format.
     */
    PH_CHECK_SUCCESS_FCT(wStatus, phalMfDuoX_Sw_SetConfig(pDataParams, PHAL_MFDUOX_WRAPPED_MODE, PH_OFF));

    /* Compute LC */
    wLC = (uint16_t) (bOptsALen + 2U /* AuthDOHdr */ + 18U /* RndA TLV */);

    /* Update LE Length. */
    if(pExpRspLen != NULL)
    {
        bLE_Len = bExpRspLen;
        (void) memcpy(aLE, pExpRspLen, bLE_Len);
    }
    else
    {
        if(wIsShortLen == PH_ON)
        {
            bLE_Len = 1;
        }
        else
        {
            bLE_Len = 2;
        }

        /* Force Extend LE information to be exchanged if greater than 255 bytes. */
        if(wLC > 255U)
        {
            bExpRspLen = 2;
        }
    }

    /* Update Command code to DataParams. */
    pDataParams->bCmdCode = PHAL_MFDUOX_CMD_AUTHENTICATE_ISO_INTERNAL;

    /* Clear Buffers. */
    (void) memset(PHAL_MFDUOX_CMD_BUF, 0x00, PHAL_MFDUOX_CMD_BUF_SIZE);
    PHAL_MFDUOX_CMD_BUF_LEN = 0;

    (void) memset(PHAL_MFDUOX_PRS_BUF, 0x00, PHAL_MFDUOX_PRS_BUF_SIZE);
    PHAL_MFDUOX_CMD_BUF_LEN = 0;

    /* Set the pointer. */
    pRndA = &PHAL_MFDUOX_PRS_BUF[PHAL_MFDUOX_PRS_BUF_SIZE - (PH_CRYPTOSYM_AES256_KEY_SIZE * 4)];
    pRndB = &PHAL_MFDUOX_PRS_BUF[PHAL_MFDUOX_PRS_BUF_SIZE - (PH_CRYPTOSYM_AES256_KEY_SIZE * 3)];
    pSignature = &PHAL_MFDUOX_PRS_BUF[PHAL_MFDUOX_PRS_BUF_SIZE - (PH_CRYPTOSYM_AES256_KEY_SIZE * 2)];

    /* Frame Cmd.ISOInternal Authenticate command -------------------------------------------------------------------------------------- */
    PHAL_MFDUOX_CMD_BUF[PHAL_MFDUOX_CMD_BUF_LEN++] = PHAL_MFDUOX_ISO7816_GENERIC_CLA;
    PHAL_MFDUOX_CMD_BUF[PHAL_MFDUOX_CMD_BUF_LEN++] = PHAL_MFDUOX_CMD_AUTHENTICATE_ISO_INTERNAL;
    PHAL_MFDUOX_CMD_BUF[PHAL_MFDUOX_CMD_BUF_LEN++] = PHAL_MFDUOX_WRAPPEDAPDU_P1;
    PHAL_MFDUOX_CMD_BUF[PHAL_MFDUOX_CMD_BUF_LEN++] = bPrivKeyNo;

    /* Frame Extended LC. */
    if(bLE_Len > 1)
    {
        PHAL_MFDUOX_CMD_BUF[PHAL_MFDUOX_CMD_BUF_LEN++] = PHAL_MFDUOX_WRAPPEDAPDU_LC;
        PHAL_MFDUOX_CMD_BUF[PHAL_MFDUOX_CMD_BUF_LEN++] = (uint8_t) ((wLC & 0xFF00) >> 8);
    }
    PHAL_MFDUOX_CMD_BUF[PHAL_MFDUOX_CMD_BUF_LEN++] = (uint8_t) ((wLC & 0x00FF));

    /* Add Command information for exchange. */
    PH_CHECK_SUCCESS_FCT(wStatus, phalMfDuoX_Sw_Int_CardExchange(
        pDataParams,
        PH_EXCHANGE_BUFFER_FIRST,
        PHAL_MFDUOX_CHAINING_BIT_INVALID,
        PHAL_MFDUOX_OPTION_NONE,
        0,
        PH_OFF,
        PHAL_MFDUOX_CMD_BUF,
        PHAL_MFDUOX_CMD_BUF_LEN,
        NULL,
        NULL,
        NULL));

    /* Add OptsA information for exchange. */
    PH_CHECK_SUCCESS_FCT(wStatus, phalMfDuoX_Sw_Int_CardExchange(
        pDataParams,
        PH_EXCHANGE_BUFFER_CONT,
        PHAL_MFDUOX_CHAINING_BIT_INVALID,
        PHAL_MFDUOX_OPTION_NONE,
        0,
        PH_OFF,
        pOptsA,
        bOptsALen,
        NULL,
        NULL,
        NULL));

    /* Reset Command Buffer */
    PHAL_MFDUOX_CMD_BUF_LEN = 0;

    /* Generate RndA */
    PH_CHECK_SUCCESS_FCT(wStatus, phCryptoRng_Seed(pDataParams->pCryptoRngDataParams, pRndB, PH_CRYPTOSYM_AES_BLOCK_SIZE));
    PH_CHECK_SUCCESS_FCT(wStatus, phCryptoRng_Rnd(pDataParams->pCryptoRngDataParams, PH_CRYPTOSYM_AES_BLOCK_SIZE, pRndA));
    bRndALen = PH_CRYPTOSYM_AES_BLOCK_SIZE;

    /* Add AuthDOHdr (Authentication Data Object Header) to command buffer. */
    PHAL_MFDUOX_CMD_BUF[PHAL_MFDUOX_CMD_BUF_LEN++] = PHAL_MFDUOX_AUTH_ISO_INTERNAL_AUTH_DO_HDR_TAG;
    PHAL_MFDUOX_CMD_BUF[PHAL_MFDUOX_CMD_BUF_LEN++] = (uint8_t) (2U /* Tag (T) + Length (L) */ + bRndALen /* Length of RndA */);

    /* Add Authentication Data Object for RndA. */
    PHAL_MFDUOX_CMD_BUF[PHAL_MFDUOX_CMD_BUF_LEN++] = PHAL_MFDUOX_AUTH_ISO_INTERNAL_RND_TAG;
    PHAL_MFDUOX_CMD_BUF[PHAL_MFDUOX_CMD_BUF_LEN++] = bRndALen;

    /* Copy RndA to command buffer. */
    (void) memcpy(&PHAL_MFDUOX_CMD_BUF[PHAL_MFDUOX_CMD_BUF_LEN], pRndA, bRndALen);
    PHAL_MFDUOX_CMD_BUF_LEN += bRndALen;

    /* Add LE. */
    (void) memcpy(&PHAL_MFDUOX_CMD_BUF[PHAL_MFDUOX_CMD_BUF_LEN], aLE, bLE_Len);
    PHAL_MFDUOX_CMD_BUF_LEN += bLE_Len;

    /* Exchange command to PICC ---------------------------------------------------------------------------------------------------- */
    PH_CHECK_SUCCESS_FCT(wStatus, phalMfDuoX_Sw_Int_CardExchange(
        pDataParams,
        PH_EXCHANGE_BUFFER_LAST,
        PHAL_MFDUOX_CHAINING_BIT_INVALID,
        (uint8_t) (PHAL_MFDUOX_OPTION_COMPLETE | PHAL_MFDUOX_PICC_STATUS_WRAPPED),
        0,
        PH_OFF,
        PHAL_MFDUOX_CMD_BUF,
        PHAL_MFDUOX_CMD_BUF_LEN,
        &pResponse,
        &wRspLen,
        NULL));

    /* Validate AuthDOHdr from response. */
    if(pResponse[bOffset] != PHAL_MFDUOX_AUTH_ISO_INTERNAL_AUTH_DO_HDR_TAG)
        return PH_ADD_COMPCODE(PH_ERR_PROTOCOL_ERROR, PH_COMP_AL_MFDUOX);
    bOffset = 2 /* AuthDOHdr TL */;

    /* Validate Tag information from RndB TLV */
    if(pResponse[bOffset++] != PHAL_MFDUOX_AUTH_ISO_INTERNAL_RND_TAG)
        return PH_ADD_COMPCODE(PH_ERR_PROTOCOL_ERROR, PH_COMP_AL_MFDUOX);

    /* Extract RndB information. */
    bRndBLen = pResponse[bOffset++];
    (void) memcpy(pRndB, &pResponse[bOffset], bRndBLen);
    bOffset += bRndBLen;

    /* Validate Tag information from Signature TLV */
    if(pResponse[bOffset++] != PHAL_MFDUOX_AUTH_ISO_INTERNAL_SIGNATURE_TAG)
        return PH_ADD_COMPCODE(PH_ERR_PROTOCOL_ERROR, PH_COMP_AL_MFDUOX);

    /* Extract Signature information. */
    bSigLen = pResponse[bOffset++];
    (void) memcpy(pSignature, &pResponse[bOffset], bSigLen);

    /* Load public Key to ASymmetric Crypto component ---------------------------------------------------------------------------------- */
    /* Update CurveID based on CryptoASym component. */
    bCurveID = (uint8_t) ((bCurveID == PHAL_MFDUOX_TARGET_CURVE_ID_NIST_P256) ? PH_CRYPTOASYM_CURVE_ID_SECP256R1 :
        PH_CRYPTOASYM_CURVE_ID_BRAINPOOL256R1);

    /* Load Public Key for verification. */
    PH_CHECK_SUCCESS_FCT(wStatus, phCryptoASym_ECC_LoadKeyDirect(
        pDataParams->pCryptoDataParamsASym,
        (uint16_t) (PH_CRYPTOASYM_PUBLIC_KEY | bCurveID),
        pPubBKey,
        wPubBKeyLen));

    /* Verify the Signature ------------------------------------------------------------------------------------------------------------ */

    /* Add Constant for Hashing. */
    PH_CHECK_SUCCESS_FCT(wStatus, phCryptoASym_ECC_Verify(
        pDataParams->pCryptoDataParamsASym,
        PH_EXCHANGE_BUFFER_FIRST,
        PH_CRYPTOASYM_HASH_ALGO_SHA256,
        aCont,
        2,
        NULL,
        0));

    /* Add Opts.A for Hashing. */
    PH_CHECK_SUCCESS_FCT(wStatus, phCryptoASym_ECC_Verify(
        pDataParams->pCryptoDataParamsASym,
        PH_EXCHANGE_BUFFER_CONT,
        PH_CRYPTOASYM_HASH_ALGO_SHA256,
        pOptsA,
        bOptsALen,
        NULL,
        0));

    /* Add RndB for Hashing. */
    PH_CHECK_SUCCESS_FCT(wStatus, phCryptoASym_ECC_Verify(
        pDataParams->pCryptoDataParamsASym,
        PH_EXCHANGE_BUFFER_CONT,
        PH_CRYPTOASYM_HASH_ALGO_SHA256,
        pRndB,
        bRndBLen,
        NULL,
        0));

    /* Add RndA for Hashing and verify the signature. */
    PH_CHECK_SUCCESS_FCT(wStatus, phCryptoASym_ECC_Verify(
        pDataParams->pCryptoDataParamsASym,
        PH_EXCHANGE_BUFFER_LAST,
        PH_CRYPTOASYM_HASH_ALGO_SHA256,
        pRndA,
        bRndALen,
        pSignature,
        bSigLen));

    /* Revert back the APDU format. */
    PH_CHECK_SUCCESS_FCT(wStatus1, phalMfDuoX_Sw_SetConfig(pDataParams, PHAL_MFDUOX_WRAPPED_MODE, wAPDU_Mode));

    return wStatus;
}

/* MIFARE DUOX Memory and Configuration management commands ---------------------------------------------------------------------------- */
phStatus_t phalMfDuoX_Sw_FreeMem(phalMfDuoX_Sw_DataParams_t * pDataParams, uint8_t ** ppMemInfo, uint16_t * pMemInfoLen)
{
    phStatus_t  PH_MEMLOC_REM wStatus = 0;
    uint8_t     PH_MEMLOC_REM bComMode = 0;

    /* Set the DataParams with command code. */
    pDataParams->bCmdCode = PHAL_MFDUOX_CMD_FREE_MEM;

    /* Frame the communication mode to be applied. */
    phalMfDuoX_Int_GetCommMode(pDataParams->bAuthState, PHAL_MFDUOX_COMMUNICATION_INVALID,
        &bComMode);

    /* Clear Command Buffer */
    (void) memset(PHAL_MFDUOX_CMD_BUF, 0x00, PHAL_MFDUOX_CMD_BUF_SIZE);
    PHAL_MFDUOX_CMD_BUF_LEN = 0;

    /* Exchange Cmd.FreeMem information to PICC. */
    PH_CHECK_SUCCESS_FCT(wStatus, phalMfDuoX_Sw_Int_ReadData(
        pDataParams,
        PH_EXCHANGE_DEFAULT,
        PH_OFF,
        bComMode,
        bComMode,
        &pDataParams->bCmdCode,
        1U,
        PHAL_MFDUOX_DATA_TO_READ_UNKNOWN,
        ppMemInfo,
        pMemInfoLen));

    return PH_ADD_COMPCODE(PH_ERR_SUCCESS, PH_COMP_AL_MFDUOX);
}

phStatus_t phalMfDuoX_Sw_GetVersion(phalMfDuoX_Sw_DataParams_t * pDataParams, uint8_t bOption, uint8_t ** ppVerInfo,
    uint16_t * pVerInfoLen)
{
    phStatus_t  PH_MEMLOC_REM wStatus = 0;
    uint8_t     PH_MEMLOC_REM bComMode = 0;

    /* Set the DataParams with command code. */
    pDataParams->bCmdCode = PHAL_MFDUOX_CMD_GET_VERSION;

    /* Clear Command Buffer */
    (void) memset(PHAL_MFDUOX_CMD_BUF, 0x00, PHAL_MFDUOX_CMD_BUF_SIZE);
    PHAL_MFDUOX_CMD_BUF_LEN = 0;

    /* Frame the communication mode to be applied. */
    phalMfDuoX_Int_GetCommMode(pDataParams->bAuthState, PHAL_MFDUOX_COMMUNICATION_INVALID,
        &bComMode);

    /* Frame GetVersion command information. */
    PHAL_MFDUOX_CMD_BUF[PHAL_MFDUOX_CMD_BUF_LEN++] = PHAL_MFDUOX_CMD_GET_VERSION;

    /* Append Option information. */
    if(bOption != PHAL_MFDUOX_GET_VERSION_EXCLUDE_FAB_ID)
    {
        PHAL_MFDUOX_CMD_BUF[PHAL_MFDUOX_CMD_BUF_LEN++] = bOption;
    }

    /* Exchange Cmd.GetVersion information to PICC. */
    PH_CHECK_SUCCESS_FCT(wStatus, phalMfDuoX_Sw_Int_ReadData(
        pDataParams,
        PH_EXCHANGE_DEFAULT,
        PH_OFF,
        bComMode,
        bComMode,
        PHAL_MFDUOX_CMD_BUF,
        PHAL_MFDUOX_CMD_BUF_LEN,
        PHAL_MFDUOX_DATA_TO_READ_UNKNOWN,
        ppVerInfo,
        pVerInfoLen));

    return PH_ADD_COMPCODE(PH_ERR_SUCCESS, PH_COMP_AL_MFDUOX);
}

/* MIFARE DUOX Symmetric Key management commands --------------------------------------------------------------------------------------- */

phStatus_t phalMfDuoX_Sw_GetKeySettings(phalMfDuoX_Sw_DataParams_t * pDataParams, uint8_t bOption, uint8_t ** ppResponse,
    uint16_t * pRspLen)
{
    phStatus_t  PH_MEMLOC_REM wStatus = 0;
    uint8_t     PH_MEMLOC_REM bComMode = 0;

    /* Set the DataParams with command code. */
    pDataParams->bCmdCode = PHAL_MFDUOX_CMD_GET_KEY_SETTINGS;

    /* Frame the communication mode to be applied. */
    phalMfDuoX_Int_GetCommMode(pDataParams->bAuthState, PHAL_MFDUOX_COMMUNICATION_INVALID,
        &bComMode);

    /* Clear Buffers. */
    (void) memset(PHAL_MFDUOX_CMD_BUF, 0x00, PHAL_MFDUOX_CMD_BUF_SIZE);
    PHAL_MFDUOX_CMD_BUF_LEN = 0;

    /* Frame the command information. */
    PHAL_MFDUOX_CMD_BUF[PHAL_MFDUOX_CMD_BUF_LEN++] = PHAL_MFDUOX_CMD_GET_KEY_SETTINGS;

    /* Add Option information to command buffer. */
    if(bOption != PHAL_MFDUOX_KEY_SETTING_PICC_APPLICATION)
    {
        PHAL_MFDUOX_CMD_BUF[PHAL_MFDUOX_CMD_BUF_LEN++] = bOption;
    }

    /* Exchange Cmd.GetKeySettings information to PICC. */
    PH_CHECK_SUCCESS_FCT(wStatus, phalMfDuoX_Sw_Int_ReadData(
        pDataParams,
        PH_EXCHANGE_DEFAULT,
        PH_OFF,
        bComMode,
        bComMode,
        PHAL_MFDUOX_CMD_BUF,
        PHAL_MFDUOX_CMD_BUF_LEN,
        PHAL_MFDUOX_DATA_TO_READ_UNKNOWN,
        ppResponse,
        pRspLen));

    return PH_ADD_COMPCODE(PH_ERR_SUCCESS, PH_COMP_AL_MFDUOX);
}

/* MIFARE DUOX ASymmetric Key management commands -------------------------------------------------------------------------------------- */
phStatus_t phalMfDuoX_Sw_ManageKeyPair(phalMfDuoX_Sw_DataParams_t * pDataParams, uint8_t bComOption, uint8_t bKeyNo,
    uint8_t bOption, uint8_t bCurveID, uint8_t * pKeyPolicy, uint8_t bWriteAccess, uint32_t dwKUCLimit,
    uint16_t wPrivKey_No, uint16_t wPrivKey_Pos, uint8_t ** ppResponse, uint16_t *pRspLen)
{
    phStatus_t  PH_MEMLOC_REM wStatus = 0;
    uint16_t    PH_MEMLOC_REM wKeyType = 0;

    uint8_t *   PH_MEMLOC_REM pCmdData = NULL;
    uint16_t    PH_MEMLOC_REM wCmdData_Len = 0;

    /* Validate Communication Options. */
    PH_CHECK_SUCCESS_FCT(wStatus, phalMfDuoX_Int_Validate_ComOption(bComOption));

    /* Set the DataParams with command code. */
    pDataParams->bCmdCode = PHAL_MFDUOX_CMD_MANAGE_KEY_PAIR;

    /* Clear Buffers. */
    (void) memset(PHAL_MFDUOX_CMD_BUF, 0x00, PHAL_MFDUOX_CMD_BUF_SIZE);
    PHAL_MFDUOX_CMD_BUF_LEN = 0;

    /* Clear Buffers. */
    (void) memset(PHAL_MFDUOX_PRS_BUF, 0x00, PHAL_MFDUOX_PRS_BUF_SIZE);
    PHAL_MFDUOX_PRS_BUF_LEN = 0;

    /* Frame the command information. */
    PHAL_MFDUOX_CMD_BUF[PHAL_MFDUOX_CMD_BUF_LEN++] = PHAL_MFDUOX_CMD_MANAGE_KEY_PAIR;
    PHAL_MFDUOX_CMD_BUF[PHAL_MFDUOX_CMD_BUF_LEN++] = bKeyNo;
    PHAL_MFDUOX_CMD_BUF[PHAL_MFDUOX_CMD_BUF_LEN++] = bOption;
    PHAL_MFDUOX_CMD_BUF[PHAL_MFDUOX_CMD_BUF_LEN++] = bCurveID;
    PHAL_MFDUOX_CMD_BUF[PHAL_MFDUOX_CMD_BUF_LEN++] = pKeyPolicy[0];
    PHAL_MFDUOX_CMD_BUF[PHAL_MFDUOX_CMD_BUF_LEN++] = pKeyPolicy[1];
    PHAL_MFDUOX_CMD_BUF[PHAL_MFDUOX_CMD_BUF_LEN++] = bWriteAccess;

    /* Append the Key Usage Counter Limit. */
    (void) memcpy(&PHAL_MFDUOX_CMD_BUF[PHAL_MFDUOX_CMD_BUF_LEN], (uint8_t *) &dwKUCLimit, 4 );
    PHAL_MFDUOX_CMD_BUF_LEN += 4;

    /* Set buffer to use for Command Data. */
    pCmdData = &PHAL_MFDUOX_CMD_BUF[PHAL_MFDUOX_CMD_BUF_LEN];

    /* Add PrivateKey to command buffer. */
    if(bOption == PHAL_MFDUOX_TARGET_ACTION_IMPORT_PRIVATE_KEY)
    {
        /* Get the Private Key from KeyStore. */
        PH_CHECK_SUCCESS_FCT(wStatus, phKeyStore_GetKeyASym(
            pDataParams->pKeyStoreDataParams,
            wPrivKey_No,
            wPrivKey_Pos,
            PH_KEYSTORE_KEY_PAIR_PRIVATE,
            &wKeyType,
            &bCurveID,
            pCmdData,
            &wCmdData_Len));

        /* Verify the Key information. */
        if(wKeyType != PH_KEYSTORE_KEY_TYPE_ECC)
        {
            /* Clear Buffers. */
            (void) memset(PHAL_MFDUOX_CMD_BUF, 0x00, PHAL_MFDUOX_CMD_BUF_SIZE);
            PHAL_MFDUOX_CMD_BUF_LEN = 0;

            /* Clear Buffers. */
            (void) memset(PHAL_MFDUOX_PRS_BUF, 0x00, PHAL_MFDUOX_PRS_BUF_SIZE);
            PHAL_MFDUOX_PRS_BUF_LEN = 0;

            return PH_ADD_COMPCODE(PH_ERR_KEY, PH_COMP_AL_MFDUOX);
        }
        else
        {
            /* Do Nothing */
        }
    }

    /* Exchange Cmd.ManageKeyPair information to PICC. */
    PH_CHECK_SUCCESS_FCT(wStatus, phalMfDuoX_Sw_Int_WriteData(
        pDataParams,
        PH_OFF,
        bComOption,
        bComOption,
        PH_OFF,
        PHAL_MFDUOX_CMD_BUF,
        PHAL_MFDUOX_CMD_BUF_LEN,
        pCmdData,
        wCmdData_Len,
        ppResponse,
        pRspLen));

    return PH_ADD_COMPCODE(PH_ERR_SUCCESS, PH_COMP_AL_MFDUOX);
}

phStatus_t phalMfDuoX_Sw_ManageCARootKey(phalMfDuoX_Sw_DataParams_t * pDataParams, uint8_t bComOption, uint8_t bKeyNo,
    uint8_t bCurveID, uint8_t * pAccessRights, uint8_t bWriteAccess, uint8_t bReadAccess, uint8_t bCRLFile,
    uint8_t * pCRLFileAID, uint16_t wPubKey_No, uint16_t wPubKey_Pos, uint8_t * pIssuer, uint8_t bIssuerLen)
{
    phStatus_t  PH_MEMLOC_REM wStatus = 0;
    uint16_t    PH_MEMLOC_REM wKeyType = 0;

    uint8_t *   PH_MEMLOC_REM pCmdData = NULL;
    uint16_t    PH_MEMLOC_REM wCmdData_Len = 0;

    /* Validate Communication Options. */
    PH_CHECK_SUCCESS_FCT(wStatus, phalMfDuoX_Int_Validate_ComOption(bComOption));

    /* Check for Issuer pointer. */
    if(bIssuerLen)
        PH_ASSERT_NULL_PARAM(pIssuer, PH_COMP_AL_MFDUOX);

    /* Set the DataParams with command code. */
    pDataParams->bCmdCode = PHAL_MFDUOX_CMD_MANAGE_CA_ROOT_KEY;

    /* Clear Buffers. */
    (void) memset(PHAL_MFDUOX_CMD_BUF, 0x00, PHAL_MFDUOX_CMD_BUF_SIZE);
    PHAL_MFDUOX_CMD_BUF_LEN = 0;

    /* Clear Buffers. */
    (void) memset(PHAL_MFDUOX_PRS_BUF, 0x00, PHAL_MFDUOX_PRS_BUF_SIZE);
    PHAL_MFDUOX_PRS_BUF_LEN = 0;

    /* Frame the command information. */
    PHAL_MFDUOX_CMD_BUF[PHAL_MFDUOX_CMD_BUF_LEN++] = PHAL_MFDUOX_CMD_MANAGE_CA_ROOT_KEY;
    PHAL_MFDUOX_CMD_BUF[PHAL_MFDUOX_CMD_BUF_LEN++] = bKeyNo;
    PHAL_MFDUOX_CMD_BUF[PHAL_MFDUOX_CMD_BUF_LEN++] = bCurveID;
    PHAL_MFDUOX_CMD_BUF[PHAL_MFDUOX_CMD_BUF_LEN++] = pAccessRights[0];
    PHAL_MFDUOX_CMD_BUF[PHAL_MFDUOX_CMD_BUF_LEN++] = pAccessRights[1];
    PHAL_MFDUOX_CMD_BUF[PHAL_MFDUOX_CMD_BUF_LEN++] = bWriteAccess;
    PHAL_MFDUOX_CMD_BUF[PHAL_MFDUOX_CMD_BUF_LEN++] = bReadAccess;
    PHAL_MFDUOX_CMD_BUF[PHAL_MFDUOX_CMD_BUF_LEN++] = bCRLFile;

    /* Add Application ID to command buffer. */
    (void) memcpy(&PHAL_MFDUOX_CMD_BUF[PHAL_MFDUOX_CMD_BUF_LEN], pCRLFileAID, PHAL_MFDUOX_APP_ID_LEN);
    PHAL_MFDUOX_CMD_BUF_LEN += PHAL_MFDUOX_APP_ID_LEN;

    /* Set buffer to use for Command Data. */
    pCmdData = &PHAL_MFDUOX_CMD_BUF[PHAL_MFDUOX_CMD_BUF_LEN];

    /* Add PublicKey to command buffer. */
    PH_CHECK_SUCCESS_FCT(wStatus, phKeyStore_GetKeyASym(
        pDataParams->pKeyStoreDataParams,
        wPubKey_No,
        wPubKey_Pos,
        PH_KEYSTORE_KEY_PAIR_PUBLIC,
        &wKeyType,
        &bCurveID,
        pCmdData,
        &wCmdData_Len));

    /* Verify the Key information. */
    if(wKeyType != PH_KEYSTORE_KEY_TYPE_ECC)
    {
        /* Clear Buffers. */
        (void) memset(PHAL_MFDUOX_CMD_BUF, 0x00, PHAL_MFDUOX_CMD_BUF_SIZE);
        PHAL_MFDUOX_CMD_BUF_LEN = 0;

        /* Clear Buffers. */
        (void) memset(PHAL_MFDUOX_PRS_BUF, 0x00, PHAL_MFDUOX_PRS_BUF_SIZE);
        PHAL_MFDUOX_PRS_BUF_LEN = 0;

        return PH_ADD_COMPCODE(PH_ERR_KEY, PH_COMP_AL_MFDUOX);
    }
    else
    {
        /* Do nothing */
    }

    /* Add Issuer to Command buffer. */
    pCmdData[wCmdData_Len++] = bIssuerLen;

    (void) memcpy(&pCmdData[wCmdData_Len], pIssuer, bIssuerLen);
    wCmdData_Len += bIssuerLen;

    /* Exchange Cmd.ManageCARootKey information to PICC. */
    PH_CHECK_SUCCESS_FCT(wStatus, phalMfDuoX_Sw_Int_WriteData(
        pDataParams,
        PH_OFF,
        bComOption,
        bComOption,
        PH_OFF,
        PHAL_MFDUOX_CMD_BUF,
        PHAL_MFDUOX_CMD_BUF_LEN,
        pCmdData,
        wCmdData_Len,
        NULL,
        NULL));

    return PH_ADD_COMPCODE(PH_ERR_SUCCESS, PH_COMP_AL_MFDUOX);
}

phStatus_t phalMfDuoX_Sw_ExportKey(phalMfDuoX_Sw_DataParams_t * pDataParams, uint8_t bComOption, uint8_t bOption,
    uint8_t bKeyNo, uint8_t ** ppResponse, uint16_t *pRspLen)
{
    phStatus_t  PH_MEMLOC_REM wStatus = 0;
    uint8_t     PH_MEMLOC_REM bCmd_ComMode = 0;

    /* Validate Communication Options. */
    PH_CHECK_SUCCESS_FCT(wStatus, phalMfDuoX_Int_Validate_ComOption(bComOption));

    /* Set the DataParams with command code. */
    pDataParams->bCmdCode = PHAL_MFDUOX_CMD_MANAGE_EXPORT_KEY;

    /* Frame the communication mode to be applied. */
    phalMfDuoX_Int_GetCommMode(pDataParams->bAuthState, PHAL_MFDUOX_COMMUNICATION_INVALID,
        &bCmd_ComMode);

    /* Clear Buffers. */
    (void) memset(PHAL_MFDUOX_CMD_BUF, 0x00, PHAL_MFDUOX_CMD_BUF_SIZE);
    PHAL_MFDUOX_CMD_BUF_LEN = 0;

    /* Frame the command information. */
    PHAL_MFDUOX_CMD_BUF[PHAL_MFDUOX_CMD_BUF_LEN++] = PHAL_MFDUOX_CMD_MANAGE_EXPORT_KEY;
    PHAL_MFDUOX_CMD_BUF[PHAL_MFDUOX_CMD_BUF_LEN++] = bOption;
    PHAL_MFDUOX_CMD_BUF[PHAL_MFDUOX_CMD_BUF_LEN++] = bKeyNo;

    /* Exchange Cmd.ExportKey information to PICC. */
    PH_CHECK_SUCCESS_FCT(wStatus, phalMfDuoX_Sw_Int_ReadData(
        pDataParams,
        PH_EXCHANGE_DEFAULT,
        PH_OFF,
        bCmd_ComMode,
        bComOption,
        PHAL_MFDUOX_CMD_BUF,
        PHAL_MFDUOX_CMD_BUF_LEN,
        PHAL_MFDUOX_DATA_TO_READ_UNKNOWN,
        ppResponse,
        pRspLen));

    return PH_ADD_COMPCODE(PH_ERR_SUCCESS, PH_COMP_AL_MFDUOX);
}

/* MIFARE DUOX Application management commands ----------------------------------------------------------------------------------------- */
phStatus_t phalMfDuoX_Sw_CreateApplication(phalMfDuoX_Sw_DataParams_t * pDataParams, uint8_t bOption, uint8_t * pAid,
    uint8_t bKeySettings1, uint8_t bKeySettings2, uint8_t bKeySettings3, uint8_t * pKeySetValues, uint8_t bKeySetValuesLen,
    uint8_t * pISOFileId, uint8_t * pISODFName, uint8_t bISODFNameLen)
{
    phStatus_t  PH_MEMLOC_REM wStatus = 0;
    uint8_t     PH_MEMLOC_REM bComMode = 0;

#ifdef RDR_LIB_PARAM_CHECK
    if(((bOption & PHAL_MFDUOX_ISO_DF_NAME_AVAILABLE) && (bISODFNameLen > PHAL_MFDUOX_ISO_DFNAME_LEN))
        || (bOption > PHAL_MFDUOX_ISO_FILE_ID_DF_NAME_AVAILABLE))
    {
        return PH_ADD_COMPCODE(PH_ERR_INVALID_PARAMETER, PH_COMP_AL_MFDUOX);
    }
#endif

    /* Set the DataParams with command code. */
    pDataParams->bCmdCode = PHAL_MFDUOX_CMD_CREATE_APPLICATION;

    /* Frame the communication mode to be applied. */
    phalMfDuoX_Int_GetCommMode(pDataParams->bAuthState, PHAL_MFDUOX_COMMUNICATION_INVALID,
        &bComMode);

    /* Clear Buffers. */
    (void) memset(PHAL_MFDUOX_CMD_BUF, 0x00, PHAL_MFDUOX_CMD_BUF_SIZE);
    PHAL_MFDUOX_CMD_BUF_LEN = 0;

    /* Frame the command information. */
    PHAL_MFDUOX_CMD_BUF[PHAL_MFDUOX_CMD_BUF_LEN++] = PHAL_MFDUOX_CMD_CREATE_APPLICATION;

    /* Add Application ID to command buffer. */
    (void) memcpy(&PHAL_MFDUOX_CMD_BUF[PHAL_MFDUOX_CMD_BUF_LEN], pAid, PHAL_MFDUOX_APP_ID_LEN);
    PHAL_MFDUOX_CMD_BUF_LEN += PHAL_MFDUOX_APP_ID_LEN;

    /* Add Key Settings to command buffer. */
    PHAL_MFDUOX_CMD_BUF[PHAL_MFDUOX_CMD_BUF_LEN++] = bKeySettings1;
    PHAL_MFDUOX_CMD_BUF[PHAL_MFDUOX_CMD_BUF_LEN++] = bKeySettings2;

    /* Add Key Settings 3 and Key Set values to command buffer. */
    if(bKeySettings2 & PHAL_MFDUOX_KEYSETT3_PRESENT)
    {
        PHAL_MFDUOX_CMD_BUF[PHAL_MFDUOX_CMD_BUF_LEN++] = bKeySettings3;
        if(bKeySettings3 & PHAL_MFDUOX_KEYSETVALUES_PRESENT)
        {
            (void) memcpy(&PHAL_MFDUOX_CMD_BUF[PHAL_MFDUOX_CMD_BUF_LEN], pKeySetValues, bKeySetValuesLen);
            PHAL_MFDUOX_CMD_BUF_LEN += bKeySetValuesLen;
        }
    }

    /* Add ISO File ID to command buffer. */
    if(bOption & PHAL_MFDUOX_ISO_FILE_ID_AVAILABLE)
    {
        PHAL_MFDUOX_CMD_BUF[PHAL_MFDUOX_CMD_BUF_LEN++] = pISOFileId[0];
        PHAL_MFDUOX_CMD_BUF[PHAL_MFDUOX_CMD_BUF_LEN++] = pISOFileId[1];
    }

    /* Add ISO DFName to command buffer. */
    if(bOption & PHAL_MFDUOX_ISO_DF_NAME_AVAILABLE)
    {
        (void) memcpy(&PHAL_MFDUOX_CMD_BUF[PHAL_MFDUOX_CMD_BUF_LEN], pISODFName, bISODFNameLen);
        PHAL_MFDUOX_CMD_BUF_LEN += bISODFNameLen;
    }

    /* Exchange Cmd.CreateApplication information to PICC. */
    PH_CHECK_SUCCESS_FCT(wStatus, phalMfDuoX_Sw_Int_WriteData(
        pDataParams,
        PH_OFF,
        bComMode,
        bComMode,
        PH_OFF,
        PHAL_MFDUOX_CMD_BUF,
        PHAL_MFDUOX_CMD_BUF_LEN,
        NULL,
        0,
        NULL,
        NULL));

    return PH_ADD_COMPCODE(PH_ERR_SUCCESS, PH_COMP_AL_MFDUOX);
}

phStatus_t phalMfDuoX_Sw_DeleteApplication(phalMfDuoX_Sw_DataParams_t * pDataParams, uint8_t * pAid, uint8_t * pDAMMAC,
    uint8_t bDAMMAC_Len)
{
    phStatus_t  PH_MEMLOC_REM wStatus = 0;
    uint8_t     PH_MEMLOC_REM bCmd_ComMode = 0;
    uint8_t     PH_MEMLOC_REM bRsp_ComMode = 0;
    uint8_t     PH_MEMLOC_REM bResetAuth = 0;

    /* Set the DataParams with command code. */
    pDataParams->bCmdCode = PHAL_MFDUOX_CMD_DELETE_APPLICATION;

    /* Frame the communication mode to be applied. */
    phalMfDuoX_Int_GetCommMode(pDataParams->bAuthState, PHAL_MFDUOX_COMMUNICATION_INVALID,
        &bCmd_ComMode);

    /*
     * At APP level, the MAC is not returned. The authenticate state should be reset and command counter needs to be incremented.
     * At PICC level, 8 bytes MAC is returned. The authenticate state should not be reset.
     *
     * So to check whether its in APP level or PICC level, check for pDataParams->pAid. If its 0x00, then its PICC level
     * else its in APP level.
     */
    bResetAuth = PH_ON;
    bRsp_ComMode = PHAL_MFDUOX_COMMUNICATION_PLAIN;
    if((pDataParams->aAid[0] == 0) && (pDataParams->aAid[1] == 0) &&
        (pDataParams->aAid[2] == 0))
    {
        bResetAuth = PH_OFF;
    }

    /* Clear Buffers. */
    (void) memset(PHAL_MFDUOX_CMD_BUF, 0x00, PHAL_MFDUOX_CMD_BUF_SIZE);
    PHAL_MFDUOX_CMD_BUF_LEN = 0;

    /* Frame the command information. */
    PHAL_MFDUOX_CMD_BUF[PHAL_MFDUOX_CMD_BUF_LEN++] = PHAL_MFDUOX_CMD_DELETE_APPLICATION;

    /* Add Application ID to command buffer. */
    (void) memcpy(&PHAL_MFDUOX_CMD_BUF[PHAL_MFDUOX_CMD_BUF_LEN], pAid, PHAL_MFDUOX_APP_ID_LEN);
    PHAL_MFDUOX_CMD_BUF_LEN += PHAL_MFDUOX_APP_ID_LEN;

    /* Add DAM MAC to command buffer. */
    if(bDAMMAC_Len)
    {
        (void) memcpy(&PHAL_MFDUOX_CMD_BUF[PHAL_MFDUOX_CMD_BUF_LEN], pDAMMAC, bDAMMAC_Len);
        PHAL_MFDUOX_CMD_BUF_LEN += bDAMMAC_Len;
    }

    /* Exchange Cmd.DeleteApplication information to PICC. */
    PH_CHECK_SUCCESS_FCT(wStatus, phalMfDuoX_Sw_Int_WriteData(
        pDataParams,
        PH_OFF,
        bCmd_ComMode,
        bRsp_ComMode,
        bResetAuth,
        PHAL_MFDUOX_CMD_BUF,
        PHAL_MFDUOX_CMD_BUF_LEN,
        NULL,
        0,
        NULL,
        NULL));

    return PH_ADD_COMPCODE(PH_ERR_SUCCESS, PH_COMP_AL_MFDUOX);
}

phStatus_t phalMfDuoX_Sw_SelectApplication(phalMfDuoX_Sw_DataParams_t * pDataParams, uint8_t bOption, uint8_t * pAppId,
    uint8_t * pAppId2)
{
    phStatus_t  PH_MEMLOC_REM wStatus = 0;

    /* Set the DataParams with command code. */
    pDataParams->bCmdCode = PHAL_MFDUOX_CMD_SELECT_APPLICATION;

    /* Clear Buffers. */
    (void) memset(PHAL_MFDUOX_CMD_BUF, 0x00, PHAL_MFDUOX_CMD_BUF_SIZE);
    PHAL_MFDUOX_CMD_BUF_LEN = 0;

    /* Frame the command information. */
    PHAL_MFDUOX_CMD_BUF[PHAL_MFDUOX_CMD_BUF_LEN++] = PHAL_MFDUOX_CMD_SELECT_APPLICATION;

    /* Add Application ID to command buffer. */
    (void) memcpy(&PHAL_MFDUOX_CMD_BUF[PHAL_MFDUOX_CMD_BUF_LEN], pAppId, PHAL_MFDUOX_APP_ID_LEN);
    PHAL_MFDUOX_CMD_BUF_LEN += PHAL_MFDUOX_APP_ID_LEN;

    /* Add Secondary Application to command buffer. */
    if(bOption)
    {
        (void) memcpy(&PHAL_MFDUOX_CMD_BUF[PHAL_MFDUOX_CMD_BUF_LEN], pAppId2, PHAL_MFDUOX_APP_ID_LEN);
        PHAL_MFDUOX_CMD_BUF_LEN += PHAL_MFDUOX_APP_ID_LEN;
    }

    /* Exchange Cmd.SelectApplication information to PICC. */
    wStatus = phalMfDuoX_Sw_Int_WriteData(
        pDataParams,
        PH_OFF,
        PHAL_MFDUOX_COMMUNICATION_PLAIN,
        PHAL_MFDUOX_COMMUNICATION_PLAIN,
        PH_ON,
        PHAL_MFDUOX_CMD_BUF,
        PHAL_MFDUOX_CMD_BUF_LEN,
        NULL,
        0,
        NULL,
        NULL);

    /* Validate Status */
    if(((wStatus & PH_ERR_MASK) != PH_ERR_SUCCESS) &&
        ((wStatus & PH_ERR_MASK) != PHAL_MFDUOX_ERR_OPERATION_OK_LIM))
        return wStatus;

    /* Store the currently selected application Id */
    (void) memcpy(pDataParams->aAid, pAppId, PHAL_MFDUOX_APP_ID_LEN);

    return PH_ADD_COMPCODE(wStatus, PH_COMP_AL_MFDUOX);
}

phStatus_t phalMfDuoX_Sw_GetApplicationIDs(phalMfDuoX_Sw_DataParams_t * pDataParams, uint8_t bOption, uint8_t ** ppAidBuff,
    uint16_t * pAidLen)
{
    phStatus_t  PH_MEMLOC_REM wStatus = 0;
    uint8_t     PH_MEMLOC_REM bComMode = 0;

    /* Validate Exchange Options. */
    PHAL_MFDUOX_VALIDATE_RX_EXCHANGE_OPTIONS(bOption);

    /* Set the DataParams with command code. */
    pDataParams->bCmdCode = PHAL_MFDUOX_CMD_GET_APPLICATION_IDS;

    /* Frame the communication mode to be applied. */
    phalMfDuoX_Int_GetCommMode(pDataParams->bAuthState, PHAL_MFDUOX_COMMUNICATION_INVALID,
        &bComMode);

    /* Frame the command information. */
    if(bOption != PH_EXCHANGE_RXCHAINING)
    {
        /* Clear Buffers. */
        (void) memset(PHAL_MFDUOX_CMD_BUF, 0x00, PHAL_MFDUOX_CMD_BUF_SIZE);
        PHAL_MFDUOX_CMD_BUF_LEN = 0;

        PHAL_MFDUOX_CMD_BUF[PHAL_MFDUOX_CMD_BUF_LEN++] = PHAL_MFDUOX_CMD_GET_APPLICATION_IDS;
    }
    else
    {
        /* Chaining is handled internally. */
    }

    /* Exchange Cmd.GetApplicationIDs information to PICC. */
    PH_CHECK_SUCCESS_FCT(wStatus, phalMfDuoX_Sw_Int_ReadData(
        pDataParams,
        bOption,
        PH_OFF,
        bComMode,
        bComMode,
        PHAL_MFDUOX_CMD_BUF,
        PHAL_MFDUOX_CMD_BUF_LEN,
        PHAL_MFDUOX_DATA_TO_READ_UNKNOWN,
        ppAidBuff,
        pAidLen));

    return PH_ADD_COMPCODE(PH_ERR_SUCCESS, PH_COMP_AL_MFDUOX);
}

phStatus_t phalMfDuoX_Sw_GetDFNames(phalMfDuoX_Sw_DataParams_t * pDataParams, uint8_t bOption, uint8_t ** ppDFBuffer,
    uint16_t * pDFInfoLen)
{
    phStatus_t  PH_MEMLOC_REM wStatus = 0;
    uint8_t     PH_MEMLOC_REM bComMode = 0;

    /* Validate Exchange Options. */
    PHAL_MFDUOX_VALIDATE_RX_EXCHANGE_OPTIONS(bOption);

    /* Set the DataParams with command code. */
    pDataParams->bCmdCode = PHAL_MFDUOX_CMD_GET_DF_NAMES;

    /* Frame the communication mode to be applied. */
    phalMfDuoX_Int_GetCommMode(pDataParams->bAuthState, PHAL_MFDUOX_COMMUNICATION_INVALID,
        &bComMode);

    /* Frame the command information. */
    if(bOption != PH_EXCHANGE_RXCHAINING)
    {
        /* Clear Buffers. */
        (void) memset(PHAL_MFDUOX_CMD_BUF, 0x00, PHAL_MFDUOX_CMD_BUF_SIZE);
        PHAL_MFDUOX_CMD_BUF_LEN = 0;

        PHAL_MFDUOX_CMD_BUF[PHAL_MFDUOX_CMD_BUF_LEN++] = PHAL_MFDUOX_CMD_GET_DF_NAMES;
    }
    else
    {
        /* Chaining is handled internally. */
    }

    /* Exchange Cmd.GetDFNames information to PICC. */
    PH_CHECK_SUCCESS_FCT(wStatus, phalMfDuoX_Sw_Int_ReadData(
        pDataParams,
        bOption,
        PH_OFF,
        bComMode,
        bComMode,
        PHAL_MFDUOX_CMD_BUF,
        PHAL_MFDUOX_CMD_BUF_LEN,
        PHAL_MFDUOX_DATA_TO_READ_UNKNOWN,
        ppDFBuffer,
        pDFInfoLen));

    return PH_ADD_COMPCODE(PH_ERR_SUCCESS, PH_COMP_AL_MFDUOX);
}

/* MIFARE DUOX File management commands ------------------------------------------------------------------------------------------------ */
phStatus_t phalMfDuoX_Sw_CreateStdDataFile(phalMfDuoX_Sw_DataParams_t * pDataParams, uint8_t bOption, uint8_t bFileNo,
    uint8_t * pISOFileId, uint8_t bFileOption, uint8_t * pAccessRights, uint8_t * pFileSize)
{
    phStatus_t  PH_MEMLOC_REM wStatus = 0;
    uint8_t     PH_MEMLOC_REM bComMode = 0;

#ifdef RDR_LIB_PARAM_CHECK
    if(bOption > PHAL_MFDUOX_ISO_FILE_ID_AVAILABLE)
    {
        return PH_ADD_COMPCODE(PH_ERR_INVALID_PARAMETER, PH_COMP_AL_MFDUOX);
    }

    PHAL_MFDUOX_IS_VALID_FILE_NO(bFileNo);
    PHAL_MFDUOX_VALIDATE_FILE_OPTIONS(bFileOption);
#endif

    /* Set the DataParams with command code. */
    pDataParams->bCmdCode = PHAL_MFDUOX_CMD_CREATE_STANDARD_DATA_FILE;

    /* Frame the communication mode to be applied. */
    phalMfDuoX_Int_GetCommMode(pDataParams->bAuthState, PHAL_MFDUOX_COMMUNICATION_INVALID,
        &bComMode);

    /* Clear Buffers. */
    (void) memset(PHAL_MFDUOX_CMD_BUF, 0x00, PHAL_MFDUOX_CMD_BUF_SIZE);
    PHAL_MFDUOX_CMD_BUF_LEN = 0;

    /* Frame the command information. */
    PHAL_MFDUOX_CMD_BUF[PHAL_MFDUOX_CMD_BUF_LEN++] = PHAL_MFDUOX_CMD_CREATE_STANDARD_DATA_FILE;
    PHAL_MFDUOX_CMD_BUF[PHAL_MFDUOX_CMD_BUF_LEN++] = bFileNo;

    /* Add ISO File ID to command buffer. */
    if(bOption == PHAL_MFDUOX_ISO_FILE_ID_AVAILABLE)
    {
        (void) memcpy(&PHAL_MFDUOX_CMD_BUF[PHAL_MFDUOX_CMD_BUF_LEN], pISOFileId, 2);
        PHAL_MFDUOX_CMD_BUF_LEN += 2;
    }

    /* Add File Options to command buffer. */
    PHAL_MFDUOX_CMD_BUF[PHAL_MFDUOX_CMD_BUF_LEN++] = bFileOption;

    /* Add Access Rights to command buffer. */
    (void) memcpy(&PHAL_MFDUOX_CMD_BUF[PHAL_MFDUOX_CMD_BUF_LEN], pAccessRights, 2);
    PHAL_MFDUOX_CMD_BUF_LEN += 2;

    /* Add File Size to command buffer. */
    (void) memcpy(&PHAL_MFDUOX_CMD_BUF[PHAL_MFDUOX_CMD_BUF_LEN], pFileSize, 3);
    PHAL_MFDUOX_CMD_BUF_LEN += 3;

    /* Exchange Cmd.CreateStdDataFile information to PICC. */
    PH_CHECK_SUCCESS_FCT(wStatus, phalMfDuoX_Sw_Int_WriteData(
        pDataParams,
        PH_OFF,
        bComMode,
        bComMode,
        PH_OFF,
        PHAL_MFDUOX_CMD_BUF,
        PHAL_MFDUOX_CMD_BUF_LEN,
        NULL,
        0,
        NULL,
        NULL));

    return PH_ADD_COMPCODE(PH_ERR_SUCCESS, PH_COMP_AL_MFDUOX);
}

phStatus_t phalMfDuoX_Sw_CreateBackupDataFile(phalMfDuoX_Sw_DataParams_t * pDataParams, uint8_t bOption, uint8_t bFileNo,
    uint8_t * pISOFileId, uint8_t bFileOption, uint8_t * pAccessRights, uint8_t * pFileSize)
{
    phStatus_t  PH_MEMLOC_REM wStatus = 0;
    uint8_t     PH_MEMLOC_REM bComMode = 0;

#ifdef RDR_LIB_PARAM_CHECK
    if(bOption > PHAL_MFDUOX_ISO_FILE_ID_AVAILABLE)
    {
        return PH_ADD_COMPCODE(PH_ERR_INVALID_PARAMETER, PH_COMP_AL_MFDUOX);
    }

    PHAL_MFDUOX_IS_VALID_FILE_NO(bFileNo);
    PHAL_MFDUOX_VALIDATE_FILE_OPTIONS(bFileOption);
#endif

    /* Set the DataParams with command code. */
    pDataParams->bCmdCode = PHAL_MFDUOX_CMD_CREATE_BACKUP_DATA_FILE;

    /* Frame the communication mode to be applied. */
    phalMfDuoX_Int_GetCommMode(pDataParams->bAuthState, PHAL_MFDUOX_COMMUNICATION_INVALID,
        &bComMode);

    /* Clear Buffers. */
    (void) memset(PHAL_MFDUOX_CMD_BUF, 0x00, PHAL_MFDUOX_CMD_BUF_SIZE);
    PHAL_MFDUOX_CMD_BUF_LEN = 0;

    /* Frame the command information. */
    PHAL_MFDUOX_CMD_BUF[PHAL_MFDUOX_CMD_BUF_LEN++] = PHAL_MFDUOX_CMD_CREATE_BACKUP_DATA_FILE;
    PHAL_MFDUOX_CMD_BUF[PHAL_MFDUOX_CMD_BUF_LEN++] = bFileNo;

    /* Add ISO File ID to command buffer. */
    if(bOption == PHAL_MFDUOX_ISO_FILE_ID_AVAILABLE)
    {
        (void) memcpy(&PHAL_MFDUOX_CMD_BUF[PHAL_MFDUOX_CMD_BUF_LEN], pISOFileId, 2);
        PHAL_MFDUOX_CMD_BUF_LEN += 2;
    }

    /* Add File Options to command buffer. */
    PHAL_MFDUOX_CMD_BUF[PHAL_MFDUOX_CMD_BUF_LEN++] = bFileOption;

    /* Add Access Rights to command buffer. */
    (void) memcpy(&PHAL_MFDUOX_CMD_BUF[PHAL_MFDUOX_CMD_BUF_LEN], pAccessRights, 2);
    PHAL_MFDUOX_CMD_BUF_LEN += 2;

    /* Add File Size to command buffer. */
    (void) memcpy(&PHAL_MFDUOX_CMD_BUF[PHAL_MFDUOX_CMD_BUF_LEN], pFileSize, 3);
    PHAL_MFDUOX_CMD_BUF_LEN += 3;

    /* Exchange Cmd.CreateBackupDataFile information to PICC. */
    PH_CHECK_SUCCESS_FCT(wStatus, phalMfDuoX_Sw_Int_WriteData(
        pDataParams,
        PH_OFF,
        bComMode,
        bComMode,
        PH_OFF,
        PHAL_MFDUOX_CMD_BUF,
        PHAL_MFDUOX_CMD_BUF_LEN,
        NULL,
        0,
        NULL,
        NULL));

    return PH_ADD_COMPCODE(PH_ERR_SUCCESS, PH_COMP_AL_MFDUOX);
}

phStatus_t phalMfDuoX_Sw_CreateValueFile(phalMfDuoX_Sw_DataParams_t * pDataParams, uint8_t bFileNo, uint8_t bFileOption,
    uint8_t * pAccessRights, uint8_t * pLowerLmit, uint8_t * pUpperLmit, uint8_t * pValue, uint8_t bLimitedCredit)
{
    phStatus_t  PH_MEMLOC_REM wStatus = 0;
    uint8_t     PH_MEMLOC_REM bComMode = 0;

#ifdef RDR_LIB_PARAM_CHECK
    PHAL_MFDUOX_IS_VALID_FILE_NO(bFileNo);
    PHAL_MFDUOX_VALIDATE_FILE_OPTIONS(bFileOption);
#endif

    /* Set the DataParams with command code. */
    pDataParams->bCmdCode = PHAL_MFDUOX_CMD_CREATE_VALUE_FILE;

    /* Frame the communication mode to be applied. */
    phalMfDuoX_Int_GetCommMode(pDataParams->bAuthState, PHAL_MFDUOX_COMMUNICATION_INVALID,
        &bComMode);

    /* Clear Buffers. */
    (void) memset(PHAL_MFDUOX_CMD_BUF, 0x00, PHAL_MFDUOX_CMD_BUF_SIZE);
    PHAL_MFDUOX_CMD_BUF_LEN = 0;

    /* Frame the command information. */
    PHAL_MFDUOX_CMD_BUF[PHAL_MFDUOX_CMD_BUF_LEN++] = PHAL_MFDUOX_CMD_CREATE_VALUE_FILE;
    PHAL_MFDUOX_CMD_BUF[PHAL_MFDUOX_CMD_BUF_LEN++] = bFileNo;
    PHAL_MFDUOX_CMD_BUF[PHAL_MFDUOX_CMD_BUF_LEN++] = bFileOption;

    /* Add Access Rights to command buffer. */
    (void) memcpy(&PHAL_MFDUOX_CMD_BUF[PHAL_MFDUOX_CMD_BUF_LEN], pAccessRights, 2);
    PHAL_MFDUOX_CMD_BUF_LEN += 2;

    /* Add LowerLimit to command buffer. */
    (void) memcpy(&PHAL_MFDUOX_CMD_BUF[PHAL_MFDUOX_CMD_BUF_LEN], pLowerLmit, 4);
    PHAL_MFDUOX_CMD_BUF_LEN += 4;

    /* Add UpperLimit to command buffer. */
    (void) memcpy(&PHAL_MFDUOX_CMD_BUF[PHAL_MFDUOX_CMD_BUF_LEN], pUpperLmit, 4);
    PHAL_MFDUOX_CMD_BUF_LEN += 4;

    /* Add Current Value to command buffer. */
    (void) memcpy(&PHAL_MFDUOX_CMD_BUF[PHAL_MFDUOX_CMD_BUF_LEN], pValue, 4);
    PHAL_MFDUOX_CMD_BUF_LEN += 4;

    /* Add Limited Credit to command buffer. */
    PHAL_MFDUOX_CMD_BUF[PHAL_MFDUOX_CMD_BUF_LEN++] = bLimitedCredit;

    /* Exchange Cmd.CreateValueFile information to PICC. */
    PH_CHECK_SUCCESS_FCT(wStatus, phalMfDuoX_Sw_Int_WriteData(
        pDataParams,
        PH_OFF,
        bComMode,
        bComMode,
        PH_OFF,
        PHAL_MFDUOX_CMD_BUF,
        PHAL_MFDUOX_CMD_BUF_LEN,
        NULL,
        0,
        NULL,
        NULL));

    return PH_ADD_COMPCODE(PH_ERR_SUCCESS, PH_COMP_AL_MFDUOX);
}

phStatus_t phalMfDuoX_Sw_CreateLinearRecordFile(phalMfDuoX_Sw_DataParams_t * pDataParams, uint8_t bOption, uint8_t bFileNo,
    uint8_t * pISOFileId, uint8_t bFileOption, uint8_t * pAccessRights, uint8_t * pRecordSize, uint8_t * pMaxNoOfRec)
{
    phStatus_t  PH_MEMLOC_REM wStatus = 0;
    uint8_t     PH_MEMLOC_REM bComMode = 0;

#ifdef RDR_LIB_PARAM_CHECK
    if(bOption > PHAL_MFDUOX_ISO_FILE_ID_AVAILABLE)
    {
        return PH_ADD_COMPCODE(PH_ERR_INVALID_PARAMETER, PH_COMP_AL_MFDUOX);
    }

    PHAL_MFDUOX_IS_VALID_FILE_NO(bFileNo);
    PHAL_MFDUOX_VALIDATE_FILE_OPTIONS(bFileOption);
#endif

    /* Set the DataParams with command code. */
    pDataParams->bCmdCode = PHAL_MFDUOX_CMD_CREATE_LINEAR_RECORD_FILE;

    /* Frame the communication mode to be applied. */
    phalMfDuoX_Int_GetCommMode(pDataParams->bAuthState, PHAL_MFDUOX_COMMUNICATION_INVALID,
        &bComMode);

    /* Clear Buffers. */
    (void) memset(PHAL_MFDUOX_CMD_BUF, 0x00, PHAL_MFDUOX_CMD_BUF_SIZE);
    PHAL_MFDUOX_CMD_BUF_LEN = 0;

    /* Frame the command information. */
    PHAL_MFDUOX_CMD_BUF[PHAL_MFDUOX_CMD_BUF_LEN++] = PHAL_MFDUOX_CMD_CREATE_LINEAR_RECORD_FILE;
    PHAL_MFDUOX_CMD_BUF[PHAL_MFDUOX_CMD_BUF_LEN++] = bFileNo;

    /* Add ISO File ID to command buffer. */
    if(bOption == PHAL_MFDUOX_ISO_FILE_ID_AVAILABLE)
    {
        (void) memcpy(&PHAL_MFDUOX_CMD_BUF[PHAL_MFDUOX_CMD_BUF_LEN], pISOFileId, 2);
        PHAL_MFDUOX_CMD_BUF_LEN += 2;
    }

    /* Add File Options to command buffer. */
    PHAL_MFDUOX_CMD_BUF[PHAL_MFDUOX_CMD_BUF_LEN++] = bFileOption;

    /* Add Access Rights to command buffer. */
    (void) memcpy(&PHAL_MFDUOX_CMD_BUF[PHAL_MFDUOX_CMD_BUF_LEN], pAccessRights, 2);
    PHAL_MFDUOX_CMD_BUF_LEN += 2;

    /* Add Record Size to command buffer. */
    (void) memcpy(&PHAL_MFDUOX_CMD_BUF[PHAL_MFDUOX_CMD_BUF_LEN], pRecordSize, 3);
    PHAL_MFDUOX_CMD_BUF_LEN += 3;

    /* Add Maximum Number of Records to command buffer. */
    (void) memcpy(&PHAL_MFDUOX_CMD_BUF[PHAL_MFDUOX_CMD_BUF_LEN], pMaxNoOfRec, 3);
    PHAL_MFDUOX_CMD_BUF_LEN += 3;

    /* Exchange Cmd.CreateLinearRecordFile information to PICC. */
    PH_CHECK_SUCCESS_FCT(wStatus, phalMfDuoX_Sw_Int_WriteData(
        pDataParams,
        PH_OFF,
        bComMode,
        bComMode,
        PH_OFF,
        PHAL_MFDUOX_CMD_BUF,
        PHAL_MFDUOX_CMD_BUF_LEN,
        NULL,
        0,
        NULL,
        NULL));

    return PH_ADD_COMPCODE(PH_ERR_SUCCESS, PH_COMP_AL_MFDUOX);
}

phStatus_t phalMfDuoX_Sw_CreateCyclicRecordFile(phalMfDuoX_Sw_DataParams_t * pDataParams, uint8_t bOption, uint8_t bFileNo,
    uint8_t * pISOFileId, uint8_t bFileOption, uint8_t * pAccessRights, uint8_t * pRecordSize, uint8_t * pMaxNoOfRec)
{
    phStatus_t  PH_MEMLOC_REM wStatus = 0;
    uint8_t     PH_MEMLOC_REM bComMode = 0;

#ifdef RDR_LIB_PARAM_CHECK
    if(bOption > PHAL_MFDUOX_ISO_FILE_ID_AVAILABLE)
    {
        return PH_ADD_COMPCODE(PH_ERR_INVALID_PARAMETER, PH_COMP_AL_MFDUOX);
    }

    PHAL_MFDUOX_IS_VALID_FILE_NO(bFileNo);
    PHAL_MFDUOX_VALIDATE_FILE_OPTIONS(bFileOption);
#endif

    /* Set the DataParams with command code. */
    pDataParams->bCmdCode = PHAL_MFDUOX_CMD_CREATE_CYCLIC_RECORD_FILE;

    /* Frame the communication mode to be applied. */
    phalMfDuoX_Int_GetCommMode(pDataParams->bAuthState, PHAL_MFDUOX_COMMUNICATION_INVALID,
        &bComMode);

    /* Clear Buffers. */
    (void) memset(PHAL_MFDUOX_CMD_BUF, 0x00, PHAL_MFDUOX_CMD_BUF_SIZE);
    PHAL_MFDUOX_CMD_BUF_LEN = 0;

    /* Frame the command information. */
    PHAL_MFDUOX_CMD_BUF[PHAL_MFDUOX_CMD_BUF_LEN++] = PHAL_MFDUOX_CMD_CREATE_CYCLIC_RECORD_FILE;
    PHAL_MFDUOX_CMD_BUF[PHAL_MFDUOX_CMD_BUF_LEN++] = bFileNo;

    /* Add ISO File ID to command buffer. */
    if(bOption == PHAL_MFDUOX_ISO_FILE_ID_AVAILABLE)
    {
        (void) memcpy(&PHAL_MFDUOX_CMD_BUF[PHAL_MFDUOX_CMD_BUF_LEN], pISOFileId, 2);
        PHAL_MFDUOX_CMD_BUF_LEN += 2;
    }

    /* Add File Options to command buffer. */
    PHAL_MFDUOX_CMD_BUF[PHAL_MFDUOX_CMD_BUF_LEN++] = bFileOption;

    /* Add Access Rights to command buffer. */
    (void) memcpy(&PHAL_MFDUOX_CMD_BUF[PHAL_MFDUOX_CMD_BUF_LEN], pAccessRights, 2);
    PHAL_MFDUOX_CMD_BUF_LEN += 2;

    /* Add Record Size to command buffer. */
    (void) memcpy(&PHAL_MFDUOX_CMD_BUF[PHAL_MFDUOX_CMD_BUF_LEN], pRecordSize, 3);
    PHAL_MFDUOX_CMD_BUF_LEN += 3;

    /* Add Maximum Number of Records to command buffer. */
    (void) memcpy(&PHAL_MFDUOX_CMD_BUF[PHAL_MFDUOX_CMD_BUF_LEN], pMaxNoOfRec, 3);
    PHAL_MFDUOX_CMD_BUF_LEN += 3;

    /* Exchange Cmd.CreateCyclicRecordFile information to PICC. */
    PH_CHECK_SUCCESS_FCT(wStatus, phalMfDuoX_Sw_Int_WriteData(
        pDataParams,
        PH_OFF,
        bComMode,
        bComMode,
        PH_OFF,
        PHAL_MFDUOX_CMD_BUF,
        PHAL_MFDUOX_CMD_BUF_LEN,
        NULL,
        0,
        NULL,
        NULL));

    return PH_ADD_COMPCODE(PH_ERR_SUCCESS, PH_COMP_AL_MFDUOX);
}

phStatus_t phalMfDuoX_Sw_DeleteFile(phalMfDuoX_Sw_DataParams_t * pDataParams, uint8_t bFileNo)
{
    phStatus_t  PH_MEMLOC_REM wStatus = 0;
    uint8_t     PH_MEMLOC_REM bComMode = 0;

#ifdef RDR_LIB_PARAM_CHECK
    PHAL_MFDUOX_IS_VALID_FILE_NO(bFileNo);
#endif

    /* Set the DataParams with command code. */
    pDataParams->bCmdCode = PHAL_MFDUOX_CMD_CREATE_DELETE_FILE;

    /* Frame the communication mode to be applied. */
    phalMfDuoX_Int_GetCommMode(pDataParams->bAuthState, PHAL_MFDUOX_COMMUNICATION_INVALID,
        &bComMode);

    /* Clear Buffers. */
    (void) memset(PHAL_MFDUOX_CMD_BUF, 0x00, PHAL_MFDUOX_CMD_BUF_SIZE);
    PHAL_MFDUOX_CMD_BUF_LEN = 0;

    (void) memset(PHAL_MFDUOX_PRS_BUF, 0x00, PHAL_MFDUOX_PRS_BUF_SIZE);
    PHAL_MFDUOX_PRS_BUF_LEN = 0;

    /* Frame the command information. */
    PHAL_MFDUOX_CMD_BUF[PHAL_MFDUOX_CMD_BUF_LEN++] = PHAL_MFDUOX_CMD_CREATE_DELETE_FILE;
    PHAL_MFDUOX_CMD_BUF[PHAL_MFDUOX_CMD_BUF_LEN++] = bFileNo;

    /* Exchange Cmd.DeleteFile information to PICC. */
    PH_CHECK_SUCCESS_FCT(wStatus, phalMfDuoX_Sw_Int_WriteData(
        pDataParams,
        PH_OFF,
        bComMode,
        bComMode,
        PH_OFF,
        PHAL_MFDUOX_CMD_BUF,
        PHAL_MFDUOX_CMD_BUF_LEN,
        NULL,
        0,
        NULL,
        NULL));

    return PH_ADD_COMPCODE(PH_ERR_SUCCESS, PH_COMP_AL_MFDUOX);
}

phStatus_t phalMfDuoX_Sw_GetFileIDs(phalMfDuoX_Sw_DataParams_t * pDataParams, uint8_t ** ppFileId, uint16_t * pFileIdLen)
{
    phStatus_t  PH_MEMLOC_REM wStatus = 0;
    uint8_t     PH_MEMLOC_REM bComMode = 0;

    /* Set the DataParams with command code. */
    pDataParams->bCmdCode = PHAL_MFDUOX_CMD_GET_FILE_IDS;

    /* Frame the communication mode to be applied. */
    phalMfDuoX_Int_GetCommMode(pDataParams->bAuthState, PHAL_MFDUOX_COMMUNICATION_INVALID,
        &bComMode);

    /* Clear Buffers. */
    (void) memset(PHAL_MFDUOX_CMD_BUF, 0x00, PHAL_MFDUOX_CMD_BUF_SIZE);
    PHAL_MFDUOX_CMD_BUF_LEN = 0;

    /* Frame the command information. */
    PHAL_MFDUOX_CMD_BUF[PHAL_MFDUOX_CMD_BUF_LEN++] = PHAL_MFDUOX_CMD_GET_FILE_IDS;

    /* Exchange Cmd.GetFileIDs information to PICC. */
    PH_CHECK_SUCCESS_FCT(wStatus, phalMfDuoX_Sw_Int_ReadData(
        pDataParams,
        PH_EXCHANGE_DEFAULT,
        PH_OFF,
        bComMode,
        bComMode,
        PHAL_MFDUOX_CMD_BUF,
        PHAL_MFDUOX_CMD_BUF_LEN,
        PHAL_MFDUOX_DATA_TO_READ_UNKNOWN,
        ppFileId,
        pFileIdLen));

    return PH_ADD_COMPCODE(PH_ERR_SUCCESS, PH_COMP_AL_MFDUOX);
}

phStatus_t phalMfDuoX_Sw_GetISOFileIDs(phalMfDuoX_Sw_DataParams_t * pDataParams, uint8_t ** ppISOFileId, uint16_t * pISOFileIdLen)
{
    phStatus_t  PH_MEMLOC_REM wStatus = 0;
    uint8_t     PH_MEMLOC_REM bComMode = 0;

    /* Set the DataParams with command code. */
    pDataParams->bCmdCode = PHAL_MFDUOX_CMD_GET_ISO_FILE_IDS;

    /* Frame the communication mode to be applied. */
    phalMfDuoX_Int_GetCommMode(pDataParams->bAuthState, PHAL_MFDUOX_COMMUNICATION_INVALID,
        &bComMode);

    /* Clear Buffers. */
    (void) memset(PHAL_MFDUOX_CMD_BUF, 0x00, PHAL_MFDUOX_CMD_BUF_SIZE);
    PHAL_MFDUOX_CMD_BUF_LEN = 0;

    /* Frame the command information. */
    PHAL_MFDUOX_CMD_BUF[PHAL_MFDUOX_CMD_BUF_LEN++] = PHAL_MFDUOX_CMD_GET_ISO_FILE_IDS;

    /* Exchange Cmd.GetISOFileIDs information to PICC. */
    PH_CHECK_SUCCESS_FCT(wStatus, phalMfDuoX_Sw_Int_ReadData(
        pDataParams,
        PH_EXCHANGE_DEFAULT,
        PH_OFF,
        bComMode,
        bComMode,
        PHAL_MFDUOX_CMD_BUF,
        PHAL_MFDUOX_CMD_BUF_LEN,
        PHAL_MFDUOX_DATA_TO_READ_UNKNOWN,
        ppISOFileId,
        pISOFileIdLen));

    return PH_ADD_COMPCODE(PH_ERR_SUCCESS, PH_COMP_AL_MFDUOX);
}

phStatus_t phalMfDuoX_Sw_GetFileSettings(phalMfDuoX_Sw_DataParams_t * pDataParams, uint8_t bFileNo, uint8_t ** ppFSBuffer,
    uint16_t * pFSBufLen)
{
    phStatus_t  PH_MEMLOC_REM wStatus = 0;
    uint8_t     PH_MEMLOC_REM bComMode = 0;

    /* Set the DataParams with command code. */
    pDataParams->bCmdCode = PHAL_MFDUOX_CMD_GET_FILE_SETTINGS;

    /* Frame the communication mode to be applied. */
    phalMfDuoX_Int_GetCommMode(pDataParams->bAuthState, PHAL_MFDUOX_COMMUNICATION_INVALID,
        &bComMode);

    /* Clear Buffers. */
    (void) memset(PHAL_MFDUOX_CMD_BUF, 0x00, PHAL_MFDUOX_CMD_BUF_SIZE);
    PHAL_MFDUOX_CMD_BUF_LEN = 0;

    /* Frame the command information. */
    PHAL_MFDUOX_CMD_BUF[PHAL_MFDUOX_CMD_BUF_LEN++] = PHAL_MFDUOX_CMD_GET_FILE_SETTINGS;
    PHAL_MFDUOX_CMD_BUF[PHAL_MFDUOX_CMD_BUF_LEN++] = bFileNo;

    /* Exchange Cmd.GetFileSettings information to PICC. */
    PH_CHECK_SUCCESS_FCT(wStatus, phalMfDuoX_Sw_Int_ReadData(
        pDataParams,
        PH_EXCHANGE_DEFAULT,
        PH_OFF,
        bComMode,
        bComMode,
        PHAL_MFDUOX_CMD_BUF,
        PHAL_MFDUOX_CMD_BUF_LEN,
        PHAL_MFDUOX_DATA_TO_READ_UNKNOWN,
        ppFSBuffer,
        pFSBufLen));

    return PH_ADD_COMPCODE(PH_ERR_SUCCESS, PH_COMP_AL_MFDUOX);
}

phStatus_t phalMfDuoX_Sw_GetFileCounters(phalMfDuoX_Sw_DataParams_t * pDataParams, uint8_t bOption, uint8_t bFileNo,
    uint8_t ** ppFileCounters, uint16_t * pFileCounterLen)
{
    phStatus_t  PH_MEMLOC_REM wStatus = 0;
    uint8_t     PH_MEMLOC_REM bCmd_ComMode = 0;

    /* Set the DataParams with command code. */
    pDataParams->bCmdCode = PHAL_MFDUOX_CMD_GET_FILE_COUNTERS;

    /* Frame the communication mode to be applied. */
    phalMfDuoX_Int_GetCommMode(pDataParams->bAuthState, bOption, &bCmd_ComMode);

    /* Clear Buffers. */
    (void) memset(PHAL_MFDUOX_CMD_BUF, 0x00, PHAL_MFDUOX_CMD_BUF_SIZE);
    PHAL_MFDUOX_CMD_BUF_LEN = 0;

    /* Frame the command information. */
    PHAL_MFDUOX_CMD_BUF[PHAL_MFDUOX_CMD_BUF_LEN++] = PHAL_MFDUOX_CMD_GET_FILE_COUNTERS;
    PHAL_MFDUOX_CMD_BUF[PHAL_MFDUOX_CMD_BUF_LEN++] = bFileNo;

    /* Exchange Cmd.GetFileCounters information to PICC. */
    PH_CHECK_SUCCESS_FCT(wStatus, phalMfDuoX_Sw_Int_ReadData(
        pDataParams,
        PH_EXCHANGE_DEFAULT,
        PH_OFF,
        bCmd_ComMode,
        bOption,
        PHAL_MFDUOX_CMD_BUF,
        PHAL_MFDUOX_CMD_BUF_LEN,
        PHAL_MFDUOX_DATA_TO_READ_UNKNOWN,
        ppFileCounters,
        pFileCounterLen));

    return PH_ADD_COMPCODE(PH_ERR_SUCCESS, PH_COMP_AL_MFDUOX);
}

phStatus_t phalMfDuoX_Sw_ChangeFileSettings(phalMfDuoX_Sw_DataParams_t * pDataParams, uint8_t bOption, uint8_t bFileNo,
    uint8_t bFileOption, uint8_t * pAccessRights, uint8_t * pAddInfo, uint8_t bAddInfoLen)
{
    phStatus_t  PH_MEMLOC_REM wStatus = 0;
    uint16_t    PH_MEMLOC_REM wCmdDataLen = 0;
    uint8_t *   PH_MEMLOC_REM pCmdData = NULL;
    uint8_t     PH_MEMLOC_REM bRsp_ComMode = 0;

#ifdef RDR_LIB_PARAM_CHECK
    PHAL_MFDUOX_IS_VALID_FILE_NO(bFileNo);
    PH_CHECK_SUCCESS_FCT(wStatus, phalMfDuoX_Int_Validate_ComOption(bOption));
    PHAL_MFDUOX_VALIDATE_FILE_OPTIONS(bFileOption);
#endif

    /* Set the DataParams with command code. */
    pDataParams->bCmdCode = PHAL_MFDUOX_CMD_CHANGE_FILE_SETTINGS;

    /* Frame the communication mode to be applied. */
    phalMfDuoX_Int_GetCommMode(pDataParams->bAuthState, bOption, &bRsp_ComMode);

    /* Clear Buffers. */
    (void) memset(PHAL_MFDUOX_CMD_BUF, 0x00, PHAL_MFDUOX_CMD_BUF_SIZE);
    PHAL_MFDUOX_CMD_BUF_LEN = 0;

    (void) memset(PHAL_MFDUOX_PRS_BUF, 0x00, PHAL_MFDUOX_PRS_BUF_SIZE);
    PHAL_MFDUOX_PRS_BUF_LEN = 0;

    /* Frame the command information. */
    PHAL_MFDUOX_CMD_BUF[PHAL_MFDUOX_CMD_BUF_LEN++] = PHAL_MFDUOX_CMD_CHANGE_FILE_SETTINGS;
    PHAL_MFDUOX_CMD_BUF[PHAL_MFDUOX_CMD_BUF_LEN++] = bFileNo;

    /* Set buffer to use for Command Data. */
    pCmdData = &PHAL_MFDUOX_CMD_BUF[PHAL_MFDUOX_CMD_BUF_LEN];

    /* Add FileOption to processing buffer. */
    pCmdData[wCmdDataLen++] = bFileOption;

    /* Add Access Rights to processing buffer. */
    (void) memcpy(&pCmdData[wCmdDataLen], pAccessRights, 2);
    wCmdDataLen += 2;

    /* Add File Size to processing buffer. */
    (void) memcpy(&pCmdData[wCmdDataLen], pAddInfo, bAddInfoLen);
    wCmdDataLen += bAddInfoLen;

    /* Exchange Cmd.ChangeFileSettings information to PICC. */
    PH_CHECK_SUCCESS_FCT(wStatus, phalMfDuoX_Sw_Int_WriteData(
        pDataParams,
        PH_OFF,
        bOption,
        bRsp_ComMode,
        PH_OFF,
        PHAL_MFDUOX_CMD_BUF,
        PHAL_MFDUOX_CMD_BUF_LEN,
        pCmdData,
        wCmdDataLen,
        NULL,
        NULL));

    return PH_ADD_COMPCODE(PH_ERR_SUCCESS, PH_COMP_AL_MFDUOX);
}

/* MIFARE DUOX Data management commands ------------------------------------------------------------------------------------------------ */
phStatus_t phalMfDuoX_Sw_ReadData(phalMfDuoX_Sw_DataParams_t * pDataParams, uint8_t bOption, uint8_t bIns, uint8_t bFileNo,
    uint8_t * pOffset, uint8_t * pLength, uint8_t ** ppResponse, uint16_t * pRspLen)
{
    phStatus_t  PH_MEMLOC_REM wStatus = 0;
    phStatus_t  PH_MEMLOC_REM wStatus1 = 0;
    uint32_t    PH_MEMLOC_REM dwTMIStatus = 0;
    uint32_t    PH_MEMLOC_REM dwLength = 0;
    uint8_t     PH_MEMLOC_REM bExchange_Option = 0;
    uint8_t     PH_MEMLOC_REM bCmd_ComMode = 0;
    uint8_t     PH_MEMLOC_REM bRsp_ComMode = 0;
    uint8_t     PH_MEMLOC_REM bTMIOption = 0;

#ifdef RDR_LIB_PARAM_CHECK
    PHAL_MFDUOX_IS_VALID_FILE_NO(bFileNo);
#endif

    /* Extract Communication and Exchange Options. */
    bRsp_ComMode = (uint8_t) (bOption & PHAL_MFDUOX_COMM_OPTIONS_MASK);
    bExchange_Option = (uint8_t) (bOption & PH_EXCHANGE_MODE_MASK);

    /* Validate Communication Options. */
    PH_CHECK_SUCCESS_FCT(wStatus, phalMfDuoX_Int_Validate_ComOption(bRsp_ComMode));

    /* Validate Exchange Options. */
    PHAL_MFDUOX_VALIDATE_RX_EXCHANGE_OPTIONS(bExchange_Option);

    /* Validate Chaining Options. */
    PHAL_MFDUOX_VALIDATE_CHAINING_OPTIONS(bIns);

    /* Frame the communication mode to be applied. */
    phalMfDuoX_Int_GetCommMode(pDataParams->bAuthState, bOption, &bCmd_ComMode);

    /* Compute the length. */
    dwLength = pLength[2];
    dwLength = dwLength << 8 | pLength[1];
    dwLength = dwLength << 8 | pLength[0];

    /* Set the DataParams with command code. */
    pDataParams->bCmdCode = (uint8_t) (bIns ? PHAL_MFDUOX_CMD_READ_DATA_ISO : PHAL_MFDUOX_CMD_READ_DATA_NATIVE);

    /* Get TMI Collection Status. */
    PH_CHECK_SUCCESS_FCT(wStatus, phTMIUtils_GetConfig((phTMIUtils_t *)pDataParams->pTMIDataParams, PH_TMIUTILS_TMI_STATUS, &dwTMIStatus));

    /* Frame the command information. */
    if(bExchange_Option != PH_EXCHANGE_RXCHAINING)
    {
        /* Clear Buffers. */
        (void) memset(PHAL_MFDUOX_CMD_BUF, 0x00, PHAL_MFDUOX_CMD_BUF_SIZE);
        PHAL_MFDUOX_CMD_BUF_LEN = 0;

        /* Add command code. */
        PHAL_MFDUOX_CMD_BUF[PHAL_MFDUOX_CMD_BUF_LEN++] = pDataParams->bCmdCode;

        /* Add File Number. */
        PHAL_MFDUOX_CMD_BUF[PHAL_MFDUOX_CMD_BUF_LEN++] = bFileNo;

        /* Add offset. */
        (void) memcpy(&PHAL_MFDUOX_CMD_BUF[PHAL_MFDUOX_CMD_BUF_LEN], pOffset, 3);
        PHAL_MFDUOX_CMD_BUF_LEN += 3;

        /* Add length. */
        (void) memcpy(&PHAL_MFDUOX_CMD_BUF[PHAL_MFDUOX_CMD_BUF_LEN], pLength, 3);
        PHAL_MFDUOX_CMD_BUF_LEN += 3;

        /* Perform TMI Collection for Command Header. */
        if(dwTMIStatus)
        {
            /* Frame the Option. */
            bTMIOption = (uint8_t) (PH_TMIUTILS_ZEROPAD_CMDBUFF | (dwLength ? 0 : PH_TMIUTILS_READ_INS));

            /* Buffer the Command information to TMI buffer. */
            PH_CHECK_SUCCESS_FCT(wStatus, phTMIUtils_CollectTMI((phTMIUtils_t *)pDataParams->pTMIDataParams, bTMIOption, PHAL_MFDUOX_CMD_BUF,
                PHAL_MFDUOX_CMD_BUF_LEN, NULL, 0, PHAL_MFDUOX_BLOCK_SIZE));
        }
    }
    else
    {
        /* Chaining is handled internally. */
    }

    /* Exchange Cmd.ReadData information to PICC. */
    wStatus = phalMfDuoX_Sw_Int_ReadData(
        pDataParams,
        bExchange_Option,
        bIns,
        bCmd_ComMode,
        bRsp_ComMode,
        PHAL_MFDUOX_CMD_BUF,
        PHAL_MFDUOX_CMD_BUF_LEN,
        dwLength,
        ppResponse,
        pRspLen);

    /* Validate Status. */
    if(((wStatus & PH_ERR_MASK) != PH_ERR_SUCCESS) && ((wStatus & PH_ERR_MASK) != PH_ERR_SUCCESS_CHAINING))
        return wStatus;

    /* Perform TMI Collection for Response. */
    if(dwTMIStatus)
    {
        /* Frame the Option. */
        bTMIOption = (uint8_t) (dwLength ? 0 : PH_TMIUTILS_READ_INS);
        bTMIOption = (uint8_t) ((wStatus == PH_ERR_SUCCESS) ? (bTMIOption | PH_TMIUTILS_ZEROPAD_DATABUFF) : bTMIOption);

        /* Buffer the Command information to TMI buffer. */
        PH_CHECK_SUCCESS_FCT(wStatus1, phTMIUtils_CollectTMI((phTMIUtils_t *)pDataParams->pTMIDataParams, bTMIOption, NULL, 0,
            *ppResponse, *pRspLen, PHAL_MFDUOX_BLOCK_SIZE));

        /* Reset the TMI buffer Offset. */
        if(!dwLength && ((wStatus & PH_ERR_MASK) == PH_ERR_SUCCESS))
        {
            /* Reset Offset in TMI. */
            PH_CHECK_SUCCESS_FCT(wStatus1, phTMIUtils_SetConfig((phTMIUtils_t *)pDataParams->pTMIDataParams, PH_TMIUTILS_TMI_OFFSET_LENGTH, 0));
        }
    }

    return wStatus;
}

phStatus_t phalMfDuoX_Sw_WriteData(phalMfDuoX_Sw_DataParams_t * pDataParams, uint8_t bOption, uint8_t bIns, uint8_t bFileNo,
    uint16_t wCRLVer, uint8_t * pOffset, uint8_t * pData, uint8_t * pLength)
{
    phStatus_t  PH_MEMLOC_REM wStatus = 0;
    uint32_t    PH_MEMLOC_REM dwTMIStatus = 0;
    uint32_t    PH_MEMLOC_REM dwLength = 0;
    uint8_t     PH_MEMLOC_REM bCmd_ComMode = 0;
    uint8_t     PH_MEMLOC_REM bRsp_ComMode = 0;
    uint8_t     PH_MEMLOC_REM bIsCRLFile = PH_OFF;

#ifdef RDR_LIB_PARAM_CHECK
    PHAL_MFDUOX_IS_VALID_FILE_NO(bFileNo);
#endif

    /* Extract Communication option */
    bCmd_ComMode = (uint8_t) (bOption & PHAL_MFDUOX_COMM_OPTIONS_MASK);

    /* Validate Communication Options. */
    PH_CHECK_SUCCESS_FCT(wStatus, phalMfDuoX_Int_Validate_ComOption(bCmd_ComMode));

    /* Validate Chaining Options. */
    PHAL_MFDUOX_VALIDATE_CHAINING_OPTIONS(bIns);

    /* Check if its a CRLFile. */
    bIsCRLFile = (uint8_t) (bOption & PHAL_MFDUOX_CRLFILE_MASK);

    /* Frame the communication mode to be verified. */
    phalMfDuoX_Int_GetCommMode(pDataParams->bAuthState, bOption, &bRsp_ComMode);

    /* Compute the Total length (Data + [CRL Signature]). */
    dwLength = pLength[2];
    dwLength = dwLength << 8 | pLength[1];
    dwLength = dwLength << 8 | pLength[0];

    /* Clear Buffers. */
    (void) memset(PHAL_MFDUOX_CMD_BUF, 0x00, PHAL_MFDUOX_CMD_BUF_SIZE);
    PHAL_MFDUOX_CMD_BUF_LEN = 0;

    (void) memset(PHAL_MFDUOX_PRS_BUF, 0x00, PHAL_MFDUOX_PRS_BUF_SIZE);
    PHAL_MFDUOX_PRS_BUF_LEN = 0;

    /* Set the DataParams with command code. */
    pDataParams->bCmdCode = (uint8_t) (bIns ? PHAL_MFDUOX_CMD_WRITE_DATA_ISO : PHAL_MFDUOX_CMD_WRITE_DATA_NATIVE);

    /* Add command code. */
    PHAL_MFDUOX_CMD_BUF[PHAL_MFDUOX_CMD_BUF_LEN++] = pDataParams->bCmdCode;

    /* Add File Number. */
    PHAL_MFDUOX_CMD_BUF[PHAL_MFDUOX_CMD_BUF_LEN++] = bFileNo;

    /* Get TMI Collection Status. */
    PH_CHECK_SUCCESS_FCT(wStatus, phTMIUtils_GetConfig((phTMIUtils_t *)pDataParams->pTMIDataParams, PH_TMIUTILS_TMI_STATUS, &dwTMIStatus));

    /* Perform TMI Collection for command and data. */
    if(dwTMIStatus)
    {
        PH_CHECK_SUCCESS_FCT(wStatus, phTMIUtils_CollectTMI((phTMIUtils_t *)pDataParams->pTMIDataParams, PH_TMIUTILS_NO_PADDING,
            PHAL_MFDUOX_CMD_BUF, PHAL_MFDUOX_CMD_BUF_LEN, NULL, 0, PHAL_MFDUOX_BLOCK_SIZE));
    }

    /* Add CLR Information */
    if(bIsCRLFile == PH_ON)
    {
        /* Add CLRVersion. */
        (void) memcpy(&PHAL_MFDUOX_CMD_BUF[PHAL_MFDUOX_CMD_BUF_LEN], (uint8_t *) &wCRLVer, 2);
        PHAL_MFDUOX_CMD_BUF_LEN += 2;
    }

    /* Add offset. */
    (void) memcpy(&PHAL_MFDUOX_CMD_BUF[PHAL_MFDUOX_CMD_BUF_LEN], pOffset, 3);
    PHAL_MFDUOX_CMD_BUF_LEN += 3;

    /* Add length. */
    (void) memcpy(&PHAL_MFDUOX_CMD_BUF[PHAL_MFDUOX_CMD_BUF_LEN], pLength, 3);
    PHAL_MFDUOX_CMD_BUF_LEN += 3;

    /* Perform TMI Collection for command and data. */
    if(dwTMIStatus)
    {
        /* Add Offset information to TMICollection. */
        PH_CHECK_SUCCESS_FCT(wStatus, phTMIUtils_CollectTMI((phTMIUtils_t *)pDataParams->pTMIDataParams, PH_TMIUTILS_NO_PADDING,
            pOffset, 3, NULL, 0, PHAL_MFDUOX_BLOCK_SIZE));

        /* Add Length and Data information to TMICollection. */
        PH_CHECK_SUCCESS_FCT(wStatus, phTMIUtils_CollectTMI((phTMIUtils_t *)pDataParams->pTMIDataParams, (PH_TMIUTILS_ZEROPAD_CMDBUFF |
            PH_TMIUTILS_ZEROPAD_DATABUFF), pLength, 3, pData, dwLength, PHAL_MFDUOX_BLOCK_SIZE));
    }

    /* Exchange Cmd.WriteData information to PICC. */
    PH_CHECK_SUCCESS_FCT(wStatus, phalMfDuoX_Sw_Int_WriteData(
        pDataParams,
        (uint8_t)!bIns,
        bCmd_ComMode,
        bRsp_ComMode,
        PH_OFF,
        PHAL_MFDUOX_CMD_BUF,
        PHAL_MFDUOX_CMD_BUF_LEN,
        pData,
        dwLength,
        NULL,
        NULL));

    return PH_ADD_COMPCODE(PH_ERR_SUCCESS, PH_COMP_AL_MFDUOX);
}

phStatus_t phalMfDuoX_Sw_GetValue(phalMfDuoX_Sw_DataParams_t * pDataParams, uint8_t bOption, uint8_t bFileNo, uint8_t ** ppValue,
    uint16_t * pValueLen)
{
    phStatus_t  PH_MEMLOC_REM wStatus = 0;
    phStatus_t  PH_MEMLOC_REM wStatus1 = 0;
    uint32_t    PH_MEMLOC_REM dwTMIStatus = 0;
    uint8_t     PH_MEMLOC_REM bCmd_ComMode = 0;
    uint8_t     PH_MEMLOC_REM bRsp_ComMode = 0;

#ifdef RDR_LIB_PARAM_CHECK
    PHAL_MFDUOX_IS_VALID_FILE_NO(bFileNo);
#endif

    /* Extract Communication and Exchange Options. */
    bRsp_ComMode = (uint8_t) (bOption & PHAL_MFDUOX_COMM_OPTIONS_MASK);

    /* Validate Communication Options. */
    PH_CHECK_SUCCESS_FCT(wStatus, phalMfDuoX_Int_Validate_ComOption(bRsp_ComMode));

    /* Frame the communication mode to be applied. */
    phalMfDuoX_Int_GetCommMode(pDataParams->bAuthState, bOption, &bCmd_ComMode);

    /* Set the DataParams with command code. */
    pDataParams->bCmdCode = PHAL_MFDUOX_CMD_GET_VALUE;

    /* Get TMI Collection Status. */
    PH_CHECK_SUCCESS_FCT(wStatus, phTMIUtils_GetConfig((phTMIUtils_t *)pDataParams->pTMIDataParams, PH_TMIUTILS_TMI_STATUS, &dwTMIStatus));

    /* Clear Buffers. */
    (void) memset(PHAL_MFDUOX_CMD_BUF, 0x00, PHAL_MFDUOX_CMD_BUF_SIZE);
    PHAL_MFDUOX_CMD_BUF_LEN = 0;

    /* Add command code. */
    PHAL_MFDUOX_CMD_BUF[PHAL_MFDUOX_CMD_BUF_LEN++] = pDataParams->bCmdCode;

    /* Add File Number. */
    PHAL_MFDUOX_CMD_BUF[PHAL_MFDUOX_CMD_BUF_LEN++] = bFileNo;

    /* Collect TMI for command header. */
    if(dwTMIStatus)
        PH_CHECK_SUCCESS_FCT(wStatus1, phTMIUtils_CollectTMI((phTMIUtils_t *)pDataParams->pTMIDataParams, PH_TMIUTILS_NO_PADDING, PHAL_MFDUOX_CMD_BUF,
            PHAL_MFDUOX_CMD_BUF_LEN, NULL, 0, PHAL_MFDUOX_BLOCK_SIZE));

    /* Exchange Cmd.GetValue information to PICC. */
    PH_CHECK_SUCCESS_FCT(wStatus, phalMfDuoX_Sw_Int_ReadData(
        pDataParams,
        PH_EXCHANGE_DEFAULT,
        PH_OFF,
        bCmd_ComMode,
        bRsp_ComMode,
        PHAL_MFDUOX_CMD_BUF,
        PHAL_MFDUOX_CMD_BUF_LEN,
        PHAL_MFDUOX_DATA_TO_READ_UNKNOWN,
        ppValue,
        pValueLen));

    /* Perform TMI Collection for Response. */
    if(dwTMIStatus)/* Buffer the Command information to TMI buffer. */
        PH_CHECK_SUCCESS_FCT(wStatus1, phTMIUtils_CollectTMI((phTMIUtils_t *)pDataParams->pTMIDataParams, PH_TMIUTILS_ZEROPAD_DATABUFF, NULL, 0,
            *ppValue, *pValueLen, PHAL_MFDUOX_BLOCK_SIZE));

    return wStatus;
}

phStatus_t phalMfDuoX_Sw_Credit(phalMfDuoX_Sw_DataParams_t * pDataParams, uint8_t bOption, uint8_t bFileNo, uint8_t * pData)
{
    phStatus_t  PH_MEMLOC_REM wStatus = 0;
    uint32_t    PH_MEMLOC_REM dwTMIStatus = 0;
    uint8_t     PH_MEMLOC_REM bRsp_ComMode = 0;

#ifdef RDR_LIB_PARAM_CHECK
    PHAL_MFDUOX_IS_VALID_FILE_NO(bFileNo);
#endif

    /* Validate Communication Options. */
    PH_CHECK_SUCCESS_FCT(wStatus, phalMfDuoX_Int_Validate_ComOption(bOption));

    /* Frame the communication mode to be verified. */
    phalMfDuoX_Int_GetCommMode(pDataParams->bAuthState, bOption, &bRsp_ComMode);

    /* Clear Buffers. */
    (void) memset(PHAL_MFDUOX_CMD_BUF, 0x00, PHAL_MFDUOX_CMD_BUF_SIZE);
    PHAL_MFDUOX_CMD_BUF_LEN = 0;

    (void) memset(PHAL_MFDUOX_PRS_BUF, 0x00, PHAL_MFDUOX_PRS_BUF_SIZE);
    PHAL_MFDUOX_PRS_BUF_LEN = 0;

    /* Set the DataParams with command code. */
    pDataParams->bCmdCode = PHAL_MFDUOX_CMD_CREDIT;

    /* Add command code. */
    PHAL_MFDUOX_CMD_BUF[PHAL_MFDUOX_CMD_BUF_LEN++] = pDataParams->bCmdCode;

    /* Add File Number. */
    PHAL_MFDUOX_CMD_BUF[PHAL_MFDUOX_CMD_BUF_LEN++] = bFileNo;

    /* Get TMI Collection Status. */
    PH_CHECK_SUCCESS_FCT(wStatus, phTMIUtils_GetConfig((phTMIUtils_t *)pDataParams->pTMIDataParams, PH_TMIUTILS_TMI_STATUS, &dwTMIStatus));

    /* Perform TMI Collection for command and data. */
    if(dwTMIStatus)
    {
        PH_CHECK_SUCCESS_FCT(wStatus, phTMIUtils_CollectTMI((phTMIUtils_t *)pDataParams->pTMIDataParams, PH_TMIUTILS_ZEROPAD_DATABUFF,
            PHAL_MFDUOX_CMD_BUF, PHAL_MFDUOX_CMD_BUF_LEN, pData, 4, PHAL_MFDUOX_BLOCK_SIZE));
    }

    /* Exchange Cmd.Credit information to PICC. */
    PH_CHECK_SUCCESS_FCT(wStatus, phalMfDuoX_Sw_Int_WriteData(
        pDataParams,
        PH_OFF,
        bOption,
        bRsp_ComMode,
        PH_OFF,
        PHAL_MFDUOX_CMD_BUF,
        PHAL_MFDUOX_CMD_BUF_LEN,
        pData,
        4,
        NULL,
        NULL));

    return PH_ADD_COMPCODE(PH_ERR_SUCCESS, PH_COMP_AL_MFDUOX);
}

phStatus_t phalMfDuoX_Sw_Debit(phalMfDuoX_Sw_DataParams_t * pDataParams, uint8_t bOption, uint8_t bFileNo, uint8_t * pData)
{
    phStatus_t  PH_MEMLOC_REM wStatus = 0;
    uint32_t    PH_MEMLOC_REM dwTMIStatus = 0;
    uint8_t     PH_MEMLOC_REM bRsp_ComMode = 0;

#ifdef RDR_LIB_PARAM_CHECK
    PHAL_MFDUOX_IS_VALID_FILE_NO(bFileNo);
#endif

    /* Validate Communication Options. */
    PH_CHECK_SUCCESS_FCT(wStatus, phalMfDuoX_Int_Validate_ComOption(bOption));

    /* Frame the communication mode to be verified. */
    phalMfDuoX_Int_GetCommMode(pDataParams->bAuthState, bOption, &bRsp_ComMode);

    /* Clear Buffers. */
    (void) memset(PHAL_MFDUOX_CMD_BUF, 0x00, PHAL_MFDUOX_CMD_BUF_SIZE);
    PHAL_MFDUOX_CMD_BUF_LEN = 0;

    (void) memset(PHAL_MFDUOX_PRS_BUF, 0x00, PHAL_MFDUOX_PRS_BUF_SIZE);
    PHAL_MFDUOX_PRS_BUF_LEN = 0;

    /* Set the DataParams with command code. */
    pDataParams->bCmdCode = PHAL_MFDUOX_CMD_DEBIT;

    /* Add command code. */
    PHAL_MFDUOX_CMD_BUF[PHAL_MFDUOX_CMD_BUF_LEN++] = pDataParams->bCmdCode;

    /* Add File Number. */
    PHAL_MFDUOX_CMD_BUF[PHAL_MFDUOX_CMD_BUF_LEN++] = bFileNo;

    /* Get TMI Collection Status. */
    PH_CHECK_SUCCESS_FCT(wStatus, phTMIUtils_GetConfig((phTMIUtils_t *)pDataParams->pTMIDataParams, PH_TMIUTILS_TMI_STATUS, &dwTMIStatus));

    /* Perform TMI Collection for command and data. */
    if(dwTMIStatus)
    {
        PH_CHECK_SUCCESS_FCT(wStatus, phTMIUtils_CollectTMI((phTMIUtils_t *)pDataParams->pTMIDataParams, PH_TMIUTILS_ZEROPAD_DATABUFF,
            PHAL_MFDUOX_CMD_BUF, PHAL_MFDUOX_CMD_BUF_LEN, pData, 4, PHAL_MFDUOX_BLOCK_SIZE));
    }

    /* Exchange Cmd.Debit information to PICC. */
    PH_CHECK_SUCCESS_FCT(wStatus, phalMfDuoX_Sw_Int_WriteData(
        pDataParams,
        PH_OFF,
        bOption,
        bRsp_ComMode,
        PH_OFF,
        PHAL_MFDUOX_CMD_BUF,
        PHAL_MFDUOX_CMD_BUF_LEN,
        pData,
        4,
        NULL,
        NULL));

    return PH_ADD_COMPCODE(PH_ERR_SUCCESS, PH_COMP_AL_MFDUOX);
}

phStatus_t phalMfDuoX_Sw_LimitedCredit(phalMfDuoX_Sw_DataParams_t * pDataParams, uint8_t bOption, uint8_t bFileNo, uint8_t * pData)
{
    phStatus_t  PH_MEMLOC_REM wStatus = 0;
    uint32_t    PH_MEMLOC_REM dwTMIStatus = 0;
    uint8_t     PH_MEMLOC_REM bRsp_ComMode = 0;

#ifdef RDR_LIB_PARAM_CHECK
    PHAL_MFDUOX_IS_VALID_FILE_NO(bFileNo);
#endif

    /* Validate Communication Options. */
    PH_CHECK_SUCCESS_FCT(wStatus, phalMfDuoX_Int_Validate_ComOption(bOption));

    /* Frame the communication mode to be verified. */
    phalMfDuoX_Int_GetCommMode(pDataParams->bAuthState, bOption, &bRsp_ComMode);

    /* Clear Buffers. */
    (void) memset(PHAL_MFDUOX_CMD_BUF, 0x00, PHAL_MFDUOX_CMD_BUF_SIZE);
    PHAL_MFDUOX_CMD_BUF_LEN = 0;

    (void) memset(PHAL_MFDUOX_PRS_BUF, 0x00, PHAL_MFDUOX_PRS_BUF_SIZE);
    PHAL_MFDUOX_PRS_BUF_LEN = 0;

    /* Set the DataParams with command code. */
    pDataParams->bCmdCode = PHAL_MFDUOX_CMD_LIMITED_CREDIT;

    /* Add command code. */
    PHAL_MFDUOX_CMD_BUF[PHAL_MFDUOX_CMD_BUF_LEN++] = pDataParams->bCmdCode;

    /* Add File Number. */
    PHAL_MFDUOX_CMD_BUF[PHAL_MFDUOX_CMD_BUF_LEN++] = bFileNo;

    /* Get TMI Collection Status. */
    PH_CHECK_SUCCESS_FCT(wStatus, phTMIUtils_GetConfig((phTMIUtils_t *)pDataParams->pTMIDataParams, PH_TMIUTILS_TMI_STATUS, &dwTMIStatus));

    /* Perform TMI Collection for command and data. */
    if(dwTMIStatus)
    {
        PH_CHECK_SUCCESS_FCT(wStatus, phTMIUtils_CollectTMI((phTMIUtils_t *)pDataParams->pTMIDataParams, PH_TMIUTILS_ZEROPAD_DATABUFF,
            PHAL_MFDUOX_CMD_BUF, PHAL_MFDUOX_CMD_BUF_LEN, pData, 4, PHAL_MFDUOX_BLOCK_SIZE));
    }

    /* Exchange Cmd.LimitedCredit information to PICC. */
    PH_CHECK_SUCCESS_FCT(wStatus, phalMfDuoX_Sw_Int_WriteData(
        pDataParams,
        PH_OFF,
        bOption,
        bRsp_ComMode,
        PH_OFF,
        PHAL_MFDUOX_CMD_BUF,
        PHAL_MFDUOX_CMD_BUF_LEN,
        pData,
        4,
        NULL,
        NULL));

    return PH_ADD_COMPCODE(PH_ERR_SUCCESS, PH_COMP_AL_MFDUOX);
}

phStatus_t phalMfDuoX_Sw_ReadRecords(phalMfDuoX_Sw_DataParams_t * pDataParams, uint8_t bOption, uint8_t bIns, uint8_t bFileNo,
    uint8_t * pRecNo, uint8_t * pRecCount, uint8_t * pRecSize, uint8_t ** ppResponse, uint16_t * pRspLen)
{
    phStatus_t  PH_MEMLOC_REM wStatus = 0;
    phStatus_t  PH_MEMLOC_REM wStatus1 = 0;
    uint32_t    PH_MEMLOC_REM dwTMIOffset_Len = 0;
    uint32_t    PH_MEMLOC_REM dwTMIBuf_Index = 0;
    uint32_t    PH_MEMLOC_REM dwTMIStatus = 0;
    uint32_t    PH_MEMLOC_REM dwDataLen = 0;
    uint32_t    PH_MEMLOC_REM dwNumRec = 0;
    uint32_t    PH_MEMLOC_REM dwNumRec_Calc = 0;
    uint32_t    PH_MEMLOC_REM dwRecLen = 0;
    uint8_t     PH_MEMLOC_REM bExchange_Option = 0;
    uint8_t     PH_MEMLOC_REM bCmd_ComMode = 0;
    uint8_t     PH_MEMLOC_REM bRsp_ComMode = 0;
    uint8_t     PH_MEMLOC_REM bTMIOption = 0;

#ifdef RDR_LIB_PARAM_CHECK
    PHAL_MFDUOX_IS_VALID_FILE_NO(bFileNo);
#endif

    /* Extract Communication and Exchange Options. */
    bRsp_ComMode = (uint8_t) (bOption & PHAL_MFDUOX_COMM_OPTIONS_MASK);
    bExchange_Option = (uint8_t) (bOption & PH_EXCHANGE_MODE_MASK);

    /* Validate Communication Options. */
    PH_CHECK_SUCCESS_FCT(wStatus, phalMfDuoX_Int_Validate_ComOption(bRsp_ComMode));

    /* Validate Exchange Options. */
    PHAL_MFDUOX_VALIDATE_RX_EXCHANGE_OPTIONS(bExchange_Option);

    /* Validate Chaining Options. */
    PHAL_MFDUOX_VALIDATE_CHAINING_OPTIONS(bIns);

    /* Frame the communication mode to be applied. */
    phalMfDuoX_Int_GetCommMode(pDataParams->bAuthState, bOption, &bCmd_ComMode);

    /* Set the DataParams with command code. */
    pDataParams->bCmdCode = (uint8_t) (bIns ? PHAL_MFDUOX_CMD_READ_RECORD_ISO : PHAL_MFDUOX_CMD_READ_RECORD_NATIVE);

    /* Get TMI Collection Status. */
    PH_CHECK_SUCCESS_FCT(wStatus, phTMIUtils_GetConfig((phTMIUtils_t *)pDataParams->pTMIDataParams, PH_TMIUTILS_TMI_STATUS, &dwTMIStatus));

    /* Frame the command information. */
    if(bExchange_Option != PH_EXCHANGE_RXCHAINING)
    {
        /* Compute the number of records. */
        dwNumRec = pRecCount[2];
        dwNumRec = dwNumRec << 8 | pRecCount[1];
        dwNumRec = dwNumRec << 8 | pRecCount[0];

        /* Compute the record length. */
        dwRecLen = pRecSize[2];
        dwRecLen = dwRecLen << 8 | pRecSize[1];
        dwRecLen = dwRecLen << 8 | pRecSize[0];

        /* Clear Buffers. */
        (void) memset(PHAL_MFDUOX_CMD_BUF, 0x00, PHAL_MFDUOX_CMD_BUF_SIZE);
        PHAL_MFDUOX_CMD_BUF_LEN = 0;

        /* Add command code. */
        PHAL_MFDUOX_CMD_BUF[PHAL_MFDUOX_CMD_BUF_LEN++] = pDataParams->bCmdCode;

        /* Add File Number. */
        PHAL_MFDUOX_CMD_BUF[PHAL_MFDUOX_CMD_BUF_LEN++] = bFileNo;

        /* Add Record Number. */
        (void) memcpy(&PHAL_MFDUOX_CMD_BUF[PHAL_MFDUOX_CMD_BUF_LEN], pRecNo, 3);
        PHAL_MFDUOX_CMD_BUF_LEN += 3;

        /* Add Record Count. */
        (void) memcpy(&PHAL_MFDUOX_CMD_BUF[PHAL_MFDUOX_CMD_BUF_LEN], pRecCount, 3);
        PHAL_MFDUOX_CMD_BUF_LEN += 3;

        /* Perform TMI Collection for Command Header. */
        if(dwTMIStatus)
        {
            /* Should provide at least wRecLen / wNumRec to update in TMI collection */
            if((0 == dwRecLen) && (0 == dwNumRec))
            {
                return PH_ADD_COMPCODE(PH_ERR_INVALID_PARAMETER, PH_COMP_AL_MFDUOX);
            }

            /* Frame the Option. */
            bTMIOption = (uint8_t) (PH_TMIUTILS_READ_INS | PH_TMIUTILS_ZEROPAD_CMDBUFF);

            /* Buffer the Command information to TMI buffer. */
            PH_CHECK_SUCCESS_FCT(wStatus, phTMIUtils_CollectTMI((phTMIUtils_t *)pDataParams->pTMIDataParams, bTMIOption, PHAL_MFDUOX_CMD_BUF,
                PHAL_MFDUOX_CMD_BUF_LEN, NULL, 0, PHAL_MFDUOX_BLOCK_SIZE));
        }
    }
    else
    {
        /* Chaining is handled internally. */
    }

    /* Exchange Cmd.ReadData information to PICC. */
    wStatus = phalMfDuoX_Sw_Int_ReadData(
        pDataParams,
        bExchange_Option,
        bIns,
        bCmd_ComMode,
        bRsp_ComMode,
        PHAL_MFDUOX_CMD_BUF,
        PHAL_MFDUOX_CMD_BUF_LEN,
        dwNumRec * dwRecLen,
        ppResponse,
        pRspLen);

    /* Validate Status. */
    if(((wStatus & PH_ERR_MASK) != PH_ERR_SUCCESS) && ((wStatus & PH_ERR_MASK) != PH_ERR_SUCCESS_CHAINING))
        return wStatus;

    /* Perform TMI Collection for Response. */
    if(dwTMIStatus)
    {
        /* Update Actual Record Length in case of zeros. */
        if((dwNumRec == 0) && (wStatus == PH_ERR_SUCCESS))
        {
            PH_CHECK_SUCCESS_FCT(wStatus1, phTMIUtils_GetConfig((phTMIUtils_t *) pDataParams->pTMIDataParams,
                PH_TMIUTILS_TMI_OFFSET_LENGTH, &dwTMIOffset_Len));

            PH_CHECK_SUCCESS_FCT(wStatus1, phTMIUtils_GetConfig((phTMIUtils_t *) pDataParams->pTMIDataParams,
                PH_TMIUTILS_TMI_BUFFER_INDEX, &dwTMIBuf_Index));

            /* calculate Rx length in case of chaining */
            dwDataLen = *pRspLen + dwTMIBuf_Index - (dwTMIOffset_Len + 11);

            /* If user updates wrong RecSize, we cant calculate RecCnt */
            if(dwDataLen % dwRecLen)
            {
                return PH_ADD_COMPCODE(PH_ERR_PROTOCOL_ERROR, PH_COMP_AL_MFDUOX);
            }

            /* Calculate actual number of records */
            dwNumRec_Calc = dwDataLen / dwRecLen;

            /* Update actual number of records to TMI buffer */
            PH_CHECK_SUCCESS_FCT(wStatus1, phTMIUtils_SetConfig((phTMIUtils_t *) pDataParams->pTMIDataParams,
                PH_TMIUTILS_TMI_OFFSET_VALUE, dwNumRec_Calc));
        }

        /* Frame the Option. */
        bTMIOption = (uint8_t) ((wStatus == PH_ERR_SUCCESS) ? PH_TMIUTILS_ZEROPAD_DATABUFF : PH_TMIUTILS_NO_PADDING);

        /* Buffer the Command information to TMI buffer. */
        PH_CHECK_SUCCESS_FCT(wStatus1, phTMIUtils_CollectTMI((phTMIUtils_t *)pDataParams->pTMIDataParams, bTMIOption, NULL, 0,
            *ppResponse, *pRspLen, PHAL_MFDUOX_BLOCK_SIZE));

        /* Reset the TMI buffer Offset. */
        if(((wStatus & PH_ERR_MASK) == PH_ERR_SUCCESS) && (dwNumRec == 0))
        {
            /* Reset Offset in TMI. */
            PH_CHECK_SUCCESS_FCT(wStatus1, phTMIUtils_SetConfig((phTMIUtils_t *)pDataParams->pTMIDataParams, PH_TMIUTILS_TMI_OFFSET_LENGTH, 0));
        }
    }

    return wStatus;
}

phStatus_t phalMfDuoX_Sw_WriteRecord(phalMfDuoX_Sw_DataParams_t * pDataParams, uint8_t bOption, uint8_t bIns, uint8_t bFileNo,
    uint8_t * pOffset, uint8_t * pData, uint8_t * pLength)
{
    phStatus_t  PH_MEMLOC_REM wStatus = 0;
    uint32_t    PH_MEMLOC_REM dwTMIStatus = 0;
    uint32_t    PH_MEMLOC_REM dwLength = 0;
    uint8_t     PH_MEMLOC_REM bRsp_ComMode = 0;

#ifdef RDR_LIB_PARAM_CHECK
    PHAL_MFDUOX_IS_VALID_FILE_NO(bFileNo);
#endif

    /* Validate Communication Options. */
    PH_CHECK_SUCCESS_FCT(wStatus, phalMfDuoX_Int_Validate_ComOption(bOption));

    /* Validate Chaining Options. */
    PHAL_MFDUOX_VALIDATE_CHAINING_OPTIONS(bIns);

    /* Frame the communication mode to be verified. */
    phalMfDuoX_Int_GetCommMode(pDataParams->bAuthState, bOption, &bRsp_ComMode);

    /* Compute the length. */
    dwLength = pLength[2];
    dwLength = dwLength << 8 | pLength[1];
    dwLength = dwLength << 8 | pLength[0];

    /* Clear Buffers. */
    (void) memset(PHAL_MFDUOX_CMD_BUF, 0x00, PHAL_MFDUOX_CMD_BUF_SIZE);
    PHAL_MFDUOX_CMD_BUF_LEN = 0;

    (void) memset(PHAL_MFDUOX_PRS_BUF, 0x00, PHAL_MFDUOX_PRS_BUF_SIZE);
    PHAL_MFDUOX_PRS_BUF_LEN = 0;

    /* Set the DataParams with command code. */
    pDataParams->bCmdCode = (uint8_t) (bIns ? PHAL_MFDUOX_CMD_WRITE_RECORD_ISO : PHAL_MFDUOX_CMD_WRITE_RECORD_NATIVE);

    /* Add command code. */
    PHAL_MFDUOX_CMD_BUF[PHAL_MFDUOX_CMD_BUF_LEN++] = pDataParams->bCmdCode;

    /* Add File Number. */
    PHAL_MFDUOX_CMD_BUF[PHAL_MFDUOX_CMD_BUF_LEN++] = bFileNo;

    /* Add offset. */
    (void) memcpy(&PHAL_MFDUOX_CMD_BUF[PHAL_MFDUOX_CMD_BUF_LEN], pOffset, 3);
    PHAL_MFDUOX_CMD_BUF_LEN += 3;

    /* Add length. */
    (void) memcpy(&PHAL_MFDUOX_CMD_BUF[PHAL_MFDUOX_CMD_BUF_LEN], pLength, 3);
    PHAL_MFDUOX_CMD_BUF_LEN += 3;

    /* Get TMI Collection Status. */
    PH_CHECK_SUCCESS_FCT(wStatus, phTMIUtils_GetConfig((phTMIUtils_t *)pDataParams->pTMIDataParams, PH_TMIUTILS_TMI_STATUS, &dwTMIStatus));

    /* Perform TMI Collection for command and data. */
    if(dwTMIStatus)
    {
        PH_CHECK_SUCCESS_FCT(wStatus, phTMIUtils_CollectTMI((phTMIUtils_t *)pDataParams->pTMIDataParams, (PH_TMIUTILS_ZEROPAD_CMDBUFF | PH_TMIUTILS_ZEROPAD_DATABUFF),
            PHAL_MFDUOX_CMD_BUF, PHAL_MFDUOX_CMD_BUF_LEN, pData, dwLength, PHAL_MFDUOX_BLOCK_SIZE));
    }

    /* Exchange Cmd.WriteRecord information to PICC. */
    PH_CHECK_SUCCESS_FCT(wStatus, phalMfDuoX_Sw_Int_WriteData(
        pDataParams,
        (uint8_t)!bIns,
        bOption,
        bRsp_ComMode,
        PH_OFF,
        PHAL_MFDUOX_CMD_BUF,
        PHAL_MFDUOX_CMD_BUF_LEN,
        pData,
        dwLength,
        NULL,
        NULL));

    return PH_ADD_COMPCODE(PH_ERR_SUCCESS, PH_COMP_AL_MFDUOX);
}

phStatus_t phalMfDuoX_Sw_UpdateRecord(phalMfDuoX_Sw_DataParams_t * pDataParams, uint8_t bOption, uint8_t bIns, uint8_t bFileNo,
    uint8_t * pRecNo, uint8_t * pOffset, uint8_t * pData, uint8_t * pLength)
{
    phStatus_t  PH_MEMLOC_REM wStatus = 0;
    uint32_t    PH_MEMLOC_REM dwTMIStatus = 0;
    uint32_t    PH_MEMLOC_REM dwLength = 0;
    uint8_t     PH_MEMLOC_REM bRsp_ComMode = 0;

#ifdef RDR_LIB_PARAM_CHECK
    PHAL_MFDUOX_IS_VALID_FILE_NO(bFileNo);
#endif

    /* Validate Communication Options. */
    PH_CHECK_SUCCESS_FCT(wStatus, phalMfDuoX_Int_Validate_ComOption(bOption));

    /* Validate Chaining Options. */
    PHAL_MFDUOX_VALIDATE_CHAINING_OPTIONS(bIns);

    /* Frame the communication mode to be verified. */
    phalMfDuoX_Int_GetCommMode(pDataParams->bAuthState, bOption, &bRsp_ComMode);

    /* Compute the length. */
    dwLength = pLength[2];
    dwLength = dwLength << 8 | pLength[1];
    dwLength = dwLength << 8 | pLength[0];

    /* Clear Buffers. */
    (void) memset(PHAL_MFDUOX_CMD_BUF, 0x00, PHAL_MFDUOX_CMD_BUF_SIZE);
    PHAL_MFDUOX_CMD_BUF_LEN = 0;

    (void) memset(PHAL_MFDUOX_PRS_BUF, 0x00, PHAL_MFDUOX_PRS_BUF_SIZE);
    PHAL_MFDUOX_PRS_BUF_LEN = 0;

    /* Set the DataParams with command code. */
    pDataParams->bCmdCode = (uint8_t) (bIns ? PHAL_MFDUOX_CMD_UPDATE_RECORD_ISO : PHAL_MFDUOX_CMD_UPDATE_RECORD_NATIVE);

    /* Add command code. */
    PHAL_MFDUOX_CMD_BUF[PHAL_MFDUOX_CMD_BUF_LEN++] = pDataParams->bCmdCode;

    /* Add File Number. */
    PHAL_MFDUOX_CMD_BUF[PHAL_MFDUOX_CMD_BUF_LEN++] = bFileNo;

    /* Add Record Number. */
    (void) memcpy(&PHAL_MFDUOX_CMD_BUF[PHAL_MFDUOX_CMD_BUF_LEN], pRecNo, 3);
    PHAL_MFDUOX_CMD_BUF_LEN += 3;

    /* Add offset. */
    (void) memcpy(&PHAL_MFDUOX_CMD_BUF[PHAL_MFDUOX_CMD_BUF_LEN], pOffset, 3);
    PHAL_MFDUOX_CMD_BUF_LEN += 3;

    /* Add length. */
    (void) memcpy(&PHAL_MFDUOX_CMD_BUF[PHAL_MFDUOX_CMD_BUF_LEN], pLength, 3);
    PHAL_MFDUOX_CMD_BUF_LEN += 3;

    /* Get TMI Collection Status. */
    PH_CHECK_SUCCESS_FCT(wStatus, phTMIUtils_GetConfig((phTMIUtils_t *)pDataParams->pTMIDataParams, PH_TMIUTILS_TMI_STATUS, &dwTMIStatus));

    /* Perform TMI Collection for command and data. */
    if(dwTMIStatus)
    {
        PH_CHECK_SUCCESS_FCT(wStatus, phTMIUtils_CollectTMI((phTMIUtils_t *)pDataParams->pTMIDataParams, (PH_TMIUTILS_ZEROPAD_CMDBUFF | PH_TMIUTILS_ZEROPAD_DATABUFF),
            PHAL_MFDUOX_CMD_BUF, PHAL_MFDUOX_CMD_BUF_LEN, pData, dwLength, PHAL_MFDUOX_BLOCK_SIZE));
    }

    /* Exchange Cmd.UpdateRecord information to PICC. */
    PH_CHECK_SUCCESS_FCT(wStatus, phalMfDuoX_Sw_Int_WriteData(
        pDataParams,
        (uint8_t)!bIns,
        bOption,
        bRsp_ComMode,
        PH_OFF,
        PHAL_MFDUOX_CMD_BUF,
        PHAL_MFDUOX_CMD_BUF_LEN,
        pData,
        dwLength,
        NULL,
        NULL));

    return PH_ADD_COMPCODE(PH_ERR_SUCCESS, PH_COMP_AL_MFDUOX);
}

phStatus_t phalMfDuoX_Sw_ClearRecordFile(phalMfDuoX_Sw_DataParams_t * pDataParams, uint8_t bFileNo)
{
    phStatus_t  PH_MEMLOC_REM wStatus = 0;
    uint32_t    PH_MEMLOC_REM dwTMIStatus = 0;
    uint8_t     PH_MEMLOC_REM bComMode = 0;

#ifdef RDR_LIB_PARAM_CHECK
    PHAL_MFDUOX_IS_VALID_FILE_NO(bFileNo);
#endif

    /* Clear Buffers. */
    (void) memset(PHAL_MFDUOX_CMD_BUF, 0x00, PHAL_MFDUOX_CMD_BUF_SIZE);
    PHAL_MFDUOX_CMD_BUF_LEN = 0;

    (void) memset(PHAL_MFDUOX_PRS_BUF, 0x00, PHAL_MFDUOX_PRS_BUF_SIZE);
    PHAL_MFDUOX_PRS_BUF_LEN = 0;

    /* Frame the communication mode to be applied. */
    phalMfDuoX_Int_GetCommMode(pDataParams->bAuthState, PHAL_MFDUOX_COMMUNICATION_INVALID,
        &bComMode);

    /* Set the DataParams with command code. */
    pDataParams->bCmdCode = PHAL_MFDUOX_CMD_CLEAR_RECORD;

    /* Add command code. */
    PHAL_MFDUOX_CMD_BUF[PHAL_MFDUOX_CMD_BUF_LEN++] = pDataParams->bCmdCode;

    /* Add File Number. */
    PHAL_MFDUOX_CMD_BUF[PHAL_MFDUOX_CMD_BUF_LEN++] = bFileNo;

    /* Get TMI Collection Status. */
    PH_CHECK_SUCCESS_FCT(wStatus, phTMIUtils_GetConfig((phTMIUtils_t *)pDataParams->pTMIDataParams, PH_TMIUTILS_TMI_STATUS, &dwTMIStatus));

    /* Perform TMI Collection for command and data. */
    if(dwTMIStatus)
    {
        PH_CHECK_SUCCESS_FCT(wStatus, phTMIUtils_CollectTMI((phTMIUtils_t *)pDataParams->pTMIDataParams, PH_TMIUTILS_ZEROPAD_CMDBUFF,
            PHAL_MFDUOX_CMD_BUF, PHAL_MFDUOX_CMD_BUF_LEN, NULL, 0, PHAL_MFDUOX_BLOCK_SIZE));
    }

    /* Exchange Cmd.WriteRecord information to PICC. */
    PH_CHECK_SUCCESS_FCT(wStatus, phalMfDuoX_Sw_Int_WriteData(
        pDataParams,
        PH_OFF,
        bComMode,
        bComMode,
        PH_OFF,
        PHAL_MFDUOX_CMD_BUF,
        PHAL_MFDUOX_CMD_BUF_LEN,
        NULL,
        0,
        NULL,
        NULL));

    return PH_ADD_COMPCODE(PH_ERR_SUCCESS, PH_COMP_AL_MFDUOX);
}

/* MIFARE DUOX Transaction Management commands ------------------------------------------------------------------------------------------ */
phStatus_t phalMfDuoX_Sw_CommitTransaction(phalMfDuoX_Sw_DataParams_t * pDataParams, uint8_t bOption, uint8_t ** ppTMC,
    uint16_t * pTMCLen, uint8_t ** ppResponse, uint16_t * pRspLen)
{
    phStatus_t  PH_MEMLOC_REM wStatus = 0;
    uint8_t     PH_MEMLOC_REM bComMode = 0;
    uint16_t    PH_MEMLOC_REM wRspLen = 0;

    uint8_t     PH_MEMLOC_REM *pResponse = NULL;

#ifdef RDR_LIB_PARAM_CHECK
    if((bOption & PHAL_MFDUOX_OPTION_MASK) > PHAL_MFDUOX_OPTION_TRANSACTION_INFO_RETURNED)
    {
        return PH_ADD_COMPCODE(PH_ERR_INVALID_PARAMETER, PH_COMP_AL_MFDUOX);
    }
#endif

    /* Set the DataParams with command code. */
    pDataParams->bCmdCode = PHAL_MFDUOX_CMD_COMMIT_TRANSACTION;

    /* Frame the communication mode to be applied. */
    phalMfDuoX_Int_GetCommMode(pDataParams->bAuthState, PHAL_MFDUOX_COMMUNICATION_INVALID,
        &bComMode);

    /* Clear Buffers. */
    (void) memset(PHAL_MFDUOX_CMD_BUF, 0x00, PHAL_MFDUOX_CMD_BUF_SIZE);
    PHAL_MFDUOX_CMD_BUF_LEN = 0;

    (void) memset(PHAL_MFDUOX_PRS_BUF, 0x00, PHAL_MFDUOX_PRS_BUF_SIZE);
    PHAL_MFDUOX_PRS_BUF_LEN = 0;

    /* Frame the command information. */
    PHAL_MFDUOX_CMD_BUF[PHAL_MFDUOX_CMD_BUF_LEN++] = PHAL_MFDUOX_CMD_COMMIT_TRANSACTION;

    /* Add Option to command buffer. */
    if(bOption != PHAL_MFDUOX_OPTION_NOT_EXCHANGED)
        PHAL_MFDUOX_CMD_BUF[PHAL_MFDUOX_CMD_BUF_LEN++] = (uint8_t) (bOption & PHAL_MFDUOX_OPTION_MASK);

    /* Exchange Cmd.CommitTransaction information to PICC. */
    PH_CHECK_SUCCESS_FCT(wStatus, phalMfDuoX_Sw_Int_ReadData(
        pDataParams,
        PH_EXCHANGE_DEFAULT,
        PH_OFF,
        bComMode,
        bComMode,
        PHAL_MFDUOX_CMD_BUF,
        PHAL_MFDUOX_CMD_BUF_LEN,
        PHAL_MFDUOX_DATA_TO_READ_UNKNOWN,
        &pResponse,
        &wRspLen));

    /* Update the response parameters. */
    if(bOption == PHAL_MFDUOX_OPTION_TRANSACTION_INFO_RETURNED)
    {
        *ppTMC = pResponse;
        *pTMCLen = 4;

        *ppResponse = &pResponse[4];
        *pRspLen = (uint16_t) (wRspLen - 4);
    }

    return PH_ADD_COMPCODE(PH_ERR_SUCCESS, PH_COMP_AL_MFDUOX);
}

phStatus_t phalMfDuoX_Sw_AbortTransaction(phalMfDuoX_Sw_DataParams_t * pDataParams)
{
    phStatus_t  PH_MEMLOC_REM wStatus = 0;
    uint8_t     PH_MEMLOC_REM bComMode = 0;

    /* Set the DataParams with command code. */
    pDataParams->bCmdCode = PHAL_MFDUOX_CMD_ABORT_TRANSACTION;

    /* Frame the communication mode to be applied. */
    phalMfDuoX_Int_GetCommMode(pDataParams->bAuthState, PHAL_MFDUOX_COMMUNICATION_INVALID,
        &bComMode);

    /* Clear Buffers. */
    (void) memset(PHAL_MFDUOX_CMD_BUF, 0x00, PHAL_MFDUOX_CMD_BUF_SIZE);
    PHAL_MFDUOX_CMD_BUF_LEN = 0;

    (void) memset(PHAL_MFDUOX_PRS_BUF, 0x00, PHAL_MFDUOX_PRS_BUF_SIZE);
    PHAL_MFDUOX_PRS_BUF_LEN = 0;

    /* Frame the command information. */
    PHAL_MFDUOX_CMD_BUF[PHAL_MFDUOX_CMD_BUF_LEN++] = PHAL_MFDUOX_CMD_ABORT_TRANSACTION;

    /* Exchange Cmd.AbortTransaction information to PICC. */
    PH_CHECK_SUCCESS_FCT(wStatus, phalMfDuoX_Sw_Int_WriteData(
        pDataParams,
        PH_OFF,
        bComMode,
        bComMode,
        PH_OFF,
        PHAL_MFDUOX_CMD_BUF,
        PHAL_MFDUOX_CMD_BUF_LEN,
        NULL,
        0,
        NULL,
        NULL));

    return PH_ADD_COMPCODE(PH_ERR_SUCCESS, PH_COMP_AL_MFDUOX);
}

phStatus_t phalMfDuoX_Sw_CommitReaderID(phalMfDuoX_Sw_DataParams_t * pDataParams, uint8_t * pTMRI, uint8_t bTMRILen,
    uint8_t ** ppEncTMRI, uint16_t * pEncTMRILen)
{
    phStatus_t  PH_MEMLOC_REM wStatus = 0;
    uint8_t     PH_MEMLOC_REM bComMode = 0;
    uint8_t     PH_MEMLOC_REM bOption = 0;
    uint16_t    PH_MEMLOC_REM wRspLen = 0;
    uint32_t    PH_MEMLOC_REM dwTMIStatus = 0;

    uint8_t     PH_MEMLOC_REM *pResponse = NULL;

    /* Commit Reader ID command Exchange ----------------------------------------------------------------------------------------------- */
    /* Set the DataParams with command code. */
    pDataParams->bCmdCode = PHAL_MFDUOX_CMD_COMMIT_READER_ID;

    /* Frame the communication mode to be applied. */
    phalMfDuoX_Int_GetCommMode(pDataParams->bAuthState, PHAL_MFDUOX_COMMUNICATION_INVALID,
        &bComMode);

    /* Clear Buffers. */
    (void) memset(PHAL_MFDUOX_CMD_BUF, 0x00, PHAL_MFDUOX_CMD_BUF_SIZE);
    PHAL_MFDUOX_CMD_BUF_LEN = 0;

    (void) memset(PHAL_MFDUOX_PRS_BUF, 0x00, PHAL_MFDUOX_PRS_BUF_SIZE);
    PHAL_MFDUOX_PRS_BUF_LEN = 0;

    /* Frame the command information. */
    PHAL_MFDUOX_CMD_BUF[PHAL_MFDUOX_CMD_BUF_LEN++] = pDataParams->bCmdCode;

    /* Exchange Cmd.CommitReaderID information to PICC. */
    PH_CHECK_SUCCESS_FCT(wStatus, phalMfDuoX_Sw_Int_WriteData(
        pDataParams,
        PH_OFF,
        bComMode,
        bComMode,
        PH_OFF,
        PHAL_MFDUOX_CMD_BUF,
        PHAL_MFDUOX_CMD_BUF_LEN,
        pTMRI,
        bTMRILen,
        &pResponse,
        &wRspLen));

    /* Update the response parameters. */
    *ppEncTMRI = pResponse;
    *pEncTMRILen = wRspLen;

    /* Perform TMICollection ----------------------------------------------------------------------------------------------------------- */

    /* Get TMI Collection status. */
    PH_CHECK_SUCCESS_FCT(wStatus, phTMIUtils_GetConfig((phTMIUtils_t *) pDataParams->pTMIDataParams,
        PH_TMIUTILS_TMI_STATUS,
        &dwTMIStatus));

    /* Perform TMI Collection. */
    if(dwTMIStatus == PH_ON)
    {
        /* Frame the command information. */
        PHAL_MFDUOX_CMD_BUF_LEN = 0;
        PHAL_MFDUOX_CMD_BUF[PHAL_MFDUOX_CMD_BUF_LEN++] = pDataParams->bCmdCode;

        /* Add TMRI to command buffer. */
        (void) memcpy(&PHAL_MFDUOX_CMD_BUF[PHAL_MFDUOX_CMD_BUF_LEN], pTMRI, bTMRILen);
        PHAL_MFDUOX_CMD_BUF_LEN += bTMRILen;

        /* Update the response length to use.
         *  In case of Authenticated, EncTMRI information needs to be provided for TMI Collection.
         */
        wRspLen = (uint16_t) ((pDataParams->bAuthState == PHAL_MFDUOX_NOT_AUTHENTICATED) ? 0 : wRspLen);

        /* Set the padding option to use for TMI collection. */
        bOption = (uint8_t) (wRspLen ? PH_TMIUTILS_ZEROPAD_DATABUFF : PH_TMIUTILS_ZEROPAD_CMDBUFF);

        /* Perform TMI COllection. */
        PH_CHECK_SUCCESS_FCT(wStatus, phTMIUtils_CollectTMI((phTMIUtils_t *) pDataParams->pTMIDataParams,
            bOption,
            PHAL_MFDUOX_CMD_BUF,
            PHAL_MFDUOX_CMD_BUF_LEN,
            pResponse,
            wRspLen,
            PHAL_MFDUOX_BLOCK_SIZE));
    }

    return PH_ADD_COMPCODE(PH_ERR_SUCCESS, PH_COMP_AL_MFDUOX);
}

/* MIFARE DUOX Cryptographic support commands ------------------------------------------------------------------------------------------- */
phStatus_t phalMfDuoX_Sw_CryptoRequest(phalMfDuoX_Sw_DataParams_t * pDataParams, uint8_t bComOption, uint8_t bAction,
    uint8_t * pInputData, uint16_t wInputLen, uint8_t ** ppResponse, uint16_t * pRspLen)
{
    phStatus_t  PH_MEMLOC_REM wStatus = 0;

    uint8_t     PH_MEMLOC_REM *pCmdData = NULL;
    uint16_t    PH_MEMLOC_REM wCmdDataLen = 0;

    /* Validate Communication options. */
    PH_CHECK_SUCCESS_FCT(wStatus, phalMfDuoX_Int_Validate_ComOption(bComOption));

    /* Set the DataParams with command code. */
    pDataParams->bCmdCode = PHAL_MFDUOX_CMD_CRYPTO_REQUEST;

    /* Clear Buffers. */
    (void) memset(PHAL_MFDUOX_CMD_BUF, 0x00, PHAL_MFDUOX_CMD_BUF_SIZE);
    PHAL_MFDUOX_CMD_BUF_LEN = 0;

    (void) memset(PHAL_MFDUOX_PRS_BUF, 0x00, PHAL_MFDUOX_PRS_BUF_SIZE);
    PHAL_MFDUOX_PRS_BUF_LEN = 0;

    /* Frame the command information. */
    PHAL_MFDUOX_CMD_BUF[PHAL_MFDUOX_CMD_BUF_LEN++] = pDataParams->bCmdCode;

    /* Set buffer to use for Command Data. */
    pCmdData = &PHAL_MFDUOX_CMD_BUF[PHAL_MFDUOX_CMD_BUF_LEN];

    /* Frame Command Data */
    pCmdData[wCmdDataLen++] = bAction;

    (void) memcpy(&pCmdData[wCmdDataLen], pInputData, wInputLen);
    wCmdDataLen += wInputLen;

    /* Exchange Cmd.CryptoRequest information to PICC. */
    PH_CHECK_SUCCESS_FCT(wStatus, phalMfDuoX_Sw_Int_WriteData(
        pDataParams,
        PH_OFF,
        bComOption,
        bComOption,
        PH_OFF,
        PHAL_MFDUOX_CMD_BUF,
        PHAL_MFDUOX_CMD_BUF_LEN,
        pCmdData,
        wCmdDataLen,
        ppResponse,
        pRspLen));

    return PH_ADD_COMPCODE(PH_ERR_SUCCESS, PH_COMP_AL_MFDUOX);
}

phStatus_t phalMfDuoX_Sw_CryptoRequestECCSign(phalMfDuoX_Sw_DataParams_t * pDataParams, uint8_t bComOption, uint8_t bOperation,
    uint8_t bAlgo, uint8_t bKeyNo, uint8_t bInputSource, uint8_t * pInputData, uint8_t bInputLen, uint8_t ** ppSign,
    uint16_t * pSignLen)
{
    phStatus_t  PH_MEMLOC_REM wStatus = 0;

    uint8_t     PH_MEMLOC_REM *pCmdData = NULL;
    uint16_t    PH_MEMLOC_REM wCmdDataLen = 0;

    /* Validate Communication options. */
    PH_CHECK_SUCCESS_FCT(wStatus, phalMfDuoX_Int_Validate_ComOption(bComOption));

    /* Set the DataParams with command code. */
    pDataParams->bCmdCode = PHAL_MFDUOX_CMD_CRYPTO_REQUEST_ECCSIGN;

    /* Clear Buffers. */
    (void) memset(PHAL_MFDUOX_CMD_BUF, 0x00, PHAL_MFDUOX_CMD_BUF_SIZE);
    PHAL_MFDUOX_CMD_BUF_LEN = 0;

    (void) memset(PHAL_MFDUOX_PRS_BUF, 0x00, PHAL_MFDUOX_PRS_BUF_SIZE);
    PHAL_MFDUOX_PRS_BUF_LEN = 0;

    /* Frame the command information. */
    PHAL_MFDUOX_CMD_BUF[PHAL_MFDUOX_CMD_BUF_LEN++] = pDataParams->bCmdCode;

    /* Set buffer to use for Command Data. */
    pCmdData = &PHAL_MFDUOX_CMD_BUF[PHAL_MFDUOX_CMD_BUF_LEN];

    /* Frame command data. */
    pCmdData[wCmdDataLen++] = PHAL_MFDUOX_TARGET_ACTION_ECC_SIGN;
    pCmdData[wCmdDataLen++] = bOperation;

    if((bOperation != PHAL_MFDUOX_TARGET_OPERATION_UPDATE_DATA) &&
        (bOperation != PHAL_MFDUOX_TARGET_OPERATION_FINALIZE_DATA))
    {
        pCmdData[wCmdDataLen++] = bAlgo;
        pCmdData[wCmdDataLen++] = bKeyNo;
    }

    pCmdData[wCmdDataLen++] = bInputSource;
    pCmdData[wCmdDataLen++] = bInputLen;

    (void) memcpy(&pCmdData[wCmdDataLen], pInputData, bInputLen);
    wCmdDataLen += bInputLen;

    /* Exchange Cmd.CryptoRequest_DUOXSign information to PICC. */
    PH_CHECK_SUCCESS_FCT(wStatus, phalMfDuoX_Sw_Int_WriteData(
        pDataParams,
        PH_OFF,
        bComOption,
        bComOption,
        PH_OFF,
        PHAL_MFDUOX_CMD_BUF,
        PHAL_MFDUOX_CMD_BUF_LEN,
        pCmdData,
        wCmdDataLen,
        ppSign,
        pSignLen));

    return PH_ADD_COMPCODE(PH_ERR_SUCCESS, PH_COMP_AL_MFDUOX);
}

phStatus_t phalMfDuoX_Sw_CryptoRequestEcho(phalMfDuoX_Sw_DataParams_t * pDataParams, uint8_t bComOption, uint8_t * pInputData,
    uint8_t bInputLen, uint8_t ** ppResponse, uint16_t * pRspLen)
{
    phStatus_t  PH_MEMLOC_REM wStatus = 0;

    uint8_t     PH_MEMLOC_REM *pCmdData = NULL;
    uint16_t    PH_MEMLOC_REM wCmdDataLen = 0;

    /* Validate Communication options. */
    PH_CHECK_SUCCESS_FCT(wStatus, phalMfDuoX_Int_Validate_ComOption(bComOption));

    /* Set the DataParams with command code. */
    pDataParams->bCmdCode = PHAL_MFDUOX_CMD_CRYPTO_REQUEST_ECHO;

    /* Clear Buffers. */
    (void) memset(PHAL_MFDUOX_CMD_BUF, 0x00, PHAL_MFDUOX_CMD_BUF_SIZE);
    PHAL_MFDUOX_CMD_BUF_LEN = 0;

    (void) memset(PHAL_MFDUOX_PRS_BUF, 0x00, PHAL_MFDUOX_PRS_BUF_SIZE);
    PHAL_MFDUOX_PRS_BUF_LEN = 0;

    /* Frame the command information. */
    PHAL_MFDUOX_CMD_BUF[PHAL_MFDUOX_CMD_BUF_LEN++] = pDataParams->bCmdCode;

    /* Set buffer to use for Command Data. */
    pCmdData = &PHAL_MFDUOX_CMD_BUF[PHAL_MFDUOX_CMD_BUF_LEN];

    /* Frame command data. */
    pCmdData[wCmdDataLen++] = PHAL_MFDUOX_TARGET_ACTION_ECC_ECHO;

    (void) memcpy(&pCmdData[wCmdDataLen], pInputData, bInputLen);
    wCmdDataLen += bInputLen;

    /* Exchange Cmd.CryptoRequest_DUOXSign information to PICC. */
    PH_CHECK_SUCCESS_FCT(wStatus, phalMfDuoX_Sw_Int_WriteData(
        pDataParams,
        PH_OFF,
        bComOption,
        bComOption,
        PH_OFF,
        PHAL_MFDUOX_CMD_BUF,
        PHAL_MFDUOX_CMD_BUF_LEN,
        pCmdData,
        wCmdDataLen,
        ppResponse,
        pRspLen));

    return PH_ADD_COMPCODE(PH_ERR_SUCCESS, PH_COMP_AL_MFDUOX);
}

/* MIFARE DUOX GPIO Management commands ------------------------------------------------------------------------------------------------- */
phStatus_t phalMfDuoX_Sw_ManageGPIO(phalMfDuoX_Sw_DataParams_t * pDataParams, uint16_t wOption, uint8_t bGPIONo, uint8_t bOperation,
    uint8_t * pNFCPauseRspData, uint16_t wNFCPauseRspDataLen, uint8_t ** ppResponse, uint16_t * pRspLen)
{
    phStatus_t  PH_MEMLOC_REM wStatus = 0;
    uint16_t    PH_MEMLOC_REM wBuffOption_PICC = 0;
    uint16_t    PH_MEMLOC_REM wTotalLen = 0;
    uint8_t     PH_MEMLOC_REM bBuffOption_SM = 0;
    uint8_t     PH_MEMLOC_REM bCmd_ComMode = 0;
    uint8_t     PH_MEMLOC_REM bRsp_ComMode = 0;
    uint8_t     PH_MEMLOC_REM bPiccErrCode = 0;
    uint8_t     PH_MEMLOC_REM bCmdOption = 0;
    uint8_t     PH_MEMLOC_REM bComplete = PH_OFF;

    uint8_t     PH_MEMLOC_REM *pSMBuff = 0;
    uint16_t    PH_MEMLOC_REM wSmBufLen = 0;

    uint8_t *   PH_MEMLOC_REM pResponse_PICC = NULL;
    uint16_t    PH_MEMLOC_REM wRspLen_PICC = 0;

    /* To resolve warning */
    PH_UNUSED_VARIABLE(bBuffOption_SM);

    /* Validate Communication options. */
    PH_CHECK_SUCCESS_FCT(wStatus, phalMfDuoX_Int_Validate_ComOption((uint8_t) wOption));

    /* Set the DataParams with command code. */
    pDataParams->bCmdCode = PHAL_MFDUOX_CMD_MANAGE_GPIO;

    /* Frame the communication mode to be applied. */
    phalMfDuoX_Int_GetCommMode(pDataParams->bAuthState, (uint8_t) wOption,
        &bCmd_ComMode);
    bRsp_ComMode = (uint8_t) wOption;

    /* Clear Buffers. */
    (void) memset(PHAL_MFDUOX_CMD_BUF, 0x00, PHAL_MFDUOX_CMD_BUF_SIZE);
    PHAL_MFDUOX_CMD_BUF_LEN = 0;

    (void) memset(PHAL_MFDUOX_PRS_BUF, 0x00, PHAL_MFDUOX_PRS_BUF_SIZE);
    PHAL_MFDUOX_PRS_BUF_LEN = 0;

    /* Frame the command information. */
    PHAL_MFDUOX_CMD_BUF[PHAL_MFDUOX_CMD_BUF_LEN++] = pDataParams->bCmdCode;
    PHAL_MFDUOX_CMD_BUF[PHAL_MFDUOX_CMD_BUF_LEN++] = bGPIONo;
    PHAL_MFDUOX_CMD_BUF[PHAL_MFDUOX_CMD_BUF_LEN++] = bOperation;

    /* Compute Total frame length (CmdHdr + CmdData (With or Without MAC)) */
#ifndef NXPBUILD__PHAL_MFDUOX_NDA
    wTotalLen = (uint16_t) (PHAL_MFDUOX_CMD_BUF_LEN + wNFCPauseRspDataLen);
#endif /* NXPBUILD__PHAL_MFDUOX_NDA */

    /* Buffer ManageGPIO command ------------------------------------------------------------------------------------------------------- */
    PH_CHECK_SUCCESS_FCT(wStatus, phalMfDuoX_Sw_Int_CardExchange(
        pDataParams,
        PH_EXCHANGE_BUFFER_FIRST,
        PHAL_MFDUOX_CHAINING_BIT_INVALID,
        PHAL_MFDUOX_OPTION_NONE,
        wTotalLen,
        PH_ON,
        PHAL_MFDUOX_CMD_BUF,
        PHAL_MFDUOX_CMD_BUF_LEN,
        NULL,
        NULL,
        NULL));

    /* Set buffering options. */
    bBuffOption_SM = PHAL_MFDUOX_RETURN_PLAIN_DATA;
    wBuffOption_PICC = PH_EXCHANGE_BUFFER_CONT;
    bCmdOption = PHAL_MFDUOX_OPTION_NONE;

    /* Generate the Secure Messaging --------------------------------------------------------------------------------------------------- */
    do
    {
        wStatus = phalMfDuoX_Sw_Int_ApplySM(
            pDataParams,
            PH_ON,
            PH_ON,
            bCmd_ComMode,
            PHAL_MFDUOX_CMD_BUF,
            PHAL_MFDUOX_CMD_BUF_LEN,
            pNFCPauseRspData,
            wNFCPauseRspDataLen,
            &pSMBuff,
            &wSmBufLen);

        /* Update SM Buffering options. */
        if((wStatus & PH_ERR_MASK) == PH_ERR_SUCCESS_CHAINING)
            bBuffOption_SM = (uint8_t) (PH_EXCHANGE_TXCHAINING | PHAL_MFDUOX_RETURN_PLAIN_DATA);

        /* Validate Status */
        if(((wStatus & PH_ERR_MASK) != PH_ERR_SUCCESS) && ((wStatus & PH_ERR_MASK) != PH_ERR_SUCCESS_CHAINING))
            break;

        /* End the Loop. */
        if((wStatus & PH_ERR_MASK) == PH_ERR_SUCCESS)
        {
            bComplete = PH_ON;

            /* Re-Apply Buffer and Command Option flags. */
            wBuffOption_PICC = PH_EXCHANGE_BUFFER_LAST;
            bCmdOption = (uint8_t) (PHAL_MFDUOX_OPTION_COMPLETE | PHAL_MFDUOX_RETURN_PICC_STATUS);
        }

        /* Exchange NFCPauseRspData and MAC (If Applicable) ---------------------------------------------------------------------------- */
        PH_CHECK_SUCCESS_FCT(wStatus, phalMfDuoX_Sw_Int_CardExchange(
            pDataParams,
            wBuffOption_PICC,
            PHAL_MFDUOX_CHAINING_BIT_INVALID,
            bCmdOption,
            0,
            PH_ON,
            pSMBuff,
            wSmBufLen,
            &pResponse_PICC,
            &wRspLen_PICC,
            &bPiccErrCode));
    } while(bComplete == PH_OFF);

    /* Validate the Status. */
    PH_CHECK_SUCCESS(wStatus);

    /* Remove the Secure Messaging ----------------------------------------------------------------------------------------------------- */
    if(bRsp_ComMode != PHAL_MFDUOX_COMMUNICATION_PLAIN)
    {
        PH_CHECK_SUCCESS_FCT(wStatus, phalMfDuoX_Sw_Int_RemoveSM(
            pDataParams,
            PH_OFF,
            PH_ON,
            PH_ON,
            bRsp_ComMode,
            pResponse_PICC,
            wRspLen_PICC,
            bPiccErrCode,
            ppResponse,
            pRspLen));
    }
    else
    {
        /* In case of SUCCESS and Communication mode as PLAIN, increment the command counter. */
        pDataParams->wCmdCtr++;
    }

    return PH_ADD_COMPCODE(PH_ERR_SUCCESS, PH_COMP_AL_MFDUOX);
}

phStatus_t phalMfDuoX_Sw_ReadGPIO(phalMfDuoX_Sw_DataParams_t * pDataParams, uint16_t wOption, uint8_t ** ppResponse,
    uint16_t * pRspLen)
{
    phStatus_t  PH_MEMLOC_REM wStatus = 0;
    uint8_t     PH_MEMLOC_REM bCmd_ComMode = 0;
    uint8_t     PH_MEMLOC_REM bRsp_ComMode = 0;

    /* Validate Communication options. */
    PH_CHECK_SUCCESS_FCT(wStatus, phalMfDuoX_Int_Validate_ComOption((uint8_t) wOption));

    /* Set the DataParams with command code. */
    pDataParams->bCmdCode = PHAL_MFDUOX_CMD_READ_GPIO;

    /* Frame the communication mode to be applied. */
    phalMfDuoX_Int_GetCommMode(pDataParams->bAuthState, (uint8_t) wOption, &bCmd_ComMode);
    bRsp_ComMode = (uint8_t) wOption;

    /* Clear Buffers. */
    (void) memset(PHAL_MFDUOX_CMD_BUF, 0x00, PHAL_MFDUOX_CMD_BUF_SIZE);
    PHAL_MFDUOX_CMD_BUF_LEN = 0;

    (void) memset(PHAL_MFDUOX_PRS_BUF, 0x00, PHAL_MFDUOX_PRS_BUF_SIZE);
    PHAL_MFDUOX_PRS_BUF_LEN = 0;

    /* Frame the command information. */
    PHAL_MFDUOX_CMD_BUF[PHAL_MFDUOX_CMD_BUF_LEN++] = pDataParams->bCmdCode;

    /* Exchange Cmd.ReadGPIO information to PICC. */
    PH_CHECK_SUCCESS_FCT(wStatus, phalMfDuoX_Sw_Int_WriteData(
        pDataParams,
        PH_OFF,
        bCmd_ComMode,
        bRsp_ComMode,
        PH_OFF,
        PHAL_MFDUOX_CMD_BUF,
        PHAL_MFDUOX_CMD_BUF_LEN,
        NULL,
        0,
        ppResponse,
        pRspLen));

    return PH_ADD_COMPCODE(PH_ERR_SUCCESS, PH_COMP_AL_MFDUOX);
}

/* MIFARE DUOX ISO7816-4 commands ------------------------------------------------------------------------------------------------------- */
phStatus_t phalMfDuoX_Sw_IsoSelectFile(phalMfDuoX_Sw_DataParams_t * pDataParams, uint8_t bOption, uint8_t bSelector, uint8_t * pFid,
    uint8_t * pDFname, uint8_t bDFnameLen, uint8_t bExtendedLenApdu, uint8_t ** ppFCI, uint16_t * pFCILen)
{
    phStatus_t  PH_MEMLOC_REM wStatus = PH_ERR_SUCCESS;
    phStatus_t  PH_MEMLOC_REM wStatusTmp = PH_ERR_SUCCESS;
    uint8_t     PH_MEMLOC_REM aData[24];
    uint16_t    PH_MEMLOC_REM wLc = 0;
    uint16_t    PH_MEMLOC_REM wLe = 0;
    uint8_t     PH_MEMLOC_REM aFileId[3] = { '\0' };
    uint8_t     PH_MEMLOC_REM aPiccDfName[7] = { 0xD2, 0x76, 0x00, 0x00, 0x85, 0x01, 0x00 };
    uint16_t    PH_MEMLOC_REM wVal = 0;
    uint8_t     PH_MEMLOC_REM bInclude_LCLE = 0;

#ifdef RDR_LIB_PARAM_CHECK
    if(bDFnameLen > 16)
    {
        return PH_ADD_COMPCODE(PH_ERR_INVALID_PARAMETER, PH_COMP_AL_MFDUOX);
    }
    if((bOption != PHAL_MFDUOX_FCI_RETURNED) && (bOption != PHAL_MFDUOX_FCI_NOT_RETURNED))
    {
        return PH_ADD_COMPCODE(PH_ERR_INVALID_PARAMETER, PH_COMP_AL_MFDUOX);
    }
#endif

    /* To resolve warning */
    PH_UNUSED_VARIABLE(wStatusTmp);

    /* Validate APDU Format. */
    PHAL_MFDUOX_VALIDATE_APDU_FORMAT(bExtendedLenApdu);

    switch(bSelector)
    {
        case PHAL_MFDUOX_SELECTOR_0: /* Select MF, DF or EF, by file identifier */
        case PHAL_MFDUOX_SELECTOR_1: /* Select child DF */
        case PHAL_MFDUOX_SELECTOR_2: /* Select EF under the current DF, by file identifier */
        case PHAL_MFDUOX_SELECTOR_3: /* Select parent DF of the current DF */
                                    /* Selection by EF Id*/
                                    /* Send MSB first to card */
            aFileId[1] = aData[0] = pFid[1];
            aFileId[0] = aData[1] = pFid[0];
            aFileId[2] = 0x00;
            wLc = 2;
            break;

        case PHAL_MFDUOX_SELECTOR_4: /* Select by DF name, see Cmd.ISOSelect for VC selection. */
            (void) memcpy(aData, pDFname, bDFnameLen);
            wLc = bDFnameLen;
            break;

        default:
            return PH_ADD_COMPCODE(PH_ERR_INVALID_PARAMETER, PH_COMP_AL_MFDUOX);
    }

    /* Update LC LE information for exchange. */
    bInclude_LCLE = (uint8_t) ((bOption == PHAL_MFDUOX_FCI_NOT_RETURNED) ? PHAL_MFDUOX_EXCHANGE_LC_ONLY :
        PHAL_MFDUOX_EXCHANGE_LC_LE_BOTH);

    wStatus = phalMfDuoX_Sw_Int_Send7816Apdu(
        pDataParams,
        bInclude_LCLE,
        PH_EXCHANGE_DEFAULT,
        bExtendedLenApdu,
        PHAL_MFDUOX_ISO7816_GENERIC_CLA,
        PHAL_MFDUOX_CMD_ISO7816_SELECT_FILE,
        bSelector,
        bOption,
        aData,
        wLc,
        wLe,
        ppFCI,
        pFCILen);

    if((wStatus & PH_ERR_MASK) == PHAL_MFDUOX_ERR_DF_7816_GEN_ERROR)
    {
        wStatusTmp = phalMfDuoX_GetConfig(pDataParams, PHAL_MFDUOX_ADDITIONAL_INFO, &wVal);
    }

    if((wStatus == PH_ERR_SUCCESS) || (wVal == PHAL_MFDUOX_ISO7816_ERR_LIMITED_FUNCTIONALITY_INS))
    {
        /* Reset Authentication should not be targeted for elementary file selection using file ID */
        if(bSelector != 0x02)
        {
            /* Reset Authentication Status here */
            phalMfDuoX_Sw_Int_ResetAuthStatus(pDataParams);
        }
        /* ISO wrapped mode is on */
        pDataParams->bWrappedMode = PH_ON;

        /* Once the selection Success, update the File Id to master data structure if the selection is done through AID */
        if((bSelector == 0x00) || (bSelector == 0x01) || (bSelector == 0x02))
        {
            (void) memcpy(pDataParams->aAid, aFileId, sizeof(aFileId));
        }
        else if((bSelector == 0x04))
        {
            /* Update the file ID to all zeros if DF Name is of PICC. */
            if(memcmp(pDFname, aPiccDfName, sizeof(aPiccDfName)) == 0)
            {
                aFileId[0] = 0x00;
                aFileId[1] = 0x00;
                aFileId[2] = 0x00;
            }
            else
            {
                aFileId[0] = 0xff;
                aFileId[1] = 0xff;
                aFileId[2] = 0xff;
            }

            (void) memcpy(pDataParams->aAid, aFileId, sizeof(aFileId));
        }
    }
    else
    {
        /* Nothing to do here. */
    }

    return wStatus;
}

phStatus_t phalMfDuoX_Sw_IsoReadBinary(phalMfDuoX_Sw_DataParams_t * pDataParams, uint16_t wOption, uint8_t bOffset, uint8_t bSfid,
    uint32_t dwBytesToRead, uint8_t bExtendedLenApdu, uint8_t ** ppResponse, uint16_t * pRspLen)
{
    uint8_t     PH_MEMLOC_REM bP1 = 0;
    uint8_t     PH_MEMLOC_REM bP2 = 0;

    /* Validate Parameters. */
    if((wOption & PH_EXCHANGE_MODE_MASK) == PH_EXCHANGE_DEFAULT)
    {
        if(bSfid & PHAL_MFDUOX_SFID_ENABLED)
        {
#ifdef RDR_LIB_PARAM_CHECK
            /* Short file id is supplied */
            PHAL_MFDUOX_IS_VALID_FILE_NO(bSfid);
#endif
            /* Short File Identifier from 00 - 1F. */
            bP1 = bSfid;

            /* Offset from 0 - 255. */
            bP2 = bOffset;
        }
        else
        {
            /* Encode Offset from 0 - 32767 */
            bP1 = bSfid;
            bP2 = bOffset;
        }
    }
    else if((wOption & PH_EXCHANGE_MODE_MASK) == PH_EXCHANGE_RXCHAINING)
    {
        /* Do Nothing. Code is handled internally. */
    }
    else
    {
        return PH_ADD_COMPCODE(PH_ERR_INVALID_PARAMETER, PH_COMP_AL_MFDUOX);
    }

    /* Validate APDU Format. */
    PHAL_MFDUOX_VALIDATE_APDU_FORMAT(bExtendedLenApdu);

    return phalMfDuoX_Sw_Int_Send7816Apdu(
        pDataParams,
        PHAL_MFDUOX_EXCHANGE_LE_ONLY,
        wOption,
        bExtendedLenApdu,
        PHAL_MFDUOX_ISO7816_GENERIC_CLA,
        PHAL_MFDUOX_CMD_ISO7816_READ_BINARY,
        bP1,
        bP2,
        NULL,
        0,
        dwBytesToRead,
        ppResponse,
        pRspLen);
}

phStatus_t phalMfDuoX_Sw_IsoUpdateBinary(phalMfDuoX_Sw_DataParams_t * pDataParams, uint8_t bOffset, uint8_t bSfid, uint8_t bExtendedLenApdu,
    uint8_t * pData, uint16_t wDataLen)
{
    phStatus_t  PH_MEMLOC_REM wStatus = PH_ERR_SUCCESS;
    uint8_t     PH_MEMLOC_REM bP1 = 0;
    uint8_t     PH_MEMLOC_REM bP2 = 0;

    if(bSfid & PHAL_MFDUOX_SFID_ENABLED)
    {
#ifdef RDR_LIB_PARAM_CHECK
        /* Short file id is supplied */
        PHAL_MFDUOX_IS_VALID_FILE_NO(bSfid);
#endif
        /* Short File Identifier from 00 - 1F. */
        bP1 = bSfid;

        /* Offset from 0 - 255. */
        bP2 = bOffset;
    }
    else
    {
        /* Encode Offset from 0 - 32767 */
        bP1 = bSfid;
        bP2 = bOffset;
    }

    /* Validate APDU Format. */
    PHAL_MFDUOX_VALIDATE_APDU_FORMAT(bExtendedLenApdu);

    wStatus = phalMfDuoX_Sw_Int_Send7816Apdu(
        pDataParams,
        PHAL_MFDUOX_EXCHANGE_LC_ONLY,
        PH_EXCHANGE_DEFAULT,
        bExtendedLenApdu,
        PHAL_MFDUOX_ISO7816_GENERIC_CLA,
        PHAL_MFDUOX_CMD_ISO7816_UPDATE_BINARY,
        bP1,
        bP2,
        pData,
        wDataLen,
        0,
        NULL,
        NULL);

    return wStatus;
}

phStatus_t phalMfDuoX_Sw_IsoReadRecords(phalMfDuoX_Sw_DataParams_t * pDataParams, uint16_t wOption, uint8_t bRecNo, uint8_t bReadAllRecords,
    uint8_t bSfid, uint32_t dwBytesToRead, uint8_t bExtendedLenApdu, uint8_t ** ppResponse, uint16_t * pRspLen)
{
    uint8_t     PH_MEMLOC_REM bP1 = 0;
    uint8_t     PH_MEMLOC_REM bP2 = 0;

    /* Validate Parameters. */
    if((wOption & PH_EXCHANGE_MODE_MASK) == PH_EXCHANGE_DEFAULT)
    {
#ifdef RDR_LIB_PARAM_CHECK
        /* Short file id is supplied */
        PHAL_MFDUOX_IS_VALID_FILE_NO(bSfid);
#endif
        /* Record Number. */
        bP1 = bRecNo;

        /* Add SFID and usage of Record number. */
        bP2 = (uint8_t) ((bSfid << 3U) | (0x04U | bReadAllRecords));
    }
    else if((wOption & PH_EXCHANGE_MODE_MASK) == PH_EXCHANGE_RXCHAINING)
    {
        /* Do Nothing. Code is handled internally. */
    }
    else
    {
        return PH_ADD_COMPCODE(PH_ERR_INVALID_PARAMETER, PH_COMP_AL_MFDUOX);
    }

    /* Validate APDU Format. */
    PHAL_MFDUOX_VALIDATE_APDU_FORMAT(bExtendedLenApdu);

    return phalMfDuoX_Sw_Int_Send7816Apdu(
        pDataParams,
        PHAL_MFDUOX_EXCHANGE_LE_ONLY,
        wOption,
        bExtendedLenApdu,
        PHAL_MFDUOX_ISO7816_GENERIC_CLA,
        PHAL_MFDUOX_CMD_ISO7816_READ_RECORD,
        bP1,
        bP2,
        NULL,
        0,
        dwBytesToRead,
        ppResponse,
        pRspLen);
}

phStatus_t phalMfDuoX_Sw_IsoAppendRecord(phalMfDuoX_Sw_DataParams_t * pDataParams, uint8_t bSfid, uint8_t bExtendedLenApdu, uint8_t * pData,
    uint16_t wDataLen)
{
    phStatus_t  PH_MEMLOC_REM wStatus = PH_ERR_SUCCESS;
    uint8_t     PH_MEMLOC_REM bP1 = 0;
    uint8_t     PH_MEMLOC_REM bP2 = 0;

#ifdef RDR_LIB_PARAM_CHECK
    /* Short file id is supplied */
    PHAL_MFDUOX_IS_VALID_FILE_NO(bSfid);
#endif

    /* Validate APDU Format. */
    PHAL_MFDUOX_VALIDATE_APDU_FORMAT(bExtendedLenApdu);

    /* Current Record. */
    bP1 = 0x00;

    /* Short File Identifier from 00 - 1F. */
    bP2 = (uint8_t) (bSfid << 3);

    wStatus = phalMfDuoX_Sw_Int_Send7816Apdu(
        pDataParams,
        PHAL_MFDUOX_EXCHANGE_LC_ONLY,
        PH_EXCHANGE_DEFAULT,
        bExtendedLenApdu,
        PHAL_MFDUOX_ISO7816_GENERIC_CLA,
        PHAL_MFDUOX_CMD_ISO7816_APPEND_RECORD,
        bP1,
        bP2,
        pData,
        wDataLen,
        0,
        NULL,
        NULL);

    return wStatus;
}

phStatus_t phalMfDuoX_Sw_IsoGetChallenge(phalMfDuoX_Sw_DataParams_t * pDataParams, uint8_t bExpRsp, uint8_t bExtendedLenApdu,
    uint8_t ** ppResponse, uint16_t * pRspLen)
{
    /* Validate APDU Format. */
    PHAL_MFDUOX_VALIDATE_APDU_FORMAT(bExtendedLenApdu);

    return phalMfDuoX_Sw_Int_Send7816Apdu(
        pDataParams,
        PHAL_MFDUOX_EXCHANGE_LE_ONLY,
        PH_EXCHANGE_DEFAULT,
        bExtendedLenApdu,
        PHAL_MFDUOX_ISO7816_GENERIC_CLA,
        PHAL_MFDUOX_CMD_ISO7816_GET_CHALLENGE,
        0x00,
        0x00,
        NULL,
        0,
        bExpRsp,
        ppResponse,
        pRspLen);
}

/* MIFARE DUOX EV Charging command ------------------------------------------------------------------------------------------------------ */
phStatus_t phalMfDuoX_Sw_VdeReadData(phalMfDuoX_Sw_DataParams_t * pDataParams, uint16_t wOption, uint8_t bFileNo, uint16_t wBytesToRead,
    uint8_t bExtendedLenApdu, uint8_t ** ppResponse, uint16_t * pRspLen)
{
    uint8_t     PH_MEMLOC_REM bP1 = 0;
    uint8_t     PH_MEMLOC_REM bP2 = 0;

    /* Validate Parameters. */
    if((wOption & PH_EXCHANGE_MODE_MASK) == PH_EXCHANGE_DEFAULT)
    {
        bP1 = bFileNo;
    }
    else if((wOption & PH_EXCHANGE_MODE_MASK) == PH_EXCHANGE_RXCHAINING)
    {
        /* Do Nothing. Code is handled internally. */
    }
    else
    {
        return PH_ADD_COMPCODE(PH_ERR_INVALID_PARAMETER, PH_COMP_AL_MFDUOX);
    }

    /* Validate APDU Format. */
    PHAL_MFDUOX_VALIDATE_APDU_FORMAT(bExtendedLenApdu);

    return phalMfDuoX_Sw_Int_Send7816Apdu(
        pDataParams,
        PHAL_MFDUOX_EXCHANGE_LE_ONLY,
        wOption,
        bExtendedLenApdu,
        PHAL_MFDUOX_ISO7816_EV_CHARGING_CLA,
        PHAL_MFDUOX_CMD_VDE_READ_DATA,
        bP1,
        bP2,
        NULL,
        0,
        wBytesToRead,
        ppResponse,
        pRspLen);
}

phStatus_t phalMfDuoX_Sw_VdeWriteData(phalMfDuoX_Sw_DataParams_t * pDataParams, uint8_t bOperation, uint8_t bExtendedLenApdu,
    uint8_t * pData, uint16_t wDataLen)
{
    /* Validate the parameter */
#ifdef RDR_LIB_PARAM_CHECK
    if(bOperation > PHAL_MFDUOX_EV_OPERATION_LOCK)
    {
        return PH_ADD_COMPCODE(PH_ERR_INVALID_PARAMETER, PH_COMP_AL_MFDUOX);
    }
#endif

    /* Validate APDU Format. */
    PHAL_MFDUOX_VALIDATE_APDU_FORMAT(bExtendedLenApdu);

    return phalMfDuoX_Sw_Int_Send7816Apdu(
        pDataParams,
        PHAL_MFDUOX_EXCHANGE_LC_LE_BOTH,
        PH_EXCHANGE_DEFAULT,
        bExtendedLenApdu,
        PHAL_MFDUOX_ISO7816_EV_CHARGING_CLA,
        PHAL_MFDUOX_CMD_VDE_WRITE_DATA,
        PHAL_MFDUOX_EV_CHARGING_VDE_WRITE_DATA_P1,
        bOperation,
        pData,
        wDataLen,
        0,
        NULL,
        NULL);
}

phStatus_t phalMfDuoX_Sw_VdeECDSASign(phalMfDuoX_Sw_DataParams_t * pDataParams, uint16_t wBytesToRead, uint8_t bExtendedLenApdu,
    uint8_t * pData, uint16_t wDataLen, uint8_t ** ppResponse, uint16_t * pRspLen)
{
    /* Validate APDU Format. */
    PHAL_MFDUOX_VALIDATE_APDU_FORMAT(bExtendedLenApdu);

    return phalMfDuoX_Sw_Int_Send7816Apdu(
        pDataParams,
        PHAL_MFDUOX_EXCHANGE_LC_LE_BOTH,
        PH_EXCHANGE_DEFAULT,
        bExtendedLenApdu,
        PHAL_MFDUOX_ISO7816_EV_CHARGING_CLA,
        PHAL_MFDUOX_CMD_VDE_ECDSA_SIGN,
        PHAL_MFDUOX_EV_CHARGING_VDE_ECDSA_SIGN_P1,
        PHAL_MFDUOX_EV_CHARGING_VDE_ECDSA_SIGN_P2,
        pData,
        wDataLen,
        wBytesToRead,
        ppResponse,
        pRspLen);
}

/* MIFARE DUOX Utility functions -------------------------------------------------------------------------------------------------------- */
phStatus_t phalMfDuoX_Sw_GetConfig(phalMfDuoX_Sw_DataParams_t * pDataParams, uint16_t wConfig, uint16_t * pValue)
{
    switch(wConfig)
    {
        case PHAL_MFDUOX_ADDITIONAL_INFO:
            *pValue = pDataParams->wAdditionalInfo;
            break;

        case PHAL_MFDUOX_WRAPPED_MODE:
            *pValue = (uint16_t) pDataParams->bWrappedMode;
            break;

        case PHAL_MFDUOX_SHORT_LENGTH_APDU:
            *pValue = (uint16_t) pDataParams->bShortLenApdu;
            break;

        case PHAL_MFDUOX_AUTH_STATE:
            *pValue = (uint16_t) pDataParams->bAuthState;
            break;

        default:
            return PH_ADD_COMPCODE(PH_ERR_UNSUPPORTED_PARAMETER, PH_COMP_AL_MFDUOX);
    }

    return PH_ADD_COMPCODE(PH_ERR_SUCCESS, PH_COMP_AL_MFDUOX);
}

phStatus_t phalMfDuoX_Sw_SetConfig(phalMfDuoX_Sw_DataParams_t * pDataParams, uint16_t wConfig, uint16_t wValue)
{
    switch(wConfig)
    {
        case PHAL_MFDUOX_ADDITIONAL_INFO:
            pDataParams->wAdditionalInfo = wValue;
            break;

        case PHAL_MFDUOX_WRAPPED_MODE:
            pDataParams->bWrappedMode = (uint8_t) wValue;
            break;

        case PHAL_MFDUOX_SHORT_LENGTH_APDU:
            pDataParams->bShortLenApdu = (uint8_t) wValue;
            break;

        case PHAL_MFDUOX_AUTH_STATE:
            pDataParams->bAuthState = (uint8_t) wValue;
            break;

        default:
            return PH_ADD_COMPCODE(PH_ERR_UNSUPPORTED_PARAMETER, PH_COMP_AL_MFDUOX);
    }

    return PH_ADD_COMPCODE(PH_ERR_SUCCESS, PH_COMP_AL_MFDUOX);
}

phStatus_t phalMfDuoX_Sw_ResetAuthentication(phalMfDuoX_Sw_DataParams_t * pDataParams)
{
    phalMfDuoX_Sw_Int_ResetAuthStatus(pDataParams);

    return PH_ADD_COMPCODE(PH_ERR_SUCCESS, PH_COMP_AL_MFDUOX);
}

#endif /* NXPBUILD__PHAL_MFDUOX_SW */
