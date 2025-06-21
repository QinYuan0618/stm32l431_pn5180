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
* Internal functions of Software implementation of MIFARE DUOX application layer.
* $Author: NXP $
* $Revision: $ (v07.13.00)
* $Date: $
*
*/

#include <ph_Status.h>

#ifdef NXPBUILD__PHAL_MFDUOX_SW

#include <phpalMifare.h>
#include <phpalI14443p4.h>

#ifdef NXPBUILD__PH_TMIUTILS
#include <phTMIUtils.h>
#endif /* NXPBUILD__PH_TMIUTILS */

#ifdef NXPBUILD__PHAL_VCA
#include <phalVca.h>
#endif /* NXPBUILD__PHAL_VCA */

#include "phalMfDuoX_Sw_Int.h"
#include "../phalMfDuoX_Int.h"

static const uint16_t PH_MEMLOC_CONST_ROM aFrameSize[] = { 16, 24, 32, 40, 48, 64, 96, 128, 256, 512, 1024, 2048, 4096 };

phStatus_t phalMfDuoX_Sw_Int_ValidateResponse(phalMfDuoX_Sw_DataParams_t * pDataParams, uint8_t bOption, uint16_t wStatus,
    uint16_t wPiccRetCode)
{
    uint16_t PH_MEMLOC_REM wPICCStatusCode = 0;

    /* Evaluate the response. */
    if(wStatus == PH_ERR_SUCCESS)
    {
        /* Frame PICC Status Code. */
        wPICCStatusCode = (uint16_t) ((bOption == PHAL_MFDUOX_ISO7816_APDU_CMD) ? wPiccRetCode : (wPiccRetCode & 0x00FF));

        /* Validate the PICC Status. */
        PH_CHECK_SUCCESS_FCT(wStatus, phalMfDuoX_Int_ComputeErrorResponse(pDataParams, wPICCStatusCode));
    }
    else
    {
        if((wStatus & PH_ERR_MASK) == PH_ERR_SUCCESS_CHAINING)
        {
            wStatus = PH_ADD_COMPCODE(PH_ERR_SUCCESS_CHAINING, PH_COMP_AL_MFDUOX);
        }

        PH_CHECK_SUCCESS(wStatus);
    }

    return PH_ADD_COMPCODE(PH_ERR_SUCCESS, PH_COMP_AL_MFDUOX);
}

phStatus_t phalMfDuoX_Sw_Int_CardExchange(phalMfDuoX_Sw_DataParams_t * pDataParams, uint16_t wBufferOption, uint8_t bChainingState,
    uint8_t bCmdOption, uint16_t wTotDataLen, uint8_t bExchangeLE, uint8_t * pData, uint16_t wDataLen, uint8_t ** ppResponse,
    uint16_t * pRespLen, uint8_t * pPiccErrCode)
{
    phStatus_t      PH_MEMLOC_REM wStatus = 0;
    phStatus_t      PH_MEMLOC_REM wPICCStatus = 0;
    uint16_t        PH_MEMLOC_REM wOption = 0;
    uint16_t        PH_MEMLOC_REM wFrameLen = 0;
    uint16_t        PH_MEMLOC_REM wWrappedLen = 0;
    uint16_t        PH_MEMLOC_REM wBytesPending = 0;
    uint16_t        PH_MEMLOC_REM wLc = 0;
    uint16_t        PH_MEMLOC_REM wRspLen = 0;
    uint8_t         PH_MEMLOC_REM bPICCStatLen = 0;
    uint8_t         PH_MEMLOC_REM bLcLen = 0;
    uint8_t         PH_MEMLOC_REM bOffset = 0;
    uint8_t         PH_MEMLOC_REM bCheckStatus = 0;
    uint8_t         PH_MEMLOC_REM bCmdFormat = 0;
    uint8_t         PH_MEMLOC_REM bChaining = PH_OFF;

    static uint16_t PH_MEMLOC_REM wBytesExchanged;
    static uint8_t  PH_MEMLOC_REM bLeLen;

    uint8_t*        PH_MEMLOC_REM pResponse = NULL;
    uint8_t         PH_MEMLOC_REM aLe[3] = { 0x00, 0x00, 0x00 };

    uint8_t         PH_MEMLOC_REM aISO7816Header[8] = { PHAL_MFDUOX_WRAPPEDAPDU_CLA, 0x00, PHAL_MFDUOX_WRAPPEDAPDU_P1, PHAL_MFDUOX_WRAPPEDAPDU_P2, 0x00, 0x00, 0x00 };
    uint8_t         PH_MEMLOC_REM bISO7816HeaderLen = 4U;

    /* Get PICC Frame size. */
    PH_CHECK_SUCCESS_FCT(wStatus, phalMfDuoX_Sw_Int_GetFrameLen(pDataParams, PH_OFF, &wFrameLen));

    /* Get Remaining bytes to be exchanged. */
    phpalMifare_GetConfig(pDataParams->pPalMifareDataParams, PHPAL_I14443P4_CONFIG_OPE_MODE, &wBytesPending);

    if(pDataParams->bWrappedMode)
    {
        if(!(wBufferOption & PH_EXCHANGE_LEAVE_BUFFER_BIT) || (wBufferOption == PH_EXCHANGE_DEFAULT))
        {
            wWrappedLen = (uint16_t) (4U /* CLA, P1, P2, LC. */ + bExchangeLE);
            wWrappedLen = (uint16_t) (pDataParams->bShortLenApdu ? wWrappedLen :
                (wWrappedLen + (2U /* Extended LC */ + bExchangeLE /* Extended LE */)));
        }
        else
        {
            wWrappedLen = bExchangeLE;
            wWrappedLen = (uint16_t) (pDataParams->bShortLenApdu ? wWrappedLen : (wWrappedLen + 1U /* Extended LE */));
        }
    }
    else
    {
        /* Nothing to do. */
    }

    /* Set the buffering options to be given to PAL layer. */
    if((wBufferOption & PH_EXCHANGE_BUFFERED_BIT) || (wBufferOption == PH_EXCHANGE_DEFAULT))
    {
        /* Update bytes exchanged */
        wBytesExchanged += (uint16_t) (((wBufferOption & PH_EXCHANGE_LEAVE_BUFFER_BIT) == 0U) ? 0U : wDataLen);

        /* Set the Chaining Options */
        bChaining = (uint8_t) (((wTotDataLen - wBytesExchanged) + wWrappedLen) > wFrameLen);
        bChaining = (uint8_t) ((wBytesPending > wFrameLen) ? PH_ON : bChaining);
        bChaining = (uint8_t) ((wBufferOption == PH_EXCHANGE_DEFAULT) ? PH_OFF : bChaining);

        /* Update bytes exchanged */
        wBytesExchanged += (uint16_t) (((wBufferOption & PH_EXCHANGE_LEAVE_BUFFER_BIT) == 0U) ? wDataLen : 0U);
        wBytesExchanged = (uint16_t) ((wBufferOption == PH_EXCHANGE_DEFAULT) ? 0U : wBytesExchanged);
    }
    else
    {
        bChaining = PH_OFF;
        wBytesExchanged = 0U;
    }

    /* Set the Options */
    bChaining = (uint8_t) ((bChainingState != PHAL_MFDUOX_CHAINING_BIT_INVALID) ? bChainingState : bChaining);
    wOption = (uint16_t) (bChaining | wBufferOption);

        /* Exchange the command in Iso7816 wrapped format ----------------------------------------------------------------------------- */
    if(pDataParams->bWrappedMode)
    {
        if((wBufferOption == PH_EXCHANGE_BUFFER_FIRST) || (wBufferOption == PH_EXCHANGE_DEFAULT))
        {
            bLeLen = 1;

            /* Set the LC information. */
            wLc = (uint16_t) (wTotDataLen - 1 /* Excluding the command code. */);

            /* Update the command code to Iso7816 header */
            aISO7816Header[1] = pData[0];

            /* Add LC if available */
            if(wLc)
            {
                /* Update LC bytes according to Extended APDU option. */
                if(pDataParams->bShortLenApdu == PH_OFF)
                {
                    aISO7816Header[bISO7816HeaderLen + bLcLen++] = 0x00U;
                    aISO7816Header[bISO7816HeaderLen + bLcLen++] = (uint8_t) ((wLc & 0x0000FF00) >> 8);

                    /* Le length is updated to two if LC is present and the APDU is extended. */
                    bLeLen = 2;
                }

                aISO7816Header[bISO7816HeaderLen + bLcLen++] = (uint8_t) (wLc & 0x000000FF);

                /* Update IHeader Length */
                bISO7816HeaderLen += bLcLen;
            }
            else
            {
                /* Update Le count */
                if(pDataParams->bShortLenApdu == PH_OFF)
                {
                    bLeLen = 3;
                }
            }

            /* Add the ISO 7816 header to layer 4 buffer. */
            PH_CHECK_SUCCESS_FCT(wStatus, phpalMifare_ExchangeL4(
                pDataParams->pPalMifareDataParams,
                (uint16_t) (bChaining | PH_EXCHANGE_BUFFER_FIRST),
                &aISO7816Header[0],
                bISO7816HeaderLen,
                NULL,
                NULL));

            /* Add the data to layer 4 buffer. */
            if((wDataLen - 1U) != 0U)
            {
                PH_CHECK_SUCCESS_FCT(wStatus, phpalMifare_ExchangeL4(
                    pDataParams->pPalMifareDataParams,
                    PH_EXCHANGE_BUFFER_CONT,
                    &pData[1],  /* Exclude the command code because it is added to INS. */
                    (uint16_t) (wDataLen - 1),
                    NULL,
                    NULL));
            }
        }

        if(wBufferOption == PH_EXCHANGE_BUFFER_CONT)
        {
            /* Add the data to layer 4 buffer. */
            PH_CHECK_SUCCESS_FCT(wStatus, phpalMifare_ExchangeL4(
                pDataParams->pPalMifareDataParams,
                wOption,
                pData,
                wDataLen,
                NULL,
                NULL));
        }

        if((wBufferOption == PH_EXCHANGE_BUFFER_LAST) || (wBufferOption == PH_EXCHANGE_DEFAULT))
        {
            if(wBufferOption == PH_EXCHANGE_BUFFER_LAST)
            {
                /* Add the data to layer 4 buffer. */
                PH_CHECK_SUCCESS_FCT(wStatus, phpalMifare_ExchangeL4(
                    pDataParams->pPalMifareDataParams,
                    (uint16_t) (bChaining | PH_EXCHANGE_BUFFER_CONT),
                    pData,
                    wDataLen,
                    NULL,
                    NULL));
            }

            /* Add Le to L4 buffer and exchange the command. */
            wStatus = phpalMifare_ExchangeL4(
                pDataParams->pPalMifareDataParams,
                PH_EXCHANGE_BUFFER_LAST,
                &aLe[0],
                (uint8_t) (bExchangeLE ? bLeLen : 0),
                &pResponse,
                &wRspLen);

            /* Validate the Status. */
            if(((wStatus & PH_ERR_MASK) != PH_ERR_SUCCESS) && ((wStatus & PH_ERR_MASK) != PH_ERR_SUCCESS_CHAINING))
            {
                /* Update PICC Error code to INVALID. */
                if(pPiccErrCode != NULL)
                    *pPiccErrCode = PHAL_MFDUOX_PICC_STATUS_INVALID;

                return wStatus;
            }

            /* Should the status needs to be verified. */
            bCheckStatus = (uint8_t) ((wStatus & PH_ERR_MASK) == PH_ERR_SUCCESS);

            /* Combine Sw1 and Sw2 status codes. */
            if(bCheckStatus)
                wPICCStatus = (uint16_t) ((pResponse[wRspLen - 2] << 8) | pResponse[wRspLen - 1]);

            /* Evaluate the Status. */
            wStatus = phalMfDuoX_Sw_Int_ValidateResponse(pDataParams, PHAL_MFDUOX_PRODUCT_CMD, wStatus, wPICCStatus);

            /* Create memory for updating the response of ISO 14443 format. */
            *ppResponse = pResponse;

            /* Update the response buffer length excluding SW1SW2. */
            *pRespLen = (uint16_t) (wRspLen - (bCheckStatus ? 2 : 0));

            /* Copy the second byte of response (SW2) to RxBuffer */
            if(bCmdOption & PHAL_MFDUOX_RETURN_PICC_STATUS)
                if(pPiccErrCode != NULL)
                    *pPiccErrCode = pResponse[wRspLen - 1];
        }

        if(wBufferOption == PH_EXCHANGE_RXCHAINING)
        {
            /* Exchange the command */
            wStatus = phpalMifare_ExchangeL4(
                pDataParams->pPalMifareDataParams,
                wBufferOption,
                pData,
                wDataLen,
                &pResponse,
                &wRspLen);

            /* Validate the Status. */
            if(((wStatus & PH_ERR_MASK) != PH_ERR_SUCCESS) && ((wStatus & PH_ERR_MASK) != PH_ERR_SUCCESS_CHAINING))
            {
                /* Update PICC Error code to INVALID. */
                if(pPiccErrCode != NULL)
                    *pPiccErrCode = PHAL_MFDUOX_PICC_STATUS_INVALID;

                return wStatus;
            }

            /* Should the status needs to be verified. */
            bCheckStatus = (uint8_t) ((wStatus & PH_ERR_MASK) == PH_ERR_SUCCESS);

            if(wRspLen != 0)
            {
                /* Combine Sw1 and Sw2 status codes. */
                if(bCheckStatus)
                    wPICCStatus = (uint16_t) ((pResponse[wRspLen - 2] << 8) | pResponse[wRspLen - 1]);

                /* Evaluate the Status. */
                wStatus = phalMfDuoX_Sw_Int_ValidateResponse(pDataParams, PHAL_MFDUOX_PRODUCT_CMD, wStatus, wPICCStatus);

                /* Create memory for updating the response of ISO 14443 format. */
                *ppResponse = pResponse;

                /* Update the response buffer length excluding SW1SW2. */
                *pRespLen = (uint16_t) (wRspLen - (bCheckStatus ? 2 : 0));

                /* Copy the second byte of response (SW2) to RxBuffer */
                if(bCmdOption & PHAL_MFDUOX_RETURN_PICC_STATUS)
                    if(pPiccErrCode != NULL)
                        *pPiccErrCode = pResponse[wRspLen - 1];
            }
        }
    }

    /* Exchange the command in Native format or ISO7816 Standard Commands ---------------------------------------------------------- */
    else
    {
        /* Exchange the data to the card in Native format. */
        wStatus = phpalMifare_ExchangeL4(
            pDataParams->pPalMifareDataParams,
            wOption,
            pData,
            wDataLen,
            &pResponse,
            &wRspLen);

        /* Validate the Status. */
        if(((wStatus & PH_ERR_MASK) != PH_ERR_SUCCESS) && ((wStatus & PH_ERR_MASK) != PH_ERR_SUCCESS_CHAINING))
        {
            /* Update PICC Error code to INVALID. */
            if(pPiccErrCode != NULL)
                *pPiccErrCode = PHAL_MFDUOX_PICC_STATUS_INVALID;

            return wStatus;
        }

        /* Verify the received data and update the response buffer with received data. */
        if((bCmdOption & PHAL_MFDUOX_OPTION_PENDING) ||
            (bCmdOption & PHAL_MFDUOX_OPTION_COMPLETE))
        {
            if(!(bCmdOption & PHAL_MFDUOX_EXCLUDE_PICC_STATUS))
            {
                if(bCmdOption & PHAL_MFDUOX_PICC_STATUS_WRAPPED)
                {
                    /* Combine Sw1 and Sw2 status codes. */
                    wPICCStatus = (uint16_t) ((pResponse[wRspLen - 2] << 8) | pResponse[wRspLen - 1]);
                    bPICCStatLen = 2;

                    bCmdFormat = PHAL_MFDUOX_ISO7816_APDU_CMD;
                }
                else
                {
                    wPICCStatus = pResponse[0];
                    bPICCStatLen = 1;

                    bCmdFormat = PHAL_MFDUOX_PRODUCT_CMD;
                }
            }

            /* Evaluate the Status. */
            wStatus = phalMfDuoX_Sw_Int_ValidateResponse(pDataParams, bCmdFormat, wStatus, wPICCStatus);

            /* Update the response buffer length excluding PICC Status Code. */
            *pRespLen = wRspLen - bPICCStatLen;

            /* Set the Offset from where the data needs to be copied. */
            bOffset = (uint8_t) ((bCmdOption & PHAL_MFDUOX_PICC_STATUS_WRAPPED) ? 0 : 1);
            bOffset = (uint8_t) ((bCmdOption & PHAL_MFDUOX_EXCLUDE_PICC_STATUS) ? 0 : bOffset);

            /* Add the Response data excluding PICC Status Code. */
            *ppResponse = &pResponse[bOffset];

            /* Update the PICC Status parameter. */
            if(bCmdOption & PHAL_MFDUOX_RETURN_PICC_STATUS)
                if(pPiccErrCode != NULL)
                    *pPiccErrCode = (uint8_t) wPICCStatus;
        }
    }

    return wStatus;
}

phStatus_t phalMfDuoX_Sw_Int_Send7816Apdu(phalMfDuoX_Sw_DataParams_t * pDataParams, uint8_t bOption, uint16_t wBufOption,
    uint8_t bExtendedLenApdu, uint8_t bClass, uint8_t bIns, uint8_t bP1, uint8_t bP2, uint8_t * pData,
    uint16_t wDataLen, uint32_t dwExpBytes, uint8_t ** ppResponse, uint16_t * pRspLen)
{
    phStatus_t  PH_MEMLOC_REM wStatus = PH_ERR_SUCCESS;
    uint8_t     PH_MEMLOC_REM aLe[3] = { 0x00, 0x00, 0x00 };
    uint8_t     PH_MEMLOC_REM *pResponse = NULL;

    uint16_t    PH_MEMLOC_REM wRspLen = 0;
    uint8_t     PH_MEMLOC_REM bLeLen = 0;

    /* Clear Buffers. */
    (void) memset(PHAL_MFDUOX_CMD_BUF, 0x00, PHAL_MFDUOX_CMD_BUF_SIZE);
    PHAL_MFDUOX_CMD_BUF_LEN = 0;

    /* Set the command code to DataParams. */
    PH_CHECK_SUCCESS_FCT(wStatus, phalMfDuoX_Int_SetCmdCode(pDataParams, bIns));

    /* Frame Standard ISO7816 - 4 Header. */
    PHAL_MFDUOX_CMD_BUF[PHAL_MFDUOX_CMD_BUF_LEN++] = bClass;
    PHAL_MFDUOX_CMD_BUF[PHAL_MFDUOX_CMD_BUF_LEN++] = bIns;
    PHAL_MFDUOX_CMD_BUF[PHAL_MFDUOX_CMD_BUF_LEN++] = bP1;
    PHAL_MFDUOX_CMD_BUF[PHAL_MFDUOX_CMD_BUF_LEN++] = bP2;

    /* Check whether LC needs to be exchanged. */
    if(bOption & PHAL_MFDUOX_EXCHANGE_LC_ONLY)
    {
        /* Check whether Length LC is represented in short APDU or extended APDU */
        if(bExtendedLenApdu == PH_ON)
        {
            /* First byte will be 0x00 if Ext APDU present. Next 2 byte contains actual data. */
            PHAL_MFDUOX_CMD_BUF[PHAL_MFDUOX_CMD_BUF_LEN++] = 0x00;

            /* As of now this field will be set to 0x00 since maximum data that can be sent is 16 bytes.
             * In case if data to be sent exceeds 255 bytes, this byte shall be used.
             */
            PHAL_MFDUOX_CMD_BUF[PHAL_MFDUOX_CMD_BUF_LEN++] = (uint8_t) ((wDataLen & 0xFF00) >> 8);
        }

        /* Short Length APDU. */
        PHAL_MFDUOX_CMD_BUF[PHAL_MFDUOX_CMD_BUF_LEN++] = (uint8_t) (wDataLen & 0x00FF);
    }

    /* Buffer ISO7816-4 Command Header. */
    PH_CHECK_SUCCESS_FCT(wStatus, phpalMifare_ExchangeL4(
        pDataParams->pPalMifareDataParams,
        PH_EXCHANGE_BUFFER_FIRST,
        PHAL_MFDUOX_CMD_BUF,
        PHAL_MFDUOX_CMD_BUF_LEN,
        &pResponse,
        &wRspLen));

    /* Check whether Le needs to be exchanged. */
    if(bOption & PHAL_MFDUOX_EXCHANGE_LE_ONLY)
    {
        /* As per ISO/IEC:7816-4(2005), Section 5, An extended LE field consists of either three bytes
         * (one byte set to '00' followed by two bytes with any value) if the LC field is absent, or
         * two bytes (with any value) if an extended LC field is present.
         */

        /* Check whether Length is represented in extended APDU format and LC is present.
         * If true, then Le should represented in 2 bytes else LE should be represented in 3 bytes
         */
        if(bExtendedLenApdu == PH_ON)
        {
            if(!(bOption & PHAL_MFDUOX_EXCHANGE_LC_ONLY))
            {
                aLe[bLeLen++] = (uint8_t) ((dwExpBytes & 0x00FF0000) >> 16);
            }

            aLe[bLeLen++] = (uint8_t) ((dwExpBytes & 0x0000FF00) >> 8);
        }

        /* Short APDU */
        aLe[bLeLen++] = (uint8_t) (dwExpBytes & 0x000000FF);
    }

    /* Exchange the command based on the INS. */
    switch(bIns)
    {
        case PHAL_MFDUOX_CMD_ISO7816_SELECT_FILE:
            wStatus = phalMfDuoX_Sw_Int_ISOSelectFile(pDataParams, pData, wDataLen, aLe, bLeLen, ppResponse, pRspLen);
            break;

        case PHAL_MFDUOX_CMD_ISO7816_READ_BINARY:
            wStatus = phalMfDuoX_Sw_Int_ISOReadBinary(pDataParams, wBufOption, aLe, bLeLen, ppResponse, pRspLen);
            break;

        case PHAL_MFDUOX_CMD_ISO7816_UPDATE_BINARY:
            wStatus = phalMfDuoX_Sw_Int_ISOUpdateBinary(pDataParams, pData, wDataLen);
            break;

        case PHAL_MFDUOX_CMD_ISO7816_READ_RECORD:
            wStatus = phalMfDuoX_Sw_Int_ISOReadRecord(pDataParams, wBufOption, aLe, bLeLen, ppResponse, pRspLen);
            break;

        case PHAL_MFDUOX_CMD_ISO7816_APPEND_RECORD:
            wStatus = phalMfDuoX_Sw_Int_ISOAppendRecord(pDataParams, pData, wDataLen);
            break;

        case PHAL_MFDUOX_CMD_ISO7816_GET_CHALLENGE:
            wStatus = phalMfDuoX_Sw_Int_ISOGetChallenge(pDataParams, aLe, bLeLen, ppResponse, pRspLen);
            break;

        case PHAL_MFDUOX_CMD_VDE_READ_DATA:
            wStatus = phalMfDuoX_Sw_Int_VdeReadData(pDataParams, wBufOption, aLe, bLeLen, ppResponse, pRspLen);
            break;

        case PHAL_MFDUOX_CMD_VDE_WRITE_DATA:
            wStatus = phalMfDuoX_Sw_Int_VdeWriteData(pDataParams, pData, wDataLen, aLe, bLeLen);
            break;

        case PHAL_MFDUOX_CMD_VDE_ECDSA_SIGN:
            wStatus = phalMfDuoX_Sw_Int_VdeECDSASign(pDataParams, pData, wDataLen, aLe, bLeLen, ppResponse, pRspLen);
            break;

        /*
         * This case cannot be achieved as the INS that are implemented are the supported ones only.
         * This case is kept for completeness of the switch statement and to avoid error while
         * implementing new command support in future.
         */
        default:
            wStatus = PH_ADD_COMPCODE(PH_ERR_UNSUPPORTED_COMMAND, PH_COMP_AL_MFDUOX);
            break;
    }

    return wStatus;
}

phStatus_t phalMfDuoX_Sw_Int_ApplySM(phalMfDuoX_Sw_DataParams_t * pDataParams, uint8_t bIsFirstFrame, uint8_t bIsLastFrame,
    uint8_t bCommMode, uint8_t * pCmdHeader, uint16_t wCmdHeaderLen, uint8_t * pCmdData, uint16_t wCmdDataLen,
    uint8_t ** ppSMBuf, uint16_t * pSMBufLen)
{
    phStatus_t  PH_MEMLOC_REM wStatus = 0;

    /* Set the Status to SUCCESS. */
    wStatus = PH_ADD_COMPCODE(PH_ERR_SUCCESS, PH_COMP_AL_MFDUOX);

    {
        /* Mark the parameters taht are not used. */
        PH_UNUSED_VARIABLE(pDataParams);
        PH_UNUSED_VARIABLE(bIsFirstFrame);
        PH_UNUSED_VARIABLE(bIsLastFrame);
        PH_UNUSED_VARIABLE(bCommMode);
        PH_UNUSED_VARIABLE(pCmdHeader);
        PH_UNUSED_VARIABLE(wCmdHeaderLen);

        *ppSMBuf = pCmdData;
        *pSMBufLen = wCmdDataLen;
    }

    return wStatus;
}

phStatus_t phalMfDuoX_Sw_Int_RemoveSM(phalMfDuoX_Sw_DataParams_t * pDataParams, uint8_t bIsISOChained, uint8_t bIsFirstFrame,
    uint8_t bIsLastFrame, uint8_t bCommMode, uint8_t * pResponse, uint16_t wRespLen, uint8_t bPiccStat, uint8_t ** ppOutBuffer,
    uint16_t * pOutBufLen)
{
    phStatus_t  PH_MEMLOC_REM wStatus = 0;
    uint16_t    PH_MEMLOC_REM wRemData = 0;
    uint16_t    PH_MEMLOC_REM wBuffOption = 0;
    uint16_t    PH_MEMLOC_REM wAESBlockSize = 0;
    uint16_t    PH_MEMLOC_REM wDataLen = 0;
    uint8_t     PH_MEMLOC_REM bHasMoreData = PH_OFF;
    uint8_t     PH_MEMLOC_REM bDecryptData = PH_ON;

    /* Compute DataLen excluding MAC information. */
    wDataLen = (uint16_t) (wRespLen ? (wRespLen - (bIsLastFrame ? 8U /* MAC excluded */ : 0U)) : 0U);
    wDataLen = (uint16_t) ((bCommMode != PHAL_MFDUOX_COMMUNICATION_PLAIN) ? wDataLen : wRespLen);

    if(bIsFirstFrame)
    {
        /* Clear Buffers. */
        (void) memset(PHAL_MFDUOX_CMD_BUF, 0x00, PHAL_MFDUOX_CMD_BUF_SIZE);
        PHAL_MFDUOX_CMD_BUF_LEN = 0;

        (void) memset(PHAL_MFDUOX_PRS_BUF, 0x00, PHAL_MFDUOX_PRS_BUF_SIZE);
        PHAL_MFDUOX_PRS_BUF_LEN = 0;

        /* Increment the command counter. */
        if(pDataParams->bAuthState != PHAL_MFDUOX_NOT_AUTHENTICATED)
            pDataParams->wCmdCtr++;

    }

    /* Performs the below code operation for,
     *  - DataManagement commands with Native Chaining where PICC data do not fit in one single frame.
     *  - All the commands where No Chaining is involved. The data fits in one complete PICC frame.
     *  - For commands that involve ISO/IEC 14443-4 Chaining, whether the frame fits in one PICC frame
     *    or chains into multiple PICC frames,
     *      - Processing of data is performed in if condition where processing for last frame
     *        of data is performed (Refer the if Statement if(bIsLastFrame...)).
     */
    if(bIsISOChained == PH_OFF)
    {
        /* Copy data from command buffer to processing buffer.
         * The below procedure is required in case if there is more PICC data that
         * could not fit into Processing buffer. In the next call the previously
         * remained PICC data needs to be copied to processing buffer.
         */
        if(PHAL_MFDUOX_CMD_BUF_OFFSET)
        {
            /* Compute the remaining data to be copied form offset. */
            wRemData = (uint16_t) (PHAL_MFDUOX_CMD_BUF_LEN - PHAL_MFDUOX_CMD_BUF_OFFSET);

            /* Clear Buffers. */
            (void) memset(PHAL_MFDUOX_PRS_BUF, 0x00, PHAL_MFDUOX_PRS_BUF_SIZE);
            PHAL_MFDUOX_PRS_BUF_LEN = 0;

            /* Compute the data. */
            (void) memcpy(PHAL_MFDUOX_PRS_BUF, &PHAL_MFDUOX_CMD_BUF[PHAL_MFDUOX_CMD_BUF_OFFSET], wRemData);
            PHAL_MFDUOX_PRS_BUF_LEN = wRemData;

            /* Reset Offset and Remaining Data. */
            wRemData = 0;
            PHAL_MFDUOX_CMD_BUF_OFFSET = 0;

            /* Set Remaining data decryption if its last frame. */
            if(bIsLastFrame)
                bDecryptData = PH_ON;
        }

        /* Buffer response information to command buffer for macing. */
        if((PHAL_MFDUOX_CMD_BUF_LEN + wDataLen) < PHAL_MFDUOX_CMD_BUF_SIZE)
        {
            (void) memcpy(&PHAL_MFDUOX_CMD_BUF[PHAL_MFDUOX_CMD_BUF_LEN], &pResponse[wRemData], (wDataLen - wRemData));
            PHAL_MFDUOX_CMD_BUF_LEN += (uint16_t) (wDataLen - wRemData);

            bHasMoreData = PH_ON;
        }

        /* Perform MACing of data based on the command buffer length and size.
         * Here if the command buffer is unable to copy the newly received PICC data, MACing of data based on AES
         * block size is first performed.
         * Then the remaining data that is not processed for macing is shifted to beginning of the command buffer
         * and then newly received PICC data is copied.
         * Additional, if there is room to allocate PICC data to processing buffer, required amount of PICC data
         * is copied to processing buffer. The remaining PICC data that is not copied will be taken from command
         * buffer for the next call.
         */
        else
        {
            /* Frame Buffering Option. */
            wBuffOption = (uint16_t) (PH_CRYPTOSYM_MAC_MODE_CMAC | PH_EXCHANGE_BUFFER_CONT);

            /* Perform MAC for Multiple of AES block size. */
            PHAL_MFDUOX_PREVIOUS_MULTIPLE(PHAL_MFDUOX_CMD_BUF_LEN, wAESBlockSize);

            /* Shift the remaining information. */
            if(PHAL_MFDUOX_IS_NOT_MULTIPLE_AES_BLOCK_SIZE(PHAL_MFDUOX_CMD_BUF_LEN))
            {
                /* Compute Remaining data to be shifted. */
                wRemData = (uint16_t) (PHAL_MFDUOX_CMD_BUF_LEN - wAESBlockSize);

                /* Shift the remaining data. */
                (void) memcpy(PHAL_MFDUOX_CMD_BUF, &PHAL_MFDUOX_CMD_BUF[wAESBlockSize], wRemData);
                PHAL_MFDUOX_CMD_BUF_LEN = wRemData;

                /* Reset command buffer. */
                (void) memset(&PHAL_MFDUOX_CMD_BUF[PHAL_MFDUOX_CMD_BUF_LEN], 0x00, (PHAL_MFDUOX_CMD_BUF_SIZE - PHAL_MFDUOX_CMD_BUF_LEN));

                /* Backup the offset from command buffer. */
                PHAL_MFDUOX_CMD_BUF_OFFSET = wRemData;

                /* Copy the data. */
                (void) memcpy(&PHAL_MFDUOX_CMD_BUF[PHAL_MFDUOX_CMD_BUF_LEN], pResponse, wDataLen);
                PHAL_MFDUOX_CMD_BUF_LEN += wDataLen;

                /* Compute Remaining data to be copied. */
                wRemData = (uint16_t) (PHAL_MFDUOX_PRS_BUF_SIZE - PHAL_MFDUOX_PRS_BUF_LEN);
                wRemData = (uint16_t) ((wRemData < wDataLen) ? wRemData : wDataLen);
                wRemData = (uint16_t) ((wRemData > PHAL_MFDUOX_CMD_BUF_LEN) ? (PHAL_MFDUOX_CMD_BUF_LEN - PHAL_MFDUOX_CMD_BUF_OFFSET) : wRemData);

                /* Copy the data. */
                (void) memcpy(&PHAL_MFDUOX_PRS_BUF[PHAL_MFDUOX_PRS_BUF_LEN], &PHAL_MFDUOX_CMD_BUF[PHAL_MFDUOX_CMD_BUF_OFFSET], wRemData);
                PHAL_MFDUOX_PRS_BUF_LEN += wRemData;

                /* Update Offset. */
                PHAL_MFDUOX_CMD_BUF_OFFSET = (uint16_t) (PHAL_MFDUOX_CMD_BUF_OFFSET + wRemData);

                /* Reset command buffer offset. */
                if(PHAL_MFDUOX_CMD_BUF_OFFSET == PHAL_MFDUOX_CMD_BUF_LEN)
                {
                    /* Check if more data needs to be copied to processing buffer. */
                    bHasMoreData = PH_OFF;
                    PHAL_MFDUOX_CMD_BUF_OFFSET = 0;
                    PHAL_MFDUOX_PRS_BUF_OFFSET = PHAL_MFDUOX_CMD_BUF_LEN;
                }
                else
                    bHasMoreData = PH_ON;

                wRemData = 0;
            }
            else
            {
                /* Reset command buffer length. */
                PHAL_MFDUOX_CMD_BUF_LEN = 0;
            }
        }

        /* Add PICC data to processing buffer only if required. */
        if(bHasMoreData)
        {
            /* Move the data to processing buffer. */
            if((PHAL_MFDUOX_PRS_BUF_LEN + wDataLen) < PHAL_MFDUOX_PRS_BUF_SIZE)
            {
                (void) memcpy(&PHAL_MFDUOX_PRS_BUF[PHAL_MFDUOX_PRS_BUF_LEN], pResponse, wDataLen);
                PHAL_MFDUOX_PRS_BUF_LEN += (uint16_t) wDataLen;

                /* Reset Offset. */
                PHAL_MFDUOX_CMD_BUF_OFFSET = 0;
            }
            else
            {
                /* Compute Remaining data to be copied. */
                wRemData = (uint16_t) (PHAL_MFDUOX_PRS_BUF_SIZE - PHAL_MFDUOX_PRS_BUF_LEN);

                /* Copy the remaining data. */
                (void) memcpy(&PHAL_MFDUOX_PRS_BUF[PHAL_MFDUOX_PRS_BUF_LEN], pResponse, wRemData);
                PHAL_MFDUOX_PRS_BUF_LEN += (uint16_t) wRemData;

                /* Backup the offset from command buffer. */
                if(PHAL_MFDUOX_PRS_BUF_OFFSET)
                {
                    PHAL_MFDUOX_CMD_BUF_OFFSET = (uint16_t) (wRemData ? (PHAL_MFDUOX_CMD_BUF_LEN - (wDataLen - wRemData)) : PHAL_MFDUOX_CMD_BUF_OFFSET);
                    PHAL_MFDUOX_PRS_BUF_OFFSET = 0;
                }
                else
                    PHAL_MFDUOX_CMD_BUF_OFFSET += (uint16_t) (wRemData + PHAL_MFDUOX_PRS_BUF_OFFSET);

                /* Update Has More Flag.*/
                bHasMoreData = (uint8_t) ((wDataLen - wRemData) ? PH_ON : PH_OFF);

                /* Update status for Chaining. */
                wStatus = PH_ADD_COMPCODE((uint16_t) (bHasMoreData ? PH_ERR_SUCCESS_CHAINING : PH_ERR_SUCCESS), PH_COMP_AL_MFDUOX);
                wStatus = (uint16_t) (((bPiccStat == PHAL_MFDUOX_RESP_OPERATION_OK) && bIsLastFrame && !bHasMoreData) ?
                    PH_ADD_COMPCODE(PH_ERR_SUCCESS, PH_COMP_AL_MFDUOX) : wStatus);
            }
        }
    }

    /* Compute MAC and verify. */
    if(bIsLastFrame || bIsISOChained)
    {
    }

    if(bIsLastFrame || ((wStatus & PH_ERR_MASK) == PH_ERR_SUCCESS_CHAINING))
    {
        /* Copy the data to response parameter. */
        if(pOutBufLen != NULL)
        {
            *ppOutBuffer = bIsISOChained ? pResponse : PHAL_MFDUOX_PRS_BUF;
            *pOutBufLen = (uint16_t) (bIsISOChained ? wDataLen : PHAL_MFDUOX_PRS_BUF_LEN);
        }
    }
    else
    {
        if(bIsISOChained == PH_ON)
        {
            *ppOutBuffer = pResponse;
            *pOutBufLen = wDataLen;
        }
    }

    return wStatus;
}

phStatus_t phalMfDuoX_Sw_Int_ReadData(phalMfDuoX_Sw_DataParams_t * pDataParams, uint16_t wOption, uint8_t bIsISOChained,
    uint8_t bCmd_ComMode, uint8_t bResp_ComMode, uint8_t * pCmdHeader, uint16_t wCmdHeaderLen, uint32_t dwDataToRead,
    uint8_t ** ppResponse, uint16_t * pRespLen)
{
    phStatus_t  PH_MEMLOC_REM wStatus = 0;
    phStatus_t  PH_MEMLOC_REM wStatus_PICC = 0;
    phStatus_t  PH_MEMLOC_REM wStatus_SM = 0;
    uint32_t    PH_MEMLOC_REM dwBlockSize = 0;
    uint32_t    PH_MEMLOC_REM dwTotalReadLen = 0;
    uint16_t    PH_MEMLOC_REM wBuffOption = PH_EXCHANGE_BUFFER_LAST;
    uint16_t    PH_MEMLOC_REM wTotalFrameLen = 0;
    uint16_t    PH_MEMLOC_REM wSMBufLen = 0;
    uint16_t    PH_MEMLOC_REM wRspLen_PICC = 0;
    uint16_t    PH_MEMLOC_REM wRspLen_SM = 0;
    uint8_t     PH_MEMLOC_REM bHasError = PH_OFF;
    uint8_t     PH_MEMLOC_REM bCmdOptions = 0;
    uint8_t     PH_MEMLOC_REM bHasChainedRsp = PH_OFF;
    uint8_t     PH_MEMLOC_REM bFirstFrame = PH_ON;
    uint8_t     PH_MEMLOC_REM bLastFrame = PH_OFF;
    uint8_t     PH_MEMLOC_REM bFinished = PH_OFF;
    uint8_t     PH_MEMLOC_REM bPiccErrCode = 0;
    uint8_t     PH_MEMLOC_REM bShortLenApdu = PH_OFF;
    uint8_t     PH_MEMLOC_REM bChainnedCmd = PHAL_MFDUOX_ADDITIONAL_FRAME;

    uint8_t *   PH_MEMLOC_REM pCmdHeader_Tmp = NULL;
    uint8_t *   PH_MEMLOC_REM pSMBuf = NULL;
    uint8_t *   PH_MEMLOC_REM pResponse_PICC = NULL;
    uint8_t *   PH_MEMLOC_REM pResponse_SM = NULL;

    if((bResp_ComMode != PHAL_MFDUOX_COMMUNICATION_PLAIN) && (pDataParams->bAuthState == PHAL_MFDUOX_NOT_AUTHENTICATED))
    {
        return PH_ADD_COMPCODE(PH_ERR_USE_CONDITION, PH_COMP_AL_MFDUOX);
    }

    /* Move the Command Header to local variable. */
    pCmdHeader_Tmp = pCmdHeader;

    /* Reset Processing Buffer Length. */
    PHAL_MFDUOX_PRS_BUF_LEN = 0;

    /* Frame options for PICC Exchange. */
    bCmdOptions = (uint8_t) (PHAL_MFDUOX_OPTION_COMPLETE | PHAL_MFDUOX_RETURN_PICC_STATUS);

    /* Compute Total frame information length.
     * This includes Command Header + Secure Messaging (Based on Communication modes)
     */
    if((wOption & 0xFF0F) == PH_EXCHANGE_DEFAULT)
    {
#ifndef NXPBUILD__PHAL_MFDUOX_NDA
        wTotalFrameLen = (uint16_t) wCmdHeaderLen;
#endif /* NXPBUILD__PHAL_MFDUOX_NDA */

        /* Set Extended Length APDU format in case of ISO Chaining and data size is greater than frame size. */
        if(pDataParams->bWrappedMode)
        {
            /* Back up current state of ShortLenAPDU information. */
            bShortLenApdu = pDataParams->bShortLenApdu;

            /* Manipulate for Read commands. */
            switch(pDataParams->bCmdCode)
            {
                case PHAL_MFDUOX_CMD_READ_DATA_NATIVE:
                case PHAL_MFDUOX_CMD_READ_DATA_ISO:
                case PHAL_MFDUOX_CMD_READ_RECORD_NATIVE:
                case PHAL_MFDUOX_CMD_READ_RECORD_ISO:
                    /* Compute Total Read Length */
                    PHAL_MFDUOX_NEAREST_MULTIPLE(dwDataToRead, dwBlockSize);
                    dwBlockSize = (uint16_t) ((dwDataToRead == dwBlockSize) ? (dwBlockSize + PH_CRYPTOSYM_AES_BLOCK_SIZE /* Padding */) : dwBlockSize);
#ifndef NXPBUILD__PHAL_MFDUOX_NDA
                    dwTotalReadLen = (uint16_t) dwDataToRead;
#endif /* NXPBUILD__PHAL_MFDUOX_NDA */

                    /* Set the format of data to be sent as short APDU when,
                     * 1. Bit[1] of bIsISOChained is set. This means user is force sending the data in short APDU format in case of BIGISO read.
                     * 2. In case data to be read is not BIGISO (Less than 256 bytes).
                     */
                    if((bIsISOChained == PHAL_MFDUOX_CHAINING_ISO_SHORT_LEN) ||
                        ((dwTotalReadLen <= 0xFF) && (dwDataToRead != 0)))
                    {
                        /* Enable Short Length APDU. */
                        pDataParams->bShortLenApdu = PH_ON;

                        /* Reset Bit[1] of 'bIsISOChained' for subsequent operations */
                        bIsISOChained &= 0xFD;
                    }

                    /* Enable Extended length APDU format in case if Response exceeds the frame size. */
                    else
                        pDataParams->bShortLenApdu = PH_OFF;
                    break;

                default:
                        pDataParams->bShortLenApdu = PH_OFF;
                    break;
            }
        }
    }
    else
    {
        wTotalFrameLen = (uint16_t) (bIsISOChained ? 0 : 1);

        pCmdHeader_Tmp = &bChainnedCmd;
        wCmdHeaderLen = wTotalFrameLen;

        wBuffOption = (uint16_t) (bIsISOChained ? wOption : PH_EXCHANGE_BUFFER_LAST);
        bFirstFrame = PH_OFF;

        /* Frame options for PICC Exchange. */
        bCmdOptions = (uint8_t) (PHAL_MFDUOX_OPTION_COMPLETE | (bIsISOChained ? PHAL_MFDUOX_EXCLUDE_PICC_STATUS : bCmdOptions));
    }

    /* Buffer Command Header for Exchange to PICC -------------------------------------------------------------------------------------- */
    if((PHAL_MFDUOX_IS_PICC_DATA_COMPLETE == PH_OFF) && (wTotalFrameLen != 0))
    {
        PH_CHECK_SUCCESS_FCT(wStatus_PICC, phalMfDuoX_Sw_Int_CardExchange(
            pDataParams,
            PH_EXCHANGE_BUFFER_FIRST,
            PHAL_MFDUOX_CHAINING_BIT_INVALID,
            PHAL_MFDUOX_OPTION_NONE,
            wTotalFrameLen,
            PH_ON,
            pCmdHeader_Tmp,
            wCmdHeaderLen,
            NULL,
            NULL,
            NULL));
    }

    /* Apply MAC on Command ------------------------------------------------------------------------------------------------------------ */
    if((wOption & 0xFF0F) == PH_EXCHANGE_DEFAULT)
    {
        PH_CHECK_SUCCESS_FCT(wStatus_SM, phalMfDuoX_Sw_Int_ApplySM(
            pDataParams,
            PH_ON,
            PH_ON,
            bCmd_ComMode,
            pCmdHeader,
            wCmdHeaderLen,
            NULL,
            0,
            &pSMBuf,
            &wSMBufLen));
    }

    /* Exchange SM Information to PICC ------------------------------------------------------------------------------------------------- */
    do
    {
        if(PHAL_MFDUOX_IS_PICC_DATA_COMPLETE == PH_OFF)
        {
            wTotalFrameLen = (uint16_t) (bHasChainedRsp ? 1 : 0);
            wStatus_PICC = phalMfDuoX_Sw_Int_CardExchange(
                pDataParams,
                wBuffOption,
                PHAL_MFDUOX_CHAINING_BIT_INVALID,
                bCmdOptions,
                wTotalFrameLen,
                PH_ON,
                bHasChainedRsp ? &bChainnedCmd : pSMBuf,
                (uint16_t) (bHasChainedRsp ? 1 : wSMBufLen),
                &pResponse_PICC,
                &wRspLen_PICC,
                &bPiccErrCode);
        }

        /* Update the PICC status to generic status variable. */
        wStatus = wStatus_PICC;

        /* Set the finished flag to end the loop. */
        if(((wStatus & PH_ERR_MASK) != PH_ERR_SUCCESS) && ((wStatus & PH_ERR_MASK) != PH_ERR_SUCCESS_CHAINING))
        {
            bFinished = PH_ON;
            bHasError = PH_ON;
        }

        /* Check if response has Success status. */
        if((wStatus & PH_ERR_MASK) == PH_ERR_SUCCESS)
        {
            bFinished = PH_ON;
            bLastFrame = PH_ON;
            PHAL_MFDUOX_IS_PICC_DATA_COMPLETE = PH_ON;
        }

        /* Verify and Remove Secure Messaging ---------------------------------------------------------------------------------------------- */
        if(!bHasError)
        {
            wStatus_SM = phalMfDuoX_Sw_Int_RemoveSM(
                pDataParams,
                bIsISOChained,
                bFirstFrame,
                bLastFrame,
                bResp_ComMode,
                pResponse_PICC,
                wRspLen_PICC,
                (uint8_t) (bFirstFrame ? PHAL_MFDUOX_RESP_OPERATION_OK : bPiccErrCode),
                &pResponse_SM,
                &wRspLen_SM);
        }

        /* Verify Status of SM */
        if(((wStatus_SM & PH_ERR_MASK) != PH_ERR_SUCCESS) && ((wStatus_SM & PH_ERR_MASK ) != PH_ERR_SUCCESS_CHAINING))
            bFinished = PH_ON;

        /* Update the SM status to generic status variable. */
        if((wStatus & PH_ERR_MASK) == PH_ERR_SUCCESS)
            wStatus = wStatus_SM;

        /* Check if response has chaining status. */
        if((wStatus & PH_ERR_MASK) == PH_ERR_SUCCESS_CHAINING)
        {
            wBuffOption = PH_EXCHANGE_DEFAULT;
            bHasChainedRsp = PH_ON;
            bFirstFrame = PH_OFF;

            /* Complete the loop in case if ISO Chained command. */
            if(bIsISOChained == PH_ON)
                bFinished = PH_ON;
        }

        /* Process response from SM. */
        if((wStatus_SM & PH_ERR_MASK) == PH_ERR_SUCCESS_CHAINING)
        {
            /* End the loop. */
            bFinished = PH_ON;

            /* Update the Generic Status. */
            wStatus = wStatus_SM;
        }
        else
        {
            PHAL_MFDUOX_IS_PICC_DATA_COMPLETE = PH_OFF;
            PHAL_MFDUOX_CMD_BUF_OFFSET = 0;
        }

        /* Copy the response to parameter. */
        if(pRespLen != NULL)
        {
            *ppResponse = pResponse_SM;
            *pRespLen = wRspLen_SM;
        }
    } while(!bFinished);

    /* Perform Reset Authentication. */
    if(bHasError)
    {
        /* Reset Authentication State. */
        phalMfDuoX_Sw_Int_ResetAuthStatus(pDataParams);
    }

    /* Revert back state of ShortLenAPDU information. */
    if(pDataParams->bWrappedMode)
        pDataParams->bShortLenApdu = bShortLenApdu;

    return wStatus;
}

phStatus_t phalMfDuoX_Sw_Int_WriteData(phalMfDuoX_Sw_DataParams_t * pDataParams, uint8_t bIsNativeChained, uint8_t bCmd_ComMode,
    uint8_t bResp_ComMode, uint8_t bResetAuth, uint8_t * pCmdHeader, uint16_t wCmdHeaderLen, uint8_t * pCmdData,
    uint32_t dwCmdDataLen, uint8_t ** ppResponse, uint16_t * pRespLen)
{
    phStatus_t  PH_MEMLOC_REM wStatus = 0;
    phStatus_t  PH_MEMLOC_REM wStatus_PICC = 0;
    phStatus_t  PH_MEMLOC_REM wStatus_SM = 0;
    uint32_t    PH_MEMLOC_REM dwRemData = 0;
    uint32_t    PH_MEMLOC_REM dwBlockSize = 0;
    uint32_t    PH_MEMLOC_REM dwOffset = 0;
    uint16_t    PH_MEMLOC_REM wTotalFrameLen = 0;
    uint16_t    PH_MEMLOC_REM wExchangeLen = 0;
    uint16_t    PH_MEMLOC_REM wWrappedLen = 0;
    uint16_t    PH_MEMLOC_REM wFrameLen = 0;
    uint16_t    PH_MEMLOC_REM wSMBufLen = 0;
    uint16_t    PH_MEMLOC_REM wDataLen = 0;
    uint16_t    PH_MEMLOC_REM wRspLen_PICC = 0;
    uint16_t    PH_MEMLOC_REM wBuffOption_PICC = PH_EXCHANGE_BUFFER_LAST;
    uint16_t    PH_MEMLOC_REM wRemData_Exchange = 0U;
    uint16_t    PH_MEMLOC_REM wBytesExchanged = 0;
    uint16_t    PH_MEMLOC_REM wTotalBytesExchanged = 0;
    uint8_t     PH_MEMLOC_REM bFinished = PH_OFF;
    uint8_t     PH_MEMLOC_REM bPiccErrCode = PH_OFF;
    uint8_t     PH_MEMLOC_REM bCmdOptions = 0;
    uint8_t     PH_MEMLOC_REM bHasError = PH_OFF;
    uint8_t     PH_MEMLOC_REM bShortLenApdu = PH_OFF;
    uint8_t     PH_MEMLOC_REM bChainnedCmd = PHAL_MFDUOX_ADDITIONAL_FRAME;
    uint8_t     PH_MEMLOC_REM bIsChainnedFrame = PH_OFF;
    uint8_t     PH_MEMLOC_REM bIsFirstFrame = PH_OFF;
    uint8_t     PH_MEMLOC_REM bIsLastFrame = PH_OFF;

    /* In case if there is no more data to exchange with PICC and PICC is still expecting data. */
    uint8_t     PH_MEMLOC_REM bRetry = 1;

    uint8_t *   PH_MEMLOC_REM pSMBuf = NULL;
    uint8_t *   PH_MEMLOC_REM pResponse_PICC = NULL;

    if((bCmd_ComMode != PHAL_MFDUOX_COMMUNICATION_PLAIN) && (pDataParams->bAuthState == PHAL_MFDUOX_NOT_AUTHENTICATED))
    {
        return PH_ADD_COMPCODE(PH_ERR_USE_CONDITION, PH_COMP_AL_MFDUOX);
    }

    /* Clear Processing buffer. */
    if(PHAL_MFDUOX_IS_PICC_DATA_COMPLETE == PH_OFF)
    {
        PHAL_MFDUOX_PRS_BUF_LEN = 0;
    }

    /* Get PICC Frame size. */
    PH_CHECK_SUCCESS_FCT(wStatus, phalMfDuoX_Sw_Int_GetFrameLen(pDataParams, bIsNativeChained, &wFrameLen));

    /* Get Encrypted Data Block Size. */
    PHAL_MFDUOX_NEAREST_MULTIPLE(dwCmdDataLen, dwBlockSize);
    dwBlockSize = (uint16_t) ((dwCmdDataLen == dwBlockSize) ? (dwBlockSize + PH_CRYPTOSYM_AES_BLOCK_SIZE /* Padding */) : dwBlockSize);

    /* Compute Total frame information length.
     * This includes Command Header + Command Data (Based on Communication modes)
     */
#ifndef NXPBUILD__PHAL_MFDUOX_NDA
    wTotalFrameLen = (uint16_t) (wCmdHeaderLen + dwCmdDataLen);
#endif /* NXPBUILD__PHAL_MFDUOX_NDA */

    /* Compute the maximum bytes that be transferred in one frame. */
    wExchangeLen = wTotalFrameLen;
    wExchangeLen = (uint16_t) (bIsNativeChained ? ((wExchangeLen < wFrameLen) ? wExchangeLen : wFrameLen) : wExchangeLen);

    /* Set Extended Length APDU format in case of ISO Chaining and data size is greater than frame size. */
    if(pDataParams->bWrappedMode)
    {
        if(bIsNativeChained == PH_OFF)
        {
            /* Back up current state of ShortLenAPDUinformation. */
            bShortLenApdu = pDataParams->bShortLenApdu;

            /* Enable Extended length APDU format in case if CommandLen + DataLen + ISO7816 Header exceeds frame size. */
            if((wExchangeLen - 5U) > wFrameLen)
                pDataParams->bShortLenApdu = PH_OFF;
        }

        /* Update wrapped length. */
        else
        {
            wWrappedLen = 6U; /* CLA, INS, P1, P2, LC, LE. */
            wWrappedLen = (uint16_t) (pDataParams->bShortLenApdu ? wWrappedLen : (wWrappedLen + 3U /* Extended LC and LE */));

            /* Update Frame Length in case */
            wFrameLen -= wWrappedLen;

            /* Update Total Frame length. */
            wExchangeLen = (uint16_t) ((wExchangeLen > wFrameLen) ? (wFrameLen + 1U) : wExchangeLen);
        }
    }

    /* Buffer Command Header to PICC exchange buffer ----------------------------------------------------------------------------------- */
    PH_CHECK_SUCCESS_FCT(wStatus_PICC, phalMfDuoX_Sw_Int_CardExchange(
        pDataParams,
        PH_EXCHANGE_BUFFER_FIRST,
        PHAL_MFDUOX_CHAINING_BIT_INVALID,
        PHAL_MFDUOX_OPTION_NONE,
        wExchangeLen,
        PH_ON,
        pCmdHeader,
        wCmdHeaderLen,
        NULL,
        NULL,
        NULL));

    /* Update Remaining data for SM and. */
    dwRemData = dwCmdDataLen;

    /* Set the Frame options. */
    bIsFirstFrame = PH_ON;
    bIsLastFrame = PH_OFF;

    /* Set Command header as exchanged information  */
    wTotalBytesExchanged = wCmdHeaderLen;
    wBytesExchanged = (uint16_t) ((pDataParams->bWrappedMode) ? (wCmdHeaderLen - 1U) : wCmdHeaderLen);

    do
    {
        /* Exclude if all data is processed but PICC exchange is pending. */
        if(bIsLastFrame == PH_OFF)
        {
            /* Update the data to be used for SM Application. */
            wDataLen = (uint16_t) ((dwRemData > wFrameLen) ? wFrameLen : dwRemData);
            wDataLen = (uint16_t) (((wCmdHeaderLen + wDataLen) > wFrameLen) ? PHAL_MFDUOX_ABS(wFrameLen, wCmdHeaderLen) : wDataLen);
            wDataLen = (uint16_t) (bIsChainnedFrame && (wDataLen >= wFrameLen) ? (wDataLen - 1U) : wDataLen);

            /* Update Remaining data to be used. */
            dwRemData -= wDataLen;

            /* Set Framing Options. */
            bIsLastFrame = (uint8_t) (dwRemData <= 0U);

            /* Apply Secure Messaging on Command ------------------------------------------------------------------------------------------- */
            wStatus_SM = phalMfDuoX_Sw_Int_ApplySM(
                pDataParams,
                bIsFirstFrame,
                bIsLastFrame,
                bCmd_ComMode,
                pCmdHeader,
                wCmdHeaderLen,
                &pCmdData[dwOffset],
                wDataLen,
                &pSMBuf,
                &wSMBufLen);

            /* Clear Framing Option */
            bIsFirstFrame = PH_OFF;

            /* Update the PICC status to generic status variable. */
            wStatus = wStatus_SM;

            /* Update the Offset */
            dwOffset += wDataLen;
        }

        /* Verify Status of SM */
        if(((wStatus & PH_ERR_MASK) != PH_ERR_SUCCESS) && ((wStatus & PH_ERR_MASK) != PH_ERR_SUCCESS_CHAINING))
        {
            bFinished = PH_ON;
            bHasError = PH_ON;
        }

        /* Set the finished flag to end the loop. */
        bFinished = bIsLastFrame;

        /* Exchange data to PICC. */
        if(bHasError == PH_OFF)
        {
            /* Backup data to be exchanged. */
            wRemData_Exchange = wSMBufLen;
            wDataLen = wSMBufLen;

            do
            {
                if(bIsNativeChained == PH_ON)
                {
                    wBuffOption_PICC = (uint16_t) (((wBytesExchanged + wDataLen) >= wFrameLen) ?
                        PH_EXCHANGE_BUFFER_LAST : PH_EXCHANGE_BUFFER_CONT);

                    wDataLen = (uint16_t) (((wBytesExchanged + wDataLen) > wFrameLen) ?
                        PHAL_MFDUOX_ABS(wFrameLen, wBytesExchanged) : wRemData_Exchange);
                }
                else
                {
                    wBuffOption_PICC = PH_EXCHANGE_BUFFER_CONT;
                }

                /* Update remaining data to exchange */
                wRemData_Exchange -= wDataLen;

                /* Update Buffer Options */
                wBuffOption_PICC = (uint16_t) (bIsLastFrame ? PH_EXCHANGE_BUFFER_LAST : wBuffOption_PICC);

                /* Update options for exchange interface. */
                bCmdOptions = (uint8_t) ((wBuffOption_PICC == PH_EXCHANGE_BUFFER_CONT) ? PHAL_MFDUOX_OPTION_NONE : PHAL_MFDUOX_OPTION_COMPLETE);
                bCmdOptions |= PHAL_MFDUOX_RETURN_PICC_STATUS;

                /* Exchange data. */
                if((wDataLen > 0U) || (bIsLastFrame == PH_ON))
                {
                    /* Clear Total exchange length */
                    wExchangeLen = (uint16_t) ((bIsNativeChained == PH_ON) ? 0U : wExchangeLen);

                    wStatus_PICC = phalMfDuoX_Sw_Int_CardExchange(
                        pDataParams,
                        wBuffOption_PICC,
                        PHAL_MFDUOX_CHAINING_BIT_INVALID,
                        bCmdOptions,
                        wExchangeLen,
                        PH_ON,
                        pSMBuf,
                        wDataLen,
                        &pResponse_PICC,
                        &wRspLen_PICC,
                        &bPiccErrCode);

                    /* Set bytes exchanged fro current frame. */
                    wBytesExchanged += wDataLen;

                    /* Set bytes exchanged */
                    wTotalBytesExchanged += wDataLen;
                }

                /* Update the SM status to generic status variable. */
                wStatus = wStatus_PICC;

                /* Set the finished flag to end the loop. */
                if((bPiccErrCode != PHAL_MFDUOX_RESP_OPERATION_OK) && (bPiccErrCode != PHAL_MFDUOX_RESP_OPERATION_OK_LIM) &&
                    (bPiccErrCode != PHAL_MFDUOX_ADDITIONAL_FRAME))
                {
                    bHasError = PH_ON;
                    bFinished = PH_ON;
                    wRemData_Exchange = 0U;
                }

                /* Exchange chaining command */
                bIsChainnedFrame = (uint8_t) ((wBuffOption_PICC == PH_EXCHANGE_BUFFER_LAST) && (bIsNativeChained == PH_ON));
                bIsChainnedFrame = (uint8_t) ((bPiccErrCode != PHAL_MFDUOX_ADDITIONAL_FRAME) ? PH_OFF : bIsChainnedFrame);

                if(bIsChainnedFrame == PH_ON)
                {
                    while(bRetry != 10U)
                    {
                        /* Update command header length */
                        wCmdHeaderLen = 1U;

                        /* Clear PICC Response Code */
                        bPiccErrCode = 0U;

                        wBytesExchanged = (uint16_t) ((pDataParams->bWrappedMode) ? 0U : wCmdHeaderLen);

                        wExchangeLen = (uint16_t) (((wTotalFrameLen - wTotalBytesExchanged) >= wFrameLen) ? wFrameLen :
                            (wCmdHeaderLen + (wTotalFrameLen - wTotalBytesExchanged)));
                        wExchangeLen = (uint16_t) (wExchangeLen + ((wTotalFrameLen - wTotalBytesExchanged) >= wFrameLen));

                        /* Update Buffer Options */
                        wBuffOption_PICC = (uint16_t) (((dwRemData != 0U) || (wRemData_Exchange != 0U)) ? PH_EXCHANGE_BUFFER_FIRST :
                            PH_EXCHANGE_DEFAULT);

                        /* Update options for exchange interface. */
                        bCmdOptions = PHAL_MFDUOX_RETURN_PICC_STATUS;
                        bCmdOptions |= (uint8_t) ((wBuffOption_PICC == PH_EXCHANGE_BUFFER_FIRST) ? PHAL_MFDUOX_OPTION_NONE :
                            PHAL_MFDUOX_OPTION_COMPLETE);

                        wStatus_PICC = phalMfDuoX_Sw_Int_CardExchange(
                            pDataParams,
                            wBuffOption_PICC,
                            PHAL_MFDUOX_CHAINING_BIT_DISABLE,
                            bCmdOptions,
                            wExchangeLen,
                            PH_ON,
                            &bChainnedCmd,
                            wCmdHeaderLen,
                            &pResponse_PICC,
                            &wRspLen_PICC,
                            &bPiccErrCode);

                        /* Shift SMBuffer to next starting position */
                        pSMBuf += ((wRemData_Exchange > 0U) ? wDataLen : 0U);
                        wDataLen = wRemData_Exchange;

                        /* Update Retry count. */
                        bRetry = (uint8_t) ((wBuffOption_PICC == PH_EXCHANGE_BUFFER_FIRST) ? 10U : (bRetry + 1U));
                        bRetry = (uint8_t) ((bPiccErrCode != PHAL_MFDUOX_ADDITIONAL_FRAME) ? 10U : bRetry);
                    }

                    /* Reset Retry count. */
                    bRetry = 1U;
                }
                else
                {
                    wCmdHeaderLen = (uint16_t) ((bIsNativeChained == PH_OFF) ? 0U : wCmdHeaderLen);
                }

                /* Clear PICC Response Code */
                bPiccErrCode = 0U;

            } while(wRemData_Exchange != 0U);
        }
        else
        {
            /* Set the finished flag to end the loop. */
            bFinished = PH_ON;
        }
    } while(!bFinished);

    /* Clear Offsets and length. */
    PHAL_MFDUOX_CMD_BUF_LEN = 0U;
    PHAL_MFDUOX_CMD_BUF_OFFSET = 0U;

    PHAL_MFDUOX_PRS_BUF_LEN = 0U;
    PHAL_MFDUOX_PRS_BUF_OFFSET = 0U;

    /* Verify and Remove Secure Messaging ---------------------------------------------------------------------------------------------- */
    if(!bHasError)
    {
        if(bResp_ComMode != PHAL_MFDUOX_COMMUNICATION_PLAIN)
        {
            PH_CHECK_SUCCESS_FCT(wStatus_SM, phalMfDuoX_Sw_Int_RemoveSM(
                pDataParams,
                PH_OFF,
                PH_ON,
                PH_ON,
                bResp_ComMode,
                pResponse_PICC,
                wRspLen_PICC,
                bPiccErrCode,
                ppResponse,
                pRespLen));
        }
        else
        {
            /* In case of SUCCESS and Communication mode as PLAIN, increment the command counter. */
            if(wStatus == PH_ERR_SUCCESS)
                pDataParams->wCmdCtr++;

            /* Copy response data to parameter */
            if (pRespLen != NULL)
            {
                *ppResponse = pResponse_PICC;
                *pRespLen = wRspLen_PICC;
            }
        }
    }

    /* Perform Reset Authentication. */
    if(bResetAuth || bHasError)
    {
        /* Clear Reset Authentication flag. */
        bResetAuth = PH_OFF;

        /* Additional Operation for Delete Application command execution. */
        if((pDataParams->bCmdCode == PHAL_MFDUOX_CMD_DELETE_APPLICATION) && (bHasError == PH_OFF))
        {
            /* Reset the Application Identifier. */
            (void) memset(pDataParams->aAid, 0x00, 3);
        }

        /* Reset Authentication State. */
        phalMfDuoX_Sw_Int_ResetAuthStatus(pDataParams);
    }

    PHAL_MFDUOX_IS_PICC_DATA_COMPLETE = PH_OFF;

    /* Revert back state of ShortLenAPDU information. */
    if(pDataParams->bWrappedMode && (bIsNativeChained == PH_OFF))
        pDataParams->bShortLenApdu = bShortLenApdu;

    return wStatus;
}

phStatus_t phalMfDuoX_Sw_Int_ISOSelectFile(phalMfDuoX_Sw_DataParams_t * pDataParams, uint8_t * pData, uint16_t wDataLen,
    uint8_t * pLe, uint8_t bLeLen, uint8_t ** ppResponse, uint16_t * pRspLen)
{
    phStatus_t  PH_MEMLOC_REM wStatusTmp = PH_ERR_SUCCESS;
    phStatus_t  PH_MEMLOC_REM wStatusTmp1 = PH_ERR_SUCCESS;
    uint8_t     PH_MEMLOC_REM *pResponse = NULL;
    uint16_t    PH_MEMLOC_REM wRspLen = 0;
    uint16_t    PH_MEMLOC_REM wVal = 0;

    /* Buffer Command Data. */
    PH_CHECK_SUCCESS_FCT(wStatusTmp, phpalMifare_ExchangeL4(
        pDataParams->pPalMifareDataParams,
        PH_EXCHANGE_BUFFER_CONT,
        pData,
        wDataLen,
        &pResponse,
        &wRspLen));

    /* Buffer LE and Exchange the command to PICC.  */
    PH_CHECK_SUCCESS_FCT(wStatusTmp, phpalMifare_ExchangeL4(
        pDataParams->pPalMifareDataParams,
        PH_EXCHANGE_BUFFER_LAST,
        pLe,
        bLeLen,
        &pResponse,
        &wRspLen));

    /* Combine Sw1 and Sw2 status codes. */
    wStatusTmp = (uint16_t) ((pResponse[wRspLen - 2] << 8) | pResponse[wRspLen - 1]);

    /* Evaluate the Status. */
    wStatusTmp = phalMfDuoX_Int_ComputeErrorResponse(pDataParams, wStatusTmp);

    /*  */
    if((wStatusTmp & PH_ERR_MASK) == PHAL_MFDUOX_ERR_DF_7816_GEN_ERROR)
    {
        PH_CHECK_SUCCESS_FCT(wStatusTmp1, phalMfDuoX_GetConfig(pDataParams, PHAL_MFDUOX_ADDITIONAL_INFO, &wVal));
    }

    /*  Check for Success and for LIMITED FUNCTIONALITY error. In both cases, FCI would be returned */
    if((wStatusTmp == PH_ERR_SUCCESS) || (wVal == PHAL_MFDUOX_ISO7816_ERR_LIMITED_FUNCTIONALITY_INS))
    {
        if(pRspLen != NULL)
        {
            *pRspLen = wRspLen - 2;
        }

        if(ppResponse != NULL)
        {
            *ppResponse = pResponse;
        }
    }
    else
    {
        /* Nothing to do here */
    }

    return wStatusTmp;
}

phStatus_t phalMfDuoX_Sw_Int_ISOReadBinary(phalMfDuoX_Sw_DataParams_t * pDataParams, uint16_t wOption, uint8_t * pLe,
    uint8_t bLeLen, uint8_t ** ppResponse, uint16_t * pRspLen)
{
    phStatus_t  PH_MEMLOC_REM wStatus = PH_ERR_SUCCESS;
    phStatus_t  PH_MEMLOC_REM wStatus_Rsp = PH_ERR_SUCCESS;
    uint8_t     PH_MEMLOC_REM *pResponse = NULL;
    uint16_t    PH_MEMLOC_REM wRspLen = 0;
    uint16_t    PH_MEMLOC_REM wOptions_Tmp = 0;

    if((wOption & PH_EXCHANGE_MODE_MASK) == PH_EXCHANGE_RXCHAINING)
    {
        bLeLen = 0;
        wOptions_Tmp = PH_EXCHANGE_RXCHAINING;
    }
    else
    {
        wOptions_Tmp = PH_EXCHANGE_BUFFER_LAST;
    }

    /* Buffer LE and Exchange the command to PICC.  */
    wStatus = phpalMifare_ExchangeL4(
        pDataParams->pPalMifareDataParams,
        wOptions_Tmp,
        pLe,
        bLeLen,
        &pResponse,
        &wRspLen);

    /* Reset Authentication state. */
    if(((wStatus & PH_ERR_MASK) != PH_ERR_SUCCESS) && ((wStatus & PH_ERR_MASK) != PH_ERR_SUCCESS_CHAINING))
    {
        phalMfDuoX_Sw_Int_ResetAuthStatus(pDataParams);
    }
    else
    {
        /* Combine Sw1 and Sw2 status codes. */
        wStatus_Rsp = (uint16_t) ((pResponse[wRspLen - 2] << 8) | pResponse[wRspLen - 1]);

        /* Evaluate the Status. */
        wStatus = phalMfDuoX_Sw_Int_ValidateResponse(pDataParams, PHAL_MFDUOX_ISO7816_APDU_CMD, wStatus, wStatus_Rsp);

        /* Copy the response to parameter. */
        *ppResponse = pResponse;
        *pRspLen = wRspLen;

        /* Decrement Status code. */
        if((wStatus & PH_ERR_MASK) == PH_ERR_SUCCESS)
            *pRspLen = *pRspLen - 2;
    }

    return wStatus;
}

phStatus_t phalMfDuoX_Sw_Int_ISOUpdateBinary(phalMfDuoX_Sw_DataParams_t * pDataParams, uint8_t * pData, uint16_t wDataLen)
{
    phStatus_t  PH_MEMLOC_REM wStatus = PH_ERR_SUCCESS;
    phStatus_t  PH_MEMLOC_REM wStatus_Rsp = PH_ERR_SUCCESS;
    uint8_t     PH_MEMLOC_REM *pResponse = NULL;
    uint16_t    PH_MEMLOC_REM wRspLen = 0;

    /* Buffer LE and Exchange the command to PICC.  */
    PH_CHECK_SUCCESS_FCT(wStatus, phpalMifare_ExchangeL4(
        pDataParams->pPalMifareDataParams,
        PH_EXCHANGE_BUFFER_LAST,
        pData,
        wDataLen,
        &pResponse,
        &wRspLen));

    /* Combine Sw1 and Sw2 status codes. */
    wStatus_Rsp = (uint16_t) ((pResponse[wRspLen - 2] << 8) | pResponse[wRspLen - 1]);

    /* Evaluate the Status. */
    wStatus = phalMfDuoX_Int_ComputeErrorResponse(pDataParams, wStatus_Rsp);

    /* Reset Authentication state. */
    if((wStatus & PH_ERR_MASK) != PH_ERR_SUCCESS)
    {
        phalMfDuoX_Sw_Int_ResetAuthStatus(pDataParams);
    }
    else
    {
        /* Do Nothing */
    }

    return wStatus;
}

phStatus_t phalMfDuoX_Sw_Int_ISOReadRecord(phalMfDuoX_Sw_DataParams_t * pDataParams, uint16_t wOption, uint8_t * pLe,
    uint8_t bLeLen, uint8_t ** ppResponse, uint16_t * pRspLen)
{
    phStatus_t  PH_MEMLOC_REM wStatus = PH_ERR_SUCCESS;
    phStatus_t  PH_MEMLOC_REM wStatus_Rsp = PH_ERR_SUCCESS;
    uint8_t     PH_MEMLOC_REM *pResponse = NULL;
    uint16_t    PH_MEMLOC_REM wRspLen = 0;
    uint16_t    PH_MEMLOC_REM wOptions_Tmp = 0;

    if((wOption & PH_EXCHANGE_MODE_MASK) == PH_EXCHANGE_RXCHAINING)
    {
        bLeLen = 0;
        wOptions_Tmp = PH_EXCHANGE_RXCHAINING;
    }
    else
    {
        wOptions_Tmp = PH_EXCHANGE_BUFFER_LAST;
    }

    /* Buffer LE and Exchange the command to PICC.  */
    wStatus = phpalMifare_ExchangeL4(
        pDataParams->pPalMifareDataParams,
        wOptions_Tmp,
        pLe,
        bLeLen,
        &pResponse,
        &wRspLen);

    /* Reset Authentication state. */
    if(((wStatus & PH_ERR_MASK) != PH_ERR_SUCCESS) && ((wStatus & PH_ERR_MASK) != PH_ERR_SUCCESS_CHAINING))
    {
        phalMfDuoX_Sw_Int_ResetAuthStatus(pDataParams);
    }
    else
    {
        /* Combine Sw1 and Sw2 status codes. */
        wStatus_Rsp = (uint16_t) ((pResponse[wRspLen - 2] << 8) | pResponse[wRspLen - 1]);

        /* Evaluate the Status. */
        wStatus = phalMfDuoX_Sw_Int_ValidateResponse(pDataParams, PHAL_MFDUOX_ISO7816_APDU_CMD, wStatus, wStatus_Rsp);

        /* Copy the response to parameter. */
        *ppResponse = pResponse;
        *pRspLen = wRspLen;

        /* Decrement Status code. */
        if((wStatus & PH_ERR_MASK) == PH_ERR_SUCCESS)
            *pRspLen = *pRspLen - 2;
    }

    return wStatus;
}

phStatus_t phalMfDuoX_Sw_Int_ISOAppendRecord(phalMfDuoX_Sw_DataParams_t * pDataParams, uint8_t * pData, uint16_t wDataLen)
{
    phStatus_t  PH_MEMLOC_REM wStatus = PH_ERR_SUCCESS;
    phStatus_t  PH_MEMLOC_REM wStatus_Rsp = PH_ERR_SUCCESS;
    uint8_t     PH_MEMLOC_REM *pResponse = NULL;
    uint16_t    PH_MEMLOC_REM wRspLen = 0;

    /* Buffer LE and Exchange the command to PICC.  */
    PH_CHECK_SUCCESS_FCT(wStatus, phpalMifare_ExchangeL4(
        pDataParams->pPalMifareDataParams,
        PH_EXCHANGE_BUFFER_LAST,
        pData,
        wDataLen,
        &pResponse,
        &wRspLen));

    /* Combine Sw1 and Sw2 status codes. */
    wStatus_Rsp = (uint16_t) ((pResponse[wRspLen - 2] << 8) | pResponse[wRspLen - 1]);

    /* Evaluate the Status. */
    wStatus = phalMfDuoX_Int_ComputeErrorResponse(pDataParams, wStatus_Rsp);

    /* Reset Authentication state. */
    if((wStatus & PH_ERR_MASK) != PH_ERR_SUCCESS)
    {
        phalMfDuoX_Sw_Int_ResetAuthStatus(pDataParams);
    }
    else
    {
        /* Do Nothing */
    }

    return wStatus;
}

phStatus_t phalMfDuoX_Sw_Int_ISOGetChallenge(phalMfDuoX_Sw_DataParams_t * pDataParams, uint8_t * pLe, uint8_t bLeLen,
    uint8_t ** ppResponse, uint16_t * pRspLen)
{
    phStatus_t  PH_MEMLOC_REM wStatus = PH_ERR_SUCCESS;
    phStatus_t  PH_MEMLOC_REM wStatus_Rsp = PH_ERR_SUCCESS;
    uint8_t     PH_MEMLOC_REM *pResponse = NULL;
    uint16_t    PH_MEMLOC_REM wRspLen = 0;

    /* Buffer LE and Exchange the command to PICC.  */
    PH_CHECK_SUCCESS_FCT(wStatus, phpalMifare_ExchangeL4(
        pDataParams->pPalMifareDataParams,
        PH_EXCHANGE_BUFFER_LAST,
        pLe,
        bLeLen,
        &pResponse,
        &wRspLen));

    /* Combine Sw1 and Sw2 status codes. */
    wStatus_Rsp = (uint16_t) ((pResponse[wRspLen - 2] << 8) | pResponse[wRspLen - 1]);

    /* Evaluate the Status. */
    wStatus = phalMfDuoX_Int_ComputeErrorResponse(pDataParams, wStatus_Rsp);

    /* Reset Authentication state. */
    phalMfDuoX_Sw_Int_ResetAuthStatus(pDataParams);

    /* Copy the response. */
    if((wStatus & PH_ERR_MASK) == PH_ERR_SUCCESS)
    {
        /* Copy the response to parameter. */
        *ppResponse = pResponse;
        *pRspLen = wRspLen - 2;
    }

    return wStatus;
}

phStatus_t phalMfDuoX_Sw_Int_VdeReadData(phalMfDuoX_Sw_DataParams_t * pDataParams, uint16_t wOption, uint8_t * pLe,
    uint8_t bLeLen, uint8_t ** ppResponse, uint16_t * pRspLen)
{
    phStatus_t  PH_MEMLOC_REM wStatus = PH_ERR_SUCCESS;
    phStatus_t  PH_MEMLOC_REM wStatus_Rsp = PH_ERR_SUCCESS;
    uint8_t     PH_MEMLOC_REM *pResponse = NULL;
    uint16_t    PH_MEMLOC_REM wRspLen = 0;
    uint16_t    PH_MEMLOC_REM wOptions_Tmp = 0;

    if((wOption & PH_EXCHANGE_MODE_MASK) == PH_EXCHANGE_RXCHAINING)
    {
        bLeLen = 0;
        wOptions_Tmp = PH_EXCHANGE_RXCHAINING;
    }
    else
    {
        wOptions_Tmp = PH_EXCHANGE_BUFFER_LAST;
    }

    /* Buffer LE and Exchange the command to PICC.  */
    wStatus = phpalMifare_ExchangeL4(
        pDataParams->pPalMifareDataParams,
        wOptions_Tmp,
        pLe,
        bLeLen,
        &pResponse,
        &wRspLen);

    /* Combine Sw1 and Sw2 status codes. */
    wStatus_Rsp = (uint16_t) ((pResponse[wRspLen - 2] << 8) | pResponse[wRspLen - 1]);

    /* Evaluate the Status. */
    wStatus = phalMfDuoX_Sw_Int_ValidateResponse(pDataParams, PHAL_MFDUOX_ISO7816_APDU_CMD, wStatus, wStatus_Rsp);

    /* Reset Authentication state. */
    if(((wStatus & PH_ERR_MASK) != PH_ERR_SUCCESS) && ((wStatus & PH_ERR_MASK) != PH_ERR_SUCCESS_CHAINING))
    {
        phalMfDuoX_Sw_Int_ResetAuthStatus(pDataParams);
    }
    else
    {
        /* Copy the response to parameter. */
        *ppResponse = pResponse;
        *pRspLen = wRspLen;

        /* Decrement Status code. */
        if((wStatus & PH_ERR_MASK) == PH_ERR_SUCCESS)
            *pRspLen = *pRspLen - 2;
    }

    return wStatus;
}

phStatus_t phalMfDuoX_Sw_Int_VdeWriteData(phalMfDuoX_Sw_DataParams_t * pDataParams, uint8_t * pData, uint16_t wDataLen,
    uint8_t * pLe, uint8_t bLeLen)
{
    phStatus_t  PH_MEMLOC_REM wStatus = PH_ERR_SUCCESS;
    phStatus_t  PH_MEMLOC_REM wStatus_Rsp = PH_ERR_SUCCESS;
    uint8_t     PH_MEMLOC_REM *pResponse = NULL;
    uint16_t    PH_MEMLOC_REM wRspLen = 0;

    /* Buffer Command Data. */
    PH_CHECK_SUCCESS_FCT(wStatus, phpalMifare_ExchangeL4(
        pDataParams->pPalMifareDataParams,
        PH_EXCHANGE_BUFFER_CONT,
        pData,
        wDataLen,
        &pResponse,
        &wRspLen));

    /* Buffer LE and Exchange the command to PICC.  */
    PH_CHECK_SUCCESS_FCT(wStatus, phpalMifare_ExchangeL4(
        pDataParams->pPalMifareDataParams,
        PH_EXCHANGE_BUFFER_LAST,
        pLe,
        bLeLen,
        &pResponse,
        &wRspLen));

    /* Combine Sw1 and Sw2 status codes. */
    wStatus_Rsp = (uint16_t) ((pResponse[wRspLen - 2] << 8) | pResponse[wRspLen - 1]);

    /* Evaluate the Status. */
    wStatus = phalMfDuoX_Int_ComputeErrorResponse(pDataParams, wStatus_Rsp);

    /* Reset Authentication state. */
    if((wStatus & PH_ERR_MASK) != PH_ERR_SUCCESS)
    {
        phalMfDuoX_Sw_Int_ResetAuthStatus(pDataParams);
    }
    else
    {
        /* Do Nothing */
    }

    return wStatus;
}

phStatus_t phalMfDuoX_Sw_Int_VdeECDSASign(phalMfDuoX_Sw_DataParams_t * pDataParams, uint8_t * pData, uint16_t wDataLen,
    uint8_t * pLe, uint8_t bLeLen, uint8_t ** ppResponse, uint16_t * pRspLen)
{
    phStatus_t  PH_MEMLOC_REM wStatus = PH_ERR_SUCCESS;
    phStatus_t  PH_MEMLOC_REM wStatus_Rsp = PH_ERR_SUCCESS;
    uint8_t     PH_MEMLOC_REM *pResponse = NULL;
    uint16_t    PH_MEMLOC_REM wRspLen = 0;

    /* Buffer Command Data. */
    PH_CHECK_SUCCESS_FCT(wStatus, phpalMifare_ExchangeL4(
        pDataParams->pPalMifareDataParams,
        PH_EXCHANGE_BUFFER_CONT,
        pData,
        wDataLen,
        &pResponse,
        &wRspLen));

    /* Buffer LE and Exchange the command to PICC.  */
    PH_CHECK_SUCCESS_FCT(wStatus, phpalMifare_ExchangeL4(
        pDataParams->pPalMifareDataParams,
        PH_EXCHANGE_BUFFER_LAST,
        pLe,
        bLeLen,
        &pResponse,
        &wRspLen));

    /* Combine Sw1 and Sw2 status codes. */
    wStatus_Rsp = (uint16_t) ((pResponse[wRspLen - 2] << 8) | pResponse[wRspLen - 1]);

    /* Evaluate the Status. */
    wStatus = phalMfDuoX_Int_ComputeErrorResponse(pDataParams, wStatus_Rsp);

    /* Reset Authentication state. */
    if((wStatus & PH_ERR_MASK) != PH_ERR_SUCCESS)
    {
        phalMfDuoX_Sw_Int_ResetAuthStatus(pDataParams);
    }
    else
    {
        /* Copy the response to parameter. */
        *ppResponse = pResponse;
        *pRspLen = wRspLen;
    }

    return wStatus;
}

phStatus_t phalMfDuoX_Sw_Int_ResetAuthStatus(phalMfDuoX_Sw_DataParams_t * pDataParams)
{
    phStatus_t PH_MEMLOC_REM wStatus = PH_ERR_USE_CONDITION;

    pDataParams->wCmdBufLen = 0;
    pDataParams->wCmdBufOffset = 0;
    pDataParams->wPrsBufLen = 0;
    pDataParams->wPrsBufOffset = 0;
    pDataParams->wCmdCtr = 0;
    pDataParams->bCmdCode = PHAL_MFDUOX_CMD_INVALID;
    pDataParams->bAuthState = PHAL_MFDUOX_NOT_AUTHENTICATED;
    pDataParams->bKeyNo = 0xFF;
    pDataParams->bPICCDataComplete = PH_OFF;

    (void) memset(pDataParams->pCmdBuf, 0x00, PHAL_MFDUOX_CMD_BUFFER_SIZE_MINIMUM);
    (void) memset(pDataParams->pPrsBuf, 0x00, PHAL_MFDUOX_PRS_BUFFER_SIZE_MINIMUM);

    return wStatus;
}

phStatus_t phalMfDuoX_Sw_Int_GetFrameLen(phalMfDuoX_Sw_DataParams_t * pDataParams, uint8_t bIsNativeChained, uint16_t * pFrameLen)
{
    uint16_t    PH_MEMLOC_REM wStatus = 0;
    uint16_t    PH_MEMLOC_REM wFSI = 0;

    PH_CHECK_SUCCESS_FCT(wStatus, phpalMifare_GetConfig(pDataParams->pPalMifareDataParams,
        PHPAL_I14443P4_CONFIG_FSI, &wFSI));

    /* Extract FSCI (PICC Frame Size) and Update the parameter. */
    *pFrameLen = aFrameSize[(uint8_t) (wFSI & 0x00FF)];

    /* Fix Frame length to 64 Bytes if Native Chaining is Enabled */
    if((bIsNativeChained == PH_ON) && (*pFrameLen > PHAL_MFDUOX_MAX_NATIVE_DATA_LEN))
        *pFrameLen = PHAL_MFDUOX_MAX_NATIVE_DATA_LEN;

    /* Remove the ISO header. */
    *pFrameLen -= 4;

    return PH_ADD_COMPCODE(PH_ERR_SUCCESS, PH_COMP_AL_MFDUOX);
}

#endif /* NXPBUILD__PHAL_MFDUOX_SW */
