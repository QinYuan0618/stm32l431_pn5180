/*----------------------------------------------------------------------------*/
/* Copyright 2009 - 2023 NXP                                                  */
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
* Internal functions of Virtual Card Architecture Application Component.
* $Author: Rajendran Kumar (nxp99556) $
* $Revision: 6146 $ (v07.13.00)
* $Date: 2020-07-13 14:31:23 +0530 (Mon, 13 Jul 2020) $
*/

#include <ph_Status.h>
#include <phpalMifare.h>
#include <ph_RefDefs.h>

#ifdef NXPBUILD__PHAL_VCA
#include <phalVca.h>
#include "phalVca_Int.h"

phStatus_t phalVca_Int_ComputeErrorResponse(uint16_t wNumBytesReceived, uint8_t bStatus)
{
    phStatus_t PH_MEMLOC_REM status;

    /* validate received response */
    if (wNumBytesReceived > 1U)
    {
        if (bStatus != PHAL_VCA_RESP_ACK_ISO4)
        {
            return PH_ADD_COMPCODE_FIXED(PH_ERR_PROTOCOL_ERROR, PH_COMP_AL_VCA);
        }

        /* proper error response */
        return PH_ERR_SUCCESS;
    }
    else if (wNumBytesReceived == 1U)
    {
        switch (bStatus)
        {
        case PHAL_VCA_RESP_ACK_ISO4:

            status = PH_ERR_SUCCESS;
            break;

        case PHAL_VCA_RESP_ERR_CMD_INVALID:

            status = PHAL_VCA_ERR_CMD_INVALID;
            break;

        case PHAL_VCA_RESP_ERR_FORMAT:

            status = PHAL_VCA_ERR_FORMAT;
            break;

        case PHAL_VCA_RESP_ERR_GEN:

            status = PHAL_VCA_ERR_GEN;
            break;

        case PHAL_VCA_RESP_ERR_CMD_OVERFLOW:

            status = PHAL_VCA_ERR_CMD_OVERFLOW;
            break;
        default:

            status = PH_ERR_PROTOCOL_ERROR;
            break;
        }

        return PH_ADD_COMPCODE(status, PH_COMP_AL_VCA);
    }
    /* Invalid error response */
    else
    {
        return PH_ADD_COMPCODE_FIXED(PH_ERR_PROTOCOL_ERROR, PH_COMP_AL_VCA);
    }
}

phStatus_t phalVca_Int_ComputeErrorResponse_Extended(void * pDataParams, uint16_t wStatus)
{
    phStatus_t PH_MEMLOC_REM status = PH_ERR_SUCCESS;
    phStatus_t  PH_MEMLOC_REM statusTmp;
    switch (wStatus)
    {
    case PHAL_VCA_RESP_ACK_ISO4:
    case PHAL_VCA_ISO7816_SUCCESS:
    case PHAL_VCA_ISO7816_PC_SUCCESS:
        status = PH_ERR_SUCCESS;
        break;
    case PHAL_VCA_RESP_ERR_CMD_INVALID:
        status = PHAL_VCA_ERR_CMD_INVALID;
        break;
    case PHAL_VCA_RESP_ERR_FORMAT:
        status = PHAL_VCA_ERR_FORMAT;
        break;
    case PHAL_VCA_RESP_ERR_GEN:
        status = PHAL_VCA_ERR_GEN;
        break;
    case PHAL_VCA_RESP_ERR_CMD_OVERFLOW:
        status = PHAL_VCA_ERR_CMD_OVERFLOW;
        break;
    case PHAL_VCA_RESP_ERR_COMMAND_ABORTED:
        status = PHAL_VCA_ERR_COMMAND_ABORTED;
        break;
    case PHAL_VCA_ISO7816_ERR_WRONG_LENGTH:
    case PHAL_VCA_ISO7816_ERR_WRONG_LE:
    case PHAL_VCA_ISO7816_ERR_FILE_NOT_FOUND:
    case PHAL_VCA_ISO7816_ERR_WRONG_PARAMS:
    case PHAL_VCA_ISO7816_ERR_WRONG_LC:
    case PHAL_VCA_ISO7816_ERR_NO_PRECISE_DIAGNOSTICS:
    case PHAL_VCA_ISO7816_ERR_EOF_REACHED:
    case PHAL_VCA_ISO7816_ERR_FILE_ACCESS:
    case PHAL_VCA_ISO7816_ERR_FILE_EMPTY:
    case PHAL_VCA_ISO7816_ERR_MEMORY_FAILURE:
    case PHAL_VCA_ISO7816_ERR_INCORRECT_PARAMS:
    case PHAL_VCA_ISO7816_ERR_WRONG_CLA:
    case PHAL_VCA_ISO7816_ERR_UNSUPPORTED_INS:
        status = PHAL_VCA_ERR_7816_GEN_ERROR;
        /* Set the error code to VC param structure*/
        PH_CHECK_SUCCESS_FCT(statusTmp, phalVca_SetConfig(
            pDataParams,
            PHAL_VCA_ADDITIONAL_INFO,
            wStatus));
        break;
    default:
        status = PH_ERR_PROTOCOL_ERROR;
        break;
    }
    return PH_ADD_COMPCODE(status, PH_COMP_AL_VCA);
}

phStatus_t phalVca_Int_PrepareProximityCheck(void * pPalMifareDataParams)
{
    phStatus_t  PH_MEMLOC_REM statusTmp;
    uint8_t     PH_MEMLOC_REM bCmd[1];
    uint8_t *   PH_MEMLOC_REM pResponse = NULL;
    uint16_t    PH_MEMLOC_REM wRxLength = 0;

    /* command code */
    bCmd[0] = PHAL_VCA_CMD_PPC;

    /* command exchange */
    PH_CHECK_SUCCESS_FCT(statusTmp, phpalMifare_ExchangeL4(
        pPalMifareDataParams,
        PH_EXCHANGE_DEFAULT,
        bCmd,
        1,
        &pResponse,
        &wRxLength));

    /* check response */
    if (wRxLength == 1U)
    {
        PH_CHECK_SUCCESS_FCT(statusTmp, phalVca_Int_ComputeErrorResponse(wRxLength, pResponse[0]));
    }
    else
    {
        return PH_ADD_COMPCODE_FIXED(PH_ERR_PROTOCOL_ERROR, PH_COMP_AL_MFP);
    }

    return PH_ERR_SUCCESS;
}

phStatus_t phalVca_Int_ProximityCheck(void * pPalMifareDataParams, uint8_t bNumSteps, uint8_t * pRndC, uint8_t * pRndRC)
{
    phStatus_t  PH_MEMLOC_REM statusTmp;
    uint8_t     PH_MEMLOC_REM bCmd[1 /* command code */ + 1 /* length */ + 7 /* max RndC length */];
    uint8_t *   PH_MEMLOC_REM pResponse = NULL;
    uint16_t    PH_MEMLOC_REM wRxLength = 0;
    uint8_t     PH_MEMLOC_REM bPayloadLen;
    uint8_t     PH_MEMLOC_REM bRndCLen = 0;
    uint8_t     PH_MEMLOC_REM bRndRCLen = 0;

    /* parameter checking */
    if ((bNumSteps == 0U) || (bNumSteps > PHAL_VCA_PC_RND_LEN) || (pRndC == NULL) || (pRndRC == NULL))
    {
        return PH_ADD_COMPCODE_FIXED(PH_ERR_INVALID_PARAMETER, PH_COMP_AL_MFP);
    }

    /* command code */
    bCmd[0] = PHAL_VCA_CMD_PC;

    /* Proximity Check loop */
    while (0U != (bNumSteps--))
    {
        /* RndC length */
        if (0U != (bNumSteps))
        {
            bPayloadLen = 1;
        }
        else
        {
            bPayloadLen = PHAL_VCA_PC_RND_LEN - bRndCLen;
        }

        /* Length */
        bCmd[1] = bPayloadLen;

        /* RndC */
        (void)memcpy(&bCmd[2], &pRndC[bRndCLen], bPayloadLen);

        /* command exchange */
        PH_CHECK_SUCCESS_FCT(statusTmp, phpalMifare_ExchangePc(
            pPalMifareDataParams,
            PH_EXCHANGE_DEFAULT,
            bCmd,
            (uint16_t)(2U + ((uint16_t)bPayloadLen)),
            &pResponse,
            &wRxLength));

        /* check response */
        if (wRxLength == (uint16_t)bPayloadLen)
        {
            /* copy RndR */
            (void)memcpy(&pRndRC[bRndRCLen], pResponse, wRxLength);
            bRndRCLen = bRndRCLen + (uint8_t)wRxLength;

            /* copy RndC */
            (void)memcpy(&pRndRC[bRndRCLen], &pRndC[bRndCLen], wRxLength);
            bRndRCLen = bRndRCLen + (uint8_t)wRxLength;
            bRndCLen = bRndCLen + (uint8_t)wRxLength;
        }
    }

    /* We expect to have exactly 7 bytes RndR + 7 bytes RndC */
    if (bRndRCLen != (PHAL_VCA_PC_RND_LEN * 2U))
    {
        return PH_ADD_COMPCODE_FIXED(PH_ERR_PROTOCOL_ERROR, PH_COMP_AL_MFP);
    }

    return PH_ERR_SUCCESS;
}

#ifdef NXPBUILD__PHAL_VCA_SW
phStatus_t phalVca_Int_PrepareProximityCheckNew(phalVca_Sw_DataParams_t * pDataParams, uint8_t *pOption, uint8_t *pPubRespTime, uint8_t * pResponse, uint16_t * pRespLen)
{
    phStatus_t  PH_MEMLOC_REM statusTmp;
    uint8_t *   PH_MEMLOC_REM pResponseTmp;
    uint16_t    PH_MEMLOC_REM wRxLength;
    uint8_t     PH_MEMLOC_REM bCmd[1] = {PHAL_VCA_CMD_PPC};
    uint8_t     PH_MEMLOC_REM bOffset = 0;

    /* Check for ISO Wrapped Mode */
    if(pDataParams->bWrappedMode)
    {
        PH_CHECK_SUCCESS_FCT(statusTmp, phalVca_Int_SendISOWrappedCmd(
            pDataParams,
            bCmd,
            0x00,   /* Lc Value */
            &pResponseTmp,
            &wRxLength));

        if(wRxLength >= 2)
        {
            PH_CHECK_SUCCESS_FCT(statusTmp, phalVca_Int_ComputeErrorResponse_Extended(pDataParams, pResponseTmp[wRxLength - 1]));
        }
        else
        {
            return PH_ADD_COMPCODE_FIXED(PH_ERR_PROTOCOL_ERROR, PH_COMP_AL_VCA);
        }
        /* Adjusting the response length i.e. removing the consideration of response data */
        wRxLength -= 2;
    }
    else
    {
        /* Command exchange */
        PH_CHECK_SUCCESS_FCT(statusTmp, phpalMifare_ExchangeL4(
            pDataParams->pPalMifareDataParams,
            PH_EXCHANGE_DEFAULT,
            bCmd,
            1,
            &pResponseTmp,
            &wRxLength));

        /* Computing the error response on SW1 */
        PH_CHECK_SUCCESS_FCT(statusTmp, phalVca_Int_ComputeErrorResponse_Extended(pDataParams, pResponseTmp[0]));

        /* Incrementing the Index to point the response data */
        pResponseTmp++;

        /* Adjusting the response length i.e. removing the consideration of response data */
        wRxLength--;
    }

    /* Check and save the contents of response data */
    if (wRxLength> 2)
    {
        /* Save Option from response data */
        *pOption = pResponseTmp[bOffset++];

        /* Save Published Response Time from response data */
        pPubRespTime[0] = pResponseTmp[bOffset++];
        pPubRespTime[1] = pResponseTmp[bOffset++];

        /* Save PPS from response data */
        if (*pOption & 0x01)
        {
            *pResponse = pResponseTmp[bOffset];
            *pRespLen = 1;
        }

        /* Save ActBitRate from response data */
        if (*pOption & 0x02)
        {
            memcpy(pResponse, &pResponseTmp[bOffset], (wRxLength - bOffset));
            *pRespLen = (uint8_t) (wRxLength - bOffset);
        }
    }
    else
    {
        return PH_ADD_COMPCODE_FIXED(PH_ERR_PROTOCOL_ERROR, PH_COMP_AL_VCA);
    }

    return PH_ERR_SUCCESS;
}

phStatus_t phalVca_Int_ProximityCheckNew(phalVca_Sw_DataParams_t * pDataParams, uint8_t bNumSteps, uint8_t * pPubRespTime, uint8_t * pRndC, uint8_t * pRndRC)
{
    phStatus_t  PH_MEMLOC_REM statusTmp;
    uint8_t     PH_MEMLOC_REM bCmd[1 /* command code */ + 1 /* length */ + 8 /* max RndC length */];
    uint8_t *   PH_MEMLOC_REM pResponse = NULL;
    uint16_t    PH_MEMLOC_REM wRxLength = 0;
    uint8_t     PH_MEMLOC_REM bPayloadLen;
    uint8_t     PH_MEMLOC_REM bRndCLen = 0;
    uint8_t     PH_MEMLOC_REM bRndRCLen = 0;
    uint16_t    PH_MEMLOC_REM wValue;
    uint16_t    PH_MEMLOC_REM wThresholdTimeUpperLimit;
    uint16_t    PH_MEMLOC_REM wThresholdTimeLowerLimit;
    void        PH_MEMLOC_REM * pHalDataParams = NULL;

    PH_CHECK_SUCCESS_FCT(statusTmp, phalVca_Int_GetHalDataParams(pDataParams->pPalMifareDataParams, &pHalDataParams));

    /* parameter checking */
    if ((bNumSteps == 0U) || (bNumSteps > PHAL_VCA_PC_RND_LEN_NEW) || (pRndC == NULL) || (pRndRC == NULL))
    {
        return PH_ADD_COMPCODE_FIXED(PH_ERR_INVALID_PARAMETER, PH_COMP_AL_VCA);
    }

    /* command code */
    bCmd[0] = PHAL_VCA_CMD_PC;

    /* Proximity Check loop */
    while (0U != (bNumSteps--))
    {
        /* RndC length */
        if (0U != (bNumSteps))
        {
            bPayloadLen = 1;
        }
        else
        {
            bPayloadLen = PHAL_VCA_PC_RND_LEN_NEW - bRndCLen;
        }

        /* Length */
        bCmd[1] = bPayloadLen;

        /* RndC */
        (void)memcpy(&bCmd[2], &pRndC[bRndCLen], bPayloadLen);

        /* Get the bOption value for the checking the timing measurement ON/OFF */
        PH_CHECK_SUCCESS_FCT(statusTmp, phalVca_GetConfig(pDataParams, PHAL_VCA_TIMING_MODE, &wValue));
        if(0U != (wValue & 0x01U))
        {
            /* Start collecting the RC timeout */
            PH_CHECK_SUCCESS_FCT(statusTmp, phhalHw_SetConfig(pHalDataParams, PHHAL_HW_CONFIG_TIMING_MODE, PHHAL_HW_TIMING_MODE_FDT));
        }
        /* Check for ISO Wrapped Mode */
        if(0U != (pDataParams->bWrappedMode))
        {
            PH_CHECK_SUCCESS_FCT(statusTmp, phalVca_Int_SendISOWrappedCmd(
                pDataParams,
                bCmd,
                (uint8_t)(1U + bPayloadLen),    /* bPayloadLen + RndC */
                &pResponse,
                &wRxLength
                ));
            if(wRxLength >= 2U)
            {
                PH_CHECK_SUCCESS_FCT(statusTmp, phalVca_Int_ComputeErrorResponse_Extended(pDataParams, pResponse[wRxLength - 1u]));
            }
            else
            {
                return PH_ADD_COMPCODE_FIXED(PH_ERR_PROTOCOL_ERROR, PH_COMP_AL_VCA);
            }
            /* Decrementing wRxLength by 2 i.e. removing status word from pResponse */
            wRxLength -= 2u;
        }
        else
        {
            /* command exchange */
            PH_CHECK_SUCCESS_FCT(statusTmp, phpalMifare_ExchangeL4(
                pDataParams->pPalMifareDataParams,
                PH_EXCHANGE_DEFAULT,
                bCmd,
                (uint16_t)(2U + ((uint16_t)bPayloadLen)),   /* (INS + bPayloadLen) + RndC */
                &pResponse,
                &wRxLength));

            /*
             * Response validation should not be performed in case if the length is
             *      1 byte  : One byte can be either a valid response or a error code which is difficult to identify
             *      0 byte  : If there is response, the passed value will be any number from the pointer which will
             *                result in false errors.
             */
            if ((wRxLength != bPayloadLen) && (bPayloadLen != 0) && (bPayloadLen != 1))
            {
                PH_CHECK_SUCCESS_FCT(statusTmp, phalVca_Int_ComputeErrorResponse_Extended(pDataParams, pResponse[wRxLength - 1]));
            }
        }

        /* check response */
        if (wRxLength == (uint16_t)bPayloadLen)
        {
            /* copy RndR */
            (void)memcpy(&pRndRC[bRndRCLen], pResponse, wRxLength);
            bRndRCLen = bRndRCLen + (uint8_t)wRxLength;

            /* copy RndC */
            (void)memcpy(&pRndRC[bRndRCLen], &pRndC[bRndCLen], wRxLength);
            bRndRCLen = bRndRCLen + (uint8_t)wRxLength;
            bRndCLen = bRndCLen + (uint8_t)wRxLength;
        }

        /* Get the bOption value for the checking the timing measurement ON/OFF */
        PH_CHECK_SUCCESS_FCT(statusTmp, phalVca_GetConfig(pDataParams, PHAL_VCA_TIMING_MODE, &wValue));
        if(0U != (wValue & 0x01U))
        {
            /* Compute threshold time from PubRespTime. Threshold time = pubRespTime + 10% of pubRespTime */
            wThresholdTimeUpperLimit = pPubRespTime[0];
            wThresholdTimeUpperLimit <<= 8U;
            wThresholdTimeUpperLimit |= pPubRespTime[1];

            /* As per the ref arch V0.17, the threshold time should not be 20% beyond the Lower bound of PubResp Time. */
            wThresholdTimeLowerLimit = (wThresholdTimeUpperLimit * 80)/100;

            /* Get the last command execution time */
            PH_CHECK_SUCCESS_FCT(statusTmp, phhalHw_GetConfig(pHalDataParams, PHHAL_HW_CONFIG_TIMING_US, &wValue));

            /* If the response is not received within the threshold time, return internal error */
            if(wValue > wThresholdTimeUpperLimit || wValue < wThresholdTimeLowerLimit)
            {
                return PH_ADD_COMPCODE_FIXED(PH_ERR_INTERNAL_ERROR, PH_COMP_AL_VCA);
            }
        }
    }
    /* We expect to have exactly 8 bytes RndR + 8 bytes RndC */
    if (bRndRCLen != (PHAL_VCA_PC_RND_LEN_NEW * 2U))
    {
        return PH_ADD_COMPCODE_FIXED(PH_ERR_PROTOCOL_ERROR, PH_COMP_AL_VCA);
    }
    return PH_ERR_SUCCESS;
}

phStatus_t phalVca_Int_SendISOWrappedCmd(phalVca_Sw_DataParams_t * pDataParams, uint8_t * pSendBuff, uint8_t  bLc, uint8_t ** pResponse, uint16_t * pRxlen)
{
    phStatus_t PH_MEMLOC_REM statusTmp = 0;
    phStatus_t PH_MEMLOC_REM status = 0;
    uint8_t    PH_MEMLOC_REM bApduLen = 4;  /* Initializing with 4 since Length of the Data(Lc) starts from 4th element of pApdu[] */
    uint8_t    PH_MEMLOC_REM pApdu[8] = { 0x90 /* CLS */, 0x00, 0x00, 0x00, 0x00 /* Lc */, 0x00, 0x00 /*  Lc for Extended Length */, 0x00 /* Le */ };

    /* Check for permissible CmdBuff size */
    if (bLc > PHAL_VCA_MAXWRAPPEDAPDU_SIZE)
    {
        return PH_ADD_COMPCODE_FIXED(PH_ERR_BUFFER_OVERFLOW, PH_COMP_AL_VCA);
    }

    pApdu[1] = pSendBuff[0];  /* Proximity Check Command Code. */

    switch(pApdu[1])
    {
    case PHAL_VCA_CMD_PPC:
        pApdu[4] = 0x00;    /* These bytes will be treated as Le */
        pApdu[5] = 0x00;    /* For extended length Apdu support */
        /* Transmit CLS INS P1 P2 Lc(not Lc for PPC) as buffer first */
        PH_CHECK_SUCCESS_FCT(statusTmp, phpalMifare_ExchangeL4(
            pDataParams->pPalMifareDataParams,
            PH_EXCHANGE_DEFAULT,
            pApdu,
            (uint16_t)((pDataParams->bExtendedLenApdu != 0U) ? 7U : 5U),    /* 2 bytes Le should be passed in case of Extended Length Apdu since Lc field is not present */
            pResponse,
            pRxlen
            ));
        break;
    case PHAL_VCA_CMD_PC:
    case PHAL_VCA_CMD_VPC:
        /* To Note: Extended APDU will be used,
         *  When user forces the 'length' to be sent as Extended length APDU. */
        if(!pDataParams->bExtendedLenApdu)
        {
            /* Encode 'Length' in Short APDU format */
            pApdu[bApduLen++]= (uint8_t)bLc; /* Set Data Length. */
        }
        else
        {
            /* Encode 'Length' in extended Length format */
            pApdu[bApduLen++] = 0x00;
            pApdu[bApduLen++] = 0x00;
            pApdu[bApduLen++] = (uint8_t)bLc; /* Set Data Length. */
        }
        /* Transmit CLS INS P1 P2 Lc as buffer first */
        PH_CHECK_SUCCESS_FCT(statusTmp, phpalMifare_ExchangeL4(
            pDataParams->pPalMifareDataParams,
            PH_EXCHANGE_BUFFER_FIRST,
            pApdu,
            bApduLen,
            pResponse,
            pRxlen
            ));
        /* Check for Lc value */
        if (bLc > 0U)
        {
            /* Transmit data as continued buffer */
            PH_CHECK_SUCCESS_FCT(statusTmp, phpalMifare_ExchangeL4(
                pDataParams->pPalMifareDataParams,
                PH_EXCHANGE_BUFFER_CONT,
                &pSendBuff[1],
                bLc,
                pResponse,
                pRxlen
                ));
        }
        /* Resetting bApduLen for further use in case of Le */
        bApduLen = 0;
        if(!pDataParams->bExtendedLenApdu)
        {
            /* Encode 'Length' in Short APDU format */
            pApdu[bApduLen++]= 0x00; /* Set the expected data length as full. */
        }
        else
        {
            /* Encode 'Length' in extended Length format */
            pApdu[bApduLen++] = 0x00;
            pApdu[bApduLen++] = 0x00; /* Set the expected data length as full. */
        }
        /* Transmit Le as buffer Last */
        PH_CHECK_SUCCESS_FCT(status,phpalMifare_ExchangeL4(
            pDataParams->pPalMifareDataParams,
            PH_EXCHANGE_BUFFER_LAST,
            pApdu,
            bApduLen,
            pResponse,
            pRxlen
            ));
        break;
    default:
        return PH_ADD_COMPCODE_FIXED(PH_ERR_UNSUPPORTED_COMMAND, PH_COMP_AL_VCA);
    }

    return PH_ERR_SUCCESS;
}
#endif /* NXPBUILD__PHAL_VCA_SW */

phStatus_t phalVca_Int_GetHalDataParams(void * pPalMifareDataParams, void** pHalDataParams)
{
    switch ((*((uint16_t*)(pPalMifareDataParams)) & 0xFF))
    {
#ifdef NXPBUILD__PHPAL_MIFARE_SW
    case PHPAL_MIFARE_SW_ID:
        *pHalDataParams = ((phpalMifare_Sw_DataParams_t *)pPalMifareDataParams)->pHalDataParams;
        break;
#endif /* NXPBUILD__PHPAL_MIFARE_SW */

    default:
        *pHalDataParams = NULL;
        break;
    }

    return PH_ADD_COMPCODE(PH_ERR_SUCCESS, PH_COMP_AL_VCA);
}

#endif /* NXPBUILD__PHAL_VCA */
