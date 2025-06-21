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
* Internal functions of Generic MIFARE DUOX Application Component of Reader Library Framework.
* $Author: NXP $
* $Revision: $ (v07.13.00)
* $Date: $
*
*/

#include <ph_Status.h>

#ifdef NXPBUILD__PHAL_MFDUOX
#include <phalMfDuoX.h>
#include "phalMfDuoX_Int.h"

phStatus_t phalMfDuoX_Int_ComputeErrorResponse(void * pDataParams, uint16_t wStatusIn)
{
    phStatus_t  PH_MEMLOC_REM wStatus = PH_ERR_SUCCESS;
    phStatus_t  PH_MEMLOC_REM wStatusTmp = PH_ERR_SUCCESS;
    uint8_t     PH_MEMLOC_REM bCmdCode = 0;

    PH_CHECK_SUCCESS_FCT(wStatus, phalMfDuoX_Int_GetCmdCode(pDataParams, &bCmdCode));

    switch(wStatusIn)
    {
        case PHAL_MFDUOX_RESP_OPERATION_OK:
        case PHAL_MFDUOX_ISO7816_SUCCESS:
        case PHAL_MFDUOX_RESP_OK:
            wStatus = PH_ERR_SUCCESS;
            break;

        case PHAL_MFDUOX_RESP_ADDITIONAL_FRAME:
            wStatus = PH_ERR_SUCCESS_CHAINING;
            break;

        case PHAL_MFDUOX_RESP_ERR_CMD_INVALID:
            wStatus = PHAL_MFDUOX_ERR_CMD_INVALID;
            break;

        case PHAL_MFDUOX_RESP_NO_CHANGES:
                wStatus = PHAL_MFDUOX_ERR_NO_CHANGES;
            break;

        case PHAL_MFDUOX_RESP_ERR_NOT_SUP:
            wStatus = PHAL_MFDUOX_ERR_NOT_SUPPORTED;
            break;

        case PHAL_MFDUOX_RESP_OUT_OF_EEPROM_ERROR:
            wStatus = PHAL_MFDUOX_ERR_OUT_OF_EEPROM;
            break;

        case PHAL_MFDUOX_RESP_INTEGRITY_ERROR:
            wStatus = PHAL_MFDUOX_ERR_PICC_CRYPTO;
            break;

        case PHAL_MFDUOX_RESP_PARAMETER_ERROR:
            wStatus = PHAL_MFDUOX_ERR_PARAMETER_ERROR;
            break;

        case PHAL_MFDUOX_RESP_NO_SUCH_KEY:
            wStatus = PHAL_MFDUOX_ERR_NO_SUCH_KEY;
            break;

        case PHAL_MFDUOX_RESP_LENGTH_ERROR:
            wStatus = PH_ERR_LENGTH_ERROR;
            break;

        case PHAL_MFDUOX_RESP_PERMISSION_DENIED:
            wStatus = PHAL_MFDUOX_ERR_PERMISSION_DENIED;
            break;

        case PHAL_MFDUOX_RESP_APPLICATION_NOT_FOUND:
            wStatus = PHAL_MFDUOX_ERR_APPLICATION_NOT_FOUND;
            break;

        case PHAL_MFDUOX_RESP_AUTHENTICATION_ERROR:
        case PHAL_MFDUOX_RESP_ERR_AUTH:
            wStatus = PH_ERR_AUTH_ERROR;
            break;

        case PHAL_MFDUOX_RESP_BOUNDARY_ERROR:
            wStatus = PHAL_MFDUOX_ERR_BOUNDARY_ERROR;
            break;

        case PHAL_MFDUOX_RESP_COMMAND_ABORTED:
            wStatus = PHAL_MFDUOX_ERR_COMMAND_ABORTED;
            break;

        case PHAL_MFDUOX_RESP_DUPLICATE:
            wStatus = PHAL_MFDUOX_ERR_DUPLICATE;
            break;

        case PHAL_MFDUOX_RESP_FILE_NOT_FOUND:
            wStatus = PHAL_MFDUOX_ERR_FILE_NOT_FOUND;
            break;

        case PHAL_MFDUOX_RESP_MEMORY_ERROR:
        case PHAL_MFDUOX_RESP_ILLEGAL_COMMAND_CODE:
            wStatus = PHAL_MFDUOX_ERR_DF_GEN_ERROR;
            PH_CHECK_SUCCESS_FCT(wStatusTmp, phalMfDuoX_SetConfig(pDataParams, PHAL_MFDUOX_ADDITIONAL_INFO, wStatusIn));
            break;

        case PHAL_MFDUOX_ISO7816_ERR_PROTOCOL_VERSION:
        case PHAL_MFDUOX_ISO7816_ERR_MEMORY_FAILURE:
        case PHAL_MFDUOX_ISO7816_ERR_WRONG_LENGTH:
        case PHAL_MFDUOX_ISO7816_ERR_INCORRECT_CMD_PARAMS:
        case PHAL_MFDUOX_ISO7816_ERR_WRONG_LE:
        case PHAL_MFDUOX_ISO7816_ERR_FILE_NOT_FOUND:
        case PHAL_MFDUOX_ISO7816_ERR_WRONG_PARAMS:
        case PHAL_MFDUOX_ISO7816_ERR_WRONG_PARAMS_P2:
        case PHAL_MFDUOX_ISO7816_ERR_WRONG_LC:
        case PHAL_MFDUOX_ISO7816_ERR_NO_PRECISE_DIAGNOSTICS:
        case PHAL_MFDUOX_ISO7816_ERR_EOF_REACHED:
        case PHAL_MFDUOX_ISO7816_ERR_FILE_ACCESS:
        case PHAL_MFDUOX_ISO7816_ERR_FILE_EMPTY:
        case PHAL_MFDUOX_ISO7816_ERR_INCORRECT_PARAMS:
        case PHAL_MFDUOX_ISO7816_ERR_WRONG_CLA:
        case PHAL_MFDUOX_ISO7816_ERR_UNSUPPORTED_INS:
        case PHAL_MFDUOX_ISO7816_ERR_LIMITED_FUNCTIONALITY_INS:
        case PHAL_MFDUOX_ISO7816_ERR_REF_DATA_NOT_USABLE:
            wStatus = PHAL_MFDUOX_ERR_DF_7816_GEN_ERROR;
            PH_CHECK_SUCCESS_FCT(wStatusTmp, phalMfDuoX_SetConfig(pDataParams, PHAL_MFDUOX_ADDITIONAL_INFO, wStatusIn));
            break;

        case PHAL_MFDUOX_RESP_OPERATION_OK_LIM:
            wStatus = PHAL_MFDUOX_ERR_OPERATION_OK_LIM;
            break;

        case PHAL_MFDUOX_RESP_ERR_CMD_OVERFLOW:
            wStatus = PHAL_MFDUOX_ERR_CMD_OVERFLOW;
            break;

        case PHAL_MFDUOX_RESP_ERR_GEN_FAILURE:
            wStatus = PHAL_MFDUOX_ERR_GEN_FAILURE;
            break;

        case PHAL_MFDUOX_RESP_ERR_BNR:
            wStatus = PHAL_MFDUOX_ERR_BNR;
            break;

        case PHAL_MFDUOX_RESP_CERT_ERROR:
            wStatus = PHAL_MFDUOX_ERR_CERTIFICATE;
            break;

        case PHAL_MFDUOX_RESP_WEAK_FIELD:
            wStatus = PHAL_MFDUOX_ERR_WEAK_FIELD;
            break;

        default:
            wStatus = PH_ERR_PROTOCOL_ERROR;
    }
    return PH_ADD_COMPCODE(wStatus, PH_COMP_AL_MFDUOX);
}

phStatus_t phalMfDuoX_Int_Validate_ComOption(uint8_t bComOption)
{
    switch(bComOption)
    {
        case PHAL_MFDUOX_COMMUNICATION_PLAIN:
            break;

        default:
            return PH_ADD_COMPCODE(PH_ERR_INVALID_PARAMETER, PH_COMP_AL_MFDUOX);
    }

    return PH_ADD_COMPCODE(PH_ERR_SUCCESS, PH_COMP_AL_MFDUOX);
}

phStatus_t phalMfDuoX_Int_GetCmdCode(void * pDataParams, uint8_t * pCmdCode)
{
    phStatus_t  PH_MEMLOC_REM wStatus = PH_ADD_COMPCODE(PH_ERR_SUCCESS, PH_COMP_AL_MFDUOX);

    switch(PH_GET_COMPID(pDataParams))
    {
#ifdef NXPBUILD__PHAL_MFDUOX_SW
        case PHAL_MFDUOX_SW_ID:
            *pCmdCode = ((phalMfDuoX_Sw_DataParams_t *) pDataParams)->bCmdCode;
            break;
#endif /* NXPBUILD__PHAL_MFDUOX_SW*/

        default:
            wStatus = PH_ADD_COMPCODE(PH_ERR_INVALID_DATA_PARAMS, PH_COMP_AL_MFDUOX);
            break;
    }

    return wStatus;
}

phStatus_t phalMfDuoX_Int_SetCmdCode(void * pDataParams, uint8_t bCmdCode)
{
    phStatus_t  PH_MEMLOC_REM wStatus = PH_ADD_COMPCODE(PH_ERR_SUCCESS, PH_COMP_AL_MFDUOX);

    switch(PH_GET_COMPID(pDataParams))
    {
#ifdef NXPBUILD__PHAL_MFDUOX_SW
        case PHAL_MFDUOX_SW_ID:
            ((phalMfDuoX_Sw_DataParams_t *) pDataParams)->bCmdCode = bCmdCode;
            break;
#endif /* NXPBUILD__PHAL_MFDUOX_SW*/

        default:
            wStatus = PH_ADD_COMPCODE(PH_ERR_INVALID_DATA_PARAMS, PH_COMP_AL_MFDUOX);
            break;
    }

    return wStatus;
}

void phalMfDuoX_Int_GetCommMode(uint8_t bAuthState, uint8_t bOption, uint8_t * pCommMode)
{
    if(bOption != PHAL_MFDUOX_COMMUNICATION_INVALID)
    {
        switch(bOption)
        {

            default:
                *pCommMode = PHAL_MFDUOX_COMMUNICATION_PLAIN;
                break;
        }
    }
    else
    {
        switch(bAuthState)
        {

            case PHAL_MFDUOX_NOT_AUTHENTICATED:
                *pCommMode = PHAL_MFDUOX_COMMUNICATION_PLAIN;
                break;

            default:
                *pCommMode = PHAL_MFDUOX_COMMUNICATION_PLAIN;
                break;
        }
    }
}

void phalMfDuoX_Int_RotateLeft(uint8_t * pData, uint8_t bDataLen, uint8_t bTimes)
{
    uint8_t bIndex_Times = 0, bIndex_Len = 0;
    uint8_t bTmp = 0;

    for(bIndex_Times = 0; bIndex_Times < bTimes; bIndex_Times++)
    {
        bTmp = pData[0];
        for(bIndex_Len = 0; bIndex_Len < bDataLen - 1; bIndex_Len++)
            pData[bIndex_Len] = pData[bIndex_Len + 1];

        pData[bDataLen - 1] = bTmp;
    }
}

void phalMfDuoX_Int_RotateRight(uint8_t * pData, uint8_t bDataLen, uint8_t bTimes)
{
    uint8_t bIndex_Times = 0, bIndex_Len = 0;
    uint8_t bTmp = 0;

    for(bIndex_Times = 0; bIndex_Times < bTimes; bIndex_Times++)
    {
        bTmp = pData[bDataLen - 1];
        for(bIndex_Len = (bDataLen - 1); bIndex_Len > 0; bIndex_Len--)
            pData[bIndex_Len] = pData[bIndex_Len - 1];

        pData[0] = bTmp;
    }
}

void phalMfDuoX_Int_EncodeBER_TLV_Len(uint16_t wLen, uint8_t * pBuffer, uint16_t * pBuffLen)
{
    if(wLen <= 127U)
    {
        /* Do Nothing. Tag is not required. */
    }
    else if( wLen > 255U)
    {
        pBuffer[(*pBuffLen)++] = PHAL_MFDUOX_ISO7816_BER_TLV_C_82;
        pBuffer[(*pBuffLen)++] = (uint8_t) (wLen >> 8U);
    }
    else
    {
        pBuffer[(*pBuffLen)++] = PHAL_MFDUOX_ISO7816_BER_TLV_C_81;
    }

    pBuffer[(*pBuffLen)++] = (uint8_t) wLen;
}

phStatus_t phalMfDuoX_Int_DecodeBER_TLV_Len(uint8_t ** ppBuffer, uint16_t * pBER_TLV_Len, uint16_t * pRspLen)
{
    if(ppBuffer != NULL)
    {
        switch((*ppBuffer)[0])
        {
            case PHAL_MFDUOX_ISO7816_BER_TLV_C_81:
                *pBER_TLV_Len = (uint16_t) (*ppBuffer)[1];

                (*ppBuffer) += 2;
                (*pRspLen) -= 2;
                break;

            case PHAL_MFDUOX_ISO7816_BER_TLV_C_82:
                *pBER_TLV_Len = (uint16_t) (((*ppBuffer)[1] << 8) | (*ppBuffer)[2]);

                (*ppBuffer) += 3;
                (*pRspLen) -= 3;
                break;

            default:
                *pBER_TLV_Len = (uint16_t) (*ppBuffer)[0];

                (*ppBuffer) += 1;
                (*pRspLen) -= 1;
                break;
        }
    }

    return PH_ERR_SUCCESS;
}

void phalMfDuoX_Int_UpdateLC(uint8_t * pData, uint16_t wDataLen, uint8_t bLE_Available, uint8_t bLE_Len)
{
    uint16_t    PH_MEMLOC_REM wISO7816_Hdr_Len = 0;
    uint16_t    PH_MEMLOC_REM wLC = 0;
    uint8_t     PH_MEMLOC_REM bLC_Len = 0;

    /* Compute ISO7816 Header Length. */
    wISO7816_Hdr_Len = (uint16_t) ((bLE_Len == 1) ? PHAL_MFDUOX_WRAPPED_HDR_LEN_NORMAL : PHAL_MFDUOX_WRAPPED_HDR_LEN_EXTENDED);

    /* Compute Actual LC. */
    wLC = (uint16_t) (wDataLen - (wISO7816_Hdr_Len + (bLE_Available ? bLE_Len : 0)));

    /* Update LC. */
    if(bLE_Len > 1)
    {
        pData[PHAL_MFDUOX_LC_POS + bLC_Len++] = 0x00;
        pData[PHAL_MFDUOX_LC_POS + bLC_Len++] = (uint8_t) ((wLC & 0xFF00) >> 8);
    }
    pData[PHAL_MFDUOX_LC_POS + bLC_Len++] = (uint8_t) (wLC & 0x00FF);
}

#endif /* NXPBUILD__PHAL_MFDUOX */
