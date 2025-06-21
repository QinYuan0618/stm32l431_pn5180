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

#ifndef PHALMFDUOX_SW_INT_H
#define PHALMFDUOX_SW_INT_H

#include <ph_Status.h>

#ifdef NXPBUILD__PHAL_MFDUOX_SW
#include <phalMfDuoX.h>

#define PHAL_MFDUOX_CMD_BUF                 pDataParams->pCmdBuf
#define PHAL_MFDUOX_CMD_BUF_SIZE            pDataParams->wCmdBufSize
#define PHAL_MFDUOX_CMD_BUF_LEN             pDataParams->wCmdBufLen
#define PHAL_MFDUOX_CMD_BUF_OFFSET          pDataParams->wCmdBufOffset

#define PHAL_MFDUOX_PRS_BUF                 pDataParams->pPrsBuf
#define PHAL_MFDUOX_PRS_BUF_SIZE            pDataParams->wPrsBufSize
#define PHAL_MFDUOX_PRS_BUF_LEN             pDataParams->wPrsBufLen
#define PHAL_MFDUOX_PRS_BUF_OFFSET          pDataParams->wPrsBufOffset

#define PHAL_MFDUOX_IS_PICC_DATA_COMPLETE   pDataParams->bPICCDataComplete

phStatus_t phalMfDuoX_Sw_Int_ValidateResponse(phalMfDuoX_Sw_DataParams_t * pDataParams, uint8_t bOption, uint16_t wStatus,
    uint16_t wPiccRetCode);

phStatus_t phalMfDuoX_Sw_Int_CardExchange(phalMfDuoX_Sw_DataParams_t * pDataParams, uint16_t wBufferOption, uint8_t bChainingState,
    uint8_t bCmdOption, uint16_t wTotDataLen, uint8_t bExchangeLE, uint8_t * pData, uint16_t wDataLen, uint8_t ** ppResponse,
    uint16_t * pRespLen, uint8_t * pPiccErrCode);

phStatus_t phalMfDuoX_Sw_Int_Send7816Apdu(phalMfDuoX_Sw_DataParams_t * pDataParams, uint8_t bOption, uint16_t wBufOption,
    uint8_t bExtendedLenApdu, uint8_t bClass, uint8_t bIns, uint8_t bP1, uint8_t bP2, uint8_t * pData,
    uint16_t wDataLen, uint32_t dwExpBytes, uint8_t ** ppResponse, uint16_t * pRspLen);

phStatus_t phalMfDuoX_Sw_Int_ApplySM(phalMfDuoX_Sw_DataParams_t * pDataParams, uint8_t bIsFirstFrame, uint8_t bIsLastFrame,
    uint8_t bCommMode, uint8_t * pCmdHeader, uint16_t wCmdHeaderLen, uint8_t * pCmdData, uint16_t wCmdDataLen,
    uint8_t ** ppSMBuf, uint16_t * pSMBufLen);

phStatus_t phalMfDuoX_Sw_Int_RemoveSM(phalMfDuoX_Sw_DataParams_t * pDataParams, uint8_t bIsISOChained, uint8_t bIsFirstFrame,
    uint8_t bIsLastFrame, uint8_t bCommMode, uint8_t * pResponse, uint16_t wRespLen, uint8_t bPiccStat, uint8_t ** ppOutBuffer,
    uint16_t * pOutBufLen);

phStatus_t phalMfDuoX_Sw_Int_ReadData(phalMfDuoX_Sw_DataParams_t * pDataParams, uint16_t wOption, uint8_t bIsISOChained,
    uint8_t bCmd_ComMode, uint8_t bResp_ComMode, uint8_t * pCmdHeader, uint16_t wCmdHeaderLen, uint32_t dwDataToRead,
    uint8_t ** ppResponse, uint16_t * pRespLen);

phStatus_t phalMfDuoX_Sw_Int_WriteData(phalMfDuoX_Sw_DataParams_t * pDataParams, uint8_t bIsNativeChained, uint8_t bCmd_ComMode,
    uint8_t bResp_ComMode, uint8_t bResetAuth, uint8_t * pCmdHeader, uint16_t wCmdHeaderLen, uint8_t * pCmdData,
    uint32_t dwCmdDataLen, uint8_t ** ppResponse, uint16_t * pRespLen);

phStatus_t phalMfDuoX_Sw_Int_ISOSelectFile(phalMfDuoX_Sw_DataParams_t * pDataParams, uint8_t * pData, uint16_t wDataLen,
    uint8_t * pLe, uint8_t bLeLen, uint8_t ** ppResponse, uint16_t * pRspLen);

phStatus_t phalMfDuoX_Sw_Int_ISOReadBinary(phalMfDuoX_Sw_DataParams_t * pDataParams, uint16_t wOption, uint8_t * pLe,
    uint8_t bLeLen, uint8_t ** ppResponse, uint16_t * pRspLen);

phStatus_t phalMfDuoX_Sw_Int_ISOUpdateBinary(phalMfDuoX_Sw_DataParams_t * pDataParams, uint8_t * pData, uint16_t wDataLen);

phStatus_t phalMfDuoX_Sw_Int_ISOReadRecord(phalMfDuoX_Sw_DataParams_t * pDataParams, uint16_t wOption, uint8_t * pLe,
    uint8_t bLeLen, uint8_t ** ppResponse, uint16_t * pRspLen);

phStatus_t phalMfDuoX_Sw_Int_ISOAppendRecord(phalMfDuoX_Sw_DataParams_t * pDataParams, uint8_t * pData, uint16_t wDataLen);

phStatus_t phalMfDuoX_Sw_Int_ISOGetChallenge(phalMfDuoX_Sw_DataParams_t * pDataParams, uint8_t * pLe, uint8_t bLeLen,
    uint8_t ** ppResponse, uint16_t * pRspLen);

phStatus_t phalMfDuoX_Sw_Int_VdeReadData(phalMfDuoX_Sw_DataParams_t * pDataParams, uint16_t wOption, uint8_t * pLe,
    uint8_t bLeLen, uint8_t ** ppResponse, uint16_t * pRspLen);

phStatus_t phalMfDuoX_Sw_Int_VdeWriteData(phalMfDuoX_Sw_DataParams_t * pDataParams, uint8_t * pData, uint16_t wDataLen,
    uint8_t * pLe, uint8_t bLeLen);

phStatus_t phalMfDuoX_Sw_Int_VdeECDSASign(phalMfDuoX_Sw_DataParams_t * pDataParams, uint8_t * pData, uint16_t wDataLen,
    uint8_t * pLe, uint8_t bLeLen, uint8_t ** ppResponse, uint16_t * pRspLen);

phStatus_t phalMfDuoX_Sw_Int_ResetAuthStatus(phalMfDuoX_Sw_DataParams_t * pDataParams);

phStatus_t phalMfDuoX_Sw_Int_GetFrameLen(phalMfDuoX_Sw_DataParams_t * pDataParams, uint8_t bIsNativeChained, uint16_t * pFrameLen);

#endif /* NXPBUILD__PHAL_MFDUOX_SW */

#endif /* PHALMFDUOX_SW_INT_H */
