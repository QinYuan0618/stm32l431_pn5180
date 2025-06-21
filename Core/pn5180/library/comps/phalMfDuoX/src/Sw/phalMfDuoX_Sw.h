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
* Software implementation of MIFARE DUOX application layer.
* $Author: NXP $
* $Revision: $ (v07.13.00)
* $Date: $
*
*/

#ifndef PHALMFDUOX_SW_H
#define PHALMFDUOX_SW_H

#include <ph_Status.h>

#ifdef NXPBUILD__PHAL_MFDUOX_SW

phStatus_t phalMfDuoX_Sw_ISOInternalAuthenticate(phalMfDuoX_Sw_DataParams_t * pDataParams, uint8_t bPrivKeyNo, uint8_t bCurveID,
    uint8_t * pPubBKey, uint16_t wPubBKeyLen, uint8_t * pOptsA, uint8_t bOptsALen, uint8_t * pExpRspLen, uint8_t bExpRspLen);

/* MIFARE DUOX Memory and Configuration management commands ----------------------------------------------------------------------------- */
phStatus_t phalMfDuoX_Sw_FreeMem(phalMfDuoX_Sw_DataParams_t * pDataParams, uint8_t ** ppMemInfo, uint16_t * pMemInfoLen);

phStatus_t phalMfDuoX_Sw_GetVersion(phalMfDuoX_Sw_DataParams_t * pDataParams, uint8_t bOption, uint8_t ** ppVerInfo,
    uint16_t * pVerInfoLen);

/* MIFARE DUOX Symmetric Key management commands ---------------------------------------------------------------------------------------- */

phStatus_t phalMfDuoX_Sw_GetKeySettings(phalMfDuoX_Sw_DataParams_t * pDataParams, uint8_t bOption, uint8_t ** ppResponse,
    uint16_t * pRspLen);

/* MIFARE DUOX ASymmetric Key management commands --------------------------------------------------------------------------------------- */
phStatus_t phalMfDuoX_Sw_ManageKeyPair(phalMfDuoX_Sw_DataParams_t * pDataParams, uint8_t bComOption, uint8_t bKeyNo,
    uint8_t bOption, uint8_t bCurveID, uint8_t * pKeyPolicy, uint8_t bWriteAccess, uint32_t dwKUCLimit,
    uint16_t wPrivKey_No, uint16_t wPrivKey_Pos, uint8_t ** ppResponse, uint16_t *pRspLen);

phStatus_t phalMfDuoX_Sw_ManageCARootKey(phalMfDuoX_Sw_DataParams_t * pDataParams, uint8_t bComOption, uint8_t bKeyNo,
    uint8_t bCurveID, uint8_t * pAccessRights, uint8_t bWriteAccess, uint8_t bReadAccess, uint8_t bCRLFile,
    uint8_t * pCRLFileAID, uint16_t wPubKey_No, uint16_t wPubKey_Pos, uint8_t * pIssuer, uint8_t bIssuerLen);

phStatus_t phalMfDuoX_Sw_ExportKey(phalMfDuoX_Sw_DataParams_t * pDataParams, uint8_t bComOption, uint8_t bOption,
    uint8_t bKeyNo, uint8_t ** ppResponse, uint16_t *pRspLen);

/* MIFARE DUOX Application management commands ------------------------------------------------------------------------------------------ */
phStatus_t phalMfDuoX_Sw_CreateApplication(phalMfDuoX_Sw_DataParams_t * pDataParams, uint8_t bOption, uint8_t * pAid,
    uint8_t bKeySettings1, uint8_t bKeySettings2, uint8_t bKeySettings3, uint8_t * pKeySetValues, uint8_t bKeySetValuesLen,
    uint8_t * pISOFileId, uint8_t * pISODFName, uint8_t bISODFNameLen);

phStatus_t phalMfDuoX_Sw_DeleteApplication(phalMfDuoX_Sw_DataParams_t * pDataParams, uint8_t * pAid, uint8_t * pDAMMAC,
    uint8_t bDAMMAC_Len);

phStatus_t phalMfDuoX_Sw_SelectApplication(phalMfDuoX_Sw_DataParams_t * pDataParams, uint8_t bOption, uint8_t * pAppId,
    uint8_t * pAppId2);

phStatus_t phalMfDuoX_Sw_GetApplicationIDs(phalMfDuoX_Sw_DataParams_t * pDataParams, uint8_t bOption, uint8_t ** ppAidBuff,
    uint16_t * pAidLen);

phStatus_t phalMfDuoX_Sw_GetDFNames(phalMfDuoX_Sw_DataParams_t * pDataParams, uint8_t bOption, uint8_t ** ppDFBuffer,
    uint16_t * pDFInfoLen);

/* MIFARE DUOX File management commands ------------------------------------------------------------------------------------------------- */
phStatus_t phalMfDuoX_Sw_CreateStdDataFile(phalMfDuoX_Sw_DataParams_t * pDataParams, uint8_t bOption, uint8_t bFileNo,
    uint8_t * pISOFileId, uint8_t bFileOption, uint8_t * pAccessRights, uint8_t * pFileSize);

phStatus_t phalMfDuoX_Sw_CreateBackupDataFile(phalMfDuoX_Sw_DataParams_t * pDataParams, uint8_t bOption, uint8_t bFileNo,
    uint8_t * pISOFileId, uint8_t bFileOption, uint8_t * pAccessRights, uint8_t * pFileSize);

phStatus_t phalMfDuoX_Sw_CreateValueFile(phalMfDuoX_Sw_DataParams_t * pDataParams, uint8_t bFileNo, uint8_t bFileOption,
    uint8_t * pAccessRights, uint8_t * pLowerLmit, uint8_t * pUpperLmit, uint8_t * pValue, uint8_t bLimitedCredit);

phStatus_t phalMfDuoX_Sw_CreateLinearRecordFile(phalMfDuoX_Sw_DataParams_t * pDataParams, uint8_t bOption, uint8_t bFileNo,
    uint8_t * pISOFileId, uint8_t bFileOption, uint8_t * pAccessRights, uint8_t * pRecordSize, uint8_t * pMaxNoOfRec);

phStatus_t phalMfDuoX_Sw_CreateCyclicRecordFile(phalMfDuoX_Sw_DataParams_t * pDataParams, uint8_t bOption, uint8_t bFileNo,
    uint8_t * pISOFileId, uint8_t bFileOption, uint8_t * pAccessRights, uint8_t * pRecordSize, uint8_t * pMaxNoOfRec);

phStatus_t phalMfDuoX_Sw_DeleteFile(phalMfDuoX_Sw_DataParams_t * pDataParams, uint8_t bFileNo);

phStatus_t phalMfDuoX_Sw_GetFileIDs(phalMfDuoX_Sw_DataParams_t * pDataParams, uint8_t ** ppFileId, uint16_t * pFileIdLen);

phStatus_t phalMfDuoX_Sw_GetISOFileIDs(phalMfDuoX_Sw_DataParams_t * pDataParams, uint8_t ** ppISOFileId, uint16_t * pISOFileIdLen);

phStatus_t phalMfDuoX_Sw_GetFileSettings(phalMfDuoX_Sw_DataParams_t * pDataParams, uint8_t bFileNo, uint8_t ** ppFSBuffer,
    uint16_t * pFSBufLen);

phStatus_t phalMfDuoX_Sw_GetFileCounters(phalMfDuoX_Sw_DataParams_t * pDataParams, uint8_t bOption, uint8_t bFileNo,
    uint8_t ** ppFileCounters, uint16_t * pFileCounterLen);

phStatus_t phalMfDuoX_Sw_ChangeFileSettings(phalMfDuoX_Sw_DataParams_t * pDataParams, uint8_t bOption, uint8_t bFileNo,
    uint8_t bFileOption, uint8_t * pAccessRights, uint8_t * pAddInfo, uint8_t bAddInfoLen);

/* MIFARE DUOX Data management commands ------------------------------------------------------------------------------------------------- */
phStatus_t phalMfDuoX_Sw_ReadData(phalMfDuoX_Sw_DataParams_t * pDataParams, uint8_t bOption, uint8_t bIns, uint8_t bFileNo,
    uint8_t * pOffset, uint8_t * pLength, uint8_t ** ppResponse, uint16_t * pRspLen);

phStatus_t phalMfDuoX_Sw_WriteData(phalMfDuoX_Sw_DataParams_t * pDataParams, uint8_t bOption, uint8_t bIns, uint8_t bFileNo,
    uint16_t wCRLVer, uint8_t * pOffset, uint8_t * pData, uint8_t * pLength);

phStatus_t phalMfDuoX_Sw_GetValue(phalMfDuoX_Sw_DataParams_t * pDataParams, uint8_t bOption, uint8_t bFileNo, uint8_t ** ppValue,
    uint16_t * pValueLen);

phStatus_t phalMfDuoX_Sw_Credit(phalMfDuoX_Sw_DataParams_t * pDataParams, uint8_t bOption, uint8_t bFileNo, uint8_t * pData);

phStatus_t phalMfDuoX_Sw_Debit(phalMfDuoX_Sw_DataParams_t * pDataParams, uint8_t bOption, uint8_t bFileNo, uint8_t * pData);

phStatus_t phalMfDuoX_Sw_LimitedCredit(phalMfDuoX_Sw_DataParams_t * pDataParams, uint8_t bOption, uint8_t bFileNo, uint8_t * pData);

phStatus_t phalMfDuoX_Sw_ReadRecords(phalMfDuoX_Sw_DataParams_t * pDataParams, uint8_t bOption, uint8_t bIns, uint8_t bFileNo,
    uint8_t * pRecNo, uint8_t * pRecCount, uint8_t * pRecSize, uint8_t ** ppResponse, uint16_t * pRspLen);

phStatus_t phalMfDuoX_Sw_WriteRecord(phalMfDuoX_Sw_DataParams_t * pDataParams, uint8_t bOption, uint8_t bIns, uint8_t bFileNo,
    uint8_t * pOffset, uint8_t * pData, uint8_t * pLength);

phStatus_t phalMfDuoX_Sw_UpdateRecord(phalMfDuoX_Sw_DataParams_t * pDataParams, uint8_t bOption, uint8_t bIns, uint8_t bFileNo,
    uint8_t * pRecNo, uint8_t * pOffset, uint8_t * pData, uint8_t * pLength);

phStatus_t phalMfDuoX_Sw_ClearRecordFile(phalMfDuoX_Sw_DataParams_t * pDataParams, uint8_t bFileNo);

/* MIFARE DUOX Transaction Management commands ------------------------------------------------------------------------------------------ */
phStatus_t phalMfDuoX_Sw_CommitTransaction(phalMfDuoX_Sw_DataParams_t * pDataParams, uint8_t bOption, uint8_t ** ppTMC,
    uint16_t * pTMCLen, uint8_t ** ppResponse, uint16_t * pRspLen);

phStatus_t phalMfDuoX_Sw_AbortTransaction(phalMfDuoX_Sw_DataParams_t * pDataParams);

phStatus_t phalMfDuoX_Sw_CommitReaderID(phalMfDuoX_Sw_DataParams_t * pDataParams, uint8_t * pTMRI, uint8_t bTMRILen,
    uint8_t ** ppEncTMRI, uint16_t * pEncTMRILen);

/* MIFARE DUOX Cryptographic support commands ------------------------------------------------------------------------------------------- */
phStatus_t phalMfDuoX_Sw_CryptoRequest(phalMfDuoX_Sw_DataParams_t * pDataParams, uint8_t bComOption, uint8_t bAction,
    uint8_t * pInputData, uint16_t wInputLen, uint8_t ** ppResponse, uint16_t * pRspLen);

phStatus_t phalMfDuoX_Sw_CryptoRequestECCSign(phalMfDuoX_Sw_DataParams_t * pDataParams, uint8_t bComOption, uint8_t bOperation,
    uint8_t bAlgo, uint8_t bKeyNo, uint8_t bInputSource, uint8_t * pInputData, uint8_t bInputLen, uint8_t ** ppSign,
    uint16_t * pSignLen);

phStatus_t phalMfDuoX_Sw_CryptoRequestEcho(phalMfDuoX_Sw_DataParams_t * pDataParams, uint8_t bComOption, uint8_t * pInputData,
    uint8_t bInputLen, uint8_t ** ppResponse, uint16_t * pRspLen);

/* MIFARE DUOX GPIO Management commands ------------------------------------------------------------------------------------------------- */
phStatus_t phalMfDuoX_Sw_ManageGPIO(phalMfDuoX_Sw_DataParams_t * pDataParams, uint16_t wOption, uint8_t bGPIONo, uint8_t bOperation,
    uint8_t * pNFCPauseRspData, uint16_t wNFCPauseRspDataLen, uint8_t ** ppResponse, uint16_t * pRspLen);

phStatus_t phalMfDuoX_Sw_ReadGPIO(phalMfDuoX_Sw_DataParams_t * pDataParams, uint16_t wOption, uint8_t ** ppResponse,
    uint16_t * pRspLen);

/* MIFARE DUOX ISO7816-4 commands ------------------------------------------------------------------------------------------------------- */
phStatus_t phalMfDuoX_Sw_IsoSelectFile(phalMfDuoX_Sw_DataParams_t * pDataParams, uint8_t bOption, uint8_t bSelector, uint8_t * pFid,
    uint8_t * pDFname, uint8_t bDFnameLen, uint8_t bExtendedLenApdu, uint8_t ** ppFCI, uint16_t * pFCILen);

phStatus_t phalMfDuoX_Sw_IsoReadBinary(phalMfDuoX_Sw_DataParams_t * pDataParams, uint16_t wOption, uint8_t bOffset, uint8_t bSfid,
    uint32_t dwBytesToRead, uint8_t bExtendedLenApdu, uint8_t ** ppResponse, uint16_t * pRspLen);

phStatus_t phalMfDuoX_Sw_IsoUpdateBinary(phalMfDuoX_Sw_DataParams_t * pDataParams, uint8_t bOffset, uint8_t bSfid, uint8_t bExtendedLenApdu,
    uint8_t * pData, uint16_t wDataLen);

phStatus_t phalMfDuoX_Sw_IsoReadRecords(phalMfDuoX_Sw_DataParams_t * pDataParams, uint16_t wOption, uint8_t bRecNo, uint8_t bReadAllRecords,
    uint8_t bSfid, uint32_t dwBytesToRead, uint8_t bExtendedLenApdu, uint8_t ** ppResponse, uint16_t * pRspLen);

phStatus_t phalMfDuoX_Sw_IsoAppendRecord(phalMfDuoX_Sw_DataParams_t * pDataParams, uint8_t bSfid, uint8_t bExtendedLenApdu, uint8_t * pData,
    uint16_t wDataLen);

phStatus_t phalMfDuoX_Sw_IsoGetChallenge(phalMfDuoX_Sw_DataParams_t * pDataParams, uint8_t bExpRsp, uint8_t bExtendedLenApdu,
    uint8_t ** ppResponse, uint16_t * pRspLen);

/* MIFARE DUOX EV Charging command ------------------------------------------------------------------------------------------------------ */
phStatus_t phalMfDuoX_Sw_VdeReadData(phalMfDuoX_Sw_DataParams_t * pDataParams, uint16_t wOption, uint8_t bFileNo, uint16_t wBytesToRead,
    uint8_t bExtendedLenApdu, uint8_t ** ppResponse, uint16_t * pRspLen);

phStatus_t phalMfDuoX_Sw_VdeWriteData(phalMfDuoX_Sw_DataParams_t * pDataParams, uint8_t bOperation, uint8_t bExtendedLenApdu,
    uint8_t * pData, uint16_t wDataLen);

phStatus_t phalMfDuoX_Sw_VdeECDSASign(phalMfDuoX_Sw_DataParams_t * pDataParams, uint16_t wBytesToRead, uint8_t bExtendedLenApdu,
    uint8_t * pData, uint16_t wDataLen, uint8_t ** ppResponse, uint16_t * pRspLen);

/* MIFARE DUOX Utility functions -------------------------------------------------------------------------------------------------------- */
phStatus_t phalMfDuoX_Sw_GetConfig(phalMfDuoX_Sw_DataParams_t * pDataParams, uint16_t wConfig, uint16_t * pValue);

phStatus_t phalMfDuoX_Sw_SetConfig(phalMfDuoX_Sw_DataParams_t * pDataParams, uint16_t wConfig, uint16_t wValue);

phStatus_t phalMfDuoX_Sw_ResetAuthentication(phalMfDuoX_Sw_DataParams_t * pDataParams);

#endif /* NXPBUILD__PHAL_MFDUOX_SW */

#endif /* PHALMFDUOX_SW_H */
