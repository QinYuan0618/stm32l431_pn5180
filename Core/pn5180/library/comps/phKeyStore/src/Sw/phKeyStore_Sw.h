/*----------------------------------------------------------------------------*/
/* Copyright 2006 - 2013, 2021 - 2022, 2024 NXP                               */
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
* Sw functions of Reader Library Framework.
* $Author: NXP $
* $Revision: $ (v07.13.00)
* $Date: $
*
*/

#ifndef PHKEYSTORE_SW_H
#define PHKEYSTORE_SW_H

#include <ph_Status.h>
#ifndef NXPRDLIB_REM_GEN_INTFS
#   include <phKeyStore.h>
#endif

/* Common Interfaces ------------------------------------------------------------------------------------------------------------------- */
phStatus_t phKeyStore_Sw_FormatKeyEntry(phKeyStore_Sw_DataParams_t * pDataParams, uint16_t wKeyNo, uint16_t wNewKeyType);

phStatus_t phKeyStore_Sw_SetKUC(phKeyStore_Sw_DataParams_t * pDataParams, uint16_t wKeyNo, uint16_t wRefNoKUC);

phStatus_t phKeyStore_Sw_GetKUC(phKeyStore_Sw_DataParams_t * pDataParams, uint16_t wRefNoKUC, uint32_t * pdwLimit,
    uint32_t * pdwCurVal);

phStatus_t phKeyStore_Sw_ChangeKUC(phKeyStore_Sw_DataParams_t * pDataParams, uint16_t wRefNoKUC, uint32_t dwLimit);

phStatus_t phKeyStore_Sw_SetConfig(phKeyStore_Sw_DataParams_t * pDataParams, uint16_t wConfig, uint16_t wValue);

phStatus_t phKeyStore_Sw_SetConfigStr(phKeyStore_Sw_DataParams_t * pDataParams, uint16_t wConfig, uint8_t *pBuffer,
    uint16_t wBuffLen);

phStatus_t phKeyStore_Sw_GetConfig(phKeyStore_Sw_DataParams_t * pDataParams, uint16_t wConfig, uint16_t * pValue);

phStatus_t phKeyStore_Sw_GetConfigStr(phKeyStore_Sw_DataParams_t * pDataParams, uint16_t wConfig, uint8_t ** ppBuffer,
    uint16_t * pBuffLen);

/* Interfaces for Symmetric Keys ------------------------------------------------------------------------------------------------------- */
phStatus_t phKeyStore_Sw_SetKey(phKeyStore_Sw_DataParams_t * pDataParams, uint16_t wKeyNo, uint16_t wKeyVer,
    uint16_t wKeyType, uint8_t * pNewKey, uint16_t wNewKeyVer);

phStatus_t phKeyStore_Sw_SetKeyAtPos(phKeyStore_Sw_DataParams_t * pDataParams, uint16_t wKeyNo, uint16_t wPos,
    uint16_t wKeyType, uint8_t * pNewKey, uint16_t wNewKeyVer);

phStatus_t phKeyStore_Sw_SetFullKeyEntry(phKeyStore_Sw_DataParams_t * pDataParams, uint16_t wNoOfKeys, uint16_t wKeyNo,
    uint16_t wNewRefNoKUC, uint16_t wNewKeyType, uint8_t * pNewKeys, uint16_t * pNewKeyVerList);

phStatus_t phKeyStore_Sw_GetKeyEntry(phKeyStore_Sw_DataParams_t * pDataParams, uint16_t wKeyNo, uint16_t wKeyVerBufSize,
    uint16_t * wKeyVersion, uint16_t * wKeyVerLen, uint16_t * pKeyType);

phStatus_t phKeyStore_Sw_GetKey(phKeyStore_Sw_DataParams_t * pDataParams, uint16_t wKeyNo, uint16_t wKeyVer,
    uint8_t bKeyBufSize, uint8_t * pKey, uint16_t * pKeyType);

#ifdef  NXPBUILD__PH_KEYSTORE_ASYM
/* Interfaces for ASymmetric Keys ------------------------------------------------------------------------------------------------------ */

phStatus_t phKeyStore_Sw_SetKeyASym(phKeyStore_Sw_DataParams_t * pDataParams, uint16_t wKeyNo, uint16_t wPos, uint16_t wKeyType,
    uint16_t wKeyInfo, uint8_t * pKey, uint16_t wKeyLen);

phStatus_t phKeyStore_Sw_GetKeyASym(phKeyStore_Sw_DataParams_t * pDataParams, uint16_t wKeyNo, uint16_t wPos, uint16_t wKeyPairType,
    uint16_t * pKeyType, uint8_t * pCurveID, uint8_t * pKey, uint16_t * pKeyLen);

phStatus_t phKeyStore_Sw_GetCurveID(phKeyStore_Sw_DataParams_t * pDataParams, uint16_t wKeyNo, uint16_t wPos, uint8_t * pCurveID);

#endif /* NXPBUILD__PH_KEYSTORE_ASYM */

#endif /* PHKEYSTORE_SW_H */
