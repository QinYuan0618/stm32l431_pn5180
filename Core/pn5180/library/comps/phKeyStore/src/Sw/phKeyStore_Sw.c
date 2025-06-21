/*----------------------------------------------------------------------------*/
/* Copyright 2006-2013,2021-2024 NXP                                          */
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
* Software KeyStore Component of Reader Library Framework.
* $Author: NXP $
* $Revision: $ (v07.13.00)
* $Date: $
*
*/

#include <ph_Status.h>
#include <phKeyStore.h>
#include <ph_RefDefs.h>

#ifdef NXPBUILD__PH_KEYSTORE_SW

#include "phKeyStore_Sw.h"
#include "phKeyStore_Sw_Int.h"

phStatus_t phKeyStore_Sw_Init(phKeyStore_Sw_DataParams_t * pDataParams, uint16_t wSizeOfDataParams, phKeyStore_Sw_KeyEntry_t * pKeyEntries,
    uint16_t wNoOfKeyEntries, phKeyStore_Sw_KeyVersionPair_t * pKeyVersionPairs, uint16_t wNoOfVersionPairs, phKeyStore_Sw_KUCEntry_t * pKUCEntries,
    uint16_t wNoOfKUCEntries)
{
    uint16_t wEntryIndex;
    uint16_t wPos;
    phStatus_t wStatus;
    phKeyStore_Sw_KeyVersionPair_t * pKeyVersion;

    if(sizeof(phKeyStore_Sw_DataParams_t) != wSizeOfDataParams)
    {
        return PH_ADD_COMPCODE_FIXED(PH_ERR_INVALID_DATA_PARAMS, PH_COMP_KEYSTORE);
    }
    PH_ASSERT_NULL(pDataParams);
    PH_ASSERT_NULL(pKeyEntries);
    PH_ASSERT_NULL(pKeyVersionPairs);
    PH_ASSERT_NULL(pKUCEntries);

    /* Init private data */
    pDataParams->wId = PH_COMP_KEYSTORE | PH_KEYSTORE_SW_ID;
    pDataParams->pKeyEntries = pKeyEntries;
    pDataParams->pKeyVersionPairs = pKeyVersionPairs;
    pDataParams->wNoOfKeyEntries = wNoOfKeyEntries;
    pDataParams->wNoOfVersions = wNoOfVersionPairs;
    pDataParams->pKUCEntries = pKUCEntries;
    pDataParams->wNoOfKUCEntries = wNoOfKUCEntries;

    for(wEntryIndex = 0; wEntryIndex < pDataParams->wNoOfKeyEntries; wEntryIndex++)
    {
        pDataParams->pKeyEntries[wEntryIndex].wKeyType = PH_KEYSTORE_INVALID_ID;
        pDataParams->pKeyEntries[wEntryIndex].wRefNoKUC = PH_KEYSTORE_INVALID_ID;

        for(wPos = 0; wPos < pDataParams->wNoOfVersions; wPos++)
        {
            PH_CHECK_SUCCESS_FCT(wStatus, phKeyStore_Sw_GetKeyValuePtrPos(pDataParams, wEntryIndex, wPos, &pKeyVersion));
            pKeyVersion->wVersion = PH_KEYSTORE_DEFAULT_ID;

#ifdef NXPBUILD__PH_KEYSTORE_ASYM
            pKeyVersion->bCurveID = PH_KEYSTORE_CURVE_ID_NONE;
            pKeyVersion->wKeyPairType = PH_KEYSTORE_KEY_PAIR_INVALID;
#endif /* NXPBUILD__PH_KEYSTORE_ASYM */

        }
    }

    for(wEntryIndex = 0; wEntryIndex < pDataParams->wNoOfKUCEntries; wEntryIndex++)
    {
        pDataParams->pKUCEntries[wEntryIndex].dwLimit = 0xFFFFFFFFU;
        pDataParams->pKUCEntries[wEntryIndex].dwCurVal = 0;
    }

    return PH_ERR_SUCCESS;
}

/* Common Interfaces ------------------------------------------------------------------------------------------------------------------- */
phStatus_t phKeyStore_Sw_FormatKeyEntry(phKeyStore_Sw_DataParams_t * pDataParams, uint16_t wKeyNo, uint16_t wNewKeyType)
{
    phStatus_t wStatus;
    uint16_t   wPos;
    phKeyStore_Sw_KeyVersionPair_t * pKeyPair;
    /* Overflow checks */
    if(wKeyNo >= pDataParams->wNoOfKeyEntries)
    {
        return PH_ADD_COMPCODE_FIXED(PH_ERR_INVALID_PARAMETER, PH_COMP_KEYSTORE);
    }

    switch(wNewKeyType)
    {
        case PH_KEYSTORE_KEY_TYPE_AES128:
        case PH_KEYSTORE_KEY_TYPE_DES:
        case PH_KEYSTORE_KEY_TYPE_2K3DES:
        case PH_KEYSTORE_KEY_TYPE_MIFARE:
        case PH_KEYSTORE_KEY_TYPE_AES192:
        case PH_KEYSTORE_KEY_TYPE_3K3DES:
        case PH_KEYSTORE_KEY_TYPE_AES256:
            break;

#ifdef  NXPBUILD__PH_KEYSTORE_ASYM
        case PH_KEYSTORE_KEY_TYPE_ECC:
            break;
#endif /* NXPBUILD__PH_KEYSTORE_ASYM */

        default:
            return PH_ADD_COMPCODE_FIXED(PH_ERR_INVALID_PARAMETER, PH_COMP_KEYSTORE);
    }

    pDataParams->pKeyEntries[wKeyNo].wKeyType = wNewKeyType;

    /* Reset CEK to master Key */
    pDataParams->pKeyEntries[wKeyNo].wRefNoKUC = PH_KEYSTORE_INVALID_ID;

    /* Reset all keys to 0x00*/
    for(wPos = 0; wPos < pDataParams->wNoOfVersions; ++wPos)
    {
        PH_CHECK_SUCCESS_FCT(wStatus, phKeyStore_Sw_GetKeyValuePtrPos(pDataParams, wKeyNo, wPos, &pKeyPair));
        pKeyPair->wVersion = 0;

        (void) memset(pKeyPair->pKey, 0x00, PH_KEYSTORE_MAX_KEY_SIZE);

#ifdef NXPBUILD__PH_KEYSTORE_ASYM
        pKeyPair->bCurveID = PH_KEYSTORE_CURVE_ID_NONE;
        pKeyPair->wKeyPairType = PH_KEYSTORE_KEY_PAIR_INVALID;
        (void) memset(pKeyPair->pPubKey, 0x00, sizeof(pKeyPair->pPubKey));
#endif /* NXPBUILD__PH_KEYSTORE_ASYM */
    }

    return PH_ERR_SUCCESS;
}

phStatus_t phKeyStore_Sw_SetKUC(phKeyStore_Sw_DataParams_t * pDataParams, uint16_t wKeyNo, uint16_t wRefNoKUC)
{
    /* Overflow checks */
    if(wKeyNo >= pDataParams->wNoOfKeyEntries)
    {
        return PH_ADD_COMPCODE_FIXED(PH_ERR_INVALID_PARAMETER, PH_COMP_KEYSTORE);
    }
    /* Check for a valid KUC entry */
    if(wRefNoKUC >= pDataParams->wNoOfKUCEntries)
    {
        return PH_ADD_COMPCODE_FIXED(PH_ERR_INVALID_PARAMETER, PH_COMP_KEYSTORE);
    }
    pDataParams->pKeyEntries[wKeyNo].wRefNoKUC = wRefNoKUC;

    return PH_ERR_SUCCESS;
}

phStatus_t phKeyStore_Sw_GetKUC(phKeyStore_Sw_DataParams_t * pDataParams, uint16_t wRefNoKUC, uint32_t * pdwLimit,
    uint32_t * pdwCurVal)
{
    /* Overflow checks */
    if(wRefNoKUC >= pDataParams->wNoOfKUCEntries)
    {
        return PH_ADD_COMPCODE_FIXED(PH_ERR_INVALID_PARAMETER, PH_COMP_KEYSTORE);
    }

    *pdwLimit = pDataParams->pKUCEntries[wRefNoKUC].dwLimit;
    *pdwCurVal = pDataParams->pKUCEntries[wRefNoKUC].dwCurVal;

    return PH_ERR_SUCCESS;
}

phStatus_t phKeyStore_Sw_ChangeKUC(phKeyStore_Sw_DataParams_t * pDataParams, uint16_t wRefNoKUC, uint32_t dwLimit)
{
    /* Overflow checks */
    if(wRefNoKUC >= pDataParams->wNoOfKUCEntries)
    {
        return PH_ADD_COMPCODE_FIXED(PH_ERR_INVALID_PARAMETER, PH_COMP_KEYSTORE);
    }
    pDataParams->pKUCEntries[wRefNoKUC].dwLimit = dwLimit;

    return PH_ERR_SUCCESS;
}

phStatus_t phKeyStore_Sw_SetConfig(phKeyStore_Sw_DataParams_t * pDataParams, uint16_t wConfig, uint16_t wValue)
{
    /* satisfy compiler */
    if(pDataParams || wConfig || wValue)
        {
        ;/*do nothing*/
        }
    return PH_ADD_COMPCODE_FIXED(PH_ERR_UNSUPPORTED_PARAMETER, PH_COMP_KEYSTORE);
}

phStatus_t phKeyStore_Sw_SetConfigStr(phKeyStore_Sw_DataParams_t * pDataParams, uint16_t wConfig, uint8_t *pBuffer,
    uint16_t wBuffLen)
{
    /* satisfy compiler */
    if(pDataParams || wConfig || pBuffer || wBuffLen)
        {
        ;/*do nothing*/
        }
    return PH_ADD_COMPCODE_FIXED(PH_ERR_UNSUPPORTED_PARAMETER, PH_COMP_KEYSTORE);
}

phStatus_t phKeyStore_Sw_GetConfig(phKeyStore_Sw_DataParams_t * pDataParams, uint16_t wConfig, uint16_t * pValue)
{
    /* satisfy compiler */
    if(pDataParams || wConfig || pValue)
        {
        ;/*do nothing*/
        }
    return PH_ADD_COMPCODE_FIXED(PH_ERR_UNSUPPORTED_PARAMETER, PH_COMP_KEYSTORE);
}

phStatus_t phKeyStore_Sw_GetConfigStr(phKeyStore_Sw_DataParams_t * pDataParams, uint16_t wConfig, uint8_t ** ppBuffer,
    uint16_t * pBuffLen)
{
    /* satisfy compiler */
    if(pDataParams || wConfig || ppBuffer || pBuffLen)
        {
        ;/*do nothing*/
        }
    return PH_ADD_COMPCODE_FIXED(PH_ERR_UNSUPPORTED_PARAMETER, PH_COMP_KEYSTORE);
}

/* Interfaces for Symmetric Keys ------------------------------------------------------------------------------------------------------- */
phStatus_t phKeyStore_Sw_SetKey(phKeyStore_Sw_DataParams_t * pDataParams, uint16_t wKeyNo, uint16_t wKeyVer,
    uint16_t wKeyType, uint8_t * pNewKey, uint16_t wNewKeyVer)
{
    phStatus_t wStatus;
    phKeyStore_Sw_KeyVersionPair_t * pKeyVer;
    PH_CHECK_SUCCESS_FCT(wStatus, phKeyStore_Sw_GetKeyValuePtrVersion(pDataParams, wKeyNo, wKeyVer, &pKeyVer));

    /* Check that Key type matches with current Key Type format */
    if(pDataParams->pKeyEntries[wKeyNo].wKeyType != wKeyType)
    {
        return PH_ADD_COMPCODE_FIXED(PH_ERR_INVALID_PARAMETER, PH_COMP_KEYSTORE);
    }

    /* copy the key and version */
    (void) memcpy(pKeyVer->pKey, pNewKey, phKeyStore_GetKeySize(wKeyType));
    pKeyVer->wVersion = wNewKeyVer;

    return PH_ERR_SUCCESS;
}

phStatus_t phKeyStore_Sw_SetKeyAtPos(phKeyStore_Sw_DataParams_t * pDataParams, uint16_t wKeyNo, uint16_t wPos, uint16_t wKeyType,
    uint8_t * pNewKey, uint16_t wNewKeyVer)
{
    phStatus_t wStatus;
    phKeyStore_Sw_KeyVersionPair_t * pKeyVer;
    PH_CHECK_SUCCESS_FCT(wStatus, phKeyStore_Sw_GetKeyValuePtrPos(pDataParams, wKeyNo, wPos, &pKeyVer));

    /* Check that Key type matches with current Key Type format */
    if(pDataParams->pKeyEntries[wKeyNo].wKeyType != wKeyType)
    {
        return PH_ADD_COMPCODE_FIXED(PH_ERR_INVALID_PARAMETER, PH_COMP_KEYSTORE);
    }

    /* copy the key and version */
    (void) memcpy(pKeyVer->pKey, pNewKey, phKeyStore_GetKeySize(wKeyType));
    pKeyVer->wVersion = wNewKeyVer;

    return PH_ERR_SUCCESS;
}

phStatus_t phKeyStore_Sw_SetFullKeyEntry(phKeyStore_Sw_DataParams_t * pDataParams, uint16_t wNoOfKeys, uint16_t wKeyNo,
    uint16_t wNewRefNoKUC, uint16_t wNewKeyType, uint8_t * pNewKeys, uint16_t * pNewKeyVerList)
{
    phStatus_t wStatus;
    uint8_t    bPos;
    uint8_t bKeyLen;
    phKeyStore_Sw_KeyVersionPair_t * pKeyVer;

    /* Overflow checks */
    if(wKeyNo >= pDataParams->wNoOfKeyEntries)
    {
        return PH_ADD_COMPCODE_FIXED(PH_ERR_INVALID_PARAMETER, PH_COMP_KEYSTORE);
    }
    /* Check for a valid KUC entry */
    if(wNewRefNoKUC >= pDataParams->wNoOfKUCEntries)
    {
        return PH_ADD_COMPCODE_FIXED(PH_ERR_INVALID_PARAMETER, PH_COMP_KEYSTORE);
    }
    /* Overflow checks */
    if(wNoOfKeys > pDataParams->wNoOfVersions)
    {
        return PH_ADD_COMPCODE_FIXED(PH_ERR_INVALID_PARAMETER, PH_COMP_KEYSTORE);
    }

    switch(wNewKeyType)
    {
        case PH_KEYSTORE_KEY_TYPE_AES128:
        case PH_KEYSTORE_KEY_TYPE_2K3DES:
        case PH_KEYSTORE_KEY_TYPE_AES192:
        case PH_KEYSTORE_KEY_TYPE_3K3DES:
        case PH_KEYSTORE_KEY_TYPE_AES256:
        case PH_KEYSTORE_KEY_TYPE_DES:
        case PH_KEYSTORE_KEY_TYPE_MIFARE:
            bKeyLen = (uint8_t) phKeyStore_GetKeySize(wNewKeyType);
            break;

        default:
            return PH_ADD_COMPCODE_FIXED(PH_ERR_INVALID_PARAMETER, PH_COMP_KEYSTORE);
    }

    pDataParams->pKeyEntries[wKeyNo].wKeyType = wNewKeyType;

    /* Reset KUC to master Key */
    pDataParams->pKeyEntries[wKeyNo].wRefNoKUC = wNewRefNoKUC;

    /* Reset all keys to 0x00*/
    for(bPos = 0; bPos < wNoOfKeys; bPos++)
    {
        PH_CHECK_SUCCESS_FCT(wStatus, phKeyStore_Sw_GetKeyValuePtrPos(pDataParams, wKeyNo, bPos, &pKeyVer));
        pKeyVer->wVersion = pNewKeyVerList[bPos];
        (void) memcpy(pKeyVer->pKey, &pNewKeys[bPos * bKeyLen], bKeyLen);
    }

    return PH_ERR_SUCCESS;
}

phStatus_t phKeyStore_Sw_GetKeyEntry(phKeyStore_Sw_DataParams_t * pDataParams, uint16_t wKeyNo, uint16_t wKeyVerBufSize,
    uint16_t * wKeyVer, uint16_t * wKeyVerLen, uint16_t * pKeyType)
{
    phStatus_t wStatus;
    uint16_t bPos;
    phKeyStore_Sw_KeyVersionPair_t * pKeyVer;

    /* Check for overflow */
    if(wKeyVerBufSize < (sizeof(uint16_t) * pDataParams->wNoOfVersions))
    {
        return PH_ADD_COMPCODE_FIXED(PH_ERR_BUFFER_OVERFLOW, PH_COMP_KEYSTORE);
    }

    for(bPos = 0; bPos < pDataParams->wNoOfVersions; bPos++)
    {
        PH_CHECK_SUCCESS_FCT(wStatus, phKeyStore_Sw_GetKeyValuePtrPos(pDataParams, wKeyNo, bPos, &pKeyVer));
        wKeyVer[bPos] = pKeyVer->wVersion;
    }
    *wKeyVerLen = pDataParams->wNoOfVersions;
    *pKeyType = pDataParams->pKeyEntries[wKeyNo].wKeyType;

    return PH_ERR_SUCCESS;
}

phStatus_t phKeyStore_Sw_GetKey(phKeyStore_Sw_DataParams_t * pDataParams, uint16_t wKeyNo, uint16_t wKeyVer, uint8_t bKeyBufSize,
    uint8_t * pKey, uint16_t * pKeyType)
{
    phStatus_t wStatus;
    uint16_t wKeySize;
    phKeyStore_Sw_KeyVersionPair_t * pKeyVer;
    PH_CHECK_SUCCESS_FCT(wStatus, phKeyStore_Sw_GetKeyValuePtrVersion(pDataParams, wKeyNo, wKeyVer, &pKeyVer));

    /* Check for Counter overflow */
    PH_CHECK_SUCCESS_FCT(wStatus, phKeyStore_Sw_CheckUpdateKUC(pDataParams, pDataParams->pKeyEntries[wKeyNo].wRefNoKUC));

    /* check buffer size */
    wKeySize = phKeyStore_GetKeySize(pDataParams->pKeyEntries[wKeyNo].wKeyType);
    if(bKeyBufSize < wKeySize)
    {
        return PH_ADD_COMPCODE_FIXED(PH_ERR_BUFFER_OVERFLOW, PH_COMP_KEYSTORE);
    }
    /* copy the key */
    (void) memcpy(pKey, pKeyVer->pKey, wKeySize);

    *pKeyType = pDataParams->pKeyEntries[wKeyNo].wKeyType;
    return PH_ERR_SUCCESS;
}

phStatus_t phKeyStore_Sw_GetKeyValuePtrVersion(phKeyStore_Sw_DataParams_t * pDataParams, uint16_t wKeyNo, uint16_t wKeyVer,
    phKeyStore_Sw_KeyVersionPair_t ** pKeyVer)
{
    uint16_t bPos;
    *pKeyVer = NULL;
    /* Overflow checks */
    if(wKeyNo >= pDataParams->wNoOfKeyEntries)
    {
        return PH_ADD_COMPCODE_FIXED(PH_ERR_INVALID_PARAMETER, PH_COMP_KEYSTORE);
    }

    for(bPos = 0; bPos < pDataParams->wNoOfVersions; bPos++)
    {
        *pKeyVer = &pDataParams->pKeyVersionPairs[(((uint16_t)(((uint32_t)wKeyNo * pDataParams->wNoOfVersions)) & 0xFFFF) + bPos)];
        if((*pKeyVer)->wVersion == wKeyVer)
        {
            break;
        }
    }
    /* No entry found */
    if(bPos == pDataParams->wNoOfVersions)
    {
        return PH_ADD_COMPCODE_FIXED(PH_ERR_INVALID_PARAMETER, PH_COMP_KEYSTORE);
    }
    return PH_ERR_SUCCESS;
}

phStatus_t phKeyStore_Sw_CheckUpdateKUC(phKeyStore_Sw_DataParams_t * pDataParams, uint16_t wKeyUsageCtrNumber)
{
    if(wKeyUsageCtrNumber != PH_KEYSTORE_INVALID_ID)
    {
        /* Check for a valid KUC entry */
        if(wKeyUsageCtrNumber >= pDataParams->wNoOfKUCEntries)
        {
            return PH_ADD_COMPCODE_FIXED(PH_ERR_INVALID_PARAMETER, PH_COMP_KEYSTORE);
        }

        /* Now let's check the limit*/
        if(pDataParams->pKUCEntries[wKeyUsageCtrNumber].dwCurVal >= pDataParams->pKUCEntries[wKeyUsageCtrNumber].dwLimit)
        {
            return PH_ADD_COMPCODE_FIXED(PH_ERR_KEY, PH_COMP_KEYSTORE);
        }
        pDataParams->pKUCEntries[wKeyUsageCtrNumber].dwCurVal++;
    }
    return PH_ERR_SUCCESS;
}

#ifdef  NXPBUILD__PH_KEYSTORE_ASYM
/* Interfaces for ASymmetric Keys ------------------------------------------------------------------------------------------------------ */
phStatus_t phKeyStore_Sw_SetKeyASym(phKeyStore_Sw_DataParams_t * pDataParams, uint16_t wKeyNo, uint16_t wPos, uint16_t wKeyType,
    uint16_t wKeyInfo, uint8_t * pKey, uint16_t wKeyLen)
{
    phStatus_t wStatus = 0;
    uint16_t   wKeyPairType = 0;
    uint8_t    bCurveId = 0;
    uint8_t    bKeySize = 0;

    phKeyStore_Sw_KeyVersionPair_t * pKeyPair;

    /* Extract KeyPair Type and Curve ID. */
    wKeyPairType = (uint16_t) (wKeyInfo & PH_KEYSTORE_KEY_PAIR_MASK);
    bCurveId = (uint8_t) (wKeyInfo & PH_KEYSTORE_CURVE_ID_MASK);

    /* Get the pointer based on KeyNo. */
    PH_CHECK_SUCCESS_FCT(wStatus, phKeyStore_Sw_GetKeyValuePtrPos(pDataParams, wKeyNo, wPos, &pKeyPair));

    /* Check that Key type matches with current Key Type. */
    if(pDataParams->pKeyEntries[wKeyNo].wKeyType != wKeyType)
    {
        return PH_ADD_COMPCODE_FIXED(PH_ERR_INVALID_PARAMETER, PH_COMP_KEYSTORE);
    }

    /* Validate CurveID */
    switch(bCurveId)
    {
        case PH_KEYSTORE_CURVE_ID_SECP256R1:
        case PH_KEYSTORE_CURVE_ID_SECP384R1:
        case PH_KEYSTORE_CURVE_ID_BRAINPOOL256R1:
        case PH_KEYSTORE_CURVE_ID_BRAINPOOL384R1:
            pKeyPair->bCurveID = bCurveId;
            break;

        default:
            return PH_ADD_COMPCODE_FIXED(PH_ERR_INVALID_PARAMETER, PH_COMP_KEYSTORE);
    }

    /* Validate KeyPair Type and Key Length. */
    switch(wKeyPairType)
    {
        case PH_KEYSTORE_KEY_PAIR_PRIVATE:
            /* Check if key length is not higher. */
            switch(wKeyLen)
            {
                case PH_KEYSTORE_KEY_TYPE_ECC_256_SIZE:
                case PH_KEYSTORE_KEY_TYPE_ECC_384_SIZE:
                    /* Copy the key and information. */
                    (void) memcpy(pKeyPair->pKey, pKey, wKeyLen);
                    break;

                default:
                    return PH_ADD_COMPCODE_FIXED(PH_ERR_PARAMETER_SIZE, PH_COMP_KEYSTORE);
            }
            break;

        case PH_KEYSTORE_KEY_PAIR_PUBLIC:
            /* Get the Key Size */
            bKeySize = (uint8_t) (((wKeyLen - 1U) / 2U) + ((wKeyLen - 1U) % 2U));

            /* Check if key length is not higher. */
            switch(bKeySize)
            {
                case PH_KEYSTORE_KEY_TYPE_ECC_256_SIZE:
                case PH_KEYSTORE_KEY_TYPE_ECC_384_SIZE:
                    /* Copy the key and information. */
                    (void) memcpy(pKeyPair->pPubKey, pKey, wKeyLen);
                    break;

                default:
                    return PH_ADD_COMPCODE_FIXED(PH_ERR_PARAMETER_SIZE, PH_COMP_KEYSTORE);
            }
            break;

        default:
            return PH_ADD_COMPCODE_FIXED(PH_ERR_INVALID_PARAMETER, PH_COMP_KEYSTORE);
    }

    /* Update the Format. */
    pKeyPair->wKeyPairType |= wKeyPairType;

    return PH_ADD_COMPCODE(PH_ERR_SUCCESS, PH_COMP_KEYSTORE);
}

phStatus_t phKeyStore_Sw_GetKeyASym(phKeyStore_Sw_DataParams_t * pDataParams, uint16_t wKeyNo, uint16_t wPos, uint16_t wKeyPairType,
    uint16_t * pKeyType, uint8_t * pCurveID, uint8_t * pKey, uint16_t * pKeyLen)
{
    phStatus_t wStatus;
    phKeyStore_Sw_KeyVersionPair_t * pKeyPair;

    /* Get the pointer based on KeyNo. */
    PH_CHECK_SUCCESS_FCT(wStatus, phKeyStore_Sw_GetKeyValuePtrPos(pDataParams, wKeyNo, wPos, &pKeyPair));

    /* Check for Counter overflow */
    PH_CHECK_SUCCESS_FCT(wStatus, phKeyStore_Sw_CheckUpdateKUC(pDataParams, pDataParams->pKeyEntries[wKeyNo].wRefNoKUC));

    /* Return the information. */
    *pKeyType = pDataParams->pKeyEntries[wKeyNo].wKeyType;
    *pCurveID = pKeyPair->bCurveID;

    /* Copy the actual length. */
    switch(*pCurveID)
    {
        case PH_KEYSTORE_CURVE_ID_SECP256R1:
        case PH_KEYSTORE_CURVE_ID_BRAINPOOL256R1:
            *pKeyLen = PH_KEYSTORE_KEY_TYPE_ECC_256_SIZE;
            break;

        case PH_KEYSTORE_CURVE_ID_SECP384R1:
        case PH_KEYSTORE_CURVE_ID_BRAINPOOL384R1:
            *pKeyLen = PH_KEYSTORE_KEY_TYPE_ECC_384_SIZE;
            break;

        default:
            *pKeyLen = 0;
            break;
    }

    /* Copy the Key to parameter. */
    switch(wKeyPairType)
    {
        case PH_KEYSTORE_KEY_PAIR_PRIVATE:
            if(!(pKeyPair->wKeyPairType & PH_KEYSTORE_KEY_PAIR_PRIVATE))
            {
                return PH_ADD_COMPCODE_FIXED(PH_ERR_INVALID_PARAMETER, PH_COMP_KEYSTORE);
            }

            (void) memcpy(pKey, pKeyPair->pKey, *pKeyLen);
            break;

        case PH_KEYSTORE_KEY_PAIR_PUBLIC:
            if(!(pKeyPair->wKeyPairType & PH_KEYSTORE_KEY_PAIR_PUBLIC))
            {
                return PH_ADD_COMPCODE_FIXED(PH_ERR_INVALID_PARAMETER, PH_COMP_KEYSTORE);
            }

            *pKeyLen = (uint16_t) ((*pKeyLen * 2) + 1 );
            (void) memcpy(pKey, pKeyPair->pPubKey, *pKeyLen);
            break;

        default:
            return PH_ADD_COMPCODE_FIXED(PH_ERR_INVALID_PARAMETER, PH_COMP_KEYSTORE);
    }

    return PH_ERR_SUCCESS;
}

phStatus_t phKeyStore_Sw_GetCurveID(phKeyStore_Sw_DataParams_t * pDataParams, uint16_t wKeyNo, uint16_t wPos, uint8_t * pCurveID)
{
    phStatus_t wStatus;
    phKeyStore_Sw_KeyVersionPair_t * pKeyPair;

    /* Get the pointer based on KeyNo. */
    PH_CHECK_SUCCESS_FCT(wStatus, phKeyStore_Sw_GetKeyValuePtrPos(pDataParams, wKeyNo, wPos, &pKeyPair));

    /* Check if Key Loaded is of ECC Key Type. */
    if(pDataParams->pKeyEntries[wKeyNo].wKeyType != PH_KEYSTORE_KEY_TYPE_ECC)
    {
        return PH_ADD_COMPCODE(PH_ERR_INVALID_PARAMETER, PH_COMP_KEYSTORE);
    }

    *pCurveID = pKeyPair->bCurveID;

    return PH_ERR_SUCCESS;
}
#endif /* NXPBUILD__PH_KEYSTORE_ASYM */

phStatus_t phKeyStore_Sw_GetKeyValuePtrPos(phKeyStore_Sw_DataParams_t * pDataParams, uint16_t wKeyNo, uint16_t wPos,
    phKeyStore_Sw_KeyVersionPair_t ** pKeyVersion)
{
    *pKeyVersion = NULL;
    /* Overflow checks */
    if(wKeyNo >= pDataParams->wNoOfKeyEntries)
    {
        return PH_ADD_COMPCODE_FIXED(PH_ERR_INVALID_PARAMETER, PH_COMP_KEYSTORE);
    }

    /* Overflow checks */
    if(wPos >= pDataParams->wNoOfVersions)
    {
        return PH_ADD_COMPCODE_FIXED(PH_ERR_INVALID_PARAMETER, PH_COMP_KEYSTORE);
    }

    *pKeyVersion = &pDataParams->pKeyVersionPairs[(((uint16_t)(((uint32_t)wKeyNo * pDataParams->wNoOfVersions)) & 0xFFFF) + wPos)];

    return PH_ERR_SUCCESS;
}

#endif /* NXPBUILD__PH_KEYSTORE_SW */
