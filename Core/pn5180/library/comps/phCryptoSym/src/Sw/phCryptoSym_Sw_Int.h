/*----------------------------------------------------------------------------*/
/* Copyright 2009, 2024 NXP                                                   */
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
* Internal functions for SW functionality of the Symmetric Cryptography component.
* $Author: NXP $
* $Revision: $ (v07.13.00)
* $Date: $
*
*/

#ifndef PHCRYPTOSYM_SW_INT_H
#define PHCRYPTOSYM_SW_INT_H

#include <ph_Status.h>
#include <phCryptoSym.h>

/** \defgroup phCryptoSym_Sw_Internals Internals
* \brief Internal Functions of the Symmetric Cryptography component.
* @{
*/

/* CMAC Key diversification method defines */
#define PH_CRYPTOSYM_SW_KDIV_MFP_AES128_CONST       0x01U
#define PH_CRYPTOSYM_SW_KDIV_MFP_AES192_CONST_1     0x11U
#define PH_CRYPTOSYM_SW_KDIV_MFP_AES192_CONST_2     0x12U
#define PH_CRYPTOSYM_SW_KDIV_MFP_AES256_CONST_1     0x41U
#define PH_CRYPTOSYM_SW_KDIV_MFP_AES256_CONST_2     0x42U
#define PH_CRYPTOSYM_SW_KDIV_MFP_3DES_CONST_1       0x21U
#define PH_CRYPTOSYM_SW_KDIV_MFP_3DES_CONST_2       0x22U
#define PH_CRYPTOSYM_SW_KDIV_MFP_3KEY3DES_CONST_1   0x31U
#define PH_CRYPTOSYM_SW_KDIV_MFP_3KEY3DES_CONST_2   0x32U
#define PH_CRYPTOSYM_SW_KDIV_MFP_3KEY3DES_CONST_3   0x33U
#define PH_CRYPTOSYM_SW_KDIV_MFUL_AES128_CONST      0x02U
#define PH_CRYPTOSYM_SW_KDIV_MFP_DIVLENGTH_AES_MAX  31U
#define PH_CRYPTOSYM_SW_KDIV_MFP_DIVLENGTH_DES_MAX  15U
/**
* \brief Generic interface function for encryption of a single AES/DES data block.
* \return Status code
* \retval #PH_ERR_SUCCESS Operation successful.
* \retval #PH_ERR_INVALID_PARAMETER Unknown key type currently loaded.
*/
phStatus_t phCryptoSym_Sw_EncryptBlock(
                                       phCryptoSym_Sw_DataParams_t * pDataParams,   /**< [In] Pointer to this layers parameter structure. */
                                       uint8_t PH_CRYTOSYM_SW_FAST_RAM * pBlock     /**< [InOut] IO buffer for the data block to perform the encryption on. */
                                       );

/**
* \brief Generic interface function for decryption of a single AES/DES data block.
* \return Status code
* \retval #PH_ERR_SUCCESS Operation successful.
* \retval #PH_ERR_INVALID_PARAMETER Unknown key type currently loaded.
*/
phStatus_t phCryptoSym_Sw_DecryptBlock(
                                       phCryptoSym_Sw_DataParams_t * pDataParams,   /**< [In] Pointer to this layers parameter structure. */
                                       uint8_t PH_CRYTOSYM_SW_FAST_RAM * pBlock     /**< [InOut] IO buffer for the data block to perform the decryption on. */
                                       );

/**
* \brief Implements the left shift according to CMAC standard.
* \return Status code
* \retval #PH_ERR_SUCCESS Operation successful.
*/
void phCryptoSym_Sw_CMAC_LeftShift(
                                   const uint8_t * pInBuffer,   /**< [In] Array containing the input buffer to be shifted. */
                                   uint8_t bInputLen,           /**< [In] Length of the input buffer. */
                                   uint8_t * pOutBuffer         /**< [Out] Array containing the output buffer where the shifted value is stored. */
                                   );
/**
* \brief Implements sub key generation according to CMAC standard.
* Implementation according to SUBK(K) section 6 of NIST SP_800-38B
* \return Status code
* \retval #PH_ERR_SUCCESS Operation successful.
* \retval #PH_ERR_INTERNAL_ERROR Unsupported block length.
*/
phStatus_t phCryptoSym_Sw_CMAC_GenerateK1K2(
    phCryptoSym_Sw_DataParams_t * pDataParams,  /**< [In] Pointer to this layers parameter structure. */
    uint8_t * pSubKey1,                         /**< [Out] Destination pointer for CMAC subkey 1 */
    uint8_t * pSubKey2                          /**< [Out] Destination pointer for CMAC subkey 2 */
    );

/**
* \brief Calculate CMAC for Key diversification
*
* \return Status code
* \retval #PH_ERR_SUCCESS Operation successful.
* \retval #PH_ERR_INVALID_PARAMETER wDataLength is larger than double the current block size.
* \retval #PH_ERR_INVALID_PARAMETER An unsupported key is loaded (or no key is loaded).
*/
phStatus_t phCryptoSym_Sw_Diversify_CMAC(
    phCryptoSym_Sw_DataParams_t * pDataParams,  /**< [In] Pointer to this layers parameter structure. */
    const uint8_t * pData,                      /**< [In] Input data; uint8_t[wDataLength]. */
    uint16_t  wDataLength,                      /**< [In] Number of input data bytes. */
    uint8_t * pMac,                             /**< [Out] Output MAC block; uint8_t[16]. */
    uint8_t * pMacLength                        /**< [Out] Length of MAC. */
    );

/** @}
* end of phCryptoSym_Sw_Internals group
*/

#endif /* PHCRYPTOSYM_SW_INT_H */
