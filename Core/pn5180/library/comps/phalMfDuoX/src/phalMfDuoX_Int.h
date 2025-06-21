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

#ifndef PHALMFDUOX_INT_H
#define PHALMFDUOX_INT_H

#include <ph_Status.h>

#ifdef NXPBUILD__PHAL_MFDUOX

/* Validate Diversification Options */
#define PHAL_MFDUOX_VALIDATE_DIVERSIFICATION_OPTIONS(Option)                        \
    switch(Option)                                                                  \
    {                                                                               \
        case PHAL_MFDUOX_NO_DIVERSIFICATION:                                        \
        case PH_CRYPTOSYM_DIV_MODE_DESFIRE:                                         \
        case PH_CRYPTOSYM_DIV_MODE_MIFARE_PLUS:                                     \
            break;                                                                  \
                                                                                    \
        default:                                                                    \
            return PH_ADD_COMPCODE(PH_ERR_KEY, PH_COMP_AL_MFDUOX);                  \
    }

/* Validate Diversification Length */
#define PHAL_MFDUOX_VALIDATE_DIVERSIFICATION_LENGTH(Option, Length)                 \
    if ((wOption != PHAL_MFDUOX_NO_DIVERSIFICATION) &&                              \
        (Length > PHAL_MFDUOX_DIV_INPUT_LEN_MAX))                                   \
    {                                                                               \
        return PH_ADD_COMPCODE(PH_ERR_INVALID_PARAMETER, PH_COMP_AL_MFDUOX);        \
    }

/* Validate Application Keys */
#define IS_INVALID_APP_KEY(KeyNo) (((KeyNo) & 0x7f) > 0x0D)

/* Validate Keytype. */
#define PHAL_MFDUOX_VALIDATE_KEYTYPE(KeyType)                                       \
    switch(KeyType)                                                                 \
    {                                                                               \
        case PH_KEYSTORE_KEY_TYPE_AES128:                                           \
        case PH_KEYSTORE_KEY_TYPE_AES256:                                           \
            break;                                                                  \
                                                                                    \
        default:                                                                    \
            return PH_ADD_COMPCODE(PH_ERR_KEY, PH_COMP_AL_MFDUOX);                  \
    }

#define PHAL_MFDUOX_NEAREST_MULTIPLE(Number, OutVar)                                \
    OutVar = ( ( ( Number + PH_CRYPTOSYM_AES_BLOCK_SIZE - 1 ) /                     \
                PH_CRYPTOSYM_AES_BLOCK_SIZE ) * PH_CRYPTOSYM_AES_BLOCK_SIZE )

#define PHAL_MFDUOX_IS_NOT_MULTIPLE_AES_BLOCK_SIZE(Number)                          \
    (Number == 0) ? 1 : (Number / PH_CRYPTOSYM_AES_BLOCK_SIZE)

#define PHAL_MFDUOX_IS_MULTIPLE_AES_BLOCK_SIZE(Number)                              \
    !(Number % PH_CRYPTOSYM_AES_BLOCK_SIZE)

#define PHAL_MFCC_AES_BLOCK_SIZE_DIFF(Value)                                        \
    (((Value > PH_CRYPTOSYM_AES_BLOCK_SIZE) ? PH_CRYPTOSYM_AES256_KEY_SIZE          \
        : PH_CRYPTOSYM_AES128_KEY_SIZE) - Value)

#define PHAL_MFDUOX_PREVIOUS_MULTIPLE(Number, OutVar)                               \
    OutVar = (PHAL_MFDUOX_IS_MULTIPLE_AES_BLOCK_SIZE(Number) ? Number :             \
             ((((Number + PH_CRYPTOSYM_AES_BLOCK_SIZE - 1) /                        \
             PH_CRYPTOSYM_AES_BLOCK_SIZE) * PH_CRYPTOSYM_AES_BLOCK_SIZE) -          \
             PH_CRYPTOSYM_AES_BLOCK_SIZE))

#define PHAL_MFDUOX_VERIFY_STATUS(DataParams, Status, FncRet)                       \
    {                                                                               \
        (Status) = (FncRet);                                                        \
        if ((Status) != PH_ERR_SUCCESS)                                             \
        {                                                                           \
            phalMfDuoX_Sw_ResetAuthentication(DataParams);                          \
            return Status;                                                          \
        }                                                                           \
    }

#define PHAL_MFDUOX_ABS(Val1, Val2)                                                 \
    ((Val1) > (Val2) ? (Val1 - Val2) : (Val2 - Val1))

/* Validate File Number. */
#define PHAL_MFDUOX_IS_VALID_FILE_NO(FileNo)                                        \
    if((FileNo & 0x7f) > 0x1f)                                                      \
    {                                                                               \
        return PH_ADD_COMPCODE(PH_ERR_INVALID_PARAMETER, PH_COMP_AL_MFDUOX);        \
    }

/* Validate File Options. */
#define PHAL_MFDUOX_VALIDATE_FILE_OPTIONS(FileOptions)                              \
    /* Validate communication modes. */                                             \
    switch(FileOptions & 0x03)                                                      \
    {                                                                               \
        case PHAL_MFDUOX_FILE_OPTION_PLAIN:                                         \
        case PHAL_MFDUOX_FILE_OPTION_MAC:                                           \
        case PHAL_MFDUOX_FILE_OPTION_FULL:                                          \
            break;                                                                  \
                                                                                    \
        default:                                                                    \
            return PH_ADD_COMPCODE(PH_ERR_INVALID_PARAMETER, PH_COMP_AL_MFDUOX);    \
    }

/* Validate Exchange Options. */
#define PHAL_MFDUOX_VALIDATE_TX_EXCHANGE_OPTIONS(Option)                            \
    /* Validate communication modes. */                                             \
    switch(Option)                                                                  \
    {                                                                               \
        case PH_EXCHANGE_DEFAULT:                                                   \
        case PH_EXCHANGE_TXCHAINING:                                                \
            break;                                                                  \
                                                                                    \
        default:                                                                    \
            return PH_ADD_COMPCODE(PH_ERR_INVALID_PARAMETER, PH_COMP_AL_MFDUOX);    \
    }

/* Validate Exchange Options. */
#define PHAL_MFDUOX_VALIDATE_RX_EXCHANGE_OPTIONS(Option)                            \
    /* Validate communication modes. */                                             \
    switch(Option)                                                                  \
    {                                                                               \
        case PH_EXCHANGE_DEFAULT:                                                   \
        case PH_EXCHANGE_RXCHAINING:                                                \
            break;                                                                  \
                                                                                    \
        default:                                                                    \
            return PH_ADD_COMPCODE(PH_ERR_INVALID_PARAMETER, PH_COMP_AL_MFDUOX);    \
    }

/* Validate Chaining Options. */
#define PHAL_MFDUOX_VALIDATE_CHAINING_OPTIONS(Option)                               \
    /* Validate communication modes. */                                             \
    switch(Option)                                                                  \
    {                                                                               \
        case PHAL_MFDUOX_CHAINING_NATIVE:                                           \
        case PHAL_MFDUOX_CHAINING_ISO:                                              \
        case PHAL_MFDUOX_CHAINING_ISO_SHORT_LEN:                                    \
            break;                                                                  \
                                                                                    \
        default:                                                                    \
            return PH_ADD_COMPCODE(PH_ERR_INVALID_PARAMETER, PH_COMP_AL_MFDUOX);    \
    }

/* Validate APDU Format. */
#define PHAL_MFDUOX_VALIDATE_APDU_FORMAT(ApduForamt)                                \
    switch(ApduForamt)                                                              \
    {                                                                               \
        case PHAL_MFDUOX_APDU_FORMAT_SHORT_LEN:                                     \
        case PHAL_MFDUOX_APDU_FORMAT_EXTENDED_LEN:                                  \
            break;                                                                  \
                                                                                    \
        default:                                                                    \
            return PH_ADD_COMPCODE(PH_ERR_INVALID_PARAMETER, PH_COMP_AL_MFDUOX);    \
    }

/* Validate Application Options */
#define PHAL_MFDUOX_VALIDATE_APP_ISO_OPTIONS(Option)                                \
    if((bOption & 0x7FU) > PHAL_MFDUOX_ISO_FILE_ID_DF_NAME_AVAILABLE)               \
    {                                                                               \
        return PH_ADD_COMPCODE(PH_ERR_INVALID_PARAMETER, PH_COMP_AL_MFDUOX);        \
    }

/* Validate DMMAC Options */
#define PHAL_MFDUOX_VALIDATE_DAMMAC_OPTIONS(Options)                                \
    switch(Options & 0xF0)                                                          \
    {                                                                               \
        case PHAL_MFDUOX_GENERATE_DAMMAC_CREATE_DELEGATED_APPLICATION:              \
        case PHAL_MFDUOX_GENERATE_DAMMAC_DELETE_APPLICATION:                        \
            break;                                                                  \
                                                                                    \
        default:                                                                    \
            return PH_ADD_COMPCODE(PH_ERR_INVALID_PARAMETER, PH_COMP_AL_MFDUOX);    \
    }

/* Validate Curve ID. */
#define PHAL_MFDUOX_VALIDATE_CURVE(CurveID)                                         \
    switch(CurveID)                                                                 \
    {                                                                               \
        case PHAL_MFDUOX_TARGET_CURVE_ID_NIST_P256:                                 \
        case PHAL_MFDUOX_TARGET_CURVE_ID_BRAINPOOL_P256R1:                          \
            break;                                                                  \
                                                                                    \
        default:                                                                    \
            return PH_ADD_COMPCODE(PH_ERR_KEY, PH_COMP_AL_MFDUOX);                  \
    }

#define PHAL_MFDUOX_MAX_PADDING_LEN                                             16U     /**< Maximum Padding data that can be used while performing Encryption. */
#define PHAL_MFDUOX_TRUNCATED_MAC_LEN                                           8U      /**< Size of truncated MAC information. */
#define PHAL_MFDUOX_DATA_TO_READ_UNKNOWN                                        0U      /**< For all the internal Read Operation calls where Data to be read is not known. */

/** MIFARE DUOX command options. This flag will be used to compute the response. */
#define PHAL_MFDUOX_OPTION_NONE                                                 0x00U   /**< Command option as None. This flag is used to discard
                                                                                         *   the processing of reception from PICC.
                                                                                         */
#define PHAL_MFDUOX_OPTION_COMPLETE                                             0x01U   /**< Command option as complete. This flag is used to check the response other than AF. */
#define PHAL_MFDUOX_OPTION_PENDING                                              0x02U   /**< Command option as complete. This flag is used to check for AF response. */

#define PHAL_MFDUOX_NO_RETURN_PLAIN_DATA                                        0x00U   /**< No Return plain data from SM application interface in case if communication mode is PLAIN. */
#define PHAL_MFDUOX_RETURN_PLAIN_DATA                                           0x04U   /**< Return plain data from SM application interface in case if communication mode is PLAIN. */
#define PHAL_MFDUOX_RETURN_PICC_STATUS                                          0x10U   /**< Return the PICC status to the caller. */
#define PHAL_MFDUOX_RETURN_CHAINING_STATUS                                      0x20U   /**< Return the chaining status to the user if available. */
#define PHAL_MFDUOX_EXCLUDE_PICC_STATUS                                         0x40U   /**< Exclude removal of status code from actual response length. */
#define PHAL_MFDUOX_PICC_STATUS_WRAPPED                                         0x80U   /**< The PICC status is wrapped. */

#define PHAL_MFDUOX_CHAINING_BIT_INVALID                                         0xFFU   /**< Invalid Option. */
#define PHAL_MFDUOX_CHAINING_BIT_DISABLE                                         0x00U   /**< Disable PAL ISO14443 chaining bit if required. */
#define PHAL_MFDUOX_CHAINING_BIT_ENABLE                                          0x01U   /**< Enable PAL ISO14443 chaining bit if required. */

#define PHAL_MFDUOX_AUTH_ISO_INTERNAL_AUTH_DO_HDR_TAG                           0x7C    /**< Tag data for ISOInternal Authenticate AuthDOHdr information. */
#define PHAL_MFDUOX_AUTH_ISO_INTERNAL_RND_TAG                                   0x81    /**< Tag data for ISOInternal Authenticate RndA / RndB information. */
#define PHAL_MFDUOX_AUTH_ISO_INTERNAL_SIGNATURE_TAG                             0x82    /**< Tag data for ISOInternal Authenticate Signature information. */

#define PHAL_MFDUOX_COMMUNICATION_INVALID                                       0xFFU   /**< Communication mode invalid or not known. */
#define PHAL_MFDUOX_CMD_INVALID                                                 0xFFU   /**< INVALID Command code. */
#define PHAL_MFDUOX_PICC_STATUS_INVALID                                         0xFFU   /**< INVALID Status Code to update the PICC response parameter. This is for internal purpose. */
#define PHAL_MFDUOX_ADDITIONAL_FRAME                                            0xAFU   /**< Command / Response code for Additional Frame. */
#define PHAL_MFDUOX_WRAPPED_HDR_LEN_NORMAL                                      0x05    /**< ISO7816 Header length. */
#define PHAL_MFDUOX_WRAPPED_HDR_LEN_EXTENDED                                    0x07    /**< ISO7816 Header length in Extended Mode. */
#define PHAL_MFDUOX_ISO7816_GENERIC_CLA                                         0x00U   /**< Class for Generic ISO7816 commands. */
#define PHAL_MFDUOX_ISO7816_EV_CHARGING_CLA                                     0x80U   /**< Class for EV Charging Command. */
#define PHAL_MFDUOX_WRAPPEDAPDU_CLA                                             0x90U   /**< Wrapped APDU code for class. */
#define PHAL_MFDUOX_WRAPPEDAPDU_P1                                              0x00U   /**< Wrapped APDU code for default P1. */
#define PHAL_MFDUOX_WRAPPEDAPDU_P2                                              0x00U   /**< Wrapped APDU code for default P2. */
#define PHAL_MFDUOX_WRAPPEDAPDU_LC                                              0x00U   /**< Wrapped APDU code for default LC. */
#define PHAL_MFDUOX_WRAPPEDAPDU_LE                                              0x00U   /**< Wrapped APDU code for default LE. */

#define PHAL_MFDUOX_LC_POS                                                      0x04    /**< Position of LC in ISO7816 format. */
#define PHAL_MFDUOX_EXCHANGE_LC_ONLY                                            0x01    /**< Option to indicate only LC should be exchanged to PICC and LE should not be exchanged. */
#define PHAL_MFDUOX_EXCHANGE_LE_ONLY                                            0x02    /**< Option to indicate only LE should be exchanged to PICC and LC should not be exchanged. */
#define PHAL_MFDUOX_EXCHANGE_LC_LE_BOTH                                         0x03    /**< Option to indicate both LC and LE should be exchanged to PICC. */

#define PHAL_MFDUOX_KEYSETT3_PRESENT                                            0x10U   /**< Bit 4 of bKeySettings2 decides the presence of the keysetting3. */
#define PHAL_MFDUOX_KEYSETVALUES_PRESENT                                        0x01U   /**< Bit 0 of bKeySettings3 decides the presence of the key set values array. */
#define PHAL_MFDUOX_COMM_OPTIONS_MASK                                           0xF0U   /**< Masking out communication options. */
#define PHAL_MFDUOX_OPTION_MASK                                                 0x7FU   /**< Masking out Options that will be used for \ref phalMfDuoX_CommitTransaction "CommitTransaction" interface. */
#define PHAL_MFDUOX_CRLFILE_MASK                                                0x01U   /**< Masking out CRLFile option from command's option information. */

#define PHAL_MFDUOX_PRODUCT_CMD                                                 0x00U   /**< Option to indicate MIFARE DUOX product commands. */
#define PHAL_MFDUOX_ISO7816_APDU_CMD                                            0x01U   /**< Option to indicate MIFARE DUOX product's Standard ISO7816 APDU commands. */

#define PHAL_MFDUOX_SESSION_MAC                                                 0x01U   /**< Session key option for Macing of data. */
#define PHAL_MFDUOX_SESSION_ENC                                                 0x02U   /**< Session key option for Encryption / Decryption of data. */

/* BER-TLV Length Constants. */
#define PHAL_MFDUOX_ISO7816_BER_TLV_L_NO_CONST                                  0x01U   /**< BER-TLV constant length formats to total of 1 bytes which includes only length information upto 127 bytes. */

#define PHAL_MFDUOX_ISO7816_BER_TLV_C_81                                        0x81U   /**< BER-TLV constant length data if information to be exchanged is between 00 to 255 bytes. */
#define PHAL_MFDUOX_ISO7816_BER_TLV_L_81                                        0x02U   /**< BER-TLV constant length formats to total of 2 bytes which includes Constant and Actual Length. */

#define PHAL_MFDUOX_ISO7816_BER_TLV_C_82                                        0x82U   /**< BER-TLV constant length data if information to be exchanged is between 0000 to 65535 bytes. */
#define PHAL_MFDUOX_ISO7816_BER_TLV_L_82                                        0x03U   /**< BER-TLV constant length formats to total of 3 bytes which includes Constant and Actual Length. */

/* EV Charging command Constants. */
#define PHAL_MFDUOX_EV_CHARGING_VDE_WRITE_DATA_P1                               0x06    /**<  Parameter 1 for VDE_WriteData command of EV Charging commands. */
#define PHAL_MFDUOX_EV_CHARGING_VDE_ECDSA_SIGN_P1                               0x0C    /**<  Parameter 1 for VDE_ECDSASign command of EV Charging commands. */
#define PHAL_MFDUOX_EV_CHARGING_VDE_ECDSA_SIGN_P2                               0x09    /**<  Parameter 2 for VDE_ECDSASign command of EV Charging commands. */

/**
 * \addtogroup phalMfDuoX_SecureMessaging_Defines
 * @{
 */

/**
 * \defgroup phalMfDuoX_SecureMessaging_Defines_CommandCodes CommandCodes
 * @{
 */
#define PHAL_MFDUOX_CMD_AUTHENTICATE_ISO_INTERNAL                               0x88    /**< MIFARE DUOX ISOInternal Authenticate command Code. */
/**
 * end of group phalMfDuoX_SecureMessaging_Defines_CommandCodes
 * @}
 */

/**
 * end of group phalMfDuoX_SecureMessaging_Defines
 * @}
 */

/**
 * \addtogroup phalMfDuoX_MemoryConfiguration_Defines
 * @{
 */

/**
 * \defgroup phalMfDuoX_MemoryConfiguration_Defines_CommandCodes CommandCodes
 * @{
 */
#define PHAL_MFDUOX_CMD_FREE_MEM                                                0x6E    /**< MIFARE DUOX Free Memory command Code. */
#define PHAL_MFDUOX_CMD_GET_VERSION                                             0x60    /**< MIFARE DUOX GetVersion command code. */
/**
 * end of group phalMfDuoX_MemoryConfiguration_Defines_CommandCodes
 * @}
 */

/**
 * end of group phalMfDuoX_MemoryConfiguration_Defines
 * @}
 */

/**
 * \addtogroup phalMfDuoX_Symm_KeyManagement_Defines
 * @{
 */

/**
 * \defgroup phalMfDuoX_Symm_KeyManagement_Defines_CommandCodes CommandCodes
 * @{
 */
#define PHAL_MFDUOX_CMD_GET_KEY_SETTINGS                                        0x45    /**< MIFARE DUOX GetKeySettings command code. */
/**
 * end of group phalMfDuoX_Symm_KeyManagement_Defines_CommandCodes
 * @}
 */

/**
 * end of group phalMfDuoX_Symm_KeyManagement_Defines
 * @}
 */

/**
 * \addtogroup phalMfDuoX_ASymm_KeyManagement_Defines
 * @{
 */

/**
 * \defgroup phalMfDuoX_ASymm_KeyManagement_Defines_CommandCodes CommandCodes
 * @{
 */
#define PHAL_MFDUOX_CMD_MANAGE_KEY_PAIR                                         0x46    /**< MIFARE DUOX ManageKeyPair command code. */
#define PHAL_MFDUOX_CMD_MANAGE_CA_ROOT_KEY                                      0x48    /**< MIFARE DUOX ManageCARootKey command code. */
#define PHAL_MFDUOX_CMD_MANAGE_EXPORT_KEY                                       0x47    /**< MIFARE DUOX ExportKey command code. */
/**
 * end of group phalMfDuoX_ASymm_KeyManagement_Defines_CommandCodes
 * @}
 */

/**
 * end of group phalMfDuoX_ASymm_KeyManagement_Defines
 * @}
 */

/**
 * \addtogroup phalMfDuoX_ApplicationManagement_Defines
 * @{
 */

/**
 * \defgroup phalMfDuoX_ApplicationManagement_Defines_CommandCodes CommandCodes
 * @{
 */
#define PHAL_MFDUOX_CMD_CREATE_APPLICATION                                      0xCA    /**< MIFARE DUOX Create Application command code. */
#define PHAL_MFDUOX_CMD_DELETE_APPLICATION                                      0xDA    /**< MIFARE DUOX Delete Application command code. */
#define PHAL_MFDUOX_CMD_SELECT_APPLICATION                                      0x5A    /**< MIFARE DUOX Select Application command code. */
#define PHAL_MFDUOX_CMD_GET_APPLICATION_IDS                                     0x6A    /**< MIFARE DUOX Get Application Ids command code. */
#define PHAL_MFDUOX_CMD_GET_DF_NAMES                                            0x6D    /**< MIFARE DUOX Get Dedicated File names command code. */
/**
 * end of group phalMfDuoX_ApplicationManagement_Defines_CommandCodes
 * @}
 */

/**
 * end of group phalMfDuoX_ApplicationManagement_Defines
 * @}
 */

/**
 * \addtogroup phalMfDuoX_FileManagement_Defines
 * @{
 */

/**
 * \defgroup phalMfDuoX_FileManagement_Defines_CommandCodes CommandCodes
 * @{
 */
#define PHAL_MFDUOX_CMD_CREATE_STANDARD_DATA_FILE                               0xCD    /**< MIFARE DUOX Create Standard Data File command code. */
#define PHAL_MFDUOX_CMD_CREATE_BACKUP_DATA_FILE                                 0xCB    /**< MIFARE DUOX Create Backup Data File command code. */
#define PHAL_MFDUOX_CMD_CREATE_VALUE_FILE                                       0xCC    /**< MIFARE DUOX Create Value File command code. */
#define PHAL_MFDUOX_CMD_CREATE_LINEAR_RECORD_FILE                               0xC1    /**< MIFARE DUOX Create Linear Record File command code. */
#define PHAL_MFDUOX_CMD_CREATE_CYCLIC_RECORD_FILE                               0xC0    /**< MIFARE DUOX Create Cyclic Record File command code. */
#define PHAL_MFDUOX_CMD_CREATE_DELETE_FILE                                      0xDF    /**< MIFARE DUOX Create Delete File command code. */
#define PHAL_MFDUOX_CMD_GET_FILE_IDS                                            0x6F    /**< MIFARE DUOX Create Get File ID's command code. */
#define PHAL_MFDUOX_CMD_GET_ISO_FILE_IDS                                        0x61    /**< MIFARE DUOX Create Get ISO File ID's command code. */
#define PHAL_MFDUOX_CMD_GET_FILE_SETTINGS                                       0xF5    /**< MIFARE DUOX Create Get File Settings command code. */
#define PHAL_MFDUOX_CMD_GET_FILE_COUNTERS                                       0xF6    /**< MIFARE DUOX Create Get File Counters command code. */
#define PHAL_MFDUOX_CMD_CHANGE_FILE_SETTINGS                                    0x5F    /**< MIFARE DUOX Create Change File Settings command code. */
/**
 * end of group phalMfDuoX_FileManagement_Defines_CommandCodes
 * @}
 */

/**
 * end of group phalMfDuoX_FileManagement_Defines
 * @}
 */

/**
 * \addtogroup phalMfDuoX_DataManagement_Defines
 * @{
 */

/**
 * \defgroup phalMfDuoX_DataManagement_Defines_CommandCodes CommandCodes
 * @{
 */
#define PHAL_MFDUOX_CMD_READ_DATA_NATIVE                                        0xBD    /**< MIFARE DUOX Read Data command code in Native chaining format. */
#define PHAL_MFDUOX_CMD_READ_DATA_ISO                                           0xAD    /**< MIFARE DUOX Read Data command code in ISO/IEC 14443-4 chaining format. */
#define PHAL_MFDUOX_CMD_WRITE_DATA_NATIVE                                       0x3D    /**< MIFARE DUOX Write Data command code in Native chaining format. */
#define PHAL_MFDUOX_CMD_WRITE_DATA_ISO                                          0x8D    /**< MIFARE DUOX Write Data command code in ISO/IEC 14443-4 chaining format. */
#define PHAL_MFDUOX_CMD_GET_VALUE                                               0x6C    /**< MIFARE DUOX Get Value command code. */
#define PHAL_MFDUOX_CMD_CREDIT                                                  0x0C    /**< MIFARE DUOX Credit command code. */
#define PHAL_MFDUOX_CMD_DEBIT                                                   0xDC    /**< MIFARE DUOX Debit command code. */
#define PHAL_MFDUOX_CMD_LIMITED_CREDIT                                          0x1C    /**< MIFARE DUOX LimitedCredit command code. */
#define PHAL_MFDUOX_CMD_READ_RECORD_NATIVE                                      0xBB    /**< MIFARE DUOX Read Records command code in Native chaining format. */
#define PHAL_MFDUOX_CMD_READ_RECORD_ISO                                         0xAB    /**< MIFARE DUOX Read Records command code in ISO/IEC 14443-4 chaining format. */
#define PHAL_MFDUOX_CMD_WRITE_RECORD_NATIVE                                     0x3B    /**< MIFARE DUOX Write Record command code in Native chaining format. */
#define PHAL_MFDUOX_CMD_WRITE_RECORD_ISO                                        0x8B    /**< MIFARE DUOX Write Record command code in ISO/IEC 14443-4 chaining format. */
#define PHAL_MFDUOX_CMD_UPDATE_RECORD_NATIVE                                    0xDB    /**< MIFARE DUOX Update Record command code in Native chaining format. */
#define PHAL_MFDUOX_CMD_UPDATE_RECORD_ISO                                       0xBA    /**< MIFARE DUOX Update Record command code in ISO/IEC 14443-4 chaining format. */
#define PHAL_MFDUOX_CMD_CLEAR_RECORD                                            0xEB    /**< MIFARE DUOX Clear Record command code. */
/**
 * end of group phalMfDuoX_DataManagement_Defines_CommandCodes
 * @}
 */

/**
 * end of group phalMfDuoX_DataManagement_Defines
 * @}
 */

/**
 * \addtogroup phalMfDuoX_TransactionManagement_Defines
 * @{
 */

/**
 * \defgroup phalMfDuoX_TransactionManagement_Defines_CommandCodes CommandCodes
 * @{
 */
#define PHAL_MFDUOX_CMD_COMMIT_TRANSACTION                                      0xC7    /**< MIFARE DUOX Commit Transaction command code. */
#define PHAL_MFDUOX_CMD_ABORT_TRANSACTION                                       0xA7    /**< MIFARE DUOX Abort Transaction command code. */
#define PHAL_MFDUOX_CMD_COMMIT_READER_ID                                        0xC8    /**< MIFARE DUOX Commit ReaderID command code. */
/**
 * end of group phalMfDuoX_TransactionManagement_Defines_CommandCodes
 * @}
 */

/**
 * end of group phalMfDuoX_TransactionManagement_Defines
 * @}
 */

/**
 * \addtogroup phalMfDuoX_CryptographicSupport_Defines
 * @{
 */

/**
 * \defgroup phalMfDuoX_CryptographicSupport_Defines_CommandCodes CommandCodes
 * @{
 */
#define PHAL_MFDUOX_CMD_CRYPTO_REQUEST                                          0x4C    /**< MIFARE DUOX Crypto Request command code. */
#define PHAL_MFDUOX_CMD_CRYPTO_REQUEST_ECCSIGN                                  0x4C    /**< MIFARE DUOX Crypto Request DUOX Sign command code. */
#define PHAL_MFDUOX_CMD_CRYPTO_REQUEST_ECHO                                     0x4C    /**< MIFARE DUOX Crypto Request Echo command code. */
/**
 * end of group phalMfDuoX_CryptographicSupport_Defines_CommandCodes
 * @}
 */

/**
 * end of group phalMfDuoX_CryptographicSupport_Defines
 * @}
 */

/**
 * \addtogroup phalMfDuoX_GPIOManagement_Defines
 * @{
 */

/**
 * \defgroup phalMfDuoX_GPIOManagement_Defines_CommandCodes CommandCodes
 * @{
 */
#define PHAL_MFDUOX_CMD_MANAGE_GPIO                                             0x42    /**< MIFARE DUOX Manage GPIO command code. */
#define PHAL_MFDUOX_CMD_READ_GPIO                                               0x43    /**< MIFARE DUOX Read GPIO command code. */
/**
 * end of group phalMfDuoX_GPIOManagement_Defines_CommandCodes
 * @}
 */

/**
 * end of group phalMfDuoX_GPIOManagement_Defines
 * @}
 */

/**
 * \addtogroup phalMfDuoX_ISO7816_Defines
 * @{
 */

/**
 * \defgroup phalMfDuoX_ISO7816_Defines_CommandCodes CommandCodes
 * @{
 */
#define PHAL_MFDUOX_CMD_ISO7816_SELECT_FILE                                     0xA4    /**< MIFARE DUOX ISOSelectFile command of ISO7816-4 Standard. */
#define PHAL_MFDUOX_CMD_ISO7816_READ_BINARY                                     0xB0    /**< MIFARE DUOX ISOReadBinary command of ISO7816-4 Standard. */
#define PHAL_MFDUOX_CMD_ISO7816_UPDATE_BINARY                                   0xD6    /**< MIFARE DUOX ISOUpdateBinary command of ISO7816-4 Standard. */
#define PHAL_MFDUOX_CMD_ISO7816_READ_RECORD                                     0xB2    /**< MIFARE DUOX ISOReadRecord command of ISO7816-4 Standard. */
#define PHAL_MFDUOX_CMD_ISO7816_APPEND_RECORD                                   0xE2    /**< MIFARE DUOX ISOAppendRecord command of ISO7816-4 Standard. */
#define PHAL_MFDUOX_CMD_ISO7816_GET_CHALLENGE                                   0x84    /**< MIFARE DUOX ISOGetChallenge command of ISO7816-4 Standard. */
/**
 * end of group phalMfDuoX_ISO7816_Defines_CommandCodes
 * @}
 */

/**
 * end of group phalMfDuoX_ISO7816_Defines
 * @}
 */

/**
 * \addtogroup phalMfDuoX_EV_Defines
 * @{
 */

/**
 * \defgroup phalMfDuoX_EV_Defines_CommandCodes CommandCodes
 * @{
 */
#define PHAL_MFDUOX_CMD_VDE_READ_DATA                                           0x02    /**< MIFARE DUOX VDE_ReadData command code of EV Charging commands. */
#define PHAL_MFDUOX_CMD_VDE_WRITE_DATA                                          0x01    /**< MIFARE DUOX VDE_WriteData command code of EV Charging commands. */
#define PHAL_MFDUOX_CMD_VDE_ECDSA_SIGN                                          0x03    /**< MIFARE DUOX VDE_ECDSASign command code of EV Charging commands. */
/**
 * end of group phalMfDuoX_EV_Defines_CommandCodes
 * @}
 */

/**
 * end of group phalMfDuoX_EV_Defines
 * @}
 */

phStatus_t phalMfDuoX_Int_ComputeErrorResponse(void * pDataParams, uint16_t wStatus);

phStatus_t phalMfDuoX_Int_Validate_ComOption(uint8_t bComOption);

phStatus_t phalMfDuoX_Int_GetCmdCode(void * pDataParams, uint8_t * pCmdCode);

phStatus_t phalMfDuoX_Int_SetCmdCode(void * pDataParams, uint8_t bCmdCode);

void phalMfDuoX_Int_RotateLeft(uint8_t * pData, uint8_t bDataLen, uint8_t bTimes);

void phalMfDuoX_Int_RotateRight(uint8_t * pData, uint8_t bDataLen, uint8_t bTimes);

void phalMfDuoX_Int_GetCommMode(uint8_t bAuthState, uint8_t bOption, uint8_t * pCommMode);

void phalMfDuoX_Int_EncodeBER_TLV_Len(uint16_t wLen, uint8_t * pBuffer, uint16_t * pBuffLen);

phStatus_t phalMfDuoX_Int_DecodeBER_TLV_Len(uint8_t ** ppBuffer, uint16_t * pBER_TLV_Len, uint16_t * pRspLen);

void phalMfDuoX_Int_UpdateLC(uint8_t * pData, uint16_t wDataLen, uint8_t bLE_Available, uint8_t bLE_Len);

#endif /* NXPBUILD__PHAL_MFDUOX */

#endif /* PHALMFDUOX_INT_H */
