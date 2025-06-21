/*----------------------------------------------------------------------------*/
/* Copyright 2016-2019, 2024 NXP                                              */
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
* Internal functions of Software implementation of MIFARE Ntag42XDna application layer.
* $Author: NXP $
* $Revision: $ (v07.13.00)
* $Date: $
*/

#ifndef PHALMFNTAG42XDNA_INT_H
#define PHALMFNTAG42XDNA_INT_H

#include <ph_Status.h>
#include <phalMfNtag42XDna.h>

/** \addtogroup ph_Private
 * @{
 */

/** \name NTAG 42x DNA / TT Native Commands */
/* @{ */
#define PHAL_MFNTAG42XDNA_CMD_AUTHENTICATE_EV2_FIRST                    0x71U   /**< MFNTAG42XDNA Authenticate Ev2 First command. */
#define PHAL_MFNTAG42XDNA_CMD_AUTHENTICATE_EV2_NON_FIRST                0x77U   /**< MFNTAG42XDNA Authenticate Ev2 Non First command. */
#define PHAL_MFNTAG42XDNA_CMD_CHANGE_KEY                                0xC4U   /**< MFNTAG42XDNA Change key cmd. */
#define PHAL_MFNTAG42XDNA_CMD_GET_KEY_VERSION                           0x64U   /**< MFNTAG42XDNA Get Key Version. */
#define PHAL_MFNTAG42XDNA_CMD_GET_VERSION                               0x60U   /**< MFNTAG42XDNA Get Version cmd. */
#define PHAL_MFNTAG42XDNA_CMD_SET_CONFIG                                0x5CU   /**< MFNTAG42XDNA Set Configuration Cmd. */
#define PHAL_MFNTAG42XDNA_CMD_GET_CARD_UID                              0x51U   /**< MFNTAG42XDNA Get Card UID cmd. */
#define PHAL_MFNTAG42XDNA_CMD_GET_FILE_SETTINGS                         0xF5U   /**< MFNTAG42XDNA Get File settings cmd. */
#define PHAL_MFNTAG42XDNA_CMD_GET_FILE_COUNTERS                         0xF6U   /**< MFNTAG42XDNA Get File Counters cmd. */
#define PHAL_MFNTAG42XDNA_CMD_GET_TAG_TAMPER_STATUS                     0xF7U   /**< MFNTAG42XDNA Get Tag Tamper Status cmd. */
#define PHAL_MFNTAG42XDNA_CMD_CHANGE_FILE_SETTINGS                      0x5FU   /**< MFNTAG42XDNA Change file settings cmd. */
#define PHAL_MFNTAG42XDNA_CMD_READ_DATA                                 0xBDU   /**< MFNTAG42XDNA Read Data cmd. */
#define PHAL_MFNTAG42XDNA_CMD_READ_DATA_ISO                             0xADU   /**< MFNTAG42XDNA Read Data cmd using ISO chaining. */
#define PHAL_MFNTAG42XDNA_CMD_WRITE_DATA                                0x3DU   /**< MFNTAG42XDNA Write data cmd. */
#define PHAL_MFNTAG42XDNA_CMD_WRITE_DATA_ISO                            0x8DU   /**< MFNTAG42XDNA Write data cmd using ISO chaining. */
#define PHAL_MFNTAG42XDNA_CMD_READ_SIG                                  0x3CU   /**< MFNTAG42XDNA Verify read signature command. */
/* @} */

/** \name NTAG 42x DNA / TT ISO7816 Commands */
/* @{ */
#define PHAL_MFNTAG42XDNA_CMD_ISO7816_SELECT_FILE                       0xA4U   /**< ISO Select File. */
#define PHAL_MFNTAG42XDNA_CMD_ISO7816_READ_BINARY                       0xB0U   /**< ISO Read Binary. */
#define PHAL_MFNTAG42XDNA_CMD_ISO7816_UPDATE_BINARY                     0xD6U   /**< ISO UPDATE Binary. */
/* @} */

/** \name NTAG 42x DNA / TT Native Response Codes */
/* @{ */
#define PHAL_MFNTAG42XDNA_RESP_OPERATION_OK                             0x00U   /**< MFNTAG42XDNA Response - Successful operation. */
#define PHAL_MFNTAG42XDNA_RESP_OK                                       0x90U   /**< MFNTAG42XDNA Response - Successful operation. */
#define PHAL_MFNTAG42XDNA_RESP_ERR_FORMAT                               0x0CU   /**< MFNTAG42XDNA Format Error. */
#define PHAL_MFNTAG42XDNA_RESP_ERR_CMD_INVALID                          0x0BU   /**< MFNTAG42XDNA Invalid Command Error. */
#define PHAL_MFNTAG42XDNA_RESP_ERR_OUT_OF_EEPROM_ERROR                  0x0EU   /**< MFNTAG42XDNA Response - Insufficient NV-Memory. */
#define PHAL_MFNTAG42XDNA_RESP_ILLEGAL_COMMAND_CODE                     0x1CU   /**< MFNTAG42XDNA command code not supported. */
#define PHAL_MFNTAG42XDNA_RESP_ERR_INTEGRITY_ERROR                      0x1EU   /**< MFNTAG42XDNA CRC or MAC does not match data padding bytes not valid. */
#define PHAL_MFNTAG42XDNA_RESP_NO_SUCH_KEY                              0x40U   /**< MFNTAG42XDNA Invalid key number specified. */
#define PHAL_MFNTAG42XDNA_RESP_CHAINING                                 0x71U   /**< MFNTAG42XDNA ISO Chaining Status. */
#define PHAL_MFNTAG42XDNA_RESP_ERR_LENGTH_ERROR                         0x7EU   /**< MFNTAG42XDNA Length of command string invalid. */
#define PHAL_MFNTAG42XDNA_RESP_PERMISSION_DENIED                        0x9DU   /**< MFNTAG42XDNA Current configuration/status does not allow the requested command. */
#define PHAL_MFNTAG42XDNA_RESP_ERR_PARAMETER_ERROR                      0x9EU   /**< MFNTAG42XDNA Value of params invalid. */
#define PHAL_MFNTAG42XDNA_RESP_APPLICATION_NOT_FOUND                    0xA0U   /**< MFNTAG42XDNA Requested AID not found on PICC. */
#define PHAL_MFNTAG42XDNA_RESP_ERR_APPL_INTEGRITY_ERROR                 0xA1U   /**< MFNTAG42XDNA Unrecoverable error within application, appln will be disabled. */
#define PHAL_MFNTAG42XDNA_RESP_ERR_AUTHENTICATION_ERROR                 0xAEU   /**< MFNTAG42XDNA Current authentication status does not allow the requested cmd. */
#define PHAL_MFNTAG42XDNA_RESP_ERR_AUTHENTICATION_DELAY                 0xADU   /**< Keep Waiting till Delay is met. */
#define PHAL_MFNTAG42XDNA_RESP_ADDITIONAL_FRAME                         0xAFU   /**< MFNTAG42XDNA Additional data frame is expected to be sent. */
#define PHAL_MFNTAG42XDNA_RESP_ERR_BOUNDARY_ERROR                       0xBEU   /**< MFNTAG42XDNA Attempt to read/write data from/to beyond the files/record's limits. */
#define PHAL_MFNTAG42XDNA_RESP_ERR_PICC_INTEGRITY                       0xC1U   /**< MFNTAG42XDNA Unrecoverable error within PICC. PICC will be disabled. */
#define PHAL_MFNTAG42XDNA_RESP_ERR_COMMAND_ABORTED                      0xCAU   /**< MFNTAG42XDNA Previous cmd not fully completed. Not all frames were requested or provided by the PCD. */
#define PHAL_MFNTAG42XDNA_RESP_ERR_PIC_DISABLED                         0xCDU   /**< MFNTAG42XDNA PICC was disabled by an unrecoverable error. */
#define PHAL_MFNTAG42XDNA_RESP_ERR_COUNT                                0xCEU   /**< MFNTAG42XDNA Num. of applns limited to 28. No additional applications possible. */
#define PHAL_MFNTAG42XDNA_RESP_ERR_DUPLICATE                            0xDEU   /**< MFNTAG42XDNA File/Application with same number already exists. */
#define PHAL_MFNTAG42XDNA_RESP_ERR_EEPROM                               0xEEU   /**< MFNTAG42XDNA Could not complete NV-Write operation due to loss of power. */
#define PHAL_MFNTAG42XDNA_RESP_ERR_FILE_NOT_FOUND                       0xF0U   /**< MFNTAG42XDNA Specified file number does not exist. */
#define PHAL_MFNTAG42XDNA_RESP_ERR_FILE_INTEGRITY                       0xF1U   /**< MFNTAG42XDNA Unrecoverable error within file. File will be disabled. */
/* @} */

/** \name NTAG 42x DNA / TT Native Response Codes */
/* @{ */
#define PHAL_MFNTAG42XDNA_ISO7816_SUCCESS                               0x9000U /**< Correct execution. */
#define PHAL_MFNTAG42XDNA_ISO7816_ERR_WRONG_LENGTH                      0x6700U /**< Wrong length. */
#define PHAL_MFNTAG42XDNA_ISO7816_ERR_WRONG_PARAMS                      0x6A86U /**< Wrong parameters P1 and/or P2. */
#define PHAL_MFNTAG42XDNA_ISO7816_ERR_WRONG_LC                          0x6A87U /**< Lc inconsistent with P1/p2. */
#define PHAL_MFNTAG42XDNA_ISO7816_ERR_WRONG_LE                          0x6C00U /**< Wrong Le. */
#define PHAL_MFNTAG42XDNA_ISO7816_ERR_NO_PRECISE_DIAGNOSTICS            0x6F00U /**< No precise diagnostics. */
#define PHAL_MFNTAG42XDNA_ISO7816_ERR_EOF_REACHED                       0x6282U /**< End of File reached. */
#define PHAL_MFNTAG42XDNA_ISO7816_ERR_LIMITED_FUNCTIONALITY_INS         0x6283U /**< Limited Functionality. */
#define PHAL_MFNTAG42XDNA_ISO7816_ERR_FILE_ACCESS                       0x6982U /**< File access not allowed. */
#define PHAL_MFNTAG42XDNA_ISO7816_ERR_FILE_EMPTY                        0x6985U /**< File empty or access conditions not satisfied. */
#define PHAL_MFNTAG42XDNA_ISO7816_ERR_FILE_NOT_FOUND                    0x6A82U /**< File not found. */
#define PHAL_MFNTAG42XDNA_ISO7816_ERR_MEMORY_FAILURE                    0x6581U /**< Memory failure (unsuccessful update). */
#define PHAL_MFNTAG42XDNA_ISO7816_ERR_INCORRECT_PARAMS                  0x6B00U /**< Wrong parameter p1 or p2. READ RECORDS. */
#define PHAL_MFNTAG42XDNA_ISO7816_ERR_WRONG_CLA                         0x6E00U /**< Wrong Class byte. */
#define PHAL_MFNTAG42XDNA_ISO7816_ERR_UNSUPPORTED_INS                   0x6D00U /**< Instruction not supported. */
/* @} */

/**
 * @}
 */

#define PHAL_MFNTAG42XDNA_WRAP_HDR_LEN                                  0x05U   /* Wrapped APDU header length */
#define PHAL_MFNTAG42XDNA_WRAPPEDAPDU_CLA                               0x90U   /* Wrapped APDU default class. */
#define PHAL_MFNTAG42XDNA_WRAPPEDAPDU_P1                                0x00U   /* Wrapped APDU default P1. */
#define PHAL_MFNTAG42XDNA_WRAPPEDAPDU_P2                                0x00U   /* Wrapped APDU default P2. */
#define PHAL_MFNTAG42XDNA_WRAPPEDAPDU_LE                                0x00U   /* Wrapped APDU default LE. */

#define PHAL_MFNTAG42XDNA_TRUNCATED_MAC_SIZE                            8u      /**< Size of the truncated MAC. */
#define PHAL_MFNTAG42XDNA_ISO_CHAINING_MODE                             0x04U   /**< Option to enable ISO chaining. */
#define PHAL_MFNTAG42XDNA_DEFAULT_MODE                                  0x00U   /**< Native Chaining. */
#define PHAL_MFNTAG42XDNA_SIG_LENGTH                                    0x38U   /**< NXP Originality Signature length */
#define PHAL_MFNTAG42XDNA_DEFAULT_UID_LENGTH                            0x07U   /**< By default EV2 card is configures as 7 byte UID */
#define PHAL_MFNTAG42XDNA_10B_UID_LENGTH                                0x09U   /**< EV2 can also be configured as 10 byte UID. */
#define PHAL_MFNTAG42XDNA_4B_UID_LENGTH                                 0x06U   /**< EV2 can also be configured as 4 byte UID. */
#define PHAL_MFNTAG42XDNA_SDM_FILE_CTR_LENGTH                           0x05U   /**< SDMReadCounter(3B) + reserved(2B) */
#define PHAL_MFNTAG42XDNA_DEF_VERSION_LENGTH                            0x1CU   /**< Version String is of 28 bytes by default(If its 7 Byte UID) */
#define PHAL_MFNTAG42XDNA_VERSION_LENGTH_WITH_FABKEY_ID                 0x1DU   /**< Version String is of 29 bytes by default(If its 7 Byte UID) */
#define PHAL_MFNTAG42XDNA_TAG_TAMPER_LENGTH                             0x02U   /**< TT PermStatus(1B) + TT CurrStatus(1B) */
#define PHAL_MFNTAG42XDNA_10B_VERSION_LENGTH                            0x1EU   /**< Version String is of 30 bytes If its 10B Byte UID */
#define PHAL_MFNTAG42XDNA_4B_VERSION_LENGTH                             0x1BU   /**< Version String is of 27 bytes If its 4B Byte UID */
#define PHAL_MFNTAG42XDNA_ISO_CHAINING_MODE_MAPPED  (PHAL_MFNTAG42XDNA_ISO_CHAINING_MODE << 2)  /**< Option to enable ISO chaining mapped for internal use. */

#define PHAL_MFNTAG42XDNA_MAXWRAPPEDAPDU_SIZE                           0x37u   /**< Maximum size of wrapped APDU 55 bytes. */
#define PHAL_MFNTAG42XDNA_MAXDFAPDU_SIZE                                0x3Cu   /**< Maximum size of DESFire APDU 60 bytes. */
#define PHAL_MFNTAG42XDNA_MAX_FRAME_SIZE                                0x40u   /**< Max size in a ISO 14443-4 frame. */

/* To avoid unused variable warnings. */
#define PHAL_MFNTAG42XDNA_UNUSED_VARIABLE(x)  {for( ( x ) = ( x ) ; ( x ) != ( x ) ; );}
#define PHAL_MFNTAG42XDNA_UNUSED_ARRAY(x)  {for( ( (x)[0] ) = ( (x)[0] ) ; ( (x)[0] ) != ( (x)[0] ) ; );}

#define PHAL_MFNTAG42XDNA_SDM_FILE_ID                                   0x02U   /*< MFNTAG42XDNA File Id where NDEF data is stored. */
#define PHAL_MFNTAG42XDNA_STANDARD_FILE_ID                              0x01U   /*< MFNTAG42XDNA File Id standard data is stored. */
#define PHAL_MFNTAG42XDNA_PLAIN_MIRRORING                               0x0EU   /*< Plain Mirroring. */
#define PHAL_MFNTAG42XDNA_NO_SDM_FOR_READING                            0x0FU   /*< No SDM For Reading. */
#define PHAL_MFNTAG42XDNA_METADATARANGE                                 0x04U   /*< Plain Mirroring. */

phStatus_t phalMfNtag42XDna_ExchangeCmd(void * pDataParams, void * pPalMifareDataParams, uint8_t bWrappedMode, uint8_t * pCmd,
    uint16_t wCmdLen, uint8_t ** ppResponse, uint16_t * wRxlen);

phStatus_t phalMfNtag42XDna_Int_ComputeErrorResponse(void * pDataParams, uint16_t wStatus);

phStatus_t phalMfNtag42XDna_Int_Send7816Apdu(void * pDataParams, void * pPalMifareDataParams, uint8_t bOption, uint8_t bIns,
    uint8_t p1, uint8_t p2, uint32_t Lc, uint8_t bExtendedLenApdu, uint8_t * pDataIn, uint32_t bLe, uint8_t ** pDataOut,
    uint16_t *pDataLen);

phStatus_t phalMfNtag42XDna_Int_ISOSelectFile(void * pDataParams, void * pPalMifareDataParams, uint8_t bOption, uint8_t * bCmdBuff,
    uint16_t wCmdLen, uint8_t bLc, uint8_t bExtendedLenApdu, uint8_t * pDataIn, uint8_t bLe, uint8_t ** ppDataOut, uint16_t *pDataLen);

phStatus_t phalMfNtag42XDna_Int_ISOUpdateBinary(void * pDataParams, void * pPalMifareDataParams, uint8_t bOption, uint8_t * bCmdBuff,
    uint16_t wCmdLen, uint32_t dwLc, uint8_t bExtendedLenApdu, uint8_t * pDataIn, uint8_t ** ppDataOut, uint16_t *pDataLen);

#endif /* PHALMFNTAG42XDNA_INT_H */
