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
* Generic MIFARE DUOX Application Component of Reader Library Framework.
* $Author: NXP $
* $Revision: $ (v07.13.00)
* $Date: $
*
*/

#ifndef PHALMFDUOX_H
#define PHALMFDUOX_H

#include <ph_Status.h>
#include <ph_TypeDefs.h>
#include <ph_RefDefs.h>
#include <phTMIUtils.h>

#ifdef NXPBUILD__PH_CRYPTOSYM
#include <phCryptoSym.h>
#endif /* NXPBUILD__PH_CRYPTOSYM */

#include <phhalHw.h>
#include <phpalMifare.h>

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

#ifdef NXPBUILD__PHAL_MFDUOX
/**
 * \addtogroup phalMfDuoX_CommonDefs
 * @{
 */

/**
 * \defgroup phalMfDuoX_Defines_BufferSize Buffer Size
 * @{
 */
#define PHAL_MFDUOX_ISO_DFNAME_LEN                                                          16U /**< Maximum ISO DFName length. */
#define PHAL_MFDUOX_BLOCK_SIZE                                                              16U /**< Block Size to be used while performing TMICollection. */
#define PHAL_MFDUOX_APP_ID_LEN                                                              3U  /**< Maximum Application Identifier length. */
#define PHAL_MFDUOX_CMD_BUFFER_SIZE_MINIMUM                                             256U    /**< Minimum size for allocating the command buffer during initializing.
                                                                                                 *   Based on the platform, the value should not go below 128 to avoid issues.
                                                                                                 */
#define PHAL_MFDUOX_PRS_BUFFER_SIZE_MINIMUM                                             512U    /**< Minimum size for allocating the response / SM processing buffer during initializing.
                                                                                                 *   Based on the platform, the value should not go below 128 to avoid issues.
                                                                                                 */
#define PHAL_MFDUOX_MAX_NATIVE_DATA_LEN                                                 64U     /**< Maximum length of data that can be passed to Pal ISO14443-4 layer for Application Chaining. */
/**
 * end of group phalMfDuoX_Defines_BufferSize
 * @}
 */

/**
 * end of group phalMfDuoX_CommonDefs
 * @}
 */
#endif /* NXPBUILD__PHAL_MFDUOX */

/***************************************************************************************************************************************/
/* Software DataParams and Initialization Interface.                                                                                   */
/***************************************************************************************************************************************/
#ifdef NXPBUILD__PHAL_MFDUOX_SW

/**
 * \defgroup phalMfDuoX_Sw Component : Software
 * \brief Software implementation of the MIFARE DUOX commands. Here the MIFARE DUOX commands are framed and
 * exchanged to PICC.
 * @{
 */

#define PHAL_MFDUOX_SW_ID                                                               0x01U   /**< ID for Software MIFARE DUOX layer. */

/** \brief Data structure for MIFARE DUOX Software layer implementation  */
typedef struct
{
    uint16_t wId;                                                                               /**< Layer ID for this component, NEVER MODIFY! */
    void * pPalMifareDataParams;                                                                /**< Pointer to the parameter structure of the palMifare component. */
    void * pKeyStoreDataParams;                                                                 /**< Pointer to the parameter structure of the KeyStore layer. */
    void * pCryptoDataParamsASym;                                                               /**< Pointer to the parameter structure of the ASymmetric Crypto component. */
    void * pCryptoDataParamsEnc;                                                                /**< Pointer to the parameter structure of the Symmetric Crypto layer for encryption. */
    void * pCryptoDataParamsMac;                                                                /**< Pointer to the parameter structure of the Symmetric Crypto layer for MACing. */
    void * pCryptoRngDataParams;                                                                /**< Pointer to the parameter structure of the Crypto layer for Random number generation. */
#ifdef NXPBUILD__PH_TMIUTILS
    void * pTMIDataParams;                                                                      /**< Pointer to the parameter structure for collecting TMI. */
#endif /* NXPBUILD__PH_TMIUTILS */
#ifdef NXPBUILD__PHAL_VCA
    void * pVCADataParams;                                                                      /**< Pointer to the parameter structure for Virtual Card. */
#endif /* NXPBUILD__PHAL_VCA */
    uint8_t * pCmdBuf;                                                                          /**< Pointer to global buffer for processing the command. */
    uint16_t wCmdBufSize;                                                                       /**< Size of global command buffer. */
    uint16_t wCmdBufLen;                                                                        /**< Length of bytes available in command buffer (\ref pCmdBuf) for processing. */
    uint16_t wCmdBufOffset;                                                                     /**< Command Buffer offset while performing crypto or exchange operations. */
    uint8_t * pPrsBuf;                                                                          /**< Pointer to global buffer for processing the response / secure messaging information. */
    uint16_t wPrsBufSize;                                                                       /**< Size of global response / secure messaging information buffer. */
    uint16_t wPrsBufLen;                                                                        /**< Length of bytes available in response / secure messaging information buffer (\ref pPrsBuf) for processing. */
    uint16_t wPrsBufOffset;                                                                     /**< Processing Buffer offset while performing crypto or exchange operations. */
    uint8_t aAid[3];                                                                            /**< Aid of the currently selected application */
    uint16_t wCmdCtr;                                                                           /**< Command count within transaction. */
    uint16_t wAdditionalInfo;                                                                   /**< Specific error codes for MIFARE DUOX generic errors or To get the response length of some commands. */
    uint8_t bWrappedMode;                                                                       /**< Wrapped APDU mode. All native commands need to be sent wrapped in ISO 7816 APDUs. */
    uint8_t bShortLenApdu;                                                                      /**< Parameter for force set Short Length APDU in case of BIG ISO read. */
    uint8_t bCmdCode;                                                                           /**< Command code. This will be used for differentiating the same error codes for different commands. */
    uint8_t bAuthState;                                                                         /**< Authenticate Command used. One of the below values will be updated
                                                                                                 *      - \ref PHAL_MFDUOX_NOT_AUTHENTICATED "Not Authenticated" \n
                                                                                                 */
    uint8_t bKeyNo;                                                                             /**< Key number against which this authentication is done */
    uint16_t wKeyType;                                                                          /**< Key Type being used for Authentication. */
    uint8_t bPICCDataComplete;                                                                  /**< Flag to Indicate PICC data Status. Indicates the following.
                                                                                                 *      - PICC Data is complete but there is still more data that needs to be provided to user.
                                                                                                 *      - PICC Data is complete and there is no data to be given to user, but last encrypted chunk
                                                                                                 *        needs to be verified.
                                                                                                 */
} phalMfDuoX_Sw_DataParams_t;

/**
 * \brief Initialization API for MIFARE DUOX software component.
 *
 * \return Status code
 * \retval #PH_ERR_SUCCESS Operation successful.
 * \retval #PH_ERR_INVALID_DATA_PARAMS
 *          - If the input size doest not match the DataParams size of this component.
 *          - If any of the DataParams are null.
 * \retval #PH_ERR_INVALID_PARAMETER If the buffers are null.
 * \retval #PH_ERR_PARAMETER_SIZE
 *          - If the buffer size is less than minimum.
 *          - If command buffer (\b wCmdBufSize) is higher than processing buffer (\b wPrsBufSize).
 */
phStatus_t phalMfDuoX_Sw_Init(
        phalMfDuoX_Sw_DataParams_t * pDataParams,                                               /**< [In] Pointer to this layer's parameter structure. */
        uint16_t wSizeOfDataParams,                                                             /**< [In] Specifies the size of the data parameter structure */
        void * pPalMifareDataParams,                                                            /**< [In] Pointer to a palMifare component context. */
        void * pKeyStoreDataParams,                                                             /**< [In] Pointer to Key Store data parameters. */
        void * pCryptoDataParamsASym,                                                           /**< [In] Pointer to the parameter structure of the ASymmetric Crypto component. */
        void * pCryptoDataParamsEnc,                                                            /**< [In] Pointer to Symmetric Crypto component context for encryption. */
        void * pCryptoDataParamsMac,                                                            /**< [In] Pointer to Symmetric Crypto component context for MACing. */
        void * pCryptoRngDataParams,                                                            /**< [In] Pointer to a CryptoRng component context. */
        void * pTMIDataParams,                                                                  /**< [In] Pointer to a TMI component. */
        void * pVCADataParams,                                                                  /**< [In] Pointer to a VCA component. */
        uint8_t * pCmdBuf,                                                                      /**< [In] Pointer to global buffer for processing the command. */
        uint16_t wCmdBufSize,                                                                   /**< [In] Size of global command buffer. Should be >= \ref PHAL_MFDUOX_CMD_BUFFER_SIZE_MINIMUM
                                                                                                 *        "Minimum Command Buffer Size"
                                                                                                 */
        uint8_t * pPrsBuf,                                                                      /**< [In] Pointer to global buffer for processing the response / secure messaging information. */
        uint16_t wPrsBufSize                                                                    /**< [In] Size of global response / secure messaging buffer.
                                                                                                 *        Should be >= \ref PHAL_MFDUOX_PRS_BUFFER_SIZE_MINIMUM "Minimum Processing Buffer Size"
                                                                                                 */
    );

/**
 * \brief Initialization API for MIFARE DUOX software component.
 *
 * \return Status code
 * \retval #PH_ERR_SUCCESS Operation successful.
 * \retval #PH_ERR_INVALID_DATA_PARAMS  If any of the DataParams are null.
 * \retval XXXX                         Other Depending on implementation and underlying component.
 */
phStatus_t phalMfDuoX_Sw_DeInit(
        phalMfDuoX_Sw_DataParams_t * pDataParams                                                /**< [In] Pointer to this layer's parameter structure. */
    );

/**
 * end of group phalMfDuoX_Sw
 * @}
 */

#endif /* NXPBUILD__PHAL_MFDUOX_SW */

/***************************************************************************************************************************************/
/* MIFARE DUOX Generic interface declarations.                                                                                          */
/***************************************************************************************************************************************/
#ifdef NXPBUILD__PHAL_MFDUOX

/** \addtogroup phalMfDuoX
 * \brief This is only a wrapper layer to abstract the different MIFARE DUOX implementations.
 * With this wrapper it is possible to support more than one MIFARE DUOX implementation
 * in parallel, by adapting this wrapper.
 *
 * \note
 *      - Below are the initializations supported by this component.
 *          - \ref phalMfDuoX_Sw_Init "Software Initialization"
 *      - The AL component uses two internal buffers for processing. One is named as \ref phalMfDuoX_Sw_DataParams_t.pCmdBuf "Command Buffer" and
 *        another as \ref phalMfDuoX_Sw_DataParams_t.pPrsBuf "Processing Buffer".
 *      - Memory for these internal buffers needs to be passed by the user during initialization.
 *      - The internal buffer size should not be less than minimum. Minimum sizes are,
 *          - \ref phalMfDuoX_Sw_DataParams_t.pCmdBuf "Command Buffer", the \b wCmdBufSize should be >= \ref PHAL_MFDUOX_CMD_BUFFER_SIZE_MINIMUM
 *            "Minimum Command Buffer Size"
 *          - \ref phalMfDuoX_Sw_DataParams_t.pPrsBuf "Processing Buffer", the \b wPrsBufSize should be >= \ref PHAL_MFDUOX_PRS_BUFFER_SIZE_MINIMUM
 *            "Minimum Processing Buffer Size"
 *          - If the sizes are less than minimum, \ref PH_ERR_PARAMETER_SIZE "Parameter Size" error will be returned.
 *      - Processing buffer size should not be less than Command buffer size else \ref PH_ERR_PARAMETER_SIZE "Parameter Size" error will be returned.
 *      - After completion of the application, call below interfaces to clear all the internal buffers, its sizes, dependent components
 *        like CryptoSym and CryptASym etc...
 *          - \ref phalMfDuoX_Sw_DeInit "De-Initialize Software Component"
 *      - Its must to Initialize the component again after calling De-Initialization.
 *      - During Initialization of HAL component, make sure the transmit and response buffer size are not less than PICC frame size.
 *      - Call \ref phalMfDuoX_GetConfig "GetConfig" with \ref PHAL_MFDUOX_ADDITIONAL_INFO "Additional Information" as Configuration identifier
 *        when any of the interface returns \ref PHAL_MFDUOX_ERR_DF_GEN_ERROR "General Failure" or \ref PHAL_MFDUOX_ERR_DF_7816_GEN_ERROR
 *        "ISO7816 General Failure".
 *
 * @{
 */

/**
 * \defgroup phalMfDuoX_ErrorCode ErrorCodes
 * \brief Error Codes received from PICC and the equivalent Reader Library error codes.
 * @{
 */

/**
 * \defgroup phalMfDuoX_ErrorCodes_PICC ErrorCodes_PICC
 * \brief The actual error codes received from PICC. These codes are for reference purpose only.
 * All the interfaces will return codes mentioned in \ref phalMfDuoX_ErrorCodes_Mapped "Mapped Codes" and not these codes.
 * @{
 */

/**
 * \defgroup phalMfDuoX_ErrorCodes_PICC_Native Native
 * \brief MIFARE DUOX Native Response Codes.
 * @{
 */
#define PHAL_MFDUOX_RESP_OPERATION_OK                                                   0x00U   /**< MFDUOX Response - Successful operation.
                                                                                                 *   Equivalent mapped error code will be #PH_ERR_SUCCESS.
                                                                                                 */
#define PHAL_MFDUOX_RESP_OPERATION_OK_LIM                                               0x01U   /**< MFDUOX Response - Successful operation with limited functionality.
                                                                                                 *   Equivalent mapped error code will be #PHAL_MFDUOX_ERR_OPERATION_OK_LIM.
                                                                                                 */
#define PHAL_MFDUOX_RESP_OK                                                             0x90U   /**< MFDUOX Response - Successful operation.
                                                                                                 *   Equivalent mapped error code will be #PH_ERR_SUCCESS.
                                                                                                 */
#define PHAL_MFDUOX_RESP_NO_CHANGES                                                     0x0CU   /**< MFDUOX Response - No changes done to backup files.
                                                                                                 *   Equivalent mapped error code will be #PHAL_MFDUOX_ERR_NO_CHANGES.
                                                                                                 */
#define PHAL_MFDUOX_RESP_ERR_NOT_SUP                                                    0x0DU   /**< MFDUOX Response - Not Supported Error.
                                                                                                 *   Equivalent mapped error code will be #PHAL_MFDUOX_ERR_NOT_SUPPORTED.
                                                                                                 */
#define PHAL_MFDUOX_RESP_OUT_OF_EEPROM_ERROR                                            0x0EU   /**< MFDUOX Response - Insufficient NV-Memory.
                                                                                                 *   Equivalent mapped error code will be #PHAL_MFDUOX_ERR_OUT_OF_EEPROM.
                                                                                                 */
#define PHAL_MFDUOX_RESP_ILLEGAL_COMMAND_CODE                                           0x1CU   /**< MFDUOX Response - Command code not supported.
                                                                                                 *   Equivalent mapped error code will be #PHAL_MFDUOX_ERR_DF_GEN_ERROR.
                                                                                                 */
#define PHAL_MFDUOX_RESP_INTEGRITY_ERROR                                                0x1EU   /**< MFDUOX Response - CRC or MAC does not match data padding bytes not valid.
                                                                                                 *   Equivalent mapped error code will be #PHAL_MFDUOX_ERR_PICC_CRYPTO.
                                                                                                 */
#define PHAL_MFDUOX_RESP_WEAK_FIELD                                                     0x1FU   /**< MFDUOX Response - Field strength not sufficient to enable power harvesting
                                                                                                 *   for the targeted current/voltage level.
                                                                                                 *   Equivalent mapped error code will be #PHAL_MFDUOX_ERR_WEAK_FIELD.
                                                                                                 */
#define PHAL_MFDUOX_RESP_NO_SUCH_KEY                                                    0x40U   /**< MFDUOX Response - Invalid key number specified.
                                                                                                 *   Equivalent mapped error code will be #PHAL_MFDUOX_ERR_NO_SUCH_KEY.
                                                                                                 */
#define PHAL_MFDUOX_RESP_LENGTH_ERROR                                                   0x7EU   /**< MFDUOX Response - Length of command string invalid.
                                                                                                 *   Equivalent mapped error code will be #PH_ERR_LENGTH_ERROR.
                                                                                                 */
#define PHAL_MFDUOX_RESP_PERMISSION_DENIED                                              0x9DU   /**< MFDUOX Response - Current configuration/status does not allow the requested command.
                                                                                                 *   Equivalent mapped error code will be #PHAL_MFDUOX_ERR_PERMISSION_DENIED.
                                                                                                 */
#define PHAL_MFDUOX_RESP_PARAMETER_ERROR                                                0x9EU   /**< MFDUOX Response - Value of Parameter invalid.
                                                                                                 *   Equivalent mapped error code will be #PHAL_MFDUOX_ERR_PARAMETER_ERROR.
                                                                                                 */
#define PHAL_MFDUOX_RESP_APPLICATION_NOT_FOUND                                          0xA0U   /**< MFDUOX Response - Requested AID not found on PICC.
                                                                                                 *   Equivalent mapped error code will be #PHAL_MFDUOX_ERR_APPLICATION_NOT_FOUND.
                                                                                                 */
#define PHAL_MFDUOX_RESP_AUTHENTICATION_ERROR                                           0xAEU   /**< MFDUOX Response - Current authentication status does not allow the requested Command.
                                                                                                 *   Equivalent mapped error code will be #PH_ERR_AUTH_ERROR.
                                                                                                 */
#define PHAL_MFDUOX_RESP_ADDITIONAL_FRAME                                               0xAFU   /**< MFDUOX Response - Additional data frame is expected to be sent.
                                                                                                 *   Equivalent mapped error code will be #PH_ERR_SUCCESS_CHAINING.
                                                                                                 */
#define PHAL_MFDUOX_RESP_BOUNDARY_ERROR                                                 0xBEU   /**< MFDUOX Response - Attempt to read/write data from/to beyond the files/record's limits.
                                                                                                 *   Equivalent mapped error code will be #PHAL_MFDUOX_ERR_BOUNDARY_ERROR.
                                                                                                 */
#define PHAL_MFDUOX_RESP_COMMAND_ABORTED                                                0xCAU   /**< MFDUOX Response - Previous Command not fully completed. Not all frames were requested or
                                                                                                 *   provided by the PCD. Equivalent mapped error code will be #PHAL_MFDUOX_ERR_COMMAND_ABORTED.
                                                                                                 */
#define PHAL_MFDUOX_RESP_CERT_ERROR                                                     0xCEU   /**< MFDUOX Response - Reader certificate or CertAccessRights related error.
                                                                                                 *   Equivalent mapped error code will be #PHAL_MFDUOX_ERR_CERTIFICATE.
                                                                                                 */
#define PHAL_MFDUOX_RESP_DUPLICATE                                                      0xDEU   /**< MFDUOX Response - File/Application with same number already exists.
                                                                                                 *   Equivalent mapped error code will be #PHAL_MFDUOX_ERR_DUPLICATE.
                                                                                                 */
#define PHAL_MFDUOX_RESP_MEMORY_ERROR                                                   0xEEU   /**< MFDUOX Response - Could not complete NV-Write operation due to loss of power.
                                                                                                 *   Equivalent mapped error code will be #PHAL_MFDUOX_ERR_DF_GEN_ERROR.
                                                                                                 */
#define PHAL_MFDUOX_RESP_FILE_NOT_FOUND                                                 0xF0U   /**< MFDUOX Response - Specified file number does not exist.
                                                                                                 *   Equivalent mapped error code will be #PHAL_MFDUOX_ERR_FILE_NOT_FOUND.
                                                                                                 */
#define PHAL_MFDUOX_RESP_ERR_AUTH                                                       0x06U   /**< MFDUOX Response - Authentication error.
                                                                                                 *   Equivalent mapped error code will be #PH_ERR_AUTH_ERROR.
                                                                                                 */
#define PHAL_MFDUOX_RESP_ERR_CMD_OVERFLOW                                               0x07U   /**< MFDUOX Response - Too many commands in the session or transaction.
                                                                                                 *   Equivalent mapped error code will be #PHAL_MFDUOX_ERR_CMD_OVERFLOW.
                                                                                                 */
#define PHAL_MFDUOX_RESP_ERR_BNR                                                        0x09U   /**< MFDUOX Response - Invalid Block number: not existing in the implementation or not valid to
                                                                                                *    target with this command. Equivalent mapped error code will be #PHAL_MFDUOX_ERR_BNR.
                                                                                                */
#define PHAL_MFDUOX_RESP_ERR_CMD_INVALID                                                0x0BU   /**< MFDUOX Response - Command is received in a state where this command is not supported, or a
                                                                                                *    totally unknown command is received. Equivalent mapped error code will be #PHAL_MFDUOX_ERR_CMD_INVALID.
                                                                                                */
#define PHAL_MFDUOX_RESP_ERR_FORMAT                                                     0x0CU   /**< MFDUOX Response - Format of the command is not correct (e.g. too many or too few bytes).
                                                                                                 *   Equivalent mapped error code will be #PHAL_MFDUOX_ERR_FORMAT.
                                                                                                 */
#define PHAL_MFDUOX_RESP_ERR_GEN_FAILURE                                                0x0FU   /**< MFDUOX Response - Failure in the operation of the PD.
                                                                                                 *   Equivalent mapped error code will be #PHAL_MFDUOX_ERR_GEN_FAILURE.
                                                                                                 */
/**
 * end of group phalMfDuoX_ErrorCodes_PICC_Native
 * @}
 */

/**
 * \defgroup phalMfDuoX_ErrorCodes_PICC_Native_ISO7816 ISO7816
 * \brief MIFARE DUOX Native ISO 7816 Response Codes.
 *
 * @note
 *  - Equivalent mapped error code for #PHAL_MFDUOX_ISO7816_SUCCESS will be #PH_ERR_SUCCESS.
 *  - Equivalent mapped error code will be #PHAL_MFDUOX_ERR_DF_7816_GEN_ERROR for others.
 *    To know the exact PICC error codes, call \ref phalMfDuoX_GetConfig "GetConfig" with
 *    \ref PHAL_MFDUOX_ADDITIONAL_INFO "Additional Information" as Configuration identifier.
 * @{
 */
#define PHAL_MFDUOX_ISO7816_SUCCESS                                                     0x9000U /**< MFDUOX ISO7816 Response - Correct execution. */
#define PHAL_MFDUOX_ISO7816_ERR_PROTOCOL_VERSION                                        0x9F00U /**< MFDUOX ISO7816 Response - Correct execution. The last nibble specifies
                                                                                                 *   the maximum supported version.
                                                                                                 *      - 0x9F00 is for MIFARE DUOX
                                                                                                 *      - 0x9Fxx is for other protocol version
                                                                                                 *   \note
                                                                                                 *      - The protocol will be further executed, allowing the reader to
                                                                                                 *        seamless fall back to that version
                                                                                                 *      - To know the exact PICC status codes, call \ref phalMfDuoX_GetConfig
                                                                                                 *        "GetConfig" with \ref PHAL_MFDUOX_ADDITIONAL_INFO "Additional Information"
                                                                                                 *        as Configuration identifier.
                                                                                                 */
#define PHAL_MFDUOX_ISO7816_ERR_MEMORY_FAILURE                                          0x6581U /**< MFDUOX ISO7816 Response - Memory failure (unsuccessful update). */
#define PHAL_MFDUOX_ISO7816_ERR_WRONG_LENGTH                                            0x6700U /**< MFDUOX ISO7816 Response - Wrong length. */
#define PHAL_MFDUOX_ISO7816_ERR_INCORRECT_CMD_PARAMS                                    0x6A80U /**< MFDUOX ISO7816 Response - Incorrect parameters in the command data field. */
#define PHAL_MFDUOX_ISO7816_ERR_INVALID_APPLN                                           0x6A82U /**< MFDUOX ISO7816 Response - Application / file not found. */
#define PHAL_MFDUOX_ISO7816_ERR_WRONG_PARAMS                                            0x6A86U /**< MFDUOX ISO7816 Response - Wrong parameters P1 and or P2. */
#define PHAL_MFDUOX_ISO7816_ERR_WRONG_LC                                                0x6A87U /**< MFDUOX ISO7816 Response - LC inconsistent with P1/p2. */
#define PHAL_MFDUOX_ISO7816_ERR_WRONG_PARAMS_P2                                         0x6A88U /**< MFDUOX ISO7816 Response - Wrong parameters P2. */
#define PHAL_MFDUOX_ISO7816_ERR_WRONG_LE                                                0x6C00U /**< MFDUOX ISO7816 Response - Wrong Le. */
#define PHAL_MFDUOX_ISO7816_ERR_NO_PRECISE_DIAGNOSTICS                                  0x6F00U /**< MFDUOX ISO7816 Response - No precise diagnostics. */
#define PHAL_MFDUOX_ISO7816_ERR_EOF_REACHED                                             0x6282U /**< MFDUOX ISO7816 Response - End of File reached. */
#define PHAL_MFDUOX_ISO7816_ERR_FILE_ACCESS                                             0x6982U /**< MFDUOX ISO7816 Response - File access not allowed. */
#define PHAL_MFDUOX_ISO7816_ERR_REF_DATA_NOT_USABLE                                     0x6984U /**< MFDUOX ISO7816 Response - Reference data not usable. */
#define PHAL_MFDUOX_ISO7816_ERR_FILE_EMPTY                                              0x6985U /**< MFDUOX ISO7816 Response - File empty or access conditions not satisfied. */
#define PHAL_MFDUOX_ISO7816_ERR_FILE_NOT_FOUND                                          0x6A82U /**< MFDUOX ISO7816 Response - File not found. */
#define PHAL_MFDUOX_ISO7816_ERR_INCORRECT_PARAMS                                        0x6B00U /**< MFDUOX ISO7816 Response - Wrong parameter p1 or p2. READ RECORDS. */
#define PHAL_MFDUOX_ISO7816_ERR_WRONG_CLA                                               0x6E00U /**< MFDUOX ISO7816 Response - Wrong Class byte. */
#define PHAL_MFDUOX_ISO7816_ERR_UNSUPPORTED_INS                                         0x6D00U /**< MFDUOX ISO7816 Response - Instruction not supported. */
#define PHAL_MFDUOX_ISO7816_ERR_LIMITED_FUNCTIONALITY_INS                               0x6283U /**< MFDUOX ISO7816 Response - Limited Functionality. */
/**
 * end of group phalMfDuoX_ErrorCodes_PICC_Native_ISO7816
 * @}
 */

/**
 * end of group phalMfDuoX_ErrorCodes_PICC
 * @}
 */

/**
 * \defgroup phalMfDuoX_ErrorCodes_Mapped ErrorCodes_Mapped
 * \brief The error codes from Library with respect to PICC Error codes.
 * @{
 */
#define PHAL_MFDUOX_ERR_NO_CHANGES                                  (PH_ERR_CUSTOM_BEGIN + 0)   /**< MFDUOX Custom error code - No changes done to backup files.
                                                                                                 *   This error represents PICC's #PHAL_MFDUOX_RESP_NO_CHANGES error.
                                                                                                 */
#define PHAL_MFDUOX_ERR_OUT_OF_EEPROM                               (PH_ERR_CUSTOM_BEGIN + 1)   /**< MFDUOX Custom error code - Insufficient NV-Memory.
                                                                                                 *   This error represents PICC's #PHAL_MFDUOX_RESP_OUT_OF_EEPROM_ERROR error.
                                                                                                 */
#define PHAL_MFDUOX_ERR_NO_SUCH_KEY                                 (PH_ERR_CUSTOM_BEGIN + 2)   /**< MFDUOX Custom error code - Invalid key number specified.
                                                                                                 *   This error represents PICC's #PHAL_MFDUOX_RESP_NO_SUCH_KEY error.
                                                                                                 */
#define PHAL_MFDUOX_ERR_PERMISSION_DENIED                           (PH_ERR_CUSTOM_BEGIN + 3)   /**< MFDUOX Custom error code - Current configuration/wStatus does not allow the requested command.
                                                                                                 *   This error represents PICC's #PHAL_MFDUOX_RESP_PERMISSION_DENIED error.
                                                                                                 */
#define PHAL_MFDUOX_ERR_APPLICATION_NOT_FOUND                       (PH_ERR_CUSTOM_BEGIN + 4)   /**< MFDUOX Custom error code - Requested AID not found on PICC.
                                                                                                 *   This error represents PICC's #PHAL_MFDUOX_RESP_APPLICATION_NOT_FOUND error.
                                                                                                 */
#define PHAL_MFDUOX_ERR_BOUNDARY_ERROR                              (PH_ERR_CUSTOM_BEGIN + 5)   /**< MFDUOX Custom error code - Attempt to read/write data from/to beyond the files/record's limits.
                                                                                                 *   This error represents PICC's #PHAL_MFDUOX_RESP_BOUNDARY_ERROR error.
                                                                                                 */
#define PHAL_MFDUOX_ERR_COMMAND_ABORTED                             (PH_ERR_CUSTOM_BEGIN + 6)   /**< MFDUOX Custom error code - Previous command not fully completed. Not all frames were requested or
                                                                                                 *   provided by the PCD. This error represents PICC's #PHAL_MFDUOX_RESP_COMMAND_ABORTED error.
                                                                                                 */
#define PHAL_MFDUOX_ERR_DUPLICATE                                   (PH_ERR_CUSTOM_BEGIN + 7)   /**< MFDUOX Custom error code - File/Application with same number already exists.
                                                                                                 *   This error represents PICC's #PHAL_MFDUOX_RESP_DUPLICATE error.
                                                                                                 */
#define PHAL_MFDUOX_ERR_FILE_NOT_FOUND                              (PH_ERR_CUSTOM_BEGIN + 8)   /**< MFDUOX Custom error code - Specified file number does not exist.
                                                                                                 *   This error represents PICC's #PHAL_MFDUOX_RESP_FILE_NOT_FOUND error.
                                                                                                 */
#define PHAL_MFDUOX_ERR_PICC_CRYPTO                                 (PH_ERR_CUSTOM_BEGIN + 9)   /**< MFDUOX Custom error code - Crypto error returned by PICC.
                                                                                                 *   This error represents PICC's #PHAL_MFDUOX_RESP_INTEGRITY_ERROR error.
                                                                                                 */
#define PHAL_MFDUOX_ERR_PARAMETER_ERROR                             (PH_ERR_CUSTOM_BEGIN + 10)  /**< MFDUOX Custom error code - Parameter value error returned by PICC.
                                                                                                 *   This error represents PICC's #PHAL_MFDUOX_RESP_PARAMETER_ERROR error.
                                                                                                 */
#define PHAL_MFDUOX_ERR_DF_GEN_ERROR                                (PH_ERR_CUSTOM_BEGIN + 11)  /**< MFDUOX Custom error code - MIFARE DUOX Generic error.
                                                                                                 *   Refer \ref phalMfDuoX_GetConfig "GetConfig" with \ref PHAL_MFDUOX_ADDITIONAL_INFO
                                                                                                 *   "Additional Information" as config option to get the exact error code. This code
                                                                                                 *   will be returned for the below PICC Error codes.
                                                                                                 *      - #PHAL_MFDUOX_RESP_MEMORY_ERROR
                                                                                                 *      - #PHAL_MFDUOX_RESP_ILLEGAL_COMMAND_CODE
                                                                                                 */
#define PHAL_MFDUOX_ERR_DF_7816_GEN_ERROR                           (PH_ERR_CUSTOM_BEGIN + 12)  /**< MFDUOX Custom error code - MIFARE DUOX ISO 7816 Generic error.
                                                                                                 *   Refer \ref phalMfDuoX_GetConfig "GetConfig" with \ref PHAL_MFDUOX_ADDITIONAL_INFO
                                                                                                 *   "Additional Information" as config option to get the exact error code. This code
                                                                                                 *   will be returned for the below PICC Error codes.
                                                                                                 *      - #PHAL_MFDUOX_ISO7816_ERR_PROTOCOL_VERSION
                                                                                                 *      - #PHAL_MFDUOX_ISO7816_ERR_MEMORY_FAILURE
                                                                                                 *      - #PHAL_MFDUOX_ISO7816_ERR_WRONG_LENGTH
                                                                                                 *      - #PHAL_MFDUOX_ISO7816_ERR_INCORRECT_CMD_PARAMS
                                                                                                 *      - #PHAL_MFDUOX_ISO7816_ERR_INVALID_APPLN
                                                                                                 *      - #PHAL_MFDUOX_ISO7816_ERR_WRONG_PARAMS
                                                                                                 *      - #PHAL_MFDUOX_ISO7816_ERR_WRONG_PARAMS_P2
                                                                                                 *      - #PHAL_MFDUOX_ISO7816_ERR_WRONG_LC
                                                                                                 *      - #PHAL_MFDUOX_ISO7816_ERR_WRONG_LE
                                                                                                 *      - #PHAL_MFDUOX_ISO7816_ERR_NO_PRECISE_DIAGNOSTICS
                                                                                                 *      - #PHAL_MFDUOX_ISO7816_ERR_EOF_REACHED
                                                                                                 *      - #PHAL_MFDUOX_ISO7816_ERR_FILE_ACCESS
                                                                                                 *      - #PHAL_MFDUOX_ISO7816_ERR_FILE_EMPTY
                                                                                                 *      - #PHAL_MFDUOX_ISO7816_ERR_FILE_NOT_FOUND
                                                                                                 *      - #PHAL_MFDUOX_ISO7816_ERR_INCORRECT_PARAMS
                                                                                                 *      - #PHAL_MFDUOX_ISO7816_ERR_WRONG_CLA
                                                                                                 *      - #PHAL_MFDUOX_ISO7816_ERR_UNSUPPORTED_INS
                                                                                                 *      - #PHAL_MFDUOX_ISO7816_ERR_LIMITED_FUNCTIONALITY_INS
                                                                                                 *      - #PHAL_MFDUOX_ISO7816_ERR_REF_DATA_NOT_USABLE
                                                                                                 */
#define PHAL_MFDUOX_ERR_CMD_INVALID                                 (PH_ERR_CUSTOM_BEGIN + 13)  /**< MFDUOX Custom error code - Command Invalid.
                                                                                                 *   This error represents PICC's #PHAL_MFDUOX_RESP_ERR_CMD_INVALID error.
                                                                                                 */
#define PHAL_MFDUOX_ERR_NOT_SUPPORTED                               (PH_ERR_CUSTOM_BEGIN + 14)  /**< MFDUOX Custom error code - Not Supported Error.
                                                                                                 *   This error represents PICC's #PHAL_MFDUOX_RESP_ERR_NOT_SUP error.
                                                                                                 */
#define PHAL_MFDUOX_ERR_OPERATION_OK_LIM                            (PH_ERR_CUSTOM_BEGIN + 15)  /**< MFDUOX Custom error code - Successful operation with limited functionality.
                                                                                                 *   This error represents PICC's #PHAL_MFDUOX_RESP_OPERATION_OK_LIM error.
                                                                                                 */
#define PHAL_MFDUOX_ERR_CMD_OVERFLOW                                (PH_ERR_CUSTOM_BEGIN + 16)  /**< MFDUOX Custom error code - Too many commands in the session or transaction.
                                                                                                 *   This error represents PICC's #PHAL_MFDUOX_RESP_ERR_CMD_OVERFLOW error.
                                                                                                 */
#define PHAL_MFDUOX_ERR_GEN_FAILURE                                 (PH_ERR_CUSTOM_BEGIN + 17)  /**< MFDUOX Custom error code - Failure in the operation of the PD.
                                                                                                 *   This error represents PICC's #PHAL_MFDUOX_RESP_ERR_GEN_FAILURE error.
                                                                                                 */
#define PHAL_MFDUOX_ERR_BNR                                         (PH_ERR_CUSTOM_BEGIN + 18)  /**< MFDUOX Custom error code - Invalid Block number: not existing in the implementation
                                                                                                 *   or not valid to target with this command.
                                                                                                 *   This error represents PICC's #PHAL_MFDUOX_RESP_ERR_BNR error.
                                                                                                 */
#define PHAL_MFDUOX_ERR_FORMAT                                      (PH_ERR_CUSTOM_BEGIN + 19)  /**< MFDUOX Custom error code - Format of the command is not correct (e.g. too many or too few bytes).
                                                                                                 *   This error represents PICC's #PHAL_MFDUOX_RESP_ERR_FORMAT error.
                                                                                                 */
#define PHAL_MFDUOX_ERR_CERTIFICATE                                 (PH_ERR_CUSTOM_BEGIN + 20)  /**< MFDUOX Custom error code - Reader certificate or CertAccessRights related error.
                                                                                                 *   This error represents PICC's #PHAL_MFDUOX_RESP_CERT_ERROR error.
                                                                                                 */
#define PHAL_MFDUOX_ERR_WEAK_FIELD                                  (PH_ERR_CUSTOM_BEGIN + 21)  /**< MFDUOX Custom error code - Field strength not sufficient to enable power
                                                                                                 *   harvesting for the targeted current/voltage level.
                                                                                                 *   This error represents PICC's #PHAL_MFDUOX_RESP_WEAK_FIELD error.
                                                                                                 */
/**
 * end of group phalMfDuoX_ErrorCodes_Mapped
 * @}
 */

/**
 * end of group phalMfDuoX_ErrorCode
 * @}
 */

/**
 * \defgroup phalMfDuoX_CommonDefs Defines
 * @{
 */

/**
 * \defgroup phalMfDuoX_SecureMessaging_Defines_AuthState AuthState
 * \brief Different type of Authenticate states.
 * @{
 */

#define PHAL_MFDUOX_NOT_AUTHENTICATED                                                   0xFFU   /**< No authentication. */
/**
 * end of group phalMfDuoX_SecureMessaging_Defines_AuthState
 * @}
 */

/**
 * \defgroup phalMfDuoX_Defines_ComModes CommunicationModes
 * \brief The communication mode to be used for Command / Response.
 * @{
 */
#define PHAL_MFDUOX_COMMUNICATION_PLAIN                                                 0x00U   /**< Plain mode of communication. The Command / Response will be is plain format. */
/**
 * end of group phalMfDuoX_Defines_ComModes
 * @}
 */

/**
 * \defgroup phalMfDuoX_Defines_TargetAPP ApplicationType
 * \brief Type of application.
 * @{
 */
#define PHAL_MFDUOX_APP_PRIMARY                                                         0x00U   /**< Option for Primary application indicator. */
#define PHAL_MFDUOX_APP_SECONDARY                                                       0x80U   /**< Option for Secondary application indicator (SAI). */
/**
* end of group phalMfDuoX_Defines_TargetAPP
* @}
*/

/**
 * \defgroup phalMfDuoX_Defines_Appln_File_Options Application_File_Options
 * \brief Options for application / file creation interfaces.
 * @{
 */
#define PHAL_MFDUOX_ISO_FILE_INFO_NOT_AVAILABLE                                         0x00U   /**< Option to indicate no ISO File ID or ISODFName are present. */
#define PHAL_MFDUOX_ISO_FILE_ID_AVAILABLE                                               0x01U   /**< Option to indicate the presence of ISO FileID. */
#define PHAL_MFDUOX_ISO_DF_NAME_AVAILABLE                                               0x02U   /**< Option to indicate the presence of ISO DFName. */
#define PHAL_MFDUOX_ISO_FILE_ID_DF_NAME_AVAILABLE                                       0x03U   /**< Option to indicate the presence of both ISO FileID and ISO DFName. */
/**
 * end of group phalMfDuoX_Defines_Appln_File_Options
 * @}
 */

/**
 * \defgroup phalMfDuoX_ASymm_KeyManagement_Defines_TargetCurve TargetCurve
 * \brief Target Action options to be used with \ref phalMfDuoX_ManageKeyPair "Manage Key-Pair" interface.
 * @{
 */
#define PHAL_MFDUOX_TARGET_CURVE_ID_NIST_P256                                           0x0CU   /**< Option for NIST P-256 Curve ID. */
#define PHAL_MFDUOX_TARGET_CURVE_ID_BRAINPOOL_P256R1                                    0x0DU   /**< Option for BrainPool P-256 R1 Curve ID. */
/**
 * end of group phalMfDuoX_ASymm_KeyManagement_Defines_TargetAction
 * @}
 */

/**
 * end of group phalMfDuoX_CommonDefs
 * @}
 */

/* MIFARE DUOX secure messaging related commands ---------------------------------------------------------------------------------------- */
/**
 * \defgroup phalMfDuoX_SecureMessaging Commands_SecureMessaging
 * \brief Describes about the MIFARE DUOX Secure Messaging related commands.
 * @{
 */

/**
 * \defgroup phalMfDuoX_SecureMessaging_Defines Defines
 * \brief Macro Definitions for Secure Messaging commands
 * @{
 */

/**
 * end of group phalMfDuoX_SecureMessaging_Defines
 * @}
 */

/**
 * \brief Performs Asymmetric Card-Unilateral Authentication. The following operations are performed using this interface.
 * - Ephemeral Key Pair (E.Pub.A) is generated by the Library.
 * - The Signature (Sig.B) received as part of response is verified using the Key Number provided in \b wKeyNo_PubKeyB parameter.
 *
 * \return Status code
 * \retval #PH_ERR_SUCCESS              Operation successful.
 * \retval #PH_ERR_INVALID_DATA_PARAMS  If DataParams is null.
 * \retval #PH_ERR_INVALID_PARAMETER    If the buffers are null.
 * \retval #PH_ERR_PROTOCOL_ERROR       If Tag information is not proper for AuthDOHdr, RndB and Signature.
 * \retval #PH_ERR_VERIFICATION_FAILED  Verification of Message / Signature combination failed.
 * \retval XXXX
 *                                      - Depending on status codes return by PICC.
 *                                      - Other Depending on implementation and underlying component.
 */
phStatus_t phalMfDuoX_ISOInternalAuthenticate(
        void * pDataParams,                                                                     /**< [In] Pointer to this layer's parameter structure. */
        uint8_t bPrivKeyNo,                                                                     /**< [In] Private Key number for signing the response.
                                                                                                 *          - At PICC level, two keys are supported.
                                                                                                 *          - At Application level, up to five keys are supported.
                                                                                                 */
        uint8_t bCurveID,                                                                       /**< [In] The targeted curve for the public key provided in \b pPubBKey parameter.
                                                                                                 *        Should be one of the below values.
                                                                                                 *           - \ref PHAL_MFDUOX_TARGET_CURVE_ID_NIST_P256 "P-256"
                                                                                                 *           - \ref PHAL_MFDUOX_TARGET_CURVE_ID_BRAINPOOL_P256R1 "BP-256"
                                                                                                 */
        uint8_t * pPubBKey,                                                                     /**< [In] Public Key (Pub.B) to be used for verification. */
        uint16_t wPubBKeyLen,                                                                   /**< [In] Length of bytes available in \b pPubBKey buffer. */
        uint8_t * pOptsA,                                                                       /**< [In] Complete PCD Options in TLV format.
                                                                                                 *        NULL in case of Optional scenario
                                                                                                 */
        uint8_t bOptsALen,                                                                      /**< [In] Length of bytes available in \b pOptsA buffer.
                                                                                                 *        Zero in case of Optional scenario.
                                                                                                 */
        uint8_t * pExpRspLen,                                                                   /**< [In] Length of expected response from Device.
                                                                                                 *          - This parameter is for exchanging the LE information.
                                                                                                 *          - If NULL is provided, then the expected Response length will be
                                                                                                 *            taken as 0x00 (1 byte) by default or 2 bytes based on LC.
                                                                                                 *          - Possible values are NULL, Array consisting of 1 byte or 2 bytes.
                                                                                                 */
        uint8_t bExpRspLen                                                                      /**< [In] Length of bytes available in \b pExpRspLen buffer. */
    );

/**
 * end of group phalMfDuoX_SecureMessaging
 * @}
 */

/* MIFARE DUOX Memory and Configuration management commands ----------------------------------------------------------------------------- */
/**
 * \defgroup phalMfDuoX_MemoryConfiguration Commands_MemoryConfiguration
 * \brief Describes about the MIFARE DUOX Memory and Configuration Management commands.
 * @{
 */

/**
 * \defgroup phalMfDuoX_MemoryConfiguration_Defines Defines
 * \brief Macro Definitions for Memory and Configuration Management commands.
 * @{
 */

/**
 * \defgroup phalMfDuoX_MemoryConfiguration_Defines_GetVersion GetVersion
 * \brief Options to be used with \ref phalMfDuoX_GetVersion "GetVersion" interface.
 * @{
 */
#define PHAL_MFDUOX_GET_VERSION_EXCLUDE_FAB_ID                                          0x00U   /**< Option for not exchanging the Option information in \ref phalMfDuoX_GetVersion
                                                                                                 *   "GetVersion" command. If used, the FabID will not be available in the response.
                                                                                                 */
#define PHAL_MFDUOX_GET_VERSION_RETURN_FAB_ID                                           0x01U   /**< Option for exchanging the Option information in \ref phalMfDuoX_GetVersion
                                                                                                 *   "GetVersion" command to retrieve the FabID information. If used, the FabID
                                                                                                 *   will be available in the response.
                                                                                                 */
/**
 * end of group phalMfDuoX_MemoryConfiguration_Defines_GetVersion
 * @}
 */

/**
 * end of group phalMfDuoX_MemoryConfiguration_Defines
 * @}
 */

/**
 * \brief Returns free memory available on the PICC
 *
 * \return Status code
 * \retval #PH_ERR_SUCCESS              Operation successful.
 * \retval #PH_ERR_INVALID_DATA_PARAMS  If DataParams is null.
 * \retval #PH_ERR_INVALID_PARAMETER    If the buffer is null.
 * \retval XXXX
 *                                      - Depending on status codes return by PICC.
 *                                      - Other Depending on implementation and underlying component.
 */
phStatus_t phalMfDuoX_FreeMem(
        void * pDataParams,                                                                     /**< [In] Pointer to this layer's parameter structure. */
        uint8_t ** ppMemInfo,                                                                   /**< [Out] Current free memory available. Response Will be of 3 bytes with LSB first. \n
                                                                                                 *              If the free memory available is 7592 bytes, then
                                                                                                 *              7592 in Hex will be 0x001F10 \n
                                                                                                 *              \b ppMemInfo will contain 10 1F 00.
                                                                                                 */
        uint16_t * pMemInfoLen                                                                  /**< [Out] Length of bytes available in \b ppMemInfo buffer. */
    );

/**
 * \brief Returns manufacturing related data of the PICC.
 *
 * \return Status code
 * \retval #PH_ERR_SUCCESS              Operation successful.
 * \retval #PH_ERR_INVALID_DATA_PARAMS  If DataParams is null.
 * \retval #PH_ERR_INVALID_PARAMETER    If the buffer is null.
 * \retval XXXX
 *                                      - Depending on status codes return by PICC.
 *                                      - Other Depending on implementation and underlying component.
 */
phStatus_t phalMfDuoX_GetVersion(
        void * pDataParams,                                                                     /**< [In] Pointer to this layer's parameter structure. */
        uint8_t bOption,                                                                        /**< [In] Option information to be exchanged. Will be one of the following,
                                                                                                 *          - \ref PHAL_MFDUOX_GET_VERSION_EXCLUDE_FAB_ID "Do Not Return FabID":
                                                                                                 *            Option byte is not exchanged to PICC.
                                                                                                 *          - \ref PHAL_MFDUOX_GET_VERSION_RETURN_FAB_ID "Return FabID":
                                                                                                 *            Option byte is exchanged to PICC.
                                                                                                 */
        uint8_t ** ppVersion,                                                                   /**< [Out] Returns the complete version information of the PICC.
                                                                                                 *         The information includes,
                                                                                                 *              - Hardware Information
                                                                                                 *              - Software Information
                                                                                                 *              - Production Related Information
                                                                                                 *                  - Will have FabID based on \b bOption information.
                                                                                                 */
        uint16_t * pVerLen                                                                      /**< [Out] Length of bytes available in \b ppVersion buffer. */
    );

/**
 * end of group phalMfDuoX_MemoryConfiguration
 * @}
 */

/* MIFARE DUOX Symmetric Key management commands ---------------------------------------------------------------------------------------- */
/**
 * \defgroup phalMfDuoX_Symm_KeyManagement Commands_SymmetricKeyManagement
 * \brief Describes about the MIFARE DUOX Symmetric Key Management commands.
 * @{
 */

/**
 * \defgroup phalMfDuoX_Symm_KeyManagement_Defines Defines
 * \brief Macro Definitions for Symmetric Key Management commands.
 * @{
 */

/**
 * \defgroup phalMfDuoX_Symm_KeyManagement_Defines_KeySetting KeySetting
 * \brief Key Settings options to be used with \ref phalMfDuoX_GetKeySettings "Get Key Settings" interface.
 * @{
 */
#define PHAL_MFDUOX_KEY_SETTING_UNKNOWN                                                 0xFFU   /**< Option for Unknown Key settings option. */
#define PHAL_MFDUOX_KEY_SETTING_PICC_APPLICATION                                        0x00U   /**< Option for retrieval of PICC or Application Key settings.
                                                                                                 *   If this option is used, the option byte will not be exchanged to PICC.
                                                                                                 */
#define PHAL_MFDUOX_KEY_SETTING_ECC_PRIVATE_KEY_METADATA                                0x01U   /**< Option for retrieval of ECC Private Key meta-data. */
#define PHAL_MFDUOX_KEY_SETTING_CA_ROOT_KEY_METADATA                                    0x02U   /**< Option for retrieval of CA Root Key meta-data. */
/**
 * end of group phalMfDuoX_Symm_KeyManagement_Defines_KeySetting
 * @}
 */

/**
 * end of group phalMfDuoX_Symm_KeyManagement_Defines
 * @}
 */

/**
 * \brief Gets PICC Key Settings of the PICC or Application Key Setting for the application. In addition it returns
 * the number of keys which are configured for the selected application and if applicable the AppKeySetSettings.
 *
 * Note:
 *      The Option information will not be exchanged to PICC in case of \ref PHAL_MFDUOX_KEY_SETTING_PICC_APPLICATION
 *      "PICC / Application Key Settings".
 *
 * \return Status code
 * \retval #PH_ERR_SUCCESS              Operation successful.
 * \retval #PH_ERR_INVALID_DATA_PARAMS  If DataParams is null.
 * \retval XXXX
 *                                      - Depending on status codes return by PICC.
 *                                      - Other Depending on implementation and underlying component.
 */
phStatus_t phalMfDuoX_GetKeySettings(
        void * pDataParams,                                                                     /**< [In] Pointer to this layer's parameter structure. */
        uint8_t bOption,                                                                        /**< [In] Option to be used for information retrieval. One of the below values.
                                                                                                 *          - \ref PHAL_MFDUOX_KEY_SETTING_PICC_APPLICATION
                                                                                                 *            "PICC / Application Key Settings"
                                                                                                 *          - \ref PHAL_MFDUOX_KEY_SETTING_ECC_PRIVATE_KEY_METADATA
                                                                                                 *            "DUOX Private Key Meta-Data"
                                                                                                 *          - \ref PHAL_MFDUOX_KEY_SETTING_CA_ROOT_KEY_METADATA
                                                                                                 *            "CA Root Key Meta-Data"
                                                                                                 */
        uint8_t ** ppResponse,                                                                  /**< [Out] Returns the key settings. */
        uint16_t * pRspLen                                                                      /**< [Out] Length bytes available in \b ppKeySettings buffer. */
    );

/**
 * end of group phalMfDuoX_Symm_KeyManagement
 * @}
 */

/* MIFARE DUOX ASymmetric Key management commands --------------------------------------------------------------------------------------- */
/**
 * \defgroup phalMfDuoX_ASymm_KeyManagement Commands_ASymmetricKeyManagement
 * \brief Describes about the MIFARE DUOX ASymmetric Key Management commands.
 * @{
 */

/**
 * \defgroup phalMfDuoX_ASymm_KeyManagement_Defines Defines
 * \brief Macro Definitions for ASymmetric Key Management commands.
 * @{
 */

/**
 * \defgroup phalMfDuoX_ASymm_KeyManagement_Defines_TargetAction TargetAction
 * \brief Target Action options to be used with \ref phalMfDuoX_ManageKeyPair "Manage Key-Pair" interface.
 * @{
 */
#define PHAL_MFDUOX_TARGET_ACTION_GENERATE_KEY_PAIR                                     0x00U   /**< Option for Key Pair generation. */
#define PHAL_MFDUOX_TARGET_ACTION_IMPORT_PRIVATE_KEY                                    0x01U   /**< Option for Private Key Import. */
#define PHAL_MFDUOX_TARGET_ACTION_UPDATE_META_DATA                                      0x02U   /**< Option for Meta-Data update. */
/**
 * end of group phalMfDuoX_ASymm_KeyManagement_Defines_TargetAction
 * @}
 */

/**
 * \defgroup phalMfDuoX_ASymm_KeyManagement_Defines_KeyPolicy KeyPolicy
 * \brief KeyPolicy Options to be used with \ref phalMfDuoX_ManageKeyPair "Manage Key-Pair" interface.
 * @{
 */
#define PHAL_MFDUOX_KEY_POLICY_DISABLED                                                 0x0000U /**< Option for Key Policy as disabled. */
#define PHAL_MFDUOX_KEY_POLICY_FREEZE_KUCLIMIT                                          0x8000U /**< Option for Key Policy as Freeze Key Usage Counter Limit. */
#define PHAL_MFDUOX_KEY_POLICY_ECC_CARD_UNILATERAL_AUTH                                 0x0100U /**< Option for Key Policy as DUOX Based Card-Unilateral with ISOInternalAuthenticate. */
#define PHAL_MFDUOX_KEY_POLICY_ECC_MUTUAL_AUTH                                          0x0080U /**< Option for Key Policy as DUOX Based Mutual Authentication. */
#define PHAL_MFDUOX_KEY_POLICY_ECC_TRANSACTION_SIGNATURE                                0x0040U /**< Option for Key Policy as DUOX Based Transaction Signature. */
#define PHAL_MFDUOX_KEY_POLICY_ECC_SECURE_DYNAMINC_MESSAGING                            0x0020U /**< Option for Key Policy as DUOX Based Secure Dynamic Messaging. */
#define PHAL_MFDUOX_KEY_POLICY_CRYPTO_REQUEST_ECC_SIGN                                  0x0010U /**< Option for Key Policy as DUOX Based CryptoRequest DUOX Sign. */
/**
 * end of group phalMfDuoX_ASymm_KeyManagement_Defines_KeyPolicy
 * @}
 */

/**
 * \defgroup phalMfDuoX_ASymm_KeyManagement_Defines_TargetKeyType TargetKeyType
 * \brief Target KeyType options to be used with \ref phalMfDuoX_ExportKey "Export Key" interface.
 * @{
 */
#define PHAL_MFDUOX_TARGET_KEY_TYPE_CA_ROOT_KEY                                         0x01U   /**< Option for Target KeyType as CA Root Key. */
/**
 * end of group phalMfDuoX_ASymm_KeyManagement_Defines_TargetAction
 * @}
 */

/**
 * end of group phalMfDuoX_ASymm_KeyManagement_Defines
 * @}
 */

/**
 * \brief Creates or updates a private key entry by generating a key pair or importing a private key.
 *
 * \note
 *      - \b bComOption will be
 *          - Communication mode of the targeted key \n
 */
/**
 *
 * \return Status code
 * \retval #PH_ERR_SUCCESS              Operation successful.
 * \retval #PH_ERR_INVALID_DATA_PARAMS  If DataParams is null.
 * \retval #PH_ERR_INVALID_PARAMETER
 *                                      - If the buffers are null.
 *                                      - The values provided in \b bComOption is not supported.
 * \retval #PH_ERR_KEY
 *                                      - If Key type is not DUOX.
 *                                      - The Key format is not Binary (Uncompressed Point Representation).
 *                                      - The Key pair is not Private type.
 * \retval XXXX
 *                                      - Depending on status codes return by PICC.
 *                                      - Other Depending on implementation and underlying component.
 */
phStatus_t phalMfDuoX_ManageKeyPair(
        void * pDataParams,                                                                     /**< [In] Pointer to this layer's parameter structure. */
        uint8_t bComOption,                                                                     /**< [In] Indicates the mode of communication to be used while exchanging the
                                                                                                 *        data to PICC.
                                                                                                 *          - \ref PHAL_MFDUOX_COMMUNICATION_PLAIN "Plain Mode"
                                                                                                 */
        uint8_t bKeyNo,                                                                         /**< [In] Key number of the key to be managed.
                                                                                                 *          - At PICC level, two keys are supported.
                                                                                                 *          - At application level, up to five keys are supported.
                                                                                                 */
        uint8_t bOption,                                                                        /**< [In] Target action to perform. Should be one of the below values.
                                                                                                 *          - \ref PHAL_MFDUOX_TARGET_ACTION_GENERATE_KEY_PAIR "Generate KeyPair"
                                                                                                 *          - \ref PHAL_MFDUOX_TARGET_ACTION_IMPORT_PRIVATE_KEY "Import Private Key"
                                                                                                 *          - \ref PHAL_MFDUOX_TARGET_ACTION_UPDATE_META_DATA "Update Meta-Data"
                                                                                                 */
        uint8_t bCurveID,                                                                       /**< [In] The targeted curve. Should be one of the below values.
                                                                                                 *           - \ref PHAL_MFDUOX_TARGET_CURVE_ID_NIST_P256 "P-256"
                                                                                                 *           - \ref PHAL_MFDUOX_TARGET_CURVE_ID_BRAINPOOL_P256R1 "BP-256"
                                                                                                 */
        uint8_t * pKeyPolicy,                                                                   /**< [In] Defines the allowed crypto operations with the targeted key.
                                                                                                 *           - Should be two bytes as follows,
                                                                                                 *               - Byte 0 => Bit 7 - 0
                                                                                                 *               - Byte 1 => Bit 15 - 8
                                                                                                 *
                                                                                                 *           - Supported values are, should be ORed
                                                                                                 *               - \ref PHAL_MFDUOX_KEY_POLICY_DISABLED "Disabled"
                                                                                                 *               - \ref PHAL_MFDUOX_KEY_POLICY_FREEZE_KUCLIMIT "Freeze Key Usage Counter Limit"
                                                                                                 *               - \ref PHAL_MFDUOX_KEY_POLICY_ECC_CARD_UNILATERAL_AUTH "UniLateral Authentication"
                                                                                                 *               - \ref PHAL_MFDUOX_KEY_POLICY_ECC_MUTUAL_AUTH "Mutual Authentication"
                                                                                                 *               - \ref PHAL_MFDUOX_KEY_POLICY_ECC_TRANSACTION_SIGNATURE "Transaction Signature"
                                                                                                 *               - \ref PHAL_MFDUOX_KEY_POLICY_ECC_SECURE_DYNAMINC_MESSAGING "Secure Dynamic Messaging"
                                                                                                 *               - \ref PHAL_MFDUOX_KEY_POLICY_CRYPTO_REQUEST_ECC_SIGN "Request DUOX Signature"
                                                                                                 */
        uint8_t bWriteAccess,                                                                   /**< [In] Defines the CommMode and access right required to update
                                                                                                 *        the key with Cmd.ManageKeyPair. Should contain below information.
                                                                                                 *          - Bits[7 - 6]: RFU
                                                                                                 *          - Bits[5 - 4]: Communication Modes, One of the below values.
                                                                                                 *              - \ref PHAL_MFDUOX_COMMUNICATION_PLAIN "Plain Mode"
                                                                                                 */
                                                                                                /**<
                                                                                                 *          - Bits[3 - 0]: Access Rights, One of the below values.
                                                                                                 *              - At PICC Level
                                                                                                 *                  - 0x00       : PICC Master Key
                                                                                                 *                  - 0x01       : VC Configuration Key
                                                                                                 *                  - 0x02       : DUOX-based Delegated Application Management
                                                                                                 *                  - 0x03 - 0x0D: DUOX-specific access rights
                                                                                                 *                  - 0x0E       : Free Access
                                                                                                 *                  - 0x0F       : No Access or RFU
                                                                                                 *              - At Application Level
                                                                                                 *                  - 0x00 - 0x0D: Authentication Required
                                                                                                 *                  - 0x0D       : [Optional] Free Access over I2C, Authentication required over NFC
                                                                                                 *                  - 0x0E       : Free Access
                                                                                                 *                  - 0x0F       : No Access or RFU
                                                                                                 */
        uint32_t dwKUCLimit,                                                                    /**< [In] Defines the key usage limit of the targeted key.
                                                                                                 *          - 0x00000000: Key Usage Counter Limit is disabled
                                                                                                 *          - Any other value: Key Usage Counter Limit enabled with the given value (LSB first).
                                                                                                 */
        uint16_t wPrivKey_No,                                                                   /**< [In] Key number in KeyStore of Private Key. */
        uint16_t wPrivKey_Pos,                                                                  /**< [In] Key position in KeyStore of Private Key. */
        uint8_t ** ppResponse,                                                                  /**< [Out] The Public Key in uncompressed point representation format.
                                                                                                 *          - Present if \b bOption = \ref PHAL_MFDUOX_TARGET_ACTION_GENERATE_KEY_PAIR
                                                                                                 *            "Generate KeyPair"
                                                                                                 *          - NULL otherwise
                                                                                                 */
        uint16_t * pRspLen                                                                      /**< [Out] Length of bytes available in \b ppResponse buffer.
                                                                                                 *          - Actual length if \b bOption = \ref PHAL_MFDUOX_TARGET_ACTION_GENERATE_KEY_PAIR
                                                                                                 *            "Generate KeyPair"
                                                                                                 *          - Zero otherwise
                                                                                                 */
    );

/**
 * \brief Creates or updates a public key entry for storing a CARootKey.
 *
 * \note
 *      - \b bComOption will be
 *          - Communication mode of the targeted key \n
 */
/**
 *
 * \return Status code
 * \retval #PH_ERR_SUCCESS              Operation successful.
 * \retval #PH_ERR_INVALID_DATA_PARAMS  If DataParams is null.
 * \retval #PH_ERR_INVALID_PARAMETER
 *                                      - If the buffers are null.
 *                                      - The values provided in \b bComOption is not supported.
 * \retval #PH_ERR_KEY
 *                                      - If Key type is not DUOX.
 *                                      - The Key format is not Binary (Uncompressed Point Representation).
 *                                      - The Key pair is not Public type.
 * \retval XXXX
 *                                      - Depending on status codes return by PICC.
 *                                      - Other Depending on implementation and underlying component.
 */
phStatus_t phalMfDuoX_ManageCARootKey(
        void * pDataParams,                                                                     /**< [In] Pointer to this layer's parameter structure. */
        uint8_t bComOption,                                                                     /**< [In] Indicates the mode of communication to be used while exchanging the
                                                                                                 *        data to PICC.
                                                                                                 *          - \ref PHAL_MFDUOX_COMMUNICATION_PLAIN "Plain Mode"
                                                                                                 */
        uint8_t bKeyNo,                                                                         /**< [In] Key number of the key to be managed.
                                                                                                 *          - At PICC level, two keys are supported.
                                                                                                 *          - At application level, up to five keys are supported.
                                                                                                 */
        uint8_t bCurveID,                                                                       /**< [In] The targeted curve. Should be one of the below values.
                                                                                                 *           - \ref PHAL_MFDUOX_TARGET_CURVE_ID_NIST_P256 "P-256"
                                                                                                 *           - \ref PHAL_MFDUOX_TARGET_CURVE_ID_BRAINPOOL_P256R1 "BP-256"
                                                                                                 */
        uint8_t * pAccessRights,                                                                /**< [In] Access rights associated with the CARootKey. Should be 2 byte. */
        uint8_t bWriteAccess,                                                                   /**< [In] Defines the CommMode and access right required to update
                                                                                                 *        the key with Cmd.ManageCARootKey. Should contain below information.
                                                                                                 *          - Bits[7 - 6]: RFU
                                                                                                 *          - Bits[5 - 4]: Communication Modes, One of the below values.
                                                                                                 *              - \ref PHAL_MFDUOX_COMMUNICATION_PLAIN "Plain Mode"
                                                                                                 */
                                                                                                /**<
                                                                                                 *          - Bits[3 - 0]: Access Rights, One of the below values.
                                                                                                 *              - At PICC Level
                                                                                                 *                  - 0x00       : PICC Master Key
                                                                                                 *                  - 0x01       : VC Configuration Key
                                                                                                 *                  - 0x02       : DUOX-based Delegated Application Management
                                                                                                 *                  - 0x03 - 0x0D: DUOX-specific access rights
                                                                                                 *                  - 0x0E       : Free Access
                                                                                                 *                  - 0x0F       : No Access or RFU
                                                                                                 *              - At Application Level
                                                                                                 *                  - 0x00 - 0x0D: Authentication Required
                                                                                                 *                  - 0x0D       : [Optional] Free Access over I2C, Authentication required over NFC
                                                                                                 *                  - 0x0E       : Free Access
                                                                                                 *                  - 0x0F       : No Access or RFU
                                                                                                 */
        uint8_t bReadAccess,                                                                    /**< [In] Defines the CommMode and access right required to read the
                                                                                                 *        key with Cmd.ExportKey. Should contain below information.
                                                                                                 *          - Bits[7 - 6]: RFU
                                                                                                 *          - Bits[5 - 4]: Communication Modes, One of the below values.
                                                                                                 *              - \ref PHAL_MFDUOX_COMMUNICATION_PLAIN "Plain Mode"
                                                                                                 */
                                                                                                /**<
                                                                                                 *          - Bits[3 - 0]: Access Rights, One of the below values.
                                                                                                 *              - At PICC Level
                                                                                                 *                  - 0x00       : PICC Master Key
                                                                                                 *                  - 0x01       : VC Configuration Key
                                                                                                 *                  - 0x02       : DUOX-based Delegated Application Management
                                                                                                 *                  - 0x03 - 0x0D: DUOX-specific access rights
                                                                                                 *                  - 0x0E       : Free Access
                                                                                                 *                  - 0x0F       : No Access or RFU
                                                                                                 *              - At Application Level
                                                                                                 *                  - 0x00 - 0x0D: Authentication Required
                                                                                                 *                  - 0x0D       : [Optional] Free Access over I2C, Authentication required over NFC
                                                                                                 *                  - 0x0E       : Free Access
                                                                                                 *                  - 0x0F       : No Access or RFU
                                                                                                 */
        uint8_t bCRLFile,                                                                       /**< [In] Defines if certificate revocation is enabled and what file holds the CRL.
                                                                                                 *          - Bit[7]    : Certificate Revocation
                                                                                                 *              - 0x00  : Disabled
                                                                                                 *              - 0x01  : Enabled
                                                                                                 *          - Bit[6 - 5]: RFU
                                                                                                 *          - Bit[6 - 5]: CRL File
                                                                                                 *              - 0x0000: RFU, if Bit7 is 0.
                                                                                                 *              - Others: File Number, if Bit7 is 1.
                                                                                                 */
        uint8_t * pCRLFileAID,                                                                  /**< [In] The application identifier holding the CRL file. Will be of 3 bytes with LSB first.
                                                                                                 *        If application 01 need to be created, then the Aid will be 01 00 00.
                                                                                                 */
        uint16_t wPubKey_No,                                                                    /**< [In] Key number in KeyStore of Public Key. */
        uint16_t wPubKey_Pos,                                                                   /**< [In] Key position in KeyStore of Public Key. */
        uint8_t * pIssuer,                                                                      /**< [In] The Trusted issuer name. Should be one of the following.
                                                                                                 *          - NULL in case if No trusted issuer name check required.
                                                                                                 *          - The Trusted issuer information otherwise. Ranging from 1 - 255 bytes
                                                                                                 */
        uint8_t bIssuerLen                                                                      /**< [In] Length of bytes available in \b pIssuer buffer. */
    );

/**
 * \brief Exports the public key value of a DUOXPrivateKey or CARootKey.
 *
 * \return Status code
 * \retval #PH_ERR_SUCCESS              Operation successful.
 * \retval #PH_ERR_INVALID_DATA_PARAMS  If DataParams is null.
 * \retval #PH_ERR_INVALID_PARAMETER
 *                                      - If the buffer is null.
 *                                      - The values provided in \b bComOption is not supported.
 * \retval XXXX
 *                                      - Depending on status codes return by PICC.
 *                                      - Other Depending on implementation and underlying component.
 */
phStatus_t phalMfDuoX_ExportKey(
        void * pDataParams,                                                                     /**< [In] Pointer to this layer's parameter structure. */
        uint8_t bComOption,                                                                     /**< [In] Indicates the mode of communication to be used while exchanging the
                                                                                                 *        data to PICC.
                                                                                                 *          - \ref PHAL_MFDUOX_COMMUNICATION_PLAIN "Plain Mode"
                                                                                                 */
        uint8_t bOption,                                                                        /**< [In] Target Key Type for Exporting. */
        uint8_t bKeyNo,                                                                         /**< [In] Key number of the key to be exported.
                                                                                                 *          - At PICC level, two keys are supported.
                                                                                                 *          - At application level, up to five keys are supported.
                                                                                                 */
        uint8_t ** ppResponse,                                                                  /**< [Out] The Public Key in uncompressed point representation format. */
        uint16_t * pRspLen                                                                      /**< [Out] Length of bytes available in \b ppResponse buffer. */
    );

/**
 * end of group phalMfDuoX_ASymm_KeyManagement
 * @}
 */

/* MIFARE DUOX Application management commands ------------------------------------------------------------------------------------------ */
/**
 * \defgroup phalMfDuoX_ApplicationManagement Commands_ApplicationManagement
 * \brief Describes about the MIFARE DUOX Application Management commands.
 * @{
 */

/**
 * \defgroup phalMfDuoX_ApplicationManagement_Defines Defines
 * \brief Macro Definitions for Application Management commands.
 * @{
 */

/**
 * \defgroup phalMfDuoX_Defines_AppType ApplicatinType
 * \brief Options for \ref phalMfDuoX_SelectApplication "Select Application" interface.
 * @{
 */
#define PHAL_MFDUOX_SELECT_PRIMARY_APP                                                  0x00U   /**< Option for Primary application selection. */
#define PHAL_MFDUOX_SELECT_SECONDARY_APP                                                0x01U   /**< Option for Secondary application selection. */
/**
 * end of group phalMfDuoX_Defines_AppType
 * @}
 */

/**
 * end of group phalMfDuoX_ApplicationManagement_Defines
 * @}
 */

/**
 * \brief Creates a New Application on the PICC. The application is initialized according to the given settings.
 * The application key of the active key set are initialized with the Default Application Key.
 *
 * \return Status code
 * \retval #PH_ERR_SUCCESS              Operation successful.
 * \retval #PH_ERR_INVALID_DATA_PARAMS  If DataParams is null.
 * \retval #PH_ERR_INVALID_PARAMETER    If the buffers are null.
 * \retval XXXX
 *                                      - Depending on status codes return by PICC.
 *                                      - Other Depending on implementation and underlying component.
 */
phStatus_t phalMfDuoX_CreateApplication(
        void * pDataParams,                                                                     /**< [In] Pointer to this layer's parameter structure. */
        uint8_t bOption,                                                                        /**< [In] Option to represent the present of ISO information.
                                                                                                 *          - \ref PHAL_MFDUOX_ISO_FILE_INFO_NOT_AVAILABLE "ISO File Info not available"
                                                                                                 *          - \ref PHAL_MFDUOX_ISO_FILE_ID_AVAILABLE "ISO File ID Available"
                                                                                                 *          - \ref PHAL_MFDUOX_ISO_DF_NAME_AVAILABLE "ISO DF Name Available"
                                                                                                 *          - \ref PHAL_MFDUOX_ISO_FILE_ID_DF_NAME_AVAILABLE "Both ISO File ID and DF Name Available"
                                                                                                 */
        uint8_t * pAid,                                                                         /**< [In] The application identifier to be used. Will be of 3 bytes with LSB first.
                                                                                                 *        If application 01 need to be created, then the Aid will be 01 00 00.
                                                                                                 */
        uint8_t bKeySettings1,                                                                  /**< [In] Application Key settings. Refer Application Key Settings from DataSheet. */
        uint8_t bKeySettings2,                                                                  /**< [In] Several other key settings.
                                                                                                 *          - Bit[7 - 6]: KeyType of the application keys of the initial AKS
                                                                                                 *              - 00: Reserved
                                                                                                 *              - 01: Reserved
                                                                                                 *              - 10: AES128 KeyType
                                                                                                 *              - 11: AES256 KeyType
                                                                                                 *          - Bit[5]    : Use of 2 byte ISO/IEC 7816-4 File Identifiers
                                                                                                 *              - 0: No 2 byte File Identifiers for files within the application
                                                                                                 *              - 1: 2 byte File Identifiers for files within the application required
                                                                                                 *          - Bit[4]    : KeySett3 presence
                                                                                                 *              - 0: Disabled
                                                                                                 *              - 1: Enabled
                                                                                                 *          - Bit[3 - 0]: Number of application keys (n)
                                                                                                 *              - 0x00 - 0x0E: Maximum 14 Keys
                                                                                                 *              - 0x0F       : Enable Application Master Temp Key
                                                                                                 */
        uint8_t bKeySettings3,                                                                  /**< [In] Additional optional key settings.
                                                                                                 *          - Bit[7 - 5]: RFU
                                                                                                 *          - Bit[4]    : Application Deletion with Application Master Key
                                                                                                 *              - 0: Depending on PICC Master Key
                                                                                                 *              - 1: Always Enabled
                                                                                                 *          - Bit[3]    : Reserved
                                                                                                 *          - Bit[2]    : Application specific Capability data
                                                                                                 *              - 0: Disabled
                                                                                                 *              - 4: Enabled
                                                                                                 *          - Bit[1]    : Application Specific VC Proximity Key
                                                                                                 *              - 0: Disabled
                                                                                                 *              - 2: Enabled
                                                                                                 *          - Bit[0]    : Application KeySet
                                                                                                 *              - 0: Disabled
                                                                                                 *              - 1: Enabled
                                                                                                 */
        uint8_t * pKeySetValues,                                                                /**< [In] The Key set values for the application. Should as mentioned below.
                                                                                                 *          - Byte0 = Application Key Set Version (ASKVersion)
                                                                                                 *          - Byte1 = Number of Key Sets (NoKeySets)
                                                                                                 *          - Byte2 = Maximum Key Size (MaxKeySize)
                                                                                                 *              - 0x10: Only AES128 Key Type is allowed (upto 16 bytes).
                                                                                                 *              - 0x20: Both AES128 and AES256 Key Types are allowed (upto 32 bytes).
                                                                                                 *          - Byte3 = Application KeySet Settings (AppKeySetSett)
                                                                                                 *              - Bit[7 - 4]: RFU
                                                                                                 *              - Bit[3 - 0]: Roll Key Access Rights.
                                                                                                 *                  - 0x00 - 0x(n - 1): Active Authentication with specified Application
                                                                                                 *                                      Roll Key. (n: number of keys in Active KeySet)
                                                                                                 *                  - 0x(n) - 0x0F    : RFU
                                                                                                 */
        uint8_t bKeySetValuesLen,                                                               /**< [In] Length of bytes available in \b pKeySetValues buffer. */
        uint8_t * pISOFileId,                                                                   /**< [In] ISO File ID to be used. Will be two bytes. */
        uint8_t * pISODFName,                                                                   /**< [In] ISO DF Name to be used. Should one of the following
                                                                                                 *          - If \b bOption = \ref PHAL_MFDUOX_ISO_DF_NAME_AVAILABLE "ISO DF Name Available",
                                                                                                 *            Provided information should be upto 16 bytes.
                                                                                                 *          - If \b bOption = \ref PHAL_MFDUOX_ISO_FILE_ID_AVAILABLE "ISO File ID Available",
                                                                                                 *            Should be NULL.
                                                                                                 */
        uint8_t bISODFNameLen                                                                   /**< [In] Length of bytes available in \b pISODFName buffer. */
    );

/**
 * \brief Permanently deletes the applications on the PICC.
 *
 * \return Status code
 * \retval #PH_ERR_SUCCESS              Operation successful.
 * \retval #PH_ERR_INVALID_DATA_PARAMS  If DataParams is null.
 * \retval #PH_ERR_INVALID_PARAMETER    If the buffers are null.
 * \retval XXXX
 *                                      - Depending on status codes return by PICC.
 *                                      - Other Depending on implementation and underlying component.
 */
phStatus_t phalMfDuoX_DeleteApplication(
        void * pDataParams,                                                                     /**< [In] Pointer to this layer's parameter structure. */
        uint8_t * pAid,                                                                         /**< [In] The application identifier to be used. Will be of 3 bytes with LSB first.
                                                                                                 *        If application 01 need to be deleted, then the Aid will be 01 00 00.
                                                                                                 */
        uint8_t * pDAMMAC,                                                                      /**< [In] [Optional, present if PICCDAMAuthKey or NXPDAMAuthKey is used for authentication]
                                                                                                 *          - The MAC calculated by the card issuer to allow delegated application deletion.
                                                                                                 *          - NULL if not targeting a PICCDAMAuthKey.
                                                                                                 */
        uint8_t bDAMMAC_Len                                                                     /**< [In] Length of bytes available in \b pDAMMAC buffer. */
    );

/**
 * \brief Selects one particular application on the PICC for further access.
 *
 * \return Status code
 * \retval #PH_ERR_SUCCESS              Operation successful.
 * \retval #PH_ERR_INVALID_DATA_PARAMS  If DataParams is null.
 * \retval #PH_ERR_INVALID_PARAMETER    If the buffers are null.
 * \retval XXXX
 *                                      - Depending on status codes return by PICC.
 *                                      - Other Depending on implementation and underlying component.
 */
phStatus_t phalMfDuoX_SelectApplication(
        void * pDataParams,                                                                     /**< [In] Pointer to this layer's parameter structure. */
        uint8_t bOption,                                                                        /**< [In] One of the below options.
                                                                                                 *          - \ref PHAL_MFDUOX_SELECT_PRIMARY_APP "Primary Application"
                                                                                                 *          - \ref PHAL_MFDUOX_SELECT_SECONDARY_APP "Secondary Application"
                                                                                                 */
        uint8_t * pAid1,                                                                        /**< [In] The primary application identifier to be used. Will be of 3 bytes with LSB first.
                                                                                                 *        If application 01 need to be selected, then the Aid will be 01 00 00.
                                                                                                 */
        uint8_t * pAid2                                                                         /**< [In] The secondary application identifier to be used. Will be of 3 bytes with LSB first.
                                                                                                 *        If application 01 need to be selected, then the Aid will be 01 00 00.
                                                                                                 */
    );

/**
 * \brief Returns application identifiers of all applications on the PICC.
 *
 * \remarks
 * The status will be \ref PH_ERR_SUCCESS "Success" if all the application ids can be obtained in one call.
 * If not, then \ref PH_ERR_SUCCESS_CHAINING "Chaining" is returned. The user has to call this interface with
 * bOption = #PH_EXCHANGE_RXCHAINING to get the remaining AIDs.
 *
 * \return Status code
 * \retval #PH_ERR_SUCCESS              Operation successful.
 * \retval #PH_ERR_SUCCESS_CHAINING     Operation successful with chaining response.
 * \retval #PH_ERR_INVALID_DATA_PARAMS  If DataParams is null.
 * \retval #PH_ERR_INVALID_PARAMETER
 *                                      - If the buffers are null.
 *                                      - For Invalid buffering options (\b bOption).
 * \retval XXXX
 *                                      - Depending on status codes return by PICC.
 *                                      - Other Depending on implementation and underlying component.
 */
phStatus_t phalMfDuoX_GetApplicationIDs(
        void * pDataParams,                                                                     /**< [In] Pointer to this layer's parameter structure. */
        uint8_t bOption,                                                                        /**< [In] One of the below options.
                                                                                                 *          - #PH_EXCHANGE_DEFAULT   : Exchanges the command and received the application ID's.
                                                                                                 *          - #PH_EXCHANGE_RXCHAINING: To Receive remaining Application ID's.
                                                                                                 */
        uint8_t ** ppAidBuff,                                                                   /**< [Out] The available identifiers of the application(s). */
        uint16_t * pAidLen                                                                      /**< [Out] Length of bytes available in \b ppAidBuff buffer. */
    );

/**
 * \brief Returns the Application IDentifiers together with a File ID and (optionally) a DF
 * Name of all active applications with ISO/IEC 7816-4 support.
 *
 * \remarks
 * The status will be \ref PH_ERR_SUCCESS "Success" if all the application DFName's can be obtained in one call.
 * If not, then \ref PH_ERR_SUCCESS_CHAINING "Chaining" is returned. The user has to call this interface with
 * bOption = #PH_EXCHANGE_RXCHAINING to get the remaining DFName's.
 *
 * \return Status code
 * \retval #PH_ERR_SUCCESS              Operation successful.
 * \retval #PH_ERR_SUCCESS_CHAINING     Operation successful with chaining response.
 * \retval #PH_ERR_INVALID_DATA_PARAMS  If DataParams is null.
 * \retval #PH_ERR_INVALID_PARAMETER
 *                                      - If the buffers are null.
 *                                      - For Invalid buffering options (\b bOption).
 * \retval XXXX
 *                                      - Depending on status codes return by PICC.
 *                                      - Other Depending on implementation and underlying component.
 */
phStatus_t phalMfDuoX_GetDFNames(
        void * pDataParams,                                                                     /**< [In] Pointer to this layer's parameter structure. */
        uint8_t bOption,                                                                        /**< [In] One of the below options.
                                                                                                *           - #PH_EXCHANGE_DEFAULT   : Exchanges the command and received the application DFName's.
                                                                                                *           - #PH_EXCHANGE_RXCHAINING: To Receive remaining Application DFName's.
                                                                                                */
        uint8_t ** ppDFBuffer,                                                                  /**< [Out] The ISO information about the application. */
        uint16_t * pDFBufLen                                                                    /**< [Out] Length of bytes available in \b pDFBuffer buffer. */
    );

/**
 * end of group phalMfDuoX_ApplicationManagement
 * @}
 */

/* MIFARE DUOX File management commands ------------------------------------------------------------------------------------------------- */
/**
 * \defgroup phalMfDuoX_FileManagement Commands_FileManagement
 * \brief Describes about the MIFARE DUOX File Management commands.
 * @{
 */

/**
 * \defgroup phalMfDuoX_FileManagement_Defines Defines
 * \brief Macro Definitions for File Management commands.
 * @{
 */

/**
 * \defgroup phalMfDuoX_FileManagement_Defines_FileOptions FileOptions
 * \brief The File Options to be used for all the File management commands.
 * @{
 */
#define PHAL_MFDUOX_FILE_OPTION_PLAIN                                                   0x00U   /**< Option for File communication mode as Plain. */
#define PHAL_MFDUOX_FILE_OPTION_PLAIN_1                                                 0x02U   /**< Option for File communication mode as Plain. */
#define PHAL_MFDUOX_FILE_OPTION_MAC                                                     0x01U   /**< Option for File communication mode as Mac. */
#define PHAL_MFDUOX_FILE_OPTION_FULL                                                    0x03U   /**< Option for File communication mode as Full. */

#define PHAL_MFDUOX_FILE_OPTION_CRL_FILE                                                0x10U   /**< Option to Enable CRL (Certificate Revocation List) File. */
#define PHAL_MFDUOX_FILE_OPTION_TMCLIMIT_PRESENT                                        0x20U   /**< Option to indicate TMCLimit configuration is enabled. */
#define PHAL_MFDUOX_FILE_OPTION_SDM_MIRRORING_ENABLED                                   0x40U   /**< Option to Enable Secure Dynamic Messaging and Mirroring support. */
#define PHAL_MFDUOX_FILE_OPTION_TMI_EXCLUSION_FILEMAP                                   0x40U   /**< Option to Enable TMI Exclusion file map. */
#define PHAL_MFDUOX_FILE_OPTION_ADDITIONAL_AR_PRESENT                                   0x80U   /**< Option to Enable Additional Access Rights. */
/**
 * end of group phalMfDuoX_FileManagement_Defines_FileOptions
 * @}
 */

/**
 * \defgroup phalMfDuoX_FileManagement_Defines_LimitedCredit LimitedCredit
 * \brief The File Options to be used for \ref phalMfDuoX_CreateValueFile "Create Value File" interface.
 * @{
 */
#define PHAL_MFDUOX_LIMITED_CREDIT_DISABLED                                             0x00U   /**< Option to disable Limited credit support. */
#define PHAL_MFDUOX_LIMITED_CREDIT_ENABLED                                              0x01U   /**< Option to enable Limited credit support. */
/**
 * end of group phalMfDuoX_FileManagement_Defines_LimitedCredit
 * @}
 */

/**
 * \defgroup phalMfDuoX_FileManagement_Defines_GetValue GetValue
 * \brief The File Options to be used for \ref phalMfDuoX_CreateValueFile "Create Value File" interface.
 * @{
 */
#define PHAL_MFDUOX_GETVALUE_FREE_ACCESS_DISABLED                                       0x00U   /**< Option to indicate No Free access to GetValue command. */
#define PHAL_MFDUOX_GETVALUE_FREE_ACCESS_ENABLED                                        0x02U   /**< Option to indicate Free access to GetValue command. */
/**
 * end of group phalMfDuoX_FileManagement_Defines_GetValue
 * @}
 */

/**
 * end of group phalMfDuoX_FileManagement_Defines
 * @}
 */

/**
 * \brief Creates files for the storage of plain unformatted user data within an existing application
 * on the PICC.
 *
 * \return Status code
 * \retval #PH_ERR_SUCCESS              Operation successful.
 * \retval #PH_ERR_INVALID_DATA_PARAMS  If DataParams is null.
 * \retval #PH_ERR_INVALID_PARAMETER
 *                                      - If the buffers are null.
 *                                      - For Invalid Option (\b bOption) information.
 *                                      - For Invalid File numbers (\b bFileNo).
 *                                      - For Invalid File communication mode (\b bFileOption).
 * \retval XXXX
 *                                      - Depending on status codes return by PICC.
 *                                      - Other Depending on implementation and underlying component.
 */
phStatus_t phalMfDuoX_CreateStdDataFile(
        void * pDataParams,                                                                     /**< [In] Pointer to this layer's parameter structure. */
        uint8_t bOption,                                                                        /**< [In] Option to represent the presence of ISO information.
                                                                                                 *          - \ref PHAL_MFDUOX_ISO_FILE_INFO_NOT_AVAILABLE
                                                                                                 *            "ISO File Info not available"
                                                                                                 *          - \ref PHAL_MFDUOX_ISO_FILE_ID_AVAILABLE "ISO File ID Available"
                                                                                                 */
        uint8_t bFileNo,                                                                        /**< [In] The file number to be created. ORed with \ref PHAL_MFDUOX_APP_SECONDARY
                                                                                                 *        "Secondary Application" indicator.
                                                                                                 */
        uint8_t * pISOFileId,                                                                   /**< [In] ISO File ID to be used. Should be two bytes. */
        uint8_t bFileOption,                                                                    /**< [In] Option for the targeted file.
                                                                                                 *          - Communication settings for the file.
                                                                                                 *              - \ref PHAL_MFDUOX_FILE_OPTION_PLAIN "Plain Mode"
                                                                                                 */
                                                                                                /**<
                                                                                                 *
                                                                                                 *          - ORed with one of the above options.
                                                                                                 *              - \ref PHAL_MFDUOX_FILE_OPTION_ADDITIONAL_AR_PRESENT
                                                                                                 *                "Additional AccessRights Present"
                                                                                                 *              - \ref PHAL_MFDUOX_FILE_OPTION_SDM_MIRRORING_ENABLED
                                                                                                 *                "SDM Mirroring Enabled"
                                                                                                 *              - \ref PHAL_MFDUOX_FILE_OPTION_CRL_FILE
                                                                                                 *                "CRL (Certificate Revocation List) File"
                                                                                                 */
        uint8_t * pAccessRights,                                                                /**< [In] The new access right to be applied for the file. Should be 2 byte.
                                                                                                 *          - Bit[15 - 12]: Read
                                                                                                 *          - Bit[11 - 8] : Write
                                                                                                 *          - Bit[7 - 4]  : ReadWrite
                                                                                                 *          - Bit[3 - 0]  : Change or RFU. Change for the 1st mandatory set of access
                                                                                                 *                          condition else RFU (i.e. 0xF)
                                                                                                 *
                                                                                                 *          - Below are the values for the above bits.
                                                                                                 *              - 0x0 - 0xD: Authentication Required
                                                                                                 *              - 0xD      : [Optional] Free access over I2C, authentication required over NFC
                                                                                                 *              - 0xE      : Free Access
                                                                                                 *              - 0xF      : No Access or RFU
                                                                                                 */
        uint8_t * pFileSize                                                                     /**< [In] The size of the file. Will be of 3 bytes with LSB first.
                                                                                                 *        If size 0x10 need to be created, then the FileSize will be 10 00 00.
                                                                                                 */
    );

/**
 * \brief Creates files for the storage of plain unformatted user data within an existing application
 * on the PICC, additionally supporting the feature of an integrated backup mechanism.
 *
 * \return Status code
 * \retval #PH_ERR_SUCCESS              Operation successful.
 * \retval #PH_ERR_INVALID_DATA_PARAMS  If DataParams is null.
 * \retval #PH_ERR_INVALID_PARAMETER
 *                                      - If the buffers are null.
 *                                      - For Invalid Option (\b bOption) information.
 *                                      - For Invalid File numbers (\b bFileNo).
 *                                      - For Invalid File communication mode (\b bFileOption).
 * \retval XXXX
 *                                      - Depending on status codes return by PICC.
 *                                      - Other Depending on implementation and underlying component.
 */
phStatus_t phalMfDuoX_CreateBackupDataFile(
        void * pDataParams,                                                                     /**< [In] Pointer to this layer's parameter structure. */
        uint8_t bOption,                                                                        /**< [In] Option to represent the presence of ISO information.
                                                                                                 *          - \ref PHAL_MFDUOX_ISO_FILE_INFO_NOT_AVAILABLE
                                                                                                 *            "ISO File Info not available"
                                                                                                 *          - \ref PHAL_MFDUOX_ISO_FILE_ID_AVAILABLE "ISO File ID Available"
                                                                                                 */
        uint8_t bFileNo,                                                                        /**< [In] The file number to be created. ORed with \ref PHAL_MFDUOX_APP_SECONDARY
                                                                                                 *        "Secondary Application" indicator.
                                                                                                 */
        uint8_t * pISOFileId,                                                                   /**< [In] ISO File ID to be used. Should be two bytes. */
        uint8_t bFileOption,                                                                    /**< [In] Option for the targeted file.
                                                                                                 *          - Communication settings for the file.
                                                                                                 *              - \ref PHAL_MFDUOX_FILE_OPTION_PLAIN "Plain Mode"
                                                                                                 */
                                                                                                /**<
                                                                                                 *
                                                                                                 *          - ORed with one of the above options.
                                                                                                 *              - \ref PHAL_MFDUOX_FILE_OPTION_ADDITIONAL_AR_PRESENT
                                                                                                 *                "Additional AccessRights Present"
                                                                                                 *              - \ref PHAL_MFDUOX_FILE_OPTION_CRL_FILE
                                                                                                 *                "CRL (Certificate Revocation List) File"
                                                                                                 */
        uint8_t * pAccessRights,                                                                /**< [In] The new access right to be applied for the file. Should be 2 byte.
                                                                                                 *          - Bit[15 - 12]: Read
                                                                                                 *          - Bit[11 - 8] : Write
                                                                                                 *          - Bit[7 - 4]  : ReadWrite
                                                                                                 *          - Bit[3 - 0]  : Change or RFU. Change for the 1st mandatory set of access
                                                                                                 *                          condition else RFU (i.e. 0xF)
                                                                                                 *
                                                                                                 *          - Below are the values for the above bits.
                                                                                                 *              - 0x0 - 0xD: Authentication Required
                                                                                                 *              - 0xD      : [Optional] Free access over I2C, authentication required over NFC
                                                                                                 *              - 0xE      : Free Access
                                                                                                 *              - 0xF      : No Access or RFU
                                                                                                 */
        uint8_t * pFileSize                                                                     /**< [In] The size of the file. Will be of 3 bytes with LSB first.
                                                                                                 *        If size 0x10 need to be created, then the FileSize will be 10 00 00.
                                                                                                 */
    );

/**
 * \brief Creates files for the storage and manipulation of 32bit signed integer values within
 * an existing application on the PICC.
 *
 * \return Status code
 * \retval #PH_ERR_SUCCESS              Operation successful.
 * \retval #PH_ERR_INVALID_DATA_PARAMS  If DataParams is null.
 * \retval #PH_ERR_INVALID_PARAMETER
 *                                      - If the buffers are null.
 *                                      - For Invalid File numbers (\b bFileNo).
 *                                      - For Invalid File communication mode (\b bFileOption).
 * \retval XXXX
 *                                      - Depending on status codes return by PICC.
 *                                      - Other Depending on implementation and underlying component.
 */
phStatus_t phalMfDuoX_CreateValueFile(
        void * pDataParams,                                                                     /**< [In] Pointer to this layer's parameter structure. */
        uint8_t bFileNo,                                                                        /**< [In] The file number to be created. ORed with \ref PHAL_MFDUOX_APP_SECONDARY
                                                                                                 *        "Secondary Application" indicator.
                                                                                                 */
        uint8_t bFileOption,                                                                    /**< [In] Option for the targeted file.
                                                                                                 *          - Communication settings for the file.
                                                                                                 *              - \ref PHAL_MFDUOX_FILE_OPTION_PLAIN "Plain Mode"
                                                                                                 */
                                                                                                /**<
                                                                                                 *
                                                                                                 *          - ORed with one of the above options.
                                                                                                 *              - \ref PHAL_MFDUOX_FILE_OPTION_ADDITIONAL_AR_PRESENT
                                                                                                 *                "Additional AccessRights Present"
                                                                                                 */
        uint8_t * pAccessRights,                                                                /**< [In] The new access right to be applied for the file. Should be 2 byte. */
        uint8_t * pLowerLmit,                                                                   /**< [In] The lower limit for the file. Will be of 4 bytes with LSB first.
                                                                                                 *        If value 0x10 need to be set as lower limit, then the value will be
                                                                                                 *        10 00 00 00.
                                                                                                 */
        uint8_t * pUpperLmit,                                                                   /**< [In] The upper limit for the file. Will be of 4 bytes with LSB first.
                                                                                                 *        If value 0x20 need to be set as upper limit, then the value will be
                                                                                                 *        20 00 00 00.
                                                                                                 */
        uint8_t * pValue,                                                                       /**< [In] The initial value. Will be of 4 bytes with LSB first.
                                                                                                 *        If value 0x10 need to be set as initial value, then the value will be
                                                                                                 *        10 00 00 00.
                                                                                                 */
        uint8_t bLimitedCredit                                                                  /**< [In] Encodes if LimitedCredit and free GetValue are allowed for this file.
                                                                                                 *          - Limited Credit Support
                                                                                                 *              - \ref PHAL_MFDUOX_LIMITED_CREDIT_DISABLED "Limited Credit Disabled"
                                                                                                 *              - \ref PHAL_MFDUOX_LIMITED_CREDIT_ENABLED "Limited Credit Enabled"
                                                                                                 *
                                                                                                 *          - Access to GetValue. Should be ORed with above values.
                                                                                                 *              - \ref PHAL_MFDUOX_GETVALUE_FREE_ACCESS_DISABLED "No Free Access to GetValue"
                                                                                                 *              - \ref PHAL_MFDUOX_GETVALUE_FREE_ACCESS_ENABLED "Free Access to GetValue"
                                                                                                 */
    );

/**
 * \brief Creates files for multiple storage of structural similar data, for example for loyalty programs within an existing application.
 * Once the file is filled, further writing is not possible unless it is cleared.
 *
 * \return Status code
 * \retval #PH_ERR_SUCCESS              Operation successful.
 * \retval #PH_ERR_INVALID_DATA_PARAMS  If DataParams is null.
 * \retval #PH_ERR_INVALID_PARAMETER
 *                                      - If the buffers are null.
 *                                      - For Invalid Option (\b bOption) information.
 *                                      - For Invalid File numbers (\b bFileNo).
 *                                      - For Invalid File communication mode (\b bFileOption).
 * \retval XXXX
 *                                      - Depending on status codes return by PICC.
 *                                      - Other Depending on implementation and underlying component.
 */
phStatus_t phalMfDuoX_CreateLinearRecordFile(
        void * pDataParams,                                                                     /**< [In] Pointer to this layer's parameter structure. */
        uint8_t bOption,                                                                        /**< [In] Option to represent the presence of ISO information.
                                                                                                 *          - \ref PHAL_MFDUOX_ISO_FILE_INFO_NOT_AVAILABLE
                                                                                                 *            "ISO File Info not available"
                                                                                                 *          - \ref PHAL_MFDUOX_ISO_FILE_ID_AVAILABLE "ISO File ID Available"
                                                                                                 */
        uint8_t bFileNo,                                                                        /**< [In] The file number to be created. ORed with \ref PHAL_MFDUOX_APP_SECONDARY
                                                                                                 *        "Secondary Application" indicator.
                                                                                                 */
        uint8_t * pISOFileId,                                                                   /**< [In] ISO File ID to be used. Should be two bytes. */
        uint8_t bFileOption,                                                                    /**< [In] Option for the targeted file.
                                                                                                 *          - Communication settings for the file.
                                                                                                 *              - \ref PHAL_MFDUOX_FILE_OPTION_PLAIN "Plain Mode"
                                                                                                 */
                                                                                                /**<
                                                                                                 *
                                                                                                 *          - ORed with one of the above options.
                                                                                                 *              - \ref PHAL_MFDUOX_FILE_OPTION_ADDITIONAL_AR_PRESENT
                                                                                                 *                "Additional AccessRights Present"
                                                                                                 */
        uint8_t * pAccessRights,                                                                /**< [In] The new access right to be applied for the file. Should be 2 byte.
                                                                                                 *          - Bit[15 - 12]: Read
                                                                                                 *          - Bit[11 - 8] : Write
                                                                                                 *          - Bit[7 - 4]  : ReadWrite
                                                                                                 *          - Bit[3 - 0]  : Change or RFU. Change for the 1st mandatory set of access
                                                                                                 *                          condition else RFU (i.e. 0xF)
                                                                                                 *
                                                                                                 *          - Below are the values for the above bits.
                                                                                                 *              - 0x0 - 0xD: Authentication Required
                                                                                                 *              - 0xD      : [Optional] Free access over I2C, authentication required over NFC
                                                                                                 *              - 0xE      : Free Access
                                                                                                 *              - 0xF      : No Access or RFU
                                                                                                 */
        uint8_t * pRecordSize,                                                                  /**< [In] The size of the file. Will be of 3 bytes with LSB first.
                                                                                                 *        If size 0x10 need to be created, then the RecordSize will be 10 00 00.
                                                                                                 */
        uint8_t * pMaxNoOfRec                                                                   /**< [In] The maximum number of record in the file. Will be of 3 bytes with LSB first.
                                                                                                 *        If size 0x04 need to be created, then the value will be 04 00 00.
                                                                                                 */
    );

/**
 * \brief Creates files for multiple storage of structural similar data, for example for logging transactions, within an existing application.
 * Once the file is filled, the PICC automatically overwrites the oldest record with the latest written one.
 *
 * \return Status code
 * \retval #PH_ERR_SUCCESS              Operation successful.
 * \retval #PH_ERR_INVALID_DATA_PARAMS  If DataParams is null.
 * \retval #PH_ERR_INVALID_PARAMETER
 *                                      - If the buffers are null.
 *                                      - For Invalid Option (\b bOption) information.
 *                                      - For Invalid File numbers (\b bFileNo).
 *                                      - For Invalid File communication mode (\b bFileOption).
 * \retval XXXX
 *                                      - Depending on status codes return by PICC.
 *                                      - Other Depending on implementation and underlying component.
 */
phStatus_t phalMfDuoX_CreateCyclicRecordFile(
        void * pDataParams,                                                                     /**< [In] Pointer to this layer's parameter structure. */
        uint8_t bOption,                                                                        /**< [In] Option to represent the presence of ISO information.
                                                                                                 *          - \ref PHAL_MFDUOX_ISO_FILE_INFO_NOT_AVAILABLE
                                                                                                 *            "ISO File Info not available"
                                                                                                 *          - \ref PHAL_MFDUOX_ISO_FILE_ID_AVAILABLE "ISO File ID Available"
                                                                                                 */
        uint8_t bFileNo,                                                                        /**< [In] The file number to be created. ORed with \ref PHAL_MFDUOX_APP_SECONDARY
                                                                                                 *        "Secondary Application" indicator.
                                                                                                 */
        uint8_t * pISOFileId,                                                                   /**< [In] ISO File ID to be used. Should be two bytes. */
        uint8_t bFileOption,                                                                    /**< [In] Option for the targeted file.
                                                                                                 *          - Communication settings for the file.
                                                                                                 *              - \ref PHAL_MFDUOX_FILE_OPTION_PLAIN "Plain Mode"
                                                                                                 */
                                                                                                /**<
                                                                                                 *
                                                                                                 *          - ORed with one of the above options.
                                                                                                 *              - \ref PHAL_MFDUOX_FILE_OPTION_ADDITIONAL_AR_PRESENT
                                                                                                 *                "Additional AccessRights Present"
                                                                                                 */
        uint8_t * pAccessRights,                                                                /**< [In] The new access right to be applied for the file. Should be 2 byte.
                                                                                                 *          - Bit[15 - 12]: Read
                                                                                                 *          - Bit[11 - 8] : Write
                                                                                                 *          - Bit[7 - 4]  : ReadWrite
                                                                                                 *          - Bit[3 - 0]  : Change or RFU. Change for the 1st mandatory set of access
                                                                                                 *                          condition else RFU (i.e. 0xF)
                                                                                                 *
                                                                                                 *          - Below are the values for the above bits.
                                                                                                 *              - 0x0 - 0xD: Authentication Required
                                                                                                 *              - 0xD      : [Optional] Free access over I2C, authentication required over NFC
                                                                                                 *              - 0xE      : Free Access
                                                                                                 *              - 0xF      : No Access or RFU
                                                                                                 */
        uint8_t * pRecordSize,                                                                  /**< [In] The size of the file. Will be of 3 bytes with LSB first.
                                                                                                 *        If size 0x10 need to be created, then the RecordSize will be 10 00 00.
                                                                                                 */
        uint8_t * pMaxNoOfRec                                                                   /**< [In] The maximum number of record in the file. Will be of 3 bytes with LSB first.
                                                                                                 *        If size 0x04 need to be created, then the value will be 04 00 00.
                                                                                                 */
    );

/**
 * \brief Permanently deactivates a file within the file directory of the currently selected application.
 *
 * \return Status code
 * \retval #PH_ERR_SUCCESS              Operation successful.
 * \retval #PH_ERR_INVALID_DATA_PARAMS  If DataParams is null.
 * \retval XXXX
 *                                      - Depending on status codes return by PICC.
 *                                      - Other Depending on implementation and underlying component.
 */
phStatus_t phalMfDuoX_DeleteFile(
        void * pDataParams,                                                                     /**< [In] Pointer to this layer's parameter structure. */
        uint8_t bFileNo                                                                         /**< [In] The file number to be deleted. ORed with \ref PHAL_MFDUOX_APP_SECONDARY
                                                                                                 *        "Secondary Application" indicator.
                                                                                                 */
    );

/**
 * \brief Returns the file IDs of all active files within the currently selected application.
 *
 * \return Status code
 * \retval #PH_ERR_SUCCESS              Operation successful.
 * \retval #PH_ERR_INVALID_DATA_PARAMS  If DataParams is null.
 * \retval #PH_ERR_INVALID_PARAMETER    If the buffer is null.
 * \retval XXXX
 *                                      - Depending on status codes return by PICC.
 *                                      - Other Depending on implementation and underlying component.
 */
phStatus_t phalMfDuoX_GetFileIDs(
        void * pDataParams,                                                                     /**< [In] Pointer to this layer's parameter structure. */
        uint8_t ** ppFileId,                                                                    /**< [Out] The buffer containing the available File ID(s). */
        uint16_t * pFileIdLen                                                                   /**< [Out] Length of bytes available in \b ppFid buffer. */
    );

/**
 * \brief Get the ISO File IDs.
 *
 * \return Status code
 * \retval #PH_ERR_SUCCESS              Operation successful.
 * \retval #PH_ERR_INVALID_DATA_PARAMS  If DataParams is null.
 * \retval #PH_ERR_INVALID_PARAMETER    If the buffer is null.
 * \retval XXXX
 *                                      - Depending on status codes return by PICC.
 *                                      - Other Depending on implementation and underlying component.
 */
phStatus_t phalMfDuoX_GetISOFileIDs(
        void * pDataParams,                                                                     /**< [In] Pointer to this layer's parameter structure. */
        uint8_t ** ppISOFileId,                                                                 /**< [Out] The buffer containing the available ISO File ID(s). */
        uint16_t * pISOFileIdLen                                                                /**< [Out] Length of bytes available in \b ppFid buffer. */
    );

/**
 * \brief Get information on the properties of a specific file
 *
 * \return Status code
 * \retval #PH_ERR_SUCCESS              Operation successful.
 * \retval #PH_ERR_INVALID_DATA_PARAMS  If DataParams is null.
 * \retval #PH_ERR_INVALID_PARAMETER    If the buffer is null.
 * \retval XXXX
 *                                      - Depending on status codes return by PICC.
 *                                      - Other Depending on implementation and underlying component.
 */
phStatus_t phalMfDuoX_GetFileSettings(
        void * pDataParams,                                                                     /**< [In] Pointer to this layer's parameter structure. */
        uint8_t bFileNo,                                                                        /**< [In] The file number for which the setting to be retrieved.
                                                                                                 *        ORed with \ref PHAL_MFDUOX_APP_SECONDARY "Secondary Application"
                                                                                                 *        indicator.
                                                                                                 */
        uint8_t ** ppFSBuffer,                                                                  /**< [Out] The buffer containing the settings. */
        uint16_t * pFSBufLen                                                                    /**< [Out] Length of bytes available in \b ppFSBuffer buffer. */
    );

/**
 * \brief Get file related counters used for Secure Dynamic Messaging.
 *
 * \return Status code
 * \retval #PH_ERR_SUCCESS              Operation successful.
 * \retval #PH_ERR_INVALID_DATA_PARAMS  If DataParams is null.
 * \retval #PH_ERR_INVALID_PARAMETER    If the buffer is null.
 * \retval XXXX
 *                                      - Depending on status codes return by PICC.
 *                                      - Other Depending on implementation and underlying component.
 */
phStatus_t phalMfDuoX_GetFileCounters(
        void * pDataParams,                                                                     /**< [In] Pointer to this layer's parameter structure. */
        uint8_t bOption,                                                                        /**< [In] Indicates the mode of communication to be used while exchanging the
                                                                                                 *        data to PICC.
                                                                                                 *          - \ref PHAL_MFDUOX_COMMUNICATION_PLAIN "Plain Mode"
                                                                                                 */
        uint8_t bFileNo,                                                                        /**< [In] File number for which the Counter information need to be received.
                                                                                                 *        ORed with \ref PHAL_MFDUOX_APP_SECONDARY "Secondary Application"
                                                                                                 *        indicator.
                                                                                                 */
        uint8_t ** ppFileCounters,                                                              /**< [Out] The SDMReadCounter information returned by the PICC. */
        uint16_t * pFileCounterLen                                                              /**< [Out] Length of bytes available in \b ppFileCounters buffer. */
    );

/**
 * \brief Changes the access parameters of an existing file.
 *
 * \return Status code
 * \retval #PH_ERR_SUCCESS              Operation successful.
 * \retval #PH_ERR_INVALID_DATA_PARAMS  If DataParams is null.
 * \retval #PH_ERR_INVALID_PARAMETER
 *                                      - If the buffers are null.
 *                                      - For Invalid File numbers (\b bFileNo).
 *                                      - For Invalid File communication mode (\b bFileOption).
 * \retval XXXX
 *                                      - Depending on status codes return by PICC.
 *                                      - Other Depending on implementation and underlying component.
 */
phStatus_t phalMfDuoX_ChangeFileSettings(
        void * pDataParams,                                                                     /**< [In] Pointer to this layer's parameter structure. */
        uint8_t bOption,                                                                        /**< [In] Indicates the mode of communication to be used while exchanging the
                                                                                                 *        data to PICC.
                                                                                                 *          - \ref PHAL_MFDUOX_COMMUNICATION_PLAIN "Plain Mode"
                                                                                                 */
        uint8_t bFileNo,                                                                        /**< [In] File number for which the setting need to be updated.
                                                                                                 *        ORed with \ref PHAL_MFDUOX_APP_SECONDARY "Secondary Application"
                                                                                                 *        indicator.
                                                                                                 */
        uint8_t bFileOption,                                                                    /**< [In] Option for the targeted file.
                                                                                                 *          - Communication settings for the file.
                                                                                                 *              - \ref PHAL_MFDUOX_FILE_OPTION_PLAIN "Plain Mode"
                                                                                                 */
                                                                                                /**<
                                                                                                 *
                                                                                                 *          - ORed with one of the above options.
                                                                                                 *              - \ref PHAL_MFDUOX_FILE_OPTION_ADDITIONAL_AR_PRESENT
                                                                                                 *                "Additional Access Rights": For all files other than TransactionMAC File.
                                                                                                 *              - \ref PHAL_MFDUOX_FILE_OPTION_SDM_MIRRORING_ENABLED
                                                                                                 *                "SDM Mirroring Enabled": If Standard File is targeted.
                                                                                                 *              - \ref PHAL_MFDUOX_FILE_OPTION_TMI_EXCLUSION_FILEMAP
                                                                                                 *                "TMI Excluded File Map": If Transaction MAC file is targeted.
                                                                                                 *              - \ref PHAL_MFDUOX_FILE_OPTION_TMCLIMIT_PRESENT "TMC Limit":
                                                                                                 *                If Transaction MAC file is targeted.
                                                                                                 */
        uint8_t * pAccessRights,                                                                /**< [In] Set of access conditions for the 1st set in the file. Should be 2 byte. */
        uint8_t * pAddInfo,                                                                     /**< [In] Buffer should contain the following information. \n
                                                                                                 *          - [NrAddARs] || [Additional access rights] ||
                                                                                                 *          - [SDMOption || SDM AccessRights || VCUIDOffset || SDMReadCtrOffset ||
                                                                                                 *            PICCDataOffset || GPIOStatusOffset || SDMMACInputOffset || SDMENCOffset ||
                                                                                                 *            SDMENCLength || SDMMACOffset || SDMReadCtrLimit] ||
                                                                                                 *          - [TMIExclFileMap] ||
                                                                                                 *          - [TMCLimit] ||
                                                                                                 *          - [CRLOptions || CNSSize] || CRLSigKey]
                                                                                                 */
        uint8_t bAddInfoLen                                                                     /**< [In] Length of bytes available in \b pAddInfo buffer. */
    );

/**
 * end of group phalMfDuoX_FileManagement
 * @}
 */

/* MIFARE DUOX Data management commands ------------------------------------------------------------------------------------------------- */
/**
 * \defgroup phalMfDuoX_DataManagement Commands_DataManagement
 * \brief Describes about the MIFARE DUOX Data Management commands.
 * @{
 */

/**
 * \defgroup phalMfDuoX_DataManagement_Defines Defines
 * \brief Macro Definitions for Data Management commands.
 * @{
 */

/**
 * \defgroup phalMfDuoX_DataManagement_Defines_Chaining Chaining
 * \brief The Options to be used for below mentioned interface.
 * \ref phalMfDuoX_ReadData "ReadData"
 * \ref phalMfDuoX_WriteData "WriteData"
 * @{
 */
#define PHAL_MFDUOX_CHAINING_NATIVE                                                     0x00    /**< Option to represent the native chaining format.
                                                                                                 *   Here AF will be available as command code in Command
                                                                                                 *   and Response.
                                                                                                 */
#define PHAL_MFDUOX_CHAINING_ISO                                                        0x01    /**< Option to represent the ISO/IEC 14443-4 chaining format.
                                                                                                 *   Here AF as command code will not be available in Command
                                                                                                 *   and Response rather the chaining will be done using the
                                                                                                 *   ISO14443 L4 protocol. In case of Wrapped Mode, Extended
                                                                                                 *   Length APDU will be used.
                                                                                                 */
#define PHAL_MFDUOX_CHAINING_ISO_SHORT_LEN                                              0x03    /**< Option to represent the ISO/IEC 14443-4 chaining format
                                                                                                 *   when ISO7816-4 wrapping is enabled. By using this option
                                                                                                 *   in wrapped mode, APDU framing is performed according to
                                                                                                 *   short length format.
                                                                                                 */
/**
 * end of group phalMfDuoX_DataManagement_Defines_Chaining
 * @}
 */

/**
 * \defgroup phalMfDuoX_DataManagement_Defines_CRLFile CRLFile
 * \brief The Options to indicate the file targeted is a CRLFile or not. To be used for below mentioned interface.
 * \ref phalMfDuoX_ReadData "ReadData"
 * \ref phalMfDuoX_WriteData "WriteData"
 * @{
 */
#define PHAL_MFDUOX_TARGET_FILE_CRLFILE                                                 0x01    /**< Option to represent the native chaining format.
                                                                                                 *   Here AF will be available as command code in Command
                                                                                                 *   and Response.
                                                                                                 */
/**
 * end of group phalMfDuoX_DataManagement_Defines_CRLFile
 * @}
 */

/**
 * end of group phalMfDuoX_DataManagement_Defines
 * @}
 */

/**
 * \brief Reads data from Standard data files, Backup data files or TransactionMAC File.
 *
 * \note
 *      - Chaining upto the size of below mentioned buffers are handled within this interface. If more data is to be read,
 *        the user has to call this function again with bOption = #PH_EXCHANGE_RXCHAINING | one of the communication options.
 *          - In case of ISO/IEC 14443-4 Chaining, HAL response buffer is utilized. The buffer can be updated during HAL initialization.
 *          - In case of Native Chaining, Processing buffer is utilized. The buffer can be updated during this layer initialization.
 *      - In either of the exchange options, its must to provide the communication mode also.
 *      - If reading of data is performed using ISO / IEC 14443-4 chaining mode with wrapped enabled, make sure to disable
 *        \ref PHAL_MFDUOX_SHORT_LENGTH_APDU "ShortLen APDU" configuration for data larger than frame size.
 *
 * \return Status code
 * \retval #PH_ERR_SUCCESS              Operation successful.
 * \retval #PH_ERR_SUCCESS_CHAINING     Indicating more data to be read.
 * \retval #PH_ERR_INVALID_DATA_PARAMS  If DataParams is null.
 * \retval #PH_ERR_INVALID_PARAMETER
 *                                      - If the buffers are null.
 *                                      - For Invalid File Number (\b bFileNo).
 *                                      - For Invalid Chaining value (\b bIns).
 *                                      - For Invalid Communication option value (\b bOption).
 *                                      - For Invalid Exchange option value (\b bOption).
 * \retval XXXX
 *                                      - Depending on status codes return by PICC.
 *                                      - Other Depending on implementation and underlying component.
 */
phStatus_t phalMfDuoX_ReadData(
        void * pDataParams,                                                                     /**< [In] Pointer to this layer's parameter structure. */
        uint8_t bOption,                                                                        /**< [In] Options for processing of Secure Messaging and reading of data.
                                                                                                 *          - Reading data.
                                                                                                 *              - #PH_EXCHANGE_DEFAULT   : Exchanges the command and received the Data.
                                                                                                 *              - #PH_EXCHANGE_RXCHAINING: To Receive remaining Data.
                                                                                                 *
                                                                                                 *          - Communication modes. To be ORed with above values
                                                                                                 *              - \ref PHAL_MFDUOX_COMMUNICATION_PLAIN "Plain Mode"
                                                                                                 */
        uint8_t bIns,                                                                           /**< [In] Type of chaining needs to be applied. One of the below values.
                                                                                                 *          - \ref PHAL_MFDUOX_CHAINING_NATIVE
                                                                                                 *            "Native Chaining (Sub-Sequent Response with 0xAF as command code)"
                                                                                                 *          - \ref PHAL_MFDUOX_CHAINING_ISO "ISO Chaining (ISO14443-4 Chaining)"
                                                                                                 *            with ExtendedLen APDU is used when Wrapped Mode is enabled.
                                                                                                 *          - \ref PHAL_MFDUOX_CHAINING_ISO_SHORT_LEN "ISO Chaining (ISO14443-4 Chaining)"
                                                                                                 *             with ShortLength APDU is used when Wrapped Mode is enabled.
                                                                                                 */
        uint8_t bFileNo,                                                                        /**< [In] The file number from where the data to be read.
                                                                                                 *        ORed with \ref PHAL_MFDUOX_APP_SECONDARY "Secondary Application"
                                                                                                 *        indicator.
                                                                                                 */
        uint8_t * pOffset,                                                                      /**< [In] The offset from where the data should be read. Will be of 3 bytes with LSB first.
                                                                                                 *        If 0x10 need to be offset, then it will be 10 00 00.
                                                                                                 *          - 0 to (FixeSize - 1): Starting position of Read operation.
                                                                                                 *          - 0xFFFFFFFF         : Return CRLFile Meta-Data
                                                                                                 */
        uint8_t * pLength,                                                                      /**< [In] The number of bytes to be read. Will be of 3 bytes with LSB first.
                                                                                                 *          - If 0x10 bytes need to be read, then it will be 10 00 00.
                                                                                                 *          - If complete file need to be read, then it will be 00 00 00.
                                                                                                 */
        uint8_t ** ppResponse,                                                                  /**< [Out] The data returned by the PICC. */
        uint16_t * pRspLen                                                                      /**< [Out] Length of bytes available in \b ppResponse buffer. */
    );

/**
 * \brief Writes data to standard data files, backup data files or these files enabled to store
 *  CRL information.
 *
 * \note
 *      - If writing of data is performed using ISO / IEC 14443-4 chaining mode with wrapped enabled, make sure to disable
 *        \ref PHAL_MFDUOX_SHORT_LENGTH_APDU "ShortLen APDU" configuration for data larger than frame size.
 *      - Implements chaining to the card. The data provided on \b pData will be chained to the card by sending data upto
 *        the frame size of the MIFARE PICC, at a time.
 *      - CRLSignature should be computed externally and provided as part of \b pData parameter along with Data.
 *
 * \return Status code
 * \retval #PH_ERR_SUCCESS              Operation successful.
 * \retval #PH_ERR_INVALID_DATA_PARAMS  If DataParams is null.
 * \retval #PH_ERR_INVALID_PARAMETER
 *                                      - If the buffers are null.
 *                                      - For Invalid File Number (\b bFileNo).
 *                                      - For Invalid Chaining value (\b bIns).
 *                                      - For Invalid Communication option value (\b bOption).
 * \retval XXXX
 *                                      - Depending on status codes return by PICC.
 *                                      - Other Depending on implementation and underlying component.
 */
phStatus_t phalMfDuoX_WriteData(
        void * pDataParams,                                                                     /**< [In] Pointer to this layer's parameter structure. */
        uint8_t bOption,                                                                        /**< [In] Options for processing of Secure Messaging and writing of data.
                                                                                                 *          - \ref PHAL_MFDUOX_COMMUNICATION_PLAIN "Plain Mode"
                                                                                                 */
                                                                                                /**<
                                                                                                 *
                                                                                                 *          ORed with \ref PHAL_MFDUOX_TARGET_FILE_CRLFILE "CRLFile" as target
                                                                                                 *          file.
                                                                                                 */
        uint8_t bIns,                                                                           /**< [In] Type of chaining needs to be applied. One of the below values.
                                                                                                 *          - \ref PHAL_MFDUOX_CHAINING_NATIVE
                                                                                                 *            "Native Chaining (Sub-Sequent Command with 0xAF as command code)"
                                                                                                 *          - \ref PHAL_MFDUOX_CHAINING_ISO "ISO Chaining (ISO14443-4 Chaining)"
                                                                                                 */
        uint8_t bFileNo,                                                                        /**< [In] The file number to which the data to be written.
                                                                                                 *        ORed with \ref PHAL_MFDUOX_APP_SECONDARY "Secondary Application"
                                                                                                 *        indicator.
                                                                                                 */
        uint16_t wCRLVer,                                                                       /**< [In] CRLVersion is a 16-bit value encoding the current version of the CRLFile.
                                                                                                 *        Valid if targeting CRL File.
                                                                                                 */
        uint8_t * pOffset,                                                                      /**< [In] The offset from where the data should be written. Will be of 3 bytes with LSB first.
                                                                                                 *        If 0x10 need to be offset, then it will be 10 00 00.
                                                                                                 */
        uint8_t * pData,                                                                        /**< [In] The data to be written to the PICC.
                                                                                                 *          - Complete Data to be provided if not targeting CRL File
                                                                                                 *          - Complete Data including CRLSignature should be provided if targeting CRF File.
                                                                                                 */
        uint8_t * pLength                                                                       /**< [In] The number of bytes to be written. Will be of 3 bytes with LSB first.
                                                                                                 *          - If 0x10 bytes need to be written, then it will be 10 00 00.
                                                                                                 *
                                                                                                 *        \note
                                                                                                 *          - If not targeting CRF File, the length will be as mentioned above.
                                                                                                 *          - If targeting CRL file, then the length will be Length of Data + Length of CRL Signature
                                                                                                 *            In this case if Data Length is 10 bytes and CRL Signature Length is 64 bytes, then
                                                                                                 *            \b pLength will be (10 + 40) 00 00 => 50 00 00
                                                                                                 */
    );

/**
 * \brief Reads the currently stored value from value files.
 *
 * \return Status code
 * \retval #PH_ERR_SUCCESS              Operation successful.
 * \retval #PH_ERR_INVALID_DATA_PARAMS  If DataParams is null.
 * \retval #PH_ERR_INVALID_PARAMETER
 *                                      - If the buffer is null.
 *                                      - For Invalid File Number (bFileNo).
 *                                      - For Invalid Communication option value (\b bOption).
 * \retval XXXX
 *                                      - Depending on status codes return by PICC.
 *                                      - Other Depending on implementation and underlying component.
 */
phStatus_t phalMfDuoX_GetValue(
        void * pDataParams,                                                                     /**< [In] Pointer to this layer's parameter structure. */
        uint8_t bOption,                                                                        /**< [In] Options for processing of Secure Messaging while retrieving
                                                                                                 *        Value information.
                                                                                                 *          - \ref PHAL_MFDUOX_COMMUNICATION_PLAIN "Plain Mode"
                                                                                                 */
        uint8_t bFileNo,                                                                        /**< [In] The file number from which the value to be retrieved.
                                                                                                 *        ORed with \ref PHAL_MFDUOX_APP_SECONDARY "Secondary Application"
                                                                                                 *        indicator.
                                                                                                 */
        uint8_t ** ppValue,                                                                     /**< [Out] The value returned by the PICC. */
        uint16_t * pValueLen                                                                    /**< [Out] Length of bytes available in \b ppValue buffer. */
    );

/**
 * \brief Increases a value stored in a Value File
 *
 * \return Status code
 * \retval #PH_ERR_SUCCESS              Operation successful.
 * \retval #PH_ERR_INVALID_DATA_PARAMS  If DataParams is null.
 * \retval #PH_ERR_INVALID_PARAMETER
 *                                      - If the buffer is null.
 *                                      - For Invalid File Number (bFileNo).
 *                                      - For Invalid Communication option value (\b bOption).
 * \retval XXXX
 *                                      - Depending on status codes return by PICC.
 *                                      - Other Depending on implementation and underlying component.
 */
phStatus_t phalMfDuoX_Credit(
        void * pDataParams,                                                                     /**< [In] Pointer to this layer's parameter structure. */
        uint8_t bOption,                                                                        /**< [In] Communication settings for the file.
                                                                                                 *          - \ref PHAL_MFDUOX_COMMUNICATION_PLAIN "Plain Mode"
                                                                                                 */
        uint8_t bFileNo,                                                                        /**< [In] The file number to which the value should be credited.
                                                                                                 *        ORed with \ref PHAL_MFDUOX_APP_SECONDARY "Secondary Application"
                                                                                                 *        indicator.
                                                                                                 */
        uint8_t * pData                                                                         /**< [In] The value to be credited. Will be of 4 bytes with LSB first.
                                                                                                 *        If value 0x10 need to be credited, then it will be 10 00 00 00.
                                                                                                 */
    );

/**
 * \brief Decreases a value stored in a Value File
 *
 * \return Status code
 * \retval #PH_ERR_SUCCESS              Operation successful.
 * \retval #PH_ERR_INVALID_DATA_PARAMS  If DataParams is null.
 * \retval #PH_ERR_INVALID_PARAMETER
 *                                      - If the buffer is null.
 *                                      - For Invalid File Number (bFileNo).
 *                                      - For Invalid Communication option value (\b bOption).
 * \retval XXXX
 *                                      - Depending on status codes return by PICC.
 *                                      - Other Depending on implementation and underlying component.
 */
phStatus_t phalMfDuoX_Debit(
        void * pDataParams,                                                                     /**< [In] Pointer to this layer's parameter structure. */
        uint8_t bOption,                                                                        /**< [In] Communication settings for the file.
                                                                                                 *          - \ref PHAL_MFDUOX_COMMUNICATION_PLAIN "Plain Mode"
                                                                                                 */
        uint8_t bFileNo,                                                                        /**< [In] The file number to which the value should be debited.
                                                                                                 *        ORed with \ref PHAL_MFDUOX_APP_SECONDARY "Secondary Application"
                                                                                                 *        indicator.
                                                                                                 */
        uint8_t * pData                                                                         /**< [In] The value to be debited. Will be of 4 bytes with LSB first.
                                                                                                 *        If value 0x10 need to be debited, then it will be 10 00 00 00.
                                                                                                 */
    );

/**
 * \brief Allows a limited increase of a value stored in a Value file without having
 * full Cmd.Credit permissions to the file.
 *
 * \return Status code
 * \retval #PH_ERR_SUCCESS              Operation successful.
 * \retval #PH_ERR_INVALID_DATA_PARAMS  If DataParams is null.
 * \retval #PH_ERR_INVALID_PARAMETER
 *                                      - If the buffer is null.
 *                                      - For Invalid File Number (bFileNo).
 *                                      - For Invalid Communication option value (\b bOption).
 * \retval XXXX
 *                                      - Depending on status codes return by PICC.
 *                                      - Other Depending on implementation and underlying component.
 */
phStatus_t phalMfDuoX_LimitedCredit(
        void * pDataParams,                                                                     /**< [In] Pointer to this layer's parameter structure. */
        uint8_t bOption,                                                                        /**< [In] Communication settings for the file.
                                                                                                 *          - \ref PHAL_MFDUOX_COMMUNICATION_PLAIN "Plain Mode"
                                                                                                 */
        uint8_t bFileNo,                                                                        /**< [In] The file number to which the value should be credited.
                                                                                                 *        ORed with \ref PHAL_MFDUOX_APP_SECONDARY "Secondary Application"
                                                                                                 *        indicator.
                                                                                                 */
        uint8_t * pData                                                                         /**< [In] The value to be credited. Will be of 4 bytes with LSB first.
                                                                                                 *        If value 0x10 need to be credited, then it will be 10 00 00 00.
                                                                                                 */
    );

/**
 * \brief Reads out a set of complete records from a Cyclic or Linear Record File.
 *
 * \note
 *      - Chaining upto the size of below mentioned buffers are handled within this interface. If more data is to be read,
 *        the user has to call this function again with bOption = #PH_EXCHANGE_RXCHAINING | one of the communication options.
 *          - In case of ISO/IEC 14443-4 Chaining, HAL response buffer is utilized. The buffer can be updated during HAL initialization.
 *          - In case of Native Chaining, Processing buffer is utilized. The buffer can be updated during this layer initialization.
 *      - In either of the exchange options, its must to provide the communication mode also.
 *      - If reading of data is performed using ISO / IEC 14443-4 chaining mode with wrapped enabled, make sure to disable
 *        \ref PHAL_MFDUOX_SHORT_LENGTH_APDU "ShortLen APDU" configuration for data larger than frame size.
 *      - If TMI collection is ON and
 *          - If \b pRecCount is zero then \b pRecSize is a mandatory parameter.
 *          - If \b pRecSize and \b pRecCount are zero, then #PH_ERR_INVALID_PARAMETER "Invalid Parameter" error will be returned.
 *          - If wrong \b pRecSize is provided, then wrong \b pRecCount value will be calculated and updated for TMI collection.
 *
 * \return Status code
 * \retval #PH_ERR_SUCCESS              Operation successful.
 * \retval #PH_ERR_SUCCESS_CHAINING     Indicating more data to be read.
 * \retval #PH_ERR_INVALID_DATA_PARAMS  If DataParams is null.
 * \retval #PH_ERR_INVALID_PARAMETER
 *                                      - If the buffers are null.
 *                                      - For Invalid File Number (\b bFileNo).
 *                                      - For Invalid Chaining value (\b bIns).
 *                                      - For Invalid Communication option value (\b bOption).
 *                                      - For Invalid Exchange option value (\b bOption).
 *                                      - If \b pRecSize and \b pRecCount are zero and TMI Collection is enabled.
 * \retval XXXX
 *                                      - Depending on status codes return by PICC.
 *                                      - Other Depending on implementation and underlying component.
 */
phStatus_t phalMfDuoX_ReadRecords(
        void * pDataParams,                                                                     /**< [In] Pointer to this layer's parameter structure. */
        uint8_t bOption,                                                                        /**< [In] Options for processing ofSecure Messaging and reading of data.
                                                                                                 *          - Reading data.
                                                                                                 *              - #PH_EXCHANGE_DEFAULT   : Exchanges the command and received the Data.
                                                                                                 *              - #PH_EXCHANGE_RXCHAINING: To Receive remaining Data.
                                                                                                 *
                                                                                                 *          - Communication modes. To be ORed with above values
                                                                                                 *              - \ref PHAL_MFDUOX_COMMUNICATION_PLAIN "Plain Mode"
                                                                                                 */
        uint8_t bIns,                                                                           /**< [In] Type of chaining needs to be applied. One of the below values.
                                                                                                 *          - \ref PHAL_MFDUOX_CHAINING_NATIVE
                                                                                                 *            "Native Chaining (Sub-Sequent command or Response with 0xAF as command code)"
                                                                                                 *          - \ref PHAL_MFDUOX_CHAINING_ISO "ISO Chaining (ISO14443-4 Chaining)"
                                                                                                 *            with ExtendedLen APDU is used when Wrapped Mode is enabled.
                                                                                                 *          - \ref PHAL_MFDUOX_CHAINING_ISO_SHORT_LEN "ISO Chaining (ISO14443-4 Chaining)"
                                                                                                 *             with ShortLength APDU is used when Wrapped Mode is enabled.
                                                                                                 */
        uint8_t bFileNo,                                                                        /**< [In] The file number from where the data to be read.
                                                                                                 *        ORed with \ref PHAL_MFDUOX_APP_SECONDARY "Secondary Application"
                                                                                                 *        indicator.
                                                                                                 */
        uint8_t * pRecNo,                                                                       /**< [In] Record number of the newest record targeted, starting to count
                                                                                                 *        from the latest record written. Will be of 3 bytes with LSB first.
                                                                                                 *        If 0x10 need to be record number, then it will be 10 00 00.
                                                                                                 */
        uint8_t * pRecCount,                                                                    /**< [In] Number of records to be read. If 0x10 need to be record number,
                                                                                                 *        then it will be 10 00 00.
                                                                                                 */
        uint8_t * pRecSize,                                                                     /**< [In] The number of bytes to be read. Will be of 3 bytes with LSB first. */
        uint8_t ** ppResponse,                                                                  /**< [Out] The data returned by the PICC. */
        uint16_t * pRspLen                                                                      /**< [Out] Length of bytes available in \b ppResponse buffer. */
    );

/**
 * \brief Writes data to a record in a Cyclic or Linear Record File.
 *
 * \remarks
 *      - If writing of data is performed using ISO / IEC 14443-4 chaining mode with wrapped enabled, make sure to disable
 *        \ref PHAL_MFDUOX_SHORT_LENGTH_APDU "ShortLen APDU" configuration for data larger than frame size.
 *      - Implements chaining to the card. The data provided on \b pData will be chained to the card by sending data upto
 *        the frame size of the MIFARE DUOX PICC, at a time.
 *
 * \return Status code
 * \retval #PH_ERR_SUCCESS              Operation successful.
 * \retval #PH_ERR_INVALID_DATA_PARAMS  If DataParams is null.
 * \retval #PH_ERR_INVALID_PARAMETER
 *                                      - If the buffers are null.
 *                                      - For Invalid File Number (\b bFileNo).
 *                                      - For Invalid Chaining value (\b bIns).
 *                                      - For Invalid Communication option value (\b bOption).
 * \retval XXXX
 *                                      - Depending on status codes return by PICC.
 *                                      - Other Depending on implementation and underlying component.
 */
phStatus_t phalMfDuoX_WriteRecord(
        void * pDataParams,                                                                     /**< [In] Pointer to this layer's parameter structure. */
        uint8_t bOption,                                                                        /**< [In] Options for processing of Secure Messaging and writing of data.
                                                                                                 *          - \ref PHAL_MFDUOX_COMMUNICATION_PLAIN "Plain Mode"
                                                                                                 */
        uint8_t bIns,                                                                           /**< [In] Type of chaining needs to be applied. One of the below values.
                                                                                                 *          - \ref PHAL_MFDUOX_CHAINING_NATIVE
                                                                                                 *            "Native Chaining (Sub-Sequent command or Response with 0xAF as command code)"
                                                                                                 *          - \ref PHAL_MFDUOX_CHAINING_ISO "ISO Chaining (ISO14443-4 Chaining)"
                                                                                                 */
        uint8_t bFileNo,                                                                        /**< [In] The file number to which the data to be written.
                                                                                                 *        ORed with \ref PHAL_MFDUOX_APP_SECONDARY "Secondary Application"
                                                                                                 *        indicator.
                                                                                                 */
        uint8_t * pOffset,                                                                      /**< [In] The offset from where the data should be written. Will be of 3 bytes with LSB first.
                                                                                                 *        If 0x10 need to be offset, then it will be 10 00 00.
                                                                                                 */
        uint8_t * pData,                                                                        /**< [In] The data to be written to the PICC. */
        uint8_t * pLength                                                                       /**< [In] The number of bytes to be written. Will be of 3 bytes with LSB first.
                                                                                                 *        If 0x10 bytes need to be written, then it will be 10 00 00.
                                                                                                 */
    );

/**
 * \brief Updates data of an existing record in a LinearRecord or CyclicRecord file.
 *
 * \remarks
 *      - If updating of data is performed using ISO / IEC 14443-4 chaining mode with wrapped enabled, make sure to disable
 *        \ref PHAL_MFDUOX_SHORT_LENGTH_APDU "ShortLen APDU" configuration for data larger than frame size.
 *      - Implements chaining to the card. The data provided on \b pData will be chained to the card by sending data upto
 *        the frame size of the MIFARE DUOX PICC, at a time.
 *
 * \return Status code
 * \retval #PH_ERR_SUCCESS              Operation successful.
 * \retval #PH_ERR_INVALID_DATA_PARAMS  If DataParams is null.
 * \retval #PH_ERR_INVALID_PARAMETER
 *                                      - If the buffers are null.
 *                                      - For Invalid File Number (\b bFileNo).
 *                                      - For Invalid Chaining value (\b bIns).
 *                                      - For Invalid Communication option value (\b bOption).
 * \retval XXXX
 *                                      - Depending on status codes return by PICC.
 *                                      - Other Depending on implementation and underlying component.
 */
phStatus_t phalMfDuoX_UpdateRecord(
        void * pDataParams,                                                                     /**< [In] Pointer to this layer's parameter structure. */
        uint8_t bOption,                                                                        /**< [In] Options for processing of Secure Messaging and updating of data.
                                                                                                 *          - \ref PHAL_MFDUOX_COMMUNICATION_PLAIN "Plain Mode"
                                                                                                 */
        uint8_t bIns,                                                                           /**< [In] Type of chaining needs to be applied. One of the below values.
                                                                                                 *          - \ref PHAL_MFDUOX_CHAINING_NATIVE
                                                                                                 *            "Native Chaining (Sub-Sequent command or Response with 0xAF as command code)"
                                                                                                 *          - \ref PHAL_MFDUOX_CHAINING_ISO "ISO Chaining (ISO14443-4 Chaining)"
                                                                                                 */
        uint8_t bFileNo,                                                                        /**< [In] The file number to which the data to be updated.
                                                                                                 *        ORed with \ref PHAL_MFDUOX_APP_SECONDARY "Secondary Application"
                                                                                                 *        indicator.
                                                                                                 */
        uint8_t * pRecNo,                                                                       /**< [In] Record number of the newest record targeted, starting to count
                                                                                                 *        from the latest record updated. Will be of 3 bytes with LSB first.
                                                                                                 *        If 0x10 need to be record number, then it will be 10 00 00.
                                                                                                 */
        uint8_t * pOffset,                                                                      /**< [In] The offset from where the data should be updated. Will be of 3 bytes with LSB first.
                                                                                                 *        If 0x10 need to be offset, then it will be 10 00 00.
                                                                                                 */
        uint8_t * pData,                                                                        /**< [In] The data to be updated to the PICC. */
        uint8_t * pLength                                                                       /**< [In] The number of bytes to be updated. Will be of 3 bytes with LSB first.
                                                                                                 *        If 0x10 bytes need to be updated, then it will be 10 00 00.
                                                                                                 */
    );

/**
 * \brief Resets a Cyclic or Linear Record File.
 *
 * \return Status code
 * \retval #PH_ERR_SUCCESS              Operation successful.
 * \retval #PH_ERR_INVALID_DATA_PARAMS  If DataParams is null.
 * \retval #PH_ERR_INVALID_PARAMETER    For Invalid File Number (\b bFileNo).
 * \retval XXXX
 *                                      - Depending on status codes return by PICC.
 *                                      - Other Depending on implementation and underlying component.
 */
phStatus_t phalMfDuoX_ClearRecordFile(
        void * pDataParams,                                                                     /**< [In] Pointer to this layer's parameter structure. */
        uint8_t bFileNo                                                                         /**< [In] The file number which needs to be cleared.
                                                                                                 *        ORed with \ref PHAL_MFDUOX_APP_SECONDARY "Secondary Application"
                                                                                                 *        indicator.
                                                                                                 */
    );

/**
 * end of group phalMfDuoX_DataManagement
 * @}
 */

/* MIFARE DUOX Transaction Management commands ------------------------------------------------------------------------------------------ */
/**
 * \defgroup phalMfDuoX_TransactionManagement Commands_TransactionManagement
 * \brief Describes about the MIFARE DUOX Transaction Management commands.
 * @{
 */

/**
 * \defgroup phalMfDuoX_TransactionManagement_Defines Defines
 * \brief Macro Definitions for Transaction Management commands.
 * @{
 */

/**
 * \defgroup phalMfDuoX_TransactionManagement_Defines_Option Option
 * \brief The Options to be used for \ref phalMfDuoX_CommitTransaction "Commit Transaction" interface.
 * @{
 */
#define PHAL_MFDUOX_OPTION_NOT_EXCHANGED                                                0x80    /**< Option byte is not exchanged to the PICC. */
#define PHAL_MFDUOX_OPTION_TRANSACTION_INFO_NOT_RETURNED                                0x00    /**< Option byte is exchanged to PICC and represent no return of TMC and TMV / TSV. */
#define PHAL_MFDUOX_OPTION_TRANSACTION_INFO_RETURNED                                    0x01    /**< Option byte is exchanged to PICC and represent return of TMC and TMV / TSV. */
/**
 * end of group phalMfDuoX_TransactionManagement_Defines_Option
 * @}
 */

/**
 * end of group phalMfDuoX_TransactionManagement_Defines
 * @}
 */

/**
 * \brief Validates all previous write access on Backup Data files, Value files and Record files within selected
 * application. If applicable, the TransactionMAC file is updated with the calculated Transaction MAC or
 * Transaction Signature.
 *
 * \note
 *      - With respect to command parameter \b bOption, PICC expects
 *          - No Option byte in command frame.
 *          - Option byte with zero as value in command frame along with command code.
 *          - Option byte with one as value in command frame along with command code.
 *
 *      - If Option byte is required to be exchanged to PICC along with command code, user needs to pass
 *        \b bOption value with MSB set.
 *          - If \b bOption = \ref PHAL_MFDUOX_OPTION_NOT_EXCHANGED "Option Not Exchanged", only command is exchanged
 *            and Option byte is not exchanged to PICC.
 *          - If \b bOption = other than \ref PHAL_MFDUOX_OPTION_NOT_EXCHANGED "Option Not Exchanged",
 *              - Both command and option bytes are exchanged to PICC.
 *              - While exchanging the option byte to PICC, the MSB bit is masked out.
 *
 * \return Status code
 * \retval #PH_ERR_SUCCESS              Operation successful.
 * \retval #PH_ERR_INVALID_DATA_PARAMS  If DataParams is null.
 * \retval #PH_ERR_INVALID_PARAMETER
 *                                      - If the buffers are null.
 *                                      - For Invalid option value. (\b bOption).
 * \retval #PH_ERR_PROTOCOL_ERROR       If the response is less than 8 bytes for the case when Return of TMC
 *                                      and TMV / TSV is selected.
 * \retval XXXX
 *                                      - Depending on status codes return by PICC.
 *                                      - Other Depending on implementation and underlying component.
 */
phStatus_t phalMfDuoX_CommitTransaction(
        void * pDataParams,                                                                     /**< [In] Pointer to this layer's parameter structure. */
        uint8_t bOption,                                                                        /**< [In] Calculated Transaction MAC/Signature requested on response.
                                                                                                 *        Should be one of the below values.
                                                                                                 *          - \ref PHAL_MFDUOX_OPTION_NOT_EXCHANGED "Option Not Exchanged"
                                                                                                 *          - \ref PHAL_MFDUOX_OPTION_TRANSACTION_INFO_NOT_RETURNED
                                                                                                 *            "Transaction Information not Returned"
                                                                                                 *          - \ref PHAL_MFDUOX_OPTION_TRANSACTION_INFO_RETURNED
                                                                                                 *            "Transaction Information Returned"
                                                                                                 */
        uint8_t ** ppTMC,                                                                       /**< [Out] The increased Transaction MAC Counter (TMC) as stored in
                                                                                                 *         FileType.TransactionMAC.
                                                                                                 */
        uint16_t * pTMCLen,                                                                     /**< [Out] Length of bytes available in \b ppTMC buffer. */
        uint8_t ** ppResponse,                                                                  /**< [Out] Returns one of the following information based on the functionality
                                                                                                 *         that is enabled during TransactionMAC File creation.
                                                                                                 *          - If Transaction MAC is Enabled, Transaction MAC Value (TMV) will
                                                                                                 *            be available.
                                                                                                 *          - If Transaction Signature is Enabled, Transaction Signature
                                                                                                 *            Value (TSV) will be available.
                                                                                                 */
        uint16_t * pRspLen                                                                      /**< [Out] Length of bytes available in \b ppResponse buffer. */
    );

/**
 * \brief Aborts all previous write accesses on Backup Data files, Value files and Record files within the selected
 * application(s). If applicable, the Transaction MAC calculation is aborted.
 *
 * \return Status code
 * \retval #PH_ERR_SUCCESS              Operation successful.
 * \retval #PH_ERR_INVALID_DATA_PARAMS  If DataParams is null.
 * \retval XXXX
 *                                      - Depending on status codes return by PICC.
 *                                      - Other Depending on implementation and underlying component.
 */
phStatus_t phalMfDuoX_AbortTransaction(
        void * pDataParams                                                                      /**< [In] Pointer to this layer's parameter structure. */
    );

/**
 * \brief Commits a ReaderID for the ongoing transaction. This will allow a back-end to identify the
 * attacking merchant in case of fraud detected.
 *
 * \return Status code
 * \retval #PH_ERR_SUCCESS              Operation successful.
 * \retval #PH_ERR_INVALID_DATA_PARAMS  If DataParams is null.
 * \retval #PH_ERR_INVALID_PARAMETER    If the buffers are null.
 * \retval XXXX
 *                                      - Depending on status codes return by PICC.
 *                                      - Other Depending on implementation and underlying component.
 */
phStatus_t phalMfDuoX_CommitReaderID(
        void * pDataParams,                                                                     /**< [In] Pointer to this layer's parameter structure. */
        uint8_t * pTMRI,                                                                        /**< [In] Transaction MAC ReaderID information. */
        uint8_t bTMRILen,                                                                       /**< [In] Length of bytes available in \b pTMRI buffer. */
        uint8_t ** ppEncTMRI,                                                                   /**< [Out] Encrypted Transaction MAC ReaderID of the latest successful transaction. */
        uint16_t * pEncTMRILen                                                                  /**< [Out] Length of bytes available in \b ppEncTMRI buffer. */
    );

/**
 * end of group phalMfDuoX_TransactionManagement
 * @}
 */

/* MIFARE DUOX Cryptographic support commands ------------------------------------------------------------------------------------------- */
/**
 * \defgroup phalMfDuoX_CryptographicSupport Commands_CryptographicSupport
 * \brief Describes about the MIFARE DUOX Cryptographic Support commands.
 * @{
 */

/**
 * \defgroup phalMfDuoX_CryptographicSupport_Defines Defines
 * \brief Macro Definitions for Cryptographic Support commands.
 * @{
 */

/**
 * \defgroup phalMfDuoX_CryptographicSupport_Defines_TargetAction TargetAction
 * \brief The Options to be used for \ref phalMfDuoX_CryptoRequest "CryptoRequest" interface.
 * @{
 */
#define PHAL_MFDUOX_TARGET_ACTION_ECC_SIGN                                              0x03    /**< Option for CryptoRequest action as Sign. */
#define PHAL_MFDUOX_TARGET_ACTION_ECC_ECHO                                              0xFD    /**< Option for CryptoRequest action as Echo. */
/**
 * end of group phalMfDuoX_CryptographicSupport_Defines_TargetAction
 * @}
 */

/**
 * \defgroup phalMfDuoX_CryptographicSupport_Defines_TargetOperation TargetOperation
 * \brief The Options to be used for \ref phalMfDuoX_CryptoRequestECCSign "CryptoRequest_DUOXSign" interface.
 * @{
 */
#define PHAL_MFDUOX_TARGET_OPERATION_INITIALIZE_SIGNATURE                               0x01    /**< Option for Operation as Initialize Signature. */
#define PHAL_MFDUOX_TARGET_OPERATION_UPDATE_DATA                                        0x02    /**< Option for Operation as Update data to be signed. */
#define PHAL_MFDUOX_TARGET_OPERATION_FINALIZE_DATA                                      0x03    /**< Option for Operation as Finalize data to be signed. */
#define PHAL_MFDUOX_TARGET_OPERATION_ONE_SHOT_RAW_DATA                                  0x04    /**< Option for Operation as One-Shot Operation with Raw Data. */
#define PHAL_MFDUOX_TARGET_OPERATION_ONE_SHOT_HASH_DATA                                 0x05    /**< Option for Operation as One-Shot Operation with Pre-Computed Hash. */
/**
 * end of group phalMfDuoX_CryptographicSupport_Defines_TargetOperation
 * @}
 */

/**
 * \defgroup phalMfDuoX_CryptographicSupport_Defines_TargetAlgorithm TargetAlgorithm
 * \brief The Options to be used for \ref phalMfDuoX_CryptoRequestECCSign "CryptoRequest_DUOXSign" interface.
 * @{
 */
#define PHAL_MFDUOX_TARGET_ALGORITHM_ECDSA_SHA256                                       0x00    /**< Option for Algorithm as ECDSA with SHA-256. */
/**
 * end of group phalMfDuoX_CryptographicSupport_Defines_TargetAction
 * @}
 */

/**
 * \defgroup phalMfDuoX_CryptographicSupport_Defines_InputSource InputSource
 * \brief The Options to be used for \ref phalMfDuoX_CryptoRequestECCSign "CryptoRequest_DUOXSign" interface.
 * @{
 */
#define PHAL_MFDUOX_INPUT_SOURCE_CMDBUF_EXPLICT_LEN                                      0xF0   /**< Option for InputSource as Command Buffer with explicit length. */
/**
 * end of group phalMfDuoX_CryptographicSupport_Defines_TargetAction
 * @}
 */

/**
 * end of group phalMfDuoX_CryptographicSupport_Defines
 * @}
 */

/**
 * \brief Executes a cryptographic operation. This is the generic API definition, including common error codes
 *
 * \return Status code
 * \retval #PH_ERR_SUCCESS              Operation successful.
 * \retval #PH_ERR_INVALID_DATA_PARAMS  If DataParams is null.
 * \retval #PH_ERR_INVALID_PARAMETER
 *                                      - If the buffers are null.
 *                                      - The values provided in \b bComOption is not supported.
 * \retval XXXX
 *                                      - Depending on status codes return by PICC.
 *                                      - Other Depending on implementation and underlying component.
 */
phStatus_t phalMfDuoX_CryptoRequest(
        void * pDataParams,                                                                     /**< [In] Pointer to this layer's parameter structure. */
        uint8_t bComOption,                                                                     /**< [In] Indicates the mode of communication to be used while exchanging the
                                                                                                 *        data to PICC.
                                                                                                 *          - \ref PHAL_MFDUOX_COMMUNICATION_PLAIN "Plain Mode"
                                                                                                 */
        uint8_t bAction,                                                                        /**< [In] Targeted action to perform. One of the below values.
                                                                                                 *          - \ref PHAL_MFDUOX_TARGET_ACTION_ECC_SIGN "Action As Signature"
                                                                                                 *          - \ref PHAL_MFDUOX_TARGET_ACTION_ECC_ECHO "Action As Echo"
                                                                                                 */
        uint8_t * pInputData,                                                                   /**< [In] Input data for which the cryptographic operation needs to be performed.
                                                                                                 *          - For targeted action - \ref PHAL_MFDUOX_TARGET_ACTION_ECC_SIGN "Action As Signature"
                                                                                                 *          - Input data should be as follows, \n
                                                                                                 *              Byte 0 =>  Target Operation to use. One of the below values.
                                                                                                 *                         - \ref PHAL_MFDUOX_TARGET_OPERATION_INITIALIZE_SIGNATURE
                                                                                                 *                           "Initialize signature operation"
                                                                                                 *                         - \ref PHAL_MFDUOX_TARGET_OPERATION_UPDATE_DATA
                                                                                                 *                           "Update data to be signed"
                                                                                                 *                         - \ref PHAL_MFDUOX_TARGET_OPERATION_FINALIZE_DATA
                                                                                                 *                           "Finalize signature operation"
                                                                                                 *                         - \ref PHAL_MFDUOX_TARGET_OPERATION_ONE_SHOT_RAW_DATA
                                                                                                 *                           "One-shot operation with raw data"
                                                                                                 *                         - \ref PHAL_MFDUOX_TARGET_OPERATION_ONE_SHOT_HASH_DATA
                                                                                                 *                           "One-shot operation with pre-computed hash"
                                                                                                 *
                                                                                                 *              For target Operations,
                                                                                                 *                         - \ref PHAL_MFDUOX_TARGET_OPERATION_INITIALIZE_SIGNATURE
                                                                                                 *                           "Initialize signature operation"
                                                                                                 *                         - \ref PHAL_MFDUOX_TARGET_OPERATION_ONE_SHOT_RAW_DATA
                                                                                                 *                           "One-shot operation with raw data"
                                                                                                 *                         - \ref PHAL_MFDUOX_TARGET_OPERATION_ONE_SHOT_HASH_DATA
                                                                                                 *                           "One-shot operation with pre-computed hash" \n
                                                                                                 *              Byte 1 =>  Target Algorithm to use.
                                                                                                 *                         - \ref PHAL_MFDUOX_TARGET_ALGORITHM_ECDSA_SHA256 "ECDSA with SHA256" \n
                                                                                                 *              Byte 2 =>  Key number of the targeted key. One of the following
                                                                                                 *                         - At PICC Level: 0x00 - 0x01 keys are supported.
                                                                                                 *                         - At APP Level : 0x00 - 0x04 keys are supported. \n
                                                                                                 *              Byte 3 =>  Input Source to use.
                                                                                                 *                         - \ref PHAL_MFDUOX_INPUT_SOURCE_CMDBUF_EXPLICT_LEN "Command Buffer with explicit length" \n
                                                                                                 *              Byte 4 => Length of Input data to be signed.
                                                                                                 *
                                                                                                 *              For target Operations,
                                                                                                 *                         - \ref PHAL_MFDUOX_TARGET_OPERATION_UPDATE_DATA
                                                                                                 *                           "Update data to be signed"
                                                                                                 *                         - \ref PHAL_MFDUOX_TARGET_OPERATION_FINALIZE_DATA
                                                                                                 *                           "Finalize signature operation" \n
                                                                                                 *              Byte 1 => Input Source to use.
                                                                                                 *                        \ref PHAL_MFDUOX_INPUT_SOURCE_CMDBUF_EXPLICT_LEN "Command Buffer with explicit length" \n
                                                                                                 *              Byte 2 => Length of Input data to be signed.
                                                                                                 *
                                                                                                 *          Followed by Input data to be signed.
                                                                                                 */
        uint16_t wInputLen,                                                                     /**< [In] Length of bytes available in \b pInputData buffer. */
        uint8_t ** ppResponse,                                                                  /**< [Out] Cryptographic output for the provided input. */
        uint16_t * pRspLen                                                                      /**< [Out] Length of bytes available in \b ppResponse buffer. */
    );

/**
 * \brief Executes an ECC signature generation
 *
 * \return Status code
 * \retval #PH_ERR_SUCCESS              Operation successful.
 * \retval #PH_ERR_INVALID_DATA_PARAMS  If DataParams is null.
 * \retval #PH_ERR_INVALID_PARAMETER
 *                                      - If the buffers are null.
 *                                      - If the InputType is not supported (\b bInputType).
 *                                      - The values provided in \b bComOption is not supported.
 * \retval XXXX
 *                                      - Depending on status codes return by PICC.
 *                                      - Other Depending on implementation and underlying component.
 */
phStatus_t phalMfDuoX_CryptoRequestECCSign(
        void * pDataParams,                                                                     /**< [In] Pointer to this layer's parameter structure. */
        uint8_t bComOption,                                                                     /**< [In] Indicates the mode of communication to be used while exchanging the
                                                                                                 *        data to PICC.
                                                                                                 *          - \ref PHAL_MFDUOX_COMMUNICATION_PLAIN "Plain Mode"
                                                                                                 */
        uint8_t bOperation,                                                                     /**< [In] Target Operation to use. One of the below values.
                                                                                                 *          - \ref PHAL_MFDUOX_TARGET_OPERATION_INITIALIZE_SIGNATURE
                                                                                                 *            "Initialize signature operation"
                                                                                                 *          - \ref PHAL_MFDUOX_TARGET_OPERATION_UPDATE_DATA
                                                                                                 *            "Update data to be signed"
                                                                                                 *          - \ref PHAL_MFDUOX_TARGET_OPERATION_FINALIZE_DATA
                                                                                                 *            "Finalize signature operation"
                                                                                                 *          - \ref PHAL_MFDUOX_TARGET_OPERATION_ONE_SHOT_RAW_DATA
                                                                                                 *            "One-shot operation with raw data"
                                                                                                 *          - \ref PHAL_MFDUOX_TARGET_OPERATION_ONE_SHOT_HASH_DATA
                                                                                                 *            "One-shot operation with pre-computed hash"
                                                                                                 */
        uint8_t bAlgo,                                                                          /**< [In] Target Algorithm to use. One of the below values
                                                                                                 *          \ref PHAL_MFDUOX_TARGET_ALGORITHM_ECDSA_SHA256 "ECDSA with SHA256"
                                                                                                 */
        uint8_t bKeyNo,                                                                         /**< [In] Key number of the targeted key. One of the following
                                                                                                 *          - At PICC Level: 0x00 - 0x01 keys are supported.
                                                                                                 *          - At APP Level : 0x00 - 0x04 keys are supported.
                                                                                                 */
        uint8_t bInputSource,                                                                   /**< [In] Input Source to use. One of the below values.
                                                                                                 *          \ref PHAL_MFDUOX_INPUT_SOURCE_CMDBUF_EXPLICT_LEN "Command Buffer with explicit length"
                                                                                                 */
        uint8_t * pInputData,                                                                   /**< [In] Input data to be signed. Can be one of the following.
                                                                                                 *          - \ref PHAL_MFDUOX_TARGET_OPERATION_ONE_SHOT_RAW_DATA "Raw Data to be Hashed"
                                                                                                 *          - \ref PHAL_MFDUOX_TARGET_OPERATION_ONE_SHOT_HASH_DATA "Pre-Computed Hashed Data"
                                                                                                 */
        uint8_t bInputLen,                                                                      /**< [In] Length of bytes available in \b pInputData buffer. */
        uint8_t ** ppSign,                                                                      /**< [Out] ECDSA Signature for the provided input. */
        uint16_t * pSignLen                                                                     /**< [Out] Length of bytes available in \b ppSign buffer. */
    );

/**
 * \brief Performs echoing of the data being transmitted. This allows to easily test the communication interface.
 *
 * \return Status code
 * \retval #PH_ERR_SUCCESS              Operation successful.
 * \retval #PH_ERR_INVALID_DATA_PARAMS  If DataParams is null.
 * \retval #PH_ERR_INVALID_PARAMETER
 *                                      - If the buffers are null.
 *                                      - If the InputType is not supported (\b bInputType).
 *                                      - The values provided in \b bComOption is not supported.
 * \retval XXXX
 *                                      - Depending on status codes return by PICC.
 *                                      - Other Depending on implementation and underlying component.
 */
phStatus_t phalMfDuoX_CryptoRequestEcho(
        void * pDataParams,                                                                     /**< [In] Pointer to this layer's parameter structure. */
        uint8_t bComOption,                                                                     /**< [In] Indicates the mode of communication to be used while exchanging the
                                                                                                 *        data to PICC.
                                                                                                 *          - \ref PHAL_MFDUOX_COMMUNICATION_PLAIN "Plain Mode"
                                                                                                 */
        uint8_t * pInputData,                                                                   /**< [In] Input data to be echoed. */
        uint8_t bInputLen,                                                                      /**< [In] Length of bytes available in \b pInputData buffer. */
        uint8_t ** ppResponse,                                                                  /**< [Out] Cryptographic output for the provided input. */
        uint16_t * pRspLen                                                                      /**< [Out] Length of bytes available in \b ppResponse buffer. */
    );

/**
 * end of group phalMfDuoX_CryptographicSupport
 * @}
 */

/* MIFARE DUOX GPIO Management commands ------------------------------------------------------------------------------------------------- */
/**
 * \defgroup phalMfDuoX_GPIOManagement Commands_GPIOManagement
 * \brief Describes about the MIFARE DUOX Cryptographic Support commands.
 * @{
 */

/**
 * \defgroup phalMfDuoX_GPIOManagement_Defines Defines
 * \brief Macro Definitions for GPIO Management commands.
 * @{
 */

/**
 * \defgroup phalMfDuoX_GPIOManagement_Defines_GPIONumber GPIONumber
 * \brief The Options for representing GPIO number. To be used with \ref phalMfDuoX_ManageGPIO "ManageGPIO" interface.
 * @{
 */
#define PHAL_MFDUOX_GPIO_NUMBER_1                                                       0x00    /**< Option to indicate GPIO number as 1. */
#define PHAL_MFDUOX_GPIO_NUMBER_2                                                       0x01    /**< Option to indicate GPIO number as 2. */
/**
 * end of group phalMfDuoX_GPIOManagement_Defines_GPIONumber
 * @}
 */

/**
 * \defgroup phalMfDuoX_GPIOManagement_Defines_Operation Operation
 * \brief The Options for representing operation to perform for the respective GPIO.
 * To be used with \ref phalMfDuoX_ManageGPIO "ManageGPIO" interface.
 * @{
 */

/**
 * \defgroup phalMfDuoX_GPIOManagement_Defines_Operation_Output Mode_Output
 * \brief The Options for representing operation to perform for the GPIO configured as output.
 * @{
 */
#define PHAL_MFDUOX_GPIO_OPERATION_GPIO_CONTROL_CLEAR                                   0x00    /**< Option to indicate GPIO Control as CLEAR.
                                                                                                 *      Clear the GPIO state to LOW(not driven) or stop power
                                                                                                 *      harvesting depending on the mode.
                                                                                                 */
#define PHAL_MFDUOX_GPIO_OPERATION_GPIO_CONTROL_SET                                     0x01    /**< Option to indicate GPIO Control as SET.
                                                                                                 *      Set the GPIO State to HIGH (driven) or start power harvesting
                                                                                                 *      depending on the mode.
                                                                                                 */
#define PHAL_MFDUOX_GPIO_OPERATION_GPIO_CONTROL_TOGGLE                                  0x02    /**< Option to indicate GPIO Control as TOGGLE.
                                                                                                 *      Toggle the GPIO State or power harvesting state depending
                                                                                                 *      on the mode.
                                                                                                 */
#define PHAL_MFDUOX_GPIO_OPERATION_NO_NFC_ACTION                                        0x00    /**< Option to indicate No NFC action. */
#define PHAL_MFDUOX_GPIO_OPERATION_PAUSE_NFC                                            0x80    /**< Option to indicate Pause NFC (only accepted over NFC). */
#define PHAL_MFDUOX_GPIO_OPERATION_RELEASE_NFC_PAUSE                                    0x80    /**< Option to indicate Release NFC Pause (only accepted over I2C) */
/**
 * end of group phalMfDuoX_GPIOManagement_Defines_Operation_Output
 * @}
 */

/**
 * \defgroup phalMfDuoX_GPIOManagement_Defines_Operation_PowerOut Mode_DownStreamPowerOut
 * \brief The Options for representing operation to perform for the GPIO configured as
 * Down-Stream Power Out.
 * @{
 */

/**
 * \defgroup phalMfDuoX_GPIOManagement_Defines_Operation_PowerOut_TargetVI Target Voltage and Current
 * \brief The Options for representing target Voltage and Current operation to perform for the GPIO
 * configured as Down-Stream Power Out. Applicable to Bits 7 - 2.
 * @{
 */
#define PHAL_MFDUOX_GPIO_OPERATION_V_I_DEFAULT                                          0x00    /**< Option to indicate Default level as configured with Cmd.SetConfiguration. */
#define PHAL_MFDUOX_GPIO_OPERATION_1_8V_100UA                                           0x04    /**< Option to indicate Power downstream voltage of 1.8V and current of 100uA. */
#define PHAL_MFDUOX_GPIO_OPERATION_1_8V_300UA                                           0x08    /**< Option to indicate Power downstream voltage of 1.8V and current of 300uA. */
#define PHAL_MFDUOX_GPIO_OPERATION_1_8V_500UA                                           0x0C    /**< Option to indicate Power downstream voltage of 1.8V and current of 500uA. */
#define PHAL_MFDUOX_GPIO_OPERATION_1_8V_1MA                                             0x10    /**< Option to indicate Power downstream voltage of 1.8V and current of 1mA. */
#define PHAL_MFDUOX_GPIO_OPERATION_1_8V_2MA                                             0x14    /**< Option to indicate Power downstream voltage of 1.8V and current of 2mA. */
#define PHAL_MFDUOX_GPIO_OPERATION_1_8V_3MA                                             0x18    /**< Option to indicate Power downstream voltage of 1.8V and current of 3mA. */
#define PHAL_MFDUOX_GPIO_OPERATION_1_8V_5MA                                             0x1C    /**< Option to indicate Power downstream voltage of 1.8V and current of 5mA. */
#define PHAL_MFDUOX_GPIO_OPERATION_1_8V_7MA                                             0x20    /**< Option to indicate Power downstream voltage of 1.8V and current of 7mA. */
#define PHAL_MFDUOX_GPIO_OPERATION_1_8V_10MA                                            0x24    /**< Option to indicate Power downstream voltage of 1.8V and current of 10mA. */
#define PHAL_MFDUOX_GPIO_OPERATION_1_8V_MAX_CURRENT                                     0x3C    /**< Option to indicate Power downstream voltage of 1.8V and maximum available current. */
#define PHAL_MFDUOX_GPIO_OPERATION_2V_100UA                                             0x44    /**< Option to indicate Power downstream voltage of 2V and current of 100uA. */
#define PHAL_MFDUOX_GPIO_OPERATION_2V_300UA                                             0x48    /**< Option to indicate Power downstream voltage of 2V and current of 300uA. */
#define PHAL_MFDUOX_GPIO_OPERATION_2V_500UA                                             0x4C    /**< Option to indicate Power downstream voltage of 2V and current of 500uA. */
#define PHAL_MFDUOX_GPIO_OPERATION_2V_1MA                                               0x50    /**< Option to indicate Power downstream voltage of 2V and current of 1mA. */
#define PHAL_MFDUOX_GPIO_OPERATION_2V_2MA                                               0x54    /**< Option to indicate Power downstream voltage of 2V and current of 2mA. */
#define PHAL_MFDUOX_GPIO_OPERATION_2V_3MA                                               0x58    /**< Option to indicate Power downstream voltage of 2V and current of 3mA. */
#define PHAL_MFDUOX_GPIO_OPERATION_2V_5MA                                               0x5C    /**< Option to indicate Power downstream voltage of 2V and current of 5mA. */
#define PHAL_MFDUOX_GPIO_OPERATION_2V_7MA                                               0x60    /**< Option to indicate Power downstream voltage of 2V and current of 7mA. */
#define PHAL_MFDUOX_GPIO_OPERATION_2V_10MA                                              0x64    /**< Option to indicate Power downstream voltage of 2V and current of 10mA. */
#define PHAL_MFDUOX_GPIO_OPERATION_2V_MAX_CURRENT                                       0x7C    /**< Option to indicate Power downstream voltage of 2V and maximum available current. */
/**
 * end of group phalMfDuoX_GPIOManagement_Defines_Operation_PowerOut_TargetVI
 * @}
 */

/**
 * \defgroup phalMfDuoX_GPIOManagement_Defines_Operation_PowerOut_Control GPIO Measurement Control
 * \brief The Options for representing GPIO Measurement Control operation to perform for the GPIO
 * configured as Down-Stream Power Out. Applicable to Bit 1.
 * @{
 */
#define PHAL_MFDUOX_GPIO_OPERATION_NO_MEASURE                                           0x00    /**< Option to indicate GPIO Measurement control to perform no Measurement. */
#define PHAL_MFDUOX_GPIO_OPERATION_EXECUTE_MEASURE                                      0x02    /**< Option to indicate GPIO Measurement Control to Execute Measurement. */
/**
 * end of group phalMfDuoX_GPIOManagement_Defines_Operation_PowerOut_Control
 * @}
 */

/**
 * \defgroup phalMfDuoX_GPIOManagement_Defines_Operation_PowerOut_Harvest Harvest
 * \brief The Options for representing GPIO Power Harvesting operation to perform for the GPIO
 * configured as Down-Stream Power Out. Applicable to Bit 0.
 * @{
 */
#define PHAL_MFDUOX_GPIO_OPERATION_STOP_POWER_HARVEST                                   0x00    /**< Option to indicate GPIO Control to Stop Power Harvest. */
#define PHAL_MFDUOX_GPIO_OPERATION_ENABLE_POWER_HARVEST                                 0x01    /**< Option to indicate GPIO Control to Enable Power Harvesting. */
/**
 * end of group phalMfDuoX_GPIOManagement_Defines_Operation_PowerOut_Control
 * @}
 */

/**
 * end of group phalMfDuoX_GPIOManagement_Defines_Operation_PowerOut
 * @}
 */

/**
 * end of group phalMfDuoX_GPIOManagement_Defines_Operation
 * @}
 */

/**
 * end of group phalMfDuoX_GPIOManagement_Defines
 * @}
 */

/**
 * \brief Perform GPIO Management
 *
 * \return Status code
 * \retval #PH_ERR_SUCCESS              Operation successful.
 * \retval #PH_ERR_INVALID_DATA_PARAMS  If DataParams is null.
 * \retval #PH_ERR_INVALID_PARAMETER
 *                                      - If the buffers are null.
 *                                      - The values provided in \b bComOption is not supported.
 * \retval XXXX
 *                                      - Depending on status codes return by PICC.
 *                                      - Other Depending on implementation and underlying component.
 */
phStatus_t phalMfDuoX_ManageGPIO(
        void * pDataParams,                                                                     /**< [In] Pointer to this layer's parameter structure. */
        uint16_t wOption,                                                                       /**< [In] Indicates the mode of communication to be used while exchanging the
                                                                                                 *        data from PICC.
                                                                                                 *          - \ref PHAL_MFDUOX_COMMUNICATION_PLAIN "Plain Mode"
                                                                                                 */
        uint8_t bGPIONo,                                                                        /**< [In] GPIO Number to use for management. One of the below values.
                                                                                                 *          - \ref PHAL_MFDUOX_GPIO_NUMBER_1 "GPIO 1"
                                                                                                 *          - \ref PHAL_MFDUOX_GPIO_NUMBER_2 "GPIO 2"
                                                                                                 */
        uint8_t bOperation,                                                                     /**< [In] Targeted Operation perform on the selected GPIO. One of the below values.
                                                                                                 *          - GPIOxMode as Output
                                                                                                 *              - \ref PHAL_MFDUOX_GPIO_OPERATION_GPIO_CONTROL_CLEAR "Clear GPIO Control"
                                                                                                 *              - \ref PHAL_MFDUOX_GPIO_OPERATION_GPIO_CONTROL_SET "Set GPIO Control"
                                                                                                 *              - \ref PHAL_MFDUOX_GPIO_OPERATION_GPIO_CONTROL_TOGGLE "Toggle GPIO Control"
                                                                                                 *              - \ref PHAL_MFDUOX_GPIO_OPERATION_NO_NFC_ACTION "No NFC Action"
                                                                                                 *              - \ref PHAL_MFDUOX_GPIO_OPERATION_PAUSE_NFC "Pause NFC"
                                                                                                 *              - \ref PHAL_MFDUOX_GPIO_OPERATION_RELEASE_NFC_PAUSE "Release NFC Pause"
                                                                                                 *
                                                                                                 *          - GPIOxMode as Down-Stream Power Out
                                                                                                 *              - GPIO Control
                                                                                                 *                  - \ref PHAL_MFDUOX_GPIO_OPERATION_STOP_POWER_HARVEST "CLEAR: Stop Power Harvesting"
                                                                                                 *                  - \ref PHAL_MFDUOX_GPIO_OPERATION_ENABLE_POWER_HARVEST "SET: Enable Power Harvesting"
                                                                                                 *
                                                                                                 *              - GPIO Measurement Control
                                                                                                 *                  - \ref PHAL_MFDUOX_GPIO_OPERATION_NO_MEASURE "No Measurement"
                                                                                                 *                  - \ref PHAL_MFDUOX_GPIO_OPERATION_EXECUTE_MEASURE "MEASURE: Execute Measurement"
                                                                                                 *
                                                                                                 *              - Target Voltage / Current Level
                                                                                                 *                  - \ref PHAL_MFDUOX_GPIO_OPERATION_V_I_DEFAULT
                                                                                                 *                    "Default level as configured with Cmd.SetConfiguration"
                                                                                                 *                  - Power downstream voltage of 1.8V
                                                                                                 *                      - \ref PHAL_MFDUOX_GPIO_OPERATION_1_8V_100UA "Current of 100uA"
                                                                                                 *                      - \ref PHAL_MFDUOX_GPIO_OPERATION_1_8V_300UA"Current of 300uA"
                                                                                                 *                      - \ref PHAL_MFDUOX_GPIO_OPERATION_1_8V_500UA "Current of 500uA"
                                                                                                 *                      - \ref PHAL_MFDUOX_GPIO_OPERATION_1_8V_1MA "Current of 1mA"
                                                                                                 *                      - \ref PHAL_MFDUOX_GPIO_OPERATION_1_8V_2MA "Current of 2mA"
                                                                                                 *                      - \ref PHAL_MFDUOX_GPIO_OPERATION_1_8V_3MA "Current of 3mA"
                                                                                                 *                      - \ref PHAL_MFDUOX_GPIO_OPERATION_1_8V_5MA "Current of 5mA"
                                                                                                 *                      - \ref PHAL_MFDUOX_GPIO_OPERATION_1_8V_7MA "Current of 7mA"
                                                                                                 *                      - \ref PHAL_MFDUOX_GPIO_OPERATION_1_8V_10MA "Current of 10mA"
                                                                                                 *                      - \ref PHAL_MFDUOX_GPIO_OPERATION_1_8V_MAX_CURRENT "Maximum Available Current"
                                                                                                 *                  - Power downstream voltage of 2V
                                                                                                 *                      - \ref PHAL_MFDUOX_GPIO_OPERATION_2V_100UA "Current of 100uA"
                                                                                                 *                      - \ref PHAL_MFDUOX_GPIO_OPERATION_2V_300UA"Current of 300uA"
                                                                                                 *                      - \ref PHAL_MFDUOX_GPIO_OPERATION_2V_500UA "Current of 500uA"
                                                                                                 *                      - \ref PHAL_MFDUOX_GPIO_OPERATION_2V_1MA "Current of 1mA"
                                                                                                 *                      - \ref PHAL_MFDUOX_GPIO_OPERATION_2V_2MA "Current of 2mA"
                                                                                                 *                      - \ref PHAL_MFDUOX_GPIO_OPERATION_2V_3MA "Current of 3mA"
                                                                                                 *                      - \ref PHAL_MFDUOX_GPIO_OPERATION_2V_5MA "Current of 5mA"
                                                                                                 *                      - \ref PHAL_MFDUOX_GPIO_OPERATION_2V_7MA "Current of 7mA"
                                                                                                 *                      - \ref PHAL_MFDUOX_GPIO_OPERATION_2V_10MA "Current of 10mA"
                                                                                                 *                      - \ref PHAL_MFDUOX_GPIO_OPERATION_2V_MAX_CURRENT "Maximum Available Current"
                                                                                                 */
        uint8_t * pNFCPauseRspData,                                                             /**< [In] NFC Pause Response Data: Data to be returned to NFC host
                                                                                                 *        in the case of �Release NFC Pause�
                                                                                                 */
        uint16_t wNFCPauseRspDataLen,                                                           /**< [In] Length of bytes available in \b pNFCPauseRspData buffer. */
        uint8_t ** ppResponse,                                                                  /**< [Out] Response from PICC as follows.
                                                                                                 *          - If \b bOperation = \ref PHAL_MFDUOX_GPIO_OPERATION_PAUSE_NFC "Pause NFC"
                                                                                                 *             then, NFC Pause Response Data: Data received from the I2C interface
                                                                                                 *          - If \b bOperation = \ref PHAL_MFDUOX_GPIO_OPERATION_EXECUTE_MEASURE
                                                                                                 *            "Execute Measure" then, Measurement result will be received.
                                                                                                 *          - NULL for others.
                                                                                                 */
        uint16_t * pRspLen                                                                      /**< [Out] Length of bytes available in \b pRspLen buffer. */
    );

/**
 * \brief Perform GPIO read.
 *
 * \return Status code
 * \retval #PH_ERR_SUCCESS              Operation successful.
 * \retval #PH_ERR_INVALID_DATA_PARAMS  If DataParams is null.
 * \retval #PH_ERR_INVALID_PARAMETER
 *                                      - If the buffers are null.
 *                                      - The values provided in \b bComOption is not supported.
 * \retval XXXX
 *                                      - Depending on status codes return by PICC.
 *                                      - Other Depending on implementation and underlying component.
 */
phStatus_t phalMfDuoX_ReadGPIO(
        void * pDataParams,                                                                     /**< [In] Pointer to this layer's parameter structure. */
        uint16_t wOption,                                                                       /**< [In] Indicates the mode of communication to be used while exchanging the
                                                                                                 *         data from PICC.
                                                                                                 *          - \ref PHAL_MFDUOX_COMMUNICATION_PLAIN "Plain Mode"
                                                                                                 */
        uint8_t ** ppResponse,                                                                  /**< [Out] Cryptographic output for the provided input. */
        uint16_t * pRspLen                                                                      /**< [Out] Length of bytes available in \b pRspLen buffer. */
    );

/**
 * end of group phalMfDuoX_GPIOManagement
 * @}
 */

/* MIFARE DUOX ISO7816-4 commands ------------------------------------------------------------------------------------------------------- */
/**
 * \defgroup phalMfDuoX_ISO7816 Commands_ISO7816
 * \brief Describes about the MIFARE DUOX ISO/IEC 7816-4 Standard commands.
 * @{
 */

/**
 * \defgroup phalMfDuoX_ISO7816_Defines Defines
 * \brief Macro Definitions for ISO/IEC 7816-4 Standard commands.
 * @{
 */

/**
 * \defgroup phalMfDuoX_ISO7816_Defines_FCI FileControlIdentifier
 * \brief Macro Definitions for ISO/IEC 7816-4 FCI modes. To be used with \ref phalMfDuoX_IsoSelectFile "ISOSelect File" interface.
 * @{
 */
#define PHAL_MFDUOX_FCI_RETURNED                                                        0x00U   /**< Option to indicate return of FCI. */
#define PHAL_MFDUOX_FCI_NOT_RETURNED                                                    0x0CU   /**< Option to indicate no return of FCI. */
/**
 * end of group phalMfDuoX_ISO7816_Defines_FCI
 * @}
 */

/**
 * \defgroup phalMfDuoX_ISO7816_Defines_Selector Selection Control
 * \brief Macro Definitions for ISO/IEC 7816-4 Selection Controls. To be used with \ref phalMfDuoX_IsoSelectFile "ISOSelect File" interface.
 * @{
 */
#define PHAL_MFDUOX_SELECTOR_0                                                          0x00U   /**< Option to indicate Selection by 2 byte file Id. */
#define PHAL_MFDUOX_SELECTOR_1                                                          0x01U   /**< Option to indicate Selection by child DF. */
#define PHAL_MFDUOX_SELECTOR_2                                                          0x02U   /**< Option to indicate Select EF under current DF. FID = EF id. */
#define PHAL_MFDUOX_SELECTOR_3                                                          0x03U   /**< Option to indicate Select parent DF of the current DF. */
#define PHAL_MFDUOX_SELECTOR_4                                                          0x04U   /**< Option to indicate Selection by DF Name. DFName and length is then valid. */
/**
 * end of group phalMfDuoX_ISO7816_Defines_Selector
 * @}
 */

/**
 * \defgroup phalMfDuoX_ISO7816_Defines_APDU APDUFormat
 * \brief Macro Definitions for ISO/IEC 7816-4 APDU format. To be used with all ISO7816 - 4 interfaces.
 * @{
 */
#define PHAL_MFDUOX_APDU_FORMAT_SHORT_LEN                                               0x00U   /**< Option to indicate ISO7816-4 APDU format is Short Length format where LC
                                                                                                 *   and LE are of 1 byte.
                                                                                                 */
#define PHAL_MFDUOX_APDU_FORMAT_EXTENDED_LEN                                            0x01U   /**< Option to indicate ISO7816-4 APDU format is Extended Length format where LC
                                                                                                 *   is 3 bytes and LE is either 2 or 3 bytes.
                                                                                                 */
 /**
 * end of group phalMfDuoX_ISO7816_Defines_APDU
 * @}
 */

/**
 * \defgroup phalMfDuoX_ISO7816_Defines_SFID SFID
 * \brief Macro Definitions for ISO/IEC 7816-4 P1 Encoding of ShortFile identifier or Offset.
 * To be used with \ref phalMfDuoX_IsoReadBinary "ISORead Binary" and \ref phalMfDuoX_IsoUpdateBinary "ISOUpdate Binary" interface.
 * @{
 */
#define PHAL_MFDUOX_SFID_DISABLED                                                       0x00U   /**< Option to indicate Encoding as offset. */
#define PHAL_MFDUOX_SFID_ENABLED                                                        0x80U   /**< Option to indicate Encoding as Short File Identifier. */
/**
 * end of group phalMfDuoX_ISO7816_Defines_SFID
 * @}
 */

/**
 * \defgroup phalMfDuoX_ISO7816_Defines_Record RecordUsage
 * \brief Macro Definitions for ISO/IEC 7816-4 Record usage. This is required for P2 information.
 * To be used with \ref phalMfDuoX_IsoReadRecords "ISORead Records".
 * @{
 */
#define PHAL_MFDUOX_RECORD_USAGE_SINGLE                                                 0x00U   /**< Option to indicate Reading of Single record. */
#define PHAL_MFDUOX_RECORD_USAGE_ALL                                                    0x01U   /**< Option to indicate Reading of all record. */
 /**
 * end of group phalMfDuoX_ISO7816_Defines_Record
 * @}
 */

/**
 * end of group phalMfDuoX_ISO7816_Defines
 * @}
 */

/**
 * \brief Perform File or Application selection. This command is implemented in compliance with ISO/IEC 7816-4.
 *
 * \note
 *      For all ISO7816 errors, library returns a command error code \ref PHAL_MFDUOX_ERR_DF_7816_GEN_ERROR "ISO7816 General Errors".
 *      To know the exact error returned by PICC call \ref phalMfDuoX_GetConfig "Get Config" with \ref PHAL_MFDUOX_ADDITIONAL_INFO
 *      "Additional Information" as Configuration Identifier.
 *
 * \return Status code
 * \retval #PH_ERR_SUCCESS              Operation successful.
 * \retval #PH_ERR_INVALID_DATA_PARAMS  If DataParams is null.
 * \retval #PH_ERR_INVALID_PARAMETER
 *                                      - If the buffers are null.
 *                                      - DFName Length is greater than 16 (\b bDFnameLen).
 *                                      - Invalid FCI (File Control Identifier) (\b bOption)
 *                                      - Invalid Selector option (\b bSelector).
 * \retval #PHAL_MFDUOX_ERR_DF_7816_GEN_ERROR Any ISO7816 Error.
 * \retval XXXX
 *                                      - Depending on status codes return by PICC.
 *                                      - Other Depending on implementation and underlying component.
 */
phStatus_t phalMfDuoX_IsoSelectFile(
        void * pDataParams,                                                                     /**< [In] Pointer to this layer's parameter structure. */
        uint8_t bOption,                                                                        /**< [In] Option for return / no return of FCI.
                                                                                                 *          - \ref PHAL_MFDUOX_FCI_RETURNED "FCI Returned"
                                                                                                 *          - \ref PHAL_MFDUOX_FCI_NOT_RETURNED "FCI Not Returned"
                                                                                                 */
        uint8_t bSelector,                                                                      /**< [In] The selector to be used.
                                                                                                 *          - \ref PHAL_MFDUOX_SELECTOR_0 "File Identifier"
                                                                                                 *          - \ref PHAL_MFDUOX_SELECTOR_1 "Child DF"
                                                                                                 *          - \ref PHAL_MFDUOX_SELECTOR_2 "EF under current DF"
                                                                                                 *          - \ref PHAL_MFDUOX_SELECTOR_3 "DF of the Current DF"
                                                                                                 *          - \ref PHAL_MFDUOX_SELECTOR_4 "DF Name"
                                                                                                 */
        uint8_t * pFid,                                                                         /**< [In] The ISO File number to be selected.
                                                                                                 *          - Valid only if \b bSelector is one of the following.
                                                                                                 *              - \ref PHAL_MFDUOX_SELECTOR_0 "File Identifier"
                                                                                                 *              - \ref PHAL_MFDUOX_SELECTOR_1 "Child DF"
                                                                                                 *              - \ref PHAL_MFDUOX_SELECTOR_2 "EF under current DF"
                                                                                                 *          - NULL for other \b bSelector options.
                                                                                                 */
        uint8_t * pDFname,                                                                      /**< [In] The ISO DFName to be selected.
                                                                                                 *          - Valid only when \b bSelector = \ref PHAL_MFDUOX_SELECTOR_4
                                                                                                 *            "DF Name".
                                                                                                 *          - NULL for other \b bSelector options.
                                                                                                 */
        uint8_t bDFnameLen,                                                                     /**< [In] Length of bytes available in \b pDFname buffer. */
        uint8_t bExtendedLenApdu,                                                               /**< [In] Flag for Extended Length APDU.
                                                                                                 *          - \ref PHAL_MFDUOX_APDU_FORMAT_SHORT_LEN "Short Length APDU"
                                                                                                 *          - \ref PHAL_MFDUOX_APDU_FORMAT_EXTENDED_LEN "Extended Length APDU"
                                                                                                 */
        uint8_t ** ppFCI,                                                                       /**< [Out] The FCI information returned by the PICC. */
        uint16_t * pFCILen                                                                      /**< [Out] Length of bytes available in \b ppFCI buffer. */
    );

/**
 * \brief Perform ISO Read Binary. This command is implemented in compliance with ISO/IEC 7816-4.
 *
 * \note
 *      For all ISO7816 errors, library returns a command error code \ref PHAL_MFDUOX_ERR_DF_7816_GEN_ERROR "ISO7816 General Errors".
 *      To know the exact error returned by PICC call \ref phalMfDuoX_GetConfig "Get Config" with \ref PHAL_MFDUOX_ADDITIONAL_INFO
 *      "Additional Information" as Configuration Identifier.
 *
 * \return Status code
 * \retval #PH_ERR_SUCCESS              Operation successful.
 * \retval #PH_ERR_INVALID_DATA_PARAMS  If DataParams is null.
 * \retval #PH_ERR_INVALID_PARAMETER
 *                                      - If the buffer is null.
 *                                      - For invalid Short File identifier (\b bSfid).
 *                                      - For Invalid Buffering Options (\b wOption).
 * \retval #PHAL_MFDUOX_ERR_DF_7816_GEN_ERROR Any ISO7816 Error.
 * \retval XXXX
 *                                      - Depending on status codes return by PICC.
 *                                      - Other Depending on implementation and underlying component.
 */
phStatus_t phalMfDuoX_IsoReadBinary(
        void * pDataParams,                                                                     /**< [In] Pointer to this layer's parameter structure. */
        uint16_t wOption,                                                                       /**< [In] One of the below options.
                                                                                                 *          - #PH_EXCHANGE_DEFAULT   : To exchange command to the PICC and
                                                                                                 *                                     receive the response.
                                                                                                 *          - #PH_EXCHANGE_RXCHAINING: To Receive pending response from PICC.
                                                                                                 */
        uint8_t bOffset,                                                                        /**< [In] The offset from where the data should be read. \n
                                                                                                 *          Regardless of \b bSfid value, the encoding of offset will be
                                                                                                 *          from 0 - 255. This will be part of P2 information.
                                                                                                 */
        uint8_t bSfid,                                                                          /**< [In] Indication to use either Short ISO File Id or Offset.
                                                                                                 *          - If \ref PHAL_MFDUOX_SFID_ENABLED "Short File Identifier", then bit
                                                                                                 *            7 is set and bits 0-4indicates short file identifier.
                                                                                                 *          - If \ref PHAL_MFDUOX_SFID_DISABLED "Short File Identifier", then bits
                                                                                                 *            0-6 indicates MSB of offset information.
                                                                                                 *          - This will be part of P1 information.
                                                                                                 *          - Ex. If actual Offset = 8063 (1F7F), then \b bSfid will be 1F and
                                                                                                 *            \b bOffset will be 7F.
                                                                                                 */
        uint32_t dwBytesToRead,                                                                 /**< [In] The number of bytes to be read from the file.
                                                                                                 *          - If zero is provided, then entire file data is returned by PICC.
                                                                                                 *          - If non-zero is provided, then data starting from offset is returned.
                                                                                                 */
        uint8_t bExtendedLenApdu,                                                               /**< [In] Flag for Extended Length APDU.
                                                                                                 *          - \ref PHAL_MFDUOX_APDU_FORMAT_SHORT_LEN "Short Length APDU"
                                                                                                 *          - \ref PHAL_MFDUOX_APDU_FORMAT_EXTENDED_LEN "Extended Length APDU"
                                                                                                 */
        uint8_t ** ppResponse,                                                                  /**< [Out] The data returned by the PICC. */
        uint16_t * pRspLen                                                                      /**< [Out] Length of bytes available in \b ppResponse buffer. */
    );

/**
 * \brief Perform ISO Update Binary. This command is implemented in compliance with ISO/IEC 7816-4.
 *
 * \note
 *      For all ISO7816 errors, library returns a command error code \ref PHAL_MFDUOX_ERR_DF_7816_GEN_ERROR "ISO7816 General Errors".
 *      To know the exact error returned by PICC call \ref phalMfDuoX_GetConfig "Get Config" with \ref PHAL_MFDUOX_ADDITIONAL_INFO
 *      "Additional Information" as Configuration Identifier.
 *
 * \return Status code
 * \retval #PH_ERR_SUCCESS              Operation successful.
 * \retval #PH_ERR_INVALID_DATA_PARAMS  If DataParams is null.
 * \retval #PH_ERR_INVALID_PARAMETER
 *                                      - If the buffer is null.
 *                                      - For invalid Short File identifier (\b bSfid).
 * \retval #PHAL_MFDUOX_ERR_DF_7816_GEN_ERROR Any ISO7816 Error.
 * \retval XXXX
 *                                      - Depending on status codes return by PICC.
 *                                      - Other Depending on implementation and underlying component.
 */
phStatus_t phalMfDuoX_IsoUpdateBinary(
        void * pDataParams,                                                                     /**< [In] Pointer to this layer's parameter structure. */
        uint8_t bOffset,                                                                        /**< [In] The offset from where the data should be updated. \n
                                                                                                 *          Regardless of \b bSfid value, the encoding of offset will be
                                                                                                 *          from 0 - 255. This will be part of P2 information.
                                                                                                 */
        uint8_t bSfid,                                                                          /**< [In] Indication to use either Short ISO File Id or Offset.
                                                                                                 *          - If \ref PHAL_MFDUOX_SFID_ENABLED "Short File Identifier", then bit
                                                                                                 *            7 is set and bits 0-4indicates short file identifier.
                                                                                                 *          - If \ref PHAL_MFDUOX_SFID_DISABLED "Short File Identifier", then bits
                                                                                                 *            0-6 indicates MSB of offset information.
                                                                                                 *          - This will be part of P1 information.
                                                                                                 *          - Ex. If actual Offset = 8063 (1F7F), then \b bSfid will be 1F and
                                                                                                 *            \b bOffset will be 7F.
                                                                                                 */
        uint8_t bExtendedLenApdu,                                                               /**< [In] Flag for Extended Length APDU.
                                                                                                 *          - \ref PHAL_MFDUOX_APDU_FORMAT_SHORT_LEN "Short Length APDU"
                                                                                                 *          - \ref PHAL_MFDUOX_APDU_FORMAT_EXTENDED_LEN "Extended Length APDU"
                                                                                                 */
        uint8_t * pData,                                                                        /**< [In] Data to be updated. */
        uint16_t wDataLen                                                                       /**< [In] Length of bytes available in \b pData buffer. */
    );

/**
 * \brief Perform ISO Read Record. This command is implemented in compliance with ISO/IEC 7816-4.
 *
 * \note
 *      For all ISO7816 errors, library returns a command error code \ref PHAL_MFDUOX_ERR_DF_7816_GEN_ERROR "ISO7816 General Errors".
 *      To know the exact error returned by PICC call \ref phalMfDuoX_GetConfig "Get Config" with \ref PHAL_MFDUOX_ADDITIONAL_INFO
 *      "Additional Information" as Configuration Identifier.
 *
 * \return Status code
 * \retval #PH_ERR_SUCCESS              Operation successful.
 * \retval #PH_ERR_INVALID_DATA_PARAMS  If DataParams is null.
 * \retval #PH_ERR_INVALID_PARAMETER
 *                                      - If the buffer is null.
 *                                      - For invalid Short File identifier (\b bSfid).
 *                                      - For Invalid Buffering Options (\b wOption).
 * \retval #PHAL_MFDUOX_ERR_DF_7816_GEN_ERROR Any ISO7816 Error.
 * \retval XXXX
 *                                      - Depending on status codes return by PICC.
 *                                      - Other Depending on implementation and underlying component.
 */
phStatus_t phalMfDuoX_IsoReadRecords(
        void * pDataParams,                                                                     /**< [In] Pointer to this layer's parameter structure. */
        uint16_t wOption,                                                                       /**< [In] One of the below options.
                                                                                                 *          - #PH_EXCHANGE_DEFAULT   : To exchange command to the PICC and
                                                                                                 *                                     receive the response.
                                                                                                 *          - #PH_EXCHANGE_RXCHAINING: To Receive pending response from PICC.
                                                                                                 */
        uint8_t bRecNo,                                                                         /**< [In] Record to read / from where to read. */
        uint8_t bReadAllRecords,                                                                /**< [In] Whether to read all records from P1 or just one.
                                                                                                 *          - \ref PHAL_MFDUOX_RECORD_USAGE_SINGLE "Read Single"
                                                                                                 *          - \ref PHAL_MFDUOX_RECORD_USAGE_ALL "Read All"
                                                                                                 */
        uint8_t bSfid,                                                                          /**< [In] Indication to use Short ISO File Id.
                                                                                                 *        File Identifiers from 0x00 - 0x1F
                                                                                                 */
        uint32_t dwBytesToRead,                                                                 /**< [In] The number of bytes to be read from the file.
                                                                                                 *          - If zero is provided, then entire file starting from the record specified.
                                                                                                 *          - If non-zero is provided, then
                                                                                                 *              - The number of bytes to be read.
                                                                                                 *              - If bigger than number of bytes available in the file, after subtracting
                                                                                                 *                MAC length if MAC is to be returned, the entire data file starting from
                                                                                                 *                the offset position is returned. If smaller, this number of bytes is
                                                                                                 *                returned (possibly containing partial record).
                                                                                                 */
        uint8_t bExtendedLenApdu,                                                               /**< [In] Flag for Extended Length APDU.
                                                                                                 *          - \ref PHAL_MFDUOX_APDU_FORMAT_SHORT_LEN "Short Length APDU"
                                                                                                 *          - \ref PHAL_MFDUOX_APDU_FORMAT_EXTENDED_LEN "Extended Length APDU"
                                                                                                 */
        uint8_t ** ppResponse,                                                                  /**< [Out] The data returned by the PICC. */
        uint16_t * pRspLen                                                                      /**< [Out] Length of bytes available in \b ppResponse buffer. */
    );

/**
 * \brief Perform ISO Append record. This command is implemented in compliance with ISO/IEC 7816-4.
 *
 * \note
 *      For all ISO7816 errors, library returns a command error code \ref PHAL_MFDUOX_ERR_DF_7816_GEN_ERROR "ISO7816 General Errors".
 *      To know the exact error returned by PICC call \ref phalMfDuoX_GetConfig "Get Config" with \ref PHAL_MFDUOX_ADDITIONAL_INFO
 *      "Additional Information" as Configuration Identifier.
 *
 * \return Status code
 * \retval #PH_ERR_SUCCESS              Operation successful.
 * \retval #PH_ERR_INVALID_DATA_PARAMS  If DataParams is null.
 * \retval #PH_ERR_INVALID_PARAMETER
 *                                      - If the buffer is null.
 *                                      - For invalid Short File identifier (\b bSfid).
 * \retval #PHAL_MFDUOX_ERR_DF_7816_GEN_ERROR Any ISO7816 Error.
 * \retval XXXX
 *                                      - Depending on status codes return by PICC.
 *                                      - Other Depending on implementation and underlying component.
 */
phStatus_t phalMfDuoX_IsoAppendRecord(
        void * pDataParams,                                                                     /**< [In] Pointer to this layer's parameter structure. */
        uint8_t bSfid,                                                                          /**< [In] Indication to use Short ISO File Id.
                                                                                                 *        File Identifiers from 0x00 - 0x1F
                                                                                                 */
        uint8_t bExtendedLenApdu,                                                               /**< [In] Flag for Extended Length APDU.
                                                                                                 *          - \ref PHAL_MFDUOX_APDU_FORMAT_SHORT_LEN "Short Length APDU"
                                                                                                 *          - \ref PHAL_MFDUOX_APDU_FORMAT_EXTENDED_LEN "Extended Length APDU"
                                                                                                 */
        uint8_t * pData,                                                                        /**< [In] Data to be appended. */
        uint16_t wDataLen                                                                       /**< [In] Length of bytes available in \b pData buffer. */
    );

/**
 * \brief Perform ISOGetChallenge. This command is implemented in compliance with ISO/IEC 7816-4.
 *
 * \note
 *      For all ISO7816 errors, library returns a command error code \ref PHAL_MFDUOX_ERR_DF_7816_GEN_ERROR "ISO7816 General Errors".
 *      To know the exact error returned by PICC call \ref phalMfDuoX_GetConfig "Get Config" with \ref PHAL_MFDUOX_ADDITIONAL_INFO
 *      "Additional Information" as Configuration Identifier.
 *
 * \return Status code
 * \retval #PH_ERR_SUCCESS              Operation successful.
 * \retval #PH_ERR_INVALID_DATA_PARAMS  If DataParams is null.
 * \retval #PH_ERR_INVALID_PARAMETER    If the buffer is null.
 * \retval XXXX
 *                                      - Depending on status codes return by PICC.
 *                                      - Other Depending on implementation and underlying component.
 */
phStatus_t phalMfDuoX_IsoGetChallenge(
        void * pDataParams,                                                                     /**< [In] Pointer to this layer's parameter structure. */
        uint8_t bExpRsp,                                                                        /**< [In] Length of expected challenge RPICC1. */
        uint8_t bExtendedLenApdu,                                                               /**< [In] Flag for Extended Length APDU.
                                                                                                 *          - \ref PHAL_MFDUOX_APDU_FORMAT_SHORT_LEN "Short Length APDU"
                                                                                                 *          - \ref PHAL_MFDUOX_APDU_FORMAT_EXTENDED_LEN "Extended Length APDU"
                                                                                                 */
        uint8_t ** ppResponse,                                                                  /**< [Out] The data returned by the PICC. */
        uint16_t * pRspLen                                                                      /**< [Out] Length of bytes available in \b ppResponse buffer. */
    );

/**
 * end of group phalMfDuoX_ISO7816
 * @}
 */

/* MIFARE DUOX EV Charging command ------------------------------------------------------------------------------------------------------ */
/**
 * \defgroup phalMfDuoX_EV Commands_EVCharging
 * \brief Describes about the MIFARE DUOX EV Charging commands.
 * @{
 */

/**
 * \defgroup phalMfDuoX_EV_Defines Defines
 * @{
 */

/**
 * \defgroup phalMfDuoX_EV_Defines_Operation Operation
 * \brief Macro Definitions for EV Charging \ref phalMfDuoX_VdeWriteData "VDE WriteData" interface.
 * @{
 */
#define PHAL_MFDUOX_EV_OPERATION_WRITE                                                  0x00U   /**< Option to indicate Operation as Write. */
#define PHAL_MFDUOX_EV_OPERATION_LOCK                                                   0x01U   /**< Option to indicate Operation as Lock. */
/**
 * end of group phalMfDuoX_EV_Defines_Operation
 * @}
 */

/**
 * end of group phalMfDuoX_EV_Defines
 * @}
 */

/**
 * \brief Reads data from Standard data File.
 *
 * \note
 *      - For all ISO7816 errors, library returns a command error code \ref PHAL_MFDUOX_ERR_DF_7816_GEN_ERROR "ISO7816 General Errors".
 *        To know the exact error returned by PICC call \ref phalMfDuoX_GetConfig "Get Config" with \ref PHAL_MFDUOX_ADDITIONAL_INFO
 *        "Additional Information" as Configuration Identifier.
 *
 * \return Status code
 * \retval #PH_ERR_SUCCESS              Operation successful.
 * \retval #PH_ERR_SUCCESS_CHAINING     Indicating more data to be read.
 * \retval #PH_ERR_INVALID_DATA_PARAMS  If DataParams is null.
 * \retval #PH_ERR_INVALID_PARAMETER
 *                                      - If the buffers are null.
 *                                      - For Invalid Exchange option value (\b wOption).
 * \retval XXXX
 *                                      - Depending on status codes return by PICC.
 *                                      - Other Depending on implementation and underlying component.
 */
phStatus_t phalMfDuoX_VdeReadData(
        void * pDataParams,                                                                     /**< [In] Pointer to this layer's parameter structure. */
        uint16_t wOption,                                                                       /**< [In] One of the below options.
                                                                                                 *          - #PH_EXCHANGE_DEFAULT   : To exchange command to the PICC and
                                                                                                 *                                     receive the response.
                                                                                                 *          - #PH_EXCHANGE_RXCHAINING: To Receive pending response from PICC.
                                                                                                 */
        uint8_t bFileNo,                                                                        /**< [In] The file number from where the data to be read. */
        uint16_t wBytesToRead,                                                                  /**< [In] The number of bytes to be read from the file.
                                                                                                 *          - If zero, any amount of data stating from zero upto 256 / 65536 bytes.
                                                                                                 *            LE will be exchanged as zero based on \b bExtendedLenApdu value.
                                                                                                 *          - If non zero, any amount of data stating from zero upto \b wBytesToRead will be returned.
                                                                                                 *            LE will be exchanged as \b wBytesToRead based on \b bExtendedLenApdu value.
                                                                                                 */
        uint8_t bExtendedLenApdu,                                                               /**< [In] Flag for Extended Length APDU.
                                                                                                 *          - \ref PHAL_MFDUOX_APDU_FORMAT_SHORT_LEN "Short Length APDU"
                                                                                                 *          - \ref PHAL_MFDUOX_APDU_FORMAT_EXTENDED_LEN "Extended Length APDU"
                                                                                                 */
        uint8_t ** ppResponse,                                                                  /**< [Out] The data returned by the PICC. */
        uint16_t * pRspLen                                                                      /**< [Out] Length of bytes available in \b ppResponse buffer. */
    );

/**
 * \brief Writes data to Standard data File and eventually lock the file.
 *
 * \note
 *      For all ISO7816 errors, library returns a command error code \ref PHAL_MFDUOX_ERR_DF_7816_GEN_ERROR "ISO7816 General Errors".
 *      To know the exact error returned by PICC call \ref phalMfDuoX_GetConfig "Get Config" with \ref PHAL_MFDUOX_ADDITIONAL_INFO
 *      "Additional Information" as Configuration Identifier.
 *
 * \return Status code
 * \retval #PH_ERR_SUCCESS              Operation successful.
 * \retval #PH_ERR_INVALID_DATA_PARAMS  If DataParams is null.
 * \retval #PH_ERR_INVALID_PARAMETER    If the buffer is null.
 * \retval #PHAL_MFDUOX_ERR_DF_7816_GEN_ERROR Any ISO7816 Error.
 * \retval XXXX
 *                                      - Depending on status codes return by PICC.
 *                                      - Other Depending on implementation and underlying component.
 */
phStatus_t phalMfDuoX_VdeWriteData(
        void * pDataParams,                                                                     /**< [In] Pointer to this layer's parameter structure. */
        uint8_t bOperation,                                                                     /**< [In] The operation to perform on the file.
                                                                                                 *          - \ref  PHAL_MFDUOX_EV_OPERATION_WRITE "Write"
                                                                                                 *          - \ref  PHAL_MFDUOX_EV_OPERATION_LOCK "Lock"
                                                                                                 */
        uint8_t bExtendedLenApdu,                                                               /**< [In] Flag for Extended Length APDU.
                                                                                                 *          - \ref PHAL_MFDUOX_APDU_FORMAT_SHORT_LEN "Short Length APDU"
                                                                                                 *          - \ref PHAL_MFDUOX_APDU_FORMAT_EXTENDED_LEN "Extended Length APDU"
                                                                                                 */
        uint8_t * pData,                                                                        /**< [In] The data to be written to the PICC. */
        uint16_t wDataLen                                                                       /**< [In] Length of bytes available in \b pData buffer. */
    );

/**
 * \brief Generates and ECDSA signature over a 32-byte challenge.
 *
 * \note
 *      For all ISO7816 errors, library returns a command error code \ref PHAL_MFDUOX_ERR_DF_7816_GEN_ERROR "ISO7816 General Errors".
 *      To know the exact error returned by PICC call \ref phalMfDuoX_GetConfig "Get Config" with \ref PHAL_MFDUOX_ADDITIONAL_INFO
 *      "Additional Information" as Configuration Identifier.
 *
 * \return Status code
 * \retval #PH_ERR_SUCCESS              Operation successful.
 * \retval #PH_ERR_INVALID_DATA_PARAMS  If DataParams is null.
 * \retval #PH_ERR_INVALID_PARAMETER    If the buffer is null.
 * \retval #PHAL_MFDUOX_ERR_DF_7816_GEN_ERROR Any ISO7816 Error.
 * \retval XXXX
 *                                      - Depending on status codes return by PICC.
 *                                      - Other Depending on implementation and underlying component.
 */
phStatus_t phalMfDuoX_VdeECDSASign(
        void * pDataParams,                                                                     /**< [In] Pointer to this layer's parameter structure. */
        uint16_t wBytesToRead,                                                                  /**< [In] The number of bytes to be read from the file.
                                                                                                 *          - If zero, any amount of data stating from zero upto 256 / 65536 bytes.
                                                                                                 *            LE will be exchanged as zero based on \b bExtendedLenApdu value.
                                                                                                 *          - If non zero, any amount of data stating from zero upto \b wBytesToRead will be returned.
                                                                                                 *            LE will be exchanged as \b wBytesToRead based on \b bExtendedLenApdu value.
                                                                                                 */
        uint8_t bExtendedLenApdu,                                                               /**< [In] Flag for Extended Length APDU.
                                                                                                 *          - \ref PHAL_MFDUOX_APDU_FORMAT_SHORT_LEN "Short Length APDU"
                                                                                                 *          - \ref PHAL_MFDUOX_APDU_FORMAT_EXTENDED_LEN "Extended Length APDU"
                                                                                                 */
        uint8_t * pData,                                                                        /**< [In] Message to be signed. */
        uint16_t wDataLen,                                                                      /**< [In] Length of bytes available in \b pData buffer. */
        uint8_t ** ppResponse,                                                                  /**< [Out] The signature of the message.
                                                                                                 *          - The Signature will be in R and S integer format. \b ppResponse = R data followed by S data.
                                                                                                 *          - Here R and S length will be based on the curve length.
                                                                                                 *          - Ex: If curve length is 256 bit, then R and S length will be 32 bytes each.
                                                                                                 */
        uint16_t * pRspLen                                                                      /**< [Out] Length of bytes available in \b ppResponse buffer. */
    );

/**
 * end of group phalMfDuoX_EV
 * @}
 */

/* MIFARE DUOX Utility functions -------------------------------------------------------------------------------------------------------- */
/**
 * \defgroup phalMfDuoX_Utility Commands_Utility
 * \brief Describes about the MIFARE DUOX Utility functions. These are not part of actual MIFARE DUOX data sheet
 * rather its for internal purpose.
 * @{
 */

/**
 * \defgroup phalMfDuoX_Utility_Defines Defines
 * \brief Macro Definitions for Utility interface support.
 * @{
 */

/**
 * \defgroup phalMfDuoX_Utility_Defines_Configuration Configuration
 * \brief Macro Definitions for \ref phalMfDuoX_GetConfig "Get Config" and \ref phalMfDuoX_SetConfig "Set Config" interfaces.
 * @{
 */
#define PHAL_MFDUOX_ADDITIONAL_INFO                                                     0x00A1  /**< Option for \ref phalMfDuoX_GetConfig "Get Config" / \ref phalMfDuoX_SetConfig
                                                                                                 *   "Set Config" to get/set additional info of a generic error or some length
                                                                                                 *   exposed by interfaces.
                                                                                                 */
#define PHAL_MFDUOX_WRAPPED_MODE                                                        0x00A2  /**< Option for \ref phalMfDuoX_GetConfig "Get Config" / \ref phalMfDuoX_SetConfig
                                                                                                 *   "Set Config" to get/set current Status of command wrapping in ISO 7816-4 APDUs.
                                                                                                 */
#define PHAL_MFDUOX_SHORT_LENGTH_APDU                                                   0x00A3  /**< Option for \ref phalMfDuoX_GetConfig "Get Config" / \ref phalMfDuoX_SetConfig
                                                                                                 *   "Set Config" to get/set current Status of Short Length APDU wrapping in ISO
                                                                                                 *   7816-4 APDUs.
                                                                                                 *      - 1: The commands will follow ISO7816 wrapped format with LC and LE as 1 byte.
                                                                                                 *      - 0: The commands will follow ISO7816 wrapped format with LC as 3 bytes and LE
                                                                                                 *           as 2 or 3 bytes.
                                                                                                 */
#define PHAL_MFDUOX_AUTH_STATE                                                          0x00A4  /**< Option for \ref phalMfDuoX_GetConfig "Get Config" / \ref phalMfDuoX_SetConfig
                                                                                                 *   "Set Config" to get/set current Status Authentication.
                                                                                                 */
/**
 * end of group phalMfDuoX_Utility_Defines_Configuration
 * @}
 */

/**
 * end of group phalMfDuoX_Utility_Defines
 * @}
 */

/**
 * \brief Perform a GetConfig command.
 *
 * \return Status code
 * \retval #PH_ERR_SUCCESS                  Operation successful.
 * \retval #PH_ERR_INVALID_DATA_PARAMS      If any of the DataParams are null.
 * \retval #PH_ERR_INVALID_PARAMETER        If the return buffer is null
 * \retval #PH_ERR_UNSUPPORTED_PARAMETER    If configuration (\b wConfig) option provided is not supported.
 */
phStatus_t phalMfDuoX_GetConfig(
        void * pDataParams,                                                                     /**< [In] Pointer to this layer's parameter structure. */
        uint16_t wConfig,                                                                       /**< [In] Configuration to read. Will be one of the below values.
                                                                                                 *        for list of supported configurations refer
                                                                                                 *        \ref phalMfDuoX_Utility_Defines_Configuration "Configuration Identifier"
                                                                                                 */
         uint16_t * pValue                                                                      /**< [Out] The value for the mentioned configuration. */
    );

/**
 * \brief Perform a SetConfig command.
 *
 * \return Status code
 * \retval #PH_ERR_SUCCESS                  Operation successful.
 * \retval #PH_ERR_INVALID_DATA_PARAMS      If any of the DataParams are null.
 * \retval #PH_ERR_UNSUPPORTED_PARAMETER    If configuration (\b wConfig) option provided is not supported.
 */
phStatus_t phalMfDuoX_SetConfig(
        void * pDataParams,                                                                     /**< [In] Pointer to this layer's parameter structure. */
        uint16_t wConfig,                                                                       /**< [In] Configuration to set. Will be one of the below values.
                                                                                                 *        for list of supported configurations refer
                                                                                                 *        \ref phalMfDuoX_Utility_Defines_Configuration "Configuration Identifier"
                                                                                                 */
        uint16_t wValue                                                                         /**< [In] The value for the mentioned configuration. */
    );

/**
 * \brief Reset the authentication
 *
 * \return Status code
 * \retval #PH_ERR_SUCCESS Operation successful.
 * \retval Other Depending on implementation and underlying component.
 */
phStatus_t phalMfDuoX_ResetAuthentication(
        void * pDataParams                                                                      /**< [In] Pointer to this layer's parameter structure. */
    );

/**
 * end of group phalMfDuoX_Utility
 * @}
 */

/**
 * end of group phalMfDuoX
 * @}
 */

#ifdef __cplusplus
} /* Extern C */
#endif

#endif /* NXPBUILD__PHAL_MFDUOX */

#endif /* PHALMFDUOX_H */
