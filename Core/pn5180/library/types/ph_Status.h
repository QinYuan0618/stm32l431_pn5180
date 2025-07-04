/*----------------------------------------------------------------------------*/
/* Copyright 2009-2025 NXP                                                    */
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
* Status Code definitions for Reader Library Framework.
* $Author$
* $Revision$ (v07.13.00)
* $Date$
*
*/

#ifndef PH_STATUS_H
#define PH_STATUS_H

#include <ph_TypeDefs.h>

#ifndef NXPBUILD_DELETE
#include <ph_NxpBuild.h>
#endif /* NXPBUILD_DELETE */

#ifdef _WIN32
#pragma warning(push)           /* PRQA S 3116 */
#pragma warning(disable:4001)   /* PRQA S 3116 */
#include <string.h>
#pragma warning(pop)            /* PRQA S 3116 */
#else
#include <string.h>
#endif

#ifdef NXPBUILD__PH_LOG
#include <phLog.h>
#endif /* NXPBUILD__PH_LOG */

/** \defgroup ph_Error Error Code Collection
* \brief Common Error Codes
* @{
*/

/** \name Success Codes
*/
/*@{*/
#define PH_ERR_SUCCESS                  ((phStatus_t)0x0000U) /**< Returned in case of no error. */
#define PH_ERR_SUCCESS_CHAINING         ((phStatus_t)0x0071U) /**< Rx chaining is not complete, further action needed. */
#define PH_ERR_SUCCESS_ACK              ((phStatus_t)0x0072U) /**< Received ACK packet for a previous transmitted packet. */
#define PH_ERR_SUCCESS_INCOMPLETE_BYTE  ((phStatus_t)0x0073U) /**< An incomplete byte was received. */
#define PH_ERR_SUCCESS_DESELECTED       ((phStatus_t)0x0074U) /**< DSL is sent for de-selection of target. */
#define PH_ERR_SUCCESS_RELEASED         ((phStatus_t)0x0075U) /**< RLS is sent for release of target. */
#define PH_ERR_SUCCESS_INFO_RECEIVED    ((phStatus_t)0x0076U) /**< Received I PDU in response for an I PDU. */
/*@}*/

/** \name Communication Errors
*/
/*@{*/
#define PH_ERR_IO_TIMEOUT               ((phStatus_t)0x0001U) /**< No reply received, e.g. PICC removal. */
#define PH_ERR_INTEGRITY_ERROR          ((phStatus_t)0x0002U) /**< Wrong CRC or parity detected. */
#define PH_ERR_COLLISION_ERROR          ((phStatus_t)0x0003U) /**< A collision occurred. */
#define PH_ERR_BUFFER_OVERFLOW          ((phStatus_t)0x0004U) /**< Attempt to write beyond buffer size. */
#define PH_ERR_FRAMING_ERROR            ((phStatus_t)0x0005U) /**< Invalid frame format. */
#define PH_ERR_PROTOCOL_ERROR           ((phStatus_t)0x0006U) /**< Received response violates protocol. */
#define PH_ERR_AUTH_ERROR               ((phStatus_t)0x0007U) /**< Authentication error. */
#define PH_ERR_READ_WRITE_ERROR         ((phStatus_t)0x0008U) /**< A Read or Write error occurred in RAM/ROM or Flash. */
#define PH_ERR_TEMPERATURE_ERROR        ((phStatus_t)0x0009U) /**< The RC sensors signal over heating. */
#define PH_ERR_RF_ERROR                 ((phStatus_t)0x000AU) /**< Error due to RF. */
#define PH_ERR_INTERFACE_ERROR          ((phStatus_t)0x000BU) /**< An error occurred in RC communication. */
#define PH_ERR_LENGTH_ERROR             ((phStatus_t)0x000CU) /**< A length error occurred. */
#define PH_ERR_RESOURCE_ERROR           ((phStatus_t)0x000DU) /**< An resource error. */
#define PH_ERR_TX_NAK_ERROR             ((phStatus_t)0x000EU) /**< TX Rejected sanely by the counterpart. */
#define PH_ERR_RX_NAK_ERROR             ((phStatus_t)0x000FU) /**< RX request Rejected sanely by the counterpart. */
#define PH_ERR_EXT_RF_ERROR             ((phStatus_t)0x0010U) /**< Error due to External RF. */
#define PH_ERR_NOISE_ERROR              ((phStatus_t)0x0011U) /**< EMVCo EMD Noise Error. */
#define PH_ERR_ABORTED                  ((phStatus_t)0x0012U) /**< Used when HAL Abort is called. */
#define PH_ERR_LPCD_ABORTED             ((phStatus_t)0x0013U) /**< LPCD is exited, without card detection. */
#define PH_ERR_INTERNAL_ERROR           ((phStatus_t)0x007FU) /**< An internal error occurred. */
#define PH_ERR_AUTH_DELAY               ((phStatus_t)0x00ADU) /**< Authentication Delay. */
/*@}*/

/** \name Parameter & Command Errors
*/
/*@{*/
#define PH_ERR_INVALID_DATA_PARAMS      ((phStatus_t)0x0020U) /**< Invalid data parameters supplied (layer id check failed). */
#define PH_ERR_INVALID_PARAMETER        ((phStatus_t)0x0021U) /**< Invalid parameter supplied. */
#define PH_ERR_PARAMETER_OVERFLOW       ((phStatus_t)0x0022U) /**< Reading/Writing a parameter would produce an overflow. */
#define PH_ERR_UNSUPPORTED_PARAMETER    ((phStatus_t)0x0023U) /**< Parameter not supported. */
#define PH_ERR_UNSUPPORTED_COMMAND      ((phStatus_t)0x0024U) /**< Command not supported. */
#define PH_ERR_USE_CONDITION            ((phStatus_t)0x0025U) /**< Condition of use not satisfied. */
#define PH_ERR_KEY                      ((phStatus_t)0x0026U) /**< A key error occurred. */
#define PH_ERR_PARAMETER_SIZE           ((phStatus_t)0x0031U) /**< An error occured because the size of the buffer is not met. */
#define PH_ERR_UNKNOWN                  ((phStatus_t)0x0032U) /**< Unknown error. */

/*@}*/

/** \name Osal Errors
*/
/*@{*/
#define PH_ERR_OSAL_ERROR               ((phStatus_t)0x0027U) /**< Error occurred during initialization. */
#define PH_ERR_OSAL_FAILURE             ((phStatus_t)0x0028U) /**< OSAL failed to perform the requested operation. */
/*@}*/

/** \name Event Errors
*/
/*@{*/
#define PH_ERR_EVENT_ERROR               ((phStatus_t)0x0029U) /**< Error occurred during initialization. */
#define PH_ERR_EVENT_FAILURE             ((phStatus_t)0x0030U) /**< Event failed to perform the requested operation. */
/*@}*/

/** @} */

/** \defgroup ph_Status Generic Definitions
* \brief Contains definitions which are generic throughout the library
* @{
*/

/**
* \name Running Modes of Reader Library
*/
/*@{*/
#define RD_LIB_MODE_EMVCO               0x01U /**< EMVCo Mode. */
#define RD_LIB_MODE_NFC                 0x02U /**< NFC Forum Mode. */
#define RD_LIB_MODE_ISO                 0x03U /**< ISO Mode. */
#define RD_LIB_MODE_FELICA              0x04U /**< FeliCa Mode. */
/*@}*/

/**
* \name Boolean Values
*/
/*@{*/
#define PH_ON                           0x0001U /**< Enabled. */
#define PH_OFF                          0x0000U /**< Disabled. */
#define PH_SUPPORTED                    0x0001U /**< Supported. */
#define PH_UNSUPPORTED                  0x0000U /**< Not Supported. */
/*@}*/

/**
* \name Configuration
*/
/*@{*/
#define PH_CONFIG_CUSTOM_BEGIN          0xE000U /**< Starting number of custom configs. */
/*@}*/

/**
* \name Component identifiers
*/
/*@{*/
#ifndef PHOSAL_H
#define PH_COMP_MASK                    ((phStatus_t)0xFF00U) /**< Component Mask for status code and component ID. */
#define PH_COMPID_MASK                  (0x00FFU) /**< ID Mask for component ID. */
#define PH_ERR_MASK                     (0x00FFU) /**< Error Mask for status code. */
#endif
#define PH_ERR_CUSTOM_BEGIN             (0x0080U) /**< Starting number of custom error codes. */
#define PH_COMP_GENERIC                 (0x0000U) /**< Generic Component Code. */
#define PH_COMP_BAL                     (0x0100U) /**< BAL Component Code. */
#define PH_COMP_HAL                     (0x0200U) /**< HAL Component Code. */
#define PH_COMP_PAL_ISO14443P3A         (0x0300U) /**< ISO14443-3A PAL-Component Code. */
#define PH_COMP_PAL_ISO14443P3B         (0x0400U) /**< ISO14443-3B PAL-Component Code. */
#define PH_COMP_PAL_ISO14443P4A         (0x0500U) /**< ISO14443-4A PAL-Component Code. */
#define PH_COMP_PAL_ISO14443P4          (0x0600U) /**< ISO14443-4 PAL-Component Code. */
#define PH_COMP_PAL_MIFARE              (0x0700U) /**< MIFARE product PAL-Component Code. */
#define PH_COMP_PAL_FELICA              (0x0800U) /**< Open FeliCa PAL-Component Code. */
#define PH_COMP_PAL_EPCUID              (0x0900U) /**< ICode EPC/UID PAL-Component Code. */
#define PH_COMP_PAL_SLI15693            (0x0A00U) /**< ICode SLI/ISO15693 PAL-Component Code. */
#define PH_COMP_PAL_I18000P3M3          (0x0B00U) /**< ISO18000-3 Mode3 PAL-Component Code. */
#define PH_COMP_PAL_I18092MPI           (0x0C00U) /**< ISO18092 passive initiator mode PAL-Component Code. */
#define PH_COMP_PAL_I18092MT            (0x0D00U) /**< ISO18092 target mode PAL-Component Code. */
#define PH_COMP_PAL_I14443P4MC          (0x0F00U) /**< ISO 14443-4 Card mode protocol. */
#define PH_COMP_AL_MFC                  (0x1000U) /**< MIFARE Classic contactless IC AL-Component Code. */
#define PH_COMP_AL_MFUL                 (0x1100U) /**< MIFARE Ultralight contactless IC AL-Component Code. */
#define PH_COMP_AL_MFP                  (0x1200U) /**< MIFARE Plus contactless IC AL-Component Code. */
#define PH_COMP_AL_MFPEVX               (0x2100U) /**< MIFARE Plus contactless IC EV1 AL-Component Code. */
#define PH_COMP_AL_VCA                  (0x1300U) /**< Virtual Card Architecture AL-Component Code. */
#define PH_COMP_AL_FELICA               (0x1400U) /**< Open FeliCa AL-Component Code. */
#define PH_COMP_AL_ICODE                (0x1500U) /**< ICode AL-Component Code. */
#define PH_COMP_AL_I18000P3M3           (0x1800U) /**< ISO18000-3 Mode3 AL-Component Code. */
#define PH_COMP_AL_MFDF                 (0x1900U) /**< MIFARE DESFire EV1 contactless IC AL Component Code. */
#define PH_COMP_AL_MFDFEVX              (0x2000U) /**< MIFARE DESFIRE EVx contactless IC(for Ev2, Ev3 and future versions) AL Component Code. */
#define PH_COMP_AL_MFDFLIGHT            (0x2300U) /**< MIFARE Prime Match AL Component Code. */
#define PH_COMP_AL_MFNTAG42XDNA         (0x2600U) /**< MIFARE Prime Ntag42XDna AL Component Code. */
#define PH_COMP_AL_MFDUOX               (0x2700U) /**< MIFARE DUOX AL Component Code. */
#define PH_COMP_AL_NTAGXDNA             (0x2800U) /**< NTAG X DNA AL Component Code. */
#define PH_COMP_AL_P40CMDPRIV           (0x1A00U) /**< P40 command libraryAL-Component Code. */
#define PH_COMP_AL_P40CMDPUB            (0x1B00U) /**< P40 command libraryAL-Component Code. */
#define PH_COMP_AL_T1T                  (0x1C00U) /**< T1T AL component code  */
#define PH_COMP_AL_TOP                  (0x1D00U) /**< Tag Operation AL component code  */
#define PH_COMP_DL_AMP                  (0x3000U) /**< Amplifier DL-Component Code. */
#define PH_COMP_DL_THSTRM               (0x3100U) /**< Thermostream DL-Component Code. */
#define PH_COMP_DL_OSCI                 (0x3200U) /**< Oscilloscope DL-Component Code. */
#define PH_COMP_DL_RDFPGA               (0x3300U) /**< Reader FPGA Box DL-Component Code. */
#define PH_COMP_DL_MSTAMPOSC            (0x3400U) /**< Master Amplifier Oscilloscope DL-Component Code. */
#define PH_COMP_DL_STEPPER              (0x3500U) /**< Stepper DL-Component Code. */
#define PH_COMP_AC_DISCLOOP             (0x4000U) /**< Discovery Loop. */
#define PH_COMP_CE_T4T                  (0x5000U) /**< Card Emulation T4T. */
#define PH_COMP_LN_LLCP                 (0x6000U) /**< LLCP code. */
#define PH_COMP_NP_SNEP                 (0x7000U) /**< SNEP Code. */
#define PH_COMP_CIDMANAGER              (0xE000U) /**< Cid Manager Component Code. */
#define PH_COMP_CRYPTOSYM               (0xE100U) /**< CryptoSym Component Code. */
#define PH_COMP_KEYSTORE                (0xE200U) /**< KeyStore Component Code. */
#define PH_COMP_TOOLS                   (0xE300U) /**< Tools Component Code. */
#define PH_COMP_CRYPTORNG               (0xE400U) /**< CryptoRng Component Code. */
#define PH_COMP_TMIUTILS                (0xE500U) /**< TMI Utilities Code. */
#define PH_COMP_CRYPTOASYM              (0xE600U) /**< CryptoASym Component Code. */
#define PH_COMP_LOG                     (0xEF00U) /**< Log Component Code. */
#ifndef PHOSAL_H
#define PH_COMP_OSAL                    (0xF000U) /**< OS AL component code. */
#endif
#define PH_COMP_DRIVER                  (0xF100U) /**< External phDriver component code. */
/*@}*/

/**
* Macro for error handling of underlying layer and exit.
*/
#define PH_CHECK_SUCCESS(status)         {if ((status) != PH_ERR_SUCCESS) {return (status);}}
#define PH_CHECK_SUCCESS_FCT(status,fct) {(status) = (fct); PH_CHECK_SUCCESS(status);}
#define PH_CHECK_SUCCESS_FCT_POS(status,fct) {(status) = (fct);}

#define PH_CHECK_ABORT(status)         {if (((status) & PH_ERR_MASK) == PH_ERR_ABORTED) {return (status);}}
#define PH_CHECK_ABORT_FCT(status,fct) {(status) = (fct); PH_CHECK_ABORT(status);}

#define PH_BREAK_ON_FAILURE(status)     {if ((status) != PH_ERR_SUCCESS) {break;}}
#define PH_CHECK_FAILURE_FCT(status,fct)  {(status) = (fct); PH_BREAK_ON_FAILURE(status);}
/**
*  Macro for component-error-code adding of current layer.
*/
#define PH_ADD_COMPCODE(stat, code)             \
    ((phStatus_t)                               \
     (                                          \
         (                                      \
             ((stat) == PH_ERR_SUCCESS)         \
             ||                                 \
             (                                  \
                 0U                             \
                 !=                             \
                 ((stat) & PH_COMP_MASK)        \
                 )                              \
             )                                  \
         ?                                      \
         (                                      \
             (phStatus_t)(stat)                 \
             )                                  \
         : (                                    \
             (((phStatus_t)(stat)) & (PH_ERR_MASK))           \
             |                                  \
             ((code) & PH_COMP_MASK))))

/** Return status for Values known at compile time. For variable status, use \ref PH_ADD_COMPCODE */
#define PH_ADD_COMPCODE_FIXED(stat,code) \
    ((phStatus_t)(((phStatus_t)(stat)) & PH_ERR_MASK) \
        | ((code) & PH_COMP_MASK))

#define PH_ADD_COMPCODE_NEG PH_ADD_COMPCODE_FIXED
#define PH_ADD_COMPCODE_POS PH_ADD_COMPCODE_FIXED
/**
*  Macro to get the component code or id using a pointer to a memory.
*/
#define PH_GET_COMPCODE(pId)            ( (*((uint16_t*)(pId))) & PH_COMP_MASK )
#define PH_GET_COMPID(pId)              ( (uint8_t)(*((uint16_t*)(pId))) )

/** \name Exchange Options
*/
/*@{*/
/**
Default exchange mode.
Combine with #PH_EXCHANGE_BUFFERED_BIT and
#PH_EXCHANGE_LEAVE_BUFFER_BIT to perform buffering.
\c ISO14443-4/ISO18092 specific:
Performs Tx/Rx chaining with the card.
Returns #PH_ERR_SUCCESS_CHAINING when RxBuffer is full and
does not ACK the last received block.
*/
#define PH_EXCHANGE_DEFAULT             0x0000U

/**
\c ISO14443-4/ISO18092 specific:
Chains given data to card/Target.
Combine with #PH_EXCHANGE_BUFFERED_BIT and
#PH_EXCHANGE_LEAVE_BUFFER_BIT to perform buffering.
Does not receive any data.
*/
#define PH_EXCHANGE_TXCHAINING          0x0001U

/**
\c ISO14443-4/ISO18092 specific:
Starts transmission with and R(ACK) block and
performs Rx chaining with the Card/Target.
Returns #PH_ERR_SUCCESS_CHAINING when RxBuffer is full and
does not ACK the last received block.
*/
#define PH_EXCHANGE_RXCHAINING          0x0002U

/**
\c ISO14443-4/ISO18092 specific:
Starts transmission with and R(ACK) block and
performs Rx chaining with the card.
Completes Rx chaining with the card if RxBuffer is full.
*/
#define PH_EXCHANGE_RXCHAINING_BUFSIZE  0x0003U

/** Mask for the above modes. All other bits are reserved. */
#define PH_EXCHANGE_MODE_MASK           0x000FU

/** Mask for custom exchange bits. These 4 bits can be used for custom exchange behavior. */
#define PH_EXCHANGE_CUSTOM_BITS_MASK    0x00F0U

/** Masking out the exchange bits. */
#define PH_EXCHANGE_BUFFER_MASK         0xF000U

/**
Does not clear the internal buffer before operation.
If this bit is set and data is transmitted,
the contents of the internal buffer are sent first.
*/
#define PH_EXCHANGE_LEAVE_BUFFER_BIT    0x4000U

/**
Buffers Tx-Data into internal buffer
instead of transmitting it.
*/
#define PH_EXCHANGE_BUFFERED_BIT        0x8000U

/**
The given data is the first part of a stream.
(Helper definition for buffering).
*/
#define PH_EXCHANGE_BUFFER_FIRST   (PH_EXCHANGE_DEFAULT | PH_EXCHANGE_BUFFERED_BIT)

/**
The given data is a subsequent part of a stream.
(Helper definition for buffering).
*/
#define PH_EXCHANGE_BUFFER_CONT    (PH_EXCHANGE_DEFAULT | PH_EXCHANGE_BUFFERED_BIT | PH_EXCHANGE_LEAVE_BUFFER_BIT)

/**
The given data is the last part of a stream.
(Helper definition for buffering).
*/
#define PH_EXCHANGE_BUFFER_LAST    (PH_EXCHANGE_DEFAULT | PH_EXCHANGE_LEAVE_BUFFER_BIT)

/**
Default transmit mode.
Combine with #PH_TRANSMIT_BUFFERED_BIT and
#PH_TRANSMIT_LEAVE_BUFFER_BIT to perform buffering.
*/
#define PH_TRANSMIT_DEFAULT             0x0000U

/**
Perform Transmit Chaining.
Combine with #PH_TRANSMIT_BUFFERED_BIT and
#PH_TRANSMIT_LEAVE_BUFFER_BIT to perform buffering.
*/
#define PH_TRANSMIT_TXCHAINING          0x0001U

/** Mask for the above modes. All other bits are reserved. */
#define PH_TRANSMIT_MODE_MASK           0x000FU

/**
Does not clear the internal buffer before transmit operation.
If this bit is set and data is transmitted,
the contents of the internal buffer are sent first.
*/
#define PH_TRANSMIT_LEAVE_BUFFER_BIT    0x4000U

/**
Buffers Tx-Data into internal buffer
instead of transmitting it.
*/
#define PH_TRANSMIT_BUFFERED_BIT        0x8000U

/**
The given data is the first part of a stream.
(Helper definition for buffering).
*/
#define PH_TRANSMIT_BUFFER_FIRST        (PH_TRANSMIT_DEFAULT | PH_TRANSMIT_BUFFERED_BIT)

/**
The given data is a subsequent part of a stream.
(Helper definition for buffering).
*/
#define PH_TRANSMIT_BUFFER_CONT         (PH_TRANSMIT_DEFAULT | PH_TRANSMIT_BUFFERED_BIT | PH_TRANSMIT_LEAVE_BUFFER_BIT)

/**
The given data is the last part of a stream.
(Helper definition for buffering).
*/
#define PH_TRANSMIT_BUFFER_LAST         (PH_TRANSMIT_DEFAULT | PH_TRANSMIT_LEAVE_BUFFER_BIT)

/**
Perform Re-transmit of data stored in HAL Tx buffer.
Should not be combined with #PH_TRANSMIT_BUFFERED_BIT and #PH_TRANSMIT_LEAVE_BUFFER_BIT.
This option should be used only in target / PICC mode.
*/
#define PH_TRANSMIT_PREV_FRAME          0x1000U

/**
Default exchange mode.
\c ISO14443-4/ISO18092 specific:
Performs Rx chaining with the card.
Returns #PH_ERR_SUCCESS_CHAINING when RxBuffer is full and
does not ACK the last received block.
*/
#define PH_RECEIVE_DEFAULT              0x0000U

/**
\c ISO14443-4/ISO18092 specific:
Starts transmission of ACK block and
performs Rx chaining with the card.
Returns #PH_ERR_SUCCESS_CHAINING when RxBuffer is full and
does not ACK the last received block.
*/
#define PH_RECEIVE_CHAINING             0x0001U

/**
\c ISO14443-4/ISO18092 specific:
Starts transmission with ACK block and
performs Rx chaining with the card.
Completes Rx chaining with the card if RxBuffer is full.
*/
#define PH_RECEIVE_CHAINING_BUFSIZE     0x0002U
/*@}*/

/** \name Log Interface
*/
/*@{*/
#ifdef NXPBUILD__PH_LOG

#define PH_LOG_VAR(pName) pName##_log
#define PH_LOG_HELPER_ALLOCATE_PARAMNAME(pParam) PH_LOG_ALLOCATE_PARAMNAME(pParam)
#define PH_LOG_HELPER_ALLOCATE_TEXT(pIdent, pText) PH_LOG_ALLOCATE_TEXT(pIdent, pText)
#define PH_LOG_HELPER_ADDSTRING(bLogType,pString) phLog_AddString(pDataParams, (bLogType), (pString))
#define PH_LOG_HELPER_ADDPARAM_UINT8(bLogType,pName,pParam) phLog_AddParam_Uint8(pDataParams, (bLogType), (pName), (pParam))
#define PH_LOG_HELPER_ADDPARAM_UINT16(bLogType,pName,pParam) phLog_AddParam_Uint16(pDataParams, (bLogType), (pName), (pParam))
#define PH_LOG_HELPER_ADDPARAM_UINT32(bLogType,pName,pParam) phLog_AddParam_Uint32(pDataParams, (bLogType), (pName), (pParam))
#define PH_LOG_HELPER_ADDPARAM_UINT64(blogType,pName,pParam) phLog_AddParam_Uint64(pDataParams, (blogType), (pName), (pParam))
#define PH_LOG_HELPER_ADDPARAM_INT32(blogType,pName,pParam) phLog_AddParam_Int32(pDataParams, (blogType), (pName), (pParam))
#define PH_LOG_HELPER_ADDPARAM_BUFFER(bLogType,pName,pParam,wLength) phLog_AddParam_Buffer(pDataParams, (bLogType),(pName),(pParam),(wLength))
#define PH_LOG_HELPER_EXECUTE(bOption) phLog_Execute(pDataParams, (bOption))

#else

#define PH_LOG_HELPER_ALLOCATE_PARAMNAME(pParam)
#define PH_LOG_HELPER_ALLOCATE_TEXT(pIdent, pText)
#define PH_LOG_HELPER_ADDSTRING(bLogType,pString)
#define PH_LOG_HELPER_ADDPARAM_UINT8(bLogType,pName,pParam)
#define PH_LOG_HELPER_ADDPARAM_UINT16(bLogType,pName,pParam)
#define PH_LOG_HELPER_ADDPARAM_UINT32(bLogType,pName,pParam)
#define PH_LOG_HELPER_ADDPARAM_BUFFER(bLogType,pName,pParam,wLength)
#define PH_LOG_HELPER_EXECUTE(bOption)

#endif /* NXPBUILD__PH_LOG */
/*@}*/

/** @}
* end of ph_Status group
*/

/** \name Debug Definitions
*/
/*@{*/
#ifdef NXPBUILD__PH_DEBUG
#   define PH_ASSERT_NULL(a) while((a) == NULL) { ; }
#   define PH_ASSERT_NULL_PARAM(a,comp_code) while((a) == NULL) { ; }
#   define PH_ASSERT_NULL_DATA_PARAM(dataparams,comp_code) while((dataparams) == NULL) { ; }
#endif /* NXPBUILD__PH_DEBUG */
#ifndef NXPBUILD__PH_DEBUG
#   define PH_ASSERT_NULL(a) {if((a) == NULL) {return PH_ERR_INVALID_PARAMETER;}}
#   define PH_ASSERT_NULL_PARAM(a,comp_code) {if((a) == NULL) {return PH_ADD_COMPCODE(PH_ERR_INVALID_PARAMETER, (comp_code));}}
#   define PH_ASSERT_NULL_DATA_PARAM(dataparams,comp_code) {if((dataparams) == NULL) {return PH_ADD_COMPCODE(PH_ERR_INVALID_DATA_PARAMS, (comp_code));}}
#endif /* NXPBUILD__PH_DEBUG */
/*@}*/
#define PH_UNUSED_VARIABLE(x) ((void)x)

#endif /* PH_STATUS_H */
