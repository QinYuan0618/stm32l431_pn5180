/*----------------------------------------------------------------------------*/
/* Copyright 2019-2020,2022 NXP                                               */
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
* Internal functions and definitions for Pn5190 HAL.
*
* $Author$
* $Revision$ (v07.13.00)
* $Date$
*/

#ifndef PHHALHW_PN5190_INT_H
#define PHHALHW_PN5190_INT_H

#include <ph_Status.h>
#include <phhalHw.h>
#include <phbalReg.h>

#ifdef _WIN32

#ifndef true
#define true 1
#endif

#ifndef false
#define false 0
#endif

#endif

/** \defgroup phhalHw_PN5190_Int Internal
* \brief Pn5190 HAL Internal functions
* @{
*/

/**
 * \brief PN5190 Specific event
 */
#define E_PH_OSAL_EVT_SIG                    (1U << 7U)     /**< signals that EVT is sent by PN5190. */

//#ifdef NXPBUILD__PHHAL_HW_DEV_PN5190
//#ifdef T_UTF
//#define E_PH_OSAL_EVT_BLOCKED                (1U << 6U)     /**< Signals another task that RdLib Thread has blocked due to unexpected event or response by PN5190. */
//#endif /* T_UTF */
//#endif /* NXPBUILD__PHHAL_HW_DEV_PN5190 */

#define DIRECTION_BYTE_LEN      0x01U
#define TYPE_FIELD_LEN          0x01U
#define LENGTH_FIELD_LEN        0x02U
#define STATUS_FIELD_LEN        0x01U

#define PHHAL_HW_PN5190_RESET_DELAY_MILLI_SECS          10U    /**< Delay used in HW reset. */
#define PHHAL_HW_PN5190_TESTBUS_ENABLE_ADDR             0x00U /**< TODO: Update correct address. */
#define PHHAL_HW_PN5190_TESTBUS_ENABLE_MASK             0x80U /**< TODO: Update correct mask. */
#define PHHAL_HW_PN5190_EXCHANGE_HEADER_SIZE            5U    /**< 3- Bytes of T and L, and 2 Bytes; TxLastBit and RxConfig */
#define PHHAL_HW_PN5190_TRANSMIT_HEADER_SIZE            5U    /**< 3- Bytes of T and L, and 2 Bytes; TxLastBit and RFU */

#define PHHAL_HW_PN5190_INT_SPI_WRITE                   0x7FU /**< Direction Bit0 -> 0 - Write; 1 - Read. */
#define PHHAL_HW_PN5190_INT_SPI_READ                    0xFFU /**< Direction Bit0 -> 0 - Write; 1 - Read. */

/* Timer configuration bits */

/* Timer config */
#define TIMER_FREQ                                      13.56          /**< Pn5190 clk frequency.*/
#define TMR_RELOAD_VALUE_MASK                           (0x000FFFFFUL) /**< The reload mask for the timer, also the maximum value that can be loaded into the timer reload register.*/
#define PHHAL_HW_PN5190_MAX_FREQ                        13560000U      /**< Pn5190 clk Maximum frequency = 13.56 MHz.*/
#define PHHAL_HW_PN5190_MIN_FREQ                        53000U         /**< Pn5190 clk Minimum frequency = 53 KHz.*/
/* TODO : Check what is the MAX and MIN Time Delay w.r.t PN5190 */
#define PHHAL_HW_PN5190_MAX_TIME_DELAY_MS               19784U         /**< Pn5190 Maximum Time Delay in milli second = 19.78443396226.*/
#define PHHAL_HW_PN5190_MIN_TIME_DELAY_US               1U             /**< Pn5190 Minimum Time Delay in micro second = 0.00001886792.*/
#define PHHAL_HW_PN5190_CONVERSION_MS_SEC               1000U          /**< MilliSec to Sec (In denominator for calculation purpose) --> 1000.*/
#define PHHAL_HW_PN5190_CONVERSION_US_SEC               1000000U       /**< MicroSec to Sec (In denominator for calculation purpose) --> 1000000.*/

#define PHHAL_HW_PN5190_I14443_ADD_DELAY_US             15U            /**< Additional digital timeout delay for ISO14443. */
#define PHHAL_HW_PN5190_I15693_ADD_DELAY_US             120U           /**< Additional digital timeout delay for ISO15693. */

#define PHHAL_HW_PN5190_IDLE_EVENT_LENGTH               12U            /**< Length of IDLE Event.*/

/**
* \name Rf Datarate Values
*/
/*@{*/
#define PHHAL_HW_RF_DATARATE_NO_CHANGE                  0x00FFU         /**< Data rate no change. */
/*@}*/

/* Macro to get the value of the specified register field */
#define PHHAL_HW_PN5190_INT_GET_VALUE(value, field)   (((value) & (PHHAL_HW_PN5190_REG_##field##_MASK)) >> (PHHAL_HW_PN5190_REG_##field##_POS))

/* Returns the RxBuffer pointer, length and size */
phStatus_t phhalHw_Pn5190_Int_GetRxBuffer(
    phhalHw_Pn5190_DataParams_t * pDataParams,        /**< [In] Pointer to this layer's parameter structure. */
    uint8_t ** pRxBuffer,                             /**< [Out] Pointer to HAL RX buffer.*/
    uint16_t * pRxBufferLen,                          /**< [Out] Length of the buffer.*/
    uint16_t * pRxBufferSize                          /**< [Out] Size of the buffer.*/
    );

/* Returns the TxBuffer pointer, length and size */
phStatus_t phhalHw_Pn5190_Int_GetTxBuffer(
    phhalHw_Pn5190_DataParams_t * pDataParams,        /**< [In] Pointer to this layer's parameter structure. */
    uint8_t ** pTxBuffer,                             /**< [Out] Pointer to HAL TX buffer.*/
    uint16_t * pTxBufferLen,                          /**< [Out] Length of the buffer.*/
    uint16_t * pTxBufferSize                          /**< [Out] Size of the buffer.*/
    );

phStatus_t phhalHw_Pn5190_Int_TimerStart(
    phhalHw_Pn5190_DataParams_t * pDataParams,        /**< [In] Pointer to this layer's parameter structure. */
    uint8_t bTimer,                                   /**< [In] Timer Option.*/
    uint32_t dwStartCond,                             /**< [In] Start condition of Timer.*/
    uint32_t dwStopCond,                              /**< [In] Stop condition of Timer.*/
    uint32_t wPrescaler,                              /**< [In] Pre-scalar value of Timer.*/
    uint32_t dwLoadValue                              /**< [In] Re-Load value of Timer.*/
    );

/**
* \brief Internal set config function.
* \return Status code
* \retval #PH_ERR_SUCCESS Operation successful.
* \retval #PH_ERR_UNSUPPORTED_PARAMETER Configuration is not supported or invalid.
* \retval #PH_ERR_INVALID_PARAMETER Parameter value is invalid.
* \retval #PH_ERR_PARAMETER_OVERFLOW Setting the parameter value would lead to an overflow.
*/

phStatus_t phhalHw_Pn5190_SetConfig_Int(
    phhalHw_Pn5190_DataParams_t * pDataParams,      /**< [In] Pointer to this layer's parameter structure. */
    uint16_t wConfig,                               /**<[In] SetConfig option.*/
    uint16_t wValue                                 /**<[In] SetConfig value.*/
    );

/* Pn5190 ISR callback */
void phhalHw_Pn5190_ISR_Callback(
    void * pDataParams                                /**< [In] Pointer to this layer's parameter structure. */
    );

phStatus_t phhalHw_Pn5190_Int_SetMinFdt(
    phhalHw_Pn5190_DataParams_t * pDataParams,        /**< [In] Pointer to this layer's parameter structure. */
    uint16_t wValue                                   /**< [In] #PH_ON or #PH_OFF. */
    );

phStatus_t phhalHw_Pn5190_Int_Retrieve_Data(
    phhalHw_Pn5190_DataParams_t * pDataParams,
    uint8_t ** ppRxBuffer,
    uint16_t * pRxLength
    );

phStatus_t phhalHw_Pn5190_Int_ClearNSetRegFields(
    phhalHw_Pn5190_DataParams_t * pDataParams,
    uint8_t bRegister,
    uint32_t dwMask,
    uint32_t dwPos,
    uint16_t wValue
    );

/* Pull NSS high/low */
void phhalHw_Pn5190_Int_WriteSSEL(
    void * pBalDataParams,                            /**< [In] Pointer to BAL layer's parameter structure. */
    uint8_t bValue                                    /**< [In] DAL macros either PH_DRIVER_SET_LOW / PH_DRIVER_SET_HIGH shall be used. */
    );

/**
* \brief Starts the timer as part of the time out behaviour.
* \note uses timer 1
* \return Status code
* \retval #PH_ERR_SUCCESS Operation successful.
* \retval Other Depending on implementation and underlying component.
*/

phStatus_t phhalHw_Pn5190_Int_SetTmo(
    phhalHw_Pn5190_DataParams_t *pDataParams,              /**< [In] Pointer to this layer's parameter structure. */
    uint16_t wTimeout,                                     /**< [In] Time out period. */
    uint8_t  bUnit                                         /**< [In] The unit unit used for specifying the delay. */
    );

/**
* \brief Retrieves the Frame Delay Time of the last command.
*
* \b Note: Frame Delay Time is defined between the last transmitted bit and the first received bit.
* \return Status code
* \retval #PH_ERR_SUCCESS Operation successful.
* \retval Other Depending on implementation and underlying component.
*/
phStatus_t phhalHw_Pn5190_Int_PCD_GetExchgFdt(
        phhalHw_Pn5190_DataParams_t * pDataParams,        /**< [In] Pointer to this layer's parameter structure. */
        uint32_t *pFdtUs                                  /**< [Out] Calculated time in microseconds from timer contents. */
);

/* Pn5190 Reset function */
void phhalHw_Pn5190_Int_Reset(void);

/* Pn5190 poll guard time callback */
void phhalHw_Pn5190_Int_GuardTimeCallBck(void);

phStatus_t phhalHw_Pn5190_Int_SetConfig_FelicaEmdReg(
    phhalHw_Pn5190_DataParams_t * pDataParams
    );

phStatus_t phhalHw_Pn5190_Int_SetConfig_FelicaEmdRegBit(
    phhalHw_Pn5190_DataParams_t * pDataParams,
    uint16_t wValue,
    uint32_t dwMaskValue
    );

phStatus_t phhalHw_Pn5190_Int_SetConfig_FelicaEmdRegByte(
    phhalHw_Pn5190_DataParams_t * pDataParams,
    uint16_t wValue,
    uint8_t bBytePos,
    uint32_t dwMaskValue
    );

/**
* \brief Apply card mode register settings (Tx and Rx Data Rate) according to given parameters.
* \return Status code
* \retval #PH_ERR_SUCCESS Operation successful.
* \retval Other Depending on implementation and underlying component.
*/
phStatus_t phhalHw_Pn5190_Int_SetCardMode(
    phhalHw_Pn5190_DataParams_t * pDataParams,        /**< [In] Pointer to this layer's parameter structure. */
    uint16_t wTxDataRate,                             /**< [In] TX data rate to be used. */
    uint16_t wRxDataRate,                             /**< [In] RX data rate to be used. */
    uint16_t wSubcarrier                              /**< [In] Sub carrier to be used. */
    );

phStatus_t phhalHw_Pn5190_Int_SetTxDataRateFraming(
    phhalHw_Pn5190_DataParams_t * pDataParams,
    uint16_t wConfig,
    uint16_t wValue);

phStatus_t phhalHw_Pn5190_Int_SetRxDataRateFraming(
    phhalHw_Pn5190_DataParams_t * pDataParams,
    uint16_t wConfig,
    uint16_t wValue);

phStatus_t phhalHw_Pn5190_Int_SetConfig_FelicaEmdRegByte(
    phhalHw_Pn5190_DataParams_t * pDataParams,
    uint16_t wValue,
    uint8_t bBytePos,
    uint32_t dwMaskValue
    );

phStatus_t phhalHw_Pn5190_Int_SetConfig_FelicaEmdRegBit(
    phhalHw_Pn5190_DataParams_t * pDataParams,
    uint16_t wValue,
    uint32_t dwMaskValue
    );

#ifndef _WIN32
phStatus_t phhalHw_Pn5190_Int_UserAbort(
    phhalHw_Pn5190_DataParams_t * pDataParams,
    uint8_t * pCMDAborted
    );
#endif

/**
* \brief Used by Hal for waiting for desired Events to Occur.
* Function return when desired event Occur Or upon timeOut.
* \return Status code
* \retval #PH_ERR_SUCCESS Operation successful.
* \retval #PH_ERR_ABORTED Current wait is aborted.
* \retval #PH_ERR_INTERNAL_ERROR Unexpected event occurred.
* \retval #PH_ERR_IO_TIMEOUT OSAL Timed-Out, resulting in PH_ERR_IO_TIMEOUT.
*/
phStatus_t phhalHw_Pn5190_Int_EventWait(
    phhalHw_Pn5190_DataParams_t * pDataParams,            /**<[In] DataParameter representing this layer. */
    uint32_t dwExpectedEvents,                            /**<[In] Specific Evt we are waiting for. */
    uint32_t dwEventTimeOut,                              /**<[In] Time in Milli-Sec, for Events to occur. */
    uint8_t bPayLoadPresent,                              /**<[In] Specifies if payload is to be returned using Pointer . */
    uint32_t * dwEventReceived                            /**<[InOut] Returns Event received */
    );

/** @}
* end of phhalHw_PN5190_Int group
*/
#endif  /* PHHALHW_PN5190_INT_H */
