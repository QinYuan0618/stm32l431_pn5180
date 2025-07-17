/*
 * emv_payment_flow.h
 *
 * EMV Payment Processing Flow Implementation
 * Complete state machine for bank card transaction processing
 *
 * Created on: Jul 17, 2025
 * Author: Administrator
 */

#ifndef INC_EMV_PAYMENT_FLOW_H_
#define INC_EMV_PAYMENT_FLOW_H_

#include "emv_transaction.h"
#include "phacDiscLoop.h"
#include "phApp_Init.h"  /* For DEBUG_PRINTF macro */
#include <stdint.h>
#include <string.h>
#include <stdio.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ================== Payment Flow State Definitions ================== */
typedef enum {
    EMV_STATE_IDLE = 0,
    EMV_STATE_APP_SELECTION,         /* 1. Application Selection */
    EMV_STATE_APP_INITIALIZATION,    /* 2. Application Initialization */
    EMV_STATE_READ_APP_DATA,         /* 3. Read Application Data */
    EMV_STATE_OFFLINE_DATA_AUTH,     /* 4. Offline Data Authentication */
    EMV_STATE_PROCESSING_RESTRICTIONS, /* 5. Processing Restrictions */
    EMV_STATE_CARDHOLDER_VERIFICATION, /* 6. Cardholder Verification */
    EMV_STATE_TERMINAL_RISK_MANAGEMENT, /* 7. Terminal Risk Management */
    EMV_STATE_TERMINAL_ACTION_ANALYSIS, /* 8. Terminal Action Analysis */
    EMV_STATE_ONLINE_DECISION,       /* 9. Online Transaction Decision */
    EMV_STATE_ONLINE_PROCESSING,     /* 10. Online Processing */
    EMV_STATE_ISSUER_AUTH,           /* 11. Issuer Authentication */
    EMV_STATE_COMPLETION,            /* 12. Completion Processing */
    EMV_STATE_SCRIPT_PROCESSING,     /* 13. Issuer Script Processing */
    EMV_STATE_SUCCESS,
    EMV_STATE_FAILED
} EMV_Payment_State_t;

/* ================== Linux Interface Command Definitions ================== */
typedef enum {
    LINUX_CMD_OFFLINE_DATA_AUTH = 0x10,    /* Offline Data Authentication */
    LINUX_CMD_PROCESS_RESTRICTIONS = 0x11,  /* Processing Restrictions Check */
    LINUX_CMD_TERMINAL_RISK_MGMT = 0x12,   /* Terminal Risk Management */
    LINUX_CMD_TERMINAL_ACTION_ANALYSIS = 0x13, /* Terminal Action Analysis */
    LINUX_CMD_ONLINE_PROCESSING = 0x14,     /* Online Processing */
    LINUX_CMD_ISSUER_AUTH = 0x15,          /* Issuer Authentication */
    LINUX_CMD_SCRIPT_PROCESSING = 0x16,     /* Script Processing */
} Linux_Command_t;

/* ================== Linux Response Code Definitions ================== */
typedef enum {
    LINUX_RESP_SUCCESS = 0x00,
    LINUX_RESP_APPROVED = 0x01,
    LINUX_RESP_DECLINED = 0x02,
    LINUX_RESP_ONLINE_REQUIRED = 0x03,
    LINUX_RESP_OFFLINE_APPROVED = 0x04,
    LINUX_RESP_OFFLINE_DECLINED = 0x05,
    LINUX_RESP_ERROR = 0xFF
} Linux_Response_t;

/* ================== Extended Transaction Context ================== */
typedef struct {
    EMV_Complete_Card_Data_t card_data;     /* Original card data */
    EMV_Payment_State_t current_state;      /* Current state */
    EMV_Payment_State_t next_state;         /* Next state */

    /* Authentication related */
    uint8_t offline_auth_result;            /* Offline authentication result */
    uint8_t restrictions_result;            /* Restrictions check result */
    uint8_t cardholder_verification;        /* Cardholder verification result */
    uint8_t risk_management_result;         /* Risk management result */
    uint8_t terminal_action_result;         /* Terminal action analysis result */

    /* Online processing */
    uint8_t online_decision;                /* Online decision */
    uint8_t authorization_response[256];    /* Authorization response */
    uint16_t auth_response_len;             /* Response length */

    /* Script processing */
    uint8_t issuer_scripts[512];            /* Issuer scripts */
    uint16_t script_len;                    /* Script length */

    /* Error handling */
    EMV_Result_t last_error;                /* Last error */
    uint8_t retry_count;                    /* Retry count */

} EMV_Payment_Context_t;

/* ================== Main Interface Functions ================== */

/**
 * @brief Initialize payment flow
 * @param context Payment context
 * @param pDataParams DiscoveryLoop parameters
 * @param amount Transaction amount (in cents)
 * @param currency_code Currency code
 * @return EMV_Result_t
 */
EMV_Result_t EMV_Payment_Initialize(EMV_Payment_Context_t *context,
                                   void *pDataParams,
                                   uint32_t amount,
                                   uint16_t currency_code);

/**
 * @brief Execute payment flow state machine
 * @param context Payment context
 * @return EMV_Result_t
 */
EMV_Result_t EMV_Payment_ProcessStateMachine(EMV_Payment_Context_t *context);

/**
 * @brief Get current state description
 * @param state State
 * @return State description string
 */
const char* EMV_Payment_GetStateDescription(EMV_Payment_State_t state);

/**
 * @brief Main EMV payment flow entry function
 * @param pDataParams DiscoveryLoop parameters
 * @param amount Transaction amount (in cents)
 * @param currency_code Currency code
 * @return EMV_Result_t
 */
EMV_Result_t EMV_ProcessPaymentFlow(void *pDataParams, uint32_t amount, uint16_t currency_code);

/* ================== State Processing Functions ================== */

EMV_Result_t EMV_State_ApplicationSelection(EMV_Payment_Context_t *context);
EMV_Result_t EMV_State_ApplicationInitialization(EMV_Payment_Context_t *context);
EMV_Result_t EMV_State_ReadApplicationData(EMV_Payment_Context_t *context);
EMV_Result_t EMV_State_OfflineDataAuthentication(EMV_Payment_Context_t *context);
EMV_Result_t EMV_State_ProcessingRestrictions(EMV_Payment_Context_t *context);
EMV_Result_t EMV_State_CardholderVerification(EMV_Payment_Context_t *context);
EMV_Result_t EMV_State_TerminalRiskManagement(EMV_Payment_Context_t *context);
EMV_Result_t EMV_State_TerminalActionAnalysis(EMV_Payment_Context_t *context);
EMV_Result_t EMV_State_OnlineDecision(EMV_Payment_Context_t *context);
EMV_Result_t EMV_State_OnlineProcessing(EMV_Payment_Context_t *context);
EMV_Result_t EMV_State_IssuerAuthentication(EMV_Payment_Context_t *context);
EMV_Result_t EMV_State_Completion(EMV_Payment_Context_t *context);
EMV_Result_t EMV_State_ScriptProcessing(EMV_Payment_Context_t *context);

/* ================== Linux Communication Interface ================== */

/**
 * @brief Send command to Linux and wait for response
 * @param cmd Command type
 * @param data Data
 * @param data_len Data length
 * @param response Response buffer
 * @param response_len Response length
 * @return Linux_Response_t
 */
Linux_Response_t EMV_SendToLinux(Linux_Command_t cmd,
                                uint8_t *data,
                                uint16_t data_len,
                                uint8_t *response,
                                uint16_t *response_len);

/**
 * @brief Format and send Linux command
 * @param cmd Command
 * @param context Context
 * @return Linux_Response_t
 */
Linux_Response_t EMV_FormatAndSendLinuxCommand(Linux_Command_t cmd, EMV_Payment_Context_t *context);

#ifdef __cplusplus
}
#endif

#endif /* INC_EMV_PAYMENT_FLOW_H_ */
