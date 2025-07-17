/*
 * emv_payment_flow.c
 *
 * EMV Payment Processing Flow Implementation
 * Complete state machine for bank card transaction processing
 *
 * Created on: Jul 17, 2025
 * Author: Administrator
 */

#include "emv_payment_flow.h"
#include "phApp_Init.h"
#include "main.h"

/* External UART handle for Linux communication */
extern UART_HandleTypeDef huart1;

/* ================== Implementation ================== */

/**
 * Initialize payment flow
 */
EMV_Result_t EMV_Payment_Initialize(EMV_Payment_Context_t *context,
                                   void *pDataParams,
                                   uint32_t amount,
                                   uint16_t currency_code)
{
    memset(context, 0, sizeof(EMV_Payment_Context_t));

    /* Set transaction parameters */
    context->card_data.amount = amount;
    context->card_data.currency_code = currency_code;
    context->card_data.transaction_type = 0x00; /* Purchase */

    /* Initial state */
    context->current_state = EMV_STATE_APP_SELECTION;
    context->next_state = EMV_STATE_APP_SELECTION;

    DEBUG_PRINTF("=== EMV Payment Flow Initialized ===\r\n");
    DEBUG_PRINTF("Amount: %lu.%02lu, Currency: 0x%04X\r\n",
                amount/100, amount%100, currency_code);

    return EMV_SUCCESS;
}

/**
 * Get state description
 */
const char* EMV_Payment_GetStateDescription(EMV_Payment_State_t state)
{
    switch(state) {
        case EMV_STATE_IDLE: return "Idle";
        case EMV_STATE_APP_SELECTION: return "Application Selection";
        case EMV_STATE_APP_INITIALIZATION: return "Application Initialization";
        case EMV_STATE_READ_APP_DATA: return "Read Application Data";
        case EMV_STATE_OFFLINE_DATA_AUTH: return "Offline Data Authentication";
        case EMV_STATE_PROCESSING_RESTRICTIONS: return "Processing Restrictions";
        case EMV_STATE_CARDHOLDER_VERIFICATION: return "Cardholder Verification";
        case EMV_STATE_TERMINAL_RISK_MANAGEMENT: return "Terminal Risk Management";
        case EMV_STATE_TERMINAL_ACTION_ANALYSIS: return "Terminal Action Analysis";
        case EMV_STATE_ONLINE_DECISION: return "Online Transaction Decision";
        case EMV_STATE_ONLINE_PROCESSING: return "Online Processing";
        case EMV_STATE_ISSUER_AUTH: return "Issuer Authentication";
        case EMV_STATE_COMPLETION: return "Completion Processing";
        case EMV_STATE_SCRIPT_PROCESSING: return "Issuer Script Processing";
        case EMV_STATE_SUCCESS: return "Transaction Success";
        case EMV_STATE_FAILED: return "Transaction Failed";
        default: return "Unknown State";
    }
}

/**
 * Main state machine processing function
 */
EMV_Result_t EMV_Payment_ProcessStateMachine(EMV_Payment_Context_t *context)
{
    EMV_Result_t result = EMV_SUCCESS;

    DEBUG_PRINTF("\r\n>>> Current State: %s\r\n",
                EMV_Payment_GetStateDescription(context->current_state));

    switch(context->current_state) {
        case EMV_STATE_APP_SELECTION:
            result = EMV_State_ApplicationSelection(context);
            if(result == EMV_SUCCESS) {
                context->next_state = EMV_STATE_APP_INITIALIZATION;
            }
            break;

        case EMV_STATE_APP_INITIALIZATION:
            result = EMV_State_ApplicationInitialization(context);
            if(result == EMV_SUCCESS) {
                context->next_state = EMV_STATE_READ_APP_DATA;
            }
            break;

        case EMV_STATE_READ_APP_DATA:
            result = EMV_State_ReadApplicationData(context);
            if(result == EMV_SUCCESS) {
                context->next_state = EMV_STATE_OFFLINE_DATA_AUTH;
            }
            break;

        case EMV_STATE_OFFLINE_DATA_AUTH:
            result = EMV_State_OfflineDataAuthentication(context);
            if(result == EMV_SUCCESS) {
                context->next_state = EMV_STATE_PROCESSING_RESTRICTIONS;
            }
            break;

        case EMV_STATE_PROCESSING_RESTRICTIONS:
            result = EMV_State_ProcessingRestrictions(context);
            if(result == EMV_SUCCESS) {
                context->next_state = EMV_STATE_CARDHOLDER_VERIFICATION;
            }
            break;

        case EMV_STATE_CARDHOLDER_VERIFICATION:
            result = EMV_State_CardholderVerification(context);
            if(result == EMV_SUCCESS) {
                context->next_state = EMV_STATE_TERMINAL_RISK_MANAGEMENT;
            }
            break;

        case EMV_STATE_TERMINAL_RISK_MANAGEMENT:
            result = EMV_State_TerminalRiskManagement(context);
            if(result == EMV_SUCCESS) {
                context->next_state = EMV_STATE_TERMINAL_ACTION_ANALYSIS;
            }
            break;

        case EMV_STATE_TERMINAL_ACTION_ANALYSIS:
            result = EMV_State_TerminalActionAnalysis(context);
            if(result == EMV_SUCCESS) {
                context->next_state = EMV_STATE_ONLINE_DECISION;
            }
            break;

        case EMV_STATE_ONLINE_DECISION:
            result = EMV_State_OnlineDecision(context);
            if(result == EMV_SUCCESS) {
                if(context->online_decision) {
                    context->next_state = EMV_STATE_ONLINE_PROCESSING;
                } else {
                    context->next_state = EMV_STATE_COMPLETION;
                }
            }
            break;

        case EMV_STATE_ONLINE_PROCESSING:
            result = EMV_State_OnlineProcessing(context);
            if(result == EMV_SUCCESS) {
                context->next_state = EMV_STATE_ISSUER_AUTH;
            }
            break;

        case EMV_STATE_ISSUER_AUTH:
            result = EMV_State_IssuerAuthentication(context);
            if(result == EMV_SUCCESS) {
                context->next_state = EMV_STATE_COMPLETION;
            }
            break;

        case EMV_STATE_COMPLETION:
            result = EMV_State_Completion(context);
            if(result == EMV_SUCCESS) {
                context->next_state = EMV_STATE_SCRIPT_PROCESSING;
            }
            break;

        case EMV_STATE_SCRIPT_PROCESSING:
            result = EMV_State_ScriptProcessing(context);
            if(result == EMV_SUCCESS) {
                context->next_state = EMV_STATE_SUCCESS;
            }
            break;

        case EMV_STATE_SUCCESS:
            DEBUG_PRINTF("=== Transaction Flow Completed Successfully ===\r\n");
            return EMV_SUCCESS;

        case EMV_STATE_FAILED:
            DEBUG_PRINTF("=== Transaction Flow Failed ===\r\n");
            return EMV_ERROR_TRANSACTION_DECLINED;

        default:
            DEBUG_PRINTF("Unknown state: %d\r\n", context->current_state);
            result = EMV_ERROR_COMMUNICATION;
            break;
    }

    /* State transition */
    if(result == EMV_SUCCESS) {
        context->current_state = context->next_state;
        DEBUG_PRINTF("<<< Transition to: %s\r\n",
                    EMV_Payment_GetStateDescription(context->next_state));
    } else {
        context->current_state = EMV_STATE_FAILED;
        context->last_error = result;
        DEBUG_PRINTF("<<< State processing failed, error code: %d\r\n", result);
    }

    return result;
}

/* ================== State Processing Function Implementations ================== */

/**
 * State 1: Application Selection
 */
EMV_Result_t EMV_State_ApplicationSelection(EMV_Payment_Context_t *context)
{
    DEBUG_PRINTF("Executing Application Selection...\r\n");

    /* Reuse existing PPSE selection logic */
    EMV_Result_t result = EMV_CollectPPSEInfo(&context->card_data);
    if(result != EMV_SUCCESS) {
        DEBUG_PRINTF("PPSE selection failed\r\n");
        return result;
    }

    /* Application selection */
    result = EMV_CollectApplicationInfo(&context->card_data);
    if(result != EMV_SUCCESS) {
        DEBUG_PRINTF("Application selection failed\r\n");
        return result;
    }

    DEBUG_PRINTF("Application selection completed\r\n");
    return EMV_SUCCESS;
}

/**
 * State 2: Application Initialization
 */
EMV_Result_t EMV_State_ApplicationInitialization(EMV_Payment_Context_t *context)
{
    DEBUG_PRINTF("Executing Application Initialization...\r\n");

    /* Reuse existing GPO logic */
    EMV_Result_t result = EMV_CollectGPOInfo(&context->card_data);
    if(result != EMV_SUCCESS) {
        DEBUG_PRINTF("GPO failed\r\n");
        return result;
    }

    DEBUG_PRINTF("Application initialization completed\r\n");
    return EMV_SUCCESS;
}

/**
 * State 3: Read Application Data
 */
EMV_Result_t EMV_State_ReadApplicationData(EMV_Payment_Context_t *context)
{
    DEBUG_PRINTF("Reading Application Data...\r\n");

    /* Reuse existing record reading logic */
    EMV_Result_t result = EMV_CollectAllRecords(&context->card_data);
    if(result != EMV_SUCCESS) {
        DEBUG_PRINTF("Read application data failed\r\n");
        return result;
    }

    DEBUG_PRINTF("Application data reading completed, %d records\r\n",
                context->card_data.sfi_record_count);
    return EMV_SUCCESS;
}

/**
 * State 4: Offline Data Authentication
 */
EMV_Result_t EMV_State_OfflineDataAuthentication(EMV_Payment_Context_t *context)
{
    DEBUG_PRINTF("Executing Offline Data Authentication...\r\n");

    uint8_t auth_data[] = {0xEF, 0x08, 0x3F, 0x1A};
    uint8_t internal_auth_response[256];
    uint16_t internal_auth_len = 0;

    DEBUG_PRINTF("SEND INTERNAL AUTHENTICATE CMD...\r\n");
    EMV_InternalAuthenticate(auth_data, sizeof(auth_data),
                            internal_auth_response, &internal_auth_len);

    /* Send certificate data to Linux for verification */
    Linux_Response_t response = EMV_FormatAndSendLinuxCommand(
        LINUX_CMD_OFFLINE_DATA_AUTH, context);

    switch(response) {
        case LINUX_RESP_SUCCESS:
            context->offline_auth_result = 1; /* Authentication successful */
            DEBUG_PRINTF("Offline data authentication successful\r\n");
            return EMV_SUCCESS;

        case LINUX_RESP_DECLINED:
            context->offline_auth_result = 0; /* Authentication failed */
            DEBUG_PRINTF("Offline data authentication failed\r\n");
            return EMV_ERROR_TRANSACTION_DECLINED;

        default:
            DEBUG_PRINTF("Linux communication failed\r\n");
            return EMV_ERROR_COMMUNICATION;
    }
}

/**
 * State 5: Processing Restrictions
 */
EMV_Result_t EMV_State_ProcessingRestrictions(EMV_Payment_Context_t *context)
{
    DEBUG_PRINTF("Checking Processing Restrictions...\r\n");

    /* Send transaction amount and restriction info to Linux for checking */
    Linux_Response_t response = EMV_FormatAndSendLinuxCommand(
        LINUX_CMD_PROCESS_RESTRICTIONS, context);

    switch(response) {
        case LINUX_RESP_SUCCESS:
            context->restrictions_result = 1; /* Passed restriction check */
            DEBUG_PRINTF("Processing restrictions check passed\r\n");
            return EMV_SUCCESS;

        case LINUX_RESP_DECLINED:
            context->restrictions_result = 0; /* Failed restriction check */
            DEBUG_PRINTF("Processing restrictions check failed\r\n");
            return EMV_ERROR_TRANSACTION_DECLINED;

        default:
            DEBUG_PRINTF("Linux communication failed\r\n");
            return EMV_ERROR_COMMUNICATION;
    }
}

/**
 * State 6: Cardholder Verification
 */
EMV_Result_t EMV_State_CardholderVerification(EMV_Payment_Context_t *context)
{
    DEBUG_PRINTF("Executing Cardholder Verification...\r\n");

    /* Simulate PIN input process */
    DEBUG_PRINTF("Please enter PIN...\r\n");

    /* In actual implementation, this would have PIN input interface */
    /* Simplified to automatic pass for now */
    context->cardholder_verification = 1;

    DEBUG_PRINTF("Cardholder verification successful\r\n");
    return EMV_SUCCESS;
}

/**
 * State 7: Terminal Risk Management
 */
EMV_Result_t EMV_State_TerminalRiskManagement(EMV_Payment_Context_t *context)
{
    DEBUG_PRINTF("Executing Terminal Risk Management...\r\n");

    /* Send transaction data to Linux for risk assessment */
    Linux_Response_t response = EMV_FormatAndSendLinuxCommand(
        LINUX_CMD_TERMINAL_RISK_MGMT, context);

    switch(response) {
        case LINUX_RESP_SUCCESS:
        case LINUX_RESP_OFFLINE_APPROVED:
            context->risk_management_result = 1; /* Risk acceptable */
            DEBUG_PRINTF("Terminal risk management passed\r\n");
            return EMV_SUCCESS;

        case LINUX_RESP_ONLINE_REQUIRED:
            context->risk_management_result = 2; /* Online required */
            DEBUG_PRINTF("Terminal risk management requires online processing\r\n");
            return EMV_SUCCESS;

        case LINUX_RESP_DECLINED:
            context->risk_management_result = 0; /* Risk too high */
            DEBUG_PRINTF("Terminal risk management declined transaction\r\n");
            return EMV_ERROR_TRANSACTION_DECLINED;

        default:
            DEBUG_PRINTF("Linux communication failed\r\n");
            return EMV_ERROR_COMMUNICATION;
    }
}

/**
 * State 8: Terminal Action Analysis
 */
EMV_Result_t EMV_State_TerminalActionAnalysis(EMV_Payment_Context_t *context)
{
    DEBUG_PRINTF("Executing Terminal Action Analysis...\r\n");

    /* Send historical transaction data to Linux for behavior analysis */
    Linux_Response_t response = EMV_FormatAndSendLinuxCommand(
        LINUX_CMD_TERMINAL_ACTION_ANALYSIS, context);

    switch(response) {
        case LINUX_RESP_SUCCESS:
        case LINUX_RESP_OFFLINE_APPROVED:
            context->terminal_action_result = 1; /* Behavior normal */
            DEBUG_PRINTF("Terminal action analysis passed\r\n");
            return EMV_SUCCESS;

        case LINUX_RESP_ONLINE_REQUIRED:
            context->terminal_action_result = 2; /* Online confirmation required */
            DEBUG_PRINTF("Terminal action analysis requires online confirmation\r\n");
            return EMV_SUCCESS;

        case LINUX_RESP_DECLINED:
            context->terminal_action_result = 0; /* Abnormal behavior */
            DEBUG_PRINTF("Terminal action analysis detected abnormal behavior\r\n");
            return EMV_ERROR_TRANSACTION_DECLINED;

        default:
            DEBUG_PRINTF("Linux communication failed\r\n");
            return EMV_ERROR_COMMUNICATION;
    }
}

/**
 * State 9: Online Transaction Decision
 */
EMV_Result_t EMV_State_OnlineDecision(EMV_Payment_Context_t *context)
{
    DEBUG_PRINTF("Making Online Transaction Decision...\r\n");

    /* Decide whether online processing is needed based on previous analysis results */
    if(context->risk_management_result == 2 ||
       context->terminal_action_result == 2) {
        context->online_decision = 1; /* Online required */
        DEBUG_PRINTF("Decision result: Online processing required\r\n");
    } else {
        context->online_decision = 0; /* Can process offline */
        DEBUG_PRINTF("Decision result: Can process offline\r\n");
    }

    return EMV_SUCCESS;
}

/**
 * State 10: Online Processing
 */
EMV_Result_t EMV_State_OnlineProcessing(EMV_Payment_Context_t *context)
{
    DEBUG_PRINTF("Executing Online Processing...\r\n");

    /* Send transaction request to Linux for online authorization */
    Linux_Response_t response = EMV_FormatAndSendLinuxCommand(
        LINUX_CMD_ONLINE_PROCESSING, context);

    switch(response) {
        case LINUX_RESP_APPROVED:
            DEBUG_PRINTF("Online authorization successful\r\n");
            return EMV_SUCCESS;

        case LINUX_RESP_DECLINED:
            DEBUG_PRINTF("Online authorization declined\r\n");
            return EMV_ERROR_TRANSACTION_DECLINED;

        default:
            DEBUG_PRINTF("Online processing failed\r\n");
            return EMV_ERROR_ONLINE_AUTH;
    }
}

/**
 * State 11: Issuer Authentication
 */
EMV_Result_t EMV_State_IssuerAuthentication(EMV_Payment_Context_t *context)
{
    DEBUG_PRINTF("Executing Issuer Authentication...\r\n");

    /* Send ARPC for issuer authentication */
    Linux_Response_t response = EMV_FormatAndSendLinuxCommand(
        LINUX_CMD_ISSUER_AUTH, context);

    switch(response) {
        case LINUX_RESP_SUCCESS:
            DEBUG_PRINTF("Issuer authentication successful\r\n");
            return EMV_SUCCESS;

        case LINUX_RESP_DECLINED:
            DEBUG_PRINTF("Issuer authentication failed\r\n");
            return EMV_ERROR_TRANSACTION_DECLINED;

        default:
            DEBUG_PRINTF("Issuer authentication communication failed\r\n");
            return EMV_ERROR_COMMUNICATION;
    }
}

/**
 * State 12: Completion Processing
 */
EMV_Result_t EMV_State_Completion(EMV_Payment_Context_t *context)
{
    DEBUG_PRINTF("Executing Completion Processing...\r\n");

    /* Generate Transaction Certificate (TC) */
    DEBUG_PRINTF("Generating Transaction Certificate (TC)...\r\n");

    /* This should generate TC according to EMV specification */
    /* Simplified implementation */
    uint8_t tc[] = {0x9F, 0x26, 0x08, 0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0};

    DEBUG_PRINTF("Transaction certificate generation completed\r\n");
    DEBUG_PRINTF("TC: ");
    for(int i = 0; i < sizeof(tc); i++) {
        DEBUG_PRINTF("%02X ", tc[i]);
    }
    DEBUG_PRINTF("\r\n");

    return EMV_SUCCESS;
}

/**
 * State 13: Issuer Script Processing
 */
EMV_Result_t EMV_State_ScriptProcessing(EMV_Payment_Context_t *context)
{
    DEBUG_PRINTF("Processing Issuer Scripts...\r\n");

    /* Check if there are issuer scripts to execute */
    if(context->script_len > 0) {
        DEBUG_PRINTF("Executing issuer scripts (%d bytes)...\r\n", context->script_len);

        /* Send scripts to Linux for processing */
        Linux_Response_t response = EMV_FormatAndSendLinuxCommand(
            LINUX_CMD_SCRIPT_PROCESSING, context);

        if(response != LINUX_RESP_SUCCESS) {
            DEBUG_PRINTF("Script execution failed\r\n");
            return EMV_ERROR_COMMUNICATION;
        }

        DEBUG_PRINTF("Issuer script execution completed\r\n");
    } else {
        DEBUG_PRINTF("No issuer scripts to process\r\n");
    }

    return EMV_SUCCESS;
}

/* ================== Linux Communication Implementation ================== */

/**
 * Send command to Linux and wait for response (NOT USED in simulation mode)
 */
Linux_Response_t EMV_SendToLinux(Linux_Command_t cmd,
                                uint8_t *data,
                                uint16_t data_len,
                                uint8_t *response,
                                uint16_t *response_len)
{
    /* This function is preserved for future real Linux communication */
    /* Currently not used as we're in simulation mode */

    /* Construct command format: [HEAD][CMD][LEN_H][LEN_L][DATA][TAIL] */
    uint8_t tx_buffer[1024];
    uint16_t tx_len = 0;

    /* Command header */
    tx_buffer[tx_len++] = 0xAA;  /* Frame header */
    tx_buffer[tx_len++] = 0x55;  /* Frame header */
    tx_buffer[tx_len++] = cmd;   /* Command */
    tx_buffer[tx_len++] = (data_len >> 8) & 0xFF;  /* Length high byte */
    tx_buffer[tx_len++] = data_len & 0xFF;         /* Length low byte */

    /* Data */
    if(data && data_len > 0) {
        memcpy(&tx_buffer[tx_len], data, data_len);
        tx_len += data_len;
    }

    /* Frame tail */
    tx_buffer[tx_len++] = 0x0D;
    tx_buffer[tx_len++] = 0x0A;

    DEBUG_PRINTF("Sending Linux command 0x%02X, data length: %d\r\n", cmd, data_len);

    /* Debug: Print command frame in hex format */
    DEBUG_PRINTF("TX Frame: ");
    for(uint16_t i = 0; i < tx_len && i < 20; i++) {  /* Print first 20 bytes only */
        DEBUG_PRINTF("%02X ", tx_buffer[i]);
    }
    if(tx_len > 20) {
        DEBUG_PRINTF("... (total %d bytes)", tx_len);
    }
    DEBUG_PRINTF("\r\n");

    /* Send command */
    if(HAL_UART_Transmit(&huart1, tx_buffer, tx_len, 5000) != HAL_OK) {
        DEBUG_PRINTF("Failed to send command\r\n");
        return LINUX_RESP_ERROR;
    }

    /* Receive response */
    uint8_t rx_buffer[1024];
    HAL_StatusTypeDef uart_status = HAL_UART_Receive(&huart1, rx_buffer, sizeof(rx_buffer), 10000);

    if(uart_status != HAL_OK) {
        if(uart_status == HAL_TIMEOUT) {
            DEBUG_PRINTF("Response timeout\r\n");
        } else {
            DEBUG_PRINTF("UART receive error: %d\r\n", uart_status);
        }
        return LINUX_RESP_ERROR;
    }

    /* Debug: Print response frame in hex format */
    DEBUG_PRINTF("RX Frame: ");
    for(uint16_t i = 0; i < 10 && i < sizeof(rx_buffer); i++) {  /* Print first 10 bytes only */
        DEBUG_PRINTF("%02X ", rx_buffer[i]);
    }
    DEBUG_PRINTF("...\r\n");

    /* Parse response: [HEAD][RESP][LEN_H][LEN_L][DATA][TAIL] */
    if(rx_buffer[0] != 0xAA || rx_buffer[1] != 0x55) {
        DEBUG_PRINTF("Response format error\r\n");
        return LINUX_RESP_ERROR;
    }

    Linux_Response_t resp_code = (Linux_Response_t)rx_buffer[2];
    uint16_t resp_data_len = (rx_buffer[3] << 8) | rx_buffer[4];

    DEBUG_PRINTF("Linux response: 0x%02X, data length: %d\r\n", resp_code, resp_data_len);

    /* Copy response data */
    if(response && response_len && resp_data_len > 0) {
        *response_len = resp_data_len;
        memcpy(response, &rx_buffer[5], resp_data_len);
    }

    return resp_code;
}

/**
 * Format and send Linux command (SIMULATION MODE)
 */
Linux_Response_t EMV_FormatAndSendLinuxCommand(Linux_Command_t cmd, EMV_Payment_Context_t *context)
{
    DEBUG_PRINTF("\r\n=== LINUX INTERFACE REQUEST ===\r\n");

    switch(cmd) {
        case LINUX_CMD_OFFLINE_DATA_AUTH:
            DEBUG_PRINTF("Command: 0x%02X - Offline Data Authentication\r\n", cmd);
            DEBUG_PRINTF("Data: Application Select Response (%d bytes)\r\n", context->card_data.app_select_len);
            DEBUG_PRINTF("Expected: Verify certificates and signatures\r\n");
            DEBUG_PRINTF("Action: Extract cert -> Verify chain -> Validate signatures\r\n");
            break;

        case LINUX_CMD_PROCESS_RESTRICTIONS:
            DEBUG_PRINTF("Command: 0x%02X - Processing Restrictions Check\r\n", cmd);
            DEBUG_PRINTF("Data: Amount=%lu.%02lu, Currency=0x%04X\r\n",
                        context->card_data.amount/100, context->card_data.amount%100, context->card_data.currency_code);
            DEBUG_PRINTF("Expected: Check amount and usage limits\r\n");
            DEBUG_PRINTF("Action: Verify limits -> Check restrictions -> Validate usage\r\n");
            break;

        case LINUX_CMD_TERMINAL_RISK_MGMT:
            DEBUG_PRINTF("Command: 0x%02X - Terminal Risk Management\r\n", cmd);
            DEBUG_PRINTF("Data: Card UID, Transaction data, Records\r\n");
            DEBUG_PRINTF("Expected: Analyze transaction risk factors\r\n");
            DEBUG_PRINTF("Action: Risk scoring -> Blacklist check -> Pattern analysis\r\n");
            break;

        case LINUX_CMD_TERMINAL_ACTION_ANALYSIS:
            DEBUG_PRINTF("Command: 0x%02X - Terminal Action Analysis\r\n", cmd);
            DEBUG_PRINTF("Data: Historical transaction patterns\r\n");
            DEBUG_PRINTF("Expected: Analyze cardholder behavior\r\n");
            DEBUG_PRINTF("Action: Behavior analysis -> Anomaly detection -> ML scoring\r\n");
            break;

        case LINUX_CMD_ONLINE_PROCESSING:
            DEBUG_PRINTF("Command: 0x%02X - Online Processing\r\n", cmd);
            DEBUG_PRINTF("Data: Card UID, Authorization request\r\n");
            DEBUG_PRINTF("Expected: Communicate with issuing bank\r\n");
            DEBUG_PRINTF("Action: Format ISO8583 -> Bank communication -> Parse response\r\n");
            break;

        case LINUX_CMD_ISSUER_AUTH:
            DEBUG_PRINTF("Command: 0x%02X - Issuer Authentication\r\n", cmd);
            DEBUG_PRINTF("Data: ARPC verification data\r\n");
            DEBUG_PRINTF("Expected: Verify issuer cryptographic response\r\n");
            DEBUG_PRINTF("Action: Verify ARPC -> Validate auth -> Check integrity\r\n");
            break;

        case LINUX_CMD_SCRIPT_PROCESSING:
            DEBUG_PRINTF("Command: 0x%02X - Issuer Script Processing\r\n", cmd);
            DEBUG_PRINTF("Data: Issuer scripts (%d bytes)\r\n", context->script_len);
            DEBUG_PRINTF("Expected: Process post-transaction commands\r\n");
            DEBUG_PRINTF("Action: Parse scripts -> Execute updates -> Log results\r\n");
            break;
    }

    DEBUG_PRINTF("=== ASSUMING SUCCESS, CONTINUE ===\r\n\r\n");

    /* Simulate processing delay */
    HAL_Delay(200);

    /* Return appropriate success responses */
    switch(cmd) {
        case LINUX_CMD_OFFLINE_DATA_AUTH:
        case LINUX_CMD_PROCESS_RESTRICTIONS:
        case LINUX_CMD_ISSUER_AUTH:
        case LINUX_CMD_SCRIPT_PROCESSING:
            DEBUG_PRINTF("Simulated Response: SUCCESS\r\n");
            return LINUX_RESP_SUCCESS;

        case LINUX_CMD_TERMINAL_RISK_MGMT:
        case LINUX_CMD_TERMINAL_ACTION_ANALYSIS:
            DEBUG_PRINTF("Simulated Response: OFFLINE_APPROVED\r\n");
            return LINUX_RESP_OFFLINE_APPROVED;

        case LINUX_CMD_ONLINE_PROCESSING:
            DEBUG_PRINTF("Simulated Response: APPROVED\r\n");
            return LINUX_RESP_APPROVED;

        default:
            return LINUX_RESP_ERROR;
    }
}

/* ================== Main Integration Interface ================== */

/**
 * Main EMV payment flow entry function - replaces EMV_ProcessTransaction_Enhanced
 */
EMV_Result_t EMV_ProcessPaymentFlow(void *pDataParams, uint32_t amount, uint16_t currency_code)
{
    EMV_Payment_Context_t payment_context;
    EMV_Result_t result;

    /* 1. Initialize payment flow */
    result = EMV_Payment_Initialize(&payment_context, pDataParams, amount, currency_code);
    if(result != EMV_SUCCESS) {
        DEBUG_PRINTF("Payment flow initialization failed\r\n");
        return result;
    }

    /* 2. Collect basic card information first */
    result = EMV_CollectCardBasicInfo((phacDiscLoop_Sw_DataParams_t*)pDataParams, &payment_context.card_data);
    if(result != EMV_SUCCESS) {
        DEBUG_PRINTF("Card basic information collection failed\r\n");
        return result;
    }

    /* 3. Execute state machine until completion or failure */
    while(payment_context.current_state != EMV_STATE_SUCCESS &&
          payment_context.current_state != EMV_STATE_FAILED) {

        result = EMV_Payment_ProcessStateMachine(&payment_context);

        if(result != EMV_SUCCESS) {
            DEBUG_PRINTF("State machine processing failed: %s\r\n",
                        EMV_Payment_GetStateDescription(payment_context.current_state));
            break;
        }

        /* Add small delay for process observation */
        HAL_Delay(500);
    }

    /* 4. Display final result */
    if(payment_context.current_state == EMV_STATE_SUCCESS) {
        DEBUG_PRINTF("\r\n=== EMV Payment Flow Completed Successfully ===\r\n");
        EMV_ShowSuccessIndication();
        return EMV_SUCCESS;
    } else {
        DEBUG_PRINTF("\r\n=== EMV Payment Flow Failed ===\r\n");
        DEBUG_PRINTF("Last error: %d, Failed state: %s\r\n",
                    payment_context.last_error,
                    EMV_Payment_GetStateDescription(payment_context.current_state));
        EMV_ShowFailureIndication();
        return payment_context.last_error;
    }
}

EMV_Result_t EMV_InternalAuthenticate(uint8_t *auth_data, uint16_t auth_data_len,
                                     uint8_t *response, uint16_t *response_len)
{
    // 构造APDU: 00 88 00 00 Lc [Data] Le
    uint8_t apdu[261];
    uint16_t apdu_len = 0;

    apdu[apdu_len++] = 0x00;  // CLA
    apdu[apdu_len++] = 0x88;  // INS: INTERNAL AUTHENTICATE
    apdu[apdu_len++] = 0x00;  // P1
    apdu[apdu_len++] = 0x00;  // P2
    apdu[apdu_len++] = auth_data_len;  // Lc

    memcpy(&apdu[apdu_len], auth_data, auth_data_len);
    apdu_len += auth_data_len;
    apdu[apdu_len++] = 0x00;  // Le

    DEBUG_PRINTF("C-APDU: ");
    for (int i = 0; i < apdu_len; i++) {
        DEBUG_PRINTF("%02X ", apdu[i]);
    }
    DEBUG_PRINTF("\r\n");

    // 发送APDU
    phStatus_t status;
    uint8_t *rx_buffer;
    uint16_t rx_len = 0;

    status = phpalI14443p4_Exchange(
        phNfcLib_GetDataParams(PH_COMP_PAL_ISO14443P4),
        PH_EXCHANGE_DEFAULT, apdu, apdu_len, &rx_buffer, &rx_len);

    if (status == PH_ERR_SUCCESS && rx_len >= 2) {
        uint8_t sw1 = rx_buffer[rx_len-2];
        uint8_t sw2 = rx_buffer[rx_len-1];

        DEBUG_PRINTF("R-SW: %02X-%02X, Len: %d\r\n", sw1, sw2, rx_len-2);

        if (sw1 == 0x90 && sw2 == 0x00) {
            *response_len = rx_len - 2;
            memcpy(response, rx_buffer, *response_len);

            for (int i = 0; i < *response_len; i++) {
                if (i % 16 == 0) DEBUG_PRINTF("\r\n");
                DEBUG_PRINTF("%02X ", rx_buffer[i]);
            }
            DEBUG_PRINTF("\r\n");
            return EMV_SUCCESS;
        }
    }
    return EMV_ERROR_COMMUNICATION;
}
