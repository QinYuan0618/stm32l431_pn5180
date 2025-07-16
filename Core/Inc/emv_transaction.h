/*
 * emv_transaction.h
 *
 *  Created on: Jul 16, 2025
 *      Author: Administrator
 */

#ifndef INC_EMV_TRANSACTION_H_
#define INC_EMV_TRANSACTION_H_

#include "phacDiscLoop.h"
#include "phpalI14443p4.h"
#include "phNfcLib.h"
#include "main.h"
#include <stdint.h>

/* EMV结果代码枚举 */
typedef enum {
    EMV_SUCCESS = 0,
    EMV_ERROR_CARD_NOT_EMV,
    EMV_ERROR_PPSE_SELECT,
    EMV_ERROR_APP_SELECT,
    EMV_ERROR_GPO,
    EMV_ERROR_READ_RECORD,
    EMV_ERROR_COMMUNICATION,
    EMV_ERROR_TRANSACTION_DECLINED,
    EMV_ERROR_ONLINE_AUTH
} EMV_Result_t;

/* EMV交易上下文结构体 */
typedef struct {
    uint8_t card_uid[10];          // 卡片UID
    uint8_t card_uid_len;          // UID长度
    uint32_t amount;               // 交易金额 (分为单位)
    uint16_t currency_code;        // 货币代码 (如0x0156表示CNY)
    uint8_t transaction_status;    // 交易状态
} EMV_Transaction_Context_t;

// ==================================================
// 修改1: 扩展EMV交易上下文，包含完整卡片数据
// ==================================================
typedef struct {
    // 基础卡片信息
    uint8_t card_uid[10];
    uint8_t card_uid_len;
    uint8_t card_sak;
    uint8_t card_atqa[2];

    // EMV应用数据
    uint8_t ppse_data[256];
    uint16_t ppse_len;

    uint8_t app_select_data[256];
    uint16_t app_select_len;

    uint8_t gpo_data[256];
    uint16_t gpo_len;

    // 应用记录数据
    uint8_t sfi_records[10][256];  // 最多10个记录
    uint16_t sfi_record_lens[10];
    uint8_t sfi_record_count;

    // 交易参数
    uint32_t amount;
    uint16_t currency_code;
    uint8_t transaction_type;

} EMV_Complete_Card_Data_t;
/* 主要接口函数声明 */

/**
 * @brief 检查是否为EMV兼容卡片
 * @param pDataParams Discovery Loop数据参数
 * @return 1-EMV兼容, 0-非EMV兼容
 */
uint8_t EMV_IsEMVCompatibleCard(void *pDataParams);

/**
 * @brief 处理EMV交易流程
 * @param pDataParams Discovery Loop数据参数
 * @param amount 交易金额(分为单位)
 * @param currency_code 货币代码
 * @return EMV交易结果
 */
EMV_Result_t EMV_ProcessTransaction(void *pDataParams, uint32_t amount, uint16_t currency_code);

/**
 * @brief 等待卡片移除
 * @param pDataParams Discovery Loop数据参数
 */
void EMV_WaitForCardRemoval(void *pDataParams);

/* EMV内部处理函数声明 */

/**
 * @brief 选择PPSE (Proximity Payment System Environment)
 * @return EMV结果代码
 */
EMV_Result_t EMV_SelectPPSE(void);

/**
 * @brief 选择应用
 * @param aid 应用标识符
 * @param aid_len AID长度
 * @return EMV结果代码
 */
EMV_Result_t EMV_SelectApplication(uint8_t *aid, uint8_t aid_len);

/**
 * @brief 获取处理选项 (Get Processing Options)
 * @param amount 交易金额
 * @param currency_code 货币代码
 * @return EMV结果代码
 */
EMV_Result_t EMV_GetProcessingOptions(uint32_t amount, uint16_t currency_code);

/**
 * @brief 读取应用数据
 * @return EMV结果代码
 */
EMV_Result_t EMV_ReadApplicationData(void);

/**
 * @brief 读取指定记录
 * @param sfi 短文件标识符
 * @param record_num 记录号
 * @return EMV结果代码
 */
EMV_Result_t EMV_ReadRecord(uint8_t sfi, uint8_t record_num);

/**
 * @brief 发送交易数据到Linux端
 * @param amount 交易金额
 * @param currency_code 货币代码
 * @return 0-成功, -1-失败
 */
int EMV_SendDataToLinux(uint32_t amount, uint16_t currency_code);

EMV_Result_t EMV_ProcessTransaction_Enhanced(void *pDataParams, uint32_t amount, uint16_t currency_code);
EMV_Result_t EMV_CollectCardBasicInfo(phacDiscLoop_Sw_DataParams_t *pDiscLoop, EMV_Complete_Card_Data_t *card_data);
EMV_Result_t EMV_CollectPPSEInfo(EMV_Complete_Card_Data_t *card_data);
EMV_Result_t EMV_CollectApplicationInfo(EMV_Complete_Card_Data_t *card_data);
EMV_Result_t EMV_CollectGPOInfo(EMV_Complete_Card_Data_t *card_data);
EMV_Result_t EMV_CollectAllRecords(EMV_Complete_Card_Data_t *card_data);
EMV_Result_t EMV_SendCompleteDataToLinux(EMV_Complete_Card_Data_t *card_data);
EMV_Result_t EMV_WaitForLinuxResult(EMV_Complete_Card_Data_t *card_data);
void EMV_ShowSuccessIndication(void);
void EMV_ShowFailureIndication(void);

/* 常用的EMV常量定义 */

/* 常见AID (Application Identifier) */
#define EMV_AID_VISA_CREDIT         {0xA0, 0x00, 0x00, 0x00, 0x03, 0x10, 0x10}
#define EMV_AID_VISA_DEBIT          {0xA0, 0x00, 0x00, 0x00, 0x03, 0x20, 0x10}
#define EMV_AID_MASTERCARD          {0xA0, 0x00, 0x00, 0x00, 0x04, 0x10, 0x10}
#define EMV_AID_UNIONPAY            {0xA0, 0x00, 0x00, 0x03, 0x33, 0x01, 0x01}
#define EMV_AID_AMEX                {0xA0, 0x00, 0x00, 0x00, 0x25, 0x01, 0x01}

/* 货币代码 */
#define EMV_CURRENCY_CNY            0x0156  // 人民币
#define EMV_CURRENCY_USD            0x0840  // 美元
#define EMV_CURRENCY_EUR            0x0978  // 欧元
#define EMV_CURRENCY_JPY            0x0392  // 日元

/* EMV状态字 */
#define EMV_SW_SUCCESS              0x9000  // 成功
#define EMV_SW_FILE_NOT_FOUND       0x6A82  // 文件未找到
#define EMV_SW_RECORD_NOT_FOUND     0x6A83  // 记录未找到
#define EMV_SW_WRONG_PARAMETERS     0x6A86  // 参数错误
#define EMV_SW_COMMAND_NOT_ALLOWED  0x6986  // 命令不允许

#endif /* INC_EMV_TRANSACTION_H_ */
