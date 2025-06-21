/*
 * pcd_iso15693.h
 *
 *  Created on: Jun 14, 2025
 *      Author: Administrator
 */

#ifndef INC_PCD_ISO15693_H_
#define INC_PCD_ISO15693_H_

#ifndef ISO15693_API_H
#define ISO15693_API_H

#include <ph_Status.h>

/* 初始化ISO15693模块 */
phStatus_t ISO15693_Init(void);

/* 检测ISO15693标签 */
phStatus_t ISO15693_DetectCard(uint8_t *pUid, uint8_t *pUidLength);

/* 读取单个块 */
phStatus_t ISO15693_ReadBlock(uint8_t bBlockNumber, uint8_t *pData, uint16_t *pDataLength);

/* 写入单个块 */
phStatus_t ISO15693_WriteBlock(uint8_t bBlockNumber, uint8_t *pData, uint8_t bDataLength);

/* 获取标签类型信息 */
phStatus_t ISO15693_GetCardType(uint8_t *pUid, char *pCardTypeName);

/* 反初始化 */
void ISO15693_DeInit(void);

/* 主函数改名test函数 */
int iso15693_test(void);

#endif /* ISO15693_API_H */

#endif /* INC_PCD_ISO15693_H_ */
