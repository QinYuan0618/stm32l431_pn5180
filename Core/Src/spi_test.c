/*
 * spi_test.c
 * \brief 这层主要是用来测试初始化之后，spi层读取寄存器和eeprom是否成功，
 * 如果成功，代表最底层spi通信正常。那么接下来可以检查nfc读卡库的问题。
 *  Created on: Jun 14, 2025
 *      Author: Administrator
 */
#include "spi_test.h"
#include <stdio.h>					// printf

int test_pn5180_spi_communication(phhalHw_Pn5180_DataParams_t * pHal)
{
    phStatus_t wStatus = 0xFFFF; //初始化为失败
    uint8_t baReadEepromConfig[4];	//EEPROM返回值
    uint32_t dwValue;			 // 寄存器返回值存储在这个变量中

    printf("\n===== PN5180 SPI Communication Test =====\n");

    /* 测试1: 读取PADCONFIG_REG寄存器 */
        printf("\n1. Reading Register[PADCONFIG_REG]...\n");
        wStatus = phhalHw_Pn5180_Instr_ReadRegister(
            pHal,
			PADCONFIG_REG,  // 0x05U寄存器
            (uint32_t *)&dwValue
        );

        if (wStatus == PH_ERR_SUCCESS) {
            printf("register read successful\n [PADCONFIG_REG]: 0x%08lX\n", dwValue);
        } else {
            printf("Failed to read [PADCONFIG_REG]: 0x%04X\n", wStatus);
        }

    /* 测试2: 读取EEPROM中的NFCID */
    printf("\n2. Reading EEPROM (Dynamic UID Config)...\n");
    wStatus = phhalHw_Pn5180_Instr_ReadE2Prom(
        pHal,
        PHHAL_HW_PN5180_DYN_UID_CFG_E2PROM_ADDR,  // 0x58地址 NFCID3 或者去读 0x51地址; 1B
        baReadEepromConfig,
        1U
    );

    if (wStatus == PH_ERR_SUCCESS) {
        printf("Read EEPROM Succesfully \n NFCID3 is 0x%02X\n", baReadEepromConfig[0]);
    } else {
        printf("Failed to read EEPROM: 0x%04X\n", wStatus);
    }

    /* 测试3: 读取PADIN_REG寄存器 */
    printf("\n3. Reading Register[PADIN_REG]...\n");
    wStatus = phhalHw_Pn5180_Instr_ReadRegister(
        pHal,
		PADIN_REG,  // 0x05U寄存器
        (uint32_t *)&dwValue
    );

    if (wStatus == PH_ERR_SUCCESS) {
        printf("register read successful\n [PADIN_REG]: 0x%08lX\n", dwValue);
    } else {
        printf("Failed to read [PADIN_REG]: 0x%04X\n", wStatus);
    }

    /* 测试4: 读取EEPROM中的FIRMWARE VERSION */
    printf("\n4. Reading EEPROM (FW VERSION)...\n");
    wStatus = phhalHw_Pn5180_Instr_ReadE2Prom(
        pHal,
        0x12,  // EEPROM中firmware version的地址，数据为2B
        baReadEepromConfig,
        2U
    );

    if (wStatus == PH_ERR_SUCCESS) {
        printf("Read EEPROM Succesfully \n FW Version is %X.%X\n", baReadEepromConfig[0], baReadEepromConfig[1]);
    } else {
        printf("Failed to read EEPROM: 0x%04X\n", wStatus);
    }

    return 0;
}

