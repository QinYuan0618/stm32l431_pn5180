/*
*         Copyright (c), NXP Semiconductors Bangalore / India
*
*                     (C)NXP Semiconductors
*       All rights are reserved. Reproduction in whole or in part is
*      prohibited without the written consent of the copyright owner.
*  NXP reserves the right to make changes without notice at any time.
* NXP makes no warranty, expressed, implied or statutory, including but
* not limited to any implied warranty of merchantability or fitness for any
*particular purpose, or that the use will not infringe any third party patent,
* copyright or trademark. NXP must not be liable for any loss or damage
*                          arising from its use.
*/

/** \file
* Generic phDriver(DAL) Component of Reader Library Framework.
*
* \brief 		STM32 HAL SPI Implementation for NXP NFC Library
* 				Modified from phbalReg_LpcOpenSpi.c for STM32L431 + PN5180
*
* $Author$		qinyuan
* $Revision$	v1
* $Date$		2025/06/06
*
* History:
*  PGh: Fixed case sensitivity for linux build
*  RS:  Generated 24. Jan 2017
*
*/

#include "phDriver.h"
#include "BoardSelection.h"
#include "main.h"			// STM32 HAL includes
#include "spi.h"			// my SPI configuration
#include <stdio.h>

#include <ph_Status.h>
#include <phbalReg.h>
#include <ph_RefDefs.h>

#define PHBAL_REG_LPCOPEN_SPI_ID                0x0DU       /**< ID for LPC Open SPI BAL component */
#define RX_BUFFER_SIZE_MAX                      272U

//static void phbalReg_LpcOpenSpiConfig(void);
void phbalReg_Stm32SpiConfig(void);

#ifdef PERF_TEST
static uint32_t dwSpiBaudRate = SSP_CLOCKRATE;
#endif /* PERF_TEST */

/**
* \brief Initialize the STM32 SPI BAL layer.
*
* \return Status code
* \retval #PH_DRIVER_SUCCESS Operation successful.
* \retval #PH_ERR_INVALID_DATA_PARAMS Parameter structure size is invalid.
*/
phStatus_t phbalReg_Init(
                                      void * pDataParams,
                                      uint16_t wSizeOfDataParams
                                      )
{
	volatile uint32_t delay;

    // 参数检查
    if((pDataParams == NULL) || (sizeof(phbalReg_Type_t) != wSizeOfDataParams))
    {
        return (PH_DRIVER_ERROR | PH_COMP_DRIVER);
    }

    // 设置BAL层参数:驱动模块的ID和总线是SPI类型
    ((phbalReg_Type_t *)pDataParams)->wId      = PH_COMP_DRIVER | PHBAL_REG_LPCOPEN_SPI_ID;
    ((phbalReg_Type_t *)pDataParams)->bBalType = PHBAL_REG_TYPE_SPI;

    // 初始化SPI（通常在MX_SPI1_Init()中已经完成）

#if 0  // ---NXP原代码
    SSP_ConfigFormat ssp_format;
    volatile uint32_t delay;

    if((pDataParams == NULL) || (sizeof(phbalReg_Type_t) != wSizeOfDataParams))
    {
        return (PH_DRIVER_ERROR | PH_COMP_DRIVER);
    }

    ((phbalReg_Type_t *)pDataParams)->wId      = PH_COMP_DRIVER | PHBAL_REG_LPCOPEN_SPI_ID;
    ((phbalReg_Type_t *)pDataParams)->bBalType = PHBAL_REG_TYPE_SPI;

    //phPlatform_Port_Host_SetPinConfig(PHPLATFORM_PORT_PIN_SPI);
    phbalReg_LpcOpenSpiConfig();

    Chip_SSP_Init(LPC_SSP);
#ifdef PERF_TEST
    Chip_SSP_SetBitRate(LPC_SSP, dwSpiBaudRate);
#endif /* PERF_TEST */

#ifndef PERF_TEST
    Chip_SSP_SetBitRate(LPC_SSP, SSP_CLOCKRATE);
#endif /* PERF_TEST */

    ssp_format.frameFormat = SSP_FRAMEFORMAT_SPI;
    ssp_format.bits = SSP_BITS_8;
    ssp_format.clockMode = SSP_CLOCK_MODE0;

    Chip_SSP_SetFormat(LPC_SSP, ssp_format.bits, ssp_format.frameFormat, ssp_format.clockMode);
    Chip_SSP_SetMaster(LPC_SSP, 1 /*Master*/);
    Chip_SSP_Enable(LPC_SSP);

    /* Wait Startup time */
    for(delay=0; delay<10000; delay++){}
#endif	// ---NXP原代码

    return PH_DRIVER_SUCCESS;
}

/**
* \brief STM32 SPI数据交换函数
* 这是最重要的函数，负责所有SPI通信
*/
phStatus_t phbalReg_Exchange(
                                        void * pDataParams,
                                        uint16_t wOption,
                                        uint8_t * pTxBuffer,
                                        uint16_t wTxLength,
                                        uint16_t wRxBufSize,
                                        uint8_t * pRxBuffer,
                                        uint16_t * pRxLength
                                        )
{
	uint8_t * pRxBuf = NULL;                    // 实际接收缓存指针
	uint8_t dummyTxByte = 0xFF;

	/* 只发送不接收 */
	if (pRxBuffer == NULL)
	{
		pRxBuf = NULL;
	}
	else /* 接收 */
	{
		pRxBuf = pRxBuffer;
	}

//1	printf("SPITX>> ");
	for (int i = 0; i < wTxLength; i++)
	{
		uint8_t txByte = (pTxBuffer != NULL) ? pTxBuffer[i] : dummyTxByte;	// 发送1字节
		uint8_t rxByte = 0x00;	// 接收1字节

		// 单字节全双工发送+接收
		if (HAL_SPI_TransmitReceive(&hspi3, &txByte, &rxByte, 1, 100) != HAL_OK)
		{
			return (PH_DRIVER_FAILURE | PH_COMP_DRIVER);
		}

//1		printf("%02X ", txByte);  // 打印发送内容

		if (pRxBuf != NULL && i < wRxBufSize)
		{
			pRxBuf[i] = rxByte;
		}
	}
//1	printf("\n");

	if (pRxBuf != NULL)
	{
//1		printf("SPIRX<< ");
		for (int i = 0; i < wTxLength && i < wRxBufSize; i++)
		{
//1			printf("%02X ", pRxBuf[i]);
		}
//1		printf("\n");
	}

	// 返回接收到的数据长度
	if (pRxLength != NULL)
	{
		*pRxLength = (pRxBuf != NULL) ? wTxLength : 0;
	}

	return PH_DRIVER_SUCCESS;
}

/**
* \brief 新增函数：设置SPI配置参数
*/
phStatus_t phbalReg_SetConfig(
    void * pDataParams,
    uint16_t wConfig,
    uint32_t dwValue
)
{
    switch(wConfig)
    {
    case PHBAL_CONFIG_SPI_BAUD:
        // STM32的SPI波特率通常在初始化时设置
        // 如果需要运行时改变，可以重新配置SPI参数
        // 这里暂时返回成功，实际项目中可能需要重新初始化SPI
        break;
    default:
        return (PH_DRIVER_ERROR | PH_COMP_DRIVER);
    }

    return PH_DRIVER_SUCCESS;
}

/**
* \brief 新增函数：获取SPI配置参数
*/
phStatus_t phbalReg_GetConfig(
    void * pDataParams,
    uint16_t wConfig,
    uint32_t * pValue
)
{
    switch(wConfig)
    {
    case PHBAL_CONFIG_SPI_BAUD:
        // 返回当前SPI时钟频率
        // 需要根据你的实际SPI配置计算
        *pValue = HAL_RCC_GetPCLK2Freq() / 16;  // 假设SPI预分频器为16
        break;
    default:
        return (PH_DRIVER_ERROR | PH_COMP_DRIVER);
    }

    return PH_DRIVER_SUCCESS;
}

static void phbalReg_LpcOpenSpiConfig(void)
{
#if 0	// ---NXP原代码
    /* Configure SSP pins (SCK, MOSI and MISO) */
    Chip_IOCON_PinMux(LPC_IOCON, (uint8_t)((((uint32_t)PHDRIVER_PIN_MOSI) & 0xFF00) >> 8),
            (uint8_t)(((uint32_t)PHDRIVER_PIN_MOSI) & 0xFF),
            IOCON_MODE_INACT,
            (uint8_t)((((uint32_t)PHDRIVER_PIN_MOSI) & 0xFF0000) >> 16));
    Chip_IOCON_PinMux(LPC_IOCON, (uint8_t)((((uint32_t)PHDRIVER_PIN_MISO) & 0xFF00) >> 8),
            (uint8_t)(((uint32_t)PHDRIVER_PIN_MISO) & 0xFF),
            IOCON_MODE_INACT,
            (uint8_t)((((uint32_t)PHDRIVER_PIN_MISO) & 0xFF0000) >> 16));
    Chip_IOCON_PinMux(LPC_IOCON, (uint8_t)((((uint32_t)PHDRIVER_PIN_SCK) & 0xFF00) >> 8),
            (uint8_t)(((uint32_t)PHDRIVER_PIN_SCK) & 0xFF),
            IOCON_MODE_INACT,
            (uint8_t)((((uint32_t)PHDRIVER_PIN_SCK) & 0xFF0000) >> 16));
#endif	// ---NXP原代码
}
