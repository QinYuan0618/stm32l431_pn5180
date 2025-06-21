/*
 * pn5180.c
 *
 *  Created on: Jun 13, 2025
 *      Author: Administrator
 */

#include "pn5180.h"
#include "spi.h"
#include "tim.h"		// us delay
#include "phhalHw.h"
#include "phhalHw_Pn5180.h"
#include "phhalHw_Pn5180_Reg.h"
#include "phhalHw_Pn5180_Instr.h"
#include "phalICode_Int.h"
#include <string.h>
#include <stdio.h>


/* spi单字节读写函数：hal库版本 */
#if (USE_SPI_HAL_LIB == 1)
static uint8_t PN5180_SPI_ReadWriteByte(uint8_t TxData)
{
    uint8_t RxData = 0;
    if(HAL_SPI_TransmitReceive(pn5180_spi_handle, &TxData, &RxData, 1, 2) != HAL_OK)
    {
        RxData = 0XFF;
    }
    return RxData;
}
#else
/* spi单字节读写函数：直接读写寄存器 */
static uint8_t PN5180_SPI_ReadWriteByte(uint8_t TxData)
{
    uint8_t retry  = 0;
    while(__HAL_SPI_GET_FLAG(pn5180_spi_handle, SPI_FLAG_TXE) == RESET)
    {
        if(++retry > 200)    return 0;
    }
    pn5180_spi_handle->Instance->DR = TxData;
    retry = 0;
    while(__HAL_SPI_GET_FLAG(pn5180_spi_handle, SPI_FLAG_RXNE) == RESET)
    {
        if(++retry > 200)    return 0;
    }
    return (uint8_t)(pn5180_spi_handle->Instance->DR & 0XFF);
}
#endif


/* 芯片复位：
 * PN5180 芯片有一个复位引脚（通常叫 RST 或 RESET），通过控制这个引脚的高低电平，可以让芯片重新启动 */
void PN5180_Reset(void)
{
    HAL_GPIO_WritePin(PN5180_RST_GPIO_Port, PN5180_RST_Pin, GPIO_PIN_SET);		// 预备
    delay_us(2000);
    HAL_GPIO_WritePin(PN5180_RST_GPIO_Port, PN5180_RST_Pin, GPIO_PIN_RESET);	// 芯片复位
    delay_us(2000);
    HAL_GPIO_WritePin(PN5180_RST_GPIO_Port, PN5180_RST_Pin, GPIO_PIN_SET);		// 芯片开始重新运行
    delay_us(2000);
}

int PN5180_BusyPinIsHigh(void)
{
    return HAL_GPIO_ReadPin(PN5180_BUSY_GPIO_Port, PN5180_BUSY_Pin) == GPIO_PIN_SET ? 1 : 0;
}

int PN5180_BusyPinIsLow(void)
{
    return HAL_GPIO_ReadPin(PN5180_BUSY_GPIO_Port, PN5180_BUSY_Pin) == GPIO_PIN_RESET ? 1 : 0;
}

void PN5180_Select(void)
{
    HAL_GPIO_WritePin(PN5180_NSS_GPIO_Port, PN5180_NSS_Pin, GPIO_PIN_RESET);
}

void PN5180_DisSelect(void)
{
    HAL_GPIO_WritePin(PN5180_NSS_GPIO_Port, PN5180_NSS_Pin, GPIO_PIN_SET);
}


//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////












void PN5180_WriteBytes(const void* Buffer, uint32_t len)
{
    int i = 0;
    uint8_t* p = (uint8_t *)Buffer;

    /* Wait for the Busy to be low */
    while(PN5180_BusyPinIsHigh()) {}

    /* Enable chip select connected to reader IC by pulling NSS low. */
    PN5180_Select();

    /* Build the Command frame and send it */
    for(i = 0; i < len; i++)
    {
        PN5180_SPI_ReadWriteByte(*p++);
    }

    /* Disable chip select connected to reader IC by pulling NSS high. */
    PN5180_DisSelect();
}

void PN5180_ReadBytes(void* Buffer, uint32_t len)
{
    int i = 0;
    uint8_t* p = (uint8_t *)Buffer;

    /* Wait for the Busy to be low */
    while(PN5180_BusyPinIsHigh()) {}

    /* Enable chip select connected to reader IC by pulling NSS low. */
    PN5180_Select();

    /* Build the Command frame and send it */
    for(i = 0; i < len; i++)
    {
        *p++ = PN5180_SPI_ReadWriteByte(0XFF);
    }

    /* Disable chip select connected to reader IC by pulling NSS high. */
    PN5180_DisSelect();
}

/* 说明：从 PN5180 芯片的 EEPROM 中读取数据
 * 参数1：Address 要读取的 EEPROM 地址（起始地址）
 * 参数2：Buffer 指向存储读取数据的缓冲区指针
 * 参数3：Length 要读取的字节数 */
void PN5180_ReadE2Prom(uint8_t Address, void* Buffer, uint8_t Length)
{
	// 发送给 pn5180 的命令帧
    uint8_t frame[] =
    {
        PHHAL_HW_PN5180_GET_INSTR_READ_E2PROM,	// 读取 EEPROM 的指令码
        Address,								// 从哪里开始读
        Length									// 要读取的数据长度
    };
    PN5180_WriteBytes(frame, sizeof(frame));	// 主机（主设备）通过 SPI 发命令帧给 PN5180 芯片（从设备）
    PN5180_ReadBytes(Buffer, Length);			// 发送完读取命令后，PN5180 会返回指定长度的数据
}

void PN5180_WriteE2Prom(uint8_t Address, const void* Buffer, uint8_t Length)
{
    uint8_t frame[] =
    {
        PHHAL_HW_PN5180_SET_INSTR_WRITE_E2PROM,
        Address,
        Length
    };
    PN5180_WriteBytes(frame, sizeof(frame));  // д��������
    PN5180_WriteBytes(Buffer, Length);        // ��������
}

void PN5180_WriteRegisterAndMask(uint8_t Reg, uint32_t Mask)
{
    uint8_t frame[] =
    {
        PHHAL_HW_PN5180_SET_INSTR_WRITE_REGISTER_AND_MASK,
        Reg,
        (uint8_t)(Mask & 0xFFU),
        (uint8_t)((Mask >> 8U) & 0xFFU),
        (uint8_t)((Mask >> 16U) & 0xFFU),
        (uint8_t)((Mask >> 24U) & 0xFFU)
    };
    PN5180_WriteBytes(frame, sizeof(frame));
}

void PN5180_WriteRegisterOrMask(uint8_t Reg, uint32_t Mask)
{
    uint8_t frame[] =
    {
        PHHAL_HW_PN5180_SET_INSTR_WRITE_REGISTER_OR_MASK,
        Reg,
        (uint8_t)(Mask & 0xFFU),
        (uint8_t)((Mask >> 8U) & 0xFFU),
        (uint8_t)((Mask >> 16U) & 0xFFU),
        (uint8_t)((Mask >> 24U) & 0xFFU)
    };
    PN5180_WriteBytes(frame, sizeof(frame));
}

void PN5180_WriteRegister(uint8_t Reg, uint32_t Value)
{
    uint8_t frame[] =
    {
        PHHAL_HW_PN5180_SET_INSTR_WRITE_REGISTER,
        Reg,
        (uint8_t)(Value & 0xFFU),
        (uint8_t)((Value >> 8U) & 0xFFU),
        (uint8_t)((Value >> 16U) & 0xFFU),
        (uint8_t)((Value >> 24U) & 0xFFU)
    };
    PN5180_WriteBytes(frame, sizeof(frame));
}

uint32_t PN5180_ReadRegister(uint8_t Reg)
{
    uint32_t value = 0;
    uint8_t frame[] =
    {
        PHHAL_HW_PN5180_GET_INSTR_READ_REGISTER,
        Reg
    };
    PN5180_WriteBytes(frame, sizeof(frame));
    PN5180_ReadBytes(&value, 4);
    return value;
}

/* 初始化 PN5180 芯片，包括复位、读取固件版本、配置中断、检查和配置数字延迟等 */
int PN5180_Init(void)
{
    uint16_t FwVersion = 0X0111;		// [待读取] 从EEPROM读取的固件版本 2Bytes

    uint8_t DigitalDelayCfg = 0X00;		// 存储从芯片中 EEPROM 读取的数字延迟配置 1Bytes

    /* Reset Hardware */
    PN5180_Reset();

    /* Get Firmware Version */
    PN5180_ReadE2Prom(PHHAL_HW_PN5180_FIRMWARE_VERSION_ADDR, &FwVersion, 2);
    if(FwVersion == 0XFFFF)
    {
        printf(" pn5180 init failed!\r\n");
        return -1;
    }
    // 提取高8位是主版本号，提取低8位是次版本号，如果正确应该是0.0
    printf(" pn5180 init ok,firmware version:%d.%d\r\n",(FwVersion >> 8 ) & 0XFF, FwVersion & 0XFF);

    /* Disable Idle IRQ */
    PN5180_WriteRegisterAndMask(IRQ_ENABLE, (uint32_t)~IRQ_SET_CLEAR_IDLE_IRQ_CLR_MASK);

    /* Clear all IRQs  */
    PN5180_WriteRegister(IRQ_SET_CLEAR, PHHAL_HW_PN5180_IRQ_SET_CLEAR_ALL_MASK);

    /* Apply HAL Digital delay when pn5180 FW version is less than 3.8. */
    if(FwVersion >= 0X308)
    {
        PN5180_ReadE2Prom(PHHAL_HW_PN5180_DIGITAL_DELAY_CONFIG_ADDR, &DigitalDelayCfg, PHHAL_HW_PN5180_DIGITAL_DELAY_CONFIG_LEN);

        /* Apply FW Digital delay and enable timer 1 for the use of FDT/FWT for FW version 3.8 onwards. */
        if (((0U == ((DigitalDelayCfg & PHHAL_HW_PN5180_DIGITAL_DELAY_ENABLE)))) ||
                (!((DigitalDelayCfg & PHHAL_HW_PN5180_FDT_TIMER_USED_MASK) == ((PHHAL_HW_PN5180_FDT_TIMER_USED) << 1U))))
        {
            /* Clear timer bits. */
            DigitalDelayCfg &= (uint8_t)~(PHHAL_HW_PN5180_FDT_TIMER_USED_MASK);

            /* Enable FW digital delay and timer 1 for FDT/FWT. */
            DigitalDelayCfg |= (uint8_t)(PHHAL_HW_PN5180_DIGITAL_DELAY_ENABLE | ((PHHAL_HW_PN5180_FDT_TIMER_USED) << 1U));

            /* Write back MISC_CONFIG value */
            PN5180_WriteE2Prom(PHHAL_HW_PN5180_DIGITAL_DELAY_CONFIG_ADDR, &DigitalDelayCfg, PHHAL_HW_PN5180_DIGITAL_DELAY_CONFIG_LEN);
        }
    }

    return 0;
}


void PN5180_FieleOff(void)
{
    uint8_t frame[2] = {PHHAL_HW_PN5180_GET_INSTR_FIELD_OFF, 0};

    PN5180_WriteBytes(frame, sizeof(frame));
}

void PN5180_FieleOn(void)
{
    uint8_t frame[2] = {PHHAL_HW_PN5180_GET_INSTR_FIELD_ON,0};

    PN5180_WriteBytes(frame, sizeof(frame));
}

uint8_t PN5180_GetFieleState(void)
{
    if((PN5180_ReadRegister(RF_STATUS) & RF_STATUS_TX_RF_STATUS_MASK ) == RF_STATUS_TX_RF_STATUS_MASK)
    {
        return 1;
    }
    return 0;
}

uint32_t PN5180_GetIRQStatus(void)
{
    return PN5180_ReadRegister(IRQ_STATUS);
}

uint32_t PN5180_GetRxStatus(void)
{
    return PN5180_ReadRegister(RX_STATUS);
}

uint32_t PN5180_GetRfStatus(void)
{
    return PN5180_ReadRegister(RF_STATUS);
}

int PN5180_ClearIRQStatus(uint32_t Mask)
{
    int ret = -1;
    PN5180_WriteRegister(IRQ_SET_CLEAR, Mask);
    if((PN5180_GetIRQStatus() & Mask) == 0)
    {
        ret = 0;
    }
    return ret;
}

/**
 * @return
 * TRANSCEIVE_STATEs:
 *  0 - idle
 *  1 - wait transmit
 *  2 - transmitting
 *  3 - wait receive
 *  4 - wait for data
 *  5 - receiving
 *  6 - loopback
 *  7 - reserved
 */
uint32_t PN5180_GetTransceiveState(void)
{
    return ((PN5180_GetRfStatus() >> 24) & 0X07);
}

void PN5180_LoadRFConfiguration(int protocol)
{
    uint8_t Command[3] = {PHHAL_HW_PN5180_SET_INSTR_LOAD_RF_CONFIGURATION, 0X00, 0X00};

    switch(protocol)
    {
    case HHAL_HW_PN5180_PROTOCOL_ISO14443:
        Command[1] = PHHAL_HW_PN5180_RF_TX_ISO14443A_106_MILLER;
        Command[2] = PHHAL_HW_PN5180_RF_RX_ISO14443A_106_MANCH_SUBC;
        break;
    case HHAL_HW_PN5180_PROTOCOL_ISO15693:
        Command[1] = PHHAL_HW_PN5180_RF_TX_ISO15693_26_1OF4_ASK100;
        Command[2] = PHHAL_HW_PN5180_RF_RX_ISO15693_26_1OF4_SC;
        break;
    case HHAL_HW_PN5180_PROTOCOL_ISO18000:
        break;
    default:
        break;
    }

    /* Send it to chip */
    PN5180_WriteBytes(Command, 3);
}
