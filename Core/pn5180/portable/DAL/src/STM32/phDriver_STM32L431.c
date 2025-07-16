/*----------------------------------------------------------------------------*/
/* Copyright 2017-2022 NXP                                                    */
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
* Generic phDriver Component of Reader Library Framework for STM32L431.
*
* \brief 这个文件是驱动程序抽象层（DAL），此组件实现RdLib软件模块所需的硬件驱动程序
* 		 实现的核心功能：GPIO操作函数、定时器/延时函数、中断相关函数
* $Author$ 		qinyuan
* $Revision$	1.2
* $Date$		2025/06/26
*
*/

#include "phDriver.h"
#include "main.h"
#include "tim.h"
#include "spi.h"
#include <stdio.h>
#include "stm32l4xx.h"
#include "gpio.h"  // PinConfig IRQ

#define false	(0UL)
#define true	(1UL)

/* NXP PN5180 库文件 - 相对于当前文件的路径 */
#include "../../inc/phDriver.h"
#include "../../inc/phDriver_Gpio.h"
#include "../../inc/phDriver_Timer.h"
#include "../../inc/phbalReg.h"

/* 板级配置文件 */
#include "../../boards/Board_Stm32l431_Pn5180.h"

/* *****************************************************************************************************************
 * 私有变量和宏定义
 * ***************************************************************************************************************** */
#define STM32_TIMER_MAX_32BIT            0xFFFFFFFFU

static pphDriver_TimerCallBck_t pTimerIsrCallBack;
static volatile uint32_t dwTimerExp;

/* 私有函数声明 */
//static void phDriver_TimerIsrCallBack(void);
// 重写中断回调函数
void HAL_TIM_PeriodElapsedCallback(TIM_HandleTypeDef *htim); // 还没实现定义

// 全局变量，用于跟踪IRQ状态
static volatile uint8_t g_irq_pending = 0;
/********************************************************************************
 * PORT/GPIO PIN API's
 *******************************************************************************/

/* GPIO FUNC_1:配置GPIO引脚的功能和属性 */
phStatus_t phDriver_PinConfig(GPIO_TypeDef* GPIOx, uint16_t GPIO_Pin, phDriver_Pin_Func_t ePinFunc, phDriver_Pin_Config_t *pPinConfig)
{
	uint32_t mode;

	// 空指针保护
	if (pPinConfig == NULL)
	    return PH_DRIVER_ERROR;

	if(GPIO_Pin == PN5180_IRQ_Pin)
	{
		GPIO_InitTypeDef GPIO_InitStruct = {0};

		HAL_GPIO_DeInit(PN5180_IRQ_GPIO_Port, PN5180_IRQ_Pin);

		mode = (pPinConfig->bPullSelect == PH_DRIVER_PULL_DOWN)?GPIO_PULLDOWN:GPIO_PULLUP;
		GPIO_InitStruct.Pull = mode;

		switch(pPinConfig->eInterruptConfig)
		{
			case PH_DRIVER_INTERRUPT_RISINGEDGE:
				GPIO_InitStruct.Mode = GPIO_MODE_IT_RISING;
				break;

			case PH_DRIVER_INTERRUPT_FALLINGEDGE:
				GPIO_InitStruct.Mode = GPIO_MODE_IT_FALLING;
				break;

			case PH_DRIVER_INTERRUPT_EITHEREDGE:
			    GPIO_InitStruct.Mode = GPIO_MODE_IT_RISING_FALLING;
			    break;

			default:
				/* Do Nothing. */
				break;
	    }
		GPIO_InitStruct.Pin = PN5180_IRQ_Pin;
		HAL_GPIO_Init(PN5180_IRQ_GPIO_Port, &GPIO_InitStruct);
	}

    /* 其他GPIO已经在GPIO_INIT实现 */
    return PH_DRIVER_SUCCESS;
}

/* GPIO FUNC_2：读GPIO引脚状态是高or低电平 */
uint8_t phDriver_PinRead(GPIO_TypeDef* GPIOx, uint16_t GPIO_Pin, phDriver_Pin_Func_t ePinFunc)
{
    return HAL_GPIO_ReadPin(GPIOx, GPIO_Pin);
}

/* GPIO FUNC_3：IRQ引脚轮询等待 */
phStatus_t phDriver_IRQPinPoll(GPIO_TypeDef* GPIOx, uint16_t GPIO_Pin, phDriver_Pin_Func_t ePinFunc, phDriver_Interrupt_Config_t eInterruptType)
{
//    uint8_t    bGpioState = 0;

//    // 检查中断是上升沿还是下降沿
//    if ((eInterruptType != PH_DRIVER_INTERRUPT_RISINGEDGE) && (eInterruptType != PH_DRIVER_INTERRUPT_FALLINGEDGE))
//    {
//        return PH_DRIVER_ERROR | PH_COMP_DRIVER;
//    }
//
//    // 如果中断是下降沿，就设置初试flag为1，等待产生中断变成0
//    if (eInterruptType == PH_DRIVER_INTERRUPT_FALLINGEDGE)
//    {
//        bGpioState = 1;
//    }
//
//    /* 等待引脚状态变化 */
//	while(phDriver_PinRead(GPIOx, GPIO_Pin, ePinFunc) == bGpioState)
//	{
//		/* 轮训等待 */
//	}

    return PH_DRIVER_SUCCESS;
}

/* GPIO FUNC_4：写GPIO引脚 */
void phDriver_PinWrite(GPIO_TypeDef* GPIOx, uint16_t GPIO_Pin, uint8_t bValue)
{
    HAL_GPIO_WritePin(GPIOx, GPIO_Pin, bValue);
}

/* GPIO FUNC_5：清除某个引脚的软件中断模式 */
void phDriver_PinClearIntStatus(GPIO_TypeDef* GPIOx, uint16_t GPIO_Pin)
{
//    uint32_t exti_line = GPIO_Pin;
//    __HAL_GPIO_EXTI_CLEAR_FLAG(exti_line);
}

/* *****************************************************************************************************************
 * Timer定时 API's
 * ***************************************************************************************************************** */

/**
 * GPIO FUNC_1：启动定时器 - 到期后选择执行回调或仅延时
 * 基于枚举定义：
 * PH_DRIVER_TIMER_SECS = 1 (每秒1个单位)
 * PH_DRIVER_TIMER_MILLI_SECS = 1000 (每秒1000个单位)
 * PH_DRIVER_TIMER_MICRO_SECS = 1000000 (每秒1000000个单位)
 */
phStatus_t phDriver_TimerStart(phDriver_Timer_Unit_t eTimerUnit, uint32_t dwTimePeriod, pphDriver_TimerCallBck_t pTimerCallBack)
{
	if(pTimerCallBack == NULL)
	{
		/* 时间单位都转成微秒 */
	    if(eTimerUnit == PH_DRIVER_TIMER_SECS)
	    {
	    	HAL_Delay(dwTimePeriod * 1000); // s -> ms
	    }
	    else if(eTimerUnit == PH_DRIVER_TIMER_MILLI_SECS)
	    {
	    	HAL_Delay(dwTimePeriod);
	    }
	    else if(eTimerUnit == PH_DRIVER_TIMER_MICRO_SECS)
	    {
	    	delay_us(dwTimePeriod);
	    }
	}
    else	/* Call the Timer callback. */
    {
        pTimerIsrCallBack = pTimerCallBack;

        __HAL_TIM_SET_AUTORELOAD(&htim2, dwTimePeriod-1);   // 替代TIMER_Open的周期设置
        __HAL_TIM_SET_COUNTER(&htim2, 0);				    // 重置计数器
        __HAL_TIM_CLEAR_IT(&htim2, TIM_IT_UPDATE);	 		// 清除中断标志

        // 一次性启动定时器并使能中断
        HAL_TIM_Base_Start_IT(&htim2);
    }

    return PH_DRIVER_SUCCESS;
}


phStatus_t phDriver_TimerStop(void)
{
#if 0
	/* 停止定时器 - 对应 Chip_TIMER_Disable */
    HAL_TIM_Base_Stop_IT(&PHDRIVER_TIMER_HANDLE);

    /* 反初始化定时器 - 对应 Chip_TIMER_DeInit */
    HAL_TIM_Base_DeInit(&PHDRIVER_TIMER_HANDLE);

    /* 禁用定时器中断 - 对应 NVIC_DisableIRQ */
    HAL_NVIC_DisableIRQ(PHDRIVER_TIMER_IRQ);

    /* 清除回调函数和标志 */
    pTimerIsrCallBack = NULL;
    dwTimerExp = 0;
#endif
    return PH_DRIVER_SUCCESS;
}



/* *****************************************************************************************************************
 * 中断处理函数
 * ***************************************************************************************************************** */
/**
 * TIM2中断处理函数 - 需要在stm32l4xx_it.c中调用
 * 或者替换现有的TIM2_DAC_IRQHandler
 *
 * 这个函数完全模拟原始LPC实现的行为：
 * 1. 清除中断标志
 * 2. 调用回调函数
 * 3. 停止并反初始化定时器
 * 4. 禁用定时器中断
 */
void PHDRIVER_TIMER_IRQ_HANDLER(void)
{
#if 0
    /* 清除定时器中断标志 - 对应 Chip_TIMER_ClearMatch */
    __HAL_TIM_CLEAR_IT(&PHDRIVER_TIMER_HANDLE, TIM_IT_UPDATE);

    /* 调用回调函数 */
    if (pTimerIsrCallBack != NULL) {
        pTimerIsrCallBack();
    }

    /* 停止定时器 - 对应 Chip_TIMER_Disable */
    HAL_TIM_Base_Stop_IT(&PHDRIVER_TIMER_HANDLE);

    /* 反初始化定时器 - 对应 Chip_TIMER_DeInit */
    HAL_TIM_Base_DeInit(&PHDRIVER_TIMER_HANDLE);

    /* 禁用定时器中断 - 对应 NVIC_DisableIRQ */
    HAL_NVIC_DisableIRQ(PHDRIVER_TIMER_IRQ);
#endif
}

#if 0		// ---NXP官方源码
void PH_DRIVER_LPC_TIMER_IRQ_HANDLER(void)
{
    Chip_TIMER_ClearMatch(PH_DRIVER_LPC_TIMER, PH_DRIVER_LPC_TIMER_MATCH_REGISTER);

    pTimerIsrCallBack();

    Chip_TIMER_Disable(PH_DRIVER_LPC_TIMER);
    Chip_TIMER_DeInit(PH_DRIVER_LPC_TIMER);

    /* Disable timer interrupt */
    NVIC_DisableIRQ(PH_DRIVER_LPC_TIMER_IRQ);
}
#endif		// ---NXP官方源码


/**
 * 默认定时器回调函数, 用于阻塞模式
 */
static void phDriver_TimerIsrCallBack(void)
{
    dwTimerExp = 1;
}

#if 0
/**
 * HAL库定时器回调函数 - 由HAL库自动调用
 */
void HAL_TIM_PeriodElapsedCallback(TIM_HandleTypeDef *htim)
{
    if (htim->Instance == PHDRIVER_TIMER_INSTANCE)
    {
        /* 调用我们的中断处理函数 */
        PHDRIVER_TIMER_IRQ_HANDLER();
    }
}
#endif
/* *****************************************************************************************************************
 * 系统功能函数
 * ***************************************************************************************************************** */

/**
 * 进入临界区
 */
void phDriver_EnterCriticalSection(void)
{
    __disable_irq();
}

/**
 * 退出临界区
 */
void phDriver_ExitCriticalSection(void)
{
    __enable_irq();
}

///**
// * GPIO EXTI中断处理函数 - 需要在stm32l4xx_it.c中调用
// * 这个函数应该被EXTI4_IRQHandler调用
// */
//void phDriver_IRQ_Handler()
//{
//    /* 清除中断标志 */
//    phDriver_PinClearIntStatus(PHDRIVER_PIN_IRQ);
//
//    /* 这里可以添加应用层的IRQ处理逻辑 */
//    /* 例如设置标志位、调用回调函数等 */
//    /* 设置IRQ处理标志 - 通知主循环有中断待处理 */
//    pn5180_irq_flag = 1;
//}


