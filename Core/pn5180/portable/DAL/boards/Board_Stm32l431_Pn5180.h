/*----------------------------------------------------------------------------*/
/* Copyright 2017-2021 NXP                                                    */
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
* $Author$		qinyuan
* $Revision$	1.1
* $Date$		2026/06/07
*
*/

#ifndef BOARD_STM32L431_PN5180_H
#define BOARD_STM32L431_PN5180_H

#include "stm32l4xx_hal.h"
#include "main.h"			// 包含cubeMX生成的引脚定义

/******************************************************************
 * Board Pin/Gpio configurations
 * 直接使用main.h中的宏定义
 ******************************************************************/
#if 0
#define PHDRIVER_PIN_RESET         ((PORT2<<8) | 5)    /**< Reset pin, Port 2, pin5. */
#define PHDRIVER_PIN_IRQ           ((PORT2<<8) | 12)   /**< Interrupt pin from Frontend to Host, Port2, pin12 */
#define PHDRIVER_PIN_BUSY          ((PORT2<<8) | 11)   /**< Frontend's Busy Status, Port2, pin11 */
#define PHDRIVER_PIN_DWL           ((PORT0<<8) | 21)   /**< Download mode pin of Frontend, Port0, pin21 */
#endif
/* PN5180 控制引脚 - 已在main.h中定义 */
#define PHDRIVER_PIN_RESET			PN5180_RST_GPIO_Port, PN5180_RST_Pin     /**< Reset pin, Port B, pin13. */
#define PHDRIVER_PIN_IRQ           	PN5180_IRQ_GPIO_Port, PN5180_IRQ_Pin     /**< Interrupt pin from Frontend to Host*/
#define PHDRIVER_PIN_BUSY          	PN5180_BUSY_GPIO_Port, PN5180_BUSY_Pin     /**< Frontend's Busy Status*/
//#define PHDRIVER_PIN_DWL          	PN5180_DWL_GPIO_Port, PN5180_DWL_Pin   /**< Download mode pin of Frontend*/
#define PHDRIVER_PIN_SSEL         	PN5180_NSS_GPIO_Port, PN5180_NSS_Pin

/* These pins are used for EMVCo Interoperability test status indication,
 * not for the generic Reader Library implementation.
 * 状态指示LED - 使用main.h中已定义的LED
 */
#if 0
#define PHDRIVER_PIN_OLED          ((PORT0<<8) | 22)   /**< ORANGE LED, Port0, pin22, Pin function 0 */
#define PHDRIVER_PIN_RLED          ((PORT2<<8) | 0)    /**< RED LED, Port2, pin0, Pin function 0 */
#define PHDRIVER_PIN_GLED          ((PORT3<<8) | 25)   /**< GREEN LED, Port3, pin25, Pin function 0 */
#define PHDRIVER_PIN_BLED          ((PORT3<<8) | 26)   /**< BLUE LED, Port3, pin26, Pin function 0 */
#define PHDRIVER_PIN_SUCCESS       ((PORT0<<8) | 2)    /**< GPIO, Port0, pin2, Pin function 0 */
#define PHDRIVER_PIN_FAIL          ((PORT0<<8) | 3)    /**< GPIO, Port0, pin3, Pin function 0 */
#endif
#if 0
#define PHDRIVER_PIN_LED_RED_PIN       LedRed_Pin
#define PHDRIVER_PIN_LED_RED_PORT      LedRed_GPIO_Port

#define PHDRIVER_PIN_LED_GREEN_PIN     LedGreen_Pin
#define PHDRIVER_PIN_LED_GREEN_PORT    LedGreen_GPIO_Port

#define PHDRIVER_PIN_LED_BLUE_PIN      LedBlue_Pin
#define PHDRIVER_PIN_LED_BLUE_PORT     LedBlue_GPIO_Port

#define PHDRIVER_PIN_LED_SYS_PIN       LedSys_Pin
#define PHDRIVER_PIN_LED_SYS_PORT      LedSys_GPIO_Port
#endif

/* GPIO and LED for applications use */
#if 0
#define PHDRIVER_PIN_GPIO          ((PORT0<<8) | 2)    /**< Port0, pin2 */
#define PHDRIVER_PIN_LED           PHDRIVER_PIN_RLED   /**< RED LED */
#endif



/******************************************************************
 * PIN Pull-Up/Pull-Down configurations.
 ******************************************************************/
#define PHDRIVER_PIN_RESET_PULL_CFG    PH_DRIVER_PULL_UP
#define PHDRIVER_PIN_IRQ_PULL_CFG      PH_DRIVER_PULL_UP
#define PHDRIVER_PIN_BUSY_PULL_CFG     PH_DRIVER_PULL_UP
#define PHDRIVER_PIN_DWL_PULL_CFG      PH_DRIVER_PULL_UP
#define PHDRIVER_PIN_NSS_PULL_CFG      PH_DRIVER_PULL_UP


/******************************************************************
 * IRQ PIN NVIC settings for STM32L431
 * 需要在CubeMX中将IRQ配置为GPIO_EXTIn并启用中断，配置成下面这样，我们并没有调用这个来配置，而是用32自带可视化配置的
 ******************************************************************/
#define PIN_IRQ_TRIGGER_TYPE    PH_DRIVER_INTERRUPT_FALLINGEDGE  /**< IRQ pin falling edge interrupt */
#define EINT_PRIORITY           2                /**< Interrupt priority. */
#define EINT_IRQn               PN5180_IRQ_EXTI_IRQn       /**< NVIC IRQ */

/*****************************************************************
 * Front End Reset logic level settings
 ****************************************************************/
#if 0
#define PH_DRIVER_SET_HIGH            1          /**< Logic High. */
#define PH_DRIVER_SET_LOW             0          /**< Logic Low. */
#endif
#define PH_DRIVER_SET_HIGH          GPIO_PIN_SET      /**< Logic High. */
#define PH_DRIVER_SET_LOW           GPIO_PIN_RESET    /**< Logic Low. */
#define RESET_POWERDOWN_LEVEL 		PH_DRIVER_SET_LOW
#define RESET_POWERUP_LEVEL   		PH_DRIVER_SET_HIGH

/*****************************************************************
 * SPI Configuration for STM32L431
 ****************************************************************/
#if 0
#define LPC_SSP             LPC_SSP0   /**< SPI Module */
#define SSP_CLOCKRATE       4000000    /**< SPI clock rate. Allowed clock rate: 6 or 4 or 3 or 2.4MHz etc. */
#endif
#define PHDRIVER_SPI_INSTANCE         SPI3              /**< SPI Instance */
#define PHDRIVER_SPI_HANDLE           hspi3             /**< SPI Handle */
#define PHDRIVER_SPI_CLOCKRATE        5000000           /**< SPI clock rate 5MHz */

 /******************************************************************/
/* Pin configuration format : Its a 32 bit format where 1st 3 bytes represents each field as shown below.
 * | Byte3 | Byte2 | Byte1 | Byte0 |
 * | ---   | FUNC  | PORT  | PIN   |
 * */
#if 0
#define PHDRIVER_PIN_MOSI     ((IOCON_FUNC2<<16) | (PORT0<<8) | 18)  /**< MOSI pin, Port0, pin18, Pin function 2 */
#define PHDRIVER_PIN_MISO     ((IOCON_FUNC2<<16) | (PORT0<<8) | 17)  /**< MISO pin, Port0, pin17, Pin function 2 */
#define PHDRIVER_PIN_SCK      ((IOCON_FUNC2<<16) | (PORT0<<8) | 15)  /**< Clock pin, Port0, pin15, Pin function 2 */
#define PHDRIVER_PIN_SSEL     ((IOCON_FUNC0<<16) | (PORT0<<8) | 16)  /**< Slave select, Port0, pin16, Pin function 0 */
#endif

/*****************************************************************
 * Timer Configuration for STM32L431
 * 使用TIM6实现微秒级延时功能，与PN5180驱动兼容
 ****************************************************************/
#if 0
#define PH_DRIVER_LPC_TIMER                    LPC_TIMER0           /**< Use LPC timer0 */
#define PH_DRIVER_LPC_TIMER_CLK                SYSCTL_CLOCK_TIMER0  /**< Timer 0 clock source */
#define PH_DRIVER_LPC_TIMER_MATCH_REGISTER     0x01  /* use match register 1 always. */
#define PH_DRIVER_LPC_TIMER_IRQ                TIMER0_IRQn          /**< NVIC Timer0 Irq */
#define PH_DRIVER_LPC_TIMER_IRQ_HANDLER        TIMER0_IRQHandler    /**< Timer0 Irq Handler */
#define PH_DRIVER_LPC_TIMER_IRQ_PRIORITY       5                    /**< NVIC Timer0 Irq priority */
#endif
#define PHDRIVER_TIMER_INSTANCE       TIM6              /**< Timer Instance */
#define PHDRIVER_TIMER_HANDLE         htim6             /**< Timer Handle */
#define PHDRIVER_TIMER_IRQ            TIM6_DAC_IRQn     /**< Timer IRQ (如果需要中断模式) */
#define PHDRIVER_TIMER_IRQ_HANDLER    TIM6_DAC_IRQHandler   /**< Timer IRQ Handler */
#define PHDRIVER_TIMER_IRQ_PRIORITY   5                 /**< Timer IRQ priority */

/* TIM6配置信息 - 用于微秒级延时 */
#define PHDRIVER_TIMER_FREQ_MHZ       1                 /**< 1MHz计数频率 (80MHz/80预分频) */
#define PHDRIVER_TIMER_MAX_US         60000             /**< 最大延时60ms (60000us) */

/* 延时函数声明 - 在tim.c中实现 */
extern void delay_us(uint16_t us);

/*****************************************************************
 * 系统配置
 ****************************************************************/
#define PHDRIVER_SYSTEM_FREQ          80000000    		/**< 系统时钟频率 80MHz */

/* 外部变量声明 - 需要在main.c中定义或者通过CubeMX生成 */
extern SPI_HandleTypeDef hspi3;
extern TIM_HandleTypeDef htim6;

/* 保持原有的clock rate定义 */
#define SSP_CLOCKRATE              PHDRIVER_SPI_CLOCKRATE

#endif /* BOARD_LPC1769PN5180_H */
