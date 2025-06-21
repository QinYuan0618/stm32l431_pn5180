/* USER CODE BEGIN Header */
/**
  ******************************************************************************
  * @file    gpio.h
  * @brief   This file contains all the function prototypes for
  *          the gpio.c file
  ******************************************************************************
  * @attention
  *
  * Copyright (c) 2025 STMicroelectronics.
  * All rights reserved.
  *
  * This software is licensed under terms that can be found in the LICENSE file
  * in the root directory of this software component.
  * If no LICENSE file comes with this software, it is provided AS-IS.
  *
  ******************************************************************************
  */
/* USER CODE END Header */
/* Define to prevent recursive inclusion -------------------------------------*/
#ifndef __GPIO_H__
#define __GPIO_H__

#ifdef __cplusplus
extern "C" {
#endif

/* Includes ------------------------------------------------------------------*/
#include "main.h"

/* USER CODE BEGIN Includes */

/* USER CODE END Includes */

/* USER CODE BEGIN Private defines */

/* USER CODE END Private defines */

void MX_GPIO_Init(void);

/* USER CODE BEGIN Prototypes */
typedef enum
{
    OFF,
    ON,
} status_t;

enum
{
	LedBlue,
	LedGreen,
	LedRed,
	LedMax,
};

enum
{
	Relay,		/* 0 */
	RelayMax,	/* 1 */
};

/* 继电器 和 LED 都可用的结构体 */
typedef struct gpio_s
{
	const char      *name;	/* 用于通过 json格式数据来控制灯或继电器 */
	GPIO_TypeDef	*group;	/* 哪一组继电器 */
	uint16_t		 pin;	/* 哪一个管脚  */
	uint8_t			 status;
} gpio_t;

/* 声明 gpio.c 中的继电器和 leds 定义 */
extern gpio_t		leds[LedMax];
extern gpio_t		relays[RelayMax];

/* 初始化继电器 GPIO 管脚 */
extern int init_relay(void);

/* 控制继电器开或者关 ON/OFF */
extern void turn_relay(int which, status_t status);

/* 初始化灯LED GPIO 管脚 */
extern int init_led(void);

/* 控制 LED 灯开或者关 ON/OFF */
extern void turn_led(int which, status_t status);

/* 切换 LED 灯为另一状态 */
extern void toggle_led(int which);

/* 让某一个 LED 闪烁 */
extern void blink_led(int which, int interval);

/* 获取继电器当前的状态ON/OFF */
extern int status_led(int which);
/* USER CODE END Prototypes */

#ifdef __cplusplus
}
#endif
#endif /*__ GPIO_H__ */

