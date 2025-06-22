/* USER CODE BEGIN Header */
/**
  ******************************************************************************
  * @file           : main.h
  * @brief          : Header for main.c file.
  *                   This file contains the common defines of the application.
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
#ifndef __MAIN_H
#define __MAIN_H

#ifdef __cplusplus
extern "C" {
#endif

/* Includes ------------------------------------------------------------------*/
#include "stm32l4xx_hal.h"

/* Private includes ----------------------------------------------------------*/
/* USER CODE BEGIN Includes */

/* USER CODE END Includes */

/* Exported types ------------------------------------------------------------*/
/* USER CODE BEGIN ET */

/* USER CODE END ET */

/* Exported constants --------------------------------------------------------*/
/* USER CODE BEGIN EC */

/* USER CODE END EC */

/* Exported macro ------------------------------------------------------------*/
/* USER CODE BEGIN EM */

/* USER CODE END EM */

/* Exported functions prototypes ---------------------------------------------*/
void Error_Handler(void);

/* USER CODE BEGIN EFP */

/* USER CODE END EFP */

/* Private defines -----------------------------------------------------------*/
#define PN5180_BUSY_Pin GPIO_PIN_1
#define PN5180_BUSY_GPIO_Port GPIOA
#define Beep_Pin GPIO_PIN_11
#define Beep_GPIO_Port GPIOA
#define PN5180_NSS_Pin GPIO_PIN_15
#define PN5180_NSS_GPIO_Port GPIOA
#define PN5180_SCK_Pin GPIO_PIN_10
#define PN5180_SCK_GPIO_Port GPIOC
#define PN5180_MISO_Pin GPIO_PIN_11
#define PN5180_MISO_GPIO_Port GPIOC
#define PN5180_MOSI_Pin GPIO_PIN_12
#define PN5180_MOSI_GPIO_Port GPIOC
#define PN5180_RST_Pin GPIO_PIN_5
#define PN5180_RST_GPIO_Port GPIOB

/* USER CODE BEGIN Private defines */
/*
 * These inlines deal with timer warrping cooectly.You are strongly encouraged to use them
 * 1. Because people otherwise forget
 * 2. Beacuse if the timer warp changes in future you won't have to alter your diver code.
 *
 *
 * time_after(a, b) returns true if the time a is after time b.
 *
 * Do this with "<0" and ">=0" to only test the sign of the result. A good complier would generate
 * better code (and a really good complier wouldn't care).Gcc is currently neither.
 *
 */

#define time_after(a, b)		( (int32_t)(b) - (int32_t)(a) < 0 )
#define time_before(a, b)		time_after(b, a)

#define time_after_eq(a, b)		( (int32_t)(a) - (int32_t)(b) >= 0 )
#define time_before_eq(a, b)	time_after_eq(b, a)
/* USER CODE END Private defines */

#ifdef __cplusplus
}
#endif

#endif /* __MAIN_H */
