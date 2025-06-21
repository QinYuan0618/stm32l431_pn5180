/* USER CODE BEGIN Header */
/**
  ******************************************************************************
  * @file    gpio.c
  * @brief   This file provides code for the configuration
  *          of all used GPIO pins.
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

/* Includes ------------------------------------------------------------------*/
#include "gpio.h"

/* USER CODE BEGIN 0 */

/* USER CODE END 0 */

/*----------------------------------------------------------------------------*/
/* Configure GPIO                                                             */
/*----------------------------------------------------------------------------*/
/* USER CODE BEGIN 1 */

/* USER CODE END 1 */

/** Configure pins as
        * Analog
        * Input
        * Output
        * EVENT_OUT
        * EXTI
*/
void MX_GPIO_Init(void)
{

  GPIO_InitTypeDef GPIO_InitStruct = {0};

  /* GPIO Ports Clock Enable */
  __HAL_RCC_GPIOH_CLK_ENABLE();
  __HAL_RCC_GPIOC_CLK_ENABLE();
  __HAL_RCC_GPIOA_CLK_ENABLE();
  __HAL_RCC_GPIOB_CLK_ENABLE();

  /*Configure GPIO pin Output Level */
  HAL_GPIO_WritePin(PN5180_DWL_GPIO_Port, PN5180_DWL_Pin, GPIO_PIN_RESET);

  /*Configure GPIO pin Output Level */
  HAL_GPIO_WritePin(PN5180_NSS_GPIO_Port, PN5180_NSS_Pin, GPIO_PIN_SET);

  /*Configure GPIO pin Output Level */
  HAL_GPIO_WritePin(PN5180_RST_GPIO_Port, PN5180_RST_Pin, GPIO_PIN_RESET);

  /*Configure GPIO pin : PN5180_DWL_Pin */
  GPIO_InitStruct.Pin = PN5180_DWL_Pin;
  GPIO_InitStruct.Mode = GPIO_MODE_OUTPUT_PP;
  GPIO_InitStruct.Pull = GPIO_NOPULL;
  GPIO_InitStruct.Speed = GPIO_SPEED_FREQ_LOW;
  HAL_GPIO_Init(PN5180_DWL_GPIO_Port, &GPIO_InitStruct);

  /*Configure GPIO pin : PN5180_BUSY_Pin */
  GPIO_InitStruct.Pin = PN5180_BUSY_Pin;
  GPIO_InitStruct.Mode = GPIO_MODE_INPUT;
  GPIO_InitStruct.Pull = GPIO_NOPULL;
  HAL_GPIO_Init(PN5180_BUSY_GPIO_Port, &GPIO_InitStruct);

  /*Configure GPIO pin : PN5180_NSS_Pin */
  GPIO_InitStruct.Pin = PN5180_NSS_Pin;
  GPIO_InitStruct.Mode = GPIO_MODE_OUTPUT_PP;
  GPIO_InitStruct.Pull = GPIO_NOPULL;
  GPIO_InitStruct.Speed = GPIO_SPEED_FREQ_HIGH;
  HAL_GPIO_Init(PN5180_NSS_GPIO_Port, &GPIO_InitStruct);

  /*Configure GPIO pin : PN5180_RST_Pin */
  GPIO_InitStruct.Pin = PN5180_RST_Pin;
  GPIO_InitStruct.Mode = GPIO_MODE_OUTPUT_PP;
  GPIO_InitStruct.Pull = GPIO_NOPULL;
  GPIO_InitStruct.Speed = GPIO_SPEED_FREQ_LOW;
  HAL_GPIO_Init(PN5180_RST_GPIO_Port, &GPIO_InitStruct);

}

/* USER CODE BEGIN 2 */
#if 0
///* 重写weak函数，通过这个按键来控制灯泡的亮灭 */
//void HAL_GPIO_EXIT_Callback(uint16_t GPIO_Pin)
//{
//	static uint8_t		relay_status = OFF;
//
//	if( Key1_Pin == GPIO_Pin )
//	{
//		relay_status ^= 1;		/* 如果是灭的就亮，亮的就灭 */
//		turn_relay(Relay, relay_status);
//	}
//}
#endif

/* USER CODE END 2 */
