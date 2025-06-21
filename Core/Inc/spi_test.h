/*
 * spi_test.h
 *
 *  Created on: Jun 14, 2025
 *      Author: Administrator
 */

#ifndef INC_SPI_TEST_H_
#define INC_SPI_TEST_H_

#include "phhalHw.h"
#include "phhalHw_Pn5180.h"
#include "phhalHw_Pn5180_Instr.h"
#include "phhalHw_pn5180_Reg.h"		// 寄存器地址宏定义
int test_pn5180_spi_communication(phhalHw_Pn5180_DataParams_t * pHal);

#endif /* INC_SPI_TEST_H_ */
