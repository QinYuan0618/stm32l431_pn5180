################################################################################
# Automatically-generated file. Do not edit!
# Toolchain: GNU Tools for STM32 (13.3.rel1)
################################################################################

# Add inputs and outputs from these tool invocations to the build variables 
C_SRCS += \
../Core/Src/gpio.c \
../Core/Src/main.c \
../Core/Src/spi.c \
../Core/Src/spi_test.c \
../Core/Src/stm32l4xx_hal_msp.c \
../Core/Src/stm32l4xx_it.c \
../Core/Src/syscalls.c \
../Core/Src/sysmem.c \
../Core/Src/system_stm32l4xx.c \
../Core/Src/tim.c \
../Core/Src/usart.c 

OBJS += \
./Core/Src/gpio.o \
./Core/Src/main.o \
./Core/Src/spi.o \
./Core/Src/spi_test.o \
./Core/Src/stm32l4xx_hal_msp.o \
./Core/Src/stm32l4xx_it.o \
./Core/Src/syscalls.o \
./Core/Src/sysmem.o \
./Core/Src/system_stm32l4xx.o \
./Core/Src/tim.o \
./Core/Src/usart.o 

C_DEPS += \
./Core/Src/gpio.d \
./Core/Src/main.d \
./Core/Src/spi.d \
./Core/Src/spi_test.d \
./Core/Src/stm32l4xx_hal_msp.d \
./Core/Src/stm32l4xx_it.d \
./Core/Src/syscalls.d \
./Core/Src/sysmem.d \
./Core/Src/system_stm32l4xx.d \
./Core/Src/tim.d \
./Core/Src/usart.d 


# Each subdirectory must supply rules for building sources it contributes
Core/Src/%.o Core/Src/%.su Core/Src/%.cyclo: ../Core/Src/%.c Core/Src/subdir.mk
	arm-none-eabi-gcc "$<" -mcpu=cortex-m4 -std=gnu11 -g3 -DDEBUG -DNFCRDLIBEX1_DISCOVERYLOOP_H -DNFCRDLIBEX1_DISCOVERYLOOP_H -DPHDRIVER_STM32L431_BOARD -DNXPBUILD__PHHAL_HW_PN5180 -DPH_OSAL_NULLOS -DARM_MATH_CM4 -DPHBAL_REG_STM32_SPI_ID=0x09 -DNXPBUILD__PHBAL_REG_STM32_SPI=1 -DNXPBUILD__PHDRIVER_STM32=1 -DUSE_HAL_DRIVER -DSTM32L431xx -c -I"E:/STM32CubeIDE/workspace_1.17.0/ISKBoard_20250602/Core/pn5180/demo/NfcrdlibEx1_DiscoveryLoop/intfs" -I"E:/STM32CubeIDE/workspace_1.17.0/ISKBoard_20250602/Core/pn5180/library/comps/phalICode/src" -I"E:/STM32CubeIDE/workspace_1.17.0/ISKBoard_20250602/Core/pn5180/library/comps/phhalHw/src/Pn5180" -I../Core/Inc -I"E:/STM32CubeIDE/workspace_1.17.0/ISKBoard_20250602/Core/pn5180/library/types" -I"E:/STM32CubeIDE/workspace_1.17.0/ISKBoard_20250602/Core/pn5180/library/comps/phacDiscLoop/src" -I"E:/STM32CubeIDE/workspace_1.17.0/ISKBoard_20250602/Core/pn5180/library/comps/phhalHw/src" -I"E:/STM32CubeIDE/workspace_1.17.0/ISKBoard_20250602/Core/pn5180/library/intfs" -I"E:/STM32CubeIDE/workspace_1.17.0/ISKBoard_20250602/Core/pn5180/portable/DAL/inc" -I"E:/STM32CubeIDE/workspace_1.17.0/ISKBoard_20250602/Core/pn5180/portable/DAL/boards" -I"E:/STM32CubeIDE/workspace_1.17.0/ISKBoard_20250602/Core/pn5180/portable/DAL/cfg" -I"E:/STM32CubeIDE/workspace_1.17.0/ISKBoard_20250602/Core/pn5180/portable/DAL/src/STM32" -I"E:/STM32CubeIDE/workspace_1.17.0/ISKBoard_20250602/Core/Inc" -I"E:/STM32CubeIDE/workspace_1.17.0/ISKBoard_20250602/Drivers/STM32L4xx_HAL_Driver/Inc" -I../Drivers/STM32L4xx_HAL_Driver/Inc/Legacy -I../Drivers/CMSIS/Device/ST/STM32L4xx/Include -I../Drivers/CMSIS/Include -I../Core/pn5180/portable/phOsal/inc -I../Drivers/STM32L4xx_HAL_Driver/Inc -O0 -ffunction-sections -fdata-sections -Wall -fstack-usage -fcyclomatic-complexity -MMD -MP -MF"$(@:%.o=%.d)" -MT"$@" --specs=nano.specs -mfpu=fpv4-sp-d16 -mfloat-abi=hard -mthumb -o "$@"

clean: clean-Core-2f-Src

clean-Core-2f-Src:
	-$(RM) ./Core/Src/gpio.cyclo ./Core/Src/gpio.d ./Core/Src/gpio.o ./Core/Src/gpio.su ./Core/Src/main.cyclo ./Core/Src/main.d ./Core/Src/main.o ./Core/Src/main.su ./Core/Src/spi.cyclo ./Core/Src/spi.d ./Core/Src/spi.o ./Core/Src/spi.su ./Core/Src/spi_test.cyclo ./Core/Src/spi_test.d ./Core/Src/spi_test.o ./Core/Src/spi_test.su ./Core/Src/stm32l4xx_hal_msp.cyclo ./Core/Src/stm32l4xx_hal_msp.d ./Core/Src/stm32l4xx_hal_msp.o ./Core/Src/stm32l4xx_hal_msp.su ./Core/Src/stm32l4xx_it.cyclo ./Core/Src/stm32l4xx_it.d ./Core/Src/stm32l4xx_it.o ./Core/Src/stm32l4xx_it.su ./Core/Src/syscalls.cyclo ./Core/Src/syscalls.d ./Core/Src/syscalls.o ./Core/Src/syscalls.su ./Core/Src/sysmem.cyclo ./Core/Src/sysmem.d ./Core/Src/sysmem.o ./Core/Src/sysmem.su ./Core/Src/system_stm32l4xx.cyclo ./Core/Src/system_stm32l4xx.d ./Core/Src/system_stm32l4xx.o ./Core/Src/system_stm32l4xx.su ./Core/Src/tim.cyclo ./Core/Src/tim.d ./Core/Src/tim.o ./Core/Src/tim.su ./Core/Src/usart.cyclo ./Core/Src/usart.d ./Core/Src/usart.o ./Core/Src/usart.su

.PHONY: clean-Core-2f-Src

