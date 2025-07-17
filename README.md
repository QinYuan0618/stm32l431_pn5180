# STM32L431 + PN5180 EMV Card Reader Project
# STM32L431 + PN5180 EMV读卡器项目

## Project Overview | 项目概述

This project implements an EMV card reader system using STM32L431 development board interfaced with PN5180 NFC module via expansion header. The system provides complete EMV transaction simulation capabilities with debugging and audio feedback features.

本项目基于STM32L431开发板，通过牛角座外接PN5180 NFC模块，实现完整的EMV银行卡读取系统。系统具备EMV交易模拟、调试输出和音频反馈等功能。

## Key Features | 主要功能

### Core Functionality | 核心功能
- **UART Debug Output** | **串口调试打印**
  - Real-time system status monitoring
  - Transaction process logging
  - 实时系统状态监控
  - 交易过程日志记录

- **EMV Card Transaction Simulation** | **EMV卡交易模拟**
  - Complete EMV payment flow implementation
  - APDU command processing
  - Card ID and application information reading
  - 完整EMV支付流程实现
  - APDU命令处理
  - 卡片ID和应用信息读取

- **Audio Feedback** | **蜂鸣器反馈**

## Hardware Requirements | 硬件要求

### Main Components | 主要组件
- **STM32L431** development board | **STM32L431**开发板
- **PN5180** NFC module | **PN5180** NFC模块
- Expansion header connector | 牛角座连接器
- Buzzer module | 蜂鸣器模块
- EMV-compatible cards for testing | EMV兼容测试卡

### Connection Interface | 连接接口
- **SPI Communication**: STM32L431 ↔ PN5180
- **GPIO Control**: Interrupt and control signals
- **UART**: Debug output interface
- **SPI通信**: STM32L431 ↔ PN5180
- **GPIO控制**: 中断和控制信号
- **串口**: 调试输出接口

## Software Architecture | 软件架构

### NXP NFC Library Integration | NXP NFC库集成

This project successfully ports the official **NXP NFC Library** to STM32 platform. Key adaptation work includes:

本项目成功将NXP官方的**NFC Library**移植到STM32平台，主要适配工作包括：

#### Low-Level Adaptations | 底层适配
- **SPI Interface**: Converted original SPI functions to STM32 HAL library calls
- **GPIO Management**: Adapted GPIO control functions for STM32 pin configuration
- **Clock Configuration**: Modified system clock and peripheral clock settings
- **Interrupt Handling**: Implemented STM32-compatible interrupt service routines

- **SPI接口**: 将原始SPI函数转换为STM32 HAL库调用
- **GPIO管理**: 适配GPIO控制函数以支持STM32引脚配置
- **时钟配置**: 修改系统时钟和外设时钟设置
- **中断处理**: 实现STM32兼容的中断服务例程

#### High-Level Implementation | 上层实现
- **Discovery Loop Extension**: Enhanced example code for EMV transaction flow
- **APDU Processing**: Implemented comprehensive Application Protocol Data Unit handling
- **Card Information Extraction**: Added functions to read card ID and application details

- **Discovery Loop扩展**: 扩展Ex1示例代码以支持EMV交易流程
- **APDU处理**: 实现完整的应用协议数据单元处理
- **卡片信息提取**: 添加读取卡片ID和应用详情等功能

## Development Environment | 开发环境

### Required Tools | 必需工具
- **STM32CubeIDE**: Primary development platform
- **NXP NFC Library**: Core NFC functionality (download required)

- **STM32CubeIDE**: 主要开发平台
- **NXP NFC Library**: 核心NFC功能（需要下载）

### Prerequisites | 前置要求

**⚠️ Important**: Before using this project, ensure you have downloaded and studied the NXP NFC Library architecture. Understanding the library structure is essential for successful implementation.

**⚠️ 重要**: 在使用本项目前，请确保您已下载并学习了NXP NFC Library的架构。理解库的结构对成功实现项目至关重要。

<img width="905" height="489" alt="087c9bb5a1c32084553cc394381c30c" src="https://github.com/user-attachments/assets/0d760934-1fa5-4f34-9ee5-857893477369" />

## EMV Transaction Flow | EMV交易流程

The system implements a complete EMV payment simulation through the following process:

系统通过以下流程实现完整的EMV支付模拟：

![08b3558bcbc193f8ecd98e8bf77b2d9](https://github.com/user-attachments/assets/21d6a193-1b5e-4dc1-97b4-1be820e5cdbb)

## Linux Interface | Linux接口

The project maintains Linux-side code interfaces for potential cross-platform compatibility and future expansion.

项目保留了Linux侧代码接口，以支持潜在的跨平台兼容性和未来扩展。

## Getting Started | 快速开始

### Setup Steps | 设置步骤

1. **Hardware Assembly** | **硬件组装**
   - Connect PN5180 module to STM32L431 via expansion header
   - Ensure proper SPI and GPIO connections
   - 通过牛角座将PN5180模块连接到STM32L431
   - 确保SPI和GPIO连接正确

2. **Software Preparation** | **软件准备**
   - Download NXP NFC Library
   - Import project into STM32CubeIDE
   - Configure build settings
   - 下载NXP NFC Library
   - 将项目导入STM32CubeIDE
   - 配置编译设置

3. **Compilation and Deployment** | **编译和部署**
   - Build the project in STM32CubeIDE
   - Flash the firmware to STM32L431
   - Connect UART for debug output
   - 在STM32CubeIDE中编译项目
   - 将固件烧录到STM32L431
   - 连接串口进行调试输出

## Usage Notes | 使用说明

### Operation Guidelines | 操作指南
- Ensure EMV card is positioned correctly near PN5180 antenna
- Monitor UART output for transaction status
- Listen for buzzer feedback during operations
- 确保EMV卡正确放置在PN5180天线附近
- 通过串口输出监控交易状态
- 操作过程中注意蜂鸣器反馈

### Troubleshooting | 故障排除
- Verify SPI connections if card detection fails
- Check NFC Library integration if APDU errors occur
- Ensure proper power supply for stable operation
- 如果卡片检测失败，请验证SPI连接
- 如果出现APDU错误，请检查NFC Library集成
- 确保电源供应稳定以保证正常操作

## Technical Specifications | 技术规格

### Communication Protocols | 通信协议
- **NFC Standard**: ISO14443 Type A/B
- **EMV Compliance**: EMV Level 1 & Level 2
- **SPI Speed**: Up to 7 MHz
- **UART Baud Rate**: 115200 bps (configurable)

### Performance Characteristics | 性能特征
- **Card Detection Range**: Up to 5cm (depending on card type)
- **Transaction Speed**: Sub-second response time
- **Power Consumption**: Optimized for STM32L431 low-power features

## 串口调试打印：
<img width="801" height="824" alt="image" src="https://github.com/user-attachments/assets/7dc7b1c1-9a2c-4789-9c30-a8fe837411e6" />

## Contributing | 贡献

This project serves as a foundation for EMV card reader development on STM32 platform. Contributions for feature enhancement and optimization are welcome.

本项目为在STM32平台上开发EMV读卡器提供了基础框架。欢迎为功能增强和优化做出贡献。

