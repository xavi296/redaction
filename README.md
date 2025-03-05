# Sensitive Data Masker (敏感信息自动脱敏插件)

[![Version](https://img.shields.io/badge/version-1.0.0-blue.svg)](https://plugins.jetbrains.com/plugin/xxx-sensitive-data-masker)
[![License](https://img.shields.io/badge/license-Apache%202.0-green.svg)](LICENSE)

[English](README_EN.md) | 简体中文

## 简介

Sensitive Data Masker 是一个 IntelliJ IDEA 插件，用于自动检测和脱敏项目中的敏感信息。它可以识别各种配置文件中的敏感数据，并自动将其替换为安全的占位符。

## 功能特点

### 自动检测敏感信息
- IP地址
- 数据库连接信息
- 密码和密钥
- API密钥
- 认证信息

### 支持多种中间件配置脱敏
- MongoDB
- Redis
- RabbitMQ
- Kafka
- ElasticSearch
- RocketMQ

### 智能识别
- 自动排除配置占位符（如 ${...} 和 @...@）
- 排除常见开源网站地址
- 排除代码引用和包声明

### 批量处理
- 支持一键处理整个项目
- 支持单文件处理
- 智能识别配置文件

## 支持的文件类型
- .properties
- .yml / .yaml
- .xml
- .json
- .conf
- .cfg
- .env
- .ini

## 安装方法

### 从 IDE 安装
1. 打开 IntelliJ IDEA
2. 进入 Settings/Preferences → Plugins
3. 选择 Marketplace 标签页
4. 搜索 "Sensitive Data Masker"
5. 点击 Install 按钮
6. 重启 IDE 完成安装

### 手动安装
1. 下载插件 [releases](https://github.com/yourusername/redaction/releases) 页面的最新版本
2. 打开 IntelliJ IDEA
3. 进入 Settings/Preferences → Plugins
4. 点击齿轮图标，选择 "Install Plugin from Disk..."
5. 选择下载的插件文件
6. 重启 IDE 完成安装

## 使用方法

### 处理单个文件
1. 在编辑器中打开需要处理的配置文件
2. 右键点击，选择 "Mask Sensitive Data"
3. 或使用快捷键：
   - Windows/Linux: `Ctrl+Alt+M`
   - macOS: `Cmd+Alt+M`

### 处理整个项目
1. 在项目视图中右键点击项目
2. 选择 "Mask All Project Configuration Files"
3. 或使用快捷键：
   - Windows/Linux: `Ctrl+Alt+Shift+M`
   - macOS: `Cmd+Alt+Shift+M`

### 自定义设置
1. 进入 Settings/Preferences → Tools → Sensitive Data Masking Settings
2. 选择需要启用的脱敏规则：
   - IP地址脱敏
   - 数据库URL脱敏
   - 密码脱敏
   - API密钥脱敏

## 示例

### 配置文件脱敏前
```properties
spring.datasource.url=jdbc:mysql://192.168.1.100:3306/mydb
spring.datasource.username=admin
spring.datasource.password=secretpass123
api.key=abcdef123456
```

### 配置文件脱敏后
```properties
spring.datasource.url=jdbc:****://****
spring.datasource.username=****
spring.datasource.password="********"
api.key="********"
```

## 注意事项
1. 插件默认会排除以下目录：
   - /target/
   - /build/
   - /dist/
   - /node_modules/
   - /.git/
2. 不会处理以下文件：
   - pom.xml
   - Java源代码文件
   - 测试代码文件

## 贡献指南
欢迎提交 Pull Request 或创建 Issue。在提交代码前，请确保：
1. 代码符合项目的编码规范
2. 添加必要的测试用例
3. 更新相关文档

## 许可证
本项目采用 [Apache 2.0 许可证](LICENSE)。

## 联系方式
- 作者：xavi
- 邮箱：spotlightxavi@163.com
- GitHub：[项目地址](https://github.com/yourusername/redaction)

## 更新日志
### 1.0.0
- 支持自动检测和脱敏敏感信息
- 支持多种中间件配置脱敏
- 支持批量处理整个项目
- 智能识别配置占位符
- 排除常见开源地址
