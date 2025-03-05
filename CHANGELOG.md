# 更新日志

## [1.0.0] - 2024-03-05

### 新增
- 自动检测和脱敏敏感信息功能
- 支持多种中间件配置脱敏
- 批量处理整个项目功能
- 智能识别配置占位符
- 排除常见开源地址功能

### 支持的敏感信息类型
- IP地址
- 数据库连接信息
- 密码和密钥
- API密钥
- 认证信息

### 支持的中间件
- MongoDB
- Redis
- RabbitMQ
- Kafka
- ElasticSearch
- RocketMQ

### 支持的文件类型
- .properties
- .yml / .yaml
- .xml
- .json
- .conf
- .cfg
- .env
- .ini 