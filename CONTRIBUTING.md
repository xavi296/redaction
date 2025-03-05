# 贡献指南

感谢您考虑为 Sensitive Data Masker 项目做出贡献！

## 开发环境设置

1. Fork 本仓库
2. Clone 您的 Fork 到本地
```bash
git clone https://github.com/your-username/redaction.git
```
3. 配置开发环境：
   - IntelliJ IDEA 2023.3 或更高版本
   - JDK 17 或更高版本
   - Gradle 8.0 或更高版本

## 构建和测试

1. 构建项目：
```bash
./gradlew build
```

2. 运行测试：
```bash
./gradlew test
```

3. 运行插件：
```bash
./gradlew runIde
```

## 提交代码

1. 创建新分支：
```bash
git checkout -b feature/your-feature-name
```

2. 提交规范：
- feat: 新功能
- fix: 修复问题
- docs: 文档修改
- style: 代码格式修改
- refactor: 代码重构
- test: 测试用例修改
- chore: 其他修改

示例：
```bash
git commit -m "feat: 添加新的脱敏规则"
```

3. 确保代码符合以下要求：
- 通过所有测试
- 遵循代码风格规范
- 添加必要的注释
- 更新相关文档

4. 提交 Pull Request：
- 清晰描述您的修改
- 关联相关的 Issue
- 提供测试用例或截图

## 报告问题

1. 使用 Issue 模板
2. 提供详细的复现步骤
3. 附上错误日志和截图
4. 说明运行环境

## 开发指南

### 添加新的脱敏规则

1. 在 `SensitiveDataService` 类中添加新的正则表达式模式
2. 在 `RedactionSettings` 中添加对应的配置项
3. 更新设置界面
4. 添加测试用例

### 代码风格

- 使用 4 空格缩进
- 遵循 Java 命名规范
- 类和公共方法必须添加 JavaDoc 注释
- 保持代码简洁，避免重复

## 发布流程

1. 版本号规范：
   - 主版本号：不兼容的 API 修改
   - 次版本号：向下兼容的功能性新增
   - 修订号：向下兼容的问题修正

2. 更新内容：
   - 修改 `plugin.xml` 中的版本号
   - 更新 CHANGELOG.md
   - 更新 README.md

## 联系方式

如有任何问题，请通过以下方式联系：
- 提交 Issue
- 发送邮件至 spotlightxavi@163.com 