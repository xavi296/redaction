package com.redaction.service;

import com.intellij.openapi.components.Service;
import com.intellij.openapi.project.Project;
import com.intellij.openapi.vfs.VirtualFile;
import com.intellij.openapi.vfs.VirtualFileManager;
import com.intellij.openapi.vfs.VfsUtil;
import com.intellij.openapi.command.WriteCommandAction;
import com.intellij.openapi.application.ApplicationManager;
import com.intellij.openapi.editor.Document;
import com.intellij.openapi.fileEditor.FileDocumentManager;
import org.jetbrains.annotations.NotNull;

import java.util.*;
import java.util.regex.Pattern;

/**
 * 敏感数据处理服务类
 * 
 * 该服务负责检测和脱敏项目中的敏感信息，包括但不限于：
 * - IP地址
 * - 数据库连接信息
 * - 各类中间件配置信息
 * - 密码和密钥
 * - API密钥
 * - 认证信息
 * 
 * 主要功能：
 * - 识别需要处理的配置文件
 * - 使用正则表达式匹配敏感信息
 * - 将敏感信息替换为安全的占位符
 * - 批量处理项目中的所有配置文件
 *
 * @version 1.0.0
 */
@Service
public final class SensitiveDataService {
    /**
     * 敏感数据匹配模式映射
     * 包含各类敏感信息的正则表达式模式
     */
    private static final Map<String, Pattern> SENSITIVE_PATTERNS = new HashMap<>();
    
    static {
        // IP地址匹配模式（排除配置占位符）
        SENSITIVE_PATTERNS.put("IP_ADDRESS", 
            Pattern.compile("\\b(?!\\$\\{)(?!\\b(?:import|package)\\b.*\\b)(?:\\d{1,3}\\.){3}\\d{1,3}\\b(?!\\})"));
        
        // 数据库URL匹配模式（排除配置占位符和Maven仓库）
        SENSITIVE_PATTERNS.put("DB_URL", 
            Pattern.compile("jdbc:(?!\\$\\{)(?!\\b(?:import|package)\\b.*\\b)[a-z]+://(?!maven\\.)[^\\s/\\$\\{\\}]+"));
            
        // MongoDB连接串匹配模式
        SENSITIVE_PATTERNS.put("MONGODB_URL",
            Pattern.compile("(?i)(?<!\\$\\{)(?<!\\b(?:import|package)\\b.*)(mongodb://|mongo\\.(?:url|host|address)\\s*=\\s*)[^\\s,}\\$\\{\\}\"]+(?!\\})"));
            
        // Redis连接串匹配模式
        SENSITIVE_PATTERNS.put("REDIS_URL",
            Pattern.compile("(?i)(?<!\\$\\{)(?<!\\b(?:import|package)\\b.*)(redis://|redis\\.(?:host|url|address)\\s*=\\s*)[^\\s,}\\$\\{\\}\"]+(?!\\})"));
            
        // RabbitMQ连接串匹配模式
        SENSITIVE_PATTERNS.put("RABBITMQ_URL",
            Pattern.compile("(?i)(?<!\\$\\{)(?<!\\b(?:import|package)\\b.*)(amqp://|rabbitmq\\.(?:host|addresses)\\s*=\\s*)[^\\s,}\\$\\{\\}\"]+(?!\\})"));
            
        // Kafka连接串匹配模式
        SENSITIVE_PATTERNS.put("KAFKA_URL",
            Pattern.compile("(?i)(?<!\\$\\{)(?<!\\b(?:import|package)\\b.*)(kafka\\.bootstrap\\.servers|bootstrap\\.servers|kafka\\.url)\\s*=\\s*[^\\s,}\\$\\{\\}\"]+(?!\\})"));
            
        // ElasticSearch连接串匹配模式
        SENSITIVE_PATTERNS.put("ES_URL",
            Pattern.compile("(?i)(?<!\\$\\{)(?<!\\b(?:import|package)\\b.*)(elasticsearch://|elasticsearch\\.(?:url|nodes)\\s*=\\s*)[^\\s,}\\$\\{\\}\"]+(?!\\})"));
            
        // RocketMQ配置匹配模式
        SENSITIVE_PATTERNS.put("ROCKETMQ_CONFIG",
            Pattern.compile("(?i)(?<!\\$\\{)(?<!\\b(?:import|package)\\b.*)(namesrv[A-Za-z]*|rocketmq\\.namesrv)\\s*=\\s*[^\\s,}\\$\\{\\}\"]+(?!\\})"));
            
        // 通用URL匹配模式（排除配置占位符和常见开源地址）
        SENSITIVE_PATTERNS.put("GENERAL_URL",
            Pattern.compile("(?i)(?<!\\$\\{)(?<!\\b(?:import|package)\\b.*)([a-zA-Z0-9_-]+\\.(url|host|addr|address|endpoint|server|servers))\\s*=\\s*(?!.*(?:maven\\.org|github\\.com|apache\\.org))[^\\s,}\\$\\{\\}\"]+(?!\\})"));
        
        // 密码匹配模式（排除配置占位符）
        SENSITIVE_PATTERNS.put("PASSWORD", 
            Pattern.compile("(?i)(?<!\\$\\{)(?<!\\b(?:import|package)\\b.*)(password|pwd|pass)[\\s_-]*=\\s*(?!@[^@\\s]+@)(?!\\$\\{[^\\}]+\\})[^\\s,}\\$\\{\\}]+(?!\\})"));
        
        // API密钥匹配模式（排除配置占位符）
        SENSITIVE_PATTERNS.put("API_KEY", 
            Pattern.compile("(?i)(?<!\\$\\{)(?<!\\b(?:import|package)\\b.*)(api[_-]?key|secret[_-]?key|token|access[_-]?key)\\s*=\\s*(?!@[^@\\s]+@)(?!\\$\\{[^\\}]+\\})[^\\s,}\\$\\{\\}]+(?!\\})"));
            
        // 通用认证信息匹配模式（排除配置占位符）
        SENSITIVE_PATTERNS.put("AUTH_INFO",
            Pattern.compile("(?i)(?<!\\$\\{)(?<!\\b(?:import|package)\\b.*)(username|user|auth)[\\s_-]*=\\s*(?!@[^@\\s]+@)(?!\\$\\{[^\\}]+\\})[^\\s,}\\$\\{\\}]+(?!\\})"));
            
        // 域名匹配模式（排除常见开源网站和配置占位符）
        SENSITIVE_PATTERNS.put("DOMAIN",
            Pattern.compile("(?i)(?<!\\$\\{)(?<!\\b(?:import|package)\\b.*)(?!(?:maven\\.org|github\\.com|apache\\.org))([a-zA-Z0-9_-]+\\.[a-zA-Z0-9_-]+\\.(com|cn|net|org|io|cloud))(?::\\d+)?(?!\\})"));
    }

    private final Project project;

    /**
     * 构造函数
     * @param project 当前项目实例
     */
    public SensitiveDataService(Project project) {
        this.project = project;
    }

    /**
     * 处理项目中所有配置文件的敏感信息
     * 
     * 该方法会：
     * 1. 递归扫描项目目录
     * 2. 识别需要处理的配置文件
     * 3. 对每个文件执行脱敏操作
     * 4. 保存修改后的文件
     */
    public void maskAllProjectFiles() {
        ApplicationManager.getApplication().runReadAction(() -> {
            try {
                VirtualFile projectDir = project.getBaseDir();
                if (projectDir == null) return;
                
                List<VirtualFile> configFiles = new ArrayList<>();
                collectConfigFiles(projectDir, configFiles);
                
                if (!configFiles.isEmpty()) {
                    ApplicationManager.getApplication().invokeLater(() -> {
                        WriteCommandAction.runWriteCommandAction(project, () -> {
                            for (VirtualFile file : configFiles) {
                                try {
                                    Document document = FileDocumentManager.getInstance().getDocument(file);
                                    if (document != null) {
                                        String content = document.getText();
                                        String maskedContent = maskSensitiveData(content);
                                        if (!content.equals(maskedContent)) {
                                            document.setText(maskedContent);
                                            FileDocumentManager.getInstance().saveDocument(document);
                                        }
                                    }
                                } catch (Exception e) {
                                    // 继续处理下一个文件
                                }
                            }
                        });
                    });
                }
            } catch (Exception e) {
                // 处理异常
            }
        });
    }

    /**
     * 递归收集需要处理的配置文件
     * 
     * @param dir 当前处理的目录
     * @param configFiles 收集到的配置文件列表
     */
    private void collectConfigFiles(VirtualFile dir, List<VirtualFile> configFiles) {
        VirtualFile[] children = dir.getChildren();
        if (children == null) return;

        for (VirtualFile child : children) {
            if (child.isDirectory()) {
                String path = child.getPath().toLowerCase();
                // 排除特定目录
                if (!path.contains("/target/") &&
                    !path.contains("/build/") &&
                    !path.contains("/dist/") &&
                    !path.contains("/node_modules/") &&
                    !path.contains("/.git/")) {
                    collectConfigFiles(child, configFiles);
                }
            } else if (isSensitiveFile(child)) {
                configFiles.add(child);
            }
        }
    }

    /**
     * 对文本内容进行敏感信息脱敏处理
     * 
     * @param content 需要处理的文本内容
     * @return 处理后的文本内容
     */
    public String maskSensitiveData(@NotNull String content) {
        String maskedContent = content;
        for (Map.Entry<String, Pattern> entry : SENSITIVE_PATTERNS.entrySet()) {
            maskedContent = entry.getValue().matcher(maskedContent).replaceAll(match -> {
                switch (entry.getKey()) {
                    case "IP_ADDRESS":
                        return "***.***.***.**";
                    case "DB_URL":
                        return "jdbc:****://****";
                    case "MONGODB_URL":
                        if (match.group().startsWith("mongodb://")) {
                            return "mongodb://****:****@****";
                        } else {
                            return match.group(1) + "=****";
                        }
                    case "REDIS_URL":
                        if (match.group().startsWith("redis://")) {
                            return "redis://****:****@****";
                        } else {
                            return match.group(1) + "=****";
                        }
                    case "RABBITMQ_URL":
                        if (match.group().startsWith("amqp://")) {
                            return "amqp://****:****@****";
                        } else {
                            return match.group(1) + "=****";
                        }
                    case "KAFKA_URL":
                    case "ROCKETMQ_CONFIG":
                    case "GENERAL_URL":
                        String prefix = match.group(1);
                        return prefix + "=****";
                    case "ES_URL":
                        if (match.group().startsWith("elasticsearch://")) {
                            return "elasticsearch://****:****@****";
                        } else {
                            return match.group(1) + "=****";
                        }
                    case "PASSWORD":
                    case "API_KEY":
                    case "AUTH_INFO":
                        prefix = match.group(1);
                        return prefix + "=\"********\"";
                    case "DOMAIN":
                        return "****.****";
                    default:
                        return "********";
                }
            });
        }
        return maskedContent;
    }

    /**
     * 判断文件是否需要进行敏感信息处理
     * 
     * 判断依据：
     * 1. 文件扩展名（.properties, .yml, .yaml, .xml等）
     * 2. 文件名特征（application.*, config.*等）
     * 3. 文件路径（排除特定目录如 target, build等）
     * 
     * @param file 要检查的文件
     * @return 如果文件需要处理返回true，否则返回false
     */
    public boolean isSensitiveFile(VirtualFile file) {
        if (file == null || !file.exists() || file.isDirectory()) {
            return false;
        }
        
        String fileName = file.getName().toLowerCase();
        String path = file.getPath().toLowerCase();
        
        // 检查文件名
        if ((fileName.contains("application.") ||
            (fileName.contains("config.") && !fileName.contains(".java")) ||  // 排除 Java 配置类
            fileName.contains("settings.") ||
            fileName.endsWith(".properties") ||
            fileName.endsWith(".yml") ||
            fileName.endsWith(".yaml") ||
            fileName.endsWith(".xml") ||
            fileName.endsWith(".json") ||
            fileName.endsWith(".conf") ||
            fileName.endsWith(".cfg") ||
            fileName.endsWith(".env") ||
            fileName.endsWith(".ini")) &&
            !fileName.equals("pom.xml")) {  // 排除 pom.xml
            
            // 排除一些不需要处理的目录和文件
            return !path.contains("/target/") &&
                   !path.contains("/build/") &&
                   !path.contains("/dist/") &&
                   !path.contains("/node_modules/") &&
                   !path.contains("/.git/") &&
                   !path.contains("/src/main/resources/META-INF/maven/") &&
                   !path.contains("/src/main/java/") &&  // 排除 Java 源代码目录
                   !path.contains("/src/test/java/");    // 排除测试源代码目录
        }
        return false;
    }
} 