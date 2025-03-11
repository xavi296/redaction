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
import com.intellij.openapi.progress.ProgressIndicator;
import com.intellij.openapi.progress.ProgressManager;
import com.intellij.openapi.progress.Task;
import com.intellij.openapi.application.ReadAction;
import com.intellij.util.concurrency.AppExecutorUtil;
import com.intellij.openapi.application.ModalityState;
import org.jetbrains.annotations.NotNull;
import com.intellij.openapi.diagnostic.Logger;
import com.intellij.psi.*;
import com.intellij.psi.search.GlobalSearchScope;
import com.intellij.openapi.application.ApplicationManager;
import com.intellij.openapi.command.WriteCommandAction;
import com.intellij.openapi.editor.Document;
import com.intellij.openapi.fileEditor.FileDocumentManager;
import com.intellij.psi.util.PsiTreeUtil;
import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.Supplier;
import java.util.regex.Pattern;
import java.util.regex.Matcher;
import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonArray;
import com.google.gson.JsonParser;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.lang.reflect.*;
import com.intellij.openapi.util.TextRange;

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
@Service(Service.Level.PROJECT)
public final class SensitiveDataService {
    private static final Logger LOG = Logger.getInstance(SensitiveDataService.class);

    private static final int REGEX_TIMEOUT_MS = 500; // 正则表达式匹配超时时间（毫秒）
    private static final int MAX_CONTENT_LENGTH = 100000; // 最大处理内容长度
    private static final int MAX_FILE_SIZE = 5 * 1024 * 1024; // 降低到5MB
    private static final int BATCH_SIZE = 500; // 降低批处理大小
    private static final int MAX_FILES_PER_BATCH = 20; // 每批最多处理的文件数
    private static final int PROCESSING_DELAY = 100; // 文件处理间隔（毫秒）
    private static final ExecutorService EXECUTOR = AppExecutorUtil.createBoundedApplicationPoolExecutor("SensitiveDataService", 2);
    
    private static final Map<String, Pattern> SENSITIVE_PATTERNS = new HashMap<>();
    private static final Map<String, Pattern> JAVA_SENSITIVE_PATTERNS = new HashMap<>();
    
    private final Project project;
    private final PsiFileFactory psiFileFactory;
    private final JavaPsiFacade javaPsiFacade;

    private static final Set<String> SENSITIVE_FIELD_KEYWORDS = new HashSet<>(Arrays.asList(
        "password", "pwd", "passwd", "secret", "key", "token",
        "username", "user", "private", "privacy", "credential",
        "apikey", "api_key", "auth", "authentication",
        "url", "uri", "endpoint", "address", "addr",
        "cluster", "host", "server", "gateway", "proxy",
        "nameserver", "namesrv", "broker", "registry",
        "zookeeper", "redis", "mysql", "mongodb", "elasticsearch",
        "kafka", "rabbitmq", "dubbo", "nacos"
    ));
    
    static {
        try {
            // IP地址匹配模式（排除配置占位符和XML schema）
            SENSITIVE_PATTERNS.put("IP_ADDRESS", 
                Pattern.compile("\\b(?!\\$\\{)(?!\\b(?:import|package|xmlns|http)\\b)(?:\\d{1,3}\\.){3}\\d{1,3}\\b(?!\\})", 
                Pattern.CASE_INSENSITIVE));
            
            // 数据库URL匹配模式
            SENSITIVE_PATTERNS.put("DB_URL", 
                Pattern.compile("(jdbc:[a-z]+://[^\\s/\\$\\{\\}]+)"));
            
            // MySQL配置
            SENSITIVE_PATTERNS.put("MYSQL_CONFIG",
                Pattern.compile("((?:spring[.])?mysql[.:].*?(?:url|host|port|username|user|password|passwd|database|db)\\s*[=:]\\s*[\"']?[^\\s,;\"']+[\"']?)",
                Pattern.CASE_INSENSITIVE));
            
            // Redis配置
            SENSITIVE_PATTERNS.put("REDIS_CONFIG",
                Pattern.compile("((?:spring[.])?redis[.:].*?(?:url|host|port|password|auth)\\s*[=:]\\s*[\"']?[^\\s,;\"']+[\"']?)",
                Pattern.CASE_INSENSITIVE));
            
            // RabbitMQ配置
            SENSITIVE_PATTERNS.put("RABBITMQ_CONFIG",
                Pattern.compile("((?:spring[.])?rabbitmq[.:].*?(?:url|host|port|username|user|password|passwd|virtual-host)\\s*[=:]\\s*[\"']?[^\\s,;\"']+[\"']?)",
                Pattern.CASE_INSENSITIVE));
            
            // MongoDB配置
            SENSITIVE_PATTERNS.put("MONGODB_CONFIG",
                Pattern.compile("((?:spring[.]data[.])?(?:mongodb|mongo)[.:].*?(?:url|host|port|username|user|password|passwd|authSource|connection)\\s*[=:]\\s*[\"']?(?:mongodb://)?[^\\s,;\"']+[\"']?)",
                Pattern.CASE_INSENSITIVE));
            
            // HiKV配置
            SENSITIVE_PATTERNS.put("HIKV_CONFIG",
                Pattern.compile("(hikv[.:].*?(?:url|host|port|username|user|password|passwd)\\s*[=:]\\s*[\"']?[^\\s,;\"']+[\"']?)",
                Pattern.CASE_INSENSITIVE));
            
            // TiDB配置
            SENSITIVE_PATTERNS.put("TIDB_CONFIG",
                Pattern.compile("(tidb[.:].*?(?:url|host|port|username|user|password|passwd)\\s*[=:]\\s*[\"']?[^\\s,;\"']+[\"']?)",
                Pattern.CASE_INSENSITIVE));
            
            // HBase配置
            SENSITIVE_PATTERNS.put("HBASE_CONFIG",
                Pattern.compile("(hbase[.:].*?(?:url|zookeeper|quorum|port|principal|keytab)\\s*[=:]\\s*[\"']?[^\\s,;\"']+[\"']?)",
                Pattern.CASE_INSENSITIVE));
            
            // Hive配置
            SENSITIVE_PATTERNS.put("HIVE_CONFIG",
                Pattern.compile("(hive[.:].*?(?:url|host|port|username|user|password|passwd|principal|keytab)\\s*[=:]\\s*[\"']?[^\\s,;\"']+[\"']?)",
                Pattern.CASE_INSENSITIVE));
            
            // Couchbase配置
            SENSITIVE_PATTERNS.put("COUCHBASE_CONFIG",
                Pattern.compile("((?:spring[.])?couchbase[.:].*?(?:url|host|port|username|user|password|passwd|bucket|server|master|name|cluster|nodes)\\s*[=:]\\s*[\"']?[^\\s,;\"']+[\"']?)",
                Pattern.CASE_INSENSITIVE));
            
            // Elasticsearch配置
            SENSITIVE_PATTERNS.put("ELASTICSEARCH_CONFIG",
                Pattern.compile("((?:spring[.]data[.])?elasticsearch[.:].*?(?:url|host|port|username|user|password|passwd|cluster)\\s*[=:]\\s*[\"']?[^\\s,;\"']+[\"']?)",
                Pattern.CASE_INSENSITIVE));
            
            // 通用密码配置
            SENSITIVE_PATTERNS.put("PASSWORD",
                Pattern.compile("(?i)(?<!spring[.]data[.]elasticsearch[.]|spring[.]data[.]mongodb[.]|spring[.]rabbitmq[.]|spring[.]redis[.]|mysql[.]|tidb[.]|hikv[.]|hbase[.]|hive[.]|couchbase[.])(password|passwd|pwd)\\s*[=:]\\s*[\"']?[^\\s,;\"']+[\"']?"));
            
            // 通用用户名配置
            SENSITIVE_PATTERNS.put("USERNAME",
                Pattern.compile("(?i)(?<!spring[.]data[.]elasticsearch[.]|spring[.]data[.]mongodb[.]|spring[.]rabbitmq[.]|spring[.]redis[.]|mysql[.]|tidb[.]|hikv[.]|hbase[.]|hive[.]|couchbase[.])(username|user)\\s*[=:]\\s*[\"']?[^\\s,;\"']+[\"']?"));
            
            // 通用URL配置
            SENSITIVE_PATTERNS.put("URL",
                Pattern.compile("(?i)(?<!spring[.]data[.]elasticsearch[.]|spring[.]data[.]mongodb[.]|spring[.]rabbitmq[.]|spring[.]redis[.]|mysql[.]|tidb[.]|hikv[.]|hbase[.]|hive[.]|couchbase[.])(url|host|endpoint)\\s*[=:]\\s*[\"']?[^\\s,;\"']+[\"']?"));
            
            // 通用端口配置
            SENSITIVE_PATTERNS.put("PORT",
                Pattern.compile("(?i)(?<!spring[.]data[.]elasticsearch[.]|spring[.]data[.]mongodb[.]|spring[.]rabbitmq[.]|spring[.]redis[.]|mysql[.]|tidb[.]|hikv[.]|hbase[.]|hive[.]|couchbase[.])(port)\\s*[=:]\\s*[\"']?\\d+[\"']?"));
            
            // RocketMQ配置
            SENSITIVE_PATTERNS.put("ROCKETMQ_CONFIG",
                Pattern.compile("((?:spring[.])?(?:rocketmq|mq)[.:].*?(?:namesrvAddr|addr|host|port|producerGroup|consumerGroup|topic|accessKey|secretKey)\\s*[=:]\\s*[\"']?[^\\s,;\"']+[\"']?)",
                Pattern.CASE_INSENSITIVE));
            
            // Dubbo配置
            SENSITIVE_PATTERNS.put("DUBBO_CONFIG",
                Pattern.compile("((?:spring[.])?dubbo[.:].*?(?:registry[.]address|address|url|host|port|username|user|password|passwd|group|version|timeout|protocol)\\s*[=:]\\s*[\"']?[^\\s,;\"']+[\"']?)",
                Pattern.CASE_INSENSITIVE));
            
            // Java类中的敏感信息匹配模式
            JAVA_SENSITIVE_PATTERNS.put("JAVA_STRING_SENSITIVE",
                Pattern.compile("(?:private|public|protected|static)?\\s*(?:final)?\\s*String\\s+(?:url|username|password|driverClass|connec|dataBase|collectionName)\\s*=\\s*\"[^\"]+\"", 
                Pattern.CASE_INSENSITIVE));
            
            JAVA_SENSITIVE_PATTERNS.put("JAVA_MONGODB_URI",
                Pattern.compile("(?:private|public|protected|static)?\\s*(?:final)?\\s*String\\s+\\w+\\s*=\\s*\"mongodb://[^\"]+\"", 
                Pattern.CASE_INSENSITIVE));
                
            JAVA_SENSITIVE_PATTERNS.put("JAVA_JDBC_URL",
                Pattern.compile("(?:private|public|protected|static)?\\s*(?:final)?\\s*String\\s+\\w+\\s*=\\s*\"jdbc:[^\"]+\"", 
                Pattern.CASE_INSENSITIVE));
                
            JAVA_SENSITIVE_PATTERNS.put("JAVA_URL_PATTERN",
                Pattern.compile("(?:private|public|protected|static)?\\s*(?:final)?\\s*String\\s+\\w+\\s*=\\s*\"(?:http[s]?|redis|zookeeper|dubbo)://[^\"]+\"", 
                Pattern.CASE_INSENSITIVE));
                
            JAVA_SENSITIVE_PATTERNS.put("JAVA_IP_PORT",
                Pattern.compile("(?:private|public|protected|static)?\\s*(?:final)?\\s*String\\s+\\w+\\s*=\\s*\"[^\"]*\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}(?::\\d+)?[^\"]*\"", 
                Pattern.CASE_INSENSITIVE));
                
            JAVA_SENSITIVE_PATTERNS.put("JAVA_DOMAIN_PORT",
                Pattern.compile("(?:private|public|protected|static)?\\s*(?:final)?\\s*String\\s+\\w+\\s*=\\s*\"[^\"]*[a-zA-Z0-9-]+\\.[a-zA-Z0-9-.]+(?::\\d+)?[^\"]*\"", 
                Pattern.CASE_INSENSITIVE));
        } catch (Exception e) {
            // 忽略初始化异常
        }
    }

    private volatile boolean isProcessing = false;

    /**
     * 构造函数
     * @param project 当前项目实例
     */
    public SensitiveDataService(@NotNull Project project) {
        this.project = project;
        this.psiFileFactory = PsiFileFactory.getInstance(project);
        this.javaPsiFacade = JavaPsiFacade.getInstance(project);
    }

    /**
     * 异步处理所有项目文件
     */
    public void maskAllProjectFiles() {
        ProgressManager.getInstance().run(new Task.Backgroundable(project, "Masking Sensitive Data", true) {
            @Override
            public void run(@NotNull ProgressIndicator indicator) {
                try {
                    indicator.setIndeterminate(false);
                    indicator.setText("Scanning project files...");
                    
                    List<VirtualFile> configFiles = new ArrayList<>();
                    ReadAction.run(() -> collectConfigFiles(project.getBaseDir(), configFiles, indicator));
                    
                    if (configFiles.isEmpty()) {
                        return;
                    }

                    int totalFiles = configFiles.size();
                    AtomicInteger processedFiles = new AtomicInteger(0);
                    
                    // 使用线程池并行处理文件
                    AppExecutorUtil.getAppExecutorService().submit(() -> {
                        for (VirtualFile file : configFiles) {
                            if (indicator.isCanceled()) {
                                break;
                            }
                            
                            indicator.setText("Processing: " + file.getName());
                            indicator.setFraction((double) processedFiles.get() / totalFiles);
                            
                            processFile(file);
                            processedFiles.incrementAndGet();
                        }
                    });
                } catch (Exception e) {
                    // 记录错误但继续处理
                }
            }
        });
    }

    /**
     * 处理指定目录下的配置文件
     */
    public void maskDirectoryFiles(@NotNull VirtualFile directory) {
        if (!directory.isDirectory() || isProcessing) {
            return;
        }

        isProcessing = true;
        ProgressManager.getInstance().run(new Task.Backgroundable(project, "Masking Directory Files", true) {
            @Override
            public void run(@NotNull ProgressIndicator indicator) {
                try {
                    indicator.setIndeterminate(false);
                    indicator.setText("Scanning directory: " + directory.getName());
                    
                    List<VirtualFile> configFiles = new ArrayList<>();
                    ReadAction.run(() -> collectConfigFiles(directory, configFiles, indicator));
                    
                    if (configFiles.isEmpty()) {
                        return;
                    }

                    // 对文件进行分批处理
                    List<List<VirtualFile>> batches = splitIntoBatches(configFiles, MAX_FILES_PER_BATCH);
                    int totalBatches = batches.size();
                    AtomicInteger processedBatches = new AtomicInteger(0);

                    for (List<VirtualFile> batch : batches) {
                        if (indicator.isCanceled()) {
                            break;
                        }

                        indicator.setText("Processing batch " + (processedBatches.get() + 1) + " of " + totalBatches);
                        indicator.setFraction((double) processedBatches.get() / totalBatches);

                        // 处理当前批次
                        processBatch(batch, indicator);
                        
                        // 批次间延迟，让出CPU
                        Thread.sleep(PROCESSING_DELAY);
                        processedBatches.incrementAndGet();
                    }
                } catch (Exception e) {
                    // 记录错误但继续处理
                } finally {
                    isProcessing = false;
                }
            }
        });
    }

    private void processBatch(List<VirtualFile> files, ProgressIndicator indicator) {
        if (files.isEmpty()) {
            return;
        }

        AtomicInteger processedCount = new AtomicInteger(0);
        int totalFiles = files.size();

        for (VirtualFile file : files) {
            if (indicator.isCanceled()) {
                break;
            }

            try {
                // 处理文件
                processFile(file);
                
                // 更新进度
                int current = processedCount.incrementAndGet();
                indicator.setFraction((double) current / totalFiles);
                indicator.setText2("处理文件 " + current + "/" + totalFiles + ": " + file.getName());
                
                // 添加处理延迟，避免UI冻结
                try {
                    Thread.sleep(PROCESSING_DELAY);
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                    break;
                }
            } catch (Exception e) {
                LOG.error("Error processing file: " + file.getPath(), e);
            }
        }
    }

    private <T> List<List<T>> splitIntoBatches(List<T> items, int batchSize) {
        List<List<T>> batches = new ArrayList<>();
        for (int i = 0; i < items.size(); i += batchSize) {
            batches.add(items.subList(i, Math.min(items.size(), i + batchSize)));
        }
        return batches;
    }

    /**
     * 处理单个文件
     */
    public void processFile(VirtualFile file) {
        if (file == null || !file.exists() || file.isDirectory() || file.getLength() > MAX_FILE_SIZE) {
            LOG.info("跳过文件处理: " + (file != null ? file.getPath() : "null") + 
                    ", 原因: " + (file == null ? "文件为空" : 
                    (!file.exists() ? "文件不存在" : 
                    (file.isDirectory() ? "是目录" : 
                    "文件过大 " + file.getLength() + " > " + MAX_FILE_SIZE))));
            return;
        }

        String fileName = file.getName().toLowerCase();
        LOG.info("开始处理文件: " + file.getPath());

        // 根据文件类型选择不同的处理方式
        if (fileName.endsWith(".java")) {
            // 处理 Java 文件
            processJavaFile(file);
        } else if (fileName.endsWith(".properties") || 
                   fileName.endsWith(".yml") || 
                   fileName.endsWith(".yaml") ||
                   fileName.endsWith(".xml") ||
                   fileName.endsWith(".json")) {
            // 处理配置文件
            processConfigFile(file);
        } else {
            LOG.info("跳过不支持的文件类型: " + file.getPath());
        }
    }

    /**
     * 处理 Java 文件
     */
    private void processJavaFile(VirtualFile file) {
        // 在主线程中收集需要替换的内容
        List<FieldReplacement> replacements = new ArrayList<>();
        ReadAction.run(() -> {
            try {
                PsiFile psiFile = PsiManager.getInstance(project).findFile(file);
                if (!(psiFile instanceof PsiJavaFile)) {
                    LOG.warn("文件不是Java文件: " + file.getPath());
                    return;
                }

                PsiJavaFile javaFile = (PsiJavaFile) psiFile;
                Document document = FileDocumentManager.getInstance().getDocument(file);
                if (document == null) {
                    LOG.error("无法获取文档对象: " + file.getPath());
                    return;
                }

                LOG.info("开始处理Java类: " + javaFile.getName() + ", 包含类数量: " + javaFile.getClasses().length);

                // 获取所有类
                for (PsiClass psiClass : javaFile.getClasses()) {
                    processPsiClass(psiClass, replacements);
                }
            } catch (Exception e) {
                LOG.error("处理Java文件失败: " + file.getPath(), e);
            }
        });

        // 如果有需要替换的内容，在主线程中执行写操作
        if (!replacements.isEmpty()) {
            LOG.info("找到需要替换的敏感字段数量: " + replacements.size() + ", 文件: " + file.getPath());
            ApplicationManager.getApplication().invokeLater(() -> {
                WriteCommandAction.runWriteCommandAction(project, () -> {
                    try {
                        Document document = FileDocumentManager.getInstance().getDocument(file);
                        if (document != null) {
                            // 从后向前替换，避免位置偏移
                            replacements.sort((a, b) -> b.startOffset - a.startOffset);
                            for (FieldReplacement replacement : replacements) {
                                LOG.debug("执行替换: 位置 " + replacement.startOffset + " 到 " + replacement.endOffset);
                                document.replaceString(
                                    replacement.startOffset,
                                    replacement.endOffset,
                                    replacement.newText
                                );
                            }
                            FileDocumentManager.getInstance().saveDocument(document);
                            LOG.info("成功完成文件替换和保存: " + file.getPath());
                        } else {
                            LOG.error("无法获取文档对象进行替换: " + file.getPath());
                        }
                    } catch (Exception e) {
                        LOG.error("执行替换操作失败: " + file.getPath(), e);
                    }
                });
            });
        } else {
            LOG.info("文件中未找到需要替换的敏感字段: " + file.getPath());
        }
    }

    /**
     * 处理配置文件
     */
    private void processConfigFile(VirtualFile file) {
        ReadAction.run(() -> {
            try {
                Document document = FileDocumentManager.getInstance().getDocument(file);
                if (document == null) {
                    LOG.error("无法获取文档对象: " + file.getPath());
                    return;
                }

                String content = document.getText();
                String fileName = file.getName().toLowerCase();
                String processedContent;

                if (fileName.endsWith(".properties")) {
                    processedContent = processConfigContent(content, "properties");
                } else if (fileName.endsWith(".yml") || fileName.endsWith(".yaml")) {
                    processedContent = processConfigContent(content, "yml");
                } else if (fileName.endsWith(".xml")) {
                    processedContent = maskXmlContent(content);
                } else if (fileName.endsWith(".json")) {
                    processedContent = maskJsonContent(content);
                } else {
                    LOG.warn("不支持的配置文件类型: " + file.getPath());
                    return;
                }

                if (!content.equals(processedContent)) {
                    ApplicationManager.getApplication().invokeLater(() -> {
                        WriteCommandAction.runWriteCommandAction(project, () -> {
                            try {
                                document.setText(processedContent);
                                FileDocumentManager.getInstance().saveDocument(document);
                                LOG.info("成功完成配置文件替换和保存: " + file.getPath());
                            } catch (Exception e) {
                                LOG.error("保存配置文件失败: " + file.getPath(), e);
                            }
                        });
                    });
                } else {
                    LOG.info("配置文件无需修改: " + file.getPath());
                }
            } catch (Exception e) {
                LOG.error("处理配置文件失败: " + file.getPath(), e);
            }
        });
    }

    private void processPsiClass(PsiClass psiClass, List<FieldReplacement> replacements) {
        LOG.info("开始处理类: " + psiClass.getQualifiedName());
        
        // 处理字段
        Collection<PsiField> fields = PsiTreeUtil.findChildrenOfType(psiClass, PsiField.class);
        LOG.info("找到字段数量: " + fields.size() + ", 类: " + psiClass.getQualifiedName());

        for (PsiField field : fields) {
            if (isSensitiveField(field)) {
                LOG.info("发现敏感字段: " + field.getName() + ", 类: " + psiClass.getQualifiedName());
                PsiExpression initializer = field.getInitializer();
                if (initializer instanceof PsiLiteralExpression) {
                    PsiLiteralExpression literalExpression = (PsiLiteralExpression) initializer;
                    Object value = literalExpression.getValue();
                    if (value instanceof String) {
                        String stringValue = (String) value;
                        TextRange textRange = literalExpression.getTextRange();
                        String maskedValue = getMaskedValueForField(field, stringValue);
                        LOG.debug("添加替换: 字段 " + field.getName() + 
                                ", 范围 " + textRange.getStartOffset() + "-" + textRange.getEndOffset() +
                                ", 掩码值: " + maskedValue);
                        replacements.add(new FieldReplacement(
                            textRange.getStartOffset(),
                            textRange.getEndOffset(),
                            "\"" + maskedValue + "\""
                        ));
                    }
                }
            }
        }
    }

    /**
     * 根据字段类型和值获取对应的掩码值
     */
    private String getMaskedValueForField(PsiField field, String originalValue) {
        String fieldText = field.getText();
        
        // MongoDB URI
        if (originalValue.startsWith("mongodb://")) {
            return "mongodb://###MASKED_USER###:###MASKED_PASSWORD###@###MASKED_HOST###:###MASKED_PORT###/###MASKED_DB###";
        }
        
        // JDBC URL
        if (originalValue.startsWith("jdbc:")) {
            return "jdbc:mysql://###MASKED_HOST###:###MASKED_PORT###/###MASKED_DB###";
        }
        
        // 其他URL模式
        for (Map.Entry<String, Pattern> entry : JAVA_SENSITIVE_PATTERNS.entrySet()) {
            if (entry.getValue().matcher(fieldText).matches()) {
                switch (entry.getKey()) {
                    case "JAVA_URL_PATTERN":
                        if (originalValue.startsWith("http://") || originalValue.startsWith("https://")) {
                            return "http://###MASKED###";
                        } else if (originalValue.startsWith("redis://")) {
                            return "redis://###MASKED_HOST###:###MASKED_PORT###";
                        } else if (originalValue.startsWith("zookeeper://")) {
                            return "zookeeper://###MASKED_HOST###:###MASKED_PORT###";
                        } else if (originalValue.startsWith("dubbo://")) {
                            return "dubbo://###MASKED_HOST###:###MASKED_PORT###";
                        }
                        break;
                    case "JAVA_IP_PORT":
                        return "###.###.###.###:####";
                    case "JAVA_DOMAIN_PORT":
                        return "###MASKED_DOMAIN###:####";
                }
            }
        }
        
        // 默认掩码
        return "###MASKED###";
    }

    private boolean isSensitiveField(PsiField field) {
        // 检查字段类型是否为String
        PsiType type = field.getType();
        if (!type.equalsToText("java.lang.String") && !type.equalsToText("String")) {
            LOG.debug("字段类型不是String: " + field.getName() + ", 类型: " + type.getPresentableText());
            return false;
        }

        String fieldName = field.getName().toLowerCase();
        PsiExpression initializer = field.getInitializer();
        
        // 检查字段值是否包含敏感信息
        if (initializer instanceof PsiLiteralExpression) {
            PsiLiteralExpression literalExpression = (PsiLiteralExpression) initializer;
            Object value = literalExpression.getValue();
            if (value instanceof String) {
                String stringValue = (String) value;
                
                // 检查是否包含敏感URL模式
                for (Map.Entry<String, Pattern> entry : JAVA_SENSITIVE_PATTERNS.entrySet()) {
                    if (entry.getValue().matcher(field.getText()).matches()) {
                        LOG.info("发现敏感URL模式: " + entry.getKey() + ", 字段: " + field.getName());
                        return true;
                    }
                }
                
                // 检查是否包含IP地址
                if (stringValue.matches(".*\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}.*")) {
                    LOG.info("发现IP地址: " + field.getName());
                    return true;
                }
                
                // 检查是否包含域名和端口
                if (stringValue.matches(".*[a-zA-Z0-9-]+\\.[a-zA-Z0-9-.]+(?::\\d+)?.*")) {
                    LOG.info("发现域名或端口: " + field.getName());
                    return true;
                }
            }
        }
        
        // 检查字段名是否包含敏感关键词
        for (String keyword : SENSITIVE_FIELD_KEYWORDS) {
            if (fieldName.contains(keyword)) {
                LOG.info("发现敏感关键词: " + keyword + ", 字段: " + field.getName());
                return true;
            }
        }

        // 检查字段注解
        for (PsiAnnotation annotation : field.getAnnotations()) {
            String annotationName = annotation.getQualifiedName();
            if (annotationName != null && (
                annotationName.contains("Sensitive") ||
                annotationName.contains("Password") ||
                annotationName.contains("Secret")
            )) {
                LOG.info("发现敏感注解: " + annotationName + ", 字段: " + field.getName());
                return true;
            }
        }

        // 检查字段注释
        PsiComment[] comments = PsiTreeUtil.getChildrenOfType(field.getParent(), PsiComment.class);
        if (comments != null) {
            for (PsiComment comment : comments) {
                String commentText = comment.getText().toLowerCase();
                if (commentText.contains("sensitive") ||
                    commentText.contains("password") ||
                    commentText.contains("secret")) {
                    LOG.info("发现敏感注释: " + commentText + ", 字段: " + field.getName());
                    return true;
                }
            }
        }

        LOG.debug("字段不敏感: " + field.getName());
        return false;
    }

    private static class FieldReplacement {
        final int startOffset;
        final int endOffset;
        final String newText;

        FieldReplacement(int startOffset, int endOffset, String newText) {
            this.startOffset = startOffset;
            this.endOffset = endOffset;
            this.newText = newText;
        }
    }

    /**
     * 使用超时控制执行任务
     */
    private <T> T processWithTimeout(Supplier<T> task, T defaultValue, long timeoutMs) {
        Future<T> future = EXECUTOR.submit(task::get);
        try {
            return future.get(timeoutMs, TimeUnit.MILLISECONDS);
        } catch (TimeoutException e) {
            LOG.warn("Task timed out after " + timeoutMs + "ms, using default value");
            future.cancel(true);
            return defaultValue;
        } catch (Exception e) {
            LOG.warn("Task failed: " + e.getMessage());
            return defaultValue;
        }
    }
    
    /**
     * 优化的敏感数据掩码处理
     */
    private String maskSensitiveDataOptimized(String content) {
        if (content == null || content.isEmpty()) {
            return content;
        }
        
        // 特殊处理MongoDB连接字符串
        Pattern mongoPattern = Pattern.compile("(mongodb://[^\\s,;\"']+)");
        Matcher mongoMatcher = mongoPattern.matcher(content);
        StringBuffer sb = new StringBuffer();
        
        while (mongoMatcher.find()) {
            String mongoUrl = mongoMatcher.group(1);
            // 将整个MongoDB URL替换为脱敏版本
            mongoMatcher.appendReplacement(sb, "mongodb://******:******@***.***.***.***/******");
        }
        mongoMatcher.appendTail(sb);
        content = sb.toString();
        
        // 处理其他配置项
        Pattern pattern = Pattern.compile("([^=:\\s]+)\\s*[=:]\\s*[\"']?([^,;\\s\"']+)[\"']?");
        Matcher matcher = pattern.matcher(content);
        sb = new StringBuffer();
        
        while (matcher.find()) {
            String key = matcher.group(1);
            try {
                matcher.appendReplacement(sb, key + "=******");
            } catch (Exception e) {
                LOG.warn("Error replacing sensitive data: " + e.getMessage());
            }
        }
        matcher.appendTail(sb);
        return sb.toString();
    }
    
    /**
     * 专门处理XML格式内容的脱敏
     */
    private String maskXmlContent(String xmlContent) {
        LOG.info("开始处理 XML 内容");
        
        // 首先检查是否是 .idea 目录下的配置文件
        if (xmlContent.contains("<?xml") && xmlContent.contains("version=") && xmlContent.contains(".idea")) {
            LOG.info("检测到 .idea 目录下的 XML 配置文件，跳过处理");
            return xmlContent;
        }
        
        try {
            // 处理XML中的IP地址 - 修改正则表达式以匹配更多情况
            Pattern ipPattern = Pattern.compile("(value\\s*=\\s*\"Http[s]?://)(\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3})(:\\d+|/|\")", Pattern.CASE_INSENSITIVE);
            Matcher ipMatcher = ipPattern.matcher(xmlContent);
            StringBuffer sb = new StringBuffer();
            
            while (ipMatcher.find()) {
                LOG.debug("找到IP地址匹配: " + ipMatcher.group());
                String prefix = ipMatcher.group(1);
                String suffix = ipMatcher.group(3);
                String replacement = prefix + "***.***.***.***" + suffix;
                ipMatcher.appendReplacement(sb, Matcher.quoteReplacement(replacement));
            }
            ipMatcher.appendTail(sb);
            String result = sb.toString();
            
            // 处理XML中的域名
            Pattern domainPattern = Pattern.compile("(value\\s*=\\s*\"Http[s]?://)([-a-zA-Z0-9.]+\\.[a-zA-Z]{2,}(?:\\.[a-zA-Z]{2,})*)([:/]|\")", Pattern.CASE_INSENSITIVE);
            Matcher domainMatcher = domainPattern.matcher(result);
            StringBuffer domainSb = new StringBuffer();
            
            while (domainMatcher.find()) {
                LOG.debug("找到域名匹配: " + domainMatcher.group());
                String prefix = domainMatcher.group(1);
                String domain = domainMatcher.group(2);
                String suffix = domainMatcher.group(3);
                
                if (!domain.contains("***.***.***.***")) {
                    String replacement = prefix + "***.***.***" + suffix;
                    domainMatcher.appendReplacement(domainSb, Matcher.quoteReplacement(replacement));
                } else {
                    domainMatcher.appendReplacement(domainSb, Matcher.quoteReplacement(prefix + domain + suffix));
                }
            }
            domainMatcher.appendTail(domainSb);
            result = domainSb.toString();
            
            // 处理XML中的其他敏感信息
            for (Map.Entry<String, Pattern> entry : SENSITIVE_PATTERNS.entrySet()) {
                String type = entry.getKey();
                if (type.equals("IP_ADDRESS")) {
                    continue;
                }
                
                Pattern pattern = entry.getValue();
                Matcher matcher = pattern.matcher(result);
                StringBuffer xmlSb = new StringBuffer();
                
                while (matcher.find()) {
                    LOG.debug("找到敏感信息匹配: " + type + " - " + matcher.group());
                    String match = matcher.group();
                    if (!isInXmlTag(result, matcher.start())) {
                        String replacement = getMaskReplacement(type, match);
                        try {
                            matcher.appendReplacement(xmlSb, Matcher.quoteReplacement(replacement));
                        } catch (Exception e) {
                            LOG.error("替换XML中的敏感数据失败: " + e.getMessage());
                        }
                    } else {
                        try {
                            matcher.appendReplacement(xmlSb, Matcher.quoteReplacement(match));
                        } catch (Exception e) {
                            LOG.error("保持XML标签不变失败: " + e.getMessage());
                        }
                    }
                }
                matcher.appendTail(xmlSb);
                result = xmlSb.toString();
            }
            
            LOG.info("XML 内容处理完成");
            return result;
        } catch (Exception e) {
            LOG.error("处理 XML 内容时发生错误: " + e.getMessage(), e);
            return xmlContent;
        }
    }
    
    /**
     * 检查位置是否在XML标签内
     */
    private boolean isInXmlTag(String content, int position) {
        try {
            int lastLt = content.lastIndexOf('<', position);
            int lastGt = content.lastIndexOf('>', position);
            boolean inTag = lastLt > lastGt;
            LOG.debug("检查位置 " + position + " 是否在XML标签内: " + inTag);
            return inTag;
        } catch (Exception e) {
            LOG.error("检查XML标签位置时发生错误: " + e.getMessage());
            return false;
        }
    }

    private String getMaskReplacement(String type, String match) {
        // 根据不同类型返回相应的掩码
        switch (type) {
            case "IP_ADDRESS":
                return "###.###.###.###";
            case "DB_URL":
                return "jdbc:mysql://###MASKED###:3306/###MASKED###";
            case "MYSQL_CONFIG":
            case "TIDB_CONFIG":
                if (match.toLowerCase().contains("password") || match.toLowerCase().contains("passwd")) {
                    return match.replaceFirst("([=:])\\s*[\"']?[^\\s,;\"']+[\"']?", "$1 ###MASKED###");
                } else if (match.toLowerCase().contains("username") || match.toLowerCase().contains("user")) {
                    return match.replaceFirst("([=:])\\s*[\"']?[^\\s,;\"']+[\"']?", "$1 ###MASKED###");
                } else if (match.toLowerCase().contains("host")) {
                    return match.replaceFirst("([=:])\\s*[\"']?[^\\s,;\"']+[\"']?", "$1 ###.###.###.###");
                } else if (match.toLowerCase().contains("port")) {
                    return match.replaceFirst("([=:])\\s*[\"']?[^\\s,;\"']+[\"']?", "$1 ###MASKED###");
                } else {
                    return match.replaceFirst("([=:])\\s*[\"']?[^\\s,;\"']+[\"']?", "$1 jdbc:mysql://###MASKED###:3306/###MASKED###");
                }
            case "REDIS_CONFIG":
                if (match.toLowerCase().contains("password") || match.toLowerCase().contains("auth")) {
                    return match.replaceFirst("([=:])\\s*[\"']?[^\\s,;\"']+[\"']?", "$1 ###MASKED###");
                } else if (match.toLowerCase().contains("host")) {
                    return match.replaceFirst("([=:])\\s*[\"']?[^\\s,;\"']+[\"']?", "$1 ###.###.###.###");
                } else if (match.toLowerCase().contains("port")) {
                    return match.replaceFirst("([=:])\\s*[\"']?[^\\s,;\"']+[\"']?", "$1 ###MASKED###");
                } else {
                    return match.replaceFirst("([=:])\\s*[\"']?[^\\s,;\"']+[\"']?", "$1 redis://###MASKED###:6379");
                }
            case "RABBITMQ_CONFIG":
                if (match.toLowerCase().contains("password") || match.toLowerCase().contains("passwd")) {
                    return match.replaceFirst("([=:])\\s*[\"']?[^\\s,;\"']+[\"']?", "$1 ###MASKED###");
                } else if (match.toLowerCase().contains("username") || match.toLowerCase().contains("user")) {
                    return match.replaceFirst("([=:])\\s*[\"']?[^\\s,;\"']+[\"']?", "$1 ###MASKED###");
                } else if (match.toLowerCase().contains("host")) {
                    return match.replaceFirst("([=:])\\s*[\"']?[^\\s,;\"']+[\"']?", "$1 ###.###.###.###");
                } else if (match.toLowerCase().contains("port")) {
                    return match.replaceFirst("([=:])\\s*[\"']?[^\\s,;\"']+[\"']?", "$1 ###MASKED###");
                } else {
                    return match.replaceFirst("([=:])\\s*[\"']?[^\\s,;\"']+[\"']?", "$1 amqp://###MASKED###:5672");
                }
            case "MONGODB_CONFIG":
                if (match.toLowerCase().contains("password") || match.toLowerCase().contains("passwd")) {
                    return match.replaceFirst("([=:])\\s*[\"']?[^\\s,;\"']+[\"']?", "$1 ###MASKED###");
                } else if (match.toLowerCase().contains("username") || match.toLowerCase().contains("user")) {
                    return match.replaceFirst("([=:])\\s*[\"']?[^\\s,;\"']+[\"']?", "$1 ###MASKED###");
                } else if (match.toLowerCase().contains("connection")) {
                    // 对整个连接字符串进行脱敏
                    return match.replaceFirst("([=:])\\s*[\"']?[^\"']*[\"']?", "$1 mongodb://###MASKED###:27017/###MASKED###?readPreference=secondaryPreferred");
                } else if (match.toLowerCase().contains("host")) {
                    return match.replaceFirst("([=:])\\s*[\"']?[^\\s,;\"']+[\"']?", "$1 ###.###.###.###");
                } else if (match.toLowerCase().contains("port")) {
                    return match.replaceFirst("([=:])\\s*[\"']?[^\\s,;\"']+[\"']?", "$1 ###MASKED###");
                } else {
                    return match.replaceFirst("([=:])\\s*[\"']?[^\\s,;\"']+[\"']?", "$1 mongodb://###MASKED###:27017");
                }
            case "HIKV_CONFIG":
            case "HBASE_CONFIG":
            case "HIVE_CONFIG":
            case "COUCHBASE_CONFIG":
                if (match.toLowerCase().contains("password") || match.toLowerCase().contains("passwd")) {
                    return match.replaceFirst("([=:])\\s*[\"']?[^\\s,;\"']+[\"']?", "$1 ###MASKED###");
                } else if (match.toLowerCase().contains("username") || match.toLowerCase().contains("user")) {
                    return match.replaceFirst("([=:])\\s*[\"']?[^\\s,;\"']+[\"']?", "$1 ###MASKED###");
                } else if (match.toLowerCase().contains("principal") || match.toLowerCase().contains("keytab")) {
                    return match.replaceFirst("([=:])\\s*[\"']?[^\\s,;\"']+[\"']?", "$1 ###MASKED###");
                } else if (match.toLowerCase().contains("host") || match.toLowerCase().contains("quorum")) {
                    return match.replaceFirst("([=:])\\s*[\"']?[^\\s,;\"']+[\"']?", "$1 ###.###.###.###");
                } else if (match.toLowerCase().contains("port")) {
                    return match.replaceFirst("([=:])\\s*[\"']?[^\\s,;\"']+[\"']?", "$1 ###MASKED###");
                } else {
                    return match.replaceFirst("([=:])\\s*[\"']?[^\\s,;\"']+[\"']?", "$1 ###MASKED###:2181");
                }
            case "ELASTICSEARCH_CONFIG":
                if (match.toLowerCase().contains("password") || match.toLowerCase().contains("passwd")) {
                    return match.replaceFirst("([=:])\\s*[\"']?[^\\s,;\"']+[\"']?", "$1 ###MASKED###");
                } else if (match.toLowerCase().contains("username") || match.toLowerCase().contains("user")) {
                    return match.replaceFirst("([=:])\\s*[\"']?[^\\s,;\"']+[\"']?", "$1 ###MASKED###");
                } else if (match.toLowerCase().contains("host")) {
                    return match.replaceFirst("([=:])\\s*[\"']?[^\\s,;\"']+[\"']?", "$1 ###.###.###.###");
                } else if (match.toLowerCase().contains("port")) {
                    return match.replaceFirst("([=:])\\s*[\"']?[^\\s,;\"']+[\"']?", "$1 ###MASKED###");
                } else {
                    return match.replaceFirst("([=:])\\s*[\"']?[^\\s,;\"']+[\"']?", "$1 http://###MASKED###:9200");
                }
            case "PASSWORD":
                return match.replaceFirst("([=:])\\s*[\"']?[^\\s,;\"']+[\"']?", "$1 ###MASKED###");
            case "USERNAME":
                return match.replaceFirst("([=:])\\s*[\"']?[^\\s,;\"']+[\"']?", "$1 ###MASKED###");
            case "URL":
                return match.replaceFirst("([=:])\\s*[\"']?[^\\s,;\"']+[\"']?", "$1 ###MASKED###");
            case "PORT":
                return match.replaceFirst("([=:])\\s*[\"']?\\d+[\"']?", "$1 ###MASKED###");
            case "ROCKETMQ_CONFIG":
                if (match.toLowerCase().contains("namesrvaddr") || match.toLowerCase().contains("addr") || 
                    match.toLowerCase().contains("host")) {
                    return match.replaceFirst("([=:])\\s*[\"']?[^\\s,;\"']+[\"']?", "$1 ###.###.###.###:9876");
                } else if (match.toLowerCase().contains("accesskey") || match.toLowerCase().contains("secretkey")) {
                    return match.replaceFirst("([=:])\\s*[\"']?[^\\s,;\"']+[\"']?", "$1 ###MASKED###");
                } else if (match.toLowerCase().contains("producergroup") || match.toLowerCase().contains("consumergroup")) {
                    return match.replaceFirst("([=:])\\s*[\"']?[^\\s,;\"']+[\"']?", "$1 ###MASKED###");
                } else if (match.toLowerCase().contains("topic")) {
                    return match.replaceFirst("([=:])\\s*[\"']?[^\\s,;\"']+[\"']?", "$1 ###MASKED###");
                } else {
                    return match.replaceFirst("([=:])\\s*[\"']?[^\\s,;\"']+[\"']?", "$1 ###MASKED###");
                }
            case "DUBBO_CONFIG":
                if (match.toLowerCase().contains("address") || match.toLowerCase().contains("url") || 
                    match.toLowerCase().contains("host")) {
                    if (match.toLowerCase().contains("nacos")) {
                        return match.replaceFirst("([=:])\\s*[\"']?[^\\s,;\"']+[\"']?", "$1 nacos://###MASKED###");
                    } else if (match.toLowerCase().contains("zookeeper")) {
                        return match.replaceFirst("([=:])\\s*[\"']?[^\\s,;\"']+[\"']?", "$1 zookeeper://###MASKED###:2181");
                    } else {
                        return match.replaceFirst("([=:])\\s*[\"']?[^\\s,;\"']+[\"']?", "$1 ###MASKED###");
                    }
                } else if (match.toLowerCase().contains("password") || match.toLowerCase().contains("passwd")) {
                    return match.replaceFirst("([=:])\\s*[\"']?[^\\s,;\"']+[\"']?", "$1 ###MASKED###");
                } else if (match.toLowerCase().contains("username") || match.toLowerCase().contains("user")) {
                    return match.replaceFirst("([=:])\\s*[\"']?[^\\s,;\"']+[\"']?", "$1 ###MASKED###");
                } else if (match.toLowerCase().contains("group") || match.toLowerCase().contains("version")) {
                    return match.replaceFirst("([=:])\\s*[\"']?[^\\s,;\"']+[\"']?", "$1 ###MASKED###");
                } else if (match.toLowerCase().contains("port")) {
                    // 保持端口号原样
                    return match;
                } else {
                    return match.replaceFirst("([=:])\\s*[\"']?[^\\s,;\"']+[\"']?", "$1 ###MASKED###");
                }
            default:
                return "###MASKED###";
        }
    }

    private void collectConfigFiles(VirtualFile dir, List<VirtualFile> configFiles, ProgressIndicator indicator) {
        if (indicator.isCanceled()) {
            return;
        }

        VirtualFile[] children = dir.getChildren();
        if (children == null) return;

        for (VirtualFile child : children) {
            if (indicator.isCanceled()) {
                break;
            }

            if (child.isDirectory()) {
                String path = child.getPath().toLowerCase();
                if (!isExcludedDirectory(path)) {
                    collectConfigFiles(child, configFiles, indicator);
                }
            } else if (isSensitiveFile(child)) {
                configFiles.add(child);
            }
        }
    }

    private boolean isExcludedDirectory(String path) {
        if (path == null) {
            return false;
        }
        
        // 排除常见的不需要处理的目录
        return path.contains("/target/") ||
               path.contains("/build/") ||
               path.contains("/.git/") ||
               path.contains("/.idea/") ||
               path.contains("/node_modules/") ||
               path.contains("/dist/") ||
               path.contains("/out/") ||
               path.contains("/bin/") ||
               path.contains("/webapp/assets/plugins/") || // 排除webapp/assets/plugins目录
               path.contains("/vendor/");
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
        if (file == null || !file.exists() || file.isDirectory() || file.getLength() > MAX_FILE_SIZE) {
            return false;
        }
        
        String fileName = file.getName().toLowerCase();
        String path = file.getPath().toLowerCase();
        
        // 排除 .idea 目录下的配置文件
        if (path.contains("/.idea/")) {
            LOG.info("跳过 .idea 目录下的文件: " + path);
            return false;
        }
        
        // 添加对Java文件的支持
        if (fileName.endsWith(".java")) {
            return !isExcludedPath(path);
        }
        
        // 如果是 XML 文件，检查内容是否包含敏感信息（排除纯 schema 定义文件）
        if (fileName.endsWith(".xml")) {
            LOG.info("检查 XML 文件: " + path);
            // 在读操作中检查文件内容
            Boolean result = ApplicationManager.getApplication().runReadAction((com.intellij.openapi.util.Computable<Boolean>) () -> {
                try {
                    Document document = FileDocumentManager.getInstance().getDocument(file);
                    if (document != null) {
                        String content = document.getText();
                        // 如果文件内容主要是 schema 定义，则跳过
                        if (content.contains("<?xml") && content.contains("xmlns:") 
                            && !content.contains("password") && !content.contains("username")
                            && !content.contains("host") && !content.contains("url")) {
                            LOG.info("跳过 schema 定义文件: " + path);
                            return false;
                        }
                    }
                } catch (Exception e) {
                    LOG.warn("检查 XML 文件时发生错误: " + file.getPath(), e);
                }
                return isConfigFile(fileName) && !isExcludedPath(path);
            });
            return result;
        }
        
        return isConfigFile(fileName) && !isExcludedPath(path);
    }

    private boolean isConfigFile(String fileName) {
        return (fileName.contains("application.") ||
                fileName.contains("config.") ||
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
                !fileName.equals("pom.xml") &&
                !fileName.equals("package.json") &&
                !fileName.equals("tsconfig.json") &&
                !fileName.equals("composer.json");
    }

    private boolean isExcludedPath(String path) {
        if (path == null) {
            return false;
        }
        
        // 排除特定文件类型
        if (path.endsWith(".class") ||
            path.endsWith(".jar") ||
            path.endsWith(".war") ||
            path.endsWith(".zip") ||
            path.endsWith(".tar") ||
            path.endsWith(".gz") ||
            path.endsWith(".jpg") ||
            path.endsWith(".jpeg") ||
            path.endsWith(".png") ||
            path.endsWith(".gif") ||
            path.endsWith(".ico") ||
            path.endsWith(".svg") ||
            path.endsWith(".ttf") ||
            path.endsWith(".woff") ||
            path.endsWith(".woff2") ||
            path.endsWith(".eot")) {
            return true;
        }
        
        // 排除webapp/assets/plugins目录下的JS和JSON文件
        if (path.contains("/webapp/assets/plugins/") && 
            (path.endsWith(".js") || path.endsWith(".json"))) {
            return true;
        }
        
        // 排除特定文件名
        String fileName = path.substring(path.lastIndexOf('/') + 1);
        return fileName.equals("package-lock.json") ||
               fileName.equals("yarn.lock") ||
               fileName.equals("composer.lock") ||
               fileName.equals("Gemfile.lock");
    }

    /**
     * 专门处理JSON格式内容的脱敏
     * 使用JSON解析器确保不破坏JSON结构
     */
    private String maskJsonContent(String jsonContent) {
        try {
            // 使用Gson解析JSON
            JsonElement jsonElement;
            if (jsonContent.trim().startsWith("[")) {
                // 处理JSON数组
                jsonElement = JsonParser.parseString(jsonContent);
                if (jsonElement.isJsonArray()) {
                    JsonArray jsonArray = jsonElement.getAsJsonArray();
                    for (int i = 0; i < jsonArray.size(); i++) {
                        if (jsonArray.get(i).isJsonObject()) {
                            JsonObject obj = jsonArray.get(i).getAsJsonObject();
                            maskJsonObject(obj);
                        }
                    }
                }
            } else {
                // 处理JSON对象
                jsonElement = JsonParser.parseString(jsonContent);
                if (jsonElement.isJsonObject()) {
                    maskJsonObject(jsonElement.getAsJsonObject());
                }
            }
            
            // 将处理后的JSON转回字符串，禁用HTML转义和Unicode转义
            Gson gson = new GsonBuilder()
                .setPrettyPrinting()
                .disableHtmlEscaping()  // 禁用HTML转义
                .create();
            return gson.toJson(jsonElement);
            
        } catch (Exception e) {
            // 如果JSON解析失败，回退到普通文本处理
            LOG.warn("Error parsing JSON, falling back to regular masking: " + e.getMessage());
            return maskJsonContentAsText(jsonContent);
        }
    }
    
    /**
     * 递归处理JSON对象中的敏感字段
     */
    private void maskJsonObject(JsonObject jsonObject) {
        // 敏感字段名列表
        Set<String> sensitiveKeys = new HashSet<>(Arrays.asList(
            "password", "pwd", "secret", "key", "token", "accessKey", "secretKey", 
            "appId", "appKey", "appSecret", "nameSpace", "env", "cluster", "refreshPath",
            "host", "ip", "url", "uri", "endpoint", "address", "addr", "username", "user"
        ));
        
        // 处理所有字段
        for (Map.Entry<String, JsonElement> entry : new HashSet<>(jsonObject.entrySet())) {
            String key = entry.getKey();
            JsonElement value = entry.getValue();
            
            // 递归处理嵌套的JSON对象
            if (value.isJsonObject()) {
                // 特殊处理 dependencies 对象
                if (key.equals("dependencies")) {
                    maskDependenciesObject(value.getAsJsonObject());
                } else {
                    maskJsonObject(value.getAsJsonObject());
                }
            }
            // 递归处理JSON数组
            else if (value.isJsonArray()) {
                JsonArray array = value.getAsJsonArray();
                for (int i = 0; i < array.size(); i++) {
                    if (array.get(i).isJsonObject()) {
                        maskJsonObject(array.get(i).getAsJsonObject());
                    }
                }
            }
            // 处理字符串值
            else if (value.isJsonPrimitive() && value.getAsJsonPrimitive().isString()) {
                String strValue = value.getAsString();
                
                // 检查是否为敏感字段
                boolean isSensitive = false;
                
                // 1. 检查字段名是否为敏感字段
                for (String sensitiveKey : sensitiveKeys) {
                    if (key.toLowerCase().contains(sensitiveKey.toLowerCase())) {
                        isSensitive = true;
                        break;
                    }
                }
                
                // 2. 检查字段值是否匹配敏感模式
                if (!isSensitive) {
                    for (Map.Entry<String, Pattern> patternEntry : SENSITIVE_PATTERNS.entrySet()) {
                        if (patternEntry.getValue().matcher(strValue).matches()) {
                            isSensitive = true;
                            break;
                        }
                    }
                }
                
                // 如果是敏感字段，进行脱敏
                if (isSensitive) {
                    // 根据字段类型选择不同的掩码
                    String maskedValue;
                    if (key.toLowerCase().contains("password") || key.toLowerCase().contains("secret") || 
                        key.toLowerCase().contains("key") || key.toLowerCase().contains("token")) {
                        maskedValue = "###MASKED###";
                    } else if (key.toLowerCase().contains("ip") || key.toLowerCase().contains("host")) {
                        maskedValue = "###.###.###.###";
                    } else if (key.toLowerCase().contains("url") || key.toLowerCase().contains("uri") || 
                               key.toLowerCase().contains("endpoint")) {
                        maskedValue = "http://###MASKED###";
                    } else {
                        maskedValue = "###MASKED###";
                    }
                    
                    jsonObject.addProperty(key, maskedValue);
                }
            }
        }
    }
    
    /**
     * 特殊处理依赖对象，脱敏版本号但保留特殊字符
     */
    private void maskDependenciesObject(JsonObject dependenciesObject) {
        for (Map.Entry<String, JsonElement> entry : new HashSet<>(dependenciesObject.entrySet())) {
            String key = entry.getKey();
            JsonElement value = entry.getValue();
            
            if (value.isJsonPrimitive() && value.getAsJsonPrimitive().isString()) {
                // 保留依赖名称，脱敏版本号
                dependenciesObject.addProperty(key, "###MASKED###");
            } else if (value.isJsonObject()) {
                // 递归处理嵌套对象
                maskJsonObject(value.getAsJsonObject());
            }
        }
    }
    
    /**
     * 当JSON解析失败时的备用方法，使用正则表达式处理
     */
    private String maskJsonContentAsText(String jsonContent) {
        // 匹配JSON中的键值对
        Pattern jsonPattern = Pattern.compile("\"([^\"]+)\"\\s*:\\s*\"([^\"]+)\"");
        Matcher matcher = jsonPattern.matcher(jsonContent);
        StringBuffer sb = new StringBuffer();
        
        while (matcher.find()) {
            String key = matcher.group(1);
            String value = matcher.group(2);
            
            // 检查是否为敏感字段
            boolean isSensitive = false;
            Set<String> sensitiveKeys = new HashSet<>(Arrays.asList(
                "password", "pwd", "secret", "key", "token", "accessKey", "secretKey", 
                "appId", "appKey", "appSecret", "nameSpace", "env", "cluster", "refreshPath",
                "host", "ip", "url", "uri", "endpoint", "address", "addr", "username", "user"
            ));
            
            for (String sensitiveKey : sensitiveKeys) {
                if (key.toLowerCase().contains(sensitiveKey.toLowerCase())) {
                    isSensitive = true;
                    break;
                }
            }
            
            // 如果是敏感字段，进行脱敏
            if (isSensitive) {
                String maskedValue;
                if (key.toLowerCase().contains("password") || key.toLowerCase().contains("secret") || 
                    key.toLowerCase().contains("key") || key.toLowerCase().contains("token")) {
                    maskedValue = "###MASKED###";
                } else if (key.toLowerCase().contains("ip") || key.toLowerCase().contains("host")) {
                    maskedValue = "###.###.###.###";
                } else if (key.toLowerCase().contains("url") || key.toLowerCase().contains("uri") || 
                           key.toLowerCase().contains("endpoint")) {
                    maskedValue = "http://###MASKED###";
                } else {
                    maskedValue = "###MASKED###";
                }
                
                matcher.appendReplacement(sb, "\"" + key + "\":\"" + maskedValue + "\"");
            } else {
                matcher.appendReplacement(sb, matcher.group());
            }
        }
        
        matcher.appendTail(sb);
        return sb.toString();
    }

    /**
     * 处理配置文件内容
     * @param content 原始内容
     * @param fileType 文件类型
     * @return 脱敏后的内容
     */
    private String processConfigContent(String content, String fileType) {
        if (content == null || content.trim().isEmpty()) {
            return content;
        }

        StringBuilder result = new StringBuilder();
        String[] lines = content.split("\n");
        int indentation = 0;  // 用于YAML缩进级别跟踪

        for (String line : lines) {
            String processedLine = line;
            
            // 跳过注释行和空行
            if (line.trim().startsWith("#") || line.trim().startsWith("//") || line.trim().isEmpty()) {
                result.append(line).append("\n");
                continue;
            }

            if (fileType.equals("properties")) {
                // 处理 properties 文件
                int equalIndex = line.indexOf('=');
                if (equalIndex > 0) {
                    String key = line.substring(0, equalIndex).trim();
                    String value = line.substring(equalIndex + 1).trim();
                    
                    // 检查是否为敏感配置
                    if (isSensitiveConfigKey(key)) {
                        String maskedValue = getMaskedConfigValue(key, value);
                        processedLine = key + "=" + maskedValue;
                    }
                }
            } else if (fileType.equals("yml") || fileType.equals("yaml")) {
                // 处理 YAML 文件
                int colonIndex = line.indexOf(':');
                if (colonIndex > 0) {
                    String currentIndent = line.substring(0, line.indexOf(line.trim()));
                    String key = line.substring(currentIndent.length(), colonIndex).trim();
                    String value = line.substring(colonIndex + 1).trim();
                    
                    // 检查是否为敏感配置
                    if (isSensitiveConfigKey(key)) {
                        String maskedValue = getMaskedConfigValue(key, value);
                        processedLine = currentIndent + key + ": " + maskedValue;
                    }
                }
            }

            result.append(processedLine).append("\n");
        }

        return result.toString();
    }

    /**
     * 检查配置键是否为敏感信息
     */
    private boolean isSensitiveConfigKey(String key) {
        key = key.toLowerCase();
        
        // 检查是否包含敏感关键词
        for (String keyword : SENSITIVE_FIELD_KEYWORDS) {
            if (key.contains(keyword.toLowerCase())) {
                return true;
            }
        }

        // 检查是否匹配敏感模式
        for (Pattern pattern : SENSITIVE_PATTERNS.values()) {
            if (pattern.matcher(key).find()) {
                return true;
            }
        }

        return false;
    }

    /**
     * 根据配置键类型返回掩码后的值
     */
    private String getMaskedConfigValue(String key, String value) {
        key = key.toLowerCase();
        
        // URL相关
        if (key.contains("url") || key.contains("uri") || key.contains("endpoint")) {
            if (value.toLowerCase().contains("jdbc:")) {
                return "jdbc:mysql://###MASKED###:3306/###MASKED###";
            } else if (value.toLowerCase().contains("mongodb://")) {
                return "mongodb://###MASKED###:27017/###MASKED###";
            } else if (value.toLowerCase().contains("redis://")) {
                return "redis://###MASKED###:6379";
            } else {
                return "http://###MASKED###";
            }
        }
        
        // 主机地址相关
        if (key.contains("host") || key.contains("address") || key.contains("ip")) {
            return "###.###.###.###";
        }
        
        // 端口相关
        if (key.contains("port")) {
            return "###MASKED###";
        }
        
        // 集群相关
        if (key.contains("cluster") || key.contains("zookeeper") || key.contains("namesrv")) {
            return "###MASKED_CLUSTER###";
        }
        
        // 密码相关
        if (key.contains("password") || key.contains("secret") || key.contains("key")) {
            return "###MASKED###";
        }
        
        // 用户名相关
        if (key.contains("username") || key.contains("user")) {
            return "###MASKED###";
        }
        
        // 默认掩码
        return "###MASKED###";
    }

    /**
     * 处理单个文件
     * @param file 需要处理的文件
     * @return 处理后的内容
     */
    public String processFile(String filePath) {
        try {
            String content = new String(Files.readAllBytes(Paths.get(filePath)));
            
            if (filePath.endsWith(".java")) {
                return maskJavaContent(content);
            } else if (filePath.endsWith(".properties")) {
                return processConfigContent(content, "properties");
            } else if (filePath.endsWith(".yml") || filePath.endsWith(".yaml")) {
                return processConfigContent(content, "yml");
            }
            
            return content;
        } catch (IOException e) {
            LOG.error("处理文件失败: " + filePath, e);
            return null;
        }
    }

    /**
     * 批量处理文件
     * @param sourceDir 源文件目录
     * @param targetDir 目标文件目录
     */
    public void batchProcessFiles(String sourceDir, String targetDir) {
        try {
            Files.walk(Paths.get(sourceDir))
                .filter(Files::isRegularFile)
                .forEach(sourcePath -> {
                    try {
                        String fileName = sourcePath.getFileName().toString();
                        if (isConfigFile(fileName)) {
                            String processedContent = processFile(sourcePath.toString());
                            if (processedContent != null) {
                                Path targetPath = Paths.get(targetDir, fileName.replace(".", "_target."));
                                Files.createDirectories(targetPath.getParent());
                                Files.write(targetPath, processedContent.getBytes());
                            }
                        }
                    } catch (IOException e) {
                        LOG.error("处理文件失败: " + sourcePath, e);
                    }
                });
        } catch (IOException e) {
            LOG.error("批量处理文件失败", e);
        }
    }

    /**
     * 处理Java类文件中的敏感信息
     */
    private String maskJavaContent(String content) {
        if (content == null || content.trim().isEmpty()) {
            return content;
        }

        // 匹配类的成员变量声明，包含敏感信息的字段
        Pattern pattern = Pattern.compile(
            "(?:private|public|protected)\\s+(?:static\\s+)?(?:final\\s+)?String\\s+\\w+(?:" +
            // 密码和认证相关
            "password|pwd|passwd|secret|key|token|username|user|private|privacy|" +
            // URL和地址相关
            "url|uri|endpoint|address|addr|" +
            // 集群和服务器相关
            "cluster|host|server|gateway|proxy|nameserver|namesrv|broker|registry|" +
            // 中间件相关
            "zookeeper|redis|mysql|mongodb|elasticsearch|kafka|rabbitmq|dubbo|nacos" +
            ")\\w*\\s*=\\s*\"[^\"]*\"",
            Pattern.CASE_INSENSITIVE
        );
        
        Matcher matcher = pattern.matcher(content);
        StringBuffer sb = new StringBuffer();
        while (matcher.find()) {
            String match = matcher.group();
            String replacement;
            
            // 根据不同类型的字段使用不同的掩码
            if (match.toLowerCase().contains("url") || 
                match.toLowerCase().contains("uri") || 
                match.toLowerCase().contains("endpoint")) {
                replacement = match.replaceFirst("\"[^\"]*\"", "\"http://###MASKED###\"");
            } else if (match.toLowerCase().contains("host") || 
                      match.toLowerCase().contains("address") || 
                      match.toLowerCase().contains("server")) {
                replacement = match.replaceFirst("\"[^\"]*\"", "\"###.###.###.###\"");
            } else if (match.toLowerCase().contains("cluster") || 
                      match.toLowerCase().contains("zookeeper") || 
                      match.toLowerCase().contains("namesrv")) {
                replacement = match.replaceFirst("\"[^\"]*\"", "\"###MASKED_CLUSTER###\"");
            } else {
                replacement = match.replaceFirst("\"[^\"]*\"", "\"###MASKED###\"");
            }
            
            matcher.appendReplacement(sb, Matcher.quoteReplacement(replacement));
        }
        matcher.appendTail(sb);
        
        return sb.toString();
    }
} 