package com.redaction.action;

import com.intellij.openapi.actionSystem.AnAction;
import com.intellij.openapi.actionSystem.AnActionEvent;
import com.intellij.openapi.actionSystem.CommonDataKeys;
import com.intellij.openapi.command.WriteCommandAction;
import com.intellij.openapi.editor.Document;
import com.intellij.openapi.editor.Editor;
import com.intellij.openapi.project.Project;
import com.intellij.openapi.vfs.VirtualFile;
import com.redaction.service.SensitiveDataService;
import org.jetbrains.annotations.NotNull;

/**
 * 敏感数据脱敏动作处理类
 * 
 * 该类负责处理单个文件的敏感数据脱敏操作。当用户在编辑器中右键选择"Mask Sensitive Data"
 * 或使用快捷键时触发此动作。
 *
 * 主要功能：
 * - 检查当前文件是否需要进行脱敏处理
 * - 调用脱敏服务处理文件内容
 * - 将脱敏后的内容更新到编辑器
 *
 * @see com.redaction.service.SensitiveDataService
 * @version 1.0.0
 */
public class MaskSensitiveDataAction extends AnAction {

    /**
     * 执行脱敏动作
     * 
     * @param e 动作事件，包含当前编辑器、文件和项目的上下文信息
     */
    @Override
    public void actionPerformed(@NotNull AnActionEvent e) {
        Project project = e.getProject();
        if (project == null) return;

        Editor editor = e.getData(CommonDataKeys.EDITOR);
        VirtualFile file = e.getData(CommonDataKeys.VIRTUAL_FILE);
        
        if (editor == null || file == null) return;

        SensitiveDataService service = project.getService(SensitiveDataService.class);
        
        // 检查文件是否需要脱敏处理
        if (!service.isSensitiveFile(file)) {
            return;
        }

        Document document = editor.getDocument();
        String content = document.getText();
        // 调用服务进行脱敏处理
        String maskedContent = service.maskSensitiveData(content);

        // 在写操作命令中更新文档内容
        WriteCommandAction.runWriteCommandAction(project, () -> 
            document.setText(maskedContent)
        );
    }

    /**
     * 更新动作的可用状态
     * 
     * 根据当前文件类型和项目状态决定是否显示和启用该动作
     *
     * @param e 动作事件，包含当前环境信息
     */
    @Override
    public void update(@NotNull AnActionEvent e) {
        Project project = e.getProject();
        VirtualFile file = e.getData(CommonDataKeys.VIRTUAL_FILE);
        
        if (project == null || file == null) {
            e.getPresentation().setEnabledAndVisible(false);
            return;
        }

        SensitiveDataService service = project.getService(SensitiveDataService.class);
        e.getPresentation().setEnabledAndVisible(service.isSensitiveFile(file));
    }
} 