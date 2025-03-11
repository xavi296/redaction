package com.redaction.action;

import com.intellij.openapi.actionSystem.AnAction;
import com.intellij.openapi.actionSystem.AnActionEvent;
import com.intellij.openapi.actionSystem.CommonDataKeys;
import com.intellij.openapi.project.Project;
import com.intellij.openapi.vfs.VirtualFile;
import com.intellij.openapi.components.ServiceManager;
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

        VirtualFile[] files = e.getData(CommonDataKeys.VIRTUAL_FILE_ARRAY);
        if (files == null || files.length == 0) return;

        SensitiveDataService service = project.getService(SensitiveDataService.class);
        
        for (VirtualFile file : files) {
            if (file.isDirectory()) {
                service.maskDirectoryFiles(file);
            } else {
                service.processFile(file);
            }
        }
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
        VirtualFile[] files = e.getData(CommonDataKeys.VIRTUAL_FILE_ARRAY);
        
        e.getPresentation().setEnabledAndVisible(
            project != null && files != null && files.length > 0
        );
    }
} 