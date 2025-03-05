package com.redaction.action;

import com.intellij.openapi.actionSystem.AnAction;
import com.intellij.openapi.actionSystem.AnActionEvent;
import com.intellij.openapi.progress.ProgressIndicator;
import com.intellij.openapi.progress.ProgressManager;
import com.intellij.openapi.progress.Task;
import com.intellij.openapi.project.Project;
import com.intellij.openapi.ui.Messages;
import com.intellij.openapi.application.ApplicationManager;
import com.redaction.service.SensitiveDataService;
import org.jetbrains.annotations.NotNull;

public class MaskAllProjectFilesAction extends AnAction {

    @Override
    public void actionPerformed(@NotNull AnActionEvent e) {
        Project project = e.getProject();
        if (project == null) return;

        int answer = Messages.showYesNoDialog(
            project,
            "这将会脱敏项目中所有配置文件中的敏感信息。是否继续？",
            "确认脱敏",
            "开始脱敏",
            "取消",
            Messages.getQuestionIcon()
        );

        if (answer == Messages.YES) {
            ProgressManager.getInstance().run(new Task.Backgroundable(project, "正在脱敏配置文件...", false) {
                @Override
                public void run(@NotNull ProgressIndicator indicator) {
                    try {
                        indicator.setIndeterminate(false);
                        indicator.setText("正在扫描配置文件...");
                        
                        SensitiveDataService service = project.getService(SensitiveDataService.class);
                        service.maskAllProjectFiles();
                        
                        indicator.setText("脱敏完成");
                        
                        ApplicationManager.getApplication().invokeLater(() -> {
                            Messages.showInfoMessage(project, 
                                "项目配置文件脱敏完成！\n" +
                                "请检查版本控制系统中的更改，确认脱敏结果。", 
                                "脱敏完成");
                        });
                    } catch (Exception ex) {
                        ApplicationManager.getApplication().invokeLater(() -> {
                            Messages.showErrorDialog(project,
                                "处理文件时发生错误：" + ex.getMessage(),
                                "脱敏错误");
                        });
                    }
                }
            });
        }
    }

    @Override
    public void update(@NotNull AnActionEvent e) {
        Project project = e.getProject();
        e.getPresentation().setEnabledAndVisible(project != null);
    }
} 