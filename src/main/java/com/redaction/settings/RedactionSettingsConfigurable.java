package com.redaction.settings;

import com.intellij.openapi.options.Configurable;
import com.intellij.openapi.options.ConfigurationException;
import com.intellij.openapi.project.Project;
import com.intellij.ui.components.JBCheckBox;
import com.intellij.util.ui.FormBuilder;
import org.jetbrains.annotations.Nls;
import org.jetbrains.annotations.Nullable;

import javax.swing.*;

/**
 * 敏感数据脱敏设置界面配置类
 * 
 * 该类负责创建和管理插件的设置界面，允许用户自定义：
 * - 需要脱敏的数据类型
 * - 脱敏规则的启用/禁用
 * 
 * 设置界面集成在 IntelliJ IDEA 的设置面板中，
 * 可通过 Settings/Preferences -> Tools -> Sensitive Data Masking Settings 访问
 *
 * @version 1.0.0
 */
public class RedactionSettingsConfigurable implements Configurable {
    private final Project project;
    
    /**
     * 界面组件：控制是否脱敏IP地址
     */
    private JBCheckBox maskIpAddressCheckBox;
    
    /**
     * 界面组件：控制是否脱敏数据库URL
     */
    private JBCheckBox maskDbUrlCheckBox;
    
    /**
     * 界面组件：控制是否脱敏密码信息
     */
    private JBCheckBox maskPasswordCheckBox;
    
    /**
     * 界面组件：控制是否脱敏API密钥
     */
    private JBCheckBox maskApiKeyCheckBox;

    /**
     * 构造函数
     * @param project 当前项目实例
     */
    public RedactionSettingsConfigurable(Project project) {
        this.project = project;
    }

    /**
     * 获取设置页面的显示名称
     * @return 设置页面标题
     */
    @Nls(capitalization = Nls.Capitalization.Title)
    @Override
    public String getDisplayName() {
        return "Sensitive Data Masking Settings";
    }

    /**
     * 创建设置界面组件
     * 
     * 创建包含以下选项的设置面板：
     * - IP地址脱敏选项
     * - 数据库URL脱敏选项
     * - 密码脱敏选项
     * - API密钥脱敏选项
     * 
     * @return 设置界面面板
     */
    @Override
    public @Nullable JComponent createComponent() {
        maskIpAddressCheckBox = new JBCheckBox("Mask IP Addresses");
        maskDbUrlCheckBox = new JBCheckBox("Mask Database URLs");
        maskPasswordCheckBox = new JBCheckBox("Mask Passwords");
        maskApiKeyCheckBox = new JBCheckBox("Mask API Keys");

        JPanel panel = FormBuilder.createFormBuilder()
                .addComponent(new JLabel("Select which types of sensitive data to mask:"))
                .addComponent(maskIpAddressCheckBox)
                .addComponent(maskDbUrlCheckBox)
                .addComponent(maskPasswordCheckBox)
                .addComponent(maskApiKeyCheckBox)
                .addComponentFillVertically(new JPanel(), 0)
                .getPanel();

        loadSettings();
        return panel;
    }

    /**
     * 从持久化存储加载设置
     */
    private void loadSettings() {
        RedactionSettings settings = RedactionSettings.getInstance(project);
        maskIpAddressCheckBox.setSelected(settings.isMaskIpAddress());
        maskDbUrlCheckBox.setSelected(settings.isMaskDbUrl());
        maskPasswordCheckBox.setSelected(settings.isMaskPassword());
        maskApiKeyCheckBox.setSelected(settings.isMaskApiKey());
    }

    /**
     * 检查设置是否被修改
     * @return 如果设置被修改返回true，否则返回false
     */
    @Override
    public boolean isModified() {
        RedactionSettings settings = RedactionSettings.getInstance(project);
        return maskIpAddressCheckBox.isSelected() != settings.isMaskIpAddress() ||
               maskDbUrlCheckBox.isSelected() != settings.isMaskDbUrl() ||
               maskPasswordCheckBox.isSelected() != settings.isMaskPassword() ||
               maskApiKeyCheckBox.isSelected() != settings.isMaskApiKey();
    }

    /**
     * 应用设置变更
     * 将界面上的设置保存到持久化存储
     */
    @Override
    public void apply() throws ConfigurationException {
        RedactionSettings settings = RedactionSettings.getInstance(project);
        settings.setMaskIpAddress(maskIpAddressCheckBox.isSelected());
        settings.setMaskDbUrl(maskDbUrlCheckBox.isSelected());
        settings.setMaskPassword(maskPasswordCheckBox.isSelected());
        settings.setMaskApiKey(maskApiKeyCheckBox.isSelected());
    }

    /**
     * 重置设置到上次保存的状态
     */
    @Override
    public void reset() {
        loadSettings();
    }
} 