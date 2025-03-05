package com.redaction.settings;

import com.intellij.openapi.components.*;
import com.intellij.openapi.project.Project;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;

@State(
    name = "RedactionSettings",
    storages = {@Storage("redactionSettings.xml")}
)
@Service
public final class RedactionSettings implements PersistentStateComponent<RedactionSettings.State> {
    public static class State {
        public boolean maskIpAddress = true;
        public boolean maskDbUrl = true;
        public boolean maskPassword = true;
        public boolean maskApiKey = true;
    }

    private State state = new State();

    public static RedactionSettings getInstance(@NotNull Project project) {
        return project.getService(RedactionSettings.class);
    }

    @Nullable
    @Override
    public State getState() {
        return state;
    }

    @Override
    public void loadState(@NotNull State state) {
        this.state = state;
    }

    public boolean isMaskIpAddress() {
        return state.maskIpAddress;
    }

    public void setMaskIpAddress(boolean maskIpAddress) {
        state.maskIpAddress = maskIpAddress;
    }

    public boolean isMaskDbUrl() {
        return state.maskDbUrl;
    }

    public void setMaskDbUrl(boolean maskDbUrl) {
        state.maskDbUrl = maskDbUrl;
    }

    public boolean isMaskPassword() {
        return state.maskPassword;
    }

    public void setMaskPassword(boolean maskPassword) {
        state.maskPassword = maskPassword;
    }

    public boolean isMaskApiKey() {
        return state.maskApiKey;
    }

    public void setMaskApiKey(boolean maskApiKey) {
        state.maskApiKey = maskApiKey;
    }
} 