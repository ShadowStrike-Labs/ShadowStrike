/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * Copyright (C) 2026 ShadowStrike Security
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published
 * by the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 */
#pragma once

#include <QObject>
#include <QVariantList>
#include <memory>

namespace ShadowStrike::PhantomHome::UI::ViewModels {

class ZeroTrustViewModel final : public QObject {
    Q_OBJECT
    Q_PROPERTY(double threshold READ threshold WRITE setThreshold NOTIFY thresholdChanged)
    Q_PROPERTY(bool zeroTrustModeActive READ zeroTrustModeActive WRITE setZeroTrustModeActive NOTIFY zeroTrustModeActiveChanged)
    Q_PROPERTY(bool requirePublisherSigned READ requirePublisherSigned WRITE setRequirePublisherSigned NOTIFY requirePublisherSignedChanged)
    Q_PROPERTY(bool requireWhitelist READ requireWhitelist WRITE setRequireWhitelist NOTIFY requireWhitelistChanged)
    Q_PROPERTY(double minReputation READ minReputation WRITE setMinReputation NOTIFY minReputationChanged)
    Q_PROPERTY(double minStaticBenign READ minStaticBenign WRITE setMinStaticBenign NOTIFY minStaticBenignChanged)
    Q_PROPERTY(int uncertainBehavior READ uncertainBehavior WRITE setUncertainBehavior NOTIFY uncertainBehaviorChanged)
    Q_PROPERTY(QVariantList prompts READ prompts NOTIFY promptsChanged)

public:
    explicit ZeroTrustViewModel(QObject* parent = nullptr);
    ~ZeroTrustViewModel() override;

    [[nodiscard]] double threshold() const noexcept;
    [[nodiscard]] bool zeroTrustModeActive() const noexcept;
    [[nodiscard]] bool requirePublisherSigned() const noexcept;
    [[nodiscard]] bool requireWhitelist() const noexcept;
    [[nodiscard]] double minReputation() const noexcept;
    [[nodiscard]] double minStaticBenign() const noexcept;
    [[nodiscard]] int uncertainBehavior() const noexcept;
    [[nodiscard]] QVariantList prompts() const;

    void setThreshold(double value);
    void setZeroTrustModeActive(bool value);
    void setRequirePublisherSigned(bool value);
    void setRequireWhitelist(bool value);
    void setMinReputation(double value);
    void setMinStaticBenign(double value);
    void setUncertainBehavior(int value);

    Q_INVOKABLE void refresh();
    Q_INVOKABLE void answerPrompt(const QVariant& promptId, const QString& choice);

signals:
    void thresholdChanged();
    void zeroTrustModeActiveChanged();
    void requirePublisherSignedChanged();
    void requireWhitelistChanged();
    void minReputationChanged();
    void minStaticBenignChanged();
    void uncertainBehaviorChanged();
    void promptsChanged();
    void requestError(QString code, QString message);

private:
    struct Impl;
    std::unique_ptr<Impl> m_impl;

    void applyPayload(const QJsonObject& payload);
    void sendConfig();
};

} // namespace ShadowStrike::PhantomHome::UI::ViewModels
