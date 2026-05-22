/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * Copyright (C) 2026 ShadowStrike Security
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published
 * by the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 */

#include "ZeroTrustViewModel.hpp"

#include <utility>

#include <QJsonArray>
#include <QJsonObject>
#include <QJsonValue>
#include <QPointer>
#include <QtGlobal>

#include "../IPC/PipeClient.hpp"

using namespace ShadowStrike::PhantomHome::UI::IPC;
using ShadowStrike::Service::CommandType;

namespace ShadowStrike::PhantomHome::UI::ViewModels {

namespace {

[[nodiscard]] int UiBehaviorFromWire(int wire) noexcept
{
    if (wire == 2) return 1; // Prompt
    if (wire == 1) return 2; // SilentBlock
    return 0;                // SilentAllow
}

[[nodiscard]] int WireBehaviorFromUi(int ui) noexcept
{
    if (ui == 1) return 2; // Prompt
    if (ui == 2) return 1; // SilentBlock
    return 0;              // SilentAllow
}

[[nodiscard]] double Clamp01(double value) noexcept
{
    if (value < 0.0) return 0.0;
    if (value > 1.0) return 1.0;
    return value;
}

} // namespace

struct ZeroTrustViewModel::Impl {
    double threshold{0.75};
    bool zeroTrustModeActive{false};
    bool requirePublisherSigned{true};
    bool requireWhitelist{false};
    double minReputation{0.60};
    double minStaticBenign{0.70};
    int uncertainBehavior{1};
    QVariantList prompts;
};

ZeroTrustViewModel::ZeroTrustViewModel(QObject* parent)
    : QObject(parent)
    , m_impl(std::make_unique<Impl>())
{
    refresh();
}

ZeroTrustViewModel::~ZeroTrustViewModel() = default;

double ZeroTrustViewModel::threshold() const noexcept { return m_impl->threshold; }
bool ZeroTrustViewModel::zeroTrustModeActive() const noexcept { return m_impl->zeroTrustModeActive; }
bool ZeroTrustViewModel::requirePublisherSigned() const noexcept { return m_impl->requirePublisherSigned; }
bool ZeroTrustViewModel::requireWhitelist() const noexcept { return m_impl->requireWhitelist; }
double ZeroTrustViewModel::minReputation() const noexcept { return m_impl->minReputation; }
double ZeroTrustViewModel::minStaticBenign() const noexcept { return m_impl->minStaticBenign; }
int ZeroTrustViewModel::uncertainBehavior() const noexcept { return m_impl->uncertainBehavior; }
QVariantList ZeroTrustViewModel::prompts() const { return m_impl->prompts; }

void ZeroTrustViewModel::setThreshold(double value)
{
    value = Clamp01(value);
    if (qFuzzyCompare(m_impl->threshold, value)) return;
    m_impl->threshold = value;
    emit thresholdChanged();
    sendConfig();
}

void ZeroTrustViewModel::setZeroTrustModeActive(bool value)
{
    if (m_impl->zeroTrustModeActive == value) return;
    m_impl->zeroTrustModeActive = value;
    emit zeroTrustModeActiveChanged();
    sendConfig();
}

void ZeroTrustViewModel::setRequirePublisherSigned(bool value)
{
    if (m_impl->requirePublisherSigned == value) return;
    m_impl->requirePublisherSigned = value;
    emit requirePublisherSignedChanged();
    sendConfig();
}

void ZeroTrustViewModel::setRequireWhitelist(bool value)
{
    if (m_impl->requireWhitelist == value) return;
    m_impl->requireWhitelist = value;
    emit requireWhitelistChanged();
    sendConfig();
}

void ZeroTrustViewModel::setMinReputation(double value)
{
    value = Clamp01(value);
    if (qFuzzyCompare(m_impl->minReputation, value)) return;
    m_impl->minReputation = value;
    emit minReputationChanged();
    sendConfig();
}

void ZeroTrustViewModel::setMinStaticBenign(double value)
{
    value = Clamp01(value);
    if (qFuzzyCompare(m_impl->minStaticBenign, value)) return;
    m_impl->minStaticBenign = value;
    emit minStaticBenignChanged();
    sendConfig();
}

void ZeroTrustViewModel::setUncertainBehavior(int value)
{
    if (value < 0 || value > 2) value = 1;
    if (m_impl->uncertainBehavior == value) return;
    m_impl->uncertainBehavior = value;
    emit uncertainBehaviorChanged();
    sendConfig();
}

void ZeroTrustViewModel::refresh()
{
    (void)PipeClient::Instance().SendAndExpect(
        CommandType::GetZeroTrustState,
        {},
        [self = QPointer<ZeroTrustViewModel>(this)](const Response& r) {
            if (!self) return;
            if (!r.ok) {
                emit self->requestError(r.errorCode, r.errorMessage);
                return;
            }
            self->applyPayload(r.payload);
        });
}

void ZeroTrustViewModel::answerPrompt(const QVariant& promptId, const QString& choice)
{
    const QString id = promptId.toString();
    if (id.isEmpty() || choice.isEmpty()) {
        emit requestError(QStringLiteral("invalid_prompt"), QStringLiteral("Prompt id and choice are required"));
        return;
    }

    (void)PipeClient::Instance().SendAndExpect(
        CommandType::AnswerZeroTrustPrompt,
        QJsonObject{{QLatin1String("id"), id}, {QLatin1String("choice"), choice}},
        [self = QPointer<ZeroTrustViewModel>(this)](const Response& r) {
            if (!self) return;
            if (!r.ok) {
                emit self->requestError(r.errorCode, r.errorMessage);
                return;
            }
            self->refresh();
        });
}

void ZeroTrustViewModel::applyPayload(const QJsonObject& payload)
{
    const double nextThreshold = Clamp01(payload.value(QLatin1String("threshold")).toDouble(m_impl->threshold));
    if (!qFuzzyCompare(m_impl->threshold, nextThreshold)) {
        m_impl->threshold = nextThreshold;
        emit thresholdChanged();
    }

    const bool nextZeroTrust = payload.value(QLatin1String("zeroTrustMode")).toBool(m_impl->zeroTrustModeActive);
    if (m_impl->zeroTrustModeActive != nextZeroTrust) {
        m_impl->zeroTrustModeActive = nextZeroTrust;
        emit zeroTrustModeActiveChanged();
    }

    const bool nextSigned = payload.value(QLatin1String("requirePublisherSigned")).toBool(m_impl->requirePublisherSigned);
    if (m_impl->requirePublisherSigned != nextSigned) {
        m_impl->requirePublisherSigned = nextSigned;
        emit requirePublisherSignedChanged();
    }

    const bool nextWhitelist = payload.value(QLatin1String("requireWhitelist")).toBool(m_impl->requireWhitelist);
    if (m_impl->requireWhitelist != nextWhitelist) {
        m_impl->requireWhitelist = nextWhitelist;
        emit requireWhitelistChanged();
    }

    const double nextReputation = Clamp01(payload.value(QLatin1String("minReputation")).toDouble(m_impl->minReputation));
    if (!qFuzzyCompare(m_impl->minReputation, nextReputation)) {
        m_impl->minReputation = nextReputation;
        emit minReputationChanged();
    }

    const double nextStatic = Clamp01(payload.value(QLatin1String("minStaticBenign")).toDouble(m_impl->minStaticBenign));
    if (!qFuzzyCompare(m_impl->minStaticBenign, nextStatic)) {
        m_impl->minStaticBenign = nextStatic;
        emit minStaticBenignChanged();
    }

    const int nextBehavior = UiBehaviorFromWire(payload.value(QLatin1String("uncertainBehavior")).toInt(
        WireBehaviorFromUi(m_impl->uncertainBehavior)));
    if (m_impl->uncertainBehavior != nextBehavior) {
        m_impl->uncertainBehavior = nextBehavior;
        emit uncertainBehaviorChanged();
    }

    QVariantList prompts;
    const QJsonArray promptArray = payload.value(QLatin1String("prompts")).toArray();
    prompts.reserve(promptArray.size());
    for (const QJsonValue& value : promptArray) {
        prompts.append(value.toObject().toVariantMap());
    }
    m_impl->prompts = std::move(prompts);
    emit promptsChanged();
}

void ZeroTrustViewModel::sendConfig()
{
    (void)PipeClient::Instance().SendAndExpect(
        CommandType::SetZeroTrustConfig,
        QJsonObject{
            {QLatin1String("threshold"), m_impl->threshold},
            {QLatin1String("requirePublisherSigned"), m_impl->requirePublisherSigned},
            {QLatin1String("requireWhitelist"), m_impl->requireWhitelist},
            {QLatin1String("minReputation"), m_impl->minReputation},
            {QLatin1String("minStaticBenign"), m_impl->minStaticBenign},
            {QLatin1String("uncertainBehavior"), WireBehaviorFromUi(m_impl->uncertainBehavior)},
            {QLatin1String("zeroTrustMode"), m_impl->zeroTrustModeActive}},
        [self = QPointer<ZeroTrustViewModel>(this)](const Response& r) {
            if (!self) return;
            if (!r.ok) {
                emit self->requestError(r.errorCode, r.errorMessage);
                self->refresh();
            }
        });
}

} // namespace ShadowStrike::PhantomHome::UI::ViewModels
