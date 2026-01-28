import re
import sys

def update_cpp():
    path = 'src/Communication/IPCManager.cpp'
    try:
        with open(path, 'r', encoding='utf-8') as f:
            content = f.read()
    except:
        with open(path, 'r', encoding='latin-1') as f:
            content = f.read()

    # 1. Update DispatchMessage Implementation
    dispatch_message_new = """void IPCManager::DispatchMessage(uint8_t* buffer, uint64_t messageId) {
    // Parse message structure
    // FILTER_MESSAGE_HEADER is at the beginning
    if (!buffer) return;
    
    PFILTER_MESSAGE_HEADER pHeader = reinterpret_cast<PFILTER_MESSAGE_HEADER>(buffer);
    
    // Payload follows the header
    uint8_t* pPayload = buffer + sizeof(FILTER_MESSAGE_HEADER);

    SHADOWSTRIKE_SCAN_VERDICT verdict = Verdict_Unknown;
    bool handled = false;

    // Lock handlers for the duration of dispatch
    std::lock_guard lock(m_handlerMutex);

    switch (pHeader->MessageType) {
        case MessageType_FileScanRequest: {
            if (m_fileScanHandler) {
                // Ensure we have enough data
                if (pHeader->DataLength < sizeof(FILE_SCAN_REQUEST)) {
                    Utils::Logger::Error("[IPCManager] Invalid payload length for FileScanRequest");
                    break;
                }
                
                PFILE_SCAN_REQUEST req = reinterpret_cast<PFILE_SCAN_REQUEST>(pPayload);
                try {
                    // Handler returns SHADOWSTRIKE_SCAN_VERDICT
                    verdict = m_fileScanHandler(*req);
                    handled = true;
                } catch (const std::exception& e) {
                    Utils::Logger::Error("[IPCManager] File scan handler exception: {}", e.what());
                    verdict = Verdict_Error;
                }
                
                // Reply
                if (handled) {
                     SCAN_VERDICT_REPLY reply = {0};
                     reply.MessageId = pHeader->MessageId;
                     reply.Verdict = verdict;
                     reply.ThreatLevel = (verdict == Verdict_Malicious) ? 100 : 0;
                     // ThreatName left empty for now
                     
                     SendToKernel(&reply, sizeof(reply));
                }
                
                m_impl->stats.byMessageType[static_cast<size_t>(MessageType_FileScanRequest)]++;
            }
            break;
        }

        case MessageType_Register:
        case MessageType_Heartbeat:
            // Handle internal messages
            break;

        default:
            Utils::Logger::Warn("[IPCManager] Unknown message type: {}", static_cast<uint32_t>(pHeader->MessageType));
            break;
    }
}"""

    # Replace the existing DispatchMessage function
    content = re.sub(
        r'void IPCManager::DispatchMessage\(uint8_t\* buffer, uint64_t messageId\) \{[\s\S]*?^\}',
        dispatch_message_new,
        content,
        flags=re.MULTILINE
    )

    # 2. Rename GetCommandTypeName to GetMessageTypeName
    content = content.replace('GetCommandTypeName', 'GetMessageTypeName')
    
    # 3. Update GetMessageTypeName Implementation
    get_msg_type_impl = """std::string_view GetMessageTypeName(SHADOWSTRIKE_MESSAGE_TYPE type) noexcept {
    switch (type) {
        case MessageType_None: return "None";
        case MessageType_Register: return "Register";
        case MessageType_Unregister: return "Unregister";
        case MessageType_Heartbeat: return "Heartbeat";
        case MessageType_FileScanRequest: return "FileScanRequest";
        case MessageType_FileScanVerdict: return "FileScanVerdict";
        case MessageType_ConfigUpdate: return "ConfigUpdate";
        case MessageType_ThreatDetected: return "ThreatDetected";
        default: return "Unknown";
    }
}"""
    content = re.sub(
        r'std::string_view GetMessageTypeName\(SHADOWSTRIKE_MESSAGE_TYPE type\) noexcept \{[\s\S]*?^\}',
        get_msg_type_impl,
        content,
        flags=re.MULTILINE
    )
    # Note: Regex above uses the NEW name because we did replace() in step 2. 
    # But wait, step 2 replaced usages, but also definition signature? 
    # Yes, "std::string_view GetCommandTypeName(CommandType type)" -> "std::string_view GetMessageTypeName(CommandType type)"
    # So the regex should match "GetMessageTypeName\(CommandType type\)" actually, or allow any type.
    # Let's refine:
    content = re.sub(
        r'std::string_view GetMessageTypeName\(.*?\) noexcept \{[\s\S]*?^\}',
        get_msg_type_impl,
        content,
        flags=re.MULTILINE
    )


    # 4. Update GetVerdictName Implementation
    get_verdict_name_impl = """std::string_view GetVerdictName(SHADOWSTRIKE_SCAN_VERDICT verdict) noexcept {
    switch (verdict) {
        case Verdict_Unknown: return "Unknown";
        case Verdict_Clean: return "Clean";
        case Verdict_Malicious: return "Malicious";
        case Verdict_Suspicious: return "Suspicious";
        case Verdict_Error: return "Error";
        case Verdict_Timeout: return "Timeout";
        default: return "Invalid";
    }
}"""
    content = re.sub(
        r'std::string_view GetVerdictName\(.*?\) noexcept \{[\s\S]*?^\}',
        get_verdict_name_impl,
        content,
        flags=re.MULTILINE
    )

    # 5. Global Replacements
    content = content.replace('CommandType', 'SHADOWSTRIKE_MESSAGE_TYPE')
    content = content.replace('KernelVerdict', 'SHADOWSTRIKE_SCAN_VERDICT')
    content = content.replace('byCommandType', 'byMessageType')
    content = content.replace('IPCConstants::FILTER_PORT_NAME', 'SHADOWSTRIKE_PORT_NAME')
    
    # 6. Specific Enum Values
    content = content.replace('SHADOWSTRIKE_MESSAGE_TYPE::None', 'MessageType_None')
    content = content.replace('SHADOWSTRIKE_MESSAGE_TYPE::ScanFile', 'MessageType_FileScanRequest')
    content = content.replace('SHADOWSTRIKE_SCAN_VERDICT::Allow', 'Verdict_Clean')
    content = content.replace('SHADOWSTRIKE_SCAN_VERDICT::Block', 'Verdict_Malicious')
    
    # 7. Fix PendingReply
    content = content.replace('std::promise<SCAN_VERDICT_REPLY>', 'std::promise<SCAN_VERDICT_REPLY>') # Already correct if replaced properly
    # But KernelReply was replaced by SCAN_VERDICT_REPLY in HPP.
    # In CPP, "struct PendingReply { ... std::promise<KernelReply> promise; };"
    # We need to replace KernelReply with SCAN_VERDICT_REPLY here too.
    content = content.replace('KernelReply', 'SCAN_VERDICT_REPLY')
    
    with open(path, 'w', encoding='utf-8') as f:
        f.write(content)

if __name__ == '__main__':
    update_cpp()
