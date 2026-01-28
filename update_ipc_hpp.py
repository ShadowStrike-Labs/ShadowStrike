import re
import sys

def update_hpp():
    path = 'src/Communication/IPCManager.hpp'
    with open(path, 'r') as f:
        content = f.read()

    # 1. Update Constants
    content = re.sub(
        r'inline constexpr const wchar_t\* FILTER_PORT_NAME = L"\\ShadowStrikePort";',
        r'inline constexpr const wchar_t* FILTER_PORT_NAME = SHADOWSTRIKE_PORT_NAME;',
        content
    )

    # 2. Remove CommandType and KernelVerdict enums
    # We replace them with comments or using declarations if needed, 
    # but the instructions say update member functions to use shared types.
    
    # Remove CommandType
    content = re.sub(
        r'enum class CommandType : uint32_t \{[\s\S]*?\};',
        r'// CommandType replaced by SHADOWSTRIKE_MESSAGE_TYPE',
        content
    )
    
    # Remove KernelVerdict
    content = re.sub(
        r'enum class KernelVerdict : uint32_t \{[\s\S]*?\};',
        r'// KernelVerdict replaced by SHADOWSTRIKE_SCAN_VERDICT',
        content
    )

    # 3. Remove KernelRequestHeader
    content = re.sub(
        r'struct KernelRequestHeader \{[\s\S]*?\};',
        r'// KernelRequestHeader replaced by FILTER_MESSAGE_HEADER',
        content
    )

    # 4. Remove FileScanRequest
    content = re.sub(
        r'struct FileScanRequest \{[\s\S]*?\};',
        r'// FileScanRequest replaced by FILE_SCAN_REQUEST',
        content
    )

    # 5. Remove KernelReply
    content = re.sub(
        r'struct KernelReply \{[\s\S]*?\};',
        r'// KernelReply replaced by SCAN_VERDICT_REPLY',
        content
    )

    # 6. Update Struct members that used KernelRequestHeader
    # ProcessNotifyRequest, ImageLoadRequest, RegistryOpRequest
    content = content.replace('KernelRequestHeader header;', 'FILTER_MESSAGE_HEADER header;')

    # 7. Update Function Signatures and Member Variables
    
    # Replace CommandType with SHADOWSTRIKE_MESSAGE_TYPE
    content = content.replace('CommandType', 'SHADOWSTRIKE_MESSAGE_TYPE')
    
    # Replace KernelVerdict with SHADOWSTRIKE_SCAN_VERDICT
    content = content.replace('KernelVerdict', 'SHADOWSTRIKE_SCAN_VERDICT')
    
    # Replace FileScanRequest with FILE_SCAN_REQUEST
    content = content.replace('FileScanRequest', 'FILE_SCAN_REQUEST')
    
    # Fix GenericMessageCallback
    # void(CommandType, ...) -> void(SHADOWSTRIKE_MESSAGE_TYPE, ...)
    # (Handled by global replace above)

    # Fix GetVerdictName return type or arg?
    # std::string_view GetVerdictName(KernelVerdict verdict) -> (SHADOWSTRIKE_SCAN_VERDICT verdict)
    # (Handled by global replace above)

    # Fix macros
    # SS_IPC_SEND_VERDICT(msgId, verdict)
    # The macro takes 'verdict'. We need to make sure the caller passes the right type or the implementation handles it.
    # The implementation SendToKernel signature changes? No, it takes void*.
    # But the usage inside macro might change.
    # The macro content:
    # ::ShadowStrike::Communication::IPCManager::Instance().SendToKernel( \
    #    &(verdict), sizeof(verdict), nullptr, nullptr, 0)
    # If verdict is now SCAN_VERDICT_REPLY struct (which is large), this macro works.
    # If verdict was just an enum, this macro is wrong for the new protocol.
    # The new protocol expects SCAN_VERDICT_REPLY struct.
    # The macro seems to send just the verdict enum in the old code?
    # "struct KernelReply { KernelVerdict verdict; ... }"
    # The old code sent 'verdict' which was likely a KernelReply struct in usage?
    # Wait, the macro takes 'verdict'. If the user passes the struct, it's fine.
    
    with open(path, 'w') as f:
        f.write(content)

if __name__ == '__main__':
    update_hpp()
