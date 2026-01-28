import re
import sys

def update_hpp():
    path = 'src/Communication/IPCManager.hpp'
    try:
        with open(path, 'r', encoding='utf-8') as f:
            content = f.read()
    except:
        with open(path, 'r', encoding='latin-1') as f:
            content = f.read()

    # 1. Add Includes
    if 'Drivers/Shared/MessageProtocol.h' not in content:
        includes = '#include "../Utils/SystemUtils.hpp"\n\n#include "../../Drivers/Shared/MessageProtocol.h"\n#include "../../Drivers/Shared/MessageTypes.h"\n#include "../../Drivers/Shared/VerdictTypes.h"\n#include "../../Drivers/Shared/PortName.h"'
        content = content.replace('#include "../Utils/SystemUtils.hpp"', includes)

    # 2. Update Constants
    content = re.sub(
        r'inline constexpr const wchar_t\* FILTER_PORT_NAME = L"\\ShadowStrikePort";',
        r'inline constexpr const wchar_t* FILTER_PORT_NAME = SHADOWSTRIKE_PORT_NAME;',
        content
    )

    # 3. Handle CommandType Enum
    # Replace usages first to avoid conflict when commenting out
    # But usages are "CommandType::Value". Shared types are "MessageType_Value".
    # Since we are modifying HPP, we care about function signatures mostly.
    # "void Foo(CommandType type)" -> "void Foo(SHADOWSTRIKE_MESSAGE_TYPE type)"
    
    content = content.replace('CommandType', 'SHADOWSTRIKE_MESSAGE_TYPE')
    
    # Now the enum definition looks like "enum class SHADOWSTRIKE_MESSAGE_TYPE ..."
    # We want to comment it out.
    content = re.sub(
        r'enum class SHADOWSTRIKE_MESSAGE_TYPE : uint32_t \{[\s\S]*?\};',
        r'// enum class CommandType replaced by SHADOWSTRIKE_MESSAGE_TYPE from shared headers',
        content
    )

    # 4. Handle KernelVerdict Enum
    content = content.replace('KernelVerdict', 'SHADOWSTRIKE_SCAN_VERDICT')
    content = re.sub(
        r'enum class SHADOWSTRIKE_SCAN_VERDICT : uint32_t \{[\s\S]*?\};',
        r'// enum class KernelVerdict replaced by SHADOWSTRIKE_SCAN_VERDICT from shared headers',
        content
    )

    # 5. Handle Structs
    # KernelRequestHeader
    content = content.replace('KernelRequestHeader', 'FILTER_MESSAGE_HEADER')
    content = re.sub(
        r'struct FILTER_MESSAGE_HEADER \{[\s\S]*?\};',
        r'// struct KernelRequestHeader replaced by FILTER_MESSAGE_HEADER',
        content
    )

    # FileScanRequest
    content = content.replace('FileScanRequest', 'FILE_SCAN_REQUEST')
    content = re.sub(
        r'struct FILE_SCAN_REQUEST \{[\s\S]*?\};',
        r'// struct FileScanRequest replaced by FILE_SCAN_REQUEST',
        content
    )
    
    # KernelReply
    content = content.replace('KernelReply', 'SCAN_VERDICT_REPLY')
    content = re.sub(
        r'struct SCAN_VERDICT_REPLY \{[\s\S]*?\};',
        r'// struct KernelReply replaced by SCAN_VERDICT_REPLY',
        content
    )

    # 6. Fix remaining usages
    # "FILTER_MESSAGE_HEADER header;" -> correct
    # "CommandType command = CommandType::None;" -> "SHADOWSTRIKE_MESSAGE_TYPE command = MessageType_None;"
    # But we replaced CommandType with SHADOWSTRIKE_MESSAGE_TYPE already.
    # So it looks like "SHADOWSTRIKE_MESSAGE_TYPE command = SHADOWSTRIKE_MESSAGE_TYPE::None;"
    # This is wrong.
    
    content = content.replace('SHADOWSTRIKE_MESSAGE_TYPE::None', 'MessageType_None')
    
    # Also fix stats array
    content = content.replace('byCommandType', 'byMessageType')
    
    # Fix macro
    content = re.sub(
        r'#define SS_IPC_SEND_VERDICT\(msgId, verdict\) \[\s\S]*?0\)',
        r'// SS_IPC_SEND_VERDICT macro removed',
        content
    )

    with open(path, 'w', encoding='utf-8') as f:
        f.write(content)

if __name__ == '__main__':
    update_hpp()
