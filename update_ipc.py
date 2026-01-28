import re
import os

# Paths
hpp_path = 'src/Communication/IPCManager.hpp'
cpp_path = 'src/Communication/IPCManager.cpp'

# Read files
with open(hpp_path, 'r') as f:
    hpp_content = f.read()
with open(cpp_path, 'r') as f:
    cpp_content = f.read()

# --- Update HPP ---

# 1. Update Constants
hpp_content = re.sub(
    r'inline constexpr const wchar_t\* FILTER_PORT_NAME = L"\ShadowStrikePort";',
    r'inline constexpr const wchar_t* FILTER_PORT_NAME = SHADOWSTRIKE_PORT_NAME;',
    hpp_content
)

# 2. Update Enums
# We need to replace CommandType with SHADOWSTRIKE_MESSAGE_TYPE or alias it.
# To allow compilation of other parts of the system that might use CommandType, maybe alias?
# But instructions say "Update member functions to use the shared types".
# So I should remove CommandType and KernelVerdict.

# Remove CommandType enum definition
hpp_content = re.sub(
    r'enum class CommandType : uint32_t \{[\s\S]*?\};',
    r'// CommandType replaced by SHADOWSTRIKE_MESSAGE_TYPE from shared headers',
    hpp_content
)

# Remove KernelVerdict enum definition
hpp_content = re.sub(
    r'enum class KernelVerdict : uint32_t \{[\s\S]*?\};',
    r'// KernelVerdict replaced by SHADOWSTRIKE_SCAN_VERDICT from shared headers',
    hpp_content
)

# 3. Update Structs
# Remove KernelRequestHeader
hpp_content = re.sub(
    r'struct KernelRequestHeader \{[\s\S]*?\};',
    r'// KernelRequestHeader replaced by FILTER_MESSAGE_HEADER',
    hpp_content
)

# Remove FileScanRequest
hpp_content = re.sub(
    r'struct FileScanRequest \{[\s\S]*?\};',
    r'// FileScanRequest replaced by FILE_SCAN_REQUEST',
    hpp_content
)

# Remove KernelReply
hpp_content = re.sub(
    r'struct KernelReply \{[\s\S]*?\};',
    r'// KernelReply replaced by SCAN_VERDICT_REPLY',
    hpp_content
)

# Update other structs to use FILTER_MESSAGE_HEADER
hpp_content = hpp_content.replace('KernelRequestHeader header;', 'FILTER_MESSAGE_HEADER header;')

# 4. Update Function Signatures
hpp_content = hpp_content.replace('FileScanRequest', 'FILE_SCAN_REQUEST')
hpp_content = hpp_content.replace('KernelVerdict', 'SHADOWSTRIKE_SCAN_VERDICT')
hpp_content = hpp_content.replace('CommandType', 'SHADOWSTRIKE_MESSAGE_TYPE')

# 5. Fix Callbacks
# FileScanCallback: std::function<KernelVerdict(const FileScanRequest&)>
# Becomes: std::function<SHADOWSTRIKE_SCAN_VERDICT(const FILE_SCAN_REQUEST&)>
# This was handled by string replacements above.

# 6. Update GenericMessageCallback
# void(CommandType, const void*, size_t) -> void(SHADOWSTRIKE_MESSAGE_TYPE, const void*, size_t)
# Handled by replacement.

# 7. Update GetCommandTypeName and GetVerdictName signatures
# Handled by replacement.

# --- Update CPP ---

# 1. Update ConnectFilterPort logic if it hardcodes the name (it uses the constant, so just hpp change is enough there).
# But wait, we need to check if it uses FilterConnectCommunicationPort with the constant.

# 2. Update DispatchMessage logic.
# It likely switches on CommandType.
# We need to map CommandType::ScanFile to MessageType_FileScanRequest.

# Replace CommandType::... with MessageType_...
replacements = {
    'CommandType::None': 'MessageType_None',
    'CommandType::ScanFile': 'MessageType_FileScanRequest',
    'CommandType::Handshake': 'MessageType_Register', # Best guess
    'CommandType::Heartbeat': 'MessageType_Heartbeat',
    'CommandType::Configure': 'MessageType_ConfigUpdate',
    # Others don't exist in shared yet, so we might need to comment them out or map to None for now?
    # Or keep the old enum for internal logic?
    # No, we removed the enum definition.
    # The shared header has: Register, Unregister, Heartbeat, FileScanRequest, FileScanVerdict, ConfigUpdate, ThreatDetected.
    # It does NOT have ProcessCreate, ImageLoad, RegistryOp.
    # This is a problem. The instructions say "Unifying the Message Protocol".
    # If I remove CommandType, I break Process/Image/Registry handlers.
    # I should probably ADD the missing types to the Shared Header?
    # "Modify IPCManager.hpp to... Remove any local struct definitions that duplicate the shared ones".
    # It implies I should keep the ones that are NOT duplicated.
    # But I replaced CommandType entirely.
    # I should probably EXTEND SHADOWSTRIKE_MESSAGE_TYPE in the shared header?
    # "Your Task: Modify IPCManager.hpp... Modify IPCManager.cpp...".
    # I am not explicitly told to modify the shared headers. "We have created shared headers...".
    # I should assume the shared headers are the source of truth for the *Protocol*.
    # If the shared headers don't have ProcessCreate, maybe those features are not part of this phase or I should use a generic type?
    # Or, I should define  to include the shared types AND the local types?
    # But  uses .
    # I will stick to what is in shared headers for the Unified Protocol parts.
    # For the parts NOT in shared headers (Process, Image, Registry), I will comment them out or #if 0 them in the switch case, 
    # OR I will just map them to 'MessageType_Max + N' if I really want to keep the code compiling.
    # But the instructions are specific about Unifying.
    # I will comment out the handlers for message types that don't exist in the shared protocol yet, 
    # assuming this phase is focusing on File Scan.
    
    'CommandType::ProcessCreate': 'MessageType_None /* TODO: Add to shared */',
    'CommandType::ProcessTerminate': 'MessageType_None /* TODO: Add to shared */',
    'CommandType::ImageLoad': 'MessageType_None /* TODO: Add to shared */',
    'CommandType::RegistryOp': 'MessageType_None /* TODO: Add to shared */',
    'KernelVerdict::Allow': 'Verdict_Clean',
    'KernelVerdict::Block': 'Verdict_Malicious',
    'KernelVerdict::Quarantine': 'Verdict_Malicious', # Mapping to malicious for now
    'KernelVerdict::Pending': 'Verdict_Unknown',
    'KernelVerdict::Defer': 'Verdict_Unknown',
    'KernelVerdict::Log': 'Verdict_Clean',
    'IPCConstants::FILTER_PORT_NAME': 'SHADOWSTRIKE_PORT_NAME'
}

for old, new in replacements.items():
    cpp_content = cpp_content.replace(old, new)

# 3. Update DispatchMessage structure parsing
# Old: auto* header = reinterpret_cast<KernelRequestHeader*>(buffer);
# New: auto* header = reinterpret_cast<FILTER_MESSAGE_HEADER*>(buffer);
cpp_content = cpp_content.replace('KernelRequestHeader', 'FILTER_MESSAGE_HEADER')

# 4. Update Reply logic
# Old: KernelReply reply; reply.verdict = ...;
# New: SCAN_VERDICT_REPLY reply; reply.Verdict = ...;
# We need to find where KernelReply is used and replace it.

# Regex to find the reply construction block in WorkerRoutine or DispatchMessage
# It's likely in SendToKernel or a specific Reply function.
# Or inside the handler calling code.

# Let's handle generic text replacements for member access
cpp_content = cpp_content.replace('header->messageId', 'header->MessageId')
cpp_content = cpp_content.replace('header->payloadSize', 'header->DataLength')
cpp_content = cpp_content.replace('header->command', 'header->MessageType')
cpp_content = cpp_content.replace('header->timestamp', 'header->Timestamp')

# FileScanRequest accessors
cpp_content = cpp_content.replace('request.header.messageId', 'header->MessageId'
