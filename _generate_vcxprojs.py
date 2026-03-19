"""
Generate 3 product-specific .vcxproj files from ShadowStrike.vcxproj
and update the original vcxproj + sln.
"""
import xml.etree.ElementTree as ET
import uuid
import copy
import re
import os

NS = 'http://schemas.microsoft.com/developer/msbuild/2003'
ET.register_namespace('', NS)

def ns_tag(tag):
    return f'{{{NS}}}{tag}'

# ── Path classification ──────────────────────────────────────────────

# Case-insensitive prefix mapping: old_prefix_lower → (new_prefix, category)
# category: 'shared', 'home', 'edr', 'exclude', 'keep'
SHARED_MAP = {
    'antievasion':          'Shared_modules\\AntiEvasion',
    'communication':        'Shared_modules\\Communication',
    'config':               'Shared_modules\\Config',
    'core':                 'Shared_modules\\Core',
    'database':             'Shared_modules\\Database',
    'exploits':             'Shared_modules\\Exploits',
    'external':             'Shared_modules\\External',
    'fuzzyhasher':          'Shared_modules\\FuzzyHasher',
    'hashstore':            'Shared_modules\\HashStore',
    'patternstore':         'Shared_modules\\PatternStore',
    'peparser':             'Shared_modules\\PEParser',
    'performance':          'Shared_modules\\Performance',
    'ransomware':           'Shared_modules\\RansomwareProtection',
    'ransomwareprotection': 'Shared_modules\\RansomwareProtection',
    'realtime':             'Shared_modules\\RealTime',
    'scripts':              'Shared_modules\\Scripts',
    'security':             'Shared_modules\\Security',
    'service':              'Shared_modules\\Service',
    'signaturestore':       'Shared_modules\\SignatureStore',
    'threatintel':          'Shared_modules\\ThreatIntel',
    'update':               'Shared_modules\\Update',
    'utils':                'Shared_modules\\Utils',
    'whitelist':            'Shared_modules\\Whitelist',
    # Note: src\Drivers (user-space filter comms) is NOT in Shared_modules - handled separately
}

HOME_MAP = {
    'banking':      'Products\\PhantomHome\\Banking',
    'privacy':      'Products\\PhantomHome\\Privacy',
    'gamemode':     'Products\\PhantomHome\\GameMode',
    'webbrowser':   'Products\\PhantomHome\\WebProtection',
    'webprotection':'Products\\PhantomHome\\WebProtection',
    'email':        'Products\\PhantomHome\\Email',
    'cryptominers':             'Products\\PhantomHome\\CryptoMinersProtection',
    'cryptominersprotection':   'Products\\PhantomHome\\CryptoMinersProtection',
    'usb':              'Products\\PhantomHome\\USB_Protection',
    'usb_protection':   'Products\\PhantomHome\\USB_Protection',
    'iot':          'Products\\PhantomHome\\IoT',
    'backup':       'Products\\PhantomHome\\Backup',
}

EDR_MAP = {
    'forensics': 'Products\\PhantomEDR\\Forensics',
}

def classify_and_remap(include_path):
    """
    Returns (new_path, category) where category is one of:
    'shared', 'home', 'edr', 'include_hdr', 'root_src', 'exclude'
    """
    low = include_path.lower()
    sep = '\\'

    # Kernel driver entries (no src\ prefix)
    if low.startswith('drivers' + sep) or low.startswith('phantomsensor' + sep):
        return (include_path, 'exclude')

    # Test entries
    if low.startswith('tests' + sep):
        return (include_path, 'exclude')

    # Include headers (third-party libs)
    if low.startswith('include' + sep):
        return (include_path, 'include_hdr')

    # src\ files
    if low.startswith('src' + sep):
        rest = include_path[4:]  # after 'src\'
        rest_low = rest.lower()

        # Root-level files (Main.cpp, pch.cpp, pch.h)
        if sep not in rest:
            return (include_path, 'root_src')

        # Get the folder name (first component after src\)
        folder = rest.split(sep)[0]
        folder_low = folder.lower()
        remainder = rest[len(folder):]  # includes leading backslash + rest

        # src\Drivers\ is user-space filter communication code - keep path, shared
        if folder_low == 'drivers':
            return (include_path, 'shared')

        # Check EDR map first (more specific)
        if folder_low in EDR_MAP:
            new_path = 'src' + sep + EDR_MAP[folder_low] + remainder
            return (new_path, 'edr')

        # Check Home map
        if folder_low in HOME_MAP:
            new_path = 'src' + sep + HOME_MAP[folder_low] + remainder
            return (new_path, 'home')

        # Check Shared map
        if folder_low in SHARED_MAP:
            new_path = 'src' + sep + SHARED_MAP[folder_low] + remainder
            return (new_path, 'shared')

        # Unknown src\ folder - treat as shared, keep path
        print(f"  WARNING: Unknown src folder '{folder}' in '{include_path}' - keeping as-is, treating as shared")
        return (include_path, 'shared')

    # Anything else - keep as-is, exclude from products
    print(f"  WARNING: Unknown path '{include_path}' - excluding")
    return (include_path, 'exclude')


def remap_element(elem, new_path):
    """Create a copy of element with remapped Include path."""
    new_elem = copy.deepcopy(elem)
    new_elem.set('Include', new_path)
    return new_elem


def process_item_group(ig, product_categories):
    """
    Process an ItemGroup, returning (new_elements_remapped, is_source_group).
    product_categories: set of categories to include for this product.
    Returns list of (new_element) for elements that match the categories.
    """
    results = []
    is_source = False
    for child in ig:
        tag = child.tag.replace(f'{{{NS}}}', '')
        if tag in ('ClCompile', 'ClInclude', 'MASM', 'None'):
            is_source = True
            inc = child.get('Include', '')
            new_path, cat = classify_and_remap(inc)
            if cat in product_categories:
                results.append(remap_element(child, new_path))
    return results, is_source


def build_product_vcxproj(template_root, product_name, product_guid, product_categories):
    """Build a new vcxproj for a product."""
    new_root = copy.deepcopy(template_root)

    # Update ProjectGuid
    for pg in new_root.findall(f'.//{ns_tag("ProjectGuid")}'):
        pg.text = product_guid

    # Update OutputFile names in Link sections
    for link in new_root.findall(f'.//{ns_tag("Link")}'):
        for out_file in link.findall(ns_tag('OutputFile')):
            # Replace ShadowStrike with product name
            out_file.text = out_file.text.replace('ShadowStrike', product_name)

    # Process ItemGroups containing source files
    item_groups_to_remove = []
    item_groups_to_add = []

    for ig in new_root.findall(ns_tag('ItemGroup')):
        # Check if this is a source ItemGroup
        has_source = False
        for child in ig:
            tag = child.tag.replace(f'{{{NS}}}', '')
            if tag in ('ClCompile', 'ClInclude', 'MASM', 'None'):
                has_source = True
                break

        if has_source:
            results, _ = process_item_group(ig, product_categories)
            item_groups_to_remove.append(ig)
            if results:
                new_ig = ET.SubElement(new_root, ns_tag('ItemGroup'))
                for elem in results:
                    new_ig.append(elem)
                item_groups_to_add.append(new_ig)

    # Remove old source ItemGroups
    for ig in item_groups_to_remove:
        new_root.remove(ig)

    return new_root


# ── Main ─────────────────────────────────────────────────────────────

VCXPROJ_PATH = r'C:\ShadowStrike\ShadowStrike\ShadowStrike.vcxproj'
SLN_PATH = r'C:\ShadowStrike\ShadowStrike\ShadowStrike.sln'
OUT_DIR = r'C:\ShadowStrike\ShadowStrike'

# Parse original
tree = ET.parse(VCXPROJ_PATH)
root = tree.getroot()

# Generate GUIDs
guid_home = '{' + str(uuid.uuid4()).upper() + '}'
guid_edr = '{' + str(uuid.uuid4()).upper() + '}'
guid_xdr = '{' + str(uuid.uuid4()).upper() + '}'

print(f"PhantomHome GUID: {guid_home}")
print(f"PhantomEDR  GUID: {guid_edr}")
print(f"PhantomXDR  GUID: {guid_xdr}")

# Define what each product includes
# All products get: shared, include_hdr, root_src
# PhantomHome adds: home
# PhantomEDR adds: edr
# PhantomXDR adds: edr (superset)
home_cats = {'shared', 'include_hdr', 'root_src', 'home'}
edr_cats = {'shared', 'include_hdr', 'root_src', 'edr'}
xdr_cats = {'shared', 'include_hdr', 'root_src', 'edr', 'home'}  # XDR is superset of EDR + could include home? No...

# Wait - re-read the spec:
# PhantomXDR includes: src/Shared_modules/* + src/Products/PhantomEDR/* + src/Products/PhantomXDR/* + src/Main.cpp + src/pch.*
# So XDR includes shared + EDR modules but NOT home modules
xdr_cats = {'shared', 'include_hdr', 'root_src', 'edr'}  # same as EDR for now (no XDR-specific modules yet)

products = [
    ('PhantomHome', guid_home, home_cats),
    ('PhantomEDR', guid_edr, edr_cats),
    ('PhantomXDR', guid_xdr, xdr_cats),
]

# ── Generate product vcxproj files ───────────────────────────────────

for product_name, product_guid, cats in products:
    print(f"\n=== Generating {product_name}.vcxproj ===")
    new_root = build_product_vcxproj(root, product_name, product_guid, cats)

    # Write output
    out_path = os.path.join(OUT_DIR, f'{product_name}.vcxproj')
    new_tree = ET.ElementTree(new_root)
    ET.indent(new_tree, space='  ')
    new_tree.write(out_path, xml_declaration=True, encoding='utf-8')

    # Count entries
    ns_dict = {'m': NS}
    cc = new_root.findall(f'.//{ns_tag("ClCompile")}')
    ci = new_root.findall(f'.//{ns_tag("ClInclude")}')
    ma = new_root.findall(f'.//{ns_tag("MASM")}')
    print(f"  ClCompile: {len(cc)}, ClInclude: {len(ci)}, MASM: {len(ma)}")

# ── Update original ShadowStrike.vcxproj ─────────────────────────────
# Remap all src\ paths + remove kernel/test entries

print(f"\n=== Updating original ShadowStrike.vcxproj ===")
# The "updated original" should include everything from src\ (shared + all products)
# but exclude kernel driver (Drivers\, PhantomSensor\) and tests\
original_cats = {'shared', 'include_hdr', 'root_src', 'home', 'edr'}

updated_root = build_product_vcxproj(root, 'ShadowStrike', '{7E511BF5-F27B-BF5E-7FE3-AF087A6A05F1}', original_cats)

out_path = os.path.join(OUT_DIR, 'ShadowStrike.vcxproj')
updated_tree = ET.ElementTree(updated_root)
ET.indent(updated_tree, space='  ')
updated_tree.write(out_path, xml_declaration=True, encoding='utf-8')

cc = updated_root.findall(f'.//{ns_tag("ClCompile")}')
ci = updated_root.findall(f'.//{ns_tag("ClInclude")}')
ma = updated_root.findall(f'.//{ns_tag("MASM")}')
print(f"  ClCompile: {len(cc)}, ClInclude: {len(ci)}, MASM: {len(ma)}")

# ── Update ShadowStrike.sln ──────────────────────────────────────────

print(f"\n=== Updating ShadowStrike.sln ===")

sln_content = open(SLN_PATH, 'r', encoding='utf-8').read()

# Build project entries to add
proj_type_guid = '{8BC9CEB8-8B4A-11D0-8D11-00A0C91BC942}'

new_projects = ''
new_configs = ''

for product_name, product_guid, _ in products:
    new_projects += f'Project("{proj_type_guid}") = "{product_name}", "{product_name}.vcxproj", "{product_guid}"\nEndProject\n'

    new_configs += f'\t\t{product_guid}.Debug|x64.ActiveCfg = Debug|x64\n'
    new_configs += f'\t\t{product_guid}.Debug|x64.Build.0 = Debug|x64\n'
    new_configs += f'\t\t{product_guid}.Debug|x86.ActiveCfg = Debug|Win32\n'
    new_configs += f'\t\t{product_guid}.Debug|x86.Build.0 = Debug|Win32\n'
    new_configs += f'\t\t{product_guid}.Release|x64.ActiveCfg = Release|x64\n'
    new_configs += f'\t\t{product_guid}.Release|x64.Build.0 = Release|x64\n'
    new_configs += f'\t\t{product_guid}.Release|x86.ActiveCfg = Release|Win32\n'
    new_configs += f'\t\t{product_guid}.Release|x86.Build.0 = Release|Win32\n'

# Insert new projects before "Global"
sln_content = sln_content.replace(
    'Global\n',
    new_projects + 'Global\n'
)

# Insert new configs before EndGlobalSection of ProjectConfigurationPlatforms
# Find the end of ProjectConfigurationPlatforms section
marker = '\tEndGlobalSection\n\tGlobalSection(SolutionProperties)'
sln_content = sln_content.replace(
    marker,
    new_configs + marker
)

with open(SLN_PATH, 'w', encoding='utf-8') as f:
    f.write(sln_content)

print("Done!")
print(f"\nGUIDs for reference:")
print(f"  PhantomHome: {guid_home}")
print(f"  PhantomEDR:  {guid_edr}")
print(f"  PhantomXDR:  {guid_xdr}")
