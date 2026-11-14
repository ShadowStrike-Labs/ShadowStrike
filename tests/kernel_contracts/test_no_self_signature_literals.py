#!/usr/bin/env python3
"""Contract: our own binaries must not carry the strings a shipped YARA rule keys on.

The 1.0.128 and 1.0.133 VM runs logged "deferred deep scan found threat in
C:\\Program Files\\ShadowStrike\\Phantom\\ShadowStrikePhantomService.exe - remediating"
(14 times in the 1.0.133 run), named SIGNATURE_BASE_HKTL_Meterpreter_Inmemory, and
then tried to quarantine the service executable and terminate the service itself.

That rule (content/yara, signature-base gen_metasploit_payloads.yar) fires on
"1 of ($sx*) or 2 of ($s*)" over ascii fullword strings. Every networked binary
imports WS2_32.dll, so one more fullword hit is enough - and the service binary
carried "ReflectiveLoader" in a human-readable API-sequence description in
ProcessInjectionDetector.cpp. The identification was real; the binary really
matched, so the remediation guard (which exempts our own binaries only from
inference) was right not to stop it. The defect is the literal, so this pins the
literals out.

Only NARROW literals are checked: the rule's strings are ascii, so a UTF-16 copy
cannot match. YARA's fullword means delimited by non-alphanumeric bytes, which is
what the lookarounds below implement (an underscore IS a delimiter for YARA).
"""
import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
# Every first-party C/C++ tree compiled into a shipped binary. PhantomEmulator and
# PhantomDisassembler are compiled into PhantomCoreLib, and the emulator's built-in
# pattern table held the second copy of the token that 843374b6 missed by scanning
# src/ alone.
SCAN_ROOTS = [ROOT / "src", ROOT / "PhantomSensor", ROOT / "PhantomEmulator",
              ROOT / "PhantomDisassembler"]
SUFFIXES = {".c", ".cpp", ".h", ".hpp", ".inl"}
INJECTION_CPP = ROOT / "src/PhantomCore/Core/Process/ProcessInjectionDetector.cpp"

# SIGNATURE_BASE_HKTL_Meterpreter_Inmemory: $sxs1 matches alone, $ss2 pairs with
# the WS2_32.dll import that every networked binary has.
FORBIDDEN_TOKENS = ("ReflectiveLoader", "metsrv.x64.dll")


def narrow_string_literals(text):
    """Yield (line, body) for each narrow string literal outside comments.

    A small lexer rather than a regex: a regex cannot tell a literal from the
    same characters inside a comment, and "http://" inside a literal must not be
    read as a comment start. Prefixed literals (L, u, U) are skipped; u8 and
    unprefixed literals are narrow and are reported.
    """
    i, n, line = 0, len(text), 1
    while i < n:
        c = text[i]
        if c == "\n":
            line += 1
            i += 1
        elif text.startswith("//", i):
            j = text.find("\n", i)
            i = n if j < 0 else j
        elif text.startswith("/*", i):
            j = text.find("*/", i + 2)
            j = n if j < 0 else j + 2
            line += text.count("\n", i, j)
            i = j
        elif c == "'":
            j = i + 1
            while j < n and text[j] != "'" and text[j] != "\n":
                j += 2 if text[j] == "\\" else 1
            i = j + 1
        elif c == '"':
            prefix = re.search(r"(u8|[LuU])?$", text[max(0, i - 2):i]).group(1)
            j = i + 1
            while j < n and text[j] != '"' and text[j] != "\n":
                j += 2 if text[j] == "\\" else 1
            if prefix in (None, "u8"):
                yield line, text[i + 1:j]
            i = j + 1
        else:
            i += 1


def fullword(token):
    return re.compile(r"(?<![A-Za-z0-9])" + re.escape(token) + r"(?![A-Za-z0-9])")


class SelfSignatureLiteralContractTests(unittest.TestCase):
    def test_the_lexer_sees_narrow_literals_and_ignores_comments_and_wide(self):
        sample = (
            '// "ReflectiveLoader" in a line comment\n'
            '/* "ReflectiveLoader" in a block comment */\n'
            'auto w = L"ReflectiveLoader";\n'
            'auto u = "http://x//y";\n'
            'auto s = "(ReflectiveLoader)";\n'
        )
        found = list(narrow_string_literals(sample))
        self.assertEqual(found, [(4, "http://x//y"), (5, "(ReflectiveLoader)")])
        self.assertTrue(fullword("ReflectiveLoader").search(found[1][1]))
        self.assertTrue(fullword("ReflectiveLoader").search("_ReflectiveLoader_"),
                        "YARA fullword treats an underscore as a delimiter")
        self.assertFalse(fullword("ReflectiveLoader").search("ReflectiveLoaderX"))

    def test_no_narrow_literal_spells_a_token_the_meterpreter_rule_keys_on(self):
        patterns = [(t, fullword(t)) for t in FORBIDDEN_TOKENS]
        offenders = []
        for root in SCAN_ROOTS:
            for path in root.rglob("*"):
                if path.suffix.lower() not in SUFFIXES or not path.is_file():
                    continue
                text = path.read_text(encoding="utf-8", errors="surrogateescape")
                if not any(t in text for t in FORBIDDEN_TOKENS):
                    continue
                for line, body in narrow_string_literals(text):
                    for token, rx in patterns:
                        if rx.search(body):
                            offenders.append(
                                f"{path.relative_to(ROOT)}:{line}: {token}")
        self.assertEqual(
            offenders, [],
            "a narrow string literal spells a fullword token of the shipped YARA rule "
            "SIGNATURE_BASE_HKTL_Meterpreter_Inmemory; with the WS2_32.dll import the "
            "service binary then matches it and the product convicts itself")

    def test_the_reflective_dll_sequence_still_names_the_technique(self):
        src = INJECTION_CPP.read_text(encoding="utf-8", errors="surrogateescape")
        start = src.find("const char* InjectionTypeToAPISequence(")
        self.assertGreaterEqual(start, 0, "InjectionTypeToAPISequence was not found")
        m = re.search(r"case InjectionType::ReflectiveDLL:.*?return \"([^\"]*)\";",
                      src[start:], re.S)
        self.assertIsNotNone(m, "the ReflectiveDLL API-sequence case was not found")
        self.assertIn("CreateRemoteThread(reflective loader", m.group(1),
                      "the description must still say what the technique calls")


if __name__ == "__main__":
    unittest.main()
