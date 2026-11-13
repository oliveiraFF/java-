"""PhishGuard 检测引擎。

api（手动检测）、worker（自动检测）和 ml/ 下的实验脚本共用这一个包，
保证三处的判定逻辑完全一致。
"""
from phishguard_detector.parser import Attachment, ParsedEmail, UrlRef, parse_bytes, parse_text

__version__ = "0.1.0"

__all__ = ["Attachment", "ParsedEmail", "UrlRef", "parse_bytes", "parse_text", "__version__"]
