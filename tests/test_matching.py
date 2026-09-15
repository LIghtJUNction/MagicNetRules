"""End-to-end matching tests using sing-box rule-set match."""

import shutil
import subprocess
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DIST_DIR = ROOT / "dist"


class MatchingTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.core = shutil.which("sing-box")
        if not cls.core:
            raise unittest.SkipTest("sing-box binary not found in PATH")

    def match(self, rule_name: str, target: str) -> bool:
        path = DIST_DIR / f"{rule_name}.srs"
        self.assertTrue(path.is_file(), f"Rule file {path.name} not found")
        cmd = [self.core, "rule-set", "match", "-f", "binary", str(path), target]
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
        output = proc.stdout.strip() or proc.stderr.strip()
        return "match rules" in output or "matched" in output

    def test_service_matches(self):
        cases = [
            ("service-openai", "chatgpt.com", True),
            ("service-openai", "api.openai.com", True),
            ("service-openai", "oaistatic.com", True),
            ("service-anthropic", "claude.ai", True),
            ("service-anthropic", "anthropic.com", True),
            ("service-google-gemini", "gemini.google.com", True),
            ("service-xai", "grok.com", True),
            ("service-xai", "x.ai", True),
            ("service-google", "www.google.com", True),
            ("service-google", "mail.google.com", True),
            ("service-google-play", "play.google.com", True),
            ("service-youtube", "youtube.com", True),
            ("service-youtube", "youtu.be", True),
            ("service-github", "github.com", True),
            ("service-github", "api.github.com", True),
            ("service-discord", "discord.com", True),
            ("service-discord", "discord.gg", True),
            ("service-netflix", "netflix.com", True),
            ("service-spotify", "spotify.com", True),
            ("service-twitter", "twitter.com", True),
            ("service-twitter", "x.com", True),
            ("service-whatsapp", "web.whatsapp.com", True),
            ("service-telegram", "t.me", True),
            ("service-telegram", "telegram.org", True),
            ("service-telegram-ip", "149.154.167.50", True),
            ("service-apple", "apple.com", True),
            ("service-icloud", "icloud.com", True),
            ("service-microsoft", "microsoft.com", True),
            ("service-bing", "bing.com", True),
            ("service-bing-cn", "cn.bing.com", True),
            ("service-tencent", "qq.com", True),
            ("service-wechat", "weixin.qq.com", True),
        ]
        for rule_name, target, expected in cases:
            with self.subTest(rule=rule_name, target=target):
                self.assertEqual(
                    self.match(rule_name, target),
                    expected,
                    f"{target} matching against {rule_name} expected {expected}",
                )

    def test_consolidated_magicnet_rules(self):
        cases = [
            # China domains
            ("magicnet-cn-domain", "baidu.com", True),
            ("magicnet-cn-domain", "weixin.qq.com", True),
            ("magicnet-cn-domain", "alipay.com", True),
            ("magicnet-cn-domain", "taobao.com", True),
            ("magicnet-cn-domain", "bilibili.com", True),
            ("magicnet-cn-domain", "zhihu.com", True),
            ("magicnet-cn-domain", "jd.com", True),
            # China IPs
            ("magicnet-cn-ip", "223.5.5.5", True),
            ("magicnet-cn-ip", "114.114.114.114", True),
            ("magicnet-cn-ip", "119.29.29.29", True),
            # Ad blocking
            ("magicnet-adblock", "doubleclick.net", True),
            ("magicnet-adblock", "adservice.google.com", True),
            ("magicnet-adblock", "admob.com", True),
            # Developer
            ("magicnet-dev", "github.com", True),
            ("magicnet-dev", "gitlab.com", True),
            ("magicnet-dev", "registry.npmjs.org", True),
            ("magicnet-dev", "hub.docker.com", True),
            ("magicnet-dev", "huggingface.co", True),
            # Media
            ("magicnet-media", "youtube.com", True),
            ("magicnet-media", "netflix.com", True),
            ("magicnet-media", "spotify.com", True),
            # Social
            ("magicnet-social", "discord.com", True),
            ("magicnet-social", "reddit.com", True),
            ("magicnet-social", "slack.com", True),
            ("magicnet-social", "notion.so", True),
            # AI
            ("magicnet-ai", "chatgpt.com", True),
            ("magicnet-ai", "claude.ai", True),
            ("magicnet-ai", "grok.com", True),
            ("magicnet-ai", "gemini.google.com", True),
            # Network test
            ("magicnet-network-test", "speedtest.net", True),
        ]
        for rule_name, target, expected in cases:
            with self.subTest(rule=rule_name, target=target):
                self.assertEqual(
                    self.match(rule_name, target),
                    expected,
                    f"{target} matching against {rule_name} expected {expected}",
                )

    def test_negative_isolation(self):
        """Verify that rules do not capture unrelated traffic."""
        negatives = [
            ("magicnet-cn-domain", "chatgpt.com"),
            ("magicnet-cn-domain", "google.com"),
            ("magicnet-cn-domain", "twitter.com"),
            ("magicnet-adblock", "baidu.com"),
            ("magicnet-adblock", "apple.com"),
            ("magicnet-cn-ip", "1.1.1.1"),
            ("magicnet-cn-ip", "8.8.8.8"),
            ("service-openai", "baidu.com"),
            ("service-google", "apple.com"),
        ]
        for rule_name, target in negatives:
            with self.subTest(rule=rule_name, target=target):
                self.assertFalse(
                    self.match(rule_name, target),
                    f"False positive: {target} matched {rule_name}",
                )


if __name__ == "__main__":
    unittest.main()
