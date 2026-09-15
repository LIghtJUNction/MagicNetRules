# MagicNetRules

**MagicNetRules** 是专为 [MagicNet](https://github.com/LIghtJUNction/MagicNet) 量身打造的高性能、自动化 sing-box 规则集系统。

集成、去重、优化并合并了各大上游优质规则源（MetaCubeX、lyc8503、KaringX、HaGeZi、SukkaLab、DDCH 等），提供紧凑高效的编译二进制规则集（`.srs`）与结构化 JSON 源规则文件。

---

## 核心特性

- **高效去重与剪枝 (Deduplication & Trie Pruning)**：
  - **后缀树剪枝**：基于反向域名字典树（Reverse Domain Trie）消除同名及多级子后缀冗余（例如已有 `example.com` 后缀，自动剔除冗余的 `sub.example.com` 后缀与 `*.example.com` 精确域名）。
  - **精准域名消冗**：凡已被 `domain_suffix` 涵盖的 `domain` 规则均自动剥离，大幅缩小规则体积与内存占用。
- **IP CIDR 智能归并 (CIDR Subnet Collapsing)**：
  - 基于 `ipaddress.collapse_addresses` 算法自动合并重叠与连续的 IPv4/IPv6 子网，减少 15%~25% 的路由条目，加速 Radix Tree 路由查找。
- **全量集成与分类合并 (Rule Set Consolidation)**：
  - **合并规则集 (Consolidated)**：将原本分散的数十个分散规则合并为高聚合的业务规则集（如 `magicnet-cn-domain`、`magicnet-cn-ip`、`magicnet-adblock`、`magicnet-media`、`magicnet-dev`、`magicnet-ai` 等），极大减少 sing-box 运行时的规则链层数。
  - **独立服务规则集 (Dedicated Services)**：为 OpenAI、Claude、Gemini、Grok、Google、YouTube、GitHub、Discord、Telegram、Twitter、WhatsApp、Netflix、Spotify 等保持高优先级独立规则，便于独立分流选择。
  - **100% 向后兼容 (Backward Compatible)**：完整保留原始命名规范的独立规则集，确保旧版配置与测试无缝运行。
- **完整 CI/CD 与自动化测试**：
  - GitHub Actions 自动化编译与测试流水线（架构校验、去重校验、SRS 编译校验、sing-box 真实流量匹配测试、数据一致性 Parity 测试）。
  - 定时自动化上游规则刷新与版本发布。

---

## 规则集结构

### 1. 合并规则集 (Consolidated Rulesets)

| 规则名称 (`dist/*.srs`) | 包含上游源 | 说明 |
| :--- | :--- | :--- |
| `magicnet-cn-domain` | MetaCubeX CN, lyc8503 CN, KaringX ChinaDomain, Tencent, WeChat, Bing CN | 大陆域名、腾讯、微信、国内直连服务全集 |
| `magicnet-cn-ip` | MetaCubeX GeoIP CN, lyc8503 GeoIP CN, KaringX China IP | 大陆 IP 段全集（经 CIDR 聚合压缩） |
| `magicnet-adblock` | lyc8503 Geosite Ads, KaringX BanAD | 广告拦截与隐私追踪防护规则 |
| `magicnet-dev` | MetaCubeX Dev, Docker, GitHub, GitLab, HuggingFace, NPM | 开发者平台、容器与代码仓库 |
| `magicnet-media` | MetaCubeX Media, Entertainment, Yuu Stream Global, Karing Media | 国际流媒体与影音娱乐 |
| `magicnet-social` | Social Media, Communication, Notion, Slack, Reddit | 国际社交媒体与协同通讯 |
| `magicnet-download` | Game Platforms Download, Windows Update, Apple Update | 游戏大文件下载与系统更新 |
| `magicnet-games` | MetaCubeX Games !cn | 国际游戏联机与平台 |
| `magicnet-ai` | Category AI !cn, Yuu AI, Karing AI | 综合 AI 与大模型服务 |
| `magicnet-dns-guard` | Category DoH, IP Geo Detect | 加密 DNS 与地理位置探测分流 |
| `magicnet-network-test` | Connectivity Check, Speedtest | 网络连通性与测速服务 |
| `magicnet-proxy` | Geolocation !cn, GFWList, Proxy Lite | 国际通用代理与 GFW 名单 |

### 2. 独立服务分流规则集 (Dedicated Service Rulesets)

- `service-openai` / `sukka-chatgpt-voice`
- `service-anthropic` (Claude)
- `service-google-gemini`
- `service-xai` (Grok)
- `service-google` / `service-google-play` / `service-youtube`
- `service-github` / `service-discord` / `service-telegram`
- `service-twitter` / `service-whatsapp`
- `service-netflix` / `service-spotify`
- `service-apple` / `service-icloud` / `service-microsoft` / `service-bing`

---

## 本地开发与测试

### 环境依赖

- Python 3.10+
- [sing-box](https://github.com/SagerNet/sing-box) (已安装于 PATH 中)

### 构建与编译

```bash
# 运行构建引擎：自动优化、去重、合并并编译为 .srs 与 .json
python3 scripts/builder.py

# 仅校验 dist/ 是否为最新（不重新写入）
python3 scripts/builder.py --check
```

### 运行测试套件

```bash
python3 -m unittest discover tests -v
```

测试套件包含：
1. `test_schema.py`: 校验所有规则集是否符合 sing-box schema 规范。
2. `test_deduplication.py`: 严格断言不存在子域名冗余、同源重复项及未合并 CIDR。
3. `test_compilation.py`: 验证所有规则均成功编译为非空有效二进制 `.srs` 文件。
4. `test_matching.py`: 使用 `sing-box rule-set match` 检验常见服务真实解析匹配。
5. `test_parity.py`: 抽样比对上游源规则与合并后规则的完整性。

---

## CI 工作流

- **`.github/workflows/ci.yml`**：每次 Push 与 PR 自动校验输出与测试套件。
- **`.github/workflows/update-upstream.yml`**：每周定时从各上游拉取最新规则、自动重新构建优化，若有更新则自动提交。
- **`.github/workflows/release.yml`**：推送版本 tag 时打包生成 `magicnet-rules.tar.gz` 与 `magicnet-rules.zip` 发布 Release。

---

## 许可证

[MIT License](LICENSE) © 2026 LIghtJUNction
