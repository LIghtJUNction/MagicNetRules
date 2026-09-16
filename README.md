# MagicNetRules

MagicNet 的 sing-box 规则构建配方。仓库只保存脚本、源清单、配置和测试；下载源与产物不进入 Git。

## 获取规则

分发文件只在本仓库的 GitHub Releases 中提供：

- `magicnet-rules.tar.gz`：单个运行时归档，包含分类 SRS 和 `manifest.json`。
- `magicnet-rules-sources.tar.gz`：本次构建的源快照、配置、编译配方，供审计和复现。
- `upstream-manifest.json`：上游提交、下载 URL、大小和 SHA-256。
- `SHA256SUMS`：以上资产的校验和。

最新运行时归档：
`https://github.com/LIghtJUNction/MagicNetRules/releases/latest/download/magicnet-rules.tar.gz`

正式构建需要可复现时，使用 Release 的具体 tag，不要固定一个可能更新的 latest 地址。下载失败、缺文件、校验不符均应停止构建，不能静默换成旧规则。

all-in-one 指一次分发的归档，不是把直连、代理、拦截规则混成一个无分类的 SRS。现有分类及兼容文件名由 `config/rulesets.json` 定义。

## 构建

需要 Python 3.10+、Git、curl，以及校验和固定的 sing-box 编译器：

```bash
export SING_BOX_INSTALL_DIR="$PWD/.cache/tools"
bash scripts/install-compiler.sh
export PATH="$SING_BOX_INSTALL_DIR:$PATH"
python3 scripts/fetch_upstream.py
python3 scripts/builder.py
python3 scripts/builder.py --check
python3 -m unittest discover tests -v
python3 scripts/package_release.py
(cd release && sha256sum --check --strict SHA256SUMS)
```

构建时解析每个上游分支一次，再按该提交下载全部所需文件；SukkaLab 的 HTTPS 源记录内容摘要。下载和解码全部成功后才替换输入快照，失败保留此前输入，但当前构建必须失败。编译器版本与 SHA-256 固定在 `scripts/install-compiler.sh`。

`dist/`、`sources/`、`sources_binary/`、`release/`、`.cache/` 均为本地产物；CI 会拒绝将它们重新提交。`--check` 在临时目录重建并逐文件比较，不会修复被修改的输出。

## 自动更新

`release.yml` 每六小时运行一次（UTC 00:23、06:23、12:23、18:23），也支持手动运行。流程为：拉取源 → 编译去重 → 重现性和匹配测试 → 打包 → 上传草稿 Release → 全部成功后发布。运行时内容未变化时不创建重复 Release；不再自动提交源文件或数据 PR。GitHub 的定时任务可能延迟，不是准点服务。

`ci.yml` 对 PR 和 main 做全新源快照构建、测试与工作区检查。

## 历史清理

`clean-history.yml` 用于此次迁移，只有该工作流文件进入 main 或手动调用时运行，不参与定时更新。它要求 main 未发生并发更新，仅从所有可写分支和标签的历史中删除 `dist/`、`sources/`、`sources_binary/`，保留其他文件和提交信息，采用原子 `force-with-lease` 推送，不修改分支保护。

历史重写后，已有克隆应重新克隆；主项目必须更新 `rules` 子模块提交。GitHub 自己维护的 PR 引用、缓存和服务端对象回收不由 Git push 控制，因此不能把“重写分支/标签”当作所有旧对象已立即物理删除。

## 上游与许可证

源映射位于 `scripts/fetch_upstream.py`，包括 MetaCubeX、lyc8503、KaringX、Yuu518、DDCHlsq、razaxq/HaGeZi 和 SukkaLab。具体下载来源记录在每次 Release 的 provenance 清单中。

本仓库构建代码使用 [MIT](LICENSE)；聚合的规则数据仍受各上游自己的许可证和署名要求约束，不能将其笼统视为本仓库的 MIT 数据。
