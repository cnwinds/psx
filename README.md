# PS5 Relapse · All-in-One

[Relapse-Exploit](https://github.com/ntfargo/Relapse-Exploit) 的一站式整合版：原仓库只包含漏洞利用链（跑通后 elfldr 监听 `9021`），缺少需要手动发送的三个 payload。本仓库把它们全部打包进 `payloads/`，并在页面上实现了自动发送——**打开一个页面即可完成全部流程**。

```
PS5 浏览器打开本页
   │
   ├─ 1. WebKit 用户态漏洞（JSC 信息泄露 + 结构化克隆池错配）
   ├─ 2. 内核漏洞（aio_multi_wait UAF）→ 内核读写 + root + 沙箱逃逸
   ├─ 3. kexp 于内核上下文拉起 elfldr，监听 127.0.0.1:9021
   │
   ├─ 4. kstuff.elf          内核补丁：FSELF / FPKG 支持（一切的基础）
   ├─ 5. etaHEN-2.5B.bin     AIO HEN：Toolbox / FTP(1337) / PKG 安装器(9090)
   └─ 6. shadowmountplus.elf 游戏镜像自动挂载（依赖 kstuff 运行）
```

## 组件关系

| 组件 | 作用 | 依赖 | 来源 |
| --- | --- | --- | --- |
| Relapse 漏洞链 | 浏览器 + 内核双阶段提权 | FW 7.00 – 13.60 | [ntfargo/Relapse-Exploit](https://github.com/ntfargo/Relapse-Exploit) |
| elfldr（已含） | 监听 9021，接收并执行 ELF | 由漏洞链自动拉起 | 随 Relapse 仓库 |
| kstuff.elf | 内核补丁：FSELF / FPKG、挂载支持 | 仅需内核漏洞 | [EchoStretch/kstuff-lite](https://github.com/EchoStretch/kstuff-lite) v1.11（FW 1.00 – 13.60） |
| etaHEN-2.5B.bin | AIO HEN：Toolbox、FTP(1337)、PKG 安装器(9090)、插件、自带 kstuff 集成 | 端口 9021 | [etaHEN/etaHEN](https://github.com/etaHEN/etaHEN) 2.5B |
| shadowmountplus.elf | 自动扫描 / 挂载 / 安装游戏镜像（.ffpkg / .exfat / .ffpfs） | kstuff-lite v1.07+ 运行中 | [drakmor/ShadowMountPlus](https://github.com/drakmor/ShadowMountPlus) 1.7beta3 |

加载顺序说明：kstuff 先打内核补丁；etaHEN 在其上构建 HEN 功能（也内嵌了自己的 kstuff）；ShadowMountPlus 需要 kstuff 处于运行状态，并自带 kstuff 自动暂停/恢复逻辑（游戏启动时暂停 kstuff、退出时恢复）。

## 使用方法

### 方式一：一站式页面（推荐）

1. 用 GitHub Pages 或局域网托管本仓库（见下），PS5 浏览器打开 `index.html`。
2. 页面自动运行漏洞链；浏览器阶段偶发失败——卡住就刷新重试，内核阶段若死机则重启主机再来。
3. 日志出现 `elfldr is listening on port 9021` 后，payload 面板自动出现。默认勾选「自动加载」，也可点「一键加载全部」或单独发送；页面通过 ROP 直接向 `127.0.0.1:9021` 发送字节流，全程无需 PC 参与。
4. 主机屏幕依次弹出 etaHEN Toolbox 与 ShadowMount+ 通知即成功。

### 方式二：PC 手动发送

页面跑完漏洞链后，用 PC 向主机 9021 端口发送（文件可在页面「文件下载」区或本仓库 `payloads/` 直接下载）：

```bash
# Linux / macOS（IP 换成你的 PS5）
nc 192.168.1.100 9021 < kstuff.elf
nc 192.168.1.100 9021 < etaHEN-2.5B.bin
nc 192.168.1.100 9021 < shadowmountplus.elf
```

Windows 可用 [etaHEN 仓库](https://github.com/etaHEN/etaHEN) 的 `send_payload.ps1`。

### 托管

- **GitHub Pages**：Fork/推送到你的仓库 → Settings → Pages → 选择 main 分支 → 用 `https://<用户名>.github.io/psx/` 访问。
- **局域网**：`python serve.py`（会打印本机地址，PS5 浏览器访问 `http://<PC IP>:8000/`）。

## 游戏镜像（ShadowMountPlus）

- 推荐格式 `.ffpkg`（UFS）；`.exfat` 用于需要外接盘兼容性的游戏；`.ffpfs` 为实验性。
- 镜像根目录必须直接是游戏文件（如 `/sce_sys/param.json`），不能再套一层文件夹。
- 默认扫描内置盘 `/data/etaHEN/games`、`/data/shadowmount` 等路径，约每 15 秒自动扫描；可用 `/data/shadowmount/config.ini` 的 `scanpath=` 自定义。
- 配置详见 [ShadowMountPlus README](https://github.com/drakmor/ShadowMountPlus#readme)。

## 稳定性提示

- WebKit 阶段可能需要多次尝试，浏览器卡死就刷新页面。
- 内核阶段可能挂起或 panic 主机，遇到就重启再试。
- 每次重启后 kstuff / etaHEN / ShadowMountPlus 均需重新加载（重跑本页流程即可）。

## 稳定性提示之外的免责声明

本项目仅供**教育与安全研究用途**，仅限在自有/授权设备上使用，不支持盗版或未经授权的访问。使用风险（系统不稳定、数据丢失、账号封禁等）由使用者自行承担。请遵守当地法律法规。

## 致谢

- **Relapse 漏洞链**：Sonic_Iso（内核漏洞）、Jordy（WebKit 漏洞与内核 bug）、ntfargo、ufm42（漏洞开发）、Dr. Yenyen（测试），以及 TheFlow、SlidyBat、Flatz、cow、nhk、bollarz、Sleirsgoevy、EchoStretch、EarthOnion
- **kstuff 系列**：sleirsgoevy、zecoxao、flatz、idlesauce、buzzer-re、Al-Azif、EchoStretch、drakmor
- **etaHEN**：LightningMods 及社区贡献者
- **ShadowMountPlus**：drakmor（ShadowMount 的开源延续）
- 页面自动发送思路参考社区 all-in-one host（ps5jb 等）

## License

MIT（见 LICENSE，漏洞链部分版权 Nathan Fargo）。各 payload 遵循其上游项目协议：kstuff-lite（GPL）、etaHEN（GPL-3.0）、ShadowMountPlus（GPL-3.0）。
