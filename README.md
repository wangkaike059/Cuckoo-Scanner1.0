# Cuckoo-Scan 1.0
Cuckoo Scan
# 布谷鸟漏洞扫描器1.0
<img width="114" alt="image" src="https://github.com/user-attachments/assets/e3bf47d3-3291-4080-a0ea-29720378b54f" />

Cuckoo 是一个简洁的漏洞扫描器，只需一条命令即可启动。该工具适用于快速识别目标域名及其子域名上可能存在的CVE-2025-29927漏洞，适合渗透测试与安全评估使用。

## 特性

- 自动发现子域名（调用 VirusTotal的API（免费版本，速率受限，真要用的话换自己的））
- 自动识别网站框架（Next.js）
- CVE 漏洞探测（无需认证、易复现）
- 输出扫描结果和漏洞详情
- 支持 Python3 直接运行，无需复杂配置

## 快速开始

### 1. 运行

```bash
python bugu.py
-程序将自动读取配置（如 API Key）、收集子域名并开始漏洞检测，控制台将实时输出发现的漏洞信息以及相关子域名扫描情况。
