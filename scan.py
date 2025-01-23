import socket
import logging
import requests  # 使用requests替代aiohttp
from concurrent.futures import ThreadPoolExecutor, as_completed
from tqdm import tqdm
import re

# 定义常见端口及其协议映射
PORT_PROTOCOLS = {
    80: "HTTP",
    443: "HTTPS",
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    110: "POP3",
    139: "NetBIOS",
    445: "Microsoft-DS",
    8080: "HTTP Proxy"
}

# 设置日志配置：只保存到文件，不打印到控制台
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(message)s", handlers=[
    logging.FileHandler("test.txt", mode="a")  # 文件输出，追加模式
])

# 扫描单个端口，检查是否开放
def scan_port(url, port, progress_bar):
    try:
        # 建立TCP连接，使用socket库连接目标地址和端口
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(2)  # 设置超时时间
            result = s.connect_ex((url, port))
            if result == 0:
                # 根据端口号获取协议，如果没有则为未知协议
                protocol = PORT_PROTOCOLS.get(port, "Unknown Protocol")
                message = "Target {0}:{1} is alive (Protocol: {2})\n".format(url, port, protocol)
                progress_bar.update(1)  # 更新进度条
                return message  # 返回活跃目标信息
        return None
    except OSError:
        return None

# 获取HTTP指纹信息（使用同步requests）
def get_http_fingerprint(url, port, progress_bar):
    try:
        # 确保URL带上协议前缀
        if port in [80, 443]:
            protocol = "https" if port == 443 else "http"
            full_url = "{0}://{1}".format(protocol, url)
            
            # 使用requests进行同步HTTP请求
            response = requests.get(full_url, timeout=3)
            if response.status_code == 200:
                message = "Target {0}:{1} is alive (HTTP(S) Fingerprint)\n".format(url, port)
                progress_bar.update(1)  # 更新进度条
                return message  # 返回活跃目标信息
        return None
    except requests.RequestException:
        return None

# 对目标地址的端口进行扫描
def scan_target(url, ports, progress_bar):
    results = []  # 用于存储存活的目标信息
    
    # 执行端口扫描任务并通过同步方式进行指纹扫描
    with ThreadPoolExecutor(max_workers=20) as executor:
        futures = []
        for port in ports:
            futures.append(executor.submit(scan_port, url, port, progress_bar))
        
        # 获取端口扫描结果
        for future in as_completed(futures):
            result = future.result()
            if result:
                results.append(result)  # 收集端口扫描存活的结果
                # 对HTTP/HTTPS端口进行指纹识别
                http_result = get_http_fingerprint(url, port, progress_bar)
                if http_result:
                    results.append(http_result)  # 添加HTTP指纹信息

    # 如果有存活的目标，将其写入文件
    if results:
        with open("test.txt", "a") as f:
            f.writelines(results)
            f.write("=" * 50 + "\n")

# 判断是否是有效的IP地址
def is_ip(address):
    ip_pattern = r"^(?:\d{1,3}\.){3}\d{1,3}$"
    return re.match(ip_pattern, address) is not None

def main():
    # 计算文件中的总任务数
    total_tasks = 0
    targets = []
    
    # 从1.txt读取目标地址和端口信息
    with open('1.txt', 'r') as file:
        for line in file:
            parts = line.strip().split(':')  # 假设格式是 'url:port1,port2,...'
            if len(parts) == 2:
                url = parts[0]
                # 处理端口列表，确保端口部分非空且每个端口是有效的整数
                try:
                    ports = list(map(int, parts[1].split(',')))  # 处理端口列表
                    if ports:  # 如果端口列表非空
                        total_tasks += len(ports)  # 每个端口都算一个任务
                        targets.append((url, ports))
                    else:
                        logging.warning("Warning: No valid ports found for {0}".format(url))
                except ValueError:
                    logging.warning("Warning: Invalid port format for {0}: {1}".format(url, parts[1]))
            else:
                logging.warning("Warning: Invalid line format: {0}".format(line.strip()))

    # 使用tqdm显示进度条，并修改进度条颜色为淡紫色
    with tqdm(total=total_tasks, unit="task", bar_format="{l_bar}{bar}| {n_fmt}/{total_fmt} [{elapsed} < {remaining}, {rate_fmt}]",
              colour="magenta", dynamic_ncols=True) as progress_bar:
        
        # 执行扫描
        for url, ports in targets:
            scan_target(url, ports, progress_bar)

if __name__ == "__main__":
    main()
