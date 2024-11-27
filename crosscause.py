'''
本脚本用于实现对于xss漏洞的风险评估，基于以下两种场景：
1.渗透测试角度，对于目录爆破取得进展的php页面进行偏重参数传递过程的测试（黑盒）
2.安全测试角度，对于给定的php页面进行以代码审计的角度进行风险评估（白盒）
'''
import re
import argparse
import requests
parser = argparse.ArgumentParser(description='A simple XSS detect tool.')

parser.add_argument(
        "--moudle","-m",
        type=str,
        required=True,
        help="the view :attack/test."
)
parser.add_argument(
        "--url","-u",
        help="URl of the php page"
)
parser.add_argument(
        "--page","-p",
        type=str,
        help="the path of the page you will test."
)
args = parser.parse_args()
def attack(url):
    response = requests.get(url)
    if response.status_code == 200:
        print("[+]URL is OK.")
        print("\nHTTP头部信息：")
        for key, value in response.headers.items():
            print(f"{key}:{value}")
        return response.headers
    else:
        print(f"请求失败：状态码：{response.status_code}")
        return None,None
"""此处可对于获取到的内容和头部信息进行参数的xss测试，由于本script目的是对给定php页面代码的审计（白盒），在此暂不展开"""
def vuln_pattern(content):
    vulnerabilities = []
    patterns = [
        {
            "pattern": r'echo\s+\$(?:_GET|_POST|_REQUEST)\[.*?\]',
            "description": "Directly echoing user input"
        },
        {
            "pattern": r'print\s+\$(?:_GET|_POST|_REQUEST)\[.*?\]',
            "description": "Directly printing user input"
        },
        {
            "pattern": r'<.*?>.*?\$(?:_GET|_POST|_REQUEST)\[.*?\].*?</.*?>',
            "description": "Embedding user input in HTML tags"
        },
    ]
    lines = content.split('\n')

    for line_number, line in enumerate(lines, start=1):
        for item in patterns:
            matches = re.finditer(item["pattern"], line)
            for match in matches:
                details = {
                    "line": line_number,
                    "content": line.strip(),
                    "description": item["description"]
                }
                #正则匹配
                if not re.search(r'htmlspecialchars\(|htmlentities\(', line):
                    details["sanitized"] = False
                    details["note"] = "No sanitization detected"
                else:
                    details["sanitized"] = True
                #实体化处理
                vulnerabilities.append(details)

    return vulnerabilities


def test(page):
    with open(page,'r',encoding='utf-8') as f:
        content = f.read()
        vulns = vuln_pattern(content)
        if vulns:
            print("[+]following maybe have XSS vuln:")
            for vulnerability in vulns:
                print(f"Line {vulnerability['line']}: {vulnerability['content']}")
                print(f"  -> {vulnerability['description']}")
                if not vulnerability["sanitized"]:
                    print("  [-]Warning: Input is not sanitized.")
        else:
            print("Maybe No XSS .")

if __name__ == "__main__":
    print(
        r""" ___    ___ ________   ________           ________   ________          ___       __   ________      ___    ___ 
|\  \  /  /|\   ____\ |\   ____\         |\   ___  \|\   __  \        |\  \     |\  \|\   __  \    |\  \  /  /|
\ \  \/  / | \  \___|_\ \  \___|_        \ \  \\ \  \ \  \|\  \       \ \  \    \ \  \ \  \|\  \   \ \  \/  / /
 \ \    / / \ \_____  \\ \_____  \        \ \  \\ \  \ \  \\\  \       \ \  \  __\ \  \ \   __  \   \ \    / / 
  /     \/   \|____|\  \\|____|\  \        \ \  \\ \  \ \  \\\  \       \ \  \|\__\_\  \ \  \ \  \   \/  /  /  
 /  /\   \     ____\_\  \ ____\_\  \        \ \__\\ \__\ \_______\       \ \____________\ \__\ \__\__/  / /    
/__/ /\ __\   |\_________\\_________\        \|__| \|__|\|_______|        \|____________|\|__|\|__|\___/ /     
|__|/ \|__|   \|_________\|_________|                                                             \|___|/      
                                                                                                               
                                                                                                               """
    )
    if args.moudle == "attack":
        print("[red attack]")
        attack(args.url)
    if args.moudle == "test":
        print("[blue safe]")
        test(args.page)