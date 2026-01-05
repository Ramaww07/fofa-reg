from curl_cffi import requests
import time
import json
import re
import random
import sys
import os
from ddddocr import DdddOcr
import base64
import string

mm = ['qabq.com', 'nqmo.com', 'end.tw', '6n9.net']
default_password = ''  # 留空则使用随机密码

def generate_password(length=12):
    """生成随机密码，至少8位，包含大小写字母和数字"""
    if length < 8:
        length = 8
    
    # 确保至少包含一个大写、一个小写、一个数字
    upper = random.choice(string.ascii_uppercase)
    lower = random.choice(string.ascii_lowercase)
    digit = random.choice(string.digits)
    
    # 剩余字符从所有字符中随机选择
    remaining_length = length - 3
    all_chars = string.ascii_letters + string.digits
    remaining = ''.join(random.choice(all_chars) for _ in range(remaining_length))
    
    # 打乱顺序
    password_list = list(upper + lower + digit + remaining)
    random.shuffle(password_list)
    return ''.join(password_list)

# 设置密码：如果有默认密码则使用，否则生成随机密码
if default_password:
    password = default_password
    password_mode = "固定密码"
else:
    password = generate_password()
    password_mode = "随机密码"

print(f"当前密码模式: {password_mode}")
print(f"使用密码: {password}\n")

# 全局初始化 OCR 实例，避免重复创建
ocr = DdddOcr(show_ad=False)

def generate_email():
    username = 'ls' + str(random.randint(1, 993219))
    domain = random.choice(mm)
    return username, username + '@' + domain

# 初始化全局变量
username, mail = generate_email()

headers = {
    'User-Agent': "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36 Edg/121.0.0.0",
    'Accept': "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
    'Content-Type': "application/x-www-form-urlencoded",
    'Cache-Control': "max-age=0",
    'sec-ch-ua': "\"Not A(Brand\";v=\"99\", \"Microsoft Edge\";v=\"121\", \"Chromium\";v=\"121\"",
    'sec-ch-ua-mobile': "?0",
    'sec-ch-ua-platform': "\"Windows\"",
    'Upgrade-Insecure-Requests': "1",
    'Origin': "https://i.nosec.org",
    'Sec-Fetch-Site': "same-origin",
    'Sec-Fetch-Mode': "navigate",
    'Sec-Fetch-User': "?1",
    'Sec-Fetch-Dest': "document",
    'Referer': "https://i.nosec.org/register?service=https://fofa.info/f_login",
    'Accept-Language': "zh-CN,zh;q=0.9,en;q=0.8,en-GB;q=0.7,en-US;q=0.6",
    'Cookie': "fofa_service=1; _nosec_cas_session=d0J0c2Y2TkkxWUhmM1k5QXlaNHpRbnB4QkdLdktFaUtOWlZDMndWNUdNemxDbjJhL1ZYRUY2cXBzZFFDNmdmWUVtKzlOaUlJbHllT2ZzbVZBWEQ4WlZVamFJQ1lUL0VCRjdveEtwSXRFb1Y3eFhFTWZDMWhwZXExekxrR1VnQXBxZmRzdmFYbWFHbWlIbkJYa3BUVlZrbGFZY2tnMjVySkw4b0t6SzFQb2pub244UlcwOUdoM3pGS0xESU0rS3hDMXFxTlRHd1EvWkMwRndkV3hOcWU0N2g2UGNwdlR5T3o5eE8zZkFzazZkOD0tLWJDSXlNdUw2UWV3OEVjOUlyeSs0WWc9PQ%3D%3D--55bb0947fef24980e0a46765a8146815152fd353"
}

def load_send():
    global send
    global hadsend
    cur_path = os.path.abspath(os.path.dirname(__file__))
    sys.path.append(cur_path)
    if os.path.exists(cur_path + "/notify.py"):
        try:
            from notify import send
            hadsend = True
        except ImportError:
            print("加载notify.py的通知服务失败，请检查~")
            hadsend = False
    else:
        print("加载通知服务失败,缺少notify.py文件")
        hadsend = False

load_send()

def get_verification_code(mail, max_retries=5, retry_interval=5):
    """获取邮件验证码，支持重试"""
    try:
        url = 'https://api.mail.cx/api/v1/auth/authorize_token'
        mail_headers = {
            'accept': 'application/json',
            'Authorization': 'Bearer undefined'
        }
        response = requests.post(url, headers=mail_headers, verify=False)
        authorize_token = response.json()
        mail_headers['Authorization'] = 'Bearer ' + authorize_token
        
        pattern = re.compile(r'PHA\+5qyi6L\+.*', re.DOTALL)
        pattern2 = re.compile(r'confirmation_token=([^"&\s]+)', re.IGNORECASE)
        
        for attempt in range(max_retries):
            print(f"正在获取邮件 (尝试 {attempt + 1}/{max_retries})...")
            time.sleep(retry_interval)
            
            url = f'https://api.mail.cx/api/v1/mailbox/{mail}'
            response = requests.get(url, headers=mail_headers, verify=False)
            data = json.loads(response.text)
            
            if data and len(data) > 0:
                mail_id = data[0]["id"]
                url = f'https://api.mail.cx/api/v1/mailbox/{mail}/{mail_id}/source'
                mail_headers['Content-Type'] = 'text/html; charset=utf-8'
                response = requests.get(url, headers=mail_headers, verify=False)
                
                result = pattern.search(response.text)
                if result:
                    matched_content = result.group().strip()
                    decoded_data = base64.b64decode(matched_content).decode('utf-8')
                    match = pattern2.search(decoded_data)
                    if match:
                        return match.group(1)
            
            print(f"邮件未到达，{retry_interval}秒后重试...")
        
        print("邮件获取超时")
        return None
    except Exception as e:
        print(f"获取邮件验证码失败: {e}")
        return None

def get_rucaptcha():
    """获取并识别验证码"""
    try:
        url = "https://i.nosec.org/rucaptcha"
        response = requests.get(url, headers=headers, verify=False)
        if response.status_code == 200:
            image = response.content
            rucaptcha = ocr.classification(image)
            print("验证码识别结果:", rucaptcha)
            return rucaptcha
        else:
            print(f"无法获取验证码图片，状态码: {response.status_code}")
            return None
    except Exception as e:
        print(f"验证码获取失败: {e}")
        return None

def token():
    """获取CSRF Token"""
    try:
        url = "https://i.nosec.org/register?service=https://fofa.info/f_login"
        response = requests.get(url, headers=headers, verify=False)
        if response.status_code == 200:
            match = re.search(r'<meta name="csrf-token" content="(.*?)" />', response.text)
            if match:
                return match.group(1)
            else:
                print("未找到Token")
        else:
            print(f"无法获取页面内容，状态码: {response.status_code}")
        return None
    except Exception as e:
        print(f"获取Token失败: {e}")
        return None

def confirmation():
    """确认邮箱激活账号"""
    try:
        confirmation_token = get_verification_code(mail)
        if confirmation_token is None:
            print("未能获取验证码，可能邮件未收到或临时邮箱被屏蔽")
            return False
        
        url = f"https://i.nosec.org/confirmation?confirmation_token={confirmation_token}"
        response = requests.get(url, verify=False)
        html_content = response.text
        pattern = re.compile(r'</strong>\s?(.*?)\s*<', re.DOTALL)
        results = pattern.findall(html_content)
        
        if results:
            extracted_texts = [result.strip() for result in results]
            for extracted_text in extracted_texts:
                msg = f"账号: {mail}\n密码: {password}\n{extracted_text}"
                print(msg)
                if hadsend:
                    send("fofa账号注册", msg)
            with open("fofa_mail.txt", "a", encoding="utf-8") as file:
                file.write(mail + "\t" + password + "\n")
            return True
        else:
            error_pattern = re.compile(r'<h2>(.*?)</h2>', re.DOTALL)
            error_match = error_pattern.search(html_content)
            if error_match:
                print(error_match.group(0).strip())
            else:
                print("激活失败，未找到具体错误信息")
            return False
    except Exception as e:
        print(f"激活账号失败: {e}")
        return False

def nosecusers(max_retries=5):
    """注册账号，支持验证码错误重试"""
    for attempt in range(max_retries):
        print(f"\n注册邮箱: {mail}")
        
        rucaptcha = get_rucaptcha()
        if rucaptcha is None:
            print("验证码获取失败，重试中...")
            continue
            
        csrf_token = token()
        if csrf_token is None:
            print("Token获取失败，重试中...")
            continue
        
        try:
            url = "https://i.nosec.org/nosecusers"
            data = {
                "utf8": "✓",
                "authenticity_token": csrf_token,
                "service": "https://fofa.info/f_login",
                "lname": "zh-CN",
                "nosecuser[email]": mail,
                "nosecuser[password]": password,
                "nosecuser[password_confirmation]": password,
                "nosecuser[username]": username,
                "_rucaptcha": rucaptcha,
                "agree": "1",
                "commit": "注册"
            }
            response = requests.post(url, headers=headers, data=data, verify=False)
            html_content = response.text
            
            # 提取响应信息
            pattern = re.compile(r'</strong>\s?(.*?)\s*<', re.DOTALL)
            results = pattern.findall(html_content)
            extracted_texts = [r.strip() for r in results if r.strip()]
            
            if extracted_texts:
                for text in extracted_texts:
                    print(text)
                
                # 检查是否需要重试的错误
                error_messages = ["注册验证码错误", "验证码错误", "验证码已过期"]
                if any(err in ' '.join(extracted_texts) for err in error_messages):
                    print(f"验证码错误，正在重试 ({attempt + 1}/{max_retries})")
                    continue
                
                # 检查是否有其他错误
                if "错误" in ' '.join(extracted_texts) or "失败" in ' '.join(extracted_texts):
                    print("注册遇到错误，跳过此账号")
                    return False
            
            # 注册成功，进行邮箱确认
            print("注册请求已发送，正在等待邮件确认...")
            return confirmation()
            
        except Exception as e:
            print(f"注册请求失败: {e}")
            continue
    
    print(f"已达到最大重试次数 {max_retries}，放弃注册")
    return False

def register_accounts(count):
    for i in range(count):
        print(f"\n开始注册第 {i+1}/{count} 个账号")
        global username, mail
        username, mail = generate_email()
        
        nosecusers()
        
        if i < count - 1:
            delay = random.randint(1, 20)
            print(f"等待 {delay} 秒后继续注册...")
            time.sleep(delay)

if __name__ == '__main__':
    try:
        if len(sys.argv) > 1:
            num_accounts = int(sys.argv[1])
        else:
            user_input = input("请输入要注册的账号数量(直接回车默认注册1个): ").strip()
            num_accounts = int(user_input) if user_input else 1
        
        if num_accounts < 1:
            print("注册数量必须大于0")
        else:
            register_accounts(num_accounts)
    except ValueError:
        print("请输入有效的数字")
    except KeyboardInterrupt:
        print("\n用户取消操作")
        print("\n程序已终止")