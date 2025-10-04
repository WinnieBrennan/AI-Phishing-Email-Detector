# phish_guard_ai_svg_no_ocr.py

import email
from email.policy import default
import base64
import re
import os
from bs4 import BeautifulSoup
import xml.etree.ElementTree as ET
from urllib.parse import urlparse
import io

# --- 第三方库 ---
# 注意：以下三个库不再需要，也无需安装
# import cairosvg
# from PIL import Image
# import pytesseract

from transformers import pipeline, AutoTokenizer, AutoModelForSequenceClassification
import torch


# ==============================================================================
# 模块1: SVG 分析器
# ==============================================================================
class SvgAnalyzer:
    """解析SVG内容，检测其中的潜在威胁。"""

    def __init__(self, svg_content):
        self.svg_content = svg_content
        self.risk_score = 0
        self.findings = []
        self.namespaces = {
            'svg': 'http://www.w3.org/2000/svg',
            'xlink': 'http://www.w3.org/1999/xlink'
        }
        try:
            self.root = ET.fromstring(self.svg_content)
        except ET.ParseError:
            self.root = None
            self.findings.append("SVG文件格式错误，无法解析。")
            self.risk_score += 50

    def analyze(self):
        if not self.root:
            return self.risk_score, self.findings

        self._detect_scripts()
        self._extract_and_analyze_links()
        self._ocr_for_hidden_text()  # 仍然调用，但内部逻辑已改变

        return self.risk_score, self.findings

    def _detect_scripts(self):
        scripts = self.root.findall('.//{http://www.w3.org/2000/svg}script')
        if scripts:
            self.risk_score += 100
            self.findings.append(f"高危：SVG中检测到 {len(scripts)} 个<script>标签，可能执行恶意代码。")

    def _extract_and_analyze_links(self):
        links = self.root.findall('.//svg:a', self.namespaces)
        urls = []
        for link in links:
            url = link.get('{http://www.w3.org/1999/xlink}href') or link.get('href')
            if url:
                urls.append(url)
                text_element = link.find('.//svg:text', self.namespaces)
                text = text_element.text if text_element is not None else "[无可见文本]"
                self.findings.append(f"发现SVG内链接：文本='{text}', URL='{url}'")
                if re.search(r'([a-z0-9]+(-[a-z0-9]+)*\.)+[a-z]{2,}', text, re.IGNORECASE):
                    if urlparse(text).netloc.lower() != urlparse(url).netloc.lower():
                        self.risk_score += 50
                        self.findings.append(f"警告：SVG链接文本 '{text}' 与实际目标URL '{url}' 的域名不匹配，高度可疑。")
        return urls

    def _ocr_for_hidden_text(self):
        """
        【功能已禁用】
        由于缺少Cairo环境依赖，此功能已被禁用。
        原功能是使用OCR技术从SVG图像中提取被渲染为路径的文本。
        """
        self.findings.append("提示：OCR功能因环境依赖问题已禁用，跳过SVG图像内隐藏文本的检测。")
        # 直接返回，不做任何操作
        return


# ==============================================================================
# 模块2: AI生成文本检测器 (无改动)
# ==============================================================================
class AiTextDetector:
    # ... (这部分代码与原来完全相同)
    def __init__(self, model_name="roberta-base-openai-detector"):
        try:
            self.tokenizer = AutoTokenizer.from_pretrained(model_name)
            self.model = AutoModelForSequenceClassification.from_pretrained(model_name)
            self.pipeline = pipeline("text-classification", model=self.model, tokenizer=self.tokenizer)
            self.enabled = True
        except Exception as e:
            print(f"警告：无法加载AI文本检测模型 '{model_name}'. 该功能将被禁用。错误: {e}")
            self.enabled = False

    def predict(self, text):
        if not self.enabled or not text.strip():
            return False, 0.0
        try:
            results = self.pipeline(text, truncation=True, max_length=510)
            for result in results:
                if result['label'] == 'Fake':
                    return True, result['score']
            return False, 0.0
        except Exception as e:
            print(f"AI文本检测时出错: {e}")
            return False, 0.0


# ==============================================================================
# 模块3: 主邮件分析器 (无改动)
# ==============================================================================
class PhishGuard:
    # ... (这部分代码与原来完全相同)
    def __init__(self):
        self.ai_detector = AiTextDetector()
        self.total_risk_score = 0
        self.analysis_report = []

    def analyze_email(self, eml_file_path):
        self.total_risk_score = 0
        self.analysis_report = [f"开始分析邮件: {eml_file_path}\n" + "=" * 50]
        with open(eml_file_path, 'rb') as f:
            msg = email.message_from_binary_file(f, policy=default)
        self._analyze_headers(msg)
        body_text = ""
        svg_contents = []
        if msg.is_multipart():
            for part in msg.walk():
                content_type = part.get_content_type()
                content_disposition = str(part.get("Content-Disposition"))
                if "attachment" not in content_disposition:
                    if content_type == "text/plain":
                        body_text += part.get_payload(decode=True).decode(part.get_content_charset() or 'utf-8',
                                                                          errors='ignore')
                    elif content_type == "text/html":
                        html_content = part.get_payload(decode=True).decode(part.get_content_charset() or 'utf-8',
                                                                            errors='ignore')
                        soup = BeautifulSoup(html_content, 'lxml')
                        for svg_tag in soup.find_all('svg'):
                            svg_contents.append(str(svg_tag))
                        body_text += soup.get_text()
                if content_type == "image/svg+xml":
                    filename = part.get_filename()
                    self.analysis_report.append(f"发现SVG附件: {filename}")
                    svg_contents.append(part.get_payload(decode=True).decode('utf-8'))
        else:
            body_text = msg.get_payload(decode=True).decode(msg.get_content_charset() or 'utf-8', errors='ignore')
        if not svg_contents:
            self.analysis_report.append("邮件中未发现SVG内容。")
        else:
            self.analysis_report.append(f"共发现 {len(svg_contents)} 处SVG内容，开始逐一分析...")
            for i, svg_data in enumerate(svg_contents):
                self.analysis_report.append(f"\n--- 分析第 {i + 1} 个SVG ---")
                svg_analyzer = SvgAnalyzer(svg_data)
                score, findings = svg_analyzer.analyze()
                self.total_risk_score += score
                self.analysis_report.extend(findings)
        self.analysis_report.append("\n--- AI生成文本分析 ---")
        is_ai, probability = self.ai_detector.predict(body_text)
        if is_ai:
            self.total_risk_score += int(probability * 25)
            self.analysis_report.append(f"警告：邮件正文有 {probability:.2%} 的可能性由AI生成。")
        else:
            self.analysis_report.append("邮件正文内容不像由AI生成。")
        self._generate_final_report()

    def _analyze_headers(self, msg):
        self.analysis_report.append("\n--- 邮件头分析 ---")
        from_header = msg.get("From", "N/A")
        to_header = msg.get("To", "N/A")
        subject_header = msg.get("Subject", "N/A")
        self.analysis_report.append(f"发件人: {from_header}")
        self.analysis_report.append(f"收件人: {to_header}")
        self.analysis_report.append(f"主题: {subject_header}")
        suspicious_subjects = ['紧急', '验证', '警告', 'urgent', 'verify', 'warning', 'action required']
        for keyword in suspicious_subjects:
            if keyword in subject_header.lower():
                self.total_risk_score += 10
                self.analysis_report.append(f"警告：主题中包含可疑关键词 '{keyword}'。")

    def _generate_final_report(self):
        self.analysis_report.append("\n" + "=" * 50)
        self.analysis_report.append("分析完成")
        self.analysis_report.append(f"最终风险评分: {self.total_risk_score}")
        if self.total_risk_score >= 100:
            verdict = "高危钓鱼邮件 (HIGH RISK)"
        elif self.total_risk_score >= 50:
            verdict = "中度可疑邮件 (MEDIUM RISK)"
        elif self.total_risk_score > 0:
            verdict = "低度可疑邮件 (LOW RISK)"
        else:
            verdict = "邮件看起来安全 (LOOKS SAFE)"
        self.analysis_report.append(f"最终结论: {verdict}")

    def print_report(self):
        for line in self.analysis_report:
            print(line)


# ==============================================================================
# 使用示例 (无改动)
# ==============================================================================
if __name__ == '__main__':
    # ... (这部分代码与原来完全相同)
    from email.mime.multipart import MIMEMultipart
    from email.mime.text import MIMEText
    from email.mime.image import MIMEImage

    phishing_svg_content = """<svg xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink" width="300" height="100"><script>alert('This could be malicious code!');</script><rect width="100%" height="100%" fill="lightblue"/><a xlink:href="https://evil-site.com/login-steal"><text x="50%" y="50%" dominant-baseline="middle" text-anchor="middle" font-size="20" fill="red">Click Here to Verify Your Account</text></a></svg>"""
    ocr_svg_content = """<svg width="400" height="80" xmlns="http://www.w3.org/2000/svg"><defs><style type="text/css">@import url('https://fonts.googleapis.com/css?family=Roboto');</style></defs><path d="M20 40 L380 40" stroke="none" fill="none"/><text font-family="Roboto" font-size="24" fill="black"><textPath xlink:href="#curve">您的密码已过期，请立即更新</textPath></text></svg>"""
    email_body_html = f"""<html><body><p>尊敬的用户，</p><p>系统检测到您的账户存在异常活动，请立即点击下方按钮进行安全验证，以防账户被盗。</p>{phishing_svg_content}<p>如果您不执行此操作，您的帐户将被永久暂停。 这是一项重要的安全措施，旨在保护您和我们的社区。</p><p>此致</p></body></html>"""

    msg = MIMEMultipart('related')
    msg['Subject'] = '【紧急警告】您的账户需要立即验证'
    msg['From'] = 'security-alert@bank-of-security.com'
    msg['To'] = 'victim@example.com'
    msg_alternative = MIMEMultipart('alternative')
    msg.attach(msg_alternative)
    msg_text = MIMEText("This is the alternative plain text part.")
    msg_alternative.attach(msg_text)
    msg_html = MIMEText(email_body_html, 'html')
    msg_alternative.attach(msg_html)
    svg_attachment = MIMEImage(ocr_svg_content.encode('utf-8'), 'svg+xml')
    svg_attachment.add_header('Content-Disposition', 'attachment', filename='verification.svg')
    msg.attach(svg_attachment)

    eml_filename = "sample_phishing_email.eml"
    with open(eml_filename, 'w') as f:
        f.write(msg.as_string())
    print(f"已创建测试邮件文件: {eml_filename}\n")

    detector = PhishGuard()
    detector.analyze_email(eml_filename)
    detector.print_report()
    os.remove(eml_filename)