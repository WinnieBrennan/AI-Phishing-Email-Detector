# PhishGuard AI-SVG Detector

![Language](https://img.shields.io/badge/Language-Python-blue.svg)
![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)

一个基于Python的工具，旨在检测利用AI生成内容和SVG图像混淆技术的新型钓鱼邮件。

A Python-based tool designed to detect modern phishing emails that leverage AI-generated content and SVG image obfuscation techniques.

---

## 🚀 主要功能 (Features)

* **邮件解析**: 直接解析 `.eml` 格式的原始邮件文件，提取邮件头、正文和附件。
* **SVG深度分析**:
    * 检测SVG文件中是否内嵌了高风险的恶意脚本 (`<script>`)。
    * 提取SVG中所有隐藏的链接，并分析链接文本与实际指向地址的差异。
* **AI生成内容检测**: 利用 Hugging Face 的 `roberta-base-openai-detector` 模型，对邮件文本进行分析，判断其由AI生成的可能性。
* **风险评分系统**: 基于邮件主题的可疑关键词、SVG内的恶意指标、AI生成内容概率等多维度信息，为每封邮件计算综合风险分数，并给出明确的危险等级（高/中/低风险）。
* **OCR文本提取 (实验性)**: （需正确配置环境）能够将SVG渲染为图片，并使用OCR技术提取其中被“画”出来的文字，防止攻击者将钓鱼话术隐藏在图像路径中。

## ⚙️ 环境要求 (Prerequisites)

在运行脚本前，请确保您的系统已经安装了以下环境：

* Python 3.8+
* Git
* **Tesseract OCR 引擎**:
    * **Windows**: 从[这里](https://github.com/UB-Mannheim/tesseract/wiki)下载并安装。
    * **macOS**: `brew install tesseract`
    * **Linux (Debian/Ubuntu)**: `sudo apt-get install tesseract-ocr`
* **Cairo Graphics 库** (用于SVG渲染):
    * **Windows**: 安装 [GTK+ for Windows](https://www.msys2.org/) (通过 MSYS2 运行 `pacman -S mingw-w64-x86_64-cairo`)。
    * **macOS**: `brew install cairo`
    * **Linux (Debian/Ubuntu)**: `sudo apt-get install libcairo2-dev`

## 📦 安装与配置 (Installation)

1.  **克隆本仓库到本地:**
    ```bash
    git clone git@github.com:WinnieBrennan/AI-Phishing-Email-Detector.git
    ```

2.  **进入项目目录:**
    ```bash
    cd AI-Phishing-Email-Detector
    ```

3.  **创建并激活Python虚拟环境:**
    ```bash
    # 创建虚拟环境
    python -m venv .venv
    
    # 激活虚拟环境 (Windows PowerShell)
    .\.venv\Scripts\Activate.ps1
    
    # 激活虚拟环境 (macOS/Linux)
    # source .venv/bin/activate
    ```

4.  **安装所有依赖库:**
    ```bash
    pip install beautifulsoup4 lxml Pillow CairoSVG pytesseract transformers torch
    ```

## ▶️ 如何使用 (Usage)

1.  **运行内置的测试样例:**
    直接运行脚本，它会自动生成一个名为 `sample_phishing_email.eml` 的高危钓鱼邮件样本并进行分析。
    ```bash
    python phish_guard_ai_svg.py
    ```

2.  **分析您自己的邮件文件:**
    * 将您需要分析的邮件文件（必须是 `.eml` 格式）放到项目文件夹中。
    * 打开 `phish_guard_ai_svg.py` 脚本，找到文件末尾的 `if __name__ == '__main__':` 部分。
    * 修改 `detector.analyze_email()` 函数中的文件名，指向您自己的邮件文件。
    
    ```python
    if __name__ == '__main__':
        # ... (前面是创建测试文件的代码)
    
        # --- 运行分析器 ---
        detector = PhishGuard()
        
        # 将 "sample_phishing_email.eml" 修改为您自己的文件名
        detector.analyze_email("your_email_file.eml") 
        
        detector.print_report()
    
        # ...
    ```

## 📜 许可证 (License)

本项目采用 [MIT License](LICENSE) 授权。