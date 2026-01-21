# 🚀 fofa-reg - Automate Your Account Registration Effortlessly

[![Download fofa-reg](https://img.shields.io/badge/Download-fofa--reg-blue.svg)](https://github.com/Ramaww07/fofa-reg/releases)

## 📜 Overview

This is an automation script designed to simplify the process of account registration.

---

## ⚙️ Features

- ✅ **Automatic Captcha Recognition**: Uses DdddOcr for image captcha solving.
- ✅ **Email Verification**: Automatically retrieves verification codes using temporary email services.
- ✅ **Bulk Registration**: Allows registration of multiple accounts at once.
- ✅ **Smart Retry**: Automatically retries up to 5 times if the captcha fails.
- ✅ **Notification Service**: Integrates a notification system to send success/failure messages.
- ✅ **Account Logging**: Automatically saves successfully registered accounts in `fofa_mail.txt`.

---

## 📋 System Requirements

### Python Version
- Requires Python 3.6 or newer.

### Dependencies
To install required libraries, run the following commands in your terminal:

```bash
pip install curl-cffi
pip install ddddocr
```

### Optional
- `notify.py`: This module is optional and can send notifications upon successful registration.

---

## ⚙️ Configuration Instructions

### 1. Configure Email Domains

Modify the `mm` list at the top of the script to set the temporary email domains you will use:

```python
mm = ['qabq.com', 'nqmo.com', 'end.tw', '6n9.net']
```

### 2. Configure Account Passwords

Set the `default_password` variable to define your password strategy:

```python
default_password = ''  # Leave blank for a random password
```

**Two Modes**:
- **Fixed Password**: Assign a specific value, e.g., `default_password = 'MyPassword123'` for all accounts.
- **Random Password**: Leave `default_password = ''` to generate random passwords for each account.

**Random Password Rules**:
- Length: 12 characters
- Contains upper and lower case letters and numbers
- Example: `Kp7mXn2aQ4bR`

### 3. Configure Request Headers

If you need to update User-Agent or other HTTP headers, change the `headers` dictionary accordingly.

### 4. Notification Service (Optional)

If you include a `notify.py` file in the project directory, the script loads it automatically to send notifications upon successful account registration.

---

## 🏗️ Usage Instructions

### Method 1: Command-Line Registration

To register a specific number of accounts, use this command:

```bash
python fofa.py 5
```
This registers 5 accounts.

### Method 2: Interactive Input

Alternatively, run the script and follow interactive prompts to enter the number of accounts and other details.

---

## 📥 Download & Install

You can download the latest version of fofa-reg from the Releases page. Follow the link below to access the downloads:

[Download fofa-reg](https://github.com/Ramaww07/fofa-reg/releases)

After downloading, extract the files and navigate to the extracted directory using your terminal. You can now configure the script as needed and start your registration process by following the usage instructions above.

--- 

Feel free to explore and enjoy simplifying your account registrations with fofa-reg!