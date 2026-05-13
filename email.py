# Email Risk Analyzer
# Detects suspicious patterns in email content

import re

def analyze_email(email_text):
    risk_score = 0
    warnings = []

    urgent_words = [
        "urgent", "immediately", "act now", "limited time",
        "verify now", "final warning", "account suspended"
    ]

    sensitive_words = [
        "password", "otp", "pin", "credit card",
        "bank account", "login details", "ssn"
    ]

    # Check urgent language
    for word in urgent_words:
        if word in email_text.lower():
            risk_score += 2
            warnings.append("Urgent or pressure-based language found")
            break

    # Check sensitive data requests
    for word in sensitive_words:
        if word in email_text.lower():
            risk_score += 3
            warnings.append("Request for sensitive information found")
            break

    # Check links
    links = re.findall(r'https?://\S+|www\.\S+', email_text)

    if links:
        risk_score += 2
        warnings.append("Email contains links")

        for link in links:
            if re.search(r'\d+\.\d+\.\d+\.\d+', link):
                risk_score += 2
                warnings.append("Suspicious IP-based link found")
                break

    # Check suspicious attachments
    suspicious_files = re.findall(r'\S+\.(exe|bat|cmd|scr|zip)', email_text.lower())

    if suspicious_files:
        risk_score += 3
        warnings.append("Suspicious attachment type mentioned")

    # Final decision
    if risk_score >= 6:
        status = "HIGH RISK"
    elif risk_score >= 3:
        status = "MEDIUM RISK"
    else:
        status = "LOW RISK"

    return status, risk_score, warnings


email = input("Enter email content:\n")

status, score, warnings = analyze_email(email)

print("\nEmail Risk Analysis Result")
print("--------------------------")
print("Status:", status)
print("Risk Score:", score)

if warnings:
    print("Warnings:")
    for warning in warnings:
        print("-", warning)
else:
    print("No major suspicious patterns found")