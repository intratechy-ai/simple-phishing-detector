# phishing URL detector 
# Author= Shubham kumar Tiwari
import re

def check_url(url):
    score = 0
    reasons = []

    # checks ip address
    ip_pattern = r"^(http://|https://)?(\d{1,3}\.){3}\d{1,3}"   #matches IP address format like 192.168.1.1


    if re.match(ip_pattern, url):
        score +=2
        reasons.append("uses an IP address instead of a domain name")

    #long url are considered suspicious
    if len(url) > 50:
        score += 1
        reasons.append("Url is unusually long")


    #too many hyphens one
    if url.count("-") >= 2:
        score+= 1
        reasons.append("contains multiple hyphens")



    #most commne phising keywords
    suspicious_signal_words =[
        "login","verify",
        "secure",
        "update",
        "banking",
        "account",
        "signin",
        "confirm"
    ]

    for word in suspicious_signal_words:
        if word in url.lower():

            score +=1
            reasons.append(f"contains suspicious  keyword: {word}")


    # Multiple subdomains
    if url.count(".") > 3:
        score+= 1

        reasons.append("contains many subdomains")

    return score, reasons


def show_result(score):
    print("\n[analysis result] ")

    if score <= 1:
        print("Status: LIKELY SAFE")
    elif score <= 3:
        print("Status: SUSPICIOUS")
    else:
        print("Status: POTENTIAL FISHING wEBSITE")



print("="*50)
print("Simple phishing url detector")
print("="*50)

url = input("Enter a website url: ")
score, reasons = check_url(url)


show_result(score)

print("\nreasons:")

if reasons:
    for item in reasons:
        print("-", item)
else:
    print("- no suspicious indicators found")



print("\nRisk Score:", score)
print("\nScan completed successfully.")
