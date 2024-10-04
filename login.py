from selenium import webdriver
import requests
url = "https://ise01.umpsa.edu.my:8443/portal/DoCoA.action"
driver = webdriver.Edge(keep_alive=False)

driver.get("https://ise01.umpsa.edu.my:8443/portal/PortalSetup.action?portal=2fe2f2b6-84d8-4a26-bc65-9f3e7b86446b") # cookies
driver.get("https://ise01.umpsa.edu.my:8443/portal/SelfRegistration.action?from=LOGIN")


headers = {
    "Accept": "*/*",
    "Accept-Language": "en-US,en;q=0.9",
    "Connection": "keep-alive",
    "Content-Type": "application/x-www-form-urlencoded; charset=UTF-8",
    "DNT": "1",
    "Origin": "https://ise01.umpsa.edu.my:8443",
    "Referer": "https://ise01.umpsa.edu.my:8443/portal/LoginSubmit.action?from=LOGIN",
    "Sec-Fetch-Dest": "empty",
    "Sec-Fetch-Mode": "cors",
    "Sec-Fetch-Site": "same-origin",
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36 Edg/130.0.0.0",
    "X-Requested-With": "XMLHttpRequest",
    "sec-ch-ua": '"Chromium";v="130", "Microsoft Edge";v="130", "Not?A_Brand";v="99"',
    "sec-ch-ua-arch": '"x86"',
    "sec-ch-ua-full-version": '"130.0.2849.13"',
    "sec-ch-ua-mobile": "?0",
    "sec-ch-ua-model": '""',
    "sec-ch-ua-platform": '"Windows"',
    "sec-ch-ua-platform-version": '"15.0.0"',
}

cookies = {
    "checkCookiesEnabled": "value",
    "token": "O1SGNYJOT2J97D1OZIUMO2NWTQ9D0XUV",
    "portalSessionId": "621fbfad-0d5b-4a17-98c7-5413016de46d",
    "APPSESSIONID": "CC6A5CEB291FBDA463151985A34BD98F",
}

data = {
    "delayToCoA": "0",
    "coaType": "Reauth",
    "coaSource": "GUEST",
    "coaReason": "Guest authenticated for network access",
    "waitForCoA": "true",
    "portalSessionId": "621fbfad-0d5b-4a17-98c7-5413016de46d",
    "token": "O1SGNYJOT2J97D1OZIUMO2NWTQ9D0XUV",
}

# If the server uses a self-signed certificate, you might need to disable SSL verification.
# Note: Disabling SSL verification is not recommended for production environments.
response = requests.post(url, headers=headers, cookies=cookies, data=data, verify=False)

print(response.status_code)
print(response.text)
