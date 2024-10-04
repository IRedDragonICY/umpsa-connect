from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.webdriver.edge.options import Options
from selenium.webdriver.edge.service import Service as EdgeService
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
import csv
import sys
import os

def main():
    url = "http://2.2.2.2/login.html"
    options = Options()
    options.add_argument('--headless')
    options.page_load_strategy = 'eager'
    service = EdgeService(executable_path="msedgedriver")

    credential_file = 'credentials.csv'

    try:
        with open(credential_file, 'r', newline='') as infile:
            reader = csv.DictReader(infile)
            fieldnames = reader.fieldnames
            first_row = next(reader, None)
            if not first_row:
                print("Tidak ada kredensial yang tersedia di file CSV.")
                sys.exit()
            username = first_row['Username']
            password = first_row['Password']
            remaining_credentials = list(reader)
    except FileNotFoundError:
        print(f"File kredensial {credential_file} tidak ditemukan.")
        sys.exit()
    except Exception as e:
        print(f"Terjadi kesalahan saat membaca kredensial: {e}")
        sys.exit()

    with webdriver.Edge(options=options, service=service) as driver:
        driver.get(url)
        wait = WebDriverWait(driver, 5)

        try:
            username_field = wait.until(EC.presence_of_element_located((By.ID, "user.username")))
            password_field = driver.find_element(By.ID, "user.password")
            login_button = driver.find_element(By.ID, "ui_login_signon_button")

            username_field.send_keys(username)
            password_field.send_keys(password)
            login_button.click()

            aup_text_element = wait.until(EC.presence_of_element_located((By.CLASS_NAME, "cisco-ise-aup-text")))
            driver.execute_script("arguments[0].scrollTop = arguments[0].scrollHeight;", aup_text_element)

            wait.until(EC.element_to_be_clickable((By.ID, "ui_aup_accept_button"))).click()

            wait.until(EC.title_is('Success'))
            print("Login berhasil")

        except Exception as e:
            print(f"Terjadi kesalahan selama login: {e}")
            sys.exit()

    if remaining_credentials:
        with open(credential_file, 'w', newline='') as outfile:
            writer = csv.DictWriter(outfile, fieldnames=fieldnames)
            writer.writeheader()
            writer.writerows(remaining_credentials)
    else:
        os.remove(credential_file)

if __name__ == "__main__":
    main()
