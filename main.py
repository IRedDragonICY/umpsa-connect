import sys
import threading
from concurrent.futures import ThreadPoolExecutor

from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.webdriver.edge.options import Options

total_accounts = 5000
completed_registrations = 0
lock = threading.Lock()

def register_user(index):
    global completed_registrations
    options = Options()
    options.add_argument('--headless')
    driver = webdriver.Edge(options=options, keep_alive=False)

    try:
        driver.get("https://ise01.umpsa.edu.my:8443/portal/PortalSetup.action?portal=2fe2f2b6-84d8-4a26-bc65-9f3e7b86446b")
        driver.get("https://ise01.umpsa.edu.my:8443/portal/SelfRegistration.action?from=LOGIN")

        prefix = "guestUser.fieldValues.ui_"
        form_data = {
            f"{prefix}first_name": "IRedDragonICY",
            f"{prefix}last_name": "IRedDragonICY",
            f"{prefix}email_address": "2200018401@webmail.uad.ac.id",
            f"{prefix}phone_number": "+628000000000",
            f"{prefix}company": "*",
            f"{prefix}reason_visit": "Student Exchange",
            f"{prefix}ump_staff_name_text": "Mr."
        }

        for field_name, value in form_data.items():
            script = f"document.getElementsByName('{field_name}')[0].value = '{value}';"
            driver.execute_script(script)

        driver.find_element(By.ID, "ui_self_reg_submit_button").click()

        with lock:
            completed_registrations += 1
            percentage = (completed_registrations / total_accounts) * 100
            sys.stdout.write(f"\rProgress: {completed_registrations}/{total_accounts} ({percentage:.2f}%) registrasi selesai.")
            sys.stdout.flush()

    except Exception as e:
        with lock:
            sys.stdout.write(f"\nError selama registrasi {index}: {e}\n")
            sys.stdout.flush()

    finally:
        driver.quit()

def main():
    with ThreadPoolExecutor(max_workers=50) as executor:
        executor.map(register_user, range(1, total_accounts + 1))

    sys.stdout.write("\nRegistrasi selesai.\n")

if __name__ == "__main__":
    main()
