import os
import time
import sys
import requests
import socket
import json
from DecimScanner import *

def cls():
    os.system("clear")

class options:

    def network_scans():
        """Network scans using DecimScanner"""
        while True:
            print("(1) TCP Scans")
            print("(2) UDP Scans")
            print("(3) ICMP Scans")
            print("(4) Other")
            print("(<) Back")
            menu_choice = input("Please enter an option from the menu: ")
            if menu_choice in ["1", "2", "3", "4", "<"]:
                break
            else:
                print("Invalid menu choice, please use the number or symbol")
                time.sleep(2)
                cls()

        if menu_choice == "<":
            return
        elif menu_choice == "1":
            cls()
            while True:
                print("(1) SYN Scan")
                print("(2) FIN Scan")
                print("(3) Null Scan")
                print("(4) ACK Scan")
                print("(5) XMAS Scan")
                print("(6) Window Scan")
                print("(7) Idle Scan")
                print("(8) Service Scan")
                print("(<) Back")
                menu_choice = input("Please enter an option from the menu: ")
                if menu_choice in ["1", "2", "3", "4", "5", "6", "7", "8", "<"]:
                    break
                else:
                    print("Invalid menu choice, please use the number or symbol")
                    time.sleep(2)
                    cls()

            if menu_choice != "<":
                while True:
                    try:
                        targets = input("Enter the target(s): ")
                        targets = utils.ValidateTargets(targets)
                        break
                    except ValueError:
                        print("Invalid targets, please enter targets seperated by commas")
                        time.sleep(3)
                        cls()

                while True:
                    ports = input("Please enter the ports you'd like to scan (Enter for default): ")
                    if ports.strip() == "":
                        ports = utils.ValidatePorts(None)
                        break
                    elif "," in ports:
                        try:
                            ports = [int(i) for i in ports.split()]
                            break
                        except ValueError:
                            print(f"Invalid port found")
                            time.sleep(2)
                            cls()
                    else:
                        try:
                            ports = [int(ports)]
                            break
                        except ValueError:
                            print("Invalid port")
                            time.sleep(2)
                            cls()

                if menu_choice == "7":
                    while True:
                        try:
                            zombie = input("Please enter the zombie you'd like to use: ")
                            socket.gethostbyname(zombie)
                            break
                        except socket.gaierror:
                            print("Zombie was unresponsive")
                            time.sleep(2)
                            cls()

                while True:
                    try:
                        timeout = input("Please enter the timeout you'd like to use (Enter for default): ")
                        if timeout.strip() == "":
                            timeout = 3
                        else:
                            timeout = float(timeout)
                        break
                    except ValueError:
                        print("Invalid timeout set")
                        time.sleep(2)
                        cls()

                while True:
                    try:
                        threads = input("Please enter the number of threads (Enter for default): ")
                        if threads.strip() == "":
                            threads = 30
                        else:
                            threads = int(threads)
                        break
                    except ValueError:
                        print("Invalid threads")

                print("Scanning, please wait..")
                ips = []
                for target in targets:
                    try:
                        ips.append(socket.gethostbyname(target))
                    except socket.gaierror:
                        while True:
                            continue_ = (f"""{target} did not respond,
would you like to remove it from the target list? Note that keeping the target may cause errors (Y/n): """)
                            if continue_.lower() in ["y", "yes", " ", ""]:
                                pass
                            elif continue_ in ["n", "no"]:
                                ips.append(target)
                            else:
                                print("Invalid option, please use y or n")
                                time.sleep(3)
                                cls()

                if menu_choice == "1":
                    results = TCPScans.SYNScan(ips, ports, timeout, threads)
                elif menu_choice == "2":
                    results = TCPScans.FINScan(ips, ports, timeout, threads)
                elif menu_choice == "3":
                    results = TCPScans.NullScan(ips, ports, timeout, threads)
                elif menu_choice == "4":
                    results = TCPScans.ACKScan(ips, ports, timeout, threads)
                elif menu_choice == "5":
                    results = TCPScans.XMASScan(ips, ports, timeout, threads)
                elif menu_choice == "6":
                    results = TCPScans.WindowScan(ips, ports, timeout, threads)
                elif menu_choice == "7":
                    results = TCPScans.IdleScan(ips, zombie, ports, timeout, threads)
                elif menu_choice == "8":
                    results = TCPScans.ServiceScan(ips, ports, timeout, threads)

                for ip in ips:
                    for port_result in results[ip]:
                        try:
                            if port_result[1] != "closed" and port_result[1] != "unresponsive":
                                if isinstance(port_result, str):
                                    pass
                                else:
                                    print(f"{ip}: {port_result[0]}: {port_result[1].strip()}")
                        except IndexError:
                            try:
                                print(f"{ip}: {int(port_result[0])}: No banner")
                            except ValueError:
                                print(f"{ip}: {port_result[0]}")
                input("Press enter to go back")
            return

        elif menu_choice == "2":
            cls()
            while True:
                print("(1) UDP connect")
                print("(<) Back")
                menu_choice = input("Please enter an option from the menu: ")
                if menu_choice in ["1", "<"]:
                    break
                else:
                    print(f"Invalid menu choice, please use the number or symbol")
                    time.sleep(2)
                    cls()

            if menu_choice != "<":

                while True:
                    try:
                        targets = input("Enter the target(s): ")
                        targets = utils.ValidateTargets(targets)
                        break
                    except ValueError:
                        print("Invalid targets, please enter targets seperated by commas")
                        time.sleep(3)
                        cls()

                while True:
                    ports = input("Please enter the ports you'd like to scan (Enter for default): ")
                    if ports.strip() == "":
                        ports = utils.ValidatePorts(None)
                        break
                    elif "," in ports:
                        try:
                            ports = [int(i) for i in ports.split()]
                            break
                        except ValueError:
                            print(f"Invalid port found")
                            time.sleep(2)
                            cls()
                    else:
                        try:
                            ports = [int(ports)]
                            break
                        except ValueError:
                            print("Invalid port")
                            time.sleep(2)
                            cls()

                while True:
                    try:
                        timeout = input("Please enter the timeout you'd like to use (Enter for default): ")
                        if timeout.strip() == "":
                            timeout = 3
                        else:
                            timeout = float(timeout)
                        break
                    except ValueError:
                        print("Invalid timeout set")
                        time.sleep(2)
                        cls()

                while True:
                    try:
                        threads = input("Please enter the number of threads (Enter for default): ")
                        if threads.strip() == "":
                            threads = 30
                        else:
                            threads = int(threads)
                        break
                    except ValueError:
                        print("Invalid threads")

                print("Scanning, please wait..")
                ips = []
                for target in targets:
                    try:
                        ips.append(socket.gethostbyname(target))
                    except socket.gaierror:
                        while True:
                            continue_ = (f"""{target} did not respond,
would you like to remove it from the target list? Note that keeping the target may cause errors (Y/n): """)
                            if continue_.lower() in ["y", "yes", " ", ""]:
                                pass
                            elif continue_ in ["n", "no"]:
                                ips.append(target)
                            else:
                                print("Invalid option, please use y or n")
                                time.sleep(3)
                                cls()

                if menu_choice == "1":
                    results = UDPScans.UDPConnect(ips, ports, timeout, threads)
                for ip in ips:
                    for result in results[ip]:
                        if result[1] != "closed" and result[1] != "unresponsive":
                            print(f"{ip}: {result[0]}: {result[1]}")

                input("Press enter to go back")

        elif menu_choice == "3":
            cls()
            while True:
                print("(1) Ping")
                print("(2) IP Scan")
                print("(<) Back")
                menu_choice = input("Please enter an option from the menu: ")
                if menu_choice in ["1", "2", "<"]:
                    break
                else:
                    print("Invalid menu choice, please use the number or symbol")
                    time.sleep(2)
                    cls()

            if menu_choice != "<":

                while True:
                    try:
                        targets = input("Enter the target(s): ")
                        targets = utils.ValidateTargets(targets)
                        break
                    except ValueError:
                        print("Invalid targets, please enter targets seperated by commas")
                        time.sleep(3)
                        cls()

                if menu_choice == "2":
                    while True:
                        ports = input("Please enter the ports you'd like to scan (Enter for default): ")
                        if ports.strip() == "":
                            ports = utils.ValidatePorts(None)
                            break
                        elif "," in ports:
                            try:
                                ports = [int(i) for i in ports.split()]
                                break
                            except ValueError:
                                print(f"Invalid port found")
                                time.sleep(2)
                                cls()
                        else:
                            try:
                                ports = [int(ports)]
                                break
                            except ValueError:
                                print("Invalid port")
                                time.sleep(2)
                                cls()

                while True:
                    try:
                        timeout = input("Please enter the timeout you'd like to use (Enter for default): ")
                        if timeout.strip() == "":
                            timeout = 3
                        else:
                            timeout = float(timeout)
                        break
                    except ValueError:
                        print("Invalid timeout set")
                        time.sleep(2)
                        cls()

                while True:
                    try:
                        threads = input("Please enter the number of threads (Enter for default): ")
                        if threads.strip() == "":
                            threads = 30
                        else:
                            threads = int(threads)
                        break
                    except ValueError:
                        print("Invalid threads")

                if menu_choice == "1":
                    while True:
                        verbose = input("Would you like to use verbosity (Y/n): ")
                        if verbose.strip() in ["", "y", "yes"]:
                            verbose = True
                            break
                        elif verbose in ["n", "no"]:
                            verbose = False
                            break
                        else:
                            print("Invalid menu choice, please use y or no")
                            time.sleep(2)
                            cls()


                print("Scanning, please wait..")

                if menu_choice == "1":
                    results = ICMPScans.ping(targets, timeout, threads, verbose)

                elif menu_choice == "2":
                    results = ICMPScans.IPScan(targets, ports, timeout, threads)

                for target in targets:
                    for result in results[target]:
                        if isinstance(result, str):
                            print(f"{target}: {result}")
                        else:
                            print(f"{target}: {result[0]}: {result[1]}")
                input("Press enter to go back")
            return

        elif menu_choice == "4":
            cls()
            while True:
                print("(1) IKE Scan")
                print("(<) Back")
                menu_choice = input("Please enter an option from the menu: ")
                if menu_choice in ["1", "<"]:
                    break
                else:
                    print("Invalid menu choice, please use the number or symbol")
                    time.sleep(2)
                    cls()

            if menu_choice != "<":

                while True:
                    try:
                        targets = input("Enter the target(s): ")
                        targets = utils.ValidateTargets(targets)
                        break
                    except ValueError:
                        print("Invalid targets, please enter targets seperated by commas")
                        time.sleep(3)
                        cls()


                while True:
                    try:
                        timeout = input("Please enter the timeout you'd like to use (Enter for default): ")
                        if timeout.strip() == "":
                            timeout = 3
                        else:
                            timeout = float(timeout)
                        break
                    except ValueError:
                        print("Invalid timeout set")
                        time.sleep(2)
                        cls()

                while True:
                    try:
                        threads = input("Please enter the number of threads (Enter for default): ")
                        if threads.strip() == "":
                            threads = 30
                        else:
                            threads = int(threads)
                        break
                    except ValueError:
                        print("Invalid threads")

                print("Scanning, please wait..")
                ips = []
                for target in targets:
                    try:
                        ips.append(socket.gethostbyname(target))
                    except socket.gaierror:
                        while True:
                            continue_ = (f"""{target} did not respond,
would you like to remove it from the target list? Note that keeping the target may cause errors (Y/n): """)
                            if continue_.lower() in ["y", "yes", " ", ""]:
                                pass
                            elif continue_ in ["n", "no"]:
                                ips.append(target)
                            else:
                                print("Invalid option, please use y or n")
                                time.sleep(3)
                                cls()

                if menu_choice == "1":
                    results = OtherScans.IKEScan(ips, timeout, threads)
                for ip in ips:
                    for result in results[ip]:
                        if result[1] != "closed" and result[1] != "unresponsive":
                            print(f"{ip}: {result[0]}")

    def DNS_scans():
        while True:
            print("(1) Reverse DNS")
            print("(2) Get host by name")
            print("(3) DNS Query")
            print("(<) Back")
            menu_choice = input("Please enter an option from the menu: ")
            if menu_choice in ["1", "2", "3", "<"]:
                break
            else:
                print("Invalid menu choice, please use the number or symbol")
                time.sleep(2)
                cls()

        if menu_choice != "<":
            while True:
                try:
                    targets = input("Enter the target(s): ")
                    targets = utils.ValidateTargets(targets)
                    break
                except ValueError:
                    print("Invalid targets, please enter targets seperated by commas")
                    time.sleep(3)
                    cls()

            if menu_choice == "3":
                querystr = input("Please enter the query you'd like to use: ")

            while True:
                try:
                    threads = input("Please enter the number of threads (Enter for default): ")
                    if threads.strip() == "":
                        threads = 30
                    else:
                        threads = int(threads)
                    break
                except ValueError:
                    print("Invalid threads")

            if menu_choice == "1":
                results = DNSScans.ReverseDNS(targets, threads)
            elif menu_choice == "2":
                results = DNSScans.Gethostbyname(targets, threads)
            elif menu_choice == "3":
                results = DNSScans.DNSQuery(targets, querytype, threads)
            print(results)
            input()
        return

    def web_scans():
        cls()
        while True:
            print("(1) Directory check")
            print("(2) Status check")
            print("(3) Web crawl")
            print("(4) Sub domain")
            print("(<) Back")
            menu_choice = input("Please enter an option from the menu: ")
            if menu_choice in ["1", "2", "3", "4", "<"]:
                break
            else:
                print("Invalid menu choice, please use the number or symbol")
                time.sleep(2)
                cls()

        if menu_choice != "<":

            while True:
                URLs = input("Please enter the URLs you'd like to check: ")
                URLs = utils.ValidateURL(URLs)

            if menu_choice == "1" or menu_choice == "4":
                while True:
                    wordlist = input("Please enter the location of wordlist you'd like to use: ")
                    if os.path.exists(wordlist):
                        break
                    else:
                        print("Unable to locate wordlist")
                        time.sleep(2)
                        cls()


            elif menu_choice == "2":
                while True:
                    statuses = input("Please enter the statuses you'd like to check for (Enter for default): ")
                    if statuses.strip() == "":
                        statuses = None
                        break
                    else:
                        try:
                            statuses = [int(i) for i in statuses]
                            break
                        except ValueError:
                            print("Invalid status found")
                            time.sleep(2)
                            cls()

            if menu_choice != "2":
                userAgent = input("Please enter the user agent you'd like to use (Enter for default): ")
                if userAgent.strip() == "":
                    userAgent = None
                while True:
                    verbose = input("Would you like to use verbosity (Y/n): ")
                    if verbose.strip() in ["", "y", "yes"]:
                        verbose = True
                        break
                    elif verbose in ["n", "no"]:
                        verbose = False
                        break
                    else:
                        print("Invalid menu choice, please use y/n")
                        time.sleep(2)
                        cls()

                if menu_choice == "3":
                    while True:
                        depth = input("Please enter the depth you'd like to scan (Enter for default): ")
                        try:
                            depth = int(depth)
                            break
                        except ValueError:
                            print("Invalid depth provided, please use a number")
                            time.sleep(2)
                            cls()

            while True:
                try:
                    timeout = input("Please enter the timeout you'd like to use (Enter for default): ")
                    if timeout.strip() == "":
                        timeout = 3
                    else:
                        timeout = float(timeout)
                    break
                except ValueError:
                    print("Invalid timeout set")
                    time.sleep(2)
                    cls()

            while True:
                try:
                    threads = input("Please enter the number of threads (Enter for default): ")
                    if threads.strip() == "":
                        threads = 30
                    else:
                        threads = int(threads)
                    break
                except ValueError:
                    print("Invalid threads")

            if menu_choice == "1":
                results = WebScans.DirCheck(URLs, wordlist, timeout, threads, userAgent, verbose)
                for url in URLs:
                    for result in results[url]:
                        if len(result) == 2:
                            print(f"{url}: {result[0]}: {result[1]}")
                            input("Press enter to go back")

            elif menu_choice == "2":
                results = WebScans.StatusCheck(URLs, statuses, timeout, threads)
                for url in URLs:
                    for result in results[url]:
                        print(f"{url}: {result}")
                        input("Press enter to go back")

            elif menu_choice == "3":
                results = WebScans.WebCrawl(URLs, timeout, threads, depth, userAgent, verbose)
                for url in URLs:
                    for result in results[url]:
                        print(f"{url}: {reuslt}")
                        input("Press enter to go back")

            elif menu_choice == "4":
                results = SubDomain(URLs, wordlist, timeout, threads, userAgent, verbose)
                for url in URLs:
                    for result in results:
                        print(f"{url}: {result[0]}: {result[1]}")
                        input("Press enter to go back")

    def bluetooth_scans():
        while True:
            print("(1) Get nearby")
            print("(2) Service scan")
            print("(<) Back")
            menu_choice = input("Please enter an option from the menu: ")
            if menu_choice in ["1", "2", "<"]:
                break
            else:
                print("Invalid menu choice, please use the number or symbol")
                time.sleep(2)
                cls()

        if menu_choice == "<":
            return

        elif menu_choice == "1":
            while True:
                print("(1) Scan by duration")
                print("(2) Scan by device count")
                print("(<) Back to main menu")
                menu_choice = input("Please enter an option from the menu: ")
                if menu_choice in ["1", "2", "<"]:
                    break
                else:
                    print("Invalid menu choice, please use the number or symbol")
                    time.sleep(2)
                    cls()
            if menu_choice == "<":
                return
            elif menu_choice == "1":
                while True:
                    try:
                        duration = int(input("Please enter how long you'd like to scan for: "))
                        break
                    except ValueError:
                        print("Invalid duration!")
                        time.sleep(2)
                        cls()
                nearby = BluetoothScans.GetNearby(duration=duration)
            else:
                while True:
                    try:
                        duration = int(input("Please enter how devices you'd like to find: "))
                        break
                    except ValueError:
                        print("Invalid device count!")
                        time.sleep(2)
                        cls()
                nearby = BluetoothScans.GetNearby(devicecount=devicecount)
            for device in nearby:
                print(device)
            input("Press enter to go back")

        elif menu_choice == "2":
            if menu_choice != "<":
                while True:
                    try:
                        targets = input("Enter the target(s): ")
                        targets = utils.ValidateTargets(targets)
                        break
                    except ValueError:
                        print("Invalid targets, please enter targets seperated by commas")
                        time.sleep(3)
                        cls()

                while True:
                    try:
                        threads = input("Please enter the number of threads (Enter for default): ")
                        if threads.strip() == "":
                            threads = 30
                        else:
                            threads = int(threads)
                        break
                    except ValueError:
                        print("Invalid threads")

            results = BluetoothScans.ServiceScan(targets, threads)
            for target in targets:
                for result in target[result]:
                    print(f"{target}: {result}")
            input("Press enter to go back")

    def OSINT():
        cls()
        while True:
            print("(1) Instagram search")
            print("(2) Facebook search")
            print("(3) Twitter search")
            print("(4) Email lookup")
            print("(5) Exif")
            print("(<) Back")
            menu_choice = input("Please enter an option from the menu: ")
            if menu_choice in ["1", "2", "3", "4", "5", "<"]:
                break
            else:
                print("Invalid menu choice, please use the number or symbol")
                time.sleep(2)
                cls()

        if menu_choice == "<":
            return

        if menu_choice not in ["4", "5"]:
            if os.path.exists("./config/googlecse.json"):
                with open("./config/googlecse.json", "r") as f:
                    data = json.load(f)
                    apikey = data['apikey']
            else:
                while True:
                    continue_ = input("""Unable to access the google cse config file.
                    Please ensure this isn't deleted and values are not default.
                    Would you like to continue anyways? (y/N): """)
                    if continue_.lower().strip() in ["", "yes", "no", "y", "n"]:
                        break
                    else:
                        print("Invalid choice, please use y or n")
                        time.sleep(2)
                        cls()
                if continue_.lower().strip() in ["", "no", "n"]:
                    return
                else:
                    data = None
            if data is not None:
                q = input("Please enter the name or account you'd like to search for: ")
                if menu_choice == "1":
                    cx = data['instagram']
                elif menu_choice == "2":
                    cx = data['facebook']
                elif menu_choice == "3":
                    cx = data['twitter']

                if "default" in cx:
                    while True:
                        continue_ = input("""Google CSE has not been configured.
                        Would you like to continue anyways? (y/N): """)
                        if continue_.lower().strip() in ["", "yes", "no", "y", "n"]:
                            cls()
                            break
                        else:
                            print("Invalid choice, please use y or n")
                            time.sleep(2)
                            cls()
                    if continue_.lower().strip() in ["", "no", "n"]:
                        return


                url = f"https://www.googleapis.com/customsearch/v1?key={apikey}&cx={cx}&q={q}&start=1"
                response = requests.get(url)
                resp_data = response.json()

                if len(resp_data['items']) <= 20:
                    for item in resp_data['items']:
                        print(f"+ {item['link']}")
                    input()
                else:
                    linkslist = [resp_data['items'][x:x+25] for x in range(0, len(resp_data['items']), 25)]
                    x = 1
                    for links in linkslist:
                        for link in links:
                            print(f"+ {link}")
                        y = input(f"Results {x}/{len(linkslist)}. Press enter to continue or type < to exit")
                        if y == "<":
                            return
                        cls()
                        x += 1









def main():
    """
Handles the main menu
    """
    cls()
    while True:
        print("(1) Network scan")
        print("(2) DNS scan")
        print("(3) Web scan")
        print("(4) Bluetooth")
        print("(5) OSINT")
        print("(<) Exit")
        menu_choice = input("Please pick an option from the menu, by number or symbol: ")
        if menu_choice in ["1", "2", "3", "4", "5", "<", "*"]:
            break
        else:
            print("Please choose an option from the menu")
            time.sleep(2)
            cls()
    global global_options
    if menu_choice == "<":
        sys.exit()
    elif menu_choice == "1":
        options.network_scans()
        main()
    elif menu_choice == "2":
        options.DNS_scans()
        main()
    elif menu_choice == "3":
        options.web_scans()
        main()
    elif menu_choice == "4":
        options.bluetooth_scans()
        main()
    elif menu_choice == "5":
        options.OSINT()
        main()


if __name__ == "__main__":
    if os.geteuid() == 0:
        main()
    else:
        print("Please run this program as root!")
