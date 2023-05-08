"""
 *  Authors: Imtiaz Karim, Syed Rafiul Hussain, Abdullah Al Ishtiaq
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
"""

#!/usr/bin/python
# import socket programming library
import socket
import os
import time
import sys
# import serial
from stat import *
import logging
import subprocess
# import thread module
from thread import *
import threading
global device
print_lock = threading.Lock()

# GLOBAL VARIABLES
OS_LINUX_RUNTIME = ['/bin/bash', '-l', '-c']

TASKLIT = 'tasklist'
KILL = ['taskkill', '/F', '/IM']

DEFAULT_BAUD=115200
DEFAULT_TIMEOUT=1

##################################################################################################

def run_command(command):
	p = subprocess.Popen(command,
						 stdout=subprocess.PIPE,
						 stderr=subprocess.STDOUT)
	return iter(p.stdout.readline, b'')

# Check if a process is running
def isProcessRunning(serviceName):
    command = ''
    command = "pidof " + serviceName
    command = OS_LINUX_RUNTIME + [command]

    result = subprocess.check_output(command)
    return serviceName in result


# Used for killing (ADB) process
def killProess(serviceName):
    command = ''
    command = "ps -ef | grep " + serviceName + " | grep -v grep | awk '{print($2}' | xargs sudo kill -9"
    command = OS_LINUX_RUNTIME + [command]
    subprocess.check_output(command)
    return


def run_adb_command(command):

    result = str(run_command(command))

    while True:
        if "error" in result.lower():
            print('reboot adb server')
            processName = "adb"

            if isProcessRunning(processName):
                print('### Killing the ADB process ###')
                killProess(processName)

            time.sleep(1)

            adb_usb_command = 'adb usb'
            print('### Trying to fix adb error with adb usb')
            run_command(adb_usb_command)

            print('ADB server stopping')
            run_command('adb kill-server')
            print('ADB Server killed')

            print('ADB server starting')
            run_command('adb start-server')
            print('ADB Server started')
            print('ADB Server restart done')

        else:
            break

    return result

def restart_adb_server():
    result = ''
    print('Killing Server')
    result = run_adb_command('adb kill-server')
    time.sleep(1)
    print('Starting server')
    result = run_adb_command('adb start-server')
    print('Server Restart done.')
    return True


# Please implement this function according to the device under test
def airplane_mode_on():
    result = 1
    print('airplane mode on\n')
    time.sleep(1)
    
    if device == "all":
        print('second adb call\n')
        subprocess.call("adb shell input tap 1325 370", shell=True) 

        print('second adb call 2\n')
    else:
        print("Please implement")
    return result


# Please implement this function according to the device under test
def airplane_mode_off():
    result = 1
    print('airplane mode off')
    time.sleep(1)
    if device == "all":
        subprocess.call("adb shell input tap 1325 370", shell=True)
    else:
        print("Please implement")
    return result

###################################################################################################

def handle_reset(client_socket):
   
    # turn off the airplane mode
    print('--- START: Handling RESET command ---')
    airplane_mode_on()
    time.sleep(1)
    client_socket.send('DONE\n')
    print('### DONE: Handling RESET command ###')



def handle_enable_s1(client_socket):
    # stop and start cellular connectivity => turn on and then off the airplane mode
    print('--- START: Handling ENABLE_S1 command ---')
    print('Enabling airplane mode')
    airplane_mode_on()

    print('Sleeping for 1 second')
    time.sleep(1)

    print('Disabling airplane mode')
    airplane_mode_off()

    client_socket.send('DONE\n')
    print('### DONE: Handling ENABLE_S1 command ###')
    return


def handle_ue_reboot(client_socket):
    print('--- START: Handling UE REBOOT command ----')
    print('Enabling airplane mode')
    airplane_mode_on()


    time.sleep(5) 

    print('@@@@@@@@@@@@@@@ SENDING DONE @@@@@@@@@@@@@@@@@@@')
    client_socket.send('DONE\n')
    print('### DONE: Handling UE REBOOT command ###')
    return


def handle_adb_server_restart(client_socket):
    print('-- START: Handling ADB SERVER RESTART  command ---')

    result = restart_adb_server()

    client_socket.send('DONE\n')
    print('### DONE: Handling ADB SERVER RESTART command ###')
    return

####################################################################################################
# thread fuction
def client_handler(client_socket):
    while True:

        # data received from client
        data = client_socket.recv(1024)

        if not data:
            print('Bye')
            # lock released on exit
            print_lock.release()
            break

        command = data.lower()

        if "reset" in command:
            handle_reset(client_socket)

        elif "enable_s1" in command:
            handle_enable_s1(client_socket)

        elif "ue_reboot" in command:
            handle_ue_reboot(client_socket)

        elif "adb_server_restart" in command:
            handle_adb_server_restart(client_socket)

    client_socket.close()
    print('--- AIRPLANE MODE ON BEFORE EXIT ---')
    airplane_mode_on()

def Main():
    global device
    host = ""
    if (len(sys.argv)<2):
        print('Usage: resetter.py <device name> all')
        exit()

    print(str(sys.argv))
    device = sys.argv[1]
    print('#############################################')
    print('######### UE Controller started #############')
    print('#############################################')

    print('Initializing the controller...')
    #airplane_mode_on()
    try:
        killProess("adb")
        print('ADB has been killed')
        time.sleep(1)
    except:
        print('ERROR: In killing adb process!')

    # AIRPLANE MODE ON.
    
    # reverse a port on your computer
    # in our case it is 12345 but it
    # can be anything

    port = 61000
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind((host, port))
    print("socket binded to post", port)

    # put the socket into listening mode
    s.listen(5)
    print("socket is listening")
    if device == "all":
        subprocess.call("adb shell exit",shell=True)
    # a forever loop until client wants to exit
    while True:
        # establish connection with client
        client_socket, addr = s.accept()

        # lock acquired by client
        print_lock.acquire()
        print('Connected to :', addr[0], ':', addr[1])

        # Start a new thread and return its identifier
        start_new_thread(client_handler, (client_socket,))
    s.close()


if __name__ == '__main__':
    Main()