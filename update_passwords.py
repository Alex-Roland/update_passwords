#!/usr/bin/env python3
import argparse
import getpass
import re
from threading import Thread, currentThread, Lock
from queue import Queue
from datetime import datetime
from netmiko import ConnectHandler
from passlib.hash import sha256_crypt
from passlib.hash import md5_crypt

parser = argparse.ArgumentParser(description = 'change password for local accounts on switches and routers')
parser.add_argument('-u', help = 'username for SSH authentication (default: admin)', default = 'admin')
parser.add_argument('-k', help = 'prompt for SSH password (default: false)', action = 'store_true')
parser.add_argument('-a', help = 'local account for password change (default: admin)', default = 'admin')
parser.add_argument('-d', help = 'file that contains device list (default: devices.csv)', default = 'devices.csv')
parser.add_argument('-t', help = 'number of threads to run', type=int, default = 20)
parser.add_argument('-w', help = 'filename to write report to (default: [time]-password-report.log)', default = 'report.log')
args = parser.parse_args()

NUM_THREADS = args.t # Used to set the maximum amount of parallel connections
PRINT_LOCK = Lock() # This will prevent the output from being sent out of order

NET_DEVICE = { # Basic device dictionary, this is copied in the main function and values are then filled in
    'device_type': '',
    'ip': '',
    'username': args.u,
    'password': '',
    'conn_timeout': 10,
}

def log_file(file): # Function to output to the screen and log the output to a file
    def write_log(msg):
        with PRINT_LOCK:
            with open(file, 'a') as f:
                print(msg, file=f)
                print(msg)
            return msg # Returns the user message so the message can be assigned to a variable for further data processing
    return write_log # Returns nested function

if args.w == 'report.log': # Creates a unique report name
    args.w = f'{datetime.now().strftime("%m-%d-%Y_%H-%M-%S")}-report.log'
    failedfile = f'{datetime.now().strftime("%m-%d-%Y_%H-%M-%S")}-failed-report.log' # If there are any issues, output to a failed file
    successfile = f'{datetime.now().strftime("%m-%d-%Y_%H-%M-%S")}-success-report.log' # Output the success to separate file

logger = log_file(args.w) # Set standard log file
log_failed = log_file(failedfile) # Set log file if there is a failed device
log_success = log_file(successfile) # Set log file for successful password changes

def run_threads(total_devices, mt_function, dq, dd, newpass, exos_hash, cisco_hash, **kwargs): # dq is the device queue and dd is the device details
    total_threads = min(NUM_THREADS, total_devices) # If the amount of loaded devices is less than the max thread count, then limit the amount of threads to device count
    for i in range(total_threads):
        thread_name = f'Thread-{i}'
        worker = Thread(name=thread_name, target=mt_function, args=(dq, dd, newpass, exos_hash, cisco_hash, kwargs))
        worker.start()
    worker.join() # Waits for all threads to stop before ending script

def send_commands(dq, dd, newpass, exos_hash, cisco_hash, kwargs): # Function to perform tasks on each line in the devices file
    while True:
        thread_name = currentThread().getName()

        if dq.empty(): # Check if device queue is empty
            logger(f'{thread_name}: Closing since there are no jobs left in the queue.')
            return

        nc_params = dq.get() # Create variable to fill with device queue information per iteration
        device_detail = dd.get() # Pull original device line, used for more specific device information so we can reference different points of data
        ip = nc_params['ip'] # Pull the IP for output formatting
        hostname = device_detail.split(',')[3] # Hostname is located at index 3 in the device detail line

        logger(f'{thread_name} {ip}: Connecting...')
        try:
            nc = ConnectHandler(**nc_params) # Establishes SSH connectivity
            logger(f'{thread_name} {ip}: Connected!')
            logger(f'{thread_name} {ip}: Sending commands...')
            try:
                if nc_params['device_type'] == 'extreme_exos':
                    oldhash = re.findall(r'{} encrypted ".*?"'.format(args.a), nc.send_command('show config aaa')) # Grab the old hash (used to check if the password changed successfully)
                    logger(nc.send_command_timing(f'configure account {args.a} encrypted {exos_hash}')) # Note: hashed password is in quotes, so argument is sent with single quotes
                    newhash = re.findall(r'{} encrypted ".*?"'.format(args.a), nc.send_command('show config aaa')) # Grab the new hash to check if the password changed successfully
                    if newhash != oldhash:
                        logger(f'{thread_name} {ip} output:\n' + nc.send_command('save'))
                        logger(f'{thread_name} {ip} output: ' + 'Password changed successfully')
                        log_success(f'{thread_name} {ip} output: ' + 'Password changed successfully')
                    else:
                        log_failed(f'{thread_name} {ip} output:' + 'Failed password change')
                elif nc_params['device_type'] == 'enterasys':
                    oldhash = re.findall(r":.*?:", nc.send_command('show config system')) # Grab the old hash (used to check if the password changed successfully)
                    logger(f'{thread_name} {ip} output:\n' + nc.send_command(f'set password {args.a}', expect_string='Please enter new password:'))
                    logger(f'{thread_name} {ip} output:\n' + nc.send_command_timing(f'{newpass}')) # Sends password twice due to verification prompt
                    logger(f'{thread_name} {ip} output:\n' + nc.send_command_timing(f'{newpass}'))
                    newhash = re.findall(r":.*?:", nc.send_command('show config system')) # Grab the new hash to check if the password changed successfully
                    if newhash != oldhash:
                        logger(f'{thread_name} {ip} output: ' + 'Password changed successfully')
                        log_success(f'{thread_name} {ip} output: ' + 'Password changed successfully')
                    else:
                        log_failed(f'{thread_name} {ip} output: ' + 'Failed password change')
                elif nc_params['device_type'] == 'cisco_ios':
                    oldhash = re.findall(r'{} privilege 15 secret 5 .*'.format(args.a), nc.send_command('show run | i username')) # Grab the old hash (used to check if the password changed successfully)
                    oldlinehash = re.findall(r'^ password', nc.send_command('show run | i password | b line'), re.MULTILINE) # Grab the old line hashes (used to check if the password changed successfully)
                    logger(f'{thread_name} {ip} output:\n' + nc.send_command('config t', expect_string=r'config'))
                    output = logger(nc.send_command_timing(f'username {args.a} privilege 15 secret 5 {cisco_hash}'))
                    if 'Can not have both a user password and a user secret' in output:
                        logger(nc.send_command_timing(f'no username {args.a}'))
                        logger(nc.send_command_timing(f'username {args.a} privilege 15 secret 5 {cisco_hash}'))
                    logger(f'{thread_name} {ip} output:\n' + nc.send_command('line con 0', expect_string=r'config-line'))
                    logger(nc.send_command_timing(f'password {newpass}'))
                    logger(f'{thread_name} {ip} output:\n' + nc.send_command('line vty 0 15', expect_string=r'config-line'))
                    logger(nc.send_command_timing(f'password {newpass}'))
                    logger(f'{thread_name} {ip} output: ' + nc.send_command('end', expect_string=rf'{hostname}'))
                    newhash = re.findall(r'{} privilege 15 secret 5 .*'.format(args.a), nc.send_command('show run | i username')) # Grab the new hash to check if the password changed successfully
                    newlinehash = re.findall(r'^ password', nc.send_command('show run | i password | b line'), re.MULTILINE) # Grab the old line hashes (used to check if the password changed successfully)
                    if newhash != oldhash and newlinehash != oldlinehash:
                        logger(f'{thread_name} {ip} output:\n' + nc.save_config())
                        logger(f'{thread_name} {ip} output: ' + 'Password changed successfully')
                        log_success(f'{thread_name} {ip} output: ' + 'Password changed successfully')
                    else:
                        log_failed(f'{thread_name} {ip} output: ' + 'Failed password change')
                elif nc_params['device_type'] == 'cisco_nxos':
                    oldhash = re.findall(r'{} password 5 .*  '.format(args.a), nc.send_command('show run | i user | ex passphrase | ex snmp')) # Grab the old hash (used to check if the password changed successfully)
                    logger(f'{thread_name} {ip} output:\n' + nc.send_command('config t', expect_string=r'config'))
                    logger(nc.send_command(f'username {args.a} password {newpass}'))
                    logger(f'{thread_name} {ip} output: ' + nc.send_command('end', expect_string=rf'{hostname}'))
                    newhash = re.findall(r'{} password 5 .*  '.format(args.a), nc.send_command('show run | i user | ex passphrase | ex snmp')) # Grab the new hash to check if the password changed successfully
                    if newhash != oldhash:
                        logger(f'{thread_name} {ip} output:\n' + nc.save_config())
                        logger(f'{thread_name} {ip} output: ' + 'Password changed successfully')
                        log_success(f'{thread_name} {ip} output: ' + 'Password changed successfully')
                    else:
                        log_failed(f'{thread_name} {ip} output: ' + 'Failed password change')
                elif nc_params['device_type'] == 'ruckus_fastiron':
                    logger(f'{thread_name} {ip} output:\n' + nc.send_command('config t', expect_string=r'config'))
                    logger(nc.send_command(f'username {args.a} password', expect_string='Enter password:'))
                    logger(f'{thread_name} {ip} output:\n' + nc.send_command_timing(f'{newpass}'))
                    logger(nc.send_command('enable super-user-password', expect_string='Enter password:'))
                    logger(f'{thread_name} {ip} output:\n' + nc.send_command_timing(f'{newpass}'))
                    logger(f'{thread_name} {ip} output: ' + nc.send_command('end', expect_string=rf'{hostname}'))
                    # Unable to look at hash for comparision since hash is obfuscated in output
                    logger(f'{thread_name} {ip} output: ' + 'Password changed successfully')
                    log_success(f'{thread_name} {ip} output: ' + 'Password changed successfully')
                else:
                    raise
            except BaseException as e:
                log_failed(f'{thread_name} {ip}: {e}')
                nc.disconnect() # Gracefully closes the SSH connection
                dq.task_done() # Indicate that a formerly enqueued task is complete
                return
            nc.disconnect() # Gracefully closes the SSH connection
            logger(f'{thread_name} {ip}: Done!')
            dq.task_done() # Indicate that a formerly enqueued task is complete
        except BaseException as e:
            log_failed(f'{thread_name} {ip}:\n {e}')
            dq.task_done() # Indicate that a formerly enqueued task is complete
        
def main():
    if args.k: # Prompts for SSH password
        password = getpass.getpass(f'{args.u} password:')

    newpass = getpass.getpass(f'New {args.a} password:')
    exos_hash = sha256_crypt.hash(newpass, rounds=5000) # rounds=5000 removes the rounds prefix in the hash
    cisco_hash = md5_crypt.using(salt_size=4).hash(newpass) # Setting salt_size to 4 makes the password Cisco IOS compatible

    start_time = datetime.now()

    device_queue = Queue(maxsize=0) # Opens a queue for the device network connection information
    device_details = Queue(maxsize=0) # Opens a queue for the detailed device information
    
    try:
        with open(args.d, 'r') as f: # Opens device file and builds the queues
            for device in f:
                if device.split(',')[0][0] == '#': # Checks if a device has been commented out
                    continue
                new_device = NET_DEVICE.copy()
                new_device['device_type'] = device.split(',')[1] # Pulls index 1 (device type), which is used as the connection profile for Netmiko
                new_device['ip'] = device.split(',')[0] # Pulls index 0 (ip), which is the IP to connect to
                new_device['password'] = password # Puts the prompted SSH user password into the dictionary
                device_queue.put(new_device) # Loads device network connetion information into the queue
                device_details.put(device) # Loads detailed device information into the queue
    except BaseException as e:
        log_failed(e)
        exit(255)
        
    total_devices = device_queue.qsize() # Used in the max thread calculation

    run_threads(total_devices=total_devices, mt_function=send_commands, dq=device_queue, dd=device_details, newpass=newpass, exos_hash=exos_hash, cisco_hash=cisco_hash) # Calls the multithreading function
    device_queue.join() # Blocks until all items in the queue have been gotten and processed

    logger(f'\nElapsed time: {str(datetime.now() - start_time)}') # Total runtime for the script

if __name__ == "__main__": # Check if script is called by the user or imported
    main()
