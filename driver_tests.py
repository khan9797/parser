import os
import subprocess

"""
A sample test case. It should return True if the test passes and False in case of failure.
"""
def test():
    return False
    
"""
Test case for testing the ping functionality.
"""
def test_ping():
    IP = '10.60.0.1'
    ping_command = "ping "+ IP +" -c 3"

    (output, error) = subprocess.Popen(ping_command,
                                   stdout=subprocess.PIPE,
                                   stderr=subprocess.PIPE,
                                   shell=True).communicate()
    if ('100% packet loss' in output.decode()):
        print(error)
        return False
    return True

"""
Test case for testing the iperf functionality.
"""
def test_iperf():
    try:
        child_output = subprocess.check_output(['sudo', 'iperf3', '-B', '10.50.0.1', '-c', '10.60.1.1', '-t', '60', '-i', '10', '-O', '5'])
        child_output = child_output.decode()
        # print(child_output)
    except subprocess.CalledProcessError as e:
        print(e)
        return False
    return True


driver_tests = [test_ping,test_iperf]