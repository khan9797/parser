import os
import subprocess


print("Running Server")
parent_output = subprocess.check_output(['sudo','iperf3','-B','10.50.1.1', '-s', '-1', '&'])
