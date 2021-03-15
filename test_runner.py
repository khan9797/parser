import os
import argparse
import subprocess
from Tester.Tester import Tester
from driver_tests import driver_tests
from cmodel_tests import cmodel_tests


if __name__ == '__main__':
    ap = argparse.ArgumentParser()
    tests = []

    # Add the arguments to the parser
    ap.add_argument("-p", "--port", required=True,
       help="Pass the PF here. Its value can either be 'sn0' or 'sn1'.")
    ap.add_argument("-m", "--module", required=True,
       help="Pass the module you want to test. Its value can either be 'driver' or 'cmodel'")
    args = vars(ap.parse_args())

    # print(args['port'],args['module'])

    if (args['module'] == 'driver'):
        pass
        # try:
        #     ping_command = "../configure_driver.sh"

        #     (output, error) = subprocess.Popen(ping_command,
        #                                    stdout=subprocess.PIPE,
        #                                    stderr=subprocess.PIPE,
        #                                    shell=True).communicate()
        # except subprocess.CalledProcessError as e:
        #     print('Unable to configure driver')

        # """
        # This is a list of the names of all the test cases defined driver_tests.py file.

        # NOTE: The names should be exactly as defined in the driver_tests.py.
        # """
        # tests = driver_tests
    elif (args['module'] == 'cmodel'):

        # try:
        #     ping_command = "../configure_cmodel.sh"

        #     (output, error) = subprocess.Popen(ping_command,
        #                                    stdout=subprocess.PIPE,
        #                                    stderr=subprocess.PIPE,
        #                                    shell=True).communicate()
        # except subprocess.CalledProcessError as e:
        #     print('Unable to configure cmodel')

        """
        This is a list of the names of all the test cases defined cmodel_tests.py file.

        NOTE: The names should be exactly as defined in the cmodel_tests.py.
        """
        
        tests = cmodel_tests

    """test_runner method of the Tester class called and list of test cases (tests) passed"""
    
    tester = Tester()
    pkt = {"test":"packet"}
    tester.test_runner(tests)
