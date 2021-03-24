import os
import argparse
import subprocess
from Tester.Tester import Tester
from driver_tests import driver_tests
from cmodel_tests import cmodel_tests


if __name__ == '__main__':
    ap = argparse.ArgumentParser()
    tests = []

    # Add the command line arguments to the parser
    ap.add_argument("-p", "--port", required=False,
       help="Pass the PF here. Its value can either be 'sn0' or 'sn1'.")
    ap.add_argument("-m", "--module", required=False,
       help="Pass the module you want to test. Its value can either be 'driver' or 'cmodel'")
    ap.add_argument("-t", "--tests", required=False, type=str,
       help="Pass the comma separated names of the test cases in quotes that you want to run in the specific module e.g \"test1,test2,test3 ...\". If no argument is passed then it will run all the test cases for that specific module. NOTE: The names of the test cases should be exactly as given in the in the code.")
    ap.add_argument("-s", "--show", required=False, type=str,
       help="Pass the module name for which you want to print the test cases.")
    args = vars(ap.parse_args())

    # print(args['port'],args['module'])

    if (args['module'] == 'driver'):
        
        # try:
        #     command = "../configure_driver.sh"

        #     (output, error) = subprocess.Popen(command,
        #                                    stdout=subprocess.PIPE,
        #                                    stderr=subprocess.PIPE,
        #                                    shell=True).communicate()
        # except subprocess.CalledProcessError as e:
        #     print('Unable to configure driver')

        # """
        # This is a list of the names of all the test cases defined driver_tests.py file.

        # NOTE: The names should be exactly as defined in the driver_tests.py.
        # """
        if (args['tests']):
            tst = list(args['tests'].split(","))
            test_list = []
            tests = driver_tests
            for test in tests:
                for t in tst:
                    if(getattr(test,'__name__') == t):
                        test_list.append(test)
            tests = test_list
            tester = Tester()
            tester.test_runner(tests)
        else:
            tests = driver_tests
            tester = Tester()
            tester.test_runner(tests)

    elif (args['module'] == 'cmodel'):

        # try:
        #     command = "../configure_cmodel.sh"

        #     (output, error) = subprocess.Popen(command,
        #                                    stdout=subprocess.PIPE,
        #                                    stderr=subprocess.PIPE,
        #                                    shell=True).communicate()
        # except subprocess.CalledProcessError as e:
        #     print('Unable to configure cmodel')

        """
        This is a list of the names of all the test cases defined cmodel_tests.py file.

        NOTE: The names should be exactly as defined in the cmodel_tests.py.
        """
        if (args['tests']): #runs specific testcases
            tst = list(args['tests'].split(","))
            test_list = []
            tests = cmodel_tests
            for test in tests:
                for t in tst:
                    if(getattr(test,'__name__') == t): #comparison between function pointers improted from cmodel_tests and testcases given as arguments
                        test_list.append(test)
            tests = test_list
            tester = Tester()
            tester.test_runner(tests)
        else: #run all testcases
            tests = cmodel_tests
            tester = Tester()
            tester.test_runner(tests)


    if (args['show'] == 'driver'):
        tests = driver_tests
        i = 1
        for test in tests:
            print(f"[{i}] => {getattr(test,'__name__')}")
            i+=1
    elif (args['show'] == 'cmodel'):
        tests = cmodel_tests
        i = 1
        for test in tests:
            print(f"[{i}] => {getattr(test,'__name__')}")
            i+=1