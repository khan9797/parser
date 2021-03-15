from datetime import datetime

class Tester(object):
    """
    A class used to run all the test cases provided

    ...

    Attributes
    ----------

    Methods
    -------
    test_runner(self, tests=None)
        Runs all the tests
    """
    
    def __init__(self):
        super(Tester, self).__init__()

    def test_runner(self, tests):
        """
        test_runner runs all the test cases provided in the `tests`. At the end
        it will print a test report showing:
        `
        Total tests ran
        Total tests Passed
        Total tests Failed
        `

        If `tests` is empty then no test case will run.

        Parameters
        ----------
        tests : list, optional
            The test cases to run (default is None)

        Raises
        ------
        """
        count   = 0
        passed  = 0
        failed  = 0
        for i in tests:
            count +=1
            run_test = i

            ret = ""

            if run_test(): #fucntion is called from here
                passed +=1
                ret = '\033[1;32m'+"PASSED"+'\033[1;m'
            else:
                failed +=1
                ret = '\033[1;31m'+"FAILED"+'\033[1;m'
            now = datetime.now()
            time = now.strftime("%H:%M:%S")
            info = '\033[1;33m'+"[INFO "+time+"]"+'\033[1;m'
            print(f"{info} {run_test.__name__} : {ret}")

        print("\nTest Report:")
        print(f"Total tests ran: {count}")
        print(f"Total tests Passed: {passed}")
        print(f"Total tests Failed: {failed}")
