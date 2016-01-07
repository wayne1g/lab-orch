from Exscript.util.interact import read_login
from Exscript.protocols import SSH2
from Exscript.protocols.Exception import TimeoutException
from Exscript import Account
import collections
import logging


def do_something(job, host, conn):
    # for console_port in console_ports:
    conn.execute('uname -a')
    print conn.response
    print repr(conn.response)
    conn.execute('ls -l')
    print conn.response
    print repr(conn.response)


def define_console_port():
    # console_array = ['1-4', '7', '9-10']
    # console_array = ['1-48']
    console_array = []
    input_str = raw_input('Please provide the list of console ports to check: ')
    console_array.append(input_str)
    console_list = []
    for ele in console_array:
        start = ele.split('-', 1)[0]
        try:
            end = ele.split('-', 1)[1]
        except:
            end = start
        this_list = list(range(int(start), int(end)+1))
        console_list.append(this_list)
    print console_list
    print list(flatten(console_list))
    return list(flatten(console_list))


def flatten(iterable, ltypes=collections.Iterable):
    import itertools as IT
    remainder = iter(iterable)
    while True:
        first = next(remainder)
        if isinstance(first, ltypes) and not isinstance(first, basestring):
            remainder = IT.chain(first, remainder)
        else:
            yield first


# todo - make functions to use kwargs*
def console_engage(jumphost, jumphost_user, jumphost_password, port, logger):

    timeout = 5
    conn = create_conn(jumphost, jumphost_user, jumphost_password)
    conn.set_timeout(timeout)

    console_port_engaged = None
    while True:
        try:
            conn.set_prompt('Connection closed by foreign host\.')
            print "NON FORMATTED RESPONSE:\n", repr(conn.response)
            print "FORMATTED RESPONSE:\n:", conn.response
            conn.execute('telnet ' + port)
            print "TRYING telnet " + port + "\n--> NON FORMATTED RESPONSE:\n", repr(conn.response)
            print "--> FORMATTED RESPONSE\n:", conn.response
            print "Console is engaged."
            console_port_engaged = True
            logger.info(port + " Connection to port closed - Port is engaged by other user/session.")
            break
        except TimeoutException as e:
            # print e, " - Waited for ", timeout, " seconds. Console server did not reject. Port should be available."
            # logger.error(port + " Connection timeout " + str(timeout) + " seconds.", exc_info=True)
            logger.info(port + " Connection successful in the last " + str(timeout) + " seconds. " +
                        "Port is NOT engaged by other user/session.")
            console_port_engaged = False
            break
    if console_port_engaged is False:
        conn.set_prompt('.*')
        conn.execute('exit')
        conn.close()
    return console_port_engaged


def define_logger():
    import os
    # Get the filename of this module
    log_file = os.path.basename(__file__)
    # Get the function name
    logger = logging.getLogger(__name__)
    logger.setLevel(logging.INFO)
    # Create a file handler
    handler = logging.FileHandler(log_file + '.log')
    handler.setLevel(logging.INFO)
    # Create a logging format
    formatter = logging.Formatter('[%(asctime)s %(filename)s:%(lineno)s - %(funcName)s()] '
                                  '---> %(levelname)s - %(message)s')
    handler.setFormatter(formatter)
    # add the handlers to the logger
    logger.addHandler(handler)
    return logger


# todo - convert all print statement to log
def console_status_disconnect(jumphost, jumphost_user, jumphost_password, port, logger, timeout):

    timeout = 5
    conn = create_conn(jumphost, jumphost_user, jumphost_password)
    conn.set_timeout(timeout)

    console_port_disconnect = None
    # while True:
    try:
        # todo - still cannot detect DISCONNECTED console port
        conn.set_prompt("Escape character is \'\^\]'\.")
        conn.execute('telnet ' + port)
        print "TRYING telnet " + port + "\n--> NON FORMATTED RESPONSE:\n", repr(conn.response)
        print "--> FORMATTED RESPONSE\n:", conn.response
        conn.set_prompt('(.*[\?\$:#].*)')
        conn.execute('send_one_line')
        print "TRYING sending empty string\n--> NON FORMATTED RESPONSE:\n", repr(conn.response)
        print "--> FORMATTED RESPONSE\n:", conn.response
        logger.info(port + " Received a character \':?$#\' in the device response " +
                    "within the last " + str(timeout) + " seconds. Port is connected.")
    except TimeoutException as e:
        print "cannot match anything with :"
        print "no response from device"
        # print "Connection to port is established for the last", timeout, "seconds."
        # print "Characters entered and read one line with additional characters returned."
        # logger.info(port + " connection timeout "+ str(timeout) + " seconds.", exc_info=True)
        logger.info(port + " Cannot receive any of the character \':?$#\' in the device response " +
                           "for the last " + str(timeout) + " seconds. Port could be disconnected.")
        console_port_disconnect = True
        print conn.response
        # break
    finally:
        if console_port_disconnect is None:
            console_port_disconnect = False
            conn.set_prompt('.*')
            conn.execute('exit')
            conn.close()
        # break
    # print "check disconnect done, disconnected? ", console_port_disconnect
    # if console_port_disconnect is False:
    #     conn.set_prompt('.*')
    #     conn.send('exit')
    #     conn.close()
    return console_port_disconnect


# todo - change the hardcoded credential to arguments for the function
def create_conn(jumphost, jumphost_user, jumphost_password):
    # To read credential from stdin
    # account = read_login()
    # account = Account('username', 'password')
    account = Account(jumphost_user, jumphost_password)
    conn = SSH2()
    # This is required for Centos jumphost issue. exscript cannot auto detect os in guess os
    conn.set_driver('shell')
    conn.connect(jumphost)
    # conn.connect('jumphost.foo.com')
    conn.login(account)
    return conn


def login_device(port_user, port_password, port, conn, logger):
    attempt = 1
    retry = 3
    login_ready = None
    while attempt < retry+1:
        try:
            conn.set_prompt('.*assword:')
            # conn.execute('username in string')
            conn.execute(port_user)
            login_ready = True
            print conn.response
            print "Yes --> We get login prompt in attempt #", attempt, "\n"
            # logger.info(port + " Device give \"login:\" prompt in attempt " + str(attempt))
            logger.info(port + " Login attempt " + str(attempt) + " Device provided \"login:\" prompt.")
            # This block below will work for device that was logged in already
            # and is running a multiple pages output CLI.. such as giving --- more --- for Junos
            # conn.set_prompt('[\r\n]+[\w\-\.]+@[\-\w+\.:]+[%>#] $')
            # conn.execute('\x00')  # Send break but it should be '\x003'
            # the above \x00 is like sending CTLR-C (but officially, it should be \x03
            # # send 'q' can break you out of the --- more --- pagination of Junos too
            # # conn.execute('q')
            break
        except:
            login_ready = False
            print "print cannot get prompt in attempt #", attempt
            logger.info(port + " Login attempt " + str(attempt) + " Device did NOT give \"login:\" prompt in attempt ")
        finally:
            # attempt += 1
            password_accepted = None
            if login_ready is True:
                print "send password to port.", conn.response
                try:
                    conn.set_prompt('[\r\n]+[\w\-\.]+@[\-\w+\.:]+[%>#$] ')
                    # conn.execute('password in string')
                    conn.execute(port_password)
                    password_accepted = True
                    logger.info(port + " Password ACCEPTED in login attempt " + str(attempt))
                except:
                    password_accepted = False
                    logger.info(port + " Password REJECTED in login attempt " + str(attempt))
                finally:
                    attempt += 1
                break
            else:
                attempt += 1

    # The conn received for this function is not closed for ongoing operations in the device.
    return login_ready, password_accepted


def main():

    logger = define_logger()
    logger.info("Test Started")

    # Define the jumphost IP address or FQDN
    jumphost = raw_input("The IP address or FQDN of the jumphost: ")
    # This is the username and password to login to the jumphost.
    jumphost_user = raw_input("Enter the username: ")
    jumphost_password = raw_input("Enter the password: ")

    console_server = raw_input("Enter the console server IP/FQDN: ")
    ports = define_console_port()
    print("Test will use this list of console ports. " + str(ports))
    logger.info("Test will use this list of console ports. " + str(ports))

    for port in ports:
        port = console_server + "-p" + str(port)
        logger.info("Working on port " + port + ".")
        console_port_disconnected = console_status_disconnect(jumphost, jumphost_user, jumphost_password, port, logger, timeout = 5)
        print "Console " + port + " Connection Status --> Disconnected?", console_port_disconnected
        if console_port_disconnected is False:
            console_port_engaged = console_engage(jumphost, jumphost_user, jumphost_password, port, logger)
            # console_port_disconnected = console_status_disconnect(conn, port, 5)
            # print "Console Port Connection Status --> Disconnected?", console_port_disconnected

            print "console_port_engaged is --> ", console_port_engaged
            if console_port_engaged is False:
                timeout = 5
                conn = create_conn(jumphost, jumphost_user, jumphost_password)
                conn.set_timeout(timeout)

                conn.set_prompt("Escape character is \'\^\]'\.")
                conn.execute('telnet ' + port)
                print "TRYING telnet " + port + "\n--> NON FORMATTED RESPONSE:\n", repr(conn.response)
                print "--> FORMATTED RESPONSE:\n", conn.response

                port_user = raw_input('Console port / Device username: ')
                port_password = raw_input('Console port / Device password: ')
                logged_in, password_accepted = login_device(port_user, port_password, port, conn, logger)

                if (logged_in is True) and (password_accepted is True):
                    logger.info(port + " Execute commands in the device.")
                    conn.set_prompt('[\r\n]+[\w\-\.]+@[\-\w+\.:]+[%>#$] ')
                    conn.execute('')
                    conn.execute('show version | no-more')
                    print conn.response
                    logger.info(conn.response)
                    # Close the connection of the current port
                    # conn.send is used instead of conn.execute as we don't need to wait for any response.
                    conn.send('exit\r')
                    logger.info(port + " Executed all commands in the device.")
                    conn.close()
                else:
                    logger.info(port + " No commands can be executed in the device.")

    logger.info("Test Ended")

if __name__ == "__main__":
    main()
