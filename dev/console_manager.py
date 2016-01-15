from Exscript.util.interact import read_login
from Exscript.protocols import SSH2
from Exscript.protocols.Exception import TimeoutException
from Exscript import Account
import collections
import logging
from pprint import pprint


def do_something(job, host, conn):
    # for console_port in console_ports:
    conn.execute('uname -a')
    print conn.response
    print repr(conn.response)
    conn.execute('ls -l')
    print conn.response
    print repr(conn.response)


def read_config(config_file):
    import yaml
    logger = define_logger()
    logger.info("Read console information from file - " + config_file)
    with open(config_file, 'r') as ymlfile:
        cfg = yaml.load(ymlfile)
    # for section in cfg:
    #     print('The section title of the config file.')
    #     print(section)
    # pprint(cfg['console_server'])
    return cfg['console_server']


def make_port_list(*args, **kwargs):
    # kwargs = {'port_list': ['2-3, 6-8']}
    port_list = []
    # iteritems() return a list containing the values of the dictionary kwargs
    # v = ['2-3, 6-8']
    for k,v in kwargs.iteritems():
        # Use ',' as the delimiter, and form a list.
        # v is ['2-3,', '6-8']
        if type(v) is int:
            v = str(v)
            j = []
            j.append(v)
            return j
        elif type(v) is str:
            v = v.split(',')
            # Remove the ',' from the elements in the list
            # v should now be ['2-3', '6-8']
            # todo - may need to remove white space for the string
            v = [ele.strip(',') for ele in v]
            for item in v:
                start = item.split('-', 1)[0]
                try:
                    end = item.split('-', 1)[1]
                except:
                    end = start
                # Convert the port range '2-3' to [2,3]
                port_range = list(range(int(start), int(end)+1))
                # Append range to port_list
                port_list.append(port_range)
    # port_list will look like this [[2, 3], [6, 7, 8]]
    # finally, return a flatten port_list e.g. [2, 3, 6, 7, 8]
    return list(flatten(port_list))


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
def console_engage(*args, **kwargs):

    port_str = kwargs['console']['name'] + "-p" + str(kwargs['port'].keys()[0])
    timeout = kwargs['timeout']
    conn = create_conn(jumphost=kwargs['jumphost'])
    conn.set_timeout(timeout)
    logger = kwargs['logger']

    console_port_engaged = None
    while True:
        try:
            conn.set_prompt('Connection closed by foreign host\.')
            print "NON FORMATTED RESPONSE:\n", repr(conn.response)
            print "FORMATTED RESPONSE:\n:", conn.response
            conn.execute('telnet ' + port_str)
            print "TRYING telnet " + port_str + "\n--> NON FORMATTED RESPONSE:\n", repr(conn.response)
            print "--> FORMATTED RESPONSE\n:", conn.response
            print "Console is engaged."
            console_port_engaged = True
            logger.info(port_str + " Connection to port closed - Port is engaged by other user/session.")
            break
        except TimeoutException as e:
            # print e, " - Waited for ", timeout, " seconds. Console server did not reject. Port should be available."
            # logger.error(port + " Connection timeout " + str(timeout) + " seconds.", exc_info=True)
            logger.info(port_str + " Connection successful in the last " + str(timeout) + " seconds. " +
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
# def console_status_disconnect(jumphost, jumphost_user, jumphost_password, port, logger, timeout):
def console_status_disconnect(*args, **kwargs):

    # port = console_server + "-p" + str(port)

    print "kwargs"
    print kwargs
    port_str = kwargs['console']['name'] + "-p" + str(kwargs['port'].keys()[0])
    conn = create_conn(jumphost=kwargs['jumphost'])
    conn.set_timeout(kwargs['timeout'])

    console_port_disconnect = None
    logger = kwargs['logger']
    timeout = kwargs['timeout']
    # while True:
    try:
        # todo - still cannot detect DISCONNECTED console port
        conn.set_prompt("Escape character is \'\^\]'\.")
        conn.execute('telnet ' + port_str)
        print "TRYING telnet " + port_str + "\n--> NON FORMATTED RESPONSE:\n", repr(conn.response)
        print "--> FORMATTED RESPONSE\n:", conn.response
        conn.set_prompt('(.*[\?\$:#].*)')
        conn.execute('send_one_line')
        print "TRYING sending empty string\n--> NON FORMATTED RESPONSE:\n", repr(conn.response)
        print "--> FORMATTED RESPONSE\n:", conn.response
        logger.info(port_str + " Received a character \':?$#\' in the device response " +
                    "within the last " + str(timeout) + " seconds. Port is connected.")
    except TimeoutException as e:
        print "cannot match anything with :"
        print "no response from device"
        # print "Connection to port is established for the last", timeout, "seconds."
        # print "Characters entered and read one line with additional characters returned."
        # logger.info(port + " connection timeout "+ str(timeout) + " seconds.", exc_info=True)
        logger.info(port_str + " Cannot receive any of the character \':?$#\' in the device response " +
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
def create_conn(*args, **kwargs):
    # To read credential from stdin
    # account = read_login()
    # account = Account('username', 'password')
    jumphost = kwargs['jumphost']
    account = Account(jumphost['username'], \
                      jumphost['password'])
    conn = SSH2()
    # This is required for Centos jumphost issue. exscript cannot auto detect os in guess os
    conn.set_driver('shell')
    conn.connect(jumphost['ip'])
    # conn.connect('jumphost.foo.com')
    conn.login(account)
    return conn


# def login_device(port_user, port_password, port, conn, logger):
def login_device(*args, **kwargs):
    pprint(kwargs)
    logger = kwargs['logger']
    conn = kwargs['conn']
    port_str = kwargs['console']['name'] + "-p" + str(kwargs['port'].keys()[0])
    username = [a['username'] for a in kwargs['port'].values()[0] if 'username' in a.keys()][0]
    password = [a['password'] for a in kwargs['port'].values()[0] if 'password' in a.keys()][0]
    attempt = 1
    retry = 3
    login_ready = None
    while attempt < retry+1:
        try:
            conn.set_prompt('.*assword:')
            # conn.execute('username in string')
            # conn.execute(port_user)
            conn.execute(username)
            login_ready = True
            print conn.response
            print "Yes --> We get login prompt in attempt #", attempt, "\n"
            # logger.info(port + " Device give \"login:\" prompt in attempt " + str(attempt))
            logger.info(port_str + " Login attempt " + str(attempt) + " Device provided \"login:\" prompt.")
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
            logger.info(port_str + " Login attempt " + str(attempt) + " Device did NOT give \"login:\" prompt in attempt ")
        finally:
            # attempt += 1
            password_accepted = None
            if login_ready is True:
                print "send password to port.", conn.response
                try:
                    conn.set_prompt('[\r\n]+[\w\-\.]+@[\-\w+\.:]+[%>#$] ')
                    # conn.execute('password in string')
                    conn.execute(password)
                    password_accepted = True
                    logger.info(port_str + " Password ACCEPTED in login attempt " + str(attempt))
                except:
                    password_accepted = False
                    logger.info(port_str + " Password REJECTED in login attempt " + str(attempt))
                finally:
                    attempt += 1
                break
            else:
                attempt += 1

    # The conn received for this function is not closed for ongoing operations in the device.
    return login_ready, password_accepted


def map_port_info(*args, **kwargs):
    # kwargs = {'port_list': ['2-3, 6-8']}
    # map port info read to individual port
    d = {}
    console = args[0]
    ports = console['ports']
    for p in ports:
        p_list = make_port_list(port_list=p['range'])
        for ele in p_list:
            if not d:
                d = {}
                d[ele] = [{'username':console['ports'][0]['username']},
                          {'password':console['ports'][0]['password']}]
            else:
                # d[ele] = [console['ports'][0]['username'], console['ports'][0]['password']]
                d[ele] = [{'username':console['ports'][0]['username']},
                          {'password':console['ports'][0]['password']}]
    print "expanded port info"
    print d
    return d


def main(*args, **kwargs):

    logger = define_logger()
    logger.info("Test Started")

    if (not args) and (not kwargs):
        # Define the jumphost IP address or FQDN
        jumphost = raw_input("The IP address or FQDN of the jumphost: ")
        # This is the username and password to login to the jumphost.
        jumphost_user = raw_input("Enter the username: ")
        jumphost_password = raw_input("Enter the password: ")
        console_server = raw_input("Enter the console server IP/FQDN: ")
        port_user = raw_input('Enter Username for this Device ' + port + ': ')
        port_password = raw_input('Enter Password for this Device ' + port + ': ')
        ports = define_console_port()
        print("Test will use this list of console ports. " + str(ports))
        logger.info("Test will use this list of console ports. " + str(ports))
    else:
        for console in console_servers:
            console_server = console['name']
            print "console_server name is"
            print console_server
            jumphost = console['jumphost']
            # make a list for all the ranges in the config read
            ports = map_port_info(console)
            pprint(ports)

            for port, port_info in ports.iteritems():
                print "running test for port", port
                # port = console_server + "-p" + str(port)
                # logger.info("Working on port " + port + ".")
                port_dict = {}
                port_dict[port] = port_info
                pprint(port_dict)
                console_port_disconnected = console_status_disconnect(console=console, port=port_dict, logger=logger, timeout=5, jumphost=jumphost)
                # print "Console " + port + " Connection Status --> Disconnected?", console_port_disconnected
                if console_port_disconnected is False:
                    console_port_engaged = console_engage(console=console, port=port_dict, logger=logger, timeout=5, jumphost=jumphost)
                    # console_port_disconnected = console_status_disconnect(conn, port, 5)
                    # print "Console Port Connection Status --> Disconnected?", console_port_disconnected

                    print "console_port_engaged is --> ", console_port_engaged
                    if console_port_engaged is False:
                        timeout = 5
                        conn = create_conn(jumphost=jumphost)
                        conn.set_timeout(timeout)
                        conn.set_prompt("Escape character is \'\^\]'\.")
                        port_str = console['name'] + "-p" + str(port)
                        print "port_str is ", port_str
                        # todo - need to detect telnet error. add exception handling here.
                        conn.execute('telnet ' + port_str)
                        # print "TRYING telnet " + port + "\n--> NON FORMATTED RESPONSE:\n", repr(conn.response)
                        print "--> FORMATTED RESPONSE:\n", conn.response
                        print "ports range password"
                        # print console['ports']['username']
                        logged_in, password_accepted = login_device(console=console, port=port_dict, logger=logger, timeout=5, conn=conn)
                        # logged_in, password_accepted = login_device(port_user, port_password, port, conn, logger)

                        if (logged_in is True) and (password_accepted is True):
                            logger.info(port_str + " Execute commands in the device.")
                            conn.set_prompt('[\r\n]+[\w\-\.]+@[\-\w+\.:]+[%>#$] ')
                            conn.execute('')
                            conn.execute('show version | no-more')
                            print conn.response
                            logger.info(conn.response)
                            # Close the connection of the current port
                            # conn.send is used instead of conn.execute as we don't need to wait for any response.
                            conn.send('exit\r')
                            logger.info(port_str + " Executed all commands in the device.")
                            conn.close()
                        else:
                            logger.info(port_str + " No commands can be executed in the device.")

    logger.info("Test Ended")

if __name__ == "__main__":
    # The deployment config file should be kept here.
    # aka the current directory of this script.
    # console = read_config('config.yml')

    # todo - Test if config file can be read.
    console_servers = read_config('config/config.yml')
    print "The console config read from file is:"
    pprint(console_servers)
    main(console_servers)
