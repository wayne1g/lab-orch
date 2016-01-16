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


def read_config(config_file, **logger):
    import yaml
    logger = logger['logger']
    logger.info("Read console information from file - " + config_file)
    # todo - exception handling cannot read file.
    with open(config_file, 'r') as ymlfile:
        cfg = yaml.load(ymlfile)
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
    port_str = kwargs['port'].keys()[0]
    port_info = kwargs['port'].values()[0]

    port = [stuff for stuff in port_info if stuff.keys()[0] == 'port'][0]
    jumphost = [stuff for stuff in port_info if stuff.keys()[0] == 'jumphost'][0]

    timeout = kwargs['timeout']
    conn = create_conn(jumphost=jumphost['jumphost'])
    conn.set_timeout(timeout)
    logger = kwargs['logger']

    console_port_engaged = None
    while True:
        try:
            conn.set_prompt('Connection closed by foreign host\.')
            conn.execute('telnet ' + port_str)
            console_port_engaged = True
            logger.info(port_str + " Connection to port closed - Port is engaged by other user/session.")
            break
        except TimeoutException as e:
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
    # logger needs to be a singleton. Otherwise, this time this is called.
    # It will create another logger base on "logger.addHandler(handler)"
    # Duplicate or more of the same log messages will appear.
    # todo -This func has not been modified to this one suggested.
    # http://stackoverflow.com/questions/7173033/duplicate-log-output-when-using-python-logging-module
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
def console_status_disconnect(*args, **kwargs):
    port_str = kwargs['port'].keys()[0]
    port_info = kwargs['port'].values()[0]

    # port = [stuff for stuff in port_info if stuff.keys()[0] == 'port'][0]
    jumphost = [stuff for stuff in port_info if stuff.keys()[0] == 'jumphost'][0]

    print "inside func port_str", port_str
    conn = create_conn(jumphost=jumphost['jumphost'])
    conn.set_timeout(kwargs['timeout'])

    console_port_disconnect = None
    logger = kwargs['logger']
    timeout = kwargs['timeout']
    try:
        # This prompt is specific to acs
        conn.set_prompt("Escape character is \'\^\]'\.")
        conn.execute('telnet ' + port_str)
        conn.set_prompt('(.*[\?\$:#].*)')
        conn.execute('send_one_line_to_check_if_the_console_port_is_responsive')
        logger.info(port_str + " Received a character \':?$#\' in the device response " +
                    "within the last " + str(timeout) + " seconds. Port is connected.")
    except TimeoutException as e:
        logger.info(port_str + " Cannot receive any of the character \':?$#\' in the device response " +
                    "for the last " + str(timeout) + " seconds. Port could be disconnected.")
        console_port_disconnect = True
        # Nothing returned from the console port. conn.buffer has the line just sent.
        # The last response is in conn.response. If there is any response, conn.buffer will have it instead.
        logger.info(port_str + "\n" + conn.response)
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
    account = Account(jumphost['username'],
                      jumphost['password'])
    conn = SSH2()
    # This is required for Centos jumphost issue. exscript cannot auto detect os in guess os
    conn.set_driver('shell')
    conn.connect(jumphost['ip'])
    # conn.connect('jumphost.foo.com')
    conn.login(account)
    return conn


def login_device(*args, **kwargs):
    logger = kwargs['logger']
    conn = kwargs['conn']

    port_str = kwargs['port'].keys()[0]
    port_info = kwargs['port'].values()[0]
    port = [stuff for stuff in port_info if stuff.keys()[0] == 'port'][0]
    username = port['port']['username']
    password = port['port']['password']

    attempt = 1
    retry = 3
    login_ready = None
    while attempt < retry+1:
        try:
            conn.set_prompt('.*assword:')
            conn.execute(username)
            login_ready = True
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
            logger.info(port_str + " Login attempt " + str(attempt) +
                        " Device did NOT give \"login:\" prompt in attempt ")
            logger.info(port_str + str(conn.buffer))
        finally:
            # attempt += 1
            password_accepted = None
            if login_ready is True:
                logger.info(port_str + " Login attempt " + str(attempt) + ". Send password to device.")
                try:
                    conn.set_prompt('[\r\n]+[\w\-\.]+@[\-\w+\.:]+[%>#$] ')
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
    """
    kwargs = {'port_list': ['2-3, 6-8']}
    This func maps the port info read in kwargs to individual port dictionary
    It will look like
    {'2': [{'username': 'foo'}, {'password': 'bar'}],
     '3': [{'username': 'foo'}, {'password': 'bar'}],
     '6': [{'username': 'foo'}, {'password': 'bar'}],
     '7': [{'username': 'foo'}, {'password': 'bar'}],
     '8': [{'username': 'foo'}, {'password': 'bar'}]}
    """
    d = {}
    console = args[0]
    ports = console['ports']
    print('======================')
    print "console is"
    pprint(console)
    for p in ports:
        p_list = make_port_list(port_list=p['range'])
        for ele in p_list:
            if not d:
                d = {}
            # d[console['name'] + '-p' + str(ele)] \
            #     = [{'username': console['ports'][0]['username']},
            #        {'password': console['ports'][0]['password']},
            #        {'jumphost': console['jumphost']}]
            d[console['name'] + '-p' + str(ele)] \
                = [{'port': console['ports'][0]},
                   {'jumphost': console['jumphost']}]
    print('======================')
    print "d is"
    pprint(d)
    print('======================')
    return d


def main(*args, **kwargs):

    logger = define_logger()
    logger.info(15*"=" + " Test Started " + 15*"=" + "\n")

    # The deployment config file should be kept here.
    # aka the current directory of this script.
    # console = read_config('config.yml')
    # todo - Test if config file can be read.
    console_servers = read_config('config/config.yml', logger=logger)

    if not kwargs['use_config_file']:
        # Define the jumphost IP address or FQDN
        jumphost = raw_input("The IP address or FQDN of the jumphost: ")
        # This is the username and password to login to the jumphost.
        jumphost_user = raw_input("Enter the username: ")
        jumphost_password = raw_input("Enter the password: ")
        console_server = raw_input("Enter the console server IP/FQDN: ")
        port_user = raw_input('Enter Username for this Device ' + port + ': ')
        port_password = raw_input('Enter Password for this Device ' + port + ': ')
        ports = define_console_port()
    else:
        for console in console_servers:
            # jumphost = console['jumphost']
            # make a list for all the ranges in the config read
            mapped_ports = map_port_info(console)

            # for port, port_info in ports.iteritems():
            ports = [{stuff[0]:stuff[1]} for stuff in mapped_ports.iteritems()]
            for port in ports:

                port_str = port.keys()[0]
                port_info = port.values()[0]
                print port_str
                print "Running test for port_str, ", port_str
                print port_info
                print "Running test for port_info, "
                pprint(port_info)
                logger.info("Working on port " + port_str + ".")

                console_port_disconnected = console_status_disconnect(port=port, timeout=5, logger=logger)
                if console_port_disconnected is False:
                    console_port_engaged = console_engage(port=port, timeout=5, logger=logger)
                    if console_port_engaged is False:
                        timeout = 5
                        jumphost = [stuff for stuff in port_info if stuff.keys()[0] == 'jumphost'][0]
                        print "fdsas "
                        pprint(port)
                        conn = create_conn(jumphost=jumphost.values()[0])
                        conn.set_timeout(timeout)
                        conn.set_prompt("Escape character is \'\^\]'\.")
                        # todo - need to detect telnet error. add exception handling here.
                        conn.execute('telnet ' + port_str)
                        logged_in, password_accepted = login_device(port=port, logger=logger,
                                                                    timeout=5, conn=conn)

                        if (logged_in is True) and (password_accepted is True):
                            logger.info(port_str + " Execute commands in the device.")
                            conn.set_prompt('[\r\n]+[\w\-\.]+@[\-\w+\.:]+[%>#$] ')
                            conn.execute('')
                            conn.execute('show version | no-more')
                            logger.info(conn.response)
                            # Close the connection of the current port
                            # conn.send is used instead of conn.execute as we don't need to wait for any response.
                            conn.send('exit\r')
                            logger.info(port_str + " Executed all commands in the device.")
                            conn.close()
                        else:
                            logger.info(port_str + " No commands can be executed in the device.")

    logger.info(15*"=" + " Test Ended " + 15*"=" + "\n")

if __name__ == "__main__":
    main(use_config_file=True)
