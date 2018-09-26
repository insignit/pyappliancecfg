#!/usr/bin/env python3

from __future__ import print_function
import locale
import os
import re
import subprocess
import sys
from os import listdir
from os.path import join, abspath

import argparse
from dialog import Dialog
from debinterface.interfaces import Interfaces

IP_PATH = '/sbin/ip'
TIME_SYNCD_CONF = '/etc/systemd/timesyncd.conf'
DHCP_DIR = '/var/lib/dhcp/'
DEFAULT_NTP_SERVERS = '0.pool.ntp.org 1.pool.ntp.org 2.pool.ntp.org 3.pool.ntp.org'

PY3 = sys.version_info[0] == 3
if PY3:
    unicode = str

IP4PATTERN = re.compile(r'(([01]?[0-9]?[0-9]|2[0-4][0-9]|2[5][0-5])\.)'
                        r'{3}([01]?[0-9]?[0-9]|2[0-4][0-9]|2[5][0-5])')


def clear_quit():
    os.system('clear')
    sys.exit(0)


def hard_quit():
    os.system('clear')
    os.kill(os.getppid(), 9)


def is_ip4(inp):
    return bool(IP4PATTERN.match(inp))


def to_str(s, encoding='utf-8'):
    """
    Given str, bytes, bytearray, or unicode (py2), return str
    """
    # This shouldn't be six.string_types because if we're on PY2 and we already
    # have a string, we should just return it.
    if isinstance(s, str):
        return s
    if PY3:
        if isinstance(s, (bytes, bytearray)):
            # https://docs.python.org/3/howto/unicode.html#the-unicode-type
            # replace error with U+FFFD, REPLACEMENT CHARACTER
            return s.decode(encoding, 'replace')
        raise TypeError(
            'expected str, bytes, or bytearray not {}'.format(type(s)))
    else:
        if isinstance(s, bytearray):
            return str(s)
        if isinstance(s, unicode):  # pylint: disable=incompatible-py3-code,undefined-variable
            return s.encode(encoding)
        raise TypeError('expected str, bytearray, or unicode')


def get_term_output(cmd_list, cwd=None):
    assert isinstance(cmd_list, list)
    proc = subprocess.Popen(
        cmd_list,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        cwd=cwd)
    err = proc.stderr.read()
    out = proc.stdout.read()
    proc.kill()
    return to_str(err) if err else '', to_str(out) if out else ''


def get_term_stdout(cmd_list, cwd=None):
    return get_term_output(
        cmd_list=cmd_list,
        cwd=cwd)[1]


def cidr_to_ipv4_netmask(cidr_bits):
    """
    Returns an IPv4 netmask
    """
    try:
        cidr_bits = int(cidr_bits)
        if not 1 <= cidr_bits <= 32:
            return ''
    except ValueError:
        return ''

    netmask = ''
    for idx in range(4):
        if idx:
            netmask += '.'
        if cidr_bits >= 8:
            netmask += '255'
            cidr_bits -= 8
        else:
            netmask += '{0:d}'.format(256 - (2 ** (8 - cidr_bits)))
            cidr_bits = 0
    return netmask


def parse_interfaces_ip(out):
    """
    Uses ip to return a dictionary of interfaces with various information about
    each (up/down state, ip address, netmask, and hwaddr)
    """
    ret = dict()

    def parse_network(value, cols):
        """
        Return a tuple of ip, netmask, broadcast
        based on the current set of cols
        """
        brd = None
        scope = None
        if '/' in value:  # we have a CIDR in this address
            ip, cidr = value.split('/')  # pylint: disable=C0103
        else:
            ip = value  # pylint: disable=C0103
            cidr = 32

        if type_ == 'inet':
            mask = cidr_to_ipv4_netmask(int(cidr))
            if 'brd' in cols:
                brd = cols[cols.index('brd') + 1]
        elif type_ == 'inet6':
            mask = cidr
            if 'scope' in cols:
                scope = cols[cols.index('scope') + 1]
        return ip, mask, brd, scope

    groups = re.compile('\r?\n\\d').split(out)
    for group in groups:
        iface = None
        data = dict()

        for line in group.splitlines():
            if ' ' not in line:
                continue
            match = re.match(
                r'^\d*:\s+([\w.\-]+)(?:@)?([\w.\-]+)?:\s+<(.+)>', line)
            if match:
                iface, parent, attrs = match.groups()
                if 'UP' in attrs.split(','):
                    data['up'] = True
                else:
                    data['up'] = False
                if parent:
                    data['parent'] = parent
                continue

            cols = line.split()
            if len(cols) >= 2:
                type_, value = tuple(cols[0:2])
                if_label = cols[-1:][0]
                if type_ in ('inet', 'inet6'):
                    if 'secondary' not in cols:
                        ipaddr, netmask, broadcast, scope = parse_network(
                            value, cols)
                        if type_ == 'inet':
                            if 'inet' not in data:
                                data['inet'] = list()
                            addr_obj = dict()
                            addr_obj['address'] = ipaddr
                            addr_obj['netmask'] = netmask
                            addr_obj['broadcast'] = broadcast
                            addr_obj['label'] = if_label
                            data['inet'].append(addr_obj)
                        elif type_ == 'inet6':
                            if 'inet6' not in data:
                                data['inet6'] = list()
                            addr_obj = dict()
                            addr_obj['address'] = ipaddr
                            addr_obj['prefixlen'] = netmask
                            addr_obj['scope'] = scope
                            data['inet6'].append(addr_obj)
                    else:
                        if 'secondary' not in data:
                            data['secondary'] = list()
                        ip_, mask, brd, scp = parse_network(value, cols)
                        data['secondary'].append({
                            'type': type_,
                            'address': ip_,
                            'netmask': mask,
                            'broadcast': brd,
                            'label': if_label,
                        })
                        del ip_, mask, brd, scp
                elif type_.startswith('link'):
                    data['hwaddr'] = value
        if iface:
            ret[iface] = data
            del iface, data
    return ret


def get_active_ip_values(iface_name):
    ifaces = linux_interfaces()

    active_values = {}
    if iface_name in ifaces \
            and 'inet' in ifaces[iface_name] \
            and ifaces[iface_name]['inet']:
        active_values = ifaces[iface_name]['inet'][0]

    route_res = get_term_stdout([IP_PATH, 'route']).strip()

    for line in route_res.splitlines():
        line = line.strip()
        if 'via' in line and line.endswith(iface_name):
            active_values['gateway'] = line.split('via')[-1].split()[0]

    return active_values


class Constants:
    DHCP = 'dhcp'
    STATIC = 'static'
    TXT_BACKGROUND_TITLE = 'PyAppliance Interface Configuration'
    TXT_ERR_ROOT_REQUIRED = 'root privileges required. run with sudo'
    TXT_NETWORK_CFG_SUCCESS = 'Network configuration completed successfully!\n\n'
    TXT_NETWORK_CFG_ERROR = 'Error occured while configuring network interface!\n\n'
    TXT_WELCOME_TITLE = 'Welcome to pyAppliance configuration!\n\n' \
                        'This tool helps you to set up your network interface.'
    TXT_SELECT_INTERFACE = 'Select interface'
    TXT_SELECT_SOURCE = 'Select address source'
    TXT_MESSAGE_DHCP = 'Configuring for DHCP provided address...'
    TXT_MESSAGE_STATIC = 'Configuring for static IP address...'
    TXT_MESSAGE_ERROR = '\Zb\Z1Error: %s\n\n\Z0Please try again.'
    TXT_CONFIG_STATIC_TITLE = 'Provide the values for static IP configuration'
    TXT_TIMESERVER_STATUS = 'Time Server Status:\n\n{0}\n\n{1}'
    TXT_NTP_SERVERS = 'NTP Server:{0}\nFallback:{1}'
    TXT_CONFIG_NTP_TITLE = 'Provide NTP server addresses'


def write_and_display_results(dlg, interfaces, selected_iface):
    interfaces.writeInterfaces()

    interfaces.downAdapter(selected_iface)
    result = interfaces.upAdapter(selected_iface)

    text = Constants.TXT_NETWORK_CFG_SUCCESS if result[0] \
        else Constants.TXT_NETWORK_CFG_ERROR

    msg = to_str(result[1]).split('isc.org/software/dhcp/')[-1]

    dlg.msgbox(text + msg)


def configure_static_interface(
        configured_iface,
        dlg,
        interfaces,
        selected_iface):
    if not configured_iface or not configured_iface.get('address'):
        configured_iface = get_active_ip_values(selected_iface)

    new_address = configured_iface.get('address', '')
    new_netmask = configured_iface.get('netmask', '')
    new_gateway = configured_iface.get('gateway', '')
    while True:
        try:
            code, values = dlg.form(Constants.TXT_CONFIG_STATIC_TITLE, [
                # title, row_nr, column_nr, field,
                #       row_nr, column_20, field_length, input_length
                ('IP Address', 1, 1, new_address, 1, 20, 15, 15),
                ('Netmask', 2, 1, new_netmask, 2, 20, 15, 15),
                ('Gateway', 3, 1, new_gateway, 3, 20, 15, 15)], width=70)

            if code in (Dialog.CANCEL, Dialog.ESC):
                return

            code = dlg.infobox(Constants.TXT_MESSAGE_STATIC)
            # simply add
            interfaces.addAdapter({
                'name': selected_iface,
                'auto': True,
                'addrFam': 'inet',
                'source': Constants.STATIC,
                'address': values[0],
                'netmask': values[1],
                'gateway': values[2]}, 0)

            write_and_display_results(dlg, interfaces, selected_iface)
        except Exception as ex:
            dlg.msgbox(text=Constants.TXT_MESSAGE_ERROR % ex, colors=True)


def configure_dhcp_interface(dlg, interfaces, selected_iface):
    dlg.infobox(Constants.TXT_MESSAGE_DHCP)
    # simply add
    interfaces.addAdapter({
        'name': selected_iface,
        'auto': True,
        'addrFam': 'inet',
        'source': Constants.DHCP}, 0)
    write_and_display_results(dlg, interfaces, selected_iface)


def linux_interfaces():
    cmd1 = get_term_stdout([IP_PATH, 'link', 'show'])
    cmd2 = get_term_stdout([IP_PATH, 'addr', 'show'])
    return parse_interfaces_ip('{0}\n{1}'.format(
        to_str(cmd1),
        to_str(cmd2)))


def check_selected_interface(interfaces, selected_iface):
    # check if selected_iface is already listed or not in interfaces file
    # using debinterfaces
    configured_iface = None
    for adapter in interfaces.adapters:
        item = adapter.export()
        if item['name'] == selected_iface:
            configured_iface = item
            break
    # remove from adapter list if it is already configured
    if configured_iface is not None:
        interfaces.removeAdapterByName(selected_iface)
    return configured_iface


def configure_interfaces(dlg):

    interfaces = Interfaces()
    choices = [
        (adapter.attributes['name'], '')
        for adapter in interfaces.adapters
        if adapter.attributes['name'] != 'lo']

    code, tag = dlg.menu(Constants.TXT_SELECT_INTERFACE, choices=choices)
    if code == Dialog.OK:
        selected_iface = tag

        configured_iface = check_selected_interface(interfaces, selected_iface)

        code, tag = dlg.menu(
            Constants.TXT_SELECT_SOURCE, choices=[
                (Constants.DHCP, 'Dynamic IP'),
                (Constants.STATIC, 'Static IP')])
        if code == Dialog.OK:
            if tag == Constants.DHCP:
                configure_dhcp_interface(dlg, interfaces, selected_iface)
            if tag == Constants.STATIC:
                configure_static_interface(
                    configured_iface,
                    dlg,
                    interfaces,
                    selected_iface)


def get_time_settings():
    prim = ''
    fallback = ''
    with open(TIME_SYNCD_CONF, 'r') as conffl:
        for line in conffl:
            stripped = line.strip()
            if stripped.startswith('NTP='):
                prim = stripped[4:]
            elif stripped.startswith('FallbackNTP='):
                fallback = stripped[12:]

    return prim, fallback


def get_timeserver_status():
    return get_term_stdout(['timedatectl', 'status'])


def configure_ntp(dlg):
    timeserver_status = get_timeserver_status()
    prim_time, fallback_time = get_time_settings()

    ntp_txt = Constants.TXT_NTP_SERVERS.format(prim_time, fallback_time) \
        if (prim_time or fallback_time) else ''

    code = dlg.yesno(
        Constants.TXT_TIMESERVER_STATUS.format(
            timeserver_status,
            ntp_txt),
        yes_label='Set NTP',
        no_label='Cancel')

    if code in (Dialog.CANCEL, Dialog.ESC):
        return

    if not prim_time or not fallback_time:
        prim_time, fallback_time = get_time_server_hints(
            prim_time,
            fallback_time)

    code, values = dlg.form(Constants.TXT_CONFIG_NTP_TITLE, [
        # title, row_nr, column_nr, field,
        #       row_nr, column_20, field_length, input_length
        ('Primary', 1, 1, prim_time, 1, 20, 35, 45),
        ('Fallback', 2, 1, fallback_time, 2, 20, 35, 45)], width=70)

    if code in (Dialog.CANCEL, Dialog.ESC):
        return

    write_ntp_settings(values[0], values[1])
    restart_timesyncd()
    if 'NTP synchronized: yes' not in timeserver_status:
        set_ntp()


def set_ntp():
    return get_term_stdout(['timedatectl', 'set-ntp' 'true'])


def restart_timesyncd():
    return get_term_stdout(['systemctl', 'restart', 'systemd-timesyncd'])


def write_ntp_settings(prim_time, fallback_time):
    with open(TIME_SYNCD_CONF, 'w') as conf_fl:
        conf_fl.writelines([
            '[Time]\n'
            'NTP={}\n'.format(prim_time),
            'FallbackNTP={}\n'.format(fallback_time)
        ])


def get_time_server_hints(prim_time, fallback_time):
    for dhcp_lease_options in get_dhcp_options():
        print('found options', dhcp_lease_options)
        if dhcp_lease_options \
                and 'domain-name-servers' in dhcp_lease_options:
            dns_servers = dhcp_lease_options['domain-name-servers'].split(',')
            if dns_servers:

                if not prim_time:
                    prim_time = dns_servers[0]

                if not fallback_time and len(dns_servers) > 1:
                    fallback_time = dns_servers[1]

    if prim_time:
        if not fallback_time:
            fallback_time = DEFAULT_NTP_SERVERS
    else:
        prim_time = DEFAULT_NTP_SERVERS

    return prim_time, fallback_time


def get_dhcp_options():
    """
    Note: does not validity checking (yet)

    :return:
    """
    for file in listdir(DHCP_DIR):
        with open(join(DHCP_DIR, file), 'r') as fl:
            in_lease = False
            current_lease_options = {}
            for line in fl.readlines():
                line = line.strip()
                if in_lease:
                    if line == '}':
                        yield current_lease_options
                        current_lease_options = {}
                        in_lease = False
                    elif line.startswith('option '):
                        option_name, value = line[7:-1].split(' ', 1)
                        current_lease_options[option_name] = value
                elif line.startswith('lease') and line.endswith('{'):
                    in_lease = True


def run_external_config(external_config):
    subprocess.run(
        abspath(external_config),
        shell=True)


def main(
        dlg,
        external_config,
        external_config_name,
        external_config_descr,
        hard_exit=False):
    choices = [
        ('Interfaces', 'static/dchp config'),
        ('NTP', 'time server'),
    ]

    if external_config:
        ext_config_option = external_config_name or external_config
        choices.append((ext_config_option, external_config_descr or ''))
    else:
        ext_config_option = None

    while True:
        code, tag = dlg.menu(
            Constants.TXT_WELCOME_TITLE,
            choices=choices)

        if code in (Dialog.CANCEL, Dialog.ESC):
            hard_quit() if hard_exit else clear_quit()

        if tag == 'Interfaces':
            configure_interfaces(dlg)
        elif tag == 'NTP':
            configure_ntp(dlg)
        elif tag == ext_config_option:
            run_external_config(external_config)
        else:
            raise Exception('Unknown option {}'.format(tag))


if __name__ == '__main__':
    # some sanity checks here, sudo only
    locale.setlocale(locale.LC_ALL, '')
    # if os.getuid() != 0:
    #     print(Constants.TXT_ERR_ROOT_REQUIRED)
    #     sys.exit(1)

    parser = argparse.ArgumentParser()
    parser.add_argument('--external_config',
                        help='external config application',
                        default=None)
    parser.add_argument('--external_config_name',
                        help='display name for the external config application',
                        default=None)
    parser.add_argument('--external_config_descr',
                        help='description for the external config application',
                        default=None)
    parser.add_argument('--hard_exit',
                        help='forces the application to use a hard exit '
                             '(logging out the user)',
                        default=False,
                        action='store_true')
    args = parser.parse_args()

    # display available interfaces to configure
    dlg = Dialog(dialog='dialog', autowidgetsize=True)
    dlg.set_background_title(Constants.TXT_BACKGROUND_TITLE)
    try:
        main(dlg,
             external_config=args.external_config,
             external_config_name=args.external_config_name,
             external_config_descr=args.external_config_descr,
             hard_exit=args.hard_exit)
    except KeyboardInterrupt:
        hard_quit() if args.hard_exit else clear_quit()
    except Exception as ex:
        dlg.msgbox('An error occurred: {}'.format(ex))
        hard_quit() if args.hard_exit else clear_quit()
