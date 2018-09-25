#!/usr/bin/env python

from __future__ import print_function
import locale
import os
import re
import subprocess
import sys
from dialog import Dialog
from debinterface.interfaces import Interfaces


IP_PATH = '/sbin/ip'
PY3 = sys.version_info[0] == 3
if PY3:
    unicode = str


IP4PATTERN = re.compile(r'(([01]?[0-9]?[0-9]|2[0-4][0-9]|2[5][0-5])\.)'
                        r'{3}([01]?[0-9]?[0-9]|2[0-4][0-9]|2[5][0-5])')


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


def _interfaces_ip(out):
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
        return (ip, mask, brd, scope)

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
                iflabel = cols[-1:][0]
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
                            addr_obj['label'] = iflabel
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
                            'label': iflabel,
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

    route_cmd = subprocess.Popen(
        '{0} route'.format(IP_PATH),
        shell=True,
        close_fds=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT).communicate()[0]
    route_res = to_str(route_cmd).strip()

    for line in route_res.splitlines():
        line = line.strip()
        if 'via' in line and line.endswith(iface_name):
            active_values['gateway'] = line.split('via')[-1].split()[0]

    return active_values


class Constants:
    DHCP = 'dhcp'
    STATIC = 'static'
    TXT_BACKGROUND_TITLE = 'Network Interface Configuration'
    TXT_ERR_ROOT_REQUIRED = 'root privileges required. run with sudo'
    TXT_NETWORK_CFG_SUCCESS = 'Network configuration completed successfully!\n\n'
    TXT_NETWORK_CFG_ERROR = 'Error occured while configuring network interface!\n\n'
    TXT_WELCOME_TITLE = 'Welcome to pydialog-interfaces configuration!\n\n' \
                        'This tool helps you to set up your network interface.'
    TXT_SELECT_INTERFACE = 'Select interface'
    TXT_SELECT_SOURCE = 'Select address source'
    TXT_MESSAGE_DHCP = 'Configuring for DHCP provided address...'
    TXT_MESSAGE_STATIC = 'Configuring for static IP address...'
    TXT_MESSAGE_ERROR = '\Zb\Z1Error: %s\n\n\Z0Please try again.'
    TXT_CONFIG_STATIC_TITLE = 'Provie the values for static IP configuration'


def clear_quit():
    os.system('clear')
    sys.exit(0)


def write_and_display_results(dlg, interfaces, selected_iface):
    interfaces.writeInterfaces()

    interfaces.downAdapter(selected_iface)
    result = interfaces.upAdapter(selected_iface)

    text = Constants.TXT_NETWORK_CFG_SUCCESS if result[0] \
        else Constants.TXT_NETWORK_CFG_ERROR

    msg = to_str(result[1]).split('isc.org/software/dhcp/')[-1]

    dlg.msgbox(text + msg)
    clear_quit()


def configure_interfaces(configured_iface, dlg, interfaces, selected_iface, tag):
    if tag == Constants.DHCP:
        dlg.infobox(Constants.TXT_MESSAGE_DHCP)

        # simply add
        interfaces.addAdapter({
            'name': selected_iface,
            'auto': True,
            'addrFam': 'inet',
            'source': Constants.DHCP}, 0)

        write_and_display_results(dlg, interfaces, selected_iface)
    if tag == Constants.STATIC:
        if not configured_iface or not configured_iface.get('address'):
            configured_iface = get_active_ip_values(selected_iface)

        new_address = configured_iface.get('address', '')
        new_netmask = configured_iface.get('netmask', '')
        new_gateway = configured_iface.get('gateway', '')

        while True:
            try:
                code, values = dlg.form(Constants.TXT_CONFIG_STATIC_TITLE, [
                    # title, row_1, column_1, field, row_1, column_20, field_length, input_length
                    ('IP Address', 1, 1, new_address, 1, 20, 15, 15),
                    # title, row_2, column_1, field, row_2, column_20, field_length, input_length
                    ('Netmask', 2, 1, new_netmask, 2, 20, 15, 15),
                    # title, row_3, column_1, field, row_3, column_20, field_length, input_length
                    ('Gateway', 3, 1, new_gateway, 3, 20, 15, 15)], width=70)

                if code in (Dialog.CANCEL, Dialog.ESC):
                    clear_quit()

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
                code = dlg.msgbox(
                    text=Constants.TXT_MESSAGE_ERROR %
                         ex, colors=True)


def linux_interfaces():
    cmd1 = subprocess.Popen(
        '{0} link show'.format(IP_PATH),
        shell=True,
        close_fds=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT).communicate()[0]
    cmd2 = subprocess.Popen(
        '{0} addr show'.format(IP_PATH),
        shell=True,
        close_fds=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT).communicate()[0]
    return _interfaces_ip('{0}\n{1}'.format(
        to_str(cmd1),
        to_str(cmd2)))


def main():
    # some sanity checks here, sudo only
    locale.setlocale(locale.LC_ALL, '')
    if os.getuid() != 0:
        print(Constants.TXT_ERR_ROOT_REQUIRED)
        sys.exit(1)

    # display available interfaces to configure
    interfaces = Interfaces()
    dlg = Dialog(dialog='dialog', autowidgetsize=True)
    dlg.set_background_title(Constants.TXT_BACKGROUND_TITLE)

    code = dlg.yesno(Constants.TXT_WELCOME_TITLE,
                     height=15, width=65, yes_label='OK', no_label='Cancel')

    if code in (Dialog.CANCEL, Dialog.ESC):
        clear_quit()

    choices = [
        (adapter.attributes['name'], '')
        for adapter in interfaces.adapters
        if adapter.attributes['name'] != 'lo']

    code, tag = dlg.menu(Constants.TXT_SELECT_INTERFACE, choices=choices)
    if code == Dialog.OK:
        selected_iface = tag

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

        code, tag = dlg.menu(
            Constants.TXT_SELECT_SOURCE, choices=[
                (Constants.DHCP, 'Dynamic IP'),
                (Constants.STATIC, 'Static IP')])
        if code == Dialog.OK:
            configure_interfaces(
                configured_iface,
                dlg,
                interfaces,
                selected_iface,
                tag)
        else:
            clear_quit()
    else:
        clear_quit()


if __name__ == '__main__':
    main()