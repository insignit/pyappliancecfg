#!/usr/bin/env python

from __future__ import print_function
import locale
import os
import sys
from dialog import Dialog
from debinterface.interfaces import Interfaces


class Iface:
    def __init__(self, name, description):
        self.name = name
        self.description = description


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

    msg = result[1].decode('utf-8')
    msg = msg.split('isc.org/software/dhcp/')[-1]

    dlg.msgbox(text + msg)
    clear_quit()


def configure_interfaces(configured_iface, dlg, interfaces, selected_iface, tag):
    if tag == Constants.DHCP:
        code = dlg.infobox(Constants.TXT_MESSAGE_DHCP)

        # simply add
        interfaces.addAdapter({
            'name': selected_iface,
            'auto': True,
            'addrFam': 'inet',
            'source': Constants.DHCP}, 0)

        write_and_display_results(dlg, interfaces, selected_iface)
    if tag == Constants.STATIC:
        new_address = '192.168.0.100'
        new_netmask = '255.255.255.0'
        new_gateway = '192.168.0.2'
        if configured_iface is not None:
            new_address = configured_iface["address"]
            new_netmask = configured_iface["netmask"]
            new_gateway = configured_iface["gateway"]
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
                     height=15, width=65, yes_label="OK", no_label="Cancel")

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
                configured_iface.export(),
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