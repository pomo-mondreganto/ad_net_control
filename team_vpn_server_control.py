#!/usr/bin/env python3

import argparse
import logging

from helpers import (
    logger,
    add_rules,
    list_rules,
    insert_rules,
    remove_rules,
    DRY_RUN,
)

INIT_RULES = [
    'INPUT -m state --state RELATED,ESTABLISHED -j ACCEPT',  # allow already established connections
    'INPUT -i lo -j ACCEPT',  # accept all local connections
    'INPUT -p icmp --icmp-type 8 -m state --state NEW,ESTABLISHED,RELATED -j ACCEPT',  # allow icmp 8
    'INPUT -p icmp --icmp-type 0 -m state --state NEW,ESTABLISHED,RELATED -j ACCEPT',  # allow icmp 0

    'INPUT -p udp --dport 30001:30999 -j ACCEPT',  # openvpn team servers
    'INPUT -p tcp --dport 9100 -j ACCEPT',  # node_exporter metrics
    'POSTROUTING -t nat -o eth0 -j MASQUERADE',  # masquerade all output
]

DROP_RULES = [
    'INPUT -j DROP',  # drop all incoming packets that are not explicitly allowed above
]

ALLOW_SSH_RULES = [
    'INPUT -p tcp --dport 22 -m state --state NEW,RELATED,ESTABLISHED -j ACCEPT',  # ingoing SSH
    'OUTPUT -p tcp --sport 22 -m state --state RELATED,ESTABLISHED -j ACCEPT',  # outgoing SSH
]


def get_ban_rules(team):
    return [
        f'FORWARD -i team{team} -j DROP',
    ]


def add_drop_rules(*_args, **_kwargs):
    add_rules(ALLOW_SSH_RULES)
    add_rules(DROP_RULES)


def remove_drop_rules(*_args, **_kwargs):
    remove_rules(DROP_RULES)
    remove_rules(ALLOW_SSH_RULES)


def init_network(**_kwargs):
    rules = INIT_RULES
    add_rules(rules)
    add_drop_rules()

    needs_forwarding = False
    with open('/proc/sys/net/ipv4/ip_forward', 'r') as f:
        if f.read().strip() != 1:
            needs_forwarding = True

    if needs_forwarding:
        logger.info('Enabling ip forwarding')

        if not DRY_RUN:
            with open('/proc/sys/net/ipv4/ip_forward', 'w') as f:
                f.write('1')


def shutdown_network(**_kwargs):
    remove_drop_rules()
    all_rules = INIT_RULES
    remove_rules(all_rules)


def ban_team(team, *_args, **_kwargs):
    if team is None:
        logger.error('Specify all required parameters: team')
        exit(1)

    insert_rules(get_ban_rules(team), 1)


COMMANDS = {
    'init': init_network,
    'shutdown': shutdown_network,
    'add_drop': add_drop_rules,
    'remove_drop': remove_drop_rules,
    'list': list_rules,
    'ban': ban_team,
}

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Manage router network during AD CTF')
    parser.add_argument('command', choices=COMMANDS.keys(), help='Command to run')
    parser.add_argument('--verbose', '-v', help='Turn verbose logging on', action='store_true')
    parser.add_argument('--dry-run', help='Just print rules (verbose mode)', action='store_true')

    args = parser.parse_args()

    if args.verbose or args.dry_run:
        logger.setLevel(logging.DEBUG)
    else:
        logger.setLevel(logging.INFO)

    if args.dry_run:
        DRY_RUN = True

    COMMANDS[args.command](**vars(args))
