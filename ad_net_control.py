#!/usr/bin/env python3

import argparse
import logging
import subprocess
import shlex

logger = logging.getLogger('ad_net_control')
logger.addHandler(logging.StreamHandler())

DRY_RUN = False

INIT_RULES = [
    'INPUT -m state --state RELATED,ESTABLISHED -j ACCEPT',  # allow already established connections
    'INPUT -p udp --dport 30001:30999 -j ACCEPT',  # openvpn team servers
    'INPUT -p udp --dport 31001:31999 -j ACCEPT',  # openvpn vulnbox servers
    'INPUT -p udp --dport 32000 -j ACCEPT',  # openvpn jury server

    'FORWARD -m state --state RELATED,ESTABLISHED -j ACCEPT',  # allow already established connections
    'FORWARD -i jury -o team+ -j ACCEPT',  # jury access to teams
    'FORWARD -i jury -o vuln+ -j ACCEPT',  # jury access to vulnboxes

    'POSTROUTING -t nat -o team+ -j MASQUERADE',  # team masquerade
    'POSTROUTING -t nat -o vuln+ -j MASQUERADE',  # vulnboxes masquerade
]

OPEN_NETWORK_RULES = [
    'FORWARD -i team+ -o vuln+ -j ACCEPT',  # teams can access all vulnboxes
    'FORWARD -i vuln+ -o vuln+ -j ACCEPT',  # vulnboxes can access each other
    'FORWARD -i team+ -o jury -j ACCEPT',  # teams can access jury
    'FORWARD -i vuln+ -o jury -j ACCEPT',  # vulnboxes can access jury (???) TODO: is it useful?
]  # teams cannot access each other (not even through vulnboxes)

DROP_RULES = [
    'INPUT -j DROP',  # drop all incoming packets
    'FORWARD -j DROP',  # drop all forwarded packets
]

ALLOW_SSH_RULES = [
    'INPUT -p tcp --dport 22 -m conntrack --ctstate NEW,ESTABLISHED -j ACCEPT',  # ingoing SSH
    'OUTPUT -p tcp --sport 22 -m conntrack --ctstate ESTABLISHED -j ACCEPT',  # outgoing ssh
]


def run_command(command):
    if not DRY_RUN:
        proc = subprocess.Popen(command)
        proc.wait()


def get_team2vuln_rules(team_count):
    """During closed network period, team can only access its own vulnbox (and vice-versa)"""
    return list(
        f'FORWARD -i team{num} -o vuln{num} -j ACCEPT'
        for num in range(1, team_count + 1)
    ) + list(
        f'FORWARD -i vuln{num} -o team{num} -j ACCEPT'
        for num in range(1, team_count + 1)
    )


def add_rules(rules):
    logger.debug('Adding rules:')
    logger.debug('\n'.join(rules))

    for rule in rules:
        command = ['iptables', '-A'] + shlex.split(rule)
        run_command(command)

    logger.info(f'Done adding {len(rules)} rules')


def remove_rules(rules):
    logger.debug('Removing rules:')
    logger.debug('\n'.join(rules))

    for rule in rules:
        command = ['iptables', '-D'] + shlex.split(rule)
        run_command(command)

    logger.info(f'Done removing {len(rules)} rules')


def add_drop_rules(*_args, **_kwargs):
    add_rules(ALLOW_SSH_RULES)
    add_rules(DROP_RULES)


def remove_drop_rules(*_args, **_kwargs):
    remove_rules(DROP_RULES)
    remove_rules(ALLOW_SSH_RULES)


def init_network(*, team_count, **_kwargs):
    rules = INIT_RULES + get_team2vuln_rules(team_count)
    add_rules(rules)

    with open('/proc/sys/net/ipv4/ip_forward', 'w') as f:
        f.write('1')

    add_drop_rules()


def open_network(*_args, **_kwargs):
    remove_drop_rules()
    add_rules(OPEN_NETWORK_RULES)
    add_drop_rules()


def close_network(*_args, **_kwargs):
    remove_rules(OPEN_NETWORK_RULES)


def shutdown_network(*, team_count, **_kwargs):
    all_rules = OPEN_NETWORK_RULES + INIT_RULES + get_team2vuln_rules(team_count)
    remove_rules(all_rules)


COMMANDS = {
    'init': init_network,
    'open': open_network,
    'close': close_network,
    'shutdown': shutdown_network,
    'add_drop': add_drop_rules,
    'remove_drop': remove_drop_rules,
}

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Manage router network during AD CTF')
    parser.add_argument('command', choices=COMMANDS.keys(), help='Command to run')
    parser.add_argument('--teams', '-t', dest='team_count', type=int, metavar='N', help='Team count', required=True)
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
