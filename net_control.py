#!/usr/bin/env python3

import argparse
import logging
import shlex
import subprocess

logger = logging.getLogger('ad_net_control')
logger.addHandler(logging.StreamHandler())

DRY_RUN = False

INIT_RULES = [
    'INPUT -m state --state RELATED,ESTABLISHED -j ACCEPT',  # allow already established connections
    'INPUT -i lo -j ACCEPT',  # accept all local connections
    'INPUT -p icmp --icmp-type 8 -m state --state NEW,ESTABLISHED,RELATED -j ACCEPT',  # allow icmp 8
    'INPUT -p icmp --icmp-type 0 -m state --state NEW,ESTABLISHED,RELATED -j ACCEPT',  # allow icmp 0

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
    'FORWARD -i vuln+ -o jury -j ACCEPT',  # vulnboxes can access jury
]  # teams cannot access each other (not even through vulnboxes)

DROP_RULES = [
    'INPUT -j DROP',  # drop all incoming packets that are not explicitly allowed above
    'FORWARD -j DROP',  # drop all forwarded packets that are not explicitly allowed above
]

ALLOW_SSH_RULES = [
    'INPUT -p tcp --dport 22 -m state --state NEW,RELATED,ESTABLISHED -j ACCEPT',  # ingoing SSH
    'OUTPUT -p tcp --sport 22 -m state --state RELATED,ESTABLISHED -j ACCEPT',  # outgoing SSH
]


def get_isolation_rules(team):
    return [
        f'FORWARD -o vuln{team} -j DROP',  # To be inserted after the rule -i teamN -o vulnN
    ]


def get_ban_rules(team):
    return [
        f'FORWARD -i team{team} -j DROP',  # To be inserted after the rule -i teamN -o vulnN
        f'FORWARD -i vuln{team} -j DROP',  # To be inserted after the rule -i vulnN -o teamN
    ]


def run_command(command):
    if not DRY_RUN:
        proc = subprocess.Popen(command)
        proc.wait()


def get_team2vuln_rules(team_count):
    """During closed network period, team can only access its own vulnbox (and vise versa)"""
    return list(
        f'FORWARD -i team{num} -o vuln{num} -j ACCEPT'
        for num in range(1, team_count + 1)
    ) + list(
        f'FORWARD -i vuln{num} -o team{num} -j ACCEPT'
        for num in range(1, team_count + 1)
    )


def get_rules_list():
    command = ['iptables', '-S']
    out = subprocess.check_output(command)
    result = out.decode().split('\n')
    result = list(map(
        lambda x: ' '.join(x.split(' ')[1:]),
        filter(lambda x: x, result),
    ))
    return result


def list_rules(*_args, **_kwargs):
    rules = get_rules_list()
    logger.info("Rules:")
    logger.info('\n'.join(rules))


def rule_exists(rule):
    if DRY_RUN:
        return False

    command = ['iptables', '-C'] + shlex.split(rule)
    rc = subprocess.call(command)
    return rc == 0


def add_rules(rules):
    logger.debug('Adding rules:')
    logger.debug('\n'.join(rules))

    for rule in rules:
        if not rule_exists(rule):
            command = ['iptables', '-A'] + shlex.split(rule)
            run_command(command)

    logger.info(f'Done adding {len(rules)} rules')


def insert_rules(rules, start):
    logger.debug("Inserting rules:")
    logger.debug('\n'.join(rules))
    logger.debug(f'To a position {start}')

    for i, rule in enumerate(rules):
        if not rule_exists(rule):
            index = start + i
            command = ['iptables', '-I', str(index)] + shlex.split(rule)
            run_command(command)

    logger.info(f'Done inserting {len(rules)} rules to a position {start}')


def remove_rules(rules):
    logger.debug('Removing rules:')
    logger.debug('\n'.join(rules))

    for rule in rules:
        if rule_exists(rule):
            command = ['iptables', '-D'] + shlex.split(rule)
            run_command(command)

    logger.info(f'Done removing {len(rules)} rules')


def add_drop_rules(*_args, **_kwargs):
    add_rules(ALLOW_SSH_RULES)
    add_rules(DROP_RULES)


def remove_drop_rules(*_args, **_kwargs):
    remove_rules(DROP_RULES)
    remove_rules(ALLOW_SSH_RULES)


def init_network(*, teams, **_kwargs):
    if teams is None:
        logger.error('Specify all required parameters: teams')
        exit(1)

    rules = INIT_RULES + get_team2vuln_rules(teams)
    add_rules(rules)
    add_drop_rules()

    logger.info('Enabling ip forwarding')

    if not DRY_RUN:
        with open('/proc/sys/net/ipv4/ip_forward', 'w') as f:
            f.write('1')


def open_network(*_args, **_kwargs):
    remove_drop_rules()
    add_rules(OPEN_NETWORK_RULES)
    add_drop_rules()


def close_network(*_args, **_kwargs):
    remove_rules(OPEN_NETWORK_RULES)


def shutdown_network(*, teams, **_kwargs):
    if teams is None:
        logger.error('Specify all required parameters: teams')
        exit(1)

    remove_drop_rules()
    all_rules = OPEN_NETWORK_RULES + INIT_RULES + get_team2vuln_rules(teams)
    remove_rules(all_rules)


def ban_team(teams, team, *_args, **_kwargs):
    if teams is None or team is None:
        logger.error('Specify all required parameters: teams, team')
        exit(1)

    count_before = len(INIT_RULES) + len(get_team2vuln_rules(teams))
    insert_rules(get_ban_rules(team), count_before)


def isolate_team(teams, team, *_args, **_kwargs):
    if teams is None or team is None:
        logger.error('Specify all required parameters: teams, team')
        exit(1)

    count_before = len(INIT_RULES) + len(get_team2vuln_rules(teams))
    insert_rules(get_isolation_rules(team), count_before)


COMMANDS = {
    'init': init_network,
    'open': open_network,
    'close': close_network,
    'shutdown': shutdown_network,
    'add_drop': add_drop_rules,
    'remove_drop': remove_drop_rules,
    'list': list_rules,
    'ban': ban_team,
    'isolate': isolate_team,
}

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Manage router network during AD CTF')
    parser.add_argument('command', choices=COMMANDS.keys(), help='Command to run')
    parser.add_argument('--teams', '-t', type=int, metavar='N', help='Team count')
    parser.add_argument('--team', type=int, metavar='N', help='Team number (1-indexed) for ban or isolation')
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
