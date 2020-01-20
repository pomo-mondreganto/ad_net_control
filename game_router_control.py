#!/usr/bin/env python3

import argparse
import logging
import shlex
import subprocess
import re

from helpers import (
    logger,
    add_rules,
    list_rules,
    insert_rules,
    remove_rules,
    DRY_RUN,
)

INIT_RULES = [
    'INPUT -m conntrack --ctstate INVALID -j DROP',  # drop invalid packets

    'FORWARD -m state --state RELATED,ESTABLISHED -j ACCEPT',  # allow already established connections
    'FORWARD -s 10.10.10.0/24 -o eth+ -j ACCEPT',  # jury access to vulnboxes

    'POSTROUTING -t nat -d 10.70.0.0/16 -j MASQUERADE',  # vulnboxes masquerade
]

OPEN_NETWORK_RULES = [
    'FORWARD -i eth+ -o eth+ -j ACCEPT',  # teams & vulnboxes can access other vulnboxes
]

DROP_RULES = [
    'FORWARD -j DROP',  # drop all forwarded packets that are not explicitly allowed above
]


def get_isolation_rules(team):
    return [
        f'FORWARD ! -s 10.60.{team}.0/24 -d 10.70.{team}.0/24 -j DROP',  # allow access from same team only
    ]


def get_ban_rules(team):
    return [
        f'FORWARD -s 10.70.{team}.0/24 -j DROP',  # deny all incoming to vulnbox
        f'FORWARD -d 10.70.{team}.0/24 -j DROP',  # deny all outgoing from vulnbox
        f'FORWARD -s 10.60.{team}.0/24 -j DROP'  # deny all ingoing from team subnet
    ]


def get_team2vuln_rules(teams_list):
    """During closed network period, team can only access its own vulnbox"""
    return list(
        f'FORWARD -s 10.60.{team}.0/24 -d 10.70.{team}.0/24 -j ACCEPT'
        for team in teams_list
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


def rule_exists(rule):
    if DRY_RUN:
        return False

    logger.debug(f"Checking if rule {rule} exists")

    command = ['iptables', '-C'] + shlex.split(rule)
    rc = subprocess.call(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    return rc == 0


def add_drop_rules(*_args, **_kwargs):
    add_rules(DROP_RULES)


def remove_drop_rules(*_args, **_kwargs):
    remove_rules(DROP_RULES)


def init_network(*, teams, **_kwargs):
    if teams is None:
        logger.error('Specify all required parameters: teams')
        exit(1)

    rules = INIT_RULES + get_team2vuln_rules(teams)
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

    forward_init_rules = list(filter(lambda x: x.startswith('FORWARD'), INIT_RULES))
    count_before = len(forward_init_rules) + len(get_team2vuln_rules(teams))
    insert_rules(get_ban_rules(team), count_before)


def isolate_team(teams, team, *_args, **_kwargs):
    if teams is None or team is None:
        logger.error('Specify all required parameters: teams, team')
        exit(1)

    forward_init_rules = list(filter(lambda x: x.startswith('FORWARD'), INIT_RULES))
    count_before = len(forward_init_rules) + len(get_team2vuln_rules(teams))
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
    parser.add_argument('--team', type=int, metavar='N', help='Team number (1-indexed) for ban or isolation')
    parser.add_argument('--verbose', '-v', help='Turn verbose logging on', action='store_true')
    parser.add_argument('--dry-run', help='Just print rules (verbose mode)', action='store_true')

    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('--teams', '-t', type=int, metavar='N', help='Team count')
    group.add_argument('--range', type=str, metavar='N-N', help='Range of teams (inclusive)')
    group.add_argument('--list', type=str, metavar='N,N,...', help='List of teams')

    args = parser.parse_args()

    if args.teams:
        parsed_teams = range(1, args.teams + 1)
    elif args.range:
        match = re.search(r"(\d+)-(\d+)", args.range)
        if not match:
            print('Invalid range')
            exit(1)

        parsed_teams = range(int(match.group(1)), int(match.group(2)) + 1)
    else:
        parsed_teams = list(map(int, args.list.split(',')))

    args.teams = parsed_teams

    if args.verbose or args.dry_run:
        logger.setLevel(logging.DEBUG)
    else:
        logger.setLevel(logging.INFO)

    if args.dry_run:
        DRY_RUN = True

    COMMANDS[args.command](**vars(args))
