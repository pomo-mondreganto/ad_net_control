#!/usr/bin/env python3

import argparse
import logging
import re
from typing import List, Optional

from helpers import (
    logger,
    add_rules,
    set_chain_policy,
    get_team_subnet,
    get_vuln_ip,
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

    'INPUT -p udp --dport 30000:31999 -j ACCEPT',  # wireguard listeners
    'INPUT -p tcp --dport 9100 -j ACCEPT',  # node_exporter metrics

    'FORWARD -m state --state RELATED,ESTABLISHED -j ACCEPT',  # allow already established connections
    'FORWARD -s 10.10.10.0/24 -j ACCEPT',  # jury access to everything

    'POSTROUTING -t nat -o wg0 -j MASQUERADE',  # everything masqueraded
    'POSTROUTING -t mangle -o wg0 -j TTL --ttl-set 137',  # To prevent ttl filtering
]

ALLOW_SSH_RULES = [
    'INPUT -p tcp --dport 22 -m state --state NEW,RELATED,ESTABLISHED -j ACCEPT',  # ingoing SSH
    'OUTPUT -p tcp --sport 22 -m state --state RELATED,ESTABLISHED -j ACCEPT',  # outgoing SSH
]


# insert them first
def get_isolation_rules(team: int):
    return [
        f'FORWARD ! -s {get_team_subnet(team)} -d {get_vuln_ip(team)} -j DROP',
    ]


# insert them first
def get_ban_rules(team: int):
    return [
        f'FORWARD -s {get_team_subnet(team)} -j DROP',
        f'FORWARD -s {get_vuln_ip(team)} -j DROP',
    ]


def get_team2vuln_rules(teams_list: List[int]):
    """During closed network period, team can only access its own vulnbox"""
    return list(
        f'FORWARD -s {get_team_subnet(num)} -d {get_vuln_ip(num)} -j ACCEPT'
        for num in teams_list
    )


def init_network(*, teams: List[int], **_kwargs):
    if teams is None:
        logger.error('Specify all required parameters: teams')
        exit(1)

    add_rules(INIT_RULES)
    add_rules(get_team2vuln_rules(teams))
    add_rules(ALLOW_SSH_RULES)
    set_chain_policy('INPUT', 'DROP')
    set_chain_policy('FORWARD', 'DROP')

    logger.info('Enabling ip forwarding')

    if not DRY_RUN:
        with open('/proc/sys/net/ipv4/ip_forward', 'w') as f:
            f.write('1')


def open_network(*_args, **_kwargs):
    set_chain_policy('FORWARD', 'ACCEPT')


def close_network(*_args, **_kwargs):
    set_chain_policy('FORWARD', 'DROP')


def shutdown_network(*, teams: Optional[List[int]], **_kwargs):
    if teams is None:
        logger.error('Specify all required parameters: teams')
        exit(1)

    remove_rules(INIT_RULES)
    remove_rules(get_team2vuln_rules(teams))
    set_chain_policy('INPUT', 'ACCEPT')
    set_chain_policy('FORWARD', 'DROP')
    remove_rules(ALLOW_SSH_RULES)


def ban_team(team: Optional[int], *_args, **_kwargs):
    insert_rules(get_ban_rules(team), 1)


def unban_team(team: Optional[int], *_args, **_kwargs):
    remove_rules(get_ban_rules(team))


def isolate_team(team: Optional[int], *_args, **_kwargs):
    insert_rules(get_isolation_rules(team), 1)


def deisolate_team(team: Optional[int], *_args, **_kwargs):
    remove_rules(get_isolation_rules(team))


COMMANDS = {
    'init': init_network,
    'open': open_network,
    'close': close_network,
    'shutdown': shutdown_network,
    'list': list_rules,
    'ban': ban_team,
    'unban': unban_team,
    'isolate': isolate_team,
    'deisolate': deisolate_team,
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
