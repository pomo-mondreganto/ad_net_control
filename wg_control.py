#!/usr/bin/env python3

import argparse
import logging
import traceback
from typing import List

import helpers

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
        f'FORWARD ! -s {helpers.get_team_subnet(team)} -d {helpers.get_vuln_ip(team)} -j DROP',
    ]


# insert them first
def get_ban_rules(team: int):
    return [
        f'FORWARD -s {helpers.get_team_subnet(team)} -j DROP',
        f'FORWARD -s {helpers.get_vuln_ip(team)} -j DROP',
    ]


def get_team2vuln_rules(teams_list: List[int]):
    """During closed network period, team can only access its own vulnbox"""
    return list(
        f'FORWARD -s {helpers.get_team_subnet(num)} -d {helpers.get_vuln_ip(num)} -j ACCEPT'
        for num in teams_list
    )


def init_network(args):
    helpers.parse_arguments_teams(args)
    helpers.add_rules(INIT_RULES)
    helpers.add_rules(get_team2vuln_rules(args.teams))
    helpers.add_rules(ALLOW_SSH_RULES)
    helpers.set_chain_policy('INPUT', 'DROP')
    helpers.set_chain_policy('FORWARD', 'DROP')

    helpers.logger.info('Enabling ip forwarding')

    if not helpers.DRY_RUN:
        with open('/proc/sys/net/ipv4/ip_forward', 'w') as f:
            f.write('1')


def open_network(_args):
    helpers.set_chain_policy('FORWARD', 'ACCEPT')


def close_network(_args):
    helpers.set_chain_policy('FORWARD', 'DROP')


def shutdown_network(args):
    helpers.parse_arguments_teams(args)
    helpers.remove_rules(INIT_RULES)
    helpers.remove_rules(get_team2vuln_rules(args.teams))

    isolation_rules = sum((get_isolation_rules(team) for team in args.teams), [])
    helpers.remove_rules(isolation_rules)

    ban_rules = sum((get_ban_rules(team) for team in args.teams), [])
    helpers.remove_rules(ban_rules)

    helpers.set_chain_policy('INPUT', 'ACCEPT')
    helpers.set_chain_policy('FORWARD', 'DROP')

    helpers.remove_rules(ALLOW_SSH_RULES)


def ban_team(args):
    helpers.insert_rules(get_ban_rules(args.team), 1)


def unban_team(args):
    helpers.remove_rules(get_ban_rules(args.team))


def isolate_team(args):
    helpers.insert_rules(get_isolation_rules(args.team), 1)


def deisolate_team(args):
    helpers.remove_rules(get_isolation_rules(args.team))


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Manage network during AD CTF')
    parser.add_argument('--verbose', '-v', help='Turn verbose logging on', action='store_true')
    parser.add_argument('--dry-run', help='Just print rules (verbose mode)', action='store_true')

    subparsers = parser.add_subparsers()

    init_parser = subparsers.add_parser('init', help='Bootstrap the network')
    init_parser.set_defaults(func=init_network)

    init_teams_group = init_parser.add_mutually_exclusive_group(required=True)
    init_teams_group.add_argument('--teams', '-t', type=int, metavar='N', help='Team count')
    init_teams_group.add_argument('--range', type=str, metavar='N-N', help='Range of teams (inclusive)')
    init_teams_group.add_argument('--list', type=str, metavar='N,N,...', help='List of teams')

    open_parser = subparsers.add_parser('open', help='Open the network')
    open_parser.set_defaults(func=open_network)

    close_parser = subparsers.add_parser('close', help='Close the network')
    close_parser.set_defaults(func=close_network)

    shutdown_parser = subparsers.add_parser('shutdown', help='Remove all the added rules')
    shutdown_parser.set_defaults(func=shutdown_network)

    shutdown_teams_group = shutdown_parser.add_mutually_exclusive_group(required=True)
    shutdown_teams_group.add_argument('--teams', '-t', type=int, metavar='N', help='Team count')
    shutdown_teams_group.add_argument('--range', type=str, metavar='N-N', help='Range of teams (inclusive)')
    shutdown_teams_group.add_argument('--list', type=str, metavar='N,N,...', help='List of teams')

    list_parser = subparsers.add_parser('list', help='List added rules')
    list_parser.set_defaults(func=helpers.list_rules)

    ban_parser = subparsers.add_parser('ban', help='Ban the team')
    ban_parser.set_defaults(func=ban_team)
    ban_parser.add_argument('--team', type=int, metavar='N', help='Team number for ban')

    unban_parser = subparsers.add_parser('unban', help='Unban the team')
    unban_parser.set_defaults(func=unban_team)
    unban_parser.add_argument('--team', type=int, metavar='N', help='Team number for unban')

    isolate_parser = subparsers.add_parser('isolate', help='Isolate the team')
    isolate_parser.set_defaults(func=isolate_team)
    isolate_parser.add_argument('--team', type=int, metavar='N', help='Team number for isolation')

    deisolate_parser = subparsers.add_parser('deisolate', help='Deisolate the team')
    deisolate_parser.set_defaults(func=deisolate_team)
    deisolate_parser.add_argument('--team', type=int, metavar='N', help='Team number for deisolation')

    parsed = parser.parse_args()

    if parsed.verbose or parsed.dry_run:
        helpers.logger.setLevel(logging.DEBUG)
    else:
        helpers.logger.setLevel(logging.INFO)

    if parsed.dry_run:
        helpers.DRY_RUN = True

    try:
        parsed.func(parsed)
    except Exception as e:
        tb = traceback.format_exc()
        print(f'Got an exception: {e}\n{tb}')
        exit(1)
