#!/usr/bin/env python3

import argparse
import logging
import traceback

import helpers

CUSTOM_CHAINS = [
    'closed-network',
    'open-network',
]

SETS = [
    'same-team',
    'team-vulnbox',
]

INIT_RULES = [
    'INPUT -m state --state RELATED,ESTABLISHED -j ACCEPT',  # allow already established connections
    'INPUT -m conntrack --ctstate INVALID -j DROP',  # drop invalid packets
    'INPUT -i lo -j ACCEPT',  # accept all local connections
    'INPUT -p icmp --icmp-type 8 -m state --state NEW,ESTABLISHED,RELATED -j ACCEPT',  # allow icmp 8
    'INPUT -p icmp --icmp-type 0 -m state --state NEW,ESTABLISHED,RELATED -j ACCEPT',  # allow icmp 0

    'INPUT -p udp --dport 30000:31999 -j ACCEPT',  # wireguard listeners
    'INPUT -p tcp --dport 9100 -j ACCEPT',  # node_exporter metrics
    'INPUT -p tcp --dport 9586 -j ACCEPT',  # wireguard exporter metrics

    'FORWARD -m state --state RELATED,ESTABLISHED -j ACCEPT',  # allow already established connections
    'FORWARD -s 10.10.10.0/24 -j ACCEPT',  # jury access to everything

    'POSTROUTING -t nat -o wg0 -j MASQUERADE',  # everything masqueraded
    'POSTROUTING -t mangle -o wg0 -j TTL --ttl-set 137',  # To prevent ttl filtering
]

ALLOW_SSH_RULES = [
    'INPUT -p tcp --dport 22 -m state --state NEW,RELATED,ESTABLISHED -j ACCEPT',  # ingoing SSH
    'OUTPUT -p tcp --sport 22 -m state --state RELATED,ESTABLISHED -j ACCEPT',  # outgoing SSH
]

OPEN_NETWORK_RULES = [
    'open-network -d 10.10.10.0/24 -j ACCEPT',  # anyone can access jury
    'open-network -d 10.80.0.0/14 -j ACCEPT',  # anyone can access vulnboxes
]

# forwarding traffic to closed-network chain
CLOSED_NETWORK_FORWARDING = ['FORWARD -j closed-network']

# forwarding traffic to open-network chain
OPEN_NETWORK_FORWARDING = ['FORWARD -j open-network']


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


def get_team2vuln_rules():
    """During closed network period, team can only access its own vulnbox"""
    return [f'closed-network -m set --match-set team-vulnbox src,dst -j ACCEPT']


def get_in_team_rules():
    return ['FORWARD -m set --match-set same-team src,dst -j ACCEPT']


def init_network(args):
    for chain in CUSTOM_CHAINS:
        helpers.create_chain(chain)
        helpers.set_chain_policy(chain, 'DROP')

    for s in SETS:
        helpers.create_set(s)

    helpers.parse_arguments_teams(args)
    helpers.add_rules(INIT_RULES)
    helpers.add_rules(ALLOW_SSH_RULES)
    helpers.set_chain_policy('INPUT', 'DROP')
    helpers.set_chain_policy('FORWARD', 'DROP')

    for team in args.teams:
        team_subnet = helpers.get_team_subnet(team)
        vulnbox_ip = helpers.get_vuln_ip(team)
        helpers.add_to_set('same-team', team_subnet, team_subnet)
        helpers.add_to_set('team-vulnbox', team_subnet, vulnbox_ip)

    helpers.add_rules(get_team2vuln_rules())
    helpers.add_rules(get_in_team_rules())

    # just add the rules to the chain
    helpers.add_rules(OPEN_NETWORK_RULES)

    close_network(args)

    helpers.logger.info('Enabling ip forwarding')

    if not helpers.DRY_RUN:
        with open('/proc/sys/net/ipv4/ip_forward', 'w') as f:
            f.write('1')


def open_network(_args):
    helpers.remove_rules(CLOSED_NETWORK_FORWARDING)
    helpers.add_rules(OPEN_NETWORK_FORWARDING)


def close_network(_args):
    helpers.remove_rules(OPEN_NETWORK_FORWARDING)
    helpers.add_rules(CLOSED_NETWORK_FORWARDING)


def shutdown_network(args):
    helpers.parse_arguments_teams(args)
    helpers.remove_rules(INIT_RULES)

    isolation_rules = sum((get_isolation_rules(team) for team in args.teams), [])
    helpers.remove_rules(isolation_rules)

    ban_rules = sum((get_ban_rules(team) for team in args.teams), [])
    helpers.remove_rules(ban_rules)

    helpers.set_chain_policy('INPUT', 'ACCEPT')
    helpers.set_chain_policy('FORWARD', 'DROP')

    helpers.remove_rules(ALLOW_SSH_RULES)
    helpers.remove_rules(CLOSED_NETWORK_FORWARDING)
    helpers.remove_rules(OPEN_NETWORK_FORWARDING)

    for chain in CUSTOM_CHAINS:
        helpers.remove_chain(chain)

    for s in SETS:
        helpers.remove_set(s)


def ban_team(args):
    helpers.insert_rules(get_ban_rules(args.team), 1)


def unban_team(args):
    helpers.remove_rules(get_ban_rules(args.team))


def isolate_team(args):
    helpers.insert_rules(get_isolation_rules(args.team), 1)


def deisolate_team(args):
    helpers.remove_rules(get_isolation_rules(args.team))


def add_teams_arguments(command_parser):
    teams_group = command_parser.add_mutually_exclusive_group(required=True)
    teams_group.add_argument('--teams', '-t', type=int, metavar='N', help='Team count')
    teams_group.add_argument('--range', type=str, metavar='N-N', help='Range of teams (inclusive)')
    teams_group.add_argument('--list', type=str, metavar='N,N,...', help='List of teams')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Manage network during AD CTF')
    parser.add_argument('--verbose', '-v', help='Turn verbose logging on', action='store_true')
    parser.add_argument('--dry-run', help='Just print rules (verbose mode)', action='store_true')

    subparsers = parser.add_subparsers()

    init_parser = subparsers.add_parser('init', help='Bootstrap the network')
    init_parser.set_defaults(func=init_network)
    add_teams_arguments(init_parser)

    open_parser = subparsers.add_parser('open', help='Open the network')
    open_parser.set_defaults(func=open_network)

    close_parser = subparsers.add_parser('close', help='Close the network')
    close_parser.set_defaults(func=close_network)

    shutdown_parser = subparsers.add_parser('shutdown', help='Remove all the added rules')
    shutdown_parser.set_defaults(func=shutdown_network)
    add_teams_arguments(shutdown_parser)

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
