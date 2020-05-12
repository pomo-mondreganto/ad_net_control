import logging
import re
import shlex
import subprocess

logger = logging.getLogger('ad_net_control')
logger.addHandler(logging.StreamHandler())

DRY_RUN = False


def run_command(command):
    if not DRY_RUN:
        proc = subprocess.Popen(command)
        proc.wait()


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

    logger.debug(f"Checking if rule {rule} exists")

    command = ['iptables', '-C'] + shlex.split(rule)
    rc = subprocess.call(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
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


def set_chain_policy(chain, policy):
    logger.debug(f'Setting chain {chain} policy to {policy}')
    command = ['iptables', '-P', chain, policy]
    run_command(command)


def chain_exists(chain):
    logger.debug(f'Checking if chain {chain} exists')
    if DRY_RUN:
        return False
    command = ['iptables', '-S']
    out = subprocess.check_output(command).decode()
    return f'-N {chain}' in out.split('\n')


def create_chain(chain):
    if not chain_exists(chain):
        logger.debug(f'Chain {chain} does already exists')
        return
    logger.debug(f'Creating chain {chain}')
    command = ['iptables', '-N', chain]
    run_command(command)


def flush_chain(chain):
    logger.debug(f'Flushing chain {chain}')
    command = ['iptables', '-F', chain]
    run_command(command)


def remove_chain(chain):
    if not chain_exists(chain):
        logger.debug(f'Chain {chain} does not exist')
        return

    flush_chain(chain)
    logger.debug(f'Removing chain {chain}')
    command = ['iptables', '-X', chain]
    run_command(command)


def get_team_subnet(team: int):
    return f'10.{60 + team // 256}.{team % 256}.0/24'


def get_vuln_ip(team: int):
    return f'10.{80 + team // 256}.{team % 256}.2'


def parse_arguments_teams(args):
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
