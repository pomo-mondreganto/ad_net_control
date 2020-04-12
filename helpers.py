import logging
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


def get_team_ip(team: int):
    return f'10.{60 + team // 256}.{team % 256}.0/24'
