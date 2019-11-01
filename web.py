from flask import Flask, request, abort, jsonify
import json
import os
from functools import wraps

import net_control

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
CONFIG = json.load(open(os.path.join(BASE_DIR, 'config.json')))

app = Flask(__name__)
app.secret_key = CONFIG['SECRET_KEY']


def with_authentication(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        if request.headers.get('SECRET') != app.secret_key:
            abort(401)
        return f(*args, **kwargs)

    return wrapper


@app.route('/api/list', methods=['GET'])
@with_authentication
def list_commands():
    return jsonify(list(net_control.COMMANDS.keys()))


@app.route('/api/run/<command>', methods=['POST'])
@with_authentication
def run_command(command):
    if command not in net_control.COMMANDS:
        return jsonify({'status': 'error', 'error': 'invalid command'}), 400

    try:
        args = request.json or {}
        net_control.COMMANDS[command](**args)
    except Exception as e:
        return jsonify({'status': 'error', 'error': str(e)}), 400

    return jsonify({'status': 'ok'})


if __name__ == '__main__':
    app.run(host='0.0.0.0')
