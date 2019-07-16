"""Slack bot that grabs the source of Slack posts."""

import hmac
import json
import os
from hashlib import sha256
from http import HTTPStatus
from sys import stderr
from time import time
from typing import Any

from slack import WebClient
# from slack.web.classes.blocks import *
# from slack.web.classes.elements import *
# from slack.web.classes.messages import Message
from slack.web.classes.dialogs import DialogBuilder
from flask import Flask, Request
from flask import request as current_request


slack_web_client = WebClient(token=os.environ['SLACK_OAUTH_TOKEN'])


# The following verification methods are based on:
# - https://api.slack.com/docs/verifying-requests-from-slack#step-by-step_walk-through_for_validating_a_request
# - https://github.com/slackapi/python-slack-events-api/blob/master/slackeventsapi/server.py

def _is_valid_timestamp(timestamp: str) -> bool:
    """Checks if the given timestamp is at most five minutes from local time."""
    return abs(time() - int(timestamp)) <= 60 * 5

def _is_valid_request_body(request_body: bytes, timestamp: str, signature: str) -> bool:
    """Verifies the contents of a Slack request against a signature."""
    signing_secret = os.environ['SLACK_SIGNING_SECRET']
    req = str.encode(f'v0:{timestamp}:') + request_body
    request_hash = 'v0=' + hmac.new(str.encode(signing_secret), req, sha256).hexdigest()
    return hmac.compare_digest(request_hash, signature)

def _is_valid_request(request: Request) -> bool:
    """Verifies the timestamp and signature of an incoming Slack request."""
    timestamp = request.headers.get('X-Slack-Request-Timestamp')
    if not _is_valid_timestamp(timestamp):
        # This could be a replay attack, so let's ignore it.
        print('Invalid timestamp', file=stderr)
        return False

    signature = request.headers.get('X-Slack-Signature')
    if not _is_valid_request_body(request.get_data(), timestamp, signature):
        print('Invalid signature', file=stderr)
        return False

    return True


def _show_source_dialog(trigger_id: str, source_text: str):
    """Displays the source text in a Slack dialog.

    Args:
        trigger_id:
            Trigger ID retrieved from a Slack interaction request.
        source_text:
            Source text to show. Will be truncated to fit inside a textarea.
    """
    source_dialog = (
        DialogBuilder()
        .callback_id('not_used')
        .title('Source of message')
        .text_area(
            name='Message source',
            label='This does not affect the original message',
            value=source_text[:2999]
        )
    )
    slack_web_client.dialog_open(
        dialog=source_dialog.to_dict(),
        trigger_id=trigger_id,
    )


def handle_slack_interaction(request: Request) -> Any:
    """Handles an interaction event request sent by Slack.

    Args:
        request: The Flask Request object.
            <http://flask.pocoo.org/docs/1.0/api/#flask.Request>

    Returns:
        Response text or object to be passed to `make_response()`.
            <http://flask.pocoo.org/docs/1.0/api/#flask.Flask.make_response>
    """
    if request.method != 'POST':
        return 'Only POST requests are accepted', HTTPStatus.METHOD_NOT_ALLOWED

    if not _is_valid_request(request):
        return '', HTTPStatus.FORBIDDEN

    # Interaction event data is sent as JSON in the `payload` parameter, using
    # application/x-www-form-urlencoded format
    payload_str = request.values['payload']
    payload = json.loads(payload_str)

    # Our dialog is purely informational, so do nothing on submission
    if payload['type'] == 'dialog_submission':
        return '', HTTPStatus.OK

    assert payload['type'] == 'message_action', (
        f'Unexpected payload type received, see contents: {payload_str}'
    )

    # slackclient v2.1.0 does not provide a convenience class for message
    # actions, so manually access the JSON fields

    # Show the source of the message in a dialog
    original_message = payload['message']
    trigger_id = payload['trigger_id']
    message_source = json.dumps(original_message, indent=2, ensure_ascii=False)
    _show_source_dialog(trigger_id, message_source)

    return '', HTTPStatus.OK


slack_interaction_listener = Flask(__name__)
slack_interaction_listener.add_url_rule(
    '/',
    view_func=lambda: handle_slack_interaction(current_request),
    methods=['GET', 'POST']
)
