"""Slack bot that grabs the source of Slack posts."""

import hmac
import json
import os
import urllib
from hashlib import sha256
from http import HTTPStatus
from sys import stderr
from time import time
from typing import Any, Tuple

from slack import WebClient
# from slack.web.classes.blocks import *
# from slack.web.classes.elements import *
# from slack.web.classes.messages import Message
from slack.web.classes.dialogs import DialogBuilder
from slack.web.classes.dialog_elements import DialogTextArea
from flask import Flask, Request
from flask import request as current_request


slack_web_client = WebClient(token=os.environ['SLACK_BOT_OAUTH_TOKEN'])


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
    request_hash = hmac.new(str.encode(signing_secret), req, sha256)
    return hmac.compare_digest('v0=' + request_hash.hexdigest(), signature)


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


def _split_upto_newline(source: str, maxlen: int) -> Tuple[str, str]:
    """Splits a string in two, limiting the length of the first part.

    Splits the given string in two, such that the first part (segment) contains
    at most `maxlen` characters.

    If the source string contains a line break ('\\n') at or before maxlen, the
    string is split at the newline, and the newline character itself is not
    included in either the source or maxlen. This ensures that source code is
    split as cleanly as possible.

    Args:
        source: String to split.
        maxlen: Maximum number of characters allowed in the segment part.

    Returns:
        Tuple of (segment, remainder). If the source text has less characters
        than max_pos, the remainder contains the empty string ('').
    """
    assert maxlen >= 0, f'maxlen must be nonnegative (value={maxlen!r})'
    split_current = split_next = maxlen
    if len(source) > maxlen:
        last_newline_pos = source.rfind('\n', 0, maxlen + 1)
        if last_newline_pos != -1:
            split_current = last_newline_pos
            split_next = last_newline_pos + 1
    return source[:split_current], source[split_next:]


def _show_source_dialog(trigger_id: str, source_text: str):
    """Displays the source text in a Slack dialog.

    If the source text is too long to fit inside a single textarea, it is split
    into multiple textareas (up to 10). Any text beyond the last textarea is
    truncated.

    Args:
        trigger_id:
            Trigger ID retrieved from a Slack interaction request.
        source_text:
            Source text to show. Will be truncated to fit inside a textarea.
    """
    TITLE = 'View message source'
    source_dialog = DialogBuilder().callback_id('not_used').title(TITLE)

    # Note: DialogTextArea in slackclient v2.1.0 allows only up to
    #       (max_value_length - 1) characters in the `value` field.
    MAX_LENGTH = DialogTextArea.max_value_length - 1
    MAX_ELEMENTS = DialogBuilder.elements_max_length

    if len(source_text) <= MAX_LENGTH:
        source_dialog.text_area(
            name='Message source',
            label='Message source',
            value=source_text
        )
    else:
        segments = []
        while source_text and len(segments) < MAX_ELEMENTS:
            segment, source_text = _split_upto_newline(source_text, MAX_LENGTH)
            segments.append(segment)
        for i, text in enumerate(segments):
            source_dialog.text_area(
                name=f'Message source ({i + 1} of {len(segments)})',
                label=f'Message source ({i + 1} of {len(segments)})',
                value=text
            )

    slack_web_client.dialog_open(
        dialog=source_dialog.to_dict(),
        trigger_id=trigger_id,
    )


def _is_slack_post(file_info: dict) -> bool:
    """Checks if the file type is a valid Slack post."""
    filetype = file_info['filetype']
    return filetype == 'post' or filetype == 'space' or filetype == 'docs'


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

    callback_id = payload['callback_id']
    original_message = payload['message']
    trigger_id = payload['trigger_id']

    if callback_id == 'view_message_source':
        # Show the source of the message in a dialog
        message_source = json.dumps(
            original_message, indent=2, ensure_ascii=False
        )
        _show_source_dialog(trigger_id, message_source)
    elif callback_id == 'view_post_source':
        # Show the source of the Slack post attached to the message
        attached_files = original_message.get('files', [])
        slack_post = next(filter(_is_slack_post, attached_files), None)
        if slack_post:
            TOKEN = os.environ['SLACK_OAUTH_TOKEN']
            post_url = urllib.request.Request(
                slack_post['url_private'],
                headers={'Authorization': f'Bearer {TOKEN}'}
            )
            post_response = urllib.request.urlopen(post_url)
            post_payload = json.loads(post_response.read())
            post_source = post_payload.get('full')
            if not post_source:
                post_source = json.dumps(
                    post_payload, indent=2, ensure_ascii=False
                )
            _show_source_dialog(trigger_id, post_source)
        else:
            slack_web_client.chat_postEphemeral(
                channel=payload['channel']['id'],
                user=payload['user']['id'],
                text='Error: This is not a Slack post.'
            )
    else:
        assert 0, f'Unexpected callback ID: {callback_id}'

    return '', HTTPStatus.OK


slack_interaction_listener = Flask(__name__)
slack_interaction_listener.add_url_rule(
    '/',
    view_func=lambda: handle_slack_interaction(current_request),
    methods=['GET', 'POST']
)
