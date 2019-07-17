"""Slack bot that grabs the source of Slack posts."""

import hmac
import json
import os
from hashlib import sha256
from http import HTTPStatus
from sys import stderr
from time import time
from typing import Any, Tuple

from flask import Flask, Request
from flask import request as current_request
import requests


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


def _send_response(response_url: str, text: str) -> None:
    """Sends text in an ephemeral message to a response URL provided by Slack.

    Args:
        response_url: URL provided by a Slack interaction request.
        text: Text to send
    """
    payload = {'text': text, 'response_type': 'ephemeral'}
    requests.post(response_url, json=payload)


def _send_source_message(response_url: str, heading: str, source: str) -> None:
    """Sends an ephemeral message containing the source of a message or post.

    If the source string is too long to fit in a single message, it will be
    split into up to 5 messages. Any remaining string after that is truncated.

    Args:
        response_url: URL provided by a Slack interaction request.
        heading: Heading text displayed above the source text.
        source: Source text of a Slack message or post.
    """
    MAX_TEXT_LENGTH = 40000

    boilerplate = f'{heading}:\n```{{source}}```'
    boilerplate_length = len(boilerplate.format(source=''))
    if len(source) <= MAX_TEXT_LENGTH - boilerplate_length:
        text = boilerplate.format(source=source)
        _send_response(response_url, text)
    else:
        boilerplate = f'{heading} ({{i}} of {{count}}):\n```{{source}}```'
        boilerplate_length = len(boilerplate.format(i=0, count=0, source=''))
        segments = []
        while source and len(segments) < 5:
            segment, source = _split_upto_newline(
                source, MAX_TEXT_LENGTH - boilerplate_length
            )
            segments.append(segment)
        for i, segment in enumerate(segments):
            text = boilerplate.format(
                i=i + 1, count=len(segments), source=segment
            )
            _send_response(response_url, text)


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

    assert payload['type'] == 'message_action', (
        f'Unexpected payload type received, see contents: {payload_str}'
    )

    # slackclient v2.1.0 does not provide a convenience class for message
    # actions, so manually access the JSON fields

    callback_id = payload['callback_id']
    original_message = payload['message']
    response_url = payload['response_url']

    if callback_id == 'view_message_source':
        # Show the source of the message in an ephemeral message
        message_source = json.dumps(
            original_message, indent=2, ensure_ascii=False
        )
        _send_source_message(
            response_url, 'Raw JSON of message', message_source)
    elif callback_id == 'view_post_source':
        # Show the source of the Slack post attached to the message
        attached_files = original_message.get('files', [])
        slack_post = next(filter(_is_slack_post, attached_files), None)
        if slack_post:
            TOKEN = os.environ['SLACK_OAUTH_TOKEN']
            post_response = requests.get(
                slack_post['url_private'],
                headers={'Authorization': f'Bearer {TOKEN}'}
            )
            post_payload = post_response.json()
            post_source = post_payload.get('full')
            if not post_source:
                post_source = json.dumps(
                    post_payload, indent=2, ensure_ascii=False
                )
            _send_source_message(
                response_url, 'Raw source of post', post_source)
        else:
            _send_response(response_url, 'Error: Not a Slack post')
    else:
        assert 0, f'Unexpected callback ID: {callback_id}'

    return '', HTTPStatus.OK


slack_interaction_listener = Flask(__name__)
slack_interaction_listener.add_url_rule(
    '/',
    view_func=lambda: handle_slack_interaction(current_request),
    methods=['GET', 'POST']
)
