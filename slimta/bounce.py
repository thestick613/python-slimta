# Copyright (c) 2012 Ian C. Good
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
# THE SOFTWARE.
#

from __future__ import absolute_import

import re
import uuid
import time
from io import BytesIO


from .envelope import Envelope
from slimta.util.encoders import xmlcharref_encode

__all__ = ['Bounce']

# {{{ default_header_template
default_header_template = re.sub(r'\r?\n', r'\r\n', """\
From: MAILER-DAEMON
To: {sender}
Subject: Undelivered Mail Returned to Sender
Auto-Submitted: auto-replied
MIME-Version: 1.0
Content-Type: multipart/report; report-type=delivery-status;
    boundary="{boundary}"
Content-Transfer-Encoding: 7bit

This is a multi-part message in MIME format.

--{boundary}
Content-Type: text/plain

Delivery failed for:
- {recipients}

Destination host responded:
{code} {message}

--{boundary}
Content-Type: message/delivery-status

Remote-MTA: dns; {client_name} [{client_ip}]
Diagnostic-Code: smtp; {code} {message}

--{boundary}
Content-Type: {content_type}

""")
# }}}

# {{{ default_footer_template
default_footer_template = re.sub(r'\r?\n', r'\r\n', """\

--{boundary}--
""")
# }}}


class Bounce(Envelope):
    """Class that inherits |Envelope| to implement a bounce message, which is
    then delivered back to the original sender to say the message failed to
    deliver.  The original message body is attached to the bounce message.

    :param envelope: The |Envelope| object of the original failed message.
    :param reply: The |Reply| object that caused the failure.
    :param headers_only: If given ``True``, the bounce will include only the
                         only the original message's headers, not the entire
                         message body.

    """

    #: The address to use as the sender of new bounce messages. Per SMTP RFCs,
    #: this should usually be an empty string.
    sender = ''

    #: Template to use for the bounce message data, inserted directly before
    #: the original message data. The template is processed with
    #: :meth:`str.format` with the following keys:
    #:
    #: * ``boundary`` -- A randomly generated MIME boundary string.
    #: * ``sender`` -- The sender of the original message.
    #: * ``recipients`` -- The recipients list, rendered by joining the
    #:                     recipients list with :attr:`.recipient_join`.
    #: * ``client_name`` -- The hostname of the original message sending
    #:                      client.
    #: * ``client_ip`` -- The IP address of the original message sending
    #:                    client.
    #: * ``protocol`` -- The protocol used to deliver the original message.
    #: * ``code`` -- The SMTP reply code that caused the message failure.
    #: * ``message`` -- The SMTP reply message that caused the message failure.
    header_template = default_header_template

    #: When bouncing a message that was going to multiple recipients, this
    #: string is used to join the list of recipients for the ``{recipients}``
    #: template key.
    recipient_join = '\r\n- '

    #: Template used to add text below the original message data. This template
    #: is processed the same way as ``header_template``.
    footer_template = default_footer_template

    #: The client information used when sending bounce messages. Injected as
    #: the :attr:`~slimta.envelope.Envelope.client` attribute of bounce
    #: messages.
    client = {'name': 'postmaster',
              'ip': '127.0.0.1',
              'host': 'localhost'}

    #: String injected as the :attr:`~slimta.envelope.Envelope.receiver`
    #: attribute of bounce messages. By default, this value is copied from the
    #: |Envelope| itself.
    receiver = None

    def __init__(self, envelope, reply, headers_only=False):
        super(Bounce, self).__init__(sender=self.sender,
                                     recipients=[envelope.sender])
        self._build_message(envelope, reply, headers_only)
        self.timestamp = time.time()
        self.client = Bounce.client
        self.receiver = Bounce.receiver or envelope.receiver

    def _get_substitution_table(self, envelope, reply, headers_only):
        rendered_rcpts = self.recipient_join.join(envelope.recipients)
        ctype = 'text/rfc822-headers' if headers_only else 'message/rfc822'
        return {'boundary': 'boundary_={0}'.format(uuid.uuid4().hex),
                'sender': envelope.sender,
                'recipients': rendered_rcpts,
                'client_name': 'unknown',
                'client_ip': 'unknown',
                'dest_host': 'unknown',
                'dest_port': 'unknown',
                'protocol': 'SMTP',
                'content_type': ctype,
                'code': reply.code,
                'message': reply.message}

    def _build_message(self, envelope, reply, headers_only):
        sub_table = self._get_substitution_table(envelope, reply, headers_only)
        new_payload = BytesIO()
        new_payload.write(
            xmlcharref_encode(self.header_template.format(**sub_table)))
        header_data, message_data = envelope.flatten()
        new_payload.write(xmlcharref_encode(header_data))
        if not headers_only:
            new_payload.write(message_data)
        new_payload.write(
            xmlcharref_encode(self.footer_template.format(**sub_table)))
        self.parse(new_payload.getvalue())

# vim:et:fdm=marker:sts=4:sw=4:ts=4
