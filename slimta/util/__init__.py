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

"""Module containing useful tools, helpers, and other features that didn't
belong under any other module.

"""

from __future__ import absolute_import

from copy import copy
from contextlib import contextmanager

import eventlet

from slimta.smtp.auth import Auth, CredentialsInvalidError

__all__ = ['dns_resolver', 'build_auth_from_dict']


dns_resolver_mod = eventlet.import_patched('dns.resolver')

#: .. versionadded:: 0.3.19
#:
#: This is an instance of `dns.resolver.Resolver()
#: <http://www.dnspython.org/docs/1.11.1/dns.resolver.Resolver-class.html>`_
#: monkey-patched with :mod:`eventlet`. Additionally it has its
#: ``retry_servfail`` attribute set to ``True``.
#:
#: Built-in slimta modules use this resolver for custom DNS queries, such as
#: *MX* record lookup. You can modify attributes such as ``timeout`` or
#: ``lifetime`` to control query behavior.
dns_resolver = dns_resolver_mod.Resolver()
dns_resolver.retry_servfail = True


def build_auth_from_dict(dict, lower_case=False, only_verify=True):
    """Helper function that constructs an |Auth| class that authenticates a
    user by checking a dictionary with the username as the key and their
    password is the associated value.

    :param dict: A dictionary or object that implements ``__getitem__()`` that
                 contains usernames mapping to passwords.
    :param lower_case: If ``True``, the username string will be lower-cased
                       before checking for it in the dictionary.
    :param only_verify: If ``True``, the resulting sub-class will not implement
                        :meth:`~slimta.smtp.auth.Auth.get_secret` or support
                        ``CRAM-MD5``.
    :returns: Generated sub-class of |Auth|.

    """
    class CustomAuth(Auth):

        def verify_secret(self, authcid, secret, authzid=None):
            username = authcid.lower() if lower_case else authcid
            try:
                assert dict[username] == secret
            except (KeyError, AssertionError):
                raise CredentialsInvalidError()
            return username

        def get_secret(self, authcid, authzid=None):
            username = authcid.lower() if lower_case else authcid
            try:
                return dict[username], username
            except KeyError:
                raise CredentialsInvalidError()

    if only_verify:
        CustomAuth.get_secret = None

    return CustomAuth


# vim:et:fdm=marker:sts=4:sw=4:ts=4
