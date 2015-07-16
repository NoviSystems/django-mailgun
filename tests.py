# -*- coding: utf-8 -*-
import unittest
from contextlib import contextmanager
try:
    import urlparse
except ImportError:
    import urllib.parse as urlparse
from cgi import parse_multipart, parse_header
import io
import email, email.message, email.header
import base64
import smtplib

import django.conf
from django.core.mail import send_mail, send_mass_mail
from django.test.utils import override_settings
from django.core.exceptions import ImproperlyConfigured
import django.utils.six as six

import httmock

import requests

django.conf.settings.configure(
    EMAIL_BACKEND = 'django_mailgun.MailgunBackend',
    MAILGUN_ACCESS_KEY = 'ACCESS-KEY',
    MAILGUN_SERVER_NAME = 'SERVER-NAME',
)

class TestMailgun(unittest.TestCase):
    """Tests the django mailgun mail backend

    Since we don't want to actually send any email to test the module,
    instead the approach taken is to use httmock to intercept the requests
    module just before in sends the actual request to the server. We then
    parse and analyze the outgoing request to see if it looks like a properly
    formed request to the MailGun API containing a properly formed email.
    """

    def setUp(self):

        # Fake out requests.Session.send. This is replaced by the httmock
        # library, but we do so here to make sure no bugs in the tests result
        # in requests being sent to the actual mailgun servers
        self.__original_send = requests.Session.send
        def new_send(*args, **kwargs):
            raise RuntimeError("Test Error: A request was made outside an "
                               "expect context")
        requests.Session.send = new_send

        # The API prefix we expect all requests to begin with.
        self.API_URL = urlparse.urlsplit(
            ("https://api.mailgun.net/v2/%s/messages.mime" %
             django.conf.settings.MAILGUN_SERVER_NAME).encode("latin1")
        )

    def tearDown(self):
        requests.Session.send = self.__original_send

    @contextmanager
    def expect(self, checkers):
        """Returns a context manager that will expect an API request to be sent
        through the requests library before the context exits.

        The request is parsed as a multipart/form-data request to the mailgun
        API. The parts of the body are passed as a dictionary to the given
        checker function, which should check that the request looks okay.

        :type checkers: list
        """
        def handler(url, request):
            for i, checker in enumerate(checkers):
                try:
                    checker(url, request)
                except AssertionError:
                    # This one didn't match. try the next one.
                    if len(checkers) == 1:
                        # or just let the assertion bubble up
                        raise
                else:
                    # This one passed
                    del checkers[i]
                    break
            else:
                # None of them matched
                raise AssertionError("Email did not match any checkers")

            return {'status_code': 200}

        with httmock.HTTMock(handler):
            yield

        self.assertEqual(len(checkers), 0, "Expected another email")

    def _make_checker(self, subject, body, fromfield, tofield, html=None):
        """Returns a function that takes a url and a Prepared Request
        and checks that it's a request to the mailgun message.mime endpoint
        specifying the sending of an email with the given parameters

        """
        def checker(url, request):
            assert isinstance(request, requests.PreparedRequest)
            assert isinstance(url, urlparse.SplitResult)

            # Note: request header keys and values will be in the native
            # string type, while the request body will be a byte string in
            # both PY2 and PY3.

            # cgi.parse_header() expects a native string type and returns
            # native string types
            # cgi.parse_multipart() expects a byte string

            # This means we have to (re)encode the boundary string (which
            # comes from parse_header) in order to pass them into the
            # second parameter of parse_multipart() on python 3

            # parse_multipart returns byte strings as parameters, as well.
            # They will need to be decoded manually for strict checking on
            # python 3.

            # Check the url is correct
            self.assertEqual(url.scheme, "https")
            self.assertEqual(url.netloc, "api.mailgun.net")
            self.assertEqual(url.path, "/v3/{}/messages.mime".format(
                django.conf.settings.MAILGUN_SERVER_NAME
            ))
            # Other components of the request url should be blank
            self.assertEqual("", url.query)
            self.assertEqual("", url.fragment)
            self.assertEqual(request.method, "POST")

            # Check that the headers look okay
            contenttype, params = parse_header(request.headers['Content-Type'])
            self.assertEqual(contenttype, "multipart/form-data")

            # HTTP basic auth should use the username "api" and the access
            # key as the password
            enc = base64.b64encode("api:{}".format(
                django.conf.settings.MAILGUN_ACCESS_KEY
            ).encode("ascii")).decode("ascii")
            self.assertEqual(request.headers['Authorization'],
                             "Basic " + enc)

            # Parse the parts of the multipart/form-data body.
            # the boundary needs to be a byte string on python 3 for
            # parse_multipart to work.
            params['boundary'] = params['boundary'].encode("ascii")
            parts = parse_multipart(io.BytesIO(request.body), params)

            # Now check the form fields. Refer to the MailGun API docs at
            # https://documentation.mailgun.com/api-sending.html#sending

            # Fields parsed from the multipart/form-data request are byte
            # strings. They need to be decoded to compare to the expected
            # values in python 3. Unicode characters are encoded with RFC
            # 2047 style encoding, which we decode with this function:
            def decode_header(h):
                return " ".join(
                    decodedbytes.decode(charset)
                    if charset is not None else decodedbytes
                    for decodedbytes, charset in email.header.decode_header(h)
                )
            self.assertEqual(
                decode_header(parts['to'][0].decode("ascii")),
                tofield
            )

            # Now to parse the "message" part of the request, which should be
            # in MIME format representing the email to send
            if six.PY3:
                m = email.message_from_bytes(parts['message'][0])
            else:
                m = email.message_from_string(parts['message'][0])
            assert isinstance(m, email.message.Message)

            # We now have an email.message.Message object

            # The header fields of the message are native strings on both PY2
            # and PY3, however, non ASCII characters in a header field will
            # still be encoded with an RFC 2047 style encoding that we'll
            # need to process manually with the above decode_header() function.

            msgfrom = decode_header(m['From'])
            msgto = decode_header(m['To'])
            msgsubject = decode_header(m['Subject'])

            self.assertEqual(msgfrom, fromfield)
            self.assertEqual(msgto, tofield)
            self.assertEqual(msgsubject, subject)

            # PY3 decodes the payload properly to a unicode string if
            # Content-Transfer-Encoding is 8bit and there is a charset
            # specified [0], but the PY2 payload gives us a byte string. We'll
            # need to decode it ourself.

            # [0] https://docs.python.org/3/library/email.message.html#email.message.Message.get_payload

            if html is None:
                # A plain text message should be the entirety of the body; an
                # HTML message the body is mixed type
                self.assertFalse(m.is_multipart())
                payload = m.get_payload()
                if six.PY2:
                    # Python 2 doesn't decode the payload for us. So we need
                    # to do that manually
                    payload = payload.decode(m.get_param("charset", "ascii"))
                self.assertEqual(payload, body)
            else:
                self.assertTrue(m.is_multipart())
                messages = m.get_payload()
                # messages should be a list of email.message.Message objects.
                assert isinstance(messages, list)
                self.assertEqual(len(messages), 2)
                if parse_header(messages[0]['Content-Type'])[0] != \
                        "text/plain":
                    messages[0], messages[1] = messages[1], messages[0]

                # At this point the first message should be the text/plain
                # message, and the second the html message

                contenttype, params = parse_header(messages[0]['Content-Type'])
                self.assertEqual(contenttype, "text/plain")
                self.assertEqual(messages[0].get_payload(), body)

                contenttype, params = parse_header(messages[1]['Content-Type'])
                self.assertEqual(contenttype, "text/html")
                self.assertEqual(messages[1].get_payload(), html)

        return checker


    def test_basic(self):
        with self.expect([self._make_checker(
            "A subject", "message body", "from@email", "to@email",
        )]):
            send_mail("A subject", "message body", "from@email", ["to@email"])

    def test_two_recp(self):
        with self.expect([self._make_checker(
                "A subject", "message body",
                "from@email", "to@email, second@email",
        )]):
            send_mail("A subject", "message body", "from@email", ["to@email",
                                                                  "second@email"])
    def test_two_emails(self):
        with self.expect([
            self._make_checker("Subject1", "body one", "from1@email",
                               "to1@email"),
            self._make_checker("subject2", "body two", "from2@email",
                                "to2@email")
        ]):
            send_mail("Subject1", "body one", "from1@email", ["to1@email"])
            send_mail("subject2", "body two", "from2@email", ["to2@email"])

    def test_no_access_key(self):
        with override_settings():
            del django.conf.settings.MAILGUN_ACCESS_KEY
            self.assertRaises(ImproperlyConfigured, send_mail, "subj","body",
                              "from",["to"])

    def test_no_access_key_fail_silently(self):
        # Fail silently is meant for errors in sending the email. A
        # configuration error in the settings should always raise an error.
        with override_settings():
            del django.conf.settings.MAILGUN_ACCESS_KEY
            self.assertRaises(ImproperlyConfigured, send_mail, "subj","body",
                              "from",["to"], fail_silently=True)

    def test_smtp_error(self):
        """Test what happens if MailGun returns HTTP 500 status code to a
        request.

        """
        with httmock.HTTMock(lambda url,request: {'status_code': 500}):
            self.assertRaises(smtplib.SMTPException,
                              send_mail,"sub", "body", "from", ["to"])

    def test_smtp_error_fail_silently(self):
        """Test what happens if MailGun returns HTTP 500 status code to a
        request.

        """
        with httmock.HTTMock(lambda url,request: {'status_code': 500}):
            # Should not raise any errors.
            send_mail("sub", "body", "from", ["to"], fail_silently=True)

    def test_html_message(self):
        with self.expect([self._make_checker(
            "A subject", "plain body", "from@email", "to@email",
            html="<body>html body</body>",
        )]):
            send_mail("A subject", "plain body", "from@email", ["to@email"],
                      html_message="<body>html body</body>")

    def test_send_mass_mail(self):
        messages = [
            ("subj1", "msg1", "from1", ["to1"]),
            ("subj2", "msg2", "from2", ["to2"]),
        ]
        expects = [
            self._make_checker("subj1", "msg1", "from1", "to1"),
            self._make_checker("subj2", "msg2", "from2", "to2"),
        ]
        with self.expect(expects):
            send_mass_mail(messages)

    def test_unicode_body(self):

        with self.expect([self._make_checker(
                "A subject", u"ŭñíçøḑĘ", "from@email", "to@email",
        )]):
            send_mail("A subject", u"ŭñíçøḑĘ", "from@email", ["to@email"])

    def test_unicode_subject(self):

        with self.expect([self._make_checker(
                u"ŭñíçøḑĘ", "message body", "from@email", "to@email",
        )]):
            send_mail(u"ŭñíçøḑĘ", "message body", "from@email", ["to@email"])

    def test_unicode_from(self):
        with self.expect([self._make_checker(
                "A subject", "message body", u"frøm <from@email>", "to@email",
        )]):
            send_mail("A subject", "message body", u"frøm <from@email>",
                      ["to@email"])

    def test_unicode_to(self):
        with self.expect([self._make_checker(
                "A subject", "message body", "from@email", u"tø <to@email>",
        )]):
            send_mail("A subject", "message body", "from@email",
                      [u"tø <to@email>"])
