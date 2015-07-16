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

if six.PY3:
    import email.policy

django.conf.settings.configure(
    EMAIL_BACKEND = 'django_mailgun.MailgunBackend',
    MAILGUN_ACCESS_KEY = 'ACCESS-KEY',
    MAILGUN_SERVER_NAME = 'SERVER-NAME',
)

class TestMailgun(unittest.TestCase):
    """Tests the django mailgun mail backend

    Since we don't want to actually send any email to test the module,
    instead the approach taken is to use httmock to intercept the requests
    module just before it sends the actual request to the server. We then
    parse and analyze the outgoing request to see if it looks like a properly
    formed request to the MailGun API containing a properly formed email.

    This is probably overkill and mostly unnecessary, since the mailgun API
    takes a MIME message, and Django constructs that for us, so there's not
    much that our mail backend actually does. It just has to make the HTTP
    request with the proper parameters. However, I still wanted to make sure
    that the backend passes email properly, and just checking that it didn't
    raise any errors or that it made *some* request just didn't seem good
    enough.

    It's more work than it should be mostly because there's a lot to deal
    with decoding and parsing, and dealing with differences with the decoding
    and parsing behavior between Python 2 and 3.
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

        Takes a list of "checker" functions. Each checker function will take
        the SplitResult url object and PreparedRequest object, and check if
        the request matches some parameters. If it doesn't, it should raise
        an AssertionError. Otherwise, it should return without error.

        The number of requests we see should exactly match the number of
        checkers given, and each request should match at least one checker
        (but a checker may only be used once. This means that if a request
        matches 2 checkers but another request only matches one, then the
        order is important)

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

    def _make_checker(self, subject, body, fromfield, tofield, html=None,
                      ccfield=None, bccfield=None):
        """Returns a function that takes a url and a Prepared Request
        and checks that it's a request to the mailgun message.mime endpoint
        specifying the sending of an email with the given parameters

        :param subject: the subject as a text string
        :param body: the body as a text string
        :param fromfield: the from address as a text string
        :param html: the html body as a text string
        :param tofield: a list of addresses to send to
        :param ccfield: a list of cc addresses
        :param bccfield: a list of bcc addresses

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
            # The boundary needs to be a byte string on python 3 for
            # parse_multipart to work.
            params['boundary'] = params['boundary'].encode("ascii")
            parts = parse_multipart(io.BytesIO(request.body), params)

            # Now check the form fields. Refer to the MailGun API docs at
            # https://documentation.mailgun.com/api-sending.html#sending

            # Fields parsed from the multipart/form-data request are ASCII byte
            # strings. Further, unicode characters are encoded with RFC
            # 2047 style encoding, the same as MIME headers. We need to
            # decode these fields ourself because parse_multipart() doesn't
            # do it. The email.header.decode_header() function does exactly
            # this.
            # Unfortunately, due to a Python bug (issue22833),
            # the decode_header() function may return bytes or a str
            # depending on its input, so we need to hack around that and
            # check the result to get it to a proper unicode string, or tests
            # will fail on Python 3.
            def decode_header(h):
                """Returns a single unicode string from the passed-in RFC
                2047 encoded header.

                :param h: A (unicode) string

                """
                parts = []
                for decodedbytes, charset in email.header.decode_header(h):
                    decodedbytes = decodedbytes.strip()
                    if isinstance(decodedbytes, six.text_type):
                        decodedbytes = decodedbytes.encode("ascii")
                    if charset is None:
                        parts.append(decodedbytes.decode("ascii"))
                    else:
                        parts.append(decodedbytes.decode(charset))
                return " ".join(parts)

            form_to = decode_header(parts['to'][0].decode("ascii")).split(",")
            form_to = [f.strip() for f in form_to]
            # Verify that each of the to, cc, and bcc recipients are in this
            # form field
            for t in tofield:
                self.assertIn(t, form_to)
            if ccfield is not None:
                for c in ccfield:
                    self.assertIn(c, form_to)
            if bccfield is not None:
                for b in bccfield:
                    self.assertIn(b, form_to)

            # Now to parse the "message" part of the request, which should be
            # in MIME format representing the email to send
            if six.PY3:
                m = email.message_from_bytes(parts['message'][0],
                                             policy=email.policy.SMTP)
            else:
                m = email.message_from_string(parts['message'][0])
            assert isinstance(m, email.message.Message)

            # We now have an email.message.Message object

            # The header fields of the message are native strings on both PY2
            # and PY3, however, on Python 2 non ASCII characters in a header
            # field will still be encoded with an RFC 2047 style encoding
            # that we'll need to process manually with the above
            # decode_header() function. (On Python 3, we use the
            # email.policy.SMTP decoder which decodes headers for us)

            if six.PY2:
                msgfrom = decode_header(m['From'])
                msgto = decode_header(m['To'])
                msgsubject = decode_header(m['Subject'])
            else:
                msgfrom = m['From']
                msgto = m['To']
                msgsubject = m['Subject']

            self.assertEqual(msgfrom, fromfield)
            self.assertEqual(msgsubject, subject)

            msgto = [msgtopart.strip() for msgtopart in msgto.split(",")]
            for t in tofield:
                self.assertIn(t, msgto)

            # Now look at the optional cc field. Getting a header
            # with __getitem__ on a Message returns None if the header
            # doesn't exist.
            msgcc = m['cc']
            if msgcc is None: msgcc = ""
            if six.PY2:
                msgcc = decode_header(msgcc)
            msgcc = [msgccpart.strip() for msgccpart in msgcc.split(",")]
            if ccfield is not None:
                for c in ccfield:
                    self.assertIn(c, msgcc)

            # And check that our bcc recipients are NOT included in any of
            # the headers
            if bccfield is not None:
                for b in bccfield:
                    self.assertNotIn(b, msgcc)
                    self.assertNotIn(b, msgto)

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
        msg = ("A subject", "message body", "from@email", ["to@email"],)
        with self.expect([self._make_checker(*msg)]):
            send_mail(*msg)

    def test_two_recp(self):
        msg = ("A subject", "message body", "from@email", ["to@email",
               "second@email"],)
        with self.expect([self._make_checker(*msg)]):
            send_mail(*msg)

    def test_two_emails(self):
        msg1 = ("Subject1", "body one", "from1@email", ["to1@email"])
        msg2 = ("subject2", "body two", "from2@email", ["to2@email"])
        with self.expect([
            self._make_checker(*msg1),
            self._make_checker(*msg2)
        ]):
            send_mail(*msg1)
            send_mail(*msg2)

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
            "A subject", "plain body", "from@email", ["to@email"],
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
            self._make_checker("subj1", "msg1", "from1", ["to1"]),
            self._make_checker("subj2", "msg2", "from2", ["to2"]),
        ]
        with self.expect(expects):
            send_mass_mail(messages)

    def test_unicode_body(self):
        msg = ("A subject", u"ŭñíçøḑĘ", "from@email", ["to@email"],)

        with self.expect([self._make_checker(*msg)]):
            send_mail(*msg)

    def test_unicode_subject(self):
        msg = (u"ŭñíçøḑĘ", "message body", "from@email", ["to@email"])

        with self.expect([self._make_checker(*msg)]):
            send_mail(*msg)

    def test_unicode_from(self):
        msg = ("A subject", "message body", u"frøm <from@email>",
                  ["to@email"])
        with self.expect([self._make_checker(*msg)]):
            send_mail(*msg)

    def test_unicode_to(self):
        msg = ("A subject", "message body", "from@email",
                  [u"tø <to@email>"])
        with self.expect([self._make_checker(*msg)]):
            send_mail(*msg)

    def test_cc(self):
       msg = django.core.mail.EmailMessage(
           "Subject", "body", "from@email", ["to@email"],
           cc=["cc@email"]
       )
       with self.expect([self._make_checker(
               "Subject", "body", "from@email", ["to@email"],
               ccfield=["cc@email"]
       )]):
           msg.send()

    def test_bcc(self):
        msg = django.core.mail.EmailMessage(
            "Subject", "body", "from@email", ["to@email"],
            bcc=["bcc@email"]
        )
        with self.expect([self._make_checker(
                "Subject", "body", "from@email", ["to@email"],
                bccfield=["bcc@email"]
        )]):
            msg.send()

    def test_cc_and_bcc(self):
        msg = django.core.mail.EmailMessage(
            "Subject", "body", "from@email", ["to@email"],
            cc=["cc@email"], bcc=["bcc@email"]
        )
        with self.expect([self._make_checker(
                "Subject", "body", "from@email", ["to@email"],
                ccfield=["cc@email"], bccfield=["bcc@email"]
        )]):
            msg.send()
