import smtplib

from django.conf import settings
from django.core.mail.backends.base import BaseEmailBackend
from django.core.mail.message import sanitize_address
import django.utils.six as six
from django.core.exceptions import ImproperlyConfigured

import requests
import requests.exceptions

StringIO = six.BytesIO

class MailgunBackend(BaseEmailBackend):
    """A Django Email backend that uses mailgun.
    """

    def __init__(self, fail_silently=False, *args, **kwargs):
        access_key, server_name = (kwargs.pop('access_key', None),
                                   kwargs.pop('server_name', None))
    
        super(MailgunBackend, self).__init__(
                        fail_silently=fail_silently, 
                        *args, **kwargs)

        try:
            self._access_key = access_key or getattr(settings, 'MAILGUN_ACCESS_KEY')
            self._server_name = server_name or getattr(settings, 'MAILGUN_SERVER_NAME')
        except AttributeError as e:
            six.raise_from(ImproperlyConfigured(*e.args), e)

        self._api_url = "https://api.mailgun.net/v3/%s/" % self._server_name

    def open(self):
        """Stub for open connection, all sends are done over HTTP POSTs
        """
        pass

    def close(self):
        """Close any open HTTP connections to the API server.
        """
        pass

    def _send(self, email_message):
        """A helper method that does the actual sending."""
        if not email_message.recipients():
            return False
        from_email = sanitize_address(email_message.from_email, email_message.encoding)
        recipients = [sanitize_address(addr, email_message.encoding)
                      for addr in email_message.recipients()]

        try:
            r = requests.post(
                    self._api_url + "messages.mime",
                    auth=("api", self._access_key),
                    data={
                           "to": ", ".join(recipients),
                           "from": from_email,
                        },
                    files={
                           "message": StringIO(
                               email_message.message().as_bytes(linesep="\r\n"))
                        }
                    )
        except requests.exceptions.RequestException as e:
            if not self.fail_silently:
                six.raise_from(smtplib.SMTPException("Could not send mail"),
                               e)
            return False

        if r.status_code != 200:
            if not self.fail_silently:
                raise smtplib.SMTPException("Mailgun server returned code {"
                                            "}".format(r.status_code))
            return False

        return True

    def send_messages(self, email_messages):
        """Sends one or more EmailMessage objects and returns the number of
        email messages sent.
        """
        if not email_messages:
            return

        num_sent = 0
        for message in email_messages:
            if self._send(message):
                num_sent += 1

        return num_sent
