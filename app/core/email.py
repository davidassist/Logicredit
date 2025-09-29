"""Email sending utilities."""
from __future__ import annotations

from email.message import EmailMessage

import aiosmtplib

from .config import Settings, get_settings


class EmailService:
    """Async email sending via SMTP."""

    def __init__(self, settings: Settings | None = None) -> None:
        self.settings = settings or get_settings()

    async def send_email(self, subject: str, recipient: str, body: str) -> None:
        message = EmailMessage()
        message["From"] = self.settings.from_email
        message["To"] = recipient
        message["Subject"] = subject
        message.set_content(body)

        await aiosmtplib.send(
            message,
            hostname=self.settings.smtp_host,
            port=self.settings.smtp_port,
            username=self.settings.smtp_username,
            password=self.settings.smtp_password,
            start_tls=self.settings.smtp_use_tls,
        )


def get_email_service() -> EmailService:
    return EmailService()
