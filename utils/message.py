import smtplib
import logging
import json
from email.mime.multipart import MIMEMultipart
from email.header import Header
from email.utils import formataddr
from email.mime.text import MIMEText

signature = '\r\n\r\n\r\nThe Altme team.\r\nhttps://altme.io/'


def msg(subject, to, messagetext):
    password = json.dumps(json.load(open('keys.json', 'r'))['smtp_password'])
    fromaddr = "relay@talao.io"
    toaddr = [to.strip()]

    if not password:
        logging.error("SMTP password missing: mode.smtp_password is empty")
        return False

    msg = MIMEMultipart()
    msg['From'] = formataddr((str(Header('Web3 Digital Wallet', 'utf-8')), fromaddr))
    msg['To'] = ", ".join(toaddr)
    msg['Subject'] = subject
    body = messagetext + signature
    msg.attach(MIMEText(body, 'plain', _charset="utf-8"))

    try:
        s = smtplib.SMTP('smtp.gmail.com', 587, timeout=15)
        s.ehlo()
        s.starttls()
        s.ehlo()
        s.login(fromaddr, password)

        s.sendmail(fromaddr, toaddr, msg.as_string())
        s.quit()
        return True

    except smtplib.SMTPAuthenticationError as e:
        logging.error("SMTP auth failed for %s: %s", fromaddr, e)
        return False
    except Exception as e:
        logging.error("SMTP error sending mail to %s: %s", toaddr, e)
        return False


if __name__ == "__main__":

    test_to = "thevenet_thierry@yahoo.fr"

    ok = message(
        subject="SMTP test from message.py",
        to=test_to,
        messagetext="This is a test email sent via message.py"
    )

    if ok:
        print("✅ Email sent successfully")
    else:
        print("❌ Email sending failed")
