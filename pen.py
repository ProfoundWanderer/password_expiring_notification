import config
from datetime import datetime, date, timedelta
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
import logging
from ldap3 import Server, Connection, ALL, NTLM
import os
import smtplib
import ssl
import sys


# if expiring send x; if expired send y
pass


def main():
    office_list = ['Bedrock-Dallas', 'Bedrock-Frisco', 'Bedrock-Houston', 'Bedrock-Minnesota', 'Bedrock-Orlando']
    expiring_passwords(setup(), office_list)
    logging.info("AD password expiration notification script (pen.py) has completed.")


def expiring_passwords(ad, office_list):
    today = date.today()
    margin = timedelta(days=3)
    email_message_dict = {}

    for user in ad.entries:
        ldap_expire_date = user['msDS-UserPasswordExpiryTimeComputed'].value
        """
        - If the user is active AND password is not set to never expire AND if they have one of the office 
          names in the distinguishedName
        - Link with what the userAccountControl values represent: 
          https://jackstromberg.com/2013/01/useraccountcontrol-attributeflag-values/
        """
        if (
                user['userAccountControl'].value == 512
                and any(word in user['distinguishedName'].value for word in office_list)
                and user['msDS-UserPasswordExpiryTimeComputed'].value != '9223372036854775807'
                and today - margin <= datetime.fromtimestamp(
                ldap_to_unix_time(ldap_expire_date)).date() <= today + margin
        ):
            expire_message = (f"Dear {user['displayName']},\n\n"
                              f"Your has expires on {ldap_to_human_time(ldap_expire_date)}. "
                              f"Make sure to change it if you have not done so already.\n\nYou can change your "
                              f"password at any time by:\n"
                              f"    1. Logging into your computer.\n"
                              f"    2. Pressing Ctrl-Alt-Del and clicking on \"Change a password\".\n"
                              f"    3. Fill in your old password and set a new password. See the password "
                              f"requirements below.\n"
                              f"    4. Press OK to return to your desktop. \n\n"
                              f"The new password must meet the minimum requirements which are:\n"
                              f"    1. Must be at least 7 characters.\n"
                              f"    2. Contain at least 3 of the 4 of the following:\n"
                              f"        - character types:\n"
                              f"        - Uppsercase - A to Z\n"
                              f"        - Lowercase - a to z\n"
                              f"        - Numeric - 0 to 9\n"
                              f"        - Symbols such as !, #, %, or &\n"
                              f"    3. It cannot match any of your past three passwords.\n\n\n"
                              f"If you have any questions, contact IT.")
            email_message_dict[user['mail'].value] = expire_message

    send_email(email_message_dict)


def ldap_to_human_time(ldap_time):
    unix = ldap_to_unix_time(ldap_time)
    return datetime.fromtimestamp(unix).strftime("%B %d, %Y at %H:%M")


def ldap_to_unix_time(ldap_time):
    return (ldap_time / 10000000) - 11644473600


def setup():
    logging.info("Setup started.")
    try:
        server = Server(config.server_name, get_info=ALL)
        connect = Connection(
            server,
            user=f'{config.domain_name}\\{config.user_name}',
            password=config.password,
            authentication=NTLM,
            auto_bind=True,
        )
    except Exception as e:
        logging.exception(e)
        logging.error(f"Unable to complete setup due to the above exception. Ending script.")
        sys.exit(0)

    connect.search(
        'dc=bedrock,dc=local',
        '(objectclass=person)',
        attributes=[
            'displayName',
            'distinguishedName',
            'mail',
            'msDS-UserPasswordExpiryTimeComputed',
            'userAccountControl',
        ],
    )

    logging.info("Setup complete.")
    return connect


def send_email(email_message_dict):
    """
    This does the final formatting of the email and sends it
    """
    log_size = os.path.getsize('pen.log')  # just for a easy reminder so the file doesn't get too large over time.

    for to_address in email_message_dict:
        body = email_message_dict[to_address]
        subject = "Your Computer Password Is Expiring"

        print(body)
        exit()

        # create a multipart message and set headers
        message = MIMEMultipart()
        message["From"] = config.from_address
        message["To"] = to_address
        message["Subject"] = subject
        # add body to the email
        message.attach(MIMEText(body, "plain"))

        exit()
        context = ssl.create_default_context()
        with smtplib.SMTP(config.smtp_server, config.smtp_port) as server:
            try:
                server.ehlo()
                server.starttls(context=context)
                server.ehlo()
                server.login(config.email_login, config.email_password)
                server.sendmail(config.from_address, to_address, message.as_string())
                logging.info("Email has successfully sent.")
            except Exception as e:
                logging.exception(e)
            finally:
                server.quit()
                logging.info(f"The log file (pen.log) is {log_size} bytes which is ~{log_size*0.000001:.3f} MB.")
                logging.info("Successfully quit server.")


if __name__ == '__main__':
    logging.basicConfig(
        format='%(asctime)s | %(levelname)s | %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S',
        filename='pen.log',
        level=logging.INFO,
    )
    logging.info("AD password expiration notification script (pen.py) has started.")
    main()
