from flask_mail import Mail
import os

mail = Mail()

def configure_mail(app, provider):
    """Configure Flask-Mail with a selected provider (gmail, outlook, yahoo)."""
    
    if provider == 'gmail':
        app.config['MAIL_SERVER'] = 'smtp.gmail.com'
        app.config['MAIL_PORT'] = 465
        app.config['MAIL_USE_SSL'] = True
        app.config['MAIL_USE_TLS'] = False
        app.config['MAIL_USERNAME'] = os.getenv('GMAIL_USERNAME')
        app.config['MAIL_PASSWORD'] = os.getenv('GMAIL_PASSWORD')

    elif provider == 'outlook':
        app.config['MAIL_SERVER'] = 'smtp.office365.com'
        app.config['MAIL_PORT'] = 587
        app.config['MAIL_USE_SSL'] = False
        app.config['MAIL_USE_TLS'] = True
        app.config['MAIL_USERNAME'] = os.getenv('OUTLOOK_USERNAME')
        app.config['MAIL_PASSWORD'] = os.getenv('OUTLOOK_PASSWORD')

    elif provider == 'yahoo':
        app.config['MAIL_SERVER'] = 'smtp.mail.yahoo.com'
        app.config['MAIL_PORT'] = 465
        app.config['MAIL_USE_SSL'] = True
        app.config['MAIL_USE_TLS'] = False
        app.config['MAIL_USERNAME'] = os.getenv('YAHOO_USERNAME')
        app.config['MAIL_PASSWORD'] = os.getenv('YAHOO_PASSWORD')

    else:
        raise ValueError(f"Unknown email provider: {provider}")
    
    mail.init_app(app)
    
def get_email_provider(email):
    """Determine the email provider from the provided email address."""
    try:
        # Split the email by '@' and get the domain
        domain = email.split('@')[1]
        
        # Check which provider it corresponds to
        if domain in ['gmail.com', 'googlemail.com']:
            return 'gmail'
        elif domain in ['outlook.com', 'hotmail.com', 'live.com']:
            return 'outlook'
        elif domain in ['yahoo.com', 'yahoo.co.in']:
            return 'yahoo'
        else:
            return None  # Unknown provider
    except IndexError:
        return None  # Invalid email format
