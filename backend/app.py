"""
Email Spam Classification Backend API
Built with Flask and AWS DynamoDB
"""

from flask import Flask, request, jsonify, render_template
from flask_cors import CORS
import boto3
from boto3.dynamodb.conditions import Key
import bcrypt
import pickle
import re
import uuid
from datetime import datetime
import smtplib
import imaplib
import email
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.header import decode_header
import os
from functools import wraps

app = Flask(__name__, 
            template_folder='../frontend/templates',
            static_folder='../frontend/static')
CORS(app)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'your-secret-key-change-in-production')

# AWS DynamoDB Configuration
# For local development, you can use DynamoDB Local
# For production, ensure EC2 has proper IAM role
# DynamoDB configuration: supports AWS and DynamoDB Local via env
AWS_REGION = os.environ.get('AWS_REGION', 'us-east-1')
DYNAMODB_ENDPOINT = os.environ.get('DYNAMODB_ENDPOINT')  # e.g., http://localhost:8000 for local

# Provide default fake credentials when using local endpoint to avoid credential errors
AWS_ACCESS_KEY_ID = os.environ.get('AWS_ACCESS_KEY_ID') or ('fakeMyKeyId' if DYNAMODB_ENDPOINT else None)
AWS_SECRET_ACCESS_KEY = os.environ.get('AWS_SECRET_ACCESS_KEY') or ('fakeSecretKey' if DYNAMODB_ENDPOINT else None)

dynamodb = boto3.resource(
    'dynamodb',
    region_name=AWS_REGION,
    endpoint_url=DYNAMODB_ENDPOINT if DYNAMODB_ENDPOINT else None,
    aws_access_key_id=AWS_ACCESS_KEY_ID,
    aws_secret_access_key=AWS_SECRET_ACCESS_KEY,
)

# Table names
USERS_TABLE = 'Users'
CONNECTED_MAILS_TABLE = 'Connected_Mails'
EMAILS_TABLE = 'Emails'

# Load spam classification model
MODEL_PATH = 'spam_model.pkl'
spam_model = None

def load_spam_model():
    """Load the spam classification model"""
    global spam_model
    try:
        with open(MODEL_PATH, 'rb') as f:
            spam_model = pickle.load(f)
        print(f"Spam model loaded successfully: {spam_model['model_name']}")
        print(f"Model accuracy: {spam_model['accuracy']*100:.2f}%")
    except FileNotFoundError:
        print(f"Warning: Model file '{MODEL_PATH}' not found. Please train the model first.")
        spam_model = None

def clean_text(text):
    """Clean and preprocess text for classification"""
    text = text.lower()
    text = re.sub(r'http\S+|www\S+', '', text)
    text = re.sub(r'\S+@\S+', '', text)
    text = re.sub(r'[^a-zA-Z\s]', '', text)
    text = re.sub(r'\s+', ' ', text).strip()
    return text

def classify_email_text(email_text):
    """
    Classify email text as spam or inbox
    Returns: 'spam' or 'inbox'
    """
    if spam_model is None:
        # If model not loaded, default to inbox
        return 'inbox'
    
    try:
        # Clean the text
        cleaned = clean_text(email_text)
        
        # Vectorize
        vectorized = spam_model['vectorizer'].transform([cleaned])
        
        # Predict
        prediction = spam_model['model'].predict(vectorized)[0]
        
        # Convert to label
        label = 'spam' if prediction == 1 else 'inbox'
        return label
    except Exception as e:
        print(f"Error classifying email: {e}")
        return 'inbox'

# ==================== DynamoDB Helper Functions ====================

def get_users_table():
    """Get Users table"""
    return dynamodb.Table(USERS_TABLE)

def get_connected_mails_table():
    """Get Connected_Mails table"""
    return dynamodb.Table(CONNECTED_MAILS_TABLE)

def get_emails_table():
    """Get Emails table"""
    return dynamodb.Table(EMAILS_TABLE)

def create_tables():
    """Create DynamoDB tables if they don't exist"""
    try:
        # If using local endpoint, we can safely create tables.
        # If using AWS, rely on IAM/credentials; table creation will proceed or fail gracefully.

        # Create Users table
        try:
            dynamodb.create_table(
                TableName=USERS_TABLE,
                KeySchema=[
                    {'AttributeName': 'user_id', 'KeyType': 'HASH'}
                ],
                AttributeDefinitions=[
                    {'AttributeName': 'user_id', 'AttributeType': 'S'},
                    {'AttributeName': 'email', 'AttributeType': 'S'}
                ],
                GlobalSecondaryIndexes=[
                    {
                        'IndexName': 'email-index',
                        'KeySchema': [
                            {'AttributeName': 'email', 'KeyType': 'HASH'}
                        ],
                        'Projection': {'ProjectionType': 'ALL'},
                        'ProvisionedThroughput': {
                            'ReadCapacityUnits': 5,
                            'WriteCapacityUnits': 5
                        }
                    }
                ],
                ProvisionedThroughput={
                    'ReadCapacityUnits': 5,
                    'WriteCapacityUnits': 5
                }
            )
            print(f"Created table: {USERS_TABLE}")
        except dynamodb.meta.client.exceptions.ResourceInUseException:
            print(f"Table {USERS_TABLE} already exists")

        # Create Connected_Mails table
        try:
            dynamodb.create_table(
                TableName=CONNECTED_MAILS_TABLE,
                KeySchema=[
                    {'AttributeName': 'mail_id', 'KeyType': 'HASH'}
                ],
                AttributeDefinitions=[
                    {'AttributeName': 'mail_id', 'AttributeType': 'S'},
                    {'AttributeName': 'user_id', 'AttributeType': 'S'}
                ],
                GlobalSecondaryIndexes=[
                    {
                        'IndexName': 'user_id-index',
                        'KeySchema': [
                            {'AttributeName': 'user_id', 'KeyType': 'HASH'}
                        ],
                        'Projection': {'ProjectionType': 'ALL'},
                        'ProvisionedThroughput': {
                            'ReadCapacityUnits': 5,
                            'WriteCapacityUnits': 5
                        }
                    }
                ],
                ProvisionedThroughput={
                    'ReadCapacityUnits': 5,
                    'WriteCapacityUnits': 5
                }
            )
            print(f"Created table: {CONNECTED_MAILS_TABLE}")
        except dynamodb.meta.client.exceptions.ResourceInUseException:
            print(f"Table {CONNECTED_MAILS_TABLE} already exists")

        # Create Emails table
        try:
            dynamodb.create_table(
                TableName=EMAILS_TABLE,
                KeySchema=[
                    {'AttributeName': 'email_id', 'KeyType': 'HASH'}
                ],
                AttributeDefinitions=[
                    {'AttributeName': 'email_id', 'AttributeType': 'S'},
                    {'AttributeName': 'user_id', 'AttributeType': 'S'}
                ],
                GlobalSecondaryIndexes=[
                    {
                        'IndexName': 'user_id-index',
                        'KeySchema': [
                            {'AttributeName': 'user_id', 'KeyType': 'HASH'}
                        ],
                        'Projection': {'ProjectionType': 'ALL'},
                        'ProvisionedThroughput': {
                            'ReadCapacityUnits': 5,
                            'WriteCapacityUnits': 5
                        }
                    }
                ],
                ProvisionedThroughput={
                    'ReadCapacityUnits': 5,
                    'WriteCapacityUnits': 5
                }
            )
            print(f"Created table: {EMAILS_TABLE}")
        except dynamodb.meta.client.exceptions.ResourceInUseException:
            print(f"Table {EMAILS_TABLE} already exists")

    except Exception as e:
        print(f"Error creating tables: {e}")

# ==================== Utility: Users ====================

def get_user_by_email(email_addr: str):
    """Lookup a user by email address via GSI."""
    users_table = get_users_table()
    resp = users_table.query(
        IndexName='email-index',
        KeyConditionExpression=Key('email').eq(email_addr)
    )
    return resp['Items'][0] if resp.get('Items') else None

# ==================== Authentication Routes ====================

@app.route('/api/register', methods=['POST'])
def register():
    """
    Register a new user
    Request body: {email, password}
    """
    try:
        data = request.get_json()
        email_addr = data.get('email')
        password = data.get('password')

        if not email_addr or not password:
            return jsonify({'error': 'Email and password required'}), 400

        # Check if user already exists
        users_table = get_users_table()
        response = users_table.query(
            IndexName='email-index',
            KeyConditionExpression=Key('email').eq(email_addr)
        )

        if response['Items']:
            return jsonify({'error': 'User already exists'}), 400

        # Hash password
        password_hash = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

        # Create user
        user_id = str(uuid.uuid4())
        users_table.put_item(
            Item={
                'user_id': user_id,
                'email': email_addr,
                'password_hash': password_hash,
                'created_at': datetime.now().isoformat()
            }
        )

        return jsonify({
            'message': 'User registered successfully',
            'user_id': user_id,
            'email': email_addr
        }), 201

    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/login', methods=['POST'])
def login():
    """
    Login user
    Request body: {email, password}
    """
    try:
        data = request.get_json()
        email_addr = data.get('email')
        password = data.get('password')

        if not email_addr or not password:
            return jsonify({'error': 'Email and password required'}), 400

        # Find user
        users_table = get_users_table()
        response = users_table.query(
            IndexName='email-index',
            KeyConditionExpression=Key('email').eq(email_addr)
        )

        if not response['Items']:
            return jsonify({'error': 'Invalid credentials'}), 401

        user = response['Items'][0]

        # Verify password
        if not bcrypt.checkpw(password.encode('utf-8'), user['password_hash'].encode('utf-8')):
            return jsonify({'error': 'Invalid credentials'}), 401

        return jsonify({
            'message': 'Login successful',
            'user_id': user['user_id'],
            'email': user['email']
        }), 200

    except Exception as e:
        return jsonify({'error': str(e)}), 500

# ==================== Mail Connection Routes ====================

@app.route('/api/connect-mail', methods=['POST'])
def connect_mail():
    """
    Save SMTP/IMAP credentials for a user
    Request body: {user_id, smtp_email, app_password, smtp_server, imap_server}
    """
    try:
        data = request.get_json()
        user_id = data.get('user_id')
        smtp_email = data.get('smtp_email')
        app_password = data.get('app_password')
        smtp_server = data.get('smtp_server', 'smtp.gmail.com')
        smtp_port = data.get('smtp_port', 587)
        imap_server = data.get('imap_server', 'imap.gmail.com')
        imap_port = data.get('imap_port', 993)

        if not all([user_id, smtp_email, app_password]):
            return jsonify({'error': 'user_id, smtp_email, and app_password required'}), 400

        # Create mail connection
        mail_id = str(uuid.uuid4())
        connected_mails_table = get_connected_mails_table()
        
        connected_mails_table.put_item(
            Item={
                'mail_id': mail_id,
                'user_id': user_id,
                'smtp_email': smtp_email,
                'app_password': app_password,  # In production, encrypt this!
                'smtp_server': smtp_server,
                'smtp_port': smtp_port,
                'imap_server': imap_server,
                'imap_port': imap_port,
                'created_at': datetime.now().isoformat()
            }
        )

        return jsonify({
            'message': 'Mail connected successfully',
            'mail_id': mail_id
        }), 201

    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/get-connected-mail/<user_id>', methods=['GET'])
def get_connected_mail(user_id):
    """Get connected mail credentials for a user"""
    try:
        connected_mails_table = get_connected_mails_table()
        response = connected_mails_table.query(
            IndexName='user_id-index',
            KeyConditionExpression=Key('user_id').eq(user_id)
        )

        if not response['Items']:
            return jsonify({'error': 'No connected mail found'}), 404

        # Return first connected mail (hide password)
        mail = response['Items'][0]
        return jsonify({
            'mail_id': mail['mail_id'],
            'smtp_email': mail['smtp_email'],
            'smtp_server': mail.get('smtp_server', 'smtp.gmail.com'),
            'imap_server': mail.get('imap_server', 'imap.gmail.com')
        }), 200

    except Exception as e:
        return jsonify({'error': str(e)}), 500

# ==================== Email Sending Routes ====================

@app.route('/api/send-mail', methods=['POST'])
def send_mail():
    """
    Send email via SMTP and classify it
    Request body: {user_id, to, subject, body}
    """
    try:
        data = request.get_json()
        user_id = data.get('user_id')
        to_email = data.get('to')
        subject = data.get('subject')
        body = data.get('body')

        if not all([user_id, to_email, subject, body]):
            return jsonify({'error': 'user_id, to, subject, and body required'}), 400

        # Get user's connected mail
        connected_mails_table = get_connected_mails_table()
        response = connected_mails_table.query(
            IndexName='user_id-index',
            KeyConditionExpression=Key('user_id').eq(user_id)
        )

        if not response['Items']:
            return jsonify({'error': 'No mail account connected'}), 400

        mail_config = response['Items'][0]

        # Send email via SMTP
        msg = MIMEMultipart()
        msg['From'] = mail_config['smtp_email']
        msg['To'] = to_email
        msg['Subject'] = subject
        msg.attach(MIMEText(body, 'plain'))

        server = smtplib.SMTP(mail_config.get('smtp_server', 'smtp.gmail.com'), 
                              mail_config.get('smtp_port', 587))
        server.starttls()
        server.login(mail_config['smtp_email'], mail_config['app_password'])
        server.send_message(msg)
        server.quit()

        # Classify the email body
        classification = classify_email_text(body)

        # Save to database
        email_id = str(uuid.uuid4())
        emails_table = get_emails_table()
        emails_table.put_item(
            Item={
                'email_id': email_id,
                'user_id': user_id,
                'from': mail_config['smtp_email'],
                'to': to_email,
                'subject': subject,
                'body': body,
                'classification': classification,
                'timestamp': datetime.now().isoformat(),
                'direction': 'sent'
            }
        )

        return jsonify({
            'message': 'Email sent successfully',
            'email_id': email_id,
            'classification': classification
        }), 200

    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/send-internal', methods=['POST'])
def send_internal():
    """
    Send an internal email without SMTP/IMAP.
    Classifies and stores two records: one for sender (sent), one for recipient (received).
    Request body: {from_user_id, to_email, subject, body}
    """
    try:
        data = request.get_json()
        from_user_id = data.get('from_user_id')
        to_email = data.get('to_email')
        subject = data.get('subject')
        body = data.get('body')

        if not all([from_user_id, to_email, subject, body]):
            return jsonify({'error': 'from_user_id, to_email, subject, and body are required'}), 400

        # Validate sender exists
        users_table = get_users_table()
        sender_resp = users_table.get_item(Key={'user_id': from_user_id})
        if 'Item' not in sender_resp:
            return jsonify({'error': 'Sender not found'}), 404
        sender = sender_resp['Item']

        # Find recipient by email
        recipient = get_user_by_email(to_email)
        if not recipient:
            return jsonify({'error': 'Recipient not found. Ask them to register first.'}), 404

        # Classify body
        classification = classify_email_text(body)

        emails_table = get_emails_table()
        now = datetime.now().isoformat()

        # Store for sender (sent)
        sent_email_id = str(uuid.uuid4())
        emails_table.put_item(Item={
            'email_id': sent_email_id,
            'user_id': from_user_id,
            'from': sender['email'],
            'to': recipient['email'],
            'subject': subject,
            'body': body,
            'classification': classification,
            'timestamp': now,
            'direction': 'sent'
        })

        # Store for recipient (received)
        received_email_id = str(uuid.uuid4())
        emails_table.put_item(Item={
            'email_id': received_email_id,
            'user_id': recipient['user_id'],
            'from': sender['email'],
            'to': recipient['email'],
            'subject': subject,
            'body': body,
            'classification': classification,
            'timestamp': now,
            'direction': 'received'
        })

        return jsonify({
            'message': 'Email stored internally',
            'classification': classification,
            'sent_email_id': sent_email_id,
            'received_email_id': received_email_id
        }), 200

    except Exception as e:
        return jsonify({'error': str(e)}), 500

# ==================== Email Fetching Routes ====================

@app.route('/api/fetch-mails', methods=['POST'])
def fetch_mails():
    """
    Fetch emails from IMAP server and classify them
    Request body: {user_id, limit (optional)}
    """
    try:
        data = request.get_json()
        user_id = data.get('user_id')
        limit = data.get('limit', 10)  # Default fetch 10 emails

        if not user_id:
            return jsonify({'error': 'user_id required'}), 400

        # Get user's connected mail
        connected_mails_table = get_connected_mails_table()
        response = connected_mails_table.query(
            IndexName='user_id-index',
            KeyConditionExpression=Key('user_id').eq(user_id)
        )

        if not response['Items']:
            return jsonify({'error': 'No mail account connected'}), 400

        mail_config = response['Items'][0]

        # Connect to IMAP server
        imap = imaplib.IMAP4_SSL(mail_config.get('imap_server', 'imap.gmail.com'),
                                 mail_config.get('imap_port', 993))
        imap.login(mail_config['smtp_email'], mail_config['app_password'])
        imap.select('INBOX')

        # Search for emails
        _, message_numbers = imap.search(None, 'ALL')
        email_ids = message_numbers[0].split()
        
        # Fetch latest emails (limited)
        fetched_emails = []
        emails_table = get_emails_table()
        
        for email_id_bytes in email_ids[-limit:]:
            _, msg_data = imap.fetch(email_id_bytes, '(RFC822)')
            email_body = msg_data[0][1]
            email_message = email.message_from_bytes(email_body)

            # Extract email details
            subject = decode_header(email_message['Subject'])[0][0]
            if isinstance(subject, bytes):
                subject = subject.decode()

            from_email = email_message.get('From')
            
            # Extract body
            body = ""
            if email_message.is_multipart():
                for part in email_message.walk():
                    if part.get_content_type() == "text/plain":
                        body = part.get_payload(decode=True).decode()
                        break
            else:
                body = email_message.get_payload(decode=True).decode()

            # Classify email
            classification = classify_email_text(body)

            # Save to database
            db_email_id = str(uuid.uuid4())
            emails_table.put_item(
                Item={
                    'email_id': db_email_id,
                    'user_id': user_id,
                    'from': from_email,
                    'to': mail_config['smtp_email'],
                    'subject': subject,
                    'body': body[:500],  # Store first 500 chars
                    'classification': classification,
                    'timestamp': datetime.now().isoformat(),
                    'direction': 'received'
                }
            )

            fetched_emails.append({
                'email_id': db_email_id,
                'from': from_email,
                'subject': subject,
                'classification': classification
            })

        imap.close()
        imap.logout()

        return jsonify({
            'message': f'Fetched {len(fetched_emails)} emails',
            'emails': fetched_emails
        }), 200

    except Exception as e:
        return jsonify({'error': str(e)}), 500

# ==================== Email Retrieval Routes ====================

@app.route('/api/emails/<user_id>', methods=['GET'])
def get_user_emails(user_id):
    """Get all emails for a user"""
    try:
        classification_filter = request.args.get('classification')  # 'spam' or 'inbox'
        
        emails_table = get_emails_table()
        response = emails_table.query(
            IndexName='user_id-index',
            KeyConditionExpression=Key('user_id').eq(user_id)
        )

        emails = response['Items']

        # Filter by classification if specified
        if classification_filter:
            emails = [e for e in emails if e.get('classification') == classification_filter]

        # Sort by timestamp (newest first)
        emails.sort(key=lambda x: x.get('timestamp', ''), reverse=True)

        return jsonify({
            'emails': emails,
            'count': len(emails)
        }), 200

    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/email/<email_id>', methods=['GET'])
def get_email_detail(email_id):
    """Get detailed information for a specific email"""
    try:
        emails_table = get_emails_table()
        response = emails_table.get_item(Key={'email_id': email_id})

        if 'Item' not in response:
            return jsonify({'error': 'Email not found'}), 404

        return jsonify(response['Item']), 200

    except Exception as e:
        return jsonify({'error': str(e)}), 500

# ==================== Frontend Routes ====================

@app.route('/')
def index():
    """Serve the main page"""
    return render_template('index.html')

@app.route('/register')
def register_page():
    """Serve the registration page"""
    return render_template('register.html')

@app.route('/login')
def login_page():
    """Serve the login page"""
    return render_template('login.html')

@app.route('/connect-mail-page')
def connect_mail_page():
    """Serve the connect mail page"""
    return render_template('connect_mail.html')

@app.route('/compose')
def compose_page():
    """Serve the compose mail page"""
    return render_template('compose.html')

@app.route('/inbox')
def inbox_page():
    """Serve the inbox page"""
    return render_template('inbox.html')

@app.route('/spam')
def spam_page():
    """Serve the spam page"""
    return render_template('spam.html')

# ==================== Health Check ====================

@app.route('/health', methods=['GET'])
def health_check():
    """Health check endpoint"""
    return jsonify({
        'status': 'healthy',
        'model_loaded': spam_model is not None,
        'timestamp': datetime.now().isoformat()
    }), 200

# ==================== Initialize ====================

if __name__ == '__main__':
    # Load spam model
    load_spam_model()
    
    # Create DynamoDB tables
    create_tables()
    
    # Run Flask app
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=True)
