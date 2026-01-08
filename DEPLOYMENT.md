# AWS Deployment Guide for Spam Email Classifier

This guide provides step-by-step instructions for deploying the Spam Email Classifier application on AWS EC2 with DynamoDB.

## Architecture Overview

- **EC2 Instance**: Hosts the Flask backend application
- **DynamoDB**: NoSQL database for storing users, mail connections, and emails
- **IAM Role**: Provides EC2 instance with permissions to access DynamoDB
- **Security Group**: Controls inbound/outbound traffic to EC2

---

## Prerequisites

1. AWS Account with appropriate permissions
2. AWS CLI installed and configured (optional but recommended)
3. SSH key pair for EC2 access
4. Trained spam model file (`spam_model.pkl`)

---

## Part 1: DynamoDB Setup

### 1.1 Create DynamoDB Tables

You can create tables via AWS Console or AWS CLI.

#### Option A: AWS Console

1. Go to **DynamoDB** in AWS Console
2. Click **Create table** for each of the following:

**Table 1: Users**
- Table name: `Users`
- Partition key: `user_id` (String)
- Create a Global Secondary Index:
  - Index name: `email-index`
  - Partition key: `email` (String)

**Table 2: Connected_Mails**
- Table name: `Connected_Mails`
- Partition key: `mail_id` (String)
- Create a Global Secondary Index:
  - Index name: `user_id-index`
  - Partition key: `user_id` (String)

**Table 3: Emails**
- Table name: `Emails`
- Partition key: `email_id` (String)
- Create a Global Secondary Index:
  - Index name: `user_id-index`
  - Partition key: `user_id` (String)

#### Option B: AWS CLI

```bash
# Create Users table
aws dynamodb create-table \
    --table-name Users \
    --attribute-definitions \
        AttributeName=user_id,AttributeType=S \
        AttributeName=email,AttributeType=S \
    --key-schema AttributeName=user_id,KeyType=HASH \
    --global-secondary-indexes \
        "[{\"IndexName\": \"email-index\",
          \"KeySchema\": [{\"AttributeName\":\"email\",\"KeyType\":\"HASH\"}],
          \"Projection\":{\"ProjectionType\":\"ALL\"},
          \"ProvisionedThroughput\": {\"ReadCapacityUnits\": 5, \"WriteCapacityUnits\": 5}}]" \
    --provisioned-throughput ReadCapacityUnits=5,WriteCapacityUnits=5 \
    --region us-east-1

# Create Connected_Mails table
aws dynamodb create-table \
    --table-name Connected_Mails \
    --attribute-definitions \
        AttributeName=mail_id,AttributeType=S \
        AttributeName=user_id,AttributeType=S \
    --key-schema AttributeName=mail_id,KeyType=HASH \
    --global-secondary-indexes \
        "[{\"IndexName\": \"user_id-index\",
          \"KeySchema\": [{\"AttributeName\":\"user_id\",\"KeyType\":\"HASH\"}],
          \"Projection\":{\"ProjectionType\":\"ALL\"},
          \"ProvisionedThroughput\": {\"ReadCapacityUnits\": 5, \"WriteCapacityUnits\": 5}}]" \
    --provisioned-throughput ReadCapacityUnits=5,WriteCapacityUnits=5 \
    --region us-east-1

# Create Emails table
aws dynamodb create-table \
    --table-name Emails \
    --attribute-definitions \
        AttributeName=email_id,AttributeType=S \
        AttributeName=user_id,AttributeType=S \
    --key-schema AttributeName=email_id,KeyType=HASH \
    --global-secondary-indexes \
        "[{\"IndexName\": \"user_id-index\",
          \"KeySchema\": [{\"AttributeName\":\"user_id\",\"KeyType\":\"HASH\"}],
          \"Projection\":{\"ProjectionType\":\"ALL\"},
          \"ProvisionedThroughput\": {\"ReadCapacityUnits\": 5, \"WriteCapacityUnits\": 5}}]" \
    --provisioned-throughput ReadCapacityUnits=5,WriteCapacityUnits=5 \
    --region us-east-1
```

---

## Part 2: IAM Role Setup

### 2.1 Create IAM Policy for DynamoDB Access

1. Go to **IAM** → **Policies** → **Create Policy**
2. Select JSON tab and paste:

```json
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": [
                "dynamodb:PutItem",
                "dynamodb:GetItem",
                "dynamodb:UpdateItem",
                "dynamodb:DeleteItem",
                "dynamodb:Query",
                "dynamodb:Scan"
            ],
            "Resource": [
                "arn:aws:dynamodb:us-east-1:*:table/Users",
                "arn:aws:dynamodb:us-east-1:*:table/Users/index/*",
                "arn:aws:dynamodb:us-east-1:*:table/Connected_Mails",
                "arn:aws:dynamodb:us-east-1:*:table/Connected_Mails/index/*",
                "arn:aws:dynamodb:us-east-1:*:table/Emails",
                "arn:aws:dynamodb:us-east-1:*:table/Emails/index/*"
            ]
        }
    ]
}
```

3. Name it: `SpamClassifier-DynamoDB-Policy`

### 2.2 Create IAM Role

1. Go to **IAM** → **Roles** → **Create Role**
2. Select **AWS Service** → **EC2**
3. Attach the policy: `SpamClassifier-DynamoDB-Policy`
4. Name the role: `SpamClassifier-EC2-Role`

---

## Part 3: EC2 Instance Setup

### 3.1 Launch EC2 Instance

1. Go to **EC2** → **Launch Instance**
2. Configure:
   - **Name**: `spam-classifier-server`
   - **AMI**: Ubuntu Server 22.04 LTS (or Amazon Linux 2023)
   - **Instance Type**: t2.medium (minimum) or t2.large (recommended)
   - **Key Pair**: Select or create a key pair
   - **IAM Role**: Select `SpamClassifier-EC2-Role`
   - **Security Group**: Create a new one with:
     - SSH (port 22) from your IP
     - HTTP (port 80) from anywhere (0.0.0.0/0)
     - Custom TCP (port 5000) from anywhere (for Flask, later use nginx)

### 3.2 Connect to EC2 Instance

```bash
chmod 400 your-key.pem
ssh -i your-key.pem ubuntu@<EC2-PUBLIC-IP>
```

### 3.3 Install Dependencies

```bash
# Update system
sudo apt update && sudo apt upgrade -y

# Install Python and pip
sudo apt install python3-pip python3-venv -y

# Install nginx (for production)
sudo apt install nginx -y

# Install git
sudo apt install git -y
```

---

## Part 4: Deploy Application

### 4.1 Upload Application Files

Option A: Use SCP to transfer files:

```bash
# On your local machine
scp -i your-key.pem -r /path/to/spam-classification ubuntu@<EC2-PUBLIC-IP>:~/
```

Option B: Clone from Git repository (recommended):

```bash
# On EC2 instance
git clone https://github.com/your-username/spam-classification.git
cd spam-classification
```

### 4.2 Set Up Python Environment

```bash
# Create virtual environment
python3 -m venv venv
source venv/bin/activate

# Install requirements
pip install -r requirements.txt
```

### 4.3 Set Environment Variables

```bash
# Create .env file
nano .env
```

Add the following:

```
AWS_REGION=us-east-1
SECRET_KEY=your-super-secret-key-change-this
PORT=5000
```

```bash
# Load environment variables
export $(cat .env | xargs)
```

### 4.4 Test the Application

```bash
# Make sure spam_model.pkl is in the root directory
# Run the Flask app
python backend/app.py
```

Access the app at: `http://<EC2-PUBLIC-IP>:5000`

---

## Part 5: Production Deployment with Gunicorn and Nginx

### 5.1 Install Gunicorn

```bash
pip install gunicorn
```

### 5.2 Create Systemd Service

```bash
sudo nano /etc/systemd/system/spam-classifier.service
```

Add:

```ini
[Unit]
Description=Spam Email Classifier Flask App
After=network.target

[Service]
User=ubuntu
WorkingDirectory=/home/ubuntu/spam-classification
Environment="PATH=/home/ubuntu/spam-classification/venv/bin"
Environment="AWS_REGION=us-east-1"
Environment="SECRET_KEY=your-super-secret-key"
ExecStart=/home/ubuntu/spam-classification/venv/bin/gunicorn --workers 3 --bind 0.0.0.0:5000 backend.app:app

[Install]
WantedBy=multi-user.target
```

### 5.3 Start and Enable Service

```bash
sudo systemctl daemon-reload
sudo systemctl start spam-classifier
sudo systemctl enable spam-classifier
sudo systemctl status spam-classifier
```

### 5.4 Configure Nginx as Reverse Proxy

```bash
sudo nano /etc/nginx/sites-available/spam-classifier
```

Add:

```nginx
server {
    listen 80;
    server_name <EC2-PUBLIC-IP or your-domain.com>;

    location / {
        proxy_pass http://127.0.0.1:5000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }

    location /static {
        alias /home/ubuntu/spam-classification/frontend/static;
    }
}
```

Enable the site:

```bash
sudo ln -s /etc/nginx/sites-available/spam-classifier /etc/nginx/sites-enabled/
sudo nginx -t
sudo systemctl restart nginx
```

---

## Part 6: Security Enhancements

### 6.1 Update Security Group

Remove port 5000 from security group (only allow port 80/443)

### 6.2 Set Up HTTPS with Let's Encrypt (Optional)

```bash
sudo apt install certbot python3-certbot-nginx -y
sudo certbot --nginx -d your-domain.com
```

### 6.3 Enable Firewall

```bash
sudo ufw allow 'Nginx Full'
sudo ufw allow OpenSSH
sudo ufw enable
```

---

## Part 7: Model Training on EC2 (Optional)

If you want to train the model on EC2:

```bash
# Install Jupyter
pip install jupyter

# Run the training notebook
jupyter notebook --no-browser --port=8888

# On your local machine, create SSH tunnel:
ssh -i your-key.pem -L 8888:localhost:8888 ubuntu@<EC2-PUBLIC-IP>
```

Then open http://localhost:8888 in your browser.

---

## Monitoring and Maintenance

### View Application Logs

```bash
# Service logs
sudo journalctl -u spam-classifier -f

# Nginx logs
sudo tail -f /var/log/nginx/access.log
sudo tail -f /var/log/nginx/error.log
```

### Restart Application

```bash
sudo systemctl restart spam-classifier
```

### Update Application

```bash
cd ~/spam-classification
git pull
source venv/bin/activate
pip install -r requirements.txt
sudo systemctl restart spam-classifier
```

---

## Cost Estimation

- **EC2 t2.medium**: ~$30/month
- **DynamoDB**: Pay per request (Free tier: 25GB storage, 25 WCU, 25 RCU)
- **Data Transfer**: Minimal for typical usage

**Total Estimated Cost**: $30-50/month depending on usage

---

## Troubleshooting

### Application won't start
```bash
# Check logs
sudo journalctl -u spam-classifier -n 50
# Check Python errors
python backend/app.py
```

### DynamoDB Access Denied
- Verify IAM role is attached to EC2 instance
- Check IAM policy permissions

### Can't connect to EC2
- Check security group allows SSH from your IP
- Verify key pair permissions: `chmod 400 your-key.pem`

---

## Security Checklist

- [ ] Changed SECRET_KEY in environment variables
- [ ] Enabled HTTPS with SSL certificate
- [ ] Restricted SSH access to specific IPs
- [ ] Encrypted sensitive data in DynamoDB
- [ ] Set up CloudWatch monitoring
- [ ] Configured automated backups
- [ ] Enabled MFA for AWS account

---

## Next Steps

1. Set up CloudWatch alarms for EC2 and DynamoDB
2. Configure automatic backups for DynamoDB
3. Implement rate limiting in the API
4. Add email validation and sanitization
5. Set up CI/CD pipeline with GitHub Actions or AWS CodePipeline

---

## Support

For issues or questions:
- Check application logs
- Review AWS CloudWatch metrics
- Consult AWS documentation for DynamoDB and EC2

---

**Deployment Complete! 🎉**

Your Spam Email Classifier is now running on AWS at: `http://<EC2-PUBLIC-IP>`
