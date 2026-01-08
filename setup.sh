#!/bin/bash

# Quick Start Script for Spam Email Classifier

echo "======================================"
echo "Spam Email Classifier - Setup Script"
echo "======================================"

# Check Python version
echo -e "\n1. Checking Python version..."
python3 --version

# Create virtual environment
echo -e "\n2. Creating virtual environment..."
python3 -m venv venv

# Activate virtual environment
echo -e "\n3. Activating virtual environment..."
source venv/bin/activate

# Install dependencies
echo -e "\n4. Installing dependencies..."
pip install --upgrade pip
pip install -r requirements.txt

# Create data directory
echo -e "\n5. Creating data directory..."
mkdir -p data

# Create environment file
echo -e "\n6. Creating .env file..."
if [ ! -f .env ]; then
    cp .env.example .env
    echo "Please edit .env file with your configuration"
fi

# Check for dataset
echo -e "\n7. Checking for dataset..."
if [ ! -f data/spam.csv ]; then
    echo "⚠️  WARNING: Dataset not found!"
    echo "Please download spam.csv from:"
    echo "https://www.kaggle.com/code/mfaisalqureshi/email-spam-detection-98-accuracy"
    echo "And place it in the data/ folder"
fi

# Check for trained model
echo -e "\n8. Checking for trained model..."
if [ ! -f spam_model.pkl ]; then
    echo "⚠️  WARNING: Trained model not found!"
    echo "Please run the training notebook: train_spam_model.ipynb"
    echo "Or start with: jupyter notebook train_spam_model.ipynb"
fi

echo -e "\n======================================"
echo "Setup Complete!"
echo "======================================"
echo -e "\nNext Steps:"
echo "1. Download the dataset and place in data/ folder"
echo "2. Train the model: jupyter notebook train_spam_model.ipynb"
echo "3. Configure AWS credentials (or use local DynamoDB)"
echo "4. Edit .env file with your configuration"
echo "5. Run the application: python backend/app.py"
echo -e "\nHappy coding! 🚀"
