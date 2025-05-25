# Rustbucket Registry
Rustbucket Registry is a Django-based web application that allows users to register and manage a swarm of Rustbucket instances. 

## Functionality
Rustbucket Registry ships with the following functionality:

## Rustbucket Registration and Lifecycle Monitoring
New Rustbuckets need only be configured with the appropriate Rustbucket Registry URL and API key. The Rustbucket Registry will then automatically register the Rustbucket and provide it with a unique identifier. The Rustbucket Registry will also provide a web interface for monitoring the Rustbucket's lifecycle.

## Rustbucket Logsink and Aggregator
The Rustbucket Registry will automatically collect and aggregate logs from all registered Rustbuckets. These logs can then be accessed through the web interface.

## Pattern Analysis and Visualization using Claude
The Rustbucket Registry will automatically analyze the logs from all registered Rustbuckets using Anthropic's Claude API and provide a web interface for visualizing the results.

## New Features

### Pull-Based Update System
The registry now supports a pull-based update system that periodically queries each active rustbucket for its latest status and information. This ensures the registry always has up-to-date information about all rustbuckets.

### Automated Log Extraction
Logs from all active rustbuckets are automatically extracted at regular intervals and stored in a secure S3 bucket. This provides a centralized and reliable storage solution for all rustbucket logs.

### Log Parsing and Database Storage
Extracted logs are automatically parsed and stored in the database, making them easily searchable and accessible through the web interface. The parser handles various log formats, including structured JSON logs and plain text logs.

### Intelligent Log Analysis with Claude
The registry now integrates with Anthropic's Claude API to provide intelligent analysis of rustbucket logs. This analysis can identify security patterns, potential threats, and provide recommendations for improved security.

### Scheduled Tasks
All of these features are automated through scheduled tasks that can be easily configured with cron jobs or Celery tasks. See the `scheduling.md` document in the design directory for more information.

## Setup and Configuration

### Requirements
- Python 3.8 or higher
- Django 5.2 or higher
- MySQL database
- AWS S3 bucket for log storage
- Anthropic API key for Claude integration

### Installation
1. Clone the repository
2. Install dependencies: `pip install -r requirements.txt`
3. Configure the database and S3 bucket settings in `.env` or `settings.py`
4. Run migrations: `python manage.py migrate`
5. Create a superuser: `python manage.py createsuperuser`
6. Start the development server: `python manage.py runserver`

### Setting Up Scheduled Tasks
See `design/scheduling.md` for detailed instructions on setting up scheduled tasks for automatic updates, log extraction, parsing, and analysis.