# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

RustBucketRegistry is a Django-based web application. It's set up to use MySQL as the database backend.

## Environment Setup

The project requires environment variables for database connection and Django's secret key. Create a `.env` file in the root directory with:

```
SECRET_KEY=your_secret_key
DB_NAME=your_db_name
DB_USER=your_db_user
DB_PASSWORD=your_db_password
DB_HOST=your_db_host
DB_PORT=your_db_port
```

## Common Commands

### Development Server

Start the development server:
```bash
python manage.py runserver
```

### Database Operations

Make migrations:
```bash
python manage.py makemigrations
```

Apply migrations:
```bash
python manage.py migrate
```

### Django Shell

Open Django interactive shell:
```bash
python manage.py shell
```

### Creating Admin User

```bash
python manage.py createsuperuser
```

### Testing

Run all tests:
```bash
python manage.py test
```

Run specific test file:
```bash
python manage.py test app_name.tests.test_module
```

Run specific test class:
```bash
python manage.py test app_name.tests.test_module.TestClass
```

### Static Files

Collect static files:
```bash
python manage.py collectstatic
```

## Project Structure

This is a standard Django project with the following structure:

- `manage.py`: Django's command-line utility for administrative tasks
- `rustbucketregistry/`: Main project package
  - `settings.py`: Project configuration (database, installed apps, middleware, etc.)
  - `urls.py`: URL routing configuration
  - `wsgi.py` & `asgi.py`: WSGI/ASGI application entry points

## Database Configuration

The project is configured to use MySQL. The connection parameters are loaded from environment variables in `settings.py`.

## Style Guidelines
- Use Google's Python Style Guide (https://google.github.io/styleguide/pyguide.html) for Python code.
- Separate test fixtures from business logic wherever possible. 