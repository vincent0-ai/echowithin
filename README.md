# EchoWithin - Flask User Authentication Project

EchoWithin is a simple web application built with Flask that demonstrates a complete user authentication system. It includes user registration, login, logout, and session management, using MongoDB as the database.

## Features

- User Registration with password hashing
- User Login and Logout
- Persistent user sessions using Flask-Login
- Protected routes accessible only to authenticated users
- Integration with MongoDB for data storage

## Prerequisites

Before you begin, ensure you have the following installed on your system:

- [Python 3.7+](https://www.python.org/downloads/)
- [pip](https://pip.pypa.io/en/stable/installation/) (Python package installer)
- [MongoDB](https://www.mongodb.com/try/download/community)

## Setup and Installation

Follow these steps to get your development environment set up and running.

1.  **Clone the Repository**

    ```bash
    git clone <your-repository-url>
    cd EchoWithin
    ```
    *(If you downloaded the code as a ZIP file, just unzip it and navigate into the project directory).*

2.  **Create a Virtual Environment**

    It's highly recommended to use a virtual environment to manage project dependencies.

    - On Windows:
      ```bash
      python -m venv venv
      .\venv\Scripts\activate
      ```
    - On macOS/Linux:
      ```bash
      python3 -m venv venv
      source venv/bin/activate
      ```

3.  **Install Dependencies**

    Install all the required Python packages using the provided `requirements.txt` file (or create one with the packages `Flask`, `Flask-Login`, `pymongo`)

    ```bash
    pip install Flask Flask-Login pymongo
    ```

4.  **Create the Secret Key File**

    The application requires a secret key for session management. Create a file named `secret.py` in the root of the project directory and add the following content. **Replace the placeholder with your own unique, secret string.**

    ```python
    # secret.py
    SECRET = "replace-this-with-a-long-random-secret-string"
    ```

5.  **Start MongoDB**

    Make sure your MongoDB server is running. The application connects to the default instance at `mongodb://localhost:27017`.

## Running the Application

Once the setup is complete, you can run the application with the following command:

```bash
python main.py
```

The application will start in debug mode and be accessible at **http://127.0.0.1:5000** in your web browser.