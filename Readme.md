# VelvetStore

VelvetStore is a Golang-based Database that provides user authentication, project creation, and real-time data storage using WebSockets. It allows users to sign up, log in, create projects, and store data associated with those projects.

## Table of Contents

- [Features](#features)
- [Getting Started](#getting-started)
  - [Prerequisites](#prerequisites)
  - [Installation](#installation)
- [Usage](#usage)
- [API Endpoints](#api-endpoints)
- [WebSocket](#websocket)
- [Dependencies](#dependencies)
- [Testing](#testing)
- [Contributing](#contributing)
- [License](#license)

## Features

- User Sign Up: New users can sign up by providing a unique username and password.
- User Login: Existing users can log in using their username and password.
- User Logout: Logged-in users can log out from the system.
- Project Creation: Logged-in users can create new projects, each with a unique project ID and an API key.
- Data Storage: Users can store data associated with their projects.
- Real-time Updates: WebSocket endpoint is provided for real-time communication with connected clients.

## Getting Started

### Prerequisites

- Go (1.15 or later) installed and configured. [Download Go](https://golang.org/dl/)

### Installation

1. Clone the repository to your local machine:

```bash
git clone https://github.com/0xsarwagya/VelvetStore.git
```

2. Navigate to the project directory:
```bash
cd VelvelStore
```

3. Install the project dependencies:
```bash
make deps
```

4. Build The Application
```bash
make build
```

### Usage

1. Run the application:
```bash
make run
```

2. The application will be accessible at http://localhost:8080/.

3. Use your preferred API client (e.g., curl, Postman) to interact with the available endpoints [(See API Endpoints)](#api-endpoints).

### API Endpoints
* **POST /signup**: Register a new user. (Request body: JSON with username and password fields)
* **POST /login**: Log in as an existing user. (Request body: JSON with username and password fields)
* **POST /logout**: Log out the currently logged-in user.
* **POST /create_project**: Create a new project for the logged-in user. (Request body: JSON with project_id field)
* **POST /set**: Store data for a specific project. (Request body: JSON with key-value pairs)
* **GET /get**: Retrieve data for a specific project.
* **GET /api_key**: Retrieve the API key for the first project of the logged-in user.

### WebSocket
The application also provides a WebSocket endpoint for real-time communication with connected clients. Clients can connect to the WebSocket endpoint (/ws) and subscribe to receive updates on data changes. The WebSocket server will send real-time data updates to subscribed clients.

### Dependencies
* [Gorilla Mux](https://github.com/gorilla/mux): Used for routing HTTP requests.
* [Logrus](https://github.com/sirupsen/logrus): Used for logging.

### Testing

* To run tests for the application:
```bash
make test
```

### Contributing
Contributions to the VelvetStore project are welcome! If you find any bugs, have feature requests, or want to contribute code improvements, please feel free to open an issue or submit a pull request.
