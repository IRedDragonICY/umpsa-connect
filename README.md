# UMPSA Connect

UMPSA Connect is a Python application with a GUI interface that streamlines the process of mass registration, email retrieval, and automatic login to the UMPSA portal.

## Features

- **Mass Registration**: Automate the registration of up to 5,000 accounts.
- **Email Retrieval**: Fetch credential emails from Gmail and extract login information.
- **Automatic Login**: Use extracted credentials to log in to the portal seamlessly.
- **User-Friendly GUI**: Intuitive interface with real-time progress updates.

## Prerequisites

- **Python 3.x**
- **Microsoft Edge WebDriver**
- **Google API Credentials**: A `client_secret.json` file for Gmail authentication.

### Python Packages

Ensure the following packages are installed:

- `beautifulsoup4`
- `google-auth`
- `google-auth-oauthlib`
- `google-api-python-client`
- `selenium`
- `tk`

Install the packages using pip:

```bash
pip install -r requirements.txt
```

> **Note**: Create a `requirements.txt` file with the list of packages above.

## Installation

1. **Clone the Repository**

   ```bash
   git clone https://github.com/username/umpsa-connect.git
   cd umpsa-connect
   ```

2. **Install Dependencies**

   ```bash
   pip install -r requirements.txt
   ```

3. **Set Up Google API Credentials**

   - Obtain the `client_secret.json` file from the Google Cloud Console.
   - Place the file in the project directory.

4. **Configure Edge WebDriver**

   - Download the [Microsoft Edge WebDriver](https://developer.microsoft.com/en-us/microsoft-edge/tools/webdriver/).
   - Ensure the WebDriver is added to your system's PATH environment variable.

## Usage

1. **Run the Application**

   Execute the main script:

   ```bash
   python main.py
   ```

2. **GUI Interface**

   - **Register**: Start the mass registration process.
   - **Fetch Email**: Retrieve emails and extract credentials.
   - **Login**: Automatically log in using available credentials.

## Project Structure

```
umpsa-connect/
├── credentials.csv        # Stores extracted credentials
├── main.py                # Main application script
├── requirements.txt       # Python package dependencies
├── client_secret.json     # Google API credentials file
├── token.json             # Token file for Gmail API authentication
└── README.md              # Project documentation
```

## Contributing

Contributions are welcome! Please fork the repository and submit a pull request for any enhancements or bug fixes.

1. Fork the Project
2. Create your Feature Branch (`git checkout -b feature/AmazingFeature`)
3. Commit your Changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the Branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

## License

Distributed under the [MIT License](LICENSE).
---

*Crafted with ❤️ by IRedDragonICY.*