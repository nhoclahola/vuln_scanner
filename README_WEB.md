# Vulnerability Scanner Web Interface

A modern web interface for the Vulnerability Scanner application that allows users to run scans, view results, and manage settings through an intuitive dashboard.

## Features

- **Modern Dashboard**: Get an overview of your security posture with vulnerability statistics and recent scan history
- **Interactive Scan Interface**: Run vulnerability scans against target websites with real-time progress updates
- **Comprehensive Scan History**: View and analyze past scan results with detailed reports
- **Customizable Settings**: Configure API keys, default scan parameters, and reporting preferences

## Screenshots

![Dashboard](https://via.placeholder.com/800x450?text=Dashboard+Screenshot)
![Scan Interface](https://via.placeholder.com/800x450?text=Scan+Interface+Screenshot)
![Scan History](https://via.placeholder.com/800x450?text=Scan+History+Screenshot)

## Installation

### Requirements

- Python 3.8+
- Flask
- Other dependencies as specified in `requirements.txt`

### Setup

1. Clone the repository:
   ```bash
   git clone https://github.com/yourusername/vuln_scanner.git
   cd vuln_scanner
   ```

2. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

3. Setup environment variables (optional):
   ```bash
   export OPENAI_API_KEY="your_openai_api_key"
   export DEEPSEEK_API_KEY="your_deepseek_api_key"
   ```

4. Start the web server:
   ```bash
   python vuln_web_app.py
   ```

5. Open your browser and navigate to:
   ```
   http://localhost:5000
   ```

## Usage

### Dashboard

The dashboard provides an overview of your vulnerability scanning activities:

- **Statistics Cards**: View total scans performed, vulnerabilities found, and critical issues
- **Vulnerability Distribution**: Chart showing the breakdown of vulnerabilities by severity
- **Recent Scans**: Quick access to your most recent scan results
- **Performance Metrics**: Review scan performance and trend analysis

### Running a New Scan

1. Navigate to the **Scan** page
2. Enter the target URL you want to scan
3. Select your LLM provider (DeepSeek or OpenAI)
4. Choose the scan type (Basic or Full)
5. Click "Start Scan" to begin
6. Monitor real-time progress and output as the scan executes
7. View detailed results when the scan completes

### Viewing Scan History

1. Navigate to the **History** page
2. Browse the list of previous scans on the left panel
3. Click on any scan to view its details
4. Use the tabs to view different formats of the report:
   - **Summary**: High-level overview of findings
   - **Detailed**: Comprehensive breakdown of each vulnerability
   - **JSON**: Raw data output for integration with other tools
5. Download reports in your preferred format

### Configuring Settings

1. Navigate to the **Settings** page
2. Configure your API keys:
   - OpenAI API Key
   - DeepSeek API Key and Base URL
3. Set your default scan parameters:
   - Default LLM Provider
   - Default Scan Type
   - Vulnerability types to scan for
4. Configure report settings:
   - Report format
   - Output directory
   - Auto-save options

## Architecture

The web interface is built using:

- **Flask**: Backend web framework
- **Bootstrap 5**: Frontend styling and components
- **Chart.js**: Data visualization
- **Server-Sent Events**: Real-time scan updates

The application follows a modular structure:
- `vuln_web_app.py`: Main Flask application
- `templates/`: HTML templates for each page
- `static/js/`: JavaScript files for frontend functionality
- `static/css/`: CSS styles for the user interface

## Customization

### Themes

The interface supports both light and dark modes. Toggle between modes using the button in the top right corner of the sidebar.

### Extending

To add new vulnerability types:
1. Update the `settings.html` template to include new options
2. Modify the backend scanning code to support the new vulnerability types
3. Update the report rendering to display the new findings

## Troubleshooting

### Common Issues

**Problem**: Scans get stuck at "Starting"
**Solution**: Check your API keys in the Settings page and ensure they're valid

**Problem**: Web interface doesn't load
**Solution**: Verify that Flask is running and check the console for any errors

**Problem**: Can't see scan results
**Solution**: Check that the scan completed successfully and that the report directory is writable

### Getting Help

For additional help, please:
- Check the main documentation
- Open an issue on the GitHub repository
- Contact the developers at support@example.com

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add some amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Acknowledgments

- Thanks to the CrewAI team for the excellent framework
- Bootstrap team for the responsive UI components
- Chart.js for the visualization libraries 