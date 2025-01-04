# CloudGuard: Cloud Security Recommendations Analyzer

CloudGuard is a tool designed to analyze and generate security recommendations for cloud environments, specifically for technologies like **Microsoft Azure**, **AWS**, and **Google Cloud**. The tool uses an advanced language model (LLM) to provide detailed, prioritized, and framework-based security recommendations, such as MITRE ATT&CK.

## Key Features

- **Technology and Subtechnology Selection**: Allows you to select primary technologies (Microsoft, AWS, Google Cloud) and their associated subtechnologies (e.g., Azure (Cloud Computing), Windows Server, etc.).
- **Workload Identification**: Detects common cloud workloads, such as Virtual Machines (VMs), containers, databases, web applications, etc.
- **Security Recommendations**: Generates detailed security recommendations for each workload, including:
  - Severity (Low, Medium, High).
  - MITRE ATT&CK Techniques.
  - MITRE ATT&CK Tactics.
  - TTPs (Tactics, Techniques, and Procedures).
- **Recommendation Verification**: Allows you to verify if recommendations can be automatically validated using tools like Azure Checker.
- **Verification Code Generation**: Generates Python code to validate the state of recommendations in Azure environments.
- **Cost-Benefit Analysis**: Provides a detailed analysis of the cost and benefit of implementing recommendations.
- **Implementation Plan**: Generates an implementation plan in Gantt chart format, including time and resource estimates.

## Prerequisites

To run CloudGuard, you will need:

1. **Python 3.8 or higher**.
2. **Streamlit**: Framework for the user interface.
3. **LiteLLM**: To interact with the Groq language model.
4. **Plotly**: To generate Gantt charts.
5. **Groq API Key**: Set the `GROQ_API_KEY` environment variable with your API key.

Install the dependencies by running:

\`\`\`bash
pip install streamlit plotly litellm
\`\`\`

## Setup

1. Clone the repository:

\`\`\`bash
git clone https://github.com/your-username/CloudGuard.git
cd CloudGuard
\`\`\`

2. Set up the Groq API key:

\`\`\`bash
export GROQ_API_KEY="your_api_key_here"
\`\`\`

3. Run the application:

\`\`\`bash
streamlit run app.py
\`\`\`

## How to Use the Tool

### Step 1: Technology Selection
- Select the technologies you want to evaluate (Microsoft, AWS, Google Cloud).

### Step 2: Subtechnology Selection
- Choose the subtechnologies associated with the selected technologies (e.g., Azure (Cloud Computing), Windows Server, etc.).

### Step 3: Workload Selection
- Select the workloads you have in your environment (e.g., Virtual Machines, Azure Kubernetes Service, Azure SQL Database, etc.).

### Step 4: Generate Recommendations
- The tool will generate detailed security recommendations for the selected workloads.

### Step 5: Verify Recommendations
- Select the recommendations you want to verify and generate Python code to validate their state in Azure.

### Step 6: Execute Verification Code
- Provide Azure credentials (Subscription ID, Client ID, Client Secret, Tenant ID) and execute the generated code.

### Step 7: Cost-Benefit Analysis
- Get a detailed analysis of the cost and benefit of implementing the recommendations.

### Step 8: Implementation Plan
- Generate an implementation plan with time and resource estimates.

## Project Structure

\`\`\`
CloudGuard/
├── app.py                  # Main application code
├── README.md               # Project documentation
├── requirements.txt        # Project dependencies
├── .env.example            # Example environment configuration file
└── assets/                 # Folder for additional resources (optional)
\`\`\`

## Example Output

### Security Recommendations
| Category                  | Recommendation                                      | Severity | MITRE Technique | MITRE ATT&CK TTP          | MITRE ATT&CK Tactic |
|---------------------------|----------------------------------------------------|----------|-----------------|---------------------------|---------------------|
| Data Protection at Rest   | Enable Azure Disk Encryption for all VMs           | High     | T1486           | Encrypt Data on Local System | Impact             |
| Network Security          | Use NSGs to restrict inbound/outbound traffic      | Medium   | T1190           | Network Denial of Service  | Initial Access     |
| Identity and Access       | Implement MFA for all administrative accounts      | High     | T1078           | Multi-Factor Authentication | Defense Evasion    |

### Implementation Plan
| Activity                  | Start Date   | End Date     | Resources       | Risks                        |
|---------------------------|--------------|--------------|-----------------|------------------------------|
| Enable Disk Encryption    | 2023-10-01   | 2023-10-03   | 2 engineers     | Possible performance impact  |
| Configure NSGs            | 2023-10-04   | 2023-10-05   | 1 engineer      | Accidental traffic blocking  |

## Contributions

Contributions are welcome! If you want to improve CloudGuard, follow these steps:

1. Fork the repository.
2. Create a branch for your feature (\`git checkout -b feature/new-feature\`).
3. Make your changes and commit them (\`git commit -m 'Add new feature'\`).
4. Push to the branch (\`git push origin feature/new-feature\`).
5. Open a Pull Request.

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.

## Contact

If you have questions or suggestions, feel free to reach out:

- **Name**: [Your Name]
- **Email**: [your-email@domain.com]
- **GitHub**: [your-username](https://github.com/your-username)