# PoC AITechGuard: AI-driven Open Source Cloud Technologies CyberSecurity Analyzer

## Abstract

**The Current State of Cybersecurity: Tools, Adversaries, SecOps, and AI with Free LLMs**: The cybersecurity landscape in 2025 is a dynamic battlefield, shaped by rapid technological advancements, evolving threats, and the increasing integration of artificial intelligence (AI) into both defensive and offensive strategies. As organizations continue to migrate to cloud environments, the complexity of securing these infrastructures has grown exponentially. Tools like AITechGuard, which leverage advanced language models (LLMs), are emerging as critical solutions to address these challenges. This introduction explores the current state of cybersecurity tools, the evolving tactics of adversaries, the transformation of Security Operations (SecOps), and the role of AI, particularly free LLMs, in enhancing cybersecurity defenses.

**Cybersecurity Tools: Bridging the Gap Between Complexity and Efficiency**: The proliferation of cloud technologies, such as Microsoft Azure, AWS, and Google Cloud, has introduced new vulnerabilities and attack surfaces. Traditional security tools often struggle to keep pace with the scale and complexity of modern cloud environments. AITechGuard represents a new generation of cybersecurity tools that utilize LLMs to analyze cloud workloads, generate security recommendations, and provide actionable insights. By automating tasks like vulnerability detection, cost-benefit analysis, and implementation planning, tools like AITechGuard enable organizations to streamline their security operations and prioritize critical threats.

**Adversaries: The Rise of AI-Powered Threats**: Cyber adversaries are increasingly leveraging AI to enhance their capabilities. From AI-generated phishing emails to deepfake impersonations, attackers are using large language models (LLMs) to craft highly convincing social engineering campaigns. Tools like WormGPT and FraudGPT, designed for malicious purposes, enable attackers to automate phishing, bypass security measures, and exploit vulnerabilities at scale37. This shift underscores the dual nature of AI in cybersecurity: while it empowers defenders, it also equips adversaries with sophisticated tools to evade detection and amplify their impact.

**SecOps: The Evolution Toward Semi-Autonomous Security**: Security Operations Centers (SOCs) are undergoing a transformation driven by AI and automation. The integration of AI-driven "co-pilots" into SOC workflows is enabling teams to manage vast amounts of data more effectively, prioritize threats, and respond to incidents with greater speed and precision9. Tools like AITechGuard exemplify this trend by using LLMs to generate Python code for verifying security recommendations and automating vulnerability fixes. This shift toward semi-autonomous security operations is critical for addressing the growing volume and sophistication of cyber threats.

**AI and Free LLMs: A Double-Edged Sword**: The adoption of free LLMs in cybersecurity tools like AITechGuard highlights the potential of AI to democratize access to advanced security capabilities. These models can analyze vast datasets, identify emerging threats, and provide tailored recommendations, making them invaluable for organizations with limited resources. However, the misuse of LLMs by adversaries poses significant risks. For instance, attackers can exploit misconfigured LLMs to access sensitive data or generate malicious content79. As such, the cybersecurity community must balance innovation with robust governance to mitigate these risks.

**AITechGuard: A Case Study in AI-Driven Cybersecurity**: AITechGuard exemplifies the convergence of AI and cybersecurity. By leveraging LLMs, the tool provides a comprehensive solution for analyzing cloud environments, generating security recommendations, and automating verification processes. Its ability to produce Python code for validating recommendations and conducting cost-benefit analyses demonstrates the practical applications of AI in enhancing cloud security. As organizations increasingly adopt cloud-native solutions, tools like AITechGuard will play a pivotal role in securing these environments against evolving threats.

# Objective and Scope

AITechGuard is a tool designed to analyze and generate security recommendations for cloud environments, specifically for technologies like **Microsoft Azure**, **AWS**, and **Google Cloud**. The tool uses an advanced language model (LLM) to provide python code to verify actual state, cost / benefit analisys and prioritized implementation plan of the selected framework-based 
recommendations.

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
3. **LiteLLM**: To interact with the Groq language model. LLM provider can be changed.
4. **Plotly**: To generate Gantt charts.
5. **Groq API Key**: Sign-up in Groq Cloud free service. Create a new API KEY. Set the `GROQ_API_KEY` environment variable with your API key.

Install the dependencies by running:

```bash
pip install streamlit plotly litellm
```

## Setup

1. Clone the repository:

```bash
git clone https://github.com/your-username/CloudGuard.git
cd CloudGuard
```

2. Set up the Groq API key:

```bash
export GROQ_API_KEY="your_api_key_here"
```

3. Run the application:

```bash
streamlit run app.py
```

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
- Python code to verify the state of the eecommendation will be generated by the AI.
- Python Dependencies will be showned.
- Needed permissions will be showned.
- Provide credentials (Subscription ID, Client ID, Client Secret, Tenant ID) and execute the generated code.
- Execute Python code outside the application.
- Paste results in the application.

### Step 7: Cost-Benefit Analysis
- Get a detailed analysis of the cost and benefit of implementing the recommendations.

### Step 8: Implementation Plan
- Generate an implementation plan with time and resource estimates.

## Project Structure

```
AITechGuard/
├── app.py                  # Main application code
├── README.md               # Project documentation
├── requirements.txt        # Project dependencies
├── .env.example            # Example environment configuration file
└── assets/                 # Folder for additional resources (optional)
```

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

This project is licensed under the GNU General Public License. See the [LICENSE](https://en.wikipedia.org/wiki/GNU_General_Public_License) file for details.

## Contact

If you have questions or suggestions, feel free to reach out:

- **Name**: [Rodrigo Jiménez del Val]
- **Email**: [rodrigo.jdelval@gmail.com]
- **GitHub**: [rodrigo-jdelval](https://github.com/rodrigo-jdelval)
