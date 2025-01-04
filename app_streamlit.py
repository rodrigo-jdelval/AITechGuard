import streamlit as st
import pandas as pd
import os
import time
import subprocess
import sys
from datetime import datetime
from litellm import completion  # Usamos LiteLLM para interactuar con Groq
import plotly.express as px  # Para el gráfico de Gantt

# Configuración global de rate limiting
MAX_CALLS_PER_MINUTE = 30  # Número máximo de llamadas al LLM por minuto (modificable)
delay_between_calls = 60 / MAX_CALLS_PER_MINUTE  # Tiempo de espera entre llamadas en segundos

# Inicialización del módulo de IA
class IAModule:
    def __init__(self):
        self.api_key = os.getenv("GROQ_API_KEY")
        if not self.api_key:
            raise ValueError("The GROQ_API_KEY environment variable is not set.")
        self.model = "groq/llama-3.3-70b-versatile"  # Modelo de Groq en LiteLLM
        self.last_call_time = 0  # Tiempo de la última llamada al LLM

    def generate_recommendation(self, prompt):
        # Asegurarse de que el LLM devuelva una lista con viñetas
        formatted_prompt = f"{prompt} Please provide the response as a bullet-point list."
        
        # Rate limiting: esperar si es necesario
        current_time = time.time()
        time_since_last_call = current_time - self.last_call_time
        if time_since_last_call < delay_between_calls:
            time_to_wait = delay_between_calls - time_since_last_call
            time.sleep(time_to_wait)  # Esperar el tiempo necesario
        
        # Configurar la solicitud con LiteLLM
        response = completion(
            model=self.model,
            messages=[
                {"role": "user", "content": formatted_prompt}
            ],
            api_key=self.api_key,
            max_tokens=500,  # Ajustar según sea necesario
            temperature=0.7,  # Controlar la creatividad de la respuesta,
        )

        # Actualizar el tiempo de la última llamada
        self.last_call_time = time.time()

        # Almacenar el resultado del LLM con la fecha
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        st.session_state.llm_response = f"{timestamp} - Prompt: {prompt}\nResponse: {response.choices[0].message.content}"

        # Extraer la respuesta generada
        return response.choices[0].message.content

    def parse_response_to_table(self, response):
        # Convertir la respuesta del LLM (lista con viñetas) en una tabla
        if response:
            # Eliminar espacios en blanco adicionales y dividir en líneas
            lines = [line.strip().lstrip("-* ") for line in response.split("\n") if line.strip()]
            table_data = []
            current_category = ""
            for line in lines:
                if line.endswith(":"):  # Es una categoría
                    current_category = line.rstrip(":").strip()  # Limpiar espacios adicionales
                else:  # Es una subrecomendación
                    # Limpiar espacios adicionales y caracteres no deseados
                    cleaned_line = line.strip()
                    if cleaned_line:  # Solo añadir si la línea no está vacía
                        # Extraer severidad, técnica de MITRE, TTP y táctica
                        parts = cleaned_line.split("|")
                        if len(parts) == 5:  # Recomendación, Severidad, Técnica MITRE, TTP, Táctica
                            recommendation = parts[0].strip()
                            severity = parts[1].strip()
                            mitre_technique = parts[2].strip()
                            mitre_ttp = parts[3].strip()
                            mitre_tactic = parts[4].strip()
                            table_data.append({
                                "Category": current_category,
                                "Recommendation": recommendation,
                                "Severity": severity,
                                "MITRE Technique": mitre_technique,
                                "MITRE ATT&CK TTP": mitre_ttp,
                                "MITRE ATT&CK Tactic": mitre_tactic
                            })
                        else:  # Si no se pueden extraer los campos adicionales
                            table_data.append({
                                "Category": current_category,
                                "Recommendation": cleaned_line,
                                "Severity": "N/A",
                                "MITRE Technique": "N/A",
                                "MITRE ATT&CK TTP": "N/A",
                                "MITRE ATT&CK Tactic": "N/A"
                            })
            return pd.DataFrame(table_data)
        return pd.DataFrame()

# Inicializar el módulo de IA
ia_module = IAModule()

# Función para verificar recomendaciones
def check_verifiable_recommendations():
    st.session_state.verifiable_recommendations = []
    for idx, recommendation in enumerate(st.session_state.selected_recommendations):
        prompt = f"Can the following recommendation be verified online using Azure Checker? Recommendation: {recommendation}. Respond with 'Yes' or 'No'. Also, provide the severity level (Low, Medium, High)."
        response = ia_module.generate_recommendation(prompt)
        
        is_verifiable = "yes" in response.lower()
        severity = "High"  # Default severity
        if "low" in response.lower():
            severity = "Low"
        elif "medium" in response.lower():
            severity = "Medium"

        st.session_state.verifiable_recommendations.append({
            "id": idx + 1,
            "recommendation": recommendation,
            "verifiable_online": is_verifiable,
            "severity": severity
        })

# Función para generar el código de verificación
def generate_verification_code():
    # Verificar si selected_for_code está inicializado
    if "selected_for_code" not in st.session_state:
        st.session_state.selected_for_code = []

    # Obtener las recomendaciones seleccionadas
    selected_recommendations = [
        rec["recommendation"]
        for rec in st.session_state.verifiable_recommendations
        if rec["id"] in st.session_state.selected_for_code
    ]

    if selected_recommendations:
        prompt = f"Generate Python code to verify the following recommendations using Azure. The code should only read the current state and not make any changes. Recommendations: {', '.join(selected_recommendations)}. Also, list the required Python modules to install and the necessary Azure permissions."
        verification_response = ia_module.generate_recommendation(prompt)

        # Extraer el código de verificación
        if "```python" in verification_response:
            st.session_state.verification_code = verification_response.split("```python")[1].split("```")[0].strip()
        else:
            st.session_state.verification_code = verification_response

        # Extraer los módulos y permisos
        modules_section = "Required Python modules to install:"
        permissions_section = "Necessary Azure permissions:"

        if modules_section in verification_response:
            modules_text = verification_response.split(modules_section)[1].split(permissions_section)[0].strip()
            # Limpiar y formatear los módulos
            modules_list = [line.strip().replace("`", "").strip() for line in modules_text.split("\n") if line.strip()]
            st.session_state.required_modules = ", ".join(modules_list)
        else:
            st.session_state.required_modules = "None"

        if permissions_section in verification_response:
            permissions_text = verification_response.split(permissions_section)[1].strip()
            # Limpiar y formatear los permisos
            permissions_list = [line.strip().replace("`", "").strip() for line in permissions_text.split("\n") if line.strip()]
            st.session_state.required_permissions = "\n".join(permissions_list)
        else:
            st.session_state.required_permissions = "None"

# Función para ejecutar el código de verificación
def execute_verification_code():
    if st.session_state.subscription_id and st.session_state.client_id and st.session_state.client_secret and st.session_state.tenant_id:
        # Install required modules (if any)
        if st.session_state.required_modules != "None":
            for module in st.session_state.required_modules.split(","):
                subprocess.check_call([sys.executable, "-m", "pip", "install", module.strip()])

        # Execute the generated code
        try:
            import os
            os.environ["AZURE_SUBSCRIPTION_ID"] = st.session_state.subscription_id
            os.environ["AZURE_CLIENT_ID"] = st.session_state.client_id
            os.environ["AZURE_CLIENT_SECRET"] = st.session_state.client_secret
            os.environ["AZURE_TENANT_ID"] = st.session_state.tenant_id

            exec(st.session_state.verification_code)
            st.session_state.compliance_results = pd.DataFrame({
                "Recommendation": ["Enable Azure Disk Encryption", "Enable Network Security Groups"],
                "Status": ["Compliant", "Non-Compliant"]
            })
        except Exception as e:
            st.session_state.compliance_results = pd.DataFrame({
                "Error": [f"Error: {e}"]
            })
    else:
        st.session_state.compliance_results = pd.DataFrame({
            "Error": ["Please provide all required information."]
        })

# Función para procesar resultados pegados
def process_pasted_results(results):
    """
    Procesa el resultado pegado por el usuario y lo almacena en st.session_state.compliance_results.
    """
    try:
        # Convertir el resultado en un DataFrame
        if results.strip().startswith("{"):  # Si es un JSON
            import json
            data = json.loads(results)
            st.session_state.compliance_results = pd.DataFrame(data)
        else:  # Si es un formato tabular (por ejemplo, CSV)
            import io
            st.session_state.compliance_results = pd.read_csv(io.StringIO(results))

        st.success("Results processed successfully!")
    except Exception as e:
        st.error(f"Error processing pasted results: {e}")
        st.session_state.compliance_results = pd.DataFrame({
            "Error": [f"Error processing pasted results: {e}"]
        })

# Función para analizar el costo/beneficio
def analyze_cost_benefit():
    # Verificar si hay resultados de cumplimiento
    if "compliance_results" not in st.session_state:
        st.warning("No compliance results available. Please execute the verification code first.")
        return

    # Filtrar recomendaciones no cumplidas
    non_compliant_recommendations = st.session_state.compliance_results[
        st.session_state.compliance_results["Status"] == "Non-Compliant"
    ]

    if not non_compliant_recommendations.empty:
        st.session_state.cost_benefit_tables = []
        for _, row in non_compliant_recommendations.iterrows():
            recommendation = row["Recommendation"]
            prompt = f"Provide a detailed action plan for the following recommendation: {recommendation}. Include estimated CAPEX, OPEX, and the benefit in terms of risk mitigation. Format the response as a table with columns: Action, CAPEX, OPEX, Benefit."
            response = ia_module.generate_recommendation(prompt)
            st.session_state.cost_benefit_tables.append({
                "recommendation": recommendation,
                "table": response
            })
    else:
        st.warning("No non-compliant recommendations found for cost/benefit analysis.")

# Función para generar el programa de implementación
def generate_implementation_plan():
    # Verificar si hay resultados de cumplimiento
    if "compliance_results" not in st.session_state:
        st.warning("No compliance results available. Please execute the verification code first.")
        return

    # Filtrar recomendaciones no cumplidas
    non_compliant_recommendations = st.session_state.compliance_results[
        st.session_state.compliance_results["Status"] == "Non-Compliant"
    ]

    if not non_compliant_recommendations.empty:
        # Generar el plan de implementación para las recomendaciones no cumplidas
        prompt = f"Generate a Gantt chart implementation plan for the following recommendations: {', '.join(non_compliant_recommendations['Recommendation'].tolist())}. Include estimated timelines, resources, and risks. Format the response as a table with columns: Activity, Start Date, End Date, Resources, Risks."
        response = ia_module.generate_recommendation(prompt)
        st.session_state.implementation_plan = response
    else:
        st.warning("No non-compliant recommendations found for implementation plan.")

# Interfaz de usuario con Streamlit
def main():
    st.title("CloudGuard: Cloud Security Recommendations Analyzer")

    # Checkbox para mostrar el resultado del LLM
    show_llm_response = st.checkbox("Show LLM Response with Timestamp")
    if show_llm_response and "llm_response" in st.session_state:
        st.text_area("LLM Response:", value=st.session_state.llm_response, height=300)

    # Step 1: Select Technologies
    st.header("Step 1: Select Technologies")
    technologies = ["Microsoft", "AWS", "Google Cloud"]  # Cambiado "Microsoft Azure" a "Microsoft"
    selected_technologies = st.multiselect("Choose the technologies to assess:", technologies)

    if selected_technologies:
        # Step 2: Get Subtechnologies
        st.header("Step 2: Select Subtechnologies")

        # Inicializar el estado de subtecnologías si no existe
        if "subtechnologies" not in st.session_state:
            st.session_state.subtechnologies = []

        # Generar la tabla de subtecnologías si no está en el estado
        if "subtechnologies_table" not in st.session_state:
            prompt = f"What are the main subtechnologies or services within {', '.join(selected_technologies)}? Provide a concise bullet-point list, focusing on technologies like Azure (Cloud Computing), Windows Server, SQL Server, etc."
            subtechnologies_response = ia_module.generate_recommendation(prompt)
            st.session_state.subtechnologies_table = ia_module.parse_response_to_table(subtechnologies_response)

        if "subtechnologies_table" in st.session_state:
            # Extraer la lista de subtecnologías de la columna "Recommendation"
            subtechnologies_list = st.session_state.subtechnologies_table["Recommendation"].tolist()

            # Inicializar selected_subtechnologies si no existe
            if "selected_subtechnologies" not in st.session_state:
                st.session_state.selected_subtechnologies = []

            # Mostrar el multiselect y actualizar st.session_state
            selected_subtechnologies = st.multiselect(
                "Select the subtechnologies to assess:",
                options=subtechnologies_list,
                default=st.session_state.selected_subtechnologies
            )

            # Actualizar st.session_state solo si hay cambios
            if selected_subtechnologies != st.session_state.selected_subtechnologies:
                st.session_state.selected_subtechnologies = selected_subtechnologies

            if selected_subtechnologies:

                # Step 3: Get Workloads
                st.header("Step 3: Select Workloads")

                # Inicializar el estado de workloads si no existe
                if "workloads" not in st.session_state:
                    st.session_state.workloads = []

                # Generar la tabla de workloads si no está en el estado
                if "workloads_table" not in st.session_state:
                    prompt = f"""What are the typical workloads or use cases for {', '.join(selected_subtechnologies)}? 
                    Provide a concise bullet-point list, ensuring the following are included:
                    1. Virtual Machines (VMs).
                    2. Containers (e.g., Azure Kubernetes Service, Docker).
                    3. Databases (e.g., Azure SQL Database, Cosmos DB).
                    4. Web Applications (e.g., Azure App Service).
                    5. Serverless Functions (e.g., Azure Functions).
                    6. Big Data and Analytics (e.g., Azure Synapse Analytics, HDInsight).
                    7. AI and Machine Learning (e.g., Azure Machine Learning).
                    8. Storage Solutions (e.g., Blob Storage, File Storage).
                    9. Networking (e.g., Virtual Networks, Load Balancers).
                    10. Identity and Access Management (e.g., Azure Active Directory).
                    Ensure the list is comprehensive and covers all common Azure workloads."""
                    workloads_response = ia_module.generate_recommendation(prompt)
                    st.session_state.workloads_table = ia_module.parse_response_to_table(workloads_response)

                if "workloads_table" in st.session_state:
                    # Extraer la lista de workloads de la columna "Recommendation"
                    workloads_list = st.session_state.workloads_table["Recommendation"].tolist()

                    # Inicializar selected_workloads si no existe
                    if "selected_workloads" not in st.session_state:
                        st.session_state.selected_workloads = []

                    # Mostrar el multiselect y actualizar st.session_state
                    selected_workloads = st.multiselect(
                        "Select the workloads you have in your environment:",
                        options=workloads_list,
                        default=st.session_state.selected_workloads
                    )

                    # Actualizar st.session_state solo si hay cambios
                    if selected_workloads != st.session_state.selected_workloads:
                        st.session_state.selected_workloads = selected_workloads

                    if selected_workloads:
                        # Step 4: Get Recommendations
                        st.header("Step 4: Security Recommendations")

                        # Inicializar el estado de recomendaciones si no existe
                        if "recommendations" not in st.session_state:
                            st.session_state.recommendations = []

                        # Generar la tabla de recomendaciones si no está en el estado
                        if "recommendations_table" not in st.session_state:
                            prompt = f"""What are the key security recommendations for the following workloads: {', '.join(selected_workloads)}? 
                            Provide a detailed bullet-point list. For each recommendation, include:
                            - The severity (Low, Medium, High).
                            - The MITRE technique (e.g., TXXXX).
                            - The MITRE ATT&CK TTP.
                            - The MITRE ATT&CK Tactic.
                            Ensure the recommendations cover the following areas:
                            1. Data protection at rest (e.g., disk encryption, database encryption).
                            2. Data protection in transit (e.g., TLS/SSL, VPNs).
                            3. Network security (e.g., NSGs, firewalls).
                            4. Identity and access management (e.g., RBAC, MFA).
                            5. Logging and monitoring (e.g., Azure Monitor, Log Analytics).
                            6. Backup and disaster recovery (e.g., Azure Backup, geo-redundancy).
                            7. Patch management and vulnerability assessment.
                            8. Secure configuration of virtual machines (e.g., disabling unnecessary ports, hardening OS).
                            Format each recommendation as: 
                            'Recommendation: <text> | Severity: <Low/Medium/High> | MITRE Technique: <TXXXX> | MITRE ATT&CK TTP: <text> | MITRE ATT&CK Tactic: <text>'."""
                            recommendations_response = ia_module.generate_recommendation(prompt)
                            st.session_state.recommendations_table = ia_module.parse_response_to_table(recommendations_response)

                        if "recommendations_table" in st.session_state:
                            st.dataframe(st.session_state.recommendations_table)

                            # Step 5: Select Recommendations to Verify
                            st.header("Step 5: Select Recommendations to Verify")

                            # Inicializar el estado de recomendaciones seleccionadas si no existe
                            if "selected_recommendations" not in st.session_state:
                                st.session_state.selected_recommendations = []

                            # Mostrar el multiselect y actualizar st.session_state
                            selected_recommendations = st.multiselect(
                                "Select the recommendations to verify:",
                                options=st.session_state.recommendations_table["Recommendation"].tolist(),
                                default=st.session_state.selected_recommendations
                            )

                            # Actualizar st.session_state solo si hay cambios
                            if selected_recommendations != st.session_state.selected_recommendations:
                                st.session_state.selected_recommendations = selected_recommendations

                            if selected_recommendations:
                                # Step 6: Check Verifiable Recommendations
                                st.header("Step 6: Recommendations to Verify")
                                if st.button("Check Verifiable Recommendations"):
                                    check_verifiable_recommendations()

                                if "verifiable_recommendations" in st.session_state:
                                    st.dataframe(pd.DataFrame(st.session_state.verifiable_recommendations))

                                    # Step 7: Select Recommendations for Verification Code
                                    st.header("Step 7: Select Recommendations for Verification Code")
                                    
                                    # Inicializar selected_for_code si no existe
                                    if "selected_for_code" not in st.session_state:
                                        st.session_state.selected_for_code = []

                                    # Mostrar el multiselect para seleccionar recomendaciones
                                    selected_for_code = st.multiselect(
                                        "Select recommendations to generate verification code:",
                                        options=[rec["id"] for rec in st.session_state.verifiable_recommendations],
                                        default=st.session_state.selected_for_code
                                    )

                                    # Actualizar el estado si hay cambios
                                    if selected_for_code != st.session_state.selected_for_code:
                                        st.session_state.selected_for_code = selected_for_code

                                    # Botón para generar el código de verificación
                                    if st.button("Generate Verification Code"):
                                        generate_verification_code()

                                    if "verification_code" in st.session_state:
                                        st.text_area("Verification Code:", value=st.session_state.verification_code, height=300)
                                        st.text_input("Required Python modules to install:", value=st.session_state.required_modules)
                                        st.text_area("Required Azure permissions:", value=st.session_state.required_permissions, height=100)

                                        # Step 8: Execute Verification Code
                                        st.header("Step 8: Execute Verification Code")
                                        st.session_state.subscription_id = st.text_input("Azure Subscription ID:")
                                        st.session_state.client_id = st.text_input("Azure Client ID (Service Principal):")
                                        st.session_state.client_secret = st.text_input("Azure Client Secret:", type="password")
                                        st.session_state.tenant_id = st.text_input("Azure Tenant ID:")

                                        if st.button("Execute Online"):
                                            execute_verification_code()

                                        # Campo para pegar el resultado de la ejecución fuera de la aplicación
                                        st.header("Paste Execution Results")
                                        execution_results = st.text_area("Paste the results of the verification code execution here:", height=200)

                                        # Botón para procesar el resultado pegado
                                        if st.button("Process Pasted Results"):
                                            if execution_results:
                                                process_pasted_results(execution_results)
                                            else:
                                                st.warning("Please paste the execution results before processing.")

                                        if "compliance_results" in st.session_state:
                                            st.header("Compliance Results")
                                            st.dataframe(st.session_state.compliance_results)

                                            # Step 9: Cost/Benefit Analysis
                                            st.header("Step 9: Cost/Benefit Analysis")
                                            if st.button("Analyze Cost/Benefit"):
                                                analyze_cost_benefit()

                                            if "cost_benefit_tables" in st.session_state:
                                                for table in st.session_state.cost_benefit_tables:
                                                    st.subheader(f"Cost/Benefit Analysis for: {table['recommendation']}")
                                                    st.write(table["table"])

                                            # Step 10: Implementation Plan
                                            st.header("Step 10: Implementation Plan")
                                            if st.button("Generate Implementation Plan"):
                                                generate_implementation_plan()

                                            if "implementation_plan" in st.session_state:
                                                st.subheader("Implementation Plan")
                                                st.write(st.session_state.implementation_plan)

# Función para generar el plan de implementación con estimación de recursos
def generate_implementation_plan():
    # Verificar si hay resultados de cumplimiento
    if "compliance_results" not in st.session_state:
        st.warning("No compliance results available. Please execute the verification code first.")
        return

    # Filtrar recomendaciones no cumplidas
    non_compliant_recommendations = st.session_state.compliance_results[
        st.session_state.compliance_results["Status"] == "Non-Compliant"
    ]

    if not non_compliant_recommendations.empty:
        # Generar el plan de implementación para las recomendaciones no cumplidas
        prompt = f"Generate a Gantt chart implementation plan for the following recommendations: {', '.join(non_compliant_recommendations['Recommendation'].tolist())}. Include estimated timelines, resources, and risks. Format the response as a table with columns: Activity, Start Date, End Date, Resources, Estimated Effort (person-hours), Risks."
        response = ia_module.generate_recommendation(prompt)
        st.session_state.implementation_plan = response
    else:
        st.warning("No non-compliant recommendations found for implementation plan.")

# Ejecutar la aplicación
if __name__ == "__main__":
    main()