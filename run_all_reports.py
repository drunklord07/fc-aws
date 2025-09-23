import subprocess
import os

def run_all_scripts():
    current_directory = os.path.dirname(os.path.realpath(__file__))

    script1_path = os.path.join(current_directory, 'create_observations_report.py')
    script2_path = os.path.join(current_directory, 'add_dashboard_sheet.py')

    if not os.path.exists(script1_path):
        print(f"Error: Script '{script1_path}' not found.")
        return
    if not os.path.exists(script2_path):
        print(f"Error: Script '{script2_path}' not found.")
        return

    print("--- Starting Orchestration of Report Generation ---")

    # Run the first script
    print(f"\nRunning {script1_path}...")
    try:
        # Use subprocess.run for better control and error handling
        result1 = subprocess.run(['python', script1_path], capture_output=True, text=True, check=True)
        print(result1.stdout)
        if result1.stderr:
            print(f"Errors from {script1_path}:\n{result1.stderr}")
    except subprocess.CalledProcessError as e:
        print(f"Failed to run {script1_path}. Error: {e}")
        print(f"Stdout:\n{e.stdout}")
        print(f"Stderr:\n{e.stderr}")
        return # Stop if the first script fails
    except Exception as e:
        print(f"An unexpected error occurred while running {script1_path}: {e}")
        return

    # Run the second script only if the first one succeeded
    print(f"\nRunning {script2_path}...")
    try:
        result2 = subprocess.run(['python', script2_path], capture_output=True, text=True, check=True)
        print(result2.stdout)
        if result2.stderr:
            print(f"Errors from {script2_path}:\n{result2.stderr}")
    except subprocess.CalledProcessError as e:
        print(f"Failed to run {script2_path}. Error: {e}")
        print(f"Stdout:\n{e.stdout}")
        print(f"Stderr:\n{e.stderr}")
        return
    except Exception as e:
        print(f"An unexpected error occurred while running {script2_path}: {e}")
        return

    print("\n--- All scripts executed successfully. ---")

if __name__ == "__main__":
    run_all_scripts()