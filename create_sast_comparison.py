import SAST_api
import requests
import sys
import yaml
import csv

# Open the YAML file
with open('config_rep.yaml', 'r') as file:
    # Load the YAML contents
    config = yaml.safe_load(file)

SAST_username = config['SAST_username']
SAST_password = config['SAST_password']
SAST_auth_url = config['SAST_auth_url']
SAST_api_url = config['SAST_api_url']


def SAST_compare_two_scans_by_date(SAST_username, SAST_password, SAST_auth_url, SAST_api_url, project_name, old_scan_date, new_scan_date):
    try:
        access_token = SAST_api.SAST_get_access_token(SAST_username, SAST_password, SAST_auth_url)
        if not access_token:
            raise Exception("Failed to obtain access token")
        
        project_id = SAST_api.SAST_get_project_ID(access_token, project_name, SAST_api_url)
        if project_id == 0:
            return ""
        
        old_scan_id = SAST_api.SAST_get_scan_id_by_date(access_token, project_id, SAST_api_url, old_scan_date)
        new_scan_id = SAST_api.SAST_get_scan_id_by_date(access_token, project_id, SAST_api_url, new_scan_date)
        
        scans_url = f"{SAST_api_url}/sast/scans/{old_scan_id}/compareSummaryTo/{new_scan_id}"
        headers = {'Authorization': f'Bearer {access_token}'}
        response = requests.get(scans_url, headers=headers)
        response.raise_for_status()
        scans_comparison = response.json()
        
        print(scans_comparison)
        
        csv_file_name = f'{project_name}_Scans_Comparison_{old_scan_date}_to_{new_scan_date}.csv'
        fieldnames = ['Severity', 'Fixed', 'New', 'Reoccured']
        
        with open(csv_file_name, mode='w', newline='') as file:
            writer = csv.DictWriter(file, fieldnames=fieldnames)
            writer.writeheader()
            
            for severity, counts in scans_comparison.items():
                if severity != 'info':
                    row = {'Severity': severity, 'Fixed': counts['fixed'], 'New': counts['new'], 'Reoccured': counts['reOccured']}
                    writer.writerow(row)
        print(f"CSV file for {project_name} : {old_scan_date} - {new_scan_date} has been written succesfully")


    except Exception as e:
        print(f"Exception: {e}")
        return ""
    
    
##################################################
# main code
######<###########################################

def main():
    
    if(len(sys.argv) < 4):
        print(f'usage: {sys.argv[0]} <project_name> <old_scan_date: YYYY-MM-DD> <new_scan_date: YYYY-MM-DD>')
        exit()

    project_name = sys.argv[1]
    old_scan_date = sys.argv[2]
    new_scan_date = sys.argv[3]

    SAST_compare_two_scans_by_date(SAST_username, SAST_password, SAST_auth_url, SAST_api_url, project_name, old_scan_date, new_scan_date)
    
if __name__ == '__main__':
    main()
    
    