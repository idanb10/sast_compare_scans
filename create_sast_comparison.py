import dateutil.parser
import SAST_api
import sys
import yaml
import csv
import os
import datetime
import dateutil

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
        
        old_scan_id, old_scan_real_date = SAST_api.SAST_get_scan_id_by_date(access_token, project_id, SAST_api_url, old_scan_date, search_direction='next')
        new_scan_id, new_scan_real_date = SAST_api.SAST_get_scan_id_by_date(access_token, project_id, SAST_api_url, new_scan_date, search_direction='last')
        
        if old_scan_id == new_scan_id:
            raise Exception("The same scan cannot be used for both comparison points. Please select a different date.")
        
        if old_scan_id is None or new_scan_id is None:
            raise Exception(f"Failed to find scans for both dates for project {project_name}. Make sure you have at least two scans to compare.")
            
        old_scan_results = SAST_api.SAST_list_scan_vulnerabilities_with_scan_id(access_token, SAST_api_url, old_scan_id)
        new_scan_results = SAST_api.SAST_list_scan_vulnerabilities_with_scan_id(access_token, SAST_api_url, new_scan_id)
        
        
        print(f"create_sast_comparison.SAST_compare_two_scans_by_date : Old scan on {old_scan_real_date} results - {old_scan_results}")
        print(f"create_sast_comparison.SAST_compare_two_scans_by_date : New scan on {new_scan_real_date} results - {new_scan_results}")
        
        fixed_vulnerabilities = SAST_api.compare_scan_vulnerabilities(old_scan_results, new_scan_results)
        print(f"create_sast_comparison.SAST_compare_two_scans_by_date : Fixed vulnerabilities {fixed_vulnerabilities}")
        
        write_scan_results_to_csv(project_name, old_scan_date, \
            new_scan_date, old_scan_results, new_scan_results, fixed_vulnerabilities)
        print(f"CSV file written successfully for project {project_name}")

    except Exception as e:
        print(f"Exception: {e}")
        return ""
    
def compare_scans_across_all_projects(SAST_username, SAST_password, SAST_auth_url, SAST_api_url, old_scan_date, new_scan_date):
    access_token = SAST_api.SAST_get_access_token(SAST_username, SAST_password, SAST_auth_url)
    if not access_token:
        raise Exception("Failed to obtain access token")


    projects = SAST_api.SAST_get_projects(access_token, SAST_api_url)
    for project in projects:
        project_name = project['name']
        print(f"Comparing scans for project: {project_name}")
        SAST_compare_two_scans_by_date(SAST_username, SAST_password, SAST_auth_url, SAST_api_url, project_name, old_scan_date, new_scan_date)        

def write_scan_results_to_csv(project_name, old_scan_date, new_scan_date, old_scan_results, new_scan_results, fixed_vulnerabilities):

    csv_file = f'SAST_Results_Comparison_For_{old_scan_date}_to_{new_scan_date}.csv'
    
    file_exists = os.path.isfile(csv_file)
    with open(csv_file, mode='a', newline='') as file:
        writer = csv.writer(file)
        if not file_exists:
            writer.writerow(['', 'fixed', '', '', old_scan_date, '', '', new_scan_date, '', ''])
            writer.writerow(['project', 'high', 'medium', 'low', 'high', 'medium', 'low', 'high', 'medium', 'low'])
        
        writer.writerow([project_name, fixed_vulnerabilities['High'], fixed_vulnerabilities['Medium'], fixed_vulnerabilities['Low'],
                         old_scan_results['High'], old_scan_results['Medium'], old_scan_results['Low'],
                         new_scan_results['High'], new_scan_results['Medium'], new_scan_results['Low']])

def validate_and_parse_date(date_str):
    try:
        return dateutil.parser.parse(date_str, dayfirst=True).date()
    except ValueError:
        print(f"Invalid date format: {date_str}. Please use a valid date format like 'DD-MM-YYYY'.")
        return None

##################################################
# main code
######<###########################################

def main():
    if len(sys.argv) not in [3, 4]:
        print(f'Usage: {sys.argv[0]} [optional : <project_name>] <old_scan_date: DD/MM/YYYY> <new_scan_date: DD/MM/YYYY')
        exit()
        
    old_scan_date_str = sys.argv[-2]
    new_scan_date_str = sys.argv[-1]

    old_scan_date = validate_and_parse_date(old_scan_date_str)
    new_scan_date = validate_and_parse_date(new_scan_date_str)

    if old_scan_date is None or new_scan_date is None:
        print("One or more dates are invalid.")
        exit()
        
    if old_scan_date > new_scan_date :
        print("The first date should be the old date, the second date should be the new date.")
        exit()
        
    old_scan_date_str = old_scan_date.strftime('%Y-%m-%d')
    new_scan_date_str = new_scan_date.strftime('%Y-%m-%d')

    if len(sys.argv) == 3:
        compare_scans_across_all_projects(SAST_username, SAST_password, SAST_auth_url, SAST_api_url, old_scan_date_str, new_scan_date_str)
    else:
        project_name = sys.argv[1]
        SAST_compare_two_scans_by_date(SAST_username, SAST_password, SAST_auth_url, SAST_api_url, project_name, old_scan_date_str, new_scan_date_str)
    
if __name__ == '__main__':
    main()
    
