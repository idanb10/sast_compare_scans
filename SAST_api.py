import requests
import datetime

def SAST_get_access_token(SAST_username, SAST_password, SAST_auth_url):
    try:
        payload = {
            'scope': 'access_control_api sast_api',
            'client_id': 'resource_owner_sast_client',
            'grant_type': 'password',
            'client_secret': '014DF517-39D1-4453-B7B3-9930C563627C',
            'username': SAST_username,
            'password': SAST_password
        }
        headers = {
            'Content-Type': 'application/x-www-form-urlencoded'
        }

        response = requests.post(SAST_auth_url, headers=headers, data=payload)
        response.raise_for_status()  # Raise exception for HTTP errors
        #print(f'get_SAST_access_token - token = {response.text}')
        access_token = response.json()['access_token']
        return access_token
    except requests.exceptions.RequestException as e:
        print(f"Exception: get SAST access token failed: {e}")
        return ""

def SAST_get_projects(access_token, SAST_api_url):
    try:
        headers = {
            'Authorization': f'Bearer {access_token}'
        }

        url = f'{SAST_api_url}/projects'

        response = requests.get(url, headers=headers)
        response.raise_for_status()  # Raise exception for HTTP errors
        
        #print('SAST_get_projects')
        return response.json()
    except requests.exceptions.RequestException as e:
        print(f"Exception: SAST_get_projects: {e}")
        return ""
    
def SAST_get_project_ID(access_token, project_name, SAST_api_url):
    try:
        projects = SAST_get_projects(access_token, SAST_api_url)
        projId = next((project['id'] for project in projects if project['name'] == project_name), 0)
    except Exception as e:
        print(f"Exception: SAST_get_project_ID: {e}")
        return ""
    return projId

def SAST_get_scan_id_by_date(access_token, project_id, SAST_api_url, scan_date, search_direction='next'):
    try:
        scans_url = f"{SAST_api_url}/sast/scans?projectId={project_id}"
        headers = {
            'Authorization': f'Bearer {access_token}'
        }
        response = requests.get(scans_url, headers=headers)
        response.raise_for_status()

        project_scans = response.json()
        
        selected_scan_id = None
        selected_scan_date = None  # Store the actual date of the selected scan
        target_scan_date = datetime.datetime.strptime(scan_date, '%Y-%m-%d').date()
        closest_date = datetime.date.max if search_direction == 'next' else datetime.date.min
        
        for scan in project_scans:
            date_and_time = scan.get('dateAndTime', {})
            if date_and_time:
                scan_date_time_str = date_and_time.get('startedOn')
                if scan_date_time_str:
                    scan_date_obj = datetime.datetime.strptime(scan_date_time_str, '%Y-%m-%dT%H:%M:%S.%f').date()
                    if (search_direction == 'next' and scan_date_obj >= target_scan_date and scan_date_obj < closest_date) or \
                        (search_direction == 'last' and scan_date_obj <= target_scan_date and scan_date_obj > closest_date):
                        closest_date = scan_date_obj
                        selected_scan_id = scan['id']
                        selected_scan_date = scan_date_obj
                        

        if selected_scan_id and selected_scan_date:
            print(f"SAST_api.SAST_get_scan_id_by_date : Selected scan id = {selected_scan_id}, selected scan date = {selected_scan_date}")
            return selected_scan_id, selected_scan_date
        else:
            return None, None
        
    except Exception as e:
        print(f"Exception: SAST_get_scan_id_by_date: {e}")
        return None, None
    
def SAST_list_scan_vulnerabilities_with_scan_id(access_token, SAST_api_url, scan_id):        
    try:
      
        scan_results_url = f"{SAST_api_url}/sast/scans/{scan_id}/resultsStatistics"
        
        headers = {'Authorization': f'Bearer {access_token}'}
        
        response = requests.get(scan_results_url, headers=headers)
        response.raise_for_status()
        scan_results = response.json()
        
        simplified_scan_results = {
            'High': scan_results.get('highSeverity', 0),
            'Medium': scan_results.get('mediumSeverity', 0),
            'Low': scan_results.get('lowSeverity', 0)
        }
        return simplified_scan_results
        
    except Exception as e:
        print(f"Exception: {e}")
        return ""            

def compare_scan_vulnerabilities(old_scan_results, new_scan_results):
    
    fixed = {
        'High': max(0, old_scan_results['High'] - new_scan_results['High']),
        'Medium': max(0, old_scan_results['Medium'] - new_scan_results['Medium']),
        'Low': max(0, old_scan_results['Low'] - new_scan_results['Low'])
    }
    return fixed

