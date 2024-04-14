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

def SAST_get_project_latest_scan_id(access_token, project_name, SAST_api_url):
    try:
        projId = SAST_get_project_ID(access_token, project_name, SAST_api_url)
        if projId == 0:
            return 0
        
        url = f"{SAST_api_url}/sast/scans?projectId={projId}&last=1"

        headers = {
            'Authorization': f'Bearer {access_token}'
        }

        response = requests.get(url, headers=headers)
        response.raise_for_status()  # Raise exception for HTTP errors
        
        response_json = response.json()
        lastScanId = response_json[0]['id']
    except Exception as e:
        print(f"Exception: SAST_get_project_latest_scan_id: {e}")
        return ""
    else:
        print(f'SAST_get_project_latest_scan_id scan_id= {lastScanId}')
        return lastScanId




def SAST_get_scan_id_by_date(access_token, project_id, SAST_api_url, scan_date):
    try:
        
        scans_url = f"{SAST_api_url}/sast/scans?projectId={project_id}"
        headers = {
            'Authorization': f'Bearer {access_token}'
        }
        response = requests.get(scans_url, headers=headers)
        response.raise_for_status()  # Raise exception for HTTP errors

        project_scans = response.json()
        
        latest_scan_id = None
        latest_scan_time = None
        
        for scan in project_scans:
            date_and_time = scan.get('dateAndTime')
            if date_and_time is None:
                continue

            scan_date_time = date_and_time.get('startedOn')
            if scan_date_time:
                scan_date_obj = datetime.datetime.strptime(scan_date_time, '%Y-%m-%dT%H:%M:%S.%f')

                if scan_date_obj.date() == datetime.datetime.strptime(scan_date, '%Y-%m-%d').date():
                    finished_scan_status = scan.get('finishedScanStatus')
                    if finished_scan_status and finished_scan_status.get('id') != 0:  # Not to include cancelled scans
                        if latest_scan_time is None or scan_date_obj > latest_scan_time:
                            latest_scan_time = scan_date_obj
                            latest_scan_id = scan['id']
        print(f"Scan id : {latest_scan_id}")                    
        
        return latest_scan_id or ""
        
    except Exception as e:
        print(f"Exception: SAST_get_scan_id_by_date: {e}")
        return ""
  
    
