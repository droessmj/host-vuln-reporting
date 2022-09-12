import os
import pandas as pd
import logging
import argparse

from datetime import datetime, timedelta, timezone
from laceworksdk import LaceworkClient

logger = logging.getLogger('host-vuln')
logger.setLevel(os.getenv('LOG_LEVEL', logging.INFO))

def get_start_end_times(day_delta=1):
    current_time = datetime.now(timezone.utc)
    start_time = current_time - timedelta(days=day_delta)
    start_time = start_time.strftime("%Y-%m-%dT%H:%M:%S%z")
    end_time = current_time.strftime("%Y-%m-%dT%H:%M:%S%z")

    return start_time, end_time


def get_relevant_mids(lw_client, start_time, end_time, filter):

    if filter != "":
        # Fetch vulnerability pages
        machine_ids = lw_client.entities.machines.search(json={
            "timeFilter": {
                "startTime": start_time,
                "endTime": end_time
            },
            "filters": [
                {
                    "field": "hostname",
                    "expression": "rlike",
                    "value": filter
                }
            ],
            "returns": [ "mid" ] 
        })
    else:
        machine_ids = lw_client.entities.machines.search(json={
            "timeFilter": {
                "startTime": start_time,
                "endTime": end_time
            },
            "returns": [ "mid" ] 
        })

    mids = list()
    for r in machine_ids:
        for mid in r['data']:
            mids.append(mid['mid'])

    return mids


def get_host_vulns(lw_client, start_time, end_time, mids):
    vulnerability_pages = lw_client.vulnerabilities.hosts.search(json={
        "timeFilter": {
            "startTime": start_time,
            "endTime": end_time
        },
        "filters": [
            {
                "field": "status",
                "expression": "in",
                "values": ["Active","New","Reopened"]
            },
            {
                "field": "mid",
                "expression": "in",
                "values": mids
            }
        ]
    })

    vulns = list()
    for r in vulnerability_pages:
        for vuln in r['data']:
            vulns.append(vuln)

    return vulns


def main(args):

    if args.debug:
        logger.setLevel('DEBUG')
        logging.basicConfig(level=logging.DEBUG)

    # Use enviroment variables to instantiate a LaceworkClient instance
    try:
        lw_client = LaceworkClient(
            account=args.account,
            subaccount=args.subaccount,
            api_key=args.api_key,
            api_secret=args.api_secret,
            profile=args.profile
        )
    except Exception:
        raise    

    # # Make Org-level API calls
    # lw.set_org_level_access(True)

    # Grab the lacework accounts that the user has access to
    user_profile = lw_client.user_profile.get()
    user_profile_data = user_profile.get("data", {})[0]

    # Build start/end times
    start_time, end_time = get_start_end_times(day_delta=args.days)

    # Iterate through all subaccounts
    for subaccount in user_profile_data.get("accounts", []):

        # Print the account name
        print(f'Processing {subaccount["accountName"]}...')

        lw_client.set_subaccount(subaccount["accountName"])

        mids = get_relevant_mids(lw_client, start_time, end_time, args.filter)
        if len(mids) > 0:
            vulns = get_host_vulns(lw_client, start_time, end_time, mids)

            vulns_df = pd.json_normalize(vulns)

            # Sort the vulns by mid, severity
            sorted_vulns_df = vulns_df.sort_values(by=['mid','severity'])

            # Emit the results to CSV
            sorted_vulns_df.to_csv(f'{datetime.today().strftime("%Y%m%d")}_CVEs-{subaccount["accountName"]}.csv', sep=",")

            if len(sorted_vulns_df.index) >= 500_000:
                print(f'WARNING: Vuln records truncated for subaccount {subaccount["accountName"]}!')

            print(f'{subaccount["accountName"]} completed.')
        
        else:
            print(f'{subaccount["accountName"]} completed.')
            continue



if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description='A script to automatically issue container vulnerability scans to Lacework based on running containers'
    )
    parser.add_argument(
        '--account',
        default=os.environ.get('LW_ACCOUNT', None),
        help='The Lacework account to use'
    )
    parser.add_argument(
        '--subaccount',
        default=os.environ.get('LW_SUBACCOUNT', None),
        help='The Lacework sub-account to use'
    )
    parser.add_argument(
        '--api-key',
        dest='api_key',
        default=os.environ.get('LW_API_KEY', None),
        help='The Lacework API key to use'
    )
    parser.add_argument(
        '--api-secret',
        dest='api_secret',
        default=os.environ.get('LW_API_SECRET', None),
        help='The Lacework API secret to use'
    )
    parser.add_argument(
        '-p', '--profile',
        default='default',
        help='The Lacework CLI profile to use'
    )
    parser.add_argument(
        '-d', '--days',
        default=2,
        help='Number of days for lookback'
    )
    parser.add_argument(
        '-f', '--filter',
        default='',
        help='Desired hostname filter for mid lookup'
    )
    parser.add_argument(
        '--debug',
        action='store_true',
        default=os.environ.get('LW_DEBUG', False),
        help='Enable debug logging'
    )

    args = parser.parse_args()
    main(args)
