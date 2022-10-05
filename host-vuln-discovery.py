from operator import truediv
import os
import pandas as pd
import logging
import argparse
import copy

from datetime import datetime, timedelta, timezone
from laceworksdk import LaceworkClient
from concurrent.futures import ThreadPoolExecutor, as_completed

logger = logging.getLogger('host-vuln')
logger.setLevel(os.getenv('LOG_LEVEL', logging.INFO))

def get_start_end_times(day_delta=1):
    current_time = datetime.now(timezone.utc)
    start_time = current_time - timedelta(days=day_delta)
    start_time = start_time.strftime("%Y-%m-%dT%H:%M:%S%z")
    end_time = current_time.strftime("%Y-%m-%dT%H:%M:%S%z")

    return start_time, end_time


def get_machine_info(lw_client, start_time, end_time, args):

    if args.filter != "":
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
                    "value": args.filter
                }
            ]
        })
    else:
        machine_ids = lw_client.entities.machines.search(json={
            "timeFilter": {
                "startTime": start_time,
                "endTime": end_time
            }
        })

    machine_info = list()
    for r in machine_ids:
        for record in r['data']:
            machine_info.append(record)

        if args.testing:
            break

    return machine_info


def get_host_vulns(lw_client, start_time, end_time, include_fixed, mids):

    values = ["Active","New","Reopened"]
    if include_fixed:
        values.append("Fixed")

    vulnerability_pages = lw_client.vulnerabilities.hosts.search(json={
        "timeFilter": {
            "startTime": start_time,
            "endTime": end_time
        },
        "filters": [
            {
                "field": "status",
                "expression": "in",
                "values": values
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


def parse_mids(machine_info):
    mids = list()
    for r in machine_info:
        mids.append(r['mid'])

    return mids


def get_online_hosts(lw_client):

    # use a static 1-hour window to define what "online" looks like
    current_time = datetime.now(timezone.utc)
    start_time = current_time - timedelta(hours=1)
    start_time = start_time.strftime("%Y-%m-%dT%H:%M:%S%z")
    end_time = current_time.strftime("%Y-%m-%dT%H:%M:%S%z")

    active_machines = lw_client.agent_info.search(json={
        "timeFilter": {
            "startTime": start_time,
            "endTime": end_time
        }
    })

    mids = set()
    for r in active_machines:
        for m in r['data']:
            mids.add(m['mid'])

    return mids


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

    # Grab the lacework accounts that the user has access to
    user_profile = lw_client.user_profile.get()
    user_profile_data = user_profile.get("data", {})[0]

    # Build start/end times
    start_time, end_time = get_start_end_times(day_delta=int(args.days))

    # Iterate through all subaccounts
    for subaccount in user_profile_data.get("accounts", []):

        # Print the account name
        print(f'Processing {subaccount["accountName"]}...')

        lw_client.set_subaccount(subaccount["accountName"])

        machine_info = get_machine_info(lw_client, start_time, end_time, args)
        mids = parse_mids(machine_info)
        mid_count = len(mids)

        if mid_count > 0:
            
            vulns = list()

            # I've seen issues when putting all the mids through at once, so we should batch them 
            # into batches of N for the moment. Also, Python has no issue if idx exceeds the length 
            # of the array, hence no bounds checking on the back side
            batch_count = 0
            batch_size = 5_000
            logger.debug(f'total mid count: {mid_count}')

            executor_tasks = list()

            if mid_count > batch_size : 
                with ThreadPoolExecutor() as executor:
                    idx = batch_count * batch_size

                    while (idx < mid_count):
                        executor_tasks.append(executor.submit(get_host_vulns, copy.deepcopy(lw_client), start_time, end_time, args.include_fixed, mids[idx:(idx+ batch_size)]))
                        batch_count += 1
                        idx = batch_count * batch_size

                        if args.testing:
                            idx  = mid_count
                    
                    #TODO: Multithread pagination? 
                    
                    for task in as_completed(executor_tasks):
                        result = task.result()
                        vulns.extend(result)

            else:
                vulns.extend(get_host_vulns(lw_client, start_time, end_time, args.include_fixed, mids))

            vulns_df = pd.json_normalize(vulns)

            # Sort the vulns by mid, severity
            sorted_vulns_df = vulns_df.sort_values(by=['mid','severity'])

            if args.machine_details:
                machine_df = pd.json_normalize(machine_info)
                sorted_vulns_df = sorted_vulns_df.merge(machine_df, on='mid', how='left', suffixes=('','_machine_info'))

                # drop all cols we don't need in the final report
                for c in sorted_vulns_df.columns:
                    if (('cveProps' in c) 
                        or ('machine_info' in c) 
                        or ('evalCtx.' in c) 
                        or ('props' in c) 
                        or ('featureKey.package_path' in c)
                        or ('evalCtx.mc_eval_guid' in c)):
                        del sorted_vulns_df[c]

                # selectively keep machineTag columns, renaming as necessary
                for c in [i for i in sorted_vulns_df.columns if 'machineTags' in i]:
                    tags_to_keep = ['machineTags.Account', 'machineTags.AmiId', 'machineTags.Name', 'machineTags.ExternalIp', 'machineTags.VmProvider']
                    # keep the column if it's in the list of tags to keep, else drop
                    if not any([True if t == c else False for t in tags_to_keep]):
                        del sorted_vulns_df[c]

                del sorted_vulns_df['entityType']

                # get all hosts that checked in within the past ~hour and add as online/offline
                active_machines = get_online_hosts(lw_client)

                sorted_vulns_df.insert(len(sorted_vulns_df.columns), "HOST_TYPE", "offline")
                for idx,_ in sorted_vulns_df.iterrows():
                    if sorted_vulns_df.loc[idx,'mid'] in active_machines:
                       sorted_vulns_df.loc[idx,'HOST_TYPE'] = 'online'
                    else:
                        sorted_vulns_df.loc[idx,'HOST_TYPE'] = 'offline'

                sorted_vulns_df = sorted_vulns_df.rename(columns={
                    'primaryIpAddr':'INTERNAL_IP',
                    'machineTags.Account': 'ACCOUNT_ID', 
                    'machineTags.AmiId': 'AMI_ID', 
                    'machineTags.Name': 'NAME', 
                    'machineTags.ExternalIp': 'EXTERNAL_IP', 
                    'machineTags.VmProvider': 'VMPROVIDER',
                    'featureKey.name': 'PACKAGE',
                    'featureKey.namespace': 'PACKAGE_NAMESPACE',
                    'featureKey.package_active': 'PACKAGE_ACTIVE',
                    'featureKey.version_installed': 'VERSION_INSTALLED',
                    'fixInfo.fixed_version': 'FIX_VERSION',
                    'fixInfo.fix_available': 'FIX_AVAILABLE'
                }, inplace=True)

                # TODO: convert 1/0 to True/False
                #sorted_vulns_df["FIX_AVAILABLE"] = sorted_vulns_df["FIX_AVAILABLE"].astype(bool)
                #sorted_vulns_df["PACKAGE_ACTIVE"] = sorted_vulns_df["PACKAGE_ACTIVE"].astype(bool)

            sorted_vulns_df = sorted_vulns_df.astype(str).drop_duplicates()
            print(f'...writing results to file...')

            # Emit the results to CSV
            sorted_vulns_df.to_csv(f'{datetime.today().strftime("%Y%m%d")}_CVEs-{subaccount["accountName"]}.csv', sep=",")

            print(f'{subaccount["accountName"]} completed.')
        
        else:
            print(f'{subaccount["accountName"]} completed.')
            continue



if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description='A script to capture host vuln reports from Lacework'
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
        '-m', '--machine-details',
        action='store_true',
        default=False,
        help='Include additional machine details'
    )
    parser.add_argument(
        '--testing',
        action='store_true',
        default=False,
        help='Pass if testing to expedite results'
    )
    parser.add_argument(
        '--include-fixed',
        action='store_true',
        default=False,
        help='Include fixed vulnerability results as well'
    )
    parser.add_argument(
        '--debug',
        action='store_true',
        default=os.environ.get('LW_DEBUG', False),
        help='Enable debug logging'
    )

    args = parser.parse_args()
    main(args)
