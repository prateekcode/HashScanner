import hashlib
import sys
import argparse
import requests


def parse_arguments():
    parser = argparse.ArgumentParser()

    # Required Arguments
    parser.add_argument("-f", "--file", dest="file", required=True,
                        help="Specify a file that should be scanned")

    parser.add_argument("-k", "--key", dest="key", required=True,
                        help="Unique API token to give rights to use endpoint")

    parser.add_argument("-hash", "--hash", dest="hash",  required=False, default="sha256",
                        help="Specify the hash function (type) to be used for the given file; default md5")

    # Optional Arguments
    parser.add_argument("-m", "--meta", dest="metadata", required=False, default=None,
                        help="Specify file metadata, 0 (don't add) or 1 (add)")

    # file_name
    parser.add_argument("-n", "--name", dest="preserve", action="store_true", required=False, default=None,
                        help="flag to preserve file name in scan")
    # archivepwd
    parser.add_argument("-p", "--password", dest="pwd", required=False, default=None,
                        help="password if submitted file is password protected")
    #samplesharing (0 or 1)
    parser.add_argument("-s", "--share", dest="share", action="store_true", default=None, required=False,
                        help="allows file scans to be shared or not (only working for paid users): allowed values 0/1")
    # downloadfrom
    parser.add_argument("-u", "--url", dest="link", default=None,
                        help="link to download file")
    parser.add_argument("-w", "--workflow", dest="workflow", default=None,
                        help="active workflows, allowed values: mcl-metadefender-rest-sanitize-disabled-unarchive")

    args = parser.parse_args()
    if args.preserve:
        args.preserve = args.file
    validate(args)
    return args


def validate(args):
    workflow_values = ['mcl', 'metadefender',
                       'rest', 'sanitize', 'disabled', 'unarchive']
    if args.workflow and args.workflow not in workflow_values:
        print("Invalid workflow variable given, allowed values: mcl-metadefender-rest-sanitize-disabled-unarchive")
        sys.exit(0)


def calculate_hash_file(filename, hash_type):
    try:
        if hash_type == "md5":
            hash = hashlib.md5()
        elif hash_type == "sha1":
            hash = hashlib.sha1()
        elif hash_type == "sha256":
            hash = hashlib.sha256()
        with open(filename, 'rb') as f:
            for chunk in iter(lambda: f.read(65536), b""):
                hash.update(chunk)
    except:
        print("Unable to hash file")
        sys.exit(0)
    return hash.hexdigest()


def retrieve_scan_file(url, api_key):
    headers = {'apikey': api_key}
    try:
        response = requests.get(url=url, headers=headers)
        output_data = response.json()
    except requests.exceptions.RequestException as e:
        print(e)
        sys.exit(0)
    except requests.exceptions.ResponseException as e:
        print(e)
        sys.exit(0)
    except requests.exceptions.ConnectionError as e:
        print(e)
        sys.exit(0)
    except requests.exceptions.HTTPError as e:
        print(e)
        sys.exit(0)
    except requests.exceptions.URLRequired as e:
        print(e.reason)
        sys.exit(0)
    return output_data


def upload_file_to_metadefender(api_key, file):
    base_url = "https://api.metadefender.com/v4/file"
    headers = {'apikey': api_key, 'content-type': "application/octet-stream"}
    try:
        response = requests.post(base_url, headers=headers, data=file)
        output_data = response.json()
    except requests.exceptions.RequestException as e:
        print(e)
        sys.exit(0)
    except requests.exceptions.HTTPError as e:
        print(e)
        sys.exit(0)
    except requests.exceptions.ConnectionError as error:
        print("Connection Error:", error)
        sys.exit(0)
    except requests.exceptions.Timeout as error:
        print("Timeout:", error)
        sys.exit(0)
    except:
        print("Unable to scan file")
        sys.exit(0)

    return output_data['data_id']


def file_analysis_result(api_key, data_id):
    base_url = "https://api.metadefender.com/v4/file/{data_id}".format(
        data_id=data_id)
    headers = {'apikey': api_key, 'x-file-metadata': '0'}
    try:
        response = requests.get(base_url, headers=headers)
        output_data = response.json()
    except requests.exceptions.RequestException as e:
        print(e)
        sys.exit(0)
    except requests.exceptions.HTTPError as e:
        print(e)
        sys.exit(0)
    except requests.exceptions.ConnectionError as e:
        print(e)
        sys.exit(0)
    except requests.exceptions.Timeout as e:
        print(e)
        sys.exit(0)
    except:
        print("Unable to retrieve file analysis result")
        sys.exit(0)
    return output_data


def show_results(results):
    print("filename: {filename}".format(
        filename=results['file_info']['display_name']))
    print("overall_status: {status}".format(
        status=results['scan_results']['scan_all_result_a']))

    for i, j in results['scan_results']['scan_details'].items():
        print("engine: {engine}".format(engine=i))
        print("threat_found: {threat}".format(
            threat=j['threat_found'] if j['threat_found'] else 'Clean'))
        print("scan_result: {scanresult}".format(
            scanresult=j['scan_result_i']))
        print("def_time: {time}".format(time=j['def_time']))


if __name__ == '__main__':
    args = parse_arguments()
    hashed_file_code = calculate_hash_file(args.file, args.hash)
    base_url = "https://api.metadefender.com/v4/hash/{}".format(
        hashed_file_code)
    retrieve_result = retrieve_scan_file(base_url, args.key)

    try:
        if retrieve_result['error']['code'] == 404003:
            data_id = upload_file_to_metadefender(args.key, args.file)
            file_result = file_analysis_result(args.key, data_id)
            while file_result['scan_results']['scan_all_result_a'] == 'In Progress':
                file_result = file_analysis_result(args.key, data_id)
            print(show_results(file_result))
    except:
        while retrieve_result['scan_results']['progress_percentage'] != 100:
            retrieve_result = retrieve_scan_file(base_url, args.key)
        print(show_results(retrieve_result))

