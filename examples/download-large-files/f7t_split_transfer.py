#
#  Copyright (c) 2019-2025, ETH Zurich. All rights reserved.
#
#  Please, refer to the LICENSE file in the root directory.
#  SPDX-License-Identifier: BSD-3-Clause
#
import firecrest as fc
import time
import re
import sys
import os
import glob


system = "<replace_with_remote_system>"
dirname = "<replace_with_remote_dir>"
filename = "<replace_with_remote_large_file>"
client_id = "<replace_with_client_id>"
client_secret = "<replace_with_client_secret>"
token_uri = "<replace_with_token_uri>"
firecrest_url = "<replace_with_firecrest_uri>"
partition = "<replace_with_scheduler_queue>"
part_size_mb = 4999
script_path = "./sbatch_split_file.sh"
localdir = "<replace_your_local_dir>"

f7t_auth = fc.ClientCredentialsAuth(client_id, client_secret, token_uri)

client = fc.Firecrest(
    firecrest_url=firecrest_url,
    authorization=fc.ClientCredentialsAuth(client_id, client_secret, token_uri)
)


def remove_remote_part(dirname: str, part: str) -> bool:
    '''
    Removes parts created on the remote server when split happened
    - Parameters
        - `dirname (str)`: absolute path of the directory where the parts are
        stored
        - `part (str)`: name of the part file created in the directory
    - Returns (`bool`)
        - `True` if the part was removed correctly
        - `False` if the part wasn't removed correctly
    '''

    try:
        print(f"Removing part file {part}")
        client.submit_delete_job(system, f"{dirname}/{part}")
        return True
    except fc.FirecrestException as fe:
        print(f"Removal failed {fe}")
        return False


def join_parts(sourcedir: str, targetpath: str) -> bool:
    '''
    Joins the parts after downloaded on local directory
    - Parameters
        - `sourcedir (str)`: directory where the parts are downloaded on local
        system
        - `targetpath (str)`: absolute path (including file name) where the
        file is restored on local system
    - Returns (`bool`)
        - `True` if file was reconstructed correctly
        - `False` if file wasn't reconstructed correctly
    '''

    try:

        targetfile = open(targetpath, "wb")
        print()

        parts = glob.glob(f'{os.path.basename(targetpath)}.part.*')
        parts.sort()
        print(parts)

        for part in parts:
            print(f"Joining part {part} to {targetpath}")
            partpath = os.path.join(sourcedir, part)

            inputfile = open(partpath, "rb")
            while True:
                bytes = inputfile.read(1024)
                if not bytes:
                    break
                targetfile.write(bytes)
            inputfile.close()
            print("Finished")

        targetfile.close()
        print(f"File {targetpath} joined")
        return True

    except IOError as ioe:
        print(f"Error writing file {targetpath} ({ioe})")
        return False
    except Exception as e:
        print(f"Error writing file {targetpath} ({e})")
        return False


def download_part(remotepath: str, localdir: str) -> bool:
    '''
    Download a part of a large file on a remote path to a local directory

    - Parameters
      - `remotepath (str)`: absolute path of a part of a remote file to
      download
      - `localdir (str)`: local directory where to store the part file
      (directory must exist)
    - Returns (`bool`):
      - `True`: the part was downloaded successfully
      - `False`: the part wasn't downloaded successfully

    '''
    print(f"Downloading {remotepath} into {localdir}")
    part_dwn = client.external_download(system, remotepath)

    file_part = remotepath.split("/")[-1]

    while True:
        time.sleep(30)  # poll for status of the download

        if part_dwn.status == "117":
            print(f"\tPart {file_part} ready to be downloaded")
            print("\tDownload to local storage started")
            part_dwn.finish_download(f"{localdir}/{file_part}")
            print("\tDownload to local storage finished")
            return True
        elif part_dwn.status == "118":
            print(f"\tDownload of {file_part} failed")
            return False


def create_sbatch_script(script_path: str, filename: str, dirname: str,
                         part_size_mb: int = "4999",
                         partition: str = "debug") -> bool:
    '''
    Creates a sbatch script to be used to divide a large file in  4.99G chunks
    - Parameters:
      - `script_path (str)`: absolute or relative path in your system where the
        sbatch file is created
      - `filename (str)`: name of the file (incl. extension) to be divided into
        chunks (example: `bigfile.tar`)
      - `dirname (str)`: path to the directory where the file to be divided is
        stored in the remote system
      - `part_size_mb (int|None)`: size in MB of the part
      - `partition (str|None)`: partition where the job will be run on the
        remote system
    - Returns (`bool`):
       - `True` if file has been created correctly
       - `False` if file couldn't be created
    '''

    try:

        sbatch_file = open(script_path, "w")

        sbatch_file.write("#!/bin/bash -l\n")
        sbatch_file.write("#SBATCH --job-name=f7t_split_file\n")
        sbatch_file.write("#SBATCH --out=f7t_split_file_%J.out\n")
        sbatch_file.write("#SBATCH --error=f7t_split_file_%J.err\n")
        sbatch_file.write("#SBATCH --ntasks=1\n")
        sbatch_file.write("#SBATCH --tasks-per-node=1\n")
        sbatch_file.write(f"#SBATCH --partition={partition}\n")
        sbatch_file.write(f"echo 'Changing to directory {dirname}'\n")
        sbatch_file.write(f"cd {dirname}\n")
        sbatch_file.write(f"echo 'Splitting file {filename} " +
                          f"into {filename}.part.[1..N]'\n")
        sbatch_file.write(f"split -b {part_size_mb}M -d {filename} " +
                          f"{filename}.part.\n")
        sbatch_file.write(f"ls -lh {filename}.part.*\n")

        return True

    except IOError as ioe:
        print(f"Error writing file {script_path} ({ioe})")
        return False
    except Exception as e:
        print(f"Error writing file {script_path} ({e})")
        return False


try:
    if not create_sbatch_script(script_path, filename, dirname, part_size_mb,
                                partition):
        sys.exit(1)

    print(f"Split the file {dirname}/{filename} in chunks of {part_size_mb}MB")

    fc_job = client.submit(system, script_local_path=script_path)  # submit job

    job_id = fc_job["jobid"]
    job_status = fc_job["result"]

    print(f"JobID[{job_id}] -> Status: {job_status}")

    while True:
        time.sleep(10)
        fc_job = client.poll(system, [job_id])
        job_status = fc_job[0]["state"]
        print(f"JobID[{job_id}] -> Status: {job_status}")

        if job_status in ["COMPLETED", "FAILED"]:
            break

    if job_status == "FAILED":
        print("Job Failed. Exiting")
        sys.exit(1)

    else:
        print("File divided correctly")

        file_list = client.list_files(system, dirname)  # list remote files

        filenames = [row["name"] for row in file_list
                     if re.search(f"{filename}.part.*", row["name"])]
        filesizes = [int(row["size"])//1048576 for row in file_list
                     if re.search(f"{filename}.part.*", row["name"])]

        print("Files created:")
        for i in range(len(filenames)):
            print(f"\t- {filenames[i]} (size: {filesizes[i]}MB)")

        print("Start downloading parts")

        for part in filenames:
            if download_part(f"{dirname}/{part}", localdir):
                remove_remote_part(dirname, part)
            else:
                sys.exit(1)

except fc.FirecrestException as fe:
    print(f"Error submitting job: {fe}")
    sys.exit(1)
except Exception as e:
    print(f"Error submitting job: {e}")
    sys.exit(1)


if join_parts(localdir, f"{localdir}/{filename}"):
    print(f"Download of {dirname}/{filename} on {localdir} completed")
else:
    print(f"Error downloading {dirname}/{filename} on {localdir}")
