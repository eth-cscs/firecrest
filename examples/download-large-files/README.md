# How to download large files using FirecREST S3 backend

## Motivation

FirecREST uses [Amazon S3](https://aws.amazon.com/s3/) as a staging area for large data transfer. 

On downloading data from a remote server (ie, HPC cluster) to a local server (ie, your laptop), the endpoint `POST /storage/xfer-external/download` internally uploads the remote file as an object on an S3 bucket, and then creates a unique temporary self-signed URL for the client to download the object.

This works fine, but S3 has [a restriction on the max size of a single the object transfer of 5 GB](https://aws.amazon.com/s3/faqs/#:~:text=The%20largest%20object%20that%20can%20be%20uploaded%20in%20a%20single%20PUT%20is%205%20GB.).
This means that if the file you try to download is bigger than 5GB, then it is not possible to use the data transfer.

## Solution 1

You can use the `POST /storage/xfer-internal/compress` [endpoint](https://firecrest.readthedocs.io/en/latest/reference.html#post--storage-xfer-internal-compress) to compress the +5GB file to achieve a compressed file smaller than 5 GB.

If this doesn't work, then you can try with Solution 2

## Solution 2

For this, we've created this [example](f7t_split_transfer.py) on how to use pyFirecREST (though it could be also done using the API) to overcome the restriction.

### How does it work?

The steps reproduced in the example are:

1. a sbatch job (in this case, using SLURM) is created to split the file in 5 GB chunks using the function `create_sbatch_script`
2. using FirecREST, the job is executed, and on success, the parts are created with the suffix `.part.<xy>` where `<xy>` are integer numbers starting with `00`, `01`, etc.
3. using a loop over the parts, FirecREST downloads each part. After each part is downloaded, the part-object in S3 is removed
4. a Python function (`join_parts`) is used to join the parts in one file
5. using the function `remove_remote_parts` the parts on the remote server are removed using FirecREST

*Note: this is just an example, there are several different ways of reproduce all the steps listed above.*

### Sample output

```
Split the file /store/f7tuser/test-split-file/large_file in chunks of 4999MB
JobID[247754] -> Status: Job submitted
JobID[247754] -> Status: RUNNING
JobID[247754] -> Status: COMPLETED
File divided correctly
Files created:
        - large_file.part.00 (size: 4999MB)
        - large_file.part.01 (size: 1145MB)
Start downloading parts
Downloading /store/f7tuser/test-split-file/large_file.part.00 into /home/localuser/partdir
        Part large_file.part.00 ready to be downloaded
        Download to local storage started
        Download to local storage finished
Removing part file large_file.part.00
Downloading /store/f7tuser/test-split-file/large_file.part.01 into /home/localuser/partdir
        Part large_file.part.01 ready to be downloaded
        Download to local storage started
        Download to local storage finished
Removing part file large_file.part.01
Joining part large_file to /home/localuser/partdir/large_file
Finished
Joining part large_file.part.00 to /home/localuser/partdir/large_file
Finished
Joining part large_file.part.01 to /home/localuser/partdir/large_file
Finished
File /home/localuser/partdir/large_file joined
```