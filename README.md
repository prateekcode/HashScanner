
# Hash Scanner

To run this program, we need to perform following instruction.

## Watch this tutorial to use this
https://youtu.be/lq_PSmZNY4M





  ### Requirement
  Python 3.8

  
## API Reference

#### Hash Lookups

```http
  GET https://api.metadefender.com/v4/hash/{hash}
```

| Parameter | Type     | Description                |
| :-------- | :------- | :------------------------- |
| `api_key` | `string` | **Required**. Your API key |
| `hash`    | `string` | **Required**  Generated Hash |   

#### Get Data Id

```http
  POST https://api.metadefender.com/v4/file
```

| Parameter | Type     | Description                       |
| :-------- | :------- | :-------------------------------- |
| `api_key` | `string` | **Required**. Your API key |
| `Content-Type` | `string` |  **application/octet-stream** |
| `file` | `file` | `file`|

#### Analyze file using Data Id

```http
  GET https://api.metadefender.com/v4/file/{data_id}
```

| Parameter | Type     | Description                       |
| :-------- | :------- | :-------------------------------- |
| `api_key` | `string` | **Required**. Your API key |
| `x-file-metadata` | `string` |  **0** |
| `data_id` | `string` | **Required**.`data_id`|

## Flags

Command | Detail
:-- | --:
-f, --file | Specify file to be scanned
-k, --key | Unique API token; required
-hash, --hash | specify hash function (md5, sha1, sha256)
-m, -meta | get metadata for scanned file
-n, --name | flag to preserve file name in scan
-p, --p | password for password protected files
-s, --share | allows file scans to be share or not
-w, --workflow | active workflows, allowed values: mcl-metadefender-rest-sanitize-disabled-unarchive

## Run Locally

Clone the project

```bash
  git clone https://github.com/prateekcode/HashScanner
```

Go to the project directory

```bash
  cd HashScanner
```

Run the Program as

```bash
  python3 hash_scanner.py -f samplefile.txt -k YOUR_API_KEY
```


## Author
[@prateekcode](https://www.github.com/prateekcode)

  
