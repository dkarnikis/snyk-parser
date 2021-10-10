# snyk-parser
Tool for dynamically parsing snyk.io database
## Requirements
`npm i fs cheerio minimist sync-request get-dependencies check-npm-dependents`
## Usage
```sh
# to search the packets in NPM CVEs and fetch the first 20 pages, splitting the output with we do:  
node parser.js --type npm --page_count 20
# to fetch only 20-40 pages, run:
node parser.js --type npm --page_count 20 --start_page 20
```
Custom filters may also be applied:  
exploit, version, package, severity, date  
```sh
# to fetch all the "Prototype Pollution" exploits for all the packages with version 
# "*" starting from page 1 and search 20 pages, do:
node parser --type npm --page_count 20 --start_page 1 --exploit "Prototype Pollution" --version "*"
```
