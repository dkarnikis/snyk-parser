# snyk-parser
Tool for dynamically parsing snyk.io database
## Requirements
`npm i fs cheerio sync-request minimist`
## Usage
```sh
# to search the packets in NPM CVEs and fetch the first 20 pages, splitting the output with ',' we do:  
node parser.js --out npm_20.dat --type npm --page_count 20 --sep ','
# to fetch only 20-40 pages, run:
node parser.js --out npm_20.dat --type npm --page_count 20 --sep ',' --start_page 20
```
