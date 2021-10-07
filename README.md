# snyk-parser
Tool for dynamically parsing snyk.io database
## Deps
fs cheerio sync-request minimist
## Usage
`node parser.js --out logname --type PACKAGE_DB --page_count PAGES_TO_SEARCH --sep SEPARATOR`  
to search the packets in NPM and fetch the first 20 pages, splitting the output with ',' we do:  
`node parser.js --out npm_20.dat --type npm --page_count 20 --sep ','`
To fetch only 20-40 pages, run:  
`node parser.js --out npm_20.dat --type npm --page_count 20 --sep ',' --start_page 20

